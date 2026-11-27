// Módulo de IA dentro de la propia plataforma (alternativa a MCP): la organización pone su propia
// llave de Anthropic en Configuración. Cuando el módulo actúa, lo hace con EXACTAMENTE los mismos
// permisos que RolePermissions.agent ya tiene por MCP — nunca abre ni cierra un caso, nunca aprueba
// un plan, nunca toca ninguna red por sí solo.
import type { Store } from "./store.js";
import { analyzeLog, analyzeEmailHeaders, containmentRules, buildIncidentReport, suggestIncidentTypes, TYPE_GUIDANCE, MAX_EVIDENCE_CHARS } from "./incident.js";
import { createFinding } from "./findings.js";
import { buildReport } from "./report.js";
import { redact } from "./redact.js";
import { PolicyEngine } from "./policy.js";
import { Gateway } from "./gateway.js";
import { builtinModules, type Module } from "./modules.js";
import type { Target } from "./scope.js";
import { runScanInitiate, runScanStop } from "./scan.js";
import type { RunRegistry } from "./server.js";
import { parseManifest, checkVulnerabilities, MAX_MANIFEST_CHARS } from "./supplychain.js";
import { IncidentCreateIn, AssessmentCreateIn } from "./schemas.js";

export type Provider = "anthropic" | "openai" | "gemini";
const MAX_ITERS = 4;
const MAX_TOKENS = 1500;
const DEFAULT_BASE: Record<Provider, string> = {
  anthropic: "https://api.anthropic.com/v1",
  openai: "https://api.openai.com/v1",
  gemini: "https://generativelanguage.googleapis.com/v1beta",
};
const baseOf = (provider: Provider, baseUrl?: string | null) => (baseUrl || DEFAULT_BASE[provider]).replace(/\/+$/, "");

export type FetchFn = typeof fetch;

/** Los proveedores (sobre todo Gemini en los niveles gratis) devuelven de vez en cuando un 429/500/502/503/504
 * transitorio — "modelo sobrecargado" o "demasiadas solicitudes", que no tiene nada que ver con la llave ni el
 * modelo. En vez de mostrárselo al humano como si fuera un error real, se reintenta varias veces con espera
 * (respetando el "Retry-After" del proveedor si lo manda, típico en 429 por cuota por minuto) antes de rendirse. */
async function fetchWithRetry(fetchImpl: FetchFn, url: string, init: Parameters<FetchFn>[1], tries = 4): Promise<Response> {
  const RETRYABLE = new Set([429, 500, 502, 503, 504]);
  let res: Response;
  for (let i = 0; i < tries; i++) {
    res = await fetchImpl(url, init);
    if (res.ok || i === tries - 1 || !RETRYABLE.has(res.status)) return res;
    const retryAfter = Number(res.headers?.get?.("retry-after"));
    const wait = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 6000) : Math.min(500 * 2 ** i, 4000) + Math.floor(Math.random() * 250);
    await new Promise((r) => setTimeout(r, wait));
  }
  return res!;
}

/** Mensaje para el humano cuando, tras reintentar, el proveedor sigue sin responder bien. Un 429 agotado tras
 * reintentos suele ser cuota por minuto (no por crédito agotado), así que se lo decimos explícito en vez de
 * dejarle solo el código numérico — eso es lo que de verdad ayuda a decidir si reintentar de nuevo o no. */
function upstreamErrorMessage(label: string, status: number, model: string): string {
  if (status === 429) return `${label} está limitando las solicitudes por ahora (429: demasiadas peticiones en poco tiempo, típico de los niveles gratuitos). Ya se reintentó varias veces solo; espera unos segundos y vuelve a preguntar.`;
  if (status === 404) return `${label} respondió 404 (revisa que el modelo "${model}" exista y esté disponible para tu llave).`;
  if (status >= 500) return `${label} respondió ${status} (falla temporal del proveedor). Ya se reintentó solo; si persiste, vuelve a intentarlo en un momento.`;
  return `${label} respondió ${status}.`;
}
export interface AiAction { tool: string; input: Record<string, unknown>; result: unknown }
export type AiResult = { answer: string; actions: AiAction[] } | { error: string; message: string };
export interface ModelInfo { id: string; label: string }

type ToolUseBlock = { type: "tool_use"; id: string; name: string; input: Record<string, unknown> };
type TextBlock = { type: "text"; text: string };
type ToolDef = { name: string; description: string; input_schema: Record<string, unknown> };

/** El actor que queda en la auditoría deja explícito que fue el módulo de IA, a petición de qué humano. */
export const aiActor = (human: string) => `ia-modulo:${human}`;

/** Lista los modelos reales disponibles con esa llave, para que el humano elija de una lista en vez de escribir el nombre a mano. */
export async function listModels(provider: Provider, apiKey: string, baseUrl: string | undefined, fetchImpl: FetchFn = fetch): Promise<ModelInfo[]> {
  const base = baseOf(provider, baseUrl);
  if (provider === "anthropic") {
    const res = await fetchImpl(`${base}/models?limit=100`, { headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01" } });
    if (!res.ok) throw new Error(res.status === 401 ? "La llave de API no es válida." : `Anthropic respondió ${res.status}.`);
    const data = await res.json() as { data: Array<{ id: string; display_name?: string }> };
    return data.data.map((m) => ({ id: m.id, label: m.display_name || m.id }));
  }
  if (provider === "openai") {
    const res = await fetchImpl(`${base}/models`, { headers: { Authorization: `Bearer ${apiKey}` } });
    if (!res.ok) throw new Error(res.status === 401 ? "La llave de API no es válida." : `La API respondió ${res.status}.`);
    const data = await res.json() as { data: Array<{ id: string }> };
    return data.data.map((m) => ({ id: m.id, label: m.id })).sort((a, b) => a.id.localeCompare(b.id));
  }
  // gemini
  const res = await fetchImpl(`${base}/models?key=${encodeURIComponent(apiKey)}&pageSize=200`);
  if (!res.ok) throw new Error(res.status === 401 || res.status === 403 ? "La llave de API no es válida." : `Gemini respondió ${res.status}.`);
  const data = await res.json() as { models?: Array<{ name: string; displayName?: string; supportedGenerationMethods?: string[] }> };
  return (data.models ?? [])
    .filter((m) => !m.supportedGenerationMethods || m.supportedGenerationMethods.includes("generateContent"))
    .map((m) => ({ id: m.name.replace(/^models\//, ""), label: m.displayName || m.name }));
}

/** Probar conexión: valida la llave (listando modelos) y, si se da un modelo, hace además una llamada real
 * mínima con ESE modelo — el mismo camino que usan los chats. Antes solo se listaban modelos, así que una
 * llave válida con un modelo inexistente o no habilitado para esa llave pasaba la prueba y luego fallaba
 * igual en el chat real; con esto se detecta aquí, antes de que el humano llegue al chat. */
export async function testApiKey(provider: Provider, apiKey: string, baseUrl: string | undefined, model?: string, fetchImpl: FetchFn = fetch): Promise<{ ok: true } | { ok: false; message: string }> {
  try { await listModels(provider, apiKey, baseUrl, fetchImpl); }
  catch (e) { return { ok: false, message: (e as Error).message || "No se pudo contactar a la API." }; }
  if (!model) return { ok: true };
  try {
    const r = await runAssistant({ provider, apiKey, model, baseUrl, system: "Responde solo con la palabra OK.", question: "Responde solo con la palabra OK, nada más.", tools: [], execTool: async () => ({}), fetchImpl });
    if ("error" in r) return { ok: false, message: `La llave funciona, pero el modelo "${model}" no respondió: ${r.message}` };
    return { ok: true };
  } catch (e) { return { ok: false, message: `La llave funciona, pero el modelo "${model}" no respondió: ${(e as Error).message || "error desconocido"}` }; }
}

type RunOpts = {
  provider: Provider; apiKey: string; model: string; baseUrl?: string | null; system: string; question: string; tools: ToolDef[];
  execTool: (name: string, input: Record<string, unknown>) => Promise<unknown>; fetchImpl: FetchFn;
};

/** Bucle de uso de herramientas. Mismo contrato (execTool) para los tres proveedores y para los dos asistentes (Incidentes y Evaluaciones). */
async function runAssistant(opts: RunOpts): Promise<AiResult> {
  if (opts.provider === "openai") return runOpenAiLoop(opts);
  if (opts.provider === "gemini") return runGeminiLoop(opts);
  return runAnthropicLoop(opts);
}

async function runAnthropicLoop(opts: RunOpts): Promise<AiResult> {
  const url = `${baseOf("anthropic", opts.baseUrl)}/messages`;
  const messages: Array<{ role: "user" | "assistant"; content: unknown }> = [{ role: "user", content: opts.question.slice(0, 4000) }];
  const actions: AiAction[] = [];
  for (let i = 0; i < MAX_ITERS; i++) {
    const res = await fetchWithRetry(opts.fetchImpl, url, {
      method: "POST",
      headers: { "x-api-key": opts.apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: opts.model, max_tokens: MAX_TOKENS, system: opts.system, messages, tools: opts.tools }),
    });
    if (!res.ok) return { error: "AI_UPSTREAM_ERROR", message: upstreamErrorMessage("Anthropic", res.status, opts.model) };
    const data = await res.json() as { content: Array<TextBlock | ToolUseBlock>; stop_reason: string };
    const toolUses = data.content.filter((b): b is ToolUseBlock => b.type === "tool_use");
    const text = data.content.filter((b): b is TextBlock => b.type === "text").map((b) => b.text).join("\n").trim();
    if (!toolUses.length || data.stop_reason !== "tool_use") return { answer: text || "(sin respuesta)", actions };

    messages.push({ role: "assistant", content: data.content });
    const toolResults: Array<{ type: "tool_result"; tool_use_id: string; content: string }> = [];
    for (const tu of toolUses) {
      const result = await opts.execTool(tu.name, tu.input);
      actions.push({ tool: tu.name, input: tu.input, result });
      toolResults.push({ type: "tool_result", tool_use_id: tu.id, content: JSON.stringify(result).slice(0, 8000) });
    }
    messages.push({ role: "user", content: toolResults });
  }
  return { answer: "Se alcanzó el límite de pasos con las herramientas; revisa las acciones ya generadas abajo.", actions };
}

async function runOpenAiLoop(opts: RunOpts): Promise<AiResult> {
  const url = `${baseOf("openai", opts.baseUrl)}/chat/completions`;
  type Msg = { role: string; content: string | null; tool_calls?: Array<{ id: string; function: { name: string; arguments: string } }>; tool_call_id?: string };
  const messages: Msg[] = [{ role: "system", content: opts.system }, { role: "user", content: opts.question.slice(0, 4000) }];
  const actions: AiAction[] = [];
  const tools = opts.tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.input_schema } }));
  for (let i = 0; i < MAX_ITERS; i++) {
    const res = await fetchWithRetry(opts.fetchImpl, url, {
      method: "POST",
      headers: { Authorization: `Bearer ${opts.apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({ model: opts.model, max_tokens: MAX_TOKENS, messages, tools, tool_choice: "auto" }),
    });
    if (!res.ok) return { error: "AI_UPSTREAM_ERROR", message: upstreamErrorMessage("La API", res.status, opts.model) };
    const data = await res.json() as { choices?: Array<{ message: Msg }> };
    const msg = data.choices?.[0]?.message;
    if (!msg) return { error: "AI_UPSTREAM_ERROR", message: "Respuesta vacía de la API." };
    const toolCalls = msg.tool_calls ?? [];
    if (!toolCalls.length) return { answer: (msg.content || "(sin respuesta)").trim(), actions };

    messages.push({ role: "assistant", content: msg.content ?? null, tool_calls: toolCalls });
    for (const tc of toolCalls) {
      let input: Record<string, unknown> = {};
      try { input = JSON.parse(tc.function.arguments || "{}"); } catch { /* argumentos no parseables: se trata como vacío */ }
      const result = await opts.execTool(tc.function.name, input);
      actions.push({ tool: tc.function.name, input, result });
      messages.push({ role: "tool", tool_call_id: tc.id, content: JSON.stringify(result).slice(0, 8000) });
    }
  }
  return { answer: "Se alcanzó el límite de pasos con las herramientas; revisa las acciones ya generadas abajo.", actions };
}

async function runGeminiLoop(opts: RunOpts): Promise<AiResult> {
  const url = `${baseOf("gemini", opts.baseUrl)}/models/${encodeURIComponent(opts.model)}:generateContent?key=${encodeURIComponent(opts.apiKey)}`;
  type Part = { text?: string; functionCall?: { name: string; args?: Record<string, unknown> }; functionResponse?: { name: string; response: unknown } };
  const contents: Array<{ role: string; parts: Part[] }> = [{ role: "user", parts: [{ text: opts.question.slice(0, 4000) }] }];
  const actions: AiAction[] = [];
  // Gemini accepts a smaller JSON Schema subset than other providers. Keep bounds in our
  // tool handlers and omit unsupported validation keywords so authorized tools do not trigger HTTP 400.
  const geminiSchema = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(geminiSchema);
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([key]) => !["maxLength", "minLength", "minimum", "maximum", "minItems", "maxItems"].includes(key))
      .map(([key, child]) => [key, geminiSchema(child)]));
  };
  const tools = [{ functionDeclarations: opts.tools.map((t) => ({ name: t.name, description: t.description, parameters: geminiSchema(t.input_schema) as Record<string, unknown> })) }];
  for (let i = 0; i < MAX_ITERS; i++) {
    const res = await fetchWithRetry(opts.fetchImpl, url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ system_instruction: { parts: [{ text: opts.system }] }, contents, tools, generationConfig: { maxOutputTokens: MAX_TOKENS } }),
    });
    if (!res.ok) return { error: "AI_UPSTREAM_ERROR", message: upstreamErrorMessage("Gemini", res.status, opts.model) };
    const data = await res.json() as { candidates?: Array<{ content: { parts: Part[] } }> };
    const parts = data.candidates?.[0]?.content?.parts ?? [];
    const calls = parts.filter((p) => p.functionCall);
    const text = parts.filter((p) => p.text).map((p) => p.text).join("\n").trim();
    if (!calls.length) return { answer: text || "(sin respuesta)", actions };

    contents.push({ role: "model", parts });
    const responseParts: Part[] = [];
    for (const c of calls) {
      const name = c.functionCall!.name, args = c.functionCall!.args ?? {};
      const result = await opts.execTool(name, args);
      actions.push({ tool: name, input: args, result });
      responseParts.push({ functionResponse: { name, response: { result } } });
    }
    contents.push({ role: "function", parts: responseParts });
  }
  return { answer: "Se alcanzó el límite de pasos con las herramientas; revisa las acciones ya generadas abajo.", actions };
}

/* =========================== Incidentes =========================== */

const INCIDENT_TOOLS: ToolDef[] = [
  {
    name: "incident_evidence_analyze",
    description: "Analiza texto de evidencia (log o cabeceras de correo) que el humano incluyó en su mensaje y lo guarda como evidencia del caso. Solo está disponible si el autorizador activó la delegación puntual para esta consulta. Solo lee el texto dado; no se conecta a ninguna red.",
    input_schema: { type: "object", properties: {
      kind: { type: "string", enum: ["log", "email_headers", "other"] },
      description: { type: "string", maxLength: 300 },
      content: { type: "string", maxLength: MAX_EVIDENCE_CHARS },
    }, required: ["kind", "description", "content"] },
  },
  {
    name: "incident_types_set",
    description: "Marca o reemplaza los tipos del caso. Solo está disponible si el autorizador activó la delegación puntual para esta consulta. Con esa autorización, marca únicamente tipos respaldados con claridad por la evidencia; sin ella, no está disponible.",
    input_schema: { type: "object", properties: {
      types: { type: "array", items: { type: "string", enum: ["phishing_email", "network_intrusion", "malware_ransomware", "ddos", "data_breach", "unauthorized_access", "web_attack", "other"] } },
    }, required: ["types"] },
  },
  {
    name: "incident_targets_set",
    description: "Marca o reemplaza qué herramientas de bloqueo (firewall/iptables-ufw, nginx, Cloudflare) tiene disponibles el equipo. Solo está disponible con delegación puntual, y aun así nunca supongas disponibilidad: el humano debe haber indicado qué herramientas posee.",
    input_schema: { type: "object", properties: {
      targets: { type: "array", items: { type: "string", enum: ["firewall", "nginx", "cloudflare"] } },
    }, required: ["targets"] },
  },
  {
    name: "incident_contain_plan",
    description: "Genera reglas de bloqueo (firewall, nginx, Cloudflare) a partir de IPs/dominios para que el equipo humano las aplique en SU PROPIA infraestructura. No ejecuta nada.",
    input_schema: { type: "object", properties: {
      ips: { type: "array", items: { type: "string" } },
      domains: { type: "array", items: { type: "string" } },
      targets: { type: "string", enum: ["firewall", "nginx", "cloudflare", "all"] },
    } },
  },
  {
    name: "incident_report",
    description: "Genera el informe acumulado del incidente (IOCs, línea de tiempo, a quién reportarlo).",
    input_schema: { type: "object", properties: { format: { type: "string", enum: ["markdown", "json"] } } },
  },
];

export async function runIncidentAssistant(opts: {
  store: Store; incidentId: string; question: string; requestedBy: string; authorizeActions?: boolean; fetchImpl?: FetchFn;
}): Promise<AiResult> {
  const { store, incidentId, question, requestedBy } = opts;
  const authorizeActions = opts.authorizeActions === true;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const secret = await store.getAiSecret();
  if (!secret) return { error: "AI_NOT_CONFIGURED", message: "El módulo de IA no está activado o no tiene una llave de API guardada. Ve a Configuración → Integración IA." };
  const rec = await store.getIncident(incidentId);
  if (!rec) return { error: "INCIDENT_NOT_FOUND", message: "El incidente no existe." };
  if (rec.incident.status === "closed") return { error: "INCIDENT_CLOSED", message: "Este incidente ya está cerrado." };

  const evidenceSummary = rec.evidence.length
    ? rec.evidence.map((e, i) => `Evidencia ${i + 1} (${e.kind}) — ${e.description}:\nIOCs: ${JSON.stringify(e.iocs)}\n${redact(e.redactedContent, 1500)}`).join("\n\n")
    : "Sin evidencia registrada todavía.";
  const system = `Eres el asistente de IA del módulo de Incidentes de "Ethical Security Copilot", dentro de la propia plataforma (no por MCP). ` +
    (authorizeActions
      ? `El autorizador/operador ha delegado expresamente, para ESTA consulta, las acciones limitadas de consola que aparecen como herramientas: analizar y guardar evidencia aportada en este chat, actualizar tipos de incidente o herramientas disponibles SOLO con datos confirmados por el humano, generar planes de contención e informes. Usa esas herramientas si son necesarias para completar la petición; no solicites una segunda confirmación dentro del chat para esas acciones autorizadas. `
      : `No tienes autorización para realizar cambios en el caso durante esta consulta. Puedes orientar en texto y usar solo herramientas de lectura/generación de informe o de plan. Si el humano solicita que guardes análisis de evidencia o actualices tipos/herramientas, pídele que active la autorización puntual de acciones antes. `) +
    `Límite estricto: la delegación solo permite esas operaciones dentro de Ethical Security Copilot. Nunca te conectas a cuentas o servicios externos ni ejecutas reglas, bloqueos, cambios de contraseña, cierre de sesiones, borrados, notificaciones o contactos. ` +
    `nunca abres ni cierras el caso (eso solo lo hace un humano). "Cerrar el paso, no contraatacar": jamás propongas ni describas atacar, acceder o dañar sistemas de terceros, ` +
    `ni siquiera los del presunto atacante. Responde siempre en español, de forma clara y concreta. ` +
    (authorizeActions
      ? `Con la autorización puntual activa puedes marcar tipos sustentados por evidencia clara y guardar el análisis pedido. Nunca inventes herramientas disponibles: para incident_targets_set exige que el humano haya indicado cuáles tiene. Las reglas generadas son borradores que el equipo debe revisar y aplicar por separado. `
      : `Sin autorización puntual, incident_types_set, incident_targets_set e incident_evidence_analyze no están disponibles. `) + `\n\n` +
    `Caso: ${rec.incident.organization} — ${rec.incident.summary}\nEstado: ${rec.incident.status}\nTipos ya marcados: ${rec.incident.types?.length ? rec.incident.types.join(", ") : "ninguno todavía"}\n` +
    `Herramientas de bloqueo ya marcadas: ${rec.incident.containmentTargets?.length ? rec.incident.containmentTargets.join(", ") : "ninguna todavía (se generará para todas por defecto)"}\n\n${evidenceSummary}`;

  const execTool = async (name: string, input: Record<string, unknown>): Promise<unknown> => {
    const actor = aiActor(requestedBy);
    if (!authorizeActions && ["incident_evidence_analyze", "incident_types_set", "incident_targets_set"].includes(name))
      return { error: "HUMAN_AUTHORIZATION_REQUIRED", message: "El autorizador debe activar la delegación puntual de acciones para esta consulta." };
    if (name === "incident_evidence_analyze") {
      const content = String(input.content ?? "").slice(0, MAX_EVIDENCE_CHARS);
      const description = String(input.description ?? "evidencia aportada en el chat de IA").slice(0, 300);
      const kind = (["log", "email_headers", "other"].includes(String(input.kind)) ? input.kind : "other") as "log" | "email_headers" | "other";
      const r = kind === "email_headers" ? analyzeEmailHeaders(content) : analyzeLog(content);
      const saved = await store.addIncidentEvidence(incidentId, { kind, description, redactedContent: redact(content, 8000), iocs: r.iocs }, actor);
      if (saved === null || saved === "CLOSED") return { error: "no se pudo guardar la evidencia" };
      const suggestedTypes = suggestIncidentTypes(kind, r.patterns).map((s) => ({ ...s, guidance: TYPE_GUIDANCE[s.type] }));
      return { evidenceId: saved.id, facts: r.facts, patterns: r.patterns, iocs: r.iocs, suggestedTypes,
        note: suggestedTypes.length ? "Son sugerencias de tipo de incidente; pregúntale al humano si quiere marcarlas antes de llamar a incident_types_set." : undefined };
    }
    if (name === "incident_types_set") {
      const types = Array.isArray(input.types) ? input.types.map(String) : [];
      const ok = await store.setIncidentTypes(incidentId, types, actor, "agent");
      if (!ok) return { error: "no se pudo guardar (¿incidente cerrado o inexistente?)" };
      return { types, guidance: Object.fromEntries(types.map((t) => [t, (TYPE_GUIDANCE as Record<string, string[]>)[t]])) };
    }
    if (name === "incident_targets_set") {
      const targets = Array.isArray(input.targets) ? input.targets.map(String) : [];
      const ok = await store.setIncidentContainmentTargets(incidentId, targets, actor, "agent");
      if (!ok) return { error: "no se pudo guardar (¿incidente cerrado o inexistente?)" };
      return { containmentTargets: targets };
    }
    if (name === "incident_contain_plan") {
      const ips = Array.isArray(input.ips) ? input.ips.map(String) : [];
      const domains = Array.isArray(input.domains) ? input.domains.map(String) : [];
      const targets = (["firewall", "nginx", "cloudflare", "all"].includes(String(input.targets)) ? input.targets : "all") as "firewall" | "nginx" | "cloudflare" | "all";
      const rules = containmentRules(ips, domains, targets);
      await store.audit({ actor, role: "agent", action: "incident:contain_plan", assessmentId: incidentId, payload: { ips: ips.length, domains: domains.length, targets, via: "ai-module" } });
      return { rules, note: "Estas reglas no se han aplicado en ningún lado." };
    }
    if (name === "incident_report") {
      const r2 = await store.getIncident(incidentId);
      if (!r2) return { error: "incidente no encontrado" };
      const format = input.format === "json" ? "json" : "markdown";
      await store.audit({ actor, role: "agent", action: "incident:report", assessmentId: incidentId, payload: { format, via: "ai-module" } });
      return { text: buildIncidentReport(r2.incident, r2.evidence, format), format };
    }
    return { error: `herramienta desconocida: ${name}` };
  };

  const writeTools = new Set(["incident_evidence_analyze", "incident_types_set", "incident_targets_set"]);
  const tools = authorizeActions ? INCIDENT_TOOLS : INCIDENT_TOOLS.filter((tool) => !writeTools.has(tool.name));
  return runAssistant({ provider: secret.provider as Provider, apiKey: secret.apiKey, model: secret.model, baseUrl: secret.baseUrl, system, question, tools, execTool, fetchImpl });
}

/* =========================== Evaluaciones ===========================
   El módulo de IA puede ahora también validar alcance, lanzar módulos (scan_initiate — sigue pasando
   SIEMPRE por la misma aprobación humana de un plan con token de un solo uso que ya exige MCP/consola),
   detener todo con el kill switch (scan_stop) y analizar cadena de suministro (supply_chain_analyze).
   Es EXACTAMENTE el mismo conjunto que RolePermissions.agent ya tiene por MCP — ni una herramienta más. */

const ASSESSMENT_TOOLS: ToolDef[] = [
  {
    name: "finding_create",
    description: "Registra un hallazgo nuevo: hechos observados separados de hipótesis de riesgo, con CVSS, confianza y evidencia redactada.",
    input_schema: { type: "object", properties: {
      title: { type: "string", minLength: 5, maxLength: 200 },
      asset: { type: "string", description: "IP, CIDR, dominio o URL dentro del alcance de la evaluación" },
      severity: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
      cvssVector: { type: "string", description: "Vector CVSS 3.x, p. ej. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" },
      cvssScore: { type: "number", minimum: 0, maximum: 10 },
      confidence: { type: "string", enum: ["high", "medium", "low"] },
      observedFacts: { type: "array", items: { type: "string" }, minItems: 1 },
      riskHypotheses: { type: "array", items: { type: "string" } },
      evidence: { type: "array", items: { type: "object", properties: {
        description: { type: "string" }, redactedContent: { type: "string", maxLength: 8000 }, reproSteps: { type: "array", items: { type: "string" } },
      }, required: ["description", "redactedContent", "reproSteps"] }, minItems: 1 },
      businessImpact: { type: "string" },
      recommendation: { type: "string" },
    }, required: ["title", "asset", "severity", "cvssVector", "cvssScore", "confidence", "observedFacts", "evidence", "businessImpact", "recommendation"] },
  },
  {
    name: "report_generate",
    description: "Genera el informe de la evaluación (Markdown o JSON) con los hallazgos ya confirmados.",
    input_schema: { type: "object", properties: {
      format: { type: "string", enum: ["markdown", "json"] },
      includeStates: { type: "array", items: { type: "string", enum: ["confirmed", "unverified"] } },
    } },
  },
  {
    name: "scope_validate",
    description: "Verifica si un target (ip, cidr, dominio, url o dispositivo) está autorizado por el alcance de la evaluación. Es solo una consulta: no ejecuta nada ni consume el presupuesto de ritmo.",
    input_schema: { type: "object", properties: {
      target: { type: "object", properties: {
        type: { type: "string", enum: ["cidr", "ip", "domain", "url", "device"] },
        value: { type: "string" },
        includeSubdomains: { type: "boolean" },
        pathPrefix: { type: "string" },
      }, required: ["type", "value"] },
    }, required: ["target"] },
  },
  {
    name: "scan_initiate",
    description: "Lanza un módulo (pasivo, laboratorio o activo) contra los targets dados. SOLO se debe llamar después de que el humano pida explícitamente en el chat que se ejecute ese módulo. En modo activo, o si el módulo cambia estado, esto NO ejecuta nada todavía: devuelve un plan pendiente de aprobación humana (planId) que un operator debe aprobar aparte, con un token de un solo uso; vuelve a llamar a esta misma herramienta con planId y approvalToken solo si el humano te entrega ese token.",
    input_schema: { type: "object", properties: {
      moduleId: { type: "string", description: "Identificador del módulo, p. ej. tcp_port_check, http_header_audit, config_audit." },
      mode: { type: "string", enum: ["passive", "lab", "active"] },
      targets: { type: "array", minItems: 1, items: { type: "object", properties: {
        type: { type: "string", enum: ["cidr", "ip", "domain", "url", "device"] },
        value: { type: "string" },
        includeSubdomains: { type: "boolean" },
        pathPrefix: { type: "string" },
      }, required: ["type", "value"] } },
      params: { type: "object", description: "Parámetros específicos del módulo (opcional)." },
      planId: { type: "string", description: "Solo si el humano ya aprobó un plan pendiente y te dio este id." },
      approvalToken: { type: "string", description: "Token de un solo uso que el humano recibió al aprobar el plan." },
    }, required: ["moduleId", "mode", "targets"] },
  },
  {
    name: "scan_stop",
    description: "Kill switch: detiene de inmediato cualquier ejecución en curso de esta evaluación (o de todas, si no se da assessmentId) y bloquea nuevas hasta que un humano authorizer lo libere. Úsalo si el humano lo pide o ante cualquier señal de que algo salió mal.",
    input_schema: { type: "object", properties: {
      allAssessments: { type: "boolean", description: "true para detener TODO, no solo esta evaluación." },
      reason: { type: "string", minLength: 3, maxLength: 300 },
    }, required: ["reason"] },
  },
  {
    name: "supply_chain_analyze",
    description: "Analiza un manifiesto de dependencias que el humano pega (package-lock.json, package.json, requirements.txt, o una lista manual 'nombre@versión') y lo cruza con OSV.dev para detectar vulnerabilidades conocidas (A03). Solo lee el texto dado; no instala ni ejecuta nada.",
    input_schema: { type: "object", properties: {
      kind: { type: "string", enum: ["npm_package_lock", "npm_package_json", "pip_requirements", "manual"] },
      content: { type: "string" },
      osvEcosystem: { type: "string", description: "Solo para kind=manual, p. ej. Go, Maven, RubyGems, crates.io, Packagist, NuGet." },
    }, required: ["kind", "content"] },
  },
];

export async function runAssessmentAssistant(opts: {
  store: Store; assessmentId: string; question: string; requestedBy: string; fetchImpl?: FetchFn;
  policy?: PolicyEngine; gateway?: Gateway; modules?: Map<string, Module>; running?: RunRegistry;
}): Promise<AiResult> {
  const { store, assessmentId, question, requestedBy } = opts;
  const modules = opts.modules ?? builtinModules();
  const running: RunRegistry = opts.running ?? new Map();
  const fetchImpl = opts.fetchImpl ?? fetch;
  const secret = await store.getAiSecret();
  if (!secret) return { error: "AI_NOT_CONFIGURED", message: "El módulo de IA no está activado o no tiene una llave de API guardada. Ve a Configuración → Integración IA." };
  const rec = await store.getAssessment(assessmentId);
  if (!rec || !rec.signatureValid) return { error: "NO_ACTIVE_ASSESSMENT", message: "La evaluación no existe o su firma no es válida." };
  const findings = await store.listFindings(assessmentId);

  const findingsSummary = findings.length
    ? findings.map((f, i) => `${i + 1}. [${f.data.severity}/${f.data.triage}] ${f.data.title} — activo: ${f.data.asset} (CVSS ${f.data.cvssScore})`).join("\n")
    : "Sin hallazgos registrados todavía.";
  const system = `Eres el asistente de IA del módulo de Evaluaciones de "Ethical Security Copilot", dentro de la propia plataforma (no por MCP). ` +
    `Actúas con EXACTAMENTE los mismos permisos que el rol "agent" ya tiene por MCP: puedes validar alcance, lanzar módulos, detener todo con el kill switch, ` +
    `analizar cadena de suministro, registrar hallazgos y generar el informe — nunca abres ni cierras la evaluación ni apruebas un plan tú mismo; eso siempre lo decide un humano. ` +
    `"Cerrar el paso, no contraatacar": jamás propongas ni realices nada contra sistemas fuera del alcance autorizado. ` +
    `IMPORTANTE sobre scan_initiate: SOLO llámala cuando el humano te pida explícitamente en el chat que ejecutes ese módulo contra esos targets — nunca por iniciativa propia ni como parte de una exploración. ` +
    `En modo activo, o si el módulo cambia estado, la primera llamada no ejecuta nada: te devuelve un plan "pending_approval" que un humano (operator) debe aprobar aparte con un token de un solo uso; ` +
    `dile eso al humano y espera — solo vuelves a llamar a scan_initiate con planId y approvalToken si el humano te los entrega después de aprobar el plan por su cuenta. ` +
    `IMPORTANTE sobre scan_stop: úsala si el humano lo pide o ante cualquier señal de que algo salió mal; después de usarla, solo un authorizer humano puede liberar el kill switch. ` +
    `Separa siempre hechos observados (lo que se vio) de hipótesis de riesgo (lo que podría pasar, sin verificar). ` +
    `La severidad debe corresponder a la banda CVSS (info 0, baja 0,1–3,9, media 4–6,9, alta 7–8,9, crítica 9–10). Responde siempre en español, de forma clara y profesional.\n\n` +
    `Evaluación: ${rec.a.name} — organización: ${rec.a.authorizer.organization}\nEstado: ${rec.a.state}\nAlcance: ${rec.a.scope.map(s => s.value).join(", ")}\n\nHallazgos actuales:\n${findingsSummary}`;

  const policy = opts.policy ?? new PolicyEngine(store, { manifests: new Map([...modules].map(([k, m]) => [k, m.manifest])) });
  const gateway = opts.gateway ?? new Gateway(policy);

  const execTool = async (name: string, input: Record<string, unknown>): Promise<unknown> => {
    const actor = aiActor(requestedBy);
    if (name === "finding_create") {
      const r2 = await createFinding(store, { ...input, assessmentId, riskHypotheses: input.riskHypotheses ?? [], triage: "unverified" } as any, actor, "agent");
      return r2.ok ? { findingId: r2.findingId, stored: true } : { error: r2.error, message: r2.message };
    }
    if (name === "report_generate") {
      const format = input.format === "json" ? "json" : "markdown";
      const includeStates = Array.isArray(input.includeStates) && input.includeStates.length ? input.includeStates.map(String) : ["confirmed"];
      const r2 = await buildReport(store, { assessmentId, format: format as "markdown" | "json", includeStates, advance: false, actor, role: "agent" });
      return r2.ok ? { text: r2.text, findings: r2.findings } : { error: r2.error };
    }
    if (name === "scope_validate") {
      return policy.validateScope(assessmentId, input.target as Target, "agent");
    }
    if (name === "scan_initiate") {
      const r2 = await runScanInitiate({ store, policy, gateway, modules, running }, "agent", actor, {
        assessmentId, moduleId: String(input.moduleId ?? ""), mode: (input.mode as "passive" | "lab" | "active") ?? "passive",
        targets: (input.targets as Target[]) ?? [], params: input.params as Record<string, string | number | boolean> | undefined,
        planId: input.planId ? String(input.planId) : undefined, approvalToken: input.approvalToken ? String(input.approvalToken) : undefined,
      });
      return r2;
    }
    if (name === "scan_stop") {
      const r2 = await runScanStop({ store, running }, "agent", actor, input.allAssessments ? undefined : assessmentId, String(input.reason ?? "detenido desde el asistente de IA"));
      return r2;
    }
    if (name === "supply_chain_analyze") {
      const content = String(input.content ?? "").slice(0, MAX_MANIFEST_CHARS);
      const kind = (["npm_package_lock", "npm_package_json", "pip_requirements", "manual"].includes(String(input.kind)) ? input.kind : "manual") as "npm_package_lock" | "npm_package_json" | "pip_requirements" | "manual";
      let sbom; try { sbom = parseManifest(kind, content, input.osvEcosystem ? String(input.osvEcosystem) : undefined); } catch (e) { return { error: "MANIFEST_PARSE_ERROR", message: (e as Error).message }; }
      let results; try { results = await checkVulnerabilities(sbom); } catch (e) { return { error: "OSV_UPSTREAM_ERROR", message: (e as Error).message }; }
      const vulnerable = results.filter((r) => r.vulns.length);
      await store.audit({ actor, role: "agent", action: "supply_chain:analyzed", assessmentId, payload: { kind, deps: sbom.length, vulnerable: vulnerable.length, via: "ai-module" } });
      return { dependencies: sbom.length, vulnerable: vulnerable.length, results, note: "Es solo informativo: nada se registra como hallazgo automáticamente. Usa finding_create para los que decidas confirmar." };
    }
    return { error: `herramienta desconocida: ${name}` };
  };

  return runAssistant({ provider: secret.provider as Provider, apiKey: secret.apiKey, model: secret.model, baseUrl: secret.baseUrl, system, question, tools: ASSESSMENT_TOOLS, execTool, fetchImpl });
}

/* =========================== Chat de creación (antes de que exista el caso) ===========================
   Por diseño, ni incident_open ni assessment_create están en RolePermissions.agent: abrir un caso o crear
   una autorización lo decide siempre un humano, nunca la IA por su cuenta (ver RolePermissions en schemas.ts
   y los comentarios en server.ts). Este chat NO rompe esa regla: solo conversa para reunir los datos y arma
   un BORRADOR; quien efectivamente crea el caso es el humano, con un clic que llama a la misma ruta humana
   (POST /api/incidents o /api/assessments) que ya exige el rol correspondiente. Una vez creado, la propia
   conversación de este chat se traslada como historial al caso nuevo, para "continuar" sin cortes. */

const INCIDENT_DRAFT_TOOLS: ToolDef[] = [
  {
    name: "incident_draft",
    description: "Arma el BORRADOR del caso con los datos ya reunidos en la conversación. NO abre el caso. Llámala solo cuando el humano ya haya dado, y tú tengas claros: organización, quién reporta, correo de contacto y qué está pasando (resumen). No inventes ningún dato que falte.",
    input_schema: { type: "object", properties: {
      organization: { type: "string", minLength: 1, maxLength: 200 },
      contactName: { type: "string", minLength: 1, maxLength: 200 },
      contactEmail: { type: "string", description: "correo de contacto" },
      summary: { type: "string", minLength: 5, maxLength: 2000 },
      affectedAssets: { type: "array", items: { type: "string" }, description: "opcional: sitio web, correo, VPN…" },
      types: { type: "array", items: { type: "string", enum: ["phishing_email", "network_intrusion", "malware_ransomware", "ddos", "data_breach", "unauthorized_access", "web_attack", "other"] } },
      containmentTargets: { type: "array", items: { type: "string", enum: ["firewall", "nginx", "cloudflare"] } },
    }, required: ["organization", "contactName", "contactEmail", "summary"] },
  },
];

export async function runIncidentDraftAssistant(opts: { store: Store; question: string; requestedBy: string; fetchImpl?: FetchFn }): Promise<AiResult> {
  const { store, question } = opts;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const secret = await store.getAiSecret();
  if (!secret) return { error: "AI_NOT_CONFIGURED", message: "El módulo de IA no está activado o no tiene una llave de API guardada. Ve a Configuración → Integración IA." };
  const system = `Eres el asistente de IA que ayuda a abrir un caso en el módulo de Incidentes de "Ethical Security Copilot", ANTES de que el caso exista. ` +
    `Tu única función aquí es conversar en español para reunir los datos mínimos: organización, quién reporta, correo de contacto y qué está pasando (resumen breve). ` +
    `Pregunta por lo que falte, uno o pocos datos a la vez; nunca inventes ni supongas un dato que el humano no te haya dado. Si el humano menciona tipos de incidente o herramientas ` +
    `de bloqueo ya disponibles (firewall, nginx, Cloudflare), inclúyelos, pero son opcionales. Cuando ya tengas los datos mínimos, llama a incident_draft — eso NO abre el caso, solo ` +
    `arma el borrador para que el humano lo revise y lo confirme con un clic en la pantalla; tras eso, la conversación continúa ya dentro del caso.`;
  const execTool = async (name: string, input: Record<string, unknown>): Promise<unknown> => {
    if (name === "incident_draft") {
      const parsed = IncidentCreateIn.safeParse(input);
      if (!parsed.success) return { error: "VALIDATION", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) };
      return { draft: parsed.data };
    }
    return { error: `herramienta desconocida: ${name}` };
  };
  return runAssistant({ provider: secret.provider as Provider, apiKey: secret.apiKey, model: secret.model, baseUrl: secret.baseUrl, system, question, tools: INCIDENT_DRAFT_TOOLS, execTool, fetchImpl });
}

const ASSESSMENT_DRAFT_TOOLS: ToolDef[] = [
  {
    name: "assessment_draft",
    description: "Arma el BORRADOR de la evaluación con los datos ya reunidos en la conversación. NO crea nada. Llámala solo cuando el humano ya haya confirmado: nombre, datos del autorizador (organización, responsable, correo, contacto de emergencia), al menos un target de alcance, la ventana de fechas (inicio y fin, formato ISO 8601), los límites de ritmo (peticiones/s y paralelismo), al menos un modo permitido y al menos un módulo permitido. No inventes ningún dato.",
    input_schema: { type: "object", properties: {
      name: { type: "string", minLength: 3, maxLength: 120 },
      authorizer: { type: "object", properties: {
        organization: { type: "string" }, name: { type: "string" }, email: { type: "string" }, phone: { type: "string" }, emergencyContact: { type: "string", description: "a quién avisar si algo sale mal" },
      }, required: ["organization", "name", "email", "emergencyContact"] },
      allowedModes: { type: "array", minItems: 1, items: { type: "string", enum: ["passive", "lab", "active"] } },
      scope: { type: "array", minItems: 1, items: { type: "object", properties: {
        type: { type: "string", enum: ["cidr", "ip", "domain", "url", "device"] },
        value: { type: "string" }, includeSubdomains: { type: "boolean" }, pathPrefix: { type: "string" },
      }, required: ["type", "value"] } },
      exclusions: { type: "array", items: { type: "object", properties: {
        reason: { type: "string" }, technique: { type: "string" },
        target: { type: "object", properties: { type: { type: "string" }, value: { type: "string" } } },
      }, required: ["reason"] } },
      window: { type: "object", properties: {
        notBefore: { type: "string", description: "fecha-hora ISO 8601" }, notAfter: { type: "string", description: "fecha-hora ISO 8601" },
        allowedHours: { type: "object", properties: { from: { type: "string" }, to: { type: "string" }, tz: { type: "string" } } },
        maxRequestsPerSecond: { type: "number" }, maxConcurrency: { type: "number" }, maxTotalRequests: { type: "number" },
      }, required: ["notBefore", "notAfter", "maxRequestsPerSecond", "maxConcurrency"] },
      allowedModules: { type: "array", minItems: 1, items: { type: "string" } },
      testAccounts: { type: "array", items: { type: "object", properties: { label: { type: "string" }, secretRef: { type: "string" } } } },
      authorizationDocRef: { type: "string" },
    }, required: ["name", "authorizer", "allowedModes", "scope", "window", "allowedModules"] },
  },
];

export async function runAssessmentDraftAssistant(opts: { store: Store; question: string; requestedBy: string; fetchImpl?: FetchFn; modules?: Map<string, Module> }): Promise<AiResult> {
  const { store, question } = opts;
  const modules = opts.modules ?? builtinModules();
  const fetchImpl = opts.fetchImpl ?? fetch;
  const secret = await store.getAiSecret();
  if (!secret) return { error: "AI_NOT_CONFIGURED", message: "El módulo de IA no está activado o no tiene una llave de API guardada. Ve a Configuración → Integración IA." };
  const system = `Eres el asistente de IA que ayuda a crear una evaluación (autorización firmada) en "Ethical Security Copilot", ANTES de que exista. ` +
    `Conversa en español para reunir: nombre de la evaluación; datos del autorizador humano (organización, responsable, correo, contacto de emergencia); ` +
    `el alcance (al menos un target: IP, CIDR, dominio, URL o dispositivo — todos dentro de lo que el humano está autorizado a probar); la ventana (fecha de inicio y fin); ` +
    `los límites de ritmo (peticiones por segundo y paralelismo); al menos un modo permitido (pasivo, laboratorio o activo); y al menos un módulo permitido. ` +
    `Módulos disponibles en esta plataforma: ${[...modules.keys()].join(", ")}. Pregunta por lo que falte, de a poco; nunca inventes ni supongas un dato. ` +
    `Cuando tengas lo mínimo confirmado por el humano, llama a assessment_draft — eso NO crea nada, solo arma el borrador para que el humano lo revise y lo confirme con un clic; ` +
    `tras eso, un humano sigue teniendo que validar el alcance, planificar y aprobar antes de que corra cualquier módulo.`;
  const execTool = async (name: string, input: Record<string, unknown>): Promise<unknown> => {
    if (name === "assessment_draft") {
      const parsed = AssessmentCreateIn.safeParse(input);
      if (!parsed.success) return { error: "VALIDATION", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) };
      return { draft: parsed.data };
    }
    return { error: `herramienta desconocida: ${name}` };
  };
  return runAssistant({ provider: secret.provider as Provider, apiKey: secret.apiKey, model: secret.model, baseUrl: secret.baseUrl, system, question, tools: ASSESSMENT_DRAFT_TOOLS, execTool, fetchImpl });
}

