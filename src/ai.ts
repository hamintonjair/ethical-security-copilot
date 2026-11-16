// Módulo de IA dentro de la propia plataforma (alternativa a MCP): la organización pone su propia
// llave de Anthropic en Configuración. Cuando el módulo actúa, lo hace con EXACTAMENTE los mismos
// permisos que RolePermissions.agent ya tiene por MCP — nunca abre ni cierra un caso, nunca aprueba
// un plan, nunca toca ninguna red por sí solo.
import type { Store } from "./store.js";
import { analyzeLog, analyzeEmailHeaders, containmentRules, buildIncidentReport, suggestIncidentTypes, TYPE_GUIDANCE, MAX_EVIDENCE_CHARS } from "./incident.js";
import { createFinding } from "./findings.js";
import { buildReport } from "./report.js";
import { redact } from "./redact.js";

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

export async function testApiKey(provider: Provider, apiKey: string, baseUrl: string | undefined, fetchImpl: FetchFn = fetch): Promise<{ ok: true } | { ok: false; message: string }> {
  try { await listModels(provider, apiKey, baseUrl, fetchImpl); return { ok: true }; }
  catch (e) { return { ok: false, message: (e as Error).message || "No se pudo contactar a la API." }; }
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
    const res = await opts.fetchImpl(url, {
      method: "POST",
      headers: { "x-api-key": opts.apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: opts.model, max_tokens: MAX_TOKENS, system: opts.system, messages, tools: opts.tools }),
    });
    if (!res.ok) return { error: "AI_UPSTREAM_ERROR", message: `Anthropic respondió ${res.status}.` };
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
    const res = await opts.fetchImpl(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${opts.apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({ model: opts.model, max_tokens: MAX_TOKENS, messages, tools, tool_choice: "auto" }),
    });
    if (!res.ok) return { error: "AI_UPSTREAM_ERROR", message: `La API respondió ${res.status}.` };
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
  const tools = [{ functionDeclarations: opts.tools.map((t) => ({ name: t.name, description: t.description, parameters: t.input_schema })) }];
  for (let i = 0; i < MAX_ITERS; i++) {
    const res = await opts.fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ system_instruction: { parts: [{ text: opts.system }] }, contents, tools, generationConfig: { maxOutputTokens: MAX_TOKENS } }),
    });
    if (!res.ok) return { error: "AI_UPSTREAM_ERROR", message: `Gemini respondió ${res.status}.` };
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
    description: "Analiza texto de evidencia (log o cabeceras de correo) que el humano incluyó en su mensaje y lo guarda como evidencia del caso. Solo lee el texto dado; no se conecta a ninguna red.",
    input_schema: { type: "object", properties: {
      kind: { type: "string", enum: ["log", "email_headers", "other"] },
      description: { type: "string", maxLength: 300 },
      content: { type: "string", maxLength: MAX_EVIDENCE_CHARS },
    }, required: ["kind", "description", "content"] },
  },
  {
    name: "incident_types_set",
    description: "Marca (o reemplaza) los tipos de incidente del caso. SOLO se debe llamar después de que el humano haya confirmado explícitamente en el chat cuáles tipos quiere marcar — nunca a partir de una sugerencia sin que el humano la haya aprobado.",
    input_schema: { type: "object", properties: {
      types: { type: "array", items: { type: "string", enum: ["phishing_email", "network_intrusion", "malware_ransomware", "ddos", "data_breach", "unauthorized_access", "web_attack", "other"] } },
    }, required: ["types"] },
  },
  {
    name: "incident_targets_set",
    description: "Marca (o reemplaza) qué herramientas de bloqueo (firewall/iptables-ufw, nginx, Cloudflare) tiene disponibles el equipo para este caso. SOLO se debe llamar después de que el humano lo confirme explícitamente en el chat.",
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
  store: Store; incidentId: string; question: string; requestedBy: string; fetchImpl?: FetchFn;
}): Promise<AiResult> {
  const { store, incidentId, question, requestedBy } = opts;
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
    `Ámbito estricto: SOLO analizas evidencia que el humano te da y generas texto para que ÉL decida y aplique — nunca te conectas a ninguna red, nunca ejecutas nada, ` +
    `nunca abres ni cierras el caso (eso solo lo hace un humano). "Cerrar el paso, no contraatacar": jamás propongas ni describas atacar, acceder o dañar sistemas de terceros, ` +
    `ni siquiera los del presunto atacante. Responde siempre en español, de forma clara y concreta. Usa las herramientas disponibles cuando el humano pida contención o un informe. ` +
    `IMPORTANTE sobre incident_types_set: cuando incident_evidence_analyze te devuelva "suggestedTypes", son solo sugerencias — pregúntale primero al humano cuáles quiere marcar y llama a incident_types_set solo con los que él confirme, nunca con todos automáticamente. ` +
    `IMPORTANTE sobre incident_targets_set: úsala solo cuando el humano te diga explícitamente qué herramientas de bloqueo (firewall, nginx, Cloudflare) tiene disponibles.\n\n` +
    `Caso: ${rec.incident.organization} — ${rec.incident.summary}\nEstado: ${rec.incident.status}\nTipos ya marcados: ${rec.incident.types?.length ? rec.incident.types.join(", ") : "ninguno todavía"}\n` +
    `Herramientas de bloqueo ya marcadas: ${rec.incident.containmentTargets?.length ? rec.incident.containmentTargets.join(", ") : "ninguna todavía (se generará para todas por defecto)"}\n\n${evidenceSummary}`;

  const execTool = async (name: string, input: Record<string, unknown>): Promise<unknown> => {
    const actor = aiActor(requestedBy);
    if (name === "incident_evidence_analyze") {
      const content = String(input.content ?? "").slice(0, MAX_EVIDENCE_CHARS);
      const kind = (["log", "email_headers", "other"].includes(String(input.kind)) ? input.kind : "other") as "log" | "email_headers" | "other";
      const r = kind === "email_headers" ? analyzeEmailHeaders(content) : analyzeLog(content);
      const saved = await store.addIncidentEvidence(incidentId, { kind, description: String(input.description ?? "evidencia aportada en el chat de IA"), redactedContent: redact(content, 8000), iocs: r.iocs }, actor);
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

  return runAssistant({ provider: secret.provider as Provider, apiKey: secret.apiKey, model: secret.model, baseUrl: secret.baseUrl, system, question, tools: INCIDENT_TOOLS, execTool, fetchImpl });
}

/* =========================== Evaluaciones ===========================
   Deliberadamente no incluye scan_initiate: lanzar módulos contra sistemas reales sigue pasando
   siempre por la aprobación humana de un plan, por MCP o por la consola — nunca por este asistente. */

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
];

export async function runAssessmentAssistant(opts: {
  store: Store; assessmentId: string; question: string; requestedBy: string; fetchImpl?: FetchFn;
}): Promise<AiResult> {
  const { store, assessmentId, question, requestedBy } = opts;
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
    `Ámbito estricto: solo puedes registrar hallazgos nuevos y generar el informe — NUNCA puedes lanzar un módulo contra una red real ni aprobar ningún plan; ` +
    `eso siempre requiere la aprobación de un humano por la consola o por MCP. Separa siempre hechos observados (lo que se vio) de hipótesis de riesgo (lo que podría pasar, sin verificar). ` +
    `La severidad debe corresponder a la banda CVSS (info 0, baja 0,1–3,9, media 4–6,9, alta 7–8,9, crítica 9–10). Responde siempre en español, de forma clara y profesional.\n\n` +
    `Evaluación: ${rec.a.name} — organización: ${rec.a.authorizer.organization}\nEstado: ${rec.a.state}\nAlcance: ${rec.a.scope.map(s => s.value).join(", ")}\n\nHallazgos actuales:\n${findingsSummary}`;

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
    return { error: `herramienta desconocida: ${name}` };
  };

  return runAssistant({ provider: secret.provider as Provider, apiKey: secret.apiKey, model: secret.model, baseUrl: secret.baseUrl, system, question, tools: ASSESSMENT_TOOLS, execTool, fetchImpl });
}
