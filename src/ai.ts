// Módulo de IA dentro de la propia plataforma (alternativa a MCP): la organización pone su propia
// llave de Anthropic en Configuración. Cuando el módulo actúa sobre un incidente, lo hace con
// EXACTAMENTE los mismos permisos que RolePermissions.agent ya tiene: analizar evidencia, generar
// reglas de contención e informes — nunca abre ni cierra un incidente, nunca toca ninguna red.
import type { Store } from "./store.js";
import { analyzeLog, analyzeEmailHeaders, containmentRules, buildIncidentReport, MAX_EVIDENCE_CHARS } from "./incident.js";
import { redact } from "./redact.js";

const API_URL = "https://api.anthropic.com/v1/messages";
const MAX_ITERS = 4;
const MAX_TOKENS = 1500;

export type FetchFn = typeof fetch;

export async function testAnthropicKey(apiKey: string, model: string, fetchImpl: FetchFn = fetch): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    const res = await fetchImpl(API_URL, {
      method: "POST",
      headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model, max_tokens: 8, messages: [{ role: "user", content: "di 'ok'" }] }),
    });
    if (res.ok) return { ok: true };
    const body = await res.text();
    return { ok: false, message: res.status === 401 ? "La llave de API no es válida." : `Anthropic respondió ${res.status}: ${body.slice(0, 200)}` };
  } catch (e) { return { ok: false, message: `No se pudo contactar a Anthropic: ${(e as Error).message}` }; }
}

type ToolUseBlock = { type: "tool_use"; id: string; name: string; input: Record<string, unknown> };
type TextBlock = { type: "text"; text: string };

const TOOLS = [
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

export interface AiAction { tool: string; input: Record<string, unknown>; result: unknown }

/** El actor que queda en la auditoría deja explícito que fue el módulo de IA, a petición de qué humano. */
const aiActor = (human: string) => `ia-modulo:${human}`;

export async function runIncidentAssistant(opts: {
  store: Store; incidentId: string; question: string; requestedBy: string; fetchImpl?: FetchFn;
}): Promise<{ answer: string; actions: AiAction[] } | { error: string; message: string }> {
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
    `ni siquiera los del presunto atacante. Responde siempre en español, de forma clara y concreta. Usa las herramientas disponibles cuando el humano pida contención o un informe.\n\n` +
    `Caso: ${rec.incident.organization} — ${rec.incident.summary}\nEstado: ${rec.incident.status}\n\n${evidenceSummary}`;

  const messages: Array<{ role: "user" | "assistant"; content: unknown }> = [{ role: "user", content: question.slice(0, 4000) }];
  const actions: AiAction[] = [];

  for (let i = 0; i < MAX_ITERS; i++) {
    const res = await fetchImpl(API_URL, {
      method: "POST",
      headers: { "x-api-key": secret.apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: secret.model, max_tokens: MAX_TOKENS, system, messages, tools: TOOLS }),
    });
    if (!res.ok) return { error: "AI_UPSTREAM_ERROR", message: `Anthropic respondió ${res.status}.` };
    const data = await res.json() as { content: Array<TextBlock | ToolUseBlock>; stop_reason: string };
    const toolUses = data.content.filter((b): b is ToolUseBlock => b.type === "tool_use");
    const text = data.content.filter((b): b is TextBlock => b.type === "text").map(b => b.text).join("\n").trim();

    if (!toolUses.length || data.stop_reason !== "tool_use") return { answer: text || "(sin respuesta)", actions };

    messages.push({ role: "assistant", content: data.content });
    const toolResults: Array<{ type: "tool_result"; tool_use_id: string; content: string }> = [];
    for (const tu of toolUses) {
      const result = await execTool(store, incidentId, requestedBy, tu.name, tu.input);
      actions.push({ tool: tu.name, input: tu.input, result });
      toolResults.push({ type: "tool_result", tool_use_id: tu.id, content: JSON.stringify(result).slice(0, 8000) });
    }
    messages.push({ role: "user", content: toolResults });
  }
  return { answer: "Se alcanzó el límite de pasos con las herramientas; revisa las acciones ya generadas abajo.", actions };
}

async function execTool(store: Store, incidentId: string, requestedBy: string, name: string, input: Record<string, unknown>): Promise<unknown> {
  const actor = aiActor(requestedBy);
  if (name === "incident_evidence_analyze") {
    const content = String(input.content ?? "").slice(0, MAX_EVIDENCE_CHARS);
    const kind = (["log", "email_headers", "other"].includes(String(input.kind)) ? input.kind : "other") as "log" | "email_headers" | "other";
    const r = kind === "email_headers" ? analyzeEmailHeaders(content) : analyzeLog(content);
    const saved = await store.addIncidentEvidence(incidentId, { kind, description: String(input.description ?? "evidencia aportada en el chat de IA"), redactedContent: redact(content, 8000), iocs: r.iocs }, actor);
    if (saved === null || saved === "CLOSED") return { error: "no se pudo guardar la evidencia" };
    return { evidenceId: saved.id, facts: r.facts, patterns: r.patterns, iocs: r.iocs };
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
    const rec = await store.getIncident(incidentId);
    if (!rec) return { error: "incidente no encontrado" };
    const format = input.format === "json" ? "json" : "markdown";
    await store.audit({ actor, role: "agent", action: "incident:report", assessmentId: incidentId, payload: { format, via: "ai-module" } });
    return { text: buildIncidentReport(rec.incident, rec.evidence, format), format };
  }
  return { error: `herramienta desconocida: ${name}` };
}
