import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { Store } from "../src/store.js";
import { Auth } from "../src/web/auth.js";
import { createHttpApp } from "../src/http.js";
import { encryptSecret, decryptSecret } from "../src/crypto.js";
import { runIncidentAssistant, runAssessmentAssistant, runIncidentDraftAssistant, runAssessmentDraftAssistant, listModels, testApiKey } from "../src/ai.js";

const assessmentInput = (over: Record<string, unknown> = {}) => ({
  name: "Evaluación de prueba IA",
  authorizer: { organization: "Org Demo", name: "Ana Responsable", email: "ana@demo.test", emergencyContact: "+57 300 000 0000" },
  allowedModes: ["passive", "lab", "active"],
  scope: [{ type: "cidr", value: "203.0.113.0/24" }],
  exclusions: [],
  window: { notBefore: "2026-11-01T00:00:00Z", notAfter: "2026-12-01T00:00:00Z", maxRequestsPerSecond: 5, maxConcurrency: 2 },
  allowedModules: ["port_check"],
  ...over,
});

test("crypto: encryptSecret/decryptSecret van y vuelven; detecta manipulación", () => {
  const key = Buffer.alloc(32, 7);
  const enc = encryptSecret("sk-ant-super-secreta", key);
  assert.equal(decryptSecret(enc, key), "sk-ant-super-secreta");
  const tampered = enc.slice(0, -2) + "ff";
  assert.throws(() => decryptSecret(tampered, key));
});

const KEY = Buffer.from("ai-signing-key-ai-signing-key-123456");
const TOKEN = "a".repeat(16) + "0123456789abcdef0123456789abcdef";
const PW = "frase-larga-de-prueba-ai-1";
let app: http.Server, store: Store, auth: Auth, base = "", origin = "";

class Client {
  cookie = ""; csrf = "";
  async call(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.cookie) headers.Cookie = this.cookie;
    if (method !== "GET") { headers.Origin = origin; if (this.csrf) headers["X-CSRF-Token"] = this.csrf; }
    const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get("set-cookie");
    if (sc) this.cookie = sc.split(";")[0];
    const text = await r.text();
    return { status: r.status, json: text ? JSON.parse(text) : null };
  }
  async login(username: string, password = PW) {
    const r = await this.call("POST", "/api/login", { username, password });
    if (r.status === 200) this.csrf = r.json.csrf;
    return r;
  }
}
const as = async (u: string) => { const c = new Client(); const r = await c.login(u); assert.equal(r.status, 200, JSON.stringify(r.json)); return c; };

before(async () => {
  store = await Store.open("memory", KEY);
  auth = new Auth(store);
  const by = { actor: "test", role: "authorizer" as const };
  for (const [u, role] of [["ana", "authorizer"], ["omar", "operator"], ["alba", "analyst"]] as const)
    assert.ok((await auth.createUser({ username: u, role, password: PW, mustChange: false }, by)).ok);
  app = createHttpApp({ store, token: TOKEN, allowedHosts: ["localhost", "127.0.0.1"] });
  await new Promise<void>(r => app.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`; origin = base;
});
after(async () => { app.closeAllConnections(); app.close(); await store.close(); });

test("IA: la configuración solo la toca un authorizer; la llave nunca se devuelve", async () => {
  const ana = await as("ana"), omar = await as("omar");
  const before1 = await ana.call("GET", "/api/ai/config");
  assert.equal(before1.status, 200); assert.equal(before1.json.enabled, false); assert.equal(before1.json.hasKey, false);

  const denied = await omar.call("POST", "/api/ai/config", { enabled: true, model: "claude-sonnet-5-5", apiKey: "sk-ant-0123456789" });
  assert.equal(denied.status, 403);

  const set = await ana.call("POST", "/api/ai/config", { enabled: true, model: "claude-sonnet-5-5", apiKey: "sk-ant-0123456789" });
  assert.equal(set.status, 200);
  assert.equal(set.json.enabled, true);
  assert.equal(set.json.hasKey, true);
  assert.equal(set.json.keyLast4, "6789");
  assert.ok(!("apiKey" in set.json) && !JSON.stringify(set.json).includes("sk-ant-"));

  // omitir apiKey conserva la ya guardada
  const keepKey = await ana.call("POST", "/api/ai/config", { enabled: false, model: "otro-modelo" });
  assert.equal(keepKey.status, 200);
  assert.equal(keepKey.json.hasKey, true);
  assert.equal(keepKey.json.model, "otro-modelo");

  const secret = await store.getAiSecret(); // sigue deshabilitado (enabled:false) => null
  assert.equal(secret, null);
  await store.setAiConfig({ enabled: true, provider: "anthropic", model: "otro-modelo" }, "ana");
  const secret2 = await store.getAiSecret();
  assert.equal(secret2?.apiKey, "sk-ant-0123456789");
});

test("IA: ai-assist exige que el módulo esté configurado", async () => {
  const freshStore = await Store.open("memory", KEY);
  const freshAuth = new Auth(freshStore);
  await freshAuth.createUser({ username: "op2", role: "operator", password: PW, mustChange: false }, { actor: "t", role: "authorizer" });
  const inc = await freshStore.createIncident({ organization: "Org", contactName: "A", contactEmail: "a@demo.test", summary: "algo pasa", affectedAssets: [] }, "op2");
  const r = await runIncidentAssistant({ store: freshStore, incidentId: inc.id, question: "¿qué hago?", requestedBy: "op2" });
  assert.ok("error" in r && r.error === "AI_NOT_CONFIGURED");
  await freshStore.close();
});

test("IA: el asistente ejecuta solo herramientas ya permitidas para el rol 'agent' y deja todo en la auditoría", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "anthropic", model: "claude-test", apiKey: "sk-ant-test-key" }, "ana");
  const inc = await freshStore.createIncident({ organization: "Org", contactName: "A", contactEmail: "a@demo.test", summary: "ataque en curso", affectedAssets: [] }, "ana");
  await freshStore.addIncidentEvidence(inc.id, { kind: "log", description: "log sospechoso", redactedContent: "GET /etc/passwd", iocs: { ips: ["203.0.113.9"], domains: [], urls: [], hashes: [], emails: [] } }, "ana");

  let call = 0;
  const fetchImpl = (async (_url: any, _opts: any) => {
    call++;
    if (call === 1) {
      return new Response(JSON.stringify({ stop_reason: "tool_use", content: [
        { type: "text", text: "Voy a generar el plan de contención." },
        { type: "tool_use", id: "t1", name: "incident_contain_plan", input: { ips: ["203.0.113.9"], domains: [], targets: "all" } },
      ] }), { status: 200 });
    }
    return new Response(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "Listo: bloquea esa IP en tu firewall." }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runIncidentAssistant({ store: freshStore, incidentId: inc.id, question: "genera el plan de contención", requestedBy: "omar", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.match(r.answer, /bloquea/);
  assert.equal(r.actions.length, 1);
  assert.equal(r.actions[0].tool, "incident_contain_plan");
  assert.ok((r.actions[0].result as any).rules["iptables.sh"].includes("203.0.113.9"));

  const audit = await freshStore.listAudit(5, 0);
  const entry = audit.rows.find(a => a.action === "incident:contain_plan");
  assert.ok(entry);
  assert.equal(entry!.actor, "ia-modulo:omar");
  assert.equal(entry!.role, "agent");
  await freshStore.close();
});

test("IA en Evaluaciones: puede registrar un hallazgo y redactar un informe, nunca lanza un módulo", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "anthropic", model: "claude-test", apiKey: "sk-ant-test-key" }, "ana");
  const a = await freshStore.createAssessment(assessmentInput(), "ana");
  for (const s of ["scope_validated", "planned", "approved", "executing"] as const) await freshStore.transition(a.id, s, "ana", "authorizer");

  let call = 0;
  const fetchImpl = (async () => {
    call++;
    if (call === 1) {
      return new Response(JSON.stringify({ stop_reason: "tool_use", content: [
        { type: "text", text: "Registro el hallazgo que describiste." },
        { type: "tool_use", id: "t1", name: "finding_create", input: {
          title: "Cabeceras de seguridad ausentes", asset: "203.0.113.10", severity: "medium",
          cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", cvssScore: 5.3, confidence: "high",
          observedFacts: ["Falta Content-Security-Policy", "Falta X-Frame-Options"], riskHypotheses: ["Clickjacking"],
          evidence: [{ description: "Respuesta HTTP", redactedContent: "HTTP/1.1 200 OK", reproSteps: ["curl -I https://203.0.113.10"] }],
          businessImpact: "Facilita ataques del lado del cliente.", recommendation: "Agregar las cabeceras faltantes.",
        } },
      ] }), { status: 200 });
    }
    return new Response(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "Listo, ya quedó registrado." }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runAssessmentAssistant({ store: freshStore, assessmentId: a.id, question: "registra este hallazgo", requestedBy: "omar", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.equal(r.actions.length, 1);
  assert.ok((r.actions[0].result as any).findingId);

  const findings = await freshStore.listFindings(a.id);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].data.severity, "medium");

  const audit = await freshStore.listAudit(5, 0);
  const entry = audit.rows.find((x) => x.action === "finding_create");
  assert.equal(entry?.actor, "ia-modulo:omar");
  assert.equal(entry?.role, "agent");

  await freshStore.close();
});

test("IA en Evaluaciones: valida alcance y lanza un módulo pasivo directo, solo cuando el humano lo pide explícitamente", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "anthropic", model: "claude-test", apiKey: "sk-ant-test-key" }, "ana");
  const a = await freshStore.createAssessment(assessmentInput({ allowedModules: ["config_audit"] }), "ana");
  for (const s of ["scope_validated", "planned", "approved"] as const) await freshStore.transition(a.id, s, "ana", "authorizer");

  let call = 0;
  const fetchImpl = (async () => {
    call++;
    if (call === 1) {
      return new Response(JSON.stringify({ stop_reason: "tool_use", content: [
        { type: "text", text: "Primero confirmo que el target está en el alcance." },
        { type: "tool_use", id: "t1", name: "scope_validate", input: { target: { type: "cidr", value: "203.0.113.0/24" } } },
      ] }), { status: 200 });
    }
    if (call === 2) {
      return new Response(JSON.stringify({ stop_reason: "tool_use", content: [
        { type: "text", text: "Está en el alcance; lanzo el análisis pasivo que pediste." },
        { type: "tool_use", id: "t2", name: "scan_initiate", input: { moduleId: "config_audit", mode: "passive", targets: [{ type: "ip", value: "203.0.113.5" }], params: { content: "server_tokens on" } } },
      ] }), { status: 200 });
    }
    return new Response(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "Listo: encontré configuración insegura." }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runAssessmentAssistant({ store: freshStore, assessmentId: a.id, question: "ejecuta config_audit sobre 203.0.113.5 con ese contenido", requestedBy: "omar", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.equal(r.actions.length, 2);
  assert.equal(r.actions[0].tool, "scope_validate");
  assert.equal((r.actions[0].result as any).authorized, true);
  assert.equal(r.actions[1].tool, "scan_initiate");
  assert.equal((r.actions[1].result as any).status, "completed");
  assert.ok((r.actions[1].result as any).facts.some((f: string) => /revela su versión/.test(f)));

  const audit = await freshStore.listAudit(10, 0);
  const entry = audit.rows.find((x) => x.action === "scan:finished");
  assert.equal(entry?.actor, "ia-modulo:omar");
  assert.equal(entry?.role, "agent");
  await freshStore.close();
});

test("IA en Evaluaciones: en modo activo (o módulo que cambia estado) no ejecuta nada hasta que un humano apruebe el plan", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "anthropic", model: "claude-test", apiKey: "sk-ant-test-key" }, "ana");
  const a = await freshStore.createAssessment(assessmentInput({ allowedModules: ["tcp_port_check"] }), "ana");
  for (const s of ["scope_validated", "planned", "approved"] as const) await freshStore.transition(a.id, s, "ana", "authorizer");

  let call = 0;
  const fetchImpl = (async () => {
    call++;
    if (call === 1) {
      return new Response(JSON.stringify({ stop_reason: "tool_use", content: [
        { type: "text", text: "Lanzo el escaneo activo que pediste." },
        { type: "tool_use", id: "t1", name: "scan_initiate", input: { moduleId: "tcp_port_check", mode: "active", targets: [{ type: "ip", value: "203.0.113.5" }], params: { ports: "80" } } },
      ] }), { status: 200 });
    }
    return new Response(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "Queda un plan pendiente de aprobación humana; avísame cuando lo apruebes." }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runAssessmentAssistant({ store: freshStore, assessmentId: a.id, question: "lanza un escaneo activo de puertos contra 203.0.113.5", requestedBy: "omar", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.equal(r.actions.length, 1);
  const result = r.actions[0].result as any;
  assert.equal(result.status, "pending_approval");
  assert.ok(result.planId);

  const plans = await freshStore.listPlans();
  assert.equal(plans.length, 1);
  assert.equal(plans[0].status, "pending_approval");
  await freshStore.close();
});

test("IA en Evaluaciones: scan_stop activa el kill switch y lo deja registrado como actor del módulo de IA", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "anthropic", model: "claude-test", apiKey: "sk-ant-test-key" }, "ana");
  const a = await freshStore.createAssessment(assessmentInput(), "ana");

  let call = 0;
  const fetchImpl = (async () => {
    call++;
    if (call === 1) {
      return new Response(JSON.stringify({ stop_reason: "tool_use", content: [
        { type: "text", text: "Detengo todo de inmediato." },
        { type: "tool_use", id: "t1", name: "scan_stop", input: { reason: "el humano pidió detener todo ya" } },
      ] }), { status: 200 });
    }
    return new Response(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "Listo, todo detenido." }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runAssessmentAssistant({ store: freshStore, assessmentId: a.id, question: "detén todo ahora mismo", requestedBy: "ana", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.equal(r.actions.length, 1);
  assert.equal((r.actions[0].result as any).killSwitch, "active");
  const info = await freshStore.killSwitchInfo();
  assert.equal(info.active, true);
  assert.equal(info.reason, "el humano pidió detener todo ya");
  await freshStore.close();
});

/* =========================== Multi-proveedor: no tiene que ser Anthropic =========================== */

test("listModels: Anthropic — llama a /models con x-api-key y devuelve id+label", async () => {
  const fetchImpl = (async (url: any, opts: any) => {
    assert.match(String(url), /\/v1\/models\?limit=100$/);
    assert.equal(opts.headers["x-api-key"], "sk-ant-x");
    return new Response(JSON.stringify({ data: [{ id: "claude-sonnet-5-5", display_name: "Claude Sonnet 5.5" }] }), { status: 200 });
  }) as typeof fetch;
  const models = await listModels("anthropic", "sk-ant-x", undefined, fetchImpl);
  assert.deepEqual(models, [{ id: "claude-sonnet-5-5", label: "Claude Sonnet 5.5" }]);
});

test("listModels: OpenAI (o compatible) — usa Authorization Bearer y una URL base propia", async () => {
  const fetchImpl = (async (url: any, opts: any) => {
    assert.equal(String(url), "https://mi-proxy.example.com/v1/models");
    assert.equal(opts.headers.Authorization, "Bearer sk-oa-x");
    return new Response(JSON.stringify({ data: [{ id: "gpt-4o-mini" }, { id: "gpt-4o" }] }), { status: 200 });
  }) as typeof fetch;
  const models = await listModels("openai", "sk-oa-x", "https://mi-proxy.example.com/v1", fetchImpl);
  assert.deepEqual(models, [{ id: "gpt-4o", label: "gpt-4o" }, { id: "gpt-4o-mini", label: "gpt-4o-mini" }]);
});

test("listModels: Gemini — pasa la llave como query param y filtra por generateContent", async () => {
  const fetchImpl = (async (url: any) => {
    assert.match(String(url), /generativelanguage\.googleapis\.com\/v1beta\/models\?key=sk-gem-x/);
    return new Response(JSON.stringify({ models: [
      { name: "models/gemini-2.5-pro", displayName: "Gemini 2.5 Pro", supportedGenerationMethods: ["generateContent"] },
      { name: "models/embedding-001", displayName: "Embedding", supportedGenerationMethods: ["embedContent"] },
    ] }), { status: 200 });
  }) as typeof fetch;
  const models = await listModels("gemini", "sk-gem-x", undefined, fetchImpl);
  assert.deepEqual(models, [{ id: "gemini-2.5-pro", label: "Gemini 2.5 Pro" }]);
});

test("testApiKey: una llave inválida (401) se reporta como tal, sin importar el proveedor", async () => {
  const fetchImpl = (async () => new Response("no", { status: 401 })) as typeof fetch;
  const r = await testApiKey("openai", "sk-mala", undefined, fetchImpl);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.message, /no es válida/);
});

test("módulo de IA (Incidentes) también funciona con un proveedor compatible con OpenAI, no solo Anthropic", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "openai", model: "gpt-4o-mini", baseUrl: "https://mi-proxy.example.com/v1", apiKey: "sk-oa-test" }, "ana");
  const inc = await freshStore.createIncident({ organization: "Org", contactName: "A", contactEmail: "a@demo.test", summary: "ataque en curso", affectedAssets: [] }, "ana");

  let call = 0;
  const fetchImpl = (async (url: any, opts: any) => {
    call++;
    assert.equal(String(url), "https://mi-proxy.example.com/v1/chat/completions");
    assert.equal(opts.headers.Authorization, "Bearer sk-oa-test");
    if (call === 1) {
      return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: null,
        tool_calls: [{ id: "c1", function: { name: "incident_contain_plan", arguments: JSON.stringify({ ips: ["203.0.113.9"], domains: [], targets: "all" }) } }] } }] }), { status: 200 });
    }
    return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "Listo: bloquea esa IP." } }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runIncidentAssistant({ store: freshStore, incidentId: inc.id, question: "genera el plan de contención", requestedBy: "omar", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.match(r.answer, /bloquea/);
  assert.equal(r.actions.length, 1);
  assert.equal(r.actions[0].tool, "incident_contain_plan");
  await freshStore.close();
});

test("módulo de IA (Incidentes) también funciona con Gemini", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "gemini", model: "gemini-2.5-pro", apiKey: "sk-gem-test" }, "ana");
  const inc = await freshStore.createIncident({ organization: "Org", contactName: "A", contactEmail: "a@demo.test", summary: "ataque en curso", affectedAssets: [] }, "ana");

  let call = 0;
  const fetchImpl = (async (url: any) => {
    call++;
    assert.match(String(url), /:generateContent\?key=sk-gem-test$/);
    if (call === 1) {
      return new Response(JSON.stringify({ candidates: [{ content: { parts: [
        { functionCall: { name: "incident_contain_plan", args: { ips: ["203.0.113.9"], domains: [], targets: "all" } } },
      ] } }] }), { status: 200 });
    }
    return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: "Listo: bloquea esa IP." }] } }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runIncidentAssistant({ store: freshStore, incidentId: inc.id, question: "genera el plan de contención", requestedBy: "omar", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.match(r.answer, /bloquea/);
  assert.equal(r.actions.length, 1);
  assert.equal(r.actions[0].tool, "incident_contain_plan");
  await freshStore.close();
});

/* ---------- Chat de creación: solo arma un borrador, nunca abre el caso ni crea la evaluación ---------- */

test("IA (chat de creación de incidente): arma el borrador pero no abre ningún caso", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "anthropic", model: "claude-test", apiKey: "sk-ant-test-key" }, "ana");

  let call = 0;
  const fetchImpl = (async () => {
    call++;
    if (call === 1) {
      return new Response(JSON.stringify({ stop_reason: "tool_use", content: [
        { type: "text", text: "Armo el borrador." },
        { type: "tool_use", id: "t1", name: "incident_draft", input: {
          organization: "Jojama", contactName: "Hamilton", contactEmail: "ham@jojama.test",
          summary: "Correo de phishing bancario recibido.",
        } },
      ] }), { status: 200 });
    }
    return new Response(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "Revisa el borrador y confírmalo." }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runIncidentDraftAssistant({ store: freshStore, question: "Jojama recibió un correo de phishing bancario, reporta Hamilton (ham@jojama.test)", requestedBy: "omar", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.match(r.answer, /confírmalo/);
  assert.equal(r.actions.length, 1);
  assert.equal(r.actions[0].tool, "incident_draft");
  assert.equal((r.actions[0].result as any).draft.organization, "Jojama");
  assert.equal((await freshStore.listIncidents()).length, 0); // nada se abrió solo
  await freshStore.close();
});

test("IA (chat de creación de incidente): sin llave configurada, responde AI_NOT_CONFIGURED", async () => {
  const freshStore = await Store.open("memory", KEY);
  const r = await runIncidentDraftAssistant({ store: freshStore, question: "abramos un caso", requestedBy: "omar" });
  assert.ok("error" in r && r.error === "AI_NOT_CONFIGURED");
  await freshStore.close();
});

test("IA (chat de creación de evaluación): arma el borrador pero no crea nada", async () => {
  const freshStore = await Store.open("memory", KEY);
  await freshStore.setAiConfig({ enabled: true, provider: "anthropic", model: "claude-test", apiKey: "sk-ant-test-key" }, "ana");

  let call = 0;
  const fetchImpl = (async () => {
    call++;
    if (call === 1) {
      return new Response(JSON.stringify({ stop_reason: "tool_use", content: [
        { type: "text", text: "Armo el borrador." },
        { type: "tool_use", id: "t1", name: "assessment_draft", input: {
          name: "Evaluación Jojama",
          authorizer: { organization: "Jojama", name: "Hamilton", email: "ham@jojama.test", emergencyContact: "+57 300 000 0000" },
          allowedModes: ["passive"],
          scope: [{ type: "cidr", value: "203.0.113.0/24" }],
          window: { notBefore: "2026-11-01T00:00:00Z", notAfter: "2026-12-01T00:00:00Z", maxRequestsPerSecond: 5, maxConcurrency: 2 },
          allowedModules: ["config_audit"],
        } },
      ] }), { status: 200 });
    }
    return new Response(JSON.stringify({ stop_reason: "end_turn", content: [{ type: "text", text: "Revisa el borrador y confírmalo." }] }), { status: 200 });
  }) as typeof fetch;

  const r = await runAssessmentDraftAssistant({ store: freshStore, question: "quiero evaluar 203.0.113.0/24 para Jojama, autoriza Hamilton", requestedBy: "omar", fetchImpl });
  assert.ok(!("error" in r), JSON.stringify(r));
  if ("error" in r) throw new Error("unreachable");
  assert.equal(r.actions.length, 1);
  assert.equal(r.actions[0].tool, "assessment_draft");
  assert.equal((r.actions[0].result as any).draft.name, "Evaluación Jojama");
  assert.equal((await freshStore.listAssessments()).length, 0); // nada se creó solo
  await freshStore.close();
});
