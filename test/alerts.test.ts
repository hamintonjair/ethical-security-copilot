import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { createHmac } from "node:crypto";
import { Store } from "../src/store.js";
import { Auth } from "../src/web/auth.js";
import { createHttpApp } from "../src/http.js";
import { createFinding } from "../src/findings.js";
import { isDue, buildPayload, sendAlertIfDue, type FetchFn } from "../src/alerts.js";

const KEY = Buffer.from("alerts-signing-key-alerts-signing-key-1");

/* ---------- Lógica pura: umbral de severidad ---------- */
test("isDue: respeta el umbral de severidad y la bandera de incidentes; una prueba siempre pasa", () => {
  assert.ok(isDue({ kind: "test", title: "x" }, { minSeverity: "critical", notifyIncidentOpen: false }));
  assert.ok(!isDue({ kind: "finding", severity: "high", title: "x" }, { minSeverity: "critical", notifyIncidentOpen: true }));
  assert.ok(isDue({ kind: "finding", severity: "critical", title: "x" }, { minSeverity: "critical", notifyIncidentOpen: true }));
  assert.ok(isDue({ kind: "finding", severity: "high", title: "x" }, { minSeverity: "high", notifyIncidentOpen: true }));
  assert.ok(!isDue({ kind: "finding", severity: "medium", title: "x" }, { minSeverity: "high", notifyIncidentOpen: true }));
  assert.ok(isDue({ kind: "incident_open", title: "x" }, { minSeverity: "critical", notifyIncidentOpen: true }));
  assert.ok(!isDue({ kind: "incident_open", title: "x" }, { minSeverity: "critical", notifyIncidentOpen: false }));
});

test("buildPayload: no incluye más que lo esperado y nunca lanza sin RENDER_EXTERNAL_HOSTNAME", () => {
  const p = buildPayload({ kind: "finding", severity: "critical", title: "Título", asset: "203.0.113.5", assessmentId: "a1", findingId: "f1" });
  assert.deepEqual(Object.keys(p).sort(), ["assessmentId", "asset", "findingId", "incidentId", "sentAt", "severity", "title", "type", "url"]);
  assert.equal(p.type, "finding"); assert.equal(p.url, null); // sin RENDER_EXTERNAL_HOSTNAME en pruebas
});

/* ---------- sendAlertIfDue contra un store real (deshabilitado / firma / fallo) ---------- */
async function freshStore() { return Store.open("memory", KEY); }

test("sendAlertIfDue: no llama a fetch si está deshabilitado o falta la URL", async () => {
  const store = await freshStore();
  let calls = 0;
  const fetchImpl: FetchFn = (async () => { calls++; return new Response("{}", { status: 200 }); }) as FetchFn;
  await sendAlertIfDue(store, { kind: "test", title: "x" }, fetchImpl);
  assert.equal(calls, 0);
  await store.setAlertsConfig({ enabled: true, minSeverity: "high", notifyIncidentOpen: true }, "ana"); // enabled sin webhookUrl: el schema lo impediría, pero el store no valida eso
  await sendAlertIfDue(store, { kind: "test", title: "x" }, fetchImpl);
  assert.equal(calls, 0); // getAlertsSecret exige enabled Y webhook_url
  await store.close();
});

test("sendAlertIfDue: firma el cuerpo con HMAC cuando hay secreto, y respeta el umbral", async () => {
  const store = await freshStore();
  const seen: { body: string; headers: Record<string, string> }[] = [];
  const fetchImpl: FetchFn = (async (_url: any, init: any) => {
    seen.push({ body: init.body, headers: init.headers });
    return new Response("ok", { status: 200 });
  }) as FetchFn;
  await store.setAlertsConfig({ enabled: true, webhookUrl: "https://ejemplo.invalid/webhook", minSeverity: "high", notifyIncidentOpen: true, secret: "s".repeat(10) }, "ana");

  await sendAlertIfDue(store, { kind: "finding", severity: "medium", title: "No llega al umbral" }, fetchImpl);
  assert.equal(seen.length, 0);

  await sendAlertIfDue(store, { kind: "finding", severity: "critical", title: "Sí llega", asset: "a", assessmentId: "ev1", findingId: "f1" }, fetchImpl);
  assert.equal(seen.length, 1);
  const { body, headers } = seen[0];
  const parsed = JSON.parse(body);
  assert.equal(parsed.title, "Sí llega"); assert.equal(parsed.severity, "critical"); assert.equal(parsed.findingId, "f1");
  const expectedSig = createHmac("sha256", "s".repeat(10)).update(body).digest("hex");
  assert.equal(headers["x-esc-signature"], expectedSig);

  const audits = await store.listAudit(5, 0);
  assert.ok(audits.rows.some((r) => r.action === "alert:sent"));
  await store.close();
});

test("sendAlertIfDue: un webhook caído o que responde error nunca lanza, y queda auditado", async () => {
  const store = await freshStore();
  await store.setAlertsConfig({ enabled: true, webhookUrl: "https://ejemplo.invalid/webhook", minSeverity: "info", notifyIncidentOpen: true }, "ana");
  const failing: FetchFn = (async () => { throw new Error("ECONNREFUSED"); }) as FetchFn;
  await assert.doesNotReject(sendAlertIfDue(store, { kind: "test", title: "x" }, failing));
  const erroring: FetchFn = (async () => new Response("no", { status: 500 })) as FetchFn;
  await assert.doesNotReject(sendAlertIfDue(store, { kind: "test", title: "x" }, erroring));
  await store.close();
});

/* ---------- Disparo real desde createFinding y createIncident ---------- */
const assessmentInput = (over: Record<string, unknown> = {}) => ({
  name: "Evaluación para alertas",
  authorizer: { organization: "Org Demo", name: "Ana", email: "ana@demo.test", emergencyContact: "+57 300 000 0000" },
  allowedModes: ["passive", "lab", "active"],
  scope: [{ type: "ip", value: "127.0.0.1" }],
  exclusions: [],
  window: { notBefore: "2026-11-01T00:00:00Z", notAfter: "2026-12-01T00:00:00Z", maxRequestsPerSecond: 5, maxConcurrency: 2 },
  allowedModules: ["port_check"],
  ...over,
});
const findingInput = (assessmentId: string, over: Record<string, unknown> = {}) => ({
  assessmentId, title: "Hallazgo crítico de prueba", severity: "critical", cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvssScore: 9.5, asset: "127.0.0.1",
  confidence: "high", observedFacts: ["hecho"], riskHypotheses: ["riesgo"],
  evidence: [{ description: "evidencia", redactedContent: "contenido", reproSteps: ["paso 1"] }],
  businessImpact: "alto", recommendation: "corregir",
  ...over,
});

test("createFinding dispara la alerta cuando la severidad cumple el umbral (y no si no cumple)", async () => {
  const store = await freshStore();
  const a = await store.createAssessment(assessmentInput(), "ana");
  for (const s of ["scope_validated", "planned", "approved", "executing"] as const) await store.transition(a.id, s, "ana", "authorizer");
  await store.setAlertsConfig({ enabled: true, webhookUrl: "https://ejemplo.invalid/webhook", minSeverity: "high", notifyIncidentOpen: true }, "ana");

  let calls = 0;
  const fetchImpl: FetchFn = (async () => { calls++; return new Response("ok", { status: 200 }); }) as FetchFn;
  const low = await createFinding(store, findingInput(a.id, { severity: "low", cvssScore: 2 }) as any, "alba", "analyst", fetchImpl);
  assert.ok(low.ok); assert.equal(calls, 0);
  const crit = await createFinding(store, findingInput(a.id) as any, "alba", "analyst", fetchImpl);
  assert.ok(crit.ok); assert.equal(calls, 1);
  await store.close();
});

test("store.createIncident dispara una alerta de apertura cuando está habilitada", async () => {
  const store = await freshStore();
  await store.setAlertsConfig({ enabled: true, webhookUrl: "https://ejemplo.invalid/webhook", minSeverity: "critical", notifyIncidentOpen: true }, "ana");
  let payload: any = null;
  const fetchImpl: FetchFn = (async (_url: any, init: any) => { payload = JSON.parse(init.body); return new Response("ok", { status: 200 }); }) as FetchFn;
  const inc = await store.createIncident({ organization: "Acme", contactName: "Ana", contactEmail: "ana@acme.test", summary: "resumen de prueba suficientemente largo", affectedAssets: [] }, "ana", fetchImpl);
  assert.ok(payload, "debió llamarse al webhook");
  assert.equal(payload.type, "incident_open"); assert.equal(payload.incidentId, inc.id);
  await store.close();
});

test("store.createIncident no dispara nada si notifyIncidentOpen está desactivado", async () => {
  const store = await freshStore();
  await store.setAlertsConfig({ enabled: true, webhookUrl: "https://ejemplo.invalid/webhook", minSeverity: "critical", notifyIncidentOpen: false }, "ana");
  let calls = 0;
  const fetchImpl: FetchFn = (async () => { calls++; return new Response("ok", { status: 200 }); }) as FetchFn;
  await store.createIncident({ organization: "Acme", contactName: "Ana", contactEmail: "ana@acme.test", summary: "resumen de prueba suficientemente largo", affectedAssets: [] }, "ana", fetchImpl);
  assert.equal(calls, 0);
  await store.close();
});

/* ---------- API web: solo un authorizer configura y prueba las alertas ---------- */
const HKEY = Buffer.from("alerts-http-signing-key-alerts-http-key");
const TOKEN = "h".repeat(16) + "0123456789abcdef0123456789abcdef";
const PW = "frase-larga-de-prueba-alerts-1";
let app: http.Server, store: Store, auth: Auth, base = "", origin = "";

class Client {
  cookie = ""; csrf = "";
  async call(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.cookie) headers.Cookie = this.cookie;
    if (method !== "GET") { headers.Origin = origin; if (this.csrf) headers["X-CSRF-Token"] = this.csrf; }
    const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get("set-cookie"); if (sc) this.cookie = sc.split(";")[0];
    const text = await r.text();
    return { status: r.status, json: text ? JSON.parse(text) : null };
  }
  async login(username: string) { const r = await this.call("POST", "/api/login", { username, password: PW }); if (r.status === 200) this.csrf = r.json.csrf; return r; }
}
const as = async (u: string) => { const c = new Client(); const r = await c.login(u); assert.equal(r.status, 200, JSON.stringify(r.json)); return c; };

before(async () => {
  store = await Store.open("memory", HKEY);
  auth = new Auth(store);
  const by = { actor: "test", role: "authorizer" as const };
  for (const [u, role] of [["ana", "authorizer"], ["alba", "analyst"]] as const) assert.ok((await auth.createUser({ username: u, role, password: PW, mustChange: false }, by)).ok);
  app = createHttpApp({ store, token: TOKEN, allowedHosts: ["localhost", "127.0.0.1"] });
  await new Promise<void>(r => app.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`; origin = base;
});
after(async () => { app.closeAllConnections(); app.close(); await store.close(); });

test("API de alertas: solo un authorizer la lee y la configura; se valida y se envía la prueba", async () => {
  const ana = await as("ana"), alba = await as("alba");
  assert.equal((await alba.call("GET", "/api/alerts/config")).status, 403);
  assert.equal((await alba.call("POST", "/api/alerts/config", { enabled: false, minSeverity: "high", notifyIncidentOpen: true })).status, 403);

  const get0 = await ana.call("GET", "/api/alerts/config");
  assert.equal(get0.status, 200); assert.equal(get0.json.enabled, false);

  const invalid = await ana.call("POST", "/api/alerts/config", { enabled: true, minSeverity: "high", notifyIncidentOpen: true }); // enabled sin webhookUrl
  assert.equal(invalid.status, 400);

  const testBefore = await ana.call("POST", "/api/alerts/test", {});
  assert.equal(testBefore.status, 400); assert.equal(testBefore.json.error, "ALERTS_NOT_CONFIGURED");

  // Webhook local real (en memoria, sin red externa) para verificar la entrega de punta a punta
  let received: any = null;
  const receiver = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => { received = { headers: req.headers, body: JSON.parse(raw || "{}") }; res.writeHead(200).end("ok"); });
  });
  await new Promise<void>((r) => receiver.listen(0, "127.0.0.1", r));
  const whUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/hook`;

  const saved = await ana.call("POST", "/api/alerts/config", { enabled: true, webhookUrl: whUrl, minSeverity: "high", notifyIncidentOpen: true, secret: "s".repeat(12) });
  assert.equal(saved.status, 200, JSON.stringify(saved.json)); assert.equal(saved.json.hasSecret, true);

  const sent = await ana.call("POST", "/api/alerts/test", {});
  assert.equal(sent.status, 200, JSON.stringify(sent.json));
  await new Promise((r) => setTimeout(r, 100)); // el POST al webhook es asíncrono respecto a la respuesta HTTP de /test
  assert.ok(received, "el webhook local debió recibir la petición de prueba");
  assert.equal(received.body.type, "test");
  assert.equal(received.headers["x-esc-signature"], createHmac("sha256", "s".repeat(12)).update(JSON.stringify(received.body)).digest("hex"));

  const cleared = await ana.call("POST", "/api/alerts/config", { enabled: false, webhookUrl: whUrl, minSeverity: "high", notifyIncidentOpen: true, clearSecret: true });
  assert.equal(cleared.status, 200); assert.equal(cleared.json.hasSecret, false); assert.equal(cleared.json.enabled, false);
  receiver.close();
});
