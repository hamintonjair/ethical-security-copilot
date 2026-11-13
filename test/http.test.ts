import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Store } from "../src/store.js";
import { createHttpApp } from "../src/http.js";

const KEY = Buffer.from("http-signing-key-http-signing-key-12");
const TOKEN = "t".repeat(16) + "0123456789abcdef0123456789abcdef";
let app: http.Server, store: Store, base = "", id = "";

before(async () => {
  store = await Store.open("memory", KEY);
  const a = await store.createAssessment({
    name: "Evaluación HTTP", authorizer: { organization: "Org", name: "Ana", email: "ana@demo.test", emergencyContact: "ana@demo.test" },
    allowedModes: ["passive", "lab"], scope: [{ type: "ip", value: "127.0.0.1" }], exclusions: [],
    window: { notBefore: "2020-01-01T00:00:00Z", notAfter: "2099-01-01T00:00:00Z", maxRequestsPerSecond: 20, maxConcurrency: 2 },
    allowedModules: ["config_audit"],
  }, "ana");
  id = a.id;
  for (const s of ["scope_validated", "planned", "approved"] as const) await store.transition(id, s, "ana", "authorizer");
  app = createHttpApp({ store, token: TOKEN, allowedHosts: ["localhost", "127.0.0.1", "esc.example.test"] });
  await new Promise<void>(r => app.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
});
after(async () => { app.closeAllConnections(); app.close(); await store.close(); });

const rpc = (headers: Record<string, string> = {}, body: unknown = { jsonrpc: "2.0", id: 1, method: "tools/list" }, path = "/mcp", method = "POST") =>
  fetch(base + path, { method, headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers }, body: method === "POST" ? JSON.stringify(body) : undefined });

test("health check abierto y sin datos; rutas desconocidas 404", async () => {
  const r = await rpc({}, {}, "/healthz", "GET");
  assert.equal(r.status, 200); assert.deepEqual(await r.json(), { status: "ok" });
  assert.equal((await rpc({}, {}, "/otra", "GET")).status, 404);
  const ready = await rpc({}, {}, "/readyz", "GET");
  assert.equal(ready.status, 200); assert.deepEqual(await ready.json(), { status: "ready" });
});

test("sin token o con token incorrecto: 401, y nunca se ejecuta nada", async () => {
  assert.equal((await rpc()).status, 401);
  assert.equal((await rpc({ Authorization: "Bearer " + "x".repeat(48) })).status, 401);
  assert.equal((await rpc({ Authorization: "Basic " + TOKEN })).status, 401);
  assert.equal((await rpc({ Authorization: TOKEN })).status, 401);
});

test("Host no permitido (DNS rebinding): 403 aun con token válido", async () => {
  // fetch no permite fijar Host; se usa un request crudo
  const { request } = await import("node:http");
  const status = await new Promise<number>((resolve, reject) => {
    const req = request(base + "/mcp", { method: "POST", headers: { Host: "evil.example", Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" } }, r => { r.resume(); resolve(r.statusCode ?? 0); });
    req.on("error", reject); req.end("{}");
  });
  assert.equal(status, 403);
});

test("solo POST, cuerpo limitado y JSON válido", async () => {
  const auth = { Authorization: `Bearer ${TOKEN}` };
  assert.equal((await rpc(auth, {}, "/mcp", "GET")).status, 405);
  const big = await fetch(base + "/mcp", { method: "POST", headers: { ...auth, "Content-Type": "application/json" }, body: "x".repeat(1_100_000) });
  assert.equal(big.status, 413);
  const bad = await fetch(base + "/mcp", { method: "POST", headers: { ...auth, "Content-Type": "application/json" }, body: "{no-json" });
  assert.equal(bad.status, 400);
});

test("cliente MCP real por HTTP: herramientas, alcance y rol fijado por el servidor", async () => {
  const client = new Client({ name: "t", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(base + "/mcp"), { requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } } }));
  const names = (await client.listTools()).tools.map(t => t.name).sort();
  assert.deepEqual(names, ["assessment_create", "finding_create", "incident_contain_plan", "incident_evidence_analyze", "incident_open", "incident_report", "report_generate", "scan_initiate", "scan_stop", "scope_validate"]);
  const call = async (name: string, args: Record<string, unknown>) => JSON.parse(((await client.callTool({ name, arguments: args })) as any).content[0].text);
  assert.equal((await call("scope_validate", { assessmentId: id, target: { type: "ip", value: "127.0.0.1" } })).authorized, true);
  assert.equal((await call("scope_validate", { assessmentId: id, target: { type: "ip", value: "8.8.8.8" } })).authorized, false);
  // Por la red el agente no puede crear autorizaciones, aunque lo intente
  const denied = await call("assessment_create", { name: "x".repeat(5), authorizer: { organization: "Org", name: "Ana", email: "a@b.co", emergencyContact: "ana" }, allowedModes: ["passive"], scope: [{ type: "ip", value: "10.0.0.1" }], window: { notBefore: "2020-01-01T00:00:00Z", notAfter: "2099-01-01T00:00:00Z", maxRequestsPerSecond: 1, maxConcurrency: 1 }, allowedModules: ["config_audit"] });
  assert.equal(denied.error, "ROLE_NOT_ALLOWED");
  const scan = await call("scan_initiate", { assessmentId: id, moduleId: "config_audit", mode: "passive", targets: [{ type: "ip", value: "127.0.0.1" }], params: { content: "PermitRootLogin yes" } });
  assert.equal(scan.status, "completed");
  await client.close();
  assert.deepEqual(await store.verifyAuditChain(), { ok: true });
});

test("configuración insegura rechazada al crear la app", () => {
  assert.throws(() => createHttpApp({ store, token: "corto", allowedHosts: ["localhost"] }), /32 caracteres/);
  assert.throws(() => createHttpApp({ store, token: TOKEN, role: "authorizer" as any, allowedHosts: ["localhost"] }), /no permitido por HTTP/);
  assert.throws(() => createHttpApp({ store, token: TOKEN, role: "operator" as any, allowedHosts: ["localhost"] }), /no permitido por HTTP/);
});
