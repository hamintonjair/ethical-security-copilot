import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { Store } from "../src/store.js";
import { Auth } from "../src/web/auth.js";
import { createHttpApp } from "../src/http.js";
import { encryptSecret, decryptSecret } from "../src/crypto.js";
import { runIncidentAssistant } from "../src/ai.js";

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
  await store.setAiConfig({ enabled: true, model: "otro-modelo" }, "ana");
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
  await freshStore.setAiConfig({ enabled: true, model: "claude-test", apiKey: "sk-ant-test-key" }, "ana");
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
