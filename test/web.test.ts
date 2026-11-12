import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { Store } from "../src/store.js";
import { Auth } from "../src/web/auth.js";
import { createHttpApp } from "../src/http.js";

const KEY = Buffer.from("web-signing-key-web-signing-key-1234");
const TOKEN = "t".repeat(16) + "0123456789abcdef0123456789abcdef";
const PW = "frase-larga-de-prueba-1";
let app: http.Server, store: Store, auth: Auth, base = "", origin = "";

class Client {
  cookie = ""; csrf = "";
  async call(method: string, path: string, body?: unknown, o: { origin?: string | null; csrf?: string | null } = {}) {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.cookie) headers.Cookie = this.cookie;
    if (method !== "GET") {
      if (o.origin !== null) headers.Origin = o.origin ?? origin;
      const c = o.csrf === undefined ? this.csrf : o.csrf;
      if (c) headers["X-CSRF-Token"] = c;
    }
    const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get("set-cookie");
    if (sc) this.cookie = sc.split(";")[0];
    const text = await r.text();
    return { status: r.status, headers: r.headers, json: text ? JSON.parse(text) : null, setCookie: sc };
  }
  async login(username: string, password = PW) {
    const r = await this.call("POST", "/api/login", { username, password });
    if (r.status === 200) this.csrf = r.json.csrf;
    return r;
  }
}
const as = async (u: string) => { const c = new Client(); const r = await c.login(u); assert.equal(r.status, 200, JSON.stringify(r.json)); return c; };

const newAssessment = () => ({
  name: "Evaluación web", authorizer: { organization: "Org", name: "Ana", email: "ana@demo.test", emergencyContact: "ana@demo.test" },
  allowedModes: ["passive", "lab"], scope: [{ type: "ip", value: "127.0.0.1" }], exclusions: [],
  window: { notBefore: "2020-01-01T00:00:00Z", notAfter: "2099-01-01T00:00:00Z", maxRequestsPerSecond: 20, maxConcurrency: 2 },
  allowedModules: ["config_audit"],
});

before(async () => {
  store = await Store.open("memory", KEY);
  auth = new Auth(store);
  const by = { actor: "test", role: "authorizer" as const };
  for (const [u, role] of [["ana", "authorizer"], ["omar", "operator"], ["alba", "analyst"], ["aud", "auditor"]] as const)
    assert.ok((await auth.createUser({ username: u, role, password: PW, mustChange: false }, by)).ok);
  assert.ok((await auth.createUser({ username: "nuevo", role: "analyst", password: PW }, by)).ok); // mustChange por defecto
  app = createHttpApp({ store, token: TOKEN, allowedHosts: ["localhost", "127.0.0.1"] });
  await new Promise<void>(r => app.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`; origin = base;
});
after(async () => { app.closeAllConnections(); app.close(); await store.close(); });

test("la interfaz estática se sirve con cabeceras de seguridad y sin traversal", async () => {
  const r = await fetch(base + "/app/");
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-security-policy") ?? "", /default-src 'none'; script-src 'self'/);
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  assert.equal((await fetch(base + "/app/main.js")).status, 200);
  assert.ok([400, 403, 404].includes((await fetch(base + "/app/..%2f..%2fpackage.json")).status));
  assert.equal((await fetch(base + "/", { redirect: "manual" })).status, 302);
});

test("login: cookie HttpOnly + SameSite=Strict; fallo genérico", async () => {
  const c = new Client();
  const bad = await c.login("ana", "incorrecta-incorrecta");
  const ghost = await new Client().login("no-existe", "incorrecta-incorrecta");
  assert.equal(bad.status, 401); assert.equal(ghost.status, 401);
  assert.deepEqual(bad.json, ghost.json); // sin enumeración de usuarios
  const ok = await c.login("ana");
  assert.equal(ok.status, 200);
  assert.match(ok.setCookie ?? "", /esc_session=/); assert.match(ok.setCookie ?? "", /HttpOnly/i); assert.match(ok.setCookie ?? "", /SameSite=Strict/i);
  assert.equal(ok.json.user.role, "authorizer");
  assert.equal(JSON.stringify(ok.json).includes("password"), false);
});

test("sin sesión: 401; CSRF y Origin se exigen en escrituras", async () => {
  assert.equal((await new Client().call("GET", "/api/dashboard")).status, 401);
  const c = await as("ana");
  assert.equal((await c.call("GET", "/api/dashboard")).status, 200);
  assert.equal((await c.call("POST", "/api/assessments", newAssessment(), { csrf: null })).status, 403);
  assert.equal((await c.call("POST", "/api/assessments", newAssessment(), { csrf: "otro-token" })).status, 403);
  assert.equal((await c.call("POST", "/api/assessments", newAssessment(), { origin: "https://evil.example" })).status, 403);
});

test("bloqueo tras 5 fallos y el acceso correcto tampoco entra mientras dura", async () => {
  const c = new Client();
  for (let i = 0; i < 5; i++) assert.equal((await c.login("omar", "mala-mala-mala-mala")).status, 401);
  assert.equal((await c.login("omar")).status, 401);
  const users = await auth.listUsers(); const omar = users.find(u => u.username === "omar")!;
  assert.ok(omar.lockedUntil);
  assert.ok((await auth.updateUser(omar.id, { unlock: true }, { actor: "test", role: "authorizer" })).ok);
  assert.equal((await c.login("omar")).status, 200);
});

test("roles: cada rol solo hace lo suyo", async () => {
  const ana = await as("ana"), alba = await as("alba"), aud = await as("aud"), omar = await as("omar");
  const made = await ana.call("POST", "/api/assessments", newAssessment());
  assert.equal(made.status, 200, JSON.stringify(made.json));
  const id = made.json.id;
  assert.equal((await alba.call("POST", "/api/assessments", newAssessment())).status, 403);
  assert.equal((await aud.call("POST", `/api/assessments/${id}/advance`, { to: "scope_validated" })).status, 403);
  assert.equal((await omar.call("GET", "/api/users")).status, 403);
  assert.equal((await alba.call("GET", "/api/audit")).status, 403);
  assert.equal((await aud.call("GET", "/api/audit")).status, 200);
  assert.equal((await aud.call("GET", `/api/assessments/${id}`)).status, 200);
  assert.equal((await ana.call("GET", "/api/users")).status, 200);
});

test("ciclo: avanzar, no saltar estados, y el kill switch detiene y bloquea", async () => {
  const ana = await as("ana"), omar = await as("omar");
  const { json: a } = await ana.call("POST", "/api/assessments", newAssessment());
  assert.equal((await ana.call("POST", `/api/assessments/${a.id}/advance`, { to: "approved" })).status >= 400, true); // salto no permitido
  for (const to of ["scope_validated", "planned", "approved"]) assert.equal((await ana.call("POST", `/api/assessments/${a.id}/advance`, { to })).status, 200);
  const det = await ana.call("GET", `/api/assessments/${a.id}`);
  assert.equal(det.json.state, "approved"); assert.equal(det.json.signatureValid, true);
  // el operador puede activar el kill switch pero no liberarlo
  assert.equal((await omar.call("POST", "/api/killswitch", { reason: "prueba" })).status, 200);
  assert.equal((await omar.call("POST", "/api/killswitch/release")).status, 403);
  assert.equal((await ana.call("GET", "/api/me")).json.killSwitch.active, true);
  assert.equal((await ana.call("POST", "/api/killswitch/release")).status, 200);
  assert.equal((await ana.call("GET", "/api/me")).json.killSwitch.active, false);
});

test("usuarios: no se puede dejar el sistema sin authorizer; contraseña débil rechazada", async () => {
  const ana = await as("ana");
  assert.equal((await ana.call("POST", "/api/users", { username: "x1", role: "analyst", password: "corta" })).status, 400);
  const users = (await ana.call("GET", "/api/users")).json as any[];
  const me = users.find(u => u.username === "ana");
  const r = await ana.call("POST", `/api/users/${me.id}/update`, { disabled: true });
  assert.equal(r.status, 400); assert.match(r.json.message, /authorizer/);
  assert.equal(JSON.stringify(users).includes("scrypt"), false); // nunca se devuelve el hash
});

test("contraseña temporal: solo permite cambiarla; luego entra y las demás sesiones se cierran", async () => {
  const c = await as("nuevo");
  assert.equal((await c.call("GET", "/api/me")).json.user.mustChange, true);
  assert.equal((await c.call("GET", "/api/dashboard")).status, 403);
  assert.equal((await c.call("POST", "/api/password", { current: PW, next: PW })).status, 400);
  assert.equal((await c.call("POST", "/api/password", { current: "no-es-la-actual-xx", next: "otra-frase-larga-9" })).status, 400);
  const other = await as("nuevo");
  assert.equal((await c.call("POST", "/api/password", { current: PW, next: "otra-frase-larga-9" })).status, 200);
  assert.equal((await c.call("GET", "/api/dashboard")).status, 200);
  assert.equal((await other.call("GET", "/api/me")).status, 401);
});

test("logout cierra la sesión en el servidor y la auditoría queda íntegra", async () => {
  const c = await as("aud");
  const old = c.cookie;
  assert.equal((await c.call("POST", "/api/logout", {})).status, 200);
  const replay = new Client(); replay.cookie = old;
  assert.equal((await replay.call("GET", "/api/me")).status, 401);
  const ana = await as("ana");
  const v = await ana.call("POST", "/api/audit/verify");
  assert.equal(v.json.ok, true);
});
