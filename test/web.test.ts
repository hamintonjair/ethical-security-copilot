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

/* ---------- OAuth (conexión de clientes MCP) ---------- */
import { createHash, randomBytes } from "node:crypto";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const form = (o: Record<string, string>) => ({ method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(o).toString() });

async function connect(ana: Client, redirect = REDIRECT) {
  const reg = await fetch(base + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [redirect] }) });
  assert.equal(reg.status, 201);
  const { client_id } = await reg.json() as any;
  const verifier = randomBytes(40).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const q = { client_id, redirect_uri: redirect, response_type: "code", code_challenge: challenge, code_challenge_method: "S256", state: "xyz" };
  return { client_id, verifier, q };
}

test("OAuth: descubrimiento, 401 con pista y flujo completo con PKCE", async () => {
  const noTok = await fetch(base + "/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  assert.equal(noTok.status, 401);
  assert.match(noTok.headers.get("www-authenticate") ?? "", /resource_metadata=".*\/\.well-known\/oauth-protected-resource"/);
  const meta = await (await fetch(base + "/.well-known/oauth-authorization-server")).json() as any;
  assert.deepEqual(meta.code_challenge_methods_supported, ["S256"]);
  assert.equal((await (await fetch(base + "/.well-known/oauth-protected-resource")).json() as any).resource, base + "/mcp");

  const ana = await as("ana");
  const { client_id, verifier, q } = await connect(ana);
  // /oauth/authorize redirige a la consola; ahí la persona inicia sesión y aprueba
  const au = await fetch(base + "/oauth/authorize?" + new URLSearchParams(q), { redirect: "manual" });
  assert.equal(au.status, 302); assert.match(au.headers.get("location") ?? "", /^\/app\/#\/autorizar\?/);
  const info = await ana.call("GET", "/api/oauth/request?" + new URLSearchParams(q));
  assert.equal(info.json.clientName, "Claude"); assert.equal(info.json.redirectHost, "claude.ai");
  const ap = await ana.call("POST", "/api/oauth/approve", { ...q, decision: "allow" });
  assert.equal(ap.status, 200, JSON.stringify(ap.json));
  const back = new URL(ap.json.redirect);
  assert.equal(back.origin + back.pathname, REDIRECT); assert.equal(back.searchParams.get("state"), "xyz");
  const code = back.searchParams.get("code")!;

  // PKCE incorrecto: falla y además quema el código
  const bad = await fetch(base + "/oauth/token", form({ grant_type: "authorization_code", code, client_id, redirect_uri: REDIRECT, code_verifier: randomBytes(40).toString("base64url") }));
  assert.equal(bad.status, 400);
  assert.equal((await fetch(base + "/oauth/token", form({ grant_type: "authorization_code", code, client_id, redirect_uri: REDIRECT, code_verifier: verifier }))).status, 400);

  // Flujo bueno con un código nuevo
  const code2 = new URL((await ana.call("POST", "/api/oauth/approve", { ...q, decision: "allow" })).json.redirect).searchParams.get("code")!;
  const tr = await fetch(base + "/oauth/token", form({ grant_type: "authorization_code", code: code2, client_id, redirect_uri: REDIRECT, code_verifier: verifier }));
  assert.equal(tr.status, 200);
  const tok = await tr.json() as any;
  assert.equal(tok.token_type, "Bearer");
  const mcp = (t: string) => fetch(base + "/mcp", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: `Bearer ${t}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  const ok = await mcp(tok.access_token);
  assert.equal(ok.status, 200); assert.match(await ok.text(), /scan_initiate/);

  // El refresh token rota: el viejo deja de servir
  const rf = await fetch(base + "/oauth/token", form({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id }));
  assert.equal(rf.status, 200); const tok2 = await rf.json() as any;
  assert.equal((await fetch(base + "/oauth/token", form({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id }))).status, 400);
  assert.equal((await mcp(tok2.access_token)).status, 200);

  // Si la cuenta que autorizó se deshabilita, el acceso muere
  const users = (await ana.call("GET", "/api/users")).json as any[];
  const extra = (await ana.call("POST", "/api/users", { username: "jefe2", role: "authorizer", password: "otra-frase-larga-7" })).json;
  assert.ok(extra.id);
  const other = new Client(); assert.equal((await other.login("jefe2", "otra-frase-larga-7")).status, 200);
  await other.call("POST", "/api/password", { current: "otra-frase-larga-7", next: "frase-nueva-larga-88" });
  const c2 = await connect(other);
  const code3 = new URL((await other.call("POST", "/api/oauth/approve", { ...c2.q, decision: "allow" })).json.redirect).searchParams.get("code")!;
  const t3 = await (await fetch(base + "/oauth/token", form({ grant_type: "authorization_code", code: code3, client_id: c2.client_id, redirect_uri: REDIRECT, code_verifier: c2.verifier }))).json() as any;
  assert.equal((await mcp(t3.access_token)).status, 200);
  assert.equal((await ana.call("POST", `/api/users/${extra.id}/update`, { disabled: true })).status, 200);
  assert.equal((await mcp(t3.access_token)).status, 401);
  assert.ok(users.length > 0);
});

test("OAuth: redirect_uri sin registrar, sin PKCE, y roles que no pueden aprobar", async () => {
  const ana = await as("ana"), alba = await as("alba");
  const { q } = await connect(ana);
  const evil = await fetch(base + "/oauth/authorize?" + new URLSearchParams({ ...q, redirect_uri: "https://evil.example/cb" }), { redirect: "manual" });
  assert.equal(evil.status, 400); // jamás redirige a una URL no registrada
  const noPkce = await fetch(base + "/oauth/authorize?" + new URLSearchParams({ ...q, code_challenge_method: "plain" }), { redirect: "manual" });
  assert.equal(noPkce.status, 400);
  assert.equal((await alba.call("POST", "/api/oauth/approve", { ...q, decision: "allow" })).status, 403);
  assert.equal((await new Client().call("POST", "/api/oauth/approve", { ...q, decision: "allow" })).status, 401);
  const deny = await ana.call("POST", "/api/oauth/approve", { ...q, decision: "deny" });
  assert.equal(new URL(deny.json.redirect).searchParams.get("error"), "access_denied");
  assert.equal(new URL(deny.json.redirect).searchParams.has("code"), false);
  const reg = await fetch(base + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://evil.example/cb"] }) });
  assert.equal(reg.status, 400); // http solo en localhost
  assert.equal((await fetch(base + "/oauth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://localhost:8080/cb"] }) })).status, 201);
});
