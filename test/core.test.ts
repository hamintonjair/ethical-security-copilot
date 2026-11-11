import { test } from "node:test";
import assert from "node:assert/strict";
import { Store } from "../src/store.js";
import { PolicyEngine } from "../src/policy.js";
import { targetMatches, isLabTarget, normalizeHost, type Target } from "../src/scope.js";
import { redact } from "../src/redact.js";

const KEY = Buffer.from("test-signing-key-test-signing-key");
const T0 = new Date("2026-11-10T15:00:00Z");

const input = (over: Record<string, unknown> = {}) => ({
  name: "Evaluación de prueba",
  authorizer: { organization: "Org Demo", name: "Ana Responsable", email: "ana@demo.test", emergencyContact: "+57 300 000 0000" },
  allowedModes: ["passive", "lab", "active"],
  scope: [
    { type: "cidr", value: "127.0.0.0/8" },
    { type: "cidr", value: "203.0.113.0/24" },
    { type: "domain", value: "example.test", includeSubdomains: true },
    { type: "url", value: "https://app.demo.test/api", pathPrefix: "/api" },
  ],
  exclusions: [{ target: { type: "ip", value: "203.0.113.50" }, reason: "producción crítica" }, { technique: "mod_dangerous", reason: "prohibido" }],
  window: { notBefore: "2026-11-10T00:00:00Z", notAfter: "2026-11-11T00:00:00Z", maxRequestsPerSecond: 5, maxConcurrency: 2 },
  allowedModules: ["port_check", "mod_dangerous", "dos_probe", "state_change_check"],
  ...over,
});

function setup(over: Record<string, unknown> = {}, now = T0, resolver?: (h: string) => Promise<string[]>) {
  const store = new Store(":memory:", KEY);
  const a = store.createAssessment(input(over), "ana");
  for (const s of ["scope_validated", "planned", "approved"] as const) store.transition(a.id, s, "ana", "authorizer");
  const policy = new PolicyEngine(store, { now: () => now, resolver: resolver ?? (async () => ["203.0.113.10"]) });
  return { store, a, policy };
}
const ip = (value: string): Target => ({ type: "ip", value });
const req = (id: string, over: Record<string, unknown> = {}) => ({
  assessmentId: id, actor: "operator" as const, mode: "lab" as const, module: "port_check",
  target: ip("127.0.0.1"), changesState: false, ...over,
});
const reasons = (d: any) => (d.allow ? [] : d.reasons);

/* ---------- Scope matching ---------- */
test("scope: IPs, CIDR y contención", () => {
  const s: Target[] = [{ type: "cidr", value: "10.0.0.0/24" }];
  assert.ok(targetMatches(ip("10.0.0.7"), s));
  assert.ok(!targetMatches(ip("10.0.1.7"), s));
  assert.ok(targetMatches({ type: "cidr", value: "10.0.0.128/25" }, s));
  assert.ok(!targetMatches({ type: "cidr", value: "10.0.0.0/16" }, s)); // más amplio que el scope
  assert.ok(targetMatches(ip("::ffff:10.0.0.9"), s)); // IPv4 mapeada
});

test("scope: evasiones de dominio y URL", () => {
  const s: Target[] = [{ type: "domain", value: "ok.test", includeSubdomains: false }];
  assert.ok(targetMatches({ type: "domain", value: "OK.test.", includeSubdomains: false }, s)); // mayúsculas y punto final
  assert.ok(!targetMatches({ type: "url", value: "https://ok.test@evil.test/" }, s));        // userinfo
  assert.ok(!targetMatches({ type: "url", value: "https://ok.test.evil.test/" }, s));        // sufijo engañoso
  assert.ok(!targetMatches({ type: "url", value: "https://sub.ok.test/" }, s));              // sin subdominios
  assert.ok(targetMatches({ type: "url", value: "https://ok.test/x" }, s));
  const u: Target[] = [{ type: "url", value: "https://app.test/api", pathPrefix: "/api" }];
  assert.ok(targetMatches({ type: "url", value: "https://app.test/api/v1" }, u));
  assert.ok(!targetMatches({ type: "url", value: "https://app.test/apiary" }, u));           // prefijo parcial
  assert.ok(!targetMatches({ type: "url", value: "https://app.test/api/../admin" }, u));     // traversal
  assert.ok(!targetMatches({ type: "url", value: "http://app.test/api" }, u));               // otro origen
});

test("scope: formas raras de IP se normalizan", () => {
  assert.equal(normalizeHost("2130706433"), "127.0.0.1");
  assert.equal(normalizeHost("127.1"), "127.0.0.1");
  assert.equal(normalizeHost("EXAMPLE.test."), "example.test");
  assert.equal(normalizeHost("a.test:8080"), null);
});

test("lab: solo localhost / red Docker", () => {
  assert.ok(isLabTarget(ip("127.0.0.1")));
  assert.ok(isLabTarget(ip("172.28.0.5")));
  assert.ok(isLabTarget({ type: "domain", value: "juice.lab.internal", includeSubdomains: false }));
  assert.ok(!isLabTarget(ip("203.0.113.10")));
  assert.ok(!isLabTarget({ type: "url", value: "https://example.test" }));
});

/* ---------- Policy engine ---------- */
test("policy: permite objetivo local en laboratorio", async () => {
  const { a, policy } = setup();
  assert.equal((await policy.check(req(a.id))).allow, true);
});

test("policy: deniega fuera de alcance, excluido y no local en lab", async () => {
  const { a, policy } = setup();
  assert.deepEqual(reasons(await policy.check(req(a.id, { target: ip("8.8.8.8") }))), ["TARGET_OUT_OF_SCOPE"]);
  assert.deepEqual(reasons(await policy.check(req(a.id, { target: ip("203.0.113.50"), mode: "passive" }))), ["TARGET_EXCLUDED"]);
  assert.deepEqual(reasons(await policy.check(req(a.id, { target: ip("203.0.113.10") }))), ["LAB_TARGET_NOT_LOCAL"]);
  assert.deepEqual(reasons(await policy.check(req(a.id, { target: { type: "cidr", value: "203.0.113.0/24" }, mode: "passive" }))), ["TARGET_EXCLUDED"]); // el CIDR contiene un activo excluido
});

test("policy: técnicas excluidas, módulos fuera de lista y hard limits", async () => {
  const { a, policy } = setup();
  assert.deepEqual(reasons(await policy.check(req(a.id, { module: "mod_dangerous" }))), ["TECHNIQUE_EXCLUDED"]);
  assert.deepEqual(reasons(await policy.check(req(a.id, { module: "otro_modulo" }))), ["MODULE_NOT_ALLOWED"]);
  assert.deepEqual(reasons(await policy.check(req(a.id, { module: "dos_probe" }))), ["HARD_LIMIT"]);          // aunque esté en la allowlist
  assert.deepEqual(reasons(await policy.check(req(a.id, { params: { mode: "bruteforce" } }))), ["HARD_LIMIT"]); // vía parámetros
});

test("policy: ventana de ejecución", async () => {
  const early = setup({}, new Date("2026-11-09T12:00:00Z"));
  assert.deepEqual(reasons(await early.policy.check(req(early.a.id))), ["OUTSIDE_WINDOW"]);
  const late = setup({}, new Date("2026-11-12T12:00:00Z"));
  assert.deepEqual(reasons(await late.policy.check(req(late.a.id))), ["OUTSIDE_WINDOW"]);
  const hours = setup({ window: { ...input().window, allowedHours: { from: "09:00", to: "17:00", tz: "America/Bogota" } } }, new Date("2026-11-10T03:00:00Z")); // 22:00 Bogotá
  assert.deepEqual(reasons(await hours.policy.check(req(hours.a.id))), ["OUTSIDE_WINDOW"]);
});

test("policy: rate limit y tope total", async () => {
  const { a, policy } = setup();
  const out: boolean[] = [];
  for (let i = 0; i < 8; i++) out.push((await policy.check(req(a.id))).allow);
  assert.equal(out.filter(Boolean).length, 5); // maxRequestsPerSecond = 5
  const cap = setup({ window: { ...input().window, maxRequestsPerSecond: 100, maxTotalRequests: 2 } });
  const res = [];
  for (let i = 0; i < 4; i++) res.push((await cap.policy.check(req(cap.a.id))).allow);
  assert.deepEqual(res, [true, true, false, false]);
});

test("policy: estado del ciclo de vida y roles", async () => {
  const store = new Store(":memory:", KEY);
  const a = store.createAssessment(input(), "ana"); // sigue en 'draft'
  const policy = new PolicyEngine(store, { now: () => T0 });
  assert.deepEqual(reasons(await policy.check(req(a.id))), ["STATE_TRANSITION_INVALID"]);
  assert.equal(store.transition(a.id, "executing", "x", "operator"), false); // no se puede saltar la aprobación
  const s = setup();
  assert.deepEqual(reasons(await s.policy.check(req(s.a.id, { actor: "auditor" }))), ["APPROVAL_REQUIRED"]);
  assert.deepEqual(reasons(await s.policy.check(req(s.a.id, { action: "assessment_create", actor: "agent" }))), ["APPROVAL_REQUIRED"]); // el agente no autoriza
});

test("policy: firma alterada invalida la autorización", async () => {
  const { store, a, policy } = setup();
  store.db.prepare("UPDATE assessments SET content_json = replace(content_json, '203.0.113.0/24', '0.0.0.0/0') WHERE id=?").run(a.id);
  assert.deepEqual(reasons(await policy.check(req(a.id))), ["SIGNATURE_INVALID"]);
});

test("policy: modo activo exige aprobación humana de un solo uso", async () => {
  const { store, a, policy } = setup();
  const t = ip("203.0.113.10");
  assert.deepEqual(reasons(await policy.check(req(a.id, { mode: "active", target: t }))), ["APPROVAL_REQUIRED"]);
  const planId = store.createPlan({ assessmentId: a.id, moduleId: "port_check", mode: "active", targets: [t], limits: {} });
  assert.throws(() => store.approvePlan(planId, "llm", "agent"));                // el LLM no puede aprobar
  const token = store.approvePlan(planId, "oscar", "operator");
  assert.deepEqual(reasons(await policy.check(req(a.id, { mode: "active", target: t, planId, approvalToken: "falso" }))), ["APPROVAL_REQUIRED"]);
  assert.equal((await policy.check(req(a.id, { mode: "active", target: t, planId, approvalToken: token }))).allow, true);
  assert.deepEqual(reasons(await policy.check(req(a.id, { mode: "active", target: t, planId, approvalToken: token }))), ["APPROVAL_REQUIRED"]); // reutilizar el token falla
});

test("policy: DNS rebinding hacia rangos sensibles se bloquea en modo activo", async () => {
  const { store, a, policy } = setup({}, T0, async () => ["169.254.169.254"]); // metadatos cloud
  const t: Target = { type: "domain", value: "api.example.test", includeSubdomains: false };
  const planId = store.createPlan({ assessmentId: a.id, moduleId: "port_check", mode: "active", targets: [t], limits: {} });
  const token = store.approvePlan(planId, "oscar", "operator");
  assert.deepEqual(reasons(await policy.check(req(a.id, { mode: "active", target: t, planId, approvalToken: token }))), ["DNS_RESOLVES_OUT_OF_SCOPE"]);
});

test("policy: kill switch bloquea todo hasta liberación humana", async () => {
  const { store, a, policy } = setup();
  store.activateKillSwitch("prueba", "oscar", "operator", a.id);
  assert.deepEqual(reasons(await policy.check(req(a.id))), ["KILL_SWITCH_ACTIVE"]);
  assert.throws(() => store.releaseKillSwitch("llm", "agent"));
  store.releaseKillSwitch("ana", "authorizer");
  assert.equal(store.getAssessment(a.id)!.a.state, "halted"); // sigue detenida: requiere nueva versión
  assert.deepEqual(reasons(await policy.check(req(a.id))), ["STATE_TRANSITION_INVALID"]);
});

/* ---------- Auditoría y redacción ---------- */
test("auditoría: cadena íntegra y manipulación detectada", async () => {
  const { store, a, policy } = setup();
  await policy.check(req(a.id)); await policy.check(req(a.id, { target: ip("8.8.8.8") }));
  assert.deepEqual(store.verifyAuditChain(), { ok: true });
  assert.throws(() => store.db.exec("UPDATE audit_log SET action='x' WHERE seq=1"), /append-only/);
  assert.throws(() => store.db.exec("DELETE FROM audit_log WHERE seq=1"), /append-only/);
  store.db.exec("DROP TRIGGER audit_no_update"); // atacante con acceso directo al archivo
  store.db.exec("UPDATE audit_log SET payload_redacted='manipulado' WHERE seq=2");
  const r = store.verifyAuditChain();
  assert.equal(r.ok, false);
  assert.equal((r as any).brokenAtSeq, 2);
});

test("redacción: secretos y PII", () => {
  const txt = "password=Sup3rS3cret email juan@demo.com tarjeta 4111 1111 1111 1111 Authorization: Bearer abcdefghijklmnop12345 AKIAABCDEFGHIJKLMNOP";
  const out = redact(txt);
  for (const leak of ["Sup3rS3cret", "juan@demo.com", "4111 1111 1111 1111", "abcdefghijklmnop12345", "AKIAABCDEFGHIJKLMNOP"]) assert.ok(!out.includes(leak), leak);
  assert.ok(redact("x".repeat(9000)).endsWith("[TRUNCATED]"));
});
