import type http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { z, ZodError } from "zod";
import { AssessmentInput, FindingInput } from "../schemas.js";
import type { Store } from "../store.js";
import type { RunRegistry } from "../server.js";
import { builtinModules } from "../modules.js";
import { createFinding } from "../findings.js";
import { buildReport } from "../report.js";
import { broadScopeProblem } from "../scope.js";
import type { State } from "../state.js";
import { Auth, WEB_ROLES, type Session, type WebRole } from "./auth.js";

const COOKIE = "esc_session";
const MAX_BODY = 200_000;
const ALL: WebRole[] = ["authorizer", "operator", "analyst", "auditor"];
const HUMAN_OPS: WebRole[] = ["authorizer", "operator"];

/** Quién puede hacer qué. El servidor lo aplica en cada ruta; la interfaz solo oculta lo que no corresponde. */
const CAN = {
  read: ALL,
  createAssessment: ["authorizer"] as WebRole[],
  advance: ["authorizer"] as WebRole[],
  decidePlan: HUMAN_OPS,
  killOn: HUMAN_OPS,
  killOff: ["authorizer"] as WebRole[],
  findings: ["authorizer", "operator", "analyst"] as WebRole[],
  finalizeReport: ["authorizer", "operator", "analyst"] as WebRole[],
  audit: ["authorizer", "operator", "auditor"] as WebRole[],
  users: ["authorizer"] as WebRole[],
};

const MODULE_LABELS: Record<string, { title: string; description: string }> = {
  config_audit: { title: "Análisis de configuración", description: "Revisa texto de configuración que tú aportas. No usa la red." },
  tcp_port_check: { title: "Prueba de puertos TCP", description: "Comprueba si hasta 32 puertos de un host aceptan conexiones." },
  http_header_audit: { title: "Cabeceras HTTP", description: "Lee solo las cabeceras de seguridad y los banners de versión." },
  lab_write_probe: { title: "Escritura de laboratorio", description: "Envía un POST inofensivo con marcador. Cambia estado: exige aprobación." },
};

class HttpError extends Error { constructor(public status: number, public code: string, message: string) { super(message); } }

export interface ApiCtx { store: Store; auth: Auth; runs: RunRegistry }

function send(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string | string[]> = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}

async function readJson(req: http.IncomingMessage): Promise<any> {
  const chunks: Buffer[] = []; let size = 0;
  for await (const c of req) { size += (c as Buffer).length; if (size > MAX_BODY) { req.destroy(); throw new HttpError(413, "BODY_TOO_LARGE", "La petición es demasiado grande."); } chunks.push(c as Buffer); }
  if (!size) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new HttpError(400, "INVALID_JSON", "El cuerpo no es JSON válido."); }
}

const cookieOf = (req: http.IncomingMessage, name: string) => (req.headers.cookie ?? "").split(/;\s*/).map(c => c.split("=")).find(([k]) => k === name)?.slice(1).join("=");
const isHttps = (req: http.IncomingMessage) => req.headers["x-forwarded-proto"] === "https" || !!(req.socket as any).encrypted;
const sessionCookie = (req: http.IncomingMessage, token: string, maxAge: number) =>
  `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${isHttps(req) ? "; Secure" : ""}`;
const safeEq = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

function originOk(req: http.IncomingMessage): boolean {
  const o = req.headers.origin;
  if (!o) return true; // clientes sin navegador; la cabecera CSRF sigue siendo obligatoria
  try { return new URL(o).host.toLowerCase() === String(req.headers.host ?? "").toLowerCase(); } catch { return false; }
}

function validationError(e: ZodError) {
  return { error: "VALIDATION", message: "Hay datos que corregir.", issues: e.issues.slice(0, 20).map(i => ({ path: i.path.join("."), message: i.message })) };
}

type Handler = (c: { req: http.IncomingMessage; res: http.ServerResponse; s: Session; body: any; params: string[]; query: URLSearchParams }) => Promise<unknown>;
interface Route { method: string; re: RegExp; roles: WebRole[]; h: Handler }

export function createApi(ctx: ApiCtx) {
  const { store, auth, runs } = ctx;
  const routes: Route[] = [];
  const route = (method: string, path: string, roles: WebRole[], h: Handler) => routes.push({ method, re: new RegExp(`^${path.replace(/:id/g, "([0-9a-fA-F-]{36})")}$`), roles, h });
  const who = (s: Session) => ({ actor: s.user.username, role: s.user.role as WebRole });
  const mustFind = async (id: string) => { const r = await store.getAssessment(id); if (!r) throw new HttpError(404, "NOT_FOUND", "La evaluación no existe."); return r; };

  /* ---------- Cuenta ---------- */
  route("GET", "/api/me", ALL, async ({ s }) => ({ user: s.user, csrf: s.csrf, killSwitch: await store.killSwitchInfo() }));
  route("POST", "/api/logout", ALL, async ({ s, req, res }) => { await auth.logout(s.id); await store.audit({ ...who(s), action: "auth:logout" }); res.setHeader("Set-Cookie", sessionCookie(req, "", 0)); return { ok: true }; });
  route("POST", "/api/password", ALL, async ({ s, body }) => {
    const r = await auth.changePassword(s.user, String(body.current ?? ""), String(body.next ?? ""), s.id);
    if (!r.ok) throw new HttpError(400, "PASSWORD", r.error);
    return { ok: true };
  });

  /* ---------- Panel ---------- */
  route("GET", "/api/dashboard", CAN.read, async () => {
    const list = await store.listAssessments();
    const counts: Record<string, number> = {};
    for (const a of list) counts[a.state] = (counts[a.state] ?? 0) + 1;
    const pending = await store.listPlans({ status: "pending_approval" });
    const names = new Map(list.map(a => [a.id, a.name]));
    const audit = await store.listAudit(8, 0);
    return {
      killSwitch: await store.killSwitchInfo(), assessments: list.length, counts,
      pendingPlans: pending.map(p => ({ ...p, assessmentName: names.get(p.assessmentId) ?? "" })),
      recentAudit: audit.rows, auditTotal: audit.total,
    };
  });

  route("GET", "/api/modules", CAN.read, async () => [...builtinModules().values()].map(m => ({ id: m.manifest.id, category: m.manifest.category, modes: m.manifest.modes, changesState: m.manifest.changesState, ...(MODULE_LABELS[m.manifest.id] ?? { title: m.manifest.id, description: "" }) })));

  /* ---------- Evaluaciones ---------- */
  route("GET", "/api/assessments", CAN.read, async () => store.listAssessments());

  const parseAssessment = (body: unknown) => {
    const input = AssessmentInput.parse(body);
    if (Date.parse(input.window.notAfter) <= Date.parse(input.window.notBefore)) throw new HttpError(400, "VALIDATION", "La ventana termina antes de empezar.");
    const broad = broadScopeProblem(input.scope); if (broad) throw new HttpError(400, "SCOPE_TOO_BROAD", broad);
    const known = new Set(builtinModules().keys());
    const unknown = input.allowedModules.filter(m => !known.has(m)); if (unknown.length) throw new HttpError(400, "VALIDATION", `Módulos desconocidos: ${unknown.join(", ")}.`);
    return input;
  };

  route("POST", "/api/assessments", CAN.createAssessment, async ({ s, body }) => {
    const a = await store.createAssessment(parseAssessment(body), s.user.username);
    await store.audit({ ...who(s), action: "assessment_create", assessmentId: a.id, payload: { name: a.name, version: a.version, scope: a.scope.length, via: "web" } });
    return { id: a.id, version: a.version, state: a.state };
  });

  route("GET", "/api/assessments/:id", CAN.read, async ({ params }) => {
    const { a, signatureValid } = await mustFind(params[0]);
    const { contentHash: _h, signature: _s, ...content } = a;
    return {
      ...content, contentHash: a.contentHash, signatureValid,
      versions: await store.listVersions(a.id), plans: await store.listPlans({ assessmentId: a.id }),
      findings: await store.listFindings(a.id), killSwitch: (await store.killSwitchInfo()).active,
    };
  });

  /** Nueva versión del alcance: vuelve a 'draft' y caduca las aprobaciones anteriores. */
  route("POST", "/api/assessments/:id/versions", CAN.createAssessment, async ({ s, params, body }) => {
    await mustFind(params[0]);
    const a = await store.createAssessment(parseAssessment(body), s.user.username, { id: params[0] });
    await store.audit({ ...who(s), action: "assessment_version", assessmentId: a.id, payload: { version: a.version, via: "web" } });
    return { id: a.id, version: a.version, state: a.state };
  });

  const MANUAL = new Set<State>(["scope_validated", "planned", "approved", "halted", "closed"]);
  route("POST", "/api/assessments/:id/advance", CAN.advance, async ({ s, params, body }) => {
    const to = String(body.to) as State;
    if (!MANUAL.has(to)) throw new HttpError(400, "VALIDATION", "Ese estado no se puede fijar a mano.");
    const { signatureValid } = await mustFind(params[0]);
    if (!signatureValid && to !== "halted" && to !== "closed") throw new HttpError(409, "SIGNATURE_INVALID", "La firma de la autorización no es válida: no se puede avanzar.");
    if (!(await store.transition(params[0], to, s.user.username, s.user.role))) throw new HttpError(409, "STATE_TRANSITION_INVALID", "Esa transición no está permitida desde el estado actual.");
    return { ok: true };
  });

  /* ---------- Planes ---------- */
  route("GET", "/api/plans", CAN.read, async ({ query }) => store.listPlans({ status: query.get("status") ?? undefined }));

  route("POST", "/api/plans/:id/approve", CAN.decidePlan, async ({ s, params }) => {
    const plan = (await store.listPlans()).find(p => p.id === params[0]);
    if (!plan) throw new HttpError(404, "NOT_FOUND", "El plan no existe.");
    if (plan.status !== "pending_approval") throw new HttpError(409, "PLAN_STATE", "El plan ya no está pendiente.");
    const cur = await store.getAssessment(plan.assessmentId);
    if (!cur || !cur.signatureValid) throw new HttpError(409, "SIGNATURE_INVALID", "La autorización no es válida.");
    if (cur.a.version !== plan.assessmentVersion) throw new HttpError(409, "PLAN_STALE", "El alcance cambió después de proponer este plan. Recházalo y que se proponga de nuevo.");
    if (!["approved", "executing"].includes(cur.a.state)) throw new HttpError(409, "STATE_TRANSITION_INVALID", "La evaluación no está aprobada para ejecutar.");
    if ((await store.killSwitchInfo()).active) throw new HttpError(409, "KILL_SWITCH_ACTIVE", "El kill switch está activo.");
    const token = await store.approvePlan(params[0], s.user.username, s.user.role);
    return { token, note: "Se muestra una sola vez. Entrégalo al agente por un canal aparte; sirve únicamente para los objetivos de este plan." };
  });

  route("POST", "/api/plans/:id/reject", CAN.decidePlan, async ({ s, params }) => {
    if (!(await store.rejectPlan(params[0], s.user.username, s.user.role))) throw new HttpError(409, "PLAN_STATE", "El plan ya no está pendiente.");
    return { ok: true };
  });

  /* ---------- Hallazgos e informes ---------- */
  route("POST", "/api/assessments/:id/findings", CAN.findings, async ({ s, params, body }) => {
    const input = FindingInput.parse({ ...body, assessmentId: params[0] });
    const r = await createFinding(store, input, s.user.username, s.user.role);
    if (!r.ok) throw new HttpError(409, r.error, r.message ?? r.error);
    return { id: r.findingId };
  });

  const TRIAGE = ["unverified", "confirmed", "false_positive", "accepted_risk"];
  route("POST", "/api/findings/:id/triage", CAN.findings, async ({ s, params, body }) => {
    if (!TRIAGE.includes(body.triage)) throw new HttpError(400, "VALIDATION", "Estado de triaje no válido.");
    if (!(await store.setTriage(params[0], body.triage, s.user.username, s.user.role))) throw new HttpError(404, "NOT_FOUND", "El hallazgo no existe.");
    return { ok: true };
  });

  const ReportIn = z.object({ format: z.enum(["markdown", "json"]).default("markdown"), includeStates: z.array(z.enum(["confirmed", "unverified", "false_positive", "accepted_risk"])).default(["confirmed"]), finalize: z.boolean().default(false) });
  route("POST", "/api/assessments/:id/report", ALL, async ({ s, params, body }) => {
    const o = ReportIn.parse(body);
    if (o.finalize && !CAN.finalizeReport.includes(s.user.role as WebRole)) throw new HttpError(403, "FORBIDDEN", "Tu rol no puede cerrar el informe.");
    const r = await buildReport(store, { assessmentId: params[0], format: o.format, includeStates: o.includeStates, advance: o.finalize, actor: s.user.username, role: s.user.role as WebRole });
    if (!r.ok) throw new HttpError(404, r.error, "La evaluación no existe o su firma no es válida.");
    return { text: r.text, findings: r.findings, format: o.format };
  });

  /* ---------- Kill switch ---------- */
  route("POST", "/api/killswitch", CAN.killOn, async ({ s, body }) => {
    const reason = String(body.reason ?? "").trim();
    if (reason.length < 3 || reason.length > 300) throw new HttpError(400, "VALIDATION", "Indica el motivo (entre 3 y 300 caracteres).");
    const assessmentId = typeof body.assessmentId === "string" && body.assessmentId ? body.assessmentId : undefined;
    let aborted = 0;
    for (const r of runs.values()) if (!assessmentId || r.assessmentId === assessmentId) { r.ctrl.abort(); aborted++; }
    await store.activateKillSwitch(reason, s.user.username, s.user.role, assessmentId);
    return { active: true, abortedRuns: aborted };
  });
  route("POST", "/api/killswitch/release", CAN.killOff, async ({ s }) => { await store.releaseKillSwitch(s.user.username, s.user.role); return { active: false }; });

  /* ---------- Auditoría ---------- */
  route("GET", "/api/audit", CAN.audit, async ({ query }) => {
    const limit = Math.min(200, Math.max(1, Number(query.get("limit") ?? 50) || 50));
    const offset = Math.max(0, Number(query.get("offset") ?? 0) || 0);
    return store.listAudit(limit, offset);
  });
  route("POST", "/api/audit/verify", CAN.audit, async ({ s }) => {
    const r = await store.verifyAuditChain();
    await store.audit({ ...who(s), action: "audit:verify", payload: { ok: r.ok } });
    return { ...r, checked: (await store.listAudit(1, 0)).total };
  });

  /* ---------- Usuarios ---------- */
  route("GET", "/api/users", CAN.users, async () => auth.listUsers());
  route("POST", "/api/users", CAN.users, async ({ s, body }) => {
    const r = await auth.createUser({ username: String(body.username ?? ""), displayName: String(body.displayName ?? ""), role: body.role, password: String(body.password ?? "") }, { actor: s.user.username, role: "authorizer" });
    if (!r.ok) throw new HttpError(400, "USER", r.error);
    return r.user;
  });
  route("POST", "/api/users/:id/update", CAN.users, async ({ s, params, body }) => {
    const patch: { disabled?: boolean; role?: WebRole; unlock?: boolean } = {};
    if (typeof body.disabled === "boolean") patch.disabled = body.disabled;
    if (typeof body.role === "string") patch.role = body.role as WebRole;
    if (body.unlock === true) patch.unlock = true;
    const r = await auth.updateUser(params[0], patch, { actor: s.user.username, role: "authorizer" });
    if (!r.ok) throw new HttpError(400, "USER", r.error);
    return { ok: true };
  });
  route("POST", "/api/users/:id/reset", CAN.users, async ({ s, params, body }) => {
    const r = await auth.resetPassword(params[0], String(body.password ?? ""), { actor: s.user.username, role: "authorizer" });
    if (!r.ok) throw new HttpError(400, "USER", r.error);
    return { ok: true };
  });

  /* ---------- Despacho ---------- */
  return async function handle(req: http.IncomingMessage, res: http.ServerResponse, path: string, query: URLSearchParams) {
    try {
      const mutating = req.method !== "GET" && req.method !== "HEAD";
      if (mutating && !originOk(req)) throw new HttpError(403, "BAD_ORIGIN", "Origen no permitido.");

      if (req.method === "POST" && path === "/api/login") {
        const b = await readJson(req);
        const ip = String(req.headers["x-forwarded-for"] ?? req.socket.remoteAddress ?? "").split(",")[0].trim();
        const r = await auth.login(String(b.username ?? ""), String(b.password ?? ""), { ip, userAgent: String(req.headers["user-agent"] ?? "") });
        if (!r.ok) throw new HttpError(401, "CREDENTIALS", "Usuario o contraseña incorrectos, o la cuenta está bloqueada temporalmente.");
        return send(res, 200, { user: r.session.user, csrf: r.session.csrf, killSwitch: await store.killSwitchInfo() }, { "Set-Cookie": sessionCookie(req, r.token, 8 * 3600) });
      }

      const match = routes.map(r => ({ r, m: r.re.exec(path) })).find(x => x.m && x.r.method === req.method);
      if (!match) {
        if (routes.some(r => r.re.test(path))) throw new HttpError(405, "METHOD_NOT_ALLOWED", "Método no permitido.");
        throw new HttpError(404, "NOT_FOUND", "No existe.");
      }
      const s = await auth.getSession(cookieOf(req, COOKIE));
      if (!s) { res.setHeader("Set-Cookie", sessionCookie(req, "", 0)); throw new HttpError(401, "UNAUTHENTICATED", "Inicia sesión para continuar."); }
      if (mutating) { const t = String(req.headers["x-csrf-token"] ?? ""); if (!safeEq(t, s.csrf)) throw new HttpError(403, "BAD_CSRF", "Falta o no es válido el token de seguridad. Recarga la página."); }
      if (s.user.mustChange && !["/api/me", "/api/password", "/api/logout"].includes(path)) throw new HttpError(403, "MUST_CHANGE_PASSWORD", "Debes cambiar tu contraseña temporal antes de continuar.");
      if (!match.r.roles.includes(s.user.role as WebRole)) {
        await store.audit({ ...who(s), action: "web:forbidden", payload: { path } });
        throw new HttpError(403, "FORBIDDEN", "Tu rol no tiene permiso para esto.");
      }
      const body = mutating ? await readJson(req) : {};
      return send(res, 200, await match.r.h({ req, res, s, body, params: match.m!.slice(1), query }));
    } catch (e) {
      if (e instanceof HttpError) return send(res, e.status, { error: e.code, message: e.message });
      if (e instanceof ZodError) return send(res, 400, validationError(e));
      console.error("error en la API web:", (e as Error).message);
      return send(res, 500, { error: "INTERNAL_ERROR", message: "Ocurrió un error inesperado." });
    }
  };
}
export { WEB_ROLES };
