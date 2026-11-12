import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  AssessmentCreateIn, ScopeValidateIn, ScanInitiateIn, ScanStopIn, FindingInput, ReportGenerateIn, RolePermissions, Role,
} from "./schemas.js";
import { Store } from "./store.js";
import { PolicyEngine } from "./policy.js";
import { Gateway, GatewayDenied } from "./gateway.js";
import { builtinModules, type Module } from "./modules.js";
import { broadScopeProblem, type Target } from "./scope.js";
import { canonical } from "./crypto.js";
import { redact } from "./redact.js";
import type { State } from "./state.js";
import { createFinding } from "./findings.js";
import { buildReport } from "./report.js";

type RoleT = z.infer<typeof Role>;
const json = (o: unknown, isError = false) => ({ content: [{ type: "text" as const, text: JSON.stringify(o, null, 2) }], ...(isError ? { isError: true } : {}) });


export type RunRegistry = Map<string, { assessmentId: string; ctrl: AbortController }>;
/** `runs` se comparte entre instancias (transporte HTTP sin estado) para que scan_stop aborte ejecuciones iniciadas en otra petición. */
export interface ServerDeps { store: Store; role: RoleT; actor: string; modules?: Map<string, Module>; policy?: PolicyEngine; runs?: RunRegistry }

export function createServer(deps: ServerDeps) {
  const { store, role, actor } = deps;
  const modules = deps.modules ?? builtinModules();
  const policy = deps.policy ?? new PolicyEngine(store, { manifests: new Map([...modules].map(([k, m]) => [k, m.manifest])) });
  const gateway = new Gateway(policy);
  const running: RunRegistry = deps.runs ?? new Map();
  const server = new McpServer({ name: "ethical-security-copilot", version: "0.1.0" });

  /** Permiso por rol: el rol lo fija quien lanza el servidor, nunca el cliente/LLM. */
  const allowed = async (tool: string, assessmentId?: string) => {
    if (RolePermissions[role].includes(tool)) return null;
    await store.audit({ actor, role, action: `tool_denied:${tool}`, assessmentId, payload: { reason: "role" } });
    return json({ error: "ROLE_NOT_ALLOWED", message: `El rol '${role}' no puede usar ${tool}. Las autorizaciones y aprobaciones las hace un humano.` }, true);
  };

  /* 1. assessment_create */
  server.registerTool("assessment_create", {
    description: "Registra una evaluación con autorizador, alcance, exclusiones, ventana y límites. Solo el rol 'authorizer' (humano).",
    inputSchema: AssessmentCreateIn.shape,
  }, async input => {
    const d = await allowed("assessment_create"); if (d) return d;
    const broad = broadScopeProblem(input.scope as Target[]);
    if (broad) return json({ error: "SCOPE_TOO_BROAD", message: broad }, true);
    const a = await store.createAssessment(input, actor);
    await store.audit({ actor, role, action: "assessment_create", assessmentId: a.id, payload: { name: a.name, version: a.version, scope: a.scope.length } });
    return json({ assessmentId: a.id, version: a.version, state: a.state, contentHash: a.contentHash, next: "Un humano debe avanzar el ciclo (validación de alcance → planificación → aprobación) con el CLI." });
  });

  /* 2. scope_validate */
  server.registerTool("scope_validate", {
    description: "Verifica si un target (ip, cidr, dominio, url, dispositivo) está autorizado por la evaluación.",
    inputSchema: ScopeValidateIn.shape,
  }, async ({ assessmentId, target }) => {
    const d = await allowed("scope_validate", assessmentId); if (d) return d;
    return json(await policy.validateScope(assessmentId, target as Target, role));
  });

  /* 3. scan_initiate */
  server.registerTool("scan_initiate", {
    description: "Lanza un módulo (pasivo, laboratorio o activo). En modo activo o con módulos que cambian estado, primero devuelve un plan pendiente de aprobación humana; luego se reenvía con planId y approvalToken.",
    inputSchema: { ...ScanInitiateIn.shape, planId: z.string().uuid().optional(), approvalToken: z.string().optional() },
  }, async ({ assessmentId, moduleId, mode, targets, params, planId, approvalToken }) => {
    const d = await allowed("scan_initiate", assessmentId); if (d) return d;
    const mod = modules.get(moduleId);
    if (!mod) return json({ error: "MODULE_NOT_FOUND" }, true);
    const rec = await store.getAssessment(assessmentId);
    if (!rec) return json({ error: "NO_ACTIVE_ASSESSMENT" }, true);
    const needsApproval = mode === "active" || mod.manifest.changesState;
    const limits = { maxRequestsPerSecond: rec.a.window.maxRequestsPerSecond, maxConcurrency: rec.a.window.maxConcurrency, notAfter: rec.a.window.notAfter, timeoutSec: mod.manifest.runner.timeoutSec };

    // Todos los targets deben estar autorizados ANTES de planificar o ejecutar
    for (const t of targets as Target[]) {
      const v = await policy.validateScope(assessmentId, t, role);
      if (!v.authorized) { await store.audit({ actor, role, action: "scan_refused", assessmentId, payload: { moduleId, target: t, reasons: v.reasons } }); return json({ status: "denied", target: t, reasons: v.reasons }, true); }
    }

    if (needsApproval && !planId) {
      const id = await store.createPlan({ assessmentId, moduleId, mode, targets, limits });
      await store.audit({ actor, role, action: "plan:created", assessmentId, payload: { planId: id, moduleId, mode } });
      return json({ status: "pending_approval", planId: id, plan: { module: moduleId, mode, targets, limits, changesState: mod.manifest.changesState }, next: "Un humano (operator) debe aprobar este plan con el CLI y entregar el token de un solo uso." });
    }
    if (planId) {
      const plan = await store.getPlan(planId);
      const planned = (plan?.targets ?? []).map((t: unknown) => canonical(t));
      if (!plan || plan.assessment_id !== assessmentId || plan.module_id !== moduleId || plan.mode !== mode || !(targets as Target[]).every(t => planned.includes(canonical(t))))
        return json({ status: "denied", reasons: ["APPROVAL_REQUIRED"], message: "El plan no coincide con lo solicitado." }, true);
    }

    const ctrl = new AbortController(); const runId = crypto.randomUUID();
    running.set(runId, { assessmentId, ctrl });
    const signal = AbortSignal.any([ctrl.signal, AbortSignal.timeout(mod.manifest.runner.timeoutSec * 1000)]);
    const facts: string[] = []; const suggestions: unknown[] = []; const denials: unknown[] = [];
    try {
      let first = true;
      for (const target of targets as Target[]) {
        if (signal.aborted) break;
        const req = { assessmentId, actor: role, mode, module: moduleId, target, changesState: mod.manifest.changesState, params };
        const dec = first && needsApproval ? await policy.check({ ...req, planId, approvalToken }) : first ? await policy.check(req) : await policy.recheck(req);
        first = false;
        if (!dec.allow) { denials.push({ target, reasons: dec.reasons }); continue; }
        const st = (await store.getAssessment(assessmentId))!.a.state as State;
        if (st === "approved") await store.transition(assessmentId, "executing", actor, role);
        try {
          const r = await mod.run({ grant: { assessmentId, mode, actor: role as any, module: moduleId }, gateway, target, params, signal, maxConcurrency: rec.a.window.maxConcurrency });
          facts.push(...r.facts); suggestions.push(...r.suggestions);
        } catch (e) {
          if (e instanceof GatewayDenied) denials.push({ target, reasons: e.reasons });
          else denials.push({ target, error: signal.aborted ? "ABORTED_OR_TIMEOUT" : (e as Error).message });
        }
      }
    } finally { running.delete(runId); }

    const out = { status: signal.aborted ? "aborted" : denials.length && !facts.length ? "denied" : "completed", facts: facts.slice(0, 200).map(f => redact(f, 500)), suggestions: suggestions.slice(0, 100), denials };
    await store.audit({ actor, role, action: "scan:finished", assessmentId, payload: { moduleId, mode, status: out.status, facts: facts.length, denials: denials.length } });
    return json(out, out.status === "denied");
  });

  /* 4. scan_stop (kill switch) */
  server.registerTool("scan_stop", {
    description: "Kill switch: detiene de inmediato las ejecuciones en curso y bloquea nuevas hasta que un humano (authorizer) lo libere. Sin assessmentId detiene todo.",
    inputSchema: ScanStopIn.shape,
  }, async ({ assessmentId, reason }) => {
    const d = await allowed("scan_stop", assessmentId); if (d) return d;
    let n = 0;
    for (const r of running.values()) if (!assessmentId || r.assessmentId === assessmentId) { r.ctrl.abort(); n++; }
    await store.activateKillSwitch(reason, actor, role, assessmentId);
    return json({ killSwitch: "active", abortedRuns: n, note: "Solo un authorizer humano puede liberarlo; la evaluación detenida requiere una nueva versión de la autorización." });
  });

  /* 5. finding_create */
  server.registerTool("finding_create", {
    description: "Registra un hallazgo (hechos observados separados de hipótesis, evidencia redactada, CVSS y confianza).",
    inputSchema: FindingInput.shape,
  }, async input => {
    const d = await allowed("finding_create", input.assessmentId); if (d) return d;
    const r = await createFinding(store, input, actor, role);
    return r.ok ? json({ findingId: r.findingId, stored: true }) : json({ error: r.error, ...(r.message ? { message: r.message } : {}) }, true);
  });

  /* 6. report_generate */
  server.registerTool("report_generate", {
    description: "Exporta resultados en Markdown o JSON, sanitizando datos sensibles y separando hechos de hipótesis.",
    inputSchema: ReportGenerateIn.shape,
  }, async ({ assessmentId, format, includeStates }) => {
    const d = await allowed("report_generate", assessmentId); if (d) return d;
    const r = await buildReport(store, { assessmentId, format, includeStates: includeStates as string[], advance: true, actor, role });
    return r.ok ? { content: [{ type: "text" as const, text: r.text }] } : json({ error: r.error }, true);
  });

  return { server, policy, store };
}
