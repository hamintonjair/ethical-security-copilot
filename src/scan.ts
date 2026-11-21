// Ejecución de módulos (scan_initiate) y detención de emergencia (scan_stop): la MISMA lógica que
// antes vivía solo dentro del servidor MCP, ahora compartida con la consola web y con el módulo de
// IA interno — para que las comprobaciones de la política (alcance, ventana, ritmo, plan aprobado)
// se apliquen exactamente igual sin importar quién llama. Nada de esto se salta la aprobación humana
// de un plan: si el módulo cambia estado o el modo es "active", sigue devolviendo "pending_approval".
import { randomUUID } from "node:crypto";
import type { Store } from "./store.js";
import type { PolicyEngine } from "./policy.js";
import type { Gateway } from "./gateway.js";
import { GatewayDenied } from "./gateway.js";
import { builtinModules, type Module } from "./modules.js";
import type { Target } from "./scope.js";
import { canonical } from "./crypto.js";
import { redact } from "./redact.js";
import type { State } from "./state.js";
import type { RunRegistry } from "./server.js";

export type RoleT = "authorizer" | "operator" | "analyst" | "agent" | "auditor";

export interface ScanInitiateArgs {
  assessmentId: string; moduleId: string; mode: "passive" | "lab" | "active"; targets: Target[];
  params?: Record<string, string | number | boolean>; planId?: string; approvalToken?: string;
}
export type ScanInitiateResult =
  | { error: "MODULE_NOT_FOUND" | "NO_ACTIVE_ASSESSMENT" }
  | { status: "denied"; target?: Target; reasons: string[]; message?: string }
  | { status: "pending_approval"; planId: string; plan: unknown; next: string }
  | { status: "completed" | "aborted"; facts: string[]; suggestions: unknown[]; denials: unknown[] };

export interface ScanDeps { store: Store; policy: PolicyEngine; gateway: Gateway; modules?: Map<string, Module>; running: RunRegistry }

export async function runScanInitiate(deps: ScanDeps, role: RoleT, actor: string, args: ScanInitiateArgs): Promise<ScanInitiateResult> {
  const { store, policy, gateway, running } = deps;
  const modules = deps.modules ?? builtinModules();
  const { assessmentId, moduleId, mode, targets, planId, approvalToken } = args;
  const params = args.params ?? {};
  const mod = modules.get(moduleId);
  if (!mod) return { error: "MODULE_NOT_FOUND" };
  const rec = await store.getAssessment(assessmentId);
  if (!rec) return { error: "NO_ACTIVE_ASSESSMENT" };
  const needsApproval = mode === "active" || mod.manifest.changesState;
  const limits = { maxRequestsPerSecond: rec.a.window.maxRequestsPerSecond, maxConcurrency: rec.a.window.maxConcurrency, notAfter: rec.a.window.notAfter, timeoutSec: mod.manifest.runner.timeoutSec };

  // Todos los targets deben estar autorizados ANTES de planificar o ejecutar.
  for (const t of targets) {
    const v = await policy.validateScope(assessmentId, t, role);
    if (!v.authorized) { await store.audit({ actor, role, action: "scan_refused", assessmentId, payload: { moduleId, target: t, reasons: v.reasons } }); return { status: "denied", target: t, reasons: v.reasons }; }
  }

  if (needsApproval && !planId) {
    const id = await store.createPlan({ assessmentId, moduleId, mode, targets, limits });
    await store.audit({ actor, role, action: "plan:created", assessmentId, payload: { planId: id, moduleId, mode } });
    return { status: "pending_approval", planId: id, plan: { module: moduleId, mode, targets, limits, changesState: mod.manifest.changesState }, next: "Un humano (operator) debe aprobar este plan con el CLI y entregar el token de un solo uso." };
  }
  if (planId) {
    const plan = await store.getPlan(planId);
    const planned = (plan?.targets ?? []).map((t: unknown) => canonical(t));
    if (!plan || plan.assessment_id !== assessmentId || plan.module_id !== moduleId || plan.mode !== mode || !targets.every(t => planned.includes(canonical(t))))
      return { status: "denied", reasons: ["APPROVAL_REQUIRED"], message: "El plan no coincide con lo solicitado." };
  }

  const ctrl = new AbortController(); const runId = randomUUID();
  running.set(runId, { assessmentId, ctrl });
  const signal = AbortSignal.any([ctrl.signal, AbortSignal.timeout(mod.manifest.runner.timeoutSec * 1000)]);
  const facts: string[] = []; const suggestions: unknown[] = []; const denials: unknown[] = [];
  try {
    let first = true;
    for (const target of targets) {
      if (signal.aborted) break;
      const req = { assessmentId, actor: role, mode, module: moduleId, target, changesState: mod.manifest.changesState, params };
      const admit = first && needsApproval ? () => policy.check({ ...req, planId, approvalToken }) : first ? () => policy.check(req) : () => policy.recheck(req);
      first = false;
      // Igual que el Gateway: si solo falla por ritmo, se espera y se reintenta en vez de negar la operación.
      let dec = await admit();
      for (let i = 0; !dec.allow && dec.reasons.length === 1 && dec.reasons[0] === "RATE_LIMIT" && i < 60 && !signal.aborted; i++) { await new Promise(r => setTimeout(r, 200)); dec = await admit(); }
      if (!dec.allow) { denials.push({ target, reasons: dec.reasons }); continue; }
      const st = (await store.getAssessment(assessmentId))!.a.state as State;
      if (st === "approved") await store.transition(assessmentId, "executing", actor, role);
      try {
        const r = await mod.run({ grant: { assessmentId, mode, actor: role as "operator" | "agent" | "authorizer" | "analyst" | "auditor", module: moduleId }, gateway, target, params, signal, maxConcurrency: rec.a.window.maxConcurrency });
        facts.push(...r.facts); suggestions.push(...r.suggestions);
      } catch (e) {
        if (e instanceof GatewayDenied) denials.push({ target, reasons: e.reasons });
        else denials.push({ target, error: signal.aborted ? "ABORTED_OR_TIMEOUT" : (e as Error).message });
      }
    }
  } finally { running.delete(runId); }

  const status = (signal.aborted ? "aborted" : denials.length && !facts.length ? "denied" : "completed") as "aborted" | "denied" | "completed";
  const out = { status, facts: facts.slice(0, 200).map(f => redact(f, 500)), suggestions: suggestions.slice(0, 100), denials };
  await store.audit({ actor, role, action: "scan:finished", assessmentId, payload: { moduleId, mode, status: out.status, facts: facts.length, denials: denials.length } });
  return out as ScanInitiateResult;
}

export async function runScanStop(deps: { store: Store; running: RunRegistry }, role: RoleT, actor: string, assessmentId: string | undefined, reason: string) {
  let n = 0;
  for (const r of deps.running.values()) if (!assessmentId || r.assessmentId === assessmentId) { r.ctrl.abort(); n++; }
  await deps.store.activateKillSwitch(reason, actor, role, assessmentId);
  return { killSwitch: "active" as const, abortedRuns: n, note: "Solo un authorizer humano puede liberarlo; la evaluación detenida requiere una nueva versión de la autorización." };
}
