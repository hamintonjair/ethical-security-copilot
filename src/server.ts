import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  AssessmentCreateIn, ScopeValidateIn, ScanInitiateIn, ScanStopIn, FindingInput, ReportGenerateIn, RolePermissions, Role,
} from "./schemas.js";
import { Store } from "./store.js";
import { PolicyEngine } from "./policy.js";
import { Gateway, GatewayDenied } from "./gateway.js";
import { builtinModules, type Module } from "./modules.js";
import { targetMatches, normalizeHost, type Target } from "./scope.js";
import { canonical } from "./crypto.js";
import { redact } from "./redact.js";
import type { State } from "./state.js";

type RoleT = z.infer<typeof Role>;
const json = (o: unknown, isError = false) => ({ content: [{ type: "text" as const, text: JSON.stringify(o, null, 2) }], ...(isError ? { isError: true } : {}) });

const SEVERITY_BANDS: Record<string, [number, number]> = { info: [0, 0], low: [0.1, 3.9], medium: [4, 6.9], high: [7, 8.9], critical: [9, 10] };

export interface ServerDeps { store: Store; role: RoleT; actor: string; modules?: Map<string, Module>; policy?: PolicyEngine }

export function createServer(deps: ServerDeps) {
  const { store, role, actor } = deps;
  const modules = deps.modules ?? builtinModules();
  const policy = deps.policy ?? new PolicyEngine(store, { manifests: new Map([...modules].map(([k, m]) => [k, m.manifest])) });
  const gateway = new Gateway(policy);
  const running = new Map<string, { assessmentId: string; ctrl: AbortController }>();
  const server = new McpServer({ name: "ethical-security-copilot", version: "0.1.0" });

  /** Permiso por rol: el rol lo fija quien lanza el servidor, nunca el cliente/LLM. */
  const allowed = (tool: string, assessmentId?: string) => {
    if (RolePermissions[role].includes(tool)) return null;
    store.audit({ actor, role, action: `tool_denied:${tool}`, assessmentId, payload: { reason: "role" } });
    return json({ error: "ROLE_NOT_ALLOWED", message: `El rol '${role}' no puede usar ${tool}. Las autorizaciones y aprobaciones las hace un humano.` }, true);
  };

  /* 1. assessment_create */
  server.registerTool("assessment_create", {
    description: "Registra una evaluación con autorizador, alcance, exclusiones, ventana y límites. Solo el rol 'authorizer' (humano).",
    inputSchema: AssessmentCreateIn.shape,
  }, async input => {
    const d = allowed("assessment_create"); if (d) return d;
    const a = store.createAssessment(input, actor);
    store.audit({ actor, role, action: "assessment_create", assessmentId: a.id, payload: { name: a.name, version: a.version, scope: a.scope.length } });
    return json({ assessmentId: a.id, version: a.version, state: a.state, contentHash: a.contentHash, next: "Un humano debe avanzar el ciclo (validación de alcance → planificación → aprobación) con el CLI." });
  });

  /* 2. scope_validate */
  server.registerTool("scope_validate", {
    description: "Verifica si un target (ip, cidr, dominio, url, dispositivo) está autorizado por la evaluación.",
    inputSchema: ScopeValidateIn.shape,
  }, async ({ assessmentId, target }) => {
    const d = allowed("scope_validate", assessmentId); if (d) return d;
    return json(policy.validateScope(assessmentId, target as Target, role));
  });

  /* 3. scan_initiate */
  server.registerTool("scan_initiate", {
    description: "Lanza un módulo (pasivo, laboratorio o activo). En modo activo o con módulos que cambian estado, primero devuelve un plan pendiente de aprobación humana; luego se reenvía con planId y approvalToken.",
    inputSchema: { ...ScanInitiateIn.shape, planId: z.string().uuid().optional(), approvalToken: z.string().optional() },
  }, async ({ assessmentId, moduleId, mode, targets, params, planId, approvalToken }) => {
    const d = allowed("scan_initiate", assessmentId); if (d) return d;
    const mod = modules.get(moduleId);
    if (!mod) return json({ error: "MODULE_NOT_FOUND" }, true);
    const rec = store.getAssessment(assessmentId);
    if (!rec) return json({ error: "NO_ACTIVE_ASSESSMENT" }, true);
    const needsApproval = mode === "active" || mod.manifest.changesState;
    const limits = { maxRequestsPerSecond: rec.a.window.maxRequestsPerSecond, maxConcurrency: rec.a.window.maxConcurrency, notAfter: rec.a.window.notAfter, timeoutSec: mod.manifest.runner.timeoutSec };

    // Todos los targets deben estar autorizados ANTES de planificar o ejecutar
    for (const t of targets as Target[]) {
      const v = policy.validateScope(assessmentId, t, role);
      if (!v.authorized) { store.audit({ actor, role, action: "scan_refused", assessmentId, payload: { moduleId, target: t, reasons: v.reasons } }); return json({ status: "denied", target: t, reasons: v.reasons }, true); }
    }

    if (needsApproval && !planId) {
      const id = store.createPlan({ assessmentId, moduleId, mode, targets, limits });
      store.audit({ actor, role, action: "plan:created", assessmentId, payload: { planId: id, moduleId, mode } });
      return json({ status: "pending_approval", planId: id, plan: { module: moduleId, mode, targets, limits, changesState: mod.manifest.changesState }, next: "Un humano (operator) debe aprobar este plan con el CLI y entregar el token de un solo uso." });
    }
    if (planId) {
      const plan = store.getPlan(planId);
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
        const st = store.getAssessment(assessmentId)!.a.state as State;
        if (st === "approved") store.transition(assessmentId, "executing", actor, role);
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
    store.audit({ actor, role, action: "scan:finished", assessmentId, payload: { moduleId, mode, status: out.status, facts: facts.length, denials: denials.length } });
    return json(out, out.status === "denied");
  });

  /* 4. scan_stop (kill switch) */
  server.registerTool("scan_stop", {
    description: "Kill switch: detiene de inmediato las ejecuciones en curso y bloquea nuevas hasta que un humano (authorizer) lo libere. Sin assessmentId detiene todo.",
    inputSchema: ScanStopIn.shape,
  }, async ({ assessmentId, reason }) => {
    const d = allowed("scan_stop", assessmentId); if (d) return d;
    let n = 0;
    for (const r of running.values()) if (!assessmentId || r.assessmentId === assessmentId) { r.ctrl.abort(); n++; }
    store.activateKillSwitch(reason, actor, role, assessmentId);
    return json({ killSwitch: "active", abortedRuns: n, note: "Solo un authorizer humano puede liberarlo; la evaluación detenida requiere una nueva versión de la autorización." });
  });

  /* 5. finding_create */
  server.registerTool("finding_create", {
    description: "Registra un hallazgo (hechos observados separados de hipótesis, evidencia redactada, CVSS y confianza).",
    inputSchema: FindingInput.shape,
  }, async input => {
    const d = allowed("finding_create", input.assessmentId); if (d) return d;
    const rec = store.getAssessment(input.assessmentId);
    if (!rec || !rec.signatureValid) return json({ error: "NO_ACTIVE_ASSESSMENT" }, true);
    if (!["executing", "verifying", "triage"].includes(rec.a.state)) return json({ error: "STATE_TRANSITION_INVALID", message: "Solo se registran hallazgos tras ejecutar un módulo." }, true);
    const [lo, hi] = SEVERITY_BANDS[input.severity];
    if (input.cvssScore < lo || input.cvssScore > hi) return json({ error: "SEVERITY_CVSS_MISMATCH", message: `La severidad '${input.severity}' no corresponde a CVSS ${input.cvssScore}.` }, true);
    const asset = input.asset.trim();
    const asTarget: Target | null = /^https?:\/\//i.test(asset) ? { type: "url", value: asset }
      : /^[\d.:a-f]+(\/\d+)?$/i.test(asset) && asset.includes(".") || asset.includes(":") && /^[\da-f:]+$/i.test(asset) ? (asset.includes("/") ? { type: "cidr", value: asset } : { type: "ip", value: asset })
      : /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(asset) ? { type: "domain", value: normalizeHost(asset) ?? asset, includeSubdomains: false } : null;
    const hostPort = /^(.+):(\d{1,5})$/.exec(asset); // "127.0.0.1:8080"
    const checkTarget = hostPort ? ({ type: "ip", value: hostPort[1] } as Target) : asTarget;
    if (checkTarget && !targetMatches(checkTarget, rec.a.scope)) return json({ error: "TARGET_OUT_OF_SCOPE", message: "El activo del hallazgo no está en el alcance." }, true);
    const clean = {
      ...input, title: redact(input.title, 200), asset: redact(asset, 300),
      observedFacts: input.observedFacts.map(f => redact(f, 1000)), riskHypotheses: input.riskHypotheses.map(f => redact(f, 1000)),
      evidence: input.evidence.map(e => ({ description: redact(e.description, 500), redactedContent: redact(e.redactedContent), reproSteps: e.reproSteps.map(s => redact(s, 500)) })),
      businessImpact: redact(input.businessImpact, 1000), recommendation: redact(input.recommendation, 1000),
    };
    const id = store.addFinding(input.assessmentId, clean);
    store.audit({ actor, role, action: "finding_create", assessmentId: input.assessmentId, payload: { id, severity: input.severity, asset: clean.asset } });
    return json({ findingId: id, stored: true });
  });

  /* 6. report_generate */
  server.registerTool("report_generate", {
    description: "Exporta resultados en Markdown o JSON, sanitizando datos sensibles y separando hechos de hipótesis.",
    inputSchema: ReportGenerateIn.shape,
  }, async ({ assessmentId, format, includeStates }) => {
    const d = allowed("report_generate", assessmentId); if (d) return d;
    const rec = store.getAssessment(assessmentId);
    if (!rec || !rec.signatureValid) return json({ error: "NO_ACTIVE_ASSESSMENT" }, true);
    const a = rec.a;
    const order = ["info", "low", "medium", "high", "critical"];
    const findings = store.listFindings(assessmentId).filter(f => (includeStates as string[]).includes(f.data.triage))
      .sort((x, y) => order.indexOf(y.data.severity) - order.indexOf(x.data.severity));
    // Avanza el ciclo hasta "reportado" solo por transiciones válidas
    for (const next of ["verifying", "triage", "reported"] as State[]) if (a.state !== "halted" && a.state !== "closed") store.transition(assessmentId, next, actor, role);
    const chain = store.verifyAuditChain();
    const meta = { assessment: a.name, version: a.version, organization: a.authorizer.organization, window: a.window, scope: a.scope, exclusions: a.exclusions.map(e => ({ target: e.target, technique: e.technique })), auditChain: chain.ok ? "íntegra" : `ALTERADA en seq ${(chain as any).brokenAtSeq}` };
    let text: string;
    if (format === "json") text = JSON.stringify({ meta, findings: findings.map(f => ({ id: f.id, ...f.data })) }, null, 2);
    else {
      const L: string[] = [`# Informe: ${a.name}`, "", `- Organización autorizadora: ${a.authorizer.organization}`, `- Ventana: ${a.window.notBefore} → ${a.window.notAfter}`, `- Alcance: ${a.scope.map(s => s.value).join(", ")}`, `- Auditoría: ${meta.auditChain}`, "", `## Resumen`, "", "| Severidad | Hallazgos |", "|---|---|", ...order.slice().reverse().map(s => `| ${s} | ${findings.filter(f => f.data.severity === s).length} |`), ""];
      for (const f of findings) {
        const x = f.data;
        L.push(`## ${x.title}`, "", `- **Activo:** ${x.asset}`, `- **Severidad:** ${x.severity} (CVSS ${x.cvssScore}, ${x.cvssVector})`, `- **Confianza:** ${x.confidence}`, `- **Triaje:** ${x.triage}`, "", "### Hechos observados", ...x.observedFacts.map((o: string) => `- ${o}`), "");
        if (x.riskHypotheses.length) L.push("### Hipótesis de riesgo (no verificadas)", ...x.riskHypotheses.map((o: string) => `- ${o}`), "");
        L.push("### Evidencia (redactada)", ...x.evidence.flatMap((e: any) => [`- ${e.description}`, "  ```", `  ${e.redactedContent.replace(/\n/g, "\n  ")}`, "  ```", ...e.reproSteps.map((s: string, i: number) => `  ${i + 1}. ${s}`)]), "", `### Impacto de negocio`, x.businessImpact, "", `### Recomendación`, x.recommendation, "");
      }
      text = L.join("\n");
    }
    text = redact(text, 500_000); // segunda barrera de sanitización
    store.audit({ actor, role, action: "report_generate", assessmentId, payload: { format, findings: findings.length } });
    return { content: [{ type: "text" as const, text }] };
  });

  return { server, policy, store };
}
