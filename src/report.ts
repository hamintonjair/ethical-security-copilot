import type { Store } from "./store.js";
import type { State } from "./state.js";
import { redact } from "./redact.js";

type Role = "authorizer" | "operator" | "analyst" | "agent" | "auditor";
const ORDER = ["info", "low", "medium", "high", "critical"];
export type ReportResult = { ok: true; text: string; findings: number } | { ok: false; error: string };

/**
 * Genera el informe. `advance` lleva el ciclo hasta "reported" (solo por transiciones válidas);
 * sin `advance` es una vista previa que no cambia nada.
 */
export async function buildReport(store: Store, o: { assessmentId: string; format: "markdown" | "json"; includeStates: string[]; advance: boolean; actor: string; role: Role }): Promise<ReportResult> {
  const rec = await store.getAssessment(o.assessmentId);
  if (!rec || !rec.signatureValid) return { ok: false, error: "NO_ACTIVE_ASSESSMENT" };
  const a = rec.a;
  const findings = (await store.listFindings(o.assessmentId)).filter(f => o.includeStates.includes(f.data.triage))
    .sort((x, y) => ORDER.indexOf(y.data.severity) - ORDER.indexOf(x.data.severity));
  if (o.advance) for (const next of ["verifying", "triage", "reported"] as State[]) if (a.state !== "halted" && a.state !== "closed") await store.transition(o.assessmentId, next, o.actor, o.role);
  const chain = await store.verifyAuditChain();
  const meta = { assessment: a.name, version: a.version, organization: a.authorizer.organization, window: a.window, scope: a.scope, exclusions: a.exclusions.map(e => ({ target: e.target, technique: e.technique })), auditChain: chain.ok ? "íntegra" : `ALTERADA en seq ${(chain as any).brokenAtSeq}` };
  let text: string;
  if (o.format === "json") text = JSON.stringify({ meta, findings: findings.map(f => ({ id: f.id, ...f.data })) }, null, 2);
  else {
    const L: string[] = [`# Informe: ${a.name}`, "", `- Organización autorizadora: ${a.authorizer.organization}`, `- Ventana: ${a.window.notBefore} → ${a.window.notAfter}`, `- Alcance: ${a.scope.map(s => s.value).join(", ")}`, `- Auditoría: ${meta.auditChain}`, "", `## Resumen`, "", "| Severidad | Hallazgos |", "|---|---|", ...ORDER.slice().reverse().map(s => `| ${s} | ${findings.filter(f => f.data.severity === s).length} |`), ""];
    for (const f of findings) {
      const x = f.data;
      L.push(`## ${x.title}`, "", `- **Activo:** ${x.asset}`, `- **Severidad:** ${x.severity} (CVSS ${x.cvssScore}, ${x.cvssVector})`, `- **Confianza:** ${x.confidence}`, `- **Triaje:** ${x.triage}`, "", "### Hechos observados", ...x.observedFacts.map((o: string) => `- ${o}`), "");
      if (x.riskHypotheses.length) L.push("### Hipótesis de riesgo (no verificadas)", ...x.riskHypotheses.map((o: string) => `- ${o}`), "");
      L.push("### Evidencia (redactada)", ...x.evidence.flatMap((e: any) => [`- ${e.description}`, "  ```", `  ${e.redactedContent.replace(/\n/g, "\n  ")}`, "  ```", ...e.reproSteps.map((s: string, i: number) => `  ${i + 1}. ${s}`)]), "", `### Impacto de negocio`, x.businessImpact, "", `### Recomendación`, x.recommendation, "");
    }
    text = L.join("\n");
  }
  text = redact(text, 500_000); // segunda barrera de sanitización
  await store.audit({ actor: o.actor, role: o.role, action: o.advance ? "report_generate" : "report_preview", assessmentId: o.assessmentId, payload: { format: o.format, findings: findings.length } });
  return { ok: true, text, findings: findings.length };
}
