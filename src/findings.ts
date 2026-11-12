import type { z } from "zod";
import type { FindingInput } from "./schemas.js";
import type { Store } from "./store.js";
import { redact } from "./redact.js";
import { normalizeHost, targetMatches, type Target } from "./scope.js";

export const SEVERITY_BANDS: Record<string, [number, number]> = { info: [0, 0], low: [0.1, 3.9], medium: [4, 6.9], high: [7, 8.9], critical: [9, 10] };
type Input = z.infer<typeof FindingInput>;
type Role = "authorizer" | "operator" | "analyst" | "agent" | "auditor";
export type FindingResult = { ok: true; findingId: string } | { ok: false; error: string; message?: string };

/** Reglas únicas para MCP y web: evaluación válida y en ejecución, severidad coherente con CVSS, activo dentro del alcance y evidencia redactada. */
export async function createFinding(store: Store, input: Input, actor: string, role: Role): Promise<FindingResult> {
  const rec = await store.getAssessment(input.assessmentId);
  if (!rec || !rec.signatureValid) return { ok: false, error: "NO_ACTIVE_ASSESSMENT" };
  if (!["executing", "verifying", "triage"].includes(rec.a.state)) return { ok: false, error: "STATE_TRANSITION_INVALID", message: "Solo se registran hallazgos tras ejecutar un módulo." };
  const [lo, hi] = SEVERITY_BANDS[input.severity];
  if (input.cvssScore < lo || input.cvssScore > hi) return { ok: false, error: "SEVERITY_CVSS_MISMATCH", message: `La severidad '${input.severity}' no corresponde a CVSS ${input.cvssScore}.` };
  const asset = input.asset.trim();
  const asTarget: Target | null = /^https?:\/\//i.test(asset) ? { type: "url", value: asset }
    : /^[\d.:a-f]+(\/\d+)?$/i.test(asset) && asset.includes(".") || asset.includes(":") && /^[\da-f:]+$/i.test(asset) ? (asset.includes("/") ? { type: "cidr", value: asset } : { type: "ip", value: asset })
    : /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(asset) ? { type: "domain", value: normalizeHost(asset) ?? asset, includeSubdomains: false } : null;
  const hostPort = /^(.+):(\d{1,5})$/.exec(asset); // "127.0.0.1:8080"
  const checkTarget = hostPort ? ({ type: "ip", value: hostPort[1] } as Target) : asTarget;
  if (checkTarget && !targetMatches(checkTarget, rec.a.scope)) return { ok: false, error: "TARGET_OUT_OF_SCOPE", message: "El activo del hallazgo no está en el alcance." };
  const clean = {
    ...input, title: redact(input.title, 200), asset: redact(asset, 300),
    observedFacts: input.observedFacts.map(f => redact(f, 1000)), riskHypotheses: input.riskHypotheses.map(f => redact(f, 1000)),
    evidence: input.evidence.map(e => ({ description: redact(e.description, 500), redactedContent: redact(e.redactedContent), reproSteps: e.reproSteps.map(s => redact(s, 500)) })),
    businessImpact: redact(input.businessImpact, 1000), recommendation: redact(input.recommendation, 1000),
  };
  const id = await store.addFinding(input.assessmentId, clean);
  await store.audit({ actor, role, action: "finding_create", assessmentId: input.assessmentId, payload: { id, severity: input.severity, asset: clean.asset } });
  return { ok: true, findingId: id };
}
