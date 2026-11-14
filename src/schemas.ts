// Ethical Security Copilot — Etapa B: esquemas (Zod) y contratos del motor de autorización.
import { z } from "zod";

/* ---------- Roles ---------- */
export const Role = z.enum([
  "authorizer",  // humano responsable: crea/versiona autorizaciones y aprueba cambios de alcance
  "operator",    // humano que planifica y aprueba ejecuciones
  "analyst",     // registra hallazgos, genera reportes
  "agent",        // el LLM vía MCP: sin poder de autorizar ni de aprobar
  "auditor",     // solo lectura de logs y reportes
]);

/* ---------- Modos ---------- */
export const Mode = z.enum(["passive", "lab", "active"]);

/* ---------- Scope ---------- */
const Cidr = z.string().regex(/^[0-9a-fA-F:.]+\/\d{1,3}$/);
const Hostname = z.string().max(253).regex(/^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/i);

export const ScopeTarget = z.discriminatedUnion("type", [
  z.object({ type: z.literal("cidr"), value: Cidr }),
  z.object({ type: z.literal("ip"), value: z.string().ip() }),
  z.object({ type: z.literal("domain"), value: Hostname, includeSubdomains: z.boolean().default(false) }),
  z.object({ type: z.literal("url"), value: z.string().url(), pathPrefix: z.string().optional() }),
  z.object({ type: z.literal("device"), value: z.string().min(1).max(128) }),
]);

export const Exclusion = z.object({
  target: ScopeTarget.optional(),                 // activos prohibidos
  technique: z.string().min(1).max(64).optional(), // técnicas/módulos prohibidos
  reason: z.string().max(500),
}).refine(e => e.target || e.technique, "Debe excluir un activo o una técnica");

export const ExecutionWindow = z.object({
  notBefore: z.string().datetime(),
  notAfter: z.string().datetime(),
  allowedHours: z.object({ from: z.string().regex(/^\d{2}:\d{2}$/), to: z.string().regex(/^\d{2}:\d{2}$/), tz: z.string() }).optional(),
  maxRequestsPerSecond: z.number().int().min(1).max(1000),
  maxConcurrency: z.number().int().min(1).max(64),
  maxTotalRequests: z.number().int().min(1).optional(),
});

export const Authorizer = z.object({
  organization: z.string().min(2),
  name: z.string().min(2),
  email: z.string().email(),
  phone: z.string().optional(),
  emergencyContact: z.string().min(2),            // a quién avisar si algo sale mal
});

/* ---------- Assessment (autorización versionada, inmutable) ---------- */
export const AssessmentInput = z.object({
  name: z.string().min(3).max(120),
  authorizer: Authorizer,
  allowedModes: z.array(Mode).min(1),
  scope: z.array(ScopeTarget).min(1),
  exclusions: z.array(Exclusion).default([]),
  window: ExecutionWindow,
  allowedModules: z.array(z.string()).min(1),      // allowlist explícita de módulos
  testAccounts: z.array(z.object({ label: z.string(), secretRef: z.string() })).default([]), // solo referencias, nunca el secreto
  authorizationDocRef: z.string().optional(),     // referencia al documento/contrato firmado
});

export const Assessment = AssessmentInput.extend({
  id: z.string().uuid(),
  version: z.number().int().min(1),
  state: z.enum(["draft", "scope_validated", "planned", "approved", "executing", "verifying", "triage", "reported", "halted", "closed"]),
  contentHash: z.string(),                         // SHA-256 del contenido canónico
  signature: z.string(),                           // Ed25519/HMAC sobre contentHash
  createdBy: z.string(),
  createdAt: z.string().datetime(),
});

/* ---------- Decisión del Policy Engine ---------- */
export const DenyReason = z.enum([
  "NO_ACTIVE_ASSESSMENT", "SIGNATURE_INVALID", "TARGET_OUT_OF_SCOPE", "TARGET_EXCLUDED",
  "TECHNIQUE_EXCLUDED", "OUTSIDE_WINDOW", "RATE_LIMIT", "MODE_NOT_ALLOWED", "MODULE_NOT_ALLOWED",
  "LAB_TARGET_NOT_LOCAL", "KILL_SWITCH_ACTIVE", "APPROVAL_REQUIRED", "STATE_TRANSITION_INVALID",
  "DNS_RESOLVES_OUT_OF_SCOPE", "HARD_LIMIT",
]);

export const PolicyDecision = z.discriminatedUnion("allow", [
  z.object({ allow: z.literal(true), decisionId: z.string().uuid(), expiresAt: z.string().datetime() }),
  z.object({ allow: z.literal(false), decisionId: z.string().uuid(), reasons: z.array(DenyReason).min(1) }),
]);

export interface PolicyEngine {
  /** Se invoca antes de CADA operación; el Gateway revalida IP final al conectar. */
  check(req: {
    assessmentId: string; actor: z.infer<typeof Role>; mode: z.infer<typeof Mode>;
    module: string; target: z.infer<typeof ScopeTarget>; changesState: boolean;
    action?: string; planId?: string; approvalToken?: string; params?: Record<string, unknown>;
  }): Promise<z.infer<typeof PolicyDecision>>;
}

/* ---------- Módulos: capacidades declaradas ---------- */
export const ModuleManifest = z.object({
  id: z.string(),
  category: z.enum(["discovery", "surface", "webmobile", "verification"]),
  modes: z.array(Mode).min(1),
  changesState: z.boolean(),                       // true => confirmación interactiva obligatoria
  intrusive: z.boolean().default(false),
  runner: z.object({ image: z.string(), args: z.array(z.string()), timeoutSec: z.number().int().max(3600) }),
});

/* ---------- Tools MCP ---------- */
export const AssessmentCreateIn = AssessmentInput;
export const ScopeValidateIn = z.object({ assessmentId: z.string().uuid(), target: ScopeTarget });
export const ScanInitiateIn = z.object({
  assessmentId: z.string().uuid(),
  moduleId: z.string(),
  mode: Mode,
  targets: z.array(ScopeTarget).min(1).max(256),
  params: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).default({}),
});
export const ScanStopIn = z.object({
  assessmentId: z.string().uuid().optional(),      // omitido => detiene TODO
  reason: z.string().min(3).max(300),
});

/* ---------- Hallazgos ---------- */
export const Severity = z.enum(["info", "low", "medium", "high", "critical"]);
export const FindingInput = z.object({
  assessmentId: z.string().uuid(),
  title: z.string().min(5).max(200),
  asset: z.string(),
  severity: Severity,
  cvssVector: z.string().regex(/^CVSS:3\.[01]\/.+/),
  cvssScore: z.number().min(0).max(10),
  confidence: z.enum(["high", "medium", "low"]),
  observedFacts: z.array(z.string()).min(1),      // hechos observados
  riskHypotheses: z.array(z.string()).default([]), // hipótesis de riesgo (separadas)
  evidence: z.array(z.object({ description: z.string(), redactedContent: z.string().max(8000), reproSteps: z.array(z.string()) })).min(1),
  businessImpact: z.string(),
  recommendation: z.string(),
  triage: z.enum(["unverified", "confirmed", "false_positive", "accepted_risk"]).default("unverified"),
});
export const ReportGenerateIn = z.object({
  assessmentId: z.string().uuid(),
  format: z.enum(["markdown", "json"]),
  includeStates: z.array(z.enum(["confirmed", "unverified"])).default(["confirmed"]),
});

/* ---------- Incidentes (Respuesta a Incidentes / Defensa Activa) ----------
   Solo analiza evidencia que la organización aporta y genera reglas/informes para que ELLOS
   los apliquen en su propia infraestructura. No abre ninguna conexión de red. */
export const IncidentCreateIn = z.object({
  organization: z.string().min(1).max(200),
  contactName: z.string().min(1).max(200),
  contactEmail: z.string().email(),
  summary: z.string().min(5).max(2000),
  affectedAssets: z.array(z.string().max(200)).max(50).default([]),
});
export const IncidentEvidenceIn = z.object({
  incidentId: z.string().uuid(),
  kind: z.enum(["log", "email_headers", "other"]),
  description: z.string().min(1).max(300),
  content: z.string().min(1).max(50_000),
});
export const IncidentContainIn = z.object({
  incidentId: z.string().uuid(),
  ips: z.array(z.string()).max(500).default([]),
  domains: z.array(z.string()).max(200).default([]),
  targets: z.enum(["firewall", "nginx", "cloudflare", "all"]).default("all"),
});
export const IncidentReportIn = z.object({
  incidentId: z.string().uuid(),
  format: z.enum(["markdown", "json"]).default("markdown"),
});
export const IncidentStatus = z.enum(["open", "contained", "closed"]);

/* ---------- Módulo de IA (API propia, dentro de la plataforma) ----------
   Actúa con los mismos permisos que RolePermissions.agent: nunca abre ni cierra un incidente. */
export const AiConfigIn = z.object({
  enabled: z.boolean(),
  model: z.string().min(1).max(100),
  apiKey: z.string().min(10).max(300).optional(), // omitido => conserva la llave ya guardada
});
export const AiAssistIn = z.object({ question: z.string().min(1).max(4000) });

/* ---------- Auditoría (hash chain) ---------- */
export const AuditEntry = z.object({
  seq: z.number().int(),
  ts: z.string().datetime(),
  actor: z.string(),
  role: Role,
  action: z.string(),
  assessmentId: z.string().uuid().nullable(),
  decisionId: z.string().uuid().nullable(),
  payloadRedacted: z.string(),
  prevHash: z.string(),
  hash: z.string(),                                // SHA-256(prevHash || canonical(entry))
});

/* ---------- Permisos por rol ---------- */
export const RolePermissions: Record<z.infer<typeof Role>, string[]> = {
  authorizer: ["assessment_create", "scope_validate", "scan_stop", "incident_open", "incident_evidence_analyze", "incident_contain_plan", "incident_report"],
  operator:   ["scope_validate", "scan_initiate", "scan_stop", "approve_plan", "incident_open", "incident_evidence_analyze", "incident_contain_plan", "incident_report"],
  analyst:    ["scope_validate", "finding_create", "report_generate", "incident_evidence_analyze", "incident_contain_plan", "incident_report"],
  agent:      ["scope_validate", "scan_initiate", "scan_stop", "finding_create", "report_generate", "incident_evidence_analyze", "incident_contain_plan", "incident_report"], // nunca abre el caso ni cierra el incidente: eso lo decide un humano
  auditor:    ["audit_read", "report_generate", "incident_report"],
};
