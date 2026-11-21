import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  AssessmentCreateIn, ScopeValidateIn, ScanInitiateIn, ScanStopIn, FindingInput, ReportGenerateIn, RolePermissions, Role,
  IncidentCreateIn, IncidentEvidenceIn, IncidentContainIn, IncidentReportIn, IncidentTypesIn, IncidentTargetsIn,
  SupplyChainAnalyzeIn,
} from "./schemas.js";
import { Store } from "./store.js";
import { PolicyEngine } from "./policy.js";
import { Gateway } from "./gateway.js";
import { builtinModules, type Module } from "./modules.js";
import { broadScopeProblem, type Target } from "./scope.js";
import { redact } from "./redact.js";
import { createFinding } from "./findings.js";
import { buildReport } from "./report.js";
import { runScanInitiate, runScanStop } from "./scan.js";
import { analyzeLog, analyzeEmailHeaders, containmentRules, buildIncidentReport, suggestIncidentTypes, TYPE_GUIDANCE, MAX_EVIDENCE_CHARS } from "./incident.js";
import { parseManifest, checkVulnerabilities, MAX_MANIFEST_CHARS } from "./supplychain.js";

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
    const r = await runScanInitiate({ store, policy, gateway, modules, running }, role, actor, { assessmentId, moduleId, mode, targets: targets as Target[], params, planId, approvalToken });
    if ("error" in r) return json(r, true);
    return json(r, r.status === "denied");
  });

  /* 4. scan_stop (kill switch) */
  server.registerTool("scan_stop", {
    description: "Kill switch: detiene de inmediato las ejecuciones en curso y bloquea nuevas hasta que un humano (authorizer) lo libere. Sin assessmentId detiene todo.",
    inputSchema: ScanStopIn.shape,
  }, async ({ assessmentId, reason }) => {
    const d = await allowed("scan_stop", assessmentId); if (d) return d;
    return json(await runScanStop({ store, running }, role, actor, assessmentId, reason));
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

  /* 7. incident_open — solo humanos (authorizer/operator) abren el caso */
  server.registerTool("incident_open", {
    description: "Abre un caso de Respuesta a Incidentes / Defensa Activa (organización bajo ataque ahora mismo). No ejecuta nada en ninguna red.",
    inputSchema: IncidentCreateIn.shape,
  }, async (input) => {
    const d = await allowed("incident_open"); if (d) return d;
    const inc = await store.createIncident(input, actor);
    return json({ incidentId: inc.id, status: inc.status });
  });

  /* 8. incident_evidence_analyze — analiza lo que la organización pega (log o cabeceras de correo); nunca abre red */
  server.registerTool("incident_evidence_analyze", {
    description: "Analiza evidencia aportada (líneas de log o cabeceras de correo) para extraer IOCs y patrones de ataque. Solo lee el texto que se le pasa; no se conecta a ninguna red.",
    inputSchema: IncidentEvidenceIn.shape,
  }, async ({ incidentId, kind, description, content }) => {
    const d = await allowed("incident_evidence_analyze", incidentId); if (d) return d;
    if (content.length > MAX_EVIDENCE_CHARS) return json({ error: "CONTENT_TOO_LARGE", message: `Máximo ${MAX_EVIDENCE_CHARS} caracteres.` }, true);
    const r = kind === "email_headers" ? analyzeEmailHeaders(content) : analyzeLog(content);
    const redacted = redact(content, 8000);
    const saved = await store.addIncidentEvidence(incidentId, { kind, description, redactedContent: redacted, iocs: r.iocs }, actor);
    if (saved === null) return json({ error: "INCIDENT_NOT_FOUND" }, true);
    if (saved === "CLOSED") return json({ error: "INCIDENT_CLOSED", message: "Este incidente ya está cerrado." }, true);
    const suggestedTypes = suggestIncidentTypes(kind, r.patterns).map((s) => ({ ...s, guidance: TYPE_GUIDANCE[s.type] }));
    return json({ facts: r.facts, patterns: r.patterns, iocs: r.iocs, evidenceId: saved.id, suggestedTypes,
      note: suggestedTypes.length ? "Son solo sugerencias; pídele al humano que confirme antes de marcarlas con incident_types_set." : undefined });
  });

  /* 8b. incident_types_set — el humano decide los tipos; la IA solo puede ejecutarlo tras pedírselo explícitamente */
  server.registerTool("incident_types_set", {
    description: "Marca (o reemplaza) los tipos de incidente del caso, tal como el humano los confirme. No se debe llamar sin que el humano haya aprobado explícitamente cada tipo.",
    inputSchema: IncidentTypesIn.extend({ incidentId: z.string().uuid() }).shape,
  }, async ({ incidentId, types }) => {
    const d = await allowed("incident_types_set", incidentId); if (d) return d;
    const ok = await store.setIncidentTypes(incidentId, types, actor, role);
    if (!ok) return json({ error: "NOT_FOUND_OR_CLOSED" }, true);
    return json({ types, guidance: Object.fromEntries(types.map((t) => [t, TYPE_GUIDANCE[t as keyof typeof TYPE_GUIDANCE]])) });
  });

  /* 8c. incident_targets_set — el humano marca qué herramientas de bloqueo ya tiene disponibles para este caso */
  server.registerTool("incident_targets_set", {
    description: "Marca (o reemplaza) las herramientas de bloqueo (firewall/iptables-ufw, nginx, Cloudflare) que el equipo ya tiene disponibles para este caso. Solo preselecciona el plan de contención; no aplica nada. No se debe llamar sin que el humano haya confirmado explícitamente cuáles usar.",
    inputSchema: IncidentTargetsIn.extend({ incidentId: z.string().uuid() }).shape,
  }, async ({ incidentId, targets }) => {
    const d = await allowed("incident_targets_set", incidentId); if (d) return d;
    const ok = await store.setIncidentContainmentTargets(incidentId, targets, actor, role);
    if (!ok) return json({ error: "NOT_FOUND_OR_CLOSED" }, true);
    return json({ containmentTargets: targets });
  });

  /* 9. incident_contain_plan — genera reglas; SIEMPRE para que el propio equipo las aplique en su infraestructura */
  server.registerTool("incident_contain_plan", {
    description: "Genera reglas de bloqueo (firewall, nginx, Cloudflare) a partir de IPs/dominios atacantes, para que el equipo de la organización las aplique en SU PROPIA infraestructura. No las ejecuta ni se conecta a ningún sistema.",
    inputSchema: IncidentContainIn.shape,
  }, async ({ incidentId, ips, domains, targets }) => {
    const d = await allowed("incident_contain_plan", incidentId); if (d) return d;
    const rec = await store.getIncident(incidentId);
    if (!rec) return json({ error: "INCIDENT_NOT_FOUND" }, true);
    const rules = containmentRules(ips, domains, targets);
    await store.audit({ actor, role, action: "incident:contain_plan", assessmentId: incidentId, payload: { ips: ips.length, domains: domains.length, targets } });
    return json({ rules, note: "Estas reglas no se han aplicado en ningún lado. Revísalas y aplícalas tú mismo en tu firewall, tu nginx o tu panel de Cloudflare." });
  });

  /* 10. incident_report */
  server.registerTool("incident_report", {
    description: "Genera el informe del incidente: IOCs acumulados, línea de tiempo de evidencia y a quién reportarlo.",
    inputSchema: IncidentReportIn.shape,
  }, async ({ incidentId, format }) => {
    const d = await allowed("incident_report", incidentId); if (d) return d;
    const rec = await store.getIncident(incidentId);
    if (!rec) return json({ error: "INCIDENT_NOT_FOUND" }, true);
    const aiHistory = await store.listAiMessages("incident", incidentId);
    const text = buildIncidentReport(rec.incident, rec.evidence, format, aiHistory);
    return { content: [{ type: "text" as const, text }] };
  });

  /* 11. supply_chain_analyze — analiza manifiestos de dependencias (SBOM) y los cruza con OSV.dev; nunca instala ni ejecuta nada */
  server.registerTool("supply_chain_analyze", {
    description: "Analiza un manifiesto de dependencias que el usuario pega (package-lock.json, package.json, requirements.txt, o una lista manual 'nombre@versión') y lo cruza con OSV.dev para detectar vulnerabilidades conocidas (A03). Solo lee el texto dado; no instala ni ejecuta nada.",
    inputSchema: SupplyChainAnalyzeIn.shape,
  }, async ({ assessmentId, kind, content, osvEcosystem }) => {
    const d = await allowed("supply_chain_analyze", assessmentId); if (d) return d;
    if (content.length > MAX_MANIFEST_CHARS) return json({ error: "CONTENT_TOO_LARGE", message: `Máximo ${MAX_MANIFEST_CHARS} caracteres.` }, true);
    const rec = await store.getAssessment(assessmentId);
    if (!rec || !rec.signatureValid) return json({ error: "NO_ACTIVE_ASSESSMENT" }, true);
    let sbom;
    try { sbom = parseManifest(kind, content, osvEcosystem); }
    catch (e) { return json({ error: "MANIFEST_PARSE_ERROR", message: (e as Error).message }, true); }
    let results;
    try { results = await checkVulnerabilities(sbom); }
    catch (e) { return json({ error: "OSV_UPSTREAM_ERROR", message: (e as Error).message }, true); }
    const vulnerable = results.filter(r => r.vulns.length);
    await store.audit({ actor, role, action: "supply_chain:analyzed", assessmentId, payload: { kind, deps: sbom.length, vulnerable: vulnerable.length } });
    return json({ dependencies: sbom.length, vulnerable: vulnerable.length, results, note: "Es solo informativo: nada se registra como hallazgo automáticamente. Usa finding_create para los que decidas confirmar." });
  });

  return { server, policy, store };
}
