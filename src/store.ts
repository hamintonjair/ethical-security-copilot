import { randomUUID } from "node:crypto";
import { z } from "zod";
import { AssessmentInput, Assessment, type Role } from "./schemas.js";
import { canonical, sha256, sign, verifySignature, newToken } from "./crypto.js";
import { canTransition, type State } from "./state.js";
import { redact } from "./redact.js";
import { openDb, type Db } from "./db.js";

type AssessmentT = z.infer<typeof Assessment>;
type Role = "authorizer" | "operator" | "analyst" | "agent" | "auditor";
const GENESIS = "0".repeat(64);
const AUDIT_LOCK = 727274; // clave del advisory lock que serializa la cadena de auditoría
const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString());

export class Store {
  private constructor(readonly db: Db, private signingKey: Buffer) {}

  /** `target`: "memory" (Postgres en proceso, para pruebas) o una URL postgres:// (p. ej. Supabase). */
  static async open(target: string, signingKey: Buffer): Promise<Store> {
    return new Store(await openDb(target), signingKey);
  }
  close() { return this.db.close(); }
  /** Comprobación de disponibilidad: consulta mínima, no devuelve datos. */
  async ping(): Promise<boolean> {
    try { await this.db.query("select 1"); return true; }
    catch (e) { const err = e as { code?: string; message?: string }; console.error("ping a la base de datos falló:", err.code ?? "", err.message ?? ""); return false; } // los errores de pg no incluyen la contraseña ni la URL
  }

  /* ---------- Auditoría (hash chain) ---------- */
  async audit(e: { actor: string; role: Role; action: string; assessmentId?: string | null; decisionId?: string | null; payload?: unknown; ts?: string }) {
    const body = {
      ts: e.ts ?? new Date().toISOString(), actor: e.actor, role: e.role, action: e.action,
      assessment_id: e.assessmentId ?? null, decision_id: e.decisionId ?? null,
      payload_redacted: redact(typeof e.payload === "string" ? e.payload : canonical(e.payload ?? {}), 4000),
    };
    await this.db.tx(async q => {
      await q.query("select pg_advisory_xact_lock($1)", [AUDIT_LOCK]); // un solo escritor a la vez => cadena lineal
      const last = (await q.query<{ hash: string }>("select hash from public.audit_log order by seq desc limit 1"))[0];
      const prevHash = last?.hash ?? GENESIS;
      const hash = sha256(prevHash + canonical(body));
      await q.query(
        `insert into public.audit_log (ts,actor,role,action,assessment_id,decision_id,payload_redacted,prev_hash,hash) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [body.ts, body.actor, body.role, body.action, body.assessment_id, body.decision_id, body.payload_redacted, prevHash, hash]);
    });
  }

  /** Recorre la cadena; devuelve la primera fila alterada o ok. */
  async verifyAuditChain(): Promise<{ ok: true } | { ok: false; brokenAtSeq: number }> {
    const rows = await this.db.query("select * from public.audit_log order by seq");
    let prev = GENESIS;
    for (const r of rows) {
      const body = { ts: iso(r.ts), actor: r.actor, role: r.role, action: r.action, assessment_id: r.assessment_id, decision_id: r.decision_id, payload_redacted: r.payload_redacted };
      if (r.prev_hash !== prev || r.hash !== sha256(prev + canonical(body))) return { ok: false, brokenAtSeq: Number(r.seq) };
      prev = r.hash;
    }
    return { ok: true };
  }

  /* ---------- Assessments (versionados, firmados) ---------- */
  async createAssessment(input: unknown, createdBy: string, opts: { id?: string } = {}): Promise<AssessmentT> {
    const parsed = AssessmentInput.parse(input);
    const id = opts.id ?? randomUUID();
    const contentJson = canonical(parsed);
    return this.db.tx(async q => {
      const v = (await q.query<{ v: number | null }>("select max(version) v from public.assessments where id=$1", [id]))[0]?.v ?? 0;
      const version = Number(v) + 1;
      const contentHash = sha256(contentJson + `|v${version}|${id}`);
      const signature = sign(this.signingKey, contentHash);
      const createdAt = new Date().toISOString();
      await q.query(`insert into public.assessments (id,version,state,content_json,content_hash,signature,created_by,created_at) values ($1,$2,'draft',$3,$4,$5,$6,$7)`,
        [id, version, contentJson, contentHash, signature, createdBy, createdAt]);
      return { ...parsed, id, version, state: "draft", contentHash, signature, createdBy, createdAt } as AssessmentT;
    });
  }

  async getAssessment(id: string): Promise<{ a: AssessmentT; signatureValid: boolean } | null> {
    const r = (await this.db.query("select * from public.assessments where id=$1 order by version desc limit 1", [id]))[0];
    if (!r) return null;
    const content = JSON.parse(r.content_json);
    const version = Number(r.version);
    const recomputed = sha256(canonical(content) + `|v${version}|${r.id}`);
    const signatureValid = recomputed === r.content_hash && verifySignature(this.signingKey, r.content_hash, r.signature);
    const a = Assessment.parse({ ...content, id: r.id, version, state: r.state, contentHash: r.content_hash, signature: r.signature, createdBy: r.created_by, createdAt: iso(r.created_at) });
    return { a, signatureValid };
  }


  /* ---------- Incidentes (Respuesta a Incidentes / Defensa Activa) ---------- */
  async createIncident(input: { organization: string; contactName: string; contactEmail: string; summary: string; affectedAssets: string[] }, createdBy: string) {
    const id = randomUUID(), createdAt = new Date().toISOString();
    await this.db.query(
      `insert into public.incidents (id, organization, contact_name, contact_email, summary, affected_assets, created_by, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [id, input.organization, input.contactName, input.contactEmail, input.summary, JSON.stringify(input.affectedAssets), createdBy, createdAt]);
    await this.audit({ actor: createdBy, role: "authorizer", action: "incident:open", assessmentId: id, payload: { organization: input.organization } });
    return { id, status: "open" as const, createdAt, createdBy, ...input };
  }

  private incidentRow(r: any) {
    return { id: r.id, organization: r.organization, contactName: r.contact_name, contactEmail: r.contact_email, summary: r.summary,
      affectedAssets: r.affected_assets, status: r.status, createdBy: r.created_by, createdAt: iso(r.created_at), closedAt: r.closed_at ? iso(r.closed_at) : null };
  }

  async getIncident(id: string) {
    const r = (await this.db.query("select * from public.incidents where id=$1", [id]))[0];
    if (!r) return null;
    const evidence = (await this.db.query("select * from public.incident_evidence where incident_id=$1 order by created_at asc", [id]))
      .map(e => ({ id: e.id, kind: e.kind, description: e.description, redactedContent: e.redacted_content, iocs: e.iocs, createdBy: e.created_by, createdAt: iso(e.created_at) }));
    return { incident: this.incidentRow(r), evidence };
  }

  async listIncidents() {
    return (await this.db.query("select i.*, (select count(*) from public.incident_evidence e where e.incident_id = i.id) evidence_count from public.incidents i order by created_at desc"))
      .map(r => ({ ...this.incidentRow(r), evidenceCount: Number(r.evidence_count) }));
  }

  async addIncidentEvidence(incidentId: string, e: { kind: string; description: string; redactedContent: string; iocs: unknown }, actor: string) {
    const r = (await this.db.query("select status from public.incidents where id=$1", [incidentId]))[0];
    if (!r) return null;
    if (r.status === "closed") return "CLOSED" as const;
    const id = randomUUID(), createdAt = new Date().toISOString();
    await this.db.query("insert into public.incident_evidence (id, incident_id, kind, description, redacted_content, iocs, created_by, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)",
      [id, incidentId, e.kind, e.description, e.redactedContent, JSON.stringify(e.iocs), actor, createdAt]);
    await this.audit({ actor, role: "analyst", action: "incident:evidence_added", assessmentId: incidentId, payload: { kind: e.kind, description: e.description } });
    return { id, createdAt };
  }

  async setIncidentStatus(id: string, status: "open" | "contained" | "closed", actor: string, role: Role) {
    const cur = (await this.db.query("select status from public.incidents where id=$1", [id]))[0];
    if (!cur) return false;
    const order = ["open", "contained", "closed"];
    if (order.indexOf(status) < order.indexOf(cur.status) && !(cur.status === "closed")) { /* se permite retroceder de contained a open */ }
    if (cur.status === "closed") return false; // un incidente cerrado no cambia de estado
    await this.db.query("update public.incidents set status=$2, closed_at=case when $2='closed' then now() else closed_at end where id=$1", [id, status]);
    await this.audit({ actor, role, action: "incident:status", assessmentId: id, payload: { from: cur.status, to: status } });
    return true;
  }

  /** Cambia de estado solo por transiciones válidas; atómico (compara el estado previo). */
  async transition(id: string, to: State, actor: string, role: Role): Promise<boolean> {
    const cur = await this.getAssessment(id);
    if (!cur || !canTransition(cur.a.state as State, to)) return false;
    const done = await this.db.query("update public.assessments set state=$3 where id=$1 and version=$2 and state=$4 returning id", [id, cur.a.version, to, cur.a.state]);
    if (!done.length) return false;
    await this.audit({ actor, role, action: `state:${cur.a.state}->${to}`, assessmentId: id });
    return true;
  }

  /* ---------- Kill switch ---------- */
  async killSwitchActive(): Promise<boolean> {
    return (await this.db.query<{ active: boolean }>("select active from public.kill_switch where id=1"))[0]?.active === true;
  }
  async activateKillSwitch(reason: string, actor: string, role: Role, assessmentId?: string) {
    await this.db.query("update public.kill_switch set active=true, reason=$1, activated_at=now() where id=1", [reason]);
    if (assessmentId) await this.transition(assessmentId, "halted", actor, role);
    await this.db.query("update public.plans set status='stopped' where status in ('approved','running','pending_approval')");
    await this.audit({ actor, role, action: "kill_switch:on", assessmentId, payload: { reason } });
  }
  /** Reactivación: solo manual y humana. */
  async releaseKillSwitch(actor: string, role: Role) {
    if (role !== "authorizer") throw new Error("Solo un authorizer humano puede liberar el kill switch");
    await this.db.query("update public.kill_switch set active=false, reason=null where id=1");
    await this.audit({ actor, role, action: "kill_switch:off" });
  }

  /* ---------- Planes y aprobación humana (token de un solo uso) ---------- */
  async createPlan(p: { assessmentId: string; moduleId: string; mode: string; targets: unknown; limits: unknown }): Promise<string> {
    const a = await this.getAssessment(p.assessmentId);
    if (!a) throw new Error("assessment inexistente");
    const id = randomUUID();
    await this.db.query(`insert into public.plans (id,assessment_id,assessment_version,module_id,mode,targets_json,limits_json,status) values ($1,$2,$3,$4,$5,$6,$7,'pending_approval')`,
      [id, p.assessmentId, a.a.version, p.moduleId, p.mode, canonical(p.targets), canonical(p.limits)]);
    return id;
  }

  /** Solo roles humanos. El token se entrega por un canal separado del LLM. */
  async approvePlan(planId: string, approver: string, role: Role): Promise<string> {
    if (role !== "operator" && role !== "authorizer") throw new Error("Solo un humano (operator/authorizer) puede aprobar");
    const token = newToken();
    const done = await this.db.query("update public.plans set status='approved', approved_by=$2, approval_token_hash=$3 where id=$1 and status='pending_approval' returning id", [planId, approver, sha256(token)]);
    if (!done.length) throw new Error("plan no está pendiente de aprobación");
    await this.audit({ actor: approver, role, action: "plan:approved", payload: { planId } });
    return token;
  }

  /** Consume el token (un solo uso, atómico) y valida evaluación, módulo, versión vigente y objetivos aprobados. */
  async consumeApproval(planId: string, token: string, expect: { assessmentId: string; moduleId: string; target?: unknown }): Promise<boolean> {
    const p = (await this.db.query("select * from public.plans where id=$1", [planId]))[0];
    if (!p || p.status !== "approved" || p.assessment_id !== expect.assessmentId || p.module_id !== expect.moduleId) return false;
    const cur = await this.getAssessment(expect.assessmentId);
    if (!cur || cur.a.version !== Number(p.assessment_version)) return false; // cambió el alcance => la aprobación caduca
    if (sha256(token) !== p.approval_token_hash) return false;
    if (expect.target !== undefined && !(JSON.parse(p.targets_json) as unknown[]).some(t => canonical(t) === canonical(expect.target))) return false;
    // El UPDATE condicionado garantiza que, aunque dos llamadas lleguen a la vez, solo una consuma el token.
    const done = await this.db.query("update public.plans set approval_token_hash=null, status='running' where id=$1 and status='approved' and approval_token_hash=$2 returning id", [planId, p.approval_token_hash]);
    return done.length === 1;
  }

  async getPlan(planId: string) {
    const p = (await this.db.query("select * from public.plans where id=$1", [planId]))[0];
    return p ? { ...p, targets: JSON.parse(p.targets_json), limits: JSON.parse(p.limits_json) } : null;
  }

  /* ---------- Consultas para la interfaz web ---------- */
  /** Última versión de cada evaluación, la más reciente primero. */
  async listAssessments(): Promise<{ id: string; version: number; state: string; createdAt: string; createdBy: string; name: string; organization: string; modes: string[]; window: { notBefore: string; notAfter: string } }[]> {
    const rows = await this.db.query("select distinct on (id) id, version, state, content_json, created_by, created_at from public.assessments order by id, version desc");
    return rows.map(r => { const c = JSON.parse(r.content_json); return { id: r.id, version: Number(r.version), state: r.state, createdAt: iso(r.created_at), createdBy: r.created_by, name: c.name, organization: c.authorizer?.organization ?? "", modes: c.allowedModes ?? [], window: { notBefore: c.window?.notBefore, notAfter: c.window?.notAfter } }; })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
  async listVersions(id: string) {
    return (await this.db.query("select version, state, content_hash, created_by, created_at from public.assessments where id=$1 order by version desc", [id]))
      .map(r => ({ version: Number(r.version), state: r.state as string, contentHash: r.content_hash as string, createdBy: r.created_by as string, createdAt: iso(r.created_at) }));
  }
  async listPlans(f: { assessmentId?: string; status?: string } = {}) {
    const rows = await this.db.query("select * from public.plans where ($1::text is null or assessment_id=$1) and ($2::text is null or status=$2) order by created_at desc limit 200", [f.assessmentId ?? null, f.status ?? null]);
    return rows.map(p => ({ id: p.id as string, assessmentId: p.assessment_id as string, assessmentVersion: Number(p.assessment_version), moduleId: p.module_id as string, mode: p.mode as string, targets: JSON.parse(p.targets_json), limits: JSON.parse(p.limits_json), status: p.status as string, approvedBy: (p.approved_by ?? null) as string | null, createdAt: iso(p.created_at) }));
  }
  async rejectPlan(planId: string, actor: string, role: Role): Promise<boolean> {
    if (role !== "operator" && role !== "authorizer") throw new Error("Solo un humano (operator/authorizer) puede rechazar");
    const done = await this.db.query("update public.plans set status='rejected', approval_token_hash=null where id=$1 and status='pending_approval' returning id", [planId]);
    if (!done.length) return false;
    await this.audit({ actor, role, action: "plan:rejected", payload: { planId } });
    return true;
  }
  async setTriage(findingId: string, triage: string, actor: string, role: Role): Promise<boolean> {
    const r = (await this.db.query("select assessment_id, data_json from public.findings where id=$1", [findingId]))[0];
    if (!r) return false;
    const data = JSON.parse(r.data_json); data.triage = triage;
    await this.db.query("update public.findings set data_json=$2, triage=$3 where id=$1", [findingId, canonical(data), triage]);
    await this.audit({ actor, role, action: "finding:triage", assessmentId: r.assessment_id, payload: { findingId, triage } });
    return true;
  }
  async listAudit(limit: number, offset: number) {
    const rows = await this.db.query("select seq, ts, actor, role, action, assessment_id, decision_id, payload_redacted, prev_hash, hash from public.audit_log order by seq desc limit $1 offset $2", [limit, offset]);
    const total = Number((await this.db.query("select count(*) n from public.audit_log"))[0].n);
    return { total, rows: rows.map(r => ({ seq: Number(r.seq), ts: iso(r.ts), actor: r.actor as string, role: r.role as string, action: r.action as string, assessmentId: (r.assessment_id ?? null) as string | null, decisionId: (r.decision_id ?? null) as string | null, payload: r.payload_redacted as string, prevHash: r.prev_hash as string, hash: r.hash as string })) };
  }
  async killSwitchInfo(): Promise<{ active: boolean; reason: string | null; activatedAt: string | null }> {
    const r = (await this.db.query("select active, reason, activated_at from public.kill_switch where id=1"))[0];
    return { active: r?.active === true, reason: r?.reason ?? null, activatedAt: r?.activated_at ? iso(r.activated_at) : null };
  }

  /* ---------- Hallazgos (la evidencia se redacta en la ingesta) ---------- */
  async addFinding(assessmentId: string, data: Record<string, unknown>): Promise<string> {
    const id = randomUUID();
    await this.db.query("insert into public.findings (id,assessment_id,data_json,triage) values ($1,$2,$3,$4)", [id, assessmentId, canonical(data), String(data.triage ?? "unverified")]);
    return id;
  }
  async listFindings(assessmentId: string): Promise<{ id: string; data: any }[]> {
    return (await this.db.query("select id,data_json from public.findings where assessment_id=$1 order by created_at, id", [assessmentId])).map(r => ({ id: r.id, data: JSON.parse(r.data_json) }));
  }
}
