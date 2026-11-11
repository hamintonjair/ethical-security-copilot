import { randomUUID } from "node:crypto";
import { z } from "zod";
import { AssessmentInput, Assessment } from "./schemas.js";
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
