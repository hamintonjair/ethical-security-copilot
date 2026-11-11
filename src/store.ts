import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { AssessmentInput, Assessment } from "./schemas.js";
import { canonical, sha256, sign, verifySignature, newToken } from "./crypto.js";
import { canTransition, type State } from "./state.js";
import { redact } from "./redact.js";

type AssessmentT = z.infer<typeof Assessment>;
type Role = "authorizer" | "operator" | "analyst" | "agent" | "auditor";
const GENESIS = "0".repeat(64);

export class Store {
  readonly db: DatabaseSync;
  constructor(path: string, private signingKey: Buffer) {
    this.db = new DatabaseSync(path);
    this.db.exec(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
  }

  /* ---------- Auditoría (hash chain) ---------- */
  audit(e: { actor: string; role: Role; action: string; assessmentId?: string | null; decisionId?: string | null; payload?: unknown; ts?: string }) {
    const last = this.db.prepare("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").get() as { hash: string } | undefined;
    const prevHash = last?.hash ?? GENESIS;
    const body = {
      ts: e.ts ?? new Date().toISOString(), actor: e.actor, role: e.role, action: e.action,
      assessment_id: e.assessmentId ?? null, decision_id: e.decisionId ?? null,
      payload_redacted: redact(typeof e.payload === "string" ? e.payload : canonical(e.payload ?? {}), 4000),
    };
    const hash = sha256(prevHash + canonical(body));
    this.db.prepare(`INSERT INTO audit_log (ts,actor,role,action,assessment_id,decision_id,payload_redacted,prev_hash,hash)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(body.ts, body.actor, body.role, body.action, body.assessment_id, body.decision_id, body.payload_redacted, prevHash, hash);
  }

  /** Recorre la cadena; devuelve la primera fila alterada o null si es íntegra. */
  verifyAuditChain(): { ok: true } | { ok: false; brokenAtSeq: number } {
    const rows = this.db.prepare("SELECT * FROM audit_log ORDER BY seq").all() as any[];
    let prev = GENESIS;
    for (const r of rows) {
      const body = { ts: r.ts, actor: r.actor, role: r.role, action: r.action, assessment_id: r.assessment_id, decision_id: r.decision_id, payload_redacted: r.payload_redacted };
      if (r.prev_hash !== prev || r.hash !== sha256(prev + canonical(body))) return { ok: false, brokenAtSeq: r.seq };
      prev = r.hash;
    }
    return { ok: true };
  }

  /* ---------- Assessments (versionados, firmados) ---------- */
  createAssessment(input: unknown, createdBy: string, opts: { id?: string } = {}): AssessmentT {
    const parsed = AssessmentInput.parse(input);
    const id = opts.id ?? randomUUID();
    const prev = this.db.prepare("SELECT MAX(version) v FROM assessments WHERE id=?").get(id) as { v: number | null };
    const version = (prev.v ?? 0) + 1;
    const contentHash = sha256(canonical(parsed) + `|v${version}|${id}`);
    const a: AssessmentT = {
      ...parsed, id, version, state: "draft", contentHash, signature: sign(this.signingKey, contentHash),
      createdBy, createdAt: new Date().toISOString(),
    };
    this.db.prepare(`INSERT INTO assessments (id,version,state,content_json,content_hash,signature,created_by,created_at) VALUES (?,?,?,?,?,?,?,?)`)
      .run(id, version, a.state, canonical(parsed), contentHash, a.signature, createdBy, a.createdAt);
    return a;
  }

  getAssessment(id: string): { a: AssessmentT; signatureValid: boolean } | null {
    const r = this.db.prepare("SELECT * FROM assessments WHERE id=? ORDER BY version DESC LIMIT 1").get(id) as any;
    if (!r) return null;
    const content = JSON.parse(r.content_json);
    const recomputed = sha256(canonical(content) + `|v${r.version}|${r.id}`);
    const signatureValid = recomputed === r.content_hash && verifySignature(this.signingKey, r.content_hash, r.signature);
    const a = Assessment.parse({ ...content, id: r.id, version: r.version, state: r.state, contentHash: r.content_hash, signature: r.signature, createdBy: r.created_by, createdAt: r.created_at });
    return { a, signatureValid };
  }

  /** Cambia de estado solo por transiciones válidas. */
  transition(id: string, to: State, actor: string, role: Role): boolean {
    const cur = this.getAssessment(id);
    if (!cur || !canTransition(cur.a.state as State, to)) return false;
    this.db.prepare("UPDATE assessments SET state=? WHERE id=? AND version=?").run(to, id, cur.a.version);
    this.audit({ actor, role, action: `state:${cur.a.state}->${to}`, assessmentId: id });
    return true;
  }

  /* ---------- Kill switch ---------- */
  killSwitchActive(): boolean {
    return (this.db.prepare("SELECT active FROM kill_switch WHERE id=1").get() as { active: number }).active === 1;
  }
  activateKillSwitch(reason: string, actor: string, role: Role, assessmentId?: string) {
    this.db.prepare("UPDATE kill_switch SET active=1, reason=?, activated_at=? WHERE id=1").run(reason, new Date().toISOString());
    if (assessmentId) this.transition(assessmentId, "halted", actor, role);
    this.db.prepare("UPDATE plans SET status='stopped' WHERE status IN ('approved','running','pending_approval')").run();
    this.audit({ actor, role, action: "kill_switch:on", assessmentId, payload: { reason } });
  }
  /** Reactivación: solo manual y humana. */
  releaseKillSwitch(actor: string, role: Role) {
    if (role !== "authorizer") throw new Error("Solo un authorizer humano puede liberar el kill switch");
    this.db.prepare("UPDATE kill_switch SET active=0, reason=NULL WHERE id=1").run();
    this.audit({ actor, role, action: "kill_switch:off" });
  }

  /* ---------- Planes y aprobación humana (token de un solo uso) ---------- */
  createPlan(p: { assessmentId: string; moduleId: string; mode: string; targets: unknown; limits: unknown }): string {
    const a = this.getAssessment(p.assessmentId);
    if (!a) throw new Error("assessment inexistente");
    const id = randomUUID();
    this.db.prepare(`INSERT INTO plans (id,assessment_id,assessment_version,module_id,mode,targets_json,limits_json,status,created_at) VALUES (?,?,?,?,?,?,?, 'pending_approval', ?)`)
      .run(id, p.assessmentId, a.a.version, p.moduleId, p.mode, canonical(p.targets), canonical(p.limits), new Date().toISOString());
    return id;
  }

  /** Solo roles humanos. El token se entrega por un canal separado del LLM. */
  approvePlan(planId: string, approver: string, role: Role): string {
    if (role !== "operator" && role !== "authorizer") throw new Error("Solo un humano (operator/authorizer) puede aprobar");
    const token = newToken();
    const r = this.db.prepare("UPDATE plans SET status='approved', approved_by=?, approval_token_hash=? WHERE id=? AND status='pending_approval'")
      .run(approver, sha256(token), planId);
    if (Number(r.changes) !== 1) throw new Error("plan no está pendiente de aprobación");
    this.audit({ actor: approver, role, action: "plan:approved", payload: { planId } });
    return token;
  }

  /** Consume el token (un solo uso) y valida que el plan sea de esa evaluación, módulo y versión vigente. */
  consumeApproval(planId: string, token: string, expect: { assessmentId: string; moduleId: string; target?: unknown }): boolean {
    const p = this.db.prepare("SELECT * FROM plans WHERE id=?").get(planId) as any;
    if (!p || p.status !== "approved" || p.assessment_id !== expect.assessmentId || p.module_id !== expect.moduleId) return false;
    const cur = this.getAssessment(expect.assessmentId);
    if (!cur || cur.a.version !== p.assessment_version) return false; // cambió el alcance => aprobación caduca
    if (sha256(token) !== p.approval_token_hash) return false;
    if (expect.target !== undefined && !(JSON.parse(p.targets_json) as unknown[]).some(t => canonical(t) === canonical(expect.target))) return false; // el token solo vale para los objetivos aprobados
    this.db.prepare("UPDATE plans SET approval_token_hash=NULL, status='running' WHERE id=?").run(planId);
    return true;
  }

  getPlan(planId: string) {
    const p = this.db.prepare("SELECT * FROM plans WHERE id=?").get(planId) as any;
    return p ? { ...p, targets: JSON.parse(p.targets_json), limits: JSON.parse(p.limits_json) } : null;
  }

  /* ---------- Hallazgos (la evidencia se redacta en la ingesta) ---------- */
  addFinding(assessmentId: string, data: Record<string, unknown>): string {
    const id = randomUUID();
    this.db.prepare("INSERT INTO findings (id,assessment_id,data_json,triage,created_at) VALUES (?,?,?,?,?)")
      .run(id, assessmentId, canonical(data), String(data.triage ?? "unverified"), new Date().toISOString());
    return id;
  }
  listFindings(assessmentId: string): { id: string; data: any }[] {
    return (this.db.prepare("SELECT id,data_json FROM findings WHERE assessment_id=? ORDER BY created_at").all(assessmentId) as any[])
      .map(r => ({ id: r.id, data: JSON.parse(r.data_json) }));
  }
}
