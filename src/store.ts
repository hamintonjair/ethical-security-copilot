import { randomUUID, createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { AssessmentInput, Assessment, type Role } from "./schemas.js";
import { canonical, sha256, sign, verifySignature, newToken, encryptSecret, decryptSecret } from "./crypto.js";
import { createHash } from "node:crypto";
import { canTransition, type State } from "./state.js";
import { redact } from "./redact.js";
import { openDb, type Db } from "./db.js";
import { sendAlertIfDue, type FetchFn as AlertFetchFn } from "./alerts.js";

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
  async createIncident(input: { organization: string; contactName: string; contactEmail: string; summary: string; affectedAssets: string[]; types?: string[]; containmentTargets?: string[] }, createdBy: string, fetchImpl: AlertFetchFn = fetch) {
    const id = randomUUID(), createdAt = new Date().toISOString(), types = input.types ?? [], containmentTargets = input.containmentTargets ?? [];
    await this.db.query(
      `insert into public.incidents (id, organization, contact_name, contact_email, summary, affected_assets, types, containment_targets, created_by, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [id, input.organization, input.contactName, input.contactEmail, input.summary, JSON.stringify(input.affectedAssets), types, containmentTargets, createdBy, createdAt]);
    await this.audit({ actor: createdBy, role: "authorizer", action: "incident:open", assessmentId: id, payload: { organization: input.organization, types, containmentTargets } });
    await sendAlertIfDue(this, { kind: "incident_open", title: `Incidente abierto: ${input.organization}`, incidentId: id }, fetchImpl);
    return { id, status: "open" as const, createdAt, createdBy, ...input, types, containmentTargets };
  }

  private incidentRow(r: any) {
    return { id: r.id, organization: r.organization, contactName: r.contact_name, contactEmail: r.contact_email, summary: r.summary,
      affectedAssets: r.affected_assets, types: r.types ?? [], containmentTargets: r.containment_targets ?? [], status: r.status, createdBy: r.created_by, createdAt: iso(r.created_at), closedAt: r.closed_at ? iso(r.closed_at) : null };
  }

  /** El humano marca o ajusta los tipos de incidente (check-out); nunca se llama automáticamente desde la detección. */
  async setIncidentTypes(id: string, types: string[], actor: string, role: Role): Promise<boolean> {
    const cur = (await this.db.query("select status from public.incidents where id=$1", [id]))[0];
    if (!cur || cur.status === "closed") return false;
    await this.db.query("update public.incidents set types=$2 where id=$1", [id, types]);
    await this.audit({ actor, role, action: "incident:types_set", assessmentId: id, payload: { types } });
    return true;
  }

  /** El humano marca qué herramientas de bloqueo (firewall/nginx/Cloudflare) ya tiene disponibles para este caso. */
  async setIncidentContainmentTargets(id: string, targets: string[], actor: string, role: Role): Promise<boolean> {
    const cur = (await this.db.query("select status from public.incidents where id=$1", [id]))[0];
    if (!cur || cur.status === "closed") return false;
    await this.db.query("update public.incidents set containment_targets=$2 where id=$1", [id, targets]);
    await this.audit({ actor, role, action: "incident:targets_set", assessmentId: id, payload: { targets } });
    return true;
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

  /* ---------- Historial del Asistente de IA (incidentes y evaluaciones) ---------- */
  async addAiMessage(subjectType: "incident" | "assessment", subjectId: string, question: string, answer: string, actor: string) {
    const id = randomUUID(), createdAt = new Date().toISOString();
    await this.db.query("insert into public.ai_messages (id, subject_type, subject_id, question, answer, actor, created_at) values ($1,$2,$3,$4,$5,$6,$7)",
      [id, subjectType, subjectId, question, answer, actor, createdAt]);
    return { id, createdAt };
  }

  async listAiMessages(subjectType: "incident" | "assessment", subjectId: string) {
    return (await this.db.query("select * from public.ai_messages where subject_type=$1 and subject_id=$2 order by created_at asc", [subjectType, subjectId]))
      .map(r => ({ id: r.id, question: r.question, answer: r.answer, actor: r.actor, createdAt: iso(r.created_at) }));
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

  /* ---------- Módulo de IA (API propia) ----------
     La llave se cifra con una subllave derivada de la misma llave de firma (nunca en texto plano en la base). */
  private aiEncKey() { return createHash("sha256").update(Buffer.concat([this.signingKey, Buffer.from("ai-key-enc-v1")])).digest(); }

  async getAiConfig(): Promise<{ enabled: boolean; provider: string; model: string; baseUrl: string | null; hasKey: boolean; keyLast4: string | null; updatedBy: string | null; updatedAt: string | null }> {
    const r = (await this.db.query("select * from public.ai_config where id=1"))[0];
    return { enabled: r?.enabled === true, provider: r?.provider ?? "anthropic", model: r?.model ?? "claude-sonnet-5-5", baseUrl: r?.base_url ?? null, hasKey: !!r?.api_key_enc, keyLast4: r?.api_key_last4 ?? null, updatedBy: r?.updated_by ?? null, updatedAt: r?.updated_at ? iso(r.updated_at) : null };
  }

  /** Solo para uso interno del servidor (módulo de IA); nunca se expone por la API ni por MCP. */
  async getAiSecret(): Promise<{ enabled: boolean; provider: string; model: string; baseUrl: string | null; apiKey: string } | null> {
    const r = (await this.db.query("select * from public.ai_config where id=1"))[0];
    if (!r?.enabled || !r?.api_key_enc) return null;
    try { return { enabled: true, provider: r.provider ?? "anthropic", model: r.model, baseUrl: r.base_url ?? null, apiKey: decryptSecret(r.api_key_enc, this.aiEncKey()) }; }
    catch { return null; } // llave cifrada ilegible (p. ej. cambió ESC_SIGNING_KEY): se trata como "no configurada"
  }

  async setAiConfig(input: { enabled: boolean; provider: string; model: string; baseUrl?: string; apiKey?: string }, actor: string): Promise<void> {
    const baseUrl = input.baseUrl ?? null;
    if (input.apiKey) {
      const enc = encryptSecret(input.apiKey, this.aiEncKey());
      await this.db.query("update public.ai_config set enabled=$1, provider=$2, model=$3, base_url=$4, api_key_enc=$5, api_key_last4=$6, updated_by=$7, updated_at=now() where id=1",
        [input.enabled, input.provider, input.model, baseUrl, enc, input.apiKey.slice(-4), actor]);
    } else {
      await this.db.query("update public.ai_config set enabled=$1, provider=$2, model=$3, base_url=$4, updated_by=$5, updated_at=now() where id=1", [input.enabled, input.provider, input.model, baseUrl, actor]);
    }
    await this.audit({ actor, role: "authorizer", action: "ai:config_updated", payload: { enabled: input.enabled, provider: input.provider, model: input.model, keyChanged: !!input.apiKey } });
  }

  /* ---------- Alertas salientes (webhook) ----------
     Estrictamente informativo: nunca bloquea ni actúa por sí sola. El secreto de firma (si se define)
     se cifra igual que la llave del módulo de IA, con una subllave distinta derivada de la misma llave de firma. */
  private alertsEncKey() { return createHash("sha256").update(Buffer.concat([this.signingKey, Buffer.from("alerts-secret-enc-v1")])).digest(); }

  async getAlertsConfig(): Promise<{ enabled: boolean; webhookUrl: string | null; minSeverity: string; notifyIncidentOpen: boolean; hasSecret: boolean; secretLast4: string | null; updatedBy: string | null; updatedAt: string | null }> {
    const r = (await this.db.query("select * from public.alerts_config where id=1"))[0];
    return { enabled: r?.enabled === true, webhookUrl: r?.webhook_url ?? null, minSeverity: r?.min_severity ?? "high", notifyIncidentOpen: r?.notify_incident_open !== false, hasSecret: !!r?.secret_enc, secretLast4: r?.secret_last4 ?? null, updatedBy: r?.updated_by ?? null, updatedAt: r?.updated_at ? iso(r.updated_at) : null };
  }

  /** Solo para uso interno del servidor (envío de alertas); nunca se expone por la API ni por MCP. */
  async getAlertsSecret(): Promise<{ webhookUrl: string; minSeverity: "info" | "low" | "medium" | "high" | "critical"; notifyIncidentOpen: boolean; secret: string | null } | null> {
    const r = (await this.db.query("select * from public.alerts_config where id=1"))[0];
    if (!r?.enabled || !r?.webhook_url) return null;
    let secret: string | null = null;
    if (r.secret_enc) { try { secret = decryptSecret(r.secret_enc, this.alertsEncKey()); } catch { secret = null; } } // llave cifrada ilegible => se trata como "sin firmar"
    return { webhookUrl: r.webhook_url, minSeverity: r.min_severity ?? "high", notifyIncidentOpen: r.notify_incident_open !== false, secret };
  }

  async setAlertsConfig(input: { enabled: boolean; webhookUrl?: string; minSeverity: string; notifyIncidentOpen: boolean; secret?: string; clearSecret?: boolean }, actor: string): Promise<void> {
    const webhookUrl = input.webhookUrl ?? null;
    if (input.secret) {
      const enc = encryptSecret(input.secret, this.alertsEncKey());
      await this.db.query("update public.alerts_config set enabled=$1, webhook_url=$2, min_severity=$3, notify_incident_open=$4, secret_enc=$5, secret_last4=$6, updated_by=$7, updated_at=now() where id=1",
        [input.enabled, webhookUrl, input.minSeverity, input.notifyIncidentOpen, enc, input.secret.slice(-4), actor]);
    } else if (input.clearSecret) {
      await this.db.query("update public.alerts_config set enabled=$1, webhook_url=$2, min_severity=$3, notify_incident_open=$4, secret_enc=null, secret_last4=null, updated_by=$5, updated_at=now() where id=1",
        [input.enabled, webhookUrl, input.minSeverity, input.notifyIncidentOpen, actor]);
    } else {
      await this.db.query("update public.alerts_config set enabled=$1, webhook_url=$2, min_severity=$3, notify_incident_open=$4, updated_by=$5, updated_at=now() where id=1",
        [input.enabled, webhookUrl, input.minSeverity, input.notifyIncidentOpen, actor]);
    }
    await this.audit({ actor, role: "authorizer", action: "alerts:config_updated", payload: { enabled: input.enabled, minSeverity: input.minSeverity, notifyIncidentOpen: input.notifyIncidentOpen, secretChanged: !!input.secret, secretCleared: !!input.clearSecret } });
  }

  /* ---------- Integraciones entrantes (telemetría defensiva) ---------- */
  private integrationsEncKey() { return createHash("sha256").update(Buffer.concat([this.signingKey, Buffer.from("security-integrations-enc-v1")])).digest(); }

  async createSecurityIntegration(input: { name: string; provider: string }, actor: string) {
    const id = randomUUID();
    const secret = newToken();
    const enc = encryptSecret(secret, this.integrationsEncKey());
    const row = (await this.db.query("insert into public.security_integrations (id,name,provider,secret_enc,secret_last4,created_by) values ($1,$2,$3,$4,$5,$6) returning id,name,provider,enabled,created_at", [id, input.name, input.provider, enc, secret.slice(-4), actor]))[0];
    await this.audit({ actor, role: "authorizer", action: "integration:created", payload: { integrationId: id, name: input.name, provider: input.provider } });
    return { id: row.id, name: row.name, provider: row.provider, enabled: row.enabled, createdAt: iso(row.created_at), secret };
  }

  async listSecurityIntegrations() {
    return (await this.db.query("select id,name,provider,enabled,secret_last4,created_by,created_at,updated_at from public.security_integrations order by created_at desc")).map(r => ({ id: r.id, name: r.name, provider: r.provider, enabled: r.enabled, secretLast4: r.secret_last4, createdBy: r.created_by, createdAt: iso(r.created_at), updatedAt: iso(r.updated_at) }));
  }

  async rotateSecurityIntegrationSecret(id: string, actor: string) {
    const secret = newToken();
    const enc = encryptSecret(secret, this.integrationsEncKey());
    const rows = await this.db.query("update public.security_integrations set secret_enc=$2,secret_last4=$3,updated_at=now() where id=$1 and enabled returning id", [id, enc, secret.slice(-4)]);
    if (!rows.length) return null;
    await this.audit({ actor, role: "authorizer", action: "integration:secret_rotated", payload: { integrationId: id } });
    return secret;
  }

  async setSecurityIntegrationEnabled(id: string, enabled: boolean, actor: string) {
    const rows = await this.db.query("update public.security_integrations set enabled=$2,updated_at=now() where id=$1 returning id", [id, enabled]);
    if (!rows.length) return false;
    await this.audit({ actor, role: "authorizer", action: enabled ? "integration:enabled" : "integration:disabled", payload: { integrationId: id } });
    return true;
  }

  /** Verifica firma HMAC antes de validar y almacenar el evento. Rechaza timestamps fuera de ±5 min. */
  async ingestSecurityEvent(id: string, timestamp: string, signature: string, rawBody: string, event: {
    eventId: string; observedAt: string; severity: string; category: string; title: string;
    asset?: string; summary: string; data?: unknown;
  }) {
    const source = (await this.db.query("select provider,secret_enc from public.security_integrations where id=$1 and enabled=true", [id]))[0];
    if (!source) return { status: "unavailable" as const };
    const ts = Number(timestamp);
    if (!Number.isFinite(ts) || Math.abs(Date.now() - ts * 1000) > 5 * 60_000) return { status: "invalid_timestamp" as const };
    let secret: string;
    try { secret = decryptSecret(source.secret_enc, this.integrationsEncKey()); } catch { return { status: "unavailable" as const }; }
    const expected = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest();
    const supplied = Buffer.from(signature.replace(/^sha256=/, ""), "hex");
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return { status: "invalid_signature" as const };
    const safeData = Object.fromEntries(Object.entries((event.data ?? {}) as Record<string, string | number | boolean | null>).map(([k, v]) => [k, /secret|token|password|authorization|cookie|credential|api.?key/i.test(k) ? "[REDACTED]" : typeof v === "string" ? redact(v, 1000) : v]));
    const safeEventId = sha256(event.eventId);
    const safeCategory = redact(event.category, 100);
    const safeTitle = redact(event.title, 300);
    const safeAsset = event.asset ? redact(event.asset, 300) : undefined;
    const safeSummary = redact(event.summary, 4000);
    const inserted = await this.db.query("insert into public.security_events (integration_id,external_event_id,observed_at,severity,category,title,asset,summary,event_data) values ($1,$2,$3,$4,$5,$6,$7,$8,$9) on conflict (integration_id,external_event_id) do nothing returning id", [id, safeEventId, event.observedAt, event.severity, safeCategory, safeTitle, safeAsset ?? null, safeSummary, JSON.stringify(safeData)]);
    if (!inserted.length) return { status: "duplicate" as const };
    await this.audit({ actor: `integration:${id}`, role: "agent", action: "security:event_received", payload: { integrationId: id, provider: source.provider, eventId: safeEventId, severity: event.severity, category: safeCategory, title: safeTitle, asset: safeAsset } });
    return { status: "accepted" as const, eventId: inserted[0].id };
  }

  async listSecurityEvents(limit = 100) {
    return (await this.db.query("select e.id,e.external_event_id,e.observed_at,e.severity,e.category,e.title,e.asset,e.summary,e.received_at,i.name integration_name,i.provider from public.security_events e join public.security_integrations i on i.id=e.integration_id order by e.received_at desc limit $1", [limit])).map(r => ({ id: r.id, externalEventId: r.external_event_id, observedAt: iso(r.observed_at), severity: r.severity, category: r.category, title: r.title, asset: r.asset, summary: r.summary, receivedAt: iso(r.received_at), integrationName: r.integration_name, provider: r.provider }));
  }

  /* ---------- Auditoría de inicios de sesión de Google Workspace ---------- */
  private googleEncKey() { return createHash("sha256").update(Buffer.concat([this.signingKey, Buffer.from("google-workspace-refresh-v1")])).digest(); }

  async createGoogleWorkspaceOAuthState(state: string, actor: string) {
    await this.db.query("delete from public.google_workspace_oauth_states where created_at < now() - interval '15 minutes'");
    await this.db.query("insert into public.google_workspace_oauth_states (state_hash,created_by) values ($1,$2)", [sha256(state), actor]);
  }

  async consumeGoogleWorkspaceOAuthState(state: string): Promise<string | null> {
    const rows = await this.db.query("delete from public.google_workspace_oauth_states where state_hash=$1 and created_at > now() - interval '15 minutes' returning created_by", [sha256(state)]);
    return rows[0]?.created_by ?? null;
  }

  async saveGoogleWorkspaceConnection(email: string, refreshToken: string, actor: string) {
    const existing = (await this.db.query("select integration_id from public.google_workspace_connections where id=1"))[0];
    let integrationId = existing?.integration_id as string | undefined;
    if (!integrationId) {
      const prior = (await this.db.query("select id from public.security_integrations where provider='google_workspace' order by created_at desc limit 1"))[0];
      integrationId = prior?.id as string | undefined;
      if (integrationId) await this.db.query("update public.security_integrations set name=$2,enabled=true,updated_at=now() where id=$1", [integrationId, `Google Workspace (${email})`]);
      else {
        integrationId = randomUUID();
        const unusedSecret = newToken();
        const encryptedUnusedSecret = encryptSecret(unusedSecret, this.integrationsEncKey());
        await this.db.query("insert into public.security_integrations (id,name,provider,secret_enc,secret_last4,created_by) values ($1,$2,'google_workspace',$3,$4,$5)",
          [integrationId, `Google Workspace (${email})`, encryptedUnusedSecret, unusedSecret.slice(-4), actor]);
      }
    }
    const refreshEnc = encryptSecret(refreshToken, this.googleEncKey());
    await this.db.query(`insert into public.google_workspace_connections (id,integration_id,admin_email,refresh_token_enc,connected_by,last_sync_at,last_sync_error,updated_at)
      values (1,$1,$2,$3,$4,null,null,now()) on conflict (id) do update set integration_id=excluded.integration_id,admin_email=excluded.admin_email,refresh_token_enc=excluded.refresh_token_enc,connected_by=excluded.connected_by,last_sync_at=null,last_sync_error=null,updated_at=now()`,
      [integrationId, email.toLowerCase(), refreshEnc, actor]);
    await this.audit({ actor, role: "authorizer", action: "google_workspace:connected", payload: { adminEmail: email.toLowerCase() } });
  }

  async googleWorkspaceStatus() {
    const r = (await this.db.query("select admin_email,last_sync_at,last_sync_error from public.google_workspace_connections where id=1"))[0];
    return r ? { connected: true, email: r.admin_email, lastSyncAt: r.last_sync_at ? iso(r.last_sync_at) : null, lastSyncError: r.last_sync_error ?? null } : { connected: false, email: null, lastSyncAt: null, lastSyncError: null };
  }

  async getGoogleWorkspaceCredentials(): Promise<{ integrationId: string; email: string; refreshToken: string } | null> {
    const r = (await this.db.query("select integration_id,admin_email,refresh_token_enc from public.google_workspace_connections where id=1"))[0];
    if (!r) return null;
    return { integrationId: r.integration_id, email: r.admin_email, refreshToken: decryptSecret(r.refresh_token_enc, this.googleEncKey()) };
  }

  async markGoogleWorkspaceSync(integrationId: string, error: string | null) {
    await this.db.query("update public.google_workspace_connections set last_sync_at=case when $2::text is null then now() else last_sync_at end,last_sync_error=$2,updated_at=now() where id=1 and integration_id=$1", [integrationId, error?.slice(0, 500) ?? null]);
  }

  async deleteGoogleWorkspaceConnection() {
    const r = (await this.db.query("delete from public.google_workspace_connections where id=1 returning integration_id,connected_by"))[0];
    if (r) {
      await this.db.query("update public.security_integrations set enabled=false,updated_at=now() where id=$1", [r.integration_id]);
      await this.audit({ actor: r.connected_by, role: "authorizer", action: "google_workspace:disconnected", payload: {} });
    }
  }

  async ingestGoogleWorkspaceLoginActivities(integrationId: string, items: Array<{
    id?: { time?: string; uniqueQualifier?: string }; actor?: { email?: string }; ipAddress?: string;
    events?: Array<{ name?: string; type?: string; parameters?: Array<{ name?: string; value?: string; boolValue?: boolean }> }>;
  }>) {
    let insertedCount = 0;
    for (const item of items.slice(0, 1000)) for (const event of (item.events ?? []).slice(0, 30)) {
      const eventName = event.name ?? event.type ?? "login_activity";
      const params = Object.fromEntries((event.parameters ?? []).slice(0, 40).map(p => {
        const name = p.name ?? ""; const value = p.value ?? p.boolValue ?? null;
        return [name, /secret|token|password|cookie|credential|code/i.test(name) ? "[REDACTED]" : typeof value === "string" ? redact(value, 300) : value];
      }));
      const affected = typeof params.affected_email_address === "string" ? params.affected_email_address : item.actor?.email;
      const isSuspicious = params.is_suspicious === true || params.is_suspicious === "true";
      const severity = /suspicious|hijacked|attack_warning|password_leak/i.test(eventName) || isSuspicious ? "high" : eventName === "login_failure" ? "medium" : eventName === "login_success" ? "info" : "low";
      const title = eventName === "login_failure" ? "Intento de inicio de sesión fallido (Google Workspace)" : eventName === "login_success" ? "Inicio de sesión en Google Workspace" : `Actividad de acceso de Google Workspace: ${eventName}`;
      const summary = `Evento ${eventName}${item.ipAddress ? ` desde IP ${item.ipAddress}` : ""}${event.type ? ` · tipo ${event.type}` : ""}`;
      const eventTime = item.id?.time && Number.isFinite(Date.parse(item.id.time)) ? new Date(item.id.time).toISOString() : new Date().toISOString();
      const sourceId = sha256(`${item.id?.uniqueQualifier ?? ""}|${item.id?.time ?? ""}|${eventName}`);
      const safeData = { source: "google_workspace_reports", eventName, eventType: event.type ?? null, ipAddress: item.ipAddress ?? null, parameters: params };
      const row = await this.db.query("insert into public.security_events (integration_id,external_event_id,observed_at,severity,category,title,asset,summary,event_data) values ($1,$2,$3,$4,'login',$5,$6,$7,$8) on conflict (integration_id,external_event_id) do nothing returning id",
        [integrationId, sourceId, eventTime, severity, title, affected ? redact(affected, 300) : null, redact(summary, 1000), JSON.stringify(safeData)]);
      if (row.length) {
        insertedCount++;
        await this.audit({ actor: "integration:google_workspace", role: "agent", action: "security:event_received", payload: { integrationId, provider: "google_workspace", eventId: sourceId, severity, category: "login", title } });
      }
    }
    return insertedCount;
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

