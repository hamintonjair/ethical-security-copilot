// Alertas salientes (webhook) para hallazgos críticos y apertura de incidentes.
// Estrictamente informativo: nunca bloquea nada, nunca reintenta indefinidamente y un fallo del
// webhook del cliente jamás debe romper el flujo principal (crear un hallazgo o abrir un incidente).
import { createHmac } from "node:crypto";
import type { Store } from "./store.js";

export type FetchFn = typeof fetch;
export type Severity = "info" | "low" | "medium" | "high" | "critical";
const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const TIMEOUT_MS = 5000;

export interface AlertEvent {
  kind: "finding" | "incident_open" | "test";
  severity?: Severity;
  title: string;
  asset?: string | null;
  assessmentId?: string | null;
  incidentId?: string | null;
  findingId?: string | null;
}

const publicBase = (): string | null => {
  const h = process.env.RENDER_EXTERNAL_HOSTNAME;
  return h ? `https://${h}` : null;
};
const linkFor = (e: AlertEvent): string | null => {
  const base = publicBase();
  if (!base) return null;
  if (e.kind === "incident_open" && e.incidentId) return `${base}/app/#/incidentes/${e.incidentId}`;
  if (e.kind === "finding" && e.assessmentId) return `${base}/app/#/evaluaciones/${e.assessmentId}/hallazgos`;
  return base;
};

/** Construye el cuerpo exacto que se envía (expuesto para pruebas). */
export function buildPayload(event: AlertEvent): Record<string, unknown> {
  return {
    type: event.kind, title: event.title, severity: event.severity ?? null, asset: event.asset ?? null,
    assessmentId: event.assessmentId ?? null, incidentId: event.incidentId ?? null, findingId: event.findingId ?? null,
    url: linkFor(event), sentAt: new Date().toISOString(),
  };
}

/** Evalúa si, con la configuración dada, este evento debe disparar una alerta. */
export function isDue(event: AlertEvent, cfg: { minSeverity: Severity; notifyIncidentOpen: boolean }): boolean {
  if (event.kind === "test") return true;
  if (event.kind === "finding") return SEVERITY_RANK[event.severity ?? "info"] >= SEVERITY_RANK[cfg.minSeverity];
  return cfg.notifyIncidentOpen;
}

/** Envía la alerta si está habilitada y el evento cumple el umbral configurado. Nunca lanza. */
export async function sendAlertIfDue(store: Store, event: AlertEvent, fetchImpl: FetchFn = fetch): Promise<void> {
  try {
    const cfg = await store.getAlertsSecret();
    if (!cfg) return; // deshabilitado, o sin webhook configurado
    if (!isDue(event, cfg)) return;
    const payload = buildPayload(event);
    const body = JSON.stringify(payload);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (cfg.secret) headers["x-esc-signature"] = createHmac("sha256", cfg.secret).update(body).digest("hex");
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
    let status = -1;
    try {
      const res = await fetchImpl(cfg.webhookUrl, { method: "POST", headers, body, signal: ac.signal });
      status = res.status;
    } finally { clearTimeout(timer); }
    await store.audit({ actor: "sistema", role: "agent", action: status >= 200 && status < 300 ? "alert:sent" : "alert:failed", payload: { type: event.kind, status } });
  } catch (e) {
    try {
      await store.audit({ actor: "sistema", role: "agent", action: "alert:failed", payload: { type: event.kind, error: String((e as Error)?.message ?? e).slice(0, 200) } });
    } catch { /* la auditoría tampoco debe romper el flujo principal */ }
  }
}
