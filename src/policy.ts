import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { z } from "zod";
import type { DenyReason, PolicyDecision, PolicyEngine as IPolicyEngine, Role, ModuleManifest } from "./schemas.js";
import { RolePermissions } from "./schemas.js";
import { Store } from "./store.js";
import { EXECUTABLE_STATES, type State } from "./state.js";
import { DEFAULT_LAB_NETS, SENSITIVE_NETS, hostOf, ipInTargets, isLabTarget, targetMatches, type Target } from "./scope.js";

type Deny = z.infer<typeof DenyReason>;
type Decision = z.infer<typeof PolicyDecision>;
type Manifest = z.infer<typeof ModuleManifest>;
type Req = Parameters<IPolicyEngine["check"]>[0];

/** Hard limits: bloqueados por diseño, sin importar autorización, modo ni rol. */
const HARD_LIMIT_PATTERNS = /(dos|ddos|flood|stress|brute|crack|spray|wipe|drop[-_]?table|delete[-_]?logs?|clear[-_]?logs?|persist|backdoor|implant|malware|ransom|exfil|dump[-_]?(creds|db)|lateral|pivot|worm|propagat)/i;

export interface PolicyOptions {
  now?: () => Date;
  resolver?: (host: string) => Promise<string[]>;
  labNets?: Target[];
  manifests?: Map<string, Manifest>;
}

export class PolicyEngine implements IPolicyEngine {
  private buckets = new Map<string, { tokens: number; ts: number }>();
  private totals = new Map<string, number>();
  private now: () => Date;
  private resolver: (host: string) => Promise<string[]>;
  private labNets: Target[];
  private manifests: Map<string, Manifest>;

  constructor(private store: Store, o: PolicyOptions = {}) {
    this.now = o.now ?? (() => new Date());
    this.resolver = o.resolver ?? (async h => (await lookup(h, { all: true })).map(r => r.address));
    this.labNets = o.labNets ?? DEFAULT_LAB_NETS;
    this.manifests = o.manifests ?? new Map();
  }

  async check(req: Req): Promise<Decision> {
    const reasons = await this.evaluate(req);
    const decisionId = randomUUID();
    this.store.audit({
      actor: req.actor, role: req.actor, action: `policy:${reasons.length ? "deny" : "allow"}`,
      assessmentId: req.assessmentId, decisionId,
      payload: { module: req.module, mode: req.mode, target: req.target, reasons },
    });
    if (reasons.length) return { allow: false, decisionId, reasons: reasons as [Deny, ...Deny[]] };
    return { allow: true, decisionId, expiresAt: new Date(this.now().getTime() + 15_000).toISOString() };
  }

  /** Revalidación de operaciones DENTRO de una ejecución ya aprobada (cada conexión/redirect): no consume aprobación, sí aplica todo lo demás. */
  async recheck(req: Req): Promise<Decision> {
    return this.check({ ...req, _preApproved: true } as Req);
  }

  resolve(host: string): Promise<string[]> { return isIP(host) ? Promise.resolve([host]) : this.resolver(host); }

  /** Valida las IP finales a las que se conectará el Gateway (anti DNS-rebinding / TOCTOU). */
  verifyIps(assessmentId: string, mode: Req["mode"], ips: string[]): Deny | null {
    const rec = this.store.getAssessment(assessmentId);
    if (!rec || !rec.signatureValid || !ips.length) return "DNS_RESOLVES_OUT_OF_SCOPE";
    const excl = rec.a.exclusions.flatMap(e => (e.target ? [e.target] : []));
    for (const ip of ips) {
      if (excl.length && ipInTargets(ip, excl)) return "TARGET_EXCLUDED";
      if (mode === "lab" && !ipInTargets(ip, this.labNets)) return "LAB_TARGET_NOT_LOCAL";
      if (ipInTargets(ip, SENSITIVE_NETS) && !ipInTargets(ip, rec.a.scope)) return "DNS_RESOLVES_OUT_OF_SCOPE";
    }
    return null;
  }

  /** scope_validate: consulta pura (sin consumir aprobación ni rate limit). */
  validateScope(assessmentId: string, target: Target, actor: Req["actor"]): { authorized: boolean; reasons: Deny[] } {
    let reasons: Deny[] = [];
    const rec = this.store.getAssessment(assessmentId);
    if (!rec) reasons = ["NO_ACTIVE_ASSESSMENT"];
    else if (!rec.signatureValid) reasons = ["SIGNATURE_INVALID"];
    else if (!targetMatches(target, rec.a.scope)) reasons = ["TARGET_OUT_OF_SCOPE"];
    else if (rec.a.exclusions.some(e => e.target && (targetMatches(target, [e.target]) || this.overlaps(target, e.target)))) reasons = ["TARGET_EXCLUDED"];
    this.store.audit({ actor, role: actor, action: "scope_validate", assessmentId, payload: { target, reasons } });
    return { authorized: reasons.length === 0, reasons };
  }

  /** Devuelve los motivos de denegación; vacío = permitido. Falla cerrado ante cualquier error. */
  private async evaluate(req: Req): Promise<Deny[]> {
    try {
      // 1. Kill switch
      if (this.store.killSwitchActive()) return ["KILL_SWITCH_ACTIVE"];

      // 2. Autorización existente y firma íntegra
      const rec = this.store.getAssessment(req.assessmentId);
      if (!rec) return ["NO_ACTIVE_ASSESSMENT"];
      if (!rec.signatureValid) return ["SIGNATURE_INVALID"];
      const a = rec.a;

      // 3. Hard limits (módulo, técnica y parámetros)
      const haystack = [req.module, req.action ?? "", ...Object.keys(req.params ?? {}), ...Object.values(req.params ?? {}).map(String)].join(" ");
      if (HARD_LIMIT_PATTERNS.test(haystack)) return ["HARD_LIMIT"];

      // 4. Permisos por rol (el agente nunca autoriza ni aprueba)
      const action = req.action ?? "scan_initiate";
      if (!RolePermissions[req.actor]?.includes(action)) return ["APPROVAL_REQUIRED"];

      // 5. Estado del ciclo de vida
      if (action === "scan_initiate" && !EXECUTABLE_STATES.includes(a.state as State)) return ["STATE_TRANSITION_INVALID"];

      // 6. Modo y módulo
      if (!a.allowedModes.includes(req.mode)) return ["MODE_NOT_ALLOWED"];
      if (!a.allowedModules.includes(req.module)) return ["MODULE_NOT_ALLOWED"];
      const manifest = this.manifests.get(req.module);
      if (manifest && !manifest.modes.includes(req.mode)) return ["MODE_NOT_ALLOWED"];
      if (a.exclusions.some(e => e.technique && (e.technique === req.module || e.technique === req.action))) return ["TECHNIQUE_EXCLUDED"];

      // 7. Ventana de ejecución
      if (!this.inWindow(a.window)) return ["OUTSIDE_WINDOW"];

      // 8. Alcance y exclusiones (backend, no el chat)
      if (!targetMatches(req.target, a.scope)) return ["TARGET_OUT_OF_SCOPE"];
      if (a.exclusions.some(e => e.target && (targetMatches(req.target, [e.target]) || this.overlaps(req.target, e.target)))) return ["TARGET_EXCLUDED"];

      // 9. Modo laboratorio: solo localhost/Docker. Pasivo: sin red (lo aplica el Gateway), aquí no se resuelve DNS.
      if (req.mode === "lab" && !isLabTarget(req.target, this.labNets)) return ["LAB_TARGET_NOT_LOCAL"];
      if (req.mode === "active") {
        const dnsReason = await this.checkDns(req.target, a.scope, a.exclusions.flatMap(e => (e.target ? [e.target] : [])));
        if (dnsReason) return [dnsReason];
      }

      // 10. Aprobación humana: obligatoria en modo activo y en toda prueba que cambie estado
      if (!(req as any)._preApproved && (req.mode === "active" || req.changesState || manifest?.changesState)) {
        if (!req.planId || !req.approvalToken) return ["APPROVAL_REQUIRED"];
        if (!this.store.consumeApproval(req.planId, req.approvalToken, { assessmentId: req.assessmentId, moduleId: req.module, target: req.target })) return ["APPROVAL_REQUIRED"];
      }

      // 11. Rate limiting y tope de peticiones (se consume una unidad por decisión permitida)
      if (!this.takeToken(a.id, a.window.maxRequestsPerSecond, a.window.maxTotalRequests)) return ["RATE_LIMIT"];
      return [];
    } catch {
      return ["HARD_LIMIT"]; // fallo cerrado
    }
  }

  private inWindow(w: { notBefore: string; notAfter: string; allowedHours?: { from: string; to: string; tz: string } }): boolean {
    const t = this.now().getTime();
    if (t < Date.parse(w.notBefore) || t > Date.parse(w.notAfter)) return false;
    if (!w.allowedHours) return true;
    const parts = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: w.allowedHours.tz }).format(this.now());
    const cur = parts.replace("24:", "00:");
    const { from, to } = w.allowedHours;
    return from <= to ? cur >= from && cur <= to : cur >= from || cur <= to; // admite ventanas nocturnas
  }

  private overlaps(t: Target, ex: Target): boolean {
    // un CIDR objetivo que contiene un activo excluido también se rechaza
    return t.type === "cidr" && (ex.type === "ip" || ex.type === "cidr") && ipInTargets(ex.type === "ip" ? ex.value : ex.value.split("/")[0], [t]);
  }

  /** Anti DNS-rebinding: cada IP resuelta debe seguir dentro del alcance y fuera de exclusiones. */
  private async checkDns(target: Target, scope: Target[], excl: Target[]): Promise<Deny | null> {
    const host = hostOf(target);
    if (!host || target.type === "cidr" || target.type === "device") return null;
    const ips = isIP(host) ? [host] : await this.resolver(host);
    if (!ips.length) return "DNS_RESOLVES_OUT_OF_SCOPE";
    for (const ip of ips) {
      if (excl.length && ipInTargets(ip, excl)) return "TARGET_EXCLUDED";
      if (ipInTargets(ip, SENSITIVE_NETS) && !ipInTargets(ip, scope)) return "DNS_RESOLVES_OUT_OF_SCOPE";
    }
    return null;
  }

  private takeToken(id: string, rps: number, maxTotal?: number): boolean {
    const nowMs = this.now().getTime();
    const b = this.buckets.get(id) ?? { tokens: rps, ts: nowMs };
    b.tokens = Math.min(rps, b.tokens + ((nowMs - b.ts) / 1000) * rps);
    b.ts = nowMs;
    if (b.tokens < 1) { this.buckets.set(id, b); return false; }
    const total = (this.totals.get(id) ?? 0) + 1;
    if (maxTotal !== undefined && total > maxTotal) return false;
    b.tokens -= 1; this.totals.set(id, total); this.buckets.set(id, b);
    return true;
  }
}
