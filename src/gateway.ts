import { connect } from "node:net";
import tls from "node:tls";
import { Resolver } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import type { PolicyEngine } from "./policy.js";
import type { Target } from "./scope.js";
import { hostOf } from "./scope.js";

export type Mode = "passive" | "lab" | "active";
export interface Grant { assessmentId: string; mode: Mode; actor: "operator" | "agent" | "authorizer" | "analyst" | "auditor"; module: string }

export class GatewayDenied extends Error {
  constructor(public reasons: string[]) { super(`Gateway: operación denegada (${reasons.join(",")})`); }
}

/**
 * Único camino a la red. Cada operación se revalida contra el Policy Engine (alcance, ventana, rate limit,
 * kill switch) y se conecta SOLO a la IP validada (pinning), de modo que un cambio de DNS posterior no sirve.
 * El modo pasivo no puede abrir conexiones.
 */
export class Gateway {
  constructor(private policy: PolicyEngine) {}

  /** Revalida la operación. Si solo falla por ritmo (RATE_LIMIT) espera y reintenta: respetar el límite es lo correcto, no un error. */
  private async admit(g: Grant, target: Target, signal?: AbortSignal) {
    if (g.mode === "passive") throw new GatewayDenied(["MODE_NOT_ALLOWED"]);
    for (let i = 0; ; i++) {
      const d = await this.policy.recheck({ assessmentId: g.assessmentId, actor: g.actor, mode: g.mode, module: g.module, target, changesState: false });
      if (d.allow) return;
      if (d.reasons.length === 1 && d.reasons[0] === "RATE_LIMIT" && i < 60 && !signal?.aborted) { await new Promise(r => setTimeout(r, 200)); continue; }
      throw new GatewayDenied(d.reasons);
    }
  }

  private async authorize(g: Grant, target: Target, signal?: AbortSignal): Promise<string[]> {
    await this.admit(g, target, signal);
    const host = hostOf(target)!;
    const ips = await this.policy.resolve(host);
    const bad = await this.policy.verifyIps(g.assessmentId, g.mode, ips);
    if (bad) throw new GatewayDenied([bad]);
    return ips;
  }

  async tcpProbe(g: Grant, host: string, port: number, signal: AbortSignal, timeoutMs = 1500): Promise<"open" | "closed" | "filtered"> {
    const target: Target = isIP(host) ? { type: "ip", value: host } : { type: "domain", value: host, includeSubdomains: false };
    const [ip] = await this.authorize(g, target, signal);
    return new Promise(resolve => {
      const s = connect({ host: ip, port });
      const done = (r: "open" | "closed" | "filtered") => { s.destroy(); resolve(r); };
      s.setTimeout(timeoutMs, () => done("filtered"));
      s.once("connect", () => done("open"));
      s.once("error", (e: NodeJS.ErrnoException) => done(e.code === "ECONNREFUSED" ? "closed" : "filtered"));
      signal.addEventListener("abort", () => done("filtered"), { once: true });
    });
  }

  /** Solo lee estado y cabeceras (nunca el cuerpo). No sigue redirects: los devuelve para revalidarlos. */
  async httpHead(g: Grant, url: string, signal: AbortSignal, opts: { method?: "HEAD" | "GET" | "POST" | "OPTIONS" | "TRACE"; body?: string; timeoutMs?: number; headers?: Record<string, string>; peekBytes?: number } = {}) {
    const u = new URL(url);
    const [ip] = await this.authorize(g, { type: "url", value: url }, signal);
    const lib = u.protocol === "https:" ? https : http;
    return new Promise<{ status: number; headers: http.IncomingHttpHeaders; location?: string; peek?: string }>((resolve, reject) => {
      const req = lib.request({
        host: u.hostname.replace(/^\[|\]$/g, ""), port: u.port || undefined, path: u.pathname + u.search, method: opts.method ?? "HEAD",
        headers: { "User-Agent": "EthicalSecurityCopilot/0.1", ...(opts.headers ?? {}) }, signal, timeout: opts.timeoutMs ?? 5000,
        lookup: (_h, _o, cb) => (_o as any)?.all ? (cb as any)(null, [{ address: ip, family: isIP(ip) }]) : (cb as any)(null, ip, isIP(ip)), // pinning a la IP validada
        servername: u.hostname,
      }, res => {
        const base = { status: res.statusCode ?? 0, headers: res.headers, location: typeof res.headers.location === "string" ? new URL(res.headers.location, url).toString() : undefined };
        const max = Math.min(opts.peekBytes ?? 0, 1024);
        if (!max) { res.destroy(); return resolve(base); } // por defecto no se lee el cuerpo
        // Lectura mínima (hasta `max` bytes) solo para reconocer una firma; el contenido nunca se devuelve a quien llama sin que el módulo lo filtre.
        const bufs: Buffer[] = []; let n = 0;
        const finish = () => { res.destroy(); resolve({ ...base, peek: Buffer.concat(bufs).subarray(0, max).toString("latin1") }); };
        res.on("data", (c: Buffer) => { bufs.push(c); n += c.length; if (n >= max) finish(); });
        res.on("end", finish); res.on("error", finish);
      });
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", reject);
      if (opts.body) req.write(opts.body);
      req.end();
    });
  }

  /** Apretón de manos TLS a la IP validada (sin enviar datos de aplicación). `legacy` intenta versiones antiguas para saber si el servidor las acepta. */
  async tlsHandshake(g: Grant, host: string, port: number, signal: AbortSignal, opts: { minVersion?: tls.SecureVersion; maxVersion?: tls.SecureVersion; legacy?: boolean; timeoutMs?: number } = {}) {
    const target: Target = isIP(host) ? { type: "ip", value: host } : { type: "domain", value: host, includeSubdomains: false };
    const [ip] = await this.authorize(g, target, signal);
    return new Promise<{ ok: true; protocol: string | null; cipher: string; authorized: boolean; authError?: string; cert: any } | { ok: false; error: string }>(resolve => {
      let done = false;
      const fin = (r: any, s?: tls.TLSSocket) => { if (done) return; done = true; s?.destroy(); resolve(r); };
      try {
        const s = tls.connect({
          host: ip, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false,
          minVersion: opts.minVersion, maxVersion: opts.maxVersion, ciphers: opts.legacy ? "ALL:@SECLEVEL=0" : undefined,
          ALPNProtocols: undefined,
        }, () => fin({ ok: true, protocol: s.getProtocol(), cipher: s.getCipher()?.name ?? "", authorized: s.authorized, authError: s.authorizationError ? String(s.authorizationError) : undefined, cert: s.getPeerCertificate(false) }, s));
        s.setTimeout(opts.timeoutMs ?? 4000, () => fin({ ok: false, error: "timeout" }, s));
        s.once("error", (e: NodeJS.ErrnoException) => fin({ ok: false, error: e.code ?? e.message }, s));
        signal.addEventListener("abort", () => fin({ ok: false, error: "aborted" }, s), { once: true });
      } catch (e) { fin({ ok: false, error: (e as Error).message }); }
    });
  }

  /** Consulta DNS de nombres bajo el dominio autorizado (p. ej. _dmarc.<dominio>). No conecta con el objetivo: solo lee registros públicos. */
  async dnsRecords(g: Grant, domain: string, name: string, type: "TXT" | "MX" | "CAA" | "NS", signal: AbortSignal): Promise<string[] | null> {
    await this.admit(g, { type: "domain", value: domain, includeSubdomains: false }, signal);
    if (name !== domain && !name.endsWith("." + domain)) throw new GatewayDenied(["TARGET_OUT_OF_SCOPE"]); // solo nombres dentro de la zona autorizada
    const r = new Resolver({ timeout: 3000, tries: 2 });
    try {
      if (type === "TXT") return (await r.resolveTxt(name)).map(parts => parts.join(""));
      if (type === "MX") return (await r.resolveMx(name)).map(m => `${m.priority} ${m.exchange}`);
      if (type === "NS") return await r.resolveNs(name);
      return (await r.resolveCaa(name)).map(c => `${c.critical ? 128 : 0} ${(c as any).issue ? "issue" : (c as any).issuewild ? "issuewild" : "iodef"} ${(c as any).issue ?? (c as any).issuewild ?? (c as any).iodef}`);
    } catch (e) {
      const c = (e as NodeJS.ErrnoException).code;
      if (c === "ENODATA" || c === "ENOTFOUND" || c === "NXDOMAIN") return [];
      return null; // no se pudo consultar (distinto de «no existe»)
    }
  }
}
