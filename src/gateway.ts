import { connect } from "node:net";
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

  private async authorize(g: Grant, target: Target): Promise<string[]> {
    if (g.mode === "passive") throw new GatewayDenied(["MODE_NOT_ALLOWED"]);
    const d = await this.policy.recheck({ assessmentId: g.assessmentId, actor: g.actor, mode: g.mode, module: g.module, target, changesState: false });
    if (!d.allow) throw new GatewayDenied(d.reasons);
    const host = hostOf(target)!;
    const ips = await this.policy.resolve(host);
    const bad = this.policy.verifyIps(g.assessmentId, g.mode, ips);
    if (bad) throw new GatewayDenied([bad]);
    return ips;
  }

  async tcpProbe(g: Grant, host: string, port: number, signal: AbortSignal, timeoutMs = 1500): Promise<"open" | "closed" | "filtered"> {
    const target: Target = isIP(host) ? { type: "ip", value: host } : { type: "domain", value: host, includeSubdomains: false };
    const [ip] = await this.authorize(g, target);
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
  async httpHead(g: Grant, url: string, signal: AbortSignal, opts: { method?: "HEAD" | "GET" | "POST"; body?: string; timeoutMs?: number } = {}) {
    const u = new URL(url);
    const [ip] = await this.authorize(g, { type: "url", value: url });
    const lib = u.protocol === "https:" ? https : http;
    return new Promise<{ status: number; headers: http.IncomingHttpHeaders; location?: string }>((resolve, reject) => {
      const req = lib.request({
        host: u.hostname.replace(/^\[|\]$/g, ""), port: u.port || undefined, path: u.pathname + u.search, method: opts.method ?? "HEAD",
        headers: { "User-Agent": "EthicalSecurityCopilot/0.1" }, signal, timeout: opts.timeoutMs ?? 5000,
        lookup: (_h, _o, cb) => (_o as any)?.all ? (cb as any)(null, [{ address: ip, family: isIP(ip) }]) : (cb as any)(null, ip, isIP(ip)), // pinning a la IP validada
        servername: u.hostname,
      }, res => {
        res.destroy(); // no se lee el cuerpo
        resolve({ status: res.statusCode ?? 0, headers: res.headers, location: typeof res.headers.location === "string" ? new URL(res.headers.location, url).toString() : undefined });
      });
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", reject);
      if (opts.body) req.write(opts.body);
      req.end();
    });
  }
}
