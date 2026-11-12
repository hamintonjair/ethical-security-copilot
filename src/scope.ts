import { BlockList, isIP } from "node:net";
import type { z } from "zod";
import type { ScopeTarget } from "./schemas.js";

export type Target = z.infer<typeof ScopeTarget>;

/** Normaliza host: minúsculas, sin punto final, IDN→punycode (vía URL). Devuelve null si es inválido. */
export function normalizeHost(raw: string): string | null {
  let h = raw.trim().toLowerCase();
  if (!h) return null;
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (isIP(h)) return h;
  if (h.endsWith(".")) h = h.slice(0, -1);
  try {
    const u = new URL(`http://${h}`); // el parser normaliza formas raras (127.1, 2130706433, 0x7f.1)
    if (u.username || u.password || u.port || u.pathname !== "/" || u.search || u.hash) return null;
    const host = u.hostname.startsWith("[") ? u.hostname.slice(1, -1) : u.hostname;
    return host || null;
  } catch { return null; }
}

function parseCidr(v: string): { addr: string; prefix: number; family: "ipv4" | "ipv6" } | null {
  const [addr, p] = v.split("/");
  const fam = isIP(addr);
  const prefix = Number(p);
  if (!fam || !Number.isInteger(prefix) || prefix < 0 || prefix > (fam === 4 ? 32 : 128)) return null;
  return { addr, prefix, family: fam === 4 ? "ipv4" : "ipv6" };
}

function listFrom(targets: Target[]): BlockList {
  const bl = new BlockList();
  for (const t of targets) {
    if (t.type === "ip") bl.addAddress(t.value, isIP(t.value) === 4 ? "ipv4" : "ipv6");
    else if (t.type === "cidr") { const c = parseCidr(t.value); if (c) bl.addSubnet(c.addr, c.prefix, c.family); }
  }
  return bl;
}

export function ipInTargets(ip: string, targets: Target[]): boolean {
  const fam = isIP(ip);
  if (!fam) return false;
  let addr = ip;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip); // IPv4 mapeada en IPv6
  if (m) addr = m[1];
  return listFrom(targets).check(addr, isIP(addr) === 4 ? "ipv4" : "ipv6");
}

function hostMatchesDomain(host: string, d: Extract<Target, { type: "domain" }>): boolean {
  const base = d.value.replace(/^\*\./, "").toLowerCase();
  const wildcard = d.value.startsWith("*.") || d.includeSubdomains;
  if (host === base && !d.value.startsWith("*.")) return true;
  return wildcard && host.endsWith("." + base);
}

/** ¿Está `target` completamente contenido en alguno de `list`? Conservador: ante duda, false. */
export function targetMatches(target: Target, list: Target[]): boolean {
  switch (target.type) {
    case "ip": return ipInTargets(target.value, list);
    case "cidr": {
      const c = parseCidr(target.value);
      if (!c) return false;
      // contenido solo si algún scope CIDR es igual o más amplio y contiene la base
      return list.some(s => {
        if (s.type !== "cidr") return false;
        const sc = parseCidr(s.value);
        return !!sc && sc.family === c.family && sc.prefix <= c.prefix && ipInTargets(c.addr, [s]);
      });
    }
    case "domain": {
      const host = normalizeHost(target.value.replace(/^\*\./, ""));
      if (!host) return false;
      if (target.value.startsWith("*.") || target.includeSubdomains) {
        // un wildcard solo cabe en un scope igual de amplio
        return list.some(s => s.type === "domain" && (s.value.startsWith("*.") || s.includeSubdomains) &&
          (host === s.value.replace(/^\*\./, "").toLowerCase() || host.endsWith("." + s.value.replace(/^\*\./, "").toLowerCase())));
      }
      return list.some(s => s.type === "domain" && hostMatchesDomain(host, s));
    }
    case "url": {
      let u: URL;
      try { u = new URL(target.value); } catch { return false; }
      if (!/^https?:$/.test(u.protocol) || u.username || u.password) return false; // bloquea http://ok.com@evil.com
      const host = normalizeHost(u.hostname);
      if (!host) return false;
      const path = decodeURIComponent(u.pathname).replace(/\/{2,}/g, "/");
      if (path.split("/").includes("..")) return false;
      return list.some(s => {
        if (s.type === "domain") return hostMatchesDomain(host, s);
        if (s.type === "ip" || s.type === "cidr") return ipInTargets(host, [s]);
        if (s.type === "url") {
          let su: URL; try { su = new URL(s.value); } catch { return false; }
          if (su.origin !== u.origin) return false;
          const prefix = s.pathPrefix ?? su.pathname;
          return prefix === "/" || path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : prefix + "/");
        }
        return false;
      });
    }
    case "device": return list.some(s => s.type === "device" && s.value === target.value);
  }
}

/** Host que realmente se contactaría (para DNS y modo laboratorio). */
export function hostOf(target: Target): string | null {
  switch (target.type) {
    case "ip": return target.value;
    case "cidr": return target.value.split("/")[0];
    case "domain": return normalizeHost(target.value.replace(/^\*\./, ""));
    case "url": try { return normalizeHost(new URL(target.value).hostname); } catch { return null; }
    case "device": return null;
  }
}

export const DEFAULT_LAB_NETS: Target[] = [
  { type: "cidr", value: "127.0.0.0/8" }, { type: "ip", value: "::1" }, { type: "cidr", value: "172.28.0.0/16" }, // red docker-compose del laboratorio
];

export function isLabTarget(target: Target, labNets: Target[] = DEFAULT_LAB_NETS): boolean {
  const h = hostOf(target);
  if (!h) return false;
  if (h === "localhost" || h.endsWith(".lab.internal")) return true;
  if (target.type === "cidr") return targetMatches(target, labNets);
  return isIP(h) !== 0 && ipInTargets(h, labNets);
}

/** Rangos que nunca se alcanzan por DNS salvo que el scope los cubra explícitamente. */
export const SENSITIVE_NETS: Target[] = [
  { type: "cidr", value: "127.0.0.0/8" }, { type: "ip", value: "::1" }, { type: "cidr", value: "169.254.0.0/16" },
  { type: "cidr", value: "10.0.0.0/8" }, { type: "cidr", value: "172.16.0.0/12" }, { type: "cidr", value: "192.168.0.0/16" },
  { type: "cidr", value: "100.64.0.0/10" }, { type: "cidr", value: "fe80::/10" }, { type: "cidr", value: "fc00::/7" },
];

/** Red de seguridad: un alcance autorizado no puede ser "casi todo Internet". Devuelve el motivo o null. */
export function broadScopeProblem(targets: Target[]): string | null {
  for (const t of targets) {
    if (t.type !== "cidr") continue;
    const c = parseCidr(t.value);
    if (!c) return `El rango ${t.value} no es válido.`;
    if (c.family === "ipv4" && c.prefix < 16) return `El rango ${t.value} es demasiado amplio (mínimo /16).`;
    if (c.family === "ipv6" && c.prefix < 48) return `El rango ${t.value} es demasiado amplio (mínimo /48).`;
  }
  return null;
}
