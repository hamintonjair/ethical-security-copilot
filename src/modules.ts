import type { z } from "zod";
import type { ModuleManifest } from "./schemas.js";
import { Gateway, GatewayDenied, type Grant } from "./gateway.js";
import { hostOf, type Target } from "./scope.js";

type Manifest = z.infer<typeof ModuleManifest>;
export interface Suggestion { title: string; severity: "info" | "low" | "medium" | "high" | "critical"; asset: string; detail: string }
export interface ModuleResult { facts: string[]; suggestions: Suggestion[] }
export interface RunCtx { grant: Grant; gateway: Gateway; target: Target; params: Record<string, string | number | boolean>; signal: AbortSignal; maxConcurrency: number }
export interface Module { manifest: Manifest; run(ctx: RunCtx): Promise<ModuleResult> }

const builtin = (id: string, category: Manifest["category"], modes: Manifest["modes"], changesState = false): Manifest => ({
  id, category, modes, changesState, intrusive: false, runner: { image: "builtin", args: [], timeoutSec: 60 },
});
const assetOf = (t: Target) => (t.type === "cidr" ? t.value : t.value);

/* ---------- Pasivo: análisis estático de configuración que aporta el usuario (sin red) ---------- */
const CONFIG_RULES: { re: RegExp; title: string; severity: Suggestion["severity"] }[] = [
  { re: /^\s*PermitRootLogin\s+yes/im, title: "SSH permite login directo de root", severity: "high" },
  { re: /^\s*PasswordAuthentication\s+yes/im, title: "SSH acepta autenticación por contraseña", severity: "medium" },
  { re: /ssl_protocols[^;\n]*TLSv1(\.0|\.1)?(?![.\d])/i, title: "Protocolos TLS obsoletos habilitados", severity: "medium" },
  { re: /^\s*autoindex\s+on/im, title: "Listado de directorios habilitado", severity: "low" },
  { re: /^\s*server_tokens\s+on/im, title: "El servidor revela su versión", severity: "low" },
  { re: /Access-Control-Allow-Origin["']?\s*[:,]?\s*["']?\*/i, title: "CORS abierto a cualquier origen", severity: "medium" },
  { re: /^\s*(debug|DEBUG)\s*[=:]\s*(true|1|on)\b/m, title: "Modo debug activo", severity: "medium" },
  { re: /(password|passwd|secret|api[_-]?key)\s*[=:]\s*["']?(?!\s)[^\s"']{4,}/i, title: "Posibles credenciales en texto claro en la configuración", severity: "high" },
];
export const configAudit: Module = {
  manifest: builtin("config_audit", "surface", ["passive", "lab", "active"]),
  async run({ target, params }) {
    const content = String(params.content ?? "");
    if (!content) return { facts: ["No se proporcionó `content` para analizar."], suggestions: [] };
    if (content.length > 100_000) throw new Error("content demasiado grande (máx. 100 KB)");
    const hits = CONFIG_RULES.filter(r => r.re.test(content));
    return {
      facts: [`Se analizaron ${content.split("\n").length} líneas de configuración sin acceso a red.`, ...hits.map(h => `Coincidencia de configuración insegura: ${h.title}`)],
      suggestions: hits.map(h => ({ title: h.title, severity: h.severity, asset: assetOf(target), detail: "Detectado por análisis estático; requiere verificación en el entorno." })),
    };
  },
};

/* ---------- Descubrimiento: puertos TCP (connect simple, concurrencia limitada) ---------- */
export const tcpPortCheck: Module = {
  manifest: builtin("tcp_port_check", "discovery", ["lab", "active"]),
  async run({ grant, gateway, target, params, signal, maxConcurrency }) {
    const host = hostOf(target);
    if (!host || target.type === "cidr") throw new Error("tcp_port_check requiere un host concreto (ip o dominio)");
    const ports = [...new Set(String(params.ports ?? "80,443").split(",").map(p => Number(p.trim())))].filter(p => Number.isInteger(p) && p > 0 && p < 65536);
    if (!ports.length || ports.length > 32) throw new Error("ports: entre 1 y 32 puertos válidos");
    const results = new Map<number, string>();
    const queue = [...ports];
    await Promise.all(Array.from({ length: Math.min(maxConcurrency, queue.length) }, async () => {
      for (let p = queue.shift(); p !== undefined && !signal.aborted; p = queue.shift()) results.set(p, await gateway.tcpProbe(grant, host, p, signal));
    }));
    const open = ports.filter(p => results.get(p) === "open");
    return {
      facts: ports.map(p => `${host}:${p} → ${results.get(p) ?? "no probado"}`),
      suggestions: open.map(p => ({ title: `Puerto ${p}/tcp expuesto`, severity: "info" as const, asset: `${host}:${p}`, detail: "Puerto accesible; confirmar si el servicio debe estar expuesto." })),
    };
  },
};

/* ---------- Superficie web: cabeceras de seguridad y banners (solo cabeceras, redirects revalidados) ---------- */
const SEC_HEADERS: [string, string, Suggestion["severity"]][] = [
  ["content-security-policy", "Falta Content-Security-Policy", "low"],
  ["x-content-type-options", "Falta X-Content-Type-Options", "low"],
  ["x-frame-options", "Falta X-Frame-Options (o frame-ancestors en CSP)", "low"],
];
export const httpHeaderAudit: Module = {
  manifest: builtin("http_header_audit", "webmobile", ["lab", "active"]),
  async run({ grant, gateway, target, signal }) {
    if (target.type !== "url") throw new Error("http_header_audit requiere un target de tipo url");
    const facts: string[] = []; const suggestions: Suggestion[] = [];
    let url = target.value;
    for (let hop = 0; hop < 4; hop++) {
      let r;
      try { r = await gateway.httpHead(grant, url, signal, { method: "HEAD" }); }
      catch (e) {
        if (e instanceof GatewayDenied) { facts.push(`Salto ${hop + 1} bloqueado por política (${e.reasons.join(",")}): ${url}`); break; }
        throw e;
      }
      facts.push(`HEAD ${url} → ${r.status}`);
      if (r.status >= 300 && r.status < 400 && r.location) { facts.push(`Redirección a ${r.location}`); url = r.location; continue; }
      const h = r.headers;
      for (const [name, title, severity] of SEC_HEADERS) {
        if (name === "x-frame-options" && /frame-ancestors/i.test(String(h["content-security-policy"] ?? ""))) continue;
        if (!h[name]) { facts.push(`Ausente: ${name}`); suggestions.push({ title, severity, asset: url, detail: `La respuesta no incluye ${name}.` }); }
      }
      if (url.startsWith("https:") && !h["strict-transport-security"]) { facts.push("Ausente: strict-transport-security"); suggestions.push({ title: "Falta HSTS", severity: "low", asset: url, detail: "HTTPS sin Strict-Transport-Security." }); }
      for (const name of ["server", "x-powered-by"] as const) {
        const v = String(h[name] ?? "");
        if (/\d+\.\d+/.test(v)) { facts.push(`Banner con versión: ${name}: ${v}`); suggestions.push({ title: `Divulgación de versión en ${name}`, severity: "low", asset: url, detail: `Cabecera ${name}: ${v}` }); }
      }
      break;
    }
    return { facts, suggestions };
  },
};

/* ---------- Laboratorio: prueba que cambia estado (POST inofensivo con marcador) — exige confirmación humana ---------- */
export const labWriteProbe: Module = {
  manifest: builtin("lab_write_probe", "verification", ["lab"], true),
  async run({ grant, gateway, target, signal }) {
    if (target.type !== "url") throw new Error("lab_write_probe requiere un target de tipo url");
    const r = await gateway.httpHead(grant, target.value, signal, { method: "POST", body: "esc-marker=harmless" });
    return { facts: [`POST inofensivo con marcador a ${target.value} → ${r.status}`], suggestions: [] };
  },
};

export const builtinModules = (): Map<string, Module> => new Map([configAudit, tcpPortCheck, httpHeaderAudit, labWriteProbe].map(m => [m.manifest.id, m]));
