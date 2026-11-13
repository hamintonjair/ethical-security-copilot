// Lote 1 — superficie web. Todos son de solo lectura: handshakes, consultas DNS y peticiones inofensivas con límites.
// Cada operación pasa por el Gateway (alcance, ventana, ritmo, kill switch). Nunca se guardan ni devuelven cuerpos, valores de cookies ni secretos.
import { isIP } from "node:net";
import { randomBytes } from "node:crypto";
import type { z } from "zod";
import type { ModuleManifest } from "./schemas.js";
import type { Module, Suggestion } from "./modules.js";
import { GatewayDenied } from "./gateway.js";
import { hostOf, type Target } from "./scope.js";

type Manifest = z.infer<typeof ModuleManifest>;
const manifest = (id: string, category: Manifest["category"], modes: Manifest["modes"]): Manifest => ({ id, category, modes, changesState: false, intrusive: false, runner: { image: "builtin", args: [], timeoutSec: 60 } });
const sug = (title: string, severity: Suggestion["severity"], asset: string, detail: string, refs: string): Suggestion => ({ title, severity, asset, detail: `${detail} [${refs}]` });
const needUrl = (t: Target) => { if (t.type !== "url") throw new Error("Este módulo requiere un target de tipo url"); return new URL(t.value); };
const portOf = (v: unknown, def: number) => { const n = Number(v ?? def); if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error("port inválido"); return n; };

/* ---------- TLS ---------- */
const WEAK_CIPHER = /RC4|3DES|DES-CBC|NULL|EXPORT|MD5|ANON/i;
const INCONCLUSIVE = /NO_PROTOCOLS|NO_CIPHERS|INVALID_VERSION|INVALID_PROTOCOL|UNSUPPORTED_PROTOCOL.*CLIENT|bad ciphers|no protocols/i;
export const tlsAudit: Module = {
  manifest: manifest("tls_audit", "surface", ["lab", "active"]),
  async run({ grant, gateway, target, params, signal }) {
    const host = hostOf(target);
    if (!host || target.type === "cidr") throw new Error("tls_audit requiere un host concreto (ip, dominio o url)");
    const port = portOf(params.port ?? (target.type === "url" ? new URL(target.value).port : undefined), 443);
    const asset = `${host}:${port}`, facts: string[] = [], out: Suggestion[] = [];
    const main = await gateway.tlsHandshake(grant, host, port, signal);
    if (!main.ok) return { facts: [`No se pudo negociar TLS en ${asset} (${main.error}).`], suggestions: [] };
    facts.push(`${asset} negoció ${main.protocol} con ${main.cipher}.`);
    const c = main.cert ?? {};
    const validTo = c.valid_to ? new Date(c.valid_to) : null;
    const days = validTo ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : null;
    facts.push(`Certificado de «${c.subject?.CN ?? "?"}» emitido por «${c.issuer?.O ?? c.issuer?.CN ?? "?"}»${validTo ? `, vence el ${validTo.toISOString().slice(0, 10)} (${days} días)` : ""}.`);
    if (days !== null && days < 0) out.push(sug("Certificado TLS vencido", "high", asset, `Venció hace ${-days} días.`, "A04:2025 · CWE-298"));
    else if (days !== null && days < 14) out.push(sug("Certificado TLS a punto de vencer", "medium", asset, `Vence en ${days} días.`, "A04:2025"));
    else if (days !== null && days < 30) out.push(sug("Certificado TLS vence pronto", "low", asset, `Vence en ${days} días.`, "A04:2025"));
    if (!main.authorized && main.authError && !/EXPIRED/.test(main.authError)) out.push(sug("El certificado TLS no es de confianza para un cliente estándar", "medium", asset, `Error de validación: ${main.authError}.`, "A04:2025 · CWE-295"));
    if (!c.asn1Curve && !c.nistCurve && typeof c.bits === "number" && c.bits < 2048) out.push(sug("Clave RSA del certificado menor de 2048 bits", "medium", asset, `Tamaño: ${c.bits} bits.`, "A04:2025 · CWE-326"));
    if (WEAK_CIPHER.test(main.cipher)) out.push(sug("Cifrado débil negociado", "high", asset, `Cifrado: ${main.cipher}.`, "A04:2025 · CWE-327"));

    for (const [v, label] of [["TLSv1", "TLS 1.0"], ["TLSv1.1", "TLS 1.1"]] as const) {
      const r = await gateway.tlsHandshake(grant, host, port, signal, { minVersion: v, maxVersion: v, legacy: true });
      if (r.ok) { facts.push(`El servidor ACEPTA ${label}.`); out.push(sug(`El servidor acepta ${label}`, "medium", asset, `${label} está obsoleto (RFC 8996).`, "A04:2025 · CWE-326")); }
      else if (INCONCLUSIVE.test(r.error)) facts.push(`No concluyente: este cliente no puede probar ${label} (${r.error}).`);
      else facts.push(`El servidor rechaza ${label} (${r.error}).`);
    }
    const t13 = await gateway.tlsHandshake(grant, host, port, signal, { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
    facts.push(t13.ok ? "El servidor soporta TLS 1.3." : `No se confirmó TLS 1.3 (${t13.error}).`);
    if (!t13.ok && !INCONCLUSIVE.test(t13.error)) out.push(sug("Sin soporte de TLS 1.3", "info", asset, "Recomendado habilitarlo junto a TLS 1.2.", "A04:2025"));
    facts.push("No se comprobó la revocación del certificado (OCSP/CRL).");
    return { facts, suggestions: out };
  },
};

/* ---------- Seguimiento de redirecciones con revalidación (común a varios módulos) ---------- */
async function follow(ctx: Parameters<Module["run"]>[0], url: string, opts: Parameters<Parameters<Module["run"]>[0]["gateway"]["httpHead"]>[3] = {}, hops = 3) {
  const trail: { url: string; status: number; headers: Record<string, any> }[] = [];
  let cur = url;
  for (let i = 0; i <= hops; i++) {
    let r;
    try { r = await ctx.gateway.httpHead(ctx.grant, cur, ctx.signal, opts); }
    catch (e) { if (e instanceof GatewayDenied) { trail.push({ url: cur, status: -1, headers: { "x-esc-denied": e.reasons.join(",") } }); break; } throw e; }
    trail.push({ url: cur, status: r.status, headers: r.headers });
    if (r.status >= 300 && r.status < 400 && r.location) { cur = r.location; continue; }
    break;
  }
  return trail;
}

/* ---------- Cookies ---------- */
const SESSIONISH = /sess|sid|auth|token|jwt|login|remember|csrf|xsrf/i;
export const cookieAudit: Module = {
  manifest: manifest("cookie_audit", "webmobile", ["lab", "active"]),
  async run(ctx) {
    needUrl(ctx.target);
    const facts: string[] = [], out: Suggestion[] = [];
    const trail = await follow(ctx, ctx.target.value, { method: "GET" });
    let seen = 0;
    for (const hop of trail) {
      if (hop.status === -1) { facts.push(`Salto bloqueado por política (${hop.headers["x-esc-denied"]}): ${hop.url}`); continue; }
      const https = hop.url.startsWith("https:");
      for (const raw of (hop.headers["set-cookie"] as string[] | undefined) ?? []) {
        seen++;
        const [pair, ...attrs] = raw.split(";").map(s => s.trim());
        const name = pair.split("=")[0]; // el valor NUNCA se guarda
        const flags = new Set(attrs.map(a => a.split("=")[0].toLowerCase()));
        const samesite = attrs.find(a => /^samesite=/i.test(a))?.split("=")[1]?.toLowerCase();
        facts.push(`Cookie «${name}»: ${https ? "https" : "http"}; Secure=${flags.has("secure")}; HttpOnly=${flags.has("httponly")}; SameSite=${samesite ?? "no definido"}.`);
        const asset = `${hop.url} (cookie ${name})`, sensitive = SESSIONISH.test(name);
        if (https && !flags.has("secure")) out.push(sug(`Cookie «${name}» sin atributo Secure`, sensitive ? "medium" : "low", asset, "Puede enviarse por HTTP sin cifrar.", "A07:2025 · CWE-614"));
        if (!flags.has("httponly") && sensitive) out.push(sug(`Cookie «${name}» sin HttpOnly`, "medium", asset, "Un script de la página podría leerla (impacto de XSS).", "A07:2025 · CWE-1004"));
        if (!samesite) out.push(sug(`Cookie «${name}» sin SameSite`, "low", asset, "Sin SameSite el navegador aplica su valor por defecto; mejor declararlo.", "CWE-352"));
        if (samesite === "none" && !flags.has("secure")) out.push(sug(`Cookie «${name}» con SameSite=None sin Secure`, "medium", asset, "Los navegadores modernos la rechazan.", "CWE-1275"));
      }
    }
    if (!seen) facts.push("La respuesta no estableció cookies (en esta ruta y sin iniciar sesión).");
    return { facts, suggestions: out };
  },
};

/* ---------- CORS ---------- */
export const corsAudit: Module = {
  manifest: manifest("cors_audit", "webmobile", ["lab", "active"]),
  async run({ grant, gateway, target, signal }) {
    needUrl(target);
    const facts: string[] = [], out: Suggestion[] = [], asset = target.value;
    const EVIL = "https://esc-origen-no-autorizado.invalid";
    for (const origin of [EVIL, "null"]) {
      const r = await gateway.httpHead(grant, target.value, signal, { method: "GET", headers: { Origin: origin } });
      const acao = String(r.headers["access-control-allow-origin"] ?? ""), acac = String(r.headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true";
      const vary = String(r.headers["vary"] ?? "");
      facts.push(`Origin: ${origin} → ${r.status}; Allow-Origin: ${acao || "(ausente)"}; Allow-Credentials: ${acac}.`);
      if (acao === origin) {
        out.push(sug(origin === "null" ? "CORS acepta el origen «null»" : "CORS refleja cualquier origen", acac ? "high" : "medium", asset,
          acac ? "Con credenciales permitidas, otro sitio podría leer respuestas autenticadas del usuario." : "Cualquier sitio puede leer respuestas de esta URL desde un navegador.", "A02:2025 · API8:2023 · CWE-942"));
        if (!/origin/i.test(vary)) out.push(sug("CORS dinámico sin «Vary: Origin»", "low", asset, "Una caché podría servir la respuesta de un origen a otro.", "CWE-942"));
      } else if (acao === "*") out.push(sug("CORS abierto con «*»", acac ? "medium" : "low", asset, "Cualquier origen puede leer la respuesta (sin credenciales). Confirmar que la URL es pública.", "A02:2025 · API8:2023"));
    }
    const pf = await gateway.httpHead(grant, target.value, signal, { method: "OPTIONS", headers: { Origin: EVIL, "Access-Control-Request-Method": "DELETE" } });
    const acam = String(pf.headers["access-control-allow-methods"] ?? "");
    facts.push(`Preflight desde origen no autorizado → ${pf.status}; Allow-Methods: ${acam || "(ausente)"}.`);
    if (String(pf.headers["access-control-allow-origin"] ?? "") === EVIL && /DELETE|PUT|PATCH/i.test(acam)) out.push(sug("El preflight autoriza métodos de escritura a cualquier origen", "high", asset, `Allow-Methods: ${acam}.`, "A01:2025 · API8:2023 · CWE-942"));
    return { facts, suggestions: out };
  },
};

/* ---------- Métodos HTTP (solo OPTIONS y TRACE; PUT/DELETE cambian estado y NO se envían) ---------- */
export const httpMethodsAudit: Module = {
  manifest: manifest("http_methods_audit", "webmobile", ["lab", "active"]),
  async run({ grant, gateway, target, signal }) {
    needUrl(target);
    const facts: string[] = [], out: Suggestion[] = [], asset = target.value;
    const o = await gateway.httpHead(grant, target.value, signal, { method: "OPTIONS" });
    const allow = String(o.headers["allow"] ?? "");
    facts.push(`OPTIONS → ${o.status}; Allow: ${allow || "(ausente)"}.`);
    const risky = ["PUT", "DELETE", "PATCH", "CONNECT"].filter(m => new RegExp(`\\b${m}\\b`, "i").test(allow));
    if (risky.length) out.push(sug(`El servidor anuncia métodos de escritura: ${risky.join(", ")}`, "low", asset, "Solo se leyó la cabecera Allow; no se probaron porque cambian estado. Confirmar que requieren autenticación.", "A02:2025 · A01:2025 · CWE-749"));
    const t = await gateway.httpHead(grant, target.value, signal, { method: "TRACE", peekBytes: 128 });
    const echoed = t.status === 200 && /TRACE\s+\//.test(t.peek ?? "");
    facts.push(`TRACE → ${t.status}${echoed ? " (devuelve la petición: habilitado)" : ""}.`);
    if (echoed) out.push(sug("TRACE habilitado", "medium", asset, "Permite técnicas de rastreo entre sitios (XST) y revela cabeceras.", "A02:2025 · CWE-693"));
    return { facts, suggestions: out };
  },
};

/* ---------- DNS y correo ---------- */
const SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail"];
export const dnsEmailAudit: Module = {
  manifest: manifest("dns_email_audit", "surface", ["active"]),
  async run({ grant, gateway, target, signal }) {
    const host = hostOf(target);
    if (!host || isIP(host) || target.type === "cidr") throw new Error("dns_email_audit requiere un dominio (o una url con dominio)");
    const facts: string[] = [], out: Suggestion[] = [];
    const q = (name: string, type: "TXT" | "MX" | "CAA" | "NS") => gateway.dnsRecords(grant, host, name, type, signal);
    const [mx, ns, caa, txt, dmarcTxt, mtasts] = [await q(host, "MX"), await q(host, "NS"), await q(host, "CAA"), await q(host, "TXT"), await q(`_dmarc.${host}`, "TXT"), await q(`_mta-sts.${host}`, "TXT")];
    if (mx === null || txt === null) return { facts: ["No se pudieron consultar los registros DNS desde este servidor."], suggestions: [] };
    const hasMail = !!mx?.length && !/^\d+ \.$/.test(mx[0]);
    facts.push(`MX: ${mx?.length ? mx.join(", ") : "ninguno"}. NS: ${ns?.length ?? 0} servidores.`);
    if (ns && ns.length === 1) out.push(sug("El dominio tiene un solo servidor de nombres", "low", host, "Un único NS es punto único de fallo.", "A06:2025"));
    // CAA
    facts.push(`CAA: ${caa?.length ? caa.join(" | ") : "ninguno"}.`);
    if (!caa?.length) out.push(sug("Sin registros CAA", "info", host, "CAA limita qué autoridades pueden emitir certificados para el dominio.", "A04:2025"));
    // SPF
    const spf = (txt ?? []).filter(t => /^v=spf1\b/i.test(t));
    if (spf.length > 1) out.push(sug("Más de un registro SPF", "medium", host, "Varios SPF invalidan la política (PermError).", "A02:2025"));
    if (!spf.length) { facts.push("SPF: no hay registro."); out.push(sug(hasMail ? "Sin registro SPF" : "Dominio sin política SPF (suplantable)", hasMail ? "medium" : "low", host, hasMail ? "Cualquiera puede enviar correo diciendo ser este dominio sin que el receptor lo cuestione." : "Si el dominio no envía correo, publicar «v=spf1 -all».", "Suplantación de correo · T1566")); }
    else {
      const s = spf[0]; facts.push(`SPF: ${s}`);
      const all = /([+\-~?]?)all\b/i.exec(s)?.[1] ?? "+";
      if (all === "+" ) out.push(sug("SPF permite a cualquiera (+all)", "high", host, "La política no restringe nada.", "Suplantación de correo · T1566"));
      else if (all === "?") out.push(sug("SPF neutral (?all)", "medium", host, "No indica qué hacer con remitentes no autorizados.", "Suplantación de correo"));
      else if (all === "~") out.push(sug("SPF con softfail (~all)", "info", host, "Aceptable al inicio; con DMARC en reject suele bastar. Valorar -all.", "Suplantación de correo"));
      const lookups = (s.match(/\b(include:|a\b|mx\b|ptr\b|exists:|redirect=)/gi) ?? []).length;
      if (lookups > 10) out.push(sug("SPF supera 10 consultas DNS", "low", host, `Al menos ${lookups} mecanismos en el primer nivel; el límite es 10 en total.`, "RFC 7208"));
    }
    // DMARC
    const dmarc = (dmarcTxt ?? []).find(t => /^v=DMARC1\b/i.test(t));
    if (!dmarc) { facts.push("DMARC: no hay registro."); out.push(sug(hasMail ? "Sin registro DMARC" : "Sin DMARC", hasMail ? "medium" : "low", `_dmarc.${host}`, "Sin DMARC los receptores no saben qué hacer con correo que falla SPF/DKIM.", "Suplantación de correo · T1566")); }
    else {
      facts.push(`DMARC: ${dmarc}`);
      const tag = (k: string) => new RegExp(`(?:^|;)\\s*${k}\\s*=\\s*([^;\\s]+)`, "i").exec(dmarc)?.[1]?.toLowerCase();
      const p = tag("p"), pct = Number(tag("pct") ?? 100);
      if (p === "none") out.push(sug("DMARC en modo monitoreo (p=none)", "low", `_dmarc.${host}`, "No bloquea suplantaciones; útil solo como fase inicial.", "Suplantación de correo"));
      if (pct < 100 && p !== "none") out.push(sug(`DMARC aplicado solo al ${pct}% del correo`, "low", `_dmarc.${host}`, "El resto no se protege.", "Suplantación de correo"));
      if (!tag("rua")) out.push(sug("DMARC sin dirección de reportes (rua)", "info", `_dmarc.${host}`, "Sin reportes no se ve quién envía en nombre del dominio.", "Suplantación de correo"));
    }
    // DKIM (selectores habituales; ausencia NO concluyente) y MTA-STS
    const found: string[] = [];
    if (hasMail) for (const sel of SELECTORS) { const r = await q(`${sel}._domainkey.${host}`, "TXT"); if (r?.some(t => /v=DKIM1|k=rsa|p=/i.test(t))) found.push(sel); }
    if (hasMail) facts.push(found.length ? `DKIM encontrado en selectores: ${found.join(", ")}.` : `DKIM: sin registros en ${SELECTORS.length} selectores habituales (no concluyente: el selector real puede ser otro).`);
    if (hasMail) { facts.push(`MTA-STS: ${mtasts?.some(t => /v=STSv1/i.test(t)) ? "publicado" : "no publicado"}.`); if (!mtasts?.some(t => /v=STSv1/i.test(t))) out.push(sug("Sin MTA-STS", "info", host, "MTA-STS exige TLS en el correo entrante.", "A04:2025")); }
    return { facts, suggestions: out };
  },
};

/* ---------- Archivos expuestos (lista fija y corta; solo se reconoce una firma, nunca se guarda contenido) ---------- */
const FILES: { path: string; label: string; sig: RegExp; severity: Suggestion["severity"]; refs: string }[] = [
  { path: "/.git/HEAD", label: "Repositorio .git expuesto", sig: /^ref: refs\//, severity: "high", refs: "A02:2025 · CWE-538" },
  { path: "/.git/config", label: "Configuración de .git expuesta", sig: /\[core\]/, severity: "high", refs: "A02:2025 · CWE-538" },
  { path: "/.env", label: "Archivo .env expuesto", sig: /^[A-Z][A-Z0-9_]*=/m, severity: "high", refs: "A02:2025 · CWE-200" },
  { path: "/.htpasswd", label: ".htpasswd expuesto", sig: /^\w[\w.-]*:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./A-Za-z0-9]{13})/m, severity: "high", refs: "A02:2025 · CWE-200" },
  { path: "/.svn/entries", label: "Metadatos .svn expuestos", sig: /^\d+\s*\n/, severity: "medium", refs: "A02:2025 · CWE-538" },
  { path: "/.DS_Store", label: ".DS_Store expuesto", sig: /^\x00\x00\x00\x01Bud1/, severity: "low", refs: "A02:2025 · CWE-538" },
  { path: "/backup.sql", label: "Volcado SQL accesible", sig: /(CREATE TABLE|INSERT INTO|-- MySQL dump|-- PostgreSQL database dump)/i, severity: "high", refs: "A02:2025 · CWE-530" },
  { path: "/database.sql", label: "Volcado SQL accesible", sig: /(CREATE TABLE|INSERT INTO|-- MySQL dump|-- PostgreSQL database dump)/i, severity: "high", refs: "A02:2025 · CWE-530" },
  { path: "/backup.zip", label: "Copia de seguridad .zip accesible", sig: /^PK\x03\x04/, severity: "high", refs: "A02:2025 · CWE-530" },
  { path: "/wp-config.php.bak", label: "Copia de wp-config accesible", sig: /DB_PASSWORD|DB_NAME/, severity: "high", refs: "A02:2025 · CWE-530" },
  { path: "/phpinfo.php", label: "phpinfo() accesible", sig: /PHP Version|phpinfo\(\)/i, severity: "medium", refs: "A02:2025 · CWE-200" },
  { path: "/server-status", label: "Estado de Apache accesible", sig: /Apache Server Status/i, severity: "medium", refs: "A02:2025 · CWE-200" },
  { path: "/actuator/env", label: "Spring Actuator /env accesible", sig: /activeProfiles|propertySources/, severity: "high", refs: "A02:2025 · CWE-200" },
];
export const exposedFilesAudit: Module = {
  manifest: manifest("exposed_files_audit", "webmobile", ["lab", "active"]),
  async run({ grant, gateway, target, signal }) {
    const base = needUrl(target).origin, facts: string[] = [], out: Suggestion[] = [];
    // Muchos sitios (SPA) responden 200 a todo: se detecta para no dar falsos positivos y se confía solo en firmas de contenido.
    const canary = await gateway.httpHead(grant, `${base}/esc-${randomBytes(6).toString("hex")}`, signal, { method: "GET", peekBytes: 16 });
    facts.push(`Ruta inexistente de control → ${canary.status}${canary.status === 200 ? " (el sitio responde 200 a todo; se usan firmas de contenido)" : ""}.`);
    let exposed = 0;
    for (const f of FILES) {
      let r;
      try { r = await gateway.httpHead(grant, base + f.path, signal, { method: "GET", peekBytes: 512 }); }
      catch (e) { if (e instanceof GatewayDenied) { facts.push(`${f.path}: bloqueado por política (${e.reasons.join(",")}).`); continue; } throw e; }
      const hit = r.status === 200 && f.sig.test(r.peek ?? "");
      if (hit) { exposed++; facts.push(`${f.path} → 200 y la firma coincide (contenido no almacenado).`); out.push(sug(f.label, f.severity, base + f.path, "Se reconoció el tipo de archivo en la respuesta; el contenido no se guarda ni se muestra. Si pudo contener secretos, rótalos.", f.refs)); }
    }
    facts.push(`Rutas sensibles probadas: ${FILES.length}; expuestas: ${exposed}.`);
    const st = await gateway.httpHead(grant, `${base}/.well-known/security.txt`, signal, { method: "GET", peekBytes: 512 });
    const hasSt = st.status === 200 && /^\s*Contact:/im.test(st.peek ?? "");
    facts.push(`security.txt: ${hasSt ? "publicado" : "no encontrado"}.`);
    if (!hasSt) out.push(sug("Sin security.txt", "info", `${base}/.well-known/security.txt`, "RFC 9116: indica a quién reportar vulnerabilidades.", "A06:2025 · RFC 9116"));
    return { facts, suggestions: out };
  },
};

export const webModules: Module[] = [tlsAudit, cookieAudit, corsAudit, httpMethodsAudit, dnsEmailAudit, exposedFilesAudit];
