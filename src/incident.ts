// Respuesta a Incidentes / Defensa Activa — análisis puramente pasivo de evidencia que la organización
// aporta (logs, cabeceras de correo). Nunca abre una conexión de red ni toca infraestructura ajena:
// genera reglas e informes para que el propio equipo los aplique en SUS sistemas.
import { redact } from "./redact.js";

export interface Iocs { ips: string[]; domains: string[]; urls: string[]; hashes: string[]; emails: string[] }
export interface Pattern { title: string; severity: "info" | "low" | "medium" | "high"; detail: string }

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;
const HASH = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const PRIVATE_IP = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|0\.|255\.)/;
const uniq = (a: string[]) => [...new Set(a)];

/** Extrae indicadores de compromiso de un texto. No asume qué significan: solo los reconoce por forma. */
export function extractIocs(text: string): Iocs {
  const ips = uniq((text.match(IPV4) ?? []).filter(ip => !PRIVATE_IP.test(ip)));
  const urls = uniq(text.match(URL_RE) ?? []);
  const domainsFromUrls = urls.map(u => { try { return new URL(u).hostname; } catch { return null; } }).filter((d): d is string => !!d);
  const domains = uniq([...(text.match(DOMAIN) ?? []), ...domainsFromUrls].filter(d => !/\.(png|jpg|jpeg|gif|css|js|svg|woff2?)$/i.test(d)));
  const hashes = uniq((text.match(HASH) ?? []).map(h => h.toLowerCase()));
  const emails = uniq((text.match(EMAIL) ?? []).map(e => e.toLowerCase()));
  return { ips, domains: domains.filter(d => !ips.includes(d)), urls, hashes, emails };
}

const LOG_PATTERNS: { re: RegExp; title: string; severity: Pattern["severity"] }[] = [
  { re: /(union\s+select|select\s+.*\s+from|or\s+1\s*=\s*1|'\s*or\s*')/i, title: "Patrón de inyección SQL en las líneas pegadas", severity: "high" },
  { re: /<script[\s>]|javascript:|onerror\s*=/i, title: "Patrón de XSS en las líneas pegadas", severity: "high" },
  { re: /\.\.[\/\\]{1,}.*(etc\/passwd|win\.ini|boot\.ini)/i, title: "Patrón de path traversal en las líneas pegadas", severity: "high" },
  { re: /(;|\||\$\().*(cat|wget|curl|nc|bash|sh|powershell|certutil)\b/i, title: "Patrón de inyección de comandos en las líneas pegadas", severity: "high" },
  { re: /wp-login\.php|xmlrpc\.php|\/\.env\b|\/\.git\/|phpmyadmin/i, title: "Rastreo de rutas sensibles conocidas", severity: "medium" },
  { re: /\b(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|zgrab)\b/i, title: "User-Agent o firma de herramienta de escaneo", severity: "medium" },
];

/** Cuenta repeticiones de "actor → línea" para detectar fuerza bruta/credential stuffing sin asumir nada del formato del log. */
function bruteForceSignal(lines: string[]): Pattern[] {
  const authLines = lines.filter(l => /(login|auth|signin|session).*(fail|denied|invalid|incorrect|401|403)/i.test(l) || /(fail|denied|invalid|incorrect).*(login|auth|password)/i.test(l));
  if (authLines.length < 5) return [];
  const byIp = new Map<string, number>();
  for (const l of authLines) for (const ip of uniq(l.match(IPV4) ?? []).filter(ip => !PRIVATE_IP.test(ip))) byIp.set(ip, (byIp.get(ip) ?? 0) + 1);
  const out: Pattern[] = [];
  for (const [ip, n] of byIp) if (n >= 5) out.push({ title: `Posible fuerza bruta / credential stuffing desde ${ip}`, severity: n >= 20 ? "high" : "medium", detail: `${n} intentos fallidos de autenticación en las líneas pegadas.` });
  if (!out.length && authLines.length >= 10) out.push({ title: "Muchos fallos de autenticación sin un origen dominante", severity: "medium", detail: `${authLines.length} líneas con fallos de autenticación; podría ser credential stuffing distribuido.` });
  return out;
}

export function analyzeLog(text: string): { facts: string[]; patterns: Pattern[]; iocs: Iocs } {
  const lines = text.split("\n");
  const patterns = [...LOG_PATTERNS.filter(p => p.re.test(text)).map(p => ({ title: p.title, severity: p.severity, detail: "Coincidencia encontrada en el texto pegado." })), ...bruteForceSignal(lines)];
  const iocs = extractIocs(text);
  return { facts: [`Se analizaron ${lines.length} líneas.`, `IOCs encontrados: ${iocs.ips.length} IP(s), ${iocs.domains.length} dominio(s), ${iocs.urls.length} URL(s), ${iocs.hashes.length} hash(es).`], patterns, iocs };
}

/** Cabeceras de correo: separa el remitente real (Received, Return-Path) del que se muestra (From), base de todo phishing. */
export function analyzeEmailHeaders(text: string): { facts: string[]; patterns: Pattern[]; iocs: Iocs } {
  const get = (name: string) => [...text.matchAll(new RegExp(`^${name}:\\s*(.+(?:\\n[ \\t].*)*)`, "gim"))].map(m => m[1].replace(/\s+/g, " ").trim());
  const from = get("From")[0] ?? "", returnPath = get("Return-Path")[0] ?? "", replyTo = get("Reply-To")[0] ?? "";
  const received = get("Received");
  const facts: string[] = [], patterns: Pattern[] = [];
  const domOf = (s: string) => s.match(/@([a-z0-9.-]+\.[a-z]{2,})/i)?.[1]?.toLowerCase();
  const fromDom = domOf(from), rpDom = domOf(returnPath), rtDom = domOf(replyTo);
  facts.push(`From: ${from || "(no encontrado)"}`, `Return-Path: ${returnPath || "(no encontrado)"}`, `Reply-To: ${replyTo || "(no encontrado)"}`, `Saltos Received: ${received.length}`);
  if (fromDom && rpDom && fromDom !== rpDom) patterns.push({ title: "El dominio visible (From) no coincide con el remitente real (Return-Path)", severity: "high", detail: `From: ${fromDom} · Return-Path: ${rpDom}. Indicio clásico de suplantación.` });
  if (fromDom && rtDom && fromDom !== rtDom) patterns.push({ title: "Reply-To apunta a un dominio distinto del remitente", severity: "medium", detail: `From: ${fromDom} · Reply-To: ${rtDom}. Las respuestas no llegan a quien parece enviar el correo.` });
  const authResults = get("Authentication-Results").join(" ");
  if (authResults) {
    facts.push(`Authentication-Results: ${authResults}`);
    for (const [k, label] of [["spf=fail", "SPF falló"], ["dkim=fail", "DKIM falló"], ["dmarc=fail", "DMARC falló"]] as const)
      if (new RegExp(k, "i").test(authResults)) patterns.push({ title: label, severity: "high", detail: `El correo no pasó la verificación (${k}).` });
  } else facts.push("Sin cabecera Authentication-Results: no se puede confirmar si pasó SPF/DKIM/DMARC.");
  const iocs = extractIocs([from, returnPath, replyTo, ...received, ...get("X-Originating-IP")].join("\n") + "\n" + text);
  return { facts, patterns, iocs };
}

const asCidr = (ip: string) => (ip.includes(":") ? `${ip}/128` : `${ip}/32`);

/** Reglas listas para pegar. Nunca se ejecutan aquí: el equipo de la empresa las aplica en SU propio equipo. */
export function containmentRules(ips: string[], domains: string[], targets: "firewall" | "nginx" | "cloudflare" | "all"): Record<string, string> {
  const out: Record<string, string> = {};
  const want = (t: string) => targets === "all" || targets === t;
  if (want("firewall") && ips.length) out["iptables.sh"] = ["#!/bin/sh", "# Bloqueo de emergencia — revisar antes de aplicar; usar `iptables -D` con la misma línea para revertir.",
    ...ips.map(ip => `iptables -I INPUT -s ${asCidr(ip)} -j DROP`)].join("\n") + "\n";
  if (want("firewall") && ips.length) out["ufw.sh"] = ["#!/bin/sh", "# Alternativa con ufw.", ...ips.map(ip => `ufw deny from ${ip}`)].join("\n") + "\n";
  if (want("nginx") && (ips.length || domains.length)) out["nginx-deny.conf"] = [
    "# Incluir dentro de server { } o http { } y recargar: nginx -s reload",
    ...ips.map(ip => `deny ${ip};`), domains.length ? `# Dominios (bloquear por Referer/Host si corresponde):\n${domains.map(d => `# ${d}`).join("\n")}` : "",
  ].filter(Boolean).join("\n") + "\n";
  if (want("cloudflare") && ips.length) out["cloudflare-rule.json"] = JSON.stringify({
    description: "Bloqueo de emergencia (Firewall Rules / WAF custom rules)",
    expression: `(ip.src in {${ips.join(" ")}})`, action: "block",
  }, null, 2) + "\n";
  if (domains.length) out["dominios-sospechosos.txt"] = domains.join("\n") + "\n# Añadir a listas de bloqueo de DNS/proxy y a la lista negra de correo si corresponde.\n";
  return out;
}

export function buildIncidentReport(inc: { organization: string; contactName: string; contactEmail: string; summary: string; affectedAssets: string[]; status: string; createdAt: string },
  evidence: { kind: string; description: string; redactedContent: string; iocs: Iocs; createdAt: string }[], format: "markdown" | "json") {
  const allIocs: Iocs = { ips: [], domains: [], urls: [], hashes: [], emails: [] };
  for (const e of evidence) for (const k of Object.keys(allIocs) as (keyof Iocs)[]) allIocs[k] = uniq([...allIocs[k], ...e.iocs[k]]);
  if (format === "json") return JSON.stringify({ incident: inc, evidenceCount: evidence.length, iocs: allIocs, evidence }, null, 2);
  const lines = [
    `# Informe de incidente — ${inc.organization}`, "", `**Estado:** ${inc.status} · **Abierto:** ${inc.createdAt}`,
    `**Reportado por:** ${inc.contactName} (${inc.contactEmail})`, `**Activos afectados:** ${inc.affectedAssets.join(", ") || "sin especificar"}`, "", `## Resumen`, inc.summary, "",
    `## Indicadores de compromiso (IOCs)`,
    `- IPs (${allIocs.ips.length}): ${allIocs.ips.join(", ") || "—"}`, `- Dominios (${allIocs.domains.length}): ${allIocs.domains.join(", ") || "—"}`,
    `- URLs (${allIocs.urls.length}): ${allIocs.urls.join(", ") || "—"}`, `- Hashes (${allIocs.hashes.length}): ${allIocs.hashes.join(", ") || "—"}`, "",
    `## Línea de tiempo de evidencia (${evidence.length})`,
    ...evidence.map(e => `- **${e.createdAt}** · ${e.kind} — ${e.description}`), "",
    `## A quién reportar`,
    `- **Hosting del atacante**: busca el abuse contact del rango de IP con \`whois <ip>\` y repórtalo con la evidencia (logs, fecha/hora en UTC, IOCs).`,
    `- **CSIRT nacional (Colombia)**: colCERT — https://www.colcert.gov.co — y la Policía Nacional (Centro Cibernético) para denuncia formal.`,
    `- **CERT/CSIRT de tu país** si no es Colombia: busca el CSIRT nacional correspondiente.`,
    `- **Tu proveedor de hosting/CDN**: para bloqueo a su nivel y, si hay exfiltración, para preservar logs.`, "",
    `## Preservar evidencia para una denuncia`,
    `- No alteres los logs originales; trabaja sobre copias.`, `- Anota fecha y hora en UTC de cada evento.`, `- Guarda los encabezados completos de los correos (no solo el cuerpo).`,
    `- Calcula y guarda el hash (SHA-256) de cada archivo de evidencia antes de compartirlo.`, "",
  ];
  return lines.join("\n");
}

export const MAX_EVIDENCE_CHARS = 50_000;
