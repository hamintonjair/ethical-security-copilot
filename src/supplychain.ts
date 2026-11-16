// Cadena de suministro (OWASP A03) — análisis puramente pasivo de manifiestos de dependencias que el
// usuario aporta (package-lock.json, package.json, requirements.txt, o una lista manual "nombre@versión").
// Solo lee texto y consulta OSV.dev (base pública de vulnerabilidades conocidas) por nombre+versión.
// Nunca instala nada, nunca ejecuta código de ningún paquete, nunca toca la infraestructura de la organización.
export type FetchFn = typeof fetch;

export type ManifestKind = "npm_package_lock" | "npm_package_json" | "pip_requirements" | "manual";

export interface SbomEntry { name: string; version: string; ecosystem: string }
export interface Vuln { id: string; summary: string; aliases: string[]; severity: "critical" | "high" | "medium" | "low" | "unknown" }
export interface SbomVuln extends SbomEntry { vulns: Vuln[] }

export const MAX_MANIFEST_CHARS = 2_000_000;
export const MAX_DEPS = 500;
const MAX_VULN_DETAILS = 300;

export function parseManifest(kind: ManifestKind, content: string, osvEcosystem?: string): SbomEntry[] {
  if (kind === "npm_package_lock") return parseNpmLock(content);
  if (kind === "npm_package_json") return parseNpmPackageJson(content);
  if (kind === "pip_requirements") return parsePipRequirements(content);
  if (kind === "manual") return parseManualList(content, osvEcosystem || "npm");
  throw new Error("Tipo de manifiesto no reconocido.");
}

function parseNpmLock(content: string): SbomEntry[] {
  let data: any;
  try { data = JSON.parse(content); } catch { throw new Error("package-lock.json no es JSON válido."); }
  const out = new Map<string, SbomEntry>();
  if (data.packages && typeof data.packages === "object") {
    // lockfileVersion 2/3: claves "node_modules/<paquete>" (o anidadas) con { version }
    for (const [p, info] of Object.entries<any>(data.packages)) {
      if (!p || !info?.version) continue;
      const idx = p.lastIndexOf("node_modules/");
      const name = idx >= 0 ? p.slice(idx + "node_modules/".length) : null;
      if (!name) continue;
      out.set(`${name}@${info.version}`, { name, version: String(info.version), ecosystem: "npm" });
    }
  } else if (data.dependencies && typeof data.dependencies === "object") {
    // lockfileVersion 1: árbol anidado de "dependencies"
    const walk = (deps: Record<string, any>) => {
      for (const [name, info] of Object.entries<any>(deps ?? {})) {
        if (info?.version) out.set(`${name}@${info.version}`, { name, version: String(info.version), ecosystem: "npm" });
        if (info?.dependencies) walk(info.dependencies);
      }
    };
    walk(data.dependencies);
  }
  if (!out.size) throw new Error("No se reconocieron dependencias en el package-lock.json.");
  return [...out.values()];
}

function parseNpmPackageJson(content: string): SbomEntry[] {
  let data: any;
  try { data = JSON.parse(content); } catch { throw new Error("package.json no es JSON válido."); }
  const out = new Map<string, SbomEntry>();
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, range] of Object.entries<any>(data[field] ?? {})) {
      const version = String(range).replace(/^[\^~>=<\s]+/, "").split(/[\s|]/)[0];
      if (name && version && /^\d/.test(version)) out.set(`${name}@${version}`, { name, version, ecosystem: "npm" });
    }
  }
  if (!out.size) throw new Error("No se encontraron dependencias con versión fija en el package.json (los rangos sin versión exacta no se pueden cruzar con precisión).");
  return [...out.values()];
}

function parsePipRequirements(content: string): SbomEntry[] {
  const out: SbomEntry[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.split("#")[0].trim();
    const m = /^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9_.!+-]*)/.exec(line);
    if (m) out.push({ name: m[1], version: m[2], ecosystem: "PyPI" });
  }
  if (!out.length) throw new Error("No se encontraron líneas `paquete==versión` en el requirements.txt.");
  return out;
}

function parseManualList(content: string, ecosystem: string): SbomEntry[] {
  const out: SbomEntry[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const at = line.lastIndexOf("@");
    if (at <= 0) continue;
    out.push({ name: line.slice(0, at).trim(), version: line.slice(at + 1).trim(), ecosystem });
  }
  if (!out.length) throw new Error("No se encontraron líneas `nombre@versión` en la lista manual.");
  return out;
}

function severityOf(v: any): Vuln["severity"] {
  const dbSev = String(v?.database_specific?.severity ?? "").toLowerCase();
  if (dbSev === "critical" || dbSev === "high" || dbSev === "medium" || dbSev === "low") return dbSev;
  for (const s of v?.severity ?? []) {
    const score = Number(s?.score);
    if (!Number.isNaN(score)) { if (score >= 9) return "critical"; if (score >= 7) return "high"; if (score >= 4) return "medium"; return "low"; }
  }
  return "unknown";
}

/** Dos pasos: un lote (`querybatch`) para saber qué IDs de vulnerabilidad aplican, y luego el detalle de cada ID
 * único encontrado (resumen, severidad, CVE). Nunca escribe nada; es una consulta pública de solo lectura. */
export async function checkVulnerabilities(deps: SbomEntry[], fetchImpl: FetchFn = fetch): Promise<SbomVuln[]> {
  if (!deps.length) return [];
  const list = deps.slice(0, MAX_DEPS);
  let batchRes: Awaited<ReturnType<FetchFn>>;
  try {
    batchRes = await fetchImpl("https://api.osv.dev/v1/querybatch", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries: list.map(d => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }),
    });
  } catch (e) { throw new Error(`No se pudo contactar a OSV.dev: ${(e as Error).message || "error de red"}.`); }
  if (!batchRes.ok) throw new Error(`OSV.dev respondió ${batchRes.status} al consultar las dependencias.`);
  const batch = await batchRes.json() as { results?: { vulns?: { id: string }[] }[] };
  const results = batch.results ?? [];
  const idSet = new Set<string>();
  for (const r of results) for (const v of r.vulns ?? []) idSet.add(v.id);
  const details = new Map<string, Vuln>();
  for (const id of [...idSet].slice(0, MAX_VULN_DETAILS)) {
    try {
      const r = await fetchImpl(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
      if (!r.ok) continue;
      const v = await r.json() as any;
      details.set(id, { id, summary: String(v.summary ?? v.details ?? "").slice(0, 300), aliases: Array.isArray(v.aliases) ? v.aliases : [], severity: severityOf(v) });
    } catch { /* un detalle que falla no bloquea el resto */ }
  }
  return list.map((d, i) => ({ ...d, vulns: (results[i]?.vulns ?? []).map(v => details.get(v.id)).filter((v): v is Vuln => !!v) }));
}
