import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Store } from "../src/store.js";
import { createServer } from "../src/server.js";
import { dnsEmailAudit } from "../src/modules_web.js";

const KEY = Buffer.from("web-modules-key-web-modules-key-1234");
const MODS = ["tls_audit", "cookie_audit", "cors_audit", "http_methods_audit", "exposed_files_audit", "http_header_audit"];
let bad: http.Server, clean: http.Server, spa: http.Server, tlsSrv: https.Server;
let badPort = 0, cleanPort = 0, spaPort = 0, tlsPort = 0;
let store: Store, id = "", call: (n: string, a: Record<string, unknown>) => Promise<any>;
const listen = (s: net.Server) => new Promise<number>(r => s.listen(0, "127.0.0.1", () => r((s.address() as net.AddressInfo).port)));

before(async () => {
  // Sitio MAL configurado (ficticio y local)
  bad = http.createServer((req, res) => {
    const origin = String(req.headers.origin ?? "");
    const cors: Record<string, string> = origin ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Access-Control-Allow-Methods": "GET, PUT, DELETE" } : {};
    if (req.method === "TRACE") { res.writeHead(200, { "Content-Type": "message/http" }); return void res.end(`TRACE ${req.url} HTTP/1.1\r\n`); }
    if (req.method === "OPTIONS") { res.writeHead(204, { Allow: "GET, HEAD, PUT, DELETE", ...cors }); return void res.end(); }
    if (req.url === "/.env") { res.writeHead(200, { "Content-Type": "text/plain" }); return void res.end("DB_PASSWORD=Sup3rSecretoXYZ\nAPI_KEY=zzz\n"); }
    if (req.url === "/.git/HEAD") { res.writeHead(200); return void res.end("ref: refs/heads/main\n"); }
    if (req.url === "/") { res.writeHead(200, { "Set-Cookie": ["sessionid=valorSecreto999; Path=/", "tema=oscuro; Path=/; SameSite=Lax"], ...cors }); return void res.end("ok"); }
    res.writeHead(404); res.end("no");
  });
  // Sitio BIEN configurado: nada expuesto, sin cookies
  clean = http.createServer((req, res) => { res.writeHead(404); res.end("no"); });
  // SPA: responde 200 con HTML a TODO (no debe generar falsos positivos)
  spa = http.createServer((req, res) => { res.writeHead(200, { "Content-Type": "text/html" }); res.end("<!doctype html><html><body>app</body></html>"); });
  [badPort, cleanPort, spaPort] = [await listen(bad), await listen(clean), await listen(spa)];

  // TLS con certificado autofirmado que vence en 5 días
  const dir = mkdtempSync(join(tmpdir(), "esc-tls-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "5", "-subj", "/CN=localhost"], { stdio: "ignore" });
  tlsSrv = https.createServer({ key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) }, (_q, r) => r.end("ok"));
  tlsPort = await listen(tlsSrv);

  store = await Store.open("memory", KEY);
  const a = await store.createAssessment({
    name: "Módulos web", authorizer: { organization: "Org", name: "Ana", email: "ana@demo.test", emergencyContact: "ana@demo.test" },
    allowedModes: ["lab"], scope: [{ type: "cidr", value: "127.0.0.0/16" }], exclusions: [],
    window: { notBefore: "2020-01-01T00:00:00Z", notAfter: "2099-01-01T00:00:00Z", maxRequestsPerSecond: 50, maxConcurrency: 4 }, allowedModules: MODS,
  } as any, "ana");
  id = a.id;
  for (const s of ["scope_validated", "planned", "approved"] as const) await store.transition(id, s, "ana", "authorizer");
  const { server } = createServer({ store, role: "agent", actor: "llm" });
  const [x, y] = InMemoryTransport.createLinkedPair(); const client = new Client({ name: "t", version: "1" });
  await Promise.all([server.connect(x), client.connect(y)]);
  call = async (name, args) => { const r: any = await client.callTool({ name, arguments: args }); return JSON.parse(r.content[0].text); };
});
after(() => { for (const s of [bad, clean, spa, tlsSrv]) { (s as any).closeAllConnections?.(); s.close(); } });

const scan = (moduleId: string, url: string, params: Record<string, unknown> = {}) => call("scan_initiate", { assessmentId: id, moduleId, mode: "lab", targets: [{ type: "url", value: url }], params });
const titles = (r: any) => r.suggestions.map((s: any) => s.title);

test("cookie_audit: detecta banderas faltantes y NUNCA devuelve el valor de la cookie", async () => {
  const r = await scan("cookie_audit", `http://127.0.0.1:${badPort}/`);
  assert.equal(r.status, "completed");
  assert.ok(titles(r).some((t: string) => /sessionid.*HttpOnly/.test(t)), JSON.stringify(titles(r)));
  assert.ok(titles(r).some((t: string) => /sessionid.*SameSite/.test(t)));
  assert.equal(JSON.stringify(r).includes("valorSecreto999"), false);
});

test("cors_audit: refleja origen + credenciales = alto; preflight con métodos de escritura", async () => {
  const r = await scan("cors_audit", `http://127.0.0.1:${badPort}/`);
  const hi = r.suggestions.filter((s: any) => s.severity === "high").map((s: any) => s.title);
  assert.ok(hi.some((t: string) => /refleja/.test(t)), JSON.stringify(r.suggestions));
  assert.ok(hi.some((t: string) => /preflight/i.test(t)));
  assert.ok((await scan("cors_audit", `http://127.0.0.1:${cleanPort}/`)).suggestions.length === 0);
});

test("http_methods_audit: detecta TRACE y métodos anunciados, sin enviar PUT/DELETE", async () => {
  const seen: string[] = []; bad.on("request", q => seen.push(q.method!));
  const r = await scan("http_methods_audit", `http://127.0.0.1:${badPort}/`);
  assert.ok(titles(r).some((t: string) => /TRACE/.test(t)));
  assert.ok(titles(r).some((t: string) => /PUT, DELETE/.test(t)));
  assert.equal(seen.some(m => m === "PUT" || m === "DELETE" || m === "PATCH"), false);
});

test("exposed_files_audit: encuentra .env y .git, sin filtrar contenido, y sin falsos positivos", async () => {
  const r = await scan("exposed_files_audit", `http://127.0.0.1:${badPort}/`);
  const t = titles(r);
  assert.ok(t.includes("Archivo .env expuesto") && t.includes("Repositorio .git expuesto"), JSON.stringify(t));
  assert.equal(JSON.stringify(r).includes("Sup3rSecretoXYZ"), false);
  const spaR = await scan("exposed_files_audit", `http://127.0.0.1:${spaPort}/`);
  assert.equal(spaR.suggestions.filter((s: any) => s.severity !== "info").length, 0, "una SPA que responde 200 a todo no es una exposición");
  assert.ok(spaR.facts.some((f: string) => /responde 200 a todo/.test(f)));
  assert.equal((await scan("exposed_files_audit", `http://127.0.0.1:${cleanPort}/`)).suggestions.filter((s: any) => s.severity !== "info").length, 0);
});

test("tls_audit: certificado autofirmado y a punto de vencer", async () => {
  const r = await call("scan_initiate", { assessmentId: id, moduleId: "tls_audit", mode: "lab", targets: [{ type: "ip", value: "127.0.0.1" }], params: { port: tlsPort } });
  assert.equal(r.status, "completed", JSON.stringify(r));
  const t = titles(r);
  assert.ok(t.some((x: string) => /no es de confianza/.test(x)), JSON.stringify(t));
  assert.ok(t.some((x: string) => /vencer/.test(x)));
  assert.ok(r.facts.some((f: string) => /TLS 1\.0/.test(f)) && r.facts.some((f: string) => /TLS 1\.3/.test(f)));
});

test("http_header_audit: ahora también pide Referrer-Policy y Permissions-Policy (info)", async () => {
  const r = await scan("http_header_audit", `http://127.0.0.1:${cleanPort}/`);
  assert.ok(r.facts.includes("Ausente: referrer-policy"));
});

test("dns_email_audit (DNS simulado): SPF +all, sin DMARC y sin CAA", async () => {
  const recs: Record<string, string[]> = { "MX:ej.test": ["10 mail.ej.test"], "TXT:ej.test": ["v=spf1 +all"], "NS:ej.test": ["ns1.ej.test"] };
  const gateway: any = { dnsRecords: async (_g: any, _d: string, name: string, type: string) => recs[`${type}:${name}`] ?? [] };
  const r = await dnsEmailAudit.run({ grant: {} as any, gateway, target: { type: "domain", value: "ej.test" } as any, params: {}, signal: new AbortController().signal, maxConcurrency: 1 });
  const t = r.suggestions.map(s => s.title);
  assert.ok(t.includes("SPF permite a cualquiera (+all)") && t.includes("Sin registro DMARC") && t.includes("Sin registros CAA") && t.includes("El dominio tiene un solo servidor de nombres"), JSON.stringify(t));
  // Buena configuración: sin hallazgos de severidad >= low
  const ok: Record<string, string[]> = { ...recs, "TXT:ej.test": ["v=spf1 include:_spf.ej.test -all"], "TXT:_dmarc.ej.test": ["v=DMARC1; p=reject; rua=mailto:d@ej.test"], "CAA:ej.test": ["0 issue letsencrypt.org"], "NS:ej.test": ["ns1.ej.test", "ns2.ej.test"], "TXT:_mta-sts.ej.test": ["v=STSv1; id=1"] };
  const g2: any = { dnsRecords: async (_g: any, _d: string, name: string, type: string) => ok[`${type}:${name}`] ?? [] };
  const r2 = await dnsEmailAudit.run({ grant: {} as any, gateway: g2, target: { type: "domain", value: "ej.test" } as any, params: {}, signal: new AbortController().signal, maxConcurrency: 1 });
  assert.equal(r2.suggestions.filter(s => s.severity !== "info").length, 0, JSON.stringify(r2.suggestions));
});

test("dns: solo nombres dentro de la zona autorizada", async () => {
  const { Gateway } = await import("../src/gateway.js");
  const gw = new Gateway({ recheck: async () => ({ allow: true, reasons: [] }) } as any);
  await assert.rejects(() => gw.dnsRecords({ assessmentId: id, mode: "active", actor: "agent", module: "dns_email_audit" }, "ej.test", "otro-dominio.com", "TXT", new AbortController().signal), /TARGET_OUT_OF_SCOPE/);
});
