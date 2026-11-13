import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Store } from "../src/store.js";
import { createServer } from "../src/server.js";

const KEY = Buffer.from("e2e-signing-key-e2e-signing-key-1234");
let vuln: http.Server, openSock: net.Server, vulnPort = 0, openPort = 0, closedPort = 0;
const hits: string[] = [];

before(async () => {
  // Objetivo vulnerable FICTICIO local: sin cabeceras de seguridad, con banners de versión, redirect hacia fuera del alcance y endpoint lento
  vuln = http.createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    if (req.url === "/redirect-out") { res.writeHead(302, { Location: "http://198.51.100.7/admin" }); return res.end(); }
    if (req.url === "/slow") return void setTimeout(() => res.end("tarde"), 8000).unref();
    res.writeHead(200, { Server: "Apache/2.2.8", "X-Powered-By": "PHP/5.3.0" }); res.end("hola");
  });
  await new Promise<void>(r => vuln.listen(0, "127.0.0.1", r)); vulnPort = (vuln.address() as net.AddressInfo).port;
  openSock = net.createServer(s => s.end()); await new Promise<void>(r => openSock.listen(0, "127.0.0.1", r)); openPort = (openSock.address() as net.AddressInfo).port;
  const tmp = net.createServer(); await new Promise<void>(r => tmp.listen(0, "127.0.0.1", r)); closedPort = (tmp.address() as net.AddressInfo).port; await new Promise(r => tmp.close(r));
});
after(() => { vuln.closeAllConnections?.(); vuln.close(); openSock.close(); });

const assessmentInput = () => ({
  name: "Laboratorio local", authorizer: { organization: "Org Demo", name: "Ana", email: "ana@demo.test", emergencyContact: "ana@demo.test" },
  allowedModes: ["passive", "lab", "active"],
  scope: [{ type: "cidr", value: "127.0.0.0/16" }],
  exclusions: [{ target: { type: "ip", value: "127.0.0.99" }, reason: "equipo excluido" }],
  window: { notBefore: "2020-01-01T00:00:00Z", notAfter: "2099-01-01T00:00:00Z", maxRequestsPerSecond: 50, maxConcurrency: 4 },
  allowedModules: ["config_audit", "tcp_port_check", "http_header_audit", "lab_write_probe"],
});

async function boot(role: "agent" | "authorizer", store: Store) {
  const { server } = createServer({ store, role, actor: role === "agent" ? "llm" : "ana" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "1" });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r: any = await client.callTool({ name, arguments: args });
    const text = r.content[0].text as string;
    let data: any = text; try { data = JSON.parse(text); } catch { /* texto plano (reportes) */ }
    return { isError: !!r.isError, data };
  };
  return { call, client };
}

test("las 6 herramientas MCP están publicadas", async () => {
  const { client } = await boot("agent", await Store.open("memory", KEY));
  const names = (await client.listTools()).tools.map(t => t.name).sort();
  assert.deepEqual(names, ["assessment_create", "finding_create", "incident_contain_plan", "incident_evidence_analyze", "incident_open", "incident_report", "report_generate", "scan_initiate", "scan_stop", "scope_validate"]);
});

test("el LLM no puede crear autorizaciones; el authorizer sí", async () => {
  const store = await Store.open("memory", KEY);
  const agent = await boot("agent", store);
  const denied = await agent.call("assessment_create", assessmentInput());
  assert.equal(denied.isError, true); assert.equal(denied.data.error, "ROLE_NOT_ALLOWED");
  const human = await boot("authorizer", store);
  const ok = await human.call("assessment_create", assessmentInput());
  assert.equal(ok.isError, false); assert.equal(ok.data.state, "draft");
});

test("ciclo completo: pasivo → laboratorio → activo con aprobación → hallazgos → reporte → kill switch", async () => {
  const store = await Store.open("memory", KEY);
  const a = await store.createAssessment(assessmentInput(), "ana");
  const id = a.id;
  const agent = await boot("agent", store);
  const host = `http://127.0.0.1:${vulnPort}`;

  // Sin cumplir el ciclo (aún en draft) no se puede ejecutar nada
  let r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "lab", targets: [{ type: "ip", value: "127.0.0.1" }], params: { ports: String(openPort) } });
  assert.equal(r.data.status, "denied"); assert.deepEqual(r.data.denials[0].reasons, ["STATE_TRANSITION_INVALID"]);

  // Un humano avanza el ciclo (canal separado del LLM)
  for (const s of ["scope_validated", "planned", "approved"] as const) assert.ok(await store.transition(id, s, "ana", "authorizer"));

  // scope_validate
  assert.equal((await agent.call("scope_validate", { assessmentId: id, target: { type: "ip", value: "127.0.0.5" } })).data.authorized, true);
  const out = await agent.call("scope_validate", { assessmentId: id, target: { type: "ip", value: "8.8.8.8" } });
  assert.deepEqual(out.data.reasons, ["TARGET_OUT_OF_SCOPE"]);
  assert.deepEqual((await agent.call("scope_validate", { assessmentId: id, target: { type: "ip", value: "127.0.0.99" } })).data.reasons, ["TARGET_EXCLUDED"]);

  // Pasivo: análisis estático, sin red
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "config_audit", mode: "passive", targets: [{ type: "ip", value: "127.0.0.1" }], params: { content: "PermitRootLogin yes\nserver_tokens on\npassword=Sup3rS3cret" } });
  assert.equal(r.data.status, "completed");
  assert.ok(r.data.suggestions.some((s: any) => /root/i.test(s.title)));
  assert.ok(!JSON.stringify(r.data).includes("Sup3rS3cret"));

  // Laboratorio: puertos
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "lab", targets: [{ type: "ip", value: "127.0.0.1" }], params: { ports: `${openPort},${closedPort}` } });
  assert.equal(r.data.status, "completed");
  assert.ok(r.data.facts.some((f: string) => f.endsWith(`${openPort} → open`)));
  assert.ok(r.data.facts.some((f: string) => f.endsWith(`${closedPort} → closed`)));

  // Laboratorio: cabeceras
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "http_header_audit", mode: "lab", targets: [{ type: "url", value: `${host}/` }] });
  assert.equal(r.data.status, "completed");
  assert.ok(r.data.facts.includes("Ausente: content-security-policy"));
  assert.ok(r.data.facts.some((f: string) => f.includes("Apache/2.2.8")));
  assert.ok(hits.every(h => h.startsWith("HEAD")), "solo se envían HEAD (no se lee contenido)");

  // Redirect hacia fuera del alcance: el Gateway lo revalida y NO se conecta
  const before = hits.length;
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "http_header_audit", mode: "lab", targets: [{ type: "url", value: `${host}/redirect-out` }] });
  assert.ok(r.data.facts.some((f: string) => /bloqueado por política \(TARGET_OUT_OF_SCOPE\)/.test(f)), JSON.stringify(r.data));
  assert.equal(hits.length, before + 1); // solo el primer salto llegó al objetivo

  // Objetivo fuera de alcance: rechazado antes de planificar
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "lab", targets: [{ type: "ip", value: "8.8.8.8" }] });
  assert.equal(r.data.status, "denied"); assert.deepEqual(r.data.reasons, ["TARGET_OUT_OF_SCOPE"]);

  // Módulo con límites duros bloqueado aunque el LLM lo pida por parámetros
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "lab", targets: [{ type: "ip", value: "127.0.0.1" }], params: { ports: "80", technique: "bruteforce" } });
  assert.ok(JSON.stringify(r.data).includes("HARD_LIMIT"));

  // ACTIVO: primero plan pendiente, el LLM no puede aprobar; el humano aprueba con token
  const t = { type: "ip", value: "127.0.0.1" };
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "active", targets: [t], params: { ports: String(openPort) } });
  assert.equal(r.data.status, "pending_approval");
  const planId = r.data.planId;
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "active", targets: [t], params: { ports: String(openPort) }, planId, approvalToken: "inventado" });
  assert.equal(r.data.status, "denied");
  await assert.rejects(() => store.approvePlan(planId, "llm", "agent"));
  const token = await store.approvePlan(planId, "oscar", "operator");
  // El token no sirve para otros objetivos del mismo plan
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "active", targets: [{ type: "ip", value: "127.0.0.2" }], params: { ports: "80" }, planId, approvalToken: token });
  assert.equal(r.data.status, "denied");
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "active", targets: [t], params: { ports: String(openPort) }, planId, approvalToken: token });
  assert.equal(r.data.status, "completed");
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "tcp_port_check", mode: "active", targets: [t], params: { ports: String(openPort) }, planId, approvalToken: token });
  assert.equal(r.data.status, "denied"); // token de un solo uso

  // Módulo que cambia estado (lab) exige confirmación humana
  const w = { type: "url", value: `${host}/` };
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "lab_write_probe", mode: "lab", targets: [w] });
  assert.equal(r.data.status, "pending_approval");
  const tok2 = await store.approvePlan(r.data.planId, "oscar", "operator");
  r = await agent.call("scan_initiate", { assessmentId: id, moduleId: "lab_write_probe", mode: "lab", targets: [w], planId: r.data.planId, approvalToken: tok2 });
  assert.equal(r.data.status, "completed");
  assert.ok(hits.some(h => h.startsWith("POST")));

  // Hallazgos: redacción, coherencia CVSS/severidad, activo en alcance
  const base = { assessmentId: id, title: "Divulgación de versión en cabeceras", asset: `${host}/`, severity: "low", cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", cvssScore: 3.7, confidence: "high",
    observedFacts: ["Server: Apache/2.2.8", "Contacto del admin: root@demo.test"], riskHypotheses: ["Un atacante podría buscar CVE de esa versión"],
    evidence: [{ description: "Respuesta a HEAD /", redactedContent: "Server: Apache/2.2.8\nAuthorization: Bearer abcdefghijklmnop12345", reproSteps: ["curl -I http://127.0.0.1:PUERTO/"] }],
    businessImpact: "Facilita el reconocimiento.", recommendation: "Ocultar versión (ServerTokens Prod).", triage: "confirmed" };
  assert.equal((await agent.call("finding_create", { ...base, severity: "critical" })).data.error, "SEVERITY_CVSS_MISMATCH");
  assert.equal((await agent.call("finding_create", { ...base, asset: "http://8.8.8.8/" })).data.error, "TARGET_OUT_OF_SCOPE");
  assert.equal((await agent.call("finding_create", base)).data.stored, true);
  await agent.call("finding_create", { ...base, title: "Hipótesis sin verificar", triage: "unverified" });

  // Reporte
  const md = (await agent.call("report_generate", { assessmentId: id, format: "markdown" })).data as string;
  assert.ok(md.includes("### Hechos observados") && md.includes("### Hipótesis de riesgo"));
  assert.ok(!md.includes("root@demo.test") && !md.includes("abcdefghijklmnop12345"), "el reporte no filtra PII ni tokens");
  assert.ok(md.includes("Divulgación de versión") && !md.includes("Hipótesis sin verificar"), "por defecto solo hallazgos confirmados");
  assert.equal((await store.getAssessment(id))!.a.state, "reported");

  // Auditoría íntegra al final
  assert.deepEqual(await store.verifyAuditChain(), { ok: true });
});

test("kill switch: aborta un escaneo en curso y bloquea todo después", async () => {
  const store = await Store.open("memory", KEY);
  const a = await store.createAssessment(assessmentInput(), "ana");
  for (const s of ["scope_validated", "planned", "approved"] as const) await store.transition(a.id, s, "ana", "authorizer");
  const agent = await boot("agent", store);
  const slow = agent.call("scan_initiate", { assessmentId: a.id, moduleId: "http_header_audit", mode: "lab", targets: [{ type: "url", value: `http://127.0.0.1:${vulnPort}/slow` }] });
  await new Promise(r => setTimeout(r, 300));
  const t0 = Date.now();
  const stop = await agent.call("scan_stop", { assessmentId: a.id, reason: "prueba de parada de emergencia" });
  assert.equal(stop.data.abortedRuns, 1);
  const res = await slow;
  assert.ok(Date.now() - t0 < 2500, "la ejecución se detuvo de inmediato");
  assert.ok(["aborted", "denied"].includes(res.data.status));
  const after = await agent.call("scan_initiate", { assessmentId: a.id, moduleId: "config_audit", mode: "passive", targets: [{ type: "ip", value: "127.0.0.1" }], params: { content: "x" } });
  assert.ok(JSON.stringify(after.data).includes("KILL_SWITCH_ACTIVE"));
  await assert.rejects(() => store.releaseKillSwitch("llm", "agent"));
  assert.deepEqual(await store.verifyAuditChain(), { ok: true });
});
