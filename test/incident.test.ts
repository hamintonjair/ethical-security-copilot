import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Store } from "../src/store.js";
import { createServer } from "../src/server.js";
import { extractIocs, analyzeEmailHeaders, containmentRules, suggestIncidentTypes, TYPE_GUIDANCE } from "../src/incident.js";

const KEY = Buffer.from("incident-key-incident-key-1234567");

async function boot(role: "agent" | "authorizer" | "operator" | "analyst" | "auditor", store: Store) {
  const { server } = createServer({ store, role, actor: `${role}-x` });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "1" });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => { const r: any = await client.callTool({ name, arguments: args }); return { isError: !!r.isError, data: JSON.parse(r.content[0].text.startsWith("{") || r.content[0].text.startsWith("[") ? r.content[0].text : "{}") || r.content[0].text, raw: r.content[0].text }; };
  return { call };
}

test("el agente no puede abrir un incidente; un humano sí", async () => {
  const store = await Store.open("memory", KEY);
  const agent = await boot("agent", store);
  const denied = await agent.call("incident_open", { organization: "Acme", contactName: "Ana", contactEmail: "ana@acme.test", summary: "Ataque en curso", affectedAssets: [] });
  assert.equal(denied.isError, true); assert.equal(denied.data.error, "ROLE_NOT_ALLOWED");
  const op = await boot("operator", store);
  const ok = await op.call("incident_open", { organization: "Acme", contactName: "Ana", contactEmail: "ana@acme.test", summary: "Ataque en curso", affectedAssets: ["web"] });
  assert.equal(ok.isError, false); assert.ok(ok.data.incidentId);
});

test("ciclo: analizar log con fuerza bruta e inyección, extraer IOCs, generar contención e informe", async () => {
  const store = await Store.open("memory", KEY);
  const op = await boot("operator", store);
  const agent = await boot("agent", store);
  const { data: { incidentId } } = await op.call("incident_open", { organization: "Acme S.A.", contactName: "Ana Gómez", contactEmail: "ana@acme.test", summary: "Múltiples intentos de acceso y una posible inyección SQL en el formulario de login.", affectedAssets: ["https://acme.test/login"] });

  const log = [
    "2026-11-13T10:00:00Z 203.0.113.9 login failed invalid password user=admin",
    "2026-11-13T10:00:02Z 203.0.113.9 login failed invalid password user=admin",
    "2026-11-13T10:00:04Z 203.0.113.9 login failed invalid password user=admin",
    "2026-11-13T10:00:06Z 203.0.113.9 login failed invalid password user=admin",
    "2026-11-13T10:00:08Z 203.0.113.9 login failed invalid password user=admin",
    "2026-11-13T10:01:00Z 203.0.113.9 GET /login?user=' OR 1=1 --",
    "2026-11-13T10:02:00Z 198.51.100.4 GET /.env sqlmap/1.6",
  ].join("\n");
  const an = await agent.call("incident_evidence_analyze", { incidentId, kind: "log", description: "log del servidor web, 13 nov", content: log });
  assert.equal(an.isError, false, JSON.stringify(an));
  assert.ok(an.data.iocs.ips.includes("203.0.113.9") && an.data.iocs.ips.includes("198.51.100.4"));
  const titles = an.data.patterns.map((p: any) => p.title);
  assert.ok(titles.some((t: string) => /fuerza bruta/i.test(t)), JSON.stringify(titles));
  assert.ok(titles.some((t: string) => /inyección SQL/i.test(t)));
  assert.ok(titles.some((t: string) => /escaneo/i.test(t)));

  // un analista también puede analizar evidencia y generar el plan de contención
  const analyst = await boot("analyst", store);
  const plan = await analyst.call("incident_contain_plan", { incidentId, ips: ["203.0.113.9", "198.51.100.4"], domains: ["malo.example"], targets: "all" });
  assert.equal(plan.isError, false);
  assert.match(plan.data.rules["iptables.sh"], /203\.0\.113\.9\/32/);
  assert.match(plan.data.rules["cloudflare-rule.json"], /198\.51\.100\.4/);
  assert.match(plan.data.rules["dominios-sospechosos.txt"], /malo\.example/);

  // el auditor solo puede leer el informe
  const auditor = await boot("auditor", store);
  const rep = await auditor.call("incident_report", { incidentId, format: "markdown" });
  assert.equal(rep.isError, false);
  assert.match(rep.raw, /203\.0\.113\.9/);
  assert.match(rep.raw, /colCERT/);
  const deniedOpen = await auditor.call("incident_open", { organization: "x", contactName: "x", contactEmail: "a@a.test", summary: "x".repeat(10), affectedAssets: [] });
  assert.equal(deniedOpen.isError, true);
});

test("evidencia sobre un incidente cerrado se rechaza", async () => {
  const store = await Store.open("memory", KEY);
  const op = await boot("operator", store);
  const { data: { incidentId } } = await op.call("incident_open", { organization: "Acme", contactName: "Ana", contactEmail: "ana@acme.test", summary: "Prueba de cierre de incidente", affectedAssets: [] });
  await store.setIncidentStatus(incidentId, "contained", "ana", "operator");
  await store.setIncidentStatus(incidentId, "closed", "ana", "operator");
  const r = await op.call("incident_evidence_analyze", { incidentId, kind: "log", description: "tarde", content: "203.0.113.9 fail" });
  assert.equal(r.isError, true); assert.equal(r.data.error, "INCIDENT_CLOSED");
});

test("extractIocs: ignora IPs privadas y assets estáticos", () => {
  const r = extractIocs("atacante 203.0.113.5 contra 10.0.0.1, ver https://malo.example/x.png y https://malo.example/panel");
  assert.deepEqual(r.ips, ["203.0.113.5"]);
  assert.ok(r.domains.includes("malo.example"));
});

test("analyzeEmailHeaders: detecta From distinto de Return-Path y SPF/DKIM fallidos", () => {
  const headers = ["From: Soporte Banco <soporte@banco-real.com>", "Return-Path: <x@enviador-malo.ru>", "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=enviador-malo.ru; dkim=fail; dmarc=fail"].join("\n");
  const r = analyzeEmailHeaders(headers);
  const t = r.patterns.map(p => p.title);
  assert.ok(t.some(x => /no coincide/.test(x)) && t.some(x => /SPF falló/.test(x)) && t.some(x => /DMARC falló/.test(x)), JSON.stringify(t));
});

test("containmentRules: sin datos no genera archivos vacíos de más", () => {
  assert.deepEqual(containmentRules([], [], "all"), {});
});

test("suggestIncidentTypes: solo sugiere, nunca decide por sí sola", () => {
  const headers = analyzeEmailHeaders(["From: Soporte Banco <soporte@banco-real.com>", "Return-Path: <x@enviador-malo.ru>", "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=enviador-malo.ru; dkim=fail; dmarc=fail"].join("\n"));
  const s = suggestIncidentTypes("email_headers", headers.patterns);
  assert.ok(s.length > 0);
  assert.equal(s[0].type, "phishing_email");
  assert.ok(typeof s[0].reason === "string" && s[0].reason.length > 0);
  // cada tipo sugerido tiene guía de bloqueo asociada
  for (const sug of s) assert.ok(Array.isArray(TYPE_GUIDANCE[sug.type]) && TYPE_GUIDANCE[sug.type].length > 0);
});

test("suggestIncidentTypes: sin patrones reconocibles no sugiere nada (no inventa un tipo)", () => {
  const s = suggestIncidentTypes("other", []);
  assert.deepEqual(s, []);
});

test("tipos de incidente: el humano los marca (check-out) vía incident_types_set; requiere permiso de rol", async () => {
  const store = await Store.open("memory", KEY);
  const op = await boot("operator", store);
  const auditor = await boot("auditor", store);
  const { data: { incidentId } } = await op.call("incident_open", { organization: "Acme", contactName: "Ana", contactEmail: "ana@acme.test", summary: "Caso para marcar tipos", affectedAssets: [] });

  // el auditor (solo lectura) no puede marcar tipos
  const denied = await auditor.call("incident_types_set", { incidentId, types: ["phishing_email"] });
  assert.equal(denied.isError, true);

  // el operador sí puede, y la respuesta incluye las opciones de bloqueo del tipo marcado
  const ok = await op.call("incident_types_set", { incidentId, types: ["phishing_email", "web_attack"] });
  assert.equal(ok.isError, false);
  assert.deepEqual(ok.data.types, ["phishing_email", "web_attack"]);
  assert.ok(Array.isArray(ok.data.guidance.phishing_email) && ok.data.guidance.phishing_email.length > 0);
  assert.ok(Array.isArray(ok.data.guidance.web_attack) && ok.data.guidance.web_attack.length > 0);

  // reemplaza (no acumula) los tipos marcados previamente
  const replaced = await op.call("incident_types_set", { incidentId, types: ["ddos"] });
  assert.equal(replaced.isError, false);
  assert.deepEqual(replaced.data.types, ["ddos"]);
});

test("tipos de incidente: no se pueden marcar sobre un caso cerrado", async () => {
  const store = await Store.open("memory", KEY);
  const op = await boot("operator", store);
  const { data: { incidentId } } = await op.call("incident_open", { organization: "Acme", contactName: "Ana", contactEmail: "ana@acme.test", summary: "Caso que se cerrará", affectedAssets: [] });
  await store.setIncidentStatus(incidentId, "contained", "ana", "operator");
  await store.setIncidentStatus(incidentId, "closed", "ana", "operator");
  const r = await op.call("incident_types_set", { incidentId, types: ["other"] });
  assert.equal(r.isError, true); assert.equal(r.data.error, "NOT_FOUND_OR_CLOSED");
});

test("al analizar evidencia de phishing, la API propone tipos (incident_evidence_analyze) sin marcarlos", async () => {
  const store = await Store.open("memory", KEY);
  const op = await boot("operator", store);
  const { data: { incidentId } } = await op.call("incident_open", { organization: "Acme", contactName: "Ana", contactEmail: "ana@acme.test", summary: "Correo sospechoso reportado por un empleado", affectedAssets: ["correo"] });
  const headers = ["From: Soporte Banco <soporte@banco-real.com>", "Return-Path: <x@enviador-malo.ru>", "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=enviador-malo.ru; dkim=fail; dmarc=fail"].join("\n");
  const r = await op.call("incident_evidence_analyze", { incidentId, kind: "email_headers", description: "Cabeceras del correo reportado", content: headers });
  assert.equal(r.isError, false);
  assert.ok(Array.isArray(r.data.suggestedTypes) && r.data.suggestedTypes.length > 0);
  assert.equal(r.data.suggestedTypes[0].type, "phishing_email");

  // la sugerencia no marcó nada por sí sola: el incidente sigue sin tipos hasta que el humano confirme
  const current = await store.getIncident(incidentId);
  assert.deepEqual(current?.incident.types ?? [], []);
});
