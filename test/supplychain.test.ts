import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Store } from "../src/store.js";
import { createServer } from "../src/server.js";
import { parseManifest, checkVulnerabilities } from "../src/supplychain.js";

const KEY = Buffer.from("supplychain-key-supplychain-key-1234");

async function boot(role: "agent" | "authorizer" | "operator" | "analyst" | "auditor", store: Store) {
  const { server } = createServer({ store, role, actor: `${role}-x` });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "1" });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => { const r: any = await client.callTool({ name, arguments: args }); return { isError: !!r.isError, data: JSON.parse(r.content[0].text.startsWith("{") || r.content[0].text.startsWith("[") ? r.content[0].text : "{}") || r.content[0].text, raw: r.content[0].text }; };
  return { call };
}

const assessmentInput = (over: Record<string, unknown> = {}) => ({
  name: "Evaluación de prueba cadena de suministro",
  authorizer: { organization: "Org Demo", name: "Ana Responsable", email: "ana@demo.test", emergencyContact: "+57 300 000 0000" },
  allowedModes: ["passive", "lab", "active"],
  scope: [{ type: "cidr", value: "203.0.113.0/24" }],
  exclusions: [],
  window: { notBefore: "2026-11-01T00:00:00Z", notAfter: "2026-12-01T00:00:00Z", maxRequestsPerSecond: 5, maxConcurrency: 2 },
  allowedModules: ["tcp_port_check"],
  ...over,
});

test("parseManifest: package-lock.json (lockfileVersion 3, campo packages)", () => {
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: { "": { name: "app" }, "node_modules/left-pad": { version: "1.3.0" }, "node_modules/foo/node_modules/bar": { version: "2.0.0" } },
  });
  const sbom = parseManifest("npm_package_lock", lock);
  assert.deepEqual(new Set(sbom.map(s => `${s.name}@${s.version}`)), new Set(["left-pad@1.3.0", "bar@2.0.0"]));
  assert.ok(sbom.every(s => s.ecosystem === "npm"));
});

test("parseManifest: package-lock.json (lockfileVersion 1, árbol dependencies)", () => {
  const lock = JSON.stringify({ dependencies: { minimist: { version: "1.2.5" }, lodash: { version: "4.17.20", dependencies: { "sub-dep": { version: "0.1.0" } } } } });
  const sbom = parseManifest("npm_package_lock", lock);
  assert.deepEqual(new Set(sbom.map(s => `${s.name}@${s.version}`)), new Set(["minimist@1.2.5", "lodash@4.17.20", "sub-dep@0.1.0"]));
});

test("parseManifest: package.json limpia rangos (^, ~)", () => {
  const pkg = JSON.stringify({ dependencies: { express: "^4.18.2" }, devDependencies: { mocha: "~10.2.0" } });
  const sbom = parseManifest("npm_package_json", pkg);
  assert.deepEqual(new Set(sbom.map(s => `${s.name}@${s.version}`)), new Set(["express@4.18.2", "mocha@10.2.0"]));
});

test("parseManifest: requirements.txt ignora comentarios y líneas sin versión fija", () => {
  const req = ["django==4.2.1", "# comentario", "requests>=2.0  # no es versión fija", "flask == 2.3.0"].join("\n");
  const sbom = parseManifest("pip_requirements", req);
  assert.deepEqual(new Set(sbom.map(s => `${s.name}@${s.version}`)), new Set(["django@4.2.1", "flask@2.3.0"]));
  assert.ok(sbom.every(s => s.ecosystem === "PyPI"));
});

test("parseManifest: lista manual con ecosistema elegido", () => {
  const sbom = parseManifest("manual", "github.com/foo/bar@1.2.3\n# comentario\ngolang.org/x/net@0.10.0", "Go");
  assert.deepEqual(sbom, [{ name: "github.com/foo/bar", version: "1.2.3", ecosystem: "Go" }, { name: "golang.org/x/net", version: "0.10.0", ecosystem: "Go" }]);
});

test("parseManifest: manifiesto inválido o vacío da un error claro", () => {
  assert.throws(() => parseManifest("npm_package_lock", "esto no es json"), /JSON válido/);
  assert.throws(() => parseManifest("pip_requirements", "sin ninguna línea útil"), /requirements\.txt/);
});

test("checkVulnerabilities: cruza el lote con OSV.dev y trae el detalle de cada vulnerabilidad", async () => {
  const calls: string[] = [];
  const fetchImpl = (async (url: string, init?: any) => {
    calls.push(url);
    if (url.endsWith("/v1/querybatch")) {
      const body = JSON.parse(init.body);
      assert.deepEqual(body.queries, [{ package: { name: "left-pad", ecosystem: "npm" }, version: "1.3.0" }, { package: { name: "safe-pkg", ecosystem: "npm" }, version: "9.9.9" }]);
      return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "GHSA-xxxx" }] }, { vulns: [] }] }) };
    }
    if (url.includes("/v1/vulns/GHSA-xxxx")) return { ok: true, json: async () => ({ summary: "Problema conocido", aliases: ["CVE-2020-0001"], database_specific: { severity: "HIGH" } }) };
    throw new Error("url inesperada: " + url);
  }) as typeof fetch;
  const results = await checkVulnerabilities([{ name: "left-pad", version: "1.3.0", ecosystem: "npm" }, { name: "safe-pkg", version: "9.9.9", ecosystem: "npm" }], fetchImpl);
  assert.equal(results.length, 2);
  assert.equal(results[0].vulns.length, 1);
  assert.deepEqual(results[0].vulns[0], { id: "GHSA-xxxx", summary: "Problema conocido", aliases: ["CVE-2020-0001"], severity: "high" });
  assert.equal(results[1].vulns.length, 0);
  assert.ok(calls.some(u => u.endsWith("/v1/querybatch")));
});

test("checkVulnerabilities: severidad por puntaje numérico cuando no hay database_specific.severity", async () => {
  const fetchImpl = (async (url: string) => {
    if (url.endsWith("/v1/querybatch")) return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "OSV-1" }] }] }) };
    return { ok: true, json: async () => ({ summary: "x", severity: [{ type: "CVSS_V3", score: "9.8" }] }) };
  }) as typeof fetch;
  const r = await checkVulnerabilities([{ name: "pkg", version: "1.0.0", ecosystem: "npm" }], fetchImpl);
  assert.equal(r[0].vulns[0].severity, "critical");
});

test("checkVulnerabilities: sin dependencias no llama a la red", async () => {
  let called = false;
  const fetchImpl = (async () => { called = true; return new Response("{}", { status: 200 }); }) as typeof fetch;
  const r = await checkVulnerabilities([], fetchImpl);
  assert.deepEqual(r, []);
  assert.equal(called, false);
});

test("supply_chain_analyze (MCP): rol no permitido, evaluación inexistente y manifiesto inválido", async () => {
  const store = await Store.open("memory", KEY);
  const auditor = await boot("auditor", store);
  const denied = await auditor.call("supply_chain_analyze", { assessmentId: "00000000-0000-0000-0000-000000000000", kind: "manual", content: "x@1" });
  assert.equal(denied.isError, true); assert.equal(denied.data.error, "ROLE_NOT_ALLOWED");

  const agent = await boot("agent", store);
  const noAssessment = await agent.call("supply_chain_analyze", { assessmentId: "00000000-0000-0000-0000-000000000000", kind: "manual", content: "x@1" });
  assert.equal(noAssessment.isError, true); assert.equal(noAssessment.data.error, "NO_ACTIVE_ASSESSMENT");

  const a = await store.createAssessment(assessmentInput(), "ana");
  const badManifest = await agent.call("supply_chain_analyze", { assessmentId: a.id, kind: "npm_package_lock", content: "no es json" });
  assert.equal(badManifest.isError, true); assert.equal(badManifest.data.error, "MANIFEST_PARSE_ERROR");
});
