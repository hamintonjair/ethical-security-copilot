import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { promisify } from "node:util";
const execFileP = promisify(execFile);
import { mkdtempSync, writeFileSync } from "node:fs";
import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { applyLocalMigrations } from "../src/db.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const KEY = "stdio-test-key-stdio-test-key-123456";
const tsx = (file: string) => ["--import", "tsx", file];
const env = (db: string, extra: Record<string, string> = {}) => ({ ...process.env, NODE_NO_WARNINGS: "1", ESC_DATABASE_URL: db, ESC_SIGNING_KEY: KEY, ...extra }) as Record<string, string>;

// Postgres real (PGlite) servido por TCP: varios procesos comparten la misma base, como harían con Supabase.
let lite: PGlite, pgServer: PGLiteSocketServer, DB_URL = "";
before(async () => {
  lite = new PGlite(); await applyLocalMigrations(lite);
  pgServer = new PGLiteSocketServer({ db: lite, port: 0, host: "127.0.0.1", maxConnections: 8 } as any);
  await pgServer.start();
  const port = (pgServer as any).server?.address?.().port ?? (pgServer as any).port;
  DB_URL = `postgres://postgres:postgres@127.0.0.1:${port}/postgres?sslmode=disable`;
});
after(async () => { await pgServer.stop(); await lite.close(); });

test("sin clave de firma el servidor se niega a arrancar", () => {
  const r = spawnSync(process.execPath, tsx("src/main.ts"), { env: { ...env(""), ESC_SIGNING_KEY: "" }, encoding: "utf8" });
  assert.notEqual(r.status, 0); assert.match(r.stderr, /ESC_SIGNING_KEY/);
});

test("proceso real: CLI humano autoriza y aprueba; el agente por stdio solo ve lo autorizado", async () => {
  const dir = mkdtempSync(join(tmpdir(), "esc-"));
  const db = DB_URL;
  const f = join(dir, "a.json");
  writeFileSync(f, JSON.stringify({
    name: "Evaluación stdio", authorizer: { organization: "Org", name: "Ana", email: "ana@demo.test", emergencyContact: "ana@demo.test" },
    allowedModes: ["passive", "lab"], scope: [{ type: "ip", value: "127.0.0.1" }], exclusions: [],
    window: { notBefore: "2020-01-01T00:00:00Z", notAfter: "2099-01-01T00:00:00Z", maxRequestsPerSecond: 10, maxConcurrency: 2 },
    allowedModules: ["config_audit"],
  }));
  const cli = async (...a: string[]) => (await execFileP(process.execPath, [...tsx("src/cli.ts"), ...a], { env: env(db), encoding: "utf8" })).stdout;
  const id = /id=([0-9a-f-]{36})/.exec(await cli("create-assessment", f))![1];
  for (const s of ["scope_validated", "planned", "approved"]) assert.match(await cli("advance", id, s), /ok/);

  const client = new Client({ name: "t", version: "1" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: tsx("src/main.ts"), env: env(db, { ESC_ROLE: "agent" }) }));
  const call = async (name: string, args: Record<string, unknown>) => JSON.parse(((await client.callTool({ name, arguments: args })) as any).content[0].text);
  assert.equal((await call("scope_validate", { assessmentId: id, target: { type: "ip", value: "127.0.0.1" } })).authorized, true);
  assert.equal((await call("scope_validate", { assessmentId: id, target: { type: "ip", value: "10.1.1.1" } })).authorized, false);
  assert.equal((await call("assessment_create", {} as any).catch(() => ({ error: "invalid" }))).error !== undefined, true);
  const scan = await call("scan_initiate", { assessmentId: id, moduleId: "config_audit", mode: "passive", targets: [{ type: "ip", value: "127.0.0.1" }], params: { content: "autoindex on" } });
  assert.equal(scan.status, "completed");
  await client.close();
  assert.equal(JSON.parse(await cli("verify-audit")).ok, true);
});
