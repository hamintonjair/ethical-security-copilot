#!/usr/bin/env node
// CLI para HUMANOS (canal separado del LLM): crear autorizaciones, avanzar el ciclo, aprobar planes, liberar el kill switch.
import { readFileSync } from "node:fs";
import { Store } from "./store.js";
import type { State } from "./state.js";

const key = process.env.ESC_SIGNING_KEY;
if (!key || key.length < 32) { console.error("ESC_SIGNING_KEY (mín. 32 caracteres) es obligatorio."); process.exit(1); }
const dbUrl = process.env.ESC_DATABASE_URL;
if (!dbUrl) { console.error("ESC_DATABASE_URL es obligatorio."); process.exit(1); }
const store = await Store.open(dbUrl, Buffer.from(key));
const who = process.env.ESC_ACTOR ?? process.env.USER ?? "humano";
const [cmd, ...args] = process.argv.slice(2);

try {
  switch (cmd) {
    case "create-assessment": { const a = await store.createAssessment(JSON.parse(readFileSync(args[0], "utf8")), who); await store.audit({ actor: who, role: "authorizer", action: "assessment_create", assessmentId: a.id }); console.log(`id=${a.id} version=${a.version} hash=${a.contentHash}`); break; }
    case "advance": { const ok = await store.transition(args[0], args[1] as State, who, "authorizer"); console.log(ok ? "ok" : "transición inválida"); process.exitCode = ok ? 0 : 1; break; }
    case "show-plan": console.log(JSON.stringify(await store.getPlan(args[0]), null, 2)); break;
    case "approve": { console.log(`approvalToken=${await store.approvePlan(args[0], who, "operator")}\n(un solo uso; válido solo para los objetivos de ese plan)`); break; }
    case "release-kill-switch": await store.releaseKillSwitch(who, "authorizer"); console.log("kill switch liberado"); break;
    case "verify-audit": { const r = await store.verifyAuditChain(); console.log(JSON.stringify(r)); process.exitCode = r.ok ? 0 : 2; break; }
    default: console.log("Uso: cli <create-assessment f.json | advance <id> <estado> | show-plan <id> | approve <planId> | release-kill-switch | verify-audit>");
  }
} finally { await store.close(); }
