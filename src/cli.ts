#!/usr/bin/env node
// CLI para HUMANOS (canal separado del LLM): crear autorizaciones, avanzar el ciclo, aprobar planes, liberar el kill switch.
import { readFileSync } from "node:fs";
import { Store } from "./store.js";
import type { State } from "./state.js";
import { Auth, WEB_ROLES, type WebRole } from "./web/auth.js";

/** Lee una contraseña sin mostrarla. En entornos sin terminal interactiva usa ESC_NEW_PASSWORD. */
async function askPassword(prompt: string): Promise<string> {
  if (process.env.ESC_NEW_PASSWORD) return process.env.ESC_NEW_PASSWORD;
  if (!process.stdin.isTTY) throw new Error("No hay terminal interactiva: define ESC_NEW_PASSWORD solo para esta orden.");
  process.stdout.write(prompt);
  return new Promise(resolve => {
    let buf = "";
    process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.setEncoding("utf8");
    const onData = (ch: string) => {
      for (const c of ch) {
        if (c === "\u0003") { process.stdout.write("\n"); process.exit(130); }
        if (c === "\r" || c === "\n") { process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.off("data", onData); process.stdout.write("\n"); return resolve(buf); }
        if (c === "\u007f" || c === "\b") buf = buf.slice(0, -1); else buf += c;
      }
    };
    process.stdin.on("data", onData);
  });
}

const key = process.env.ESC_SIGNING_KEY;
if (!key || key.length < 32) { console.error("ESC_SIGNING_KEY (mín. 32 caracteres) es obligatorio."); process.exit(1); }
const dbUrl = process.env.ESC_DATABASE_URL;
if (!dbUrl) { console.error("ESC_DATABASE_URL es obligatorio."); process.exit(1); }
const store = await Store.open(dbUrl, Buffer.from(key));
const who = process.env.ESC_ACTOR ?? process.env.USER ?? "humano";
const auth = new Auth(store);
const [cmd, ...args] = process.argv.slice(2);

try {
  switch (cmd) {
    case "create-assessment": { const a = await store.createAssessment(JSON.parse(readFileSync(args[0], "utf8")), who); await store.audit({ actor: who, role: "authorizer", action: "assessment_create", assessmentId: a.id }); console.log(`id=${a.id} version=${a.version} hash=${a.contentHash}`); break; }
    case "advance": { const ok = await store.transition(args[0], args[1] as State, who, "authorizer"); console.log(ok ? "ok" : "transición inválida"); process.exitCode = ok ? 0 : 1; break; }
    case "show-plan": console.log(JSON.stringify(await store.getPlan(args[0]), null, 2)); break;
    case "approve": { console.log(`approvalToken=${await store.approvePlan(args[0], who, "operator")}\n(un solo uso; válido solo para los objetivos de ese plan)`); break; }
    case "release-kill-switch": await store.releaseKillSwitch(who, "authorizer"); console.log("kill switch liberado"); break;
    case "create-user": { // create-user <usuario> <authorizer|operator|analyst|auditor> [nombre]
      const role = args[1] as WebRole;
      if (!args[0] || !WEB_ROLES.includes(role)) { console.log(`Uso: create-user <usuario> <${WEB_ROLES.join("|")}> [nombre visible]`); process.exitCode = 1; break; }
      const pw = await askPassword("Contraseña temporal (mín. 12 caracteres): ");
      const r = await auth.createUser({ username: args[0], displayName: args.slice(2).join(" "), role, password: pw, mustChange: true }, { actor: who, role: "authorizer" });
      console.log(r.ok ? `usuario ${r.user.username} creado (${role}); deberá cambiar la contraseña al entrar` : `error: ${r.error}`); process.exitCode = r.ok ? 0 : 1; break;
    }
    case "reset-password": { // reset-password <usuario>
      const u = (await auth.listUsers()).find(x => x.username === args[0]);
      if (!u) { console.log("usuario no encontrado"); process.exitCode = 1; break; }
      const r = await auth.resetPassword(u.id, await askPassword("Nueva contraseña temporal: "), { actor: who, role: "authorizer" });
      console.log(r.ok ? "contraseña restablecida; deberá cambiarla al entrar" : `error: ${r.error}`); process.exitCode = r.ok ? 0 : 1; break;
    }
    case "unlock-user": { // unlock-user <usuario>
      const u = (await auth.listUsers()).find(x => x.username === args[0]);
      if (!u) { console.log("usuario no encontrado"); process.exitCode = 1; break; }
      const r = await auth.updateUser(u.id, { unlock: true }, { actor: who, role: "authorizer" });
      console.log(r.ok ? "cuenta desbloqueada" : `error: ${r.error}`); break;
    }
    case "list-users": for (const u of await auth.listUsers()) console.log(`${u.username}\t${u.role}\t${u.disabled ? "deshabilitado" : "activo"}${u.lockedUntil ? "\tbloqueado hasta " + u.lockedUntil : ""}`); break;
    case "verify-audit": { const r = await store.verifyAuditChain(); console.log(JSON.stringify(r)); process.exitCode = r.ok ? 0 : 2; break; }
    default: console.log("Uso: cli <create-assessment f.json | advance <id> <estado> | show-plan <id> | approve <planId> | release-kill-switch | verify-audit | create-user <usuario> <rol> | reset-password <usuario> | unlock-user <usuario> | list-users>");
  }
} finally { await store.close(); }
