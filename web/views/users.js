import { h, api, panel, empty, seal, fmtDate, toast, formDialog, confirmDialog, ROLE } from "../lib.js";

const ROLE_HELP = { authorizer: "Define el alcance, aprueba planes y gestiona usuarios.", operator: "Activa el kill switch y consulta.", analyst: "Registra hallazgos y genera informes.", auditor: "Solo lectura, con acceso a la auditoría." };
const PW_HINT = "Mínimo 12 caracteres. La persona deberá cambiarla al entrar.";

export async function usersView(ctx) {
  const users = await api("GET", "/api/users");
  const reload = () => ctx.go("#/usuarios", true);
  const run = async (p, ok) => { try { await p; toast(ok); await reload(); } catch (e) { toast(e.message, true); } };

  const create = async () => {
    const v = await formDialog({ title: "Nuevo usuario", submit: "Crear usuario", fields: [
      { name: "username", label: "Usuario", required: true, hint: "Minúsculas, números, punto, guion o guion bajo (3–40)." },
      { name: "displayName", label: "Nombre" },
      { name: "role", label: "Rol", type: "select", value: "analyst", options: Object.entries(ROLE) },
      { name: "password", label: "Contraseña temporal", type: "password", required: true, autocomplete: "new-password", hint: PW_HINT }] });
    if (v) await run(api("POST", "/api/users", v), `Usuario «${v.username}» creado.`);
  };
  const role = async (u) => {
    const v = await formDialog({ title: `Rol de ${u.username}`, intro: "Sus sesiones abiertas se cerrarán.", submit: "Cambiar rol", fields: [{ name: "role", label: "Rol", type: "select", value: u.role, options: Object.entries(ROLE).map(([k, l]) => [k, `${l}: ${ROLE_HELP[k]}`]) }] });
    if (v && v.role !== u.role) await run(api("POST", `/api/users/${u.id}/update`, { role: v.role }), "Rol actualizado.");
  };
  const reset = async (u) => {
    const v = await formDialog({ title: `Restablecer contraseña de ${u.username}`, intro: "Se cerrarán sus sesiones y deberá cambiarla al entrar.", submit: "Restablecer", fields: [{ name: "password", label: "Contraseña temporal", type: "password", required: true, autocomplete: "new-password", hint: PW_HINT }] });
    if (v) await run(api("POST", `/api/users/${u.id}/reset`, v), "Contraseña restablecida.");
  };
  const toggle = async (u) => {
    if (!u.disabled && !(await confirmDialog({ title: `Deshabilitar a ${u.username}`, danger: true, confirm: "Deshabilitar", body: h("p", { class: "muted" }, "No podrá entrar y sus sesiones se cerrarán. Puedes habilitarlo de nuevo después.") }))) return;
    await run(api("POST", `/api/users/${u.id}/update`, { disabled: !u.disabled }), u.disabled ? "Usuario habilitado." : "Usuario deshabilitado.");
  };
  const unlock = (u) => run(api("POST", `/api/users/${u.id}/update`, { unlock: true }), "Cuenta desbloqueada.");

  const isLocked = (u) => u.lockedUntil && new Date(u.lockedUntil) > new Date();
  const rows = users.map((u) => h("tr", {},
    h("td", {}, h("strong", {}, u.username), u.displayName ? h("div", { class: "muted" }, u.displayName) : null, u.id === ctx.me.user.id ? h("div", { class: "muted" }, "Eres tú") : null),
    h("td", {}, ROLE[u.role] ?? u.role),
    h("td", {}, u.disabled ? seal("Deshabilitado", "bad") : isLocked(u) ? seal("Bloqueado", "warn") : u.mustChange ? seal("Cambio pendiente", "warn") : seal("Activo", "ok")),
    h("td", {}, fmtDate(u.lastLogin)),
    h("td", {}, h("div", { class: "row" },
      h("button", { class: "btn small", onclick: () => role(u) }, "Rol"), h("button", { class: "btn small", onclick: () => reset(u) }, "Restablecer contraseña"),
      isLocked(u) ? h("button", { class: "btn small", onclick: () => unlock(u) }, "Desbloquear") : null,
      u.id !== ctx.me.user.id ? h("button", { class: `btn small ${u.disabled ? "" : "danger"}`, onclick: () => toggle(u) }, u.disabled ? "Habilitar" : "Deshabilitar") : null))));
  return { crumb: "Usuarios", title: "Usuarios", node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Usuarios"), h("p", {}, "Quién puede entrar a la consola y qué puede hacer.")), h("button", { class: "btn primary", onclick: create }, "Nuevo usuario")),
    panel(null, users.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Usuario", "Rol", "Estado", "Último acceso", ""].map((t) => h("th", {}, t)))), h("tbody", {}, rows))) : empty("Sin usuarios", "Crea el primero."))) };
}
