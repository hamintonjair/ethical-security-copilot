import { h, api, panel, seal, fmtDate, toast, ROLE } from "../lib.js";

export async function accountView(ctx) {
  const u = ctx.me.user, forced = u.mustChange;
  const err = h("p", { class: "err", hidden: true, role: "alert" });
  let n = 0;
  const f = (label, name, hint) => { const id = `pw${++n}`; return h("div", { class: "field" }, h("label", { for: id }, label), h("input", { id, name, type: "password", required: true, autocomplete: name === "current" ? "current-password" : "new-password" }), hint ? h("span", { class: "hint" }, hint) : null); };
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault(); err.hidden = true; const g = (k) => form.elements[k].value;
    if (g("next") !== g("again")) { err.textContent = "Las contraseñas nuevas no coinciden."; err.hidden = false; return; }
    try { await api("POST", "/api/password", { current: g("current"), next: g("next") }); ctx.me.user.mustChange = false; toast("Contraseña cambiada."); ctx.go("#/"); }
    catch (ex) { err.textContent = ex.message; err.hidden = false; }
  } }, f("Contraseña actual", "current"), f("Contraseña nueva", "next", "Mínimo 12 caracteres. Una frase larga funciona mejor que una palabra con símbolos."), f("Repite la contraseña nueva", "again"), err,
    h("button", { class: "btn primary", type: "submit" }, "Cambiar contraseña"));
  return { crumb: "Mi cuenta", title: "Mi cuenta", node: h("div", { class: "stack narrow" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, forced ? "Elige tu contraseña" : "Mi cuenta"), forced ? h("p", {}, "Entraste con una contraseña temporal. Cámbiala para continuar.") : null)),
    panel("Cuenta", h("div", { class: "body" }, h("dl", { class: "facts" }, h("dt", {}, "Usuario"), h("dd", {}, u.username), h("dt", {}, "Nombre"), h("dd", {}, u.displayName || "—"), h("dt", {}, "Rol"), h("dd", {}, ROLE[u.role] ?? u.role)))),
    panel("Cambiar contraseña", h("div", { class: "body" }, form))) };
}
