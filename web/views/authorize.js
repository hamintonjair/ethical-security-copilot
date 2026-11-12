import { h, api, panel, errorBox } from "../lib.js";

export async function authorizeView(ctx) {
  const qs = location.hash.split("?")[1] ?? "";
  const q = Object.fromEntries(new URLSearchParams(qs));
  if (!ctx.can("users")) return { crumb: "Conectar cliente", node: h("div", { class: "stack narrow" }, h("h1", {}, "Conectar un cliente"), h("p", {}, "Solo un autorizador puede aprobar esta conexión. Entra con una cuenta de autorizador e inténtalo de nuevo.")) };
  let info;
  try { info = await api("GET", `/api/oauth/request?${qs}`); } catch (e) { return { crumb: "Conectar cliente", node: errorBox(e) }; }
  const decide = async (decision, btns) => {
    btns.forEach((b) => (b.disabled = true));
    try { const r = await api("POST", "/api/oauth/approve", { ...q, decision }); location.href = r.redirect; }
    catch (e) { btns.forEach((b) => (b.disabled = false)); err.textContent = e.message; err.hidden = false; }
  };
  const err = h("p", { class: "err", hidden: true, role: "alert" });
  const allow = h("button", { class: "btn primary", onclick: () => decide("allow", [allow, deny]) }, "Permitir conexión");
  const deny = h("button", { class: "btn", onclick: () => decide("deny", [allow, deny]) }, "Cancelar");
  return { crumb: "Conectar cliente", title: "Conectar cliente", node: h("div", { class: "stack narrow" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Conectar un cliente"), h("p", {}, "Una aplicación pide acceso al servidor MCP como agente."))),
    panel(null, h("div", { class: "body stack" },
      h("dl", { class: "facts" }, h("dt", {}, "Aplicación"), h("dd", {}, info.clientName || "Sin nombre"), h("dt", {}, "Volverá a"), h("dd", { class: "mono" }, info.redirectHost)),
      h("p", {}, "Podrá consultar y validar alcances, proponer y lanzar ejecuciones dentro de evaluaciones que tú ya aprobaste, y registrar hallazgos."),
      h("p", { class: "muted" }, "No podrá aprobar planes activos, liberar el kill switch ni administrar usuarios: eso sigue siendo solo tuyo. Si dejas de ser autorizador, el acceso deja de valer."),
      h("p", { class: "muted" }, "Permite solo si tú iniciaste esta conexión desde tu aplicación."), err, h("div", { class: "row" }, allow, deny)))) };
}
