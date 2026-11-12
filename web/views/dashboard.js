import { h, api, panel, empty, seal, stateSeal, fmtDate, STATE } from "../lib.js";
import { actionLabel, plansTable } from "./shared.js";

export async function dashboardView(ctx) {
  const reload = () => ctx.go("#/");
  const d = await api("GET", "/api/dashboard");
  const list = await api("GET", "/api/assessments");
  const names = new Map(list.map((a) => [a.id, a.name]));
  const order = Object.keys(STATE);
  const counts = order.filter((s) => d.counts[s]);

  const node = h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Panel"),
      h("p", {}, d.killSwitch.active ? "Todo está detenido. Nada se ejecuta hasta que un autorizador libere el kill switch." : "Resumen de lo que necesita una decisión y de lo último que pasó."))),
    panel("Planes esperando aprobación",
      d.pendingPlans.length ? plansTable(d.pendingPlans, { canDecide: ctx.can("decidePlan"), nameOf: (id) => names.get(id), reload, showAssessment: true })
        : empty("Nada pendiente", "No hay planes esperando una decisión.")),
    h("div", { class: "grid2" },
      panel("Evaluaciones", counts.length
        ? h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, counts.map((s) => h("tr", {}, h("td", {}, stateSeal(s)), h("td", {}, String(d.counts[s]))))))) 
        : empty("Aún no hay evaluaciones", ctx.can("createAssessment") ? "Crea la primera para empezar." : "Un autorizador debe crear la primera.",
            ctx.can("createAssessment") ? h("a", { class: "btn primary", href: "#/evaluaciones/nueva" }, "Nueva evaluación") : null),
        h("a", { href: "#/evaluaciones" }, "Ver todas")),
      panel("Registro de auditoría", h("div", { class: "body" }, h("p", {}, `${d.auditTotal} registros encadenados por hash.`),
        ctx.can("audit") ? h("p", {}, h("a", { href: "#/auditoria" }, "Abrir el libro y verificar la cadena")) : h("p", { class: "muted" }, "Tu rol no accede al libro de auditoría.")))),
    ctx.can("audit") ? panel("Actividad reciente", d.recentAudit.length
      ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Cuándo"), h("th", {}, "Quién"), h("th", {}, "Qué"))),
          h("tbody", {}, d.recentAudit.map((r) => h("tr", {}, h("td", {}, fmtDate(r.ts)), h("td", {}, r.actor), h("td", {}, actionLabel(r.action)))))))
      : empty("Sin actividad todavía")) : null);
  return { crumb: "Panel", title: "Panel", node };
}
