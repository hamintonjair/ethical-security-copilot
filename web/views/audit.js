import { h, api, panel, empty, seal, fmtDate, shortHash, toast, ROLE } from "../lib.js";
import { actionLabel } from "./shared.js";

const PAGE = 50;

export async function auditView(ctx) {
  let offset = 0, broken = null;
  const list = h("div", {});
  const status = h("div", {});
  const render = async () => {
    const d = await api("GET", `/api/audit?limit=${PAGE}&offset=${offset}`);
    const items = d.rows.map((r) => h("li", { class: broken === r.seq ? "broken" : "" },
      h("div", { class: "what" }, actionLabel(r.action)),
      h("div", { class: "meta" }, h("span", {}, fmtDate(r.ts)), h("span", {}, `${r.actor} (${ROLE[r.role] ?? r.role})`), h("span", { class: "mono", title: r.hash }, `#${r.seq} · ${shortHash(r.hash)}…`)),
      r.payload && r.payload !== "{}" && r.payload !== "null" ? h("details", {}, h("summary", {}, "Detalle"), h("pre", { class: "report" }, pretty(r.payload))) : null));
    const pages = Math.ceil(d.total / PAGE), page = offset / PAGE + 1;
    list.replaceChildren(panel(`Registro (${d.total} eventos)`, items.length ? h("ol", { class: `chain${broken ? " bad" : ""}` }, items) : empty("Sin eventos", "Todavía no hay actividad registrada."),
      h("div", { class: "row" }, h("button", { class: "btn small", disabled: offset === 0, onclick: () => { offset -= PAGE; render(); } }, "Más recientes"),
        h("span", { class: "muted" }, `Página ${page} de ${Math.max(1, pages)}`),
        h("button", { class: "btn small", disabled: offset + PAGE >= d.total, onclick: () => { offset += PAGE; render(); } }, "Más antiguos"))));
  };
  const verify = async (btn) => {
    btn.disabled = true;
    try {
      const r = await api("POST", "/api/audit/verify");
      broken = r.ok ? null : r.brokenAtSeq;
      status.replaceChildren(r.ok ? h("p", {}, seal("Cadena íntegra", "ok"), ` Se recalcularon los ${r.checked} eventos y cada uno encadena con el anterior.`)
        : h("p", {}, seal("Cadena rota", "bad"), ` El evento #${r.brokenAtSeq} no coincide con su huella. Alguien modificó el registro: trátalo como un incidente.`));
      await render();
    } catch (e) { toast(e.message, true); } finally { btn.disabled = false; }
  };
  const btn = h("button", { class: "btn primary", onclick: () => verify(btn) }, "Verificar cadena");
  await render();
  return { crumb: "Auditoría", title: "Auditoría", node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Auditoría"), h("p", {}, "Registro de solo-añadir. Cada evento guarda la huella del anterior, así que cualquier cambio posterior se detecta."))),
    h("div", { class: "row" }, btn), status, list) };
}

function pretty(s) { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return String(s); } }
