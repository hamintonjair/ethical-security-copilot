import { h, api, openDialog, toast, copyText, seal, fmtDate, MODE, PLAN, PLAN_TONE, STATE, targetText, panel, empty } from "../lib.js";

/* ---------- Registro de auditoría en lenguaje llano ---------- */
const ACTIONS = {
  "policy:allow": "Operación permitida", "policy:deny": "Operación denegada", scope_validate: "Consulta de alcance", "plan:created": "Plan propuesto",
  "plan:approved": "Plan aprobado", "plan:rejected": "Plan rechazado", "kill_switch:on": "Kill switch activado", "kill_switch:off": "Kill switch liberado",
  assessment_create: "Evaluación creada", assessment_version: "Nueva versión del alcance", finding_create: "Hallazgo registrado", "finding:triage": "Triaje de hallazgo",
  report_generate: "Informe cerrado", report_preview: "Vista previa de informe", "scan:finished": "Ejecución terminada", scan_refused: "Ejecución rechazada",
  "auth:login": "Inicio de sesión", "auth:login_failed": "Intento de entrada fallido", "auth:logout": "Cierre de sesión", "auth:password_changed": "Contraseña cambiada",
  "user:create": "Usuario creado", "user:update": "Usuario modificado", "user:reset_password": "Contraseña restablecida", "audit:verify": "Cadena verificada", "oauth:approve": "Conexión de cliente MCP aprobada", "oauth:deny": "Conexión de cliente MCP rechazada", "web:forbidden": "Acceso denegado por rol",
};
export function actionLabel(a) {
  if (ACTIONS[a]) return ACTIONS[a];
  const m = /^state:(\w+)->(\w+)$/.exec(a);
  if (m) return `Estado: ${STATE[m[1]] ?? m[1]} → ${STATE[m[2]] ?? m[2]}`;
  if (a.startsWith("tool_denied:")) return `Herramienta denegada por rol (${a.slice(12)})`;
  return a;
}

/* ---------- Módulos ---------- */
let modules = null;
export async function getModules() { return (modules ??= await api("GET", "/api/modules")); }
export async function moduleTitle(id) { return (await getModules()).find((m) => m.id === id)?.title ?? id; }

/* ---------- Revisión de planes ---------- */
function tokenDialog(token) {
  return openDialog((close) => h("form", { method: "dialog", onsubmit: (e) => { e.preventDefault(); close(true); } },
    h("h2", {}, "Plan aprobado"),
    h("p", { class: "muted" }, "Este token se muestra una sola vez. Entrégalo al agente por un canal aparte; solo sirve para los objetivos de este plan y se consume al usarlo."),
    h("code", { class: "token" }, token),
    h("div", { class: "actions" },
      h("button", { type: "button", class: "btn", onclick: () => copyText(token) }, "Copiar token"),
      h("button", { type: "submit", class: "btn primary" }, "Ya lo guardé"))));
}

/** Muestra el plan y deja aprobar o rechazar. Devuelve true si algo cambió. */
export async function reviewPlan(plan, assessmentName) {
  const title = await moduleTitle(plan.moduleId);
  const mods = await getModules();
  const changes = mods.find((m) => m.id === plan.moduleId)?.changesState;
  const choice = await openDialog((close) => h("form", { method: "dialog" },
    h("h2", {}, "Revisar plan"),
    h("dl", { class: "facts" },
      h("dt", {}, "Evaluación"), h("dd", {}, assessmentName ?? plan.assessmentId),
      h("dt", {}, "Módulo"), h("dd", {}, title),
      h("dt", {}, "Modo"), h("dd", {}, MODE[plan.mode] ?? plan.mode),
      h("dt", {}, "Objetivos"), h("dd", {}, plan.targets.map((t) => h("div", { class: "mono" }, targetText(t)))),
      h("dt", {}, "Límites"), h("dd", {}, `${plan.limits.maxRequestsPerSecond} peticiones/s · ${plan.limits.maxConcurrency} en paralelo · hasta ${fmtDate(plan.limits.notAfter)}`),
      h("dt", {}, "Cambia estado"), h("dd", {}, changes ? "Sí: la prueba modifica algo en el objetivo." : "No: solo lee.")),
    h("div", { class: "actions" },
      h("button", { type: "button", class: "btn", onclick: () => close(null) }, "Cerrar"),
      h("button", { type: "button", class: "btn danger", onclick: () => close("reject") }, "Rechazar"),
      h("button", { type: "button", class: "btn primary", onclick: () => close("approve") }, "Aprobar"))));
  if (!choice) return false;
  try {
    if (choice === "reject") { await api("POST", `/api/plans/${plan.id}/reject`); toast("Plan rechazado."); return true; }
    const r = await api("POST", `/api/plans/${plan.id}/approve`);
    await tokenDialog(r.token); return true;
  } catch (e) { toast(e.message, true); return false; }
}

export function plansTable(plans, { canDecide, nameOf, reload, showAssessment }) {
  if (!plans.length) return empty("No hay planes", "Cuando el agente proponga una ejecución en modo activo o con una prueba que cambia estado, aparecerá aquí.");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, showAssessment ? h("th", {}, "Evaluación") : null, h("th", {}, "Módulo"), h("th", {}, "Modo"), h("th", {}, "Objetivos"), h("th", {}, "Estado"), h("th", {}, "Propuesto"), h("th", {}, ""))),
    h("tbody", {}, plans.map((p) => {
      const title = h("td", {}, "…"); moduleTitle(p.moduleId).then((t) => { title.textContent = t; });
      return h("tr", {},
        showAssessment ? h("td", {}, h("a", { href: `#/evaluaciones/${p.assessmentId}/planes` }, nameOf?.(p.assessmentId) || p.assessmentId.slice(0, 8))) : null,
        title, h("td", {}, MODE[p.mode] ?? p.mode),
        h("td", {}, p.targets.slice(0, 3).map((t) => h("div", { class: "mono" }, targetText(t))), p.targets.length > 3 ? h("span", { class: "faint" }, `y ${p.targets.length - 3} más`) : null),
        h("td", {}, seal(PLAN[p.status] ?? p.status, PLAN_TONE[p.status] ?? "")), h("td", {}, fmtDate(p.createdAt)),
        h("td", {}, p.status === "pending_approval" && canDecide ? h("button", { class: "btn small primary", onclick: async () => { if (await reviewPlan(p, nameOf?.(p.assessmentId))) reload(); } }, "Revisar") : null));
    }))));
}
export { panel };
