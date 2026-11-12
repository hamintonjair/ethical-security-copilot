import { h, api, panel, empty, seal, stateSeal, fmtDate, shortHash, toast, confirmDialog, download, copyText, STATE, MODE, SEVERITY, SEV_TONE, TRIAGE, TARGET_TYPE, targetText } from "../lib.js";
import { plansTable, getModules } from "./shared.js";
import { assessmentForm } from "./assessments.js";

const ORDER = ["draft", "scope_validated", "planned", "approved", "executing", "verifying", "triage", "reported", "closed"];
const HELP = {
  draft: "La evaluación existe pero todavía no autoriza nada. Valida el alcance para continuar.",
  scope_validated: "El alcance y la firma están revisados. El siguiente paso es planificar.",
  planned: "Lista para autorizar. Al aprobarla, el agente podrá ejecutar los módulos permitidos dentro de la ventana.",
  approved: "Autorizada. Los módulos pasivos y de laboratorio corren solos; el modo activo sigue pidiendo aprobación por plan.",
  executing: "Ya hubo ejecuciones. Puedes registrar hallazgos y revisar planes.",
  verifying: "En verificación de hallazgos.", triage: "En triaje: marca cada hallazgo como confirmado, falso positivo o riesgo aceptado.",
  reported: "El informe quedó cerrado. Puedes cerrar la evaluación.", halted: "Está detenida y no se puede reanudar. Para continuar hay que crear una nueva versión de la autorización.",
  closed: "Cerrada. Solo queda consultarla.",
};
const NEXT = {
  draft: [["scope_validated", "Validar alcance", false]], scope_validated: [["planned", "Pasar a planificación", false]],
  planned: [["approved", "Aprobar la evaluación", false], ["scope_validated", "Volver a validar el alcance", false]],
  approved: [["halted", "Detener la evaluación", true]], executing: [["halted", "Detener la evaluación", true]],
  reported: [["closed", "Cerrar la evaluación", false]], halted: [["closed", "Cerrar la evaluación", false]], verifying: [["halted", "Detener la evaluación", true]], triage: [["halted", "Detener la evaluación", true]],
};
const CONFIRM = {
  approved: "Aprobar autoriza al agente a ejecutar los módulos permitidos sobre el alcance, dentro de la ventana y los límites definidos. Revisa que todo esté correcto.",
  halted: "La evaluación quedará detenida y no se podrá reanudar: habrá que crear una nueva versión de la autorización.",
  closed: "Una evaluación cerrada ya no admite cambios.",
};
const TABS = [["resumen", "Resumen"], ["ciclo", "Ciclo de vida"], ["planes", "Planes"], ["hallazgos", "Hallazgos"], ["informe", "Informe"]];

export async function assessmentView(ctx, id, tab = "resumen") {
  const d = await api("GET", `/api/assessments/${id}`);
  const reload = () => ctx.go(`#/evaluaciones/${id}/${tab}`);
  if (tab === "version") return versionView(ctx, d);
  const names = new Map([[id, d.name]]);

  const body = ({ resumen: () => summary(d), ciclo: () => lifecycle(ctx, d, reload), planes: () => panel(null, plansTable(d.plans, { canDecide: ctx.can("decidePlan"), nameOf: (x) => names.get(x), reload })),
    hallazgos: () => findingsTab(ctx, d, reload), informe: () => reportTab(ctx, d) }[tab] ?? (() => summary(d)))();
  const tabCount = { planes: d.plans.filter((p) => p.status === "pending_approval").length, hallazgos: d.findings.length };

  const node = h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, d.name), h("p", { class: "row" }, stateSeal(d.state), seal(`Versión ${d.version}`, "mute"),
      d.signatureValid ? seal("Firma válida", "ok") : seal("Firma NO válida", "bad")))),
    h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, l]) => h("button", { role: "tab", "aria-selected": String(k === tab), onclick: () => ctx.go(`#/evaluaciones/${id}/${k}`) }, l, tabCount[k] ? ` (${tabCount[k]})` : ""))),
    body);
  return { crumb: `Evaluaciones › ${d.name}`, title: d.name, node };
}

/* ---------- Resumen ---------- */
function summary(d) {
  const L = d.window;
  return h("div", { class: "stack" },
    h("div", { class: "grid2" },
      panel("Autorización", h("div", { class: "body" }, h("dl", { class: "facts" },
        h("dt", {}, "Organización"), h("dd", {}, d.authorizer.organization), h("dt", {}, "Responsable"), h("dd", {}, `${d.authorizer.name} · ${d.authorizer.email}${d.authorizer.phone ? " · " + d.authorizer.phone : ""}`),
        h("dt", {}, "En emergencia"), h("dd", {}, d.authorizer.emergencyContact), h("dt", {}, "Documento"), h("dd", {}, d.authorizationDocRef || "—"),
        h("dt", {}, "Creada"), h("dd", {}, `${fmtDate(d.createdAt)} por ${d.createdBy}`), h("dt", {}, "Huella"), h("dd", { class: "mono" }, d.contentHash)))),
      panel("Ventana y límites", h("div", { class: "body" }, h("dl", { class: "facts" },
        h("dt", {}, "Desde"), h("dd", {}, fmtDate(L.notBefore)), h("dt", {}, "Hasta"), h("dd", {}, fmtDate(L.notAfter)),
        h("dt", {}, "Horario"), h("dd", {}, L.allowedHours ? `${L.allowedHours.from}–${L.allowedHours.to} (${L.allowedHours.tz})` : "Sin restricción"),
        h("dt", {}, "Ritmo"), h("dd", {}, `${L.maxRequestsPerSecond} peticiones/s · ${L.maxConcurrency} en paralelo${L.maxTotalRequests ? ` · máx. ${L.maxTotalRequests}` : ""}`),
        h("dt", {}, "Modos"), h("dd", {}, d.allowedModes.map((m) => MODE[m] ?? m).join(", ")), h("dt", {}, "Módulos"), h("dd", {}, d.allowedModules.join(", ")))))),
    panel("Alcance autorizado", h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Tipo"), h("th", {}, "Objetivo"))),
      h("tbody", {}, d.scope.map((t) => h("tr", {}, h("td", {}, TARGET_TYPE[t.type] ?? t.type), h("td", { class: "mono" }, targetText(t)))))))),
    d.exclusions.length ? panel("Exclusiones", h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Qué"), h("th", {}, "Motivo"))),
      h("tbody", {}, d.exclusions.map((e) => h("tr", {}, h("td", { class: "mono" }, e.technique ? `Técnica: ${e.technique}` : targetText(e.target)), h("td", {}, e.reason))))))) : null,
    d.testAccounts?.length ? panel("Cuentas de prueba (solo referencias)", h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, d.testAccounts.map((a) => h("tr", {}, h("td", {}, a.label), h("td", { class: "mono" }, a.secretRef))))))) : null,
    panel("Versiones", h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Versión"), h("th", {}, "Estado"), h("th", {}, "Creada"), h("th", {}, "Huella"))),
      h("tbody", {}, d.versions.map((v) => h("tr", {}, h("td", {}, `v${v.version}`), h("td", {}, stateSeal(v.state)), h("td", {}, `${fmtDate(v.createdAt)} · ${v.createdBy}`), h("td", { class: "mono" }, shortHash(v.contentHash) + "…"))))))));
}

/* ---------- Ciclo ---------- */
function lifecycle(ctx, d, reload) {
  const idx = ORDER.indexOf(d.state);
  const halted = d.state === "halted";
  const actions = ctx.can("advance") ? NEXT[d.state] ?? [] : [];
  const act = async ([to, label, danger]) => {
    if (CONFIRM[to] && !(await confirmDialog({ title: label, danger, confirm: label, body: h("p", { class: "muted" }, CONFIRM[to]) }))) return;
    try { await api("POST", `/api/assessments/${d.id}/advance`, { to }); toast("Estado actualizado."); reload(); } catch (e) { toast(e.message, true); }
  };
  return h("div", { class: "stack" },
    panel("Dónde está", h("div", { class: "body stack" },
      h("ol", { class: `steps${halted ? " halted" : ""}`, "aria-label": "Ciclo de vida" }, ORDER.map((s, i) => h("li", { class: halted ? (i === 0 ? "now" : "") : i < idx ? "done" : i === idx ? "now" : "", "aria-current": !halted && i === idx ? "step" : null },
        h("span", { class: "n" }, i < idx && !halted ? "✓" : String(i + 1)), h("span", { class: "t" }, STATE[s])))),
      halted ? h("p", {}, seal("Detenida", "bad"), " ", HELP.halted) : h("p", {}, HELP[d.state]),
      h("p", { class: "hint" }, "Los pasos de ejecución, verificación, triaje e informe avanzan solos cuando hay ejecuciones y al cerrar el informe."))),
    ctx.can("advance") ? panel("Acciones", h("div", { class: "body row" },
      actions.map((a, i) => h("button", { class: `btn ${a[2] ? "danger" : i === 0 ? "primary" : ""}`, onclick: () => act(a) }, a[1])),
      d.state !== "closed" ? h("a", { class: "btn", href: `#/evaluaciones/${d.id}/version` }, "Nueva versión del alcance") : null,
      !actions.length && d.state === "closed" ? h("span", { class: "muted" }, "No hay acciones disponibles.") : null)) : null);
}

async function versionView(ctx, d) {
  if (!ctx.can("createAssessment")) return { crumb: d.name, node: h("p", { class: "err" }, "Solo un autorizador puede crear versiones.") };
  const form = await assessmentForm(ctx, { initial: d, submitText: "Crear nueva versión", onSave: async (body) => { const r = await api("POST", `/api/assessments/${d.id}/versions`, body); toast(`Versión ${r.version} creada como borrador.`); ctx.go(`#/evaluaciones/${d.id}/ciclo`); } });
  return { crumb: `Evaluaciones › ${d.name} › Nueva versión`, title: "Nueva versión", node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Nueva versión del alcance"),
      h("p", {}, "La versión nueva vuelve a borrador y las aprobaciones de planes anteriores dejan de valer. Hay que repetir el ciclo."))), form) };
}

/* ---------- Hallazgos ---------- */
function findingsTab(ctx, d, reload) {
  const canWrite = ctx.can("findings");
  const open = ["executing", "verifying", "triage"].includes(d.state);
  const formBox = h("div", {});
  const list = d.findings.length ? d.findings.map(({ id, data: x }) => h("article", { class: "finding" },
    h("div", { class: "row" }, h("h3", { class: "grow" }, x.title), seal(SEVERITY[x.severity] ?? x.severity, SEV_TONE[x.severity] ?? ""),
      canWrite ? h("select", { "aria-label": "Triaje", onchange: async (e) => { try { await api("POST", `/api/findings/${id}/triage`, { triage: e.target.value }); toast("Triaje actualizado."); } catch (ex) { toast(ex.message, true); reload(); } } },
        Object.entries(TRIAGE).map(([v, l]) => h("option", { value: v, selected: v === x.triage }, l))) : seal(TRIAGE[x.triage] ?? x.triage, "mute")),
    h("p", { class: "muted" }, h("span", { class: "mono" }, x.asset), ` · CVSS ${x.cvssScore} · confianza ${x.confidence}`),
    h("details", {}, h("summary", {}, "Ver detalle"),
      h("h3", {}, "Hechos observados"), h("ul", {}, x.observedFacts.map((f) => h("li", {}, f))),
      x.riskHypotheses?.length ? [h("h3", {}, "Hipótesis de riesgo (sin verificar)"), h("ul", {}, x.riskHypotheses.map((f) => h("li", {}, f)))] : null,
      h("h3", {}, "Evidencia (redactada)"), x.evidence.map((e) => h("div", {}, h("p", {}, e.description), h("pre", { class: "report" }, e.redactedContent), e.reproSteps?.length ? h("ol", {}, e.reproSteps.map((s) => h("li", {}, s))) : null)),
      h("div", { class: "cols" }, h("div", {}, h("h3", {}, "Impacto de negocio"), h("p", {}, x.businessImpact)), h("div", {}, h("h3", {}, "Recomendación"), h("p", {}, x.recommendation)))))) : [empty("Sin hallazgos", "Los hallazgos aparecen aquí cuando el agente o un analista los registran.")];
  return h("div", { class: "stack" },
    panel("Hallazgos", h("div", {}, list), canWrite ? h("button", { class: "btn small primary", disabled: !open, title: open ? "" : "Disponible cuando la evaluación ya tuvo ejecuciones", onclick: () => { formBox.replaceChildren(findingForm(d, () => reload())); formBox.scrollIntoView({ block: "start" }); } }, "Registrar hallazgo") : null),
    formBox, canWrite && !open ? h("p", { class: "hint" }, "Se pueden registrar hallazgos cuando la evaluación ya tuvo ejecuciones (estado «En ejecución» o posterior).") : null);
}

function findingForm(d, done) {
  const lines = (v) => String(v).split("\n").map((s) => s.trim()).filter(Boolean);
  const err = h("p", { class: "err", hidden: true, role: "alert" });
  let n = 0;
  const f = (label, ctl, hint) => { const id = `ff${++n}`; ctl.id = id; return h("div", { class: "field" }, h("label", { for: id }, label), ctl, hint ? h("span", { class: "hint" }, hint) : null); };
  const T = (name, v = "", o = {}) => h("input", { type: o.type ?? "text", name, value: v, required: true, step: o.step, min: o.min, max: o.max });
  const A = (name, rows = 3, req = true) => h("textarea", { name, rows, required: req });
  const S = (name, o) => h("select", { name }, Object.entries(o).map(([v, l]) => h("option", { value: v }, l)));
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault(); err.hidden = true; const g = (k) => form.elements[k].value;
    try {
      await api("POST", `/api/assessments/${d.id}/findings`, {
        title: g("title"), asset: g("asset"), severity: g("severity"), cvssVector: g("vector"), cvssScore: Number(g("score")), confidence: g("confidence"), triage: g("triage"),
        observedFacts: lines(g("facts")), riskHypotheses: lines(g("hyp")),
        evidence: [{ description: g("evdesc"), redactedContent: g("evbody"), reproSteps: lines(g("repro")) }], businessImpact: g("impact"), recommendation: g("reco") });
      toast("Hallazgo registrado."); done();
    } catch (ex) { err.textContent = ex.issues?.length ? `${ex.message} ${ex.issues.map((i) => `${i.path}: ${i.message}`).join("; ")}` : ex.message; err.hidden = false; }
  } },
    f("Título", T("title")), f("Activo afectado", T("asset"), "Debe estar dentro del alcance. Ej.: https://app.ejemplo.com o 10.0.0.5:8080"),
    h("div", { class: "cols" }, f("Severidad", S("severity", SEVERITY)), f("Puntaje CVSS", T("score", "0", { type: "number", step: "0.1", min: "0", max: "10" }), "Debe corresponder a la severidad."),
      f("Confianza", S("confidence", { high: "Alta", medium: "Media", low: "Baja" })), f("Triaje inicial", S("triage", TRIAGE))),
    f("Vector CVSS", T("vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")),
    f("Hechos observados", A("facts"), "Uno por línea. Solo lo que se vio, sin suposiciones."), f("Hipótesis de riesgo (opcional)", A("hyp", 2, false), "Uno por línea. Lo que podría pasar y no está verificado."),
    f("Evidencia: qué muestra", T("evdesc")), f("Evidencia: contenido", A("evbody", 4), "Se redactan automáticamente credenciales, tokens y datos personales."), f("Pasos para reproducir", A("repro", 3, false), "Uno por línea."),
    f("Impacto de negocio", A("impact", 2)), f("Recomendación", A("reco", 2)), err,
    h("div", { class: "row" }, h("button", { type: "submit", class: "btn primary" }, "Guardar hallazgo"), h("button", { type: "button", class: "btn", onclick: () => form.remove() }, "Cancelar")));
  return panel("Nuevo hallazgo", h("div", { class: "body" }, form));
}

/* ---------- Informe ---------- */
function reportTab(ctx, d) {
  const out = h("div", {});
  let last = null;
  const states = h("div", { class: "checks" }, Object.entries(TRIAGE).map(([v, l]) => h("label", {}, h("input", { type: "checkbox", name: "st", value: v, checked: v === "confirmed" }), l)));
  const fmt = h("select", { id: "rfmt" }, h("option", { value: "markdown" }, "Markdown"), h("option", { value: "json" }, "JSON"));
  const gen = async (finalize) => {
    const includeStates = [...states.querySelectorAll("input:checked")].map((i) => i.value);
    if (!includeStates.length) return toast("Elige al menos un estado de hallazgo.", true);
    if (finalize && !(await confirmDialog({ title: "Cerrar el informe", confirm: "Cerrar informe", body: h("p", { class: "muted" }, "La evaluación pasará a «Informada». Podrás generar vistas previas todas las veces que quieras, pero este paso solo avanza el ciclo."), danger: false }))) return;
    try {
      const r = await api("POST", `/api/assessments/${d.id}/report`, { format: fmt.value, includeStates, finalize });
      last = { text: r.text, format: r.format };
      out.replaceChildren(h("p", { class: "muted" }, `${r.findings} hallazgo(s) incluidos.`), h("pre", { class: "report" }, r.text),
        h("div", { class: "row" }, h("button", { class: "btn", onclick: () => copyText(last.text) }, "Copiar"), h("button", { class: "btn", onclick: () => download(`informe-${d.id.slice(0, 8)}.${last.format === "json" ? "json" : "md"}`, last.text, last.format === "json" ? "application/json" : "text/markdown") }, "Descargar")));
      if (finalize) { toast("Informe cerrado."); ctx.go(`#/evaluaciones/${d.id}/informe`); }
    } catch (e) { toast(e.message, true); }
  };
  return h("div", { class: "stack" }, panel("Generar informe", h("div", { class: "body stack" },
    h("div", { class: "field" }, h("span", { class: "legend" }, "Incluir hallazgos"), states, h("span", { class: "hint" }, "Por defecto solo los confirmados.")),
    h("div", { class: "field" }, h("label", { for: "rfmt" }, "Formato"), fmt),
    h("div", { class: "row" }, h("button", { class: "btn primary", onclick: () => gen(false) }, "Vista previa"),
      ctx.can("finalize") ? h("button", { class: "btn", onclick: () => gen(true) }, "Cerrar informe") : null),
    h("p", { class: "hint" }, "El informe separa hechos observados de hipótesis, redacta datos sensibles e incluye el estado de la cadena de auditoría."))), out);
}
