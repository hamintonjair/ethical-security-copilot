import { h, api, panel, empty, stateSeal, fmtDate, toast, MODE, TARGET_TYPE, ApiError } from "../lib.js";
import { getModules } from "./shared.js";

export async function assessmentsView(ctx) {
  const list = await api("GET", "/api/assessments");
  const node = h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Evaluaciones"), h("p", {}, "Cada evaluación es una autorización firmada: define qué se puede probar, cuándo y con qué límites.")),
      ctx.can("createAssessment") ? h("a", { class: "btn primary", href: "#/evaluaciones/nueva" }, "Nueva evaluación") : null),
    panel(null, list.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Evaluación"), h("th", {}, "Organización"), h("th", {}, "Estado"), h("th", {}, "Ventana"), h("th", {}, "Versión"))),
      h("tbody", {}, list.map((a) => h("tr", { class: "link", tabindex: "0", onclick: () => ctx.go(`#/evaluaciones/${a.id}`), onkeydown: (e) => { if (e.key === "Enter") ctx.go(`#/evaluaciones/${a.id}`); } },
        h("td", {}, h("a", { href: `#/evaluaciones/${a.id}` }, a.name)), h("td", {}, a.organization), h("td", {}, stateSeal(a.state)),
        h("td", {}, `${fmtDate(a.window.notBefore)} → ${fmtDate(a.window.notAfter)}`), h("td", {}, `v${a.version}`))))))
      : empty("Aún no hay evaluaciones", ctx.can("createAssessment") ? "Crea la primera para definir un alcance autorizado." : "Un autorizador debe crear la primera.",
          ctx.can("createAssessment") ? h("a", { class: "btn primary", href: "#/evaluaciones/nueva" }, "Nueva evaluación") : null)));
  return { crumb: "Evaluaciones", title: "Evaluaciones", node };
}

export async function newAssessmentView(ctx) {
  if (!ctx.can("createAssessment")) return { crumb: "Evaluaciones", node: h("p", { class: "err" }, "Solo un autorizador puede crear evaluaciones.") };
  const form = await assessmentForm(ctx, { submitText: "Crear evaluación", onSave: async (body) => {
    const r = await api("POST", "/api/assessments", body); toast("Evaluación creada como borrador."); ctx.go(`#/evaluaciones/${r.id}`);
  } });
  return { crumb: "Evaluaciones › Nueva", title: "Nueva evaluación", node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Nueva evaluación"), h("p", {}, "Se crea como borrador. Después tú avanzas el ciclo: validar alcance, planificar y aprobar."))), form) };
}

/* ---------- Formulario (crear y nueva versión) ---------- */
const LABELS = { name: "Nombre", authorizer: "Entidad autorizadora", allowedModes: "Modos", scope: "Alcance", exclusions: "Exclusiones", window: "Ventana", allowedModules: "Módulos", testAccounts: "Cuentas de prueba", authorizationDocRef: "Documento de autorización" };
const FIELD = { organization: "organización", name: "nombre", email: "correo", phone: "teléfono", emergencyContact: "contacto de emergencia", value: "valor", reason: "motivo", notBefore: "inicio", notAfter: "fin", maxRequestsPerSecond: "peticiones por segundo", maxConcurrency: "paralelismo", label: "etiqueta", secretRef: "referencia" };
function es(msg) {
  if (/^Required$/i.test(msg)) return "falta este dato";
  if (/Invalid ip/i.test(msg)) return "no es una IP válida";
  if (/Invalid email/i.test(msg)) return "no es un correo válido";
  if (/Invalid url/i.test(msg)) return "no es una URL válida";
  if (/Invalid datetime/i.test(msg)) return "fecha no válida";
  let m = /at least (\d+) character/.exec(msg); if (m) return `mínimo ${m[1]} caracteres`;
  if (/at least 1 element/.test(msg)) return "elige o añade al menos uno";
  if (/^Invalid/i.test(msg)) return "formato no válido";
  return msg;
}
function issueText(i) {
  const parts = i.path.split("."); const out = [];
  for (const p of parts) out.push(/^\d+$/.test(p) ? `n.º ${Number(p) + 1}` : LABELS[p] ?? FIELD[p] ?? p);
  return `${out.join(", ")}: ${es(i.message)}`;
}

const toLocal = (iso) => { const d = new Date(iso); const p = (n) => String(n).padStart(2, "0"); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; };
let uid = 0;
const field = (label, ctl, hint) => { const id = `fld${++uid}`; ctl.id = id; return h("div", { class: "field" }, h("label", { for: id }, label), ctl, hint ? h("span", { class: "hint" }, hint) : null); };
const text = (name, value = "", o = {}) => h("input", { type: o.type ?? "text", name, value, required: o.required, placeholder: o.placeholder, autocomplete: "off" });
const sel = (name, opts, value) => h("select", { name }, opts.map(([v, l]) => h("option", { value: v, selected: v === value }, l)));
const rm = (row) => h("button", { type: "button", class: "btn small", "aria-label": "Quitar fila", onclick: () => row.remove() }, "Quitar");

export async function assessmentForm(ctx, { initial, submitText, onSave }) {
  const mods = await getModules();
  const i = initial ?? {};
  const now = new Date(); const week = new Date(now.getTime() + 7 * 864e5);
  const W = i.window ?? { notBefore: now.toISOString(), notAfter: week.toISOString(), maxRequestsPerSecond: 5, maxConcurrency: 2 };
  const A = i.authorizer ?? {};

  /* alcance */
  const scopeBox = h("div", {});
  const scopeRow = (t = { type: "ip", value: "" }) => {
    const extra = h("div", {});
    const type = sel("type", Object.entries(TARGET_TYPE), t.type);
    const value = text("value", t.value ?? "", { placeholder: "Valor", required: true });
    const paint = () => {
      extra.replaceChildren();
      if (type.value === "domain") extra.append(h("label", { class: "hint" }, h("input", { type: "checkbox", name: "includeSubdomains", checked: !!t.includeSubdomains }), " Incluir subdominios"));
      if (type.value === "url") extra.append(h("input", { type: "text", name: "pathPrefix", value: t.pathPrefix ?? "", placeholder: "Prefijo de ruta (opcional), p. ej. /api" }));
    };
    type.addEventListener("change", paint); paint();
    const row = h("div", { class: "listrow", "data-kind": "scope" }, type, h("div", {}, value, extra)); row.append(rm(row)); return row;
  };
  (i.scope?.length ? i.scope : [undefined]).forEach((t) => scopeBox.append(scopeRow(t)));

  /* exclusiones */
  const exclBox = h("div", {});
  const exclRow = (e) => {
    const kind = e?.technique ? "technique" : e?.target?.type ?? "ip";
    const row = h("div", { class: "listrow excl", "data-kind": "excl" },
      sel("kind", [...Object.entries(TARGET_TYPE), ["technique", "Técnica o módulo"]], kind),
      text("value", e?.technique ?? e?.target?.value ?? "", { placeholder: "Activo o nombre del módulo", required: true }),
      text("reason", e?.reason ?? "", { placeholder: "Motivo", required: true })); row.append(rm(row)); return row;
  };
  (i.exclusions ?? []).forEach((e) => exclBox.append(exclRow(e)));

  /* cuentas de prueba */
  const accBox = h("div", {});
  const accRow = (a) => { const row = h("div", { class: "listrow two", "data-kind": "acc" }, text("label", a?.label ?? "", { placeholder: "Etiqueta, p. ej. usuario normal", required: true }), text("secretRef", a?.secretRef ?? "", { placeholder: "Nombre del secreto en tu gestor", required: true })); row.append(rm(row)); return row; };
  (i.testAccounts ?? []).forEach((a) => accBox.append(accRow(a)));

  const modeBox = h("div", { class: "checks" }, [["passive", "Pasivo", "Analiza datos que tú aportas. No usa la red."], ["lab", "Laboratorio", "Solo localhost y la red Docker del laboratorio."], ["active", "Activo controlado", "Contra sistemas reales; cada plan exige tu aprobación."]]
    .map(([v, l, d]) => h("label", {}, h("input", { type: "checkbox", name: "mode", value: v, checked: (i.allowedModes ?? ["passive", "lab"]).includes(v) }), h("span", {}, h("strong", {}, l), h("br"), h("span", { class: "hint" }, d)))));
  const modBox = h("div", { class: "checks" }, mods.map((m) => h("label", {}, h("input", { type: "checkbox", name: "module", value: m.id, checked: (i.allowedModules ?? ["config_audit"]).includes(m.id) }),
    h("span", {}, h("strong", {}, m.title), m.changesState ? h("span", { class: "hint" }, " · cambia estado") : null, h("br"), h("span", { class: "hint" }, m.description)))));

  const errBox = h("div", { role: "alert" });
  const btn = h("button", { type: "submit", class: "btn primary" }, submitText);
  const f = h("form", { novalidate: false, onsubmit: async (e) => {
    e.preventDefault(); errBox.replaceChildren(); btn.disabled = true;
    const fd = new FormData(f);
    const rows = (kind) => [...f.querySelectorAll(`[data-kind="${kind}"]`)];
    const val = (row, n) => row.querySelector(`[name="${n}"]`)?.value.trim();
    const scope = rows("scope").map((r) => { const t = { type: val(r, "type"), value: val(r, "value") }; if (t.type === "domain") t.includeSubdomains = !!r.querySelector('[name="includeSubdomains"]')?.checked; if (t.type === "url" && val(r, "pathPrefix")) t.pathPrefix = val(r, "pathPrefix"); return t; });
    const exclusions = rows("excl").map((r) => { const k = val(r, "kind"); return k === "technique" ? { technique: val(r, "value"), reason: val(r, "reason") } : { target: { type: k, value: val(r, "value") }, reason: val(r, "reason") }; });
    const hours = fd.get("hFrom") && fd.get("hTo") ? { from: fd.get("hFrom"), to: fd.get("hTo"), tz: String(fd.get("tz") || "America/Bogota") } : undefined;
    const body = {
      name: String(fd.get("name")).trim(), authorizationDocRef: String(fd.get("doc")).trim() || undefined,
      authorizer: { organization: String(fd.get("org")).trim(), name: String(fd.get("aname")).trim(), email: String(fd.get("email")).trim(), phone: String(fd.get("phone")).trim() || undefined, emergencyContact: String(fd.get("emergency")).trim() },
      allowedModes: fd.getAll("mode"), allowedModules: fd.getAll("module"), scope, exclusions,
      testAccounts: rows("acc").map((r) => ({ label: val(r, "label"), secretRef: val(r, "secretRef") })),
      window: { notBefore: fd.get("from") ? new Date(String(fd.get("from"))).toISOString() : "", notAfter: fd.get("to") ? new Date(String(fd.get("to"))).toISOString() : "", maxRequestsPerSecond: Number(fd.get("rps")), maxConcurrency: Number(fd.get("conc")), ...(fd.get("total") ? { maxTotalRequests: Number(fd.get("total")) } : {}), ...(hours ? { allowedHours: hours } : {}) },
    };
    try { await onSave(body); }
    catch (ex) {
      const issues = ex instanceof ApiError ? ex.issues : [];
      errBox.replaceChildren(h("p", { class: "err" }, ex.message), issues.length ? h("ul", { class: "errlist" }, issues.map((x) => h("li", {}, issueText(x)))) : null);
      errBox.scrollIntoView({ block: "center" });
    } finally { btn.disabled = false; }
  } },
    h("fieldset", {}, h("legend", {}, "La evaluación"),
      field("Nombre", text("name", i.name ?? "", { required: true }), "Cómo la reconocerá tu equipo."),
      field("Documento de autorización (opcional)", text("doc", i.authorizationDocRef ?? ""), "Referencia al contrato o carta firmada. No pegues el documento.")),
    h("fieldset", {}, h("legend", {}, "Quién autoriza"), h("div", { class: "cols" },
      field("Organización", text("org", A.organization ?? "", { required: true })), field("Nombre del responsable", text("aname", A.name ?? "", { required: true })),
      field("Correo", text("email", A.email ?? "", { type: "email", required: true })), field("Teléfono (opcional)", text("phone", A.phone ?? "")),
      field("Contacto de emergencia", text("emergency", A.emergencyContact ?? "", { required: true }), "A quién avisar si algo sale mal."))),
    h("fieldset", {}, h("legend", {}, "Modos permitidos"), h("div", { class: "field" }, modeBox)),
    h("fieldset", {}, h("legend", {}, "Alcance"), h("p", { class: "hint field" }, "Solo lo que escribas aquí podrá probarse. Los rangos CIDR deben ser /16 o más pequeños (IPv6, /48)."), scopeBox,
      h("button", { type: "button", class: "btn small", onclick: () => scopeBox.append(scopeRow()) }, "Añadir objetivo"), h("div", { class: "field" })),
    h("fieldset", {}, h("legend", {}, "Exclusiones"), h("p", { class: "hint field" }, "Activos o técnicas que nunca se tocan, aunque estén dentro del alcance."), exclBox,
      h("button", { type: "button", class: "btn small", onclick: () => exclBox.append(exclRow()) }, "Añadir exclusión"), h("div", { class: "field" })),
    h("fieldset", {}, h("legend", {}, "Ventana y límites"), h("div", { class: "cols" },
      field("Inicio", h("input", { type: "datetime-local", name: "from", value: toLocal(W.notBefore), required: true })), field("Fin", h("input", { type: "datetime-local", name: "to", value: toLocal(W.notAfter), required: true })),
      field("Peticiones por segundo", text("rps", W.maxRequestsPerSecond, { type: "number", required: true })), field("Operaciones en paralelo", text("conc", W.maxConcurrency, { type: "number", required: true })),
      field("Tope de peticiones (opcional)", text("total", W.maxTotalRequests ?? "", { type: "number" })),
      field("Horario permitido desde (opcional)", text("hFrom", W.allowedHours?.from ?? "", { placeholder: "09:00" })), field("hasta", text("hTo", W.allowedHours?.to ?? "", { placeholder: "17:00" })),
      field("Zona horaria del horario", text("tz", W.allowedHours?.tz ?? "America/Bogota")))),
    h("fieldset", {}, h("legend", {}, "Módulos permitidos"), h("div", { class: "field" }, modBox)),
    h("fieldset", {}, h("legend", {}, "Cuentas de prueba (opcional)"), h("p", { class: "hint field" }, "Escribe solo el nombre con el que guardas cada credencial en tu gestor de secretos. Nunca la contraseña."), accBox,
      h("button", { type: "button", class: "btn small", onclick: () => accBox.append(accRow()) }, "Añadir cuenta"), h("div", { class: "field" })),
    errBox, h("div", { class: "row" }, btn, h("a", { class: "btn", href: i.id ? `#/evaluaciones/${i.id}` : "#/evaluaciones" }, "Cancelar")));
  return f;
}
