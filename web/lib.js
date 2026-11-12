// Utilidades de la interfaz. Todo el contenido dinámico entra como texto (nunca como HTML).

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked" || k === "disabled" || k === "selected" || k === "required" || k === "hidden") el[k] = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  const add = (c) => {
    if (c == null || c === false) return;
    if (Array.isArray(c)) return c.forEach(add);
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  };
  kids.forEach(add);
  return el;
}

/* ---------- API ---------- */
let csrf = "";
export const setCsrf = (t) => { csrf = t; };
export class ApiError extends Error {
  constructor(status, body) { super(body?.message || "Error inesperado."); this.status = status; this.code = body?.error; this.issues = body?.issues ?? []; }
}
export async function api(method, path, body) {
  let res;
  try {
    res = await fetch(path, { method, credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch { throw new ApiError(0, { message: "No hay conexión con el servidor. Si estaba en reposo, espera un minuto y reintenta." }); }
  let data = null;
  try { data = await res.json(); } catch { /* sin cuerpo */ }
  if (!res.ok) {
    if (res.status === 401 && path !== "/api/login") window.dispatchEvent(new CustomEvent("esc:unauthenticated"));
    throw new ApiError(res.status, data);
  }
  return data;
}

/* ---------- Formato ---------- */
export const fmtDate = (iso) => iso ? new Date(iso).toLocaleString("es-CO", { dateStyle: "medium", timeStyle: "short" }) : "—";
export const shortHash = (s) => (s ? s.slice(0, 8) : "");
export const ROLE = { authorizer: "Autorizador", operator: "Operador", analyst: "Analista", auditor: "Auditor" };
export const STATE = { draft: "Borrador", scope_validated: "Alcance validado", planned: "Planificada", approved: "Aprobada", executing: "En ejecución", verifying: "Verificando", triage: "Triaje", reported: "Informada", halted: "Detenida", closed: "Cerrada" };
export const STATE_TONE = { draft: "mute", approved: "ok", executing: "ok", reported: "ok", halted: "bad", closed: "mute" };
export const MODE = { passive: "Pasivo", lab: "Laboratorio", active: "Activo" };
export const SEVERITY = { info: "Informativa", low: "Baja", medium: "Media", high: "Alta", critical: "Crítica" };
export const SEV_TONE = { info: "mute", low: "", medium: "warn", high: "bad", critical: "bad" };
export const TRIAGE = { unverified: "Sin verificar", confirmed: "Confirmado", false_positive: "Falso positivo", accepted_risk: "Riesgo aceptado" };
export const PLAN = { pending_approval: "Pendiente", approved: "Aprobado", rejected: "Rechazado", running: "Usado", done: "Terminado", stopped: "Detenido" };
export const PLAN_TONE = { pending_approval: "warn", approved: "ok", rejected: "bad", stopped: "bad", running: "mute", done: "mute" };
export const seal = (text, tone = "") => h("span", { class: `seal ${tone}` }, text);
export const stateSeal = (s) => seal(STATE[s] ?? s, STATE_TONE[s] ?? "");
export const targetText = (t) => (t.type === "url" ? t.value + (t.pathPrefix ? ` (${t.pathPrefix})` : "") : t.type === "domain" ? t.value + (t.includeSubdomains ? " + subdominios" : "") : t.value);
export const TARGET_TYPE = { ip: "IP", cidr: "Rango CIDR", domain: "Dominio", url: "URL", device: "Dispositivo" };

/* ---------- Avisos ---------- */
export function toast(message, bad = false) {
  const t = h("div", { class: `toast${bad ? " bad" : ""}` }, message);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), bad ? 7000 : 3800);
}

/* ---------- Diálogos ---------- */
export function openDialog(build) {
  return new Promise((resolve) => {
    const dlg = h("dialog", {});
    const close = (v) => { dlg.close(); dlg.remove(); resolve(v); };
    dlg.append(build(close));
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(null); });
    document.body.append(dlg);
    dlg.showModal();
  });
}

/** Formulario en diálogo. `fields`: [{name,label,type,hint,required,options,value,rows}]. Devuelve los valores o null. */
export function formDialog({ title, intro, fields = [], submit = "Aceptar", danger = false, extra }) {
  return openDialog((close) => {
    const err = h("p", { class: "err", hidden: true, role: "alert" });
    const inputs = fields.map((f) => {
      const id = "f_" + Math.random().toString(36).slice(2);
      const ctl = f.type === "select"
        ? h("select", { id, name: f.name }, f.options.map(([v, l]) => h("option", { value: v, selected: v === f.value }, l)))
        : f.type === "textarea" ? h("textarea", { id, name: f.name, rows: f.rows ?? 3, required: f.required }, f.value ?? "")
        : h("input", { id, name: f.name, type: f.type ?? "text", required: f.required, value: f.value ?? "", autocomplete: f.autocomplete ?? "off" });
      return { f, ctl, node: h("div", { class: "field" }, h("label", { for: id }, f.label), ctl, f.hint ? h("span", { class: "hint" }, f.hint) : null) };
    });
    const form = h("form", { method: "dialog" },
      h("h2", {}, title), intro ? h("p", { class: "muted" }, intro) : null, extra ?? null,
      h("div", { class: "stack" }, inputs.map((i) => i.node)), err,
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn", onclick: () => close(null) }, "Cancelar"),
        h("button", { type: "submit", class: `btn ${danger ? "solid-danger" : "primary"}` }, submit)));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const v = {};
      for (const { f, ctl } of inputs) {
        v[f.name] = ctl.value.trim?.() ?? ctl.value;
        if (f.required && !v[f.name]) { err.textContent = `Completa «${f.label}».`; err.hidden = false; ctl.focus(); return; }
      }
      close(v);
    });
    queueMicrotask(() => form.querySelector("input,select,textarea")?.focus());
    return form;
  });
}

export const confirmDialog = ({ title, body, confirm = "Confirmar", danger = false }) =>
  openDialog((close) => h("form", { method: "dialog", onsubmit: (e) => { e.preventDefault(); close(true); } },
    h("h2", {}, title), body, h("div", { class: "actions" },
      h("button", { type: "button", class: "btn", onclick: () => close(false) }, "Cancelar"),
      h("button", { type: "submit", class: `btn ${danger ? "solid-danger" : "primary"}` }, confirm)))).then((v) => v === true);

export const noticeDialog = ({ title, body, button = "Entendido" }) =>
  openDialog((close) => h("form", { method: "dialog", onsubmit: (e) => { e.preventDefault(); close(true); } },
    h("h2", {}, title), body, h("div", { class: "actions" }, h("button", { type: "submit", class: "btn primary" }, button))));

export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copiado."); } catch { toast("No se pudo copiar; selecciónalo a mano.", true); }
}

export function download(filename, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: filename });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const panel = (title, body, actions) => h("section", { class: "panel" },
  title ? h("header", {}, h("h3", {}, title), actions ?? null) : null, body);
export const empty = (title, text, action) => h("div", { class: "empty" }, h("strong", {}, title), text ? h("p", {}, text) : null, action ?? null);
export const errorBox = (e) => h("div", { class: "panel" }, empty("No se pudo cargar", e.message));
