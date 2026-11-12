import { h, api, setCsrf, ROLE, formDialog, confirmDialog, toast, seal, fmtDate, errorBox, ApiError } from "./lib.js";
import { dashboardView } from "./views/dashboard.js";
import { assessmentsView, newAssessmentView } from "./views/assessments.js";
import { assessmentView } from "./views/assessment.js";
import { auditView } from "./views/audit.js";
import { usersView } from "./views/users.js";
import { accountView } from "./views/account.js";

const root = document.getElementById("root");
const ctx = { me: null, kill: null };
const PERM = { kill: ["authorizer", "operator"], release: ["authorizer"], audit: ["authorizer", "operator", "auditor"], users: ["authorizer"], createAssessment: ["authorizer"], advance: ["authorizer"], decidePlan: ["authorizer", "operator"], findings: ["authorizer", "operator", "analyst"], finalize: ["authorizer", "operator", "analyst"] };
ctx.can = (a) => !!ctx.me && PERM[a].includes(ctx.me.user.role);
ctx.go = (hash) => { if (location.hash === hash) renderRoute(); else location.hash = hash; };
ctx.refreshKill = async () => { const r = await api("GET", "/api/me"); ctx.kill = r.killSwitch; paintKill(); };

/* ---------- Inicio de sesión ---------- */
function loginScreen(notice) {
  document.title = "Entrar · Ethical Security Copilot";
  const err = h("p", { class: "err", role: "alert", hidden: !notice }, notice ?? "");
  const user = h("input", { id: "u", type: "text", autocomplete: "username", required: true, autocapitalize: "none", spellcheck: "false" });
  const pass = h("input", { id: "p", type: "password", autocomplete: "current-password", required: true });
  const btn = h("button", { type: "submit", class: "btn primary" }, "Entrar");
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault(); btn.disabled = true; err.hidden = true;
    try {
      const r = await api("POST", "/api/login", { username: user.value, password: pass.value });
      setCsrf(r.csrf); ctx.me = r; ctx.kill = r.killSwitch; shell();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; pass.value = ""; pass.focus(); }
    finally { btn.disabled = false; }
  } },
    h("div", { class: "field" }, h("label", { for: "u" }, "Usuario"), user),
    h("div", { class: "field" }, h("label", { for: "p" }, "Contraseña"), pass), err, btn);
  root.replaceChildren(h("main", { class: "login" },
    h("section", { class: "lead" },
      h("div", {}, h("p", { class: "brand" }, "Ethical Security Copilot"), h("h1", {}, "Pruebas de seguridad, solo con autorización."),
        h("p", {}, "Aquí se autorizan las evaluaciones, se aprueban sus planes y se revisa todo lo que ocurrió.")),
      h("ul", { class: "rules" },
        h("li", {}, "El alcance se comprueba en el servidor antes de cada operación."),
        h("li", {}, "Aprobar un plan es siempre una decisión humana."),
        h("li", {}, "Cada acción queda en un registro encadenado por hash."))),
    h("section", { class: "formside" }, h("h2", {}, "Entrar a la consola"), form)));
  user.focus();
}

/* ---------- Estructura general ---------- */
const NAV = [["#/", "Panel", () => true], ["#/evaluaciones", "Evaluaciones", () => true], ["#/auditoria", "Auditoría", () => ctx.can("audit")], ["#/usuarios", "Usuarios", () => ctx.can("users")], ["#/cuenta", "Mi cuenta", () => true]];
let crumb, killSlot, killBar, content, navEl;

function shell() {
  const u = ctx.me.user;
  navEl = h("nav", { class: "nav", "aria-label": "Principal" }, NAV.filter(([, , ok]) => ok()).map(([href, label]) => h("a", { href }, label)));
  crumb = h("div", { class: "crumb" });
  killSlot = h("div", { class: "kill" });
  killBar = h("div", { hidden: true });
  content = h("main", { class: "content", id: "main", tabindex: "-1" });
  root.replaceChildren(h("div", { class: "app" },
    h("aside", { class: "rail" },
      h("div", { class: "brand" }, "Ethical Security Copilot", h("small", {}, "Autorizar, aprobar, auditar")), navEl,
      h("div", { class: "rail-foot" }, h("strong", {}, u.displayName || u.username), h("span", {}, ROLE[u.role]),
        h("button", { class: "btn ghost", onclick: logout }, "Cerrar sesión"))),
    h("div", { class: "main" }, h("header", { class: "topbar" }, crumb, killSlot), killBar, content)));
  paintKill();
  if (!location.hash) location.hash = "#/"; else renderRoute();
}

function paintKill() {
  if (!killSlot) return;
  const k = ctx.kill; if (!k) return;
  killSlot.replaceChildren(k.active ? seal("Kill switch activo", "bad") : seal("Kill switch inactivo", "ok"),
    !k.active && ctx.can("kill") ? h("button", { class: "btn danger small", onclick: stopAll }, "Detener todo") : null);
  killBar.hidden = !k.active; killBar.className = k.active ? "killbar" : "";
  killBar.replaceChildren(...(k.active ? [
    h("strong", {}, "Todo está detenido."), h("span", {}, `Motivo: ${k.reason ?? "sin motivo registrado"}.`),
    ctx.can("release") ? h("button", { class: "btn small", onclick: release }, "Liberar kill switch") : h("span", {}, "Solo un autorizador puede liberarlo."),
  ] : []));
}

async function stopAll() {
  const v = await formDialog({ title: "Detener todo", danger: true, submit: "Detener todo",
    intro: "Aborta los escaneos en curso, bloquea cualquier ejecución nueva y detiene las evaluaciones. Solo un autorizador puede volver a habilitar el sistema.",
    fields: [{ name: "reason", label: "Motivo", required: true, hint: "Queda en el registro de auditoría." }] });
  if (!v) return;
  try { const r = await api("POST", "/api/killswitch", { reason: v.reason }); toast(`Todo detenido. Ejecuciones abortadas: ${r.abortedRuns}.`); await ctx.refreshKill(); renderRoute(); }
  catch (e) { toast(e.message, true); }
}
async function release() {
  const ok = await confirmDialog({ title: "Liberar el kill switch", confirm: "Liberar",
    body: h("p", { class: "muted" }, "Se permitirán nuevas ejecuciones. Las evaluaciones que quedaron detenidas siguen detenidas: hay que crear una nueva versión de su autorización.") });
  if (!ok) return;
  try { await api("POST", "/api/killswitch/release"); toast("Kill switch liberado."); await ctx.refreshKill(); renderRoute(); } catch (e) { toast(e.message, true); }
}
async function logout() { try { await api("POST", "/api/logout"); } catch { /* da igual */ } ctx.me = null; setCsrf(""); location.hash = ""; loginScreen(); }

/* ---------- Rutas ---------- */
const UUID = "([0-9a-f-]{36})";
const ROUTES = [
  [/^#\/?$/, () => dashboardView(ctx)],
  [/^#\/evaluaciones$/, () => assessmentsView(ctx)],
  [/^#\/evaluaciones\/nueva$/, () => newAssessmentView(ctx)],
  [new RegExp(`^#/evaluaciones/${UUID}(?:/(\\w+))?$`), (m) => assessmentView(ctx, m[1], m[2])],
  [/^#\/auditoria$/, () => auditView(ctx)],
  [/^#\/usuarios$/, () => usersView(ctx)],
  [/^#\/cuenta$/, () => accountView(ctx)],
];
let token = 0;
async function renderRoute() {
  if (!ctx.me || !content) return;
  const my = ++token;
  const hash = location.hash || "#/";
  navEl.querySelectorAll("a").forEach((a) => { const on = a.getAttribute("href") === "#/" ? hash === "#/" : hash.startsWith(a.getAttribute("href")); on ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"); });
  if (ctx.me.user.mustChange && hash !== "#/cuenta") { location.hash = "#/cuenta"; return; }
  const hit = ROUTES.map(([re, f]) => [re.exec(hash), f]).find(([m]) => m);
  content.replaceChildren(h("p", { class: "muted" }, "Cargando…"));
  try {
    if (!hit) { crumb.textContent = "No encontrado"; content.replaceChildren(h("p", {}, "Esa página no existe. ", h("a", { href: "#/" }, "Volver al panel"))); return; }
    try { await ctx.refreshKill(); } catch { /* se mantiene el último estado */ }
    const view = await hit[1](hit[0]);
    if (my !== token) return;
    crumb.textContent = view.crumb ?? ""; document.title = `${view.title ?? view.crumb ?? "Consola"} · Ethical Security Copilot`;
    content.replaceChildren(view.node);
    content.focus({ preventScroll: true }); window.scrollTo(0, 0);
  } catch (e) { if (my === token && !(e instanceof ApiError && e.status === 401)) content.replaceChildren(errorBox(e)); }
}

window.addEventListener("hashchange", renderRoute);
window.addEventListener("esc:unauthenticated", () => { if (ctx.me) { ctx.me = null; setCsrf(""); loginScreen("Tu sesión terminó. Inicia sesión de nuevo."); } });

(async () => {
  try { const r = await api("GET", "/api/me"); setCsrf(r.csrf); ctx.me = r; ctx.kill = r.killSwitch; shell(); }
  catch { loginScreen(); }
})();
