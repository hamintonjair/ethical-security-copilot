import { h, api, panel, toast, fmtDate, errorBox } from "../lib.js";

export async function aiConfigView(ctx) {
  let cfg;
  try { cfg = await api("GET", "/api/ai/config"); } catch (e) { return { crumb: "Configuración", node: errorBox(e) }; }

  const enabled = h("input", { type: "checkbox", checked: cfg.enabled });
  const model = h("input", { type: "text", value: cfg.model, required: true });
  const apiKey = h("input", { type: "password", autocomplete: "off", placeholder: cfg.hasKey ? `Guardada (termina en …${cfg.keyLast4})` : "sk-ant-…" });
  const status = h("p", { class: "muted" }, cfg.hasKey ? `Llave guardada, termina en …${cfg.keyLast4}. ` : "Sin llave guardada todavía. ",
    cfg.updatedAt ? `Última actualización: ${fmtDate(cfg.updatedAt)} por ${cfg.updatedBy}.` : "");
  const err = h("p", { class: "err", hidden: true, role: "alert" });
  const testOut = h("p", {});

  const save = async () => {
    err.hidden = true;
    try {
      cfg = await api("POST", "/api/ai/config", { enabled: enabled.checked, model: model.value.trim(), apiKey: apiKey.value.trim() || undefined });
      apiKey.value = ""; apiKey.placeholder = cfg.hasKey ? `Guardada (termina en …${cfg.keyLast4})` : "sk-ant-…";
      status.textContent = cfg.hasKey ? `Llave guardada, termina en …${cfg.keyLast4}. Última actualización: ${fmtDate(cfg.updatedAt)} por ${cfg.updatedBy}.` : "Sin llave guardada todavía.";
      toast("Configuración guardada.");
    } catch (e) { err.textContent = e.issues?.length ? e.issues.map((i) => i.message).join(" ") : e.message; err.hidden = false; }
  };
  const test = async () => {
    testOut.textContent = "Probando…"; testOut.className = "muted";
    try {
      const r = await api("POST", "/api/ai/config/test", { apiKey: apiKey.value.trim() || undefined, model: model.value.trim() });
      testOut.textContent = r.ok ? "✓ Conexión correcta." : `✗ ${r.message}`;
      testOut.className = r.ok ? "" : "err";
    } catch (e) { testOut.textContent = `✗ ${e.message}`; testOut.className = "err"; }
  };

  return { crumb: "Configuración", title: "Configuración", node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Integración de IA"),
      h("p", {}, "Conecta un modelo de IA por API, además (o en vez) de conectarlo por MCP. Cuando actúa aquí dentro, tiene exactamente los mismos permisos que ya tiene el rol 'agent': nunca abre ni cierra un incidente, nunca toca ninguna red por sí solo."))),
    panel("Llave de API de Anthropic", h("div", { class: "body stack" },
      h("div", { class: "field" }, h("label", {}, enabled, " Activar el módulo de IA")),
      h("div", { class: "field" }, h("label", {}, "Modelo"), model, h("span", { class: "hint" }, "Identificador del modelo de Anthropic, p. ej. claude-sonnet-5-5.")),
      h("div", { class: "field" }, h("label", {}, "Llave de API"), apiKey, h("span", { class: "hint" }, "Se cifra antes de guardarse. Déjala en blanco para conservar la actual.")),
      status, err,
      h("div", { class: "row" }, h("button", { class: "btn primary", onclick: save }, "Guardar"), h("button", { class: "btn", type: "button", onclick: test }, "Probar conexión")),
      testOut))) };
}
