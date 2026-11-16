import { h, api, panel, toast, fmtDate, errorBox } from "../lib.js";

const PROVIDERS = [
  ["anthropic", "Anthropic (Claude)"],
  ["openai", "Compatible con OpenAI (OpenAI, Azure OpenAI, u otro endpoint con el mismo protocolo)"],
  ["gemini", "Google Gemini"],
];
const DEFAULT_BASE = {
  anthropic: "https://api.anthropic.com/v1",
  openai: "https://api.openai.com/v1",
  gemini: "https://generativelanguage.googleapis.com/v1beta",
};

export async function aiConfigView(ctx) {
  let cfg;
  try { cfg = await api("GET", "/api/ai/config"); } catch (e) { return { crumb: "Configuración", node: errorBox(e) }; }

  const enabled = h("input", { type: "checkbox", checked: cfg.enabled });
  const provider = h("select", {}, PROVIDERS.map(([v, l]) => h("option", { value: v, selected: v === cfg.provider }, l)));
  const baseUrl = h("input", { type: "text", value: cfg.baseUrl ?? "", placeholder: DEFAULT_BASE[cfg.provider] ?? "" });
  const baseUrlField = h("div", { class: "field" }, h("label", {}, "URL base (opcional)"), baseUrl,
    h("span", { class: "hint" }, "Déjala en blanco para usar la URL oficial del proveedor. Solo cámbiala si usas un proxy o un endpoint propio compatible."));
  const modelSelect = h("select", {}, cfg.model ? [h("option", { value: cfg.model, selected: true }, cfg.model)] : []);
  const modelManual = h("input", { type: "text", value: cfg.model ?? "", hidden: true, placeholder: "id del modelo" });
  const modelMsg = h("span", { class: "hint" }, "Pulsa \"Cargar modelos\" con tu llave puesta abajo para elegir de una lista real.");
  const apiKey = h("input", { type: "password", autocomplete: "off", placeholder: cfg.hasKey ? `Guardada (termina en …${cfg.keyLast4})` : "Pega aquí tu llave de API" });
  const status = h("p", { class: "muted" }, cfg.hasKey ? `Llave guardada, termina en …${cfg.keyLast4}. ` : "Sin llave guardada todavía. ",
    cfg.updatedAt ? `Última actualización: ${fmtDate(cfg.updatedAt)} por ${cfg.updatedBy}.` : "");
  const err = h("p", { class: "err", hidden: true, role: "alert" });
  const testOut = h("p", {});

  let manualMode = false;
  const toggleManual = (on) => {
    manualMode = on;
    modelSelect.hidden = on; modelManual.hidden = !on;
    manualToggle.textContent = on ? "Elegir de una lista" : "Escribir el id a mano";
  };
  const manualToggle = h("button", { type: "button", class: "btn small", onclick: () => toggleManual(!manualMode) }, "Escribir el id a mano");
  const currentModel = () => (manualMode ? modelManual.value.trim() : modelSelect.value);

  const onProviderChange = () => { baseUrl.placeholder = DEFAULT_BASE[provider.value] ?? ""; };
  provider.addEventListener("change", onProviderChange);

  const loadModels = async () => {
    modelMsg.textContent = "Cargando modelos…"; modelMsg.className = "hint";
    try {
      const key = apiKey.value.trim();
      const r = await api("POST", "/api/ai/config/models", { provider: provider.value, apiKey: key || undefined, baseUrl: baseUrl.value.trim() || undefined });
      const cur = currentModel();
      modelSelect.replaceChildren(...r.models.map((m) => h("option", { value: m.id, selected: m.id === cur }, m.label === m.id ? m.id : `${m.label} (${m.id})`)));
      if (!r.models.some((m) => m.id === cur) && cur) modelSelect.prepend(h("option", { value: cur, selected: true }, cur));
      toggleManual(false);
      modelMsg.textContent = `${r.models.length} modelo(s) disponible(s).`; modelMsg.className = "hint";
    } catch (e) {
      const msg = e.message.replace(/\.?$/, "");
      modelMsg.textContent = `No se pudieron cargar: ${msg}. Puedes escribir el id a mano.`; modelMsg.className = "err";
      toggleManual(true);
    }
  };

  const fieldsBox = h("div", { class: "stack" },
    h("div", { class: "field" }, h("label", {}, "Proveedor"), provider, h("span", { class: "hint" }, "No tiene que ser Claude: cualquier API compatible con OpenAI o con Gemini funciona igual.")),
    baseUrlField,
    h("div", { class: "field" }, h("label", {}, "Llave de API"), apiKey, h("span", { class: "hint" }, "Se cifra antes de guardarse. Déjala en blanco al guardar para conservar la actual; sí hace falta para cargar los modelos o probar la conexión.")),
    h("div", { class: "field" }, h("label", {}, "Modelo"),
      h("div", { class: "row" }, modelSelect, modelManual, h("button", { type: "button", class: "btn small", onclick: loadModels }, "Cargar modelos"), manualToggle),
      modelMsg));
  const toggleFields = () => { fieldsBox.hidden = !enabled.checked; };
  enabled.addEventListener("change", toggleFields);
  toggleFields();

  const save = async () => {
    err.hidden = true;
    try {
      const body = { enabled: enabled.checked, provider: provider.value, model: currentModel(), baseUrl: baseUrl.value.trim() || undefined, apiKey: apiKey.value.trim() || undefined };
      cfg = await api("POST", "/api/ai/config", body);
      apiKey.value = ""; apiKey.placeholder = cfg.hasKey ? `Guardada (termina en …${cfg.keyLast4})` : "Pega aquí tu llave de API";
      status.textContent = cfg.hasKey ? `Llave guardada, termina en …${cfg.keyLast4}. Última actualización: ${fmtDate(cfg.updatedAt)} por ${cfg.updatedBy}.` : "Sin llave guardada todavía.";
      toast("Configuración guardada.");
    } catch (e) { err.textContent = e.issues?.length ? e.issues.map((i) => i.message).join(" ") : e.message; err.hidden = false; }
  };
  const test = async () => {
    testOut.textContent = "Probando…"; testOut.className = "muted";
    try {
      const r = await api("POST", "/api/ai/config/test", { provider: provider.value, apiKey: apiKey.value.trim() || undefined, baseUrl: baseUrl.value.trim() || undefined });
      testOut.textContent = r.ok ? "✓ Conexión correcta." : `✗ ${r.message}`;
      testOut.className = r.ok ? "" : "err";
    } catch (e) { testOut.textContent = `✗ ${e.message}`; testOut.className = "err"; }
  };

  return { crumb: "Configuración", title: "Configuración", node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Integración de IA"),
      h("p", {}, "Conecta un modelo de IA por API, además (o en vez) de conectarlo por MCP. No tiene que ser Anthropic: también funciona con cualquier API compatible con OpenAI o con Gemini. Cuando actúa aquí dentro, tiene exactamente los mismos permisos que ya tiene el rol 'agent': nunca abre ni cierra un incidente, nunca toca ninguna red por sí solo."))),
    panel("Conexión del módulo de IA", h("div", { class: "body stack" },
      h("div", { class: "field" }, h("label", {}, enabled, " Activar el módulo de IA")),
      fieldsBox,
      status, err,
      h("div", { class: "row" }, h("button", { class: "btn primary", onclick: save }, "Guardar"), h("button", { class: "btn", type: "button", onclick: test }, "Probar conexión")),
      testOut))) };
}
