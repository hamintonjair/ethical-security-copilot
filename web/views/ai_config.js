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

const SEVERITIES = [["info", "Info o más (todo)"], ["low", "Baja o más"], ["medium", "Media o más"], ["high", "Alta o crítica"], ["critical", "Solo crítica"]];

function alertsPanel(ctx, acfg) {
  const enabled = h("input", { type: "checkbox", checked: acfg.enabled });
  const webhookUrl = h("input", { type: "text", value: acfg.webhookUrl ?? "", placeholder: "https://tu-servidor.ejemplo/webhooks/esc" });
  const minSeverity = h("select", {}, SEVERITIES.map(([v, l]) => h("option", { value: v, selected: v === acfg.minSeverity }, l)));
  const notifyIncident = h("input", { type: "checkbox", checked: acfg.notifyIncidentOpen });
  const secret = h("input", { type: "password", autocomplete: "off", placeholder: acfg.hasSecret ? `Guardado (termina en …${acfg.secretLast4})` : "Opcional: para firmar el cuerpo (HMAC-SHA256)" });
  const clearSecret = h("input", { type: "checkbox" });
  const clearSecretField = h("div", { class: "field", hidden: !acfg.hasSecret }, h("label", {}, clearSecret, " Quitar el secreto de firma guardado"));
  const status = h("p", { class: "muted" }, acfg.updatedAt ? `Última actualización: ${fmtDate(acfg.updatedAt)} por ${acfg.updatedBy}.` : "Aún no configuradas.");
  const err = h("p", { class: "err", hidden: true, role: "alert" });
  const testOut = h("p", {});

  const fieldsBox = h("div", { class: "stack" },
    h("div", { class: "field" }, h("label", {}, "URL del webhook"), webhookUrl, h("span", { class: "hint" }, "Se envía un POST en JSON cuando ocurra un evento que cumpla el umbral. Es solo un aviso: nada se bloquea ni se ejecuta automáticamente desde aquí.")),
    h("div", { class: "field" }, h("label", {}, "Avisar desde"), minSeverity, h("span", { class: "hint" }, "Umbral de severidad para los hallazgos registrados en evaluaciones.")),
    h("div", { class: "field" }, h("label", {}, notifyIncident, " Avisar también al abrir un incidente")),
    h("div", { class: "field" }, h("label", {}, "Secreto de firma (opcional)"), secret, h("span", { class: "hint" }, "Si lo defines, cada envío incluye la cabecera X-ESC-Signature (HMAC-SHA256 del cuerpo) para que tu endpoint verifique que viene de aquí.")),
    clearSecretField);
  const toggleFields = () => { fieldsBox.hidden = !enabled.checked; };
  enabled.addEventListener("change", toggleFields);
  toggleFields();

  const save = async () => {
    err.hidden = true;
    try {
      const body = { enabled: enabled.checked, webhookUrl: webhookUrl.value.trim() || undefined, minSeverity: minSeverity.value, notifyIncidentOpen: notifyIncident.checked, secret: secret.value.trim() || undefined, clearSecret: clearSecret.checked || undefined };
      acfg = await api("POST", "/api/alerts/config", body);
      secret.value = ""; clearSecret.checked = false;
      secret.placeholder = acfg.hasSecret ? `Guardado (termina en …${acfg.secretLast4})` : "Opcional: para firmar el cuerpo (HMAC-SHA256)";
      clearSecretField.hidden = !acfg.hasSecret;
      status.textContent = `Última actualización: ${fmtDate(acfg.updatedAt)} por ${acfg.updatedBy}.`;
      toast("Configuración de alertas guardada.");
    } catch (e) { err.textContent = e.issues?.length ? e.issues.map((i) => i.message).join(" ") : e.message; err.hidden = false; }
  };
  const test = async () => {
    testOut.textContent = "Enviando…"; testOut.className = "muted";
    try { await api("POST", "/api/alerts/test", {}); testOut.textContent = "✓ Enviada. Revisa el registro de auditoría o tu endpoint."; testOut.className = ""; }
    catch (e) { testOut.textContent = `✗ ${e.message}`; testOut.className = "err"; }
  };

  return panel("Alertas por webhook", h("div", { class: "body stack" },
    h("p", { class: "muted" }, "Avisa a un endpoint propio (o a un servicio como n8n, Slack-webhook o similar) cuando aparezca un hallazgo de severidad alta o se abra un incidente. Es solo una notificación: la plataforma nunca actúa sola a partir de ella."),
    h("div", { class: "field" }, h("label", {}, enabled, " Activar las alertas")),
    fieldsBox,
    status, err,
    h("div", { class: "row" }, h("button", { class: "btn primary", onclick: save }, "Guardar"), h("button", { class: "btn", type: "button", onclick: test }, "Enviar alerta de prueba")),
    testOut));
}

export async function aiConfigView(ctx) {
  let cfg, acfg;
  try { [cfg, acfg] = await Promise.all([api("GET", "/api/ai/config"), api("GET", "/api/alerts/config")]); } catch (e) { return { crumb: "Configuración", node: errorBox(e) }; }

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
      const r = await api("POST", "/api/ai/config/test", { provider: provider.value, apiKey: apiKey.value.trim() || undefined, baseUrl: baseUrl.value.trim() || undefined, model: currentModel() || undefined });
      testOut.textContent = r.ok ? "✓ Conexión correcta." : `✗ ${r.message}`;
      testOut.className = r.ok ? "" : "err";
    } catch (e) { testOut.textContent = `✗ ${e.message}`; testOut.className = "err"; }
  };

  // Al entrar (o volver) a esta vista, si ya hay una llave guardada se comprueba sola con esa llave —
  // así se ve de una vez si la conexión sigue viva, sin tener que pegar la llave de nuevo y pulsar
  // los botones a mano cada vez que se sale y se vuelve.
  if (cfg.enabled && cfg.hasKey) { loadModels(); test(); }

  return { crumb: "Configuración", title: "Configuración", node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Integración de IA"),
      h("p", {}, "Conecta un modelo de IA por API, además (o en vez) de conectarlo por MCP. No tiene que ser Anthropic: también funciona con cualquier API compatible con OpenAI o con Gemini. Cuando actúa aquí dentro, tiene exactamente los mismos permisos que ya tiene el rol 'agent': nunca abre ni cierra un incidente, nunca toca ninguna red por sí solo."))),
    panel("Conexión del módulo de IA", h("div", { class: "body stack" },
      h("div", { class: "field" }, h("label", {}, enabled, " Activar el módulo de IA")),
      fieldsBox,
      status, err,
      h("div", { class: "row" }, h("button", { class: "btn primary", onclick: save }, "Guardar"), h("button", { class: "btn", type: "button", onclick: test }, "Probar conexión")),
      testOut)),
    alertsPanel(ctx, acfg)) };
}
