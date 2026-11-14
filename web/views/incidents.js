import { h, api, panel, empty, seal, fmtDate, toast, copyText, download, formDialog, confirmDialog, errorBox, ROLE } from "../lib.js";

const STATUS = { open: "Abierto", contained: "Contenido", closed: "Cerrado" };
const STATUS_TONE = { open: "warn", contained: "ok", closed: "mute" };
const KIND = { log: "Log del servidor", email_headers: "Cabeceras de correo", other: "Otro" };
const SEV_TONE = { info: "mute", low: "", medium: "warn", high: "bad" };

export async function incidentsView(ctx) {
  const list = await api("GET", "/api/incidents");
  const open = async () => {
    const v = await formDialog({
      title: "Abrir incidente", submit: "Abrir caso",
      intro: "Para cuando a la organización la están atacando ahora mismo. No se toca ninguna red: solo se analiza lo que pegues aquí.",
      fields: [
        { name: "organization", label: "Organización", required: true },
        { name: "contactName", label: "Quién reporta", required: true },
        { name: "contactEmail", label: "Correo de contacto", type: "email", required: true },
        { name: "summary", label: "Qué está pasando", type: "textarea", required: true, hint: "Breve: qué se observó y cuándo empezó." },
        { name: "affectedAssets", label: "Activos afectados (opcional)", hint: "Separados por coma: sitio web, correo, VPN…" },
      ],
    });
    if (!v) return;
    const body = { ...v, affectedAssets: (v.affectedAssets ?? "").split(",").map((s) => s.trim()).filter(Boolean) };
    try { const r = await api("POST", "/api/incidents", body); toast("Caso abierto."); ctx.go(`#/incidentes/${r.id}`); } catch (e) { toast(e.message, true); }
  };
  const rows = list.map((i) => h("tr", {}, h("td", {}, h("a", { href: `#/incidentes/${i.id}` }, i.organization)), h("td", {}, i.summary.slice(0, 80)),
    h("td", {}, seal(STATUS[i.status] ?? i.status, STATUS_TONE[i.status])), h("td", {}, `${i.evidenceCount} evidencia(s)`), h("td", {}, fmtDate(i.createdAt))));
  return { crumb: "Incidentes", title: "Incidentes", node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Incidentes"), h("p", {}, "Respuesta a Incidentes / Defensa Activa: cerrar el paso a un ataque en curso, en tus propios sistemas.")),
      ctx.can("openIncident") ? h("button", { class: "btn primary", onclick: open }, "Abrir incidente") : null),
    panel(null, list.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Organización", "Resumen", "Estado", "Evidencia", "Abierto"].map((t) => h("th", {}, t)))), h("tbody", {}, rows)))
      : empty("Sin incidentes", "Cuando algo esté pasando, abre un caso para analizar la evidencia y generar la contención."))) };
}

export async function incidentView(ctx, id) {
  let d;
  try { d = await api("GET", `/api/incidents/${id}`); } catch (e) { return { crumb: "Incidentes", node: errorBox(e) }; }
  const reload = () => ctx.go(`#/incidentes/${id}`, true);
  const closed = d.status === "closed";

  const setStatus = async (status) => {
    if (status === "closed" && !(await confirmDialog({ title: "Cerrar el incidente", confirm: "Cerrar", danger: true, body: h("p", { class: "muted" }, "Ya no se podrá añadir más evidencia. Genera el informe antes si lo necesitas.") }))) return;
    try { await api("POST", `/api/incidents/${id}/status`, { status }); toast("Estado actualizado."); reload(); } catch (e) { toast(e.message, true); }
  };

  const evBox = h("div", {});
  const addEvidence = () => {
    let n = 0; const f = (label, ctl, hint) => { const id2 = `ie${++n}`; ctl.id = id2; return h("div", { class: "field" }, h("label", { for: id2 }, label), ctl, hint ? h("span", { class: "hint" }, hint) : null); };
    const err = h("p", { class: "err", hidden: true, role: "alert" });
    const form = h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.hidden = true; const g = (k) => form.elements[k].value;
      try { const r = await api("POST", `/api/incidents/${id}/evidence`, { kind: g("kind"), description: g("description"), content: g("content") }); toast(`Analizado: ${r.patterns.length} patrón(es), ${Object.values(r.iocs).flat().length} IOC(s).`); form.remove(); reload(); }
      catch (ex) { err.textContent = ex.issues?.length ? ex.issues.map((i) => i.message).join(" ") : ex.message; err.hidden = false; }
    } },
      f("Tipo", h("select", { name: "kind" }, h("option", { value: "log" }, "Log del servidor"), h("option", { value: "email_headers" }, "Cabeceras de correo"), h("option", { value: "other" }, "Otro texto"))),
      f("Descripción breve", h("input", { name: "description", required: true })),
      f("Contenido", h("textarea", { name: "content", rows: 10, required: true }), "Pega las líneas de log o las cabeceras completas del correo. Se redactan automáticamente credenciales y tokens antes de guardar."),
      err, h("div", { class: "row" }, h("button", { class: "btn primary", type: "submit" }, "Analizar y guardar"), h("button", { class: "btn", type: "button", onclick: () => form.remove() }, "Cancelar")));
    evBox.replaceChildren(panel("Nueva evidencia", h("div", { class: "body" }, form))); evBox.scrollIntoView({ block: "start" });
  };

  const allIps = [...new Set(d.evidence.flatMap((e) => e.iocs?.ips ?? []))], allDomains = [...new Set(d.evidence.flatMap((e) => e.iocs?.domains ?? []))];
  const containBox = h("div", {});
  const buildContain = async () => {
    try {
      const r = await api("POST", `/api/incidents/${id}/contain`, { ips: allIps, domains: allDomains, targets: "all" });
      const files = Object.entries(r.rules);
      containBox.replaceChildren(h("div", { class: "stack" }, h("p", { class: "muted" }, "Estas reglas no se aplican solas: cópialas y ejecútalas tú en tu propio firewall, nginx o Cloudflare."),
        ...files.map(([name, content]) => h("div", { class: "stack" }, h("div", { class: "row" }, h("strong", {}, name), h("button", { class: "btn small", onclick: () => copyText(content) }, "Copiar"), h("button", { class: "btn small", onclick: () => download(name, content, "text/plain") }, "Descargar")), h("pre", { class: "report" }, content)))));
    } catch (e) { toast(e.message, true); }
  };

  const aiBox = h("div", {});
  const askAi = async (question, textarea) => {
    aiBox.replaceChildren(h("p", { class: "muted" }, "Pensando…"));
    try {
      const r = await api("POST", `/api/incidents/${id}/ai-assist`, { question });
      const actionNodes = r.actions.map((a) => {
        if (a.result?.rules) return h("div", { class: "stack" }, h("strong", {}, "Plan de contención generado:"), ...Object.entries(a.result.rules).map(([name, content]) => h("div", { class: "stack" }, h("div", { class: "row" }, h("span", {}, name), h("button", { class: "btn small", onclick: () => copyText(content) }, "Copiar"), h("button", { class: "btn small", onclick: () => download(name, content, "text/plain") }, "Descargar")), h("pre", { class: "report" }, content))));
        if (a.result?.text) return h("div", { class: "stack" }, h("strong", {}, "Informe generado:"), h("pre", { class: "report" }, a.result.text));
        if (a.result?.facts) return h("div", { class: "stack" }, h("strong", {}, "Evidencia analizada:"), h("p", { class: "muted" }, `${a.result.patterns?.length ?? 0} patrón(es) detectado(s).`));
        return null;
      }).filter(Boolean);
      aiBox.replaceChildren(h("div", { class: "stack" }, h("p", {}, r.answer), ...actionNodes));
      if (textarea) textarea.value = "";
      if (r.actions.length) reload();
    } catch (e) { aiBox.replaceChildren(h("p", { class: "err" }, e.message)); }
  };
  const aiPanel = () => {
    if (!ctx.aiEnabled) return panel("Asistente de IA", h("div", { class: "body" }, h("p", { class: "muted" }, "El módulo de IA no está activado. Un autorizador puede activarlo en Configuración → Integración IA.")));
    const q = h("textarea", { rows: 3, placeholder: "Pídele algo, p. ej.: «revisa la evidencia y dime qué hacer» o «genera el plan de contención con los IOCs que ya tenemos»." });
    return panel("Asistente de IA", h("div", { class: "body stack" },
      h("p", { class: "muted" }, "Usa el modelo configurado por tu organización. Solo analiza y redacta; nunca ejecuta nada por sí solo ni abre o cierra el caso."),
      q, h("button", { class: "btn primary", onclick: () => askAi(q.value, q) }, "Preguntar a la IA"), aiBox));
  };

  const reportBox = h("div", {});
  const buildReport = async (format) => {
    try { const r = await api("GET", `/api/incidents/${id}/report?format=${format}`); reportBox.replaceChildren(h("pre", { class: "report" }, r.text), h("div", { class: "row" }, h("button", { class: "btn small", onclick: () => copyText(r.text) }, "Copiar"), h("button", { class: "btn small", onclick: () => download(`incidente-${id.slice(0, 8)}.${format === "json" ? "json" : "md"}`, r.text, format === "json" ? "application/json" : "text/markdown") }, "Descargar"))); }
    catch (e) { toast(e.message, true); }
  };

  const evList = d.evidence.length ? d.evidence.map((e) => h("article", { class: "finding" },
    h("div", { class: "row" }, h("strong", { class: "grow" }, e.description), seal(KIND[e.kind] ?? e.kind, "mute"), h("span", { class: "muted" }, fmtDate(e.createdAt))),
    h("details", {}, h("summary", {}, "Ver detalle"),
      h("p", { class: "muted" }, "IOCs: ", ["ips", "domains", "urls", "hashes", "emails"].map((k) => (e.iocs?.[k]?.length ? `${k} (${e.iocs[k].length}): ${e.iocs[k].join(", ")}` : null)).filter(Boolean).join(" · ") || "ninguno"),
      h("pre", { class: "report" }, e.redactedContent)))) : [empty("Sin evidencia todavía", "Añade un log o unas cabeceras de correo para empezar el análisis.")];

  return { crumb: `Incidentes › ${d.organization}`, title: d.organization, node: h("div", { class: "stack" },
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, d.organization), h("p", { class: "row" }, seal(STATUS[d.status] ?? d.status, STATUS_TONE[d.status]), h("span", { class: "muted" }, `Abierto ${fmtDate(d.createdAt)} por ${d.createdBy}`)))),
    panel("Resumen", h("div", { class: "body" }, h("dl", { class: "facts" }, h("dt", {}, "Contacto"), h("dd", {}, `${d.contactName} · ${d.contactEmail}`),
      h("dt", {}, "Activos afectados"), h("dd", {}, d.affectedAssets.join(", ") || "sin especificar"), h("dt", {}, "Qué está pasando"), h("dd", {}, d.summary)),
      !closed ? h("div", { class: "row" }, d.status === "open" ? h("button", { class: "btn", onclick: () => setStatus("contained") }, "Marcar como contenido") : null, h("button", { class: "btn danger", onclick: () => setStatus("closed") }, "Cerrar incidente")) : null)),
    panel(`Evidencia (${d.evidence.length})`, h("div", {}, evList), !closed ? h("button", { class: "btn small primary", onclick: addEvidence }, "Añadir evidencia") : null),
    evBox,
    !closed ? aiPanel() : null,
    panel("Plan de contención", h("div", { class: "body stack" }, h("p", { class: "muted" }, `IOCs acumulados: ${allIps.length} IP(s), ${allDomains.length} dominio(s).`),
      h("button", { class: "btn primary", disabled: !allIps.length && !allDomains.length, onclick: buildContain }, "Generar reglas de bloqueo"), containBox)),
    panel("Informe", h("div", { class: "body stack" }, h("div", { class: "row" }, h("button", { class: "btn primary", onclick: () => buildReport("markdown") }, "Ver informe (Markdown)"), h("button", { class: "btn", onclick: () => buildReport("json") }, "Ver informe (JSON)")), reportBox))) };
}
