import { h, errorBox } from "../lib.js";

// Mini renderizador de Markdown: construye nodos con textContent (nunca innerHTML), así que el contenido no puede inyectar HTML.
function inline(text) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*\s][^*]*\*)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    out.push(t.startsWith("**") ? h("strong", {}, t.slice(2, -2)) : t.startsWith("`") ? h("code", {}, t.slice(1, -1)) : h("em", {}, t.slice(1, -1)));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function renderMarkdown(src) {
  const lines = src.replace(/\r/g, "").split("\n");
  const root = h("div", { class: "manual" });
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (!l.trim()) { i++; continue; }
    const hd = /^(#{1,3})\s+(.*)$/.exec(l);
    if (hd) { root.append(h(`h${hd[1].length + 1 > 4 ? 4 : hd[1].length === 1 ? 1 : hd[1].length}`, { id: undefined }, inline(hd[2]))); i++; continue; }
    if (/^\|/.test(l)) {
      const rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) { rows.push(lines[i].trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim())); i++; }
      const [head, , ...body] = rows;
      root.append(h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, head.map((c) => h("th", {}, inline(c))))), h("tbody", {}, body.map((r) => h("tr", {}, r.map((c) => h("td", {}, inline(c)))))))));
      continue;
    }
    if (/^\s*[-*]\s+/.test(l) || /^\s*\d+\.\s+/.test(l)) {
      const ordered = /^\s*\d+\./.test(l), items = [];
      while (i < lines.length && (/^\s*[-*]\s+/.test(lines[i]) || /^\s*\d+\.\s+/.test(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && items.length))) {
        const sub = /^\s{2,}[-*]\s+(.*)$/.exec(lines[i]);
        if (sub && items.length) items[items.length - 1].subs.push(sub[1]);
        else items.push({ text: lines[i].replace(/^\s*(?:[-*]|\d+\.)\s+/, ""), subs: [] });
        i++;
      }
      root.append(h(ordered ? "ol" : "ul", {}, items.map((it) => h("li", {}, inline(it.text), it.subs.length ? h("ul", {}, it.subs.map((s) => h("li", {}, inline(s)))) : null))));
      continue;
    }
    const para = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,3}\s|\||\s*[-*]\s+|\s*\d+\.\s+)/.test(lines[i])) para.push(lines[i++].trim());
    root.append(h("p", {}, inline(para.join(" "))));
  }
  return root;
}

export async function manualView() {
  let text;
  try { const r = await fetch("/app/manual.md", { cache: "no-cache" }); if (!r.ok) throw new Error("No se pudo cargar el manual."); text = await r.text(); }
  catch (e) { return { crumb: "Manual", node: errorBox(e) }; }
  return { crumb: "Manual", title: "Manual", node: h("div", { class: "stack" }, renderMarkdown(text)) };
}
