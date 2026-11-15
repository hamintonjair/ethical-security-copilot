// Convierte los informes (ya redactados) a PDF para entregar a un cliente o a un CSIRT.
// Lee un subconjunto de Markdown suficiente para nuestros propios informes: encabezados,
// listas, tablas simples, bloques de código y negrita. No es un motor de Markdown general.
import PDFDocument from "pdfkit";

const PAGE = { size: "A4" as const, margins: { top: 56, bottom: 56, left: 56, right: 56 } };
const INK = "#1a1f2b", MUTED = "#5b6472", RULE = "#d7dbe3", CODE_BG = "#f1f3f6";

/** Escribe texto con **negrita** inline. `prefix` (p. ej. "•  ") se escribe sin negrita antes, en el mismo renglón. */
function renderInline(doc: PDFKit.PDFDocument, text: string, opts: { size?: number; color?: string; width?: number; prefix?: string; x?: number; y?: number } = {}) {
  const size = opts.size ?? 10.5, color = opts.color ?? INK;
  const width = opts.width ?? doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const parts = text.split(/(\*\*[^*]+\*\*)/g).filter((p) => p !== "");
  const segs = (opts.prefix ? [{ text: opts.prefix, bold: false }] : []).concat(
    parts.map((p) => ({ text: p.startsWith("**") && p.endsWith("**") ? p.slice(2, -2) : p, bold: p.startsWith("**") && p.endsWith("**") })));
  if (!segs.length) return;
  segs.forEach((seg, i) => {
    const isLast = i === segs.length - 1;
    doc.font(seg.bold ? "Helvetica-Bold" : "Helvetica").fontSize(size).fillColor(color);
    const base = { continued: !isLast, width };
    if (i === 0 && opts.x !== undefined && opts.y !== undefined) doc.text(seg.text, opts.x, opts.y, base);
    else doc.text(seg.text, base);
  });
}

/** Genera un PDF a partir del título y del texto Markdown ya producido por buildReport()/buildIncidentReport(). */
export function markdownToPdf(title: string, markdown: string, meta?: { subtitle?: string }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument(PAGE);
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    doc.font("Helvetica-Bold").fontSize(18).fillColor(INK).text(title);
    if (meta?.subtitle) doc.moveDown(0.15).font("Helvetica").fontSize(10).fillColor(MUTED).text(meta.subtitle);
    doc.moveDown(0.6);
    doc.strokeColor(RULE).lineWidth(1).moveTo(doc.page.margins.left, doc.y).lineTo(doc.page.width - doc.page.margins.right, doc.y).stroke();
    doc.moveDown(0.8);

    const lines = markdown.split("\n");
    let inCode = false, codeBuf: string[] = [];
    let tableRows: string[][] = [];
    const flushTable = () => {
      if (!tableRows.length) return;
      const rows = tableRows.filter((r) => !r.every((c) => /^-+$/.test(c.trim())));
      const colW = (doc.page.width - doc.page.margins.left - doc.page.margins.right) / Math.max(1, rows[0]?.length ?? 1);
      for (const row of rows) {
        const y0 = doc.y;
        row.forEach((cell, i) => doc.font("Helvetica").fontSize(9.5).fillColor(INK).text(cell.trim(), doc.page.margins.left + i * colW, y0, { width: colW - 6 }));
        doc.moveDown(0.3);
      }
      doc.moveDown(0.2);
      tableRows = [];
    };
    for (const raw of lines) {
      const line = raw;
      if (line.trim().startsWith("```")) { inCode = !inCode; if (!inCode) { flushCode(); } continue; }
      if (inCode) { codeBuf.push(line); continue; }
      if (/^\s*\|.*\|\s*$/.test(line)) { tableRows.push(line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|")); continue; }
      else if (tableRows.length) flushTable();

      if (!line.trim()) { doc.moveDown(0.35); continue; }
      const h3 = /^###\s+(.*)/.exec(line), h2 = /^##\s+(.*)/.exec(line), h1 = /^#\s+(.*)/.exec(line);
      if (h1) { ensureSpace(doc, 40); doc.moveDown(0.4).font("Helvetica-Bold").fontSize(15).fillColor(INK).text(h1[1]); doc.moveDown(0.2); continue; }
      if (h2) { ensureSpace(doc, 32); doc.moveDown(0.5).font("Helvetica-Bold").fontSize(13).fillColor(INK).text(h2[1]); doc.moveDown(0.15); continue; }
      if (h3) { ensureSpace(doc, 24); doc.moveDown(0.3).font("Helvetica-Bold").fontSize(11).fillColor(INK).text(h3[1]); doc.moveDown(0.1); continue; }
      const bullet = /^\s*[-*]\s+(.*)/.exec(line);
      if (bullet) { renderBullet(doc, bullet[1]); continue; }
      const num = /^\s*(\d+)\.\s+(.*)/.exec(line);
      if (num) { renderBullet(doc, `${num[1]}. ${num[2]}`, 14); continue; }
      renderInline(doc, line.trim());
      doc.moveDown(0.1);
    }
    function flushCode() {
      if (!codeBuf.length) return;
      const text = codeBuf.join("\n"); codeBuf = [];
      const w = doc.page.width - doc.page.margins.left - doc.page.margins.right;
      doc.font("Courier").fontSize(9);
      const h = doc.heightOfString(text, { width: w - 16 }) + 12;
      ensureSpace(doc, h + 10);
      const y0 = doc.y;
      doc.rect(doc.page.margins.left, y0, w, h).fill(CODE_BG);
      doc.fillColor(INK).font("Courier").fontSize(9).text(text, doc.page.margins.left + 8, y0 + 6, { width: w - 16 });
      doc.moveDown(0.3);
    }
    flushTable(); flushCode();
    doc.end();
  });
}

function ensureSpace(doc: PDFKit.PDFDocument, needed: number) {
  if (doc.y + needed > doc.page.height - doc.page.margins.bottom) doc.addPage();
}
function renderBullet(doc: PDFKit.PDFDocument, text: string, indent = 12) {
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right - indent + 12;
  ensureSpace(doc, 18);
  renderInline(doc, text, { prefix: "•  ", width: w, x: doc.page.margins.left + indent - 12, y: doc.y });
  doc.moveDown(0.08);
}
