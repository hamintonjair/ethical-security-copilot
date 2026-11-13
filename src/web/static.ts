import type http from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, extname, sep } from "node:path";
import { fileURLToPath } from "node:url";

// Desde src/web o dist/web, la carpeta pública está dos niveles arriba.
const ROOT = resolve(fileURLToPath(new URL("../../web/", import.meta.url)));
const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8", ".md": "text/markdown; charset=utf-8",
};

/** Cabeceras para todas las respuestas. Sin scripts ni estilos en línea: todo viene de este mismo origen. */
export function securityHeaders(res: http.ServerResponse) {
  res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
}

/** Sirve /app/*. Devuelve false si no es una ruta de la interfaz. */
export async function serveStatic(req: http.IncomingMessage, res: http.ServerResponse, path: string): Promise<boolean> {
  if (path !== "/app" && !path.startsWith("/app/")) return false;
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405, { Allow: "GET, HEAD" }); res.end(); return true; }
  if (path === "/app") { res.writeHead(301, { Location: "/app/" }); res.end(); return true; }
  const rel = path === "/app/" ? "index.html" : decodeURIComponent(path.slice(5));
  if (!/^[A-Za-z0-9._\/-]+$/.test(rel) || rel.includes("..")) { res.writeHead(404); res.end(); return true; }
  const file = resolve(ROOT, rel);
  if (!file.startsWith(ROOT + sep)) { res.writeHead(404); res.end(); return true; }
  try {
    const data = await readFile(file);
    const ext = extname(file);
    res.writeHead(200, { "Content-Type": TYPES[ext] ?? "application/octet-stream", "Content-Length": data.length, "Cache-Control": ext === ".woff2" ? "public, max-age=31536000, immutable" : "no-cache" });
    res.end(req.method === "HEAD" ? undefined : data);
  } catch { res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); res.end("No encontrado"); }
  return true;
}
