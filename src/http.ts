#!/usr/bin/env node
// Servidor MCP por HTTP (Streamable HTTP, sin estado) para alojarlo en Render u otro host.
// Seguridad: token Bearer obligatorio (comparación en tiempo constante), allowlist de Host (anti DNS-rebinding),
// límite de cuerpo, sin CORS, y SOLO roles no humanos: autorizar y aprobar se hace con el CLI, nunca por la red.
import http from "node:http";
import { pathToFileURL } from "node:url";
import { timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Store } from "./store.js";
import { createServer, type RunRegistry } from "./server.js";
import { PolicyEngine } from "./policy.js";
import { builtinModules } from "./modules.js";
import { sha256 } from "./crypto.js";
import { Auth } from "./web/auth.js";
import { OAuth, OAuthError } from "./oauth.js";
import { createApi } from "./web/api.js";
import { securityHeaders, serveStatic } from "./web/static.js";

const HTTP_ROLES = ["agent", "analyst", "auditor"] as const;
type HttpRole = (typeof HTTP_ROLES)[number];
const MAX_BODY = 1_000_000;

export interface HttpOptions { store: Store; token: string; role?: HttpRole; allowedHosts: string[]; actor?: string; publicUrl?: string }

const safeEqual = (a: string, b: string) => timingSafeEqual(Buffer.from(sha256(a), "hex"), Buffer.from(sha256(b), "hex"));
const send = (res: http.ServerResponse, code: number, body: unknown) => {
  res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  res.end(JSON.stringify(body));
};


const readBody = async (req: http.IncomingMessage, limit = 20_000): Promise<Record<string, any>> => {
  const chunks: Buffer[] = []; let size = 0;
  for await (const c of req) { size += (c as Buffer).length; if (size > limit) throw new OAuthError("invalid_request", "Cuerpo demasiado grande.", 413); chunks.push(c as Buffer); }
  const text = Buffer.concat(chunks).toString("utf8");
  if (String(req.headers["content-type"] ?? "").includes("application/json")) { try { return JSON.parse(text || "{}"); } catch { throw new OAuthError("invalid_request", "JSON no válido."); } }
  return Object.fromEntries(new URLSearchParams(text));
};

export function createHttpApp(o: HttpOptions): http.Server {
  if (o.token.length < 32) throw new Error("ESC_HTTP_TOKEN debe tener al menos 32 caracteres");
  const role: HttpRole = o.role ?? "agent";
  if (!HTTP_ROLES.includes(role)) throw new Error(`Rol '${role}' no permitido por HTTP (solo ${HTTP_ROLES.join(", ")}).`);
  const modules = builtinModules();
  const policy = new PolicyEngine(o.store, { manifests: new Map([...modules].map(([k, m]) => [k, m.manifest])) });
  const runs: RunRegistry = new Map();
  const api = createApi({ store: o.store, auth: new Auth(o.store), runs });
  const oauth = new OAuth(o.store);
  const hosts = new Set(o.allowedHosts.map(h => h.toLowerCase()));

  const app = http.createServer(async (req, res) => {
    try {
      const host = String(req.headers.host ?? "").toLowerCase().replace(/:\d+$/, "");
      if (!hosts.has(host)) return send(res, 403, { error: "HOST_NOT_ALLOWED" });
      securityHeaders(res);
      const [path, qs = ""] = (req.url ?? "").split("?");
      if (path === "/healthz") return send(res, 200, { status: "ok" }); // sin datos; solo para el health check de la plataforma
      const base = (o.publicUrl ?? `${req.headers["x-forwarded-proto"] === "https" ? "https" : "http"}://${req.headers.host}`).replace(/\/$/, "");
      if (path.startsWith("/.well-known/oauth-protected-resource")) return send(res, 200, { resource: `${base}/mcp`, authorization_servers: [base], bearer_methods_supported: ["header"] });
      if (path.startsWith("/.well-known/oauth-authorization-server")) return send(res, 200, {
        issuer: base, authorization_endpoint: `${base}/oauth/authorize`, token_endpoint: `${base}/oauth/token`, registration_endpoint: `${base}/oauth/register`,
        response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"] });
      if (path === "/oauth/authorize" && req.method === "GET") {
        const q = new URLSearchParams(qs);
        try { await oauth.checkRequest(Object.fromEntries(q)); } catch (e) { if (e instanceof OAuthError) return send(res, 400, { error: e.code, error_description: e.message }); throw e; }
        res.writeHead(302, { Location: `/app/#/autorizar?${q.toString()}`, "Cache-Control": "no-store" }); return void res.end();
      }
      if (path === "/oauth/register" || path === "/oauth/token") {
        if (req.method !== "POST") return send(res, 405, { error: "METHOD_NOT_ALLOWED" });
        try {
          const b = await readBody(req);
          if (path === "/oauth/register") return send(res, 201, await oauth.register(b));
          return send(res, 200, await oauth.token(b));
        } catch (e) { if (e instanceof OAuthError) return send(res, e.status, { error: e.code, error_description: e.message }); throw e; }
      }
      if (path === "/") { res.writeHead(302, { Location: "/app/" }); return void res.end(); }
      if (path.startsWith("/api/")) return await api(req, res, path, new URLSearchParams(qs));
      if (await serveStatic(req, res, path)) return;
      if (path === "/readyz") return (await o.store.ping()) ? send(res, 200, { status: "ready" }) : send(res, 503, { status: "db_unavailable" }); // sin detalles del error
      if (path !== "/mcp") return send(res, 404, { error: "NOT_FOUND" });

      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization ?? ""));
      // Token fijo (CLI, scripts) o token OAuth emitido a un authorizer que aprobó la conexión.
      const grant = m ? (safeEqual(m[1], o.token) ? { actor: o.actor ?? `mcp-http-${role}` } : await oauth.verifyAccess(m[1]).then(v => v && { actor: `mcp-oauth-${v.username}` })) : null;
      if (!grant) { res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`); return send(res, 401, { error: "UNAUTHORIZED" }); }
      if (req.method !== "POST") return send(res, 405, { error: "METHOD_NOT_ALLOWED", message: "Servidor sin estado: usa POST." });

      const chunks: Buffer[] = []; let size = 0;
      for await (const c of req) {
        size += (c as Buffer).length;
        if (size > MAX_BODY) { // se corta la lectura y se cierra la conexión (no se deja un socket a medias en el pool del cliente)
          res.writeHead(413, { "Content-Type": "application/json", Connection: "close" });
          return void res.end(JSON.stringify({ error: "BODY_TOO_LARGE" }), () => req.socket?.destroy());
        }
        chunks.push(c as Buffer);
      }
      let body: unknown;
      try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return send(res, 400, { error: "INVALID_JSON" }); }

      // Instancia nueva por petición (sin estado); el rol lo fija el servidor, nunca el cliente.
      const { server } = createServer({ store: o.store, role, actor: grant.actor, modules, policy, runs });
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => { void transport.close(); void server.close(); });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (e) {
      console.error("error de petición:", (e as Error).message); // nunca se registran cabeceras ni cuerpos
      if (!res.headersSent) send(res, 500, { error: "INTERNAL_ERROR" });
    }
  });
  app.requestTimeout = 120_000; app.headersTimeout = 15_000;
  return app;
}

// Punto de entrada (solo si se ejecuta directamente)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const need = (k: string, min = 1) => { const v = process.env[k]; if (!v || v.length < min) { console.error(`${k} es obligatorio${min > 1 ? ` (mín. ${min} caracteres)` : ""}.`); process.exit(1); } return v; };
  const key = need("ESC_SIGNING_KEY", 32), token = need("ESC_HTTP_TOKEN", 32), dbUrl = need("ESC_DATABASE_URL");
  const port = Number(process.env.PORT ?? 3000);
  const allowedHosts = [...(process.env.ESC_ALLOWED_HOSTS ?? "").split(",").map(s => s.trim()).filter(Boolean), process.env.RENDER_EXTERNAL_HOSTNAME ?? "", "localhost", "127.0.0.1"].filter(Boolean);
  const store = await Store.open(dbUrl, Buffer.from(key));
  const app = createHttpApp({ store, token, role: (process.env.ESC_ROLE as HttpRole) ?? "agent", allowedHosts });
  app.listen(port, "0.0.0.0", () => console.error(`Ethical Security Copilot HTTP en :${port} (hosts: ${allowedHosts.join(", ")})`));
  for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => app.close(() => void store.close().then(() => process.exit(0))));
}
