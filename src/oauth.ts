// OAuth 2.1 con PKCE (S256) para clientes MCP públicos. Quien autoriza es siempre una persona (cuenta web con rol authorizer);
// el token resultante solo da el rol de agente del servidor MCP, nunca permisos de la consola web.
import { createHash, randomBytes } from "node:crypto";
import type { Store } from "./store.js";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const rnd = (n = 32) => randomBytes(n).toString("base64url");
const ACCESS_MS = 3600_000, REFRESH_MS = 30 * 86400_000, CODE_MS = 5 * 60_000, MAX_CLIENTS = 200;

export class OAuthError extends Error { constructor(public code: string, message = code, public status = 400) { super(message); } }

export interface AuthRequest { client_id: string; redirect_uri: string; code_challenge: string; code_challenge_method: string; response_type: string; state?: string }

function validRedirect(u: string): boolean {
  try {
    const x = new URL(u);
    if (x.hash) return false;
    if (x.protocol === "https:") return true;
    return x.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(x.hostname);
  } catch { return false; }
}

export class OAuth {
  constructor(private store: Store) {}
  private get db() { return this.store.db; }

  async register(body: any) {
    const uris = Array.isArray(body?.redirect_uris) ? body.redirect_uris.map(String) : [];
    if (!uris.length || uris.length > 10 || !uris.every(validRedirect)) throw new OAuthError("invalid_redirect_uri", "redirect_uris debe ser una lista de URLs https (o http en localhost) sin fragmento.");
    await this.db.query("delete from public.oauth_clients where created_at < now() - interval '7 days' and client_id not in (select client_id from public.oauth_tokens)");
    if (Number((await this.db.query("select count(*) n from public.oauth_clients"))[0].n) >= MAX_CLIENTS) throw new OAuthError("temporarily_unavailable", "Demasiados registros; inténtalo más tarde.", 429);
    const client_id = rnd(18), client_name = String(body?.client_name ?? "").slice(0, 80);
    await this.db.query("insert into public.oauth_clients (client_id, client_name, redirect_uris) values ($1,$2,$3)", [client_id, client_name, JSON.stringify(uris)]);
    return { client_id, client_name, redirect_uris: uris, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] };
  }

  /** Valida la petición de autorización. Un cliente o redirect_uri desconocido NUNCA redirige: se muestra el error. */
  async checkRequest(p: Record<string, string | undefined>): Promise<{ clientName: string; redirectUri: string }> {
    const c = (await this.db.query("select * from public.oauth_clients where client_id=$1", [p.client_id ?? ""]))[0];
    if (!c) throw new OAuthError("invalid_client", "Cliente desconocido.");
    if (!(c.redirect_uris as string[]).includes(p.redirect_uri ?? "")) throw new OAuthError("invalid_request", "redirect_uri no está registrada para este cliente.");
    if (p.response_type !== "code") throw new OAuthError("unsupported_response_type", "Solo response_type=code.");
    if (p.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(p.code_challenge ?? "")) throw new OAuthError("invalid_request", "Se exige PKCE con S256.");
    return { clientName: c.client_name, redirectUri: p.redirect_uri! };
  }

  async issueCode(userId: string, p: AuthRequest): Promise<string> {
    await this.checkRequest(p as any);
    await this.db.query("delete from public.oauth_codes where expires_at < now()");
    const code = rnd();
    await this.db.query("insert into public.oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at) values ($1,$2,$3,$4,$5,$6)",
      [sha(code), p.client_id, userId, p.redirect_uri, p.code_challenge, new Date(Date.now() + CODE_MS).toISOString()]);
    return code;
  }

  private async mint(clientId: string, userId: string) {
    const access = rnd(), refresh = rnd();
    await this.db.query("insert into public.oauth_tokens (access_hash, refresh_hash, client_id, user_id, access_expires_at, refresh_expires_at) values ($1,$2,$3,$4,$5,$6)",
      [sha(access), sha(refresh), clientId, userId, new Date(Date.now() + ACCESS_MS).toISOString(), new Date(Date.now() + REFRESH_MS).toISOString()]);
    await this.db.query("delete from public.oauth_tokens where refresh_expires_at < now()");
    return { access_token: access, token_type: "Bearer", expires_in: ACCESS_MS / 1000, refresh_token: refresh };
  }

  async token(f: Record<string, string | undefined>) {
    if (f.grant_type === "authorization_code") {
      // El código se consume de forma atómica: un segundo uso falla aunque llegue a la vez.
      const row = (await this.db.query("delete from public.oauth_codes where code_hash=$1 returning *", [sha(f.code ?? "")]))[0];
      if (!row || new Date(row.expires_at).getTime() < Date.now() || row.client_id !== f.client_id || row.redirect_uri !== f.redirect_uri) throw new OAuthError("invalid_grant", "Código inválido o vencido.");
      const verifier = f.code_verifier ?? "";
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || createHash("sha256").update(verifier).digest("base64url") !== row.code_challenge) throw new OAuthError("invalid_grant", "PKCE no coincide.");
      const u = (await this.db.query("select role, disabled from public.users where id=$1", [row.user_id]))[0];
      if (!u || u.disabled || u.role !== "authorizer") throw new OAuthError("invalid_grant", "La cuenta que autorizó ya no puede hacerlo.");
      return this.mint(row.client_id, row.user_id);
    }
    if (f.grant_type === "refresh_token") {
      const row = (await this.db.query("delete from public.oauth_tokens where refresh_hash=$1 returning *", [sha(f.refresh_token ?? "")]))[0]; // rotación: el refresh viejo deja de servir
      if (!row || row.client_id !== f.client_id || new Date(row.refresh_expires_at).getTime() < Date.now()) throw new OAuthError("invalid_grant", "Refresh token inválido o vencido.");
      const u = (await this.db.query("select role, disabled from public.users where id=$1", [row.user_id]))[0];
      if (!u || u.disabled || u.role !== "authorizer") throw new OAuthError("invalid_grant", "La cuenta que autorizó ya no puede hacerlo.");
      return this.mint(row.client_id, row.user_id);
    }
    throw new OAuthError("unsupported_grant_type", "Tipo de concesión no soportado.");
  }

  /** ¿Es un access token vigente de una cuenta authorizer activa? */
  async verifyAccess(token: string): Promise<{ clientId: string; username: string } | null> {
    if (token.length < 20 || token.length > 200) return null;
    const r = (await this.db.query("select t.client_id, u.username from public.oauth_tokens t join public.users u on u.id=t.user_id where t.access_hash=$1 and t.access_expires_at > now() and not u.disabled and u.role='authorizer'", [sha(token)]))[0];
    return r ? { clientId: r.client_id, username: r.username } : null;
  }
}
