import { randomBytes } from "node:crypto";
import type { Store } from "./store.js";

const SCOPE = "openid email https://www.googleapis.com/auth/admin.reports.audit.readonly";

export interface GoogleWorkspaceEnv {
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
}

export const googleWorkspaceConfigured = (env: GoogleWorkspaceEnv) => !!(env.clientId && env.clientSecret && env.redirectUri);

export async function googleWorkspaceAuthorizationUrl(store: Store, env: GoogleWorkspaceEnv, actor: string) {
  if (!googleWorkspaceConfigured(env)) throw new Error("Falta configurar el cliente OAuth de Google Workspace en el servidor.");
  const state = randomBytes(32).toString("base64url");
  await store.createGoogleWorkspaceOAuthState(state, actor);
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: env.clientId!, redirect_uri: env.redirectUri!, response_type: "code",
    scope: SCOPE, access_type: "offline", prompt: "consent", include_granted_scopes: "true", state,
  }).toString();
  return url.toString();
}

export async function completeGoogleWorkspaceAuthorization(store: Store, env: GoogleWorkspaceEnv, input: { code?: string; state?: string; error?: string }) {
  if (!googleWorkspaceConfigured(env)) throw new Error("La conexión de Google Workspace no está configurada en el servidor.");
  if (input.error) throw new Error("Google canceló la autorización.");
  if (!input.code || !input.state) throw new Error("La respuesta de Google no está completa.");
  const actor = await store.consumeGoogleWorkspaceOAuthState(input.state);
  if (!actor) throw new Error("La autorización venció o ya fue utilizada. Vuelve a intentarlo desde Configuración.");

  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code: input.code, client_id: env.clientId!, client_secret: env.clientSecret!, redirect_uri: env.redirectUri!, grant_type: "authorization_code" }),
    signal: AbortSignal.timeout(15_000),
  });
  const token = await tokenResponse.json() as { access_token?: string; refresh_token?: string; id_token?: string; error?: string };
  if (!tokenResponse.ok || !token.access_token || !token.refresh_token || !token.id_token) throw new Error("Google no entregó un permiso renovable. Revisa el consentimiento OAuth e inténtalo de nuevo.");

  const verifyUrl = new URL("https://oauth2.googleapis.com/tokeninfo");
  verifyUrl.searchParams.set("id_token", token.id_token);
  const profileResponse = await fetch(verifyUrl, { signal: AbortSignal.timeout(10_000) });
  const profile = await profileResponse.json() as { aud?: string; email?: string; email_verified?: string; hd?: string };
  if (!profileResponse.ok || profile.aud !== env.clientId || !profile.email || profile.email_verified !== "true" || !profile.hd || profile.email.toLowerCase().endsWith("@gmail.com")) {
    await revokeGoogleToken(token.refresh_token);
    throw new Error("Autoriza con una cuenta administradora de Google Workspace de tu dominio; una cuenta personal @gmail.com no ofrece estos registros.");
  }
  await store.saveGoogleWorkspaceConnection(profile.email, token.refresh_token, actor);
}

async function getAccessToken(refreshToken: string, env: GoogleWorkspaceEnv) {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: env.clientId!, client_secret: env.clientSecret!, refresh_token: refreshToken, grant_type: "refresh_token" }),
    signal: AbortSignal.timeout(15_000),
  });
  const result = await response.json() as { access_token?: string; error?: string };
  if (!response.ok || !result.access_token) throw new Error(result.error === "invalid_grant" ? "La autorización de Google venció o fue revocada. Desconecta y vuelve a conectar la cuenta." : "No se pudo renovar la autorización de Google.");
  return result.access_token;
}

export async function syncGoogleWorkspaceLoginEvents(store: Store, env: GoogleWorkspaceEnv) {
  if (!googleWorkspaceConfigured(env)) throw new Error("La conexión de Google Workspace no está configurada en el servidor.");
  const connection = await store.getGoogleWorkspaceCredentials();
  if (!connection) throw new Error("Conecta primero una cuenta administradora de Google Workspace.");
  const accessToken = await getAccessToken(connection.refreshToken, env);
  const since = new Date(Date.now() - 7 * 24 * 60 * 60_000).toISOString();
  const url = new URL("https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login");
  url.search = new URLSearchParams({ startTime: since, maxResults: "1000" }).toString();
  const response = await fetch(url, { headers: { authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(20_000) });
  const data = await response.json() as { items?: GoogleActivity[]; error?: { message?: string; errors?: Array<{ reason?: string }> } };
  if (!response.ok) {
    const reason = data.error?.errors?.[0]?.reason;
    const detail = (data.error?.message ?? "").replace(/[\\r\\n]+/g, " ").slice(0, 240);
    if (response.status === 401) {
      throw new Error(`Google Reports API devolvió 401${detail ? `: ${detail}` : ""}. La autorización guardada no sirve para esta consulta; desconecta y vuelve a conectar la cuenta administradora. Si persiste, revisa que Admin SDK API esté habilitada en el proyecto OAuth.`);
    }
    if (response.status === 403 && (reason === "insufficientPermissions" || reason === "forbidden" || !reason)) {
      throw new Error(`Google rechazó la consulta (403${reason ? `, ${reason}` : ""})${detail ? `: ${detail}` : ""}. Confirma que la cuenta tenga rol de administrador con acceso a informes de auditoría y que Admin SDK API esté habilitada.`);
    }
    throw new Error(`Google Reports API devolvió ${response.status}${reason ? ` (${reason})` : ""}${detail ? `: ${detail}` : "."}`);
  }
  try {
    const count = await store.ingestGoogleWorkspaceLoginActivities(connection.integrationId, data.items ?? []);
    await store.markGoogleWorkspaceSync(connection.integrationId, null);
    return { received: count, scanned: data.items?.length ?? 0, account: connection.email };
  } catch (e) {
    await store.markGoogleWorkspaceSync(connection.integrationId, "No se pudieron guardar los eventos importados.");
    throw e;
  }
}

export async function disconnectGoogleWorkspace(store: Store) {
  const connection = await store.getGoogleWorkspaceCredentials();
  if (connection) await revokeGoogleToken(connection.refreshToken);
  await store.deleteGoogleWorkspaceConnection();
}

async function revokeGoogleToken(token: string) {
  try {
    await fetch("https://oauth2.googleapis.com/revoke", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token }), signal: AbortSignal.timeout(10_000) });
  } catch { /* el borrado local no depende de que Google responda */ }
}

interface GoogleActivity {
  id?: { time?: string; uniqueQualifier?: string };
  actor?: { email?: string };
  ipAddress?: string;
  events?: Array<{ name?: string; type?: string; parameters?: Array<{ name?: string; value?: string; boolValue?: boolean }> }>;
}


