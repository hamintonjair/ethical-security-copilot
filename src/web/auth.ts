import { randomBytes, scrypt as scryptCb, timingSafeEqual, createHash } from "node:crypto";
import { promisify } from "node:util";
import type { Store } from "../store.js";

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, len: number, o: { N: number; r: number; p: number; maxmem: number }) => Promise<Buffer>;

export const WEB_ROLES = ["authorizer", "operator", "analyst", "auditor"] as const;
export type WebRole = (typeof WEB_ROLES)[number];
export interface WebUser { id: string; username: string; displayName: string; role: WebRole; mustChange: boolean; disabled: boolean }
export interface Session { id: string; csrf: string; user: WebUser }

const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };
const KEYLEN = 64;
export const SESSION_ABSOLUTE_MS = 8 * 3600_000;   // 8 h como máximo
export const SESSION_IDLE_MS = 30 * 60_000;        // 30 min sin actividad
const MAX_FAILS = 5;

const b64 = (b: Buffer) => b.toString("base64");
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/* ---------- Contraseñas ---------- */
export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const h = await scrypt(pw, salt, KEYLEN, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${b64(salt)}$${b64(h)}`;
}

export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, N, r, p, salt, hash] = stored.split("$");
  if (alg !== "scrypt" || !hash) return false;
  const want = Buffer.from(hash, "base64");
  const got = await scrypt(pw, Buffer.from(salt, "base64"), want.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
  return got.length === want.length && timingSafeEqual(got, want);
}

// Hash de relleno: un usuario inexistente cuesta lo mismo que uno real (sin enumeración por tiempo).
let dummy: Promise<string> | null = null;
const dummyHash = () => (dummy ??= hashPassword("relleno-sin-uso-" + randomBytes(8).toString("hex")));

/** Política: largo antes que complejidad. Devuelve el motivo en español o null si es válida. */
export function passwordProblem(pw: string, username?: string): string | null {
  if (pw.length < 12) return "La contraseña debe tener al menos 12 caracteres.";
  if (pw.length > 128) return "La contraseña no puede superar los 128 caracteres.";
  if (new Set(pw).size < 5) return "La contraseña es demasiado repetitiva.";
  if (username && pw.toLowerCase().includes(username.toLowerCase())) return "La contraseña no puede contener el nombre de usuario.";
  return null;
}

/* ---------- Usuarios ---------- */
const toUser = (r: any): WebUser => ({ id: r.id, username: r.username, displayName: r.display_name, role: r.role, mustChange: r.must_change, disabled: r.disabled });
const USERNAME_RE = /^[a-z0-9._-]{3,40}$/;

export class Auth {
  constructor(private store: Store) {}
  private get db() { return this.store.db; }

  async createUser(o: { username: string; displayName?: string; role: WebRole; password: string; mustChange?: boolean }, by: { actor: string; role: "authorizer" }): Promise<{ ok: true; user: WebUser } | { ok: false; error: string }> {
    const username = o.username.trim().toLowerCase();
    if (!USERNAME_RE.test(username)) return { ok: false, error: "El usuario debe tener entre 3 y 40 caracteres: letras minúsculas, números, punto, guion o guion bajo." };
    if (!WEB_ROLES.includes(o.role)) return { ok: false, error: "Rol no válido." };
    const problem = passwordProblem(o.password, username);
    if (problem) return { ok: false, error: problem };
    if ((await this.db.query("select 1 from public.users where username=$1", [username])).length) return { ok: false, error: "Ese usuario ya existe." };
    const row = (await this.db.query("insert into public.users (username, display_name, password_hash, role, must_change) values ($1,$2,$3,$4,$5) returning *",
      [username, (o.displayName ?? "").trim().slice(0, 80), await hashPassword(o.password), o.role, o.mustChange ?? true]))[0];
    await this.store.audit({ actor: by.actor, role: by.role, action: "user:create", payload: { username, role: o.role } });
    return { ok: true, user: toUser(row) };
  }

  async listUsers() {
    return (await this.db.query("select * from public.users order by username")).map(r => ({ ...toUser(r), lockedUntil: r.locked_until ? new Date(r.locked_until).toISOString() : null, lastLogin: r.last_login ? new Date(r.last_login).toISOString() : null, createdAt: new Date(r.created_at).toISOString() }));
  }

  private async activeAuthorizers(exceptId: string): Promise<number> {
    return Number((await this.db.query("select count(*) n from public.users where role='authorizer' and not disabled and id<>$1", [exceptId]))[0].n);
  }

  /** Deshabilitar / cambiar rol: nunca se deja el sistema sin un authorizer activo. */
  async updateUser(id: string, patch: { disabled?: boolean; role?: WebRole; unlock?: boolean }, by: { actor: string; role: "authorizer" }): Promise<{ ok: true } | { ok: false; error: string }> {
    const u = (await this.db.query("select * from public.users where id=$1", [id]))[0];
    if (!u) return { ok: false, error: "Usuario no encontrado." };
    const losesAuthorizer = u.role === "authorizer" && !u.disabled && ((patch.disabled === true) || (patch.role !== undefined && patch.role !== "authorizer"));
    if (losesAuthorizer && (await this.activeAuthorizers(id)) === 0) return { ok: false, error: "Debe quedar al menos un authorizer activo." };
    if (patch.role !== undefined && !WEB_ROLES.includes(patch.role)) return { ok: false, error: "Rol no válido." };
    await this.db.query("update public.users set disabled=coalesce($2, disabled), role=coalesce($3, role), failed_attempts=case when $4 then 0 else failed_attempts end, locked_until=case when $4 then null else locked_until end where id=$1",
      [id, patch.disabled ?? null, patch.role ?? null, patch.unlock === true]);
    if (patch.disabled === true || patch.role !== undefined) await this.db.query("delete from public.sessions where user_id=$1", [id]); // cierra sus sesiones
    await this.store.audit({ actor: by.actor, role: by.role, action: "user:update", payload: { username: u.username, ...patch } });
    return { ok: true };
  }

  /** Restablece la contraseña (temporal): obliga a cambiarla al entrar y cierra sus sesiones. */
  async resetPassword(id: string, password: string, by: { actor: string; role: "authorizer" }): Promise<{ ok: true } | { ok: false; error: string }> {
    const u = (await this.db.query("select username from public.users where id=$1", [id]))[0];
    if (!u) return { ok: false, error: "Usuario no encontrado." };
    const problem = passwordProblem(password, u.username);
    if (problem) return { ok: false, error: problem };
    await this.db.query("update public.users set password_hash=$2, must_change=true, failed_attempts=0, locked_until=null where id=$1", [id, await hashPassword(password)]);
    await this.db.query("delete from public.sessions where user_id=$1", [id]);
    await this.store.audit({ actor: by.actor, role: by.role, action: "user:reset_password", payload: { username: u.username } });
    return { ok: true };
  }

  async changePassword(user: WebUser, current: string, next: string, keepSessionId: string): Promise<{ ok: true } | { ok: false; error: string }> {
    const row = (await this.db.query("select password_hash from public.users where id=$1", [user.id]))[0];
    if (!row || !(await verifyPassword(current, row.password_hash))) return { ok: false, error: "La contraseña actual no es correcta." };
    if (current === next) return { ok: false, error: "La contraseña nueva debe ser distinta de la actual." };
    const problem = passwordProblem(next, user.username);
    if (problem) return { ok: false, error: problem };
    await this.db.query("update public.users set password_hash=$2, must_change=false where id=$1", [user.id, await hashPassword(next)]);
    await this.db.query("delete from public.sessions where user_id=$1 and id<>$2", [user.id, keepSessionId]); // cierra las demás sesiones
    await this.store.audit({ actor: user.username, role: user.role, action: "auth:password_changed" });
    return { ok: true };
  }

  /* ---------- Inicio de sesión ---------- */
  /** Mensaje idéntico para usuario inexistente, contraseña errónea, cuenta bloqueada o deshabilitada. */
  async login(username: string, password: string, ctx: { ip?: string; userAgent?: string }): Promise<{ ok: true; token: string; session: Session } | { ok: false }> {
    const name = username.trim().toLowerCase().slice(0, 40);
    const u = (await this.db.query("select * from public.users where username=$1", [name]))[0];
    const locked = !!u && u.locked_until && new Date(u.locked_until).getTime() > Date.now();
    const valid = await verifyPassword(password.slice(0, 256), u?.password_hash ?? (await dummyHash()));
    if (!u || locked || u.disabled || !valid) {
      if (u && !locked && !u.disabled) {
        const fails = Number(u.failed_attempts) + 1;
        // Bloqueo creciente: 1 min tras el 5.º fallo, duplicando hasta un máximo de 15 min.
        const lockMs = fails >= MAX_FAILS ? Math.min(15 * 60_000, 60_000 * 2 ** (fails - MAX_FAILS)) : 0;
        await this.db.query("update public.users set failed_attempts=$2, locked_until=$3 where id=$1", [u.id, fails, lockMs ? new Date(Date.now() + lockMs).toISOString() : null]);
      }
      await this.store.audit({ actor: name || "?", role: "auditor", action: "auth:login_failed", payload: { reason: !u ? "unknown" : locked ? "locked" : u.disabled ? "disabled" : "bad_password", ip: ctx.ip } });
      return { ok: false };
    }
    await this.db.query("update public.users set failed_attempts=0, locked_until=null, last_login=now() where id=$1", [u.id]);
    const token = randomBytes(32).toString("base64url");
    const csrf = randomBytes(24).toString("base64url");
    await this.db.query("insert into public.sessions (id, user_id, csrf, expires_at, ip, user_agent) values ($1,$2,$3,$4,$5,$6)",
      [sha(token), u.id, csrf, new Date(Date.now() + SESSION_ABSOLUTE_MS).toISOString(), ctx.ip?.slice(0, 64) ?? null, ctx.userAgent?.slice(0, 200) ?? null]);
    await this.db.query("delete from public.sessions where expires_at < now()"); // limpieza oportunista
    const user = toUser(u);
    await this.store.audit({ actor: user.username, role: user.role, action: "auth:login", payload: { ip: ctx.ip } });
    return { ok: true, token, session: { id: sha(token), csrf, user } };
  }

  async getSession(token: string | undefined): Promise<Session | null> {
    if (!token || token.length < 20 || token.length > 100) return null;
    const id = sha(token);
    const r = (await this.db.query("select s.csrf, s.last_seen, s.expires_at, u.* from public.sessions s join public.users u on u.id = s.user_id where s.id=$1", [id]))[0];
    if (!r || r.disabled) return null;
    const now = Date.now();
    if (new Date(r.expires_at).getTime() < now || new Date(r.last_seen).getTime() < now - SESSION_IDLE_MS) { await this.db.query("delete from public.sessions where id=$1", [id]); return null; }
    if (now - new Date(r.last_seen).getTime() > 60_000) await this.db.query("update public.sessions set last_seen=now() where id=$1", [id]);
    return { id, csrf: r.csrf, user: toUser(r) };
  }

  async logout(sessionId: string) { await this.db.query("delete from public.sessions where id=$1", [sessionId]); }
}
