import { readFileSync, readdirSync } from "node:fs";
import { PGlite } from "@electric-sql/pglite";
import pg from "pg";

export interface Db {
  query<T = any>(sql: string, params?: unknown[]): Promise<T[]>;
  /** Ejecuta `fn` dentro de una transacción (COMMIT si termina, ROLLBACK si lanza). */
  tx<T>(fn: (q: Db) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

const MIGRATIONS_DIR = new URL("../supabase/migrations/", import.meta.url);

/** Aplica las migraciones del repositorio (misma fuente que usa Supabase). Solo para la base en memoria / entornos locales. */
export async function applyLocalMigrations(db: { exec(sql: string): Promise<unknown> }) {
  // Supabase ya trae estos roles; en una base local hay que crearlos para que las migraciones sean idénticas.
  await db.exec(`do $$ begin
    if not exists (select from pg_roles where rolname='anon') then create role anon nologin; end if;
    if not exists (select from pg_roles where rolname='authenticated') then create role authenticated nologin; end if;
  end $$;`);
  for (const f of readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith(".sql")).sort())
    await db.exec(readFileSync(new URL(f, MIGRATIONS_DIR), "utf8"));
}

/** "memory" => Postgres en proceso (PGlite) con el esquema real; si no, URL de conexión (p. ej. Supabase). */
export async function openDb(target: string): Promise<Db> {
  if (target === "memory") {
    const lite = new PGlite();
    await applyLocalMigrations(lite);
    const wrap = (q: { query: PGlite["query"] }): Db => ({
      query: async (sql, params) => (await q.query(sql, params as any[])).rows as any[],
      tx: async fn => (lite as any).transaction((t: any) => fn(wrap(t))),
      close: async () => {},
    });
    const root = wrap(lite);
    return { ...root, close: () => lite.close() };
  }
  const local = /@(localhost|127\.0\.0\.1)[:/]/.test(target);
  const pool = new pg.Pool({ connectionString: target, max: 5, ssl: local ? undefined : { rejectUnauthorized: true } });
  const wrapClient = (c: pg.PoolClient): Db => ({
    query: async (sql, params) => (await c.query(sql, params as any[])).rows,
    tx: async fn => fn(wrapClient(c)), // ya estamos en una transacción
    close: async () => {},
  });
  return {
    query: async (sql, params) => (await pool.query(sql, params as any[])).rows,
    tx: async fn => {
      const c = await pool.connect();
      try { await c.query("BEGIN"); const r = await fn(wrapClient(c)); await c.query("COMMIT"); return r; }
      catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
      finally { c.release(); }
    },
    close: () => pool.end(),
  };
}
