-- Módulo de IA dentro de la propia plataforma (además de MCP). Fila única (id=1): llave de API
-- cifrada en el servidor (nunca en texto plano), elegida por un authorizer. El módulo de IA, cuando
-- actúa, lo hace exactamente con los mismos permisos que el rol 'agent' ya tiene en RolePermissions:
-- nunca abre ni cierra un incidente, nunca aprueba nada.
create table if not exists public.ai_config (
  id smallint primary key default 1 check (id = 1),
  enabled boolean not null default false,
  provider text not null default 'anthropic',
  model text not null default 'claude-sonnet-5-5',
  api_key_enc text,
  api_key_last4 text,
  updated_by text,
  updated_at timestamptz
);
insert into public.ai_config (id) values (1) on conflict (id) do nothing;
alter table public.ai_config enable row level security;
revoke all on public.ai_config from anon, authenticated;
