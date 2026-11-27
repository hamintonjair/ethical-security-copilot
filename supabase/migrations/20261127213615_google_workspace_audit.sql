-- OAuth de Google Workspace para lectura de auditoría de inicios de sesión.
-- Tokens y estados solo son accesibles por el backend; nunca por PostgREST.
create table if not exists public.google_workspace_oauth_states (
  state_hash text primary key check (length(state_hash) = 64),
  created_by text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.google_workspace_connections (
  id smallint primary key default 1 check (id = 1),
  integration_id uuid not null unique references public.security_integrations(id) on delete cascade,
  admin_email text not null,
  refresh_token_enc text not null,
  connected_by text not null,
  last_sync_at timestamptz,
  last_sync_error text,
  updated_at timestamptz not null default now()
);

alter table public.google_workspace_oauth_states enable row level security;
alter table public.google_workspace_connections enable row level security;
revoke all on public.google_workspace_oauth_states, public.google_workspace_connections from anon, authenticated;

