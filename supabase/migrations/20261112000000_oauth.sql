-- OAuth 2.1 (PKCE) para conectar clientes MCP (p. ej. Claude). Solo accesible desde el servidor.
create table if not exists public.oauth_clients (
  client_id text primary key,
  client_name text not null default '',
  redirect_uris jsonb not null,
  created_at timestamptz not null default now()
);
create table if not exists public.oauth_codes (
  code_hash text primary key,                  -- sha256 del código; el código no se guarda
  client_id text not null references public.oauth_clients(client_id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  redirect_uri text not null,
  code_challenge text not null,
  expires_at timestamptz not null
);
create table if not exists public.oauth_tokens (
  id uuid primary key default gen_random_uuid(),
  access_hash text not null unique,
  refresh_hash text not null unique,
  client_id text not null references public.oauth_clients(client_id) on delete cascade,
  user_id uuid not null references public.users(id) on delete cascade,
  access_expires_at timestamptz not null,
  refresh_expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists oauth_tokens_user_idx on public.oauth_tokens (user_id);
alter table public.oauth_clients enable row level security;
alter table public.oauth_codes   enable row level security;
alter table public.oauth_tokens  enable row level security;
revoke all on public.oauth_clients, public.oauth_codes, public.oauth_tokens from anon, authenticated;
