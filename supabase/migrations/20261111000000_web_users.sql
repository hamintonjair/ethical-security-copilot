-- Interfaz web: cuentas propias y sesiones. Solo accesibles desde el servidor (RLS activo, sin permisos para anon/authenticated).

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique check (username ~ '^[a-z0-9._-]{3,40}$'),
  display_name text not null default '',
  password_hash text not null,                 -- scrypt con sal propia; nunca la contraseña
  role text not null check (role in ('authorizer','operator','analyst','auditor')),
  disabled boolean not null default false,
  must_change boolean not null default false,  -- obliga a cambiar la contraseña temporal
  failed_attempts integer not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now(),
  last_login timestamptz
);

create table if not exists public.sessions (
  id text primary key,                         -- sha256 del token de la cookie (el token no se guarda)
  user_id uuid not null references public.users(id) on delete cascade,
  csrf text not null,
  created_at timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  expires_at timestamptz not null,
  ip text,
  user_agent text
);
create index if not exists sessions_user_idx on public.sessions (user_id);

alter table public.users    enable row level security;
alter table public.sessions enable row level security;
revoke all on public.users, public.sessions from anon, authenticated;
