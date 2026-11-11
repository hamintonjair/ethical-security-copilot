-- Ethical Security Copilot — almacenamiento en Postgres (Supabase)
-- Acceso solo desde el servidor (rol de servicio / conexión directa). Nada de esto debe ser accesible vía la API pública.

create table if not exists public.assessments (
  id text not null,
  version integer not null,
  state text not null,
  content_json text not null,          -- JSON canónico (texto, para que el hash sea reproducible)
  content_hash text not null,
  signature text not null,
  created_by text not null,
  created_at timestamptz not null default now(),
  primary key (id, version)
);

create table if not exists public.plans (
  id text primary key,
  assessment_id text not null,
  assessment_version integer not null,
  module_id text not null,
  mode text not null,
  targets_json text not null,
  limits_json text not null,
  status text not null check (status in ('pending_approval','approved','rejected','running','done','stopped')),
  approved_by text,                    -- siempre un humano
  approval_token_hash text,            -- token de un solo uso (solo su hash)
  created_at timestamptz not null default now()
);

create table if not exists public.findings (
  id text primary key,
  assessment_id text not null,
  data_json text not null,             -- ya redactado en la ingesta
  triage text not null default 'unverified',
  created_at timestamptz not null default now()
);

create table if not exists public.kill_switch (
  id integer primary key check (id = 1),
  active boolean not null default false,
  reason text,
  activated_at timestamptz
);
insert into public.kill_switch (id, active) values (1, false) on conflict do nothing;

-- Auditoría append-only con cadena de hashes. prev_hash único => no se pueden bifurcar ramas de la cadena.
create table if not exists public.audit_log (
  seq bigint generated always as identity primary key,
  ts timestamptz not null,
  actor text not null,
  role text not null,
  action text not null,
  assessment_id text,
  decision_id text,
  payload_redacted text not null,
  prev_hash text not null unique,
  hash text not null
);

create or replace function public.audit_log_immutable() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'audit_log es append-only';
end $$;

drop trigger if exists audit_no_update on public.audit_log;
create trigger audit_no_update before update or delete on public.audit_log
  for each row execute function public.audit_log_immutable();
drop trigger if exists audit_no_truncate on public.audit_log;
create trigger audit_no_truncate before truncate on public.audit_log
  for each statement execute function public.audit_log_immutable();

-- Seguridad: RLS activo SIN políticas => ni anon ni authenticated pueden leer o escribir.
alter table public.assessments enable row level security;
alter table public.plans       enable row level security;
alter table public.findings    enable row level security;
alter table public.kill_switch enable row level security;
alter table public.audit_log   enable row level security;

revoke all on public.assessments, public.plans, public.findings, public.kill_switch, public.audit_log from anon, authenticated;
revoke all on function public.audit_log_immutable() from anon, authenticated, public;
