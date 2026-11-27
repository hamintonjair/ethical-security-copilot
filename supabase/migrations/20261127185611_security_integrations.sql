-- Fuentes de telemetría para recibir alertas externas mediante webhooks firmados.
-- El secreto se cifra con ESC_SIGNING_KEY; el valor en claro solo se muestra al crearlo/rotarlo.
create table if not exists public.security_integrations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  provider text not null check (provider in ('generic', 'google_workspace', 'microsoft', 'wazuh', 'cloudflare', 'other')),
  secret_enc text not null,
  secret_last4 text not null,
  enabled boolean not null default true,
  created_by text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.security_events (
  id uuid primary key default gen_random_uuid(),
  integration_id uuid not null references public.security_integrations(id),
  external_event_id text not null,
  observed_at timestamptz not null,
  severity text not null check (severity in ('info','low','medium','high','critical')),
  category text not null,
  title text not null,
  asset text,
  summary text not null,
  event_data jsonb not null default '{}',
  received_at timestamptz not null default now(),
  unique (integration_id, external_event_id)
);
create index if not exists security_events_received_idx on public.security_events (received_at desc);
create index if not exists security_events_severity_idx on public.security_events (severity, received_at desc);
alter table public.security_integrations enable row level security;
alter table public.security_events enable row level security;
revoke all on public.security_integrations, public.security_events from anon, authenticated;
