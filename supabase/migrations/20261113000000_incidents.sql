-- Sesión de Respuesta a Incidentes / Defensa Activa. Solo analiza evidencia que la empresa aporta
-- y genera reglas/informes para que ELLOS los apliquen en su propia infraestructura; no toca ninguna red.
create table if not exists public.incidents (
  id uuid primary key default gen_random_uuid(),
  organization text not null,
  contact_name text not null,
  contact_email text not null,
  summary text not null,
  affected_assets jsonb not null default '[]',
  status text not null default 'open' check (status in ('open','contained','closed')),
  created_by text not null,
  created_at timestamptz not null default now(),
  closed_at timestamptz
);
create table if not exists public.incident_evidence (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  kind text not null check (kind in ('log','email_headers','other')),
  description text not null,
  redacted_content text not null,
  iocs jsonb not null default '{}',
  created_by text not null,
  created_at timestamptz not null default now()
);
create index if not exists incident_evidence_incident_idx on public.incident_evidence (incident_id);
alter table public.incidents enable row level security;
alter table public.incident_evidence enable row level security;
revoke all on public.incidents, public.incident_evidence from anon, authenticated;
