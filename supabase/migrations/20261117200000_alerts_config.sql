-- Alertas salientes (webhook) para hallazgos de severidad alta/crítica y apertura de incidentes.
-- Fila única (id=1): un authorizer la configura desde Configuración. El secreto de firma (si se
-- define) se cifra en el servidor igual que la llave del módulo de IA; nunca en texto plano.
-- Es estrictamente informativo: la plataforma nunca actúa sola a partir de una alerta, solo avisa.
create table if not exists public.alerts_config (
  id smallint primary key default 1 check (id = 1),
  enabled boolean not null default false,
  webhook_url text,
  min_severity text not null default 'high' check (min_severity in ('info', 'low', 'medium', 'high', 'critical')),
  notify_incident_open boolean not null default true,
  secret_enc text,
  secret_last4 text,
  updated_by text,
  updated_at timestamptz
);
insert into public.alerts_config (id) values (1) on conflict (id) do nothing;
alter table public.alerts_config enable row level security;
revoke all on public.alerts_config from anon, authenticated;
