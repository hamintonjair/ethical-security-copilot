-- Tipos de incidente: el humano los marca (check-out) al abrir o editar el caso. La detección
-- automática (src/incident.ts: suggestIncidentTypes) solo sugiere a partir de la evidencia; nunca
-- escribe esta columna por sí sola.
alter table public.incidents add column if not exists types text[] not null default '{}';
