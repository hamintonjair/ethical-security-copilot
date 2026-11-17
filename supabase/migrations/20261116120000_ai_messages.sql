-- Historial de preguntas/respuestas del Asistente de IA (incidentes y evaluaciones), para que no se
-- pierda al recargar la página. Solo texto; la IA nunca escribe aquí nada que el humano no haya pedido.
create table if not exists public.ai_messages (
  id uuid primary key default gen_random_uuid(),
  subject_type text not null check (subject_type in ('incident', 'assessment')),
  subject_id text not null,
  question text not null,
  answer text not null,
  actor text not null,
  created_at timestamptz not null default now()
);
create index if not exists ai_messages_subject_idx on public.ai_messages (subject_type, subject_id, created_at);
alter table public.ai_messages enable row level security;
revoke all on public.ai_messages from anon, authenticated;
