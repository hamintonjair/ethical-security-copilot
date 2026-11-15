-- Herramientas de bloqueo (firewall/iptables-ufw, nginx, Cloudflare) que el humano marca como
-- disponibles al abrir o editar el caso. Solo preselecciona qué genera el plan de contención
-- por defecto; nunca se aplica nada por sí sola ni sustituye poder elegir "todas".
alter table public.incidents add column if not exists containment_targets text[] not null default '{}';
