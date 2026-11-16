-- Soporte multi-proveedor para el módulo de IA por API: además de Anthropic, OpenAI y
-- cualquier endpoint compatible con OpenAI o con la API de Gemini, con URL base configurable
-- (por defecto se usa la URL oficial de cada proveedor si se deja en blanco).
alter table public.ai_config add column if not exists base_url text;
