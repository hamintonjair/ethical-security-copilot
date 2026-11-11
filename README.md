# Ethical Security Copilot (MCP)

Servidor MCP que ejecuta comprobaciones técnicas **solo dentro de una autorización firmada**. El alcance se verifica en el backend antes de cada operación; lo que diga el chat no autoriza nada.

## Instalación y pruebas
    npm install
    npm test            # 24 pruebas sobre Postgres en proceso (PGlite) con el esquema real de supabase/migrations. Node >= 22

## Secretos
    export ESC_SIGNING_KEY=$(openssl rand -hex 32)   # firma de autorizaciones; sin valor por defecto
    export ESC_DATABASE_URL='postgres://postgres:<CLAVE>@db.<ref>.supabase.co:5432/postgres'   # Supabase (conexión directa o pooler)
Guarda ambos valores fuera del repositorio (nunca en el chat ni en Git). La conexión a Supabase exige TLS verificado. Si cambia, las autorizaciones existentes quedan inválidas (firma no coincide).

## Roles y canales
- Humano (CLI): `npx tsx src/cli.ts create-assessment a.json | advance <id> <estado> | approve <planId> | release-kill-switch | verify-audit`
- Agente (LLM, MCP): `ESC_ROLE=agent npx tsx src/main.ts` — no puede crear autorizaciones, aprobar ni liberar el kill switch.

Ciclo: `draft → scope_validated → planned → approved` (humano) → ejecución (agente, con aprobación por plan en modo activo o si el módulo cambia estado) → `report_generate` lleva a `reported`.

## Configuración en un cliente MCP
    { "mcpServers": { "ethical-security-copilot": { "command": "npx", "args": ["tsx", "src/main.ts"],
      "env": { "ESC_ROLE": "agent", "ESC_DATABASE_URL": "<url>", "ESC_SIGNING_KEY": "<tu clave>" } } } }

## Base de datos (Supabase / Postgres)
El esquema vive en `supabase/migrations/` (auditoría append-only, RLS sin políticas, permisos revocados a `anon`/`authenticated`). Solo el servidor y el CLI deben conectarse, con credenciales privadas; no expongas estas tablas por la API pública. Las pruebas usan el mismo SQL sobre PGlite.

## Laboratorio
    docker compose up -d     # objetivo ficticio en 172.28.0.10 (red aislada, sin Internet)
Usa `mode: "lab"`; el Policy Engine solo admite localhost, `*.lab.internal` y 172.28.0.0/16.

## Límites
Módulos integrados sin shell (TCP connect, HEAD HTTP, análisis estático). Los hard limits (DoS, fuerza bruta, exfiltración, persistencia, movimiento lateral) se bloquean por diseño. Firma HMAC con clave en el entorno; para separar autorizador y servidor, migrar a Ed25519.
