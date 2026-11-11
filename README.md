# Ethical Security Copilot (MCP)

Servidor MCP que ejecuta comprobaciones técnicas **solo dentro de una autorización firmada**. El alcance se verifica en el backend antes de cada operación; lo que diga el chat no autoriza nada.

## Instalación y pruebas
    npm install
    npm test            # 22 pruebas (unitarias, E2E MCP y proceso stdio real). Requiere Node >= 22.13

## Secretos
    export ESC_SIGNING_KEY=$(openssl rand -hex 32)   # firma de autorizaciones; sin valor por defecto
    export ESC_DB=./esc.db
Guarda la clave fuera del repositorio. Si cambia, las autorizaciones existentes quedan inválidas (firma no coincide).

## Roles y canales
- Humano (CLI): `npx tsx src/cli.ts create-assessment a.json | advance <id> <estado> | approve <planId> | release-kill-switch | verify-audit`
- Agente (LLM, MCP): `ESC_ROLE=agent npx tsx src/main.ts` — no puede crear autorizaciones, aprobar ni liberar el kill switch.

Ciclo: `draft → scope_validated → planned → approved` (humano) → ejecución (agente, con aprobación por plan en modo activo o si el módulo cambia estado) → `report_generate` lleva a `reported`.

## Configuración en un cliente MCP
    { "mcpServers": { "ethical-security-copilot": { "command": "npx", "args": ["tsx", "src/main.ts"],
      "env": { "ESC_ROLE": "agent", "ESC_DB": "./esc.db", "ESC_SIGNING_KEY": "<tu clave>" } } } }

## Laboratorio
    docker compose up -d     # objetivo ficticio en 172.28.0.10 (red aislada, sin Internet)
Usa `mode: "lab"`; el Policy Engine solo admite localhost, `*.lab.internal` y 172.28.0.0/16.

## Límites
Módulos integrados sin shell (TCP connect, HEAD HTTP, análisis estático). Los hard limits (DoS, fuerza bruta, exfiltración, persistencia, movimiento lateral) se bloquean por diseño. Firma HMAC local; para separar autorizador y servidor, migrar a Ed25519.
