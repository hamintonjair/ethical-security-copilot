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


## Alojar en Render (transporte HTTP)
El servidor HTTP (`dist/http.js`) es sin estado, con token Bearer y rol fijado por el servidor (solo `agent`, `analyst` o `auditor`; autorizar y aprobar se hace siempre con el CLI, nunca por la red).

Build: `npm ci --include=dev && npm run build` · Start: `npm start` · Health check: `/healthz`

Variables de entorno (créalas en el panel de Render; **nunca** en el repositorio):
| Variable | Contenido |
|---|---|
| `ESC_SIGNING_KEY` | Clave de firma (mín. 32 car.). Debe ser la **misma** que uses en el CLI. |
| `ESC_HTTP_TOKEN` | Token Bearer de los clientes MCP (mín. 32 car.). |
| `ESC_DATABASE_URL` | Cadena del **Session pooler** de Supabase (Render no tiene IPv6; la conexión directa de Supabase sí lo exige). |
| `ESC_DATABASE_CA` | Certificado CA de Supabase en PEM (Database → Settings → SSL configuration). TLS siempre se verifica. |
| `ESC_ALLOWED_HOSTS` | Opcional: dominios propios adicionales. `RENDER_EXTERNAL_HOSTNAME` ya se acepta. |

Cliente MCP remoto: URL `https://<servicio>.onrender.com/mcp` con cabecera `Authorization: Bearer <ESC_HTTP_TOKEN>`.
Para el CLI humano apunta a la misma base: `ESC_DATABASE_URL=… ESC_SIGNING_KEY=… npx tsx src/cli.ts …`.

## Interfaz web

Consola en `/app/` (misma instancia que el MCP en `/mcp`): panel, evaluaciones con ciclo de vida, planes (aprobación humana), hallazgos, informes, auditoría con verificación de la cadena y gestión de usuarios.

- Cuentas propias (usuario + contraseña, scrypt), sesión con cookie `HttpOnly`/`SameSite=Strict`, token CSRF, bloqueo tras 5 fallos y cierre por inactividad (30 min).
- Roles: `authorizer`, `operator`, `analyst`, `auditor`.
- Primer usuario (una sola vez, desde tu equipo, con la misma `ESC_DATABASE_URL` y `ESC_SIGNING_KEY` que Render):

```bash
ESC_DATABASE_URL="..." ESC_SIGNING_KEY="..." npx tsx src/cli.ts create-user <usuario> authorizer
```

La contraseña se pide oculta y deberá cambiarse al primer acceso. Otros comandos: `reset-password`, `unlock-user`, `list-users`.

## Conectar Claude (OAuth)

El servidor MCP acepta, además del token fijo `ESC_HTTP_TOKEN`, OAuth 2.1 con PKCE (registro dinámico de clientes). En Claude: *Conectores → Agregar conector personalizado* con `https://<tu-servicio>.onrender.com/mcp`. Se abrirá la consola para que un **authorizer** inicie sesión y apruebe la conexión. El token resultante solo da el rol de agente del MCP (nunca permisos de la consola), caduca en 1 h con refresh rotatorio, y deja de valer si esa cuenta se deshabilita o deja de ser authorizer.

## Módulos y manual

Módulos incluidos: `config_audit`, `tcp_port_check`, `http_header_audit`, `tls_audit`, `cookie_audit`, `cors_audit`, `http_methods_audit`, `dns_email_audit`, `exposed_files_audit` y `lab_write_probe`. Todos son de solo lectura o de impacto mínimo y pasan por el Gateway (alcance, ventana, ritmo, kill switch).

El manual de uso (conceptos, flujo, catálogo de módulos, mapa de cobertura frente a OWASP/MITRE, solución de problemas) está en [`web/manual.md`](web/manual.md) y en el menú **Manual** de la consola.

## Incidentes: Respuesta a Incidentes / Defensa Activa

Sesión aparte de las evaluaciones, para cuando la organización está siendo atacada ahora mismo. Analiza evidencia que tú aportas (logs, cabeceras de correo) para extraer IOCs y patrones de ataque, genera reglas de contención (iptables, ufw, nginx, Cloudflare) y el informe del caso con guía de a quién reportarlo. No toca ninguna red: las reglas se generan para que el propio equipo las aplique en su infraestructura.

Herramientas MCP: `incident_open` (solo autorizador/operador), `incident_evidence_analyze`, `incident_contain_plan`, `incident_report`.

## Módulo de IA por API (además de MCP)

Segunda forma de conectar un modelo de IA, integrada en la propia consola, sin necesitar un cliente MCP aparte. Un autorizador guarda su llave de Anthropic en *Configuración → Integración IA* (se cifra con AES-256-GCM, nunca se devuelve ni se registra). Desde ahí, el panel *Asistente de IA* de cada incidente deja pedirle a la IA que analice la evidencia, genere el plan de contención o el informe, en lenguaje natural.

Disponible en dos lugares, con el mismo panel *Asistente de IA*:
- **Incidentes**: analizar evidencia, generar el plan de contención y el informe (`incident_evidence_analyze`, `incident_contain_plan`, `incident_report`). Nunca abre ni cierra un incidente.
- **Evaluaciones** (pestaña Hallazgos): registrar hallazgos nuevos y redactar un borrador del informe (`finding_create`, `report_generate`). Nunca lanza un módulo contra una red real ni aprueba ningún plan — eso sigue siempre a cargo de un humano.

En ambos casos, el asistente actúa con exactamente los mismos permisos que ya tenía el rol `agent` por MCP. Cada acción que dispara queda en el mismo registro de auditoría encadenado, con el actor `ia-modulo:<usuario>`.
