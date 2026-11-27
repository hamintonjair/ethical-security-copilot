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
Para practicar sin tocar sistemas reales, hay un objetivo ficticio local:

    docker compose up -d     # objetivo ficticio en 172.28.0.10 (red aislada, sin Internet)
Usa `mode: "lab"`; el Policy Engine solo admite localhost, `*.lab.internal` y 172.28.0.0/16. Solo funciona
corriendo el servidor ESC en tu propia máquina (no desde la consola desplegada en Render).

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
- La consola también puede lanzar módulos y usar el kill switch directamente (no solo por MCP): `POST /api/assessments/:id/scan` y `POST /api/scan/stop` (authorizer, operator), con la misma lógica compartida de alcance, ventana, ritmo y aprobación de plan (`src/scan.ts`).
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

Herramientas MCP: `incident_open` (solo autorizador/operador), `incident_types_set`, `incident_targets_set`, `incident_evidence_analyze`, `incident_contain_plan`, `incident_report`.

**Herramientas de bloqueo disponibles.** Igual que el tipo de incidente, el caso puede marcar (al abrirlo o después con "Marcar / editar herramientas de bloqueo") cuáles herramientas de contención tiene el equipo: firewall/`iptables`-`ufw`, Nginx o Cloudflare. Es solo una preselección — si no se marca ninguna, el plan de contención se genera igualmente para las tres; si se marcan una o varias, "Generar reglas de bloqueo" solo produce esas. Nunca se aplica nada por sí sola.

**Tipo de incidente (check-out humano + detección automática).** Cada caso puede marcarse con uno o varios tipos (phishing, intrusión en la red, malware/ransomware, DDoS, fuga de datos, acceso no autorizado, ataque web, otro). Dos caminos, ambos sin saltarse al humano:
- **Manual**: al abrir el caso, o después con "Marcar / editar tipos", el humano marca los checkboxes que correspondan (`incident_types_set`).
- **Automático (solo sugerencia)**: al analizar cada evidencia, `incident_evidence_analyze` también devuelve `suggestedTypes` — tipos que el sistema detecta por los patrones ya reconocidos (SPF/DKIM/DMARC fallidos, fuerza bruta, inyección, exfiltración, etc.), cada uno con su razón. La sugerencia nunca se guarda sola: la consola la muestra junto con las opciones de bloqueo de ese tipo y dos botones, "Marcar estos tipos" u "Omitir" — el humano decide.

Una vez marcado un tipo (manual o aceptando la sugerencia), el caso muestra su guía de contención curada ("Opciones de bloqueo") para ese tipo, pensada para que el equipo la ejecute en su propia infraestructura — nunca se aplica desde la plataforma.

**Recuperación supervisada de Facebook.** Al marcar `facebook_account_takeover`, el incidente ofrece un flujo para confirmar el consentimiento del titular, abrir los canales oficiales, recuperar primero el correo o teléfono asociado cuando haga falta y separar la cuenta personal de los activos empresariales. El titular opera Facebook e introduce directamente cualquier contraseña, código, CAPTCHA o documento. La consola no accede a sesiones de Meta ni automatiza la verificación de identidad; Facebook conserva esa decisión. Para activos empresariales, otro administrador legítimo puede revisar permisos y el titular puede contactar el soporte que tenga disponible.

**Exportar a PDF.** Tanto el informe de un incidente (`GET /api/incidents/:id/report?format=pdf`) como la vista previa del informe de una evaluación (`GET /api/assessments/:id/report?format=pdf&includeStates=...`) se pueden descargar en PDF con un clic ("Descargar PDF" en la consola) — útil para entregar a un cliente o adjuntar a una denuncia ante el CSIRT. La descarga de la evaluación es siempre una vista previa: no avanza el ciclo ni reemplaza el "Cerrar informe" (que sigue firmando y cambiando el estado).

## Cadena de suministro (SBOM + vulnerabilidades conocidas)

Pestaña **Cadena de suministro** dentro de cada evaluación. Pegas el manifiesto de dependencias de un proyecto (`package-lock.json`, `package.json`, `requirements.txt`, o una lista manual `nombre@versión` para cualquier otro ecosistema) y la plataforma genera el SBOM y lo cruza contra [OSV.dev](https://osv.dev) para detectar vulnerabilidades conocidas (CVE/GHSA). Es puramente pasivo: no instala ni ejecuta nada, y ningún hallazgo se guarda solo — "Registrar hallazgo" solo prellena el formulario para que un humano confirme severidad y CVSS.

Herramienta MCP: `supply_chain_analyze` (autorizador, operador, analista, agente). Ruta web: `POST /api/assessments/:id/supply-chain`.

## Módulo de IA por API (además de MCP)

Segunda forma de conectar un modelo de IA, integrada en la propia consola, sin necesitar un cliente MCP aparte. No tiene que ser Anthropic: en *Configuración → Integración IA* un autorizador elige el **proveedor** (Anthropic/Claude, cualquier API **compatible con OpenAI** —OpenAI, Azure OpenAI, un proxy propio, etc., con URL base configurable— o **Google Gemini**), pega su llave y pulsa "Cargar modelos" para elegir el modelo de una lista real obtenida en vivo de esa API (con respaldo para escribir el id a mano si la carga falla). La llave se cifra con AES-256-GCM y nunca se devuelve ni se registra. Los campos de proveedor/URL/llave/modelo solo aparecen una vez marcado "Activar el módulo de IA". Desde ahí, el panel *Asistente de IA* de cada incidente deja pedirle a la IA que analice la evidencia, genere el plan de contención o el informe, en lenguaje natural — con el mismo ciclo de herramientas sea cual sea el proveedor elegido.

Disponible en dos lugares, en un panel *Asistente de IA* fijo en la columna derecha (se mantiene a la vista mientras se desplaza el resto de la página; en pantallas angostas pasa a una sola columna):
- **Incidentes**: analizar evidencia, generar el plan de contención y el informe (`incident_evidence_analyze`, `incident_contain_plan`, `incident_report`), y marcar tipos de incidente o herramientas de bloqueo disponibles (`incident_types_set`, `incident_targets_set`) **solo** tras la confirmación explícita del humano en el chat. Nunca abre ni cierra un incidente.
- **Evaluaciones**: validar alcance (`scope_validate`), lanzar un módulo (`scan_initiate`) **solo** cuando el humano lo pida explícitamente en el chat — en modo activo o si el módulo cambia estado, la primera llamada no ejecuta nada: devuelve un plan `pending_approval` que un humano (`operator`) debe aprobar aparte con un token de un solo uso, exactamente igual que por MCP o por la consola —, detener todo con el kill switch (`scan_stop`), analizar cadena de suministro (`supply_chain_analyze`), registrar hallazgos y redactar un borrador del informe (`finding_create`, `report_generate`). Nunca abre ni cierra la evaluación ni aprueba un plan por su cuenta — eso sigue siempre a cargo de un humano.

En ambos casos, el asistente actúa con exactamente los mismos permisos que ya tenía el rol `agent` por MCP — ni una herramienta más. Cada acción que dispara queda en el mismo registro de auditoría encadenado, con el actor `ia-modulo:<usuario>`.

**Chat de creación** (listados de *Incidentes* y *Evaluaciones*): antes de que el caso exista, se puede conversar con la IA para armarlo — describe lo que pasa (o lo que quieres evaluar) y ella pregunta lo que falte. Ni `incident_open` ni `assessment_create` están en `RolePermissions.agent` (abrir un caso o crear una autorización lo decide siempre un humano, nunca la IA por su cuenta), así que este chat **no abre ni crea nada**: solo arma un borrador (`incident_draft` / `assessment_draft`) que el humano revisa y confirma con un clic — ese clic llama a la misma ruta humana de siempre (`POST /api/incidents` o `/api/assessments`, con el mismo permiso de rol de siempre). Al confirmar, la conversación que lo originó pasa a ser el historial de IA del caso nuevo, así que "continúa" sin cortes dentro de él.

## Alertas por webhook

Estrictamente informativo: la plataforma nunca actúa sola a partir de una alerta, solo avisa. Un
authorizer las activa en *Configuración → Alertas por webhook*: define una URL propia (un endpoint
suyo, o un servicio como n8n, un webhook de Slack/Teams, etc.) y un umbral de severidad mínimo. A
partir de ahí, un POST en JSON se envía cuando:

- se registra un **hallazgo** (`finding_create`, por MCP o por la consola) de severidad igual o
  superior al umbral elegido;
- se **abre un incidente** (si la opción "Avisar también al abrir un incidente" está activa).

El cuerpo lleva `type`, `title`, `severity`, `asset`, `assessmentId`/`incidentId`/`findingId` y
`url` (enlace a la consola, cuando se conoce el host público). Si se define un secreto, cada envío
incluye la cabecera `X-ESC-Signature` con un HMAC-SHA256 del cuerpo para que el endpoint propio
verifique el origen; el secreto se guarda cifrado (AES-256-GCM), igual que la llave del módulo de
IA. Hay un botón "Enviar alerta de prueba" para comprobar la entrega sin esperar a un hallazgo
real. Un fallo o una caída del webhook nunca rompe el flujo principal — solo queda auditado
(`alert:sent` / `alert:failed`).

