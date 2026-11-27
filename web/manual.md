# Manual de uso

## 1. Qué es esta herramienta

Ethical Security Copilot ayuda a revisar la seguridad de sistemas **que tienes autorización para probar**. Un agente de IA (Claude) hace el trabajo técnico, pero **no puede salirse de lo que tú autorizaste**: el servidor revisa cada paso contra la autorización antes de tocar la red.

Principio rector: **sin autorización firmada, alcance claro y una persona al mando, no se ejecuta nada.**

- Tú decides qué se puede probar, cuándo y con qué ritmo.
- El agente propone y ejecuta, pero no puede ampliar el alcance, aprobar sus propios planes activos ni liberar el kill switch.
- Todo queda en un registro de auditoría encadenado por huellas; si alguien lo altera, se detecta.

## 2. Conceptos básicos

- **Evaluación**: la autorización. Guarda quién autoriza, el alcance, las exclusiones, la ventana de tiempo, los límites de ritmo y los módulos permitidos. Está firmada: cualquier cambio posterior invalida la firma.
- **Alcance**: lo único que se puede probar (IP, rango, dominio, URL). Una URL autoriza peticiones web a esa dirección; **no** autoriza conexiones TCP al servidor. Para eso hay que añadir el dominio o la IP.
- **Exclusiones**: activos o técnicas que nunca se tocan, aunque estén dentro del alcance.
- **Ventana**: fechas, horario opcional y límites (peticiones por segundo, paralelismo, tope total).
- **Modos**:
  - *Pasivo*: analiza datos que tú aportas. No usa la red.
  - *Laboratorio*: solo localhost o tu red de pruebas (Docker).
  - *Activo controlado*: contra sistemas reales. Cada plan necesita tu aprobación.
- **Módulo**: una prueba concreta y acotada (ver sección 6).
- **Plan**: en modo activo, el agente primero propone un plan. Tú lo apruebas y obtienes un **token de un solo uso** que sirve únicamente para ese plan.
- **Hallazgo**: un problema registrado. Separa **hechos observados** (lo que se vio) de **hipótesis de riesgo** (lo que podría pasar, sin verificar). La evidencia se redacta: credenciales, tokens y datos personales se enmascaran.
- **Kill switch** («Detener todo»): corta de inmediato cualquier ejecución. Cualquier operador puede activarlo; solo un autorizador lo libera.
- **Auditoría**: registro de solo-añadir de todo lo que pasa. El botón *Verificar cadena* recalcula las huellas.

## 3. Roles

| Rol | Puede |
|---|---|
| Autorizador | Crear evaluaciones, avanzar el ciclo, aprobar planes, liberar el kill switch, gestionar usuarios, ver auditoría. |
| Operador | Aprobar o rechazar planes, activar el kill switch, registrar hallazgos, ver auditoría. |
| Analista | Registrar hallazgos, hacer triaje y generar informes. |
| Auditor | Solo lectura, con acceso a la auditoría. |

El agente (Claude) tiene su propio rol, limitado: puede validar alcances, proponer y lanzar ejecuciones dentro de evaluaciones ya aprobadas, y registrar hallazgos.

## 4. Primeros pasos

1. **Entra** en la consola con tu usuario. Si entraste con una contraseña temporal, la consola te pedirá cambiarla (mínimo 12 caracteres; una frase larga es mejor que una palabra con símbolos).
2. **Conecta a Claude**: en Claude, *Conectores → Agregar conector personalizado* con la dirección `/mcp` de tu servidor. Se abrirá la consola para que un autorizador pulse *Permitir conexión*. El acceso caduca cada hora y se renueva solo.
3. **Crea tu primera evaluación** (sección 5).

## 5. Flujo completo, paso a paso

1. **Nueva evaluación**: nombre, quién autoriza, modos, alcance, exclusiones, ventana y módulos. Empieza con lo mínimo necesario: alcance estrecho, ritmo bajo (5 peticiones por segundo) y ventana corta.
2. **Avanzar el ciclo** (pestaña *Ciclo de vida*): *Validar alcance → Pasar a planificación → Aprobar la evaluación*. Hasta aprobarla, el agente no puede ejecutar nada.
3. **Pedirle a Claude** que trabaje (ejemplos en la sección 8). Primero valida el alcance; después propone la ejecución.
4. **Aprobar el plan** (solo modo activo): pestaña *Planes* → revisar módulo, objetivos y límites → *Aprobar* → copiar el token de un solo uso y dárselo a Claude. Si algo no te convence, *Rechazar*.
5. **Revisar hallazgos**: pestaña *Hallazgos*. Haz el triaje de cada uno: *Confirmado*, *Falso positivo* o *Riesgo aceptado*.
6. **Informe**: pestaña *Informe*. Elige qué estados incluir, mira la *Vista previa* y, si está bien, *Cerrar informe*.
7. **Cerrar la evaluación** desde *Ciclo de vida*.

Si cambias el alcance, usa **Nueva versión del alcance**: vuelve a borrador, se anulan las aprobaciones de planes anteriores y hay que repetir el ciclo. Los hallazgos ya registrados se conservan.

## 6. Incidentes: Respuesta a Incidentes / Defensa Activa

Para cuando a la organización la están atacando **ahora mismo**. Es una sesión aparte de las evaluaciones, pensada para la urgencia. Mantiene el mismo límite ético: **nunca toca la red de nadie**, ni la del atacante ni la tuya. Solo analiza lo que tú le pegas (logs, cabeceras de correo) y genera reglas e informes para que **tu propio equipo** los aplique en **su propia infraestructura**. Cerrar el paso, no contraatacar: entrar a los sistemas del atacante es ilegal (en Colombia, Ley 1273 de 2009) aunque haya empezado él.

1. **Abrir el caso** (autorizador u operador): organización, quién reporta, qué está pasando, activos afectados y, opcionalmente, el **tipo de incidente** (ver más abajo) y las **herramientas de bloqueo** con las que ya cuenta el equipo (firewall/`iptables`-`ufw`, Nginx, Cloudflare). Ambas son opcionales y editables después, desde el resumen del caso, con "Marcar / editar tipos" y "Marcar / editar herramientas de bloqueo".
2. **Añadir evidencia**: pega líneas de log o las cabeceras completas de un correo sospechoso. Se analiza al instante:
   - **Logs**: extrae IPs, dominios, URLs y hashes; detecta patrones de inyección SQL, XSS, path traversal, inyección de comandos, rastreo de rutas sensibles, firmas de herramientas de escaneo (sqlmap, nikto, nmap…) y fuerza bruta/credential stuffing (5+ fallos de autenticación desde la misma IP).
   - **Cabeceras de correo**: compara el remitente visible (`From`) con el real (`Return-Path`) y `Reply-To`, y lee `Authentication-Results` para ver si SPF/DKIM/DMARC fallaron. Es la forma más rápida de confirmar un phishing en curso.
   - El contenido se guarda redactado (sin credenciales ni tokens) y nunca se muestra más allá de lo necesario.
3. **Tipo de incidente: check-out humano + detección automática.** El caso se puede etiquetar con uno o varios tipos (phishing, intrusión en la red, malware/ransomware, DDoS, fuga de datos, acceso no autorizado, ataque web, otro):
   - **Manual (check-out)**: tú marcas los checkboxes del tipo que corresponda, al abrir el caso o después con "Marcar / editar tipos" en el resumen. Es la vía normal y la única que decide algo por sí misma.
   - **Automático**: cada vez que analizas evidencia, el sistema detecta por sí solo qué tipo(s) encajan según los patrones hallados (p. ej. SPF/DKIM/DMARC fallidos → phishing; fuerza bruta/inyección → ataque web; muchas IPs simultáneas → DDoS) y te los **sugiere** con su razón, junto con las opciones de bloqueo de ese tipo. **Nunca se marca solo**: aparecen dos botones, "Marcar estos tipos" (lo confirmas tú) u "Omitir" — el humano siempre tiene la última palabra.
   - En cuanto un tipo queda marcado (a mano o aceptando la sugerencia), el caso muestra su propia guía curada de **opciones de bloqueo** para ese tipo exacto — contención pensada para que tu equipo la ejecute en su infraestructura, nunca aplicada desde aquí.
   - **Facebook comprometido**: marca "Robo de cuenta de Facebook / Meta" para abrir la recuperación supervisada. Confirma que el titular autorizó la ayuda, acompáñalo por la recuperación oficial, recupera primero su correo o teléfono si también perdió acceso y revisa por separado los activos empresariales. El titular opera Facebook y completa directamente contraseñas, códigos, CAPTCHA o verificaciones de identidad; la plataforma no puede suplantarlo ni restaurar la cuenta por sí sola.
   - **Asistencia de IA para cualquier tipo marcado**: dentro de cada tipo puedes pedir un plan contextual. La IA separa el análisis que puede hacer en la plataforma, las tareas del titular/equipo y los cambios que requieren aprobación humana. El botón prepara el plan; no aplica bloqueos ni modifica cuentas o sistemas.
4. **Plan de contención**: con las IPs/dominios acumulados de toda la evidencia, genera reglas listas para pegar: `iptables`, `ufw`, un bloque `nginx deny`, una regla de Cloudflare (Firewall Rules / WAF) y una lista de dominios sospechosos. Si marcaste herramientas de bloqueo al abrir el caso (o las editaste después), "Generar reglas de bloqueo" solo produce esas; si no marcaste ninguna, las genera para las tres. **Nada se ejecuta**: las aplicas tú mismo en tu firewall, tu servidor o tu panel.
5. **Informe**: línea de tiempo de la evidencia, todos los IOCs acumulados, y a quién reportar: el *abuse contact* del hosting del atacante (`whois <ip>`), el CSIRT nacional (**colCERT** en Colombia, más la Policía Nacional - Centro Cibernético, para denuncia formal), o el CERT de tu país si no es Colombia. Incluye cómo preservar evidencia para una denuncia. El botón "Descargar PDF" genera un documento listo para adjuntar a esa denuncia o enviar al cliente.
6. **Estados**: *Abierto → Contenido → Cerrado*. Un incidente cerrado no admite más evidencia, ni se le pueden cambiar los tipos, ni se puede reabrir.

Pídeselo a Claude, por ejemplo: «Analiza este log del incidente `<id>` y dime qué encuentra», «Genera el plan de contención con las IPs que ya encontramos» o «¿Qué tipo de incidente sugiere esta evidencia y qué opciones de bloqueo tiene?».

## 7. Catálogo de módulos

Todos son de solo lectura o de impacto mínimo. Ninguno explota vulnerabilidades. Las referencias son del OWASP Top 10 2025 (A0x), OWASP API Top 10 2023 (APIx) y CWE.

### Análisis de configuración (`config_audit`)
- **Modos**: pasivo, laboratorio, activo. No usa la red.
- **Parámetro**: `content` (texto de configuración, hasta 100 KB).
- **Qué detecta**: SSH con root o contraseña, TLS obsoleto en nginx, listado de directorios, banners de versión, CORS abierto, modo debug y posibles credenciales en texto claro. (A02, A04)
- **Consejo**: pega la configuración sin contraseñas reales.

### Prueba de puertos TCP (`tcp_port_check`)
- **Modos**: laboratorio, activo. **Parámetro**: `ports` (hasta 32, por defecto 80 y 443).
- **Qué hace**: intenta conectar; no envía datos. Estados: abierto, cerrado, filtrado.
- **Cómo leerlo**: lo importante es lo que *no* debería estar expuesto (SSH, bases de datos, paneles). Detrás de un CDN describe al CDN, no a tu servidor. (A02)

### Cabeceras HTTP (`http_header_audit`)
- **Modos**: laboratorio, activo. **Objetivo**: URL.
- **Qué revisa**: CSP, X-Content-Type-Options, X-Frame-Options, HSTS (y su vigencia), Referrer-Policy, Permissions-Policy y banners con versión. (A02, CWE-1021, CWE-693)

### Cifrado TLS y certificado (`tls_audit`)
- **Modos**: laboratorio, activo. **Objetivo**: dominio, IP o URL. **Parámetro opcional**: `port` (443 por defecto).
- **Qué revisa**: versión y cifrado negociados, vencimiento, confianza del certificado, clave RSA menor de 2048, aceptación de TLS 1.0/1.1 y soporte de TLS 1.3.
- **Límites**: no comprueba revocación (OCSP/CRL). Si este servidor no puede probar TLS 1.0/1.1, lo dice como «no concluyente». (A04, CWE-295, CWE-326, CWE-327)

### Cookies (`cookie_audit`)
- **Modos**: laboratorio, activo. **Objetivo**: URL.
- **Qué revisa**: Secure, HttpOnly y SameSite de las cookies que la página establece sin iniciar sesión. **Nunca guarda los valores.**
- **Límite**: solo ve las cookies de esa ruta anónima; no las de después del login. (A07, CWE-614, CWE-1004, CWE-352)

### CORS (`cors_audit`)
- **Modos**: laboratorio, activo. **Objetivo**: URL.
- **Qué revisa**: si el sitio refleja un origen ajeno o acepta `null`, si permite credenciales y si el preflight autoriza métodos de escritura. Son 3 peticiones. (A02, API8, CWE-942)

### Métodos HTTP (`http_methods_audit`)
- **Modos**: laboratorio, activo. **Objetivo**: URL.
- **Qué hace**: lee la cabecera `Allow` y prueba `TRACE`. **No envía PUT, DELETE ni PATCH**, porque cambian el estado del sistema. (A02, CWE-749)

### DNS y correo (`dns_email_audit`)
- **Modo**: solo activo. **Objetivo**: dominio (o URL con dominio).
- **Qué revisa**: SPF (`+all`, `?all`, `~all`, exceso de consultas), DMARC (ausente, `p=none`, `pct`, `rua`), DKIM en 6 selectores habituales, MTA-STS, CAA, servidores de nombres y MX.
- **Límites**: solo consulta nombres dentro del dominio autorizado. La ausencia de DKIM en esos selectores **no es concluyente**: el selector real puede ser otro. Es la base para evitar la suplantación y el phishing en nombre de tu dominio.

### Archivos expuestos (`exposed_files_audit`)
- **Modos**: laboratorio, activo. **Objetivo**: URL (se usa su origen).
- **Qué hace**: 13 rutas conocidas (`.git`, `.env`, `.htpasswd`, volcados SQL, copias `.zip`, `phpinfo`, `server-status`, Actuator…) más `security.txt`. Solo da positivo si **el contenido coincide con la firma del archivo**, así que una app de una sola página que responde 200 a todo no genera falsos positivos. **El contenido nunca se guarda ni se muestra.**
- **Si hay un positivo**: corrige el acceso y **rota cualquier secreto** que pudiera haber en el archivo. (A02, CWE-200, CWE-538, CWE-530)

### Escritura de laboratorio (`lab_write_probe`)
- **Modo**: solo laboratorio. Envía un POST inofensivo con un marcador. Cambia estado, por eso exige aprobación.

## 8. Módulo de IA dentro de la plataforma (además de MCP)

Hasta ahora, la única forma de que un modelo de IA razone sobre tus casos era conectar Claude por MCP desde tu propia cuenta. Esta sección añade una **segunda forma, por API**, integrada en la propia consola: tú guardas tu llave una sola vez y la plataforma la usa para ayudarte, sin que tengas que abrir Claude aparte. **No tiene que ser Anthropic**: funciona igual con cualquier API compatible con OpenAI o con Google Gemini.

- **Dónde se configura**: *Configuración → Integración IA* (solo un autorizador). Los campos de configuración solo aparecen después de marcar la casilla "Activar el módulo de IA".
  - **Proveedor**: elige entre *Anthropic (Claude)*, *Compatible con OpenAI* (OpenAI, Azure OpenAI, o cualquier endpoint propio que hable el mismo protocolo) o *Google Gemini*.
  - **URL base (opcional)**: déjala en blanco para usar la URL oficial del proveedor elegido; solo se cambia si usas un proxy o un endpoint propio.
  - **Llave de API**: se guarda cifrada (AES-256-GCM) con una llave derivada de `ESC_SIGNING_KEY`; nunca se devuelve ni se muestra completa, solo sus últimos 4 caracteres.
  - **Modelo**: pulsa *Cargar modelos* con la llave puesta para traer la lista real de modelos disponibles de esa cuenta/API y elegir uno del desplegable — ya no se escribe el nombre a mano. Si la carga falla (llave inválida, sin conexión), aparece el motivo y un botón *Escribir el id a mano* como respaldo.
  - El botón *Probar conexión* comprueba que la llave funciona con el proveedor y la URL elegidos, sin exponerla.
- **Dónde se usa**: en ambos módulos, el panel *Asistente de IA* vive fijo en la **columna derecha** de la pantalla (se mantiene a la vista mientras te desplazas por el resto de la página; en pantallas angostas pasa a mostrarse en una sola columna, debajo del contenido).
  - **Incidentes** → panel a la derecha en cada caso. Le escribes lo que necesitas («revisa la evidencia y dime qué hacer», «genera el plan de contención») y responde en lenguaje natural; puede analizar evidencia, generar reglas de contención, generar el informe, y marcar el tipo de incidente o las herramientas de bloqueo disponibles (las mismas herramientas que ya tenía el agente por MCP, incluidas `incident_types_set` e `incident_targets_set`) — pero nunca marca nada sin que tú se lo confirmes explícitamente en la conversación. La respuesta se muestra formateada (títulos, listas, negrita) en vez de texto plano, y cada pregunta con su respuesta queda guardada: al volver a abrir el caso o la evaluación, todo el historial de la conversación sigue ahí. Ese mismo historial se incluye, al final, en el informe (markdown, JSON o PDF) del incidente o de la evaluación, bajo "Historial del asistente de IA" — claramente marcado como análisis asistido por IA para apoyar la revisión humana, no como un hallazgo verificado ni una decisión de la plataforma.
  - **Evaluaciones** → mismo panel a la derecha, visible en cualquier pestaña. Puede validar alcance (`scope_validate`), registrar un hallazgo, redactar un borrador del informe, analizar cadena de suministro (`supply_chain_analyze`) y, lo nuevo, **lanzar un módulo** (`scan_initiate`) y **detener todo con el kill switch** (`scan_stop`) — exactamente el mismo conjunto que `RolePermissions.agent` ya tenía por MCP, ni una herramienta más. `scan_initiate` **solo** se dispara cuando tú se lo pides explícitamente en el chat (nunca por iniciativa propia ni como parte de una exploración); si el modo es activo o el módulo cambia estado, esa primera llamada no ejecuta nada: te avisa que hay un plan "pendiente de aprobación" con un `planId`, y un humano (`operator`) debe aprobarlo aparte y entregarle el token de un solo uso — igual que si lo hicieras por MCP o por la consola. El kill switch (`scan_stop`) detiene de inmediato cualquier ejecución en curso; después, solo un `authorizer` humano puede liberarlo.
- **Mismos límites que el rol `agent` de siempre**: en cada sesión, el asistente solo puede usar las herramientas que `RolePermissions.agent` ya tenía permitidas por MCP. **Nunca** puede abrir/cerrar un incidente o una evaluación, ni aprobar un plan por su cuenta: eso lo decide siempre un humano, con el mismo mecanismo de plan + token de un solo uso que ya exige MCP o la consola.
- **El humano sigue siendo quien decide**: el control no es una pantalla de confirmación aparte — es que la IA solo actúa cuando tú se lo pides explícitamente, por escrito, en la propia conversación; esa instrucción queda también en la auditoría.
- **Auditoría**: cada acción que dispara el asistente queda en el mismo registro encadenado, con el actor `ia-modulo:<usuario que preguntó>`, para distinguirla de lo hecho por MCP o a mano.
- **Costo**: las llamadas a la API del proveedor elegido las paga la cuenta dueña de la llave que configuraste; la plataforma no añade ningún cargo propio.
- **Chat de creación, antes de que el caso exista**: en los listados de *Incidentes* y de *Evaluaciones* hay un panel para conversar con la IA y armar el caso — cuéntale qué está pasando (o qué quieres evaluar) y te pregunta lo que falte. Ni `incident_open` ni `assessment_create` están en `RolePermissions.agent`: abrir un caso o crear una autorización lo decide siempre un humano, nunca la IA por su cuenta. Así que este chat no abre ni crea nada — solo arma un **borrador** que te muestra para revisar; recién al pulsar *Confirmar* se abre el caso (o se crea la evaluación como borrador), con el mismo permiso de rol de siempre. Esa misma conversación queda como el historial de IA del caso nuevo, así que al entrar a él la ves ahí mismo, continuada, sin tener que repetir nada.

## 8bis. Cadena de suministro: SBOM y vulnerabilidades conocidas (A03)

Dentro de cada evaluación, en la pestaña **Cadena de suministro**, puedes analizar las dependencias de un proyecto sin que la herramienta instale ni ejecute nada: solo lee el texto del manifiesto que le pegas y lo cruza contra [OSV.dev](https://osv.dev), la base pública de vulnerabilidades conocidas (incluye CVE y avisos de GitHub).

- **Qué formatos acepta**: `package-lock.json` (npm, lockfileVersion 1-3), `package.json` (limpia los rangos `^`/`~`), `requirements.txt` (Python/pip, requiere `==`), o una **lista manual** `nombre@versión` (una línea por paquete) con el ecosistema que elijas — así cubre cualquier otro lenguaje (Go, Java/Maven, Ruby, Rust, PHP, .NET…) aunque no tenga un parser dedicado.
- **Qué genera**: la lista de paquetes (SBOM) con su versión y ecosistema, y para cada uno las vulnerabilidades conocidas que le correspondan: su identificador (CVE/GHSA/OSV), un resumen y una severidad aproximada.
- **Qué NO hace**: no instala paquetes, no ejecuta código de ninguna dependencia, no toca la infraestructura de la organización, y **no registra ningún hallazgo por sí solo** — el botón *Registrar hallazgo* junto a cada dependencia vulnerable solo prellena el formulario de hallazgo (título, activo, hechos, recomendación) para que tú elijas la severidad y el puntaje CVSS y lo confirmes.
- **Quién puede usarlo**: autorizador, operador, analista, y el agente de IA por MCP o por el módulo de IA interno (con los mismos límites de siempre: nunca abre ni cierra nada por su cuenta).
- **Auditoría**: cada análisis queda registrado (`supply_chain:analyzed`) con cuántas dependencias se revisaron y cuántas resultaron vulnerables — el contenido del manifiesto no se guarda.

## 8ter. Alertas por webhook

Estrictamente informativo: avisa a un endpoint propio cuando pase algo que merece atención, pero
**nunca actúa por sí sola** — ni bloquea, ni contiene, ni cierra nada.

- **Dónde se configura**: *Configuración → Alertas por webhook* (solo un autorizador). Se activa con
  la casilla, se define la **URL del webhook** (tu propio endpoint, o un servicio como n8n, un
  webhook de Slack/Teams, etc.) y el **umbral de severidad** desde el que avisar para hallazgos
  (de "info" hasta "solo crítica"); aparte, una casilla decide si también avisa al abrirse un
  incidente.
- **Qué dispara una alerta**: registrar un hallazgo (`finding_create`, por MCP o por la consola) de
  severidad igual o mayor al umbral elegido, o abrir un incidente nuevo.
- **Qué lleva el envío**: un POST en JSON con `type` (`finding` o `incident_open`), `title`,
  `severity`, `asset`, los identificadores correspondientes (`assessmentId`/`incidentId`/
  `findingId`) y `url` (enlace directo a la consola, si se conoce el host público). Si defines un
  **secreto de firma**, cada envío incluye la cabecera `X-ESC-Signature` (HMAC-SHA256 del cuerpo)
  para que tu endpoint verifique que viene de aquí; el secreto se guarda cifrado, igual que la llave
  del módulo de IA.
- **Botón de prueba**: *Enviar alerta de prueba* dispara un envío de ejemplo sin esperar a un
  hallazgo real, para confirmar que la URL y la firma funcionan.
- **Si el webhook falla o no responde**: nunca rompe el flujo principal (el hallazgo o el incidente
  se crean igual); solo queda registrado en la auditoría (`alert:sent` o `alert:failed`).

## 9. Mapa de cobertura: del ataque a la defensa

La herramienta **no ataca**: encuentra las condiciones que los atacantes aprovechan y te dice cómo cerrarlas.

| Ataque o riesgo | Qué hace la herramienta hoy | Defensa clave |
|---|---|---|
| Acceso roto / mala configuración (A01, A02) | Cabeceras, métodos, archivos expuestos, CORS, configuración | Mínimo privilegio, endurecimiento, no exponer paneles ni archivos internos |
| Fallos criptográficos (A04) | Auditoría TLS, análisis de configuración | TLS 1.2+/1.3, certificados vigentes, HSTS, no guardar secretos en texto claro |
| Fallos de autenticación y sesión (A07) | Cookies (Secure/HttpOnly/SameSite) | MFA, contraseñas largas, bloqueo de intentos, cookies seguras |
| Suplantación y phishing (ATT&CK T1566) | SPF, DKIM, DMARC, MTA-STS | DMARC en `reject`, SPF con `-all`, formación de usuarios |
| Cadena de suministro (A03) | SBOM + cruce con vulnerabilidades conocidas (ver §8bis) | Fijar versiones, revisar dependencias, firmar artefactos |
| Inyección y XSS (A05, CWE-79, CWE-89) | Solo defensas indirectas (CSP, cabeceras) | Consultas parametrizadas, escape de salida, CSP; pruebas en laboratorio con permiso |
| Registro y alertas (A09) | *Próximo lote* (análisis de logs) | Registrar eventos de seguridad y alertar |
| API: autorización a nivel de objeto/función (API1, API5) | No se prueba de forma automática | Revisión de código, pruebas con cuentas de prueba autorizadas |
| Exposición de red (ATT&CK Reconocimiento) | Puertos TCP | Cerrar puertos innecesarios, segmentar |
| Denegación de servicio, fuerza bruta, malware, ransomware, movimiento lateral, exfiltración | **Fuera de alcance por diseño** | Copias aisladas, segmentación, EDR, límites de tasa, MFA, monitoreo |

**Por qué hay cosas fuera de alcance**: son técnicas que dañan o que requieren explotar. La herramienta mantiene límites duros: sin denegación de servicio, sin cargas destructivas, sin extraer datos reales, sin persistencia ni movimiento lateral.

## 10. Cómo pedírselo a Claude

Dile qué evaluación usar (su ID está en la dirección de la página). Ejemplos:

- «Valida con `scope_validate` si `https://misitio.com/` está en el alcance de la evaluación `<id>`.»
- «Revisa las cabeceras de seguridad de `https://misitio.com/`.»
- «Audita el TLS y el certificado de `misitio.com`.»
- «Comprueba SPF, DKIM y DMARC de `misitio.com`.»
- «Busca archivos sensibles expuestos en `https://misitio.com/`.»
- «Analiza esta configuración de nginx: …» (modo pasivo, sin red)
- «Registra como hallazgo lo que encontraste, separando hechos de hipótesis.»
- «Genera el informe de la evaluación.»

En modo activo, Claude te dirá que hay un plan pendiente. Apruébalo en la consola y pásale el token.

## 11. Triaje, severidad e informes

- **Severidad y CVSS**: cada hallazgo lleva un puntaje que debe corresponder a su banda (info 0, baja 0,1–3,9, media 4–6,9, alta 7–8,9, crítica 9–10).
- **Confianza**: alta (confirmado con evidencia directa), media o baja.
- **Triaje**: *Sin verificar* → *Confirmado*, *Falso positivo* o *Riesgo aceptado*. Revisa cada uno antes de informar.
- **Informe**: por defecto incluye solo los confirmados. Está disponible en Markdown, JSON y **PDF** (botón "Descargar PDF" en la pestaña *Informe*), y siempre indica el estado de la cadena de auditoría. La descarga en PDF es siempre una vista previa: no avanza el ciclo ni reemplaza *Cerrar informe*.

## 12. Límites éticos y legales

- Prueba **solo** sistemas tuyos o con **permiso escrito** del dueño. La herramienta no puede comprobar la propiedad: esa responsabilidad es tuya.
- Si usas hosting, CDN o nube (Cloudflare, Vercel, AWS…), revisa su política de pruebas de seguridad.
- Si el sitio está detrás de un CDN, las pruebas de red describen al CDN, no a tu servidor de origen.
- Empieza siempre con ritmo bajo y ventanas cortas; amplía solo si hace falta.
- Nunca pegues contraseñas, tokens o claves en el chat. Para cuentas de prueba, guarda **solo el nombre** del secreto en tu gestor de secretos.

## 13. Solución de problemas

| Mensaje | Qué significa | Qué hacer |
|---|---|---|
| `TARGET_OUT_OF_SCOPE` | El objetivo no está en el alcance (una URL no autoriza un dominio ni sus puertos) | Crear una nueva versión del alcance con el objetivo correcto |
| `TARGET_EXCLUDED` | Está en las exclusiones | Quitarlo de las exclusiones si fue un error |
| `STATE_TRANSITION_INVALID` | La evaluación no está aprobada | Avanzar el ciclo hasta *Aprobada* |
| `RATE_LIMIT` | Se superó el ritmo permitido | Los módulos esperan y reintentan solos; si persiste, sube el ritmo con cuidado |
| `ROLE_NOT_ALLOWED` | Ese rol no puede hacer esa acción | Hacerla un humano con el rol adecuado desde la consola |
| «Firma NO válida» | La autorización fue modificada fuera de la herramienta | Tratarlo como incidente; crear una nueva versión |
| Kill switch activo | Alguien detuvo todo | Un autorizador debe revisarlo y liberarlo |
| Conector de Claude no verifica | El servidor no responde o está arrancando | Esperar un minuto (el plan gratuito de Render duerme) y reintentar |

## 14. Seguridad de la propia herramienta

- Las contraseñas se guardan con scrypt; las sesiones duran 8 horas como máximo y se cierran tras 30 minutos sin actividad.
- Tras 5 intentos fallidos la cuenta se bloquea temporalmente.
- Rota las credenciales que compartas por error (por ejemplo, la contraseña de la base de datos) y actualiza la variable en el servidor.
- Revisa la **Auditoría** con regularidad y usa *Verificar cadena*.

## 15. Referencias

- OWASP Top 10 2025: https://owasp.org/Top10/2025/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/
- CWE Top 25 2025: https://cwe.mitre.org/top25/
- MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/
- RFC 9116 (security.txt): https://www.rfc-editor.org/rfc/rfc9116
- RFC 8996 (retiro de TLS 1.0 y 1.1): https://www.rfc-editor.org/rfc/rfc8996

