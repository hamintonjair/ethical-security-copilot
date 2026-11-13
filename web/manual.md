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

1. **Abrir el caso** (autorizador u operador): organización, quién reporta, qué está pasando, activos afectados.
2. **Añadir evidencia**: pega líneas de log o las cabeceras completas de un correo sospechoso. Se analiza al instante:
   - **Logs**: extrae IPs, dominios, URLs y hashes; detecta patrones de inyección SQL, XSS, path traversal, inyección de comandos, rastreo de rutas sensibles, firmas de herramientas de escaneo (sqlmap, nikto, nmap…) y fuerza bruta/credential stuffing (5+ fallos de autenticación desde la misma IP).
   - **Cabeceras de correo**: compara el remitente visible (`From`) con el real (`Return-Path`) y `Reply-To`, y lee `Authentication-Results` para ver si SPF/DKIM/DMARC fallaron. Es la forma más rápida de confirmar un phishing en curso.
   - El contenido se guarda redactado (sin credenciales ni tokens) y nunca se muestra más allá de lo necesario.
3. **Plan de contención**: con las IPs/dominios acumulados de toda la evidencia, genera reglas listas para pegar: `iptables`, `ufw`, un bloque `nginx deny`, una regla de Cloudflare (Firewall Rules / WAF) y una lista de dominios sospechosos. **Nada se ejecuta**: las aplicas tú mismo en tu firewall, tu servidor o tu panel.
4. **Informe**: línea de tiempo de la evidencia, todos los IOCs acumulados, y a quién reportar: el *abuse contact* del hosting del atacante (`whois <ip>`), el CSIRT nacional (**colCERT** en Colombia, más la Policía Nacional - Centro Cibernético, para denuncia formal), o el CERT de tu país si no es Colombia. Incluye cómo preservar evidencia para una denuncia.
5. **Estados**: *Abierto → Contenido → Cerrado*. Un incidente cerrado no admite más evidencia ni se puede reabrir.

Pídeselo a Claude, por ejemplo: «Analiza este log del incidente `<id>` y dime qué encuentra» o «Genera el plan de contención con las IPs que ya encontramos».

## 6. Catálogo de módulos

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

## 7. Mapa de cobertura: del ataque a la defensa

La herramienta **no ataca**: encuentra las condiciones que los atacantes aprovechan y te dice cómo cerrarlas.

| Ataque o riesgo | Qué hace la herramienta hoy | Defensa clave |
|---|---|---|
| Acceso roto / mala configuración (A01, A02) | Cabeceras, métodos, archivos expuestos, CORS, configuración | Mínimo privilegio, endurecimiento, no exponer paneles ni archivos internos |
| Fallos criptográficos (A04) | Auditoría TLS, análisis de configuración | TLS 1.2+/1.3, certificados vigentes, HSTS, no guardar secretos en texto claro |
| Fallos de autenticación y sesión (A07) | Cookies (Secure/HttpOnly/SameSite) | MFA, contraseñas largas, bloqueo de intentos, cookies seguras |
| Suplantación y phishing (ATT&CK T1566) | SPF, DKIM, DMARC, MTA-STS | DMARC en `reject`, SPF con `-all`, formación de usuarios |
| Cadena de suministro (A03) | *Próximo lote* (dependencias y SBOM) | Fijar versiones, revisar dependencias, firmar artefactos |
| Inyección y XSS (A05, CWE-79, CWE-89) | Solo defensas indirectas (CSP, cabeceras) | Consultas parametrizadas, escape de salida, CSP; pruebas en laboratorio con permiso |
| Registro y alertas (A09) | *Próximo lote* (análisis de logs) | Registrar eventos de seguridad y alertar |
| API: autorización a nivel de objeto/función (API1, API5) | No se prueba de forma automática | Revisión de código, pruebas con cuentas de prueba autorizadas |
| Exposición de red (ATT&CK Reconocimiento) | Puertos TCP | Cerrar puertos innecesarios, segmentar |
| Denegación de servicio, fuerza bruta, malware, ransomware, movimiento lateral, exfiltración | **Fuera de alcance por diseño** | Copias aisladas, segmentación, EDR, límites de tasa, MFA, monitoreo |

**Por qué hay cosas fuera de alcance**: son técnicas que dañan o que requieren explotar. La herramienta mantiene límites duros: sin denegación de servicio, sin cargas destructivas, sin extraer datos reales, sin persistencia ni movimiento lateral.

## 8. Cómo pedírselo a Claude

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

## 9. Triaje, severidad e informes

- **Severidad y CVSS**: cada hallazgo lleva un puntaje que debe corresponder a su banda (info 0, baja 0,1–3,9, media 4–6,9, alta 7–8,9, crítica 9–10).
- **Confianza**: alta (confirmado con evidencia directa), media o baja.
- **Triaje**: *Sin verificar* → *Confirmado*, *Falso positivo* o *Riesgo aceptado*. Revisa cada uno antes de informar.
- **Informe**: por defecto incluye solo los confirmados. Está disponible en Markdown y JSON, y siempre indica el estado de la cadena de auditoría.

## 10. Límites éticos y legales

- Prueba **solo** sistemas tuyos o con **permiso escrito** del dueño. La herramienta no puede comprobar la propiedad: esa responsabilidad es tuya.
- Si usas hosting, CDN o nube (Cloudflare, Vercel, AWS…), revisa su política de pruebas de seguridad.
- Si el sitio está detrás de un CDN, las pruebas de red describen al CDN, no a tu servidor de origen.
- Empieza siempre con ritmo bajo y ventanas cortas; amplía solo si hace falta.
- Nunca pegues contraseñas, tokens o claves en el chat. Para cuentas de prueba, guarda **solo el nombre** del secreto en tu gestor de secretos.

## 11. Solución de problemas

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

## 12. Seguridad de la propia herramienta

- Las contraseñas se guardan con scrypt; las sesiones duran 8 horas como máximo y se cierran tras 30 minutos sin actividad.
- Tras 5 intentos fallidos la cuenta se bloquea temporalmente.
- Rota las credenciales que compartas por error (por ejemplo, la contraseña de la base de datos) y actualiza la variable en el servidor.
- Revisa la **Auditoría** con regularidad y usa *Verificar cadena*.

## 13. Referencias

- OWASP Top 10 2025: https://owasp.org/Top10/2025/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/
- CWE Top 25 2025: https://cwe.mitre.org/top25/
- MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/
- RFC 9116 (security.txt): https://www.rfc-editor.org/rfc/rfc9116
- RFC 8996 (retiro de TLS 1.0 y 1.1): https://www.rfc-editor.org/rfc/rfc8996
