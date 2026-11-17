# Objetivo de laboratorio: OWASP Juice Shop

Esta carpeta solo contiene el `Dockerfile` que despliega [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
como un segundo servicio de Render, separado de la consola de Ethical Security Copilot.

**Por qué este objetivo es legítimo para practicar en él:**
- Juice Shop lo construye y publica el propio OWASP (Open Worldwide Application Security Project)
  específicamente para que se le hagan pruebas de seguridad — es el objetivo de entrenamiento más usado
  del mundo para hacking ético (lo usan cursos, universidades, y certificaciones).
- Esta copia la despliega tu propia organización, en tu propia cuenta de Render. No es un sistema de un
  tercero ni de producción: es tuyo, para tu laboratorio.
- Contiene decenas de vulnerabilidades intencionales (inyección, control de acceso roto, XSS, lógica de
  negocio, criptografía débil, etc.) con un marcador de progreso ("Score Board") para que veas qué vas
  encontrando.

**Cómo se usa junto con Ethical Security Copilot:**
1. Este servicio se despliega una sola vez (ya documentado en el README principal) y te da una URL propia,
   p. ej. `https://esc-lab-juiceshop.onrender.com`.
2. En la consola de Ethical Security Copilot creas una evaluación nueva cuyo **alcance** sea exactamente
   esa URL (tipo `url`, con tu propio nombre y correo como autorizador — es tu laboratorio, tú lo
   autorizas). Modo `active` (es un objetivo real en Internet, no local).
3. Sigues el ciclo normal: validar alcance → planificar módulos → aprobar → ejecutar → revisar hallazgos →
   informe. Los módulos integrados (cabeceras HTTP, TLS, puertos, exposición de documentos expuesta,
   robots/sitemap, CORS…) ya encuentran varias cosas reales en Juice Shop sin tocar nada manualmente.
4. Para explorar más a fondo (inyección, lógica de negocio, XSS) se navega la aplicación igual que un
   usuario, con las herramientas manuales típicas de un hacker ético (Burp/ZAP, DevTools) — eso queda
   fuera del alcance automatizado de la plataforma, que es deliberadamente pasivo/no intrusivo.

No reemplaces esta imagen por la de un sistema real sin autorización explícita y por escrito: la legitimidad
de este laboratorio viene de que Juice Shop fue publicado por su propio dueño (OWASP) para ser atacado.
