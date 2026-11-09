# ADR-010 — Cercano Chat: chat de soporte embebido con gestión en consola

- **Estado:** Aceptado
- **Fecha:** 2026-11-09
- **Fase:** F4.5 (complemento entre F4 y F5)
- **Decisores:** Dueño del producto, Coordinador
- **Relacionados:** [`docs/specs/chat.md`](../specs/chat.md), [`docs/PLAN-F4.5-CHAT.md`](../PLAN-F4.5-CHAT.md), [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md)

## 1. Contexto

Cercano resuelve el soporte remoto con sesiones de escritorio, archivos y terminal. Muchos incidentes pequeños (una impresora, una contraseña, una aplicación que no abre) no necesitan una sesión remota completa: necesitan una conversación rápida con el técnico, con historial y, si hace falta, una escalada a la sesión remota. Hoy el cliente ya dispone de un chat **dentro de cada sesión** (heredado de upstream), pero no de un canal de soporte persistente e independiente de la sesión.

El dueño del producto decidió que el chat:

- viva **dentro del cliente Cercano ya instalado** (sin una segunda aplicación que instalar y mantener);
- se gestione desde una **pantalla de conversaciones en `console-web`**;
- incluya **adjuntos (imágenes y PDF)**, **notificaciones de escritorio** y **escalado a sesión remota**;
- se entregue como **fase F4.5**, después de F4 (consola, RBAC y 2FA), para no interrumpir la verificación de F3 ni duplicar controles de acceso.

## 2. Decisión

1. **Cliente:** el chat se embebe en el cliente Cercano existente (Flutter + Rust) como módulo nuevo y **ventana dedicada** del mismo cliente (pestaña como fallback si el multi-window no es viable), con el diseño de `docs/specs/chat.md` §14 y el mockup `docs/specs/chat-ui-reference.png`. Se distribuye como el parche `006-client-support-chat.patch`; no se edita `vendor/` directamente. Por defecto está habilitado para el instalador `soporte` y deshabilitado para `tecnico`, configurable en el perfil firmado.
2. **Gestión:** `console-web` incorpora la pestaña «Conversaciones» con cola, filtros, reclamación, asignación, cierre, reapertura y escalado. Los técnicos usan sus cuentas y permisos de F4 (`chat:attend`, `chat:manage`, `chat:read`).
3. **Persistencia:** las conversaciones, mensajes y metadatos de adjuntos viven en `cercano-api` (SQLite). Los adjuntos viven en disco, bajo un directorio configurable, y se sirven solo por endpoint autenticado. El cliente no guarda el historial como fuente de verdad.
4. **Tiempo real:** REST para escritura/lectura y **SSE** para «pokes» sin contenido (el receptor vuelve a consultar por REST). No se usa WebSocket en v1 porque SSE no requiere `Upgrade`, funciona con cabecera `Authorization` desde `fetch` y notifica con la pestaña en segundo plano; WebSocket queda como mejora si se añaden indicadores de escritura o presencia.
5. **Identidad del cliente final:** sin cuenta. El cliente usa el par Ed25519 que ya posee para su ID; registra la clave pública una vez con el token de despliegue (`X-Cercano-Client-Token`, solo sobre HTTPS), el servidor la fija (TOFU) y cada conexión se autentica con un reto firmado y un token de chat de corta duración. Un cambio de clave exige un reset administrativo auditado. Cuando F3-07 emita tokens de registro por instalador, sustituirán al token compartido.
6. **Nombre visible del contacto:** la primera vez que se usa el chat el cliente pide **Nombre y Apellido**; se guardan solo en la configuración local del cliente y como snapshot en `chat_conversations` (no hay cuenta ni tabla de contactos). El técnico ve el nombre natural como etiqueta principal y el nombre del equipo como contexto. En conversaciones posteriores se reutiliza; editarlo afecta solo a conversaciones nuevas. Es un dato personal: no se audita, no se registra en logs/notificaciones y se borra con la retención.
7. **Privacidad:** sin cifrado extremo a extremo en v1. La cola, el historial multi-equipo y la supervisión exigen que el servidor pueda almacenar y servir el mensaje; se compensa con TLS obligatorio, permisos, retención de 90 días y auditoría de metadatos sin contenido. La limitación queda en el modelo de amenazas.
8. **Auditoría:** categoría nueva `chat` en `audit-core`. Se audita quién abre, escribe, adjunta, asigna, cierra, reabre y escala; **nunca** el cuerpo del mensaje, el nombre del contacto, el nombre original del adjunto ni tokens. `trace_id` = `conversation_id`.
9. **Escalado:** el botón de la consola abre `cercano://connect?device=<id>&trace=<conversation_id>` en el equipo del técnico; la sesión remota conserva el consentimiento normal de la persona usuaria y comparte `trace_id` con la conversación.
10. **Fase:** F4.5, después de F4; depende además de F3-13 (rol de instalador), F3-02 (perfil) y F3-05 (empaquetado) para la identidad y el esquema de URL.

## 3. Consecuencias

**Positivas**

- Un solo cliente instalado para recibir soporte y conversar; sin un segundo instalador, actualizador ni bandeja.
- El técnico identifica a la persona por su nombre natural y no solo por el nombre del equipo, lo que reduce errores de atención y conversaciones con el equipo equivocado.
- El historial y la cola sobreviven a reinicios y a equipos técnicos distintos; el cliente no necesita mantener estado.
- La consola reutiliza autenticación, diseño y despliegue existentes; no hay servicio ni puerto nuevo.
- La auditoría permite reconstruir la atención sin almacenar contenido sensible.

**Negativas y riesgos**

- El cliente upstream se toca con un parche más (R2): se mitiga con módulo nuevo, hooks delgados y registro en `patches/INDEX.md`.
- El servidor puede leer los mensajes (sin E2E): se mitiga con TLS, permisos, retención y transparencia; E2E queda como evaluación futura.
- La identidad TOFU con token compartido permite una suplantación inicial si el token se filtra; se mitiga con TLS, fijación de clave, auditoría y el futuro token por instalador.
- Los adjuntos pueden transportar malware; v1 solo acepta imágenes y PDF, valida magic bytes, no ejecuta y deja un punto de extensión para antivirus.
- Las notificaciones requieren la app en ejecución o la consola abierta; el historial queda en el servidor y se ve al abrir.
- El nombre y apellido son datos personales; se guardan en el snapshot de la conversación y en la configuración local, se excluyen de la auditoría y se borran con la retención.
- Sin 2FA de F4 no se habilita en producción.

## 4. Alternativas consideradas

| Alternativa | Por qué se descarta |
|---|---|
| Aplicación separada «Cercano Chat» | Duplica instalador, actualizador, autenticación, bandeja y soporte; el requisito se cumple con el cliente existente. |
| Chat solo web/PWA | No cumple «aplicación instalada», pierde notificaciones nativas fiables y no reutiliza la identidad del dispositivo. |
| Reutilizar el chat de sesión de upstream | Está atado a una sesión remota activa y a su protocolo; no sirve para conversaciones persistentes ni cola. |
| WebSocket desde el inicio | Añade `Upgrade`, configuración de proxy y autenticación en el primer frame; SSE cubre la necesidad v1 con menos piezas. |
| Cifrado extremo a extremo | Impide la cola, el historial en varios equipos y la supervisión; se pospone y se documenta. |
| Guardar el historial solo en el cliente | Se pierde al reinstalar, no permite atender desde la consola ni auditar; no es viable. |

## 5. Referencias

- [`docs/specs/chat.md`](../specs/chat.md) — contrato de datos, API, autenticación, SSE, adjuntos y límites.
- [`docs/PLAN-F4.5-CHAT.md`](../PLAN-F4.5-CHAT.md) — tareas, criterios de aceptación y gate.
- [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md) — componentes y modelo de amenazas.
- [`docs/specs/audit-events.md`](../specs/audit-events.md) — categoría `chat` y acciones.
- [`docs/status/TAREAS.md`](../status/TAREAS.md) — estado vivo de F4.5.
