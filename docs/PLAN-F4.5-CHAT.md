# Plan de trabajo — F4.5: Cercano Chat

**Versión:** 1.0 · **Fecha:** 2026-11-09 · **Fase:** F4.5 (complemento entre F4 y F5)
**Depende de:** F4 cerrado (consola, RBAC, 2FA), F3-13 (rol de instalador), F3-02 (perfil firmado), F3-05 (empaquetado Windows) y F2-02 (auditoría encadenada).
**Documentos:** [`docs/specs/chat.md`](specs/chat.md) es el contrato técnico; [`docs/adr/010-cercano-chat.md`](adr/010-cercano-chat.md) es la decisión.

## 1. Objetivo (hito M3.5)

Una persona usuaria con **Cercano Soporte** instalado abre una conversación desde el cliente y resuelve un problema pequeño con un técnico que la atiende desde **`console-web`**: texto, historial, adjuntos de imagen/PDF, notificaciones y, si hace falta, escalado a una sesión remota. Todo queda auditado sin guardar el contenido de los mensajes.

**No es objetivo:** una aplicación de chat separada, chat web/PWA, cifrado extremo a extremo, edición/borrado de mensajes, búsqueda full-text, respuestas rápidas, transcripciones o antivirus de adjuntos en v1.

## 2. Decisiones de producto

| Tema | Decisión |
|---|---|
| Cliente | Chat embebido en el cliente Cercano existente, en una **ventana dedicada** del mismo cliente (pestaña como fallback si el multi-window no es viable); el requisito «aplicación de chat instalada» se cumple con Cercano Soporte. El diseño sigue el mockup del dueño (`docs/specs/chat-ui-reference.png`). |
| Gestión | Pestaña «Conversaciones» en `console-web`. |
| v1 | Texto + historial + cola/asignación/cierre + adjuntos (imágenes y PDF) + notificaciones + escalado remoto. |
| Identidad | Dispositivo sin cuenta: Ed25519 del cliente, clave fijada por el servidor y reto firmado. |
| Nombre del contacto | La primera vez se piden **Nombre y Apellido**; se guardan solo en la configuración local del cliente y como snapshot en la conversación. El técnico ve el nombre natural como etiqueta principal y el equipo como contexto. No hay cuenta ni tabla de contactos. |
| Persistencia | Servidor (`cercano-api`/SQLite); el cliente no es fuente de verdad. |
| Tiempo real | SSE + REST; sin WebSocket en v1. |
| Privacidad | Sin E2E; TLS, permisos, retención y auditoría sin contenido. |
| Fase | F4.5, después de F4. |

## 3. Arquitectura

La arquitectura, el modelo de datos, la API, la autenticación, la SSE, los adjuntos y los límites están en [`docs/specs/chat.md`](specs/chat.md). Resumen:

- **Cliente:** módulo Rust nuevo (red, firma, SSE, toast) + página Flutter nueva; parche `006-client-support-chat.patch`; hooks delgados; sin reestructurar el cliente upstream.
- **API:** módulo `chat/` en `cercano-api`; migración 004; `ChatHub`; SSE; retención; auditoría `chat.*`.
- **Consola:** `ChatView` con lista y conversación; badge, notificaciones y reconexión; sin librerías nuevas.
- **Despliegue:** sin puertos nuevos; nginx ajusta SSE y tamaño de subida; TLS obligatorio.

## 4. Matriz de capacidades

| | Soporte (cliente final) | Técnico (`chat:attend`) | Supervisor (`chat:manage`) | Auditor (`chat:read`) |
|---|---|---|---|---|
| Iniciar conversación | Sí (una abierta) | No | No | No |
| Ver su conversación | Sí | Sí | Sí | Sí |
| Cola en espera | No | Sí | Sí | Sí |
| Conversación ajena | No | No | Sí | Sí |
| Reclamar/liberar | No | Sí | Sí | No |
| Asignar/reabrir/reset identidad | No | No | Sí | No |
| Responder/adjuntar/cerrar | Solo cerrar la suya | Las suyas | Todas | No |
| Escalar a sesión remota | No | Las suyas | Todas | No |

## 5. Tareas

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F4.5-01 | Especificación, ADR y planificación | — | Coordinador | Dueño/QA |
| F4.5-02 | Migración 004 y modelos | F4.5-01, F4 cerrado | ControlPlane | QA |
| F4.5-03 | Autenticación de dispositivo | F4.5-02, F3-13 | ControlPlane | Seguridad |
| F4.5-04 | API REST de conversaciones y mensajes | F4.5-03, F4 | ControlPlane | QA |
| F4.5-05 | Adjuntos | F4.5-04 | ControlPlane | Seguridad |
| F4.5-06 | SSE, `ChatHub`, lecturas y resumen | F4.5-04 | ControlPlane | QA |
| F4.5-07 | Auditoría, límites y retención | F4.5-02…06, F2-02 | ControlPlane | Seguridad |
| F4.5-08 | Consola: vista Conversaciones | F4.5-04/05/06, F4 | Web | QA |
| F4.5-09 | Consola: badge, notificaciones, reconexión, accesibilidad | F4.5-08 | Web | QA |
| F4.5-10 | Cliente: módulo Rust y parche 006 | F4.5-03/04/06, F3-02 | Cliente | Seguridad |
| F4.5-11 | Cliente: UI Flutter, entrada, adjuntos, i18n | F4.5-10, F4.5-13 | Cliente | QA |
| F4.5-12 | Escalado a sesión remota (`cercano://`) | F4.5-08/11, F3-05 | Cliente + Web | Seguridad |
| F4.5-13 | Perfil `policy.chat` y aplicación en servidor | F3-01/02/13, F4.5-04 | ControlPlane + Cliente | Seguridad |
| F4.5-14 | E2E, seguridad, carga básica y cierre | F4.5-02…13 | QA + Seguridad | Coordinador |
| F4.5-15 | Guía de despliegue y operación | F4.5-14 | Coordinador | QA |

### Detalle y criterios de aceptación

**F4.5-01 Especificación, ADR y planificación.**
Crear `docs/specs/chat.md`, `docs/adr/010-cercano-chat.md` y este plan; actualizar `ARQUITECTURA.md`, `ROADMAP.md`, `TAREAS.md`, `PLAN-DE-PRUEBAS.md`, el esquema de auditoría y el informe F4.5-01. No se toca código.
*CA:* documentos coherentes; esquema de auditoría válido en JSON; tareas y `TC-F4.5-*` registrados; `git diff` solo de documentación; F4.5-01 `En verificación`.

**F4.5-02 Migración 004 y modelos.**
Añadir a `control-plane/cercano-api/src/db.rs` la migración `004_chat_schema` con las tablas e índices de `docs/specs/chat.md` §5, incluidos `contact_first_name` y `contact_last_name` en `chat_conversations`. Crear `src/chat/mod.rs` con los structs/servicios base y la actualización de `schema_migrations` esperada (4 filas). Actualizar las pruebas de `db.rs`.
*CA:* migración sobre BD vacía y sobre BD con 001–003 aplicadas; sin pérdida de datos; índices presentes; `cargo test -p cercano-api` en verde; prueba de idempotencia de migraciones.

**F4.5-03 Autenticación de dispositivo.**
Crear `src/chat/auth.rs` y las rutas `POST /api/chat/devices/register`, `/auth/challenge`, `/auth/verify`, `/devices/{id}/reset`. Añadir `CERCANO_CLIENT_INGEST_TOKEN` como precondición del registro (solo HTTPS), fijación de clave, nonces de un solo uso, tokens de 15 min, revocación y auditoría `chat.device.*`/`chat.auth.failed`.
*CA:* registro válido; clave distinta → 409 y auditoría; nonce reusado/caducado → 401; firma inválida → 401; token expirado/revocado → 401; reset invalida todo; ninguna clave privada ni token en logs; pruebas de integración.

**F4.5-04 API REST de conversaciones y mensajes.**
Crear `src/chat/conversations.rs`, `src/routes/chat.rs` y el montaje en `lib.rs`. Implementar crear/listar/leer, mensajes, claim/release/assign/close/reopen, agentes y resumen; permisos `chat:attend`/`chat:manage`/`chat:read` de F4; transiciones de estado; idempotencia por `client_message_id`; paginación; límites de texto y conversaciones/día; validar y guardar `contact_first_name`/`contact_last_name` (obligatorios, 1–64, sin controles); incluir el nombre en la búsqueda de la cola; actualizar `docs/specs/api.yaml` con los endpoints y esquemas.
*CA:* flujo completo por API; nombre/apellido obligatorios y validados; snapshot en la conversación; búsqueda por nombre y equipo; dos dispositivos y dos técnicos no se cruzan (IDOR); claim concurrente → 409; conversación cerrada → 409 al escribir; reintento no duplica; todo endpoint de escritura deja evento; OpenAPI válido; pruebas de integración.

**F4.5-05 Adjuntos.**
Crear `src/chat/attachments.rs`: subida binaria, magic bytes, límites, SHA-256, almacenamiento atómico, descarga autenticada, limpieza de huérfanos y cuota por conversación. Ajustar `deploy/nginx.conf` y `deploy/README.md` (`client_max_body_size`, SSE) y `Config` con el directorio y topes.
*CA:* PNG/JPEG/WebP/PDF aceptados; SVG/EXE/ZIP rechazados; >10 MiB → 413; nombre con ruta saneado; descarga ajena → 403; archivo huérfano no queda tras un fallo; `nosniff` y `no-store`; pruebas de integración y revisión de Seguridad.

**F4.5-06 SSE, `ChatHub`, lecturas y resumen.**
Crear `src/chat/events.rs`: `broadcast` de 256, audiencias `Device`/`User`/`Queue`, `GET /api/chat/events`, heartbeat, `resync`, validación de token cada 60 s, lecturas/no leídos, `other_last_read_at` para el doble check y `GET /api/chat/summary`. Añadir `tokio-stream` a `cercano-api/Cargo.toml` y el hub a `AppState`.
*CA:* el asignado recibe el poke de mensaje; el dispositivo dueño lo recibe; un tercero no; reconexión + refetch no pierde mensajes; atraso → `resync`; token revocado cierra el stream; SSE no lleva contenido; `other_last_read_at` refleja la última lectura del otro participante; pruebas de integración/stream.

**F4.5-07 Auditoría, límites y retención.**
Añadir `Category::Chat` en `control-plane/audit-core/src/model.rs` y la política de retención; emitir los eventos de `docs/specs/chat.md` §10; implementar los límites de tasa (mensajes, conversaciones/día, adjuntos/día, SSE) con 429 y `Retry-After`; tarea diaria de retención de conversaciones cerradas y adjuntos; evento `chat.retention.purged`.
*CA:* cadena `chat.*` verificable con eventos antiguos; búsqueda automática no encuentra cuerpos, nombres de archivo, tokens ni claves en la base de auditoría; retención borra cerradas y conserva abiertas; 429 auditado; `cercano-audit verify` en verde.

**F4.5-08 Consola: vista Conversaciones.**
Añadir `'chat'` a `ActiveTab`, la pestaña en `TabBar.tsx` con badge, el render en `App.tsx` y `ChatView.tsx` con lista/filtros/búsqueda, conversación, mensajes, adjuntos, composer y acciones. Mostrar **nombre y apellido como etiqueta principal** y el equipo/hostname como secundario; incluir ambos en la búsqueda. Añadir tipos y métodos de API (o `api/chat.ts`) y un hook de estado. En modo demostración, mensaje claro de no disponibilidad (sin datos falsos).
*CA:* nombre natural + equipo visibles; búsqueda por nombre y equipo; cola/filtros; reclamar/liberar/cerrar/reabrir/asignar; enviar/adjuntar; estados vacío/cargando/error; `npm run build` y `npm run lint:design` en verde; QA manual con dos técnicos y dos dispositivos; sin regresiones en las vistas existentes.

**F4.5-09 Consola: badge, notificaciones, reconexión y accesibilidad.**
Badge de cola + no leídos y título `(N)`; permiso de `Notification` explícito; notificación solo con `document.hidden`; clic enfoca la conversación; banner de reconexión SSE; foco, teclado, `aria-live`, contraste, claro/oscuro y `prefers-reduced-motion`.
*CA:* notificación sin cuerpo; permiso denegado no rompe; badge correcto; reconexión visible; navegación completa por teclado; QA manual.

**F4.5-10 Cliente: módulo Rust y parche 006.**
Crear `vendor/client/src/cercano_chat.rs` (registro, firma, REST, SSE con `reqwest` + feature `stream`, token en memoria, reconexión, toast con `tauri-winrt-notification`), hooks en `src/lib.rs` y `src/flutter_ffi.rs`, y el parche `patches/006-client-support-chat.patch` registrado en `patches/INDEX.md`. Añadir la feature `stream` a `reqwest`; no agregar crates nuevas.
*CA:* registro/auth/firma; rechazo de HTTP; token nunca en disco/logs; SSE y reconexión; toast sin contenido; pruebas unitarias de firma/parseo; el parche aplica limpio sobre el upstream base y no cambia rutas existentes.

**F4.5-11 Cliente: UI Flutter, entrada, adjuntos e i18n.**
Crear `vendor/client/flutter/lib/cercano_chat/` (modelo, página, widgets), el botón «Chat de soporte» en el panel izquierdo del cliente Soporte y la **ventana dedicada** (multi-window; pestaña como fallback) con el diseño de `docs/specs/chat.md` §14 y el mockup `docs/specs/chat-ui-reference.png`: cabecera con icono/nombre del perfil, estado del servicio («En línea»/«Reconectando»/«Atendido por …»), aviso informativo, hilo de burbujas con avatares genéricos/iniciales, horas, doble check de leído, adjuntos (imagen/PDF), composer, pie de privacidad y estados (bienvenida, en cola, activa, cerrada, sin conexión). **Primera vez:** formulario obligatorio de **Nombre y Apellido** antes de crear la conversación; se guarda solo en la configuración local (`chat-contact-first-name`, `chat-contact-last-name`), se precarga en las siguientes y se puede editar para conversaciones nuevas. Sin presencia por técnico ni indicador de escritura en v1; el punto verde significa «servicio en línea». Añadir claves a `template.rs` y a todos los `src/lang/*.rs` (vacías donde corresponda; español en `es.rs`). Wrappers Dart a mano.
*CA:* la ventana se abre desde el cliente y respeta el mockup (cabecera, aviso, hilo, composer, pie); la marca sale del perfil y no hay ACME hardcodeado; primera vez pide nombre y apellido y no deja continuar sin ambos; conversaciones posteriores los reutilizan; edición aplica solo a nuevas; el nombre no aparece en logs/telemetría/notificaciones; doble check según `other_last_read_at`; sin typing/presencia; iniciar/enviar/recibir; imagen en línea y PDF descargable; toast al minimizar; reconexión; perfil desactiva el chat; i18n sin claves faltantes; `flutter test` del modelo en verde; QA manual en Windows 10/11; sin regresiones en la UI existente.

**F4.5-12 Escalado a sesión remota.**
Añadir el manejo de `cercano://connect?device=&trace=` en el cliente (alias del manejador actual) y el registro del esquema en el empaquetado Windows (F3-05); botón y respaldo «Copiar ID» en la consola; evento `chat.escalated`; propagar `trace` a `conn_audit_ref`.
*CA:* el botón abre el cliente en el equipo del técnico; la sesión remota conserva el consentimiento; la traza de chat y la de sesión coinciden en `cercano-audit`; sin cliente/esquema, el respaldo funciona; evento emitido.

**F4.5-13 Perfil `policy.chat` y aplicación en servidor.**
Extender `docs/specs/cercano-profile.schema.json` y `.md` con `policy.chat {enabled, allow_attachments, allow_remote_escalation}`; valores por defecto (`soporte` true, `tecnico` false); validación en el cliente; registrar el flag en el instalador (F3-07/F3-13) y comprobarlo en el servidor para conversaciones/adjuntos/escalado. Los perfiles antiguos se interpretan con los defaults.
*CA:* perfil sin `chat` sigue siendo válido; `soporte` con chat true inicia; `tecnico` no inicia aunque edite su configuración; `allow_attachments=false` → 403 en adjuntos; `allow_remote_escalation=false` → botón oculto y 403 en el evento; pruebas de esquema y de servidor.

**F4.5-14 E2E, seguridad, carga básica y cierre.**
Ejecutar los `TC-F4.5-*` en el laboratorio con Windows 10/11, consola y API; pruebas de IDOR, replay, revocación, límites, adjuntos maliciosos, SSE y retención; carga básica (p. ej. 20 conversaciones concurrentes, 100 mensajes/min); informe `docs/status/informes/F4.5-14.md` y cierre.
*CA:* suite en verde; sin hallazgos críticos/altos; flujo completo + `cercano-audit verify`; sin secretos, cuerpos ni nombres de contacto en logs/auditoría; gate firmado por Coordinador.

**F4.5-15 Guía de despliegue y operación.**
Actualizar `deploy/README.md` y crear `docs/guias/chat.md`: TLS/CA de confianza, nginx (SSE y subida), variables, respaldos, retención, cómo desactivar el chat, reset de identidad, solución de problemas y aviso de privacidad.
*CA:* otra persona sigue la guía desde cero y pone el chat en el laboratorio; incluye cómo revocar y cómo verificar la auditoría.

## 6. Reglas de seguridad no negociables

1. **TLS obligatorio**; el chat no funciona sobre HTTP. El certificado debe ser de confianza del cliente.
2. **Nunca** se guardan cuerpos de mensajes, **nombre o apellido del contacto**, nombres originales de adjuntos, tokens ni claves en auditoría, logs, notificaciones o telemetría.
3. **Identidad fijada:** una clave distinta para el mismo `device_id` se rechaza y exige reset administrativo auditado.
4. **Autorización en cada ruta:** dueño, asignación o permiso; pruebas de IDOR con dos dispositivos y dos técnicos.
5. **Adjuntos:** solo imágenes/PDF, magic bytes, tamaño, sin ejecución, descarga autenticada, sin URL pública.
6. **Límites de tasa** y `429` con `Retry-After`; el abuso se audita.
7. **2FA** de F4 para técnicos en producción; sin F4, solo laboratorio.
8. **Retención** de mensajes/adjuntos independiente de la auditoría; el borrado no rompe la cadena.
9. **Interruptor** `CERCANO_CHAT_ENABLED` para desactivar la función por política.
10. **Sin E2E** en v1: se documenta la capacidad del servidor de leer los mensajes y se protege el volumen y los respaldos.

## 7. Pruebas

El catálogo completo está en [`docs/PLAN-DE-PRUEBAS.md`](PLAN-DE-PRUEBAS.md) §6 (F4.5) y se materializa en `tests/cases/TC-F4.5-*.md` durante la implementación. Grupos:

- **Auth:** registro, clave duplicada, nonce reusado/caducado, firma inválida, token expirado/revocado, reset.
- **Conversaciones:** crear/idempotencia, paginación, claim/conflicto, assign/release, close/reopen, IDOR.
- **Nombre del contacto:** primera vez obligatorio (nombre y apellido), validación, precarga en la siguiente, edición solo para nuevas, snapshot en la conversación, respaldo al nombre del equipo, ausencia en auditoría/logs/notificaciones.
- **Adjuntos:** formatos válidos, rechazos, tamaño, nombre con ruta, descarga ajena, hash.
- **Límites:** mensajes/min, conversaciones/día, adjuntos/día, `Retry-After`.
- **Auditoría/retención:** cadena, sin contenido, purga de cerradas, abiertas intactas.
- **SSE:** audiencia, reconexión/refetch, `resync`, token revocado.
- **Consola:** filtros/badge, notificación oculta, acciones, accesibilidad, claro/oscuro, modo demostración.
- **Cliente:** entrada, ventana y cabecera con marca del perfil, aviso, hilo, composer, pie, doble check de leído, sin typing/presencia, enviar/recibir, imagen/PDF, toast, reconexión, perfil desactivado, escalado, i18n.
- **E2E/seguridad:** flujo completo + `cercano-audit verify`, corte de red, HTTP rechazado, 2FA, sin secretos, sin contenido en notificaciones.

## 8. Gate F4.5

- 100 % de tareas `Hecho` o diferidas con justificación.
- Suite de la fase en verde en CI y laboratorio; flujo completo para ambos roles.
- Sin hallazgos críticos o altos abiertos; medios/bajos con plan.
- `cercano-audit verify` sobre una cadena con eventos de chat, remoto y administración.
- Sin cuerpos, **nombres de contacto**, tokens, claves ni nombres de archivo en auditoría/logs; búsqueda automática documentada.
- `npm run build` y `npm run lint:design` de la consola; `cargo fmt`, `cargo clippy -D warnings`, `cargo test` y `cargo deny check` del backend; parche 006 aplicable; `flutter test` del modelo.
- Guía de operación publicada y recapacitación de QA/Coordinador.

## 9. Fuera de alcance

Aplicación separada, PWA, E2E, edición/borrado, búsqueda full-text, respuestas rápidas, transcripciones, antivirus, más formatos, audio/video, presencia/escritura, multi-tenant, Linux/macOS como objetivo de v1.

## 10. Riesgos

| Riesgo | Mitigación |
|---|---|
| Deriva de upstream por el parche 006 | Módulo nuevo, hooks delgados, parche registrado, rebase trimestral. |
| Privacidad (servidor lee mensajes) | TLS, permisos, retención, auditoría sin contenido; E2E evaluado a futuro. |
| Adjuntos maliciosos | Whitelist, magic bytes, tamaño, descarga como adjunto, antivirus como extensión. |
| Notificaciones poco fiables | SSE + toast con la app abierta; badge e historial persistente. |
| TLS/CA en LAN | Guía, CA de confianza, rechazo de HTTP; laboratorio con TLS. |
| F4/F3 retrasados | F4.5 no empieza hasta F4 cerrado y F3-13/F3-05 hechos; el diseño queda listo. |
| SQLite bajo carga | WAL, índices, límites y paginación; PostgreSQL si crece. |
| Pérdida de identidad al reinstalar | Reset administrativo auditado y mensaje claro. |

## 11. Mapa de archivos (implementación)

| Subsistema | Archivos |
|---|---|
| API | `control-plane/cercano-api/src/chat/{mod,auth,conversations,attachments,events,retention}.rs`, `src/routes/chat.rs`, `src/lib.rs`, `src/db.rs`, `src/config.rs`, `Cargo.toml`, `tests/chat_*.rs` |
| Auditoría | `control-plane/audit-core/src/model.rs`, `src/retention.rs`, `docs/specs/audit-events.md`, `docs/specs/audit-events.schema.json` |
| Consola | `console-web/src/components/views/ChatView.tsx`, `src/components/chat/*`, `src/types/index.ts`, `src/api/{client,chat}.ts`, `src/App.tsx`, `src/components/layout/TabBar.tsx` |
| Cliente | `vendor/client/src/cercano_chat.rs`, `src/lib.rs`, `src/flutter_ffi.rs`, `flutter/lib/cercano_chat/*`, `flutter/lib/desktop/pages/desktop_home_page.dart`, `flutter/lib/desktop/pages/desktop_tab_page.dart`, `flutter/lib/consts.dart`, `src/lang/template.rs` y `src/lang/*.rs`, `Cargo.toml`, `patches/006-client-support-chat.patch`, `patches/INDEX.md` |
| Despliegue | `deploy/nginx.conf`, `deploy/README.md`, `docs/guias/chat.md` |
| Pruebas | `tests/cases/TC-F4.5-*.md`, `tests/e2e/chat.{ps1,sh}`, `control-plane/cercano-api/tests/chat_*.rs` |
| Estado | `docs/status/TAREAS.md`, `docs/status/informes/F4.5-*.md` |
