# Especificación de Cercano Chat

**Versión:** 1.0 · **Fecha:** 2026-11-09 · **Fase:** F4.5 · **Estado:** diseño aprobado; pendiente de implementación
**Documentos relacionados:** [`docs/adr/010-cercano-chat.md`](../adr/010-cercano-chat.md), [`docs/PLAN-F4.5-CHAT.md`](../PLAN-F4.5-CHAT.md), [`docs/specs/audit-events.md`](audit-events.md), [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md)

---

## 1. Propósito y alcance

Cercano Chat permite que la persona usuaria de un equipo con el cliente **Cercano Soporte** abra una conversación con el equipo técnico sin iniciar una sesión remota. Sirve para incidentes pequeños y permite escalar a una sesión remota cuando el chat no alcanza.

**La marca visible del chat (nombre de soporte, organización, logo, color de acento, textos de bienvenida/aviso/privacidad) se configura desde el panel de administración (`console-web`); no queda hardcodeada en el cliente ni depende solo del perfil del instalador.**

**Incluido en v1**

- Conversación de texto persistente, con historial y estado (`waiting`, `assigned`, `active`, `closed`).
- **Nombre visible del contacto:** la primera vez que se usa el chat (aplicación recién instalada o sin nombre guardado) el cliente pide **Nombre y Apellido**; en conversaciones posteriores los reutiliza. El técnico ve el nombre natural como etiqueta principal y el nombre del equipo como contexto.
- Cola y pantalla de gestión en `console-web`: filtros, reclamación, asignación, liberación, cierre, reapertura y escalado.
- Identidad por dispositivo, sin cuenta para el cliente final.
- Adjuntos: imágenes PNG/JPEG/WebP (en línea) y PDF (descarga).
- SSE para avisos en tiempo real; REST para todo lo demás.
- Notificaciones de escritorio en el cliente y en el navegador (sin contenido del mensaje).
- Auditoría `chat.*` sin cuerpo de mensajes.
- Retención configurable de mensajes y adjuntos.

**Fuera de alcance en v1**

- Aplicación separada, cliente web/PWA, cifrado extremo a extremo.
- Edición o borrado de mensajes, búsqueda full-text, respuestas rápidas, transcripciones, exportación.
- Antivirus de adjuntos, más formatos de archivo, audio/video, llamadas.
- Indicadores de escritura, presencia, multi-tenant.
- Linux/macOS como plataforma objetivo (la UI Flutter es portable, pero v1 se prueba en Windows 10/11).

---

## 2. Roles y capacidades

| Capacidad | Cliente final (`soporte`) | Técnico (`chat:attend`) | Supervisor (`chat:manage`) | Auditor (`chat:read`) |
|---|---|---|---|---|
| Iniciar conversación | Sí (una abierta por dispositivo) | No | No | No |
| Ver su conversación / historial | Sí | Sí | Sí | Sí |
| Ver cola en espera | No | Sí | Sí | Sí |
| Ver conversación de otro técnico | No | No | Sí | Sí |
| Reclamar / liberar | No | Sí | Sí | No |
| Asignar a otro / reabrir | No | No | Sí | No |
| Responder / adjuntar | No | Sí, en las suyas | Sí, en todas | No |
| Cerrar | Su conversación | Las suyas | Todas | No |
| Escalar a sesión remota | No | Sí, en las suyas | Sí, en todas | No |
| Resetear identidad de dispositivo | No | No | Sí | No |

Los permisos se definen en F4 (RBAC). Mientras F4 no esté cerrado, F4.5 solo se usa en laboratorio; no se inventa un sistema de permisos paralelo.

---

## 3. Arquitectura y flujo

```
Cliente Cercano (Flutter + Rust, parche 006)
  │  HTTPS  REST /api/chat/*  +  SSE /api/chat/events
  ▼
cercano-api (axum)
  ├─ chat_devices, nonces y sesiones de dispositivo (Ed25519)
  ├─ conversaciones, mensajes, adjuntos y lecturas (SQLite)
  ├─ ChatHub (broadcast) → SSE con pokes sin contenido
  ├─ audit-core: categoría chat (sin contenido)
  └─ tarea diaria de retención de mensajes/adjuntos
  ▲
  │ HTTPS  REST + SSE
console-web (técnicos)
  └─ pestaña «Conversaciones» + notificaciones del navegador
```

- No hay puerto ni servicio nuevo: todo pasa por `cercano-web` (443) hacia `cercano-api:21114`.
- **TLS obligatorio.** El cliente no inicia el chat si `api_server` no empieza por `https://`; el token de registro nunca se envía en claro.
- El **cliente no es fuente de verdad**: el historial vive en el servidor. Al abrir, carga la conversación abierta y los mensajes; si estuvo cerrado, los mensajes nuevos aparecen al arrancar.

### 3.1 Flujo de una conversación

1. La persona usuaria pulsa «Chat de soporte» en el cliente. La primera vez completa **Nombre y Apellido**; después escribe el primer mensaje y lo envía.
2. El cliente se registra/autentica si hace falta y crea la conversación (`waiting`). La API emite `chat.opened` y `chat.message.created` y avisa a la cola por SSE.
3. Un técnico ve la conversación en `console-web`, la reclama (`assigned`) y responde. Al primer mensaje del técnico pasa a `active`.
4. Cada mensaje o adjunto se persiste y se avisa al otro lado con un poke; el receptor consulta por REST con su token.
5. El técnico cierra (`closed`) o la persona usuaria cierra desde el cliente. La conversación queda de solo lectura.
6. Si hace falta, el técnico escala a una sesión remota; la sesión conserva el consentimiento normal y comparte `trace_id` con la conversación.

---

## 4. Identidad y autenticación

### 4.1 Cliente final (dispositivo)

Sin cuenta. El cliente usa el par Ed25519 con el que ya se identifica ante el servidor de rendezvous (`Config::get_key_pair` en el cliente). El flujo es:

1. **Registro (una vez):** `POST /api/chat/devices/register` con `X-Cercano-Client-Token`, `device_id`, `public_key` e `installer_id` si el perfil lo aporta. El servidor fija la clave (TOFU). Si ya existe otra clave para ese `device_id`, responde `409 key_mismatch`, audita y no permite chat hasta un reset administrativo.
2. **Reto:** `POST /api/chat/auth/challenge` → nonce de 32 bytes, un solo uso, 120 s.
3. **Firma:** el cliente firma el nonce con su clave privada Ed25519.
4. **Verificación:** `POST /api/chat/auth/verify` → token opaco `cercano_chat_<64 hex>`, 15 min.
5. **Uso:** `Authorization: Bearer cercano_chat_…` en REST y SSE. Al expirar o revocarse, el cliente repite el reto. La SSE valida el token al conectar y cada 60 s; si deja de ser válido, cierra el stream.

**Token de despliegue:** en v1 el registro usa el `CERCANO_CLIENT_INGEST_TOKEN` ya existente, solo sobre HTTPS y con límite de 5 registros/hora/IP. Es un secreto de despliegue, no por dispositivo; la clave Ed25519 fijada es la identidad real. Cuando F3-07 emita tokens de registro por instalador, se sustituye y se retira del flujo de chat.

**Reset:** un `chat:manage` puede revocar la identidad (`POST /api/chat/devices/{device_id}/reset`), lo que invalida clave, nonces y tokens y deja evento `chat.device.revoked`. La persona usuaria vuelve a registrar en el siguiente uso.

### 4.2 Técnicos

Usan el token de sesión existente (`cercano_sess_…`) de `POST /api/auth/login` y los permisos de F4:

- `chat:attend`: cola, conversaciones propias, responder, adjuntar, cerrar.
- `chat:manage`: todo, asignar, reabrir, resetear identidades.
- `chat:read`: lectura total sin escritura.

En producción el permiso `chat:attend` exige 2FA (F4). La API comprueba el permiso en cada ruta y devuelve `403` sin filtrar datos.

### 4.3 Reglas de autenticación

- Registro y reto: solo HTTPS; el registro falla en cerrado si el token de despliegue no está configurado.
- Nonces de un solo uso; un nonce usado, caducado o de otro dispositivo se rechaza con `401`.
- Tokens de chat almacenados en la base; se pueden revocar individualmente; caducan a los 15 min.
- El cliente guarda el token **solo en memoria**; nunca en disco, logs, portapapeles ni telemetría.
- Límites: challenge 10/min/dispositivo; verify 20/min/dispositivo; registro 5/hora/IP. Un exceso devuelve `429` con `Retry-After`.
- Cambiar de dispositivo, reinstalar o rotar la clave exige reset administrativo. La UI muestra un mensaje claro («Contacta a soporte para restablecer el chat»), no un error genérico.

### 4.4 Nombre visible del contacto (cliente final)

El nombre del equipo (`device_name`/`hostname`) no basta para que el técnico identifique a la persona ni para que esta reconozca con quién habla. Por eso, la primera vez que se usa el chat se piden **Nombre y Apellido**.

- **Cuándo se pide:** al abrir el chat por primera vez, antes de crear la primera conversación, si el cliente no tiene un nombre guardado (aplicación recién instalada o configuración local perdida). Los campos son obligatorios: 1–64 caracteres cada uno, sin caracteres de control, con espacios recortados; se admiten letras Unicode, tildes, guiones y apóstrofos.
- **Dónde se guarda:** solo en la configuración local del cliente, como dos valores (`chat-contact-first-name`, `chat-contact-last-name`). No hay cuenta ni tabla de contactos. En conversaciones posteriores se precarga y se reutiliza; «Editar nombre» permite cambiarlo y el cambio aplica a conversaciones nuevas (las anteriores conservan su snapshot).
- **Qué viaja al servidor:** `contact_first_name` y `contact_last_name` al crear la conversación. La API los guarda como **snapshot en `chat_conversations`**, junto al snapshot del equipo. No se guardan en una tabla de perfiles ni se asocian a una cuenta.
- **Qué ve el técnico:** nombre y apellido como etiqueta principal, y el nombre del equipo/hostname como secundario (por ejemplo, «Ana Pérez · PC-RECEPCION»). La búsqueda de la cola incluye el nombre del contacto y el del equipo.
- **Privacidad:** el nombre es un dato personal. No se escribe en auditoría, logs, telemetría ni notificaciones; se borra con la conversación según la retención. Si el cliente no lo envía (por ejemplo, una conversación heredada), la consola muestra el nombre del equipo como respaldo.
- **Reinstalación:** al no existir el valor local, se vuelve a pedir. Si el equipo conserva una conversación abierta, esta sigue visible; el formulario se pide para la siguiente conversación nueva.

---

## 5. Modelo de datos

Migración **008_chat_schema**, aditiva. Se aplica **después de la 007 de F4** (`007_console_rbac_2fa`) sobre bases existentes sin tocar tablas previas. `schema_migrations` pasa de 7 a 8 filas.

```sql
CREATE TABLE IF NOT EXISTS chat_devices (
    device_id    TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    public_key   TEXT NOT NULL,
    installer_id TEXT,
    display_name TEXT,
    last_auth_at TEXT,
    revoked_at   TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chat_auth_nonces (
    id         TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES chat_devices(device_id) ON DELETE CASCADE,
    nonce      TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chat_device_sessions (
    token      TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES chat_devices(device_id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chat_conversations (
    id               TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    device_name      TEXT,
    device_hostname  TEXT,
    device_os        TEXT,
    installer_id     TEXT,
    status           TEXT NOT NULL DEFAULT 'waiting'
                     CHECK (status IN ('waiting','assigned','active','closed')),
    assigned_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    contact_first_name TEXT,
    contact_last_name  TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    last_message_at  TEXT,
    closed_at        TEXT,
    closed_by        TEXT
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id                TEXT PRIMARY KEY,
    conversation_id   TEXT NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
    sender_type       TEXT NOT NULL CHECK (sender_type IN ('client','technician','system')),
    sender_id         TEXT,
    sender_name       TEXT,
    body              TEXT NOT NULL DEFAULT '',
    client_message_id TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chat_attachments (
    id            TEXT PRIMARY KEY,
    message_id    TEXT NOT NULL UNIQUE REFERENCES chat_messages(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    mime          TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    storage_key   TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chat_reads (
    conversation_id TEXT NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
    reader_type     TEXT NOT NULL CHECK (reader_type IN ('device','user')),
    reader_id       TEXT NOT NULL,
    last_read_at    TEXT NOT NULL,
    PRIMARY KEY (conversation_id, reader_type, reader_id)
);

CREATE TABLE IF NOT EXISTS chat_branding (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    organization_name TEXT,
    support_name      TEXT NOT NULL DEFAULT 'Cercano Soporte',
    logo_url          TEXT,
    accent_color      TEXT NOT NULL DEFAULT '#3B5BFF',
    welcome_text      TEXT,
    info_text         TEXT,
    privacy_text      TEXT,
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by        TEXT
);
INSERT OR IGNORE INTO chat_branding (id) VALUES (1);

CREATE INDEX IF NOT EXISTS idx_chat_conversations_status
    ON chat_conversations(status, last_message_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_conversations_assignee
    ON chat_conversations(assigned_user_id, status);
CREATE INDEX IF NOT EXISTS idx_chat_conversations_device
    ON chat_conversations(device_id, status);
CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation
    ON chat_messages(conversation_id, created_at, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_messages_client_id
    ON chat_messages(conversation_id, sender_type, sender_id, client_message_id)
    WHERE client_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_chat_attachments_message
    ON chat_attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_chat_device_sessions_expiry
    ON chat_device_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_chat_nonces_expiry
    ON chat_auth_nonces(expires_at);
CREATE INDEX IF NOT EXISTS idx_chat_reads_reader
    ON chat_reads(reader_type, reader_id);
```

### Decisiones del modelo

- **Snapshot del equipo:** `chat_conversations` guarda `device_name`, `device_hostname` y `device_os` y **no tiene FK a `devices`**. Borrar un dispositivo no borra el historial de conversaciones. `chat_devices` sí tiene FK a `devices` (la identidad muere con el dispositivo).
- **Snapshot del contacto:** `contact_first_name` y `contact_last_name` se congelan al crear la conversación para que el técnico vea el nombre natural y el historial no cambie si la persona edita su nombre local después. Son datos personales: se borran con la conversación y no se auditan.
- **Snapshot del remitente:** `sender_name` congela el nombre visible del técnico o del equipo, para que el historial siga siendo legible si el usuario se renombra o se elimina.
- **Sin FK para el remitente:** `sender_id` es un string; la conversación debe sobrevivir al borrado del usuario.
- **Idempotencia:** `client_message_id` (UUIDv7 generado por el cliente) evita duplicados en reintentos. Un único índice parcial cubre la combinación.
- **Una conversación abierta por dispositivo:** lo garantiza la lógica de `POST /conversations` dentro de una transacción, no un constraint, porque la definición de «abierta» es un conjunto de estados.
- **Cierre de usuario técnico:** si F4 borra un usuario, `assigned_user_id` queda `NULL`; F4.5-04 debe liberar sus conversaciones abiertas a `waiting` en la misma operación.

### 5.1 Estados

```
waiting ──claim/assign──► assigned ──primer mensaje técnico──► active
   ▲                         │                                   │
   └────release──────────────┴──────────────close────────────────┤
                              closed ──reopen (chat:manage)──► waiting
```

- `waiting`: sin técnico. Visible en la cola.
- `assigned`: técnico asignado; todavía no respondió.
- `active`: hubo respuesta técnica.
- `closed`: solo lectura. `closed_by` = `device:<id>`, `user:<id>` o `system`.
- `close` es idempotente: cerrar una cerrada devuelve `200` con el estado actual.
- Un dispositivo con una conversación abierta recibe esa conversación al iniciar otra; el primer mensaje se añade a la existente.
- No hay estado `abandoned` en v1; la retención limpia las cerradas antiguas y la cola puede cerrarse manualmente.

### 5.2 Retención

- Mensajes y adjuntos de conversaciones **cerradas** se eliminan a los **90 días** del cierre (`CERCANO_CHAT_RETENTION_DAYS`, configurable). La conversación se conserva como registro mínimo (cabecera) o se elimina en cascada con sus mensajes; el borrado de mensajes/adjuntos es lo importante. Se elimina la conversación completa al purgar.
- Conversaciones **abiertas** no se purgan, aunque sean antiguas; la cola las muestra y un administrador puede cerrarlas.
- La tarea de retención corre al arrancar y cada 24 h; registra `chat.retention.purged` con el corte y los contadores. Si falla, se registra y se reintenta en la siguiente ejecución.
- La retención de **auditoría** es independiente: los eventos `chat.*` siguen la política de auditoría (365 días por defecto) y no contienen contenido.

---

## 6. API

Base: `/api/chat`. Todas las respuestas son JSON salvo el stream SSE, la subida/descarga de adjuntos y las respuestas `204`. Convenciones existentes: `x-trace-id` opcional, errores `{ "error": "...", "message": "..." }`, `Authorization: Bearer`.

### 6.1 Registro y sesión del dispositivo

#### `POST /api/chat/devices/register`

Cabeceras: `X-Cercano-Client-Token: <token de despliegue>`, `Content-Type: application/json`. Solo HTTPS.

```json
{
  "device_id": "123456789",
  "public_key": "Base64-Ed25519-32-bytes",
  "installer_id": "0192e2fb-3d5a-7182-9654-2c7da197824b",
  "display_name": "PC-RECEPCION"
}
```

- `201` `{ "device_id": "...", "status": "registered", "registered_at": "..." }`
- `200` `{ "device_id": "...", "status": "already_registered", "registered_at": "..." }` si la clave coincide.
- `409` `key_mismatch` si ya hay otra clave; no se modifica nada.
- `401` token ausente/incorrecto; `403` HTTP; `429` límite.

#### `POST /api/chat/auth/challenge`

```json
{ "device_id": "123456789" }
```

`200`:

```json
{
  "challenge_id": "0192e2fb-3d5a-7182-9654-2c7da197824c",
  "nonce": "Base64-32-bytes",
  "expires_at": "2026-11-09T10:31:00.000Z"
}
```

`404` si el dispositivo no está registrado o está revocado; `429` límite. El nonce es de un solo uso y caduca en 120 s.

#### `POST /api/chat/auth/verify`

```json
{
  "challenge_id": "0192e2fb-3d5a-7182-9654-2c7da197824c",
  "signature": "Base64-Ed25519-del-nonce"
}
```

`200`:

```json
{
  "token": "cercano_chat_<64 hex>",
  "expires_at": "2026-11-09T10:45:00.000Z"
}
```

`401` firma inválida, reto usado/caducado o dispositivo revocado. El token vale 15 min; se acepta hasta 3 conexiones SSE simultáneas por dispositivo.

#### `POST /api/chat/devices/{device_id}/reset` (`chat:manage`)

Invalida clave, nonces y tokens; `200` `{ "device_id": "...", "status": "reset" }`. Audita `chat.device.revoked`.

### 6.2 Conversaciones (dispositivo y técnico)

#### `POST /api/chat/conversations`

Auth: token de chat del dispositivo. Cuerpo:

```json
{
  "contact_first_name": "Ana",
  "contact_last_name": "Pérez",
  "body": "Hola, no puedo imprimir",
  "client_message_id": "0192e2fb-3d5a-7182-9654-2c7da197824c"
}
```

- `201` si crea la conversación; `200` si ya había una abierta (y añade el mensaje). Devuelve `ConversationDetail` con los últimos 50 mensajes.
- `400` si `contact_first_name`/`contact_last_name` faltan o exceden 64 caracteres, o si `body` está vacío o supera 4 000 caracteres.
- `429` por límite diario de conversaciones. Si la conversación anterior está cerrada, se crea una nueva.
- El nombre y apellido se guardan como snapshot; no se actualizan en conversaciones existentes.

#### `GET /api/chat/conversations/{id}?limit=50&before=<message_id>`

Auth: dispositivo dueño, técnico con acceso o `chat:read`/`chat:manage`. Devuelve `ConversationDetail` con mensajes anteriores a `before` (si se indica) y `next_before`. `403`/`404` si no tiene acceso.

#### `POST /api/chat/conversations/{id}/messages`

```json
{ "body": "Sigue sin imprimir", "client_message_id": "0192..." }
```

`201` `Message`; `400` vacío/largo; `403` sin acceso; `409` conversación cerrada; `429` límite. Si `client_message_id` ya existe, devuelve `200` con el mensaje existente (idempotencia).

#### `POST /api/chat/conversations/{id}/attachments`

Cuerpo binario. Cabeceras obligatorias:

| Cabecera | Valor |
|---|---|
| `Content-Type` | `image/png`, `image/jpeg`, `image/webp` o `application/pdf` |
| `X-File-Name-B64` | Nombre original UTF-8 codificado en Base64 (máx. 255 bytes) |
| `X-Client-Message-Id` | UUIDv7 del cliente (idempotencia) |

El servidor valida MIME + **magic bytes**, tamaño y que la conversación esté abierta y accesible. Crea un mensaje con `body` vacío y su adjunto. `201` `Message` con `attachment`; `413` tamaño; `415` tipo; `409` cerrada; `429` límite.

#### `GET /api/chat/attachments/{id}`

Auth: dispositivo dueño o técnico con acceso. Responde bytes con `Content-Type` del adjunto, `Content-Disposition: attachment; filename="adjunto-<id>.<ext>"`, `X-Content-Type-Options: nosniff`, `Cache-Control: private, no-store`. No hay URL pública.

#### `POST /api/chat/conversations/{id}/read`

Auth: dispositivo o técnico con acceso. Sin cuerpo. `204`. Actualiza `chat_reads.last_read_at` al instante del servidor. El otro participante lo ve como `other_last_read_at` en el siguiente `GET`/refetch y puede mostrar el doble check.

#### `POST /api/chat/conversations/{id}/close`

Auth: dispositivo dueño o técnico con acceso. Cuerpo opcional `{ "reason": "resolved" }` (máx. 256). `200` `ConversationSummary`. Idempotente.

#### Operaciones del técnico

| Ruta | Permiso | Cuerpo / respuesta |
|---|---|---|
| `GET /api/chat/conversations?status=waiting&assigned=me&q=texto&limit=50&cursor=...` | `chat:attend` | `{ "conversations": [...], "next_cursor": null }` |
| `GET /api/chat/conversations/{id}` | `chat:attend` | `ConversationDetail` |
| `POST /api/chat/conversations/{id}/claim` | `chat:attend` | `200` `ConversationSummary`; `409 already_assigned` |
| `POST /api/chat/conversations/{id}/release` | asignado o `chat:manage` | `200`; vuelve a `waiting` |
| `POST /api/chat/conversations/{id}/assign` | `chat:manage` | `{ "user_id": "..." }` → `200` |
| `POST /api/chat/conversations/{id}/close` | `chat:attend` | `200` |
| `POST /api/chat/conversations/{id}/reopen` | `chat:manage` | `200`; vuelve a `waiting` sin asignar |
| `POST /api/chat/conversations/{id}/escalate` | asignado o `chat:manage` | `{ "trace_id"?: "..." }` → `200` `{ "device_id": "...", "trace_id": "...", "url": "cercano://connect?device=...&trace=..." }` |
| `GET /api/chat/agents` | `chat:manage` | `{ "agents": [{ "id": "...", "username": "..." }] }` |
| `GET /api/chat/summary` | `chat:attend` | `{ "waiting": 3, "assigned_to_me": 1, "active": 2, "unread": 4 }` |

`q` busca en `device_name`, `device_hostname`, `contact_first_name` y `contact_last_name` (LIKE, sin full-text). `status` acepta `waiting`, `assigned`, `active`, `closed` o `open` (los tres primeros). La lista se ordena por `last_message_at DESC` (o `created_at` si no hay mensajes) y usa un cursor opaco para la página siguiente.

### 6.3 Branding del chat

#### `GET /api/chat/branding`

Público, sin autenticación ni secretos. Devuelve el objeto de marca. Si no hay fila, se usan los defaults.

**Respuesta `200`:**

```json
{
  "organization_name": null,
  "support_name": "Cercano Soporte",
  "logo_url": null,
  "accent_color": "#3B5BFF",
  "welcome_text": null,
  "info_text": null,
  "privacy_text": null,
  "updated_at": "2026-11-09T10:20:00.000Z",
  "updated_by": null
}
```

#### `PUT /api/chat/branding`

Permiso: `chat:manage_branding` (solo `admin`; ver `PLAN-F4-CONSOLA.md` §3). Valida y actualiza la fila singleton; audita `chat.branding.updated`.

**Cuerpo:**

```json
{
  "organization_name": "Mi Organización",
  "support_name": "Soporte Técnico",
  "logo_url": "https://cdn.ejemplo.com/logo.svg",
  "accent_color": "#1A73E8",
  "welcome_text": "¡Bienvenido! Un técnico le atenderá en breve.",
  "info_text": "Está conversando con el equipo de soporte de Mi Organización.",
  "privacy_text": "Su consulta es confidencial. Se guarda un historial para seguimiento."
}
```

**Validaciones:**
- `organization_name` ≤ 128 caracteres (puede ser `null`/vacío).
- `support_name` 1–64 caracteres.
- `logo_url`: debe ser `https://` o cadena vacía/`null`.
- `accent_color`: formato `#RRGGBB` (7 caracteres, hexadecimal).
- `welcome_text`, `info_text`, `privacy_text`: ≤ 512 caracteres cada uno (pueden ser `null`/vacío).

**Respuestas:**
- `200` con el objeto actualizado.
- `400` `validation_error` si algún campo no pasa la validación.
- `403` sin permiso `chat:manage`.
- `401` token ausente/incorrecto.

---

### 6.4 Objetos

**`ConversationSummary`**

```json
{
  "id": "0192e2fb-3d5a-7182-9654-2c7da197824c",
  "device_id": "123456789",
  "device_name": "PC-RECEPCION",
  "device_hostname": "WS-RECEPCION",
  "device_os": "Windows 11 Pro",
  "status": "waiting",
  "assigned_user_id": null,
  "assigned_username": null,
  "contact_first_name": "Ana",
  "contact_last_name": "Pérez",
  "created_at": "2026-11-09T10:20:00.000Z",
  "updated_at": "2026-11-09T10:20:00.000Z",
  "last_message_at": "2026-11-09T10:20:00.000Z",
  "last_message_preview": "Hola, no puedo imprimir",
  "unread_count": 1
}
```

**`ConversationDetail`** = `ConversationSummary` + `closed_at`, `closed_by`, `messages` (máx. 50), `next_before` y `other_last_read_at` (última lectura del otro participante, para el doble check; `null` si no hay).

**`Message`**

```json
{
  "id": "0192e2fb-3d5a-7182-9654-2c7da1978250",
  "conversation_id": "0192e2fb-3d5a-7182-9654-2c7da197824c",
  "sender_type": "client",
  "sender_id": "123456789",
  "sender_name": "PC-RECEPCION",
  "body": "Hola, no puedo imprimir",
  "attachment": null,
  "created_at": "2026-11-09T10:20:00.000Z"
}
```

**`Attachment`**

```json
{
  "id": "0192e2fb-3d5a-7182-9654-2c7da1978251",
  "name": "captura.png",
  "mime": "image/png",
  "size_bytes": 48213,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

`last_message_preview` se trunca a 160 caracteres y no incluye adjuntos (si el último mensaje es solo adjunto, muestra `[adjunto]`).

### 6.5 Errores

| HTTP | `error` | Cuándo |
|---|---|---|
| 400 | `validation_error` | Campo vacío, largo, cursor inválido, `contact_first_name`/`contact_last_name`/`reason` fuera de rango; campos de branding inválidos |
| 401 | `unauthorized` | Token ausente, inválido, expirado, reto usado/caducado, firma inválida |
| 403 | `forbidden` | Sin permiso, conversación ajena, HTTP en registro, chat desactivado por política |
| 404 | `not_found` | Conversación, mensaje, adjunto o dispositivo inexistente |
| 409 | `key_mismatch` / `already_assigned` / `conversation_closed` | Conflicto de estado |
| 413 | `payload_too_large` | Adjunto > 10 MiB |
| 415 | `unsupported_media_type` | Tipo no permitido o magic bytes no coinciden |
| 429 | `rate_limited` | Límite; incluye `Retry-After` |
| 500 | `internal_error` | Fallo interno; no filtra detalles |

---

## 7. SSE (avisos en tiempo real)

### `GET /api/chat/events`

Auth: `Authorization: Bearer cercano_chat_…` (dispositivo) o `cercano_sess_…` (técnico). Responde `text/event-stream`:

```
event: poke
id: 0192e2fb-3d5a-7182-9654-2c7da1978260
data: {"type":"message","conversation_id":"0192e2fb-3d5a-7182-9654-2c7da197824c","message_id":"0192e2fb-3d5a-7182-9654-2c7da1978250"}

: ping
```

- **El poke no contiene texto ni adjuntos.** El receptor consulta por REST con su token. Así un fallo de filtrado no filtra contenido.
- `type`: `message` (mensaje nuevo), `status` (claim/release/close/reopen), `queue` (conversación nueva o cambio de cola), `resync` (el receptor se atrasó; refetchear).
- **Audiencias:** `Device(device_id)` recibe solo su conversación; `User(user_id)` recibe las suyas asignadas; `Queue` recibe metadatos de cola para técnicos. Un dispositivo nunca recibe pokes de otro.
- **Heartbeat:** comentario `: ping` cada 15 s (`CERCANO_CHAT_SSE_HEARTBEAT_SECS`).
- **Reconexión:** el cliente reconecta con espera exponencial (1, 2, 5, 30 s) y refetchea al conectar. Al reconectar no hay pérdida: los mensajes están en la base. No se implementa polling de respaldo en v1.
- **Atraso:** si el consumidor no puede seguir el `broadcast` (capacidad 256), recibe `resync` y refetchea.
- **Caducidad/revocación:** el servidor valida el token al conectar y cada 60 s; si deja de ser válido, cierra el stream.
- **Proxy:** el servidor envía `X-Accel-Buffering: no`; nginx necesita `proxy_buffering off` y `proxy_read_timeout` largo para `/api/chat/events`.

---

## 8. Adjuntos

| Regla | Valor v1 |
|---|---|
| Tipos | `image/png`, `image/jpeg`, `image/webp` (en línea), `application/pdf` (descarga) |
| Rechazados | SVG, HTML, ejecutables, scripts, ZIP/archivos comprimidos, Office, cualquier otro |
| Tamaño | 10 MiB por archivo (`CERCANO_CHAT_MAX_ATTACHMENT_BYTES`) |
| Cantidad | 1 por mensaje; 20/día/dispositivo; 3/min/dispositivo |
| Cuota | 50 MiB por conversación (suma de adjuntos) |
| Validación | MIME declarado **y** magic bytes; tamaño; conversación abierta; permisos |
| Hash | SHA-256 calculado en el servidor; se guarda y se audita |
| Nombre | Base64 en `X-File-Name-B64`; se decodifica, se toma el basename, se recortan controles; se guarda como `original_name` |
| Almacenamiento | `CERCANO_CHAT_ATTACHMENT_DIR/<año>/<mes>/<uuid>`; permisos 0600; escritura atómica |
| Descarga | Endpoint autenticado; nombre genérico; `nosniff`; `no-store`; sin URL pública |
| Antivirus | No en v1; punto de extensión `chat_attachment_scanner`; los PDF se abren fuera de la app bajo responsabilidad del técnico |

Si falla la transacción después de escribir el archivo, se borra el archivo. Un mensaje con adjunto tiene `body` vacío; se muestran la miniatura (imágenes) o una tarjeta con nombre y tamaño (PDF). No se permite adjuntar antes de crear la conversación: el primer mensaje es texto.

---

## 9. Escalado a sesión remota

- En `console-web`, el botón **«Abrir sesión remota»** emite `chat.escalated` y abre `cercano://connect?device=<device_id>&trace=<conversation_id>` en el equipo del técnico.
- El cliente Cercano Técnico maneja el esquema y usa `trace` como `conn_audit_ref`/`trace_id` de la sesión. La conversación y la sesión remota comparten traza.
- La sesión remota conserva el **consentimiento normal de la persona usuaria** (F3-14); el chat no concede acceso. Si el equipo está fuera de línea, la consola muestra el estado del dispositivo y no intenta la conexión.
- Respaldo si el esquema no está registrado o el cliente no está instalado: diálogo con el ID del dispositivo y botón «Copiar ID».
- El registro de `cercano://` se hace en F4.5-12 junto con el empaquetado (F3-05); `rustdesk://` puede quedar como alias interno, nunca visible en la UI.

---

## 10. Auditoría

Categoría `chat` en `audit-core` y en [`docs/specs/audit-events.schema.json`](audit-events.schema.json). `source: api`; `trace_id` = `conversation_id` en los eventos de conversación.

| Acción | Actor | Subject | `details` (sin contenido) |
|---|---|---|---|
| `chat.device.registered` | device | device | `installer_id`, `ip` |
| `chat.device.key_mismatch` | device | device | `reason: key_mismatch` |
| `chat.device.revoked` | user/system | device | `reason` |
| `chat.auth.failed` | device | device | `reason` (`invalid_signature`, `challenge_expired`, `challenge_used`, `device_revoked`) |
| `chat.opened` | device | conversation | `device_id`, `installer_id` |
| `chat.message.created` | device/user | conversation | `message_id`, `sender_type`, `length`, `has_attachment` |
| `chat.attachment.created` | device/user | conversation | `message_id`, `attachment_id`, `mime`, `size_bytes`, `sha256` |
| `chat.assigned` | user | conversation | `from_user_id`, `to_user_id` |
| `chat.released` | user | conversation | `previous_user_id` |
| `chat.closed` | device/user | conversation | `closed_by`, `reason` |
| `chat.reopened` | user | conversation | `conversation_id` |
| `chat.escalated` | user | conversation | `device_id`, `trace_id` |
| `chat.rate_limited` | device/user | conversation/device | `limit`, `retry_after_secs` |
| `chat.denied` | device/user | conversation | `reason`, `required_permission` |
| `chat.retention.purged` | system | system | `cutoff`, `conversations_deleted`, `messages_deleted`, `attachments_deleted` |
| `chat.branding.updated` | user | system | `fields` (lista de campos cambiados; sin secretos) |

Prohibido en `details`: cuerpo del mensaje, **nombre o apellido del contacto**, nombre original del adjunto, tokens, claves privadas, contenido de archivos. Los eventos de retención se conservan según la política de auditoría (365 días por defecto) aunque el mensaje ya no exista.

---

## 11. Seguridad, privacidad y modelo de amenazas

| Amenaza | Mitigación |
|---|---|
| Suplantación de dispositivo | Fijación de clave Ed25519 (TOFU) + token de despliegue solo HTTPS + reset auditado; a futuro, token por instalador. |
| Robo de token de chat | TTL 15 min, solo memoria, revocación, validación periódica de SSE, sin logs. |
| IDOR | Cada ruta comprueba dueño/asignación/permiso; pruebas con dos dispositivos y dos técnicos. |
| Replay de autenticación | Nonce único, caducidad 120 s, un solo uso, firma Ed25519. |
| Fuerza bruta / spam | Límites de tasa por dispositivo/IP/técnico; 429 + `Retry-After`; cierre y revocación administrativa. |
| Divulgación en el servidor | TLS, permisos, retención, respaldos protegidos; **sin E2E** documentado; los operadores con acceso al servidor pueden leer los mensajes. |
| XSS / inyección | React escapa; no se usa HTML; Flutter `Text`; nombres de adjunto escapados; `nosniff`. |
| Adjunto malicioso | Solo imágenes/PDF, magic bytes, tamaño, sin ejecución, descarga como adjunto; antivirus fuera de v1. |
| Fuga en notificaciones | Texto genérico, sin cuerpo; permiso explícito del navegador. |
| Sesión de consola robada | Mismo modelo que la consola actual (Bearer en localStorage); 2FA de F4; HTTPS. |
| Chat desactivado por política | `CERCANO_CHAT_ENABLED=false` corta las rutas y el cliente; evento/estado visible. |
| Fuga por logs | Nunca se registran cuerpos, tokens ni nombres de archivo; solo IDs, longitudes, MIME y tamaños. |

**Privacidad:** los mensajes se guardan en claro en SQLite y los adjuntos en disco. El nombre y apellido del contacto son datos personales: se guardan en el snapshot de la conversación, se borran con la retención y no se escriben en auditoría, logs, telemetría ni notificaciones. El operador debe proteger el volumen, los respaldos y el acceso físico/lógico al servidor; la retención limita la exposición. La persona usuaria ve un aviso de que la conversación es atendida por el equipo de soporte y de que se guarda un historial.

---

## 12. Configuración

| Variable | Defecto | Uso |
|---|---|---|
| `CERCANO_CHAT_ENABLED` | `true` | Interruptor global; si es `false`, las rutas responden `403 chat_disabled` y el cliente oculta el chat. |
| `CERCANO_CHAT_ATTACHMENT_DIR` | `/opt/cercano/data/chat-attachments` | Directorio de adjuntos; permisos 0600. |
| `CERCANO_CHAT_RETENTION_DAYS` | `90` | Retención de mensajes/adjuntos de conversaciones cerradas. |
| `CERCANO_CHAT_MAX_ATTACHMENT_BYTES` | `10485760` | Tamaño máximo por archivo. |
| `CERCANO_CHAT_DEVICE_TOKEN_TTL_MINUTES` | `15` | Vida del token de chat. |
| `CERCANO_CHAT_MESSAGE_RATE_PER_MINUTE` | `30` | Mensajes por dispositivo/minuto. |
| `CERCANO_CHAT_USER_MESSAGE_RATE_PER_MINUTE` | `60` | Mensajes por técnico/minuto. |
| `CERCANO_CHAT_CONVERSATION_DAILY_LIMIT` | `5` | Conversaciones nuevas por dispositivo/día. |
| `CERCANO_CHAT_ATTACHMENT_DAILY_LIMIT` | `20` | Adjuntos por dispositivo/día. |
| `CERCANO_CHAT_SSE_HEARTBEAT_SECS` | `15` | Latido SSE. |

**Nginx:** `location = /api/chat/events` con `proxy_buffering off`, `proxy_read_timeout 1h`, `proxy_http_version 1.1`; `client_max_body_size 12m` para `/api/chat/conversations/*/attachments` (o global). El resto de `/api/` mantiene 60 s.

**Perfil del instalador (F4.5-13):** extiende `policy` con un objeto opcional:

```json
"chat": {
  "enabled": true,
  "allow_attachments": true,
  "allow_remote_escalation": true
}
```

- `soporte`: `enabled` por defecto `true`; `tecnico`: por defecto `false`.
- Perfiles antiguos sin `chat` se interpretan con esos valores por defecto.
- El servidor aplica el rol de instalador (F3-13); el flag es política de UX y se registra en el instalador cuando F3-07 lo guarde. Un `tecnico` no puede abrir conversaciones aunque edite su configuración local.
- El cliente exige `api_server` HTTPS para habilitar el chat; un perfil con `chat.enabled=true` y API HTTP se rechaza con un aviso claro.

### 12.1 Marca del chat configurable

La fuente de la marca visible (nombre de la organización, nombre de soporte, logo, color de acento y textos de bienvenida/aviso/privacidad) es la tabla `chat_branding` y los endpoints `GET/PUT /api/chat/branding`. El cliente lee la marca al abrir la ventana del chat y la usa para la cabecera, el aviso, el pie y el color de acento. Si la API no está disponible o no hay configuración, hace fallback a los valores por defecto (`Cercano Soporte`, `#3B5BFF`, textos built-in) y, como último recurso, a la identidad del perfil del instalador (`identity.app_name`, `identity.icon`).

**Importante:** la identidad del instalador (ejecutable `.exe` e icono de la barra de tareas) **sigue siendo la del perfil firmado F3** porque se fija al instalar. Cambiar la marca del chat desde la consola no cambia el icono de la barra de tareas ni el nombre del ejecutable; eso requeriría regenerar el instalador con un nuevo perfil.

---

## 13. Compatibilidad y versionado

- La migración 008 es aditiva; no cambia tablas ni endpoints existentes. Se aplica después de la 007 de F4.
- La API de chat es v1 bajo `/api/chat`; un cambio incompatible requiere `/api/chat/v2` o un nuevo contrato documentado.
- El perfil gana un objeto opcional `chat`; el esquema sube de MINOR y los clientes antiguos rechazan perfiles que no entienden (comportamiento seguro). El generador no emite `chat` para clientes que no lo soportan.
- El parche 006 es aditivo y se registra en `patches/INDEX.md`; no reestructura rutas existentes.
- El chat no cambia el protocolo de rendezvous/relay ni los puertos.

---

## 14. Diseño de la ventana del cliente (referencia)

La ventana de chat es una **ventana dedicada** del mismo cliente Cercano (multi-window; pestaña como fallback si la plataforma no lo soporta), abierta desde el botón «Chat de soporte» del panel izquierdo o la bandeja. Tamaño inicial ~560×700 px, redimensionable, mínimo 380×520. Tema claro y oscuro del cliente; tipografía y espaciado existentes; sin animaciones que distraigan (respetar `prefers-reduced-motion` / reducción de movimiento de Flutter). Título: «Soporte <nombre de soporte>» y los controles de minimizar/cerrar de la ventana. El icono de la barra de tareas es el del perfil (F3); el icono por defecto es el de Cercano.

### 14.1 Anatomía y correspondencia con v1

| Zona | Comportamiento v1 |
|---|---|
| **Cabecera** | Usa `support_name`/`organization_name`/`logo_url`/`accent_color` de la configuración admin (`GET /api/chat/branding`). Muestra logo (si hay `logo_url`) o icono del perfil; título «Soporte <support_name>»; subtítulo con `organization_name` si está definido. Estado del servicio: «En línea» (API alcanzable y chat habilitado), «Reconectando» (SSE/REST caídos) o «Atendido por <técnico>» cuando está asignada. El punto verde va acompañado de texto, nunca solo color. |
| **Aviso** | Tarjeta informativa con `info_text` de la configuración; si no hay, «Está conversando con un técnico de soporte de <organization_name o support_name>.» Se muestra al inicio de la conversación y se puede colapsar; no ocupa espacio si ya hay historial. |
| **Hilo** | Burbujas del cliente a la derecha (color `accent_color`, texto blanco) y del técnico a la izquierda (superficie neutra). Avatar del cliente con icono/iniciales; del técnico, icono genérico de soporte o iniciales (sin foto). Hora local en cada mensaje. Separadores de fecha. Adjuntos como miniatura (imagen) o tarjeta con nombre/tamaño (PDF). Mensajes de sistema centrados. |
| **Leído** | Un check = enviado; doble check = el otro participante marcó leído (`other_last_read_at >= created_at`). No se muestra el doble check en mensajes propios de sistema. |
| **Composer** | Campo multilínea con `welcome_text` como placeholder si la conversación está vacía; botón de adjuntar (imagen/PDF), botón de enviar. `Enter` envía, `Shift+Enter` salta línea; enviar deshabilitado si está vacío o sin conexión; estado de subida y error visibles. |
| **Pie** | Texto `privacy_text` de la configuración; si no hay, «Su consulta es confidencial», con enlace/tooltip a la política: acceso restringido al equipo de soporte y retención configurable. Si la política no respalda «confidencial», se usa «Conversación privada · se guarda para seguimiento». |
| **Estados** | Sin conversación: bienvenida + formulario de Nombre/Apellido (primera vez) y «Iniciar conversación». En cola: «En espera de un técnico». Asignada/activa: nombre del técnico y composer. Cerrada: solo lectura + «Nueva conversación». Sin conexión: banner de reconexión y composer deshabilitado. |

### 14.2 Elementos que no son v1

- **Presencia por técnico y punto verde junto al avatar:** en v1 el verde significa «servicio en línea», no que una persona esté conectada. No hay presencia por técnico.
- **Indicador de escritura («…»):** fuera de v1 (requiere eventos efímeros de typing). Se reserva el espacio y se evalúa como mejora.
- **Foto del técnico:** se sustituye por icono genérico o iniciales; no se almacenan fotos.
- **Marca fija:** no hay marca fija. Todo (nombre, logo, color, textos) sale de la configuración admin (`GET /api/chat/branding`), con fallback a `Cercano Soporte` / `#3B5BFF` / textos built-in y, como último recurso, a la identidad del perfil del instalador.

### 14.3 Accesibilidad

- Contraste suficiente en ambos temas (el texto sobre el color de acento usa blanco; el punto verde se acompaña de texto).
- Navegación completa por teclado, foco visible, etiquetas semánticas y `aria`/Semantics en Flutter.
- Los mensajes nuevos se anuncian sin robar el foco; los adjuntos tienen nombre accesible y texto alternativo.
- No se depende solo del color para estado, leído o error.

---

## 15. Referencias

- [`docs/adr/010-cercano-chat.md`](../adr/010-cercano-chat.md)
- [`docs/PLAN-F4.5-CHAT.md`](../PLAN-F4.5-CHAT.md)
- [`docs/specs/audit-events.md`](audit-events.md)
- [`docs/PLAN-DE-PRUEBAS.md`](../PLAN-DE-PRUEBAS.md)
- [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md)
