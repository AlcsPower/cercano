# Guía de Despliegue y Operación de Cercano Chat

**Versión:** 1.0 · **Fecha:** 2026-11-09 · **Fase:** F4.5  
**Documentos de referencia:** [`docs/specs/chat.md`](../specs/chat.md), [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md), [`deploy/nginx.conf`](../../deploy/nginx.conf), [`deploy/README.md`](../../deploy/README.md), [`docs/guias/auditoria.md`](auditoria.md)

---

## 1. Prerrequisitos

### 1.1 Infraestructura obligatoria

| Componente | Versión mínima | Rol en Cercano Chat |
|------------|----------------|---------------------|
| **TLS/CA de confianza** | — | Terminación HTTPS en `cercano-web` (puerto 443). El cliente **no inicia el chat si `api_server` no empieza por `https://`**; el token de registro nunca se envía en claro. |
| **cercano-api** | F4.5 (migración 004 aplicada) | API REST + SSE: `/api/chat/*`. Autenticación Ed25519, conversaciones, mensajes, adjuntos, branding, retención, auditoría `chat.*`. |
| **cercano-web** (Nginx) | 1.27+ | Terminación TLS, proxy inverso a `cercano-api:21114`, configuración SSE y subida de adjuntos. |
| **console-web** | F4.5 | Pestaña «Conversaciones» para técnicos: cola, asignación, respuesta, adjuntos, cierre, reapertura, escalado, branding. |
| **Cliente Cercano Soporte** | F4.5 (parche 006) | Ventana de chat dedicada, registro de dispositivo, nombre/apellido del contacto, SSE, notificaciones, escalado `cercano://`. |

### 1.2 Por qué el chat exige HTTPS

- **Registro de dispositivo** (`POST /api/chat/devices/register`): envía la clave pública Ed25519 y el token de despliegue `CERCANO_CLIENT_INGEST_TOKEN`. En HTTP, cualquiera en la red captura la clave y suplantaría el dispositivo.
- **Reto/firma** (`/auth/challenge`, `/auth/verify`): el nonce y la firma viajan en el cuerpo. Sin TLS, un atacante reproduce el reto y obtiene tokens de chat.
- **Tokens de chat** (`cercano_chat_…`, 15 min): se usan en `Authorization: Bearer` en REST y SSE. En HTTP se roban y se usan para leer/escribir conversaciones ajenas.
- **SSE** (`/api/chat/events`): stream persistente con pokes; sin TLS, un proxy intermedio puede inyectar eventos o cerrar la conexión.

> **Si la API está en HTTP:** el cliente muestra un aviso claro («El chat requiere HTTPS») y **deshabilita el botón de chat**. No hay modo degradado.

---

## 2. Variables de entorno (`CERCANO_CHAT_*`)

Todas se configuran en `cercano-api` (Docker: `environment` en `docker-compose.yml`; systemd: `/opt/cercano/api.env`).

| Variable | Defecto | Descripción | Ejemplo producción |
|----------|---------|-------------|-------------------|
| `CERCANO_CHAT_ENABLED` | `true` | Interruptor global. `false` → rutas devuelven `403 chat_disabled`, cliente oculta el chat. | `true` |
| `CERCANO_CHAT_ATTACHMENT_DIR` | `/opt/cercano/data/chat-attachments` | Directorio raíz de adjuntos. Permisos **0600** en archivos; usuario `cercano` (UID 1000). | `/opt/cercano/data/chat-attachments` |
| `CERCANO_CHAT_RETENTION_DAYS` | `90` | Días tras el cierre para purgar mensajes y adjuntos. Conversaciones abiertas no se purgan. | `90` |
| `CERCANO_CHAT_MAX_ATTACHMENT_BYTES` | `10485760` (10 MiB) | Tamaño máximo por archivo. Nginx `client_max_body_size` debe ser ≥ este valor + margen. | `10485760` |
| `CERCANO_CHAT_DEVICE_TOKEN_TTL_MINUTES` | `15` | Vida del token `cercano_chat_…`. | `15` |
| `CERCANO_CHAT_MESSAGE_RATE_PER_MINUTE` | `30` | Mensajes por dispositivo/minuto. Exceso → `429` con `Retry-After`. | `30` |
| `CERCANO_CHAT_USER_MESSAGE_RATE_PER_MINUTE` | `60` | Mensajes por técnico/minuto. | `60` |
| `CERCANO_CHAT_CONVERSATION_DAILY_LIMIT` | `5` | Conversaciones nuevas por dispositivo/día. | `5` |
| `CERCANO_CHAT_ATTACHMENT_DAILY_LIMIT` | `20` | Adjuntos por dispositivo/día. | `20` |
| `CERCANO_CHAT_SSE_HEARTBEAT_SECS` | `15` | Intervalo de `: ping` en SSE. | `15` |

> **Pendiente:** `CERCANO_CHAT_ATTACHMENT_QUOTA_BYTES` (cuota por conversación, 50 MiB en spec) — no aparece como variable; se hardcodea en el código. Marcar como pendiente de exponer si se necesita ajustar sin recompilar.

---

## 3. Nginx: configuración para SSE y adjuntos

El archivo base es `deploy/nginx.conf`. Añada/ajuste lo siguiente **dentro del bloque `server { listen 443 ssl; ... }`**:

```nginx
# ── SSE: /api/chat/events ──
location = /api/chat/events {
    proxy_pass http://cercano-api:21114/api/chat/events;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;

    # Crítico para SSE
    proxy_buffering off;              # Sin buffering: eventos llegan en tiempo real
    proxy_read_timeout 1h;            # Stream largo; evita cierre por inactividad
    proxy_cache off;                  # No cachear el stream
    proxy_set_header Connection "";   # Mantiene keep-alive HTTP/1.1
}

# ── Subida de adjuntos: /api/chat/conversations/*/attachments ──
location ~ ^/api/chat/conversations/.*/attachments$ {
    proxy_pass http://cercano-api:21114;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;

    client_max_body_size 12m;         # ≥ CERCANO_CHAT_MAX_ATTACHMENT_BYTES (10 MiB) + cabeceras
    proxy_read_timeout 60s;
    proxy_request_buffering off;      # Envía el cuerpo sin buffer al upstream
}

# ── Resto de /api/ (ya existe, mantener 60s) ──
location /api/ {
    proxy_pass http://cercano-api:21114/api/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_connect_timeout 5s;
    proxy_read_timeout 60s;
}
```

### 3.1 Verificación rápida

```bash
# Recargar Nginx
docker compose exec cercano-web nginx -t && docker compose exec cercano-web nginx -s reload

# Probar SSE (requiere token de chat válido)
curl -N -H "Authorization: Bearer cercano_chat_XXXX" https://cercano.example.com/api/chat/events
# Debe responder text/event-stream y mostrar ": ping" cada 15s

# Probar subida de adjunto (10 MiB)
dd if=/dev/zero of=test.pdf bs=1M count=10
curl -X POST -H "Authorization: Bearer cercano_chat_XXXX" \
  -H "Content-Type: application/pdf" \
  -H "X-File-Name-B64: $(echo -n 'test.pdf' | base64)" \
  -H "X-Client-Message-Id: $(uuidgen)" \
  --data-binary @test.pdf \
  https://cercano.example.com/api/chat/conversations/<ID>/attachments
# Debe devolver 201 con el Message + Attachment
```

---

## 4. Almacenamiento de adjuntos

### 4.1 Estructura en disco

```
CERCANO_CHAT_ATTACHMENT_DIR/
├── 2026/
│   ├── 11/
│   │   ├── 0192e2fb-3d5a-7182-9654-2c7da1978251   (archivo binario, permisos 0600)
│   │   └── ...
│   └── 12/
└── 2027/
```

- **Permisos:** archivos `0600`, directorios `0700`. Usuario/grupo `cercano:cercano` (UID 1000).
- **Escritura atómica:** el servidor escribe en `<storage_key>.tmp` y renombra al finalizar.
- **Limpieza:** si la transacción falla tras escribir el archivo, el servidor borra el `.tmp`/archivo.

### 4.2 Respaldos (backup)

| Qué incluir | Qué NO incluir |
|-------------|----------------|
| Directorio completo `chat-attachments/` (estructura año/mes) | Archivos `.tmp` residuales (indican fallo previo) |
| Base de datos `cercano.db` (tablas `chat_attachments`, `chat_messages`, `chat_conversations`) | Cachés, logs, sockets, `lost+found` |
| Clave de firma de auditoría (`audit_signing_key`) | Claves privadas de `hbbs`/`hbbr` (están en otro directorio) |

**Comando de respaldo sugerido (bare-metal):**

```bash
#!/bin/bash
# backup-chat-attachments.sh — ejecutar diario via cron/systemd-timer
set -euo pipefail
DATE=$(date +%F)
DEST="/mnt/backups/cercano/chat-attachments-$DATE.tar.gz.enc"
tar -czf - -C /opt/cercano/data chat-attachments \
  | openssl enc -aes-256-gcm -salt -pbkdf2 -pass file:/etc/cercano/backup-passphrase \
  > "$DEST"
echo "Backup: $DEST ($(du -h "$DEST" | cut -f1))"
```

### 4.3 Cuota y limpieza

- **Cuota por conversación:** 50 MiB (suma de `size_bytes` en `chat_attachments` por `conversation_id`). Límite hardcodeado en v1 (ver *Pendiente* en §2).
- **Limpieza automática:** la tarea de retención (cada 24 h y al arrancar) elimina adjuntos de conversaciones **cerradas** con `closed_at` > `CERCANO_CHAT_RETENTION_DAYS` (90 por defecto). Evento `chat.retention.purged` registra contadores.
- **Limpieza manual (admin):**
  ```sql
  -- Identificar conversaciones cerradas antiguas con adjuntos huérfanos
  SELECT c.id, c.closed_at, SUM(a.size_bytes) AS total_bytes
  FROM chat_conversations c
  JOIN chat_messages m ON m.conversation_id = c.id
  JOIN chat_attachments a ON a.message_id = m.id
  WHERE c.status = 'closed' AND c.closed_at < datetime('now', '-90 days')
  GROUP BY c.id
  HAVING total_bytes > 52428800;  -- 50 MiB
  ```
  Borrar archivos huérfanos en disco que no tengan fila en `chat_attachments` (comparar `storage_key` con nombres de archivo).

---

## 5. Marca del chat desde el panel admin (F4.5-16)

### 5.1 Endpoints

| Método | Ruta | Permiso | Descripción |
|--------|------|---------|-------------|
| `GET` | `/api/chat/branding` | Público (sin auth) | Devuelve marca actual o defaults |
| `PUT` | `/api/chat/branding` | `chat:manage` | Valida y actualiza; audita `chat.branding.updated` |

### 5.2 Campos y validaciones

| Campo | Tipo | Reglas | Default |
|-------|------|--------|---------|
| `organization_name` | string | ≤ 128 chars, puede ser `null`/vacío | `null` |
| `support_name` | string | 1–64 chars, obligatorio | `Cercano Soporte` |
| `logo_url` | string | **Debe ser `https://`** o `null`/vacío; sin `http://` ni `data:` | `null` |
| `accent_color` | string | **Formato `#RRGGBB`** (7 chars hex), ej. `#1A73E8` | `#3B5BFF` |
| `welcome_text` | string | ≤ 512 chars, puede ser `null` | `null` |
| `info_text` | string | ≤ 512 chars, puede ser `null` | `null` |
| `privacy_text` | string | ≤ 512 chars, puede ser `null` | `null` |

### 5.3 Ejemplo de actualización

```bash
curl -X PUT -H "Authorization: Bearer cercano_sess_XXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_name": "Mi Organización",
    "support_name": "Soporte Técnico",
    "logo_url": "https://cdn.ejemplo.com/logo.svg",
    "accent_color": "#1A73E8",
    "welcome_text": "¡Bienvenido! Un técnico le atenderá en breve.",
    "info_text": "Está conversando con el equipo de soporte de Mi Organización.",
    "privacy_text": "Su consulta es confidencial. Se guarda un historial para seguimiento."
  }' \
  https://cercano.example.com/api/chat/branding
```

### 5.4 Fallback y efecto sin reinstalar

1. **Fuente primaria:** `GET /api/chat/branding` → tabla `chat_branding`.
2. **Fallback 1:** defaults hardcodeados en el cliente (`Cercano Soporte`, `#3B5BFF`, textos built-in).
3. **Fallback 2 (último recurso):** identidad del perfil del instalador (`identity.app_name`, `identity.icon`).

> **Importante:** Cambiar la marca desde la consola **sí actualiza** la ventana del chat (cabecera, color, logo, textos) **sin reinstalar el cliente**. El cliente lee la marca al abrir la ventana.
>
> **El icono/ejecutable del instalador (`.exe`, barra de tareas) NO cambia:** eso queda fijado en el perfil firmado F3. Para cambiarlo, regenere el instalador con un nuevo perfil (`cercano-builder`).

---

## 6. Operación diaria

### 6.1 Permisos requeridos (F4 RBAC)

| Permiso | Quién | Qué permite |
|---------|-------|-------------|
| `chat:attend` | Técnicos | Ver cola, reclamar (`claim`), liberar (`release`), responder, adjuntar, cerrar sus conversaciones, escalar a sesión remota. |
| `chat:manage` | Supervisores | Todo lo anterior + asignar a otro (`assign`), reabrir (`reopen`), ver todas, resetear identidad de dispositivo (`POST /devices/{id}/reset`), branding (`PUT /branding`), ver agentes (`GET /agents`), resumen (`GET /summary`). |
| `chat:read` | Auditores | Lectura total sin escritura. |

> En producción, `chat:attend` exige **2FA (F4)**. La API devuelve `403` sin filtrar datos si falta el permiso.

### 6.2 Flujo operativo en console-web

| Acción | Endpoint | Quién | Efecto |
|--------|----------|-------|--------|
| Ver cola | `GET /api/chat/conversations?status=waiting` | `chat:attend` | Lista paginada con `q` (busca en nombre contacto, equipo, hostname) |
| Ver asignadas | `GET /api/chat/conversations?assigned=me` | `chat:attend` | Propias en `assigned`/`active` |
| Reclamar | `POST /api/chat/conversations/{id}/claim` | `chat:attend` | `waiting` → `assigned`; audita `chat.assigned` |
| Liberar | `POST /api/chat/conversations/{id}/release` | Asignado o `chat:manage` | `assigned`/`active` → `waiting`; audita `chat.released` |
| Asignar a otro | `POST /api/chat/conversations/{id}/assign` | `chat:manage` | Cuerpo: `{ "user_id": "..." }`; audita `chat.assigned` |
| Responder | `POST /api/chat/conversations/{id}/messages` | `chat:attend` (en las suyas) | `assigned` → `active` al primer mensaje; audita `chat.message.created` |
| Adjuntar | `POST /api/chat/conversations/{id}/attachments` | `chat:attend` (en las suyas) | Valida MIME + magic bytes, 10 MiB; audita `chat.attachment.created` |
| Cerrar | `POST /api/chat/conversations/{id}/close` | Dueño o técnico con acceso | `closed`, `closed_by`; idempotente; audita `chat.closed` |
| Reabrir | `POST /api/chat/conversations/{id}/reopen` | `chat:manage` | `closed` → `waiting` sin asignar; audita `chat.reopened` |
| Escalar a remota | Botón «Abrir sesión remota» | `chat:attend` (en las suyas) | Emite `chat.escalated`, abre `cercano://connect?device=<id>&trace=<conv_id>` |
| Reset identidad | `POST /api/chat/devices/{device_id}/reset` | `chat:manage` | Invalida clave, nonces, tokens; audita `chat.device.revoked` |

### 6.3 Reset de identidad de dispositivo

- **Cuándo:** usuario cambió de dispositivo, reinstaló, rotó la clave, o hubo `409 key_mismatch`.
- **Efecto:** invalida `public_key`, nonces, tokens en `chat_devices`, `chat_auth_nonces`, `chat_device_sessions`. Marca `revoked_at`. El cliente vuelve a registrar en el siguiente uso.
- **Mensaje al usuario:** «Contacte a soporte para restablecer el chat» (no error genérico).

---

## 7. Retención

| Qué | Cuándo | Configurable | Qué NO se borra |
|-----|--------|--------------|-----------------|
| **Mensajes y adjuntos** de conversaciones **cerradas** | 90 días tras `closed_at` (`CERCANO_CHAT_RETENTION_DAYS`) | Sí (variable de entorno) | Conversaciones abiertas (aunque antiguas), cabecera de conversación (si se conserva como registro mínimo), eventos de auditoría `chat.*` |
| **Eventos de auditoría `chat.*`** | 365 días (política de auditoría) | Por política de auditoría (`CERCANO_AUDIT_RETENTION_DAYS`) | Checkpoints firmados, cadena de hashes |

### 7.1 Cómo cambiar la retención

```bash
# Docker Compose
# Editar docker-compose.yml: environment: CERCANO_CHAT_RETENTION_DAYS=180
docker compose up -d --no-deps cercano-api

# Systemd
sudo sed -i 's/CERCANO_CHAT_RETENTION_DAYS=.*/CERCANO_CHAT_RETENTION_DAYS=180/' /opt/cercano/api.env
sudo systemctl restart cercano-api
```

### 7.2 Verificación de purga

```bash
# Ver último evento de retención
curl -H "Authorization: Bearer cercano_sess_XXXX" \
  https://cercano.example.com/api/audit/export?category=chat&action=retention.purged&limit=1

# Respuesta esperada (details):
# { "cutoff": "2026-08-10T00:00:00Z", "conversations_deleted": 12, "messages_deleted": 340, "attachments_deleted": 45 }
```

---

## 8. Desactivar el chat por política

```bash
# Docker Compose
environment:
  - CERCANO_CHAT_ENABLED=false
docker compose up -d --no-deps cercano-api

# Systemd
sudo sed -i 's/CERCANO_CHAT_ENABLED=.*/CERCANO_CHAT_ENABLED=false/' /opt/cercano/api.env
sudo systemctl restart cercano-api
```

### 8.1 Efectos

| Componente | Comportamiento |
|------------|----------------|
| **API** | Todas las rutas `/api/chat/*` devuelven `403 { "error": "forbidden", "message": "chat_disabled" }` |
| **Cliente Cercano Soporte** | Oculta el botón «Chat de soporte» y la entrada del menú; si ya tenía la ventana abierta, muestra banner «Chat desactivado por política» y deshabilita el composer |
| **console-web** | Pestaña «Conversaciones» muestra estado «Chat desactivado»; no permite crear/ver/gestionar |
| **Auditoría** | No genera eventos nuevos de chat (excepto intentos denegados → `chat.denied` con `reason: chat_disabled`) |

> Para reactivar: `CERCANO_CHAT_ENABLED=true` + reinicio de `cercano-api`. No requiere migración ni pérdida de datos.

---

## 9. Diagnóstico: problemas comunes

### 9.1 Tabla de códigos y causas

| Código | `error` | Causa típica | Comprobación / Solución |
|--------|---------|--------------|--------------------------|
| **401** | `unauthorized` | Token ausente/expirado, firma inválida, nonce usado/caducado, dispositivo revocado | Verificar reloj del cliente (NTP); `curl -v /auth/challenge` → firma con clave correcta; revisar `chat.device.revoked` en auditoría |
| **403** | `forbidden` | Sin permiso, HTTP en registro, chat desactivado, conversación ajena | `CERCANO_CHAT_ENABLED=true` + HTTPS; permisos F4 (`chat:attend`/`chat:manage`); 2FA activo para técnicos |
| **409** | `key_mismatch` | Otra clave Ed25519 ya registrada para ese `device_id` | **Reset administrativo** (`POST /devices/{id}/reset` con `chat:manage`); no reintentar registro |
| **409** | `already_assigned` | Técnico intenta `claim` una conversación ya asignada | Verificar cola; usar `release` antes si corresponde |
| **409** | `conversation_closed` | Mensaje/adjunto en conversación cerrada | Reabrir (`reopen` con `chat:manage`) o crear nueva |
| **413** | `payload_too_large` | Adjunto > 10 MiB (`CERCANO_CHAT_MAX_ATTACHMENT_BYTES`) | Reducir archivo; verificar `client_max_body_size 12m` en Nginx |
| **415** | `unsupported_media_type` | Tipo no permitido (no PNG/JPEG/WebP/PDF) o **magic bytes no coinciden** | Verificar `file --mime-type` y extensión; no renombrar `.exe` a `.pdf` |
| **429** | `rate_limited` | Límite de tasa (mensajes, adjuntos, conversaciones, challenge, verify) | Esperar `Retry-After` segundos; revisar límites en §2; no automatizar reintentos sin backoff |
| **SSE no conecta** | — | Proxy buffer, timeout corto, HTTP/1.0, TLS self-signed sin confianza | `proxy_buffering off`, `proxy_read_timeout 1h`, `proxy_http_version 1.1` en Nginx; CA de confianza en cliente |
| **Cliente sin nombre** | — | Primera vez y no completó Nombre/Apellido | El cliente bloquea el envío hasta rellenar ambos campos (1–64 chars, sin controles) |
| **Branding no actualizado** | — | Cliente cacheó respuesta anterior o CDN en `logo_url` | Cerrar y reabrir ventana de chat; `logo_url` debe ser `https://` y accesible desde el cliente; purgar CDN si aplica |
| **TLS self-signed** | — | Navegador/cliente rechaza certificado autofirmado | Instalar CA corporativa en el equipo del usuario; o usar certificado válido (Let's Encrypt, PKI interna) |

### 9.2 Comandos de diagnóstico

```bash
# 1. Verificar estado del chat en la API
curl -H "Authorization: Bearer cercano_sess_XXXX" \
  https://cercano.example.com/api/chat/summary
# { "waiting": 3, "assigned_to_me": 1, "active": 2, "unread": 4 }

# 2. Probar registro de dispositivo (simular cliente)
curl -X POST -H "X-Cercano-Client-Token: $CERCANO_CLIENT_INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"TEST-001","public_key":"'$(openssl rand -base64 32)'","display_name":"Test"}' \
  https://cercano.example.com/api/chat/devices/register

# 3. Verificar SSE (mantener abierto)
curl -N -H "Authorization: Bearer cercano_chat_XXXX" \
  https://cercano.example.com/api/chat/events

# 4. Ver logs de cercano-api (Docker)
docker compose logs -f cercano-api | grep -i chat

# 5. Ver eventos de auditoría recientes
curl -H "Authorization: Bearer cercano_sess_XXXX" \
  "https://cercano.example.com/api/audit/export?category=chat&limit=20"

# 6. Verificar branding actual
curl https://cercano.example.com/api/chat/branding

# 7. Comprobar permisos de técnico
curl -H "Authorization: Bearer cercano_sess_XXXX" \
  https://cercano.example.com/api/chat/agents
```

---

## 10. Auditoría

### 10.1 Eventos `chat.*` (categoría `chat`, `source: api`)

| Acción | Actor | Subject | `details` (campos clave) |
|--------|-------|---------|---------------------------|
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

### 10.2 Qué NO contiene la auditoría

- ❌ **Cuerpo del mensaje** (`body`)
- ❌ **Nombre y apellido del contacto** (`contact_first_name`, `contact_last_name`)
- ❌ **Nombre original del adjunto** (`original_name`)
- ❌ **Tokens** (`cercano_chat_…`, `cercano_sess_…`, `CERCANO_CLIENT_INGEST_TOKEN`)
- ❌ **Claves privadas** Ed25519
- ❌ **Contenido de archivos** (solo `sha256`, `mime`, `size_bytes`)

### 10.3 Verificación offline

```bash
# Exportar eventos de chat (JSONL)
curl -H "Authorization: Bearer cercano_sess_XXXX" \
  "https://cercano.example.com/api/audit/export?category=chat&format=jsonl" \
  > chat-audit-$(date +%F).jsonl

# Verificar integridad de la cadena + firmas de checkpoints
cercano-audit verify chat-audit-2026-11-09.jsonl --pubkey <CLAVE_PUBLICA_HEX>
# Código de salida 0 = OK; ≠0 = alteración/borrado/reordenación/truncamiento/firma inválida
```

### 10.4 Exportación SIEM

- **Syslog RFC 5424** (UDP/TCP/TLS planificado): configurar en `cercano-api` (`CERCANO_AUDIT_SYSLOG_*`).
- **JSONL continuo**: webhook con firma HMAC-SHA256 (`CERCANO_AUDIT_WEBHOOK_URL`, `CERCANO_AUDIT_WEBHOOK_SECRET`).
- **Cursor persistente**: `audit_export_checkpoint` en BD evita duplicados/pérdidas tras reinicios.
- **Proteger exportaciones**: son datos sensibles; eliminar según retención aprobada.

---

## 11. Seguridad y privacidad

| Control | Implementación |
|---------|----------------|
| **Acceso restringido** | Solo técnicos con `chat:attend`/`chat:manage` y 2FA (F4); auditores con `chat:read`. Rutas validan permiso y propiedad en cada request. |
| **Sin E2E** | **Documentado:** mensajes y adjuntos en claro en SQLite y disco. Operadores con acceso al servidor pueden leerlos. No apto para datos clasificados sin capa adicional. |
| **Retención** | 90 días mensajes/adjuntos cerrados; 365 días auditoría. Limita exposición. |
| **Respaldos protegidos** | Cifrados (AES-256-GCM), frase de paso fuera del repo, ubicación secundaria, prueba de restauración periódica. |
| **Sin secretos en logs** | Nunca se logean cuerpos, tokens, claves, nombres de archivo. Solo IDs, longitudes, MIME, tamaños, SHA-256. |
| **2FA de técnicos (F4)** | Obligatorio para `chat:attend` en producción. La API comprueba el permiso y devuelve `403` si falta. |
| **Límites de tasa** | Por dispositivo/IP/técnico: challenge 10/min, verify 20/min, registro 5/hora/IP, mensajes 30/min (dispositivo), 60/min (técnico), adjuntos 3/min/20/día, conversaciones 5/día. `429` + `Retry-After`. |
| **Adjuntos seguros** | Solo PNG/JPEG/WebP/PDF; validación MIME + **magic bytes**; 10 MiB; sin ejecución; descarga autenticada con `nosniff`, `no-store`, nombre genérico. |
| **Notificaciones sin contenido** | Texto genérico («Nuevo mensaje de soporte»), sin cuerpo ni nombre del contacto. |
| **Identidad de dispositivo** | TOFU Ed25519 + token de despliegue solo HTTPS + reset auditado. Futuro: token por instalador (F3-07). |

---

## 12. Lista de verificación final

### 12.1 Puesta en marcha (Go-live)

| # | Verificación | Comando / Acción | ✅ |
|---|--------------|------------------|----|
| 1 | Certificados TLS válidos en `cercano-web` (`/etc/nginx/certs/`) | `openssl x509 -in /etc/nginx/certs/cercano.crt -text -noout \| grep -A1 Validity` | |
| 2 | `CERCANO_CHAT_ENABLED=true` en `cercano-api` | `docker compose exec cercano-api env \| grep CERCANO_CHAT_ENABLED` | |
| 3 | Directorio adjuntos existe y permisos 0700/0600 | `ls -ld /opt/cercano/data/chat-attachments` | |
| 4 | Nginx con `proxy_buffering off` y `proxy_read_timeout 1h` en `/api/chat/events` | `docker compose exec cercano-web nginx -T \| grep -A10 'location = /api/chat/events'` | |
| 5 | `client_max_body_size 12m` en location adjuntos | `docker compose exec cercano-web nginx -T \| grep -A5 'attachments'` | |
| 6 | Branding configurado (o defaults aceptables) | `curl https://cercano.example.com/api/chat/branding` | |
| 7 | Técnicos con `chat:attend` + 2FA activo | Consola web → Usuarios → permisos | |
| 8 | Cliente Cercano Soporte con `api_server=https://...` en perfil | Verificar instalador / configuración | |
| 9 | Registro de dispositivo funciona (HTTPS + token) | `curl -X POST ... /api/chat/devices/register` → 201/200 | |
| 10 | SSE conecta y muestra `: ping` cada 15s | `curl -N -H "Authorization: Bearer ..." /api/chat/events` | |
| 11 | Subida adjunto 10 MiB PDF/imagen → 201 | `curl -X POST ... /attachments` con archivo de prueba | |
| 12 | Conversación fluye: abrir → cola → claim → responder → cerrar | Prueba E2E en console-web + cliente | |
| 13 | Escalado a remota abre `cercano://` con `trace_id` | Botón «Abrir sesión remota» en consola | |
| 14 | Auditoría genera eventos `chat.*` sin contenido | `curl ... /api/audit/export?category=chat` | |
| 15 | Verificación offline de auditoría pasa | `cercano-audit verify export.jsonl --pubkey ...` | |
| 16 | Backup adjuntos + BD + clave auditoría programado y probado | Restaurar en entorno de pruebas | |
| 17 | Retención configurada (90 días) y tarea diaria corre | Revisar logs `chat.retention.purged` tras 24h | |
| 18 | Documentar procedimiento de reset identidad y desactivación chat | Wiki/runbook interno | |

### 12.2 Desactivación (Offboarding / Política)

| # | Acción | Comando / Verificación | ✅ |
|---|--------|------------------------|----|
| 1 | `CERCANO_CHAT_ENABLED=false` + reinicio API | `systemctl restart cercano-api` / `docker compose up -d --no-deps cercano-api` | |
| 2 | Cliente oculta chat y muestra aviso | Abrir cliente → sin botón «Chat de soporte» | |
| 3 | Console-web muestra «Chat desactivado» | Pestaña Conversaciones → estado | |
| 4 | API devuelve `403 chat_disabled` en todas las rutas `/api/chat/*` | `curl /api/chat/conversations` → 403 | |
| 5 | Auditoría registra `chat.denied` con `reason: chat_disabled` | `curl ... /api/audit/export?category=chat&action=denied` | |
| 6 | Respaldos de adjuntos y BD conservados según retención | Verificar ubicación y cifrado | |
| 7 | Comunicar a técnicos y usuarios finales | Email / canal interno | |

---

## 13. Datos marcados como pendientes

| Tema | Qué falta | Impacto |
|------|-----------|---------|
| `CERCANO_CHAT_ATTACHMENT_QUOTA_BYTES` | Cuota por conversación (50 MiB en spec) no expuesta como variable de entorno; hardcodeada en código. | No ajustable sin recompilar `cercano-api`. |
| `CERCANO_CLIENT_INGEST_TOKEN` | Token de despliegue único para registro de dispositivos. En v1 se usa el token existente; F3-07 lo sustituirá por tokens por instalador. | Secreto compartido; rotar si se filtra. Documentar procedimiento de rotación. |
| Esquema `cercano://` | Registro del esquema en Windows (F4.5-12 + F3-05). | Sin registro, el escalado muestra diálogo con ID para copiar. |
| Límite de conexiones SSE simultáneas | Spec dice «3 por dispositivo»; no expuesto como variable. | Hardcodeado; si hay NAT agresivo, puede necesitar ajuste. |
| Magic bytes permitidos | Lista exacta de signatures PNG/JPEG/WebP/PDF en código; no en spec. | Si un archivo válido es rechazado, revisar implementación. |

---

**Fin de la guía.**  
Archivo creado: `docs/guias/chat.md`  
Todos los endpoints, variables, códigos, validaciones y procedimientos provienen de `docs/specs/chat.md` y documentos de referencia. No se inventaron valores; lo no definido se marca como pendiente en la tabla final.