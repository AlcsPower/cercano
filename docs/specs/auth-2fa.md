# 2FA TOTP (RFC 6238) — Especificación F4-01

**Versión:** 0.1 · **Fecha:** 2026-11-10 · **Estado:** redactado por Agente-Seguridad · **Relacionado con:** F4-01, F4-02, F4-03, F4-04, F4-05

---

## 1. Propósito y alcance

Este documento especifica la implementación de la autenticación en dos factores (2FA) basada en TOTP RFC 6238 para la consola web de **Cercano**. El objetivo es proporcionar un flujo de enrolamiento, verificación y recuperación seguro para cuentas que lo requieran (`is_2fa_required = 1`), mientras que las cuentas sin 2FA forzado pueden iniciar sesión con credenciales simples.

El ámbito cubre:
- Enrolamiento y confirmación de factor TOTP.
- Login en dos pasos para cuentas con 2FA requerido.
- Recuperación con códigos SHA-256 de un solo uso.
- Bloqueo temporal después de 5 fallos en 15 minutos.
- Revocación de factor y cierre de sesiones activas.
- Eventos de auditoría `auth.2fa_*` sin filtrar secretos ni códigos.
- Modelo de datos migratorio (`007_console_rbac_2fa`) y permisos por rol.

No se incluye WebAuthn/FIDO2, SSO/OIDC, 2FA por SMS/email ni multi-tenant. Estas extensiones se evalúan en F5/F6.

---

## 2. Roles y matriz de permisos

La matriz de permisos reutiliza `users.role` con los roles `admin`, `operator`, `auditor` y el legacy `user` (tratado como `operator` de solo lectura hasta que un administrador lo cambie). Los permisos `2fa:*` se asignan por rol:

| Permiso | admin | operator | auditor | legacy `user` |
|---|---:|---:|---:|:---:|
| `users:read` / `users:manage` | sí / sí | propio / no | propio / no | propio / no (solo propia) |
| `roles:read` / `roles:manage` | sí / sí | no / no | no / no | no / no |
| `devices:read` / `devices:manage` | sí / sí | sí / no | sí / no | sí / no |
| `audit:read` / `audit:export` | sí / sí | no / no | sí / sí | no / no |
| `settings:read` / `settings:manage` | sí / sí | sí / no | sí / no | sí / no |
| `builder:create:soporte` / `builder:create:tecnico` | sí / sí | sí / no | no / no | no / no |
| `builder:download` | sí | sí | no | no |
| `chat:attend` / `chat:manage` / `chat:read` | sí / sí / sí | sí / no / sí | no / no / sí | no / no / sí |
| `2fa:enroll` / `2fa:revoke` | sí / sí | sí / propio | sí / no | sí / propio (solo propia) |

**Notas de rol:**
- **admin:** gestiona usuarios, roles, dispositivos, auditoría, ajustes, generador y factores 2FA.
- **operator:** atiende dispositivos y chat; puede enrolar y revocar su propio factor 2FA; no gestiona usuarios ni el generador `tecnico`.
- **auditor:** solo lee y exporta auditoría, dispositivos y ajustes; no escribe.
- **legacy `user`:** comportamiento idéntico a `operator` de solo lectura para permisos 2FA.

Los permisos `chat:attend`/`chat:manage`/`chat:read` se definen en F4 y se aplican a las vistas de consola (ver `docs/specs/chat.md` §2).

---

## 3. Flujo 2FA TOTP RFC 6238

Todos los tiempos y formatos siguen las especificaciones RFC 6238: algoritmo SHA-1, paso de 30 segundos, código de 6 dígitos, ventana de validez ±1 paso.

### 3.1 Enrolamiento (`POST /api/auth/2fa/enroll`)

1. El usuario autenticado (con sesión activa) solicita el enrolamiento.
2. La API responde con:
   - Un URI `otpauth://` para codificar en QR.
   - El secreto TOTP en **base32** **una sola vez** (nunca se vuelve a entregar).
3. El usuario escanea el QR con su aplicación autenticadora (Google Authenticator, Authy, etc.).
4. El usuario ingresa un código TOTP válido para confirmar.
5. La API verifica el código y marca `totp_enabled = 1` y `totp_confirmed_at = NOW()` en la fila del usuario.

**Endpoints:**
- `POST /api/auth/2fa/enroll` — requiere permiso `2fa:enroll`. Responde `200 { otpauth_uri: "...", totp_secret_base32: "..." }`.
- `POST /api/auth/2fa/confirm` — requiere permiso `2fa:enroll`. Cuerpo: `{ "totp_code": "123456" }`. Responde `200` si el código es válido; si éxito, establece `totp_enabled = 1` y `totp_confirmed_at = NOW()`.

### 3.2 Login en dos pasos (`POST /api/auth/login`)

El login sigue un flujo condicional:

1. **Paso 1:** `POST /api/auth/login` con usuario y contraseña.
   - Si el usuario **no** requiere 2FA (`is_2fa_required = 0`): responde `200` con sesión normal (`cercano_sess_...` token) y la sesión se emite inmediatamente.
   - Si el usuario **sí** requiere 2FA (`is_2fa_required = 1`): responde `202 { mfa_required: true, mfa_token: "...", expires_at: "..." }` y **no** emite sesión. El `mfa_token` es un desafío de un solo uso, vigente 5 minutos, guardado en `mfa_challenges.token` (con `user_id` y `expires_at`).

2. **Paso 2:** `POST /api/auth/2fa/verify` con `mfa_token` y `totp_code` (o `recovery_code`).
   - La API valida el `mfa_token` contra la tabla `mfa_challenges`, y luego verifica el código TOTP contra `users.totp_secret`.
   - Si el `totp_code` es inválido, se intenta el `recovery_code` (único uso, marcado `used` al consumir).
   - Si la verificación tiene éxito: se emite sesión normal (`cercano_sess_...`) y se responde `200`.
   - **La sesión solo existe después de 2FA**; no hay cabecera `X-2fa-Token` ni marca `is_2fa_verified` en la respuesta.

**Códigos de respuesta HTTP:**
- `200` — login exitoso (con o sin 2FA, o verificación completada).
- `202` — 2FA pendiente; el cliente debe llamar al paso 2.
- `401` — TOTP inválido, recovery code inválido/ya usado, mfa_token expirado o no corresponde al usuario.
- `429` — demasiados intentos; `Retry-After` sugerido.

### 3.3 Recovery codes (códigos de recuperación)

- Al activar 2FA (`totp_enabled = 1`), se generan **8 códigos de un solo uso**.
- Cada código se almacena como **hash SHA-256** en `users.recovery_codes` (JSON `[{ "hash": "...", "used": false }, ...]`), **nunca en claro**.
- Al usar un código de recuperación:
  - Se busca un registro en `recovery_codes` donde `used = false` y el hash coincide con el código proporcionado.
  - Si se encuentra, se marca `used = true` y se audita `auth.2fa_recovery_used`.
  - Si ya fue usado o no existe, se responde `401`.
- Los códigos son **únicos por cuenta**; no hay "reset maestro". Si se pierden los 8 códigos, un administrador con `users:manage` puede desvincular el 2FA (`2fa:revoke`) y el usuario debe enrolar nuevamente.

### 3.4 Bloqueo

- 5 fallos de 2FA por cuenta **o** IP en una ventana de 15 minutos activa el bloqueo.
- Se reutiliza la función `is_locked_out` y la tabla `login_attempts` ya existentes.
- Al bloquearse: `auth.2fa_failed` se audita con `reason: "account_locked"`; las nuevas solicitudes de 2FA/verify responden `429 account_locked` (mismo criterio que el bloqueo de login).
- El bloqueo expira automáticamente después de 15 minutos sin intervención manual.

### 3.5 Revocación y cierre de sesiones

- **Usuario:** puede desvincular su factor 2FA mediante `POST /api/auth/2fa/revoke` (requiere `2fa:revoke`). Esto:
  - Elimina `totp_secret`, `recovery_codes`; deja `totp_enabled = 0` y `totp_confirmed_at = NULL`; y pone `is_2fa_required = 0` (el administrador debe volver a exigirlo tras el reenrolamiento).
  - Marca todos los `mfa_challenges` del usuario como usados/expireados.
  - Revoca todas las sesiones activas del usuario (establece `revoked_at` en `sessions`).
  - Audita `auth.2fa_revoked`.
- **Administrador:** puede forzar la revocación de cualquier usuario mediante el mismo endpoint con permiso `2fa:revoke`.

### 3.6 Códigos de error

| Código | Significado |
|---:|---|
| `200` | Operación exitosa. |
| `202` | 2FA pendiente; espera código TOTP o recovery code. |
| `400` | Solicitud inválida (código mal formado, campos faltantes). |
| `401` | TOTP inválido, recovery code usado/no existente, mfa_token expirado/no corresponde. |
| `429` | Demasiados intentos o cuenta bloqueada; `Retry-After` en headers. |

---

## 4. Datos y migración 007 exacta

La migración `007_console_rbac_2fa` es **aditiva**: añade columnas a la tabla `users` existente y crea la tabla `mfa_challenges`. **No se recrea** la tabla `users` ni se pierden datos. La migración se aplica después de `006_device_roles_schema` y antes de la migración `008_chat_schema` de F4.5.

### 4.1 Estructura SQL (SQLite dialecto)

```sql
-- 007_console_rbac_2fa: aditiva, después de 006 y antes de 008
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN is_2fa_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_confirmed_at TEXT;
ALTER TABLE users ADD COLUMN recovery_codes TEXT;

CREATE TABLE IF NOT EXISTS mfa_challenges (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 4.2 Descripción de columnas

| Columna | Tipo | Descripción |
|---|---|---|
| `users.totp_secret` | `TEXT` | Secreto TOTP en **base32**; nunca en logs/auditoría. |
| `users.totp_enabled` | `INTEGER` | `0` = 2FA desactivado/pendiente, `1` = 2FA activado y confirmado. |
| `users.is_2fa_required` | `INTEGER` | `0` = 2FA opcional (login normal), `1` = 2FA obligatorio para login. |
| `users.totp_confirmed_at` | `TEXT` | Marca de tiempo ISO/UTC cuando el usuario confirmó su secreto TOTP (valor de `datetime('now')`). |
| `users.recovery_codes` | `TEXT` | JSON `[{ "hash": "...SHA-256...", "used": false }, ...]`; 8 códigos al crear 2FA. |
| `mfa_challenges` | tabla nueva | Desafíos MFA de un solo uso: `token` (clave), `user_id`, `expires_at`, `used_at`, `created_at`. |

### 4.3 Orden de migraciones

| Migración | Nombre | Contenido |
|---|---|---|
| 006 | `006_device_roles_schema` | Ya aplicado; añade `devices.role` y su índice. |
| **007** | **`007_console_rbac_2fa`** | **Añade campos TOTP y `mfa_challenges`** (este documento). |
| 008 | `008_chat_schema` (F4.5) | Migración de chat; se mergea después de 007. |

No se debe ejecutar `008` antes de que `007` haya sido aplicado sobre la base correspondiente.

---

## 5. Eventos de auditoría `auth.2fa_*`

Todos los eventos de 2FA siguen el esquema común de auditoría de Cercano (categoría `auth`, acciones `auth.2fa_*`). **Nunca** se incluye el secreto TOTP ni el código TOTP en el objeto `details`. Los códigos de recuperación tienen su propio evento y el hash se omite o se anonimiza.

### 5.1 Lista de acciones

| Acción | Descripción |
|---|---|
| `auth.2fa_enroll` | Usuario enrola un nuevo factor TOTP.
| `auth.2fa_verify` | Verificación exitosa de TOTP/recovery en login.
| `auth.2fa_failed` | Fallo de TOTP, recovery o bloqueo.
| `auth.2fa_recovery_used` | Un código de recuperación fue consumido.
| `auth.2fa_revoked` | Factor 2FA desvinculado (por usuario o admin).

### 5.2 Estructura esperada en `details`

Cada evento debe contener campos contextuales pero **nunca** secretos ni códigos puros. Ejemplos:

- `auth.2fa_enroll`: `{ "method": "totp", "ip": "..." }` — sin `totp_secret`.
- `auth.2fa_verify`: `{ "status": "success", "mfa_token_id": "...", "ip": "..." }` — sin código TOTP.
- `auth.2fa_failed`: `{ "reason": "invalid_code", "attempt_count": 3, "ip": "..." }` — sin secreto.
- `auth.2fa_recovery_used`: `{ "code_index": 3, "ip": "..." }` — sin hash SHA-256 en claro.
- `auth.2fa_revoked`: `{ "by": "user|admin", "ip": "..." }` — sin datos sensibles.

**Prohibido en `details`:** `totp_secret`, cualquier código TOTP en claro, hashes SHA-256 de recovery codes en claro, punteros a secretos.

### 5.3 Integración con la cadena de auditoría

- Los eventos `auth.2fa_*` se encadenan con `prev_hash` / `hash` SHA-256 RFC 8785 (JCS), igual que `auth.login`, `auth.fail`, `auth.logout`.
- El evento `auth.2fa_failed` se emite cada vez que un código inválido es presentado o se alcanza el límite de 5 fallos (que desencadena bloqueo).
- El evento `auth.2fa_recovery_used` se emite cuando un código de recuperación es consumido exitosamente; el objeto `details` incluye `code_index` (1–8) pero **no** el hash.

---

## 6. Seguridad

### 6.1 Almacenamiento de secretos TOTP

- `totp_secret` se guarda en la base de datos en **base32** plano (no cifrado a nivel de campo en v1).
- **Deuda explícita:** la falta de cifrado de campo es una deuda conocida que el Agente-Seguridad puede exigir resolver en una fase posterior con cifrado mediante clave de entorno. Hasta entonces, se protege el volumen/BD y se documenta este documento.
- **Nunca** se debe registrar `totp_secret` en logs, eventos de auditoría, telemetría ni en ningún artefacto de salida.
- Las claves de generación/validación TOTP viven en el código Rust (biblioteca `totp-rs`) y nunca se exponen en variables de entorno accesibles en repositorio.

### 6.2 2FA obligatorio por `is_2fa_required`

- Cuando `is_2fa_required = 1` en la fila del usuario, el login **siempre** requiere el paso 2 (`mfa_token` + código TOTP/recovery).
- No hay bypass administrativo directo por petición HTTP; la comprobación es en el middleware de login.
- La API **no permite** activar `is_2fa_required = 1` si `totp_enabled = 0`; el intento se rechaza y se audita, evitando cuentas bloqueadas sin factor.
- Un administrador puede desactivar el requisito (`is_2fa_required = 0`) solo revocando el factor (`2fa:revoke`) y dejando al usuario sin 2FA; esto debe auditarse.

### 6.3 Recuperación por admin

- Un administrador con `users:manage` y `2fa:revoke` puede:
  - Desvincular el 2FA de cualquier usuario (`2fa:revoke`).
  - Forzar la reinscripción (`DELETE` de `totp_secret` + nuevos códigos de recuperación).
  - Ver el estado agregado (cuántos códigos se usaron y cuántos quedan), **nunca** los hashes ni los códigos en claro.
- Todas estas operaciones generan `auth.2fa_revoked` o eventos de auditoría asociados.

### 6.4 Sin logs/telemetría de secretos

- No se debe emitir `totp_secret` en ningún log de acceso, error o acceso remoto.
- Las validaciones TOTP se realizan dentro del proceso API; los resultados (éxito/fallo) sí pueden registrarse sin el secreto.
- Si se necesita depuración, usar variables de entorno `RUST_LOG` con filtrado; nunca imprimir el secreto.

---

## 7. Pruebas y criterios de aceptación

### 7.1 Casos de prueba (relación con la gate F4)

| ID | Caso | Expectativa |
|---|---|---|
| TC-F4-001 | Matriz rol → endpoint/vista; admin/operator/auditor y legacy `user` | Permisos `2fa:enroll`/`2fa:revoke` según rol; `legacy user` solo propia cuenta. |
| TC-F4-003 | Login sin 2FA requerido → 200 y sesión | Cuando `is_2fa_required = 0`, login normal sin paso 2. |
| TC-F4-004 | Login con 2FA requerido → 202, sin sesión; verify TOTP → 200 | Flujo de dos pasos; sesión solo después de `POST /api/auth/2fa/verify`. |
| TC-F4-005 | TOTP inválido/caducado → 401, `auth.2fa_failed`, bloqueo tras 5 | Límite de 5 fallos en 15 min; evento auditado. |
| TC-F4-006 | Recovery code: primer uso OK, segundo 401, `used` persistido | Primer uso exitoso; segundo intento devuelve 401 y marca `used`. |
| TC-F4-007 | Revocar 2FA invalida sesiones y exige reenrolamiento | `POST /api/auth/2fa/revoke` revoca sesiones activas; usuario debe enrolar de nuevo. |

### 7.2 Criterios de aceptación de la gate F4

- Matriz de permisos `2fa:*` cubierta para cada rol/endpoint/vista.
- Flujo de dos pasos login → 202 → verify → 200 con sesión; sin sesión intermedia.
- Recovery codes SHA-256 de un solo uso; solo primer uso exitoso; segundo 401.
- Bloqueo tras 5 fallos/15 min; `auth.2fa_failed` auditado; expiración automática.
- Revocación revoca sesiones activas y exige reenrolamiento.
- Eventos `auth.2fa_*` definidos; sin secreto ni código en `details`.
- Migración 007 aplicada sin recrear `users`; `schema_migrations` pasa de 6 a 7.
- Sin secretos TOTP en logs, auditoría ni telemetría.
- `is_2fa_required` obliga al paso 2; admin puede revocar pero debe auditarse.

### 7.3 Relación con otras tareas F4

- **F4-01:** Esta especificación (documento). Aprobar matriz, flujo y migración.
- **F4-02:** Aplicar migración `007_console_rbac_2fa` sobre la base de datos; actualizar pruebas de migración.
- **F4-03:** API de usuarios, roles y ajustes con enforcement de `users:*`, `roles:*`, `settings:*` (incluye chequeo `is_2fa_required` en login).
- **F4-04:** Implementación del API `/api/auth/2fa/enroll`, `/confirm`, `/verify`, `/revoke` en `cercano-api`; la UI de enrolamiento queda en F4-06.
- **F4-05:** Middleware RBAC y permisos `chat:*`; integración con vistas de consola.
- **F4-06:** Consola: `UsersView`, `RolesView`, `AuditView`, `SettingsView`, `TwoFAView`; login con 2FA de dos pasos.

---

## 8. Decisiones y deuda técnica

| Decisión | Justificación | Deuda / Futuro |
|---|---|---|
| TOTP en base32 sin cifrado de campo (v1) | Implementación más rápida, reuso de `totp-rs` cliente; compatible con aplicaciones authenticator existentes. | Deuda explícita: se documenta que en una fase posterior se cifrará con clave de entorno (o se migrará a WebAuthn). |
| 8 recovery codes de un solo uso | Suficiente para casos de pérdida de dispositivo; balanceo usabilidad/seguridad. | Si se pierden todos, admin debe desvincular 2FA (`2fa:revoke`) y usuario recluta. |
| Sin cifrado a nivel de campo en BD | Evita complejidad de gestión de claves de cifrado en v1. | Ver deuda anterior; decisión futura dependiendo de requisitos regulatorios. |
| `totp_secret` base32 en BD, no en logs | Separación de preocupaciones: BD confiable, logs no seguros. | Revisar que ningún `eprintln`/log capture la columna. |
| Eventos `auth.2fa_*` sin secreto en `details` | Cumplimiento con regla "Zero Secret Leaks" del subsistema de auditoría. | Auditoría interna para validar cumplimiento antes de merge. |

---

## Enlaces relativos (solo documentación)

- [`docs/PLAN-F4-CONSOLA.md`](../PLAN-F4-CONSOLA.md) — plan general F4.
- [`docs/specs/chat.md`](../specs/chat.md) — permisos `chat:*` y marca.
- [`docs/specs/audit-events.md`](../specs/audit-events.md) — esquema de eventos, subsección 6.16.
- [`docs/PLAN-F4.5-CHAT.md`](../PLAN-F4.5-CHAT.md) — chat F4.5, permisos y dependencias.
- [`docs/status/TAREAS.md`](../status/TAREAS.md) — estado vivo de tareas F4.
- [`control-plane/cercano-api/src/db.rs`](../../control-plane/cercano-api/src/db.rs) — formato de migraciones SQL.
- [`control-plane/cercano-api/src/auth.rs`](../../control-plane/cercano-api/src/auth.rs) — formato de sesiones y login_handler.