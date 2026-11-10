# Especificación — Identidad, grupos, estrategias y federación (F5)

**Versión:** 0.1 · **Fecha:** 2026-11-10 · **Estado:** contrato propuesto; lo aprueba el dueño en F5-01 y lo implementan F5-02…F5-08.
**Decisión:** [ADR-012](../adr/012-identidad-grupos-federacion.md). **Plan:** [PLAN-F5-IDENTIDAD.md](../PLAN-F5-IDENTIDAD.md). **Pruebas:** [PLAN-DE-PRUEBAS.md](../PLAN-DE-PRUEBAS.md) §6 «F5».

> Regla de oro: todo lo de este documento se **calcula y aplica en el servidor**. La consola y el cliente solo muestran lo que el API concede. Ausencia de grupo, concesión, política o proveedor nunca amplía permisos.

## 1. Alcance

| Incluye | No incluye |
|---|---|
| Grupos de usuarios y dispositivos, membresías y concesiones entre grupos | Multi-tenant, roles definidos por usuario |
| Libreta técnica sin secretos | Bóveda de credenciales, contraseñas de administrador |
| Estrategias versionadas global/grupo/dispositivo y política efectiva explicable | Aprovisionamiento SCIM, sincronización bidireccional |
| Login OIDC (PKCE) y LDAP sobre TLS, vinculación explícita | Federación del cliente controlado (fuera de v1) |
| Recuperación de identidad y cuenta break-glass | Cambio de ID de dispositivo y Windows LAPS (diferidos, §11) |

## 2. Modelo de datos (migración 009)

Siete tablas nuevas, aditivas. DDL portable: claves de texto UUID generadas en Rust, marcas de tiempo
`TEXT` canónicas generadas en Rust, booleanos como `INTEGER` 0/1, sin `datetime('now')`, `strftime`
ni `AUTOINCREMENT`, e índices explícitos. El DDL por motor lo escribe F5-02 (en F8 será portado).

| Tabla | Columnas y restricciones |
|---|---|
| `groups` | `id` PK, `kind` `CHECK (kind IN ('user','device'))`, `name`, `description`, `created_at`, `created_by`, `updated_at`, `updated_by`; `UNIQUE (kind, name)` |
| `group_members` | `group_id` → `groups(id) ON DELETE CASCADE`, `subject_type` `CHECK (subject_type IN ('user','device'))`, `subject_id`, `added_at`, `added_by`; PK `(group_id, subject_type, subject_id)`; índice `(subject_type, subject_id)` |
| `group_grants` | `from_group_id`, `to_group_id` → `groups(id) ON DELETE CASCADE`, `permission` `CHECK (permission IN ('read','operate'))`, `created_at`, `created_by`; PK `(from_group_id, to_group_id, permission)`; `CHECK (from_group_id <> to_group_id)` |
| `address_book` | `id` PK, `name`, `device_id` → `devices(id) ON DELETE CASCADE`, `group_id` → `groups(id) ON DELETE SET NULL`, `host`, `port`, `tags`, `notes`, `created_at`, `created_by`, `updated_at`, `updated_by` |
| `policies` | `id` PK, `scope_type` `CHECK (scope_type IN ('global','group','device'))`, `scope_id` **NOT NULL** (`''` para global), `version` entero, `document`, `document_sha256`, `state` `CHECK (state IN ('draft','active','superseded','revoked'))`, `effective_from`, `expires_at`, `created_at`, `created_by`, `revoked_at`, `revoked_by`; `UNIQUE (scope_type, scope_id, version)`; índice único parcial sobre `(scope_type, scope_id)` `WHERE state = 'active'`; `CHECK (scope_type <> 'global' OR scope_id = '')` |
| `identity_providers` | `id` PK, `kind` `CHECK (kind IN ('oidc','ldap'))`, `name` UNIQUE, `config` (JSON sin secretos), `secret_ref` (nombre de variable de entorno), `enabled` entero, `created_at`, `created_by`, `updated_at`, `updated_by` |
| `federated_identities` | `id` PK, `provider_id` → `identity_providers(id) ON DELETE CASCADE`, `subject`, `user_id` → `users(id) ON DELETE CASCADE`, `created_at`, `last_login_at`, `revoked_at`; `UNIQUE (provider_id, subject)`; `UNIQUE (provider_id, user_id)` |

Notas de integridad:

- `group_members.subject_id` es polimórfico y no puede llevar clave foránea. F5-03 valida la
  existencia en la misma transacción y **limpia membresías** al borrar un usuario o dispositivo.
- `scope_id` no nulo con `''` para global evita la semántica de `NULL` en índices únicos (SQLite
  considera distintos dos `NULL`), que permitiría dos políticas globales activas.
- Una política es inmutable: editar crea versión nueva y marca la anterior `superseded` en la misma
  transacción.
- No se toca `audit_events` ni ninguna tabla existente.

## 3. Permisos

Se añaden ocho permisos a la matriz fija de `permissions.rs` (F4-05). `admin` los tiene todos.

| Permiso | admin | operator | auditor | legacy `user` |
|---|---|---|---|---|
| `groups:read` | sí | sí | sí | no |
| `groups:manage` | sí | no | no | no |
| `book:read` | sí | sí | no | no |
| `book:manage` | sí | no | no | no |
| `policy:read` | sí | sí | sí | no |
| `policy:manage` | sí | no | no | no |
| `idp:manage` | sí | no | no | no |
| `identity:manage` | sí | no | no | no |

Alcance (F5-04), en este orden y denegando por defecto:

1. `admin` ve y opera todo; las denegaciones relevantes se auditan igual.
2. Un usuario ve un dispositivo si comparte grupo con él o si alguno de sus grupos tiene una concesión
   `read` (o `operate`) hacia un grupo del dispositivo. `operate` implica `read`.
3. La libreta se filtra con las mismas reglas: una entrada es visible si su `device_id` es visible o
   si su `group_id` es visible. Una entrada sin dispositivo ni grupo solo la ve `admin`.
4. Un `id` fuera de alcance responde **404** (no 403) para no confirmar existencia; el intento se
   audita como `authz.denied` con el recurso solicitado.
5. La pertenencia a grupos de un usuario no amplía sus permisos de rol: un `operator` en un grupo no
   obtiene `groups:manage`.

## 4. Estrategias

### 4.1 Documento

JSON con lista cerrada de claves (clave desconocida ⇒ política inválida, se rechaza al crear):

| Clave | Tipo | Valor restrictivo |
|---|---|---|
| `allow_incoming`, `allow_outgoing` | bool | `false` |
| `unattended_access` | bool | `false` |
| `require_approval` | bool | `true` |
| `allow_file_transfer`, `allow_clipboard`, `allow_audio`, `allow_terminal`, `allow_port_forward` | bool | `false` |
| `hide_network_settings` | bool | `true` |
| `enable_elevation`, `unattended_elevation` | bool | `false` |
| `chat.enabled`, `chat.attachments` | bool | `false` |
| `session.max_duration_minutes` | entero ≥ 1 | menor |
| `policy.cache_ttl_seconds` | entero 60…3600 | menor |

Los nombres de `policy` son los del perfil firmado ([`cercano-profile.md`](cercano-profile.md) §3.4)
para que cliente y servidor hablen el mismo idioma.

### 4.2 Resolución

Entradas: perfil firmado vigente (P0), política global activa, políticas activas de **todos** los
grupos del dispositivo, política activa del dispositivo. Algoritmo determinista:

1. Para cada clave, reunir los valores definidos en cada ámbito.
2. Si no hay ninguno fuera de P0, el valor es el de P0 (o su valor por defecto).
3. Si los hay, aplicar la dirección restrictiva de la tabla: `false` gana en booleanos restrictivos,
   `true` gana en `require_approval` y `hide_network_settings`, el menor gana en enteros.
4. Entre grupos empatados no hay azar: se aplica el valor restrictivo; si el empate persiste, el
   `group_id` lexicográficamente menor aporta el valor.
5. El resultado nunca puede superar P0: `unattended_access`, `enable_elevation` y
   `unattended_elevation` no pasan de `false` a `true`, y las claves ausentes de P0 no se inventan.
6. Una política `expired`, `revoked`, `draft`, con `document_sha256` que no coincide o con JSON
   inválido **no participa**; se registra un evento y se resuelve sin ella.

### 4.3 Explicación y caché

`GET /api/policies/effective?device_id=…` devuelve el documento efectivo y, por clave:
`{"value", "source": "profile"|"global"|"group:<id>"|"device", "rule": "only-definition"|"restrictive"|"most-specific"}`.
La consola (F5-11) muestra esa explicación; nunca presenta como efectivo un valor que el API rechaza.

El cliente guarda el documento con `issued_at` y `expires_at = issued_at + policy.cache_ttl_seconds`
(300 s por defecto). Sin red aplica la copia si no caducó; si caducó, **falla cerrado** para conexiones
nuevas (mantiene el equipo operativo y muestra el aviso), nunca aplica una política editada localmente.

## 5. OIDC

Flujo `GET /api/auth/oidc/{provider}/start` → 302 al proveedor → `GET /api/auth/oidc/{provider}/callback`.
Authorization Code con PKCE `S256`; `state` y `nonce` de un solo uso, TTL 10 minutos, guardados en el
servidor (no en cookie firmada).

| Validación | Regla |
|---|---|
| `iss` | Igual exactamente al configurado; no se acepta otro emisor |
| `aud` | Contiene el `client_id`; si hay varios, `azp` obligatorio |
| Firma | JWKS del emisor por `https`; caché 1 h; `kid` desconocido fuerza recarga (máx. 1/min) |
| Tiempos | `exp`/`iat` con tolerancia máxima de 60 s |
| `state`/`nonce` | Presentes, no usados, no caducados; si no, 401 sin sesión |
| Retorno | `redirect_uri` exacta; ninguna otra aceptada |
| Sesión | Solo tras todas las validaciones; token nunca en URL ni en logs |

Claims: `sub` obligatorio (identidad), `iss`, `aud`; `email` solo informativo; `amr`/`acr` se aceptan
como prueba de MFA **solo si** el proveedor tiene configurado `mfa_claim` y coincide. En caso
contrario se exige TOTP de Cercano tras el callback (202 y `/api/auth/2fa/verify`).

Vinculación: nunca automática. Un admin con `identity:manage` o el propio usuario con sesión válida y
reautenticación (contraseña + TOTP si lo tiene) vincula la identidad; si el correo coincide con otra
cuenta, se devuelve `identity_exists` y se exige la vinculación explícita. Desvincular o deshabilitar
el proveedor revoca las sesiones activas de las identidades afectadas.

Indisponibilidad: los inicios nuevos fallan con 503 y `Retry-After`; las sesiones vigentes no se
cortan; nunca se concede acceso privilegiado por fallo del proveedor; la cuenta local sigue disponible.

## 6. LDAP

Configuración (JSON, sin secretos): `url` (`ldaps://` obligatorio o StartTLS), `base_dn`, `bind_dn`,
`secret_ref`, `user_filter` con `{username}`, `group_attr`, `group_allowlist` (`DN → {role,
cercano_group_id}`), `default_role` (`auditor` o `none` = denegar), `timeout_ms` (≤ 5000).

Flujo: bind de servicio → búsqueda del usuario con filtro escapado (RFC 4515) y `size limit 2` → bind
del usuario con su contraseña → lectura de grupos → mapeo por allowlist → sesión. Después del bind
exitoso, **siempre** se exige TOTP de Cercano.

Reglas: sin bind simple sobre claro (ni siquiera localhost); sin persistencia de contraseñas; errores
genéricos (credenciales inválidas, sin revelar si la cuenta existe); timeout y servidor caído ⇒ 503,
sin sesión; ningún grupo fuera de la allowlist concede rol; `admin` solo por entrada explícita en la
allowlist, nunca por defecto.

## 7. Recuperación y cuenta break-glass

- Un administrador local (tabla `users`) puede iniciar sesión con contraseña + TOTP aunque OIDC/LDAP
  estén configurados o caídos. Ningún ajuste de proveedor desactiva esa ruta.
- Su uso emite `auth.break_glass_login` (actor, IP, resultado); la consola muestra el aviso.
- Códigos de recuperación de F4-04 siguen vigentes; un admin con `users:manage` puede desvincular 2FA
  o una identidad federada, con auditoría y sin secreto en el evento.
- El procedimiento completo (quién puede, cómo y cómo se prueba) se documenta en F5-13.

## 8. Migración y orden

- F5-02 usa la **migración 009** (siguiente libre hoy). Si F6-02 se adelanta, el Coordinador fija el
  orden y F5 toma el número siguiente; las dos migraciones son aditivas y no se solapan.
- No hay migración de datos: todo son tablas nuevas. `schema_migrations` llega a 9.
- Reversión: al ser aditiva, revertir es borrar las siete tablas con un procedimiento documentado; no
  se destruyen datos existentes.

## 9. Auditoría

Categoría `console` para cambios de configuración y `auth` para autenticación; no se añaden categorías
nuevas. Nunca se registran contraseñas, tokens, códigos TOTP, secretos LDAP/OIDC ni credenciales.

| Evento | Categoría | Cuándo |
|---|---|---|
| `group.created`, `group.updated`, `group.deleted` | console | CRUD de grupo |
| `group.member_added`, `group.member_removed` | console | Membresía |
| `group.grant_added`, `group.grant_removed` | console | Concesión entre grupos |
| `book.entry_created`, `book.entry_updated`, `book.entry_deleted` | console | Libreta |
| `policy.created`, `policy.activated`, `policy.revoked` | console | Estrategias |
| `idp.created`, `idp.updated`, `idp.disabled` | console | Proveedores |
| `identity.linked`, `identity.unlinked` | auth | Vinculación |
| `auth.oidc_login`, `auth.oidc_failed`, `auth.ldap_login`, `auth.ldap_failed` | auth | Login federado |
| `auth.break_glass_login` | auth | Cuenta local de emergencia |
| `authz.denied` | auth | Denegación (ya existe) |

## 10. API

Todas las rutas exigen sesión válida y el permiso indicado; el alcance se aplica en el servidor.

| Método y ruta | Permiso |
|---|---|
| `GET/POST /api/groups`, `GET/PATCH/DELETE /api/groups/{id}` | `groups:read` / `groups:manage` |
| `POST/DELETE /api/groups/{id}/members/{subject_type}/{subject_id}` | `groups:manage` |
| `GET/POST /api/groups/{id}/grants`, `DELETE /api/groups/{id}/grants/{to}/{permission}` | `groups:read` / `groups:manage` |
| `GET/POST /api/address-book`, `PATCH/DELETE /api/address-book/{id}` | `book:read` / `book:manage` |
| `GET/POST /api/policies`, `POST /api/policies/{id}/activate`, `POST /api/policies/{id}/revoke` | `policy:read` / `policy:manage` |
| `GET /api/policies/effective?device_id=` | `policy:read` + dispositivo en alcance |
| `GET/POST /api/idp`, `PATCH/DELETE /api/idp/{id}`, `POST /api/idp/{id}/test` | `idp:manage` |
| `GET /api/auth/oidc/{provider}/start`, `GET .../callback` | públicas (con `state`) |
| `POST /api/auth/login` con `provider_id` de tipo `ldap` | pública |
| `GET/POST/DELETE /api/identity/links` | `identity:manage` o el propio usuario reautenticado |

Códigos: 400 validación, 401 sin sesión, 403 sin permiso (auditado), 404 fuera de alcance, 409
conflicto (versión activa, identidad ya vinculada), 503 proveedor no disponible con `Retry-After`.
Paginación por `limit`/`offset` (máx. 200) y `total`; listas estables por clave.

## 11. Diferidos y criterio de revisión

- **Cambio de ID de dispositivo (F5-09):** diferido. Se revisa solo si aparece una necesidad operativa
  real; el ADR de F5-09 debe cubrir colisiones, tombstone, referencias (auditoría, sesiones, chat,
  perfiles) y recuperación antes de cualquier código.
- **Windows LAPS (F5-10):** diferido. Se revisa si un cliente lo exige y Seguridad aprueba el flujo
  (consentimiento, permiso dedicado, 2FA, entrega efímera, sin almacenamiento); no se crea bóveda.

## 12. Casos de prueba

El catálogo está en [`PLAN-DE-PRUEBAS.md`](../PLAN-DE-PRUEBAS.md) §6 «F5»; los detalles en
`tests/cases/TC-F5-*.md` se escriben con la tarea que implementa cada caso.
