# Plan de trabajo — F4: Consola web, RBAC y 2FA

**Versión:** 0.2 · **Fecha:** 2026-11-11 · **Estado:** aprobado por el Coordinador (2026-11-10); v0.2 añade F4-11…F4-13 tras la revisión de F4-06/F4-07 · **Fase:** F4 · **Duración estimada:** 4 semanas
**Objetivo (M3):** administración completa (usuarios, dispositivos, auditoría, generador y ajustes) desde el navegador, con permisos por rol y 2FA.
**Depende de:** F1-04 (usuarios/sesiones), F2-08 (auditoría de API/consola) y, solo para el generador, F3-07 (servicio de build).
**Documentos:** [`docs/specs/chat.md`](specs/chat.md) (permisos `chat:*` y marca), [`docs/PLAN-F4.5-CHAT.md`](PLAN-F4.5-CHAT.md), [`docs/PLAN-F3-GENERADOR.md`](PLAN-F3-GENERADOR.md).

## 1. Objetivo y alcance

- **RBAC** sobre `users.role` (`admin`, `operator`, `auditor`), con permisos granulares por endpoint y vista; sin tabla de permisos configurable en v1 (roles fijos).
- **2FA TOTP** (RFC 6238) para cuentas que lo requieran; enrolamiento, verificación en login, códigos de recuperación, revocación y auditoría.
- **Consola:** usuarios, roles, auditoría, ajustes, 2FA y la integración del generador. Se reutiliza el diseño existente; no se rehace la interfaz.
- **Enforcement** en el API; el frontend oculta acciones, pero el servidor es la autoridad.

**F4 / F3:** F4 **no** depende técnicamente de F3 salvo la integración del generador (F4-07). F3-07 ya está hecho (2026-11-09); F4-07 sigue esperando F4-05/06 (RBAC/consola). F4 puede ejecutarse en paralelo con F3 una vez F1-04 y F2-08 están hechos. El orden F3 → F4 del roadmap es de planificación, no una dependencia dura.

## 2. Dependencias reales

| Dependencia | Estado / uso | Tareas F4 |
|---|---|---|
| F1-04 — auth, usuarios y sesiones | Hecho; `users`, `sessions`, `AuthenticatedUser`, login/logout | Base de RBAC y 2FA |
| F2-08 — auditoría de API/consola | Hecho; eventos `auth.*`/`console.*` y consulta | Auditoría de RBAC/2FA y vista de auditoría |
| F3-07 — servicio de build en `cercano-api` | **Hecho (2026-11-09)**; cola, jobs, artefactos | F4-07 desbloqueado en la parte F3; sigue esperando F4-05/06 |
| F4.5 — Cercano Chat | Planificado; permisos `chat:attend/manage/read`, marca en F4.5-16 | F4 debe incluirlos en la matriz de permisos |

## 3. Roles y permisos

Se reutiliza `users.role`; el rol legacy `user` se trata como `operator` de solo lectura hasta que un administrador lo cambie. No se crea una tabla de permisos: el mapa rol → permisos vive en código y se prueba.

| Permiso | admin | operator | auditor |
|---|---:|---:|---:|
| `users:read` / `users:manage` | sí / sí | propio / no | propio / no |
| `roles:read` / `roles:manage` | sí / sí | no / no | no / no |
| `devices:read` / `devices:manage` | sí / sí | sí / no | sí / no |
| `audit:read` / `audit:export` | sí / sí | no / no | sí / sí |
| `settings:read` / `settings:manage` | sí / sí | sí / no | sí / no |
| `builder:create:soporte` / `builder:create:tecnico` | sí / sí | sí / no | no / no |
| `builder:download` | sí | sí | no |
| `chat:attend` / `chat:manage` / `chat:read` | sí / sí / sí | sí / no / sí | no / no / sí |
| `server:keys:rotate` | sí | no | no |
| `db:admin` (F8-08: respaldo, restauración y migración de BD) | sí | no | no |
| `2fa:enroll` / `2fa:revoke` | sí / sí | sí / propio | sí / no |

- El **administrador** gestiona usuarios, roles, dispositivos, auditoría, ajustes, generador y claves.
- El **operador** atiende dispositivos y chat; no gestiona usuarios ni el generador `tecnico`.
- El **auditor** solo lee y exporta auditoría, dispositivos y ajustes; no escribe.
- **Permisos de chat (aclaración v0.2).** `chat:manage` = supervisión (asignar, reabrir, resetear identidad de dispositivo; ver `docs/specs/chat.md`); la marca del chat usa `chat:manage_branding` (`PUT /api/chat/branding`, F4.5-16). `chat:write` y `chat:close` (responder/cerrar) los reciben `admin` y `operator`. Como los roles son fijos, `chat:manage` y `chat:manage_branding` los tiene solo `admin`. El código (`permissions.rs`) ya sigue este reparto; F4-13 lo deja documentado y probado.
- **Grants individuales.** El código incluye la tabla `user_permissions` (permisos concedidos a una cuenta además de su rol; la usa el servicio de builds). Es una extensión no prevista en v0.1: se acepta, pero cada grant se audita y F4-13 lo documenta. No sustituye la regla «roles fijos»: no hay UI para editarla en v1.

## 4. 2FA: TOTP

**Decisión:** TOTP RFC 6238, SHA-1, 30 s, 6 dígitos, ventana ±1. Se usa `totp-rs` (MIT, ya usado por el cliente) en `cercano-api`; no se implementa criptografía propia. Si el revisor prefiere no añadir la dependencia, F4-01 debe aprobar la alternativa con `sha1` + `hmac` y pruebas de vectores RFC.

- **Enrolamiento:** usuario autenticado → `POST /api/auth/2fa/enroll` devuelve `otpauth://` (QR) y el secreto una sola vez; `POST /api/auth/2fa/confirm` con un código válido activa `totp_enabled`.
- **Login en dos pasos:**
  1. `POST /api/auth/login` con usuario/contraseña. Si el usuario no requiere 2FA, responde `200` con la sesión como hoy.
  2. Si requiere 2FA, responde `202 { "mfa_required": true, "mfa_token": "...", "expires_at": "..." }` y **no** emite sesión. `mfa_token` es un desafío de un solo uso, 5 min, guardado en `mfa_challenges`.
  3. `POST /api/auth/2fa/verify` con `mfa_token` + `totp_code` (o `recovery_code`) → `200` con la sesión normal. La sesión **solo existe después** de 2FA; no hay cabecera `X-2fa-Token` ni `is_2fa_verified`.
- **Recuperación:** 8 códigos de un solo uso, generados al activar; se guardan como hash SHA-256 en `users.recovery_codes` (JSON `[{hash, used}]`), nunca en claro. Al usarse uno, se marca `used` y se audita.
- **Bloqueo:** 5 fallos de 2FA por cuenta/IP en 15 min, reutilizando `is_locked_out` y `login_attempts`; se audita `auth.2fa_failed`.
- **Obligatoriedad (v0.2, F4-11).** `is_2fa_required` arranca en 0 y hoy solo se pone en 1 al confirmar el TOTP, así que nada obliga a enrolar y un usuario puede desvincular su propio factor. Se añade la política de servidor `auth.require_2fa_roles` (por defecto `admin,operator`): una cuenta de esos roles sin factor recibe una sesión limitada que solo permite `2fa:enroll`/`2fa:confirm` y `logout` (`403 mfa_enrollment_required` en el resto); `2fa:revoke` propio queda denegado para roles obligatorios (solo un admin puede desvincular, audita y fuerza reenrolamiento). La sesión registra `mfa_verified`, que F3 (elevación, ADR-009) y F8 (reautenticación) consultan.
- **Revocación:** el usuario o un admin puede desvincular el factor; se revocan las sesiones activas del usuario y se audita `auth.2fa_revoked`.
- **Secretos:** `totp_secret` en base32 en `users`; nunca en logs/auditoría. **v0.2 (F4-12): se cifra en reposo** con AES-256-GCM y una clave de servidor (`CERCANO_SECRETS_KEY` o archivo con permisos 0600), con prefijo de versión `enc:v1:` y migración de datos de los secretos existentes (sin cambio de esquema). Motivo: la elevación con credenciales y el respaldo de F8 dependen del 2FA, y un respaldo con secretos TOTP en claro anularía el factor. Los códigos de recuperación ya están hasheados.
- **Auditoría:** `auth.2fa_enroll`, `auth.2fa_verify`, `auth.2fa_failed`, `auth.2fa_recovery_used`, `auth.2fa_revoked`; sin secreto ni código en `details`.

## 5. Datos y API

### 5.1 Migración 007 (aditiva)

```sql
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

- `users.role` no cambia; se admiten `admin`, `operator`, `auditor` y el legacy `user`.
- No se recrea la tabla `users` ni se pierden datos.
- La migración 007 se aplica después de 006 (`006_device_roles_schema`). La migración de chat de F4.5 será 008 y debe mergearse después de 007 para mantener el orden; el Coordinador fija el orden de merge.

### 5.2 Endpoints

| Endpoint | Permiso | Función |
|---|---|---|
| `GET /api/users`, `POST /api/users`, `GET/PATCH/DELETE /api/users/:id` | `users:read/manage` | Lista/CRUD; admin todas, operator/auditor solo la propia y sin cambiar rol |
| `GET /api/roles` | `roles:read` | Roles fijos del sistema (matriz de permisos) |
| `POST /api/auth/2fa/enroll` | `2fa:enroll` | Secreto + otpauth una vez |
| `POST /api/auth/2fa/confirm` | `2fa:enroll` | Activa 2FA con un TOTP válido |
| `POST /api/auth/2fa/verify` | login (mfa_token) | Verifica TOTP/recovery y emite sesión |
| `POST /api/auth/2fa/revoke` | `2fa:revoke` | Desvincula y revoca sesiones |
| `GET/PATCH /api/settings` | `settings:read/manage` | Ajustes generales; la marca del chat sigue en `chat:manage` (F4.5-16) |
| `GET/POST /api/builder/*` | `builder:*` | Depende de F3-07; no se define aquí su contrato |

- El login devuelve `202` para 2FA pendiente; hay que actualizar `console-web/src/api/client.ts` y `AuthContext` para el segundo paso.
- No se cambian los contratos de `/api/chat/*`; se les aplican los permisos `chat:*` (F4.5-04).

### 5.3 Enforcement

- Un middleware/extractor RBAC resuelve el `AuthenticatedUser` de la sesión (no JWT; token opaco en `sessions`) y comprueba el permiso de la ruta. Sin permiso: `403` + evento `authz.denied`.
- La sesión se emite solo tras 2FA cuando el usuario lo requiere. No hay un segundo middleware de 2FA por petición.
- Las vistas de la consola ocultan acciones sin permiso; el API siempre vuelve a comprobar.

## 6. Consola

| Vista | Estado | F4 |
|---|---|---|
| `LoginView` | existe | Segundo paso 2FA (TOTP/recovery) y enrolamiento si falta |
| `DashboardView` | existe | Indicador de 2FA activo y permisos |
| `DevicesView` | existe | Acciones según `devices:*` |
| `SecurityView` | existe | Rotación de claves según `server:keys:rotate` |
| `BuilderView` | existe (mock) | Integración con F3-07 (F4-07) |
| `UsersView` | nueva | CRUD de usuarios; rol; 2FA requerido |
| `RolesView` | nueva | Matriz fija de permisos por rol (solo lectura) |
| `AuditView` | nueva | Consulta/exportación de auditoría con filtros |
| `SettingsView` | nueva | Ajustes generales; no duplica la marca del chat (F4.5-16) |
| `TwoFAView` | nueva | Enrolamiento, recovery codes, revocación |

Todas las vistas nuevas: estados vacío/carga/error, teclado, foco visible, `aria-live` para errores, contraste y `prefers-reduced-motion`. No se añade Storybook ni un runner de UI nuevo: `npm run build` + `lint:design` + QA manual; las pruebas de lógica van en el API.

## 7. Tareas

| ID | Tarea | Dep. | Rol | Verifica | CA |
|---|---|---|---|---|---|
| F4-01 | Especificar matriz de permisos, flujo 2FA y modelo de datos; actualizar `audit-events.md` con `auth.2fa_*` | F1-04, F2-08 | Coordinador + Seguridad | Revisión de la matriz y del flujo; sin códigos de recuperación en claro | Documento aprobado; matriz cubre cada vista/endpoint; eventos definidos |
| F4-02 | Migración 007: campos 2FA en `users` y `mfa_challenges`; actualizar pruebas de migración | F4-01 | ControlPlane | QA | Migración sobre BD vacía y con 001–006; sin pérdida; `cargo test` |
| F4-03 | API de usuarios, roles y ajustes; enforcement de `users:*`, `roles:*`, `settings:*` | F4-02 | ControlPlane | QA | CRUD y 403 por rol; sin contraseñas, secretos ni hashes en respuestas |
| F4-04 | 2FA en el API: enrolar/confirmar/verify/revoke/recovery; login en dos pasos; bloqueo | F4-02, F4-03 | ControlPlane | Seguridad | TOTP válido/inválido; recovery de un solo uso; sesión solo tras 2FA; lockout; auditoría |
| F4-05 | Middleware RBAC y permisos `chat:*`; pruebas de la matriz | F4-03 | ControlPlane | QA | Cada rol/endpoint esperado; 403 auditado; no rompe `/api/chat` |
| F4-06 | Consola: `UsersView`, `RolesView`, `AuditView`, `SettingsView`, `TwoFAView`; Login con 2FA | F4-03, F4-04, F4-05 | Web | QA | Vistas con estados; login en dos pasos; `npm run build` y `lint:design`; QA manual |
| F4-07 | Integración del generador en la consola (depende F3-07) | F3-07, F4-05, F4-06 | Web | QA | Generar/descargar según `builder:*`; errores claros; sin permisos → 403 |
| F4-11 | Política de 2FA obligatoria: `auth.require_2fa_roles`, enrolamiento forzado, sin autorrevocación para roles obligatorios, `mfa_verified` en la sesión | F4-04, F4-06 | ControlPlane + Web | Seguridad | Admin/operator sin factor solo enrolan; `2fa:revoke` propio denegado y auditado; `mfa_verified` verdadero solo tras 2FA; `LoginView` guía el enrolamiento |
| F4-12 | Cifrado en reposo del secreto TOTP (AES-256-GCM, `enc:v1:`), migración de datos y guía de la clave | F4-04 | ControlPlane | Seguridad | Ningún secreto en claro en BD/respaldo; arranque falla de forma cerrada sin clave; rotación documentada; pruebas de migración y de clave errónea |
| F4-13 | Matriz de permisos final: `chat:write/close/manage/manage_branding`, `db:admin` (F8-08) y grants `user_permissions` documentados, auditados y probados | F4-05, F4-11 | ControlPlane | QA | `GET /api/roles` y el plan coinciden con `permissions.rs`; prueba automática matriz-vs-código; builder `tecnico` solo admin o grant explícito |
| F4-08 | Pruebas de permisos, IDOR, 2FA y sesiones; laboratorio LAN | F4-03…07, F4-11…13 | QA | Coordinador | Matriz verde; IDOR 403; revocación de sesiones; sin secretos en logs |
| F4-09 | E2E y gate F4: login + 2FA + usuarios + auditoría + generador | F4-08 | QA | Coordinador | Suite verde; sin hallazgos altos; informe |
| F4-10 | Cierre: documentación de operador, guía de 2FA y recuperación, informe de fase | F4-09 | Coordinador | Dueño | Docs publicadas; gate firmado |

## 8. Pruebas y gate

Casos principales (detalle en `tests/cases/`):

| ID | Caso |
|---|---|
| TC-F4-001 | Matriz rol → endpoint/vista; admin/operator/auditor y legacy `user` |
| TC-F4-002 | IDOR en usuarios y dispositivos; 403 y evento |
| TC-F4-003 | Login sin 2FA requerido → 200 y sesión |
| TC-F4-004 | Login con 2FA requerido → 202, sin sesión; verify TOTP → 200 |
| TC-F4-005 | TOTP inválido/caducado → 401, `auth.2fa_failed`, bloqueo tras 5 |
| TC-F4-006 | Recovery code: primer uso OK, segundo 401, `used` persistido |
| TC-F4-007 | Revocar 2FA invalida sesiones y exige reenrolamiento |
| TC-F4-008 | Rol obligatorio sin factor: login → sesión limitada, solo enrolar; resto 403 `mfa_enrollment_required` |
| TC-F4-009 | `2fa:revoke` propio denegado a admin/operator; un admin sí puede y la cuenta debe reenrolar |
| TC-F4-012 | Secreto TOTP cifrado en BD y en respaldo; sin clave el API no arranca; clave errónea → error, no 2FA abierto |
| TC-F4-013 | La matriz de `permissions.rs` coincide con `GET /api/roles` y con este plan; grants individuales auditados |
| TC-F4-014 | `mfa_verified` falso en sesión sin 2FA; la elevación (F3) y la reautenticación (F8) lo exigen |
| TC-F4-010 | Migración 007 sobre BD existente; `schema_migrations` = 7 |
| TC-F4-011 | `GET /api/users` sin permiso → 403 auditado |
| TC-F4-020 | Vistas nuevas: vacío/carga/error/accesibilidad |
| TC-F4-030 | E2E: login admin + 2FA + usuarios + auditoría + generador |
| TC-F4-040 | Gate: suite verde, 0 críticos/altos, docs actualizadas |

**Gate F4:** 100 % de `TC-F4-*` en verde en CI y laboratorio; 0 hallazgos críticos/altos; matriz de permisos demostrada; 2FA obligatoria para admin/operator en producción **aplicada por el servidor (F4-11)**; secreto TOTP cifrado en reposo (F4-12); sin secretos/códigos en logs/auditoría; consola con `npm run build` y `lint:design`; documentación de operador y recuperación.

## 9. Fuera de alcance, riesgos y decisiones

- **Fuera de alcance:** WebAuthn/FIDO2, SSO/OIDC/LDAP (F5), permisos personalizables por el usuario, 2FA por SMS/email, multi-tenant.
- **TOTP vs WebAuthn:** TOTP en F4; WebAuthn se evalúa en F5/F6.
- **Recuperación:** 8 códigos de un solo uso; si se pierden, un admin con `users:manage` desvincula el 2FA y el usuario vuelve a enrolar. Se audita; no hay “reset maestro”.
- **Secreto TOTP en BD:** cifrado en reposo en F4-12 (decisión del Coordinador, v0.2); la clave se gestiona como las demás claves operativas (F7-07) y se incluye en la guía de respaldos de F8.
- **Bloqueo:** 5 fallos/15 min por cuenta/IP; no bloquear la cuenta de servicio/admin de bootstrap sin una ruta de recuperación documentada.
- **Legacy `user`:** se trata como `operator` de solo lectura hasta que un admin lo cambie; no se migra en bloque.
- **Builder:** F4-07 ya tiene F3-07; espera F4-05/06 (RBAC/consola). El resto de F4 puede ir en paralelo con F3.

## 10. Relación con F4.5

- La consola F4 aporta los permisos `chat:attend`/`chat:manage`/`chat:read` y la sesión de técnico con 2FA; F4.5 los consume.
- La marca del chat se configura en la consola (F4.5-16), no en `SettingsView`; `PUT /api/chat/branding` exige `chat:manage`.
- El icono/nombre del ejecutable del instalador sigue en el perfil firmado F3; la marca de la ventana de chat es dinámica.
- F4.5 puede avanzar en paralelo (UI mock, schema) pero su cierre depende de F4 para RBAC/2FA.
