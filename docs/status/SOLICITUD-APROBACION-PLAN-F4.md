# Solicitud de revisión y aprobación — Plan F4 (Consola, RBAC y 2FA)

**Para:** Coordinador · **De:** Agente Web / ControlPlane (sesión actual) · **Fecha:** 2026-11-09
**Asunto:** Revisar y aprobar `docs/PLAN-F4-CONSOLA.md`; confirmar el arranque de F4 en paralelo con F3.

## 1. Contexto

- **F3-07 (servicio de build en `cercano-api`) ya está Hecho** (`5e9e4ea`). El generador ya tiene cola, jobs, artefactos y permisos básicos.
- Se creó el plan F4 en [`docs/PLAN-F4-CONSOLA.md`](../PLAN-F4-CONSOLA.md), en la rama `docs/F4.5-01-chat-design` (worktree `.worktrees/f4.5-docs`, commit `3c4e5dc`; actualización de F3-07 en `e6368ee`).
- El plan F4.5 de Cercano Chat ya existe en [`docs/PLAN-F4.5-CHAT.md`](../PLAN-F4.5-CHAT.md), con contrato en [`docs/specs/chat.md`](../specs/chat.md) y ADR [`docs/adr/010-cercano-chat.md`](../adr/010-cercano-chat.md); F4.5-01 está en verificación.

## 2. Qué se pide aprobar

1. **F4 no espera a F3.** F4 depende de F1-04 y F2-08 (hechos). Solo **F4-07** (generador en la consola) depende de F3-07 (ya hecho) y de F4-05/06 (RBAC/consola). El resto de F4 puede ejecutarse en paralelo con F3.
2. **RBAC** sobre `users.role` (`admin`, `operator`, `auditor`; `user` legacy como `operator` de solo lectura), con matriz de permisos por endpoint y vista. Sin tabla de permisos configurable en v1.
3. **2FA TOTP** (RFC 6238) con `totp-rs` (MIT): enrolamiento, login en dos pasos (`202` + `mfa_token`, sesión solo tras verificar), códigos de recuperación con hash SHA-256 de un solo uso, bloqueo tras 5 fallos y auditoría `auth.2fa_*`. El secreto TOTP se guarda en la BD; en v1 no se cifra a nivel de campo (se documenta como deuda o se añade cifrado si Seguridad lo exige).
4. **Migración 005 aditiva:** `totp_secret`, `totp_enabled`, `is_2fa_required`, `totp_confirmed_at`, `recovery_codes` y `mfa_challenges`; no se recrea `users`.
5. **Tareas F4-01…F4-10** y su reflejo en `docs/status/TAREAS.md`. F4-05/06 (RBAC/consola) deben ir antes de F4-07.
6. **Relación F4.5:** la consola aporta `chat:attend/manage/read` y la marca del chat (F4.5-16); el icono/nombre del ejecutable sigue en el perfil firmado F3.

## 3. Estado y evidencia

| Rama / worktree | Commit | Estado |
|---|---|---|
| `docs/F4.5-01-chat-design` (`.worktrees/f4.5-docs`) | `3c4e5dc`, `e6368ee` | Plan F4, guía de operación del chat, marca del chat, TAREAS/ROADMAP. Sin marca fija en la UI. |
| `feat/F4.5-08-console-chat` (`.worktrees/f4.5-console`) | `c3f3856` | Consola de chat y formulario de marca, mock-first; rebasada sobre F3-07. |
| `feat/F4.5-02-chat-schema` (`.worktrees/f4.5-02`) | `c6416fa` | Migración 004 y modelos; pendiente de ejecutar la suite. |

- **Consola:** `tsc --noEmit` y `lint:design` en verde. `npm run build` no se pudo ejecutar en este equipo: esbuild devuelve `spawn EPERM` por el sandbox; debe correrse en CI/fuera del sandbox.
- **Rust:** `cargo fmt --check` verde. `cargo test` no se pudo ejecutar: faltan `link.exe` (MSVC) y `dlltool.exe` (GNU) en este equipo. CI/laboratorio debe ejecutar la suite.
- **Docs:** esquema de auditoría válido en JSON; enlaces y `diff --check` revisados; sin marca fija ni referencias de ejemplo no deseadas.

## 4. Riesgos y deuda

- **Bloqueo de verificación local:** sin enlazador no se puede afirmar que F4.5-02 compile ni que las pruebas pasen. Lo mismo para el backend Rust de F4.
- **2FA en reposo:** el secreto TOTP queda en la BD; si Seguridad exige cifrado de campo, F4-01 debe incluirlo antes de implementar.
- **F4-07 no es un cableado menor:** el `BuilderView` actual es una simulación y no coincide con `cercano-profile` (rol, `policy`, `installation`; color/logo no forman parte del perfil F3). Debe esperar F4-05/06 y requerir una alineación del formulario; no se debe presentar como terminado.
- **Historia mezclada:** el commit `5895214` (F3-03, del otro agente) incluyó los documentos F4.5-01. La rama de docs parte de ahí; si se quiere historia limpia, conviene cherry-pick de `3c4e5dc`/`e6368ee` sobre una base limpia.
- **F4.5-08/16 están en curso, no cerradas:** la UI es mock-first; la integración live espera F4.5-04/05/06. No se declaran `Hecho`.

## 5. Decisión solicitada

1. **Aprobar o rechazar** el plan F4 y la conclusión F4/F3.
2. Si se aprueba: marcar **F4-01 `En curso`**, asignar QA/Seguridad y confirmar si F4-07 espera F4-05/06 (recomendado) o si se autoriza adelantarlo con la auth admin actual.
3. Confirmar el cierre de **F4.5-01** (documentación) o pedir cambios.
4. Definir **dónde correr** `cargo test -p cercano-api` y `npm run build` (CI o laboratorio con Build Tools) para desbloquear la verificación.

---

**Respuesta esperada:** aprobación del plan con cambios concretos (si los hay), o rechazo con el motivo. Con la aprobación, el siguiente paso es F4-01 y la asignación de F4-02/03.
