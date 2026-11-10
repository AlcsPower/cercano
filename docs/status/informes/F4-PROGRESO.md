# Informe de avance — F4 (Consola, RBAC y 2FA) y F4.5 (Cercano Chat)

**Fecha:** 2026-11-10 · **Rama canónica local:** `docs/F0-01-gobernanza` · **Remoto:** `98c43b6` (sin push de estos docs)
**F3:** cerrada (F3-18 y cierre de fase 3 en `98c43b6`). F4/F4.5 ya no esperan F3.

## 1. Resumen ejecutivo

| Fase | Tareas | Estado real |
|---|---:|---|
| **F4** | 10 | 3 implementadas y **en verificación**; 0 cerradas; 7 pendientes. |
| **F4.5** | 16 | 1 doc en verificación; 4 en curso (una con migración obsoleta); 11 pendientes. |

El [plan F4](../../PLAN-F4-CONSOLA.md) está aprobado e integrado en la canónica local, junto con el [plan F4.5](../../PLAN-F4.5-CHAT.md), la spec de chat, la guía de operación y `TAREAS`. La deuda principal no es de diseño: **no hay compilación ni tests Rust** en este equipo y las ramas de código están detrás de la canónica. El remoto aún no tiene estos documentos porque no se hizo push.

## 2. F4 — estado por tarea

| ID | Tarea | Estado | Evidencia / rama |
|---|---|---|---|
| F4-01 | Matriz RBAC, flujo 2FA y eventos `auth.2fa_*` | En verificación | `docs/F4-01-rbac-2fa` · `eee8e2f`; spec en `docs/specs/auth-2fa.md` (esa rama) y auditoría 6.16. |
| F4-02 | Migración **007** (`totp_*`, `recovery_codes`, `mfa_challenges`) | En verificación | `feat/F4-02-rbac-2fa-schema` · `dcb5b5f`; informe en `docs/status/informes/F4-02.md` (esa rama). |
| F4-03 | API usuarios/roles/ajustes con permisos | En verificación | `feat/F4-03-rbac-api` · `a4b65c9`; informe en `docs/status/informes/F4-03.md` (esa rama). |
| F4-04 | 2FA TOTP: enrolar, login en dos pasos, recovery, revocar | Pendiente | Bloqueada por verificación de F4-02/03; sin código aún. |
| F4-05 | Middleware RBAC y permisos `chat:*` | Pendiente | `permissions.rs` ya existe en F4-03; falta middleware y chat. |
| F4-06 | Consola: usuarios, roles, auditoría, ajustes, 2FA y login | Pendiente | Depende F4-03/04/05. |
| F4-07 | Generador en consola | Pendiente | F3-07 hecho; espera F4-05/06. |
| F4-08 | Pruebas de permisos, IDOR, 2FA y sesiones | Pendiente | Depende F4-03…07. |
| F4-09 | E2E y gate F4 | Pendiente | Depende F4-08. |
| F4-10 | Cierre, documentación e informe F4 | Pendiente | Depende F4-09. |

**Entregado en F4-03:** CRUD de usuarios, `GET /api/roles`, `GET/PATCH /api/settings`, reglas de último administrador, autoprotección, revocación de sesiones y pruebas de integración. No incluye 2FA (F4-04) ni el middleware general (F4-05).

## 3. F4.5 — estado por tarea

| ID | Tarea | Estado | Evidencia / rama |
|---|---|---|---|
| F4.5-01 | Spec, ADR y planificación | En verificación | Docs en canónica; [plan](../../PLAN-F4.5-CHAT.md), [spec](../../specs/chat.md), [ADR](../../adr/010-cercano-chat.md). |
| F4.5-02 | Migración **008** y modelos | En curso | `feat/F4.5-02-chat-schema` · `c6416fa`; **stale**: migración 004, basada en F3-02. Debe rebasarse y renumerarse a 008. |
| F4.5-03 | Autenticación de dispositivo | Pendiente | Depende F4.5-02 y F3-13 (hecho). |
| F4.5-04 | API REST de conversaciones/mensajes | Pendiente | Depende F4.5-03 y F4 cerrado. |
| F4.5-05 | Adjuntos | Pendiente | Depende F4.5-04. |
| F4.5-06 | SSE, `ChatHub`, lecturas y resumen | Pendiente | Depende F4.5-04. |
| F4.5-07 | Auditoría, límites y retención | Pendiente | Depende F4.5-02…06. |
| F4.5-08 | Consola: vista Conversaciones | En curso | `feat/F4.5-08-console-chat` · `6c04c22`; mock-first, `tsc`/`lint:design` pasan. |
| F4.5-09 | Badge, notificaciones, reconexión, accesibilidad | Pendiente | Depende F4.5-08. |
| F4.5-10 | Cliente: módulo Rust y parche 006 | Pendiente | Depende F4.5-03/04/06 y F3-02. |
| F4.5-11 | Cliente: UI Flutter, nombre, adjuntos, i18n | Pendiente | Depende F4.5-10 y F4.5-13. |
| F4.5-12 | Escalado a sesión remota | Pendiente | Depende F4.5-08/11 y F3-05. |
| F4.5-13 | Perfil `policy.chat` y servidor | Pendiente | Depende F3-01/02/13 y F4.5-04. |
| F4.5-14 | E2E, seguridad, carga y cierre | Pendiente | Depende F4.5-02…13. |
| F4.5-15 | Guía de despliegue y operación | En curso | [Guía](../../guias/chat.md) escrita; depende de F4.5-14 para cierre. |
| F4.5-16 | Marca del chat configurable | En curso | Formulario `ChatBrandingForm.tsx` en `6c04c22`; falta API/DB de branding. |

**Ya disponible en F4.5:** plan de 16 tareas, spec de chat con branding configurable sin marca hardcodeada, ADR, guía de 504 líneas, vista de consola mock y formulario de branding. **No disponible:** backend de chat, SSE, adjuntos, cliente Flutter, escalado y branding persistido.

## 4. Verificación y evidencia

- **Rust (`cercano-api`):** `cargo fmt` y `fmt --check` pasan. `cargo test` **no corre** en este equipo: faltan `gcc.exe` y `dlltool.exe`; no hay evidencia de compilación. Las pruebas de F4-02 y F4-03 están escritas pero no ejecutadas.
- **Consola:** `tsc --noEmit` y `lint:design` pasan en F4.5-08; `npm run build` no se puede ejecutar por `spawn EPERM` del sandbox.
- **Docs:** enlaces y numeración revisados; migraciones **007** (F4) y **008** (F4.5); sin referencias a marcas reales.
- **Integración:** los docs F4/F4.5 están en la canónica local. Las ramas de código F4-01/02/03 y F4.5-08/02 están **detrás** de esa canónica y necesitan rebase. El remoto está en `98c43b6`: el plan y los informes no están publicados.

## 5. Bloqueos y riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Sin compilador C/enlazador | F4-02/03 y todo el backend F4.5 sin verificación real | CI/laboratorio con MSVC + `cargo test`, `clippy`, `deny`. |
| Ramas de código detrás de la canónica | PRs con conflictos o base incorrecta | Rebase sobre `42e6068` en orden F4-01 → F4-02 → F4-03; F4.5-08 y F4.5-02 después. |
| F4.5-02 con migración **004** | Colisión con 007/008 y orden de migraciones | Rebasear sobre F4-02 y renumerar a **008** antes de mergear. |
| F4.5-08 es mock | La consola no habla con el backend real | Cablear tras F4.5-04/06; no presentar como terminada. |
| F4.5-16 solo UI | Branding no persiste | Implementar API/DB de `chat_branding` en F4.5-16. |
| 2FA sin cifrado de campo | Secreto TOTP en BD en base32 | Deuda explícita en la spec; evaluar cifrado por entorno antes de producción. |
| Sin push | El remoto no muestra plan ni informes | Empujar `42e6068` o el merge que corresponda. |

## 6. Próximos pasos recomendados

1. **Publicar** la canónica local actual o el merge equivalente; hoy el remoto no tiene el plan F4/F4.5.
2. **Rebasar** F4-01, F4-02 y F4-03 sobre la canónica y mergear en ese orden.
3. **Verificar** F4-01 (Seguridad), F4-02/03 (QA) con `cargo test`, `clippy`, `deny`; marcar `Hecho`.
4. Continuar **F4-04** (2FA API) y **F4-05** (middleware/`chat:*`); después F4-06, F4-07, F4-08/09/10.
5. **F4.5-02**: rebase + migración 008; luego F4.5-03…07, cableado real de F4.5-08, backend de F4.5-16 y cierre F4.5-14/15.

## 7. Conclusión

F4 tiene la base correcta y tres tareas listas para verificación; F4.5 tiene el diseño y la consola mock, pero su backend y su migración están pendientes. El avance es real en documentación y estructura, pero **no está verificado** hasta que se ejecute la suite en CI/laboratorio y se integren las ramas de código. La canónica local ya contiene ambos planes; falta publicarla.
