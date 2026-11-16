# Cierre de Fase 5 — Hito M4: Identidad, Control de Acceso y Federación

**Fecha:** 2026-11-16  
**Estado:** Hecho  
**Coordinador:** Aprobado  
**Alcance:** F5-01 a F5-13 (13 tareas completadas, verificadas o diferidas formalmente con ADR)

---

## 1. Resumen Ejecutivo

La **Fase 5 (Hito M4: Identidad y Control de Acceso)** del proyecto **Cercano** ha sido completada en su totalidad con éxito, en estricto cumplimiento de `docs/PLAN-F5-IDENTIDAD.md`, las directrices de arquitectura de `docs/ARQUITECTURA.md`, las reglas de clean-room y gobernanza de `AGENTS.md`, y bajo la disciplina de diseño mínimo y máxima robustez (`/ponytail`).

Se ha implementado una arquitectura integral de gestión de identidades, control de acceso basado en roles y grupos (RBAC extendido), libreta de direcciones centralizada, motor determinista de resolución de políticas y federación corporativa mediante OIDC (PKCE) y LDAP sobre TLS. Las decisiones de diferimiento para escenarios que introducían riesgos de seguridad o desincronización de auditoría (cambio de ID de dispositivo y Windows LAPS) fueron formalizadas mediante Decisiones de Arquitectura (ADR-013 y ADR-014) aprobadas por Coordinador y Seguridad.

Aspectos clave completados:
- **Modelo de Grupos N:M y Concesiones:** Grupos de usuarios y dispositivos con concesiones cruzadas (`read`, `operate`), validación estricta de alcance (scoping) y defensa exhaustiva contra accesos IDOR (404 no-enumerativo con registro en auditoría).
- **Libreta de Direcciones Centralizada:** Catálogo administrable sin secretos, filtrado por alcance y etiquetas.
- **Motor de Estrategias y Precedencia P0->P1->P2->P3:** Jerarquía determinista e infranqueable donde el perfil firmado (P0) actúa como techo estricto que ninguna política central o local puede relajar.
- **Cliente Cercano Nativo:** Descarga segura, validación SHA-256, cacheo local protegido y modo seguro *fail-closed* ante desconexión o expiración de políticas.
- **Federación OIDC con PKCE:** Flujo Authorization Code con S256 PKCE, `state` de un solo uso, `nonce`, validación estricta de emisor/audiencia/reloj y requerimiento de 2FA TOTP si no hay claim MFA externa.
- **Autenticación LDAP sobre TLS:** Conexión segura obligatoria (`ldaps://` o StartTLS), escape RFC 4515 contra inyección, mapeo explícito de grupos (`group_allowlist`) y requerimiento incondicional de segundo factor TOTP Cercano.
- **Acceso de Emergencia (Break-Glass):** Autenticación local independiente de la disponibilidad de proveedores federados para evitar bloqueos del sistema.
- **Consola Web:** Nueva vista unificada de «Estrategias e Identidad» con subpestañas de grupos, libreta, políticas, diagnóstico interactivo de política efectiva y proveedores SSO.

---

## 2. Matriz de Entregables de Fase 5

| Tarea | Descripción | Entregable Principal | Estado |
|---|---|---|---|
| **F5-01** | Aprobación modelo F5, amenazas y migraciones | `docs/specs/identidad.md`, catálogo `TC-F5-001…070` en plan de pruebas | Hecho |
| **F5-02** | Migración 009 y modelos Rust | DDL SQLite aditivo en `db.rs` y modelos en `cercano-api/src/identity/mod.rs` | Hecho |
| **F5-03** | API CRUD de grupos y libreta con auditoría | Endpoints `/api/groups`, `/api/address-book` y auditoría en `groups.rs` | Hecho |
| **F5-04** | Enforcement de alcance por rol/grupo e IDOR | Middleware y verificadores de alcance en `scope.rs`, suite `identity_scope_test.rs` | Hecho |
| **F5-05** | Servicio de estrategias y política efectiva | Módulo `policies.rs`, resolución P0->P1->P2->P3, suite `identity_policies_test.rs` | Hecho |
| **F5-06** | Cliente: descarga, cacheo y aplicación de estrategias | Parche `012-client-effective-policy.patch`, suite `client_policies_test.rs` | Hecho |
| **F5-07** | Inicio de sesión OIDC con PKCE y vinculación | Módulo `identity/oidc.rs`, validación de tokens, suite `identity_oidc_test.rs` | Hecho |
| **F5-08** | Autenticación LDAP sobre TLS y mapeo de grupos | Módulo `identity/ldap.rs`, escape RFC 4515, suite `identity_ldap_test.rs` | Hecho |
| **F5-09** | Evaluar cambio de ID de dispositivo | `docs/adr/013-diferimiento-cambio-id-dispositivo.md` (diferido formalmente) | Hecho |
| **F5-10** | Evaluar/integrar Windows LAPS | `docs/adr/014-diferimiento-windows-laps.md` (diferido formalmente) | Hecho |
| **F5-11** | Consola web: grupos, libreta, estrategias y diagnóstico | Componente `IdentityView.tsx`, integración en `TabBar.tsx` y `App.tsx` | Hecho |
| **F5-12** | Pruebas de integración globales y abuso de identidad | Suite `identity_integration_f5_test.rs`, 32/32 pruebas de Fase 5 en verde | Hecho |
| **F5-13** | Documentación de operador y cierre F5 | Runbook `docs/guias/identidad-y-recuperacion.md` e informe de cierre | Hecho |

---

## 3. Verificación de Criterios del Gate F5

| Criterio del Gate F5 | Evidencia Demostrada | Resultado |
|---|---|---|
| **100% de tareas Hecho o Diferidas** | Las 13 tareas completadas y verificadas con informes en `docs/status/informes/F5-*.md` y ADRs 013/014. | Conforme |
| **Pruebas integrales de identidad en verde** | 32 pruebas automatizadas en las 7 suites de Fase 5 ejecutadas y aprobadas al 100% (0 fallos). | Conforme |
| **Techo P0 infranqueable verificado** | Pruebas demuestran que ninguna política central o local puede superar las restricciones del perfil firmado P0. | Conforme |
| **Integridad de auditoría inmutable** | Registro inmutable de todos los eventos `group.*`, `policy.*`, `idp.*`, `auth.oidc_login`, `auth.ldap_login` y `authz.denied`. | Conforme |
| **Privacidad y cero fuga de secretos** | Inspección automatizada en auditoría y logs confirma: **cero contraseñas de bind, tokens, claves privadas ni secretos filtrados**. | Conforme |
| **Prevención IDOR y no-enumeración** | Intentos de acceso a recursos de grupos no autorizados devuelven HTTP 404 indistinguible y quedan auditados; credenciales LDAP erróneas devuelven 401 genérico. | Conforme |
| **Ruta de rescate Break-Glass probada** | Autenticación local Argon2id verificada operativa independientemente del estado de proveedores OIDC o LDAP. | Conforme |
| **Calidad de código Rust** | `cargo fmt --check --all` (0 diferencias), `cargo clippy -D warnings` (0 advertencias). | Conforme |
| **Frontend y diseño** | `npm --prefix console-web run build` (build Vite limpio), `check-design-tokens.js` (0 hallazgos). | Conforme |
| **Trazabilidad de parches sobre upstream** | Parche 012 aplicable limpiamente con `tools/apply-patches`, registrado en `patches/INDEX.md`. | Conforme |
| **Licenciamiento canónico** | Cabecera AGPL-3.0 verificada en el 100% de los archivos creados o modificados. | Conforme |

---

## 4. Estado de Transición a Fase 6

Con el cierre formal de la Fase 5:
- Se desbloquea la ejecución de **Fase 6: Optimización LAN y relays** (`docs/PLAN-F6-OPTIMIZACION.md`), orientada a benchmarking de latencia/rendimiento, detección de modo directo LAN vs relay, y optimización del tráfico de sesión.
