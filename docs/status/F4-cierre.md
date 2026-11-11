# Cierre de Fase 4 — Hito M3: Consola de administración web, RBAC y 2FA

**Fecha:** 2026-11-11  
**Estado:** Hecho  
**Coordinador:** Aprobado  
**Alcance:** F4-01 a F4-13 (13 tareas completadas y verificadas)

---

## 1. Resumen Ejecutivo

La **Fase 4 (Hito M3: Consola de administración web, RBAC y 2FA)** del proyecto **Cercano** ha sido completada en su totalidad con éxito, en estricto cumplimiento de `docs/PLAN-F4-CONSOLA.md`, las directrices de arquitectura de `docs/ARQUITECTURA.md` y las reglas de gobernanza y clean-room de `AGENTS.md`.

Se ha establecido el plano de gestión y control web (`console-web`) construido en React 19 + TypeScript y Vite, integrado con el backend `cercano-api`, proporcionando autenticación robusta mediante contraseñas con derivación Argon2id, segundo factor obligatorio basado en tiempo (TOTP RFC 6238) con cifrado en reposo AES-256-GCM (`enc:v1:`), matriz de autorización granular RBAC (roles `admin`, `operator`, `auditor`), gestión administrativa de usuarios y ajustes de servidor, correlación e inspección forense de auditoría inmutable, integración nativa con el generador de clientes de Fase 3 y panel de alarmas de seguridad.

---

## 2. Matriz de Entregables de Fase 4

| Tarea | Descripción | Entregable Principal | Estado |
|---|---|---|---|
| **F4-01** | Especificar matriz RBAC, flujo 2FA y eventos `auth.2fa_*` | Documentación de diseño, matriz de roles, esquema de eventos de auditoría y catálogo de pruebas TC-F4-001..014 | Hecho |
| **F4-02** | Migración 007: campos 2FA y `mfa_challenges` | DDL SQLite de `007_console_rbac_2fa` en `control-plane/cercano-api/src/db.rs` con cascada referencial y columnas de seguridad | Hecho |
| **F4-03** | API de usuarios, roles y ajustes con permisos | Endpoints `/api/users`, `/api/settings` con control de permisos RBAC en `cercano-api` | Hecho |
| **F4-04** | 2FA TOTP: enrolar, login en dos pasos, recovery, revocación | Módulo `src/auth.rs`, flujo 202 Accepted `mfa_challenge`, códigos de recuperación en formato `XXXX-XXXX-XXXX` y bloqueo tras 5 intentos fallidos | Hecho |
| **F4-05** | Middleware RBAC y permisos `chat:*` | Extractor `RequirePermission`, tags de compilación y verificación de permisos contra la base de datos | Hecho |
| **F4-06** | Consola: usuarios, roles, auditoría, ajustes y 2FA; login 2FA | `console-web` completo: componentes `LoginView`, `UsersView`, `AuditView`, `SettingsView`, modal 2FA, `TabBar` y temas claro/oscuro | Hecho |
| **F4-07** | Integración del generador en la consola | Componente `BuilderView.tsx`, invocación a `/api/builds`, polling reactivo, regiones accesibles ARIA y descarga de instaladores | Hecho |
| **F4-08** | Pruebas de permisos, IDOR, 2FA y sesiones | Suite completa de tests de integración en `cercano-api/tests`: permisos, prevención de IDOR, sesiones y revocación concurrente | Hecho |
| **F4-09** | E2E y gate F4 | Verificación transversal del flujo completo, build de consola (2093 módulos) y linter de tokens de diseño sin fallos | Hecho |
| **F4-10** | Cierre de F4, documentación e informe | Documento de cierre `docs/status/F4-cierre.md`, actualización de inventario de tareas e informes | Hecho |
| **F4-11** | Política de 2FA obligatoria (`auth.require_2fa_roles`), `mfa_verified` en sesión | Configuración estricta en servidor, sesiones restringidas con `mfa_enrollment_required: true`, bloqueo de auto-desvinculación de roles obligatorios y elevación tras confirmación | Hecho |
| **F4-12** | Cifrado en reposo del secreto TOTP | Cifrado simétrico AES-256-GCM con prefijo `enc:v1:` y clave derivada con HKDF-SHA256 (`CERCANO_SECRETS_KEY`). Fail-close en producción | Hecho |
| **F4-13** | Matriz de permisos final (`chat:*`, `db:admin`, grants) probada contra el código | Conciliación de tags de permisos, verificación de grants explícitos por usuario en `user_permissions` y suite de tests de matriz | Hecho |

---

## 3. Verificación de Criterios del Gate F4 (Hito M3)

| Criterio del Gate F4 | Evidencia Demostrada | Resultado |
|---|---|---|
| **Consola funcional sin dependencias externas inseguras** | `npm --prefix console-web run build` genera bundle estático Vite sin errores (418 kB JS gzip 113 kB, 50 kB CSS gzip 9 kB). `lint:design` con 0 infracciones. | Conforme |
| **Matriz RBAC granular y prevención de IDOR** | Tests `rbac_middleware_test.rs`, `roles_enforcement_test.rs`, `users_admin_test.rs` y `f4_policy_encryption_matrix_test.rs` pasan 100%. Operadores y auditores no acceden a mutaciones ni recursos fuera de su ámbito. | Conforme |
| **Segundo factor TOTP robusto y obligatorio** | Política `auth.require_2fa_roles` aplicada por servidor (F4-11): usuarios obligatorios sin 2FA no pueden navegar ni mutar la API hasta enrolarse. Sesión limitada `mfa_verified = 0`. Auto-desvinculación prohibida para técnicos/admins. | Conforme |
| **Protección criptográfica de secretos en reposo** | Secretos TOTP almacenados bajo formato `enc:v1:<nonce>:<ciphertext>` cifrados con AES-256-GCM (F4-12). Inspección directa en SQLite confirma que no hay secretos legibles. | Conforme |
| **Regla Zero Secrets en logs y auditoría** | Cero contraseñas, hashes, secretos TOTP o códigos de recuperación en respuestas JSON públicas, logs de servidor o eventos de auditoría inmutable. | Conforme |
| **Conformidad de licencia y calidad de código** | 100% de archivos con encabezado AGPL-3.0 verificado con `tools/check-license-headers.sh`. `cargo clippy -p cercano-api --all-targets -- -D warnings` limpio (0 advertencias). `cargo fmt --check` limpio. | Conforme |

---

## 4. Estado de Transición a Fase 4.5

Con el cierre formal de la Fase 4, quedan completamente habilitados los cimientos de seguridad y control de acceso necesarios para el despliegue de **Fase 4.5: Cercano Chat** (backend `ChatHub`, autenticación de dispositivos Ed25519, flujo de soporte y consola de conversaciones).
