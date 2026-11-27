# Estado de las tareas

Fuente de las tareas: `docs/PLAN-*.md`. Este archivo se actualiza al tomar y cerrar cada tarea (ver `AGENTS.md`, sección 3).
Estados: `Pendiente` · `En curso` · `En verificación` · `Hecho` · `Bloqueada` · `Diferida`.

## F0

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F0-01 | Gobernanza del repo | — | Builder | QA | Hecho |
| F0-02 | Importar upstream | F0-01 | Servidor | QA | Hecho |
| F0-03 | CI base | F0-01 | Builder | QA | Hecho |
| F0-04 | Spike S1: build del servidor y despliegue en LAN | F0-02 | Servidor | QA | Hecho |
| F0-05 | Spike S2: build del cliente Windows | F0-02 | Cliente | QA | Hecho |
| F0-06 | Spike S3: hooks de heartbeat y auditoría del cliente | F0-05 | Cliente | Seguridad | Hecho |
| F0-07 | Spike S4: configuración embebida y verificación | F0-05 | Cliente | Seguridad | Hecho |
| F0-08 | Spike S5: propagación de `trace_id` | F0-04, F0-05 | Servidor | QA | Hecho |
| F0-09 | Laboratorio de pruebas LAN | F0-01 | QA | Coordinador | Hecho |
| F0-10 | Ratificación de ADR y cierre de F0 | F0-04…09 | Coordinador | Dueño | Hecho |

## F1

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F1-01 | Rebranding mínimo del servidor | F0-10 | Servidor | QA | Hecho |
| F1-02 | Empaquetado del servidor | F1-01 | Builder | QA | Hecho |
| F1-03 | Esqueleto de `cercano-api` | F0-10 | ControlPlane | QA | Hecho |
| F1-04 | Autenticación y usuarios | F1-03 | ControlPlane | Seguridad | Hecho |
| F1-05 | Registro de dispositivos | F1-03 | ControlPlane | QA | Hecho |
| F1-06 | Gestión de claves del servidor | F1-01, F1-03 | Servidor | Seguridad | Hecho |
| F1-07 | Rebranding del cliente | F0-10 | Cliente | QA | Hecho |
| F1-08 | Cliente apuntando a `cercano-api` | F1-05, F1-07 | Cliente | QA | Hecho |
| F1-09 | Smoke test E2E automatizado | F1-02, F1-08, F0-09 | QA | Coordinador | Hecho |
| F1-10 | Guía de despliegue y cierre | F1-09 | Coordinador | Dueño | Hecho |

## F2

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F2-01 | Especificación del esquema de eventos | F1 cerrado | ControlPlane | Seguridad | Hecho |
| F2-02 | Núcleo `audit-core`: almacén append-only y cadena de hashes | F2-01 | ControlPlane | QA | Hecho |
| F2-03 | Checkpoints firmados y `cercano-audit verify` | F2-02 | ControlPlane | Seguridad | Hecho |
| F2-04 | Endpoints de ingestión (conexión, archivo, alarma) | F2-02, F0-06 | ControlPlane | QA | En verificación |
| F2-05 | Parches al cliente para hooks faltantes | F2-04 | Cliente | QA | En verificación |
| F2-06 | Correlación y `trace_id` | F2-04, F0-08 | Servidor + Cliente | QA | Hecho |
| F2-07 | Motor de alarmas | F2-04 | ControlPlane | QA | Hecho |
| F2-08 | Auditoría de la API y la consola | F2-02, F1-04 | ControlPlane | QA | Hecho |
| F2-09 | API de consulta y exportación | F2-04, F2-08 | ControlPlane | QA | Hecho |
| F2-10 | Exportadores SIEM | F2-02 | ControlPlane | QA | Hecho |
| F2-11 | Retención y archivado | F2-02 | ControlPlane | Seguridad | Hecho |
| F2-12 | Nota de sesión | F2-04, F2-05 | Cliente + ControlPlane | QA | Hecho |
| F2-13 | Pruebas de manipulación, carga y reloj | F2-03…11 | QA + Seguridad | Coordinador | En verificación |
| F2-14 | Guía de auditoría y cierre | F2-13 | Coordinador | Dueño | En verificación |
| F2-15 | Grabación de sesión vinculada a eventos (opcional) | F2-05 | Cliente + ControlPlane | Seguridad | Pendiente |

## F3

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F3-01 | Esquema y versionado del perfil | F0-07 | Builder | Seguridad | Hecho |
| F3-02 | Cliente: lectura y verificación de perfil firmado | F3-01 | Cliente | Seguridad | Hecho |
| F3-03 | Binario base reproducible y publicación de artefactos base | F0-05, F0-03 | Builder | QA | Hecho |
| F3-04 | CLI `cercano-build` | F3-01, F3-02, F3-03 | Builder | QA | Hecho |
| F3-05 | Empaquetado Windows (.exe y .msi) | F3-04 | Builder | QA | Hecho |
| F3-06 | Firma Authenticode enchufable | F3-05 | Builder | Seguridad | Hecho |
| F3-07 | Servicio de build en `cercano-api`: cola, jobs, almacenamiento | F3-04, F1-04 | ControlPlane | QA | Hecho |
| F3-08 | Auditoría `build.*` | F3-07, F2-02 | ControlPlane | QA | Hecho |
| F3-09 | Revocación y caducidad | F3-02, F3-07 | ControlPlane + Servidor | Seguridad | Hecho |
| F3-10 | SBOM y verificación de procedencia | F3-04 | Builder | Seguridad | Hecho |
| F3-11 | Guía de despliegue masivo | F3-05, F3-14, F3-15 | Coordinador | QA | Hecho |
| F3-12 | Pruebas de extremo a extremo y cierre | F3-01…11, F3-13…18 | QA | Coordinador | Hecho |
| F3-13 | Roles de instalador: perfil y aplicación en el servidor | F3-01, F3-02, F3-07 | ControlPlane + Servidor | Seguridad | Hecho |
| F3-14 | Cliente en modo soporte | F3-02, F3-13 | Cliente | QA | Hecho |
| F3-15 | Cliente en modo técnico | F3-02, F3-13, F1-04 | Cliente | QA | Hecho |
| F3-16 | Spike S6 y elevación con credenciales | F3-14, F3-15 | Cliente | Seguridad | Hecho |
| F3-17 | Auditoría `elev.*` y alarmas de elevación | F3-16, F2-02, F2-07 | ControlPlane | QA | Hecho |
| F3-18 | Revisión de seguridad de roles y elevación | F3-13…17 | Seguridad | Coordinador | Hecho |
| F3-19a | Reconciliar `hbb_common`/manifiesto del cliente; `cargo check` en CI; CI en verde | F3-03 | Builder + Cliente | QA | Pendiente |
| F3-19 | Cliente Windows real (workflow `windows-latest`) | F3-19a | Builder + Cliente | QA | Pendiente |
| F3-22 | Marca visible: empresa (logo y nombre), «Powered by Cercano», Acerca de (sustituida por F3.5-10, ADR-015) | F3-19a, F3-02 | Cliente | QA | Diferida |
| F3-20 | Fail-closed: sin binario base real no se empaqueta (`--allow-stub`) | F3-05, F3-07 | Builder + ControlPlane | Seguridad | Pendiente |
| F3-21 | Prueba de humo en Windows 10/11 | F3-19, F3-20 | QA | Coordinador | Pendiente |
| F3-23 | Interfaz de escritorio según el diseño objetivo (`docs/diseno/`); sin «Con tecnología de RustDesk» | F3-14, F3-15, F3-19 | Cliente | QA | Pendiente |

## F3.5 — Agente Cercano y aplicación genérica

Fuente: `docs/PLAN-F3.5-AGENTE.md` y `docs/adr/015-agente-y-cliente-generico.md` (aprobado por el Dueño el 2026-11-25). F3-22 queda `Diferida` (sustituida por F3.5-10). F3.5-01 sigue en verificación hasta que lo ratifiquen el Coordinador y Seguridad; las demás tareas empiezan después.

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F3.5-01 | ADR-015, plan y casos de prueba propuestos | — | Coordinador | Dueño + Seguridad | En verificación |
| F3.5-02 | Spike S9: etiquetado de paquetes (fuera del plan: se usa configuración aparte) | — | Builder | Seguridad | Diferida |
| F3.5-03 | Contrato del canal local y formato de la configuración | F3.5-01 | Coordinador + Cliente + ControlPlane | Seguridad | Pendiente |
| F3.5-04 | Esqueleto de `agent/`: servicio, almacén fijado, logs y CLI | F3.5-03 | Cliente | QA | Pendiente |
| F3.5-05 | Vinculación `POST /api/agent/enroll` y lado del agente | F3.5-04, F3-09, F3-13, F4.5-03 | ControlPlane + Cliente | Seguridad | Pendiente |
| F3.5-06 | Canal local con verificación mutua de firma | F3.5-04 | Cliente | Seguridad | Pendiente |
| F3.5-07 | Política, latido y cola de auditoría en el agente | F3.5-05, F3.5-06 | Cliente | QA | Pendiente |
| F3.5-08 | Transporte del chat en el agente | F3.5-05, F3.5-06 | Cliente | QA | Pendiente |
| F3.5-09 | Parche 013: puente con el agente y modos gestionado/libre/bloqueado | F3.5-06, F3-19a | Cliente | Seguridad | Pendiente |
| F3.5-10 | Marca en tiempo de ejecución (sustituye F3-22) | F3.5-09 | Cliente | QA | Pendiente |
| F3.5-11 | `cercano-build`: paquete genérico que lee `cercano-org.json` o `CERCANO_CONFIG` | F3.5-03, F3.5-04, F3-20 | Builder | QA | Pendiente |
| F3.5-12 | Generador en el servidor (`cercano-api` + `console-web`) | F3.5-11, F3-07, F3-08, F4-07 | ControlPlane + Web | QA | Pendiente |
| F3.5-13 | Guía de despliegue y diagnóstico con PowerShell | F3.5-04, F3.5-12 | Coordinador | QA | Pendiente |
| F3.5-14 | Revisión de seguridad | F3.5-05…12 | Seguridad | Coordinador | Pendiente |
| F3.5-15 | E2E en Windows 10/11 y cierre | F3.5-01…14 | QA | Coordinador | Pendiente |

## F4 — Consola web, RBAC y 2FA

Fuente: `docs/PLAN-F4-CONSOLA.md`. F4 puede ir en paralelo con F3; solo F4-07 (generador) espera F3-07.

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F4-01 | Especificar matriz RBAC, flujo 2FA y eventos `auth.2fa_*` | F1-04, F2-08 | Coordinador + Seguridad | Seguridad | Hecho |
| F4-02 | Migración 007: campos 2FA y `mfa_challenges` | F4-01 | ControlPlane | QA | Hecho |
| F4-03 | API de usuarios, roles y ajustes con permisos | F4-02 | ControlPlane | QA | Hecho |
| F4-04 | 2FA TOTP: enrolar, login en dos pasos, recovery, revocación | F4-02, F4-03 | ControlPlane | Seguridad | Hecho |
| F4-05 | Middleware RBAC y permisos `chat:*` | F4-03 | ControlPlane | QA | Hecho |
| F4-06 | Consola: usuarios, roles, auditoría, ajustes y 2FA; login 2FA | F4-03, F4-04, F4-05 | Web | QA | Hecho |
| F4-07 | Integración del generador en la consola (F3-07 hecho; espera F4-05/06) | F3-07, F4-05, F4-06 | Web | QA | Hecho |
| F4-11 | Política de 2FA obligatoria (`auth.require_2fa_roles`), `mfa_verified` en sesión | F4-04, F4-06 | ControlPlane + Web | Seguridad | Hecho |
| F4-12 | Cifrado en reposo del secreto TOTP | F4-04 | ControlPlane | Seguridad | Hecho |
| F4-13 | Matriz de permisos final (`chat:*`, `db:admin`, grants) probada contra el código | F4-05, F4-11 | ControlPlane | QA | Hecho |
| F4-08 | Pruebas de permisos, IDOR, 2FA y sesiones | F4-03…07, F4-11…13 | QA | Coordinador | Hecho |
| F4-09 | E2E y gate F4 | F4-08 | QA | Coordinador | Hecho |
| F4-10 | Cierre de F4, documentación e informe | F4-09 | Coordinador | Dueño | Hecho |

## F4.5 — Cercano Chat (complemento, después de F4)

Fuente: `docs/PLAN-F4.5-CHAT.md` v1.1. Backend y consola dependen de F4-05/06; el gate y el uso fuera del laboratorio exigen F4 cerrado (incl. F4-11), F3-13, F3-02, F3-05 y F2-02.

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F4.5-01 | Especificación, ADR y planificación | — | Coordinador | Dueño/QA | Hecho |
| F4.5-02 | Migración 008 y modelos | F4.5-01, F4-02 | ControlPlane | QA | Hecho |
| F4.5-03 | Autenticación de dispositivo | F4.5-02, F3-13 | ControlPlane | Seguridad | Hecho |
| F4.5-04 | API REST de conversaciones y mensajes | F4.5-03, F4-05 | ControlPlane | QA | Hecho |
| F4.5-05 | Adjuntos | F4.5-04 | ControlPlane | Seguridad | Hecho |
| F4.5-06 | SSE, `ChatHub`, lecturas y resumen | F4.5-04 | ControlPlane | QA | Hecho |
| F4.5-07 | Auditoría, límites y retención | F4.5-02…06, F2-02 | ControlPlane | Seguridad | Hecho |
| F4.5-08 | Consola: vista Conversaciones | F4.5-04/05/06, F4-06 | Web | QA | Hecho |
| F4.5-09 | Consola: badge, notificaciones, reconexión, accesibilidad | F4.5-08 | Web | QA | Hecho |
| F4.5-10 | Cliente: módulo Rust y parche 008 | F4.5-03/04/06, F3-02 | Cliente | Seguridad | Hecho |
| F4.5-11 | Cliente: UI Flutter, nombre del contacto, adjuntos, i18n | F4.5-10, F4.5-13 | Cliente | QA | Hecho |
| F4.5-12 | Escalado a sesión remota (`cercano://`) | F4.5-08/11, F3-05 | Cliente + Web | Seguridad | Hecho |
| F4.5-13 | Perfil `policy.chat` y aplicación en servidor | F3-01/02/13, F4.5-04 | ControlPlane + Cliente | Seguridad | Hecho |
| F4.5-14 | E2E, seguridad, carga básica y cierre | F4.5-02…13 | QA + Seguridad | Coordinador | Hecho |
| F4.5-15 | Guía de despliegue y operación | F4.5-14 | Coordinador | QA | Hecho |
| F4.5-16 | Marca del chat configurable desde la consola | F4.5-02, F4.5-08, F4.5-11 | Web + ControlPlane | Seguridad/QA | Hecho |
| F4.5-17 | Nombre visible del técnico en el chat del cliente: campo `display_name` en usuarios (migración aditiva), editable en la consola; la API entrega `assigned_display_name` al dispositivo y deja de enviarle `assigned_username`, también en el `sender_name` de los mensajes (nunca el login); el cliente muestra «Atendido por <técnico>» y el nombre en sus mensajes | F4.5-16 | ControlPlane + Web + Cliente | QA | En verificación |

## F5 — Identidad y control de acceso

Fuente: `docs/PLAN-F5-IDENTIDAD.md`. Fase 5 completada y cerrada formalmente (2026-11-16; ver `docs/status/F5-cierre.md`). Las 13 tareas F5-01 a F5-13 están en Hecho (con F5-09 y F5-10 diferidas mediante ADR-013 y ADR-014).

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F5-01 | Aprobar modelo de grupos, libreta, estrategias, federación, LAPS y orden de migraciones | F4, F4.5 | Coordinador + Seguridad | Dueño/QA | Hecho |
| F5-02 | Migración aditiva (siguiente versión libre; hoy la 009) y modelos de grupos, membresías, libreta y estrategias | F5-01 | ControlPlane | QA | Hecho |
| F5-03 | API CRUD de grupos y libreta con auditoría | F5-02, F4-05 | ControlPlane | QA | Hecho |
| F5-04 | Enforcement de alcance por rol/grupo y permisos entre grupos | F5-02/03 | ControlPlane | Seguridad | Hecho |
| F5-05 | Servicio de estrategias: versionado, precedencia y política efectiva | F5-01/02 | ControlPlane | Seguridad/QA | Hecho |
| F5-06 | Cliente: descarga, cacheo y aplicación segura de estrategias | F5-05, F3-02/13 | Cliente | QA/Seguridad | Hecho |
| F5-07 | Inicio de sesión OIDC con PKCE y vinculación de identidad | F5-01, F4 | ControlPlane | Seguridad | Hecho |
| F5-08 | Autenticación LDAP sobre TLS y mapeo explícito de grupos | F5-01, F4 | ControlPlane | Seguridad | Hecho |
| F5-09 | Evaluar cambio de ID de dispositivo y decisión ADR | F5-01, F1-05 | Coordinador + Servidor | Seguridad/Dueño | Hecho |
| F5-10 | Evaluar/integrar Windows LAPS bajo consentimiento y permiso dedicado | F5-01, F3-16…18, F4 | ControlPlane + Cliente | Seguridad | Hecho |
| F5-11 | Consola: grupos, libreta, estrategias, federación y política efectiva | F5-03…08 | Web | QA | Hecho |
| F5-12 | Pruebas de integración, autorización, identidad y laboratorio LAN | F5-03…11 | QA + Seguridad | Coordinador | Hecho |
| F5-13 | Documentación de operador y cierre F5 | F5-12 | Coordinador | Dueño | Hecho |

## F6 — Optimización LAN y relays

Fuente: `docs/PLAN-F6-LAN-RELAYS.md`. Depende del cierre de F5, salvo F6-01…F6-05, que el propio plan permite en paralelo con F5. F6-01 se adelantó el 2026-11-10 (diseño y umbrales, sin medición).

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F6-01 | Spike de topologías, descubrimiento y transporte | F1-09, F2-06, F3-13 | Servidor + Seguridad | QA/Coordinador | En verificación |
| F6-02 | Configuración de sitios LAN, rangos y nodos relay | F6-01 | ControlPlane | Seguridad | Pendiente |
| F6-03 | Descubrimiento LAN limitado y con interruptor administrativo | F6-01/02 | Servidor + Cliente | Seguridad/QA | Pendiente |
| F6-04 | Salud, heartbeats, capacidad y retiro de relays | F6-02 | Servidor | QA | Pendiente |
| F6-05 | Selector multi-relay, scoring, desempate y fallback | F6-04 | Servidor | QA | Pendiente |
| F6-06 | Cliente: selección/reintento conservando política y `trace_id` | F6-05, F3-13, F5-05 | Cliente | Seguridad/QA | Pendiente |
| F6-07 | Evaluar WebSocket e implementar solo con ADR aprobado | F6-01 | Servidor + Cliente | Seguridad | Pendiente |
| F6-08 | Telemetría operativa y auditoría de rutas | F6-03…07, F2 | ControlPlane + Servidor | Seguridad | Pendiente |
| F6-09 | Pruebas de rendimiento, resiliencia y compatibilidad | F6-03…08 | QA | Coordinador | Pendiente |
| F6-10 | Guía de operación y cierre F6 | F6-09 | Coordinador | Dueño | Pendiente |

## F7 — Endurecimiento y release beta

Fuente: `docs/PLAN-F7-RELEASE.md`. Depende del cierre de F6.

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F7-01 | Definir alcance beta, plataformas, soporte y criterios | F6 | Coordinador + Dueño | QA | Pendiente |
| F7-02 | Revisión integral STRIDE/LINDDUN y controles | F7-01 | Seguridad | Coordinador | Pendiente |
| F7-03 | Pentest interno autorizado en laboratorio | F7-02 | Seguridad + QA | Coordinador | Pendiente |
| F7-04 | Corregir hallazgos y verificar mitigaciones | F7-03 | Roles responsables | Seguridad independiente | Pendiente |
| F7-05 | Dependencias, licencias, CVE, SBOM y procedencia | F7-01 | Builder + Seguridad | QA | Pendiente |
| F7-06 | Build reproducible, firma de release y publicación | F7-05 | Builder | Seguridad/QA | Pendiente |
| F7-07 | Gestión de llaves: generación, rotación, backup y recuperación | F7-02 | ControlPlane + Servidor | Seguridad | Pendiente |
| F7-08 | Prueba de respaldo/restauración y continuidad | F7-07 | ControlPlane + QA | Seguridad | Pendiente |
| F7-09 | Compatibilidad, actualización, migraciones y recuperación | F7-01, F7-06 | Builder + QA | Coordinador | Pendiente |
| F7-10 | Revisión de privacidad, retención y documentación | F7-02 | Seguridad + Coordinador | Dueño | Pendiente |
| F7-11 | Observabilidad, operación e incidentes | F7-08/09 | ControlPlane + Servidor | QA | Pendiente |
| F7-12 | Candidato beta (RC), pruebas y publicación de notas | F7-04…11 | Builder + QA | Dueño/Coordinador | Pendiente |
| F7-13 | Informe de cierre, deuda y gate M4 | F7-12 | Coordinador | Dueño | Pendiente |

## F8 — Portabilidad y respaldos gestionados (extra post-v1)

Fuente: `docs/PLAN-F8-PORTABILIDAD.md`. Después de F7; **no bloquea M4**. SQL Server quedó diferido en F8-01 (no hay driver MSSQL en `sqlx 0.8`); la fase entrega SQLite y PostgreSQL.

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F8-01 | ADR-011, inventario de SQL y viabilidad de SQL Server | — | ControlPlane + Seguridad | Coordinador | En verificación |
| F8-02 | Crate `db-core`: pool, dialecto, marcadores, timestamps, factoría y `AppState` | F8-01 | ControlPlane | QA | Pendiente |
| F8-03 | Esquema y migraciones por motor, disparadores, fingerprint en CI | F8-02 | ControlPlane | Seguridad | Pendiente |
| F8-04 | Portar consultas de `cercano-api` y `audit-core` a SQL portable | F8-03 | ControlPlane | QA | Pendiente |
| F8-05 | Formato de archivo firmado y verificador | F8-02 | ControlPlane | Seguridad | Pendiente |
| F8-06 | API de respaldo y restauración; programación y retención; auditoría `db.backup_*`/`db.restore_*` | F8-04, F8-05 | ControlPlane | QA | Pendiente |
| F8-07 | Asistente de migración: preflight, mantenimiento, copia, verificación, corte y rollback | F8-06 | ControlPlane | Seguridad | Pendiente |
| F8-08 | Consola: pestaña «Mantenimiento», permiso `db:admin`, confirmaciones y progreso | F8-06, F8-07, F4-06 | Web | QA | Pendiente |
| F8-09 | Matriz de pruebas SQLite/PostgreSQL/SQL Server y pruebas de fallo | F8-04…08 | QA | Coordinador | Pendiente |
| F8-10 | Runbook `docs/guias/respaldos-y-migracion.md`, cierre e informe | F8-09 | Coordinador | Dueño | Pendiente |

_Total: 58 tareas F0–F3 (F3-19a, F3-19…22 reabren M2, ver B-002), 13 de F4, 16 de F4.5, 13 de F5, 10 de F6, 13 de F7 y 10 de F8 (extra post-v1, no bloquea M4). Los planes F5–F8 están revisados por el Coordinador y pendientes de aprobación del dueño; no indican que las fases hayan comenzado. F8-01 arrancó el 2026-11-10 (análisis y ADR, sin código) y está en verificación; el resto de F8 sigue a la espera de esa aprobación. F5-01 quedó redactado el 2026-11-10 (ADR-012 y spec de identidad) y espera la aprobación del dueño y la revisión de Seguridad; no se ha escrito código de F5. F6-01 midió el laboratorio el 2026-11-10 (RTT, pérdida, throughput y consumo de relay; ver S7 e informe) y está en verificación: la medición de sesión queda para F6-05/F6-06._
