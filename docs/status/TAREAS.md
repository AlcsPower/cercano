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
| F1-05 | Registro de dispositivos | F1-03, F0-06 | ControlPlane | QA | Hecho |
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
| F2-15 | Grabación de sesión vinculada a eventos *(opcional)* | F2-05 | Cliente + ControlPlane | Seguridad | Pendiente |

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
| F3-12 | Pruebas de extremo a extremo y cierre | F3-01…11, F3-13…18 | QA | Coordinador | Pendiente |
| F3-13 | Roles de instalador: perfil y aplicación en el servidor | F3-01, F3-02, F3-07 | ControlPlane + Servidor | Seguridad | Hecho |
| F3-14 | Cliente en modo soporte | F3-02, F3-13 | Cliente | QA | Pendiente |
| F3-15 | Cliente en modo técnico | F3-02, F3-13, F1-04 | Cliente | QA | Pendiente |
| F3-16 | Spike S6 y elevación con credenciales | F3-14, F3-15 | Cliente | Seguridad | Pendiente |
| F3-17 | Auditoría `elev.*` y alarmas de elevación | F3-16, F2-02, F2-07 | ControlPlane | QA | Pendiente |
| F3-18 | Revisión de seguridad de roles y elevación | F3-13…17 | Seguridad | Coordinador | Pendiente |

_Total: 53 tareas (F0–F3) + 15 de F4.5. F4–F7 se detallan al cerrar la fase anterior._

## F4.5 — Cercano Chat (complemento, después de F4)

Fuente: `docs/PLAN-F4.5-CHAT.md`. Depende de F4 cerrado, F3-13, F3-02, F3-05 y F2-02.

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F4.5-01 | Especificación, ADR y planificación | — | Coordinador | Dueño/QA | En verificación |
| F4.5-02 | Migración 004 y modelos | F4.5-01, F4 cerrado | ControlPlane | QA | Pendiente |
| F4.5-03 | Autenticación de dispositivo | F4.5-02, F3-13 | ControlPlane | Seguridad | Pendiente |
| F4.5-04 | API REST de conversaciones y mensajes | F4.5-03, F4 cerrado | ControlPlane | QA | Pendiente |
| F4.5-05 | Adjuntos | F4.5-04 | ControlPlane | Seguridad | Pendiente |
| F4.5-06 | SSE, `ChatHub`, lecturas y resumen | F4.5-04 | ControlPlane | QA | Pendiente |
| F4.5-07 | Auditoría, límites y retención | F4.5-02…06, F2-02 | ControlPlane | Seguridad | Pendiente |
| F4.5-08 | Consola: vista Conversaciones | F4.5-04/05/06, F4 cerrado | Web | QA | Pendiente |
| F4.5-09 | Consola: badge, notificaciones, reconexión, accesibilidad | F4.5-08 | Web | QA | Pendiente |
| F4.5-10 | Cliente: módulo Rust y parche 006 | F4.5-03/04/06, F3-02 | Cliente | Seguridad | Pendiente |
| F4.5-11 | Cliente: UI Flutter, nombre del contacto, adjuntos, i18n | F4.5-10, F4.5-13 | Cliente | QA | Pendiente |
| F4.5-12 | Escalado a sesión remota (`cercano://`) | F4.5-08/11, F3-05 | Cliente + Web | Seguridad | Pendiente |
| F4.5-13 | Perfil `policy.chat` y aplicación en servidor | F3-01/02/13, F4.5-04 | ControlPlane + Cliente | Seguridad | Pendiente |
| F4.5-14 | E2E, seguridad, carga básica y cierre | F4.5-02…13 | QA + Seguridad | Coordinador | Pendiente |
| F4.5-15 | Guía de despliegue y operación | F4.5-14 | Coordinador | QA | Pendiente |
