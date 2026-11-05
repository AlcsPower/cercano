# Estado de las tareas

Fuente de las tareas: `docs/PLAN-*.md`. Este archivo se actualiza al tomar y cerrar cada tarea (ver `AGENTS.md`, sección 3).
Estados: `Pendiente` · `En curso` · `En verificación` · `Hecho` · `Bloqueada` · `Diferida`.


## F0

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F0-01 | Gobernanza del repo | — | Builder | QA | En curso |
| F0-02 | Importar upstream | F0-01 | Servidor | QA | Hecho |
| F0-03 | CI base | F0-01 | Builder | QA | Hecho |
| F0-04 | Spike S1: build del servidor y despliegue en LAN | F0-02 | Servidor | QA | Pendiente |
| F0-05 | Spike S2: build del cliente Windows | F0-02 | Cliente | QA | Pendiente |
| F0-06 | Spike S3: hooks de heartbeat y auditoría del cliente | F0-05 | Cliente | Seguridad | Pendiente |
| F0-07 | Spike S4: configuración embebida y verificación | F0-05 | Cliente | Seguridad | Pendiente |
| F0-08 | Spike S5: propagación de `trace_id` | F0-04, F0-05 | Servidor | QA | Pendiente |
| F0-09 | Laboratorio de pruebas LAN | F0-01 | QA | Coordinador | Hecho |
| F0-10 | Ratificación de ADR y cierre de F0 | F0-04…09 | Coordinador | Dueño | Pendiente |

## F1

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F1-01 | Rebranding mínimo del servidor | F0-10 | Servidor | QA | Pendiente |
| F1-02 | Empaquetado del servidor | F1-01 | Builder | QA | Pendiente |
| F1-03 | Esqueleto de `cercano-api` | F0-10 | ControlPlane | QA | Hecho |
| F1-04 | Autenticación y usuarios | F1-03 | ControlPlane | Seguridad | Pendiente |
| F1-05 | Registro de dispositivos | F1-03, F0-06 | ControlPlane | QA | Pendiente |
| F1-06 | Gestión de claves del servidor | F1-01, F1-03 | Servidor | Seguridad | Pendiente |
| F1-07 | Rebranding del cliente | F0-10 | Cliente | QA | Pendiente |
| F1-08 | Cliente apuntando a `cercano-api` | F1-05, F1-07 | Cliente | QA | Pendiente |
| F1-09 | Smoke test E2E automatizado | F1-02, F1-08, F0-09 | QA | Coordinador | Pendiente |
| F1-10 | Guía de despliegue y cierre | F1-09 | Coordinador | Dueño | Pendiente |

## F2

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F2-01 | Especificación del esquema de eventos | F1 cerrado | ControlPlane | Seguridad | Pendiente |
| F2-02 | Núcleo `audit-core`: almacén append-only y cadena de hashes | F2-01 | ControlPlane | QA | Pendiente |
| F2-03 | Checkpoints firmados y `cercano-audit verify` | F2-02 | ControlPlane | Seguridad | Pendiente |
| F2-04 | Endpoints de ingestión (conexión, archivo, alarma) | F2-02, F0-06 | ControlPlane | QA | Pendiente |
| F2-05 | Parches al cliente para hooks faltantes | F2-04 | Cliente | QA | Pendiente |
| F2-06 | Correlación y `trace_id` | F2-04, F0-08 | Servidor + Cliente | QA | Pendiente |
| F2-07 | Motor de alarmas | F2-04 | ControlPlane | QA | Pendiente |
| F2-08 | Auditoría de la API y la consola | F2-02, F1-04 | ControlPlane | QA | Pendiente |
| F2-09 | API de consulta y exportación | F2-04, F2-08 | ControlPlane | QA | Pendiente |
| F2-10 | Exportadores SIEM | F2-02 | ControlPlane | QA | Pendiente |
| F2-11 | Retención y archivado | F2-02 | ControlPlane | Seguridad | Pendiente |
| F2-12 | Nota de sesión | F2-04, F2-05 | Cliente + ControlPlane | QA | Pendiente |
| F2-13 | Pruebas de manipulación, carga y reloj | F2-03…11 | QA + Seguridad | Coordinador | Pendiente |
| F2-14 | Guía de auditoría y cierre | F2-13 | Coordinador | Dueño | Pendiente |
| F2-15 | Grabación de sesión vinculada a eventos *(opcional)* | F2-05 | Cliente + ControlPlane | Seguridad | Pendiente |

## F3

| ID | Tarea | Dep. | Rol | Verifica | Estado |
|---|---|---|---|---|---|
| F3-01 | Esquema y versionado del perfil | F0-07 | Builder | Seguridad | Pendiente |
| F3-02 | Cliente: lectura y verificación de perfil firmado | F3-01 | Cliente | Seguridad | Pendiente |
| F3-03 | Binario base reproducible y publicación de artefactos base | F0-05, F0-03 | Builder | QA | Pendiente |
| F3-04 | CLI `cercano-build` | F3-01, F3-02, F3-03 | Builder | QA | Pendiente |
| F3-05 | Empaquetado Windows (.exe y .msi) | F3-04 | Builder | QA | Pendiente |
| F3-06 | Firma Authenticode enchufable | F3-05 | Builder | Seguridad | Pendiente |
| F3-07 | Servicio de build en `cercano-api`: cola, jobs, almacenamiento | F3-04, F1-04 | ControlPlane | QA | Pendiente |
| F3-08 | Auditoría `build.*` | F3-07, F2-02 | ControlPlane | QA | Pendiente |
| F3-09 | Revocación y caducidad | F3-02, F3-07 | ControlPlane + Servidor | Seguridad | Pendiente |
| F3-10 | SBOM y verificación de procedencia | F3-04 | Builder | Seguridad | Pendiente |
| F3-11 | Guía de despliegue masivo | F3-05 | Coordinador | QA | Pendiente |
| F3-12 | Pruebas de extremo a extremo y cierre | F3-01…11 | QA | Coordinador | Pendiente |

_Total: 47 tareas (F0–F3). F4–F7 se detallan al cerrar la fase anterior._
