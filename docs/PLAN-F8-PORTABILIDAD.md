# Plan de trabajo — F8: Portabilidad y respaldos gestionados

**Versión:** 0.1 · **Fecha:** 2026-11-10 · **Fase:** F8 (extra post-v1, después de F7) · **Duración estimada:** 4–6 semanas
**Depende de:** F2-02 (auditoría encadenada), F4-04 (2FA, para reautenticar), F4-05/F4-06 (RBAC y consola), F3-07 (patrón de trabajos con progreso).
**No bloquea M4.** Es un extra pedido por el dueño el 2026-11-10; se planifica ahora aunque el roadmap (§2) detalle las fases al cerrar la anterior.
**Documentos:** [`ROADMAP.md`](ROADMAP.md) §4 y §7 (D3, D10, D11), [`ARQUITECTURA.md`](ARQUITECTURA.md) §1, [`adr/011-portabilidad-bd.md`](adr/011-portabilidad-bd.md) (decisión), [`specs/db-portabilidad.md`](specs/db-portabilidad.md) (contrato), [`guias/respaldos-y-migracion.md`](guias/respaldos-y-migracion.md) (operación), [`guias/chat.md`](guias/chat.md) §4.2 (respaldos de adjuntos), [`guias/rotacion-claves.md`](guias/rotacion-claves.md) §4 (respaldos de claves).

## 1. Objetivo (hito M5)

Un administrador, desde la consola, **crea, verifica y restaura** respaldos del control plane y **migra el motor de base de datos** de SQLite a PostgreSQL —SQL Server quedó fuera en F8-01 porque `sqlx 0.8` no tiene driver MSSQL— sin pérdida de datos, con verificación previa al corte, rollback posible y auditoría completa de la operación.

Hoy el respaldo es un `tar` manual que ni siquiera incluye `cercano.db` ([`guias/chat.md`](guias/chat.md) §4.2) y «PostgreSQL opcional» (ADR-003, [`ARQUITECTURA.md`](ARQUITECTURA.md) §3) no existe en el código: `sqlx` solo compila `sqlite` y las 142 sentencias de `cercano-api` y `audit-core` usan sintaxis SQLite en 25 casos y en todo el DDL (inventario de F8-01).

## 2. No objetivos

- Alta disponibilidad, réplicas, varios nodos de API o migración sin corte.
- Cifrado de la base de datos en reposo o de los respaldos dentro de la aplicación (el operador los cifra al sacarlos del equipo).
- Migrar los adjuntos de chat fuera de su directorio: el respaldo los lista por hash y opcionalmente los incluye.
- Cambiar el motor de instalación por defecto: SQLite sigue siendo el predeterminado.

## 3. Decisiones

| ID | Decisión de diseño de F8 (no son las D1–D11 del roadmap) |
|---|---|
| F8-D1 | **SQL Server diferido en F8-01 (2026-11-10).** `sqlx 0.8` no tiene driver MSSQL (retirado en la 0.7), así que no había nada que validar: F8 entrega SQLite y PostgreSQL. Si se retoma, se evalúa `tiberius` detrás de la misma interfaz, con spike y estimación propios; PostgreSQL no se ve afectado. |
| F8-D2 | Capa de datos nueva `control-plane/db-core`: enum de pool (`Sqlite`/`Pg`; un eventual `Mssql` espera a que exista driver) y `Dialect` con reescritura de marcadores (`?` → `$n` en PostgreSQL), omitiendo literales y comentarios. Sin ORM y sin duplicar el SQL por motor. |
| F8-D3 | El SQL se escribe **una vez**; lo que cambia por motor son los fragmentos que no son portables: DDL de migraciones, plantilla de *upsert* (`ON CONFLICT` / patrón `UPDATE` + `INSERT`) y disparadores. |
| F8-D4 | **Los timestamps se generan en Rust** en formato canónico `%Y-%m-%dT%H:%M:%S%.3fZ`, no con `datetime('now')`. Se eliminan los 36 usos en `cercano-api` y los 4 `strftime`. **`audit_events.ts` no se reescribe**: cambiaría el hash de la cadena. |
| F8-D5 | Booleanos como entero pequeño (`0`/`1`): `INTEGER` en SQLite, `SMALLINT` en PostgreSQL, `BIT`/`TINYINT` en SQL Server. Evita un conversor de tipos por consulta. |
| F8-D6 | **Un solo formato de archivo** sirve para respaldo, restauración y migración: cabecera de manifiesto + una línea JSON por fila, comprimido con gzip, con SHA-256 por tabla y firma Ed25519 con `audit_signing_key` sobre un mensaje con prefijo de dominio (`cercano-backup-v1\0`), para que una firma de respaldo nunca valga como firma de checkpoint; F8-01 puede decidir una clave dedicada. Reutiliza el patrón de sobre de `audit-core/src/retention.rs`. Una dependencia nueva: `flate2` (ya usada por `audit-core`). |
| F8-D7 | El respaldo **no incluye** `id_ed25519` ni `audit_signing_key`. La consola avisa y el runbook mantiene la copia de claves como paso aparte: un archivo descargable por HTTP con secretos multiplica el riesgo, y sin claves el servidor restaurado no puede verificar checkpoints. |
| F8-D8 | Migración con **modo mantenimiento** y corte por configuración: snapshot previo, copia por lotes con checksums, verificación de conteos y de la cadena, escritura atómica de `database_url` en el TOML y respuesta `requires_restart: true` (patrón ya usado por la rotación de claves en F1-06). El origen no se toca: es el rollback. |

## 4. Arquitectura

### 4.1 Capa de datos

```
cercano-api ──► db-core::Db (enum de pool)
                     ├─ Sqlite(SqlitePool)   ← actual
                     └─ Pg(PgPool)
                 Dialect::{Sqlite, Postgres}
```

- `AppState.db` pasa de `SqlitePool` a `db_core::Db`; `audit-core` recibe el pool concreto de su motor.
- `db_core::sql(dialect, "… ? …")` reescribe marcadores; unit test con literales que contienen `?`, `--` y `/* */`.
- Conexión: `CERCANO_DATABASE_URL` acepta `sqlite://…` y `postgres://…`; cualquier otro esquema falla al arrancar con un error claro. Sin URL, SQLite como hoy.
- Cada motor conserva sus ajustes: WAL y `busy_timeout` solo en SQLite; *pool* máximo y *timeouts* equivalentes en PostgreSQL.

### 4.2 Esquema y migraciones

- `migrations/<motor>/NNN_nombre.sql`, embebidas con `include_str!`; `MIGRATIONS` enumera versión y nombre y `sql_for(engine)` devuelve el texto. Todas las migraciones que existan al empezar F8 (hoy 001–008; F3, F5 y F6 pueden añadir más antes) existen en ambos motores.
- Disparadores de inmutabilidad de auditoría equivalentes al `RAISE(ABORT)` de SQLite: `BEFORE UPDATE OR DELETE … RAISE EXCEPTION` en PL/pgSQL.
- *Fingerprint* de esquema por motor (introspección normalizada: `PRAGMA table_info`, `information_schema`) comparado con un archivo versionado en CI: detecta deriva entre motores.
- Migraciones de datos (normalización de timestamps legados) idempotentes y en transacción; nunca tocan `audit_events`.

### 4.3 Formato de respaldo

Contrato detallado en [`specs/db-portabilidad.md`](specs/db-portabilidad.md) §3; resumen:

```
cercano-backup-20261110T182000Z.jsonl.gz
  línea 1: {"format":1,"engine":"sqlite","schema_version":8,"created_at":"…","tables":[{"name":"users","rows":12,"sha256":"…"}],
            "attachments":{"included":true,"count":3,"total_bytes":…},"archive_sha256":"…","key_id":"…","signature":"…"}
  línea 2..n: {"table":"users","row":{…}}
```

- Firma sobre el manifiesto + hash de cada tabla; el verificador rechaza antes de leer datos.
- Crear respaldo: `sqlite3 .backup` **no** se usa; se lee por tabla en lotes ordenados por clave y se escribe a `.tmp` con *rename* atómico (patrón de adjuntos de chat).
- Retención por número de copias (30 por defecto), nunca por edad sola, para no borrar el último respaldo bueno.

### 4.4 Restauración

1. Subir el archivo, verificar firma y hashes.
2. Snapshot automático del estado actual (respaldo firmado) antes de tocar nada.
3. Aplicar a un esquema *scratch* (`cercano_restore_<uuid>` en PostgreSQL; archivo temporal en SQLite) y comparar conteos.
4. Intercambio y verificación de cadena con `cercano-audit verify`; si algo falla, se descarta *scratch* y no se tocó producción.
- Requisitos: permiso `db:admin`, reautenticación con contraseña y, si la cuenta tiene 2FA, código TOTP (F4-04), confirmación tipada del nombre del motor, y cero trabajos de build en curso.

### 4.5 Migración asistida

`preflight` (conectividad, destino vacío, versión de esquema, espacio, estimación) → mantenimiento (escrituras `503` + `Retry-After`, lecturas permitidas) → snapshot firmado → copia por lotes de 500 filas con checksum por tabla → verificación (conteos + cadena) → corte (TOML atómico `0600`, `requires_restart: true`) → `db.migration_completed`.

Rollback: el origen queda intacto y bloqueado en solo lectura; `POST /api/db/migration/{id}/rollback` descarta el destino y sale de mantenimiento. Un trabajo interrumpido se detecta por un marcador en `system_info` al arrancar: se informa en la consola y **no** se reanuda solo.

### 4.6 Consola

Nueva pestaña **«Mantenimiento»** (`ActiveTab` + `TabBar` + `MaintenanceView`, visible solo con `db:admin`): estado del motor y del esquema, respaldos (crear, descargar, verificar, borrar), programación y retención, restauración y asistente de migración con progreso por sondeo de 1 s (patrón de `builds`). Permiso nuevo `db:admin`, solo para `admin` (los demás roles no lo reciben). Endpoints bajo `/api/db/*`.

## 5. Tareas

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F8-01 | ADR-011, inventario de SQL y spike de viabilidad MSSQL | — | ControlPlane + Seguridad | Coordinador |
| F8-02 | Crate `db-core`: pool, dialecto, marcadores, timestamps, factoría y `AppState` | F8-01 | ControlPlane | QA |
| F8-03 | Esquema y migraciones por motor, disparadores, fingerprint en CI | F8-02 | ControlPlane | Seguridad |
| F8-04 | Portar consultas de `cercano-api` y `audit-core` a SQL portable | F8-03 | ControlPlane | QA |
| F8-05 | Formato de archivo firmado y verificador | F8-02 | ControlPlane | Seguridad |
| F8-06 | API de respaldo y restauración; programación y retención; auditoría `db.backup_*`/`db.restore_*` | F8-04, F8-05 | ControlPlane | QA |
| F8-07 | Asistente de migración: preflight, mantenimiento, copia, verificación, corte y rollback | F8-06 | ControlPlane | Seguridad |
| F8-08 | Consola: pestaña «Mantenimiento», permiso `db:admin`, confirmaciones y progreso | F8-06, F8-07, F4-06 | Web | QA |
| F8-09 | Matriz de pruebas SQLite/PostgreSQL y pruebas de fallo | F8-04…08 | QA | Coordinador |
| F8-10 | Runbook `docs/guias/respaldos-y-migracion.md`, cierre e informe | F8-09 | Coordinador | Dueño |

### Detalle y criterios de aceptación

**F8-01 ADR-011, inventario y veredicto.**
**Cerrado el 2026-11-10** (pendiente de verificación del Coordinador): ADR-011 ratificado contra el código, inventario completo (142 sentencias, 25 no portables más el DDL) y veredicto sobre SQL Server: **diferido porque `sqlx 0.8` no tiene driver MSSQL**, así que no hubo spike que hacer. Comprobado el reintento del cliente ante `503` (120 s, deduplicado por `nonce`); hbbs/hbbr no emiten auditoría. Evidencia, cifras y correcciones al inventario previsto en [`status/informes/F8-01.md`](status/informes/F8-01.md).
*CA:* cumplido — alternativas descartadas, veredicto con criterio de salida para el caso de retomarlo, D10 y R12 actualizados y estimación revisada (3–4 semanas).

**F8-02 Crate `db-core`.**
Crear `control-plane/db-core` con `Db`, `Dialect`, `sql()`, helpers de tiempo canónicos, factoría de conexión y errores; migrar `AppState` y la inicialización de `main.rs`.
*CA:* la suite actual pasa en SQLite sin cambios de comportamiento; unit test del reescritor con `?` dentro de literales y comentarios; una URL desconocida falla con un error claro al arrancar, no a mitad de una petición.

**F8-03 Esquema y migraciones por motor.**
Extraer las migraciones a archivos por motor; portar los 8 esquemas con sus índices; disparadores de inmutabilidad en PL/pgSQL; `schema_migrations` equivalente; fingerprint versionado. Cada migración se parte en sentencias ejecutables (`sqlx::raw_sql` o una llamada por sentencia): hoy se envían varias en una sola (`db.rs:388`) y PostgreSQL no lo admite preparado.
*CA:* base vacía y base con todas las migraciones existentes migran en ambos motores; `UPDATE`/`DELETE` sobre `audit_events` falla en ambos; el fingerprint coincide entre motores tras migrar; idempotencia probada.

**F8-04 Consultas portables.**
Portar las consultas de `cercano-api` (dispositivos, sesiones, login, admin, builds, chat, alarmas, revocación, auditoría) y de `audit-core` (almacén, checkpoints, retención); timestamps en Rust; *upsert* por dialecto; sin `strftime` ni `datetime('now')`; identidad (`RETURNING`) encapsulada en `db-core`; extracción de JSON de `query_events` (`json_extract`/`COLLATE NOCASE`) encapsulada también (spec §2.7).
*CA:* contrato de pruebas ejecutado contra ambos motores; migración de datos legados normaliza timestamps sin tocar `audit_events`; `cargo test` verde en SQLite y PostgreSQL.

**F8-05 Formato de archivo firmado.**
Implementar escritura/lectura del archivo según [`specs/db-portabilidad.md`](specs/db-portabilidad.md) §3, manifiesto, compresión, firma con `audit_signing_key` y verificador independiente.
*CA:* *round-trip* completo; archivo manipulado (una fila, el manifiesto o el hash) se rechaza con el nombre de la tabla afectada; archivo de `format` más nuevo se rechaza con mensaje claro; ninguna clave privada en el archivo ni en logs.

**F8-06 API de respaldo y restauración.**
Endpoints `/api/db/status`, `/api/db/backups` (POST, GET, DELETE, `{id}/download`, `{id}/verify`), `/api/db/backups/schedule`, `/api/db/restore`; tarea de respaldo periódico (patrón del bucle de checkpoints de `main.rs`); descarga autenticada con `Content-Disposition` y sin *path traversal*; auditoría `db.backup_*` y `db.restore_*`; `docs/specs/api.yaml` actualizado.
*CA:* respaldo creado por API y por programación; descarga solo con `db:admin` y sesión válida; restauración en entorno limpio reproduce conteos y la cadena verifica; firma inválida o destino ocupado abortan sin escribir; falta de espacio deja `.tmp` y error claro; snapshot previo obligatorio antes de restaurar.

**F8-07 Asistente de migración.**
Implementar §4.5: preflight, modo mantenimiento, marcador en `system_info`, copia por lotes con checksums, verificación, corte por TOML atómico y rollback; bloqueo con builds en curso.
*CA:* SQLite→PostgreSQL en el laboratorio sin pérdida (conteos y cadena); rollback probado y auditado; corte responde `requires_restart: true` y el reinicio arranca en el destino; interrupción a mitad de copia no deja producción a medias y el estado se informa en la consola; escrituras durante mantenimiento devuelven `503` con `Retry-After`; ningún evento de auditoría emitido durante el mantenimiento se pierde (reintento o cola verificados en F8-01; si no existen, los añade F8-07).

**F8-08 Consola.**
`MaintenanceView` + pestaña + `ActiveTab`; permiso `db:admin` en `permissions.rs`; formularios de respaldo/restauración/migración con confirmación tipada y reautenticación; progreso por sondeo; textos de riesgo y aviso de claves.
*CA:* un `admin` completa el ciclo; `operator`/`auditor` no ven la pestaña ni obtienen datos por API (403); confirmación incorrecta no ejecuta; el progreso avanza y el error se muestra tras un fallo inyectado; sin regresiones de accesibilidad ni de modo oscuro.

**F8-09 Matriz de pruebas.**
Compose con PostgreSQL; CI por motor con `CERCANO_TEST_DATABASE_URL`; pruebas de fallo: disco lleno, firma inválida, esquema más nuevo, destino no vacío, copia interrumpida, fallo de escritura del TOML, contraseña incorrecta; prueba de restauración hecha por alguien que no escribió el código; repetición en cada motor de los casos de integridad de auditoría de F2 (TC-F2-001…005 y 031) sobre la cadena portada.
*CA:* verde en ambos motores; restauración completa en < 30 min con el runbook; informe con evidencia y hallazgos.

**F8-10 Runbook y cierre.**
`docs/guias/respaldos-y-migracion.md` (redactado el 2026-11-10; se ajusta a lo implementado): respaldo local y fuera del equipo, claves aparte, restauración, migración, rollback, modo mantenimiento y diagnóstico; **mantener** los `TC-F8-*` ya registrados en `PLAN-DE-PRUEBAS.md`, `deploy/README.md` (directorio de respaldos) e informe de cierre.
*CA:* checklist ejecutable por el operador; documentos enlazados desde el roadmap; fase marcada `Hecho` solo con F8-09 en verde.

## 6. Auditoría

Categoría `db` (variante nueva en `audit-core`), sin contenido de datos personales ni secretos. Contrato y campos permitidos en [`specs/db-portabilidad.md`](specs/db-portabilidad.md) §6 y [`specs/audit-events.md`](specs/audit-events.md) §6.18:

`db.backup_created`, `db.backup_verified`, `db.backup_downloaded`, `db.backup_deleted`, `db.restore_started`, `db.restore_completed`, `db.restore_failed`, `db.migration_preflight`, `db.migration_started`, `db.migration_verified`, `db.migration_completed`, `db.migration_failed`, `db.migration_rollback`, `db.reauth_denied`.

El esquema JSON y el catálogo de auditoría ya aceptan la categoría `db`; F8-06/F8-07 añaden los vectores de prueba con hash canónico. Las operaciones de base de datos nunca se pueden desactivar por política, igual que el resto de la auditoría.

## 7. Matriz de pruebas

| Escenario | SQLite | PostgreSQL | SQL Server |
|---|---|---|---|
| Esquema + disparadores | sí | sí | fuera de F8 |
| Suite de API completa | sí | sí | fuera de F8 |
| Respaldo → restauración | sí | sí | fuera de F8 |
| Migración origen→destino | — | destino desde SQLite | fuera de F8 |
| Fallos inyectados | sí | sí | fuera de F8 |

SQL Server quedó fuera en F8-01 (§3): la columna se conserva solo como diseño futuro y la fase cierra con SQLite y PostgreSQL.

## 8. Riesgos y deuda

- **R10 (deriva entre motores).** Mitigado con el fingerprint de esquema y CI por motor; deuda conocida: dos DDL que mantener por migración nueva.
- **R11 (restauración o migración destructiva).** Snapshot firmado previo, *scratch*, verificación y origen intacto como rollback.
- **R12 (SQL Server).** Cerrado en F8-01: no hay driver MSSQL en `sqlx 0.8`; diferido. Retomarlo exige capa `tiberius`, spike y decisión aparte.
- Deuda aceptada: copia por lotes de 500 filas en lugar de `COPY`; si una migración supera ~2 h en el tamaño objetivo, se optimiza con carga masiva del motor destino (`shortcut:` anotado en el código).
- Deuda aceptada: los respaldos se firman pero no se cifran en la aplicación; el runbook obliga a cifrarlos fuera del equipo.

## 9. Estimación

| Tarea | Estimación |
|---|---|
| F8-01 | hecho (3–5 días) |
| F8-02 | 3–4 días |
| F8-03 | 4–6 días |
| F8-04 | 8–10 días |
| F8-05 | 3–4 días |
| F8-06 | 5–7 días |
| F8-07 | 6–8 días |
| F8-08 | 4–5 días |
| F8-09 | 4–6 días |
| F8-10 | 2–3 días |
| **Total** | **3–4 semanas** (SQL Server fuera de alcance) |

SQL Server con `tiberius` no forma parte de F8: queda como trabajo futuro documentado en [`adr/011-portabilidad-bd.md`](adr/011-portabilidad-bd.md) §7, con el spike y la estimación que exige retomarlo.
