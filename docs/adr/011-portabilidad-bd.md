# ADR-011 — Portabilidad de base de datos y respaldos gestionados

- **Estado:** Propuesto (lo ratifica F8-01 con el veredicto del spike de SQL Server)
- **Fecha:** 2026-11-10
- **Fase:** F8 (extra post-v1)
- **Decisores:** Dueño del producto, Coordinador, Agente-ControlPlane, Agente-Seguridad
- **Relacionados:** [`docs/specs/db-portabilidad.md`](../specs/db-portabilidad.md), [`docs/PLAN-F8-PORTABILIDAD.md`](../PLAN-F8-PORTABILIDAD.md), [`docs/guias/respaldos-y-migracion.md`](../guias/respaldos-y-migracion.md), [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md), y `ROADMAP.md` §7 (D3, D10, D11)

## 1. Contexto

Hoy todo el control plane vive en **un archivo SQLite** (`cercano.db`, WAL). Es la decisión de ADR-003 y funciona para el despliegue objetivo (LAN, un nodo, cientos de equipos), pero deja tres huecos:

1. **Respaldo.** El único procedimiento documentado es un `tar` manual de adjuntos de chat ([`guias/chat.md`](../guias/chat.md) §4.2) que ni siquiera copia la base de datos. Copiar `cercano.db` en caliente produce una copia inconsistente porque el WAL va aparte; restaurar nunca se ha probado.
2. **Migración.** «PostgreSQL opcional» (ADR-003) no existe en el código: `sqlx` solo compila `sqlite`, las 126 consultas de `cercano-api` y las 16 de `audit-core` usan sintaxis SQLite, y las 8 migraciones son DDL SQLite en constantes de Rust. Migrar hoy es un proyecto, no una operación.
3. **Requisitos del cliente.** Organizaciones con DBA propio piden PostgreSQL o SQL Server, respaldo desde la interfaz y una ventana de migración con rollback. Sin eso, Cercano queda fuera de esas licitaciones.

Restricciones que condicionan el diseño:

- `audit_events.ts` está **dentro del hash** de cada evento: su formato no puede cambiar al portar el motor, o se invalida toda la cadena existente.
- La inmutabilidad de auditoría depende de disparadores `RAISE(ABORT)` propios de SQLite.
- El servidor es un contenedor sin `pg_dump` ni `mssql-tools`, y no se quiere añadir dependencias de sistema.

## 2. Decisión

1. **Motores.** SQLite sigue siendo el motor de instalación por defecto. **PostgreSQL** pasa a ser un motor soportado de primera clase. **SQL Server** se soporta si F8-01 valida su driver; si no, se implementa con `tiberius` bajo la misma interfaz o se difiere. La fase no se bloquea por SQL Server.
2. **Una sola capa de acceso** (`control-plane/db-core`): enum de pool (`Sqlite`/`Pg`/`Mssql`), `Dialect` y reescritura de marcadores (`?` → `$n` o `@pN`, omitiendo literales y comentarios). **Sin ORM.** El SQL se escribe una vez; solo cambian DDL, plantilla de *upsert* y disparadores.
3. **Los timestamps se generan en Rust** (`%Y-%m-%dT%H:%M:%S%.3fZ`), no con `datetime('now')` ni `CURRENT_TIMESTAMP`. Se eliminan 36 usos de `datetime('now')` y 4 de `strftime`. **`audit_events.ts` no se reescribe.**
4. **Booleanos como entero pequeño** (`INTEGER`/`SMALLINT`/`BIT` con `0`/`1`): un solo camino de lectura y escritura para los tres motores.
5. **Un solo formato de archivo firmado** sirve para respaldar, restaurar y migrar: manifiesto + una línea JSON por fila, gzip, SHA-256 por tabla y firma Ed25519 con `audit_signing_key`. Así la migración no necesita un mecanismo aparte ni binarios externos.
6. **El respaldo se opera desde la consola** (crear, verificar, descargar, borrar, programar, restaurar) con permiso `db:admin`, reautenticación y confirmación tipada. Retención por número de copias, escritura atómica y descarga autenticada.
7. **La restauración es verificada y reversible**: firma y hashes antes de leer, snapshot firmado del estado actual, aplicación en un esquema *scratch*, comparación de conteos y verificación de la cadena, y solo entonces el intercambio.
8. **La migración es asistida, con corte**: preflight, modo mantenimiento, copia por lotes con checksums, verificación, corte escribiendo `database_url` en el TOML (atómico, `0600`) y `requires_restart: true`. El origen no se toca y es el rollback.
9. **El archivo no contiene material de claves** (`id_ed25519`, `audit_signing_key`): se respaldan con el procedimiento aparte de [`guias/rotacion-claves.md`](../guias/rotacion-claves.md). La consola y el runbook lo advierten.
10. **Auditoría de la operación** con categoría nueva `db` (`db.backup_*`, `db.restore_*`, `db.migration_*`), sin contenido de datos ni secretos.
11. **No objetivos:** alta disponibilidad, réplicas, varios nodos de API, migración sin corte, cifrado de la base o del respaldo dentro de la aplicación.

## 3. Consecuencias

**Positivas**

- Un cliente con PostgreSQL o SQL Server puede adoptar Cercano sin renunciar a su base corporativa, con una ventana de migración medida y reversible.
- El respaldo deja de ser un procedimiento que nadie ejecutó: se crea, se verifica y se restaura desde la consola, y la restauración se prueba por alguien distinto de quien la escribió.
- Un solo formato reduce el código: respaldo, restauración y migración comparten escritura, verificación y transporte.
- La cadena de auditoría sobrevive al cambio de motor porque su formato de tiempo no cambia.

**Negativas y riesgos**

- **Tres esquemas que mantener.** Cada migración nueva se escribe en tres dialectos; se mitiga con *fingerprint* por motor y CI con los motores en cada PR que toque SQL (R10).
- **Superficie de error nueva y destructiva.** Restaurar o migrar puede perder datos; se mitiga con snapshot previo, *scratch*, verificación, confirmación tipada y reautenticación (R11).
- **Dependencia de un driver joven.** El driver MSSQL de `sqlx 0.8` puede no estar a la altura; el spike F8-01 decide y `tiberius` queda como salida (R12).
- **Deriva funcional.** Una consulta puede comportarse distinto por motor (colaciones, orden de `NULL`, tipos); la matriz de pruebas de F8-09 debe correr el contrato completo en cada motor, no solo el esquema.
- **Coste operativo de SQL Server** para el cliente (licencia y administración), ajeno a la licencia AGPL de Cercano.

## 4. Alternativas consideradas

| Alternativa | Por qué se descarta |
|---|---|
| Quedarse solo con SQLite y documentar `pgloader`/`pg_dump` | No da respaldo desde la consola, ni verificación, ni rollback; exige parar el servicio y un DBA; el respaldo sigue sin probarse. |
| ORM (Diesel/SeaORM) que abstraiga el motor | Reescribe 142 consultas y añade un tercer lenguaje de consulta; el SQL actual es explícito y probado. |
| `sqlx::Any` para conmutar en tiempo de ejecución | No cubre SQL Server y borra el tipado; los errores aparecen en ejecución. |
| Copia del archivo SQLite como respaldo | Inconsistente con WAL activo; no sirve cuando el origen es PostgreSQL o SQL Server. |
| Volcados nativos (`pg_dump`, `BACKUP DATABASE`) desde la API | Añade binarios al contenedor, tres rutas distintas y ningún formato común para migrar entre motores. |
| Cifrar los respaldos dentro de la aplicación | Añade gestión de claves y una dependencia criptográfica; el operador ya cifra al sacarlos del equipo y aquí el archivo está junto a la BD que protege. |
| Réplicas o migración sin corte en F8 | Convierte una fase de portabilidad en un proyecto de HA; queda como trabajo posterior sobre PostgreSQL. |

## 5. Referencias

- Contrato técnico: [`docs/specs/db-portabilidad.md`](../specs/db-portabilidad.md).
- Plan de fase con tareas y criterios: [`docs/PLAN-F8-PORTABILIDAD.md`](../PLAN-F8-PORTABILIDAD.md).
- Operación: [`docs/guias/respaldos-y-migracion.md`](../guias/respaldos-y-migracion.md).
- Auditoría: [`docs/specs/audit-events.md`](../specs/audit-events.md) §6.18.
