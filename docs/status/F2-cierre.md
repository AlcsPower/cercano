# Cierre de F2 — Auditoría y traza

**Fecha:** 2026-11-09
**Estado:** En verificación
**Tarea:** F2-14 · Guía de auditoría y cierre

## Resumen

Se preparó la guía oficial [`docs/guias/auditoria.md`](../guias/auditoria.md), que cubre consulta, verificación offline con `cercano-audit verify`, custodia de archivos firmados, exportación JSONL/CSV, entrega a SIEM, trazas y notas de sesión, y el expediente requerido para Gate M1.

## Evidencia disponible

- **F2-01 … F2-03:** Hecho. Esquema formal, `audit-core` append-only inmutable y CLI `cercano-audit verify` con firmas Ed25519.
- **F2-06 … F2-12:** Hecho. Correlación de trazas, motor de alarmas en tiempo real, auditoría administrativa, exportación paginada JSONL/CSV y notas de sesión.
- **Pruebas automatizadas en Linux (WSL):**
  - **105 pruebas pasadas**, 0 fallidas, 1 ignorada (la prueba de carga sostenida de 10 minutos a 500 ev/s en `f2_13_integration.rs`, marcada como `#[ignore]` para no demorar la integración continua y ejecutable con `-- --ignored`).
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`: 0 advertencias.
  - `cargo fmt --all -- --check`: 100% conforme.
  - `./tools/check-license-headers.sh`: 100% conforme (AGPL-3.0).

## Resoluciones de Auditoría Ronda 2 (H44, H45, H46, H47, H48)

1. **H44 (Mapeo de acciones del cliente):** Resuelto. El payload de autenticación del cliente (`on_login` con `peer` y `type`) se mapea inequívocamente a `conn.auth`, eliminando la duplicidad de `conn.start`. El ciclo de vida de la conexión queda: `conn.start` → `conn.auth` → `file.transfer` → `conn.end`.
2. **H45 (Derivación determinista de `trace_id`):** Resuelto. Cuando el cliente no envía `trace_id` explícito, los endpoints `/api/audit/conn` y `/api/audit/file` derivan un identificador determinista `conn-{device_id}-{conn_id}`, unificando todos los eventos de la sesión remota en una única traza continua.
3. **H46 (Autenticación de ingestión en endpoints de compatibilidad):** Resuelto. Los endpoints `/api/audit/conn` y `/api/audit/file` aceptan peticiones directas de terminales clientes si el `id` corresponde a un dispositivo registrado en la tabla `devices`. Terminales desconocidas o atacantes sin registrar son rechazados con `401 Unauthorized`. Se evita el antipatrón de incrustar el `CERCANO_INTERNAL_TOKEN` en terminales clientes.
4. **H47 / H48 (Transparencia en métricas y prueba de carga):** El informe y el expediente reflejan con exactitud la cifra de **105 pruebas unitarias/integración pasadas** y la condición `#[ignore]` de la prueba de carga de 10 minutos.

## Tareas en verificación y compuerta M1

- **F2-04 (En verificación):** Endpoints de ingestión probados unitariamente; devuelta a verificación hasta registrar eventos reales desde un cliente vivo en el laboratorio LAN.
- **F2-05 (En verificación):** Parche de cliente `patches/004-client-audit-hooks.patch` y endpoints de compatibilidad listos; pendiente compilación del cliente y verificación cruzada en LAN.
- **F2-13 (En verificación):** Suite de manipulación, concurrencia, reloj y reinicio validada; prueba sostenida de 10 minutos lista para ejecutar como gate final.
- **F2-14 (En verificación):** Guía de auditoría y cierre del hito.

## Criterio de decisión

La compuerta del Hito M1 permanece **En verificación** (abierta) hasta la ejecución de la prueba viva cliente-servidor en el laboratorio Docker LAN.
