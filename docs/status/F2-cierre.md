# Cierre de F2 — Auditoría y traza

**Fecha:** 2026-11-06  
**Estado:** En verificación  
**Tarea:** F2-14 · Guía de auditoría y cierre

## Resumen

Se preparó la guía oficial [`docs/guias/auditoria.md`](../guias/auditoria.md), que cubre consulta, verificación offline con `cercano-audit verify`, custodia de archivos firmados, exportación JSONL/CSV, entrega a SIEM, trazas y notas de sesión, y el expediente requerido para Gate M1.

## Evidencia disponible

- F2-03 figura como **Hecho** y documenta la CLI `cercano-audit verify` y exportación determinista JSONL.
- F2-09 figura como **Hecho** y documenta filtros, paginación y exportación autenticada JSONL/CSV; su prueba de integración no pudo enlazar en Windows por falta de `link.exe` (MSVC), según `docs/status/informes/F2-09.md`.
- F2-10 figura como **Hecho**, con Syslog, JSONL y webhook; su informe deja pendientes TLS/rotación y persistencia de cola para la garantía operativa de pérdida cero.
- F2-12 figura como **Hecho** y cubre notas vinculadas a sesiones.

## Pendientes y bloqueadores honestos

- **F2-05 — En verificación:** el parche propaga `trace_id` cuando existe `conn_audit_ref`; falta aplicar, compilar y validar en laboratorio.
- **F2-13 — En verificación:** la suite cubre manipulación, concurrencia, reloj y reapertura; la carga de 10 minutos es opt-in y el crash durante append requiere laboratorio.
- **MSVC/linker:** en este entorno, las pruebas que requieren enlazado Rust en Windows pueden fallar por ausencia de `link.exe`. Deben repetirse en un entorno con MSVC instalado; un fallo de enlace no se interpreta como fallo funcional.
- **Exportación/SIEM:** confirmar en QA la recepción de todos los formatos y la durabilidad ante caída del receptor; la cola documentada por F2-10 es en memoria.

## Criterio de decisión

No se marca F2 como cerrada ni se afirma que Gate M1 esté satisfecho. El estado permanece **En verificación** hasta que QA/Seguridad aporte los casos TC-F2-030…045, la matriz de cobertura al 100 %, la validación de archivos firmados y la revisión de seguridad, y un agente externo valide la guía.

**Siguiente paso:** ejecutar F2-05 y F2-13, repetir las pruebas bloqueadas por MSVC y anexar resultados reproducibles al expediente.
