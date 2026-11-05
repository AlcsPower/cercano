# Cómo contribuir a Cercano

Cercano se desarrolla con un equipo mixto de personas y agentes coordinados. Todas las reglas están en **[`AGENTS.md`](AGENTS.md)**; este archivo es el resumen para quien llega por primera vez.

## Antes de empezar

1. Lee [`docs/ROADMAP.md`](docs/ROADMAP.md) y [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md).
2. Busca tu tarea en [`docs/status/TAREAS.md`](docs/status/TAREAS.md) (la lista completa con dependencias está en los `docs/PLAN-*.md`).
3. Comprueba que sus dependencias estén en `Hecho` y que no haya un bloqueo en [`docs/status/BLOCKERS.md`](docs/status/BLOCKERS.md).

## Flujo de trabajo

- Rama por tarea: `feat/<ID>-slug`, `fix/<ID>-slug` o `docs/<ID>-slug` (por ejemplo `feat/F1-03-esqueleto-api`).
- Commits en formato Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Un PR por tarea, con la plantilla del repositorio. Debe indicar el ID de la tarea, las pruebas ejecutadas y cualquier cambio en `vendor/`.
- Verifica y fusiona **otra persona o agente**, nunca quien implementó.

## Reglas que no se negocian

- **Licencia:** todo el código nuevo es AGPL-3.0. Las dependencias nuevas deben ser compatibles.
- **Clean-room:** no uses, descargues ni inspecciones binarios de RustDesk Server Pro ni código de procedencia dudosa. Solo documentación pública y código abierto.
- **Código heredado:** no se edita `vendor/` directamente; los cambios van como parches en `patches/` y se registran en `patches/INDEX.md`.
- **Secretos:** nunca en el repositorio, en logs ni en artefactos.
- **Marca:** sin nombre ni logo de RustDesk; el logo de Cercano se usa según [`branding/README.md`](branding/README.md).

## Calidad mínima para cerrar una tarea

Criterios de aceptación cumplidos con evidencia, `cargo fmt`, `cargo clippy -D warnings`, `cargo test` y `cargo deny check` en verde (para código Rust), documentación actualizada y sin secretos. El detalle está en `AGENTS.md`, sección 4.

## Seguridad

Para reportar una vulnerabilidad, sigue [`SECURITY.md`](SECURITY.md). No abras issues públicos con detalles.
