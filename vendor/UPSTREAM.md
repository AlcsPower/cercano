# Registro de Upstream (`vendor/`)

Este documento registra los componentes de software de código abierto importados en `vendor/` que sirven como base para Cercano, de acuerdo con `AGENTS.md` §5, `ARQUITECTURA.md` §2 y el plan `PLAN-F0-F1.md` (tarea `F0-02`).

## Reglas de gestión

1. **Inmutabilidad directa:** El código contenido en `vendor/` no se modifica directamente. Cualquier cambio, adaptación o corrección debe aplicarse a través de parches registrados en `patches/INDEX.md` y gestionados con `tools/apply-patches`.
2. **Licencia:** Todo el código importado está licenciado bajo **GNU Affero General Public License v3.0 (AGPL-3.0)**.
3. **Limpieza del repositorio:** El código de upstream se importa sin los historiales `.git` para mantener el monorepo liviano y ágil.

---

## Componentes importados

### 1. Servidor (`vendor/server`)

- **Proyecto:** RustDesk Server (`hbbs`, `hbbr` y utilidades)
- **Repositorio origen:** `https://github.com/rustdesk/rustdesk-server.git`
- **Etiqueta (tag):** `1.1.9`
- **Hash de commit:** `d81010224d24f8be57c42b772e6e7b5c77463661`
- **Fecha del commit:** `2023-12-05 17:22:40 +0800`
- **Licencia:** GNU Affero General Public License v3.0 (AGPL-3.0)
- **Ruta local:** `vendor/server/`
- **Propósito en Cercano:** Proporcionar la base de servidor de señalización / rendezvous (`hbbs`) y relay (`hbbr`) para la conexión entre agentes y clientes.

### 2. Cliente (`vendor/client`)

- **Proyecto:** RustDesk Client (Flutter + Rust backend)
- **Repositorio origen:** `https://github.com/rustdesk/rustdesk.git`
- **Etiqueta (tag):** `1.5.1`
- **Hash de commit:** `23e5bb471a040d62f0a6ad52591fb30784265b73`
- **Fecha del commit:** `2026-11-01 13:50:20 +0800`
- **Licencia:** GNU Affero General Public License v3.0 (AGPL-3.0)
- **Ruta local:** `vendor/client/`
- **Propósito en Cercano:** Proporcionar la base para el cliente multiplataforma de escritorio, que será rebrandeado y conectado a `cercano-api`.

---

## Procedimiento para sincronización / actualización de Upstream

Cuando se decida actualizar la base de upstream (ej. tras un nuevo release estable):

1. Verificar que la nueva etiqueta mantenga la compatibilidad con la licencia AGPL-3.0.
2. Descargar la nueva etiqueta en un directorio temporal.
3. Actualizar los contenidos en `vendor/<componente>`.
4. Ejecutar `tools/apply-patches` para verificar si los parches existentes en `patches/` aplican limpiamente o requieren rebase.
5. Actualizar la tabla de este documento con el nuevo commit, etiqueta y fecha.
6. Ejecutar la suite de pruebas y generar el informe correspondiente.
