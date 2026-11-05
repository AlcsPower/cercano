# Índice de parches sobre upstream (`vendor/`)

Este archivo registra todos los parches aplicados sobre el código base de upstream según las reglas de `AGENTS.md` §5.
Los parches se almacenan en este directorio (`patches/*.patch`) y se aplican mediante `tools/apply-patches`.

## Reglas para parches

1. **Un parche = un propósito** con ID de tarea y justificación.
2. No editar `vendor/` directamente sin crear y registrar el parche correspondiente.
3. Todo parche debe ser idempotente y poder aplicarse en orden numérico/alfabético mediante `tools/apply-patches`.
4. Preferir extensión (nuevos módulos, hooks, flags de configuración) sobre modificación de lógica existente.
5. Cada parche debe contener cabecera con metadatos: autor, fecha, tarea asociada y resumen.

---

## Registro de parches

| Archivo de parche | Tarea | Componente | Descripción | Archivos modificados | Fecha | Autor |
|---|---|---|---|---|---|---|
| `001-server-rebranding.patch` | F1-01 | `vendor/server` | Rebranding mínimo de `hbbs`, `hbbr` y `cercano-server-util` (versión, banners de bienvenida, CLI) preservando protocolo de red y Ed25519 | `src/common.rs`, `src/hbbr.rs`, `src/main.rs`, `src/relay_server.rs`, `src/rendezvous_server.rs`, `src/utils.rs` | 2026-11-05 | Agente-Servidor |

---

### [001-server-rebranding.patch] Tarea F1-01: Rebranding mínimo del servidor

- **Archivo:** `patches/001-server-rebranding.patch`
- **Componente:** `vendor/server`
- **Tarea:** `F1-01`
- **Fecha:** `2026-11-05`
- **Autor/Rol:** `Agente-Servidor`
- **Motivo / Justificación:** Rebranding de marca en binarios de backend para mostrar "Cercano Server (hbbs/hbbr)" junto con la versión upstream base (1.1.9) en flags `--version`, `--help` y logs de arranque. Se mantiene total compatibilidad binaria del protocolo de red (puertos 21115, 21116, 21117, formato protobuf de mensajes y criptografía Ed25519).
- **Archivos modificados:**
  - `vendor/server/src/common.rs`
  - `vendor/server/src/hbbr.rs`
  - `vendor/server/src/main.rs`
  - `vendor/server/src/relay_server.rs`
  - `vendor/server/src/rendezvous_server.rs`
  - `vendor/server/src/utils.rs`
- **Estrategia de actualización (upstream sync):** Verificar que los nombres de los binarios y opciones de línea de comandos en upstream sigan usando `clap v2` (o adaptar a `clap v3/v4` si upstream migra), asegurando que los banners de bienvenida no interfieran con la inicialización de puertos.

---

### Plantilla de registro para nuevos parches

Al añadir un parche, agregar una fila en la tabla superior y documentar la sección detallada abajo:

```markdown
### [NNN-slug.patch] Tarea <ID>: <Título del parche>

- **Archivo:** `patches/<NNN-slug>.patch`
- **Componente:** `vendor/server` | `vendor/client`
- **Tarea:** `<ID>`
- **Fecha:** `<YYYY-MM-DD>`
- **Autor/Rol:** `<Agente>`
- **Motivo / Justificación:** `<Por qué se requiere modificar upstream en lugar de extender>`
- **Archivos modificados:**
  - `<ruta/al/archivo>`
- **Estrategia de actualización (upstream sync):** `<Cómo conciliar este parche cuando se actualice la versión de upstream>`
```
