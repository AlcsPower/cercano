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
| `002-client-rebranding.patch` | F1-07 | `vendor/client` | Rebranding del cliente desktop y Flutter: nombre visible "Cercano", bundle ID `com.cercano.client`, rutas de config aisladas (`.config/cercano`, `AppData/Roaming/Cercano`), textos de interfaz, pantalla Acerca de con licencia AGPL-3.0 y enlace a repositorio | `Cargo.toml`, `res/*`, `src/*`, `flutter/*`, `vendor/server/libs/hbb_common/*` | 2026-11-05 | Agente-Cliente |
| `003-client-default-endpoints.patch` | F1-08 | `vendor/client` | Configuración por defecto de red apuntando a ID Server `127.0.0.1:21116`, Relay `127.0.0.1:21117`, API Server `http://127.0.0.1:21114`, y latido de telemetría hacia `POST /api/devices/heartbeat` | `src/common.rs`, `src/rendezvous_mediator.rs`, `src/client.rs`, `src/hbbs_http/sync.rs`, `vendor/server/libs/hbb_common/src/config.rs` | 2026-11-05 | Agente-Cliente |

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

### [002-client-rebranding.patch] Tarea F1-07: Rebranding del cliente

- **Archivo:** `patches/002-client-rebranding.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F1-07`
- **Fecha:** `2026-11-05`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Reemplazo integral de identidad de marca en el cliente RustDesk v1.5.1 para evitar conflictos de instalación y configuración con clientes oficiales de upstream. Se aísla el identificador de bundle a `com.cercano.client`, rutas de configuración local (`.config/cercano`, `AppData/Roaming/Cercano`), textos de interfaz a "Cercano", pantalla de "Acerca de" con atribución formal a AGPL-3.0 y enlace a código fuente, integración con iconos corporativos de Cercano, y unificación del crate de configuración compartida `hbb_common`.
- **Archivos modificados:**
  - `vendor/client/Cargo.toml`
  - `vendor/client/flatpak/com.rustdesk.RustDesk.metainfo.xml`
  - `vendor/client/flutter/android/app/build.gradle`
  - `vendor/client/flutter/android/app/src/main/res/values/strings.xml`
  - `vendor/client/flutter/ios/Runner/Info.plist`
  - `vendor/client/flutter/lib/desktop/pages/desktop_setting_page.dart`
  - `vendor/client/flutter/macos/Runner.xcodeproj/project.pbxproj`
  - `vendor/client/flutter/macos/Runner/Info.plist`
  - `vendor/client/flutter/windows/runner/Runner.rc`
  - `vendor/client/flutter/windows/runner/main.cpp`
  - `vendor/client/res/rustdesk.desktop`
  - `vendor/client/res/rustdesk.service`
  - `vendor/client/src/clipboard.rs`
  - `vendor/client/src/common.rs`
  - `vendor/client/src/manual_update.rs`
  - `vendor/client/src/platform/windows.rs`
  - `vendor/server/libs/hbb_common/Cargo.toml`
  - `vendor/server/libs/hbb_common/src/config.rs`
- **Estrategia de actualización (upstream sync):** Revisar claves de bundle en Flutter y macOS/Windows runners al actualizar de Flutter Rust Bridge / upstream tag. Verificar que `hbb_common::config::APP_NAME` se mantenga como el punto central de derivación de directorios locales.

---

### [003-client-default-endpoints.patch] Tarea F1-08: Cliente apuntando a cercano-api

- **Archivo:** `patches/003-client-default-endpoints.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F1-08`
- **Fecha:** `2026-11-05`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Configuración de los endpoints de conexión y telemetría por defecto del cliente para apuntar al entorno soberano local de Cercano:
  - Rendezvous/ID Server: `127.0.0.1:21116`
  - Relay Server: `127.0.0.1:21117`
  - API Server: `http://127.0.0.1:21114`
  - Telemetría / Heartbeat: adaptación de `start_hbbs_sync_async()` para emitir latidos regulares hacia `POST /api/devices/heartbeat` enviando `id`, `uuid`, `os`, `hostname`, `name` y `version`.
- **Archivos modificados:**
  - `vendor/client/src/client.rs`
  - `vendor/client/src/common.rs`
  - `vendor/client/src/hbbs_http/sync.rs`
  - `vendor/client/src/rendezvous_mediator.rs`
  - `vendor/server/libs/hbb_common/src/config.rs`
- **Estrategia de actualización (upstream sync):** Verificar la compatibilidad del formato del payload JSON enviado por `sync.rs` contra la especificación OpenAPI de `cercano-api` (`/api/devices/heartbeat`).

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
