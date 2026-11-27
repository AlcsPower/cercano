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
| `004-client-audit-hooks.patch` | F2-05 | `vendor/client` | Propaga `trace_id`, par autenticado y tipo en `conn.end`, añade volumen y SHA-256 (tope 512 MiB al emitir) y autentica emisión con `X-Cercano-Client-Token` solo sobre HTTPS | `src/server/connection.rs` | 2026-11-09 | Agente-Cliente |
| `005-client-signed-profile.patch` | F3-02 | `vendor/client` | Localización, verificación de firma Ed25519 y aplicación de perfil de cliente firmado (`cercano-profile.signed.json`), comprobación de caducidad y restricciones de rol | `src/cercano_profile.rs`, `src/common.rs`, `src/lib.rs` | 2026-11-09 | Agente-Cliente |
| `006-client-roles-modes.patch` | F3-14, F3-15 | `vendor/client` | Modos soporte y técnico: helpers de rol, bloqueo de salida y libreta en soporte, control de salida y sesión en técnico, protección de ajustes de red y elevación estructurada | `src/cercano_profile.rs`, `src/client.rs`, `src/flutter.rs`, `src/ui_interface.rs` | 2026-11-10 | Agente-Cliente |
| `007-client-elevation.patch` | F3-16 | `vendor/client` | Flujo de elevación supervisada con credenciales: consentimiento obligatorio, `SecureElevationCredential` con zeroize, límite de 3 fallos y un solo uso | `src/cercano_profile.rs`, `src/platform/windows.rs`, `src/server/portable_service.rs` | 2026-11-10 | Agente-Cliente |
| `008-client-support-chat.patch` | F4.5-10 | `vendor/client` | Módulo `cercano_chat.rs`, autenticación Ed25519 con reto/firma, REST, SSE con feature stream, reconexión, toast Windows y FFI Flutter | `Cargo.toml`, `src/cercano_chat.rs`, `src/lib.rs`, `src/flutter_ffi.rs` | 2026-11-16 | Agente-Cliente |
| `009-client-flutter-chat.patch` | F4.5-11 | `vendor/client` | Interfaz Flutter de Cercano Chat, modelo, vista de bienvenida y onboarding (nombre/apellido), hilo de mensajes, composer, adjuntos, botón en panel soporte e i18n | `flutter/lib/cercano_chat/*`, `flutter/lib/desktop/pages/*`, `flutter/test/*`, `src/lang/*` | 2026-11-16 | Agente-Cliente |
| `010-client-remote-escalation.patch` | F4.5-12 | `vendor/client` | Soporte del esquema `cercano://connect?device=&trace=` en Flutter y CLI, y propagación de `trace` hacia `conn_audit_ref` | `flutter/lib/common.dart`, `src/core_main.rs`, `src/rendezvous_mediator.rs`, `src/server.rs` | 2026-11-16 | Agente-Cliente |
| `011-client-policy-chat.patch` | F4.5-13 | `vendor/client` | Soporte de `policy.chat` (`enabled`, `allow_attachments`, `allow_remote_escalation`) y helpers de verificación | `src/cercano_profile.rs` | 2026-11-16 | Agente-Cliente |
| `012-client-effective-policy.patch` | F5-06 | `vendor/client` | Descarga, cacheo acotado y aplicación de política efectiva central, degradación offline fail-closed (TC-F5-024) y protección contra adulteración local (TC-F5-025) | `src/cercano_profile.rs` | 2026-11-16 | Agente-Cliente |
| `015-client-reproducible-build-date.patch` | F3-03 | `vendor/client` | `BUILD_DATE` toma `SOURCE_DATE_EPOCH` (UTC) si está definido, en lugar de la hora local de compilación (TC-F3-021) | `libs/hbb_common/src/lib.rs` | 2026-11-25 | Agente-Builder |
| `016-client-wpwd-mut.patch` | F3-16 | `vendor/client` | `wpwd` mutable en `create_process_with_logon` para que compile el borrado seguro de 007 (E0596 en el build de Windows) | `src/platform/windows.rs` | 2026-11-25 | Agente-Cliente |
| `017-client-chat-dart-compile.patch` | F3-17 | `vendor/client` | El chat Flutter (009) compila en Windows: import de `bind`, `Colors.green` en lugar de `Colors.emerald`, errata `CrossAxisAlignment` | `flutter/lib/cercano_chat/cercano_chat_model.dart`, `flutter/lib/cercano_chat/cercano_chat_page.dart` | 2026-11-26 | Agente-Builder |

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
- **Corrección (2026-11-27, F4.5-10):** se quitó el hunk que apuntaba `hbb_common` a `../server/libs/hbb_common` en `vendor/client/Cargo.toml`; F3-19a (71aff6f) lo devolvió a `libs/hbb_common` en `vendor/` y el parche ya no se podía revertir.

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
- **Corrección (2026-11-27, F4.5-10):** se quitó una línea de contexto sobrante del hunk de `rendezvous_mediator.rs` que no entraba en su conteo.

---

### [004-client-audit-hooks.patch] Tarea F2-05: Hooks de auditoría del cliente

- **Archivo:** `patches/004-client-audit-hooks.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F2-05`
- **Fecha:** `2026-11-09`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** El cliente ya dispone de la ruta de auditoría y de `conn_audit_ref`; el parche propaga ese identificador como `trace_id`, propaga el par remoto autenticado y el tipo de conexión en el fin de sesión (`conn.end`), añade volumen y SHA-256 (tope de 512 MiB calculado sobre el archivo local al emitir, no sobre los bytes en tránsito) a las transferencias de un único fichero, y envía el token dedicado de cliente (`api-token`) en la cabecera `X-Cercano-Client-Token` exclusivamente cuando la URL usa HTTPS (descartándolo con advertencia en HTTP plano para prevenir fugas de secretos).
- **Archivos modificados:**
  - `src/server/connection.rs`
- **Estrategia de actualización (upstream sync):** Reaplicar sobre `post_conn_audit`, `post_file_audit`, `post_audit_async` y el cierre de conexión; si upstream cambia sus DTOs de auditoría, conservar `trace_id`, `bytes`, `sha256` y el `type` del cierre, y validar contra el endpoint de ingestión vigente.

---

### [005-client-signed-profile.patch] Tarea F3-02: Lectura y verificación de perfil firmado en el cliente

- **Archivo:** `patches/005-client-signed-profile.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F3-02`
- **Fecha:** `2026-11-09`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Implementa el módulo `cercano_profile` en el cliente para cargar y verificar criptográficamente el perfil firmado (`cercano-profile.signed.json` o ruta `CERCANO_PROFILE_PATH`) antes de iniciar. Utiliza Ed25519 sobre JSON canónico, valida la caducidad (`expires_at`), aplica los invariantes de rol (`soporte` sin conexiones salientes, `tecnico` sin acceso desatendido), y aplica la configuración en `config::OVERWRITE_SETTINGS` y `config::APP_NAME`. Si la firma es inválida, falta la firma, el rol fue alterado o el perfil ha caducado, la carga es rechazada de inmediato.
- **Archivos modificados:**
  - `src/cercano_profile.rs`
  - `src/common.rs`
  - `src/lib.rs`
- **Estrategia de actualización (upstream sync):** El módulo `cercano_profile` es puramente aditivo; se engancha en `load_custom_client()` en `src/common.rs`. Al actualizar upstream, verificar que `config::OVERWRITE_SETTINGS` y `config::APP_NAME` continúen existiendo en `hbb_common`.
- **Corrección (2026-11-27, F4.5-10):** la cabecera de `cercano_profile.rs` declaraba 469 líneas en vez de 470; además el parche repetía íntegra la sección de `src/server/connection.rs` de la 004 (hooks de auditoría), que se eliminó porque no se aplicaba tras la 004.

---

### [006-client-roles-modes.patch] Tareas F3-14 y F3-15: Modos de cliente Soporte y Técnico

- **Archivo:** `patches/006-client-roles-modes.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F3-14`, `F3-15`
- **Fecha:** `2026-11-10`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Implementa el comportamiento, restricciones y capacidades diferenciadas en el cliente Cercano conforme a la Matriz de la Sección 1 de `PLAN-F3-GENERADOR.md` y las directrices arquitectónicas de `ADR-008`:
  - **Rol Soporte (`role: "soporte"`) [F3-14]:**
    - Bloqueo estricto e incondicional de conexiones salientes (`validate_outgoing_connection`) con mensaje descriptivo ("Cercano Soporte está configurado exclusivamente para recibir asistencia técnica").
    - Bloqueo de libreta de direcciones y lista de dispositivos remotos (`is_address_book_enabled() -> false`).
    - Bloqueo e inmutabilidad de ajustes de servidor, clave y red (`is_network_settings_locked() -> true` y filtros en `ui_interface.rs`).
    - Consentimiento obligatorio de la persona usuaria para cada sesión entrante, salvo que el perfil firmado habilite explícitamente `unattended_access`.
    - Indicador permanente de sesión activa y capacidad de terminación inmediata por el usuario final.
    - Notificación y diálogo estructurado de elevación entrante (`ElevationRequestNotification`: motivo, solicitante, ticket y timestamp), impidiendo que el cliente soporte emita solicitudes de elevación.
  - **Rol Técnico (`role: "tecnico"`) [F3-15]:**
    - Control de conexiones salientes exigiendo sesión técnica autenticada en `cercano-api` (`can_initiate_outgoing_connections() -> bool`).
    - Libreta y dispositivos restringidos exclusivamente a personal técnico con sesión iniciada.
    - Manejo de sesión técnica (`set_technician_session`, `get_technician_session_token`) y cierre de sesión seguro (`clear_technician_session`) que limpia completamente el estado local, tokens y credenciales en memoria al hacer logout.
    - Ajustes de red y servidor bloqueados (fijados por el perfil preconfigurado).
    - Emisión de solicitudes de elevación condicionada al permiso `elev:use`.
- **Archivos modificados:**
  - `src/cercano_profile.rs`
  - `src/client.rs`
  - `src/flutter.rs`
  - `src/ui_interface.rs`
- **Estrategia de actualización (upstream sync):** Las verificaciones se sitúan en puntos de entrada clave (`Client::start`, `session_start_`, `is_option_fixed`, `try_set_options`). Al actualizar upstream, verificar que `Client::start` y `try_set_options` mantengan su firma o adaptar el hook de validación.

---

### [007-client-elevation.patch] Tarea F3-16: Spike S6 y elevación con credenciales

- **Archivo:** `patches/007-client-elevation.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F3-16`
- **Fecha:** `2026-11-10`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Implementa el flujo integral de elevación administrativa supervisada en Windows (Spike S6, ADR-009):
  - **Consentimiento obligatorio de la persona usuaria:** En `src/cercano_profile.rs`, las credenciales de elevación no son aceptadas ni procesadas a menos que el usuario final haya aprobado explícitamente la solicitud (`ElevationConsentResponse::Approved`). Si el usuario rechaza (`Denied`), el flujo se aborta de inmediato sin transmitir nada.
  - **Estructura de credenciales segura (`SecureElevationCredential`):** Encapsula usuario, dominio y contraseña con borrado seguro de memoria RAM (`zeroize` volátil) ejecutado inmediatamente tras su uso y de forma determinista en `Drop`. Implementa `Debug` y `Display` con redacción permanente (`[REDACTED]`) para evitar fugas en logs o volcados.
  - **Soporte universal de cuentas:** Análisis sintáctico para cuentas locales (`.\Admin`, `Admin`) y cuentas de dominio Active Directory (`CORP\admin`, `admin@corp.lan`).
  - **Control de intentos y prevención de bloqueos (`ElevationSessionTracker`):** Límite estricto de máximo 3 intentos fallidos consecutivos por sesión antes del bloqueo temporal (`MAX_FAILED_ELEVATION_ATTEMPTS = 3`), protegiendo cuentas de dominio contra directivas de bloqueo de Active Directory.
  - **Mínimo privilegio y caducidad:** Consentimiento de un solo uso que expira de inmediato tras ser consumido y caduca a los 60 segundos si no se ejecuta.
  - **Borrado seguro de buffers de Windows:** En `src/platform/windows.rs` (`create_process_with_logon`) y `src/server/portable_service.rs` (`start_portable_service`), los vectores UTF-16 (`wpwd`) y cadenas UTF-8 de contraseñas son sobreescritos con ceros en memoria volátil inmediatamente tras la invocación a las APIs de Windows.
- **Archivos modificados:**
  - `src/cercano_profile.rs`
  - `src/platform/windows.rs`
  - `src/server/portable_service.rs`
- **Estrategia de actualización (upstream sync):** Los componentes de elevación residen principalmente en `cercano_profile.rs`. En `platform/windows.rs` y `server/portable_service.rs`, el zeroize se aplica directamente sobre los buffers locales tras la llamada a `CreateProcessWithLogonW`. Al sincronizar con upstream, comprobar que `create_process_with_logon` mantenga la firma y aplicar la limpieza volátil sobre cualquier buffer auxiliar de contraseña.

---

### [008-client-support-chat.patch] Tarea F4.5-10: Módulo Rust del cliente Cercano Chat

- **Archivo:** `patches/008-client-support-chat.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F4.5-10`
- **Fecha:** `2026-11-16`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Implementa el soporte nativo de Cercano Chat en el cliente de escritorio:
  - **Módulo `cercano_chat.rs`:** Gestión de identidad de dispositivo fijada (`Config::get_id`, `Config::get_key_pair`), registro automático ante `cercano-api`, flujo criptográfico reto/firma con Ed25519 sobre 32 bytes de nonce (`POST /api/chat/auth/challenge` y `verify`).
  - **Manejo de tokens en memoria:** Los tokens de sesión de chat (`cercano_chat_...`) residen estrictamente en memoria volátil (`RwLock<Option<String>>`), nunca en disco ni volcados en trazas de logs.
  - **Regla estricta de TLS:** Comprobación estricta de endpoints HTTPS; rechazo incondicional de protocolos en texto claro (`http://`).
  - **Cliente REST y SSE en tiempo real:** Comunicación REST (`conversations`, `messages`, `attachments`, `branding`, `read`, `close`) y stream continuo de eventos Server-Sent Events (`/api/chat/events`) con bucle de reconexión y espera exponencial (1, 2, 5, 30 s).
  - **Notificaciones de escritorio:** Notificación tipo Toast nativa en Windows (`tauri-winrt-notification`) ante eventos de mensajes nuevos. Garantía estricta de privacidad: no contiene cuerpos de mensajes ni nombres de contactos.
  - **Dependencias controladas:** Activación de la característica `"stream"` en `reqwest 0.12` en `vendor/client/Cargo.toml`; cero crates externas adicionales añadidas.
  - **Puente FFI:** Funciones exportadas en `src/flutter_ffi.rs` para enlazar directamente con la interfaz Flutter multi-ventana en F4.5-11.
- **Archivos modificados:**
  - `Cargo.toml`
  - `src/cercano_chat.rs`
  - `src/lib.rs`
  - `src/flutter_ffi.rs`
- **Estrategia de actualización (upstream sync):** La lógica de chat está completamente encapsulada en `src/cercano_chat.rs`. En `src/lib.rs` y `src/flutter_ffi.rs` solo se añaden declaraciones públicas que no colisionan con llamadas existentes de RustDesk.
- **Corrección (2026-11-27, F4.5-10):** la cabecera de `cercano_chat.rs` declaraba 654 líneas en vez de 652 y `git apply` rechazaba el parche como corrupto; el contenido ya coincidía con `vendor/`.

---

### [009-client-flutter-chat.patch] Tarea F4.5-11: Interfaz Flutter de Cercano Chat

- **Archivo:** `patches/009-client-flutter-chat.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F4.5-11`
- **Fecha:** `2026-11-16`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Implementa la interfaz visual completa de Cercano Chat en Flutter:
  - **Módulo `flutter/lib/cercano_chat/`:** Modelo de datos reactivo con Provider (`cercano_chat_model.dart`), página principal con diseño especificado en `docs/specs/chat.md` §14 (`cercano_chat_page.dart`), y puente FFI (`cercano_chat_ffi_bridge.dart`).
  - **Formulario inicial de contacto:** Obligatoriedad de Nombre y Apellido la primera vez; almacenamiento persistente en opciones locales (`chat-contact-first-name`, `chat-contact-last-name`) sin transferir a telemetría ni logs.
  - **Hilo de conversación multietapa:** Soporta estados bienvenida, en cola, activa, cerrada y sin conexión. Burbujas diferenciadas por tipo de remitente con color de acento corporativo, doble check de leído según `other_last_read_at`, previsualización de imágenes y tarjetas para PDF.
  - **Acceso en panel de Soporte:** Botón «Chat de soporte» en `desktop_home_page.dart` (modo entrante/soporte) y apertura como pestaña dedicada en `desktop_tab_page.dart`.
  - **Internacionalización:** Claves añadidas a `src/lang/es.rs` y `template.rs`.
  - **Pruebas de modelo:** Suite de pruebas en `flutter/test/cercano_chat_model_test.dart`.
- **Archivos modificados:**
  - `flutter/lib/cercano_chat/cercano_chat_ffi_bridge.dart`
  - `flutter/lib/cercano_chat/cercano_chat_model.dart`
  - `flutter/lib/cercano_chat/cercano_chat_page.dart`
  - `flutter/lib/desktop/pages/desktop_home_page.dart`
  - `flutter/lib/desktop/pages/desktop_tab_page.dart`
  - `flutter/test/cercano_chat_model_test.dart`
  - `src/lang/es.rs`
  - `src/lang/template.rs`
- **Estrategia de actualización (upstream sync):** La funcionalidad reside casi en su totalidad dentro del directorio aislado `lib/cercano_chat/`. En `desktop_home_page.dart` y `desktop_tab_page.dart` solo se insertan widgets autocontenidos.

---

### [010-client-remote-escalation.patch] Tarea F4.5-12: Escalado a sesión remota `cercano://` y propagación de traza

- **Archivo:** `patches/010-client-remote-escalation.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F4.5-12`
- **Fecha:** `2026-11-16`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Implementa el escalado a sesión remota desde la consola de chat hacia el cliente técnico:
  - **Mapeo de esquema URI:** Añade soporte para el formato `cercano://connect?device=<device_id>&trace=<trace_id>` en `urlLinkToCmdArgs` de `common.dart`, extrayendo el ID de dispositivo tanto del path como de query params, así como el identificador de correlación `trace`.
  - **Manejo en CLI:** Permite flags `--trace` y `--trace_id` en `core_main_invoke_new_connection` de `core_main.rs`, alimentando la variable de entorno de sesión `CERCANO_CONN_AUDIT_REF`.
  - **Inyección en auditoría de conexión:** Actualiza `ConnectionMeta::default()` en `server.rs` y `connection_meta` en `rendezvous_mediator.rs` para asignar el `conn_audit_ref` en el `ControlledContext` de la sesión cuando `CERCANO_CONN_AUDIT_REF` está presente. Con ello, todos los eventos de auditoría remota (`conn.new`, `conn.end`, etc.) heredan el `trace_id` de la conversación para correlación en `cercano-audit`.
- **Archivos modificados:**
  - `flutter/lib/common.dart`
  - `src/core_main.rs`
  - `src/rendezvous_mediator.rs`
  - `src/server.rs`
- **Estrategia de actualización (upstream sync):** Modificaciones mínimas y quirúrgicas en los puntos de entrada de unilinks/CLI y en la construcción del contexto de conexión. En futuras versiones de upstream, verificar únicamente que los argumentos de línea de comandos en `core_main.rs` y `common.dart` no colisionen.

---

### [011-client-policy-chat.patch] Tarea F4.5-13: Soporte de policy.chat y verificaciones en cliente

- **Archivo:** `patches/011-client-policy-chat.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F4.5-13`
- **Fecha:** `2026-11-16`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Incorpora la deserialización y evaluación de la subsección `policy.chat` del perfil firmado de Cercano en el cliente (`src/cercano_profile.rs`):
  - Añade `ChatPolicyDto` (`enabled`, `allow_attachments`, `allow_remote_escalation`) con defaults seguros (`allow_attachments: true`, `allow_remote_escalation: true`).
  - Aplica la invariante de rol: si `chat.enabled` se omite, los perfiles de soporte lo habilitan por defecto (`true`) y los técnicos lo deshabilitan (`false`).
  - Expone los helpers públicos `is_chat_enabled()`, `is_chat_allow_attachments()`, y `is_chat_allow_remote_escalation()`.
- **Archivos modificados:**
  - `src/cercano_profile.rs`
- **Estrategia de actualización (upstream sync):** Modificación contenida exclusivamente en el módulo `cercano_profile.rs`, independiente de la lógica central de upstream.

---

### [012-client-effective-policy.patch] Tarea F5-06: Descarga, cacheo y aplicación segura de estrategias

- **Archivo:** `patches/012-client-effective-policy.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F5-06`
- **Fecha:** `2026-11-16`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** Implementa en `vendor/client/src/cercano_profile.rs` el modelo de cliente para consumir políticas centrales de `/api/policies/effective`:
  - `CachedEffectivePolicy`: almacena la política resuelta con `issued_at`, `expires_at` y `cache_ttl_seconds`.
  - `update_cached_policy`: valida la vigencia temporal y acota los permisos recibidos frente al perfil firmado P0 (regla 5 de `docs/specs/identidad.md`).
  - `evaluate_policy_status`: evalúa si la copia en caché está vigente (`Valid` / `CachedValid`) o caducada. Si la red no está disponible y la caché expira, conmuta atómicamente a `ExpiredFailClosed`.
  - `can_accept_incoming_connection` y `can_accept_outgoing_connection`: bloquean nuevas conexiones si la política expiró sin conectividad central (comportamiento *fail-closed* conforme a TC-F5-024).
  - Inmunidad a adulteración local (TC-F5-025): cualquier intento de elevar privilegios localmente es neutralizado forzosamente por el perfil firmado P0.
  - Helpers de consulta de políticas efectivas para transferencia de archivos, portapapeles, audio y duración de sesión.
- **Archivos modificados:**
  - `src/cercano_profile.rs`
- **Estrategia de actualización (upstream sync):** Funcionalidad contenida en `cercano_profile.rs` sin alterar código base heredado de RustDesk.

### [015-client-reproducible-build-date.patch] Tarea F3-03: BUILD_DATE reproducible

- **Archivo:** `patches/015-client-reproducible-build-date.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F3-03`
- **Fecha:** `2026-11-25`
- **Autor/Rol:** `Agente-Builder`
- **Motivo / Justificación:** `hbb_common::gen_version()` (llamada desde `vendor/client/build.rs`) escribía `chrono::Local::now()` con precisión de minuto en `BUILD_DATE`. Por eso dos compilaciones del mismo commit daban hashes distintos y fallaba TC-F3-021 en el job del binario base. No hay punto de extensión: la constante se genera dentro de esa función. Con `SOURCE_DATE_EPOCH` definido (lo fija `builder/build-base.sh` a la fecha del commit) se usa esa fecha en UTC; sin él, el comportamiento no cambia.
- **Archivos modificados:**
  - `libs/hbb_common/src/lib.rs`
- **Estrategia de actualización (upstream sync):** Cambio de una sola expresión en `gen_version()`. Si upstream añade soporte para `SOURCE_DATE_EPOCH`, este parche se elimina.

---

### [016-client-wpwd-mut.patch] Tarea F3-16: `wpwd` mutable para el borrado seguro

- **Archivo:** `patches/016-client-wpwd-mut.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F3-16`
- **Fecha:** `2026-11-25`
- **Autor/Rol:** `Agente-Cliente`
- **Motivo / Justificación:** El parche 007 sobrescribe con ceros y vacía `wpwd` (la contraseña en UTF-16) tras `CreateProcessWithLogonW`, pero la variable se declaraba sin `mut` y el build de Windows fallaba con E0596. Se numera 016 porque 013, 014 y 015 están reservados por PR abiertos.
- **Archivos modificados:**
  - `src/platform/windows.rs` (una línea: `let wpwd` → `let mut wpwd`)
- **Estrategia de actualización (upstream sync):** Va junto con 007; si upstream cambia `create_process_with_logon`, reaplicar ambos.

---

### [017-client-chat-dart-compile.patch] Tarea F3-17: el chat Flutter compila en Windows

- **Archivo:** `patches/017-client-chat-dart-compile.patch`
- **Componente:** `vendor/client`
- **Tarea:** `F3-17`
- **Fecha:** `2026-11-26`
- **Autor/Rol:** `Agente-Builder`
- **Motivo / Justificación:** El parche 009 dejó tres errores de Dart que rompían `flutter build windows`: `cercano_chat_model.dart` usaba `bind` sin importar `platform_model.dart`; `cercano_chat_page.dart` usaba `Colors.emerald` (inexistente en Flutter; se usa `Colors.green`) y la errata `CrossCrossAlignment`.
- **Archivos modificados:**
  - `flutter/lib/cercano_chat/cercano_chat_model.dart` (un import)
  - `flutter/lib/cercano_chat/cercano_chat_page.dart` (color y errata)
- **Estrategia de actualización (upstream sync):** Va junto con 009; si se reescribe, corregir en el propio 009.

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
