# Contrato del canal local agente ↔ aplicación y configuración de la organización

**Versión del protocolo:** 1 · **Versión del formato de configuración:** 1 · **Tarea:** F3.5-03
**Decisión:** [ADR-015](../adr/015-agente-y-cliente-generico.md) §2.3, §2.4, §2.7 y §2.10 · **Plan:** [`PLAN-F3.5-AGENTE.md`](../PLAN-F3.5-AGENTE.md)
**Esquemas:** [`agente-ipc.schema.json`](agente-ipc.schema.json) (mensajes) y [`cercano-org.schema.json`](cercano-org.schema.json) (configuración)
**Ejemplos:** [`examples/agente-ipc/`](examples/agente-ipc/) · **Pruebas:** `agent/tests/contract.rs`
**Estado:** borrador para aprobación de Seguridad (la lista de operaciones de §6 necesita su visto bueno).

Este documento fija lo que implementan F3.5-06 (servidor del canal en el agente), F3.5-09 (puente en la
aplicación), F3.5-05 (vinculación con la configuración) y F3.5-11/F3.5-12 (instalador y generador).
Palabras como **debe** y **no debe** son normativas.

## 1. Partes y frontera de confianza

| Parte | Proceso | Cuenta | Papel en el canal |
|---|---|---|---|
| Agente | `cercano-agent.exe run`, servicio `CercanoAgent` | `LocalSystem` | Servidor de la tubería |
| Aplicación | `cercano.exe` (interfaz y servicio heredado) | Usuario interactivo o `LocalSystem` | Cliente |

La tubería cruza una frontera de privilegios. El agente trata todo lo que llega como no confiable
aunque el llamante haya pasado la verificación de §3: valida contra el esquema, aplica límites y no
expone ninguna operación que cambie configuración, claves o vinculación (§6.3).

## 2. La tubería

- **Nombre:** `\\.\pipe\cercano-agent`. Uno solo por equipo; no hay instancias por usuario.
- **Creación:** `CreateNamedPipeW` con `PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE |
  FILE_FLAG_OVERLAPPED` y `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS`.
  Si la primera instancia falla con `ERROR_ACCESS_DENIED` o `ERROR_PIPE_BUSY` otro proceso se adelantó:
  el agente registra `ipc.squatted` en su log, no sirve y lo indica en `cercano-agent status`.
- **Instancias:** como máximo 8 conexiones simultáneas (`nMaxInstances = 8`); la novena espera.
- **DACL** (protegida, sin herencia), en SDDL:

  ```
  D:P(A;;GA;;;SY)(A;;GRGW;;;IU)(D;;GA;;;NU)
  ```

  `SYSTEM` control total; usuarios interactivos (`IU`) lectura y escritura; inicios de sesión de red
  (`NU`) denegados de forma explícita, además de `PIPE_REJECT_REMOTE_CLIENTS`. El servicio heredado de
  la aplicación corre como `SYSTEM` y entra por la primera entrada. Nadie más que `SYSTEM` puede crear
  instancias ni cambiar la DACL. Propietario: `SYSTEM`.
- **Tiempos:** `hello` debe llegar en 5 s desde la conexión; una trama empezada debe completarse en 5 s;
  una conexión sin tráfico 10 minutos se cierra (las suscritas con `chat.subscribe` no caducan
  mientras la conexión siga viva).

## 3. Verificación mutua

Ninguna parte envía datos de la organización antes de verificar a la otra. Una verificación fallida
cierra la conexión **sin respuesta** y deja una línea en el log de quien verificó (sin secretos): PID,
ruta de la imagen y motivo. Esto cubre TC-F3.5-007 y TC-F3.5-008.

### 3.1 El agente verifica al llamante

1. `GetNamedPipeClientProcessId` → PID. Si la llamada falla, se rechaza.
2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` y `QueryFullProcessImageNameW` → ruta de la imagen.
3. La ruta, normalizada (`GetFinalPathNameByHandleW` sobre el archivo abierto, sin enlaces), debe estar
   **dentro del directorio de instalación** leído de `HKLM\SOFTWARE\Cercano\Agent\InstallDir` (clave
   escrita por el instalador; solo administradores pueden modificarla).
4. `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, revocación de toda la cadena, sin interfaz)
   sobre esa imagen debe devolver éxito.
5. El **firmante** de la imagen debe ser el mismo que el del propio `cercano-agent.exe`: mismo sujeto
   del certificado hoja y misma huella SHA-256 de su clave pública. Comparar la clave y no la huella del
   certificado permite renovarlo sin romper el canal; un cambio de clave exige publicar agente y
   aplicación juntos (ya se empaquetan juntos, ADR-015 §3).

Entre el paso 2 y el 5 el agente mantiene abierto el manejador del proceso y del archivo para que la
imagen no pueda sustituirse a mitad de la comprobación.

### 3.2 La aplicación verifica al agente

1. `GetNamedPipeServerProcessId` → PID.
2. `QueryServiceStatusEx("CercanoAgent")` debe dar el **mismo PID** y estado `SERVICE_RUNNING`.
3. El token del proceso debe ser `S-1-5-18` (`LocalSystem`).
4. La imagen debe ser `<InstallDir>\cercano-agent.exe`, con `WinVerifyTrust` correcto y el mismo
   firmante que `cercano.exe` (misma regla que §3.1.5).

Si algo falla, la aplicación pasa al estado **bloqueado** (ADR-015 §2.6), nunca a libre.

### 3.3 Compilaciones sin firma

Las compilaciones de desarrollo no llevan Authenticode. Los pasos 4 y 5 de §3.1 y el paso 4 de §3.2
solo se pueden desactivar con la *feature* de Cargo `insecure-dev-ipc`, que **no** debe activarse en
el paquete publicado (F3.5-11 lo comprueba en el build; F3.5-14 lo revisa). Las comprobaciones de PID,
servicio y cuenta se mantienen siempre.

## 4. Tramas

```
+----------------------+-----------------------------------------+
| longitud: u32 LE (4) | carga: JSON UTF-8 (longitud bytes)      |
+----------------------+-----------------------------------------+
```

- **Longitud:** entero sin signo de 32 bits, *little endian*, que cuenta solo la carga.
- **Tamaño máximo de la carga:** **65 536 bytes** (`max_frame_bytes`, anunciado en `hello`). Mínimo 2.
- **Carga:** un único objeto JSON en UTF-8 sin BOM, que valida contra `agente-ipc.schema.json`.
  Profundidad máxima de anidamiento 32. Claves duplicadas: trama inválida.
- Una longitud 0, mayor que el máximo o una carga que no es JSON válido: el agente responde
  `bad_frame` o `frame_too_large` con `id: null` **y cierra la conexión**, sin leer el resto. Una
  trama que es JSON pero no cumple el esquema responde `invalid_params` (o `unknown_op`) y la conexión
  sigue.
- **Tasa:** como máximo 20 peticiones por segundo y conexión, con ráfaga de 40. Por encima, `rate_limited`
  con `retry_after_ms`. Cinco `bad_frame` o `rate_limited` seguidos cierran la conexión.

## 5. Mensajes

Hay tres formas, distinguidas por sus campos obligatorios (`additionalProperties: false` en todas):

| Forma | Sentido | Campos |
|---|---|---|
| Petición | aplicación → agente | `id` (1…2³²−1), `op`, `params` (objeto, `{}` si no hay) |
| Respuesta | agente → aplicación | `id`, `ok: true` y `result`, o `ok: false` y `error {code, message, retry_after_ms?}` |
| Evento | agente → aplicación | `event`, `data`; sin `id` |

- La aplicación elige los `id` y no los repite mientras haya una petición pendiente con el mismo `id`.
- El agente puede responder fuera de orden; la aplicación correlaciona por `id`.
- Los eventos solo se envían tras `hello` y, los de chat, tras `chat.subscribe`.
- `error.message` es texto para diagnóstico en español, sin secretos; la aplicación decide por `code`.

### 5.1 Negociación de versión (`hello`)

La primera petición de cada conexión **debe** ser `hello`; cualquier otra recibe `handshake_required`.
La aplicación envía las versiones que admite (`protocol_versions`); el agente responde con la **mayor
común** en `protocol_version`. Sin versión común: `unsupported_version` y la aplicación se bloquea
mostrando que agente y aplicación están desalineados. Un segundo `hello` en la misma conexión recibe
`invalid_params`.

Reglas de evolución: añadir operaciones, campos opcionales de resultado o eventos nuevos **no** cambia la
versión (la aplicación ignora eventos desconocidos y una operación desconocida devuelve `unknown_op`).
Quitar o cambiar el significado de algo exige una versión nueva; el agente admite la anterior al menos
durante una versión menor del producto.

## 6. Operaciones

| `op` | Parámetros | Resultado | Errores propios |
|---|---|---|---|
| `hello` | `protocol_versions`, `client_name`, `client_version` | `protocol_version`, `agent_version`, `state`, `max_frame_bytes` | `unsupported_version` |
| `get_config` | — | `profile_id`, `rendezvous_server`, `relay_server`, `server_public_key` | `not_enrolled`, `revoked` |
| `get_branding` | — | `organization_name`, `accent_color` (o `null`), `logo` (PNG en base64, ≤ 32 KiB, o `null`) | `not_enrolled` |
| `get_role` | — | `role` (`soporte` o `tecnico`) | `not_enrolled`, `revoked` |
| `get_policy` | — | `policy` (mismos campos que `policy` del perfil F3-01), `source`, `fetched_at`, `valid_until` | `not_enrolled`, `revoked`, `policy_expired` |
| `chat.list_conversations` | `include_closed?`, `limit?` (≤ 100) | `conversations[]` | `forbidden_by_policy`, `server_unreachable` |
| `chat.get_messages` | `conversation_id`, `after_seq?`, `limit?` (≤ 200) | `messages[]` | `not_found`, `forbidden_by_policy`, `server_unreachable` |
| `chat.send_message` | `conversation_id?` (`null` abre una nueva), `body` (1…4000) | `conversation_id`, `message_id`, `seq` | `forbidden_by_policy`, `server_unreachable` |
| `chat.mark_read` | `conversation_id`, `up_to_seq` | `{}` | `not_found` |
| `chat.subscribe` | — | `{}`; después, eventos `chat.message` y `chat.conversation` | `forbidden_by_policy` |
| `chat.get_attachment` | `attachment_id`, `offset`, `length` (≤ 32 768) | `data_base64`, `eof` | `not_found`, `forbidden_by_policy` |
| `audit.submit` | `events[]` (1…50) | `accepted`, `duplicates` | — |
| `status` | — | `state`, `agent_version`, `protocol_version`, `server_reachable`, `policy_valid_until`, `last_heartbeat_at`, `audit_queue_len` | — |

Notas:

- **`state`** vale `managed`, `unenrolled`, `revoked`, `policy_expired` o `error`. Todo lo que no sea
  `managed` lleva a la aplicación a **bloqueado**. El agente también lo empuja como evento `state`
  cuando cambia.
- **`get_config`** solo entrega lo necesario para hablar con hbbs/hbbr (ADR-015 §2.2). No entrega la URL
  de `cercano-api`, el token de registro, la credencial del dispositivo ni la clave de perfiles.
- **`get_policy`** sirve la política efectiva calculada por el agente con el perfil como techo
  (ADR-012). Si `valid_until` ya pasó y no hay red, responde `policy_expired` (fallo cerrado, TC-F3.5-010).
- **Chat:** `chat.*` exige `policy.chat.enabled`; si no, `forbidden_by_policy`. El token del chat no
  sale nunca del agente (F3.5-08). `technician_name` y `sender_name` de un técnico son su nombre
  visible (`assigned_display_name`), nunca su usuario de inicio de sesión (F4.5-17, `chat.md`). El envío de adjuntos desde la aplicación queda para F3.5-08 como
  operación nueva compatible (§5.1).
- **`audit.submit`:** la aplicación entrega `event_id`, `ts`, `action`, `outcome` y opcionalmente
  `trace_id`, `subject` y `details`. Solo acepta acciones `conn.*`, `elev.*`, `chat.*` y `client.*`. El
  agente añade `source`, el actor de dispositivo, `prev_hash` y `hash`; la aplicación no puede
  fijarlos. Deduplica por `event_id` (`duplicates`) y encola para el envío (F3.5-07).

### 6.1 Errores

| `code` | Cuándo | ¿Cierra la conexión? |
|---|---|---|
| `bad_frame` | Longitud 0 o carga que no es JSON UTF-8 | Sí |
| `frame_too_large` | Longitud > `max_frame_bytes` | Sí |
| `handshake_required` | Petición antes de `hello` | No |
| `unsupported_version` | Sin versión común en `hello` | Sí |
| `unknown_op` | `op` fuera de la lista de §6 | No |
| `invalid_params` | La petición no cumple el esquema o `hello` repetido | No |
| `not_enrolled` | El agente aún no está vinculado | No |
| `revoked` | El instalador o el dispositivo fueron revocados | No |
| `policy_expired` | Política caducada y sin red | No |
| `forbidden_by_policy` | La política no permite la operación (p. ej. chat desactivado) | No |
| `not_found` | Conversación o adjunto inexistentes o ajenos | No |
| `rate_limited` | Límite de §4 superado; trae `retry_after_ms` | Tras 5 seguidos |
| `server_unreachable` | La operación necesita a `cercano-api` y no responde | No |
| `internal` | Fallo inesperado del agente (detalle solo en su log) | No |

### 6.2 Correspondencia con el estado de la aplicación

| Situación | Estado de la aplicación |
|---|---|
| No existe `HKLM\SOFTWARE\Cercano\Agent` | Libre |
| Existe la clave y la tubería no responde, o falla la verificación de §3.2 | Bloqueado |
| `hello` responde `state` distinto de `managed`, o `unsupported_version` | Bloqueado |
| `hello` responde `managed` | Gestionado |

### 6.3 Lo que el canal no permite

- **No hay operaciones de escritura de configuración.** No existe nada equivalente a `set_config`,
  `enroll`, `re-enroll`, cambiar la clave fijada, los hosts o la política. El esquema cierra la lista
  de `op`, y la prueba `no_config_write_ops` falla si alguien añade una operación cuyo nombre sugiera
  escritura (`set`, `write`, `update`, `enroll`, `pin`, `key`, `config` salvo `get_config`, `policy`
  salvo `get_policy`). Vincular o volver a vincular solo se hace con `cercano-agent enroll` o
  `re-enroll` como administrador, o con el instalador.
- **No viajan secretos:** ni token de registro, ni credencial o clave privada del dispositivo, ni clave
  de perfiles, ni token del chat, ni credenciales de elevación (ADR-009, van por la sesión cifrada).

## 7. Registro

El agente registra cada conexión aceptada o rechazada (PID, imagen, motivo) y cada error del canal,
nunca el contenido de `chat.*` ni los `details` de auditoría. Las reglas de redacción son las de
`agent/src/logs.rs` (F3.5-04).

## 8. Pruebas del contrato

`cargo test -p cercano-agent --test contract` comprueba:

- los dos esquemas compilan (Draft-07);
- cada intercambio de `ipc-validos.json` valida (petición, respuesta y, en las correctas, el resultado
  contra `definitions/results/<op>`), y cada mensaje de `ipc-invalidos.json` se rechaza;
- `org-valido-*.json` validan y `org-invalido-*.json` se rechazan;
- la lista de `op` coincide con §6 y no contiene operaciones de escritura;
- un código de configuración de tamaño máximo (§9.4) cabe en 4096 caracteres y en una línea de
  `msiexec`, y decodificado sigue validando.

## 9. Configuración de la organización (`cercano-org.json`)

### 9.1 Contenido

| Campo | Tipo | Descripción |
|---|---|---|
| `config_version` | `1` | Versión del formato. Una versión desconocida se rechaza. |
| `organization_name` | texto 1…128, sin caracteres de control | Nombre visible en el instalador interactivo y en la marca |
| `profile_signing_public_key` | Ed25519, 32 bytes en base64 estándar | Verifica las dos firmas; se fija al instalar (ADR-015 §2.4) |
| `enroll_token` | base64url, 32…128 caracteres | Token de registro (caducidad, usos y revocación en el servidor). Secreto de bajo privilegio |
| `signed_profile` | objeto | Sobre `SignedCercanoProfile` de `cercano-api`: `profile` (esquema F3-01 **sin** `identity.icon`), `signature`, `algorithm: "ed25519"`, `key_id?` |
| `config_signature` | Ed25519, 64 bytes en base64 estándar | Firma del objeto completo sin este campo |

No lleva logo: lo descarga el agente tras vincularse (ADR-015 §2.9). Ejemplos:
[`org-valido-soporte.json`](examples/agente-ipc/org-valido-soporte.json) y
[`org-valido-tecnico.json`](examples/agente-ipc/org-valido-tecnico.json). Las firmas de los ejemplos
son de relleno: validan la forma, no la criptografía; F3.5-05 añade vectores firmados de verdad.

### 9.2 Firmas

Las dos firmas usan la clave de perfiles de la organización y la canonicalización RFC 8785 de
`audit-core` (la misma con que `cercano-api` firma hoy el perfil):

1. `signed_profile.signature` = Ed25519(canónico(`signed_profile.profile`)). Es la firma F3-01 de
   siempre, así que el perfil se puede extraer y verificar por separado.
2. `config_signature` = Ed25519(canónico(objeto completo **sin** `config_signature`)). Protege
   `organization_name`, `enroll_token` y la propia clave: cambiar un byte de cualquier campo invalida la
   configuración (TC-F3.5-004).

**Huella de la clave** que muestran el instalador y `cercano-agent status`: SHA-256 de los 32 bytes de la
clave, en hexadecimal en minúsculas; se muestran los 16 primeros bytes en grupos de 4 caracteres
(`3f2a 9c01 …`).

### 9.3 Validación (agente e instalador)

En este orden, y ante el primer fallo se aborta sin escribir nada:

1. Código: longitud ≤ 4096, solo alfabeto base64url sin relleno; decodificar. Archivo: tamaño ≤ 4096
   bytes.
2. JSON UTF-8 sin claves duplicadas que valida contra `cercano-org.schema.json`.
3. `config_signature` y `signed_profile.signature` verifican con `profile_signing_public_key`.
4. Si ya hay una clave fijada, `profile_signing_public_key` debe ser **igual**; si no, se rechaza
   (TC-F3.5-005), salvo reinstalación como administrador o rotación firmada (ADR-015 §2.4, F3.5-05).
5. `profile.expiration.expires_at`, si existe, no ha pasado.
6. Validación semántica del perfil F3-01 (invariantes de rol, `CercanoProfile::validate`).

Tras vincular (F3.5-05), el agente **borra** `enroll_token` de lo que guarda; nunca lo escribe en logs,
en `status` ni en `export-diagnostics`.

### 9.4 Código de configuración y tamaño máximo

- **Código** = base64url **sin relleno** (RFC 4648 §5) de los bytes UTF-8 del JSON en forma compacta.
  Alfabeto `A–Z a–z 0–9 - _`: no necesita comillas en `cmd`, PowerShell ni `msiexec`.
- **Tamaño máximo: 4096 caracteres de código** (3072 bytes de JSON). El generador (F3.5-12) debe
  rechazar configuraciones mayores; el agente y el instalador rechazan códigos mayores antes de
  decodificar. El esquema por sí solo no acota el tamaño (algunos campos del perfil F3-01 admiten
  textos largos), por eso el límite se comprueba sobre el código.
- **Por qué cabe en `msiexec`:** `msiexec /i cercano.msi /qn CERCANO_CONFIG=<4096 caracteres>` ocupa
  unos 4130 caracteres, por debajo del límite de 8191 de `cmd.exe` y de los 32 767 de `CreateProcess`.
  Las propiedades públicas de Windows Installer no tienen un límite menor. La prueba del contrato
  comprueba la longitud de la línea con el código de tamaño máximo; la instalación real con ese código
  se demuestra en F3.5-11 (TC-F3.5-015), cuando exista el `.msi` genérico.
- Un perfil típico (ejemplos de este directorio) produce un código de unos 2000 caracteres.

### 9.5 Dónde se busca

Lo implementa F3.5-11 y se recoge aquí para que el contrato sea completo: propiedad `CERCANO_CONFIG`
del `.msi`, luego `cercano-org.json` en la carpeta del instalador; con `cercano-agent enroll --config
<código o ruta>` en equipos ya instalados. Sin ninguna, se instala solo la aplicación en modo libre.

## 10. Cuestiones abiertas para Seguridad (F3.5-14)

1. Aprobar la lista cerrada de operaciones de §6 y la DACL de §2.
2. Confirmar la regla de «mismo firmante» por clave pública del certificado hoja (§3.1.5).
3. Confirmar que `audit.submit` limita las categorías a `conn`, `elev`, `chat` y `client`.
