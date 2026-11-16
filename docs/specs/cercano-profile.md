# Especificación del Esquema de Perfil de Instalador (`cercano-profile`)

**Versión:** 1.0.0 · **Fase:** F3 (Generador de Instaladores) · **Tarea:** F3-01  
**Esquema JSON:** [`cercano-profile.schema.json`](cercano-profile.schema.json)  
**Licencia:** AGPL-3.0

---

## 1. Propósito

Un **perfil de Cercano** (`CercanoProfile`) es un documento JSON inmutable y firmado criptográficamente que define las capacidades operativas, los servidores de enlace, la política de seguridad y el comportamiento de instalación de un binario cliente (`.exe` o `.msi`).

El generador de instaladores (`cercano-build` o `POST /builds`) toma este perfil y lo empaqueta junto al binario base reproducible, asegurando que un instalador **Soporte** nunca pueda iniciar conexiones salientes ni actuar como controlador, y que un instalador **Técnico** opere bajo control estricto de identidad.

---

## 2. Tipos de Perfil y Roles

| Propiedad | Soporte (`role: "soporte"`) | Técnico (`role: "tecnico"`) |
|---|---|---|
| **Público objetivo** | Usuario final asistido | Personal de soporte / Administrador TI |
| **Conexiones entrantes (`allow_incoming`)** | **true** (obligatorio) | Opcional (por defecto false) |
| **Conexiones salientes (`allow_outgoing`)** | **false** (estrictamente prohibido) | **true** (obligatorio) |
| **Acceso desatendido (`unattended_access`)** | Configurable (true o false) | **false** (estrictamente prohibido) |
| **Elevación con credenciales** | Receptor (aprueba solicitud) | Emisor (requiere cuenta y permiso) |
| **Caducidad por defecto** | Permanente o largo plazo | Recomendado ≤ 90 días |

---

## 3. Estructura de Campos

### 3.1 Raíz
* `schema_version` (*string*, requerido): Versión semántica del esquema (`1.0.0`).
* `profile_id` (*string UUID*, requerido): Identificador único del perfil.
* `created_at` (*string RFC3339*, opcional): Fecha de emisión.
* `role` (*enum ["soporte", "tecnico"]*, requerido): Rol operativo del perfil.

### 3.2 `server` (Requerido)
* `rendezvous_server` (*string*, requerido): Host y puerto del servidor de señalización (ej. `cercano.lan:21116`).
* `relay_server` (*string*, requerido): Host y puerto del relay (ej. `relay.lan:21117`).
* `api_server` (*string URI*, requerido): URL base HTTP/S de la API (ej. `https://cercano.lan:21114`).
* `server_public_key` (*string Base64*, requerido): Clave pública Ed25519 del servidor.

### 3.3 `identity` (Opcional)
* `app_name` (*string*, 1-64 caracteres): Nombre visible del aplicativo.
* `about_text` (*string*): Texto de atribución y licencia AGPL-3.0.
* `icon` (*string*): Ruta o recurso del icono institucional.

### 3.4 `policy` (Requerido)
* `allow_incoming` (*boolean*, requerido): Habilita recepción de conexiones.
* `allow_outgoing` (*boolean*, requerido): Habilita emisión de conexiones.
* `unattended_access` (*boolean*, requerido): Permite acceso sin confirmación presencial.
* `require_approval` (*boolean*, requerido): Exige confirmación interactiva en pantalla.
* `allow_file_transfer` (*boolean*, default true): Habilita transferencia de archivos.
* `allow_clipboard` (*boolean*, default true): Habilita portapapeles compartido.
* `allow_audio` (*boolean*, default true): Habilita transmisión de audio.
* `allow_terminal` (*boolean*, default false): Habilita consola interactiva.
* `allow_port_forward` (*boolean*, default false): Habilita túneles TCP.
* `hide_network_settings` (*boolean*, default true): Bloquea edición local de servidores.
* `enable_elevation` (*boolean*, default false): Habilita solicitudes de elevación administrativa.
* `unattended_elevation` (*boolean*, default false): Permite elevación desatendida previa autorización.
* `chat` (*object*, opcional, F4.5-13): Política soberana de Cercano Chat.
  * `enabled` (*boolean*, opcional): Habilita la funcionalidad de chat en el cliente. Por defecto `true` para rol `soporte`, `false` para rol `tecnico`.
  * `allow_attachments` (*boolean*, default true): Habilita el envío y recepción de archivos adjuntos (imágenes/PDF).
  * `allow_remote_escalation` (*boolean*, default true): Permite el escalado interactivo de la conversación hacia una sesión remota.

### 3.5 `installation` (Requerido)
* `mode` (*enum ["installed", "portable"]*, requerido): Modo de empaquetado.
* `install_path` (*string*, opcional): Directorio destino en el sistema de archivos.
* `auto_start` (*boolean*, requerido): Inicio automático con el sistema.
* `create_desktop_shortcut` (*boolean*, requerido): Creación de acceso directo.
* `silent` (*boolean*, requerido): Instalación silenciosa desatendida.

### 3.6 `identification` (Opcional)
* `device_group` (*string*): Grupo de inventario asignado al registrarse.
* `default_owner` (*string*): Usuario u operador predeterminado.

### 3.7 `expiration` (Opcional)
* `expires_at` (*string RFC3339*): Fecha de expiración tras la cual el cliente no inicia.
* `max_uses` (*integer ≥ 1*): Límite de instalaciones permitidas.

---

## 4. Reglas de Validación Cruzada (Cross-Field Constraints)

1. **Rechazo de propiedades adicionales (`additionalProperties: false`):** Todo campo no reconocido en la raíz o en los sub-objetos provoca el rechazo inmediato del perfil, impidiendo vectores de contaminación de parámetros.
2. **Invariante de Rol Soporte:** Si `role == "soporte"`, `policy.allow_outgoing` **debe ser false**. Si un perfil soporte declara `allow_outgoing: true`, el validador lo rechaza con error de esquema.
3. **Invariante de Rol Técnico:** Si `role == "tecnico"`, `policy.unattended_access` y `policy.unattended_elevation` **deben ser false**. Los instaladores técnicos no operan como hosts desatendidos.

---

## 5. Política de Versionado y Compatibilidad Hacia Atrás

El esquema se versiona bajo SemVer (`MAJOR.MINOR.PATCH`):

1. **`MAJOR` (Incompatible):** Se incrementa si se eliminan campos, se cambian nombres de propiedades, o se agregan campos obligatorios que invalidan perfiles previos. Los clientes rechazan de forma segura perfiles con `major` superior al soportado.
2. **`MINOR` (Compatible hacia atrás):** Se incrementa al introducir nuevos campos opcionales dentro de sub-objetos conocidos. Los clientes antiguos ignorarán campos opcionales nuevos si su esquema lo tolera, pero en el generador oficial se sincroniza la versión de esquema.
3. **`PATCH` (Correcciones):** Modificaciones a descripciones, expresiones regulares o metadatos sin alterar la estructura válida.
