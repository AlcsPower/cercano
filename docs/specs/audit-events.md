# Especificación del Esquema de Eventos de Auditoría y Cadena de Integridad

**Versión:** 1.0  
**Fecha:** 2026-11-06  
**Estado:** Aprobado / Especificación Oficial  
**Módulos de referencia:** `audit-core`, `control-plane/cercano-api`, `server/hbbs`, `server/hbbr`, `client`  
**Documentos relacionados:** `docs/ARQUITECTURA.md` §4, `docs/PLAN-F2-AUDITORIA.md`, `docs/specs/audit-events.schema.json`

---

## 1. Propósito y Principios de Diseño

El sistema de auditoría de **Cercano** proporciona un registro estructurado, inalterable y verificable de forma independiente de todos los eventos relevantes de seguridad y operación en la plataforma de escritorio remoto. Cumple con los objetivos del hito **M1 (Fase F2)**:

1. **Inalterabilidad criptográfica (*Append-Only Hash Chain*):** Cada evento de auditoría queda enlazado criptográficamente con el evento precedente mediante una función resumen SHA-256 aplicada sobre una representación canónica determinista (RFC 8785 - JCS). Cualquier modificación, inserción, eliminación o reordenamiento de eventos invalida la cadena.
2. **Trazabilidad de extremo a extremo (`trace_id`):** Todas las operaciones pertenecientes a una misma sesión de escritorio remoto, transferencia de archivos o flujo de trabajo administrativo comparten un `trace_id` (UUIDv7) propagado entre cliente, servicios de señalización (*hbbs*), repetidores (*hbbr*) y la API de control plane.
3. **Verificación *offline* sin dependencia del servidor:** El formato y el encadenamiento permiten que la herramienta de línea de comandos `cercano-audit verify` o cualquier auditor externo compruebe la autenticidad e integridad de un volcado JSONL/CSV sin necesidad de contar con la base de datos ni con servicios en ejecución.
4. **Privacidad y Seguridad por Diseño (*Zero Secret Leaks*):** Ningún evento almacena credenciales en claro, claves privadas ni datos brutos que expongan la confidencialidad de los usuarios o del sistema.

---

## 2. Esquema Común de Evento de Auditoría

El archivo formal JSON Schema Draft-07 se encuentra publicado en:  
[`docs/specs/audit-events.schema.json`](file:///c:/Users/alcs/OneDrive%20-%20cercano.local/Documentos/Mis%20Proyectos/Cercano/docs/specs/audit-events.schema.json).

### 2.1 Campos Obligatorios y Opcionales

| Campo | Tipo | Requerido | Descripción |
|---|---|:---:|---|
| `event_id` | `string` (UUID) | **Sí** | Identificador único universal del evento. Formato estándar UUIDv7 (48 bits de milisegundos UTC ordenables + 74 bits de entropía pseudoaleatoria). |
| `trace_id` | `string` | **Sí** | Identificador de correlación que asocia todos los eventos de una misma sesión o transacción de extremo a extremo. |
| `ts` | `string` (ISO 8601) | **Sí** | Marca de tiempo UTC en formato RFC 3339 con milisegundos (`YYYY-MM-DDTHH:MM:SS.sssZ`). |
| `source` | `string` (Enum) | **Sí** | Componente emisor: `client`, `hbbs`, `hbbr`, `api`, `console`, `builder`. |
| `category` | `string` (Enum) | **Sí** | Categoría funcional: `conn`, `file`, `alarm`, `console`, `auth`, `build`. |
| `action` | `string` (Pattern) | **Sí** | Acción auditada jerárquica: `^(conn\|file\|alarm\|console\|auth\|build)(\.[a-z0-9_]+)+$`. |
| `actor` | `object` | **Sí** | Entidad que inicia o ejecuta la acción (usuario, dispositivo o sistema). |
| `subject` | `object` | No | Entidad receptora, recurso o dispositivo sobre el que recae la acción. |
| `outcome` | `string` (Enum) | **Sí** | Resultado: `success` (éxito), `failure` (fallo funcional/error), `denied` (denegado por política o falta de privilegios). |
| `details` | `object` | **Sí** | Objeto estructurado con parámetros contextuales de la acción (véase §6). |
| `prev_hash` | `string` (SHA-256) | **Sí** | Cadena de 64 caracteres hexadecimales en minúsculas con el hash del evento anterior (64 ceros en el bloque génesis). |
| `hash` | `string` (SHA-256) | **Sí** | Cadena de 64 caracteres hexadecimales en minúsculas que sella criptográficamente este evento. |

### 2.2 Estructura del Objeto `actor`

| Propiedad | Tipo | Requerido | Descripción |
|---|---|:---:|---|
| `id` | `string` | **Sí** | Identificador único del actor (ID de usuario de BD, UUID de dispositivo, o identificador de proceso). |
| `actor_type` | `string` (Enum) | **Sí** | Tipo de entidad: `user` (operador humano), `device` (agente o cliente de máquina), `system` (servicio interno). |
| `name` | `string` | No | Nombre de usuario, hostname o etiqueta legible. |
| `ip` | `string` | No | Dirección IPv4 o IPv6 desde la cual se originó la petición. |

### 2.3 Estructura del Objeto `subject`

| Propiedad | Tipo | Requerido | Descripción |
|---|---|:---:|---|
| `id` | `string` | **Sí** | Identificador único del recurso o entidad afectada. |
| `subject_type` | `string` (Enum) | **Sí** | Clasificación del sujeto: `device`, `user`, `group`, `session`, `installer`, `setting`, `system`. |
| `name` | `string` | No | Nombre o denominación representativa del recurso afectado. |

---

## 3. Canonicación JSON Determinista (RFC 8785 - JCS)

Para garantizar que el cálculo de la función hash sea idéntico en cualquier lenguaje (Rust, Go, TypeScript, Python) o plataforma, Cercano exige el cumplimiento estricto del estándar **RFC 8785: JSON Canonicalization Scheme (JCS)**.

### Reglas de Serialización Canónica:
1. **Juego de caracteres:** Codificación exclusiva en **UTF-8 sin BOM**.
2. **Espaciado y separadores:** Se eliminan todos los espacios en blanco, tabulaciones y saltos de línea fuera de los valores literales de cadena. No se permiten espacios tras comas (`,`) ni tras dos puntos (`:`).
3. **Ordenamiento de propiedades:** Las claves de todos los objetos JSON deben ordenarse lexicográficamente según el valor numérico de sus unidades de código UTF-16 (coincidente con los code points de Unicode en el plano multilingüe básico).
4. **Formato numérico:** Los números enteros y de coma flotante se representan según las especificaciones de ECMAScript / IEEE 754:
   - Sin ceros a la izquierda innecesarios.
   - Sin punto decimal flotante si el valor es entero (ej. `10` en vez de `10.0`).
   - Sin ceros terminales redundantes en la parte fraccionaria (ej. `1.5` en vez de `1.500`).
   - Exponentes en minúsculas (`e`) sin signos `+` innecesarios.
5. **Escape de caracteres en cadenas:**
   - Únicamente se escapan las comillas dobles (`\"`), la barra invertida (`\\`) y los caracteres de control ASCII entre `0x00` y `0x1F`.
   - Se utilizan las secuencias cortas estandarizadas: `\b` (`0x08`), `\t` (`0x09`), `\n` (`0x0A`), `\f` (`0x0C`), `\r` (`0x0D`). Los demás caracteres de control se escapan como `\u00XX` en minúsculas.
   - No se permite escapar la barra inclinada (`/`).
6. **Literales booleanos y nulos:** Siempre en minúsculas (`true`, `false`, `null`). Las propiedades con valor `null` no deben omitirse si forman parte del esquema; sin embargo, en Cercano se prefiere omitir claves opcionales no utilizadas.

---

## 4. Fórmula de Cálculo del Hash y Cadena de Integridad

### 4.1 Definición Matemática

Dado un evento $E_i$ con $i \ge 0$:

$$\text{hash}_i = \text{SHA-256}\Big(\text{prev\_hash\_ascii}_i \mathbin{\Vert} \text{JCS}\big(\text{Payload}(E_i)\big)\Big)$$

Donde:
- $\text{prev\_hash\_ascii}_i$: Representación en formato ASCII de 64 caracteres en minúsculas del hash del evento anterior $\text{hash}_{i-1}$.
- $\text{Payload}(E_i)$: El objeto JSON del evento conteniendo todos sus campos **excluyendo** los campos de encadenamiento `hash` y `prev_hash`.
- $\text{JCS}(\cdot)$: La función de canonicación según el estándar RFC 8785.
- $\mathbin{\Vert}$: Concatenación binaria de secuencias de bytes directas (sin separadores intermedios).
- $\text{SHA-256}(\cdot)$: Algoritmo de resumen criptográfico (FIPS PUB 180-4) codificado como 64 caracteres hexadecimales en minúsculas (`[0-9a-f]{64}`).

### 4.2 Especificación del Bloque Génesis

Para el primer evento de auditoría de una partición o almacén ($i=0$), el valor de `prev_hash` se define formalmente como exactamente **64 caracteres cero en minúsculas**:

```
0000000000000000000000000000000000000000000000000000000000000000
```

En la concatenación binaria, este valor aporta exactamente 64 bytes ASCII con el código `0x30`.

### 4.3 Almacenamiento y Checkpoints Firmados

Al almacenarse en base de datos (SQLite / PostgreSQL) o transmitirse a sistemas SIEM, el evento $E_i$ contiene tanto `prev_hash` como `hash`.  
Adicionalmente, cada $N$ eventos (por defecto $N=10\,000$) o cada $T$ minutos (por defecto $T=60$), el subsistema `audit-core` emite un **Checkpoint firmado** con clave asimétrica **Ed25519** separada de la base de datos, garantizando no repudio aun ante compromiso total del acceso de lectura de la base de datos.

---

## 5. Reglas Estrictas de Seguridad sobre Datos Sensibles

> [!CAUTION]
> **PROHIBICIÓN ABSOLUTA DE SECRETOS EN AUDITORÍA:**  
> La regla de oro del subsistema de auditoría de Cercano es que los logs y eventos son accesibles por personal de auditoría y exportados a plataformas externas (SIEM). Por tanto, **ningún secreto o dato que comprometa la confidencialidad puede registrarse en el objeto `details` ni en ningún otro campo del evento**.

### Matriz de Verificación de Datos:

| Categoría | Elementos Estrictamente PROHIBIDOS | Representación PERMITIDA y Requerida |
|---|---|---|
| **Credenciales de Acceso** | Contraseñas en texto claro, hashes de contraseñas (bcrypt/argon2/sha256 de password). | Solo el identificador de usuario, tipo de método de autenticación (`password_preset`, `temporary_password`, `pin`), y resultado booleano. |
| **Tokens de Sesión y API** | Tokens JWT completos, *Bearer tokens*, *API keys* privadas, cookies de sesión completas. | Solo el identificador opaco o huella pública truncada (ej. `tok_998877665544332211`, `key_id`). |
| **Criptografía y Claves** | Claves privadas (Ed25519, RSA, ECDSA), semillas criptográficas, claves de cifrado simétrico AES/ChaCha. | Solo claves públicas en Base64 o huellas digitales SHA-256 (ej. `SHA256:d41d8cd9...`). |
| **Archivos y Portapapeles** | Contenido binario o texto en bruto de ficheros transferidos, contenido copiado al portapapeles. | Metadatos exclusivos: ruta remota (`remote_path`), nombre de archivo (`file_name`), tamaño en bytes (`bytes_transferred`), y hash SHA-256 del contenido (`sha256`). |
| **Datos Personales Sensibles** | Números de tarjeta de crédito, números de identificación personal innecesarios, datos médicos. | Identificadores de usuario internos de la organización (`usr_...`). |

---

## 6. Catálogo de Acciones Estándar y Vectores de Prueba Oficiales

A continuación se detalla la especificación de los 12 tipos de eventos fundamentales que conforman la cobertura mínima de Cercano (paridad con Server Pro y extensiones Cercano).

Para cada evento se incluye el vector de prueba matemático oficial:
1. Objeto JSON original completo.
2. Cadena canónica RFC 8785 generada ($\text{JCS}$).
3. Hash SHA-256 resultante encadenado secuencialmente desde el bloque génesis.

---

### 6.1 `conn.start` — Inicio de Sesión de Escritorio / Control Remoto

- **Emisor (`source`):** `client` (o `hbbs` en eventos de rendezvous).
- **Categoría (`category`):** `conn`.
- **Condición:** Se emite en el momento exacto en que se establece la conexión interactiva entre el controlador y el controlado.
- **Campos esperados en `details`:** `session_type` (`desktop`, `file_transfer`, `port_forward`, `camera`, `terminal`), `auth_method` (`manual_confirm`, `password_preset`, `temporary_password`, `side_switch`), `two_factor_verified` (`boolean`), `client_version`, `rendezvous_server`, `relay_server` (opcional), `is_direct_lan` (`boolean`).

> [!NOTE]
> **Compatibilidad cliente heredado:** Los campos heredados (`auth_method`, `session_type`, `client_version`) son opcionales cuando el evento proviene de la ingestión del cliente legado vía `/api/audit/conn` (`action: "new"`).

#### Vector de Prueba: Evento Génesis (Índice 1)

**JSON Completo:**
```json
{
  "event_id": "0192e2fb-3d5a-7182-9654-2c7da197824c",
  "trace_id": "0192e2fb-3d5a-7182-9654-2c7da197824b",
  "ts": "2026-11-06T15:00:00.000Z",
  "source": "client",
  "category": "conn",
  "action": "conn.start",
  "actor": {
    "id": "usr_01j00000000000000000000001",
    "actor_type": "user",
    "name": "admin",
    "ip": "192.168.1.50"
  },
  "subject": {
    "id": "dev_01j00000000000000000000002",
    "subject_type": "device",
    "name": "PC-CONTABILIDAD"
  },
  "outcome": "success",
  "details": {
    "session_type": "desktop",
    "auth_method": "password_preset",
    "two_factor_verified": true,
    "client_version": "1.3.0",
    "rendezvous_server": "hbbs.lan:21116",
    "relay_server": "hbbr.lan:21117",
    "is_direct_lan": false
  },
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "b628eb2049e7f117336db76dd0c48611a77d4bddbecda81650b8e2a450f0e323"
}
```

**JCS canónico (`canonical_json_without_hash_fields`):**
```json
{"action":"conn.start","actor":{"actor_type":"user","id":"usr_01j00000000000000000000001","ip":"192.168.1.50","name":"admin"},"category":"conn","details":{"auth_method":"password_preset","client_version":"1.3.0","is_direct_lan":false,"relay_server":"hbbr.lan:21117","rendezvous_server":"hbbs.lan:21116","session_type":"desktop","two_factor_verified":true},"event_id":"0192e2fb-3d5a-7182-9654-2c7da197824c","outcome":"success","source":"client","subject":{"id":"dev_01j00000000000000000000002","name":"PC-CONTABILIDAD","subject_type":"device"},"trace_id":"0192e2fb-3d5a-7182-9654-2c7da197824b","ts":"2026-11-06T15:00:00.000Z"}
```
**`hash` calculado:** `b628eb2049e7f117336db76dd0c48611a77d4bddbecda81650b8e2a450f0e323`

---

### 6.2 `conn.end` — Finalización de Sesión de Escritorio

- **Emisor (`source`):** `client`.
- **Categoría (`category`):** `conn`.
- **Condición:** Se emite al cerrarse la sesión (por usuario o corte de red).
- **Campos esperados en `details`:** `duration_seconds` (`number`), `close_reason` (`user_disconnected`, `remote_closed`, `timeout`, `network_error`), `bytes_sent`, `bytes_received`, `session_notes` (opcional, notas libres adjuntadas por el técnico).

#### Vector de Prueba: Evento 2

**JSON Completo:**
```json
{
  "event_id": "0192e2fc-1a2b-7341-a123-9f8e7d6c5b4a",
  "trace_id": "0192e2fb-3d5a-7182-9654-2c7da197824b",
  "ts": "2026-11-06T15:15:30.000Z",
  "source": "client",
  "category": "conn",
  "action": "conn.end",
  "actor": {
    "id": "usr_01j00000000000000000000001",
    "actor_type": "user",
    "name": "admin",
    "ip": "192.168.1.50"
  },
  "subject": {
    "id": "dev_01j00000000000000000000002",
    "subject_type": "device",
    "name": "PC-CONTABILIDAD"
  },
  "outcome": "success",
  "details": {
    "duration_seconds": 930,
    "close_reason": "user_disconnected",
    "bytes_sent": 14502800,
    "bytes_received": 3829000,
    "session_notes": "Soporte mensual y actualización de parches"
  },
  "prev_hash": "b628eb2049e7f117336db76dd0c48611a77d4bddbecda81650b8e2a450f0e323",
  "hash": "59a485effb765f553590d51fbcc9c3e8f0dcc8910d36c4c72dc322a3c4e12b87"
}
```
**`hash` calculado:** `59a485effb765f553590d51fbcc9c3e8f0dcc8910d36c4c72dc322a3c4e12b87`

---

### 6.3 `conn.auth` — Autenticación de Conexión Abierta

- **Emisor (`source`):** `client`.
- **Categoría (`category`):** `conn`.
- **Condición:** Se emite cuando una conexión establecida completa exitosamente la autenticación de pares.
- **Actor (`actor`):** Dispositivo o usuario par que inicia o controla la sesión (`peer`).
- **Sujeto (`subject`):** Equipo o terminal accedido/controlado (`id`).
- **Campos en `details`:** `peer` (id y nombre del par), `conn_type` (`remote`, `file_transfer`, `port_forward`, `view_camera`, `terminal`), `primary_auth` (`0` ninguno, `1` contraseña, `2` clave), `two_factor` (`0` o `1`).

---

### 6.4 `conn.event` — Evento de Conexión No Clasificado (Compatibilidad)

- **Emisor (`source`):** `client`.
- **Categoría (`category`):** `conn`.
- **Condición:** Se registra solo si el cliente heredado envía una acción de conexión no clasificada o desconocida en `/api/audit/conn`.

---


### 6.5 `conn.fail` — Intento Fallido de Conexión

- **Emisor (`source`):** `hbbs` o `client`.
- **Categoría (`category`):** `conn`.
- **Condición:** Fallo de autenticación en conexión remota o rechazo del interlocutor.
- **Campos esperados en `details`:** `error_code`, `error_message`, `attempt_number`, `auth_method`.

#### Vector de Prueba: Evento 3

**JSON Completo:**
```json
{
  "event_id": "0192e2fd-5c8e-7111-b222-3a4b5c6d7e8f",
  "trace_id": "0192e2fd-5c8e-7111-b222-3a4b5c6d7e80",
  "ts": "2026-11-06T15:20:10.000Z",
  "source": "hbbs",
  "category": "conn",
  "action": "conn.fail",
  "actor": {
    "id": "dev_01j00000000000000000000099",
    "actor_type": "device",
    "ip": "10.0.0.88"
  },
  "subject": {
    "id": "dev_01j00000000000000000000002",
    "subject_type": "device",
    "name": "PC-CONTABILIDAD"
  },
  "outcome": "failure",
  "details": {
    "error_code": "AUTH_PASSWORD_INVALID",
    "error_message": "Credenciales de conexión incorrectas",
    "attempt_number": 1,
    "auth_method": "password_preset"
  },
  "prev_hash": "59a485effb765f553590d51fbcc9c3e8f0dcc8910d36c4c72dc322a3c4e12b87",
  "hash": "a3627d1b6ad042130ff846cd6de7aa0a0da77037b10b0e421909aba8db9809b8"
}
```
**`hash` calculado:** `a3627d1b6ad042130ff846cd6de7aa0a0da77037b10b0e421909aba8db9809b8`

---

### 6.6 `file.transfer` — Transferencia de Archivos

- **Emisor (`source`):** `client`.
- **Categoría (`category`):** `file`.
- **Condición:** Envío o descarga completada de un archivo durante la sesión (modo dedicado o copiar/pegar).
- **Campos esperados en `details`:** `direction` (`upload`, `download`), `remote_path`, `file_name`, `bytes_transferred`, `sha256` (hash SHA-256 del fichero transferido), `transfer_mode` (`dedicated_session`, `clipboard_copy_paste`).
- **Compatibilidad con el cliente heredado (`POST /api/audit/file`):** el cliente envía `type` (0 = `upload`, 1 = `download`), `path`, `bytes`, `sha256` y un `info` con la lista de archivos. La API mapea `path` a `remote_path`, toma `file_name` de la lista o del nombre del fichero, y usa `info.files[].size` como volumen cuando `bytes` no viene. Si `path` está vacío, `transfer_mode` es `clipboard_copy_paste`. Un `sha256` con formato distinto de 64 hexadecimales se rechaza con HTTP 400. El parche del cliente calcula el hash solo cuando el evento cubre un único fichero con ruta local resoluble; los lotes multiarchivo llevan volumen pero no hash.

#### Vector de Prueba: Evento 4

**JSON Completo:**
```json
{
  "event_id": "0192e2fe-8f0a-7444-8888-112233445566",
  "trace_id": "0192e2fb-3d5a-7182-9654-2c7da197824b",
  "ts": "2026-11-06T15:08:45.000Z",
  "source": "client",
  "category": "file",
  "action": "file.transfer",
  "actor": {
    "id": "usr_01j00000000000000000000001",
    "actor_type": "user",
    "name": "admin",
    "ip": "192.168.1.50"
  },
  "subject": {
    "id": "dev_01j00000000000000000000002",
    "subject_type": "device",
    "name": "PC-CONTABILIDAD"
  },
  "outcome": "success",
  "details": {
    "direction": "upload",
    "remote_path": "C:\\Sistemas\\Contabilidad\\Update.msi",
    "file_name": "Update.msi",
    "bytes_transferred": 48924160,
    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "transfer_mode": "dedicated_session"
  },
  "prev_hash": "a3627d1b6ad042130ff846cd6de7aa0a0da77037b10b0e421909aba8db9809b8",
  "hash": "e376d334a9656490ed36e0dbe238b5e9a91a978d07d862c5066312c953d63b46"
}
```
**`hash` calculado:** `e376d334a9656490ed36e0dbe238b5e9a91a978d07d862c5066312c953d63b46`

---

### 6.7 `auth.login` — Autenticación Exitosa en la API / Consola

- **Emisor (`source`):** `api`.
- **Categoría (`category`):** `auth`.
- **Condición:** Un usuario completa satisfactoriamente su login en la consola o API.
- **Campos esperados en `details`:** `auth_type` (`credentials`, `credentials_2fa`, `sso_oidc`), `user_agent`, `token_id` (identificador opaco del token emitido).

#### Vector de Prueba: Evento 5

**JSON Completo:**
```json
{
  "event_id": "0192e2ff-1111-7000-9000-abcdef012345",
  "trace_id": "0192e2ff-1111-7000-9000-abcdef012340",
  "ts": "2026-11-06T14:55:00.000Z",
  "source": "api",
  "category": "auth",
  "action": "auth.login",
  "actor": {
    "id": "usr_01j00000000000000000000001",
    "actor_type": "user",
    "name": "admin",
    "ip": "192.168.1.50"
  },
  "outcome": "success",
  "details": {
    "auth_type": "credentials_2fa",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CercanoWeb/1.0",
    "token_id": "tok_998877665544332211"
  },
  "prev_hash": "e376d334a9656490ed36e0dbe238b5e9a91a978d07d862c5066312c953d63b46",
  "hash": "3cc2f1e47d412cee62efd5bb2c4a4a6733c0a77536a76eb2d83782b6762d603e"
}
```
**`hash` calculado:** `3cc2f1e47d412cee62efd5bb2c4a4a6733c0a77536a76eb2d83782b6762d603e`

---

### 6.8 `auth.fail` — Intento Fallido de Autenticación en la API

- **Emisor (`source`):** `api`.
- **Categoría (`category`):** `auth`.
- **Condición:** Solicitud de login con credenciales erróneas o 2FA inválido.
- **Campos esperados en `details`:** `attempted_username`, `reason` (`invalid_password`, `invalid_2fa`, `account_locked`), `attempt_count`.

#### Vector de Prueba: Evento 6

**JSON Completo:**
```json
{
  "event_id": "0192e300-2222-7000-9000-abcdef012346",
  "trace_id": "0192e300-2222-7000-9000-abcdef012341",
  "ts": "2026-11-06T14:54:12.000Z",
  "source": "api",
  "category": "auth",
  "action": "auth.fail",
  "actor": {
    "id": "usr_unknown_invitado",
    "actor_type": "user",
    "ip": "192.168.1.199"
  },
  "outcome": "denied",
  "details": {
    "attempted_username": "invitado",
    "reason": "invalid_password",
    "attempt_count": 3
  },
  "prev_hash": "3cc2f1e47d412cee62efd5bb2c4a4a6733c0a77536a76eb2d83782b6762d603e",
  "hash": "4b97c4f8f2e34c9ca78b343c990c334177376ba6048e7075ab2129eb5f0f84cb"
}
```
**`hash` calculado:** `4b97c4f8f2e34c9ca78b343c990c334177376ba6048e7075ab2129eb5f0f84cb`

---

### 6.9 `auth.logout` — Cierre de Sesión de Usuario

- **Emisor (`source`):** `api`.
- **Categoría (`category`):** `auth`.
- **Condición:** Desconexión voluntaria o revocación de token.
- **Campos esperados en `details`:** `reason` (`user_requested`, `session_expired`, `admin_forced`), `token_id`.

#### Vector de Prueba: Evento 7

**JSON Completo:**
```json
{
  "event_id": "0192e301-3333-7000-9000-abcdef012347",
  "trace_id": "0192e2ff-1111-7000-9000-abcdef012340",
  "ts": "2026-11-06T15:40:00.000Z",
  "source": "api",
  "category": "auth",
  "action": "auth.logout",
  "actor": {
    "id": "usr_01j00000000000000000000001",
    "actor_type": "user",
    "name": "admin",
    "ip": "192.168.1.50"
  },
  "outcome": "success",
  "details": {
    "reason": "user_requested",
    "token_id": "tok_998877665544332211"
  },
  "prev_hash": "4b97c4f8f2e34c9ca78b343c990c334177376ba6048e7075ab2129eb5f0f84cb",
  "hash": "d30f6d5a768d42dcd34a7c1183bf227907e52bc4b8d960818f362d92cbba69f8"
}
```
**`hash` calculado:** `d30f6d5a768d42dcd34a7c1183bf227907e52bc4b8d960818f362d92cbba69f8`

---

### 6.10 `console.rotate_key` — Rotación de Clave Criptográfica

- **Emisor (`source`):** `console`.
- **Categoría (`category`):** `console`.
- **Condición:** Un administrador ejecuta la rotación programada o de emergencia de la clave pública del servidor rendezvous / relay.
- **Campos esperados en `details`:** `key_type` (`ed25519`), `previous_public_key_fingerprint`, `new_public_key` (clave pública en Base64), `rotation_reason`.

#### Vector de Prueba: Evento 8

**JSON Completo:**
```json
{
  "event_id": "0192e302-4444-7000-9000-abcdef012348",
  "trace_id": "0192e302-4444-7000-9000-abcdef012342",
  "ts": "2026-11-06T16:00:00.000Z",
  "source": "console",
  "category": "console",
  "action": "console.rotate_key",
  "actor": {
    "id": "usr_01j00000000000000000000001",
    "actor_type": "user",
    "name": "admin",
    "ip": "192.168.1.50"
  },
  "subject": {
    "id": "key_server_ed25519_2026",
    "subject_type": "setting",
    "name": "Servidor Rendezvous Clave Pública"
  },
  "outcome": "success",
  "details": {
    "key_type": "ed25519",
    "previous_public_key_fingerprint": "SHA256:d41d8cd98f00b204e9800998ecf8427e",
    "new_public_key": "kQ9bE4zXkX2+k7yZ+M8v9oP+wR3tY2uI1oP0aS4dF5g=",
    "rotation_reason": "periodic_scheduled_rotation"
  },
  "prev_hash": "d30f6d5a768d42dcd34a7c1183bf227907e52bc4b8d960818f362d92cbba69f8",
  "hash": "f86b48eb67e5ccb0aadcaf349492a60291742358f2e0ce565b21ea1aa7a1ac94"
}
```
**`hash` calculado:** `f86b48eb67e5ccb0aadcaf349492a60291742358f2e0ce565b21ea1aa7a1ac94`

---

### 6.11 `console.user_create` — Creación de Usuario Administrativo u Operador

- **Emisor (`source`):** `console`.
- **Categoría (`category`):** `console`.
- **Condición:** Un administrador da de alta un nuevo usuario en la consola web.
- **Campos esperados en `details`:** `username`, `email`, `role`, `enforce_2fa`, `group_ids`.

#### Vector de Prueba: Evento 9

**JSON Completo:**
```json
{
  "event_id": "0192e303-5555-7000-9000-abcdef012349",
  "trace_id": "0192e303-5555-7000-9000-abcdef012343",
  "ts": "2026-11-06T16:05:00.000Z",
  "source": "console",
  "category": "console",
  "action": "console.user_create",
  "actor": {
    "id": "usr_01j00000000000000000000001",
    "actor_type": "user",
    "name": "admin",
    "ip": "192.168.1.50"
  },
  "subject": {
    "id": "usr_01j00000000000000000000088",
    "subject_type": "user",
    "name": "operador_red"
  },
  "outcome": "success",
  "details": {
    "username": "operador_red",
    "email": "operador@cercano.local",
    "role": "operator",
    "enforce_2fa": true,
    "group_ids": [
      "grp_soporte_nivel1"
    ]
  },
  "prev_hash": "f86b48eb67e5ccb0aadcaf349492a60291742358f2e0ce565b21ea1aa7a1ac94",
  "hash": "52b6899dcacb082b38551704223eb15d2dd70b654c575df3abdfe41039b1842b"
}
```
**`hash` calculado:** `52b6899dcacb082b38551704223eb15d2dd70b654c575df3abdfe41039b1842b`

---

### 6.12 `alarm.ip_burst` — Disparo de Alarma por Ráfaga de Tráfico Anómala

- **Emisor (`source`):** `api` (Motor de alarmas).
- **Categoría (`category`):** `alarm`.
- **Condición:** Detección de ráfagas anómalas de peticiones o conexiones procedentes de una misma IP o prefijo IPv6.
- **Campos esperados en `details`:** `alarm_name`, `source_prefix`, `rate_detected_per_minute`, `threshold`, `mitigation_action`, `block_duration_minutes`.

#### Vector de Prueba: Evento 10

**JSON Completo:**
```json
{
  "event_id": "0192e304-6666-7000-9000-abcdef01234a",
  "trace_id": "0192e304-6666-7000-9000-abcdef012344",
  "ts": "2026-11-06T16:10:00.000Z",
  "source": "api",
  "category": "alarm",
  "action": "alarm.ip_burst",
  "actor": {
    "id": "sys_rate_limiter",
    "actor_type": "system",
    "name": "AlarmEngine"
  },
  "subject": {
    "id": "ip_subnet_2001_db8",
    "subject_type": "system",
    "name": "2001:db8:cafe::/48"
  },
  "outcome": "denied",
  "details": {
    "alarm_name": "ALM_BURST_IPV6",
    "source_prefix": "2001:db8:cafe::/48",
    "rate_detected_per_minute": 185,
    "threshold": 60,
    "mitigation_action": "temporary_block_prefix",
    "block_duration_minutes": 30
  },
  "prev_hash": "52b6899dcacb082b38551704223eb15d2dd70b654c575df3abdfe41039b1842b",
  "hash": "618dc72b0e9b6bdda3ae925602bc58b26ca91ac7f55371592f6da1a8fbfff719"
}
```
**`hash` calculado:** `618dc72b0e9b6bdda3ae925602bc58b26ca91ac7f55371592f6da1a8fbfff719`

---

### 6.13 `alarm.scope_violation` — Intento de Acceso Fuera de Alcance

- **Emisor (`source`):** `hbbs`.
- **Categoría (`category`):** `alarm`.
- **Condición:** Un operador intenta conectarse a un dispositivo fuera del alcance asignado a su grupo.
- **Campos esperados en `details`:** `alarm_name`, `reason`, `user_group`, `required_permission`, `action_attempted`.

#### Vector de Prueba: Evento 11

**JSON Completo:**
```json
{
  "event_id": "0192e305-7777-7000-9000-abcdef01234b",
  "trace_id": "0192e305-7777-7000-9000-abcdef012345",
  "ts": "2026-11-06T16:15:22.000Z",
  "source": "hbbs",
  "category": "alarm",
  "action": "alarm.scope_violation",
  "actor": {
    "id": "usr_01j00000000000000000000088",
    "actor_type": "user",
    "name": "operador_red",
    "ip": "192.168.1.120"
  },
  "subject": {
    "id": "dev_01j99999999999999999999999",
    "subject_type": "device",
    "name": "SRV-DATACENTER-CORE"
  },
  "outcome": "denied",
  "details": {
    "alarm_name": "ALM_SCOPE_VIOLATION",
    "reason": "user_group_not_authorized_for_target_device",
    "user_group": "grp_soporte_nivel1",
    "required_permission": "device:connect:datacenter",
    "action_attempted": "conn.start"
  },
  "prev_hash": "618dc72b0e9b6bdda3ae925602bc58b26ca91ac7f55371592f6da1a8fbfff719",
  "hash": "ce022af42a607d56643dae5beca21b8d3e0db7d830884850e7c436421d34bd42"
}
```
**`hash` calculado:** `ce022af42a607d56643dae5beca21b8d3e0db7d830884850e7c436421d34bd42`

---

### 6.14 `build.installer_generated` — Generación de Instalador Personalizado

- **Emisor (`source`):** `builder` (`cercano-builder`).
- **Categoría (`category`):** `build`.
- **Condición:** Finalización exitosa de un trabajo de empaquetado y firma de instalador cliente personalizado con configuración embebida.
- **Campos esperados en `details`:** `target_os`, `profile_name`, `embedded_server_host`, `binary_sha256`, `signature_status`, `signature_key_id`, `build_duration_ms`.

#### Vector de Prueba: Evento 12

**JSON Completo:**
```json
{
  "event_id": "0192e306-8888-7000-9000-abcdef01234c",
  "trace_id": "0192e306-8888-7000-9000-abcdef012346",
  "ts": "2026-11-06T16:20:00.000Z",
  "source": "builder",
  "category": "build",
  "action": "build.installer_generated",
  "actor": {
    "id": "usr_01j00000000000000000000001",
    "actor_type": "user",
    "name": "admin",
    "ip": "192.168.1.50"
  },
  "subject": {
    "id": "pkg_cercano_win_x64_v130",
    "subject_type": "installer",
    "name": "cercano-setup-x64-v1.3.0.exe"
  },
  "outcome": "success",
  "details": {
    "target_os": "windows-x64",
    "profile_name": "perfil_lan_oficinas",
    "embedded_server_host": "cercano.local",
    "binary_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "signature_status": "signed",
    "signature_key_id": "key_code_sign_2026",
    "build_duration_ms": 1845
  },
  "prev_hash": "ce022af42a607d56643dae5beca21b8d3e0db7d830884850e7c436421d34bd42",
  "hash": "56cb8604287e301cacd764bc2ea89f45cbf42a6fed993036faf380eecb01f621"
}
```
**`hash` calculado:** `56cb8604287e301cacd764bc2ea89f45cbf42a6fed993036faf380eecb01f621`

---

## 7. Verificación Offline de la Cadena (`cercano-audit verify`)

El algoritmo de verificación implementado en `audit-core` (tarea F2-02) y expuesto mediante la herramienta CLI `cercano-audit verify` (tarea F2-03) sigue los siguientes pasos:

1. **Lectura secuencial:** Recorrer el archivo de eventos (JSON Lines o volcado) de principio a fin.
2. **Validación del génesis:**
   - Para el primer evento $E_0$, comprobar que `prev_hash == "0000000000000000000000000000000000000000000000000000000000000000"`.
3. **Cálculo y comparación de hash:**
   - Excluir del objeto las claves `hash` y `prev_hash`.
   - Serializar el objeto restante a bytes UTF-8 según RFC 8785 (JCS).
   - Computar $\text{SHA-256}(\text{ASCII}(E_i.\text{prev\_hash}) \mathbin{\Vert} \text{JCS\_bytes})$.
   - Comparar el resultado con $E_i.\text{hash}$. Si discrepan, emitir error inmediato `ERR_HASH_MISMATCH` indicando $E_i.\text{event\_id}$ (evidencia de manipulación o corrupción de contenido).
4. **Continuidad de enlace:**
   - Para $i > 0$, verificar que $E_i.\text{prev\_hash} == E_{i-1}.\text{hash}$.
   - Si no coincide, emitir error `ERR_CHAIN_BROKEN` (evidencia de reordenamiento, evento insertado o evento eliminado).
5. **Comprobación de Checkpoint:**
   - Si un checkpoint firmado acompaña al bloque, verificar la firma Ed25519 con la clave pública de auditoría registrada.

---

## 8. Criterios de Aceptación y Checklist de F2-01

- [x] Esquema formal JSON Schema Draft-07 en [`docs/specs/audit-events.schema.json`](file:///c:/Users/alcs/OneDrive%20-%20cercano.local/Documentos/Mis%20Proyectos/Cercano/docs/specs/audit-events.schema.json).
- [x] Validación estricta de sintaxis JSON Schema y compatibilidad de tipos.
- [x] Documentación exhaustiva en [`docs/specs/audit-events.md`](file:///c:/Users/alcs/OneDrive%20-%20cercano.local/Documentos/Mis%20Proyectos/Cercano/docs/specs/audit-events.md) con reglas RFC 8785 (JCS).
- [x] Especificación exacta de la fórmula de hash y bloque génesis de 64 ceros.
- [x] Catálogo con los 12 tipos de eventos requeridos y vectores de prueba numéricamente verificados.
- [x] Regla estricta de seguridad que prohíbe el almacenamiento de contraseñas, secretos, tokens o binarios en `details`.
