# Guía de Procedimiento: Gestión y Rotación de Claves del Servidor

**Código:** GUIA-SEC-001  
**Componentes:** `cercano-api`, `cercano-hbbs`, `cercano-hbbr`  
**Criterio de Aceptación Asociado:** TC-F1-031  
**Licencia:** AGPL-3.0-only  

---

## 1. Fundamentos Criptográficos y Arquitectura

Cercano utiliza criptografía de curvas elípticas basada en **Ed25519** para autenticar las comunicaciones entre clientes y el servidor rendezvous/relay (`hbbs`/`hbbr`):

- **Clave pública (`id_ed25519.pub`):** 32 bytes binarios (256 bits), codificada en formato Base64 estándar (44 caracteres terminados en `=`). Se distribuye a los clientes y es expuesta de forma pública por la API de control.
- **Clave privada / secreta (`id_ed25519`):** 64 bytes binarios (semilla secreta de 32 bytes + clave pública de 32 bytes), codificada en formato Base64 estándar (88 caracteres). Solo reside en el almacenamiento del servidor.

### Reglas críticas de seguridad
> [!CAUTION]
> 1. La clave privada **NUNCA** se expone en la API REST, respuestas HTTP, registros de log estructurado ni mensajes de error.
> 2. En sistemas de archivos tipo POSIX (Linux), el archivo `id_ed25519` debe poseer permisos estrictos `0600` (lectura/escritura exclusiva para el usuario de servicio no privilegiado `cercano`).
> 3. Ninguna clave privada debe ser versionada en repositorios git ni incrustada en imágenes de contenedor docker públicas.

---

## 2. Consulta Pública de Clave del Servidor

Para evitar configuraciones manuales propensas a error, `cercano-api` expone el endpoint público sin autenticación:

```http
GET /api/server/public-key HTTP/1.1
Host: servidor.cercano.lan:21114
```

### Respuesta Exitosa (`200 OK`)
```json
{
  "public_key": "lRHZiVhN0oDD1fsuACtV6S2FOneftReV7m4eUnIEzIQ=",
  "key_type": "ed25519"
}
```

Los clientes de Cercano y la consola web de administración pueden consultar este endpoint para obtener la clave pública activa de manera automática durante el aprovisionamiento.

---

## 3. Procedimiento Operativo de Rotación

La rotación de claves criptográficas debe realizarse periódicamente (p. ej. cada 6 meses) o de forma inmediata ante cualquier sospecha de compromiso del servidor.

### 3.1. Ejecución vía API Administrativa

La rotación está protegida mediante autenticación Bearer y requiere privilegios del rol `admin`.

```bash
# 1. Autenticar como administrador
TOKEN=$(curl -s -X POST http://127.0.0.1:21114/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<CONTRASEÑA_ADMIN>"}' \
  | jq -r .token)

# 2. Solicitar la rotación de claves
curl -s -X POST http://127.0.0.1:21114/api/server/keys/rotate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"Rotacion programada semestral 2026-S2"}' | jq
```

### Respuesta Exitosa (`200 OK`)
```json
{
  "status": "rotated",
  "public_key": "m7p0Q+6P2pY00eTsvxP8uQ11/f7b0m1c4vF9o+8pP1M=",
  "key_type": "ed25519",
  "rotated_at": "2026-11-05T15:30:00Z",
  "backup_path": "/opt/cercano/data/id_ed25519.pub.bak.20261105_153000"
}
```

### 3.2. Operaciones internas automatizadas por `cercano-api`
1. **Respaldo automático:** Crea copias timestamped de las claves anteriores:
   - `id_ed25519.pub.bak.<TIMESTAMP>`
   - `id_ed25519.bak.<TIMESTAMP>` (con permisos `0600`)
2. **Generación segura:** Genera un nuevo par Ed25519 con generador criptográfico seguro del sistema (`OsRng`) garantizando que la representación Base64 no incluya caracteres conflictivos (`/` o `:`).
3. **Escritura atómica y permisos:** Escribe el nuevo par en disco estableciendo permisos `0600` en la clave privada.
4. **Registro de auditoría:** Genera traza JSON estructurada indicando `admin_id`, `admin_user`, `public_key` nueva y motivo. La clave privada se mantiene estrictamente omitida del log.

### 3.3. Reinicio / Recarga de `hbbs` y `hbbr`
Dado que `hbbs` carga el par de claves al iniciar el proceso, tras la rotación debe recargarse el contenedor o servicio del servidor:

```bash
# Si se utiliza docker-compose:
docker compose restart hbbs hbbr

# Si se utiliza systemd:
sudo systemctl restart cercano-hbbs cercano-hbbr
```

---

## 4. Respaldo Cifrado Fuera de Línea (Offsite Backup)

Los respaldos de claves nunca deben almacenarse en texto plano en medios compartidos. Debe aplicarse cifrado asimétrico o simétrico robusto.

### 4.1. Respaldo Cifrado con GPG (AES-256)
```bash
BACKUP_DIR="/opt/cercano/data"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Crear archivo tar con los respaldos de claves
tar -czf - -C "$BACKUP_DIR" id_ed25519 id_ed25519.pub \
  | gpg --symmetric --cipher-algo AES256 -o "$BACKUP_DIR/keys_backup_${TIMESTAMP}.tar.gz.gpg"

# Asegurar permisos del artefacto cifrado
chmod 0600 "$BACKUP_DIR/keys_backup_${TIMESTAMP}.tar.gz.gpg"
```

### 4.2. Respaldo Cifrado con Age
```bash
# Cifrado hacia clave pública de seguridad institucional
tar -czf - -C "$BACKUP_DIR" id_ed25519 id_ed25519.pub \
  | age -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p \
  -o "$BACKUP_DIR/keys_backup_${TIMESTAMP}.tar.gz.age"
```

---

## 5. Mitigación del Rechazo de Clientes Antiguos (TC-F1-031)

### 5.1. Comportamiento Criptográfico (TC-F1-031)
Cuando la clave del servidor rota, los clientes que intenten establecer sesión utilizando la clave pública anterior experimentarán un fallo en el apretón de manos (*handshake*):
- El servidor `hbbs` firma el reto criptográfico con su nueva clave privada.
- El cliente, al verificar la firma contra la clave pública antigua almacenada en su configuración local, detecta discrepancia de firma y aborta la conexión.
- En el servidor queda registrado el rechazo de conexión por discordancia de clave.

### 5.2. Estrategias de Transición y Mitigación

Para minimizar la interrupción del servicio en la organización:

1. **Aprovisionamiento Dinámico vía API (Recomendado):**
   Los clientes configurados para sincronizar parámetros mediante `GET /api/server/public-key` detectan la nueva clave y actualizan su caché local antes de abrir nuevas sesiones remotas.
2. **Distribución Coordinada por Política Central:**
   En despliegues de dominio Windows (Active Directory / GPO) o Linux (Ansible), la nueva clave pública debe distribuirse en el archivo de configuración del cliente de manera coordinada con la ventana de mantenimiento.
3. **Ventana de Mantenimiento Comunicada:**
   Programar la rotación de claves en horarios de bajo impacto operativo notificando previamente a los operadores de mesa de ayuda.

### 5.3. Procedimiento de Rollback de Emergencia

Si se requiere revertir temporalmente la rotación debido a clientes críticos no actualizados:

```bash
DATA_DIR="/opt/cercano/data"
TIMESTAMP="<TIMESTAMP_DEL_BACKUP>"

# 1. Restaurar copias respaldadas
cp "$DATA_DIR/id_ed25519.pub.bak.$TIMESTAMP" "$DATA_DIR/id_ed25519.pub"
cp "$DATA_DIR/id_ed25519.bak.$TIMESTAMP" "$DATA_DIR/id_ed25519"
chmod 0600 "$DATA_DIR/id_ed25519"

# 2. Reiniciar el servicio servidor
docker compose restart hbbs hbbr || sudo systemctl restart cercano-hbbs

# 3. Validar recuperación en el endpoint
curl -s http://127.0.0.1:21114/api/server/public-key | jq
```
