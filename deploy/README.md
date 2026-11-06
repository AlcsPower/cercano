# Cercano — Guía de Despliegue y Empaquetado del Servidor

Este directorio contiene las definiciones de infraestructura y empaquetado para el stack unificado de Cercano:
1. **Consola Web y Proxy Reverso con TLS (`cercano-web`):** SPA administrativa con Nginx, terminación HTTPS y proxy seguro.
2. **API de Control Plane (`cercano-api`):** API REST de autenticación, directorio de dispositivos y claves Ed25519.
3. **Servidor de Señalización/Rendezvous (`hbbs`):** Descubrimiento de ID, NAT traversal y coordinación de sesiones.
4. **Servidor de Retransmisión/Relay (`hbbr`):** Túnel de retransmisión cifrado para sesiones que no logran conexión directa P2P.

Cumple con **PLAN-F0-F1.md** (F1-02), **docs/ARQUITECTURA.md** y mitiga los hallazgos de seguridad **H6** y **H11**.

---

> [!CAUTION]
> ### Requisito de Seguridad Crítico: TLS en Redes Corporativas (Hallazgo H6)
> En entornos corporativos o redes LAN donde puedan existir equipos no administrados o tráfico interceptable, **el acceso administrativo a la API y a la consola DEBE transitar obligatoriamente bajo TLS (HTTPS)**.
> Por diseño endurecido, `cercano-api` no expone el puerto `21114` en texto plano hacia la red externa (`0.0.0.0`), sino que restringe su enlace a `127.0.0.1` o a la red privada de Docker, canalizando todo el tráfico externo de administración a través de `cercano-web` (puerto 443 HTTPS).
> Si no se proveen certificados corporativos en `deploy/certs/`, Nginx operará en HTTP (puerto 80) para pruebas internas de laboratorio. En producción, monte los certificados corporativos (`cercano.crt` y `cercano.key`).

---

## 1. Arquitectura y Puertos de Red

| Servicio | Binario / Imagen | Protocolo | Puertos | Propósito |
|---|---|---|---|---|
| `cercano-web` | `nginx:1.27-alpine` | TCP | `80` (HTTP), `443` (HTTPS) | Consola web SPA y terminación TLS para `cercano-api` |
| `cercano-api` | `cercano-api` | TCP | `127.0.0.1:21114` (local) | API REST de control plane, autenticación y dispositivos |
| `hbbs` | `cercano-server` | TCP | `21115` | Prueba de tipo NAT (rendezvous NAT test) |
| `hbbs` | `cercano-server` | TCP/UDP | `21116` | Registro de ID, sincronización y heartbeat |
| `hbbr` | `cercano-server` | TCP | `21117` | Retransmisión de tráfico remoto (relay) |
| `hbbs` / `hbbr` | `cercano-server` | TCP | `21118` / `21119` | Conexiones WebSocket para clientes web (opcional) |

---

## 2. Volumen Persistente y Gestión de Claves

Los servicios comparten el volumen de datos persistente montado en `/opt/cercano/data`:

1. **Par de claves Ed25519 (`id_ed25519` / `id_ed25519.pub`):**
   - `hbbs` genera y lee las claves en el directorio de trabajo compartido (`/opt/cercano/data`).
   - `cercano-api` lee la clave pública desde `/opt/cercano/data/id_ed25519.pub` para exponerla en `GET /api/server/public-key`.
   - Ante rotación vía `POST /api/server/keys/rotate`, `cercano-api` respalda y actualiza el par de claves en `/opt/cercano/data/` con permisos `0600`.
2. **Base de Datos SQLite (`cercano.db`):**
   - Base de datos relacional para usuarios, sesiones, roles y dispositivos administrada por `cercano-api`.
3. **Seguridad y permisos:**
   - Todos los contenedores de backend se ejecutan sin privilegios de `root`, bajo el usuario del sistema `cercano` (UID `1000:1000`).

---

## 3. Despliegue Rápido con Docker Compose

### Prerrequisitos
- Docker Engine 24.0+
- Docker Compose v2.20+

### Paso 1: Configurar Certificados TLS (Recomendado)
Para activar HTTPS en la consola administrativa, coloque su certificado y clave privada en el subdirectorio `deploy/certs/`:
```bash
mkdir -p deploy/certs
# Ejemplo para generar certificado autofirmado para pruebas LAN:
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout deploy/certs/cercano.key \
  -out deploy/certs/cercano.crt \
  -subj "/CN=cercano.lan/O=Cercano/C=NI"
```

### Paso 2: Arranque del Stack
Desde la raíz del proyecto o desde el directorio `deploy/`:
```bash
cd deploy
docker compose up -d --build
```

### Paso 3: Verificación
Verifique que los 4 contenedores estén en estado saludable (`healthy` o `running`):
```bash
docker compose ps
```
Acceso a la Consola Web:
- **HTTPS:** `https://<IP-DEL-SERVIDOR>/` (o `http://<IP-DEL-SERVIDOR>/` en puerto 80).
