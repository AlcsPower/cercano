# Cercano — Guía de Despliegue y Empaquetado del Servidor

Este directorio contiene las definiciones de infraestructura y empaquetado para el servidor unificado de Cercano, incluyendo el servidor de señalización/rendezvous (`hbbs`), el servidor de retransmisión/relay (`hbbr`) y la API de plano de control (`cercano-api`).

Cumple con **PLAN-F0-F1.md** (F1-02) y la arquitectura definida en **docs/ARQUITECTURA.md**.

---

## 1. Arquitectura y Puertos de Red

| Servicio | Binario | Protocolo | Puertos | Propósito |
|---|---|---|---|---|
| `cercano-api` | `cercano-api` | TCP | `21114` | API REST de control plane, autenticación, dispositivos y claves |
| `hbbs` | `hbbs` | TCP | `21115` | Prueba de tipo NAT (rendezvous NAT test) |
| `hbbs` | `hbbs` | TCP/UDP | `21116` | Registro de ID, sincronización y heartbeat |
| `hbbr` | `hbbr` | TCP | `21117` | Retransmisión de tráfico remoto (relay) |
| `hbbs` / `hbbr` | — | TCP | `21118` / `21119` | Conexiones WebSocket para clientes web (opcional) |

---

## 2. Volumen Persistente y Gestión de Claves

Los tres servicios comparten el volumen de datos persistente montado en `/opt/cercano/data`:

1. **Par de claves Ed25519 (`id_ed25519` / `id_ed25519.pub`):**
   - `hbbs` genera y lee las claves en el directorio de trabajo compartido (`/opt/cercano/data`).
   - `cercano-api` lee la clave pública desde `/opt/cercano/data/id_ed25519.pub` para exponerla en `GET /api/server/public-key`.
   - Ante rotación vía `POST /api/server/keys/rotate`, `cercano-api` respalda y actualiza el par de claves en `/opt/cercano/data/` con permisos `0600`.
2. **Base de Datos SQLite (`cercano.db`):**
   - Base de datos relacional para usuarios, sesiones, roles y dispositivos administrada por `cercano-api`.
3. **Seguridad y permisos:**
   - Todos los contenedores se ejecutan sin privilegios de `root`, bajo el usuario del sistema `cercano` (UID `1000:1000`).

---

## 3. Despliegue Rápido con Docker Compose

### Prerrequisitos
- Docker Engine 24.0+
- Docker Compose v2.20+

### Arranque del Stack
Desde la raíz del proyecto o desde el directorio `deploy/`:

```bash
# Navegar al directorio deploy
cd deploy

# Construir y levantar los contenedores en segundo plano
docker compose up -d --build
```

### Comprobación de Estado
```bash
# Listar contenedores y estado de healthcheck
docker compose ps

# Ver logs en tiempo real de todos los servicios
docker compose logs -f

# Ver logs de un servicio específico
docker compose logs -f cercano-api
docker compose logs -f hbbs
docker compose logs -f hbbr
```

### Verificación de Operatividad
1. **Healthcheck de la API:**
   ```bash
   curl -f http://localhost:21114/healthz
   # Respuesta esperada: {"status":"ok","version":"0.1.0"}
   ```

2. **Consulta pública de clave Ed25519:**
   ```bash
   curl -s http://localhost:21114/api/server/public-key | jq
   # Respuesta esperada: {"public_key":"...","key_type":"ed25519"}
   ```

3. **Comprobación de puertos de hbbs y hbbr:**
   ```bash
   nc -zvw3 localhost 21115 21116 21117
   ```

---

## 4. Despliegue Bare-Metal con Systemd

Para entornos Linux sin Docker, se proporcionan unidades systemd en `deploy/systemd/`:

1. **Crear usuario y carpetas:**
   ```bash
   sudo groupadd -g 1000 cercano
   sudo useradd -u 1000 -g cercano -d /opt/cercano -s /bin/bash cercano
   sudo mkdir -p /opt/cercano/bin /opt/cercano/data
   sudo chown -R cercano:cercano /opt/cercano
   ```

2. **Copiar binarios compilados:**
   ```bash
   sudo cp target/release/hbbs target/release/hbbr target/release/cercano-api /opt/cercano/bin/
   sudo chmod +x /opt/cercano/bin/*
   ```

3. **Instalar y activar servicios:**
   ```bash
   sudo cp deploy/systemd/cercano-*.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now cercano-hbbr
   sudo systemctl enable --now cercano-hbbs
   sudo systemctl enable --now cercano-api
   ```

---

## 5. Procedimiento de Rotación de Claves

Cuando se ejecute una rotación de claves a través de `cercano-api`:
```bash
# Reiniciar hbbs y hbbr para que tomen las nuevas claves
docker compose restart hbbs hbbr

# O en systemd:
sudo systemctl restart cercano-hbbs cercano-hbbr
```
Consulte `docs/guias/rotacion-claves.md` para detalles completos.
