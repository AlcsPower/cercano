# Laboratorio de pruebas LAN de Cercano

Entorno reproducible basado en **Docker Desktop** para pruebas de integración, simulación de tráfico cliente-servidor (Spike S3) y degradación de red (TC-F0-001 y TC-F0-002).

## 1. Topología

Red aislada Docker: `cercano-lan` (`172.28.0.0/16`).

| Servicio | Nombre del contenedor | IP interna | Puertos en host | Propósito |
|---|---|---|---|---|
| API Stub | `cercano-api-stub` | `172.28.0.10` | `21114` | Registra tráfico JSONL y responde `/healthz`, `/api/heartbeat`, etc. |
| Cercano Server | `cercano-server` | `172.28.0.11` | `21115-21117` TCP, `21116` UDP | hbbs (rendezvous) y hbbr (relay) |
| SIEM Sink | `cercano-siem-sink` | `172.28.0.12` | `8088` TCP, `514` UDP | Receptor de auditoría para pruebas TC-F2-040 |
| Cliente Linux 1 | `cercano-client-linux-1` | `172.28.0.21` | — | Ubuntu con `NET_ADMIN` para emulación de red (`tc netem`) |
| Cliente Linux 2 | `cercano-client-linux-2` | `172.28.0.22` | — | Ubuntu para segundo extremo de conexión P2P |

### Clientes Windows en el host
Como Docker Desktop en Windows expone los puertos a `localhost`:
- El cliente Windows de prueba se apunta a:
  - **Servidor ID/Rendezvous:** `127.0.0.1:21116`
  - **Servidor Relay:** `127.0.0.1:21117`
  - **Servidor API:** `http://127.0.0.1:21114`

## 2. Comandos rápidos

### En Windows PowerShell (Docker Desktop)
```powershell
# 1. Levantar el laboratorio (construye imágenes e inicia red)
.\tests\lab\lab.ps1 up

# 2. Ver estado de los contenedores
.\tests\lab\lab.ps1 status

# 3. Ejecutar prueba rápida de conectividad
.\tests\lab\lab.ps1 smoke

# 4. Ver logs en tiempo real del API Stub
.\tests\lab\lab.ps1 logs cercano-api-stub

# 5. Destruir el laboratorio al terminar
.\tests\lab\lab.ps1 down
```

### En Bash / Linux / WSL
```bash
./tests/lab/lab.sh up
./tests/lab/lab.sh smoke
./tests/lab/lab.sh down
```

## 3. Emulación de condiciones de red (Netem)

Para validar la tolerancia a latencia o forzar conexión por relay (TC-F0-002):

```powershell
# Inyectar 100ms de latencia en client-1:
.\tests\lab\lab.ps1 netem latency 100

# Bloquear UDP directo (obliga a la sesión a pasar por el relay hbbr):
.\tests\lab\lab.ps1 netem drop-udp

# Limpiar todas las reglas de red:
.\tests\lab\lab.ps1 netem reset
```

## 4. Inspección de tráfico capturado (Spike S3)

Todas las llamadas HTTP recibidas por el `cercano-api-stub` se registran en:
`tests/lab/data/api-stub/requests.jsonl`

También se pueden consultar vía API:
`curl http://localhost:21114/api/events`
