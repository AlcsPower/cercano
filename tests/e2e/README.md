# Tests E2E — Cercano

Este directorio contiene las suites de pruebas de extremo a extremo (End-to-End) automatizadas de Cercano.

## Suite de Smoke Test (Fase 1 — F1-09)

La suite de smoke test valida la integración completa entre los componentes del núcleo de Cercano:
- **`cercano-api`** (Control plane en Rust Axum, SQLite, endpoints de auth y gestión de dispositivos).
- **`hbbs`** (Servidor de señalización y rendezvous en puertos 21115 y 21116).
- **`hbbr`** (Servidor de retransmisión / relay en puerto 21117).
- **Clientes** (`cercano-client-a` y `cercano-client-b`).

### Ejecución en Windows (PowerShell)

```powershell
# Ejecución estándar (asume servicios activos)
.\tests\e2e\smoke.ps1

# Parámetros personalizados
.\tests\e2e\smoke.ps1 -ApiUrl "http://localhost:21114" -ServerHost "127.0.0.1" -GracePeriodSecs 5 -OutJson "tests/e2e/results.json"

# Con levantado automático de docker-compose
.\tests\e2e\smoke.ps1 -Up -Down
```

### Ejecución en Linux / macOS / CI (Bash)

```bash
# Permisos de ejecución
chmod +x tests/e2e/smoke.sh

# Ejecución estándar
./tests/e2e/smoke.sh

# Con parámetros
./tests/e2e/smoke.sh --api-url=http://127.0.0.1:21114 --server-host=127.0.0.1 --grace-period=5 --out-json=tests/e2e/results.json
```

### Casos de prueba validados

| ID | Nombre | Descripción |
|---|---|---|
| `TC-SMK-01a` | Salud `cercano-api` | `GET /healthz` retorna `{"status":"ok",...}` |
| `TC-SMK-01-Port21114` | Puerto 21114 TCP | Control plane HTTP axum accesible |
| `TC-SMK-01-Port21115` | Puerto 21115 TCP | `hbbs` NAT type test |
| `TC-SMK-01-Port21116` | Puerto 21116 TCP | `hbbs` rendezvous TCP |
| `TC-SMK-01-Port21117` | Puerto 21117 TCP | `hbbr` relay TCP |
| `TC-SMK-01-Port21116-UDP` | Puerto 21116 UDP | `hbbs` rendezvous UDP probing |
| `TC-SMK-02` | Clave pública del servidor | `GET /api/server/public-key` devuelve Ed25519 de 32 bytes |
| `TC-SMK-03a` | Bootstrap admin | `POST /api/auth/bootstrap` aprovisiona admin de forma segura |
| `TC-SMK-03b` | Login admin | `POST /api/auth/login` emite Bearer token seguro |
| `TC-SMK-04a` | Heartbeat Cliente A | Registro inicial de cliente Linux vía `POST /api/devices/heartbeat` |
| `TC-SMK-04b` | Heartbeat Cliente B | Registro inicial de cliente Windows vía `POST /api/devices/heartbeat` |
| `TC-SMK-05` | Inventario de dispositivos | `GET /api/devices` valida presencia y metadatos con estado `online` |
| `TC-SMK-06` | Conectividad Rendezvous/Relay | Puertos 21116 y 21117 simultáneamente operativos |
| `TC-SMK-06-LAN` | Red LAN inter-cliente | Ping directo verificado entre clientes LAN en contenedores |
| `TC-SMK-07` | Transición a offline | Dispositivo inactivo pasa automáticamente a `offline` tras tiempo de gracia |
