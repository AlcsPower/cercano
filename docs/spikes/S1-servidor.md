# Spike S1: Compilación de Cercano Server y Despliegue en Laboratorio LAN

- **ID de Spike:** S1
- **Tarea asociada:** F0-04
- **Fecha:** 2026-11-05
- **Rol:** Agente-Servidor
- **Estado:** Hecho
- **Criterios de Aceptación:** TC-F0-001, TC-F0-002

---

## 1. Resumen Ejecutivo

Este spike valida la hipótesis de viabilidad técnica para compilar y desplegar los servicios centrales de Cercano Server (`hbbs` y `hbbr`) a partir del código fuente importado en `vendor/server` (RustDesk Server 1.1.9).

Se verificó:
1. Compilación limpia y reproducible en contenedor Linux usando Docker multi-etapa (`rust:bookworm` -> `ubuntu:24.04`).
2. Generación automática y persistencia del par de claves Ed25519 (`id_ed25519` y `id_ed25519.pub`) y la base de datos SQLite (`db_v2.sqlite3`).
3. Correcto arranque y escucha de los servidores en los puertos estándar:
   - `hbbs`: 21115 (TCP NAT test), 21116 (TCP/UDP Rendezvous), 21118 (Web console WS).
   - `hbbr`: 21117 (TCP Relay), 21119 (WS Relay).
4. Comunicación y conectividad completa desde clientes en la red LAN (`tests/lab/docker-compose.yml`), verificado mediante el script de pruebas automatizado `.\tests\lab\lab.ps1 smoke`.

---

## 2. Entorno y Toolchain

### 2.1 Toolchain de Compilación (Builder Stage)
- **Imagen base:** `rust:bookworm` (Debian 12 Bookworm, Rust 1.85+)
- **Target:** `x86_64-unknown-linux-gnu`
- **Herramientas:** Cargo & Rustc 1.85+

### 2.2 Dependencias de Sistema Requeridas
| Paquete | Propósito |
|---|---|
| `build-essential` | Compilador C/C++ (`gcc`, `g++`, `make`) para dependencias nativas |
| `pkg-config` | Detección de bibliotecas del sistema para crates de Rust |
| `libssl-dev` | Enlaces a OpenSSL para conexiones seguras |
| `libsodium-dev` | Criptografía Ed25519 requerida por `sodiumoxide` |

*Nota:* `hbb_common` utiliza `protobuf_codegen` en modo `pure()`, por lo que no fue necesario instalar el binario `protoc` del sistema para la generación de protos.

### 2.3 Entorno de Ejecución (Runtime Stage)
- **Imagen base:** `ubuntu:24.04` LTS (Noble Numbat)
- **Librerías dinámicas:** `libssl3`, `libsodium23`, `ca-certificates`
- **Utilidades de red:** `netcat-openbsd`, `iproute2`, `curl`

---

## 3. Métricas de Compilación y Artefactos

### 3.1 Tiempos de Compilación
- **Tiempo de build limpio (`cargo build --release`):** 5 minutos 00 segundos (300.7 segundos).
- **Compilación incremental / cacheada:** < 10 segundos.

### 3.2 Binarios Resultantes y Tamaños
Los binarios fueron compilados en perfil `release` dentro del contenedor:

| Binario | Ruta en Contenedor | Tamaño | Propósito |
|---|---|---|---|
| `hbbs` | `/opt/cercano/bin/hbbs` | 8.5 MB | ID, rendezvous, signaling y administración NAT |
| `hbbr` | `/opt/cercano/bin/hbbr` | 4.9 MB | Servidor de relay de paquetes |
| `rustdesk-utils` | `/opt/cercano/bin/rustdesk-utils` | 608 KB | Herramientas auxiliares |
| **Total** | | **~14.0 MB** | Binarios independientes |

Ambos binarios responden correctamente a las banderas de ayuda `--help` y versión `--version`.

---

## 4. Puertos y Generación de Claves

### 4.1 Matriz de Puertos Activos
| Puerto | Protocolo | Servicio | Función | Verificación |
|---|---|---|---|---|
| 21115 | TCP | `hbbs` | NAT type testing (STUN traversal) | Succeeded (nc) |
| 21116 | TCP | `hbbs` | Rendezvous & heartbeat | Succeeded (nc) |
| 21116 | UDP | `hbbs` | Rendezvous UDP & hole punching | Succeeded (nc -u) |
| 21117 | TCP | `hbbr` | Relay server | Succeeded (nc) |
| 21118 | TCP | `hbbs` | Web console / WebSocket | En escucha |
| 21119 | TCP | `hbbr` | WebSocket Relay | En escucha |

### 4.2 Criptografía y Claves de Servidor
Al primer arranque, `hbbs` detecta la ausencia de claves y ejecuta `gen_sk(wait)` (`src/common.rs:108`):
1. Genera un par de claves Ed25519 (`sign::gen_keypair()`).
2. Escribe la clave privada en `id_ed25519` (88 bytes, Base64).
3. Escribe la clave pública en `id_ed25519.pub` (44 bytes, Base64).
4. Inicializa la base de datos SQLite en `db_v2.sqlite3` (`journal_mode=WAL`).

En las pruebas realizadas en el laboratorio, se generó y verificó la clave pública:
- Clave pública obtenida: `lRHZiVhN0oDD1fsuACtV6S2FOneftReV7m4eUnIEzIQ=`
- Los archivos se almacenan en el volumen persistente montado en `/opt/cercano/data` (`tests/lab/data/server`).

---

## 5. Instrucciones Reproducibles

### 5.1 Compilación de la Imagen Docker
Desde la raíz del repositorio:
```bash
docker build -t cercano-server:latest -f deploy/Dockerfile.server .
```

### 5.2 Despliegue en el Laboratorio LAN
1. Iniciar los servicios del laboratorio (API stub, servidor y clientes Linux):
   ```powershell
   .\tests\lab\lab.ps1 up
   ```
2. Ejecutar la suite de pruebas de humo (smoke test):
   ```powershell
   .\tests\lab\lab.ps1 smoke
   ```
3. Ver logs en tiempo real del servidor:
   ```powershell
   .\tests\lab\lab.ps1 logs cercano-server
   ```
4. Detener el laboratorio:
   ```powershell
   .\tests\lab\lab.ps1 down
   ```

---

## 6. Evidencia de Pruebas

### 6.1 Salida del Smoke Test Automatizado (`.\tests\lab\lab.ps1 smoke`)
```text
==> Verificando endpoint /healthz en API Stub (172.28.0.10 / localhost:21114)...
API Stub OK: {"status":"ok","service":"cercano-api-stub"}
==> Verificando conectividad LAN entre client-linux-1 y client-linux-2...
Ping client-1 -> client-2: OK (172.28.0.22)
==> Verificando puertos del servidor desde client-linux-1 (21115 TCP, 21116 TCP, 21117 TCP, 21116 UDP)...
Connection to 172.28.0.11 21115 port [tcp/*] succeeded!
Connection to 172.28.0.11 21116 port [tcp/*] succeeded!
Connection to 172.28.0.11 21117 port [tcp/*] succeeded!
Connection to 172.28.0.11 21116 port [udp/*] succeeded!
==> Smoke test completado con éxito.
```

### 6.2 Logs de Arranque del Servidor
```text
=== Cercano Server Mock / Runner ===
Ejecutando binarios reales de Cercano Server...
INFO [src/relay_server.rs:82] Listening on tcp :21117
INFO [src/relay_server.rs:84] Listening on websocket :21119
INFO [src/relay_server.rs:87] Start
INFO [src/common.rs:143] Private/public key written to id_ed25519/id_ed25519.pub
INFO [src/peer.rs:84] DB_URL=./db_v2.sqlite3
INFO [src/rendezvous_server.rs:101] Listening on tcp/udp :21116
INFO [src/rendezvous_server.rs:102] Listening on tcp :21115, extra port for NAT test
INFO [src/rendezvous_server.rs:103] Listening on websocket :21118
INFO [src/rendezvous_server.rs:185] Start
```

---

## 7. Hallazgos y Decisiones

1. **Compilación Limpia:** El código de `vendor/server` compila sin parches sobre Rust estable (1.85+). Solo se observaron advertencias de lints menores (`box_pointers` y desuso de `u32::max_value`).
2. **Ubicación de Datos:** Los binarios asumen por defecto el directorio de trabajo actual para almacenar `id_ed25519`, `id_ed25519.pub` y `db_v2.sqlite3`. El entrypoint cambia a `/opt/cercano/data` antes de ejecutarlos para garantizar persistencia en el volumen de Docker.
3. **Desacoplamiento:** Los binarios no requieren `rustdesk-server-pro` ni componentes propietarios; la versión de código abierto es autosuficiente para las funciones de rendezvous y relay.
4. **Siguientes Tareas:**
   - Habilita `F0-08` (Spike S5: `trace_id`).
   - Sienta las bases para `F1-01` (Rebranding mínimo del servidor) y `F1-02` (Empaquetado definitivo con usuario no privilegiado).
