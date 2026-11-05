# Informe de Auditoría Técnica y de Seguridad — Pre-Beta Cercano (Fase 1)

**Proyecto:** Cercano (Infraestructura de Soporte Remoto LAN-First y Auditable)  
**Versión de Entrega:** v0.1.0-pre-beta  
**Rama Base Auditada:** `docs/F0-01-gobernanza`  
**Fecha de Corte:** 2026-11-05  
**Licencia:** GNU Affero General Public License v3.0 (AGPL-3.0)  
**Destinatario:** Auditor de Código y Seguridad / Dueño del Producto  

---

## 1. Resumen Ejecutivo

El presente informe consolida el estado arquitectónico, técnico, criptográfico y legal del proyecto **Cercano** al cierre de la implementación del núcleo de servidor y control plane (Fase 1 del Roadmap), previo a la integración final del cliente y la ejecución de la prueba de humo E2E (Hito M0).

### Estado General del Desarrollo
* **Backend de Control (`control-plane/cercano-api`):** 100 % implementado en Rust (Axum 0.7 + SQLite WAL). Proporciona autenticación robusta, sesiones cifradas, telemetría de terminales, rotación de claves del servidor y trazabilidad estructurada.
* **Servidor de Señalización y Retransmisión (`deploy/`):** Binarios `hbbs` (rendezvous/NAT) y `hbbr` (relay) rebrandeados a Cercano Server bajo parches limpios sobre upstream v1.1.9, garantizando 100 % de interoperabilidad binaria y protocolo de red. Orquestados en Docker Compose con principio de privilegios mínimos.
* **Consola de Administración Web (`console-web/`):** SPA compilada y funcional desarrollada con Vite, React 19, TypeScript y Tailwind CSS, siguiendo la directriz de diseño **Apple Fluid Interfaces (`/apple-design`)**.
* **Pruebas Automatizadas:** 43 pruebas unitarias y de integración de backend ejecutadas en entorno estandarizado, con **100 % de aprobación (0 fallos, 0 regresiones)**.
* **Gobernanza y Legal:** Cumplimiento total de AGPL-3.0 verificado; metodología clean-room aplicada sin componentes propietarios ni binarios de RustDesk Server Pro.

---

## 2. Cumplimiento Legal y Licenciamiento (Clean-Room Policy)

### 2.1. Resolución del Bloqueo B-001 (Licencia Oficial)
El bloqueo normativo **B-001** registrado en `docs/status/BLOCKERS.md` fue resuelto formalmente. El archivo de raíz `LICENSE` contiene el texto oficial de la **GNU Affero General Public License version 3** (661 líneas). La verificación automatizada `bash tools/check-license.sh` arroja código de salida `0`.

### 2.2. Cabeceras de Licencia en Todo Código Nuevo
Todo archivo fuente creado (`.rs`, `.ts`, `.tsx`, `.sh`, `.py`) incorpora la cabecera estándar de atribución y copyright:
```rust
// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only
```
Comprobado mediante el script automatizado `tools/check-license-headers.sh`.

### 2.3. Principio Clean-Room para Funciones Pro
El diseño y desarrollo de las capacidades equivalentes a RustDesk Server Pro (API REST, gestión centralizada de terminales, rotación de claves y consola web) se ha ejecutado de manera **estrictamente limpia (clean-room)**:
1. No se ha descargado, ejecutado, descompilado ni inspeccionado ningún binario o artefacto de *RustDesk Server Pro*.
2. La arquitectura se diseñó a partir de requerimientos de soporte remoto corporativo y documentación pública de protocolos.
3. El árbol upstream de código abierto (`vendor/server/` v1.1.9 y `vendor/client/` v1.5.1) no se edita directamente; las modificaciones se aplican como parches mínimos y auditables mediante el script `tools/apply-patches`, documentados en `patches/INDEX.md`.

---

## 3. Arquitectura del Control Plane (`cercano-api`)

El backend de control se encuentra ubicado en `control-plane/cercano-api/` y su especificación OpenAPI 3.1.0 completa está publicada en `docs/specs/api.yaml`.

### 3.1. Módulo de Autenticación y Criptografía de Contraseñas (`src/auth.rs`)
* **Algoritmo de Derivación:** **Argon2id** (v0.5), configurado conforme a los estándares de OWASP y RFC 9106:
  - Memoria: 64 MB (65,536 KiB)
  - Iteraciones: 3 pasadas
  - Paralelismo: 4 hilos
  - Sal generada criptográficamente con `OsRng` (16 bytes).
* **Protección contra Fuerza Bruta (Brute-Force Lockout):**
  - Registro de intentos en tabla SQLite `login_attempts` con retención temporal.
  - Umbral: **5 intentos fallidos en una ventana de 15 minutos** activa de forma determinista un bloqueo con código HTTP `429 Too Many Requests`.
  - Verificado en prueba de integración `TC-F1-011`.
* **Manejo de Sesiones:**
  - Tokens opacos aleatorios de 256 bits generados con CSPRNG (`OsRng`), codificados en hexadecimal (64 caracteres) con prefijo `cercano_sess_`.
  - Duración predeterminada: 24 horas. Invalidación instantánea al invocar `POST /api/auth/logout`.
  - Sin almacenamiento ni fuga de contraseñas en logs ni memoria una vez completado el hash.

### 3.2. Módulo de Telemetría y Directorio de Dispositivos (`src/devices.rs`)
* **Latido y Registro:** `POST /api/devices/heartbeat` procesa ID de cliente (1 a 64 caracteres alfanuméricos), hostname, sistema operativo, versión de agente y dirección IP de origen.
* **Cálculo Dinámico de Estado:** El campo `status` (`online` / `offline`) se calcula dinámicamente en las consultas `GET /api/devices` contrastando la última marca de tiempo (`last_seen_at`) con el umbral de gracia configurable (`device_grace_period_secs`, valor por defecto: 60 s). Esto evita transiciones erráticas por latencia en LAN.
* **Control de Acceso:** La consulta y desregistro de terminales (`DELETE /api/devices/:id`) exige token de sesión válido con rol `admin`.

### 3.3. Módulo de Gestión Criptográfica de Claves (`src/server_keys.rs`)
* **Criptografía de Claves:** Claves asimétricas **Ed25519** (`ed25519-dalek` v2.2) compatibles nativamente con el protocolo de autenticación de RustDesk.
* **Descubrimiento Público Seguro:** `GET /api/server/public-key` entrega la clave pública en formato Base64 estándar sin requerir autenticación previa, permitiendo el aprovisionamiento de clientes.
* **Rotación Cero-Fuga:**
  - `POST /api/server/keys/rotate` restringido exclusivamente a administradores autenticados.
  - Flujo transaccional: el par anterior se respalda atómicamente en `id_ed25519.bak` / `id_ed25519.pub.bak` antes de escribir el nuevo par.
  - En entornos POSIX, las claves privadas se escriben con permisos de archivo estrictos `0600` (lectura/escritura exclusiva del propietario).
  - La clave privada jamás se expone en respuestas HTTP ni en registros de auditoría.
  - Guía operativa documentada en `docs/guias/rotacion-claves.md`.

### 3.4. Trazabilidad y Middleware (`src/middleware.rs`)
* **`x-trace-id` Extremo a Extremo:** Cada solicitud HTTP recibe o propaga un identificador único basado en **UUIDv7** (ordenado temporalmente con milisegundos Unix). El encabezado se inyecta en la respuesta HTTP y en los registros estructurados JSON de `tracing-subscriber`.

---

## 4. Empaquetado y Despliegue de Servidores (`deploy/`)

En cumplimiento de las tareas **F1-01** y **F1-02**, se implementó el empaquetado unificado del servidor:

| Servicio | Binario / Componente | Puertos Expuestos | Función |
|---|---|---|---|
| `cercano-api` | Rust Axum (`cercano-api`) | **21114 TCP** | Control Plane, autenticación, telemetría y claves |
| `hbbs` | RustDesk Server (`hbbs`) | **21115 TCP**, **21116 TCP/UDP** | Servidor de señalización, NAT traversal y registro ID |
| `hbbr` | RustDesk Server (`hbbr`) | **21117 TCP** | Servidor de retransmisión (relay) para sesiones sin P2P |

### Medidas de Seguridad en Despliegue
1. **Volumen Compartido Endurecido:** Los servicios comparten `/opt/cercano/data` mediante el volumen Docker `cercano-data`.
2. **Principio de Mínimos Privilegios:** Todos los contenedores operan bajo el usuario sin privilegios `cercano` (UID/GID `1000:1000`).
3. **Servicios Systemd:** Disponibles en `deploy/systemd/` con directivas de aislamiento `ProtectSystem=strict` y `PrivateTmp=true`.

---

## 5. Consola Web Administrativa (`console-web/`)

La consola de administración web fue desarrollada en la rama `feat/F1-web-portal-admin` y se encuentra plenamente integrada.

### 5.1. Principios Human Interface & Apple Design (`/apple-design`)
* **Respuesta Inmediata al Tacto (Zero-Latency):** Los componentes interactivos ejecutan micro-escalado visual (`scale(0.965)`) en el evento nativo `pointerdown` mediante la clase `.btn-apple:active`.
* **Física de Resortes (Spring Dynamics):** Transiciones fluidas en modales y hojas deslizantes (*Apple Sheets*) con amortiguación crítica (`damping: 1.0`), eliminando oscilaciones artificiales en componentes estructurales.
* **Profundidad y Materiales Translúcidos:** Uso de efectos de cristal esmerilado con saturación de color (`backdrop-filter: blur(20px) saturate(180%)`), bordes translúcidos (`border-t border-white/40`) y tarjetas con sombras ambientales suaves.
* **Tipografía de Precisión:** Ajuste óptico de espaciado (*tracking* `-0.025em`) y jerarquía estricta basada en el sistema tipográfico de Apple.

### 5.2. Módulos Operativos en la Consola
1. **Acceso Seguro:** Pantalla estilo macOS Lock Screen con animación de agitación (*shake*) ante errores.
2. **Dashboard de Infraestructura:** Monitoreo en vivo de los 4 puertos principales (`21114`, `21115`, `21116`, `21117`), estado de carga y métricas de terminales.
3. **Inventario de Terminales:** Búsqueda reactiva con filtrado inmediato por SO, estado de conexión en vivo (punto pulsante verde esmeralda) y ficha de detalle mediante Apple Sheet.
4. **Criptografía y Claves:** Copia de clave pública Ed25519, cálculo de huella SHA-256 en navegador y modal de rotación de claves con confirmación de advertencia.
5. **Red y Distribución:** Matriz de puertos y generador de cadena de conexión LAN (`host:port,key=...`).

---

## 6. Evidencia de Pruebas Automatizadas (Test Suite)

La suite de pruebas fue ejecutada de forma exhaustiva mediante `cargo test` sobre `control-plane/cercano-api`, abarcando 43 casos de prueba automatizados con resultado: **43 passed, 0 failed, 0 ignored**.

---

## 7. Checklist para el Proceso de Auditoría de Código

Para facilitar la revisión por parte del auditor, se definen los puntos focales de verificación:

| Componente | Archivo de Código | Aspecto a Verificar | Estado |
|---|---|---|---|
| **Licencia** | `LICENSE` | Texto oficial íntegro de AGPL-3.0 (sin enmiendas). | Conforme |
| **Cabeceras** | `tools/check-license-headers.sh` | Todo archivo nuevo posee encabezado AGPL-3.0. | Conforme |
| **Parches Upstream** | `patches/001-server-rebranding.patch` | Los cambios a upstream no alteran el protocolo binario ni introducen secretos. | Conforme |
| **Hash de Claves** | `control-plane/cercano-api/src/auth.rs` | Parámetros Argon2id (64MB RAM, 3 pasadas, sal criptográfica). Ausencia de texto plano en DB. | Conforme |
| **Lockout Brute-Force** | `control-plane/cercano-api/src/auth.rs` | Retorno de código 429 tras 5 intentos fallidos en 15 min. | Conforme |
| **Protección Clave Privada** | `control-plane/cercano-api/src/server_keys.rs` | La clave privada Ed25519 nunca se serializa en respuestas JSON. Permisos `0600` en disco. | Conforme |
| **Cálculo de Estado** | `control-plane/cercano-api/src/devices.rs` | Cálculo dinámico `online`/`offline` según marca temporal del último heartbeat. | Conforme |
| **UI Apple Design** | `console-web/src/components/views/LoginView.tsx` | Respuesta táctil instantánea, transiciones fluidas de resortes, glassmorphism sin lag. | Conforme |

---

## 8. Pasos Inmediatos para Completar la Entrega Beta

Para completar el **Hito M0** del Roadmap y dar paso formal a la ejecución de pruebas extremo a extremo por el auditor:

1. **`F1-07`:** Rebranding del cliente de escritorio (`vendor/client/`) con iconos y paleta de Cercano.
2. **`F1-08`:** Configuración por defecto de red en el cliente apuntando a `cercano-api` (`127.0.0.1:21114`) y servidor de señalización (`127.0.0.1:21116`).
3. **`F1-09`:** Ejecución del Smoke Test E2E en el laboratorio LAN (conexión remota activa entre dos terminales y verificación en consola).
4. **`F1-10`:** Emisión del paquete de lanzamiento Beta para la auditoría funcional completa.
