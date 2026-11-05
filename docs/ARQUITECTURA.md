# Cercano — Arquitectura y decisiones

**Versión:** 0.2 · **Fecha:** 2026-11-05

## 1. Componentes

```
 Cliente Cercano (Flutter + Rust)
   │        │
   │        └──► cercano-hbbs  (rendezvous/ID)   TCP/UDP 21115–21116
   │             cercano-hbbr  (relay)             TCP 21117
   │   P2P / conexión directa en LAN ◄──► otro cliente
   │
   └── HTTPS ──► cercano-api (control plane)       TCP 21114
                    │   ├─ usuarios, dispositivos, roles
                    │   ├─ ingestión de auditoría ─► audit-core (append-only + hash chain)
                    │   ├─ jobs de build ─────────► cercano-builder ─► artefactos firmados
                    │   └─ exportadores (syslog/CEF/JSONL/webhook)
                    └──► BD (SQLite por defecto / PostgreSQL)

 console-web (SPA) ── HTTPS ──► cercano-api
```

Se conservan los puertos por defecto de upstream (TCP 21114–21119, UDP 21116) para facilitar compatibilidad y documentación.

| Componente | Origen | Lenguaje | Notas |
|---|---|---|---|
| `client/` | Fork de `rustdesk/rustdesk` | Rust + Flutter | Parches mínimos; interfaz principal Flutter (Sciter está obsoleto) |
| `server/` (hbbs, hbbr, utils) | Fork de `rustdesk/rustdesk-server` | Rust | Parches mínimos |
| `control-plane/` (`cercano-api`) | Nuevo | Rust (axum, sqlx) | Equivale funcionalmente al API de Server Pro, implementado clean-room |
| `audit-core/` | Nuevo | Rust (crate) | Núcleo reutilizable: esquema, cadena de hashes, verificación |
| `builder/` (`cercano-builder`) | Nuevo | Rust + scripts CI | Generador de instaladores |
| `console-web/` | Nuevo | TypeScript (SPA) | F4 |
| `deploy/` | Nuevo | Docker, systemd | Compose y unidades |
| `tests/` | Nuevo | Rust/Python/Bash | e2e y laboratorio LAN |
| `branding/` | Nuevo | SVG, PNG, ICO | Logo, iconos y guía de marca (ver `branding/README.md`) |

## 2. Estructura del repositorio

```
cercano/
├── AGENTS.md  README.md  LICENSE  NOTICE  SECURITY.md  CONTRIBUTING.md
├── branding/ (logo, iconos, guía de marca)
├── docs/ (roadmap, planes, adr/, spikes/, status/, specs/, guias/)
├── vendor/ (código de upstream, con commit base documentado)
├── client/  server/  control-plane/  audit-core/  builder/  console-web/
├── deploy/  tests/  tools/
└── patches/  (parches sobre upstream, uno por archivo .patch + índice)
```

## 3. Decisiones de arquitectura (ADR)

| ADR | Decisión | Motivo | Estado |
|---|---|---|---|
| 001 | Monorepo; upstream importado en `vendor/` (subtree) y parches en `patches/` | Un único lugar para agentes y CI; rebase controlado | Propuesto |
| 002 | Control plane en Rust (axum + sqlx) | Mismo lenguaje que el servidor; un solo toolchain; binarios estáticos | Propuesto |
| 003 | SQLite por defecto, PostgreSQL opcional | Despliegues LAN pequeños sin dependencias | Propuesto |
| 004 | Auditoría append-only con cadena de hashes y checkpoints firmados Ed25519 | Evidencia de manipulación verificable offline | Propuesto |
| 005 | Generador: «compilar una vez, configurar muchas» con perfil firmado embebido; recompilación solo para cambios de recursos | Rapidez (segundos en vez de minutos) | Propuesto, depende de S4 |
| 006 | `trace_id` (UUIDv7) generado por el cliente controlador al iniciar sesión y propagado a todos los eventos | Traza extremo a extremo | Propuesto, depende de S5 |
| 007 | Todo el código nuevo bajo AGPL-3.0; clean-room para funciones Pro | Cumplimiento de licencia | Firme |

Los ADR se formalizan en `docs/adr/NNN-titulo.md` al ratificarse en F0-10.

## 4. Modelo de auditoría

**Esquema común de evento (JSON):**

| Campo | Descripción |
|---|---|
| `event_id` | UUIDv7 |
| `trace_id` | Identificador de sesión/operación, común a todos los eventos relacionados |
| `ts` | Marca de tiempo UTC con precisión de milisegundos o mejor |
| `source` | `client`, `hbbs`, `hbbr`, `api`, `console`, `builder` |
| `category` | `conn`, `file`, `alarm`, `console`, `auth`, `build` |
| `action` | Acción específica, p. ej. `conn.start`, `conn.end`, `file.transfer`, `auth.fail` |
| `actor` | Usuario o dispositivo que actúa (ID, nombre, IP) |
| `subject` | Dispositivo/usuario/recurso afectado |
| `outcome` | `success`, `failure`, `denied` |
| `details` | Objeto con campos específicos de la acción |
| `prev_hash`, `hash` | Cadena de integridad |

**Integridad:** `hash = SHA-256(prev_hash ‖ JSON canónico del evento sin los campos de hash)`. Cada N eventos o T minutos se emite un *checkpoint* firmado (Ed25519) con el último hash y el contador. La herramienta `cercano-audit verify` valida cadena y firmas sin necesitar el servidor.

**Cobertura mínima (paridad con Pro):**

- Conexión: tipos Escritorio remoto, Transferencia de archivos, Transferencia de puerto, Cámara, Terminal y «Sin sesión» (autenticación fallida); dispositivo controlado, lado controlador (usuario, ID, nombre, IP), inicio, fin, duración, método de autenticación (confirmación manual, contraseña única, contraseña permanente, cambio de lados) y 2FA, y nota libre.
- Archivos: dirección, ruta en el equipo controlado, tamaño o cantidad (con detalle de los mayores en transferencias múltiples), tanto en sesiones dedicadas como en copiar/pegar durante escritorio remoto.
- Alarmas: acceso fuera de la lista blanca de IP, más de 30 intentos consecutivos, múltiples intentos en un minuto, ráfagas desde un mismo prefijo IPv6, fallos o simultaneidad en logins de Terminal con privilegios, violación del alcance de sesión; en cuentas: más de 30 intentos consecutivos y múltiples intentos en un minuto o una hora.
- Consola: gestión de grupos, usuarios, dispositivos, libreta, roles de admin y de control; login, desconexión de dispositivos, cambios de 2FA y restablecimiento de contraseñas.

**Extras Cercano:** eventos `build.*` (generación, firma y revocación de instaladores), retención configurable y exportación continua a SIEM.

## 5. Hipótesis a validar en F0

| ID | Hipótesis | Spike | Si es falsa |
|---|---|---|---|
| H1 | El cliente OSS ya emite llamadas HTTP de heartbeat/sysinfo al API configurado | S3 | Parche en cliente (F1-08) |
| H2 | El cliente OSS ya genera los datos de auditoría de conexión/archivo/alarma y los envía a un endpoint | S3 | Parche en cliente (F2-05), con mayor esfuerzo |
| H3 | El formato de esas llamadas se puede inferir observando el tráfico del cliente contra un API stub | S3 | Definir protocolo propio y parchear cliente y API |
| H4 | El cliente puede aceptar configuración embebida; la verificación de firma puede apuntar a una clave propia | S4 | Alternativa: compilación por perfil (ADR-005 pasa a recompilar) |
| H5 | Se puede propagar un `trace_id` por rendezvous/relay sin romper compatibilidad | S5 | Correlación por (ID controlador, ID controlado, ventana de tiempo) |

Importante: S3–S5 se hacen observando el **código abierto** del cliente y su tráfico contra nuestro API stub. No se examinan binarios de Server Pro.

## 6. Modelo de amenazas (resumen)

| Amenaza | Ejemplo | Mitigación |
|---|---|---|
| Suplantación | Cliente falso se registra como dispositivo | Claves por dispositivo, tokens firmados, revocación |
| Manipulación | Alterar o borrar registros de auditoría | Append-only, hash chain, checkpoints firmados, copia a SIEM |
| Repudio | Un técnico niega una sesión | Auditoría de origen servidor + cliente, `trace_id` |
| Divulgación | Robo de instalador con claves embebidas | Perfiles con claves de menor privilegio, revocación, caducidad |
| Denegación | Inundación de intentos de conexión | Alarmas y limitación de tasa |
| Elevación | Técnico accede fuera de su alcance | Control de acceso por rol/grupo; alarma de violación de alcance |
| Cadena de suministro | Dependencia comprometida | `cargo-deny`, `cargo-audit`, SBOM, builds reproducibles, firma |
| MITM en LAN | Interceptación en red local | Cifrado extremo a extremo del protocolo, verificación de clave del servidor, TLS en API |

Cada fase incluye una revisión de seguridad del Agente-Seguridad (ver `AGENTS.md`).

## 7. Licencia y límites legales

- `rustdesk/rustdesk` y `rustdesk/rustdesk-server` están bajo **AGPL-3.0**. El derivado debe mantenerse en AGPL-3.0 y ofrecer el código fuente a quienes lo usen en red, incluidos los usuarios del servidor.
- **Estado actual:** el `LICENSE` del repo sigue siendo MIT. No se importa código de upstream hasta reemplazarlo por el texto oficial de AGPL-3.0 (bloqueo B-001 en `docs/status/BLOCKERS.md`; se comprueba con `tools/check-license.sh`).
- Mantener avisos de copyright originales y un archivo `NOTICE` con atribución.
- **Marca:** los distribuibles no usan el nombre ni el logo de RustDesk; se describe el origen en `NOTICE` y `README`. El logo de Cercano se usa según `branding/README.md`.
- **Clean-room:** las funciones equivalentes a Server Pro se diseñan desde documentación pública y comportamiento observable del código abierto. Ningún agente descarga, ejecuta, descompila ni inspecciona binarios de Server Pro, ni usa código de procedencia dudosa. Si un agente tiene dudas de procedencia, lo reporta al Coordinador antes de continuar.
- Las dependencias nuevas deben tener licencia compatible con AGPL-3.0; `cargo-deny` lo verifica en CI.

## 8. Compatibilidad con upstream

- Objetivo: mantener compatibilidad de protocolo con clientes upstream cuando sea posible, sin que sea requisito.
- Cada parche a `vendor/` se registra en `patches/INDEX.md` con motivo, archivos y plan de actualización.
- Sincronización con upstream: revisión trimestral (`docs/upstream-sync.md`).
