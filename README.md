<p align="center">
  <img src="branding/logo/cercano-wordmark-light.svg" alt="Cercano" height="72">
</p>

<p align="center"><em>Soporte remoto, como si estuvieras ahí.</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/Licencia-AGPL--3.0-blue.svg" alt="Licencia AGPL-3.0">
  <img src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/React-18-61dafb.svg" alt="React 18">
  <img src="https://img.shields.io/badge/Tests-194%20passing-brightgreen.svg" alt="Tests Status">
</p>

---

# Cercano

**Cercano** es una plataforma integral de soporte y asistencia remota para equipos de TI e instituciones: **auditable**, **segura por defecto**, **optimizada para redes corporativas/LAN** y concebida con **código 100% abierto**.

Ofrece las capacidades empresariales que tradicionalmente se reservan a versiones de pago en herramientas propietarias (como RustDesk Server Pro), centrándose en cuatro pilares:
1. **Auditoría inmutable con integridad demostrable**: Cada sesión, comando, transferencia de archivos y evento administrativo se firma y sella en una cadena criptográfica de hashes con checkpoints Ed25519 verificables sin conexión al servidor.
2. **Trazabilidad de extremo a extremo (`trace_id`)**: Correlación temporal y operativa precisa entre el cliente, el servidor de señalización/relay y la consola de gestión.
3. **Generador y empaquetador de instaladores personalizados (Hito M2)**: Compilación reproducible de instaladores Windows (`.exe` y `.msi`) configurados por rol (`soporte` vs `tecnico`), con firma digital Authenticode enchufable, listas de materiales de software (SBOM CycloneDX/SPDX) y verificación de procedencia.
4. **Seguridad y roles aplicados en el servidor (ADR-008)**: El servidor valida de forma inmutable el tipo de instalador (`installer_id`), bloqueando cualquier intento de inicio de conexiones o escalada no autorizada desde clientes de soporte y disparando alarmas de seguridad críticas.

> 🚀 **Estado del Proyecto: Fase 3 avanzada (Hito M2: Generador de instaladores personalizados).**  
> Fases 0 (Fundación), 1 (Núcleo y Paridad Básica) y 2 (Auditoría y Traza Inmutable) completadas. Consulta el detalle en [`docs/status/TAREAS.md`](docs/status/TAREAS.md) y [`docs/ROADMAP.md`](docs/ROADMAP.md).  
> **Rama principal de trabajo y coordinación:** [`docs/F0-01-gobernanza`](https://github.com/AlcsPower/cercano/tree/docs/F0-01-gobernanza).

---

## Componentes y Arquitectura

El monorepo está organizado en módulos desacoplados y libres de dependencias propietarias:

```
cercano/
├── builder/
│   └── cercano-build/    # CLI y generador de paquetes Windows (.exe/.msi), Authenticode, SBOM y procedencia
├── control-plane/
│   ├── audit-core/       # Crate Rust: Cadena criptográfica SHA-256 (RFC 8785) con DB SQLite append-only
│   ├── cercano-api/      # API REST: Auth Argon2id, cola de compilación, revocación, sesiones y alarmas
│   └── cercano-audit/    # Herramienta CLI: Exportación y verificación forense fuera de línea
├── console-web/          # Consola Web administrativa: React 18 + Vite + Tailwind CSS (Diseño Apple/Emil)
├── vendor/               # Código base del cliente y servidor gestionado bajo parches limpios e idempotentes
├── patches/              # Parches modulares con gobernanza estricta (001 a 006) per AGENTS.md
├── branding/             # Guía de marca, logotipos oficiales (SVG/PNG) e iconos de instalador (.ico)
├── docs/                 # Documentación técnica, especificaciones RFC, guías de despliegue y ADRs
└── tools/                # Utilidades de desarrollo, scripts de parches y verificación de licencias AGPL-3.0
```

---

## Capacidades Implementadas

| Capacidad | Descripción | Componente | Estado |
|---|---|---|---|
| **Cadena Criptográfica de Auditoría** | Registro append-only con serialización canónica RFC 8785, ligada a un bloque génesis mediante SHA-256 y protegida contra escritura/borrado en SQLite. | `audit-core` | ✅ Producción |
| **Checkpoints Firmados & Verificador CLI** | Creación periódica de checkpoints firmados con Ed25519 y CLI `cercano-audit` para verificación independiente de integridad en archivos JSONL. | `cercano-audit` | ✅ Producción |
| **Correlación de Traza (`trace_id`)** | Agregación de eventos y métricas de sesión (duración exacta, bytes transferidos, archivos) a través de `GET /api/audit/traces/:trace_id`. | `cercano-api` | ✅ Producción |
| **Motor de Alarmas en Tiempo Real** | Detección automática en ventana deslizante para fuerza bruta, ráfagas de IP, violaciones de lista blanca CIDR y violación de roles. | `cercano-api` | ✅ Producción |
| **Consola Web Administrativa** | UI moderna, accesible, con fuentes auto-hospedadas (100% offline), tema claro/oscuro de alto contraste y previsualizador interactivo. | `console-web` | ✅ Producción |
| **Generador CLI `cercano-build`** | Compilación y empaquetado reproducible (Estrategia A) a partir de perfiles JSON validados bajo JSON Schema y firmados con Ed25519. | `cercano-build` | ✅ Producción |
| **Empaquetado Windows (.exe y .msi)** | Generación de instaladores `.exe` auto-extraíbles y paquetes `.msi` (WiX v4/CFBF) con UpgradeCodes estables y desinstalación limpia. | `cercano-build` | ✅ Producción |
| **Firma Authenticode Enchufable** | Firma digital con soporte para drivers `signtool`, `osslsigncode` y `mock`, con sello de tiempo RFC 3161 obligatorio y aborto atómico. | `cercano-build` | ✅ Producción |
| **Servicio de Compilación en API** | Endpoints `POST /api/builds`, cola asíncrona, control de concurrencia semafórico, almacenamiento y retención con RBAC estricto. | `cercano-api` | ✅ Producción |
| **Auditoría Encadenada `build.*`** | Trazabilidad completa de generación de instaladores: `build.requested`, `build.started`, `build.completed`, `build.downloaded`, `build.revoked`. | `cercano-api` | ✅ Producción |
| **Revocación y Caducidad Inmediata** | Publicación de listas de revocación con caché HTTP y ETag; rechazo fulminante de dispositivos revogados o caducados (< 60 s). | `cercano-api` | ✅ Producción |
| **SBOM y Atestación de Procedencia** | Generación de SBOMs estándar CycloneDX (v1.5) y SPDX (v2.3) con hash reproducible exacto en `SHA256SUMS` y `build-provenance.json`. | `cercano-build` | ✅ Producción |
| **Enforcement de Roles en Servidor** | Mitigación autoritativa (ADR-008): el servidor bloquea el inicio de conexiones desde instaladores `soporte` y dispara `alarm.role_violation`. | `cercano-api` | ✅ Producción |
| **Guía de Despliegue Masivo** | Documentación exhaustiva para despliegues empresariales mediante GPO, Microsoft Intune, RMM, exclusiones EDR y scripts de validación. | `docs/guias/` | ✅ Producción |

---

## Requisitos Previos

- **Rust**: 1.75 o superior (con `cargo`)
- **Node.js**: v18.0 o superior (con `npm` 9+)
- **SQLite3**: Incluido o disponible en el sistema
- **Linux / WSL / macOS / Windows**

---

## Inicio Rápido (Desarrollo Local)

### 1. Clonar el repositorio
```bash
git clone -b docs/F0-01-gobernanza https://github.com/AlcsPower/cercano.git
cd cercano
```

### 2. Ejecutar la suite de pruebas del backend (Rust)
Todas las pruebas del core criptográfico, API, generador y CLI pueden ejecutarse con:
```bash
cargo test --workspace
```
*(194 pruebas unitarias y de integración garantizan el funcionamiento y la resistencia contra manipulación).*

### 3. Ejecutar la Consola Web
```bash
cd console-web
npm install
npm run dev
```
La consola estará disponible en `http://localhost:3000`.

### 4. Generar un instalador con `cercano-build`
```bash
# Compilar el CLI generador
cargo build --release -p cercano-build

# Generar instalador para rol soporte con SBOM y firma
./target/release/cercano-build \
  --profile perfiles/soporte.json \
  --out dist/ \
  --package-windows \
  --sbom
```

### 5. Verificar una traza de auditoría con el CLI
```bash
# Exportar base de datos a formato JSONL canónico
cargo run -p cercano-audit -- export-db /ruta/a/audit.db eventos.jsonl

# Verificar la validez de la cadena de hashes y las firmas Ed25519
cargo run -p cercano-audit -- verify eventos.jsonl --pubkey <CLAVE_PUBLICA_HEX>
```

---

## Especificaciones y Gobernanza

- **ADR-008 — Roles de Instalador:** Decisión arquitectónica rectora: *«El rol se aplica en el servidor, no solo en el instalador»* ([`docs/adr/008-roles-instalador.md`](docs/adr/008-roles-instalador.md)).
- **Guía de Despliegue Masivo:** Guía técnica para GPO, Microsoft Intune, herramientas RMM y parámetros silenciosos ([`docs/guias/despliegue-masivo.md`](docs/guias/despliegue-masivo.md)).
- **Guía de Empaquetado Windows:** Especificación de instaladores `.exe` y paquetes `.msi` ([`docs/guias/empaquetado-windows.md`](docs/guias/empaquetado-windows.md)).
- **Cercano Chat (F4.5):** Chat de soporte embebido en el cliente y gestionado desde la consola; contrato en [`docs/specs/chat.md`](docs/specs/chat.md), plan en [`docs/PLAN-F4.5-CHAT.md`](docs/PLAN-F4.5-CHAT.md) y decisión en [`docs/adr/010-cercano-chat.md`](docs/adr/010-cercano-chat.md).
- **Esquema de Eventos de Auditoría**: Especificado formalmente bajo JSON Schema Draft-07 en [`docs/specs/audit-events.schema.json`](docs/specs/audit-events.schema.json) y detallado en [`docs/specs/audit-events.md`](docs/specs/audit-events.md).
- **Reglas de Trabajo para Agentes y Colaboradores**: Consulta [`AGENTS.md`](AGENTS.md).
- **Seguridad y Clean-Room**: Prohibición estricta de ingeniería inversa o descompilación de binarios comerciales. Cercano se construye bajo el principio *clean-room* a partir de documentación pública y estándares abiertos. Consulta [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md).

---

## Licencia

Cercano se distribuye bajo los términos de la **GNU Affero General Public License v3.0 (AGPL-3.0)**. Consulta el archivo [`LICENSE`](LICENSE) para ver los términos completos.

La atribución a los proyectos originales de los que deriva se encuentra registrada en el archivo [`NOTICE`](NOTICE).  
*Cercano es un proyecto comunitario independiente y no está afiliado ni respaldado por RustDesk.*
