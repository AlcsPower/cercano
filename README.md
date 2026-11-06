<p align="center">
  <img src="branding/logo/cercano-wordmark-light.svg" alt="Cercano" height="72">
</p>

<p align="center"><em>Soporte remoto, como si estuvieras ahí.</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/Licencia-AGPL--3.0-blue.svg" alt="Licencia AGPL-3.0">
  <img src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/React-18-61dafb.svg" alt="React 18">
  <img src="https://img.shields.io/badge/Tests-87%20passing-brightgreen.svg" alt="Tests Status">
</p>

---

# Cercano

**Cercano** es una plataforma integral de soporte y asistencia remota para equipos de TI e instituciones: **auditable**, **segura por defecto**, **optimizada para redes corporativas/LAN** y concebida con **código 100% abierto**.

Ofrece las capacidades empresariales que tradicionalmente se reservan a versiones de pago en herramientas propietarias (como RustDesk Server Pro), centrándose en tres pilares:
1. **Auditoría inmutable con integridad demostrable**: Cada sesión, comando, transferencia de archivos y evento administrativo se firma y sella en una cadena criptográfica de hashes con checkpoints Ed25519 verificables sin conexión al servidor.
2. **Trazabilidad de extremo a extremo (`trace_id`)**: Correlación temporal y operativa precisa entre el cliente, el servidor de señalización/relay y la consola de gestión.
3. **Personalizador y generador de clientes**: Configuración visual de instaladores corporativos bloqueados, con identidad propia, claves embebidas y políticas centralizadas.

> 🚀 **Estado del Proyecto: Fase 2 en curso (Auditoría y Traza Inmutable - Hito M1 completado).**  
> Fases 0 (Fundación) y 1 (Núcleo y Paridad Básica) completadas. Consulta el detalle en [`docs/status/TAREAS.md`](docs/status/TAREAS.md) y [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Componentes y Arquitectura

El monorepo está organizado en módulos desacoplados y libres de dependencias propietarias:

```
cercano/
├── control-plane/
│   ├── audit-core/       # Crate Rust: Cadena criptográfica SHA-256 (RFC 8785) con DB SQLite append-only
│   ├── cercano-api/      # API REST: Auth Argon2id, gestión de dispositivos, alarmas e ingestión de auditoría
│   └── cercano-audit/    # Herramienta CLI: Exportación y verificación forense fuera de línea
├── console-web/          # Consola Web administrativa: React 18 + Vite + Tailwind CSS (Diseño Apple/Emil)
├── client/               # Cliente de soporte remoto de escritorio
├── server/               # Servidores de señalización (hbbs) y relay (hbbr)
├── branding/             # Guía de marca, logotipos oficiales (SVG/PNG) y paleta institucional
├── docs/                 # Documentación técnica, especificaciones RFC, ADR y planes de prueba
└── tools/                # Scripts de validación de licencias y utilidades de desarrollo
```

---

## Capacidades Implementadas

| Capacidad | Descripción | Estado |
|---|---|---|
| **Cadena Criptográfica de Auditoría** | Registro append-only con serialización canónica RFC 8785, ligada a un bloque génesis mediante SHA-256 y protegida contra escritura/borrado vía triggers de hardware/DB en SQLite. | ✅ Producción (`audit-core`) |
| **Checkpoints Firmados & Verificador CLI** | Creación periódica de checkpoints firmados con Ed25519 y CLI `cercano-audit` para verificación independiente de integridad en archivos JSONL. | ✅ Producción (`cercano-audit`) |
| **Correlación de Traza (`trace_id`)** | Agregación de eventos y métricas de sesión (duración exacta, bytes transferidos, archivos) a través de `GET /api/audit/traces/:trace_id`. | ✅ Producción (`cercano-api`) |
| **Motor de Alarmas en Tiempo Real** | Detección automática en ventana deslizante para fuerza bruta, ráfagas de IP, violaciones de lista blanca CIDR y alcances no autorizados. | ✅ Producción (`cercano-api`) |
| **Auditoría Administrativa Completa** | Trazabilidad inmutable de todas las mutaciones: login, logout, rotación de claves, altas y bajas de dispositivos. | ✅ Producción (`cercano-api`) |
| **Consola Web Administrativa** | UI moderna, accesible, con fuentes auto-hospedadas (100% offline), soporte de tema claro/oscuro de alto contraste y previsualizador interactivo de clientes. | ✅ Producción (`console-web`) |
| **Gestión de Claves de Servidor** | Generación de pares Ed25519, lectura segura de claves públicas y rotación con respaldo automático de claves anteriores. | ✅ Producción (`cercano-api`) |

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
git clone https://github.com/AlcsPower/cercano.git
cd cercano
```

### 2. Ejecutar la suite de pruebas del backend (Rust)
Todas las pruebas del core criptográfico, API y CLI pueden ejecutarse con:
```bash
cargo test --workspace
```
*(87 pruebas unitarias y de integración garantizan el funcionamiento y la resistencia contra manipulación).*

### 3. Ejecutar la Consola Web
```bash
cd console-web
npm install
npm run dev
```
La consola estará disponible en `http://localhost:3000`.

### 4. Verificar una traza de auditoría con el CLI
Para auditar la integridad de un archivo de log exportado:
```bash
# Exportar base de datos a formato JSONL canónico
cargo run -p cercano-audit -- export-db /ruta/a/audit.db eventos.jsonl

# Verificar la validez de la cadena de hashes y las firmas Ed25519
cargo run -p cercano-audit -- verify eventos.jsonl --pubkey <CLAVE_PUBLICA_HEX>
```

---

## Especificaciones y Gobernanza

- **Esquema de Eventos de Auditoría**: Especificado formalmente bajo JSON Schema Draft-07 en [`docs/specs/audit-events.schema.json`](docs/specs/audit-events.schema.json) y detallado en [`docs/specs/audit-events.md`](docs/specs/audit-events.md).
- **Reglas de Trabajo para Agentes y Colaboradores**: Consulta [`AGENTS.md`](AGENTS.md).
- **Seguridad y Clean-Room**: Prohibición estricta de ingeniería inversa o descompilación de binarios comerciales. Cercano se construye bajo el principio *clean-room* a partir de documentación pública y estándares abiertos. Consulta [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md).

---

## Licencia

Cercano se distribuye bajo los términos de la **GNU Affero General Public License v3.0 (AGPL-3.0)**. Consulta el archivo [`LICENSE`](LICENSE) para ver los términos completos.

La atribución a los proyectos originales de los que deriva se encuentra registrada en el archivo [`NOTICE`](NOTICE).  
*Cercano es un proyecto comunitario independiente y no está afiliado ni respaldado por RustDesk.*
