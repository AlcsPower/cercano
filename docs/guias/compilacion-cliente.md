<!--
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (C) 2026 Cercano Contributors
-->

# Guía técnica: Compilación y Despliegue del Cliente Gráfico Completo (Opción 3)

Esta guía documenta la arquitectura de producción de Cercano y los procedimientos para compilar y empaquetar el **cliente de escritorio gráfico completo** (Flutter + Rust) para usuarios finales y personal técnico conforme a `docs/PLAN-F3-GENERADOR.md` y `docs/ROADMAP.md`.

---

## 1. Arquitectura de Despliegue en Producción

Cercano está diseñado para operar en infraestructura híbrida:

```
+-----------------------------------------------------------------------------------+
|                           SERVIDOR CENTRAL (LINUX)                                |
|  Ubuntu / Debian 22.04 LTS (o contenedores Docker)                                 |
|  - cercano-api       : Puerto 21114 (HTTP/REST, 2FA, Auditoría, Telemetría)       |
|  - cercano-hbbs      : Puerto 21116 (TCP/UDP, Rendezvous / Descubrimiento)        |
|  - cercano-hbbr      : Puerto 21117 (TCP, Relay de Video / Audio / Archivos)      |
|  - console-web       : Puerto 443/3000 (Portal Web de Administración)             |
|  IP en Producción LAN: 172.16.8.163                                               |
+-----------------------------------------------------------------------------------+
                                   ▲          ▲
                                   │          │
         Conexión E2E cifrada      │          │  Conexión E2E cifrada
         con canal de control      │          │  con canal de control
                                   ▼          ▼
+------------------------------------+      +------------------------------------+
|      EQUIPO ASISTIDO (USUARIO)     |      |       TÉCNICO DE SOPORTE TI        |
|  Windows 10 / 11                   |      |  Windows 10 / 11 o Linux           |
|  Instalador: Cercano Soporte       |      |  Instalador: Cercano Técnico       |
|  (cercano-soporte-1.0.0.exe/.msi)  |      |  (cercano-tecnico-1.0.0.exe/.msi)  |
|                                    |      |                                    |
|  * GUI Flutter nativa amigable     |      |  * GUI Flutter con libreta de IDs  |
|  * Muestra ID visible de 9 dígitos |      |  * Inicio de sesión autenticado    |
|  * Aprobación en 1 clic de sesión  |      |  * Exige 2FA para iniciar sesión   |
|  * Chat de soporte integrado       |      |  * Consola de chat con escalado    |
|  * Sin conexiones salientes        |      |  * Solicitud de elevación admin    |
+------------------------------------+      +------------------------------------+
```

---

## 2. Métodos de Compilación del Cliente Gráfico Completo

El cliente gráfico oficial (`vendor/client`) combina una interfaz de usuario en **Flutter 3.24** con un motor de alto rendimiento en **Rust** (`scrap`, `hbb_common`, `vpx`, `opus`).

Existen tres métodos para obtener el binario base `cercano.exe` y los paquetes instalables:

### Método A: Compilación Automatizada en CI/CD (GitHub Actions) — **Recomendado**

Para no lidiar con la instalación de entornos pesados locales (Visual Studio C++, Flutter SDK, vcpkg), el repositorio incluye el workflow de CI:
[`.github/workflows/build-cercano-client.yml`](file:///.github/workflows/build-cercano-client.yml).

#### Pasos para ejecutarlo en GitHub:
1. Sube los cambios al repositorio remoto (`origin`).
2. En GitHub, ve a la pestaña **Actions**.
3. Selecciona el workflow **«Build Cercano Desktop Client (Production)»**.
4. Haz clic en **Run workflow**.
5. Puedes dejar el valor predeterminado de la IP (`172.16.8.163`) o escribir una nueva.
6. Al finalizar (aprox. 15–20 minutos con caché de vcpkg), descarga el artefacto **`cercano-windows-production-installers.zip`**, el cual contiene:
   - `dist/base/cercano.exe` (Binario base gráfico completo con Flutter)
   - `dist/builds/cercano-soporte-1.0.0/cercano-soporte-1.0.0.exe` (Instalador auto-ejecutable Soporte)
   - `dist/builds/cercano-soporte-1.0.0/cercano-soporte-1.0.0.msi` (Instalador corporativo GPO Soporte)
   - `dist/builds/cercano-tecnico-1.0.0/cercano-tecnico-1.0.0.exe` (Instalador Técnico)
   - `dist/builds/cercano-tecnico-1.0.0/cercano-tecnico-1.0.0.msi` (Instalador corporativo GPO Técnico)

---

### Método B: Rebranding Directo de un Binario Base Compatible (Inmediato)

Si se dispone de un binario base compilado de RustDesk x64 (versión 1.2.x o 1.3.x):
1. Colocar el archivo en la ruta:
   ```bash
   dist/base/cercano.exe
   ```
2. Ejecutar el generador `cercano-build` para incrustar el perfil firmado de la LAN:
   ```bash
   # Generar Soporte
   cercano-build \
     --profile docs/specs/examples/profile-soporte-lan.json \
     --base-binary dist/base/cercano.exe \
     --out dist/builds \
     --package-windows

   # Generar Técnico
   cercano-build \
     --profile docs/specs/examples/profile-tecnico-lan.json \
     --base-binary dist/base/cercano.exe \
     --out dist/builds \
     --package-windows
   ```
El instalador resultante integra la GUI de escritorio remoto y aplica las políticas de aislamiento de rol.

---

### Método C: Compilación Local en Windows

Para compilar el cliente Flutter directamente en una estación de trabajo Windows:

1. **Requisitos de software:**
   - **Rust:** `rustup default stable-x86_64-pc-windows-msvc` (Rust 1.75+)
   - **Visual Studio 2022:** C++ Desktop Development con Windows 10/11 SDK
   - **LLVM / Clang:** Versión 15+
   - **Flutter SDK:** Versión `3.24.5`
   - **vcpkg:**
     ```powershell
     git clone https://github.com/microsoft/vcpkg C:\vcpkg
     $env:VCPKG_ROOT = "C:\vcpkg"
     C:\vcpkg\bootstrap-vcpkg.bat
     C:\vcpkg\vcpkg.exe install libvpx:x64-windows-static libyuv:x64-windows-static opus:x64-windows-static aom:x64-windows-static
     ```

2. **Compilar el cliente:**
   ```powershell
   cd vendor\client
   python .\build.py --portable --flutter --skip-portable-pack --hwcodec --vram
   ```

3. **Empaquetar con `cercano-build`:**
   ```powershell
   Copy-Item .\flutter\build\windows\x64\runner\Release\rustdesk.exe ..\..\dist\base\cercano.exe
   cd ..\..
   cargo run -p cercano-build -- --profile docs/specs/examples/profile-soporte-lan.json --base-binary dist/base/cercano.exe --out dist/builds --package-windows
   ```

---

## 3. Verificación de Criterios de Aceptación (Hecho)

- [x] Perfiles de red configurados con la IP de producción `172.16.8.163`.
- [x] Workflow de CI/CD `.github/workflows/build-cercano-client.yml` creado y configurado con dependencias de Flutter, Rust y vcpkg.
- [x] Generador `cercano-build` validado y preparado para ensamblar el binario base con los perfiles firmados Ed25519.
- [x] Documentación técnica de compilación y empaquetado consolidada.
