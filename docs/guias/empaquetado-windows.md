<!--
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (C) 2026 Cercano Contributors
-->

# Guía técnica: Empaquetado Windows (.exe y .msi)

Esta guía documenta la arquitectura, especificación de identificadores, parámetros de instalación silenciosa, gestión de ciclo de vida y políticas de aislamiento de roles para los instaladores de Windows de Cercano conforme a la tarea **F3-05** y `docs/PLAN-F3-GENERADOR.md`.

---

## 1. Visión general

Cercano genera dos tipos de instaladores especializados para Windows a partir de un perfil JSON firmado (`cercano-profile.signed.json`):

1. **Cercano Soporte** (`role: "soporte"`): Diseñado para el equipo de la persona usuaria asistida. Capacidades restringidas: solo recibe conexiones con aprobación explícita (salvo acceso desatendido configurado por política), sin conexiones salientes, sin libreta y con ajustes de red bloqueados.
2. **Cercano Técnico** (`role: "tecnico"`): Diseñado para el personal de TI. Capacidades avanzadas: inicio de sesión autenticado, inicio de conexiones, libreta de dispositivos, solicitud de elevación administrativa.

Ambos roles se empaquetan en dos formatos nativos de Windows:
- **Instalador ejecutable (`.exe`)**: Auto-instalable, preparado para ejecución interactiva o despliegue silencioso (`/S`).
- **Instalador de Windows Installer (`.msi`)**: Formato estándar de base de datos relacional CFBF/OLE para despliegue masivo corporativo mediante Directiva de Grupo (GPO), Microsoft Intune o herramientas RMM.

---

## 2. Aislamiento de roles e identificadores

Para garantizar que ambos roles puedan coexistir en distintos equipos de una organización sin conflicto y que su gestión sea determinista, cada rol posee identificadores estables y separados:

| Parámetro | Cercano Soporte | Cercano Técnico |
|---|---|---|
| **Nombre de producto** | `Cercano Soporte` | `Cercano Técnico` |
| **Rol en perfil** | `soporte` | `tecnico` |
| **UpgradeCode (MSI)** | `{C38CA110-5090-4100-B001-000000509001}` | `{C38CA110-7EC1-4200-B002-0000007EC102}` |
| **Directorio de instalación predeterminado** | `%ProgramFiles%\Cercano Soporte` | `%ProgramFiles%\Cercano Tecnico` |
| **Clave de registro (Uninstall)** | `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte` | `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Tecnico` |
| **Nombre de artefacto EXE** | `cercano-soporte-<versión>.exe` | `cercano-tecnico-<versión>.exe` |
| **Nombre de artefacto MSI** | `cercano-soporte-<versión>.msi` | `cercano-tecnico-<versión>.msi` |
| **Definición WiX Toolset** | `cercano-soporte-<versión>.wxs` | `cercano-tecnico-<versión>.wxs` |

> [!IMPORTANT]
> Los `UpgradeCode` son GUIDs estables e inmutables entre versiones del mismo rol. Esto permite a Windows Installer detectar actualizaciones automáticamente (`MajorUpgrade`) y conservar el historial de instalación corporativo.

---

## 3. Contenido embebido en los artefactos

Cada paquete generado contiene de manera autosuficiente:
1. **Binario ejecutable del cliente (`cercano.exe`)**: Compilado reproduciblemente (Estrategia A) con verificación de perfil en compilación.
2. **Perfil firmado (`cercano-profile.signed.json`)**: Firma Ed25519 sobre JSON canónico (RFC 8785) con clave del generador, bloqueando cualquier manipulación o intento de escalada local de capacidades.
3. **Descriptor de metadatos (`installer-metadata.json`)**: Especificación de rol, versión, UpgradeCode, claves de registro y reglas de ciclo de vida.
4. **Scripts de ciclo de vida (`install.cmd` y `uninstall.cmd`)**: Lógica nativa de instalación limpia, reemplazo de roles y desinstalación sin dejar archivos huérfanos.

---

## 4. Generación con `cercano-build`

El CLI `cercano-build` integra la generación de ambos instaladores mediante el indicador `--package-windows` (o `-w` / `--windows`):

```bash
# Generación para rol soporte (con binario base reproducible)
cercano-build \
  --profile docs/specs/examples/profile-soporte-valido.json \
  --base-binary dist/base/cercano.exe \
  --out dist/builds \
  --package-windows

# Generación para rol técnico con UpgradeCode personalizado (opcional)
cercano-build \
  --profile docs/specs/examples/profile-tecnico-valido.json \
  --base-binary dist/base/cercano.exe \
  --out dist/builds \
  --package-windows \
  --upgrade-code "C38CA110-7EC1-4200-B002-0000007EC102"
```

### Estructura de salida generada
```text
dist/builds/cercano-soporte-1.0.0/
├── cercano.exe                     # Binario base reproducible empaquetado
├── cercano-profile.signed.json     # Perfil firmado Ed25519
├── cercano-soporte-1.0.0.exe       # Instalador Windows auto-instalable (.exe)
├── cercano-soporte-1.0.0.msi       # Instalador Windows Installer (.msi)
├── cercano-soporte-1.0.0.wxs       # Definición WiX v4 del paquete
├── installer-metadata.json         # Metadatos del instalador y aislamiento
├── build-manifest.json             # Manifiesto de procedencia y trazabilidad
└── SHA256SUMS                      # Sumas de verificación criptográficas
```

---

## 5. Parámetros de instalación silenciosa

### 5.1. Instalador `.msi` (`msiexec.exe`)

Diseñado para despliegue por directiva de grupo (GPO), Microsoft Intune o consolas RMM:

```powershell
# Instalación silenciosa básica (sin interfaz, sin reinicio forzado)
msiexec.exe /i "cercano-soporte-1.0.0.msi" /quiet /norestart

# Instalación desatendida con barra de progreso pasiva
msiexec.exe /i "cercano-soporte-1.0.0.msi" /passive /norestart

# Instalación silenciosa con registro detallado para auditoría
msiexec.exe /i "cercano-soporte-1.0.0.msi" /quiet /norestart /l*v "C:\Logs\cercano-install.log"

# Instalación silenciosa especificando directorio personalizado
msiexec.exe /i "cercano-soporte-1.0.0.msi" INSTALLDIR="D:\Herramientas\Cercano Soporte" /quiet /norestart

# Desinstalación silenciosa del paquete MSI
msiexec.exe /x "cercano-soporte-1.0.0.msi" /quiet /norestart
```

#### Propiedades públicas soportadas en MSI:
- `INSTALLDIR`: Ruta destino de instalación (por defecto `%ProgramFiles%\Cercano <Rol>`).
- `AUTOSTART`: `1` (por defecto) para registrar inicio automático con Windows; `0` para deshabilitarlo.
- `DESKTOPSHORTCUT`: `1` (por defecto) para crear acceso directo en el escritorio público.
- `ARPCOMMENTS`, `ARPCONTACT`, `ARPHELPLINK`: Textos informativos en «Programas y características».

---

### 5.2. Instalador `.exe`

Diseñado para instalación asistida o distribución mediante scripts PowerShell/CMD:

```powershell
# Instalación completamente silenciosa
.\cercano-soporte-1.0.0.exe /S

# Parámetros alternativos soportados para instalación silenciosa
.\cercano-soporte-1.0.0.exe --silent-install
.\cercano-soporte-1.0.0.exe /quiet

# Instalación silenciosa en directorio destino personalizado
.\cercano-soporte-1.0.0.exe /S /D="C:\Program Files\Cercano Personalizado"

# Desinstalación completamente limpia y silenciosa
.\cercano-soporte-1.0.0.exe /uninstall /S
```

---

## 6. Gestión del ciclo de vida

### 6.1. Instalación limpia
- Extrae y copia `cercano.exe`, `cercano-profile.signed.json`, `installer-metadata.json` y el desinstalador limpio en el directorio de instalación.
- Registra el producto en la clave de desinstalación de Windows:
  - `DisplayName`: Nombre comercial del rol (`Cercano Soporte` o `Cercano Técnico`).
  - `DisplayVersion`: Versión del cliente (`1.0.0`).
  - `Publisher`: `Cercano Contributors`.
  - `InstallLocation`: Directorio absoluto de instalación.
  - `UninstallString`: Comando para invocar la desinstalación.
  - `QuietUninstallString`: Comando para desinstalación silenciosa automática.
  - `Role`: Identificador del rol (`soporte` o `tecnico`).
  - `UpgradeCode`: GUID de actualización de Windows Installer.
- Crea accesos directos en el menú Inicio (`%ProgramData%\Microsoft\Windows\Start Menu\Programs`).

### 6.2. Actualización sobre instalación previa (mismo rol)
- Detecta la instalación previa a través del `UpgradeCode` y la clave de desinstalación del registro.
- Reemplaza en su lugar los archivos binarios y el perfil firmado manteniendo la configuración previa no conflictiva.
- Actualiza `DisplayVersion` y fecha de modificación en el registro.
- No deja archivos temporales ni bibliotecas obsoletas huérfanas.

### 6.3. Coexistencia y reemplazo entre roles en el mismo equipo
Conforme al modelo de seguridad de Cercano (ADR-008), **un equipo cliente solo puede operar bajo un rol activo**:
- Si se intenta instalar `Cercano Técnico` en un equipo donde ya reside `Cercano Soporte`:
  - En modo interactivo: Despliega una advertencia limpia indicando:
    > *"ADVERTENCIA: Se ha detectado una instalación previa de 'Cercano Soporte'. Conforme a la política de roles de Cercano, no se permite la coexistencia de ambos roles en el mismo equipo. Se procederá a desinstalar 'Cercano Soporte' y reemplazarlo limpiamente por 'Cercano Técnico'."*
  - En modo silencioso (`/S` o `/quiet`): Registra la advertencia en el log de auditoría del instalador y procede con la sustitución limpia:
    1. Detiene los procesos activos del rol anterior.
    2. Ejecuta la desinstalación limpia del rol anterior eliminando sus archivos, accesos directos y entradas de registro.
    3. Instala el nuevo rol de forma aislada.

### 6.4. Desinstalación limpia
- Detiene cualquier proceso `cercano.exe` en ejecución o servicio asociado.
- Elimina todos los archivos del directorio de instalación (`cercano.exe`, `cercano-profile.signed.json`, metadatos y temporales).
- Elimina el directorio de instalación raíz.
- Elimina los accesos directos del menú Inicio y del Escritorio.
- Elimina la clave de registro de desinstalación bajo `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`.
- **Garantía:** No quedan archivos huérfanos, procesos residuales ni claves de registro inactivas.

---

## 7. Verificación y pruebas de aceptación

Las pruebas automatizadas en `builder/cercano-build/tests/cli_test.rs` validan:
1. `test_windows_packaging_soporte`: Generación de `.exe`, `.msi`, `.wxs`, metadatos y sumas de comprobación en menos de 30 s.
2. `test_windows_packaging_tecnico_with_base_binary`: Integración de binario base, aislamiento de roles (`C38CA110-7EC1-4200-B002-0000007EC102`), flags silenciosos documentados y advertencias de reemplazo.
3. `test_windows_packaging_custom_upgrade_code`: Capacidad de inyectar identificadores corporativos personalizados.
4. Verificación de integridad OLE Compound Document (CFBF) en el archivo `.msi` y encabezado PE `MZ` en el archivo `.exe`.
5. Verificación de todas las sumas SHA-256 de los artefactos producidos en `SHA256SUMS`.
