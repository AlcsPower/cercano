<!--
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (C) 2026 Cercano Contributors
-->

# Guía técnica: Despliegue masivo y desatendido de instaladores Cercano

Esta guía documenta los procedimientos, parámetros técnicos, directivas de seguridad y scripts de automatización para el despliegue silencioso y a escala de los clientes de **Cercano** en infraestructuras Windows corporativas, mediante **Group Policy Objects (GPO)**, **Microsoft Intune (Endpoint Manager)** y herramientas **RMM** (NinjaOne, Datto RMM, ManageEngine Endpoint Central, Ansible).

---

## 1. Introducción y arquitectura de roles

### 1.1. Principio de menor privilegio y roles de cliente (ADR-008)

Cercano genera dos tipos diferenciados de instaladores basados en el perfil criptográficamente firmado (`cercano-profile.signed.json`):

| Característica | Cercano Soporte (`role: "soporte"`) | Cercano Técnico (`role: "tecnico"`) |
|---|---|---|
| **Público objetivo** | Equipos de usuarios finales / puestos de trabajo corporativos | Personal autorizado de TI / Helpdesk / Administradores de red |
| **Inicio de conexiones** | **Bloqueado** (el cliente no puede actuar como emisor de conexiones) | Habilitado (requiere cuenta autenticada en `cercano-api`) |
| **Recepción de asistencia** | Sí. Con consentimiento explícito (o acceso desatendido autorizado) | Opcional (asistencia entre técnicos) |
| **Libreta de dispositivos** | Oculta e inhabilitada | Accesible según permisos RBAC asignados en la consola |
| **Elevación administrativa** | Receptor de elevación (aprueba o deniega solicitudes UAC) | Emisor de elevación (requiere permiso `elev:use`) |
| **Ajustes de red y clave** | Bloqueados y fijos por perfil | Bloqueados y fijos por perfil |
| **Caducidad predeterminada** | Indefinida (revocable de forma centralizada) | 90 días por defecto (revocable de forma centralizada) |
| **Directorio de instalación** | `%ProgramFiles%\Cercano Soporte` | `%ProgramFiles%\Cercano Tecnico` |
| **UpgradeCode MSI** | `{C38CA110-5090-4100-B001-000000509001}` | `{C38CA110-7EC1-4200-B002-0000007EC102}` |

> [!IMPORTANT]
> **El rol se impone y valida en el servidor, no únicamente en el instalador:**
> Conforme al diseño de [ADR-008](../ARQUITECTURA.md#3-decisiones-de-arquitectura-adr), el servidor de señalización (*hbbs*) y `cercano-api` verifican el rol declarado en el perfil firmado al momento del registro. Un instalador `soporte` no puede iniciar conexiones ni solicitar elevación aunque se altere su configuración local o memoria; cualquier intento generará un evento de alarma `alarm.role_violation` en la auditoría.

### 1.2. Procedimiento de distribución segura del instalador Técnico

El instalador `Cercano Técnico` confiere acceso de control y solicitud de elevación a personal acreditado. Para prevenir su filtración o instalación en equipos de usuario general:

1. **Aislamiento en repositorio de red (ACLs restringidas):**
   - El artefacto `cercano-tecnico-<versión>.msi` / `.exe` debe almacenarse en un recurso compartido exclusivo (p. ej., `\\servidor\TI-Tools$\CercanoTecnico`), accesible únicamente por el grupo de seguridad de dominio `SG-TI-Soporte-N2` o administradores de dominio.
   - Prohibir terminantemente permisos de lectura a los grupos `Domain Users`, `Everyone` o `Authenticated Users`.
2. **Distribución dirigida en Intune/GPO:**
   - La asignación de la aplicación `Cercano Técnico` en Microsoft Intune debe aplicarse exclusivamente a un grupo de dispositivos de TI (`SG-Intune-Dispositivos-Tecnicos`) o a un grupo de usuarios técnicos de Helpdesk, **nunca a «All Devices» o «All Users»**.
3. **Rotación y caducidad:**
   - Los instaladores técnicos generados por el generador (`cercano-build` o `cercano-api`) poseen una vigencia máxima configurable de 90 días. Pasado ese tiempo, el instalador no podrá registrarse en el servidor sin emitir una versión actualizada firmada.
4. **Revocación inmediata ante extravío o sospecha:**
   - Si un equipo de un técnico es sustraído o un instalador técnico se sospecha expuesto, el administrador debe revocar el `installer_id` o el `device_id` desde la consola de `cercano-api` en *Dispositivos -> Revocar*. El servidor denegará conexiones en menos de 60 segundos.

---

## 2. Parámetros de ejecución silenciosa y códigos de salida

### 2.1. Paquetes Windows Installer (`.msi` vía `msiexec.exe`)

Los paquetes `.msi` generados por Cercano cumplen estrictamente el estándar de Windows Installer:

```powershell
# Sintaxis de instalación silenciosa básica
msiexec.exe /i "cercano-soporte-1.0.0.msi" /qn /norestart

# Sintaxis recomendada con registro detallado para despliegue corporativo
msiexec.exe /i "cercano-soporte-1.0.0.msi" /qn /norestart /L*V "C:\Windows\Temp\cercano-soporte-install.log"
```

#### Parámetros soportados:
- `/i <ruta>`: Instala el producto.
- `/qn`: Modo completamente desatendido y silencioso (sin interfaz gráfica, diálogos ni avisos).
- `/qb`: Modo silencioso básico con barra de progreso pasiva.
- `/norestart`: Suprime cualquier reinicio automático del sistema.
- `/L*V "<ruta_log>"`: Genera un log exhaustivo y detallado (verbose) de la instalación.
- `INSTALLDIR="<ruta>"`: Define una ruta alternativa de instalación (por defecto `%ProgramFiles%\Cercano Soporte` o `%ProgramFiles%\Cercano Tecnico`).
- `AUTOSTART=1`: Registra el arranque del servicio al iniciar el sistema (predeterminado `1`; use `0` para deshabilitar).
- `DESKTOPSHORTCUT=1`: Crea el acceso directo en el escritorio público (predeterminado `1`; use `0` para suprimir).

### 2.2. Instaladores ejecutables (`.exe`)

El ejecutable auto-instalable empaquetado por Cercano integra el script de ciclo de vida con detección automática de roles previos:

```powershell
# Instalación totalmente silenciosa
.\cercano-soporte-1.0.0.exe /S

# Banderas equivalentes admitidas
.\cercano-soporte-1.0.0.exe /quiet /norestart
.\cercano-soporte-1.0.0.exe --silent-install

# Instalación silenciosa en ruta personalizada
.\cercano-soporte-1.0.0.exe /S /D="C:\Program Files\Cercano Personalizado"
```

### 2.3. Tabla de códigos de salida (Exit Codes)

| Código de salida | Constante Windows Installer | Significado | Acción del sistema de despliegue |
|---|---|---|---|
| `0` | `ERROR_SUCCESS` | Operación completada con éxito. | Finalizar con éxito. |
| `1602` | `ERROR_INSTALL_USEREXIT` | Cancelado por el usuario o script previo. | Fallo / Requiere investigación manual. |
| `1603` | `ERROR_INSTALL_FAILURE` | Error fatal durante la instalación (permisos insuficientes, disco lleno). | Consultar log en `C:\Windows\Temp\`. |
| `1618` | `ERROR_INSTALL_ALREADY_RUNNING` | Otra instancia de `msiexec` está activa en el equipo. | Reintentar tras 60 segundos. |
| `1638` | `ERROR_PRODUCT_VERSION` | Conflicto de versión (misma versión o versión más reciente instalada). | Validar versión instalada. |
| `3010` | `ERROR_SUCCESS_REBOOT_REQUIRED` | Instalación completada con éxito; reinicio pendiente. | Notificar éxito con reinicio diferido. |
| `1641` | `ERROR_SUCCESS_REBOOT_INITIATED` | Instalador inició un reinicio del sistema. | El host se reiniciará. |
| `1` | `ERROR_INVALID_FUNCTION` | Argumento o sintaxis incorrecta en instalador `.exe`. | Revisar parámetros pasados. |

---

## 3. Despliegue mediante Directivas de Grupo (GPO / Active Directory)

### 3.1. Método A: Asignación nativa de software basada en equipo (`.msi`)

Este método asigna el paquete `.msi` a los equipos antes de que los usuarios inicien sesión, ejecutándose con privilegios de `NT AUTHORITY\SYSTEM`.

#### Paso 1: Preparación del recurso compartido de red
1. Cree una carpeta en un servidor de archivos o controlador de dominio:
   `D:\Deploy\Cercano\Soporte\`
2. Copie allí el archivo `cercano-soporte-1.0.0.msi`.
3. Comparta la carpeta como recurso de red UNC: `\\cercano-dc\Deploy$\Cercano\Soporte\`.
4. Configure los permisos de seguridad NTFS y SMB:
   - **Permisos de recurso compartido (Share Permissions):** `Domain Computers` -> Lectura; `Domain Admins` -> Control Total.
   - **Permisos NTFS (Security Permissions):** `Domain Computers` -> Leer y ejecutar; `Domain Admins` -> Modificar/Control Total.

> [!CAUTION]
> Windows Installer se ejecuta en el contexto de la cuenta de máquina (`NOMBRE-EQUIPO$`). Si `Domain Computers` no tiene permisos de lectura sobre la ruta UNC compartida, la instalación fallará con el código `1619` o `1603`.

#### Paso 2: Configuración de la GPO
1. Abra la consola de administración de directivas de grupo (`gpmc.msc`).
2. Cree una nueva GPO denominada `GPO - Cercano Soporte - Despliegue Masivo`.
3. Vincule la GPO a la Unidad Organizativa (OU) donde residen los equipos de usuario final (p. ej., `OU=PuestosTrabajo,OU=Equipos,DC=cercano,DC=lan`).
4. Edite la GPO y navegue a:
   **Configuración del equipo -> Directivas -> Configuración de software -> Instalación de software**.
5. Haga clic derecho -> **Nuevo -> Paquete...**
6. **Crítico:** En el diálogo de selección de archivo, escriba la ruta UNC completa:
   `\\cercano-dc\Deploy$\Cercano\Soporte\cercano-soporte-1.0.0.msi` *(nunca use una letra de unidad local como `C:` o `D:`)*.
7. Seleccione el método de implementación: **Asignada**.
8. En las propiedades del paquete recién creado:
   - Pestaña **Implementación**: Marque «Desinstalar esta aplicación cuando quede fuera del ámbito de administración».
   - Pestaña **Opciones avanzadas**: Desmarque la opción de ignorar idioma si aplica.

---

### 3.2. Método B: Script de inicio de equipo (Startup Script en PowerShell/CMD)

Recomendado para paquetes `.exe` o cuando se requiere validación previa de arquitectura, control de versiones existentes y logging centralizado antes de invocar la instalación.

#### Script de inicio PowerShell: `Deploy-Cercano-Startup.ps1`

Guarde el siguiente script en la carpeta de scripts de la GPO (`\\cercano.lan\sysvol\cercano.lan\Policies\{GUID}\Machine\Scripts\Startup\`):

```powershell
<#
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (C) 2026 Cercano Contributors
  Script de inicio para despliegue automatizado de Cercano Soporte
#>
[CmdletBinding()]
param(
    [string]$DeployShare = "\\cercano-dc\Deploy$\Cercano\Soporte",
    [string]$TargetVersion = "1.0.0",
    [string]$Role = "soporte"
)

$ErrorActionPreference = "Stop"
$LogFile = "C:\Windows\Temp\cercano-gpo-startup.log"

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Timestamp] $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

Write-Log "=== Inicio de proceso de despliegue Cercano ($Role) ==="

# 1. Validar arquitectura del procesador (64 bits requerido)
if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Log "[ERROR] El sistema operativo no es de 64 bits. Abortando instalación."
    exit 1
}

# 2. Comprobar instalación existente a través del registro
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte"
$NeedsInstall = $true

if (Test-Path $RegPath) {
    $CurrentVer = (Get-ItemProperty -Path $RegPath -Name "DisplayVersion" -ErrorAction SilentlyContinue).DisplayVersion
    Write-Log "[INFO] Versión instalada actualmente: $CurrentVer"
    
    if ($CurrentVer -eq $TargetVersion) {
        Write-Log "[INFO] La versión requerida ($TargetVersion) ya está instalada. No se requieren cambios."
        $NeedsInstall = $false
    } else {
        Write-Log "[INFO] Se detectó versión anterior ($CurrentVer). Procediendo a actualizar a $TargetVersion."
    }
} else {
    Write-Log "[INFO] No se detectó instalación previa de Cercano Soporte. Procediendo con instalación limpia."
}

if ($NeedsInstall) {
    $MsiSource = Join-Path $DeployShare "cercano-$Role-$TargetVersion.msi"
    if (-not (Test-Path $MsiSource)) {
        Write-Log "[ERROR] No se localizó el paquete fuente en $MsiSource."
        exit 2
    }

    $MsiLog = "C:\Windows\Temp\cercano-install-msi.log"
    $Arguments = "/i `"$MsiSource`" /qn /norestart /L*V `"$MsiLog`""
    Write-Log "[EXEC] Ejecutando: msiexec.exe $Arguments"

    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
    $ExitCode = $Process.ExitCode
    Write-Log "[EXEC] Proceso finalizado con código de salida: $ExitCode"

    if ($ExitCode -eq 0 -or $ExitCode -eq 3010) {
        Write-Log "[SUCCESS] Despliegue de Cercano completado con éxito."
        exit 0
    } else {
        Write-Log "[FAILURE] La instalación de Cercano falló con código $ExitCode. Consulte $MsiLog."
        exit $ExitCode
    }
}

exit 0
```

#### Vinculación en la GPO:
1. En el editor de directivas de grupo, navegue a:
   **Configuración del equipo -> Directivas -> Configuración de Windows -> Scripts (Inicio/Apagado) -> Inicio**.
2. Seleccione la pestaña **Scripts de PowerShell** -> Haga clic en **Agregar...**
3. Nombre del script: `Deploy-Cercano-Startup.ps1`.
4. Parámetros de script: `-DeployShare "\\cercano-dc\Deploy$\Cercano\Soporte" -TargetVersion "1.0.0"`.

---

## 4. Despliegue mediante Microsoft Intune (Endpoint Manager)

Microsoft Intune permite distribuir Cercano tanto mediante el formato simplificado de aplicación de línea de negocio (LOB) `.msi` como mediante la aplicación Win32 (`.intunewin`). Se **recomienda el empaquetado Win32** por brindar reglas de detección avanzadas, control granular de dependencias y capacidad de rollback.

### 4.1. Preparación del paquete Win32 (`.intunewin`)

1. Descargue la utilidad oficial `Microsoft Win32 Content Prep Tool` (`IntuneWinAppUtil.exe`).
2. Organice una estructura local de trabajo:
   ```text
   C:\IntuneBuild\
   ├── Source\
   │   └── cercano-soporte-1.0.0.msi
   └── Output\
   ```
3. Ejecute la herramienta de empaquetado:
   ```cmd
   IntuneWinAppUtil.exe -c C:\IntuneBuild\Source -s cercano-soporte-1.0.0.msi -o C:\IntuneBuild\Output -q
   ```
4. Se generará el artefacto empaquetado `C:\IntuneBuild\Output\cercano-soporte-1.0.0.intunewin`.

### 4.2. Configuración en el portal de Microsoft Intune

1. Inicie sesión en [Microsoft Endpoint Manager admin center](https://endpoint.microsoft.com).
2. Navegue a **Aplicaciones -> Windows -> Agregar**.
3. Tipo de aplicación: Seleccione **Aplicación de Windows (Win32)**.
4. Cargue el archivo `cercano-soporte-1.0.0.intunewin`.

#### Información de la aplicación:
- **Nombre:** Cercano Soporte
- **Descripción:** Cliente oficial de asistencia técnica remota y soporte desatendido de Cercano.
- **Editor:** Cercano Contributors
- **Versión de la aplicación:** 1.0.0
- **Categoría:** Herramientas y soporte empresarial
- **Mostrar como aplicación destacada en Portal de empresa:** No

#### Programa:
- **Comando de instalación:**
  ```cmd
  msiexec.exe /i "cercano-soporte-1.0.0.msi" /qn /norestart /L*V "C:\Windows\Temp\cercano-intune-install.log"
  ```
- **Comando de desinstalación:**
  ```cmd
  msiexec.exe /x {C38CA110-5090-4100-B001-000000509001} /qn /norestart
  ```
  *(o invocando el script de desinstalación limpia: `"%ProgramFiles%\Cercano Soporte\uninstall.cmd" /quiet`)*.
- **Comportamiento de tiempo de instalación:** **Sistema** (System-level installation).
- **Comportamiento de reinicio del dispositivo:** **Determinar según el código de retorno**.
- **Códigos de retorno:** Mantenga los valores estándar de Intune (`0` Éxito, `3010` Reinicio pendiente).

#### Requisitos:
- **Arquitectura del sistema operativo:** 64 bits.
- **Sistema operativo mínimo:** Windows 10 21H2 (compilación 19044) o superior.

#### Reglas de detección (Detection Rules):
Seleccione **Formato de reglas: Configurar reglas de detección manualmente**.

**Regla 1 (Clave de Registro):**
- **Tipo de regla:** Registro
- **Ruta de acceso a la clave:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte`
- **Nombre del valor:** `DisplayVersion`
- **Método de detección:** Comparación de versión de cadena
- **Operador:** Mayor o igual que (`>=`)
- **Valor:** `1.0.0`
- **Asociado a una aplicación de 32 bits en clientes de 64 bits:** No

**Regla 2 (Comprobación de Archivo Binario - Opcional):**
- **Tipo de regla:** Archivo
- **Ruta de acceso:** `%ProgramFiles%\Cercano Soporte`
- **Archivo o carpeta:** `cercano.exe`
- **Método de detección:** El archivo o la carpeta existen.

---

## 5. Despliegue mediante plataformas RMM y automatización

### 5.1. Script idempotente para NinjaOne / Datto RMM (PowerShell)

Este script puede ejecutarse de forma periódica o a demanda mediante tareas de automatización programada en NinjaOne o Datto RMM. Se encarga de descargar el instalador firmado vía HTTPS desde el servidor central de Cercano, verificar su hash SHA-256 e instalarlo silenciosamente.

```powershell
<#
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (C) 2026 Cercano Contributors
  Script de despliegue automatizado e idempotente para consolas RMM
#>
$ServerApiUrl   = "https://cercano-api.cercano.lan:21114"
$InstallerRole  = "soporte"
$TargetVersion  = "1.0.0"
$ExpectedSha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" # Reemplazar con hash del manifiesto
$WorkDir        = "C:\Windows\Temp\CercanoDeploy"
$PackageName    = "cercano-$InstallerRole-$TargetVersion.msi"
$DownloadUrl    = "$ServerApiUrl/api/v1/builds/download/$PackageName"
$LocalMsiPath   = Join-Path $WorkDir $PackageName

try {
    # 1. Comprobar estado de instalación previo
    $RegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte"
    if (Test-Path $RegKey) {
        $InstalledVer = (Get-ItemProperty -Path $RegKey).DisplayVersion
        if ($InstalledVer -eq $TargetVersion) {
            Write-Host "[OK] Cercano Soporte $TargetVersion ya se encuentra instalado. Idempotencia satisfecha."
            exit 0
        }
    }

    # 2. Crear directorio de trabajo seguro
    if (-not (Test-Path $WorkDir)) {
        New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    }

    # 3. Descarga del artefacto instalador
    Write-Host "[INFO] Descargando instalador desde $DownloadUrl..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $LocalMsiPath -UseBasicParsing -TimeoutSec 120

    # 4. Verificación de integridad SHA-256 (cuando el hash esté definido)
    if ($ExpectedSha256 -and $ExpectedSha256 -ne "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855") {
        $ComputedHash = (Get-FileHash -Path $LocalMsiPath -Algorithm SHA256).Hash
        if ($ComputedHash -ne $ExpectedSha256) {
            throw "Fallo de integridad criptográfica: El hash calculado ($ComputedHash) no coincide con el esperado ($ExpectedSha256)."
        }
        Write-Host "[OK] Verificación de integridad SHA-256 completada."
    }

    # 5. Ejecución silenciosa de msiexec
    $LogPath = "C:\Windows\Temp\cercano-rmm-install.log"
    Write-Host "[EXEC] Iniciando instalación silenciosa de $PackageName..."
    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$LocalMsiPath`" /qn /norestart /L*V `"$LogPath`"" -Wait -PassThru -NoNewWindow

    if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
        Write-Host "[SUCCESS] Instalación completada exitosamente con código $($Process.ExitCode)."
        Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 0
    } else {
        throw "La instalación falló con código de error $($Process.ExitCode). Revise el log en $LogPath."
    }
}
catch {
    Write-Error "[FATAL] Fallo en despliegue RMM: $_"
    exit 1
}
```

---

### 5.2. Despliegue con Ansible para Windows

Playbook de Ansible (`deploy-cercano.yml`) para despliegue desatendido en flotas gestionadas mediante WinRM o SSH:

```yaml
# SPDX-License-Identifier: AGPL-3.0-only
# Playbook de despliegue corporativo Cercano Soporte
---
- name: Despliegue masivo y desatendido de Cercano Soporte en Windows
  hosts: windows_workstations
  gather_facts: yes
  vars:
    cercano_version: "1.0.0"
    cercano_role: "soporte"
    cercano_msi_url: "https://cercano-api.cercano.lan:21114/api/v1/builds/download/cercano-soporte-1.0.0.msi"
    cercano_product_id: "{C38CA110-5090-4100-B001-000000509001}"
    cercano_temp_msi: "C:\\Windows\\Temp\\cercano-soporte-{{ cercano_version }}.msi"

  tasks:
    - name: Comprobar arquitectura del sistema operativo
      ansible.builtin.assert:
        that:
          - ansible_architecture == "64-bit"
        fail_msg: "Cercano requiere un sistema operativo de 64 bits."

    - name: Descargar paquete MSI firmado de Cercano
      ansible.windows.win_get_url:
        url: "{{ cercano_msi_url }}"
        dest: "{{ cercano_temp_msi }}"
        validate_certs: yes

    - name: Instalar paquete MSI de Cercano de forma desatendida
      ansible.windows.win_package:
        path: "{{ cercano_temp_msi }}"
        product_id: "{{ cercano_product_id }}"
        arguments: "/qn /norestart /L*V C:\\Windows\\Temp\\cercano-ansible-install.log"
        state: present
      register: msi_result

    - name: Verificar que el servicio Cercano esté en ejecución y en inicio automático
      ansible.windows.win_service:
        name: cercano
        start_mode: auto
        state: started
      ignore_errors: yes

    - name: Limpiar archivo temporal MSI
      ansible.windows.win_file:
        path: "{{ cercano_temp_msi }}"
        state: absent
```

---

## 6. Actualización y coexistencia/reemplazo de roles

### 6.1. Actualización sobre versiones anteriores (mismo rol)

Los paquetes `.msi` de Cercano implementan la directiva `<MajorUpgrade>` de Windows Installer gobernada por el `UpgradeCode` fijo por rol:
- Al desplegar `cercano-soporte-1.0.1.msi` en un equipo con `cercano-soporte-1.0.0.msi`, Windows Installer:
  1. Detecta la presencia de la versión previa a través de `{C38CA110-5090-4100-B001-000000509001}`.
  2. Detiene ordenadamente el servicio y procesos activos de `cercano.exe`.
  3. Reemplaza el binario base `cercano.exe` y el perfil firmado `cercano-profile.signed.json`.
  4. Actualiza los metadatos de versión en `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte`.
  5. Inicia el nuevo servicio sin requerir reinicio del sistema ni intervención manual.

### 6.2. Regla crítica de aislamiento de roles (ADR-008)

> [!WARNING]
> **En un mismo equipo cliente no pueden coexistir simultáneamente los roles `soporte` y `tecnico`.**
> Si un equipo tiene instalado `Cercano Soporte` y se ejecuta el instalador de `Cercano Técnico` (o viceversa):
> 1. El instalador detecta la clave de registro del rol opuesto:
>    - Para técnico: busca `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte`.
>    - Para soporte: busca `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Tecnico`.
> 2. **En modo interactivo:** Alerta al operador del conflicto y solicita confirmación antes de desinstalar el rol previo.
> 3. **En modo silencioso (`/S`, `/quiet`, `/qn`):** Escribe una advertencia en el registro de log:
>    `[CERCANO] Reemplazando rol soporte con rol tecnico conforme a la politica de roles.`
> 4. Detiene inmediatamente los procesos del rol anterior, invoca su desinstalador limpio (`uninstall.cmd /quiet`) eliminando binarios, perfiles y entradas de registro huérfanas, y acto seguido efectúa la instalación limpia del nuevo rol.

---

## 7. Desinstalación completamente limpia

Cercano garantiza un desmantelamiento total sin dejar archivos residuales, servicios huérfanos ni configuraciones obsoletas que puedan comprometer futuros despliegues.

### 7.1. Comandos de desinstalación silenciosa

```powershell
# Opción 1: Desinstalación mediante Windows Installer (usando ProductCode o UpgradeCode)
msiexec.exe /x {C38CA110-5090-4100-B001-000000509001} /qn /norestart

# Opción 2: Desinstalación mediante script nativo embebido (PowerShell)
& "$env:ProgramFiles\Cercano Soporte\uninstall.cmd" /quiet

# Equivalente en símbolo del sistema (CMD):
# "%ProgramFiles%\Cercano Soporte\uninstall.cmd" /quiet
```

### 7.2. Script de purga profunda (PowerShell Cleanup Utility)

Si se requiere desinstalar y purgar minuciosamente cualquier caché de sesión previa, certificados temporales o perfiles:

```powershell
<#
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (C) 2026 Cercano Contributors
  Script de desinstalación limpia y purga total de Cercano
#>
[CmdletBinding()]
param(
    [ValidateSet("soporte", "tecnico", "todos")]
    [string]$TargetRole = "todos"
)

Write-Host "=== Iniciando purga limpia de Cercano ($TargetRole) ===" -ForegroundColor Cyan

# 1. Detener procesos activos
$Processes = Get-Process -Name "cercano" -ErrorAction SilentlyContinue
if ($Processes) {
    Write-Host "[1/5] Deteniendo procesos activos de cercano.exe..."
    $Processes | Stop-Process -Force
    Start-Sleep -Seconds 2
}

# 2. Detener y desregistrar servicio de Windows si existe
$Service = Get-Service -Name "cercano" -ErrorAction SilentlyContinue
if ($Service) {
    Write-Host "[2/5] Deteniendo y eliminando servicio Windows 'cercano'..."
    Stop-Service -Name "cercano" -Force -ErrorAction SilentlyContinue
    sc.exe delete cercano | Out-Null
}

# 3. Eliminar claves de registro de Desinstalación
$KeysToRemove = @()
if ($TargetRole -in @("soporte", "todos")) {
    $KeysToRemove += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte"
}
if ($TargetRole -in @("tecnico", "todos")) {
    $KeysToRemove += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Tecnico"
}

foreach ($Key in $KeysToRemove) {
    if (Test-Path $Key) {
        Write-Host "[3/5] Eliminando clave de registro: $Key"
        Remove-Item -Path $Key -Recurse -Force
    }
}

# 4. Eliminar directorios de programa
$PathsToDelete = @()
if ($TargetRole -in @("soporte", "todos")) {
    $PathsToDelete += "${env:ProgramFiles}\Cercano Soporte"
}
if ($TargetRole -in @("tecnico", "todos")) {
    $PathsToDelete += "${env:ProgramFiles}\Cercano Tecnico"
}

foreach ($Path in $PathsToDelete) {
    if (Test-Path $Path) {
        Write-Host "[4/5] Eliminando directorio de instalación: $Path"
        Remove-Item -Path $Path -Recurse -Force
    }
}

# 5. Purgar datos de aplicación y perfiles locales en %ProgramData%
$DataPath = "${env:ProgramData}\Cercano"
if (Test-Path $DataPath) {
    Write-Host "[5/5] Purgando datos locales compartidos en $DataPath"
    Remove-Item -Path $DataPath -Recurse -Force
}

# Eliminar accesos directos públicos
$Shortcuts = @(
    "${env:PUBLIC}\Desktop\Cercano Soporte.lnk",
    "${env:PUBLIC}\Desktop\Cercano Técnico.lnk",
    "${env:ProgramData}\Microsoft\Windows\Start Menu\Programs\Cercano Soporte.lnk",
    "${env:ProgramData}\Microsoft\Windows\Start Menu\Programs\Cercano Técnico.lnk"
)
foreach ($Lnk in $Shortcuts) {
    if (Test-Path $Lnk) {
        Remove-Item -Path $Lnk -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "=== Purga completada exitosamente. Sin archivos ni registros huérfanos. ===" -ForegroundColor Green
```

---

## 8. Antivirus, EDR y Windows Defender SmartScreen

### 8.1. Firma Authenticode corporativa (F3-06)

Todos los artefactos `.exe` y `.msi` generados por el generador de Cercano (`cercano-build` o `cercano-api`) deben contar con firma digital Authenticode válida y marca de tiempo RFC 3161 (tarea **F3-06**).

#### Distribución de certificados corporativos en los puestos de trabajo:
En entornos corporativos que utilicen una Autoridad de Certificación (CA) interna o certificado de firma privado, es imprescindible que la CA raíz y el certificado emisor estén registrados en los almacenes del sistema antes del despliegue masivo para evitar avisos o bloqueos de Windows Defender SmartScreen:

```cmd
:: Agregar certificado de la CA Raíz a las Autoridades de Certificación de Confianza
certutil.exe -addstore -f "Root" "\\cercano-dc\Deploy$\Certs\CA_Corporativa_Root.crt"

:: Agregar certificado de firma de Cercano a Editores de Confianza (Trusted Publishers)
certutil.exe -addstore -f "TrustedPublisher" "\\cercano-dc\Deploy$\Certs\Cercano_CodeSigning.cer"
```

Alternativamente, distribuya ambos certificados mediante GPO en:
**Configuración del equipo -> Directivas -> Configuración de Windows -> Configuración de seguridad -> Directivas de clave pública -> Entidades de certificación raíz de confianza / Editores de confianza**.

### 8.2. Exclusiones recomendadas para Antivirus y EDR (Defender for Endpoint, CrowdStrike, SentinelOne)

Para evitar falsos positivos derivados de las operaciones de captura de pantalla, inyección de eventos de ratón/teclado y elevación UAC en sesiones remotas:

#### Exclusiones de proceso:
- `%ProgramFiles%\Cercano Soporte\cercano.exe`
- `%ProgramFiles%\Cercano Tecnico\cercano.exe`

#### Exclusiones de carpetas:
- `%ProgramFiles%\Cercano Soporte\`
- `%ProgramFiles%\Cercano Tecnico\`
- `%ProgramData%\Cercano\`

#### Reglas de Firewall de Windows (Tráfico Saliente y Entrante):
Cercano requiere comunicación con los siguientes puertos y servicios centrales:

| Destino / Servicio | Protocolo | Puertos | Propósito |
|---|---|---|---|
| `cercano-hbbs` | TCP y UDP | `21115`, `21116` | Rendezvous, señalización, registro y heartbeat |
| `cercano-hbbr` | TCP | `21117` | Servidor de retransmisión (relay) |
| `cercano-api` | TCP (HTTPS) | `21114` | Autenticación, perfiles, auditoría y chat |
| P2P en red local | UDP / TCP | Dinámico (LAN) | Conexión directa peer-to-peer dentro de la subred |

Comando PowerShell para crear la regla de firewall local en los endpoints:
```powershell
New-NetFirewallRule -DisplayName "Cercano Cliente - Red Corporativa" `
    -Direction Outbound `
    -Program "%ProgramFiles%\Cercano Soporte\cercano.exe" `
    -Action Allow `
    -Profile Domain,Private
```

---

## 9. Script de verificación posterior al despliegue (Post-Deployment Health Check)

El siguiente script en PowerShell puede ejecutarse como paso de validación en consolas RMM, secuencias de tareas de SCCM/MDT o auditoría de cumplimiento en Intune.

Guarde el script como `Test-CercanoDeployment.ps1`:

```powershell
<#
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (C) 2026 Cercano Contributors
  Script de verificación de salud y auditoría post-despliegue de Cercano
#>
[CmdletBinding()]
param(
    [ValidateSet("soporte", "tecnico")]
    [string]$ExpectedRole = "soporte",
    [string]$ExpectedVersion = "1.0.0",
    [string]$ServerHost = "cercano-api.cercano.lan"
)

$TestsPassed = 0
$TotalTests = 5

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Auditoría de Post-Despliegue de Cercano ($ExpectedRole) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verificación del registro de instalación
$RegKey = if ($ExpectedRole -eq "soporte") {
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte"
} else {
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Tecnico"
}

Write-Host "[Prueba 1/5] Verificando clave de desinstalación en el Registro..." -NoNewline
if (Test-Path $RegKey) {
    $InstalledVer = (Get-ItemProperty -Path $RegKey -Name "DisplayVersion" -ErrorAction SilentlyContinue).DisplayVersion
    if ($InstalledVer -ge $ExpectedVersion) {
        Write-Host " [OK] (Versión: $InstalledVer)" -ForegroundColor Green
        $TestsPassed++
    } else {
        Write-Host " [FALLO] (Versión instalada $InstalledVer < esperada $ExpectedVersion)" -ForegroundColor Red
    }
} else {
    Write-Host " [FALLO] (Clave no encontrada en $RegKey)" -ForegroundColor Red
}

# 2. Verificación de binarios y perfil firmado en disco
$InstallDir = if ($ExpectedRole -eq "soporte") {
    "${env:ProgramFiles}\Cercano Soporte"
} else {
    "${env:ProgramFiles}\Cercano Tecnico"
}

$ExePath = Join-Path $InstallDir "cercano.exe"
$ProfilePath = Join-Path $InstallDir "cercano-profile.signed.json"

Write-Host "[Prueba 2/5] Verificando archivos críticos en $InstallDir..." -NoNewline
if ((Test-Path $ExePath) -and (Test-Path $ProfilePath)) {
    Write-Host " [OK] (Binario y perfil firmado presentes)" -ForegroundColor Green
    $TestsPassed++
} else {
    Write-Host " [FALLO] (Faltan archivos esenciales)" -ForegroundColor Red
}

# 3. Verificación de firma digital Authenticode
Write-Host "[Prueba 3/5] Verificando firma digital Authenticode en cercano.exe..." -NoNewline
if (Test-Path $ExePath) {
    $Sig = Get-AuthenticodeSignature -FilePath $ExePath
    if ($Sig.Status -eq "Valid") {
        Write-Host " [OK] (Firma válida: $($Sig.SignerCertificate.Subject))" -ForegroundColor Green
        $TestsPassed++
    } else {
        Write-Host " [ADVERTENCIA/FALLO] (Estado de firma: $($Sig.Status))" -ForegroundColor Yellow
        # En entornos de prueba de laboratorio LAN sin CA comercial, se puede admitir si la CA de pruebas está instalada
        if ($Sig.Status -eq "UnknownError" -or $Sig.Status -eq "NotSigned") {
            Write-Host "         Revise si el certificado raíz corporativo fue instalado." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host " [OMITIDO] (No existe el ejecutable)" -ForegroundColor Red
}

# 4. Verificación de servicio o proceso
Write-Host "[Prueba 4/5] Verificando estado del servicio o proceso de Cercano..." -NoNewline
$Service = Get-Service -Name "cercano" -ErrorAction SilentlyContinue
$Proc = Get-Process -Name "cercano" -ErrorAction SilentlyContinue

if (($Service -and $Service.Status -eq "Running") -or ($Proc)) {
    Write-Host " [OK] (Servicio/Proceso activo y en ejecución)" -ForegroundColor Green
    $TestsPassed++
} else {
    Write-Host " [FALLO] (Ni el servicio ni el proceso se encuentran activos)" -ForegroundColor Red
}

# 5. Verificación de conectividad con el servidor central
Write-Host "[Prueba 5/5] Comprobando conectividad de red con $ServerHost:21114..." -NoNewline
try {
    $TcpConn = Test-NetConnection -ComputerName $ServerHost -Port 21114 -WarningAction SilentlyContinue
    if ($TcpConn.TcpTestSucceeded) {
        Write-Host " [OK] (Conectividad TCP 21114 exitosa)" -ForegroundColor Green
        $TestsPassed++
    } else {
        Write-Host " [ADVERTENCIA] (No se pudo conectar al puerto 21114 de $ServerHost)" -ForegroundColor Yellow
    }
} catch {
    Write-Host " [ERROR DE RED] ($($_.Exception.Message))" -ForegroundColor Red
}

Write-Host "----------------------------------------------------------" -ForegroundColor Cyan
$SummaryColor = if ($TestsPassed -eq $TotalTests) { "Green" } else { "Yellow" }
Write-Host "Resultado final: $TestsPassed de $TotalTests pruebas superadas." -ForegroundColor $SummaryColor

if ($TestsPassed -ge 4) {
    Write-Host "Despliegue verificado y operativo." -ForegroundColor Green
    exit 0
} else {
    Write-Host "El despliegue presenta anomalías que requieren atención." -ForegroundColor Red
    exit 1
}
```

---

## 10. Resumen de buenas prácticas operativas

1. **Prueba previa en el Laboratorio LAN (F0-09):** Pruebe siempre los paquetes generados en máquinas virtuales limpias de Windows 10 y Windows 11 antes de vincular las GPO o políticas de Intune a la flota completa.
2. **Registro de eventos en la Auditoría:** Cada instalador desplegado que se comunique con el servidor reportará su `installer_id`, `role`, `version` y huella digital del equipo, quedando auditado en la categoría `build` y `conn` de `cercano-api`.
3. **Mantenimiento de licencias y atribución:** Tanto en despliegues interactivos como silenciosos, los metadatos de «Programas y características» y los diálogos de información preservan la licencia **GNU AGPL-3.0** y el enlace al repositorio oficial conforme a la política legal del proyecto.
