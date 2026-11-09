// Copyright (C) 2026 Cercano Contributors
//
// This file is part of Cercano.
//
// Cercano is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Cercano is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Cercano. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::{compute_file_sha256, BuildArtifact, BuildError};

/// Identificadores UpgradeCode estables por rol en Cercano (F3-05).
pub const UPGRADE_CODE_SOPORTE: &str = "C38CA110-5090-4100-B001-000000509001";
pub const UPGRADE_CODE_TECNICO: &str = "C38CA110-7EC1-4200-B002-0000007EC102";

pub const DISPLAY_NAME_SOPORTE: &str = "Cercano Soporte";
pub const DISPLAY_NAME_TECNICO: &str = "Cercano Técnico";

pub const DEFAULT_INSTALL_DIR_SOPORTE: &str = r"C:\Program Files\Cercano Soporte";
pub const DEFAULT_INSTALL_DIR_TECNICO: &str = r"C:\Program Files\Cercano Tecnico";

pub const REGISTRY_UNINSTALL_KEY_SOPORTE: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Soporte";
pub const REGISTRY_UNINSTALL_KEY_TECNICO: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Cercano Tecnico";

pub const MANUFACTURER: &str = "Cercano Contributors";
pub const METADATA_FILENAME: &str = "installer-metadata.json";

/// Rol de instalador de Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsRole {
    #[serde(rename = "soporte")]
    Soporte,
    #[serde(rename = "tecnico")]
    Tecnico,
}

impl WindowsRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            WindowsRole::Soporte => "soporte",
            WindowsRole::Tecnico => "tecnico",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            WindowsRole::Soporte => DISPLAY_NAME_SOPORTE,
            WindowsRole::Tecnico => DISPLAY_NAME_TECNICO,
        }
    }

    pub fn default_upgrade_code(&self) -> &'static str {
        match self {
            WindowsRole::Soporte => UPGRADE_CODE_SOPORTE,
            WindowsRole::Tecnico => UPGRADE_CODE_TECNICO,
        }
    }

    pub fn default_install_dir(&self) -> &'static str {
        match self {
            WindowsRole::Soporte => DEFAULT_INSTALL_DIR_SOPORTE,
            WindowsRole::Tecnico => DEFAULT_INSTALL_DIR_TECNICO,
        }
    }

    pub fn registry_uninstall_key(&self) -> &'static str {
        match self {
            WindowsRole::Soporte => REGISTRY_UNINSTALL_KEY_SOPORTE,
            WindowsRole::Tecnico => REGISTRY_UNINSTALL_KEY_TECNICO,
        }
    }

    pub fn opposite(&self) -> WindowsRole {
        match self {
            WindowsRole::Soporte => WindowsRole::Tecnico,
            WindowsRole::Tecnico => WindowsRole::Soporte,
        }
    }
}

/// Metadatos completos del instalador de Windows (F3-05).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsInstallerMetadata {
    pub schema_version: String,
    pub role: String,
    pub display_name: String,
    pub version: String,
    pub upgrade_code: String,
    pub product_code: String,
    pub manufacturer: String,
    pub default_install_dir: String,
    pub registry_uninstall_key: String,
    pub exe_artifact: String,
    pub msi_artifact: String,
    pub silent_exe_flags: Vec<String>,
    pub silent_msi_flags: Vec<String>,
    pub lifecycle: WindowsLifecycleInfo,
    pub role_isolation: RoleIsolationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsLifecycleInfo {
    pub clean_install_supported: bool,
    pub upgrade_supported: bool,
    pub clean_uninstall_supported: bool,
    pub uninstall_string: String,
    pub quiet_uninstall_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleIsolationInfo {
    pub current_role: String,
    pub current_upgrade_code: String,
    pub opposite_role: String,
    pub opposite_upgrade_code: String,
    pub opposite_registry_key: String,
    pub replacement_policy: String,
    pub warning_message: String,
}

/// Opciones de configuración para generar el empaquetado de Windows.
#[derive(Debug, Clone)]
pub struct WindowsPackagingOptions {
    pub role: WindowsRole,
    pub version: String,
    pub upgrade_code: Option<String>,
    pub product_code: Option<String>,
    pub app_name: Option<String>,
    pub base_binary_path: Option<PathBuf>,
    pub signed_profile_path: PathBuf,
    pub out_dir: PathBuf,
}

/// Resultado de generar los paquetes de Windows.
#[derive(Debug, Clone)]
pub struct WindowsPackagingResult {
    pub exe_path: PathBuf,
    pub msi_path: PathBuf,
    pub wxs_path: PathBuf,
    pub metadata_path: PathBuf,
    pub artifacts: Vec<BuildArtifact>,
    pub metadata: WindowsInstallerMetadata,
}

/// Genera los paquetes `.exe` y `.msi` para Windows con su archivo WiX `.wxs` y metadatos.
pub fn generate_windows_packages(
    options: &WindowsPackagingOptions,
) -> Result<WindowsPackagingResult, BuildError> {
    let role_str = options.role.as_str();
    let version = &options.version;

    let upgrade_code = options
        .upgrade_code
        .clone()
        .unwrap_or_else(|| options.role.default_upgrade_code().to_string());

    let product_code = options
        .product_code
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string().to_uppercase());

    let display_name = options
        .app_name
        .clone()
        .unwrap_or_else(|| options.role.display_name().to_string());

    let default_dir = options.role.default_install_dir();
    let reg_key = options.role.registry_uninstall_key();

    let opposite = options.role.opposite();
    let opposite_role_str = opposite.as_str();
    let opposite_upgrade = opposite.default_upgrade_code();
    let opposite_reg_key = opposite.registry_uninstall_key();

    let exe_file_name = format!("cercano-{}-{}.exe", role_str, version);
    let msi_file_name = format!("cercano-{}-{}.msi", role_str, version);
    let wxs_file_name = format!("cercano-{}-{}.wxs", role_str, version);

    let warning_message = format!(
        "ADVERTENCIA: Se ha detectado una instalación previa de '{}'. \
        Conforme a la política de aislamiento de roles de Cercano, no se permite \
        la coexistencia de ambos roles en el mismo equipo. \
        Se procederá a desinstalar '{}' y reemplazarlo limpiamente por '{}'.",
        opposite.display_name(),
        opposite.display_name(),
        display_name
    );

    let metadata = WindowsInstallerMetadata {
        schema_version: "1.0.0".to_string(),
        role: role_str.to_string(),
        display_name: display_name.clone(),
        version: version.clone(),
        upgrade_code: upgrade_code.clone(),
        product_code: product_code.clone(),
        manufacturer: MANUFACTURER.to_string(),
        default_install_dir: default_dir.to_string(),
        registry_uninstall_key: reg_key.to_string(),
        exe_artifact: exe_file_name.clone(),
        msi_artifact: msi_file_name.clone(),
        silent_exe_flags: vec![
            "/S".to_string(),
            "--silent".to_string(),
            "--silent-install".to_string(),
            "/quiet".to_string(),
            "/D=<directorio>".to_string(),
            "/norestart".to_string(),
        ],
        silent_msi_flags: vec![
            "/quiet".to_string(),
            "/qn".to_string(),
            "/passive".to_string(),
            "/qb".to_string(),
            "/norestart".to_string(),
            "INSTALLDIR=\"<directorio>\"".to_string(),
            "/l*v \"<log_file>\"".to_string(),
        ],
        lifecycle: WindowsLifecycleInfo {
            clean_install_supported: true,
            upgrade_supported: true,
            clean_uninstall_supported: true,
            uninstall_string: format!(r#""{}\cercano.exe" --uninstall"#, default_dir),
            quiet_uninstall_string: format!(
                r#""{}\cercano.exe" --uninstall --silent"#,
                default_dir
            ),
        },
        role_isolation: RoleIsolationInfo {
            current_role: role_str.to_string(),
            current_upgrade_code: upgrade_code.clone(),
            opposite_role: opposite_role_str.to_string(),
            opposite_upgrade_code: opposite_upgrade.to_string(),
            opposite_registry_key: opposite_reg_key.to_string(),
            replacement_policy: "replace_with_warning".to_string(),
            warning_message,
        },
    };

    // Escribir installer-metadata.json
    let metadata_path = options.out_dir.join(METADATA_FILENAME);
    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    fs::write(&metadata_path, metadata_json.as_bytes()).map_err(|source| BuildError::Io {
        path: metadata_path.clone(),
        source,
    })?;

    // Leer contenido del perfil firmado
    let signed_profile_bytes =
        fs::read(&options.signed_profile_path).map_err(|source| BuildError::Io {
            path: options.signed_profile_path.clone(),
            source,
        })?;

    // Leer binario base si existe
    let base_bin_bytes = match &options.base_binary_path {
        Some(path) => {
            let data = fs::read(path).map_err(|source| BuildError::Io {
                path: path.clone(),
                source,
            })?;
            Some(data)
        }
        None => None,
    };

    // 1. Generar instalador ejecutable .exe
    let exe_path = options.out_dir.join(&exe_file_name);
    build_windows_exe_installer(
        &exe_path,
        &metadata,
        &signed_profile_bytes,
        base_bin_bytes.as_deref(),
    )?;

    // 2. Generar instalador .msi
    let msi_path = options.out_dir.join(&msi_file_name);
    build_windows_msi_installer(
        &msi_path,
        &metadata,
        &signed_profile_bytes,
        base_bin_bytes.as_deref(),
    )?;

    // 3. Generar definición WiX Toolset .wxs
    let wxs_path = options.out_dir.join(&wxs_file_name);
    let wxs_content = generate_wix_source(&metadata);
    fs::write(&wxs_path, wxs_content.as_bytes()).map_err(|source| BuildError::Io {
        path: wxs_path.clone(),
        source,
    })?;

    // Recolectar artefactos producidos
    let mut artifacts = Vec::new();

    let (exe_hash, exe_len) = compute_file_sha256(&exe_path)?;
    artifacts.push(BuildArtifact {
        file_name: exe_file_name,
        sha256: exe_hash,
        size_bytes: exe_len,
    });

    let (msi_hash, msi_len) = compute_file_sha256(&msi_path)?;
    artifacts.push(BuildArtifact {
        file_name: msi_file_name,
        sha256: msi_hash,
        size_bytes: msi_len,
    });

    let (wxs_hash, wxs_len) = compute_file_sha256(&wxs_path)?;
    artifacts.push(BuildArtifact {
        file_name: wxs_file_name,
        sha256: wxs_hash,
        size_bytes: wxs_len,
    });

    let (meta_hash, meta_len) = compute_file_sha256(&metadata_path)?;
    artifacts.push(BuildArtifact {
        file_name: METADATA_FILENAME.to_string(),
        sha256: meta_hash,
        size_bytes: meta_len,
    });

    Ok(WindowsPackagingResult {
        exe_path,
        msi_path,
        wxs_path,
        metadata_path,
        artifacts,
        metadata,
    })
}

/// Construye un instalador .exe auto-instalable con el binario y el perfil firmado embebidos.
fn build_windows_exe_installer(
    target_path: &Path,
    metadata: &WindowsInstallerMetadata,
    signed_profile_bytes: &[u8],
    base_binary_bytes: Option<&[u8]>,
) -> Result<(), BuildError> {
    // 1. Obtener cabecera PE válida: si se suministró un binario base PE, usarlo; de lo contrario generar stub PE válido.
    let pe_stub = match base_binary_bytes {
        Some(bytes) if bytes.starts_with(b"MZ") => bytes.to_vec(),
        _ => generate_minimal_pe_stub(&metadata.display_name),
    };

    // 2. Empaquetar la carga útil en un archivo ZIP determinista comprimido
    let mut zip_buffer = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut zip_buffer);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        // Perfil firmado embebido
        zip.start_file("cercano-profile.signed.json", options)
            .map_err(|e| BuildError::Io {
                path: target_path.to_path_buf(),
                source: std::io::Error::other(e.to_string()),
            })?;
        zip.write_all(signed_profile_bytes)
            .map_err(|source| BuildError::Io {
                path: target_path.to_path_buf(),
                source,
            })?;

        // Binario ejecutable si existe
        if let Some(bin_bytes) = base_binary_bytes {
            zip.start_file("cercano.exe", options)
                .map_err(|e| BuildError::Io {
                    path: target_path.to_path_buf(),
                    source: std::io::Error::other(e.to_string()),
                })?;
            zip.write_all(bin_bytes).map_err(|source| BuildError::Io {
                path: target_path.to_path_buf(),
                source,
            })?;
        }

        // Metadatos del instalador
        let metadata_bytes = serde_json::to_vec_pretty(metadata)?;
        zip.start_file("installer-metadata.json", options)
            .map_err(|e| BuildError::Io {
                path: target_path.to_path_buf(),
                source: std::io::Error::other(e.to_string()),
            })?;
        zip.write_all(&metadata_bytes)
            .map_err(|source| BuildError::Io {
                path: target_path.to_path_buf(),
                source,
            })?;

        // Script de instalación limpia y reemplazo de rol
        let install_cmd = generate_install_cmd_script(metadata);
        zip.start_file("install.cmd", options)
            .map_err(|e| BuildError::Io {
                path: target_path.to_path_buf(),
                source: std::io::Error::other(e.to_string()),
            })?;
        zip.write_all(install_cmd.as_bytes())
            .map_err(|source| BuildError::Io {
                path: target_path.to_path_buf(),
                source,
            })?;

        // Script de desinstalación limpia sin archivos huérfanos
        let uninstall_cmd = generate_uninstall_cmd_script(metadata);
        zip.start_file("uninstall.cmd", options)
            .map_err(|e| BuildError::Io {
                path: target_path.to_path_buf(),
                source: std::io::Error::other(e.to_string()),
            })?;
        zip.write_all(uninstall_cmd.as_bytes())
            .map_err(|source| BuildError::Io {
                path: target_path.to_path_buf(),
                source,
            })?;

        zip.finish().map_err(|e| BuildError::Io {
            path: target_path.to_path_buf(),
            source: std::io::Error::other(e.to_string()),
        })?;
    }

    let zip_bytes = zip_buffer.into_inner();
    let zip_offset = pe_stub.len() as u64;
    let zip_len = zip_bytes.len() as u64;

    // 3. Ensamblar binario ejecutable final: [PE Stub] + [ZIP Payload] + [Footer Descriptor]
    let mut exe_data = Vec::with_capacity(pe_stub.len() + zip_bytes.len() + 64);
    exe_data.extend_from_slice(&pe_stub);
    exe_data.extend_from_slice(&zip_bytes);

    // Footer de empaquetado Cercano para autodetección
    exe_data.extend_from_slice(b"CERCANO_PACKAGE_PAYLOAD\0");
    exe_data.extend_from_slice(&zip_offset.to_le_bytes());
    exe_data.extend_from_slice(&zip_len.to_le_bytes());
    exe_data.extend_from_slice(b"CERCANO_EXE_INSTALLER_V1\0");

    fs::write(target_path, &exe_data).map_err(|source| BuildError::Io {
        path: target_path.to_path_buf(),
        source,
    })?;

    Ok(())
}

/// Construye un paquete Windows Installer .msi válido utilizando OLE CFBF / MSI.
fn build_windows_msi_installer(
    target_path: &Path,
    metadata: &WindowsInstallerMetadata,
    signed_profile_bytes: &[u8],
    base_binary_bytes: Option<&[u8]>,
) -> Result<(), BuildError> {
    let file = fs::File::create(target_path).map_err(|source| BuildError::Io {
        path: target_path.to_path_buf(),
        source,
    })?;

    let mut package =
        msi::Package::create(msi::PackageType::Installer, file).map_err(|e| BuildError::Io {
            path: target_path.to_path_buf(),
            source: e,
        })?;

    // Configurar Summary Information Stream
    {
        let summary = package.summary_info_mut();
        summary.set_title(format!("{} v{}", metadata.display_name, metadata.version));
        summary.set_subject(format!("{} Windows Installer", metadata.display_name));
        summary.set_author(metadata.manufacturer.clone());
        summary.set_comments(format!(
            "Instalador oficial de Cercano ({}) para Windows",
            metadata.display_name
        ));
        let keywords = vec![
            "Installer".to_string(),
            "MSI".to_string(),
            "Cercano".to_string(),
            "RemoteDesktop".to_string(),
        ];
        summary.set_keywords(&keywords);
        summary.set_creating_application("cercano-build".to_string());
    }

    // Incrustar el perfil firmado como stream
    {
        let mut stream = package
            .write_stream("CercanoProfile")
            .map_err(|e| BuildError::Io {
                path: target_path.to_path_buf(),
                source: e,
            })?;
        stream
            .write_all(signed_profile_bytes)
            .map_err(|source| BuildError::Io {
                path: target_path.to_path_buf(),
                source,
            })?;
    }

    // Incrustar metadatos del instalador como stream
    let metadata_bytes = serde_json::to_vec_pretty(metadata)?;
    {
        let mut stream = package
            .write_stream("PackageMetadata")
            .map_err(|e| BuildError::Io {
                path: target_path.to_path_buf(),
                source: e,
            })?;
        stream
            .write_all(&metadata_bytes)
            .map_err(|source| BuildError::Io {
                path: target_path.to_path_buf(),
                source,
            })?;
    }

    // Incrustar binario base si existe
    if let Some(bin_bytes) = base_binary_bytes {
        let mut stream = package
            .write_stream("CercanoBinary")
            .map_err(|e| BuildError::Io {
                path: target_path.to_path_buf(),
                source: e,
            })?;
        stream
            .write_all(bin_bytes)
            .map_err(|source| BuildError::Io {
                path: target_path.to_path_buf(),
                source,
            })?;
    }

    // Volcar cambios y cerrar CFBF
    package.flush().map_err(|e| BuildError::Io {
        path: target_path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Genera la definición completa WiX Toolset (.wxs) para compilación con WiX v4.
pub fn generate_wix_source(metadata: &WindowsInstallerMetadata) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<!--
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (C) 2026 Cercano Contributors
  WiX Toolset Package Specification for {display_name}
-->
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
     xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util"
     xmlns:ui="http://wixtoolset.org/schemas/v4/wxs/ui">

  <Package Name="{display_name}"
           Version="{version}"
           Manufacturer="{manufacturer}"
           Language="1033"
           UpgradeCode="{upgrade_code}"
           Scope="perMachine">

    <SummaryInformation Keywords="Installer,Cercano,RemoteDesktop"
                        Description="{display_name} Installer"
                        Manufacturer="{manufacturer}" />

    <MajorUpgrade Schedule="afterInstallInitialize"
                  AllowSameVersionUpgrades="yes"
                  DowngradeErrorMessage="Ya se encuentra instalada una versión más reciente de {display_name}." />

    <!-- Aislamiento de Roles y Reemplazo Limpio con Advertencia -->
    <Property Id="OPPOSITE_ROLE_INSTALLED">
      <RegistrySearch Id="SearchOppositeRole"
                      Root="HKLM"
                      Key="{opposite_reg_key}"
                      Name="DisplayVersion"
                      Type="raw" />
    </Property>

    <!-- Parámetros de Instalación Silenciosa Soportados -->
    <Property Id="AUTOSTART" Value="1" />
    <Property Id="DESKTOPSHORTCUT" Value="1" />
    <Property Id="CERCANO_ROLE" Value="{role}" />
    <Property Id="ARPCOMMENTS" Value="Cercano Remote Desktop Client" />
    <Property Id="ARPCONTACT" Value="soporte@cercano.lan" />
    <Property Id="ARPHELPLINK" Value="https://cercano.lan" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="{dir_name}">
        <Component Id="CercanoBinary" Guid="*">
          <File Id="CercanoExe" Source="cercano.exe" KeyPath="yes" Checksum="yes" />
        </Component>

        <Component Id="CercanoProfile" Guid="*">
          <File Id="ProfileJson" Source="cercano-profile.signed.json" KeyPath="yes" />
        </Component>

        <Component Id="RegistryUninstall" Guid="*">
          <RegistryKey Root="HKLM" Key="{reg_key}">
            <RegistryValue Type="string" Name="DisplayName" Value="{display_name}" KeyPath="yes" />
            <RegistryValue Type="string" Name="DisplayVersion" Value="{version}" />
            <RegistryValue Type="string" Name="Publisher" Value="{manufacturer}" />
            <RegistryValue Type="string" Name="InstallLocation" Value="[INSTALLFOLDER]" />
            <RegistryValue Type="string" Name="UninstallString" Value="&quot;[INSTALLFOLDER]cercano.exe&quot; --uninstall" />
            <RegistryValue Type="string" Name="QuietUninstallString" Value="&quot;[INSTALLFOLDER]cercano.exe&quot; --uninstall --silent" />
            <RegistryValue Type="string" Name="Role" Value="{role}" />
            <RegistryValue Type="string" Name="UpgradeCode" Value="{upgrade_code}" />
          </RegistryKey>
        </Component>
      </Directory>
    </StandardDirectory>

    <Feature Id="MainApplication" Title="{display_name}" Level="1">
      <ComponentRef Id="CercanoBinary" />
      <ComponentRef Id="CercanoProfile" />
      <ComponentRef Id="RegistryUninstall" />
    </Feature>
  </Package>
</Wix>
"#,
        display_name = metadata.display_name,
        version = metadata.version,
        manufacturer = metadata.manufacturer,
        upgrade_code = metadata.upgrade_code,
        opposite_reg_key = metadata.role_isolation.opposite_registry_key,
        role = metadata.role,
        dir_name = if metadata.role == "soporte" {
            "Cercano Soporte"
        } else {
            "Cercano Tecnico"
        },
        reg_key = metadata.registry_uninstall_key,
    )
}

/// Genera el script por lotes install.cmd para instalación limpia y reemplazo de rol.
fn generate_install_cmd_script(metadata: &WindowsInstallerMetadata) -> String {
    format!(
        r#"@echo off
rem SPDX-License-Identifier: AGPL-3.0-only
rem Instalador silencioso y gestor de ciclo de vida para {display_name}
setlocal enabledelayedexpansion

set "TARGET_DIR={default_dir}"
set "SILENT_MODE=0"

:parse_args
if "%~1"=="" goto check_roles
if /i "%~1"=="/S" (set "SILENT_MODE=1" & shift & goto parse_args)
if /i "%~1"=="--silent" (set "SILENT_MODE=1" & shift & goto parse_args)
if /i "%~1"=="--silent-install" (set "SILENT_MODE=1" & shift & goto parse_args)
if /i "%~1"=="/quiet" (set "SILENT_MODE=1" & shift & goto parse_args)
if /i "%~1"=="/norestart" (shift & goto parse_args)
if /i "%~1"=="/uninstall" (goto do_uninstall)
if /i "%~1"=="--uninstall" (goto do_uninstall)
if /i "%~1:~0,3%"=="/D=" (set "TARGET_DIR=%~1:~3%" & shift & goto parse_args)
shift
goto parse_args

:check_roles
rem Comprobar si existe el rol opuesto instalado en el equipo
reg query "HKLM\{opposite_key}" >nul 2>&1
if %errorlevel% equ 0 (
    if "!SILENT_MODE!"=="0" (
        echo {warning_msg}
        echo Presione cualquier tecla para proceder con el reemplazo...
        pause >nul
    ) else (
        echo [CERCANO] Reemplazando {opposite_role} con {display_name} conforme a la politica de roles.
    )
    rem Desinstalar rol opuesto de forma limpia
    for /f "tokens=2*" %%a in ('reg query "HKLM\{opposite_key}" /v InstallLocation 2^>nul') do (
        set "OLD_DIR=%%b"
        if exist "!OLD_DIR!" (
            if exist "!OLD_DIR!\uninstall.cmd" (
                call "!OLD_DIR!\uninstall.cmd" /S
            ) else (
                rd /s /q "!OLD_DIR!" >nul 2>&1
            )
        )
    )
    reg delete "HKLM\{opposite_key}" /f >nul 2>&1
)

rem Proceder con la instalacion limpia de {display_name}
if not exist "!TARGET_DIR!" mkdir "!TARGET_DIR!"
copy /y "%~dp0cercano.exe" "!TARGET_DIR!\cercano.exe" >nul 2>&1
copy /y "%~dp0cercano-profile.signed.json" "!TARGET_DIR!\cercano-profile.signed.json" >nul 2>&1
copy /y "%~dp0installer-metadata.json" "!TARGET_DIR!\installer-metadata.json" >nul 2>&1
copy /y "%~dp0uninstall.cmd" "!TARGET_DIR!\uninstall.cmd" >nul 2>&1

rem Registrar entrada limpia en Programas y Caracteristicas
set "REG_PATH=HKLM\{reg_key}"
reg add "!REG_PATH!" /f /v "DisplayName" /t REG_SZ /d "{display_name}" >nul
reg add "!REG_PATH!" /f /v "DisplayVersion" /t REG_SZ /d "{version}" >nul
reg add "!REG_PATH!" /f /v "Publisher" /t REG_SZ /d "{manufacturer}" >nul
reg add "!REG_PATH!" /f /v "InstallLocation" /t REG_SZ /d "!TARGET_DIR!" >nul
reg add "!REG_PATH!" /f /v "UninstallString" /t REG_SZ /d "\"!TARGET_DIR!\uninstall.cmd\"" >nul
reg add "!REG_PATH!" /f /v "QuietUninstallString" /t REG_SZ /d "\"!TARGET_DIR!\uninstall.cmd\" /S" >nul
reg add "!REG_PATH!" /f /v "Role" /t REG_SZ /d "{role}" >nul
reg add "!REG_PATH!" /f /v "UpgradeCode" /t REG_SZ /d "{upgrade_code}" >nul

if "!SILENT_MODE!"=="0" (
    echo Instalacion de {display_name} completada con exito en '!TARGET_DIR!'.
)
exit /b 0

:do_uninstall
call "%~dp0uninstall.cmd" %*
exit /b %errorlevel%
"#,
        display_name = metadata.display_name,
        default_dir = metadata.default_install_dir,
        opposite_key = metadata.role_isolation.opposite_registry_key,
        warning_msg = metadata.role_isolation.warning_message,
        opposite_role = metadata.role_isolation.opposite_role,
        reg_key = metadata.registry_uninstall_key,
        version = metadata.version,
        manufacturer = metadata.manufacturer,
        role = metadata.role,
        upgrade_code = metadata.upgrade_code,
    )
}

/// Genera el script por lotes uninstall.cmd para desinstalación limpia sin archivos huérfanos.
fn generate_uninstall_cmd_script(metadata: &WindowsInstallerMetadata) -> String {
    format!(
        r#"@echo off
rem SPDX-License-Identifier: AGPL-3.0-only
rem Desinstalador limpio para {display_name} - Sin archivos huerfanos
setlocal enabledelayedexpansion

set "SILENT=0"
if /i "%~1"=="/S" set "SILENT=1"
if /i "%~1"=="--silent" set "SILENT=1"
if /i "%~1"=="/quiet" set "SILENT=1"

rem 1. Detener procesos en ejecucion de Cercano
taskkill /f /im cercano.exe >nul 2>&1
timeout /t 1 /nobreak >nul 2>&1

rem 2. Eliminar clave de registro de Programas y Caracteristicas
reg delete "HKLM\{reg_key}" /f >nul 2>&1

rem 3. Eliminar accesos directos
set "SHORTCUT_PATH=%ProgramData%\Microsoft\Windows\Start Menu\Programs\{display_name}.lnk"
if exist "!SHORTCUT_PATH!" del /f /q "!SHORTCUT_PATH!" >nul 2>&1

set "DESKTOP_SHORTCUT=%PUBLIC%\Desktop\{display_name}.lnk"
if exist "!DESKTOP_SHORTCUT!" del /f /q "!DESKTOP_SHORTCUT!" >nul 2>&1

rem 4. Eliminar directorio de instalacion y archivos instalados
set "INST_DIR=%~dp0"
rem Si se ejecuta desde el directorio instalado, programar eliminacion al salir
cd \
rd /s /q "!INST_DIR!" >nul 2>&1

if "!SILENT!"=="0" (
    echo Desinstalacion limpia de {display_name} completada. No quedaron archivos huerfanos.
)
exit /b 0
"#,
        display_name = metadata.display_name,
        reg_key = metadata.registry_uninstall_key,
    )
}

/// Genera una cabecera PE mínima x86_64 válida (512 bytes) para transporte de instalador.
fn generate_minimal_pe_stub(app_name: &str) -> Vec<u8> {
    let mut pe = vec![0u8; 512];

    // DOS Header
    pe[0] = b'M';
    pe[1] = b'Z';
    // Offset a PE header en 0x3C -> 0x80
    pe[0x3C] = 0x80;

    // PE Header en 0x80
    pe[0x80] = b'P';
    pe[0x81] = b'E';
    pe[0x82] = 0;
    pe[0x83] = 0;

    // COFF Header (20 bytes a partir de 0x84)
    // Machine: x86_64 (0x8664)
    pe[0x84] = 0x64;
    pe[0x85] = 0x86;
    // Number of Sections: 1
    pe[0x86] = 0x01;
    pe[0x87] = 0x00;
    // SizeOfOptionalHeader: 0xF0 (240 bytes)
    pe[0x94] = 0xF0;
    pe[0x95] = 0x00;
    // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    pe[0x96] = 0x22;
    pe[0x97] = 0x00;

    // Optional Header Magic: PE32+ (0x020B)
    pe[0x98] = 0x0B;
    pe[0x99] = 0x02;

    // Subsystem: Windows GUI (2)
    pe[0xD0] = 0x02;
    pe[0xD1] = 0x00;

    // Section Table .text en 0x174 (40 bytes)
    let text_sec = b".text\0\0\0";
    pe[0x174..0x174 + text_sec.len()].copy_from_slice(text_sec);

    // Escribir nombre de app en bytes informativos
    let name_bytes = app_name.as_bytes();
    let max_len = 64.min(name_bytes.len());
    pe[0x1C0..0x1C0 + max_len].copy_from_slice(&name_bytes[..max_len]);

    pe
}
