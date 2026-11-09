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
use std::path::{Path, PathBuf};
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use cercano_api::profile::{CercanoProfile, ProfileRole, SignedCercanoProfile};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod windows;

/// Clave privada de desarrollo por defecto (32 bytes deterministas).
pub const DEFAULT_DEV_SIGNING_KEY_BYTES: [u8; 32] = [42u8; 32];
pub const DEFAULT_DEV_KEY_ID: &str = "cercano-dev-key";
pub const DEFAULT_SIGNED_PROFILE_NAME: &str = "cercano-profile.signed.json";
pub const DEFAULT_MANIFEST_NAME: &str = "build-manifest.json";
pub const DEFAULT_CHECKSUMS_NAME: &str = "SHA256SUMS";

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("Error de E/S en '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Error de serialización/deserialización JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Error de validación de invariantes de perfil: {0}")]
    ProfileValidation(#[from] cercano_api::profile::ProfileValidationError),

    #[error("Error de firma o canonicalización del perfil: {0}")]
    ProfileVerification(#[from] cercano_api::profile::ProfileVerificationError),

    #[error("Formato inválido de clave privada Ed25519: {0}")]
    InvalidSigningKeyFormat(String),

    #[error("El binario base especificado no existe: '{0}'")]
    BaseBinaryNotFound(PathBuf),

    #[error("El archivo de perfil especificado no existe: '{0}'")]
    ProfileNotFound(PathBuf),
}

/// Opciones de compilación y empaquetado para el CLI cercano-build.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub profile_path: PathBuf,
    pub out_dir: PathBuf,
    pub signing_key_path: Option<PathBuf>,
    pub key_id: Option<String>,
    pub base_binary_path: Option<PathBuf>,
    pub dry_run: bool,
    pub package_windows: bool,
    pub upgrade_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildArtifact {
    pub file_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaseBinaryInfo {
    pub file_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Manifiesto de compilación y procedencia `build-manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildManifest {
    pub schema_version: String,
    pub build_id: String,
    pub profile_id: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    pub version: String,
    pub strategy: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_binary: Option<BaseBinaryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_metadata: Option<windows::WindowsInstallerMetadata>,
    pub artifacts: Vec<BuildArtifact>,
}

/// Resultado de una ejecución exitosa de empaquetado.
#[derive(Debug, Clone)]
pub struct BuildResult {
    pub target_dir: PathBuf,
    pub role: String,
    pub version: String,
    pub profile_id: String,
    pub signed_profile_path: PathBuf,
    pub manifest_path: PathBuf,
    pub checksums_path: PathBuf,
    pub base_binary_path: Option<PathBuf>,
    pub windows_exe_path: Option<PathBuf>,
    pub windows_msi_path: Option<PathBuf>,
    pub elapsed_ms: u128,
}

/// Parsea una clave privada Ed25519 desde bytes crudos (32 bytes), keypair (64 bytes),
/// representación Hexadecimal o Base64.
pub fn parse_signing_key(bytes: &[u8]) -> Result<SigningKey, BuildError> {
    // 1. Si es texto UTF-8, comprobar primero si es Hex (64 caracteres) o Base64
    if let Ok(text) = std::str::from_utf8(bytes) {
        let trimmed = text.trim();
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(decoded) = hex::decode(trimmed) {
                if decoded.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    return Ok(SigningKey::from_bytes(&arr));
                }
            }
        }

        if let Ok(decoded) = BASE64_STANDARD.decode(trimmed) {
            if decoded.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded);
                return Ok(SigningKey::from_bytes(&arr));
            } else if decoded.len() == 64 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded[..32]);
                return Ok(SigningKey::from_bytes(&arr));
            }
        }
    }

    // 2. 32 bytes binarios directos
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        return Ok(SigningKey::from_bytes(&arr));
    }

    // 3. 64 bytes binarios directos (keypair)
    if bytes.len() == 64 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        return Ok(SigningKey::from_bytes(&arr));
    }

    Err(BuildError::InvalidSigningKeyFormat(
        "La clave privada Ed25519 debe constar de 32 bytes binarios, 64 caracteres hex o Base64 válido".to_string(),
    ))
}

/// Carga la clave de firma desde un archivo o retorna la clave determinista de desarrollo.
pub fn load_signing_key(path: Option<&Path>) -> Result<SigningKey, BuildError> {
    match path {
        Some(p) => {
            let data = fs::read(p).map_err(|source| BuildError::Io {
                path: p.to_path_buf(),
                source,
            })?;
            parse_signing_key(&data)
        }
        None => Ok(SigningKey::from_bytes(&DEFAULT_DEV_SIGNING_KEY_BYTES)),
    }
}

/// Lee y valida un perfil JSON (ya sea raw CercanoProfile o SignedCercanoProfile).
/// Retorna la estructura CercanoProfile validada y el sobre firmado si existía.
pub fn load_and_validate_profile(
    path: &Path,
) -> Result<(CercanoProfile, Option<SignedCercanoProfile>), BuildError> {
    if !path.is_file() {
        return Err(BuildError::ProfileNotFound(path.to_path_buf()));
    }

    let content = fs::read_to_string(path).map_err(|source| BuildError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    // Intentar primero como sobre firmado SignedCercanoProfile
    if let Ok(signed) = serde_json::from_str::<SignedCercanoProfile>(&content) {
        signed.profile.validate()?;
        return Ok((signed.profile.clone(), Some(signed)));
    }

    // Intentar como perfil crudo CercanoProfile
    let profile: CercanoProfile = serde_json::from_str(&content)?;
    profile.validate()?;
    Ok((profile, None))
}

/// Calcula el hash SHA-256 en formato hexadecimal minúscula.
pub fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Calcula el hash SHA-256 y tamaño en bytes de un archivo.
pub fn compute_file_sha256(path: &Path) -> Result<(String, u64), BuildError> {
    let data = fs::read(path).map_err(|source| BuildError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let len = data.len() as u64;
    Ok((compute_sha256(&data), len))
}

/// Ejecuta el proceso de build y empaquetado (Estrategia A) o valida en modo dry-run.
pub fn execute_build(options: &BuildOptions) -> Result<Option<BuildResult>, BuildError> {
    let start_time = Instant::now();

    // 1. Cargar y validar el perfil y sus invariantes
    let (profile, existing_signed) = load_and_validate_profile(&options.profile_path)?;

    // Si es dry-run, terminar tras validar con éxito
    if options.dry_run {
        return Ok(None);
    }

    // 2. Comprobar binario base si fue provisto
    if let Some(ref base_path) = options.base_binary_path {
        if !base_path.is_file() {
            return Err(BuildError::BaseBinaryNotFound(base_path.clone()));
        }
    }

    // 3. Determinar o generar el sobre firmado
    let signed_profile = match (existing_signed, &options.signing_key_path) {
        (Some(signed), None) => {
            // Mantener sobre firmado original si no se especificó otra clave
            signed
        }
        _ => {
            let signing_key = load_signing_key(options.signing_key_path.as_deref())?;
            let key_id = options
                .key_id
                .clone()
                .or_else(|| Some(DEFAULT_DEV_KEY_ID.to_string()));
            profile.sign(&signing_key, key_id)?
        }
    };

    let role_str = match profile.role {
        ProfileRole::Soporte => "soporte",
        ProfileRole::Tecnico => "tecnico",
    };
    let version_str = &profile.schema_version;

    // 4. Crear carpeta de artefacto con el nombre del rol: cercan-{rol}-{versión}
    let bundle_folder_name = format!("cercano-{}-{}", role_str, version_str);
    let target_dir = options.out_dir.join(&bundle_folder_name);
    fs::create_dir_all(&target_dir).map_err(|source| BuildError::Io {
        path: target_dir.clone(),
        source,
    })?;

    // 5. Copiar binario base si existe
    let mut base_binary_info = None;
    let mut packaged_base_path = None;
    let mut artifacts = Vec::new();

    if let Some(ref base_path) = options.base_binary_path {
        let file_name = base_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("cercano");
        let dest_path = target_dir.join(file_name);
        fs::copy(base_path, &dest_path).map_err(|source| BuildError::Io {
            path: dest_path.clone(),
            source,
        })?;

        let (base_hash, base_len) = compute_file_sha256(&dest_path)?;
        base_binary_info = Some(BaseBinaryInfo {
            file_name: file_name.to_string(),
            sha256: base_hash.clone(),
            size_bytes: base_len,
        });
        artifacts.push(BuildArtifact {
            file_name: file_name.to_string(),
            sha256: base_hash,
            size_bytes: base_len,
        });
        packaged_base_path = Some(dest_path);
    }

    // 6. Escribir perfil firmado `cercano-profile.signed.json`
    let signed_profile_path = target_dir.join(DEFAULT_SIGNED_PROFILE_NAME);
    let signed_json = serde_json::to_string_pretty(&signed_profile)?;
    fs::write(&signed_profile_path, signed_json.as_bytes()).map_err(|source| BuildError::Io {
        path: signed_profile_path.clone(),
        source,
    })?;

    let (profile_hash, profile_len) = compute_file_sha256(&signed_profile_path)?;
    artifacts.push(BuildArtifact {
        file_name: DEFAULT_SIGNED_PROFILE_NAME.to_string(),
        sha256: profile_hash,
        size_bytes: profile_len,
    });

    // 7. Empaquetado Windows (.exe y .msi) si fue solicitado (F3-05)
    let mut windows_exe_path = None;
    let mut windows_msi_path = None;
    let mut windows_metadata = None;

    if options.package_windows {
        let win_role = match profile.role {
            ProfileRole::Soporte => windows::WindowsRole::Soporte,
            ProfileRole::Tecnico => windows::WindowsRole::Tecnico,
        };

        let app_name_override = profile.identity.as_ref().and_then(|id| id.app_name.clone());

        let win_opts = windows::WindowsPackagingOptions {
            role: win_role,
            version: version_str.clone(),
            upgrade_code: options.upgrade_code.clone(),
            product_code: None,
            app_name: app_name_override,
            base_binary_path: packaged_base_path.clone(),
            signed_profile_path: signed_profile_path.clone(),
            out_dir: target_dir.clone(),
        };

        let win_res = windows::generate_windows_packages(&win_opts)?;
        for art in win_res.artifacts {
            artifacts.push(art);
        }
        windows_exe_path = Some(win_res.exe_path);
        windows_msi_path = Some(win_res.msi_path);
        windows_metadata = Some(win_res.metadata);
    }

    // 8. Generar `build-manifest.json`
    let build_id = uuid::Uuid::new_v4().to_string();
    let app_name = profile.identity.as_ref().and_then(|id| id.app_name.clone());
    let manifest = BuildManifest {
        schema_version: "1.0.0".to_string(),
        build_id,
        profile_id: profile.profile_id.clone(),
        role: role_str.to_string(),
        app_name,
        version: version_str.clone(),
        strategy: "A".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        signing_key_id: signed_profile.key_id.clone(),
        base_binary: base_binary_info,
        windows_metadata,
        artifacts,
    };

    let manifest_path = target_dir.join(DEFAULT_MANIFEST_NAME);
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, manifest_json.as_bytes()).map_err(|source| BuildError::Io {
        path: manifest_path.clone(),
        source,
    })?;

    // 9. Generar `SHA256SUMS` para todos los archivos generados (ordenados alfabéticamente)
    let checksums_path = target_dir.join(DEFAULT_CHECKSUMS_NAME);
    let mut file_entries = Vec::new();

    for entry in fs::read_dir(&target_dir).map_err(|source| BuildError::Io {
        path: target_dir.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| BuildError::Io {
            path: target_dir.clone(),
            source,
        })?;
        let path = entry.path();
        if path.is_file() {
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if fname != DEFAULT_CHECKSUMS_NAME {
                let (hash, _) = compute_file_sha256(&path)?;
                file_entries.push((fname.to_string(), hash));
            }
        }
    }

    file_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut checksums_content = String::new();
    for (name, hash) in file_entries {
        checksums_content.push_str(&format!("{}  {}\n", hash, name));
    }

    fs::write(&checksums_path, checksums_content.as_bytes()).map_err(|source| BuildError::Io {
        path: checksums_path.clone(),
        source,
    })?;

    let elapsed_ms = start_time.elapsed().as_millis();

    Ok(Some(BuildResult {
        target_dir,
        role: role_str.to_string(),
        version: version_str.clone(),
        profile_id: profile.profile_id,
        signed_profile_path,
        manifest_path,
        checksums_path,
        base_binary_path: packaged_base_path,
        windows_exe_path,
        windows_msi_path,
        elapsed_ms,
    }))
}
