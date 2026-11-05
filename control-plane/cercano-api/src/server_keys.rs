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
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::OsRng;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::auth::AuthenticatedUser;
use crate::AppState;

pub const KEY_TYPE_ED25519: &str = "ed25519";
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_KEYPAIR_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum ServerKeyError {
    #[error("Server public key not found at path: {0}")]
    KeyNotFound(String),
    #[error("I/O error accessing server keys: {0}")]
    Io(String),
    #[error("Invalid server key content: {0}")]
    InvalidKey(String),
    #[error("Admin privileges required: {0}")]
    Forbidden(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl IntoResponse for ServerKeyError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            ServerKeyError::KeyNotFound(path) => (
                StatusCode::NOT_FOUND,
                "key_not_found",
                format!("Clave pública del servidor no encontrada en la ruta configurada: {path}"),
            ),
            ServerKeyError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            ServerKeyError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone())
            }
            ServerKeyError::InvalidKey(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_key",
                format!("Formato de clave inválido: {msg}"),
            ),
            ServerKeyError::Io(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "io_error",
                format!("Error de entrada/salida al acceder a las claves del servidor: {msg}"),
            ),
        };

        let body = Json(json!({
            "error": code,
            "message": message,
        }));

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct PublicKeyResponse {
    pub public_key: String,
    pub key_type: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct RotateKeysRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RotateKeysResponse {
    pub status: &'static str,
    pub public_key: String,
    pub key_type: &'static str,
    pub rotated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
}

/// Key pair generated internally. Private key is strictly retained within this struct
/// during rotation file writing and is NEVER transmitted over the wire or logged.
pub struct GeneratedKeyPair {
    pub public_key_base64: String,
    pub private_key_base64: String,
}

/// Generates a cryptographically secure Ed25519 keypair.
///
/// Follows upstream server conventions:
/// - Public key: 32 bytes encoded in Base64 (44 chars).
/// - Private key: 64 bytes (seed + public key) encoded in Base64 (88 chars).
/// - Loops up to 300 iterations if public key contains `/` or `:` to prevent CLI/URL parsing issues.
pub fn generate_server_keypair() -> Result<GeneratedKeyPair, ServerKeyError> {
    let mut signing_key = SigningKey::generate(&mut OsRng);
    let mut pub_bytes = signing_key.verifying_key().to_bytes();
    let mut pub_b64 = BASE64_STANDARD.encode(pub_bytes);

    for _ in 0..300 {
        if !pub_b64.contains('/') && !pub_b64.contains(':') {
            break;
        }
        signing_key = SigningKey::generate(&mut OsRng);
        pub_bytes = signing_key.verifying_key().to_bytes();
        pub_b64 = BASE64_STANDARD.encode(pub_bytes);
    }

    let priv_bytes = signing_key.to_keypair_bytes();
    let priv_b64 = BASE64_STANDARD.encode(priv_bytes);

    Ok(GeneratedKeyPair {
        public_key_base64: pub_b64,
        private_key_base64: priv_b64,
    })
}

/// Derives the private key path from the public key path.
/// E.g. `/path/to/id_ed25519.pub` -> `/path/to/id_ed25519`.
pub fn derive_private_key_path<P: AsRef<Path>>(pub_path: P) -> PathBuf {
    let path = pub_path.as_ref();
    if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
        if let Some(stripped) = file_name.strip_suffix(".pub") {
            return path.with_file_name(stripped);
        }
    }
    path.with_extension("priv")
}

/// Reads and validates the server public key from the given filesystem path.
pub fn read_public_key<P: AsRef<Path>>(path: P) -> Result<String, ServerKeyError> {
    let path_ref = path.as_ref();
    if !path_ref.exists() {
        return Err(ServerKeyError::KeyNotFound(path_ref.display().to_string()));
    }

    let raw = fs::read_to_string(path_ref)
        .map_err(|e| ServerKeyError::Io(format!("Lectura de {}: {}", path_ref.display(), e)))?;

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ServerKeyError::InvalidKey(
            "El archivo de clave pública está vacío".to_string(),
        ));
    }

    let decoded = BASE64_STANDARD
        .decode(trimmed)
        .map_err(|e| ServerKeyError::InvalidKey(format!("Decodificación Base64 fallida: {}", e)))?;

    if decoded.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(ServerKeyError::InvalidKey(format!(
            "Longitud de clave pública inválida: {} bytes (esperado: {})",
            decoded.len(),
            ED25519_PUBLIC_KEY_BYTES
        )));
    }

    Ok(trimmed.to_string())
}

#[cfg(unix)]
fn set_secure_permissions<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path.as_ref())?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path.as_ref(), perms)
}

#[cfg(not(unix))]
fn set_secure_permissions<P: AsRef<Path>>(_path: P) -> std::io::Result<()> {
    Ok(())
}

fn current_utc_iso_timestamp() -> (String, String) {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();

    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    let mut year = 1970;
    let mut d = days;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &dim in &days_in_months {
        if d < dim {
            break;
        }
        d -= dim;
        month += 1;
    }
    let day = d + 1;

    let iso = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    );
    let compact = format!("{:04}{:02}{:02}_{:02}{:02}{:02}", year, month, day, h, m, s);
    (iso, compact)
}

/// Rotates server Ed25519 keys:
/// 1. Backs up existing public and private keys with timestamped suffixes.
/// 2. Generates a fresh Ed25519 keypair.
/// 3. Writes new private key (0600 on Unix) and public key to disk.
/// 4. Logs audit event with public key only (private key NEVER logged).
pub fn rotate_keys<P: AsRef<Path>>(
    pub_path: P,
    reason: Option<&str>,
    admin_user: &AuthenticatedUser,
) -> Result<RotateKeysResponse, ServerKeyError> {
    if admin_user.role != "admin" {
        return Err(ServerKeyError::Forbidden(
            "Se requieren privilegios de administrador para rotar las claves del servidor"
                .to_string(),
        ));
    }

    let pub_path_ref = pub_path.as_ref();
    let priv_path = derive_private_key_path(pub_path_ref);

    if let Some(parent) = pub_path_ref.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                ServerKeyError::Io(format!(
                    "Creación de directorio {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }
    }

    let (iso_ts, compact_ts) = current_utc_iso_timestamp();

    let mut backup_pub_path_str: Option<String> = None;
    if pub_path_ref.exists() {
        let pub_bak = format!("{}.bak.{}", pub_path_ref.display(), compact_ts);
        fs::copy(pub_path_ref, &pub_bak).map_err(|e| {
            ServerKeyError::Io(format!("Respaldo de clave pública a {}: {}", pub_bak, e))
        })?;
        backup_pub_path_str = Some(pub_bak);
    }

    if priv_path.exists() {
        let priv_bak = format!("{}.bak.{}", priv_path.display(), compact_ts);
        fs::copy(&priv_path, &priv_bak).map_err(|e| {
            ServerKeyError::Io(format!("Respaldo de clave privada a {}: {}", priv_bak, e))
        })?;
        let _ = set_secure_permissions(&priv_bak);
    }

    let new_keys = generate_server_keypair()?;

    fs::write(&priv_path, &new_keys.private_key_base64).map_err(|e| {
        ServerKeyError::Io(format!(
            "Escritura de nueva clave privada en {}: {}",
            priv_path.display(),
            e
        ))
    })?;
    let _ = set_secure_permissions(&priv_path);

    fs::write(pub_path_ref, &new_keys.public_key_base64).map_err(|e| {
        ServerKeyError::Io(format!(
            "Escritura de nueva clave pública en {}: {}",
            pub_path_ref.display(),
            e
        ))
    })?;

    tracing::info!(
        admin_id = %admin_user.id,
        admin_user = %admin_user.username,
        public_key = %new_keys.public_key_base64,
        reason = ?reason,
        "Server keys rotated successfully"
    );

    Ok(RotateKeysResponse {
        status: "rotated",
        public_key: new_keys.public_key_base64,
        key_type: KEY_TYPE_ED25519,
        rotated_at: iso_ts,
        backup_path: backup_pub_path_str,
    })
}

/// GET /api/server/public-key
///
/// Public unauthenticated endpoint returning the server's public key
/// so clients or management web console can configure without manual extraction.
pub async fn get_public_key_handler(
    State(state): State<AppState>,
) -> Result<Json<PublicKeyResponse>, ServerKeyError> {
    let public_key = read_public_key(&state.config.server_key_path)?;
    Ok(Json(PublicKeyResponse {
        public_key,
        key_type: KEY_TYPE_ED25519.to_string(),
    }))
}

/// POST /api/server/keys/rotate
///
/// Protected endpoint requiring administrator privileges.
/// Rotates server key pair, backs up existing keys, updates on-disk files.
/// Never leaks or returns private key.
pub async fn rotate_keys_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    body: Option<Json<RotateKeysRequest>>,
) -> Result<Json<RotateKeysResponse>, ServerKeyError> {
    let reason = body.as_ref().and_then(|b| b.reason.as_deref());
    let response = rotate_keys(&state.config.server_key_path, reason, &user)?;
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;
    use tempfile::tempdir;

    #[test]
    fn test_generate_server_keypair_validity() {
        let keys = generate_server_keypair().unwrap();

        assert_eq!(keys.public_key_base64.len(), 44);
        assert_eq!(keys.private_key_base64.len(), 88);
        assert!(!keys.public_key_base64.contains('/'));
        assert!(!keys.public_key_base64.contains(':'));

        let decoded_pub = BASE64_STANDARD.decode(&keys.public_key_base64).unwrap();
        assert_eq!(decoded_pub.len(), 32);

        let vk_bytes: [u8; 32] = decoded_pub.try_into().unwrap();
        let _vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();

        let decoded_priv = BASE64_STANDARD.decode(&keys.private_key_base64).unwrap();
        assert_eq!(decoded_priv.len(), 64);
    }

    #[test]
    fn test_read_public_key_from_lab_data() {
        let lab_path = "tests/lab/data/server/id_ed25519.pub";
        if Path::new(lab_path).exists() {
            let key = read_public_key(lab_path).unwrap();
            assert_eq!(key.len(), 44);
            assert_eq!(key, "lRHZiVhN0oDD1fsuACtV6S2FOneftReV7m4eUnIEzIQ=");
        }
    }

    #[test]
    fn test_read_public_key_not_found() {
        let res = read_public_key("nonexistent_dir/id_ed25519.pub");
        match res {
            Err(ServerKeyError::KeyNotFound(path)) => {
                assert!(path.contains("nonexistent_dir"));
            }
            _ => panic!("Expected KeyNotFound error"),
        }
    }

    #[test]
    fn test_derive_private_key_path() {
        let pub_path = Path::new("/opt/cercano/data/id_ed25519.pub");
        let priv_path = derive_private_key_path(pub_path);
        assert_eq!(priv_path, PathBuf::from("/opt/cercano/data/id_ed25519"));

        let custom_path = Path::new("server.pub");
        assert_eq!(
            derive_private_key_path(custom_path),
            PathBuf::from("server")
        );
    }

    #[test]
    fn test_rotate_keys_flow_and_backup() {
        let dir = tempdir().unwrap();
        let pub_path = dir.path().join("id_ed25519.pub");
        let priv_path = dir.path().join("id_ed25519");

        let initial_keys = generate_server_keypair().unwrap();
        fs::write(&pub_path, &initial_keys.public_key_base64).unwrap();
        fs::write(&priv_path, &initial_keys.private_key_base64).unwrap();

        let admin_user = AuthenticatedUser {
            id: "admin-1".to_string(),
            username: "admin".to_string(),
            role: "admin".to_string(),
            created_at: "2026-11-05 10:00:00".to_string(),
        };

        let rotate_res =
            rotate_keys(&pub_path, Some("scheduled maintenance"), &admin_user).unwrap();

        assert_eq!(rotate_res.status, "rotated");
        assert_eq!(rotate_res.key_type, "ed25519");
        assert_ne!(rotate_res.public_key, initial_keys.public_key_base64);
        assert!(rotate_res.backup_path.is_some());

        let new_on_disk_pub = fs::read_to_string(&pub_path).unwrap();
        assert_eq!(new_on_disk_pub.trim(), rotate_res.public_key);

        let new_on_disk_priv = fs::read_to_string(&priv_path).unwrap();
        assert_ne!(new_on_disk_priv.trim(), initial_keys.private_key_base64);
        assert_eq!(new_on_disk_priv.trim().len(), 88);
    }

    #[test]
    fn test_rotate_keys_rejects_non_admin() {
        let dir = tempdir().unwrap();
        let pub_path = dir.path().join("id_ed25519.pub");

        let operator_user = AuthenticatedUser {
            id: "user-2".to_string(),
            username: "operator".to_string(),
            role: "operator".to_string(),
            created_at: "2026-11-05 10:00:00".to_string(),
        };

        let res = rotate_keys(&pub_path, None, &operator_user);
        match res {
            Err(ServerKeyError::Forbidden(msg)) => {
                assert!(msg.contains("administrador"));
            }
            _ => panic!("Expected Forbidden error"),
        }
    }
}
