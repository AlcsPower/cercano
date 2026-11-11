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

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::net::SocketAddr;
use thiserror::Error;
use uuid::Uuid;

use crate::AppState;

pub const MAX_FAILED_LOGIN_ATTEMPTS: i64 = 5;
pub const LOCKOUT_DURATION_MINUTES: u32 = 15;
pub const SESSION_EXPIRATION_HOURS: u32 = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeEntry {
    pub hash: String,
    pub used: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorEnrollResponse {
    pub otpauth_uri: String,
    pub totp_secret_base32: String,
}

#[derive(Debug, Deserialize)]
pub struct TwoFactorConfirmRequest {
    pub totp_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorConfirmResponse {
    pub status: &'static str,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TwoFactorVerifyRequest {
    pub mfa_token: String,
    pub totp_code: Option<String>,
    pub recovery_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TwoFactorRevokeRequest {
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorRevokeResponse {
    pub status: &'static str,
}

pub fn generate_mfa_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(token, "{:02x}", b);
    }
    token
}

pub fn generate_recovery_code() -> String {
    const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    let mut code = String::with_capacity(14);
    for (i, b) in bytes.iter().enumerate() {
        if i == 4 || i == 8 {
            code.push('-');
        }
        let idx = (*b as usize) % CHARSET.len();
        code.push(CHARSET[idx] as char);
    }
    code
}

pub fn hash_recovery_code(raw: &str) -> String {
    let clean = raw.trim().replace('-', "").to_uppercase();
    let mut hasher = Sha256::new();
    hasher.update(clean.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

pub fn derive_totp_key(raw_key: &str) -> [u8; 32] {
    let trimmed = raw_key.trim();
    if trimmed.len() == 64 {
        if let Ok(bytes) = (0..trimmed.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
        {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return key;
            }
        }
    }
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    let res = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&res);
    key
}

pub fn encrypt_totp_secret(secret_base32: &str, key_str: &str) -> Result<String, AuthError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let key_bytes = derive_totp_key(key_str);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| AuthError::Hashing(format!("Invalid encryption key: {e}")))?;

    let mut iv_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext = cipher
        .encrypt(nonce, secret_base32.as_bytes())
        .map_err(|e| AuthError::Hashing(format!("Encryption error: {e}")))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&iv_bytes);
    combined.extend_from_slice(&ciphertext);

    let encoded = B64.encode(&combined);
    Ok(format!("enc:v1:{}", encoded))
}

pub fn decrypt_totp_secret(stored_val: &str, key_str: &str) -> Result<String, AuthError> {
    if !stored_val.starts_with("enc:v1:") {
        // Plaintext legacy fallback for backwards compatibility
        return Ok(stored_val.to_string());
    }

    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let encoded = &stored_val["enc:v1:".len()..];
    let combined = B64
        .decode(encoded)
        .map_err(|e| AuthError::Validation(format!("Invalid base64 in encrypted secret: {e}")))?;

    if combined.len() < 12 + 16 {
        return Err(AuthError::Validation(
            "Encrypted secret ciphertext too short".to_string(),
        ));
    }

    let (iv_bytes, ciphertext) = combined.split_at(12);
    let key_bytes = derive_totp_key(key_str);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| AuthError::Hashing(format!("Invalid decryption key: {e}")))?;
    let nonce = Nonce::from_slice(iv_bytes);

    let plaintext_bytes = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        AuthError::Validation("Decryption failed: invalid key or corrupted ciphertext".to_string())
    })?;

    String::from_utf8(plaintext_bytes)
        .map_err(|e| AuthError::Validation(format!("Decrypted secret is not valid utf-8: {e}")))
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Password hashing error: {0}")]
    Hashing(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Bootstrap already completed")]
    BootstrapAlreadyCompleted,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Account temporarily locked")]
    AccountLocked,
    #[error("User inactive")]
    UserInactive,
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("MFA enrollment required for this role")]
    MfaEnrollmentRequired,
    #[error("Audit error: {0}")]
    Audit(#[from] audit_core::AuditError),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AuthError::MfaEnrollmentRequired => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "forbidden",
                        "code": "mfa_enrollment_required",
                        "message": "Se requiere configurar autenticación de dos factores (2FA) antes de acceder a este recurso.",
                    })),
                )
                    .into_response();
            }
            AuthError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, "validation_error", msg.clone())
            }
            AuthError::BootstrapAlreadyCompleted => (
                StatusCode::CONFLICT,
                "bootstrap_already_completed",
                "El bootstrap inicial de administrador ya ha sido completado.".to_string(),
            ),
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Credenciales de autenticación inválidas.".to_string(),
            ),
            AuthError::AccountLocked => (
                StatusCode::TOO_MANY_REQUESTS,
                "account_locked",
                format!(
                    "Demasiados intentos fallidos. Bloqueo temporal por {} minutos.",
                    LOCKOUT_DURATION_MINUTES
                ),
            ),
            AuthError::UserInactive => (
                StatusCode::UNAUTHORIZED,
                "user_inactive",
                "El usuario se encuentra inactivo.".to_string(),
            ),
            AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone()),
            AuthError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            AuthError::Db(err) => {
                tracing::error!("Database error during auth operation: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Error interno en la base de datos.".to_string(),
                )
            }
            AuthError::Hashing(err) => {
                tracing::error!("Password hashing error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Error en procesamiento criptográfico de contraseñas.".to_string(),
                )
            }
            AuthError::Audit(err) => {
                tracing::error!("Audit error during auth operation: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_error",
                    format!("Error interno registrando auditoría: {err}"),
                )
            }
        };

        let body = Json(json!({
            "error": code,
            "message": message,
        }));

        (status, body).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct BootstrapRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutResponse {
    pub status: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub id: String,
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub mfa_verified: bool,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                AuthError::Unauthorized("Cabecera Authorization no proporcionada".to_string())
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                AuthError::Unauthorized("Formato de cabecera Bearer token inválido".to_string())
            })?;

        let row = sqlx::query(
            r#"
            SELECT u.id, u.username, u.role, u.is_active, u.created_at, s.mfa_verified
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ?
              AND s.revoked_at IS NULL
              AND s.expires_at > datetime('now')
            "#,
        )
        .bind(token)
        .fetch_optional(&state.db)
        .await?;

        let row = match row {
            Some(r) => r,
            None => {
                return Err(AuthError::Unauthorized(
                    "Token de sesión inválido, expirado o revocado".to_string(),
                ));
            }
        };

        let is_active: i64 = row.get("is_active");
        if is_active == 0 {
            return Err(AuthError::UserInactive);
        }

        let mfa_verified_val: i64 = row.try_get("mfa_verified").unwrap_or(0);
        let mfa_verified = mfa_verified_val != 0;
        let role: String = row.get("role");

        // F4-11: Mandatory 2FA enforcement for required roles
        if state.config.require_2fa_roles.contains(&role) && !mfa_verified {
            let path = parts.uri.path();
            let is_allowed = path == "/api/auth/2fa/enroll"
                || path == "/api/auth/2fa/confirm"
                || path == "/api/auth/logout"
                || path == "/api/auth/me";

            if !is_allowed {
                let client_ip = extract_client_ip(
                    &parts.headers,
                    parts
                        .extensions
                        .get::<axum::extract::ConnectInfo<SocketAddr>>()
                        .map(|ci| ci.0),
                    &state.config.trusted_proxies,
                );
                let trace_id = extract_trace_id(&parts.headers);

                let audit_input = EventInput::new(
                    trace_id,
                    Source::Api,
                    Category::Auth,
                    "auth.2fa_required",
                    Actor::with_details(
                        row.get::<String, _>("id"),
                        "user",
                        Some(row.get::<String, _>("username")),
                        Some(client_ip.clone()),
                    ),
                    Outcome::Denied,
                    json!({
                        "username": row.get::<String, _>("username"),
                        "role": role,
                        "client_ip": client_ip,
                        "path": path,
                        "reason": "mfa_enrollment_required",
                    }),
                );
                let _ = state.audit.append(audit_input).await;

                return Err(AuthError::MfaEnrollmentRequired);
            }
        }

        Ok(AuthenticatedUser {
            id: row.get("id"),
            username: row.get("username"),
            role,
            created_at: row.get("created_at"),
            mfa_verified,
        })
    }
}

/// Hashes password using Argon2id with robust parameters (64 MB, 3 passes, 4 threads, 32-byte output).
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let params =
        Params::new(65536, 3, 4, Some(32)).map_err(|e| AuthError::Hashing(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Hashing(e.to_string()))?
        .to_string();
    Ok(password_hash)
}

/// Verifies a password against an Argon2id PHC string.
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, AuthError> {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(h) => h,
        Err(e) => return Err(AuthError::Hashing(e.to_string())),
    };
    let params =
        Params::new(65536, 3, 4, Some(32)).map_err(|e| AuthError::Hashing(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AuthError::Hashing(e.to_string())),
    }
}

/// Generates a cryptographically secure session token prefixed with `cercano_sess_`.
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(13 + 64);
    token.push_str("cercano_sess_");
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(token, "{:02x}", b);
    }
    token
}

/// Extracts client IP from standard HTTP headers or falls back to the socket peer address.
///
/// Proxy headers are honored only when the peer is one of the configured trusted proxies,
/// otherwise a proxy (e.g. nginx on the Docker network) would be recorded as every client.
pub fn extract_client_ip(
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    trusted_proxies: &[String],
) -> String {
    let is_trusted_proxy = match peer_addr {
        Some(addr) => {
            !trusted_proxies.is_empty()
                && crate::alarms::is_ip_in_whitelist(&addr.ip().to_string(), trusted_proxies)
        }
        // Unit tests build the router without connect info; treat as the local proxy.
        None => true,
    };

    if is_trusted_proxy {
        if let Some(forwarded) = headers.get("x-forwarded-for") {
            if let Ok(s) = forwarded.to_str() {
                if let Some(first) = s.split(',').next() {
                    let trimmed = first.trim();
                    if !trimmed.is_empty() {
                        return trimmed.to_string();
                    }
                }
            }
        }
        if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(s) = real_ip.to_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    if let Some(addr) = peer_addr {
        addr.ip().to_string()
    } else {
        "127.0.0.1".to_string()
    }
}

/// Extracts trace_id from headers (x-trace-id or x-request-id) or generates a new UUIDv7.
pub fn extract_trace_id(headers: &HeaderMap) -> String {
    headers
        .get("x-trace-id")
        .or_else(|| headers.get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

/// Checks if an account or IP is temporarily locked due to repeated failed logins.
/// Evaluates account lockout (by username) and IP lockout (by IP address) separately
/// to prevent brute-force attacks without enabling denial-of-service against legitimate users.
pub async fn is_locked_out(pool: &SqlitePool, username: &str, ip: &str) -> Result<bool, AuthError> {
    // 1. Account-level lockout: check failed attempts for this username
    let user_row = sqlx::query(
        r#"
        SELECT COUNT(*) as failed_count
        FROM login_attempts
        WHERE username = ?
          AND success = 0
          AND attempted_at > datetime('now', '-15 minutes')
        "#,
    )
    .bind(username)
    .fetch_one(pool)
    .await?;

    let user_count: i64 = user_row.get("failed_count");
    if user_count >= MAX_FAILED_LOGIN_ATTEMPTS {
        return Ok(true);
    }

    // 2. IP-level lockout: check failed attempts for this IP address
    let ip_row = sqlx::query(
        r#"
        SELECT COUNT(*) as failed_count
        FROM login_attempts
        WHERE ip_address = ?
          AND success = 0
          AND attempted_at > datetime('now', '-15 minutes')
        "#,
    )
    .bind(ip)
    .fetch_one(pool)
    .await?;

    let ip_count: i64 = ip_row.get("failed_count");
    if ip_count >= MAX_FAILED_LOGIN_ATTEMPTS {
        return Ok(true);
    }

    Ok(false)
}

/// Records a login attempt into `login_attempts` for audit and brute-force tracking.
pub async fn record_login_attempt(
    pool: &SqlitePool,
    username: &str,
    ip: &str,
    success: bool,
) -> Result<(), AuthError> {
    sqlx::query(
        r#"
        INSERT INTO login_attempts (username, ip_address, success)
        VALUES (?, ?, ?)
        "#,
    )
    .bind(username)
    .bind(ip)
    .bind(if success { 1 } else { 0 })
    .execute(pool)
    .await?;
    Ok(())
}

fn validate_credentials_input(username: &str, password: &str) -> Result<(), AuthError> {
    let trimmed_user = username.trim();
    if trimmed_user.len() < 3 || trimmed_user.len() > 64 {
        return Err(AuthError::Validation(
            "El nombre de usuario debe tener entre 3 y 64 caracteres.".to_string(),
        ));
    }
    if !trimmed_user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AuthError::Validation(
            "El nombre de usuario solo puede contener letras, números, guiones y puntos."
                .to_string(),
        ));
    }
    if password.len() < 8 || password.len() > 128 {
        return Err(AuthError::Validation(
            "La contraseña debe tener entre 8 y 128 caracteres.".to_string(),
        ));
    }
    Ok(())
}

/// POST /api/auth/bootstrap
/// Initial administrator provisioning. Only succeeds if zero users exist in the database.
pub async fn bootstrap_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<BootstrapRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AuthError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    validate_credentials_input(&payload.username, &payload.password)?;

    // Atomic transaction to ensure race-condition safety on bootstrap
    let mut tx = state.db.begin().await?;

    let count_row = sqlx::query("SELECT COUNT(*) as count FROM users")
        .fetch_one(&mut *tx)
        .await?;
    let user_count: i64 = count_row.get("count");

    if user_count > 0 {
        return Err(AuthError::BootstrapAlreadyCompleted);
    }

    let user_id = Uuid::now_v7().to_string();
    let hashed_pw = hash_password(&payload.password)?;

    sqlx::query(
        r#"
        INSERT INTO users (id, username, password_hash, role, is_active)
        VALUES (?, ?, ?, 'admin', 1)
        "#,
    )
    .bind(&user_id)
    .bind(payload.username.trim())
    .bind(&hashed_pw)
    .execute(&mut *tx)
    .await?;

    let user_row = sqlx::query("SELECT created_at FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&mut *tx)
        .await?;
    let created_at: String = user_row.get("created_at");

    tx.commit().await?;

    let username_str = payload.username.trim().to_string();

    let audit_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "auth.bootstrap",
        Actor::with_details(
            &user_id,
            "user",
            Some(username_str.clone()),
            Some(client_ip.clone()),
        ),
        Outcome::Success,
        json!({
            "username": username_str,
            "role": "admin",
            "client_ip": client_ip,
        }),
    )
    .with_subject(Subject::with_details(
        &user_id,
        "user",
        Some(username_str.clone()),
    ));

    state.audit.append(audit_input).await?;

    tracing::info!(
        user_id = %user_id,
        username = %payload.username.trim(),
        "Initial administrator bootstrap completed successfully"
    );

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: user_id,
            username: payload.username.trim().to_string(),
            role: "admin".to_string(),
            created_at,
        }),
    ))
}

/// POST /api/auth/login
/// Authenticates user credentials, enforces lockout, and issues a session token
/// or a 2FA challenge if 2FA is required for the user account.
pub async fn login_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Response, AuthError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);
    let username = payload.username.trim();

    // Evaluate IP whitelist and IP burst rate limits via alarm engine
    match state
        .alarms
        .check_ip_whitelist(&client_ip, Some(&trace_id), Some(username))
        .await
    {
        Ok(Some(_)) => {
            tracing::warn!(ip = %client_ip, "Login blocked: IP outside configured whitelist");
            return Err(AuthError::Forbidden(
                "Acceso denegado: la IP no pertenece a la lista blanca configurada.".to_string(),
            ));
        }
        Ok(None) => {}
        // Fail closed: if the whitelist cannot be evaluated, do not authenticate.
        Err(err) => return Err(AuthError::Audit(err)),
    }
    let _ = state
        .alarms
        .record_ip_attempt(&client_ip, Some(&trace_id), Some(username))
        .await;

    // Check brute-force lockout
    if is_locked_out(&state.db, username, &client_ip).await? {
        tracing::warn!(
            username = %username,
            ip = %client_ip,
            "Login rejected: account or IP temporarily locked"
        );
        let audit_input = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.failed",
            Actor::with_details(
                username,
                "user",
                Some(username.to_string()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "target_username": username,
                "reason": "account_or_ip_locked",
                "client_ip": client_ip,
            }),
        );
        let _ = state.audit.append(audit_input).await;
        let _ = state
            .alarms
            .record_login_failure(username, Some(&client_ip), Some(&trace_id))
            .await;
        return Err(AuthError::AccountLocked);
    }

    // Lookup user
    let user_row = sqlx::query(
        "SELECT id, username, password_hash, role, is_active, is_2fa_required, totp_enabled FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(&state.db)
    .await?;

    let user = match user_row {
        Some(row) => row,
        None => {
            record_login_attempt(&state.db, username, &client_ip, false).await?;
            tracing::warn!(
                username = %username,
                ip = %client_ip,
                "Login failed: user not found"
            );
            let audit_input = EventInput::new(
                trace_id.clone(),
                Source::Api,
                Category::Auth,
                "auth.failed",
                Actor::with_details(
                    username,
                    "user",
                    Some(username.to_string()),
                    Some(client_ip.clone()),
                ),
                Outcome::Failure,
                json!({
                    "target_username": username,
                    "reason": "user_not_found",
                    "client_ip": client_ip,
                }),
            );
            let _ = state.audit.append(audit_input).await;
            let _ = state
                .alarms
                .record_login_failure(username, Some(&client_ip), Some(&trace_id))
                .await;
            return Err(AuthError::InvalidCredentials);
        }
    };

    let is_active: i64 = user.get("is_active");
    if is_active == 0 {
        record_login_attempt(&state.db, username, &client_ip, false).await?;
        tracing::warn!(
            username = %username,
            ip = %client_ip,
            "Login failed: account is inactive"
        );
        let user_id: String = user.get("id");
        let audit_input = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.failed",
            Actor::with_details(
                &user_id,
                "user",
                Some(username.to_string()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "target_username": username,
                "reason": "user_inactive",
                "client_ip": client_ip,
            }),
        );
        let _ = state.audit.append(audit_input).await;
        let _ = state
            .alarms
            .record_login_failure(username, Some(&client_ip), Some(&trace_id))
            .await;
        return Err(AuthError::UserInactive);
    }

    let stored_hash: String = user.get("password_hash");
    let is_valid = verify_password(&payload.password, &stored_hash)?;

    if !is_valid {
        record_login_attempt(&state.db, username, &client_ip, false).await?;
        tracing::warn!(
            username = %username,
            ip = %client_ip,
            "Login failed: password mismatch"
        );
        let user_id: String = user.get("id");
        let audit_input = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.failed",
            Actor::with_details(
                &user_id,
                "user",
                Some(username.to_string()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "target_username": username,
                "reason": "invalid_password",
                "client_ip": client_ip,
            }),
        );
        let _ = state.audit.append(audit_input).await;
        let _ = state
            .alarms
            .record_login_failure(username, Some(&client_ip), Some(&trace_id))
            .await;
        return Err(AuthError::InvalidCredentials);
    }

    let user_id: String = user.get("id");
    let user_role: String = user.get("role");
    let is_2fa_required: i64 = user.get("is_2fa_required");
    let totp_enabled: i64 = user.get("totp_enabled");

    // If 2FA has been enrolled and activated (or required with factor active), issue a 5-minute mfa_challenge.
    if totp_enabled == 1 || is_2fa_required == 1 {
        let mfa_token = generate_mfa_token();
        sqlx::query(
            r#"
            INSERT INTO mfa_challenges (token, user_id, expires_at)
            VALUES (?, ?, datetime('now', '+5 minutes'))
            "#,
        )
        .bind(&mfa_token)
        .bind(&user_id)
        .execute(&state.db)
        .await?;

        let challenge_row = sqlx::query("SELECT expires_at FROM mfa_challenges WHERE token = ?")
            .bind(&mfa_token)
            .fetch_one(&state.db)
            .await?;
        let expires_at: String = challenge_row.get("expires_at");

        tracing::info!(
            username = %username,
            user_id = %user_id,
            "Credentials valid, 2FA challenge issued"
        );

        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({
                "mfa_required": true,
                "mfa_token": mfa_token,
                "expires_at": expires_at,
            })),
        )
            .into_response());
    }

    // If user's role mandates 2FA but factor is not yet enrolled, issue a restricted session (mfa_verified = 0)
    // and flag mfa_enrollment_required: true in response.
    let mfa_enrollment_required = state.config.require_2fa_roles.contains(&user_role);

    record_login_attempt(&state.db, username, &client_ip, true).await?;

    let token = generate_session_token();
    let expiration_modifier = format!("+{} hours", SESSION_EXPIRATION_HOURS);

    sqlx::query(
        r#"
        INSERT INTO sessions (token, user_id, expires_at, mfa_verified)
        VALUES (?, ?, datetime('now', ?), 0)
        "#,
    )
    .bind(&token)
    .bind(&user_id)
    .bind(&expiration_modifier)
    .execute(&state.db)
    .await?;

    let session_row = sqlx::query("SELECT expires_at FROM sessions WHERE token = ?")
        .bind(&token)
        .fetch_one(&state.db)
        .await?;
    let expires_at: String = session_row.get("expires_at");

    let audit_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "auth.login",
        Actor::with_details(
            &user_id,
            "user",
            Some(username.to_string()),
            Some(client_ip.clone()),
        ),
        Outcome::Success,
        json!({
            "username": username,
            "role": user_role,
            "client_ip": client_ip,
            "mfa_enrollment_required": mfa_enrollment_required,
        }),
    )
    .with_subject(Subject::with_details(
        &user_id,
        "user",
        Some(username.to_string()),
    ));

    state.audit.append(audit_input).await?;

    tracing::info!(
        username = %username,
        user_id = %user_id,
        mfa_enrollment_required = %mfa_enrollment_required,
        "User authenticated successfully, session token issued"
    );

    if mfa_enrollment_required {
        return Ok((
            StatusCode::OK,
            Json(json!({
                "token": token,
                "expires_at": expires_at,
                "user": {
                    "id": user_id,
                    "username": username.to_string(),
                    "role": user_role,
                },
                "mfa_enrollment_required": true,
            })),
        )
            .into_response());
    }

    Ok((
        StatusCode::OK,
        Json(LoginResponse {
            token,
            expires_at,
            user: UserInfo {
                id: user_id,
                username: username.to_string(),
                role: user_role,
            },
        }),
    )
        .into_response())
}

/// POST /api/auth/2fa/enroll
/// Authenticated handler that generates a new TOTP secret in base32 and otpauth:// URI,
/// stores provisionally in users.totp_secret, returns { otpauth_uri, totp_secret_base32 }.
pub async fn two_factor_enroll_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> Result<Json<TwoFactorEnrollResponse>, AuthError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    if !crate::permissions::has_permission(&user.role, crate::permissions::TWOFA_ENROLL) {
        crate::permissions::audit_authz_denied(
            &state.audit,
            &user,
            crate::permissions::TWOFA_ENROLL,
            &client_ip,
            &trace_id,
        )
        .await;
        return Err(AuthError::Forbidden(
            "Falta el permiso 2fa:enroll.".to_string(),
        ));
    }

    let secret = totp_rs::Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| AuthError::Hashing(e.to_string()))?;

    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Cercano".to_string()),
        user.username.clone(),
    )
    .map_err(|e| AuthError::Hashing(e.to_string()))?;

    let otpauth_uri = totp.get_url();

    let encrypted_secret = encrypt_totp_secret(&secret_base32, &state.config.totp_encryption_key)?;

    sqlx::query("UPDATE users SET totp_secret = ? WHERE id = ?")
        .bind(&encrypted_secret)
        .bind(&user.id)
        .execute(&state.db)
        .await?;

    let audit_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "auth.2fa_enroll",
        Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip.clone()),
        ),
        Outcome::Success,
        json!({
            "method": "totp",
            "client_ip": client_ip,
        }),
    )
    .with_subject(Subject::with_details(
        &user.id,
        "user",
        Some(user.username.clone()),
    ));

    state.audit.append(audit_input).await?;

    Ok(Json(TwoFactorEnrollResponse {
        otpauth_uri,
        totp_secret_base32: secret_base32,
    }))
}

/// POST /api/auth/2fa/confirm
/// Authenticated handler receiving { totp_code }. Validates against provisional secret.
/// Upon success: generates 8 single-use recovery codes (XXXX-XXXX-XXXX), computes their SHA-256 hashes,
/// stores JSON array in users.recovery_codes, sets totp_enabled = 1, is_2fa_required = 1,
/// totp_confirmed_at = datetime('now'). Returns HTTP 200 with { status: "confirmed", recovery_codes: [...] }.
pub async fn two_factor_confirm_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    user: AuthenticatedUser,
    Json(payload): Json<TwoFactorConfirmRequest>,
) -> Result<Json<TwoFactorConfirmResponse>, AuthError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    if !crate::permissions::has_permission(&user.role, crate::permissions::TWOFA_ENROLL) {
        crate::permissions::audit_authz_denied(
            &state.audit,
            &user,
            crate::permissions::TWOFA_ENROLL,
            &client_ip,
            &trace_id,
        )
        .await;
        return Err(AuthError::Forbidden(
            "Falta el permiso 2fa:enroll.".to_string(),
        ));
    }

    let user_row = sqlx::query("SELECT totp_secret FROM users WHERE id = ?")
        .bind(&user.id)
        .fetch_one(&state.db)
        .await?;
    let stored_secret: Option<String> = user_row.get("totp_secret");

    let stored_secret = match stored_secret {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return Err(AuthError::Validation(
                "No hay secreto 2FA provisional para confirmar. Llame a /api/auth/2fa/enroll primero."
                    .to_string(),
            ));
        }
    };

    let decrypted_secret = decrypt_totp_secret(&stored_secret, &state.config.totp_encryption_key)?;
    let secret = totp_rs::Secret::Encoded(decrypted_secret);
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| AuthError::Hashing(e.to_string()))?;

    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Cercano".to_string()),
        user.username.clone(),
    )
    .map_err(|e| AuthError::Hashing(e.to_string()))?;

    let code = payload.totp_code.trim();
    if code.len() != 6 || !totp.check_current(code).unwrap_or(false) {
        return Err(AuthError::Validation(
            "Código TOTP inválido o expirado.".to_string(),
        ));
    }

    // Generate 8 single-use recovery codes: XXXX-XXXX-XXXX
    let mut raw_codes: Vec<String> = Vec::with_capacity(8);
    let mut hashed_entries: Vec<RecoveryCodeEntry> = Vec::with_capacity(8);

    for _ in 0..8 {
        let code = generate_recovery_code();
        let hash = hash_recovery_code(&code);
        hashed_entries.push(RecoveryCodeEntry { hash, used: false });
        raw_codes.push(code);
    }

    let recovery_json = serde_json::to_string(&hashed_entries)
        .map_err(|e| AuthError::Validation(format!("Error serializando recovery codes: {e}")))?;

    sqlx::query(
        r#"
        UPDATE users
        SET totp_enabled = 1,
            is_2fa_required = 1,
            totp_confirmed_at = datetime('now'),
            recovery_codes = ?
        WHERE id = ?
        "#,
    )
    .bind(&recovery_json)
    .bind(&user.id)
    .execute(&state.db)
    .await?;

    // Elevate active sessions for this user to MFA verified
    sqlx::query("UPDATE sessions SET mfa_verified = 1 WHERE user_id = ? AND revoked_at IS NULL")
        .bind(&user.id)
        .execute(&state.db)
        .await?;

    tracing::info!(
        user_id = %user.id,
        username = %user.username,
        "2FA TOTP confirmed and activated"
    );

    Ok(Json(TwoFactorConfirmResponse {
        status: "confirmed",
        recovery_codes: raw_codes,
    }))
}

/// POST /api/auth/2fa/verify
/// Public verification handler receiving { mfa_token, totp_code?, recovery_code? }.
/// Validates challenge in mfa_challenges. Checks TOTP code OR unused recovery code.
/// Upon success: marks challenge used, marks recovery code used if applicable,
/// creates full session, emits auth.2fa_verify, returns 200 with session token and user info.
/// On failure: increments failure count, handles 5-failure lockout (429), emits auth.2fa_failed, returns 401.
pub async fn two_factor_verify_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<TwoFactorVerifyRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    let mfa_token = payload.mfa_token.trim();
    if mfa_token.is_empty() {
        return Err(AuthError::Validation("mfa_token es requerido.".to_string()));
    }

    // Look up challenge
    let challenge_row = sqlx::query(
        r#"
        SELECT c.token, c.user_id, c.expires_at, c.used_at,
               u.username, u.role, u.is_active, u.totp_secret, u.recovery_codes, u.totp_enabled
        FROM mfa_challenges c
        JOIN users u ON c.user_id = u.id
        WHERE c.token = ?
        "#,
    )
    .bind(mfa_token)
    .fetch_optional(&state.db)
    .await?;

    let challenge = match challenge_row {
        Some(row) => row,
        None => {
            let audit_input = EventInput::new(
                trace_id.clone(),
                Source::Api,
                Category::Auth,
                "auth.2fa_failed",
                Actor::with_details(
                    "unknown",
                    "user",
                    Some("unknown".to_string()),
                    Some(client_ip.clone()),
                ),
                Outcome::Failure,
                json!({
                    "reason": "invalid_challenge",
                    "client_ip": client_ip,
                }),
            );
            let _ = state.audit.append(audit_input).await;
            return Err(AuthError::Unauthorized(
                "Desafío MFA no encontrado o inválido.".to_string(),
            ));
        }
    };

    let user_id: String = challenge.get("user_id");
    let username: String = challenge.get("username");
    let user_role: String = challenge.get("role");
    let is_active: i64 = challenge.get("is_active");
    let totp_enabled: i64 = challenge.get("totp_enabled");
    let used_at: Option<String> = challenge.get("used_at");
    let expires_at_str: String = challenge.get("expires_at");

    if is_active == 0 {
        return Err(AuthError::UserInactive);
    }

    if used_at.is_some() {
        let audit_input = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.2fa_failed",
            Actor::with_details(
                &user_id,
                "user",
                Some(username.clone()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "reason": "challenge_already_used",
                "client_ip": client_ip,
            }),
        );
        let _ = state.audit.append(audit_input).await;
        return Err(AuthError::Unauthorized(
            "El desafío MFA ya fue utilizado.".to_string(),
        ));
    }

    // Check expiration: compares against SQLite datetime('now')
    let is_expired_row = sqlx::query("SELECT (? <= datetime('now')) as expired")
        .bind(&expires_at_str)
        .fetch_one(&state.db)
        .await?;
    let is_expired: i64 = is_expired_row.get("expired");

    if is_expired != 0 {
        let audit_input = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.2fa_failed",
            Actor::with_details(
                &user_id,
                "user",
                Some(username.clone()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "reason": "expired_challenge",
                "client_ip": client_ip,
            }),
        );
        let _ = state.audit.append(audit_input).await;
        return Err(AuthError::Unauthorized(
            "El desafío MFA ha expirado.".to_string(),
        ));
    }

    // Check brute-force lockout
    if is_locked_out(&state.db, &username, &client_ip).await? {
        let audit_input = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.2fa_failed",
            Actor::with_details(
                &user_id,
                "user",
                Some(username.clone()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "target_username": username,
                "reason": "account_locked",
                "client_ip": client_ip,
            }),
        );
        let _ = state.audit.append(audit_input).await;
        return Err(AuthError::AccountLocked);
    }

    if totp_enabled == 0 {
        return Err(AuthError::Unauthorized(
            "2FA no está habilitado para esta cuenta.".to_string(),
        ));
    }

    let stored_secret: Option<String> = challenge.get("totp_secret");
    let recovery_codes_json: Option<String> = challenge.get("recovery_codes");

    let mut verified = false;
    let mut method = "totp";
    let mut recovery_index_used: Option<usize> = None;
    let mut updated_recovery_json: Option<String> = None;

    // 1. Try TOTP code if provided
    if let Some(ref code) = payload.totp_code {
        let trimmed_code = code.trim();
        if !trimmed_code.is_empty() {
            if let Some(ref secret_str) = stored_secret {
                if let Ok(decrypted_secret) =
                    decrypt_totp_secret(secret_str, &state.config.totp_encryption_key)
                {
                    if let Ok(secret_bytes) = totp_rs::Secret::Encoded(decrypted_secret).to_bytes()
                    {
                        if let Ok(totp) = totp_rs::TOTP::new(
                            totp_rs::Algorithm::SHA1,
                            6,
                            1,
                            30,
                            secret_bytes,
                            Some("Cercano".to_string()),
                            username.clone(),
                        ) {
                            if trimmed_code.len() == 6
                                && totp.check_current(trimmed_code).unwrap_or(false)
                            {
                                verified = true;
                                method = "totp";
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Try recovery code if not verified
    if !verified {
        if let Some(ref raw_code) = payload.recovery_code {
            let trimmed = raw_code.trim();
            if !trimmed.is_empty() {
                if let Some(ref json_str) = recovery_codes_json {
                    if let Ok(mut entries) =
                        serde_json::from_str::<Vec<RecoveryCodeEntry>>(json_str)
                    {
                        let hash = hash_recovery_code(trimmed);
                        for (idx, entry) in entries.iter_mut().enumerate() {
                            if !entry.used && entry.hash == hash {
                                entry.used = true;
                                recovery_index_used = Some(idx + 1);
                                updated_recovery_json = serde_json::to_string(&entries).ok();
                                verified = true;
                                method = "recovery";
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if !verified {
        record_login_attempt(&state.db, &username, &client_ip, false).await?;
        let is_now_locked = is_locked_out(&state.db, &username, &client_ip).await?;

        let reason = if is_now_locked {
            "account_locked"
        } else if payload.recovery_code.is_some() {
            "invalid_recovery"
        } else {
            "invalid_code"
        };

        let audit_input = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.2fa_failed",
            Actor::with_details(
                &user_id,
                "user",
                Some(username.clone()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "target_username": username,
                "reason": reason,
                "client_ip": client_ip,
            }),
        );
        let _ = state.audit.append(audit_input).await;

        if is_now_locked {
            return Err(AuthError::AccountLocked);
        } else {
            return Err(AuthError::Unauthorized(
                "Código TOTP o de recuperación inválido.".to_string(),
            ));
        }
    }

    // Verification succeeded
    sqlx::query("UPDATE mfa_challenges SET used_at = datetime('now') WHERE token = ?")
        .bind(mfa_token)
        .execute(&state.db)
        .await?;

    if let (Some(idx), Some(new_json)) = (recovery_index_used, updated_recovery_json) {
        sqlx::query("UPDATE users SET recovery_codes = ? WHERE id = ?")
            .bind(&new_json)
            .bind(&user_id)
            .execute(&state.db)
            .await?;

        let audit_input = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.2fa_recovery_used",
            Actor::with_details(
                &user_id,
                "user",
                Some(username.clone()),
                Some(client_ip.clone()),
            ),
            Outcome::Success,
            json!({
                "code_index": idx,
                "client_ip": client_ip,
            }),
        )
        .with_subject(Subject::with_details(
            &user_id,
            "user",
            Some(username.clone()),
        ));
        let _ = state.audit.append(audit_input).await;
    }

    record_login_attempt(&state.db, &username, &client_ip, true).await?;

    let token = generate_session_token();
    let expiration_modifier = format!("+{} hours", SESSION_EXPIRATION_HOURS);

    sqlx::query(
        r#"
        INSERT INTO sessions (token, user_id, expires_at, mfa_verified)
        VALUES (?, ?, datetime('now', ?), 1)
        "#,
    )
    .bind(&token)
    .bind(&user_id)
    .bind(&expiration_modifier)
    .execute(&state.db)
    .await?;

    let session_row = sqlx::query("SELECT expires_at FROM sessions WHERE token = ?")
        .bind(&token)
        .fetch_one(&state.db)
        .await?;
    let expires_at: String = session_row.get("expires_at");

    let audit_input = EventInput::new(
        trace_id.clone(),
        Source::Api,
        Category::Auth,
        "auth.2fa_verify",
        Actor::with_details(
            &user_id,
            "user",
            Some(username.clone()),
            Some(client_ip.clone()),
        ),
        Outcome::Success,
        json!({
            "status": "success",
            "method": method,
            "client_ip": client_ip,
        }),
    )
    .with_subject(Subject::with_details(
        &user_id,
        "user",
        Some(username.clone()),
    ));
    state.audit.append(audit_input).await?;

    let login_audit = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "auth.login",
        Actor::with_details(
            &user_id,
            "user",
            Some(username.clone()),
            Some(client_ip.clone()),
        ),
        Outcome::Success,
        json!({
            "username": username,
            "role": user_role,
            "client_ip": client_ip,
            "2fa": true,
        }),
    )
    .with_subject(Subject::with_details(
        &user_id,
        "user",
        Some(username.clone()),
    ));
    let _ = state.audit.append(login_audit).await;

    tracing::info!(
        username = %username,
        user_id = %user_id,
        method = %method,
        "2FA verification successful, session token issued"
    );

    Ok(Json(LoginResponse {
        token,
        expires_at,
        user: UserInfo {
            id: user_id,
            username,
            role: user_role,
        },
    }))
}

/// POST /api/auth/2fa/revoke
/// Authenticated handler (user can revoke own, admin can revoke another).
/// Clears totp_secret, totp_enabled = 0, is_2fa_required = 0, totp_confirmed_at = NULL, recovery_codes = NULL.
/// Cancels open challenges and active sessions. Emits auth.2fa_revoked.
pub async fn two_factor_revoke_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    caller: AuthenticatedUser,
    payload: Option<Json<TwoFactorRevokeRequest>>,
) -> Result<Json<TwoFactorRevokeResponse>, AuthError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    let target_id = payload
        .as_ref()
        .and_then(|p| p.user_id.as_deref())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let (target_user_id, by) = match target_id {
        Some(id) if id != caller.id => {
            if !crate::permissions::is_admin(&caller.role) {
                crate::permissions::audit_authz_denied(
                    &state.audit,
                    &caller,
                    crate::permissions::TWOFA_REVOKE,
                    &client_ip,
                    &trace_id,
                )
                .await;
                return Err(AuthError::Forbidden(
                    "Solo administradores pueden revocar 2FA de otros usuarios.".to_string(),
                ));
            }
            (id.to_string(), "admin")
        }
        _ => {
            if state.config.require_2fa_roles.contains(&caller.role) {
                let audit_input = EventInput::new(
                    trace_id.clone(),
                    Source::Api,
                    Category::Auth,
                    "auth.2fa_revoke_denied",
                    Actor::with_details(
                        &caller.id,
                        "user",
                        Some(caller.username.clone()),
                        Some(client_ip.clone()),
                    ),
                    Outcome::Denied,
                    json!({
                        "username": caller.username,
                        "role": caller.role,
                        "reason": "self_revocation_disallowed_for_mandatory_role",
                        "client_ip": client_ip,
                    }),
                );
                let _ = state.audit.append(audit_input).await;
                return Err(AuthError::Forbidden(
                    "Los roles obligatorios no pueden desvincular su propio segundo factor."
                        .to_string(),
                ));
            }

            if !crate::permissions::has_permission(&caller.role, crate::permissions::TWOFA_REVOKE) {
                crate::permissions::audit_authz_denied(
                    &state.audit,
                    &caller,
                    crate::permissions::TWOFA_REVOKE,
                    &client_ip,
                    &trace_id,
                )
                .await;
                return Err(AuthError::Forbidden(
                    "Falta el permiso 2fa:revoke.".to_string(),
                ));
            }
            (caller.id.clone(), "user")
        }
    };

    // Verify target user exists
    let user_row = sqlx::query("SELECT id, username FROM users WHERE id = ?")
        .bind(&target_user_id)
        .fetch_optional(&state.db)
        .await?;

    let (target_id, target_username) = match user_row {
        Some(row) => (row.get::<String, _>("id"), row.get::<String, _>("username")),
        None => return Err(AuthError::Validation("Usuario no encontrado.".to_string())),
    };

    // Clear 2FA fields
    sqlx::query(
        r#"
        UPDATE users
        SET totp_secret = NULL,
            totp_enabled = 0,
            is_2fa_required = 0,
            totp_confirmed_at = NULL,
            recovery_codes = NULL
        WHERE id = ?
        "#,
    )
    .bind(&target_id)
    .execute(&state.db)
    .await?;

    // Cancel open challenges
    sqlx::query(
        "UPDATE mfa_challenges SET used_at = datetime('now') WHERE user_id = ? AND used_at IS NULL",
    )
    .bind(&target_id)
    .execute(&state.db)
    .await?;

    // Invalidate active sessions
    sqlx::query(
        "UPDATE sessions SET revoked_at = datetime('now') WHERE user_id = ? AND revoked_at IS NULL",
    )
    .bind(&target_id)
    .execute(&state.db)
    .await?;

    let audit_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "auth.2fa_revoked",
        Actor::with_details(
            &caller.id,
            "user",
            Some(caller.username.clone()),
            Some(client_ip.clone()),
        ),
        Outcome::Success,
        json!({
            "by": by,
            "target_user_id": target_id,
            "target_username": target_username,
            "client_ip": client_ip,
        }),
    )
    .with_subject(Subject::with_details(
        &target_id,
        "user",
        Some(target_username),
    ));

    state.audit.append(audit_input).await?;

    tracing::info!(
        target_user_id = %target_id,
        by = %by,
        "2FA factor revoked successfully"
    );

    Ok(Json(TwoFactorRevokeResponse { status: "revoked" }))
}

/// POST /api/auth/logout
/// Revokes active session corresponding to the Bearer token provided.
pub async fn logout_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<LogoutResponse>, AuthError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            AuthError::Unauthorized("Cabecera Authorization no proporcionada".to_string())
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            AuthError::Unauthorized("Formato de cabecera Bearer token inválido".to_string())
        })?;

    let session_row = sqlx::query(
        r#"
        SELECT s.user_id, u.username
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ? AND s.revoked_at IS NULL
        "#,
    )
    .bind(token)
    .fetch_optional(&state.db)
    .await?;

    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = datetime('now') WHERE token = ? AND revoked_at IS NULL",
    )
    .bind(token)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        tracing::debug!("Logout called on nonexistent or already revoked token");
    } else {
        tracing::info!("Session successfully revoked upon logout");
        let (user_id, username) = match session_row {
            Some(row) => (
                row.get::<String, _>("user_id"),
                row.get::<String, _>("username"),
            ),
            None => ("unknown".to_string(), "unknown".to_string()),
        };

        let audit_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Auth,
            "auth.logout",
            Actor::with_details(
                &user_id,
                "user",
                Some(username.clone()),
                Some(client_ip.clone()),
            ),
            Outcome::Success,
            json!({
                "username": username,
                "reason": "user_requested",
                "client_ip": client_ip,
            }),
        )
        .with_subject(Subject::with_details(&user_id, "user", Some(username)));

        state.audit.append(audit_input).await?;
    }

    Ok(Json(LogoutResponse {
        status: "ok",
        message: "Sesión revocada correctamente",
    }))
}

/// GET /api/auth/me
/// Returns current user details extracted from Bearer session authentication.
pub async fn me_handler(user: AuthenticatedUser) -> Result<Json<AuthenticatedUser>, AuthError> {
    Ok(Json(user))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_hashing_and_verification() {
        let password = "SuperSecretPassword123!";
        let hash = hash_password(password).unwrap();

        // Must be Argon2id format with robust parameters (m=65536, t=3, p=4)
        assert!(hash.starts_with("$argon2id$"));
        assert!(hash.contains("m=65536,t=3,p=4"));
        // Never contain plaintext password in hash
        assert!(!hash.contains(password));

        // Verify correct password
        assert!(verify_password(password, &hash).unwrap());

        // Verify incorrect password
        assert!(!verify_password("WrongPassword!", &hash).unwrap());
    }

    #[test]
    fn test_generate_session_token_format() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();

        assert_eq!(t1.len(), 77); // 13 ("cercano_sess_") + 64 hex characters
        assert_eq!(t2.len(), 77);
        assert_ne!(t1, t2);
        assert!(t1.starts_with("cercano_sess_"));
        assert!(t2.starts_with("cercano_sess_"));
        let hex_part = &t1["cercano_sess_".len()..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_validate_credentials_input() {
        assert!(validate_credentials_input("admin", "ValidPassword123").is_ok());
        assert!(validate_credentials_input("ad", "ValidPassword123").is_err());
        assert!(validate_credentials_input("user@domain", "ValidPassword123").is_err());
        assert!(validate_credentials_input("admin", "short").is_err());
    }

    #[test]
    fn test_extract_client_ip() {
        let mut headers = HeaderMap::new();
        let trusted = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let loopback_proxy = trusted(&["127.0.0.1/32", "::1/128"]);

        // 1. Without socket or headers -> default loopback
        assert_eq!(
            extract_client_ip(&headers, None, &loopback_proxy),
            "127.0.0.1"
        );

        // 2. Loopback socket (trusted proxy) -> honors X-Forwarded-For and X-Real-IP
        let loopback: SocketAddr = "127.0.0.1:45678".parse().unwrap();
        headers.insert("x-forwarded-for", "192.168.1.50, 10.0.0.1".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, Some(loopback), &loopback_proxy),
            "192.168.1.50"
        );

        headers.remove("x-forwarded-for");
        headers.insert("x-real-ip", "10.10.10.20".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, Some(loopback), &loopback_proxy),
            "10.10.10.20"
        );

        // 3. IPv6 loopback [::1] (trusted proxy) -> honors headers
        let loopback_v6: SocketAddr = "[::1]:45678".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, Some(loopback_v6), &loopback_proxy),
            "10.10.10.20"
        );

        // 4. Remote socket (untrusted client) -> ignores spoofed proxy headers completely
        let remote: SocketAddr = "192.168.1.200:54321".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, Some(remote), &loopback_proxy),
            "192.168.1.200"
        );

        // 5. Docker bridge proxy configured as trusted -> uses the real forwarded client IP
        let bridge: SocketAddr = "172.18.0.5:40000".parse().unwrap();
        let docker_proxy = trusted(&["172.16.0.0/12"]);
        headers.insert("x-forwarded-for", "192.168.1.77".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, Some(bridge), &docker_proxy),
            "192.168.1.77"
        );
    }
}
