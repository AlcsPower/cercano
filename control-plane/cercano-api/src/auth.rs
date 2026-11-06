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
use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqlitePool};
use std::net::SocketAddr;
use thiserror::Error;
use uuid::Uuid;

use crate::AppState;

pub const MAX_FAILED_LOGIN_ATTEMPTS: i64 = 5;
pub const LOCKOUT_DURATION_MINUTES: u32 = 15;
pub const SESSION_EXPIRATION_HOURS: u32 = 24;

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
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
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
            SELECT u.id, u.username, u.role, u.is_active, u.created_at
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

        Ok(AuthenticatedUser {
            id: row.get("id"),
            username: row.get("username"),
            role: row.get("role"),
            created_at: row.get("created_at"),
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

/// Extracts client IP from standard HTTP headers or falls back to local address.
pub fn extract_client_ip(headers: &HeaderMap, peer_addr: Option<SocketAddr>) -> String {
    let is_trusted_proxy = match peer_addr {
        Some(addr) => addr.ip().is_loopback(),
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
    Json(payload): Json<BootstrapRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AuthError> {
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
/// Authenticates user credentials, enforces lockout, and issues a session token.
pub async fn login_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    let client_ip = extract_client_ip(&headers, connect_info.map(|ci| ci.0));
    let username = payload.username.trim();

    // Check brute-force lockout
    if is_locked_out(&state.db, username, &client_ip).await? {
        tracing::warn!(
            username = %username,
            ip = %client_ip,
            "Login rejected: account or IP temporarily locked"
        );
        return Err(AuthError::AccountLocked);
    }

    // Lookup user
    let user_row = sqlx::query(
        "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
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
        return Err(AuthError::InvalidCredentials);
    }

    // Login successful
    record_login_attempt(&state.db, username, &client_ip, true).await?;

    let user_id: String = user.get("id");
    let user_role: String = user.get("role");
    let token = generate_session_token();

    let expiration_modifier = format!("+{} hours", SESSION_EXPIRATION_HOURS);

    sqlx::query(
        r#"
        INSERT INTO sessions (token, user_id, expires_at)
        VALUES (?, ?, datetime('now', ?))
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

    tracing::info!(
        username = %username,
        user_id = %user_id,
        "User authenticated successfully, session token issued"
    );

    Ok(Json(LoginResponse {
        token,
        expires_at,
        user: UserInfo {
            id: user_id,
            username: username.to_string(),
            role: user_role,
        },
    }))
}

/// POST /api/auth/logout
/// Revokes active session corresponding to the Bearer token provided.
pub async fn logout_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<LogoutResponse>, AuthError> {
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

        // 1. Without socket or headers -> default loopback
        assert_eq!(extract_client_ip(&headers, None), "127.0.0.1");

        // 2. Loopback socket (trusted proxy) -> honors X-Forwarded-For and X-Real-IP
        let loopback: SocketAddr = "127.0.0.1:45678".parse().unwrap();
        headers.insert("x-forwarded-for", "192.168.1.50, 10.0.0.1".parse().unwrap());
        assert_eq!(extract_client_ip(&headers, Some(loopback)), "192.168.1.50");

        headers.remove("x-forwarded-for");
        headers.insert("x-real-ip", "10.10.10.20".parse().unwrap());
        assert_eq!(extract_client_ip(&headers, Some(loopback)), "10.10.10.20");

        // 3. IPv6 loopback [::1] (trusted proxy) -> honors headers
        let loopback_v6: SocketAddr = "[::1]:45678".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, Some(loopback_v6)),
            "10.10.10.20"
        );

        // 4. Remote socket (untrusted client) -> ignores spoofed proxy headers completely
        let remote: SocketAddr = "192.168.1.200:54321".parse().unwrap();
        assert_eq!(extract_client_ip(&headers, Some(remote)), "192.168.1.200");
    }
}
