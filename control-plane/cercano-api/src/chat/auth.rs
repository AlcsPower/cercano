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

//! Device authentication and registration for Cercano Chat (F4.5-03).
//!
//! Handles device registration with public key pinning, single-use Ed25519
//! nonces, short-lived chat session tokens, and administrative identity resets.

use std::fmt::Write;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::chat::{validate_device_id, validate_optional_text, MAX_OPTIONAL_TEXT_LEN};
use crate::permissions;
use crate::AppState;

const NONCE_TTL_SECONDS: i64 = 120;

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_id: String,
    pub public_key: String,
    pub installer_id: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    pub device_id: String,
    pub status: String,
    pub registered_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub nonce: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyChallengeRequest {
    pub challenge_id: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyChallengeResponse {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct ResetDeviceRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResetDeviceResponse {
    pub device_id: String,
    pub status: String,
}

#[derive(Debug)]
pub enum ChatAuthError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    ConflictKeyMismatch,
    RateLimited(u64),
    Internal(String),
}

impl IntoResponse for ChatAuthError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "validation_error", "message": msg })),
            )
                .into_response(),
            Self::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized", "message": msg })),
            )
                .into_response(),
            Self::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "forbidden", "message": msg })),
            )
                .into_response(),
            Self::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "not_found", "message": msg })),
            )
                .into_response(),
            Self::ConflictKeyMismatch => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "conflict",
                    "code": "key_mismatch",
                    "message": "Clave pública no coincide con el dispositivo registrado."
                })),
            )
                .into_response(),
            Self::RateLimited(retry_after) => {
                let mut resp = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": "rate_limited", "message": "Demasiadas peticiones." })),
                )
                    .into_response();
                resp.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    retry_after.to_string().parse().unwrap(),
                );
                resp
            }
            Self::Internal(msg) => {
                tracing::error!("ChatAuth internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal_error", "message": "Error interno del servidor." })),
                )
                    .into_response()
            }
        }
    }
}

fn parse_datetime_flexible(s: &str) -> Result<DateTime<Utc>, ()> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Ok(DateTime::from_naive_utc_and_offset(ndt, Utc));
    }
    Err(())
}

fn check_https(headers: &HeaderMap) -> Result<(), ChatAuthError> {
    if let Some(proto) = headers.get("x-forwarded-proto") {
        if let Ok(proto_str) = proto.to_str() {
            if proto_str.trim().eq_ignore_ascii_case("http") {
                return Err(ChatAuthError::Forbidden(
                    "El registro de chat requiere HTTPS.".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(fwd) = headers.get("x-forwarded-for") {
        if let Ok(s) = fwd.to_str() {
            if let Some(first) = s.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }
    if let Some(real) = headers.get("x-real-ip") {
        if let Ok(s) = real.to_str() {
            let ip = s.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn extract_trace_id(headers: &HeaderMap) -> String {
    headers
        .get("x-trace-id")
        .or_else(|| headers.get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

pub async fn register_device_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterDeviceRequest>,
) -> Result<Response, ChatAuthError> {
    if !state.config.chat_enabled {
        return Err(ChatAuthError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    check_https(&headers)?;

    // Fail closed if ingest token is not configured
    let configured_token = state.config.client_ingest_token.trim();
    if configured_token.is_empty() {
        return Err(ChatAuthError::Unauthorized(
            "Registro de chat cerrado: token de despliegue no configurado en servidor.".to_string(),
        ));
    }

    // Verify deployment token
    let client_token_header = headers
        .get("x-cercano-client-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();

    if client_token_header != configured_token {
        return Err(ChatAuthError::Unauthorized(
            "Token de despliegue no válido.".to_string(),
        ));
    }

    let device_id = validate_device_id(&payload.device_id).map_err(ChatAuthError::BadRequest)?;
    let raw_key = payload.public_key.trim();
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_key)
        .map_err(|_| ChatAuthError::BadRequest("Clave pública base64 inválida.".to_string()))?;

    if key_bytes.len() != 32 {
        return Err(ChatAuthError::BadRequest(
            "La clave pública Ed25519 debe contener exactamente 32 bytes.".to_string(),
        ));
    }

    let key_arr: [u8; 32] = key_bytes.clone().try_into().unwrap();
    let _ = VerifyingKey::from_bytes(&key_arr)
        .map_err(|_| ChatAuthError::BadRequest("Clave pública Ed25519 inválida.".to_string()))?;

    let canonical_pubkey = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

    let display_name = validate_optional_text(
        payload.display_name.as_deref(),
        "Nombre del dispositivo",
        MAX_OPTIONAL_TEXT_LEN,
    )
    .map_err(ChatAuthError::BadRequest)?;

    let client_ip = extract_client_ip(&headers);
    let trace_id = extract_trace_id(&headers);

    // Ensure device exists in `devices` table to satisfy foreign key
    let name_for_device = display_name.clone().unwrap_or_else(|| device_id.clone());
    let now_str = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO devices (id, name, status, created_at) VALUES (?, ?, 'online', ?)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name",
    )
    .bind(&device_id)
    .bind(&name_for_device)
    .bind(&now_str)
    .execute(&state.db)
    .await
    .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    // Check existing chat device
    let existing = sqlx::query(
        "SELECT public_key, created_at, revoked_at FROM chat_devices WHERE device_id = ?",
    )
    .bind(&device_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    if let Some(row) = existing {
        let stored_key: String = row.try_get("public_key").unwrap_or_default();
        let created_at: String = row.try_get("created_at").unwrap_or_default();
        let revoked_at: Option<String> = row.try_get("revoked_at").ok().flatten();

        if revoked_at.is_some() {
            return Err(ChatAuthError::Forbidden(
                "Dispositivo revocado administrativamente. Contacta a soporte para restablecer el chat.".to_string(),
            ));
        }

        if stored_key == canonical_pubkey {
            return Ok((
                StatusCode::OK,
                Json(RegisterDeviceResponse {
                    device_id,
                    status: "already_registered".to_string(),
                    registered_at: created_at,
                }),
            )
                .into_response());
        } else {
            // Key mismatch -> Audit and deny
            let actor = Actor::with_details(
                &device_id,
                "device",
                display_name.clone(),
                Some(client_ip.clone()),
            );
            let subject = Subject::with_type(&device_id, "device");
            let audit_input = EventInput::new(
                trace_id,
                Source::Api,
                Category::Chat,
                "chat.device.key_mismatch",
                actor,
                Outcome::Denied,
                json!({
                    "reason": "key_mismatch",
                    "device_id": &device_id,
                    "ip": &client_ip
                }),
            )
            .with_subject(subject);
            let _ = state.audit.append(audit_input).await;

            return Err(ChatAuthError::ConflictKeyMismatch);
        }
    }

    // Insert new registration
    sqlx::query(
        "INSERT INTO chat_devices (device_id, public_key, installer_id, display_name, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&device_id)
    .bind(&canonical_pubkey)
    .bind(payload.installer_id.as_deref())
    .bind(display_name.as_deref())
    .bind(&now_str)
    .execute(&state.db)
    .await
    .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    let actor = Actor::with_details(
        &device_id,
        "device",
        display_name.clone(),
        Some(client_ip.clone()),
    );
    let subject = Subject::with_type(&device_id, "device");
    let mut audit_details = json!({
        "device_id": &device_id,
        "ip": &client_ip
    });
    if let Some(ref inst) = payload.installer_id {
        audit_details["installer_id"] = json!(inst);
    }
    let audit_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Chat,
        "chat.device.registered",
        actor,
        Outcome::Success,
        audit_details,
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            device_id,
            status: "registered".to_string(),
            registered_at: now_str,
        }),
    )
        .into_response())
}

pub async fn request_challenge_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ChallengeRequest>,
) -> Result<Response, ChatAuthError> {
    if !state.config.chat_enabled {
        return Err(ChatAuthError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    check_https(&headers)?;

    let device_id = validate_device_id(&payload.device_id).map_err(ChatAuthError::BadRequest)?;

    // Check device exists and is not revoked
    let device_row =
        sqlx::query("SELECT device_id, revoked_at FROM chat_devices WHERE device_id = ?")
            .bind(&device_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    let Some(row) = device_row else {
        return Err(ChatAuthError::NotFound(
            "Dispositivo no registrado o revocado.".to_string(),
        ));
    };

    let revoked_at: Option<String> = row.try_get("revoked_at").ok().flatten();
    if revoked_at.is_some() {
        return Err(ChatAuthError::NotFound(
            "Dispositivo no registrado o revocado.".to_string(),
        ));
    }

    let challenge_id = Uuid::now_v7().to_string();
    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_base64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);

    let now = Utc::now();
    let expires_at = (now + chrono::Duration::seconds(NONCE_TTL_SECONDS)).to_rfc3339();
    let created_at = now.to_rfc3339();

    sqlx::query(
        "INSERT INTO chat_auth_nonces (id, device_id, nonce, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&challenge_id)
    .bind(&device_id)
    .bind(&nonce_base64)
    .bind(&expires_at)
    .bind(&created_at)
    .execute(&state.db)
    .await
    .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(ChallengeResponse {
            challenge_id,
            nonce: nonce_base64,
            expires_at,
        }),
    )
        .into_response())
}

pub async fn verify_challenge_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyChallengeRequest>,
) -> Result<Response, ChatAuthError> {
    if !state.config.chat_enabled {
        return Err(ChatAuthError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let challenge_id = payload.challenge_id.trim();
    if challenge_id.is_empty() {
        return Err(ChatAuthError::BadRequest(
            "challenge_id es obligatorio.".to_string(),
        ));
    }

    let client_ip = extract_client_ip(&headers);
    let trace_id = extract_trace_id(&headers);

    let nonce_row = sqlx::query(
        "SELECT id, device_id, nonce, expires_at, used_at FROM chat_auth_nonces WHERE id = ?",
    )
    .bind(challenge_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    let Some(row) = nonce_row else {
        return Err(ChatAuthError::Unauthorized(
            "Reto no encontrado.".to_string(),
        ));
    };

    let device_id: String = row.try_get("device_id").unwrap_or_default();
    let nonce_base64: String = row.try_get("nonce").unwrap_or_default();
    let expires_at_str: String = row.try_get("expires_at").unwrap_or_default();
    let used_at: Option<String> = row.try_get("used_at").ok().flatten();

    let actor = Actor::with_details(&device_id, "device", None, Some(client_ip.clone()));
    let subject = Subject::with_type(&device_id, "device");

    if used_at.is_some() {
        let audit_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Chat,
            "chat.auth.failed",
            actor,
            Outcome::Denied,
            json!({
                "reason": "challenge_used",
                "challenge_id": challenge_id,
                "ip": &client_ip
            }),
        )
        .with_subject(subject);
        let _ = state.audit.append(audit_input).await;

        return Err(ChatAuthError::Unauthorized(
            "Reto ya utilizado.".to_string(),
        ));
    }

    let expires_at = parse_datetime_flexible(&expires_at_str)
        .map_err(|_| ChatAuthError::Internal("Formato de fecha inválido en DB.".to_string()))?;

    if Utc::now() > expires_at {
        let audit_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Chat,
            "chat.auth.failed",
            actor,
            Outcome::Denied,
            json!({
                "reason": "challenge_expired",
                "challenge_id": challenge_id,
                "ip": &client_ip
            }),
        )
        .with_subject(subject);
        let _ = state.audit.append(audit_input).await;

        return Err(ChatAuthError::Unauthorized("Reto caducado.".to_string()));
    }

    // Query device public key
    let device_row =
        sqlx::query("SELECT public_key, revoked_at FROM chat_devices WHERE device_id = ?")
            .bind(&device_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    let Some(dev) = device_row else {
        return Err(ChatAuthError::Unauthorized(
            "Dispositivo no encontrado.".to_string(),
        ));
    };

    let revoked_at: Option<String> = dev.try_get("revoked_at").ok().flatten();
    if revoked_at.is_some() {
        let audit_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Chat,
            "chat.auth.failed",
            actor,
            Outcome::Denied,
            json!({
                "reason": "device_revoked",
                "challenge_id": challenge_id,
                "ip": &client_ip
            }),
        )
        .with_subject(subject);
        let _ = state.audit.append(audit_input).await;

        return Err(ChatAuthError::Unauthorized(
            "Dispositivo revocado.".to_string(),
        ));
    }

    let public_key_base64: String = dev.try_get("public_key").unwrap_or_default();
    let pubkey_bytes = base64::engine::general_purpose::STANDARD
        .decode(&public_key_base64)
        .map_err(|_| {
            ChatAuthError::Internal("Clave pública corrupta en base de datos.".to_string())
        })?;

    let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
        ChatAuthError::Internal("Longitud de clave pública inválida en base de datos.".to_string())
    })?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|_| ChatAuthError::Internal("Error instanciando VerifyingKey.".to_string()))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload.signature.trim())
        .map_err(|_| ChatAuthError::Unauthorized("Firma base64 no válida.".to_string()))?;

    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        ChatAuthError::Unauthorized("Longitud de firma Ed25519 inválida.".to_string())
    })?;

    let signature = Signature::from_bytes(&sig_arr);

    let nonce_raw_bytes = base64::engine::general_purpose::STANDARD
        .decode(&nonce_base64)
        .map_err(|_| ChatAuthError::Internal("Nonce corrupto en base de datos.".to_string()))?;

    // Strict verification of the nonce signature
    if verifying_key
        .verify_strict(&nonce_raw_bytes, &signature)
        .is_err()
    {
        let audit_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Chat,
            "chat.auth.failed",
            actor,
            Outcome::Denied,
            json!({
                "reason": "invalid_signature",
                "challenge_id": challenge_id,
                "ip": &client_ip
            }),
        )
        .with_subject(subject);
        let _ = state.audit.append(audit_input).await;

        return Err(ChatAuthError::Unauthorized("Firma inválida.".to_string()));
    }

    // Mark nonce as used
    let now_str = Utc::now().to_rfc3339();
    sqlx::query("UPDATE chat_auth_nonces SET used_at = ? WHERE id = ?")
        .bind(&now_str)
        .bind(challenge_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    // Update last_auth_at
    sqlx::query("UPDATE chat_devices SET last_auth_at = ? WHERE device_id = ?")
        .bind(&now_str)
        .bind(&device_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    // Generate chat session token: cercano_chat_<64 hex>
    let mut token_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut token_entropy);
    let mut session_token = String::with_capacity(13 + 64);
    session_token.push_str("cercano_chat_");
    for b in token_entropy {
        let _ = write!(session_token, "{:02x}", b);
    }

    let ttl_minutes = state.config.chat_device_token_ttl_minutes.max(1);
    let session_expires = (Utc::now() + chrono::Duration::minutes(ttl_minutes)).to_rfc3339();

    sqlx::query(
        "INSERT INTO chat_device_sessions (token, device_id, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&session_token)
    .bind(&device_id)
    .bind(&session_expires)
    .bind(&now_str)
    .execute(&state.db)
    .await
    .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(VerifyChallengeResponse {
            token: session_token,
            expires_at: session_expires,
        }),
    )
        .into_response())
}

pub async fn reset_device_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(device_id_raw): Path<String>,
    Json(payload): Json<ResetDeviceRequest>,
) -> Result<Response, ChatAuthError> {
    if !state.config.chat_enabled {
        return Err(ChatAuthError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    // Must have chat:manage permission
    let has_manage =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_MANAGE)
            .await;

    if !has_manage && user.role != "admin" {
        return Err(ChatAuthError::Forbidden(
            "Se requiere permiso chat:manage para restablecer dispositivos.".to_string(),
        ));
    }

    let device_id = validate_device_id(&device_id_raw).map_err(ChatAuthError::BadRequest)?;
    let trace_id = extract_trace_id(&headers);

    let existing = sqlx::query("SELECT device_id FROM chat_devices WHERE device_id = ?")
        .bind(&device_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    if existing.is_none() {
        return Err(ChatAuthError::NotFound(
            "Dispositivo no encontrado en registro de chat.".to_string(),
        ));
    }

    let now_str = Utc::now().to_rfc3339();

    // Revoke all existing sessions and nonces, and mark revoked in chat_devices
    sqlx::query(
        "UPDATE chat_device_sessions SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
    )
    .bind(&now_str)
    .bind(&device_id)
    .execute(&state.db)
    .await
    .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    sqlx::query("UPDATE chat_auth_nonces SET used_at = ? WHERE device_id = ? AND used_at IS NULL")
        .bind(&now_str)
        .bind(&device_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    // Delete chat_devices entry so it can be re-registered with a new key cleanly (as required by administrative reset)
    sqlx::query("DELETE FROM chat_devices WHERE device_id = ?")
        .bind(&device_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

    let actor = Actor::with_type(&user.id, "user");
    let subject = Subject::with_type(&device_id, "device");
    let audit_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Chat,
        "chat.device.revoked",
        actor,
        Outcome::Success,
        json!({
            "device_id": &device_id,
            "reason": payload.reason.unwrap_or_else(|| "administrative_reset".to_string())
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    Ok((
        StatusCode::OK,
        Json(ResetDeviceResponse {
            device_id,
            status: "reset".to_string(),
        }),
    )
        .into_response())
}

/// Extractor for routes that require an authenticated chat device session (`Authorization: Bearer cercano_chat_...`).
#[derive(Debug, Clone)]
pub struct AuthenticatedChatDevice {
    pub device_id: String,
    pub session_token: String,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthenticatedChatDevice {
    type Rejection = ChatAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                ChatAuthError::Unauthorized("Cabecera Authorization ausente.".to_string())
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                ChatAuthError::Unauthorized("Formato de token Bearer inválido.".to_string())
            })?;

        if !token.starts_with("cercano_chat_") {
            return Err(ChatAuthError::Unauthorized(
                "Token de chat de dispositivo inválido.".to_string(),
            ));
        }

        let row = sqlx::query(
            "SELECT s.device_id, s.expires_at, s.revoked_at, d.revoked_at as device_revoked
             FROM chat_device_sessions s
             LEFT JOIN chat_devices d ON s.device_id = d.device_id
             WHERE s.token = ?",
        )
        .bind(token)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ChatAuthError::Internal(e.to_string()))?;

        let Some(session) = row else {
            return Err(ChatAuthError::Unauthorized(
                "Sesión de chat no encontrada.".to_string(),
            ));
        };

        let device_id: String = session.try_get("device_id").unwrap_or_default();
        let expires_at_str: String = session.try_get("expires_at").unwrap_or_default();
        let session_revoked: Option<String> = session.try_get("revoked_at").ok().flatten();
        let device_revoked: Option<String> = session.try_get("device_revoked").ok().flatten();

        if session_revoked.is_some() || device_revoked.is_some() {
            return Err(ChatAuthError::Unauthorized(
                "Sesión de chat revocada.".to_string(),
            ));
        }

        let expires_at = parse_datetime_flexible(&expires_at_str)
            .map_err(|_| ChatAuthError::Internal("Formato de fecha inválido en DB.".to_string()))?;

        if Utc::now() > expires_at {
            return Err(ChatAuthError::Unauthorized(
                "Sesión de chat expirada.".to_string(),
            ));
        }

        Ok(Self {
            device_id,
            session_token: token.to_string(),
        })
    }
}
