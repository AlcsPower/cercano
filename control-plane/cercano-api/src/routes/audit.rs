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

use std::str::FromStr;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use audit_core::{
    Actor, AuditError, AuditEvent, Category, EventFilter, EventInput, Outcome, Source, Subject,
};

use crate::auth::AuthenticatedUser;
use crate::AppState;

/// Error type for audit route handling.
#[derive(Debug, thiserror::Error)]
pub enum AuditRouteError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Audit core error: {0}")]
    Audit(#[from] AuditError),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
}

impl IntoResponse for AuditRouteError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AuditRouteError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, "validation_error", msg.clone())
            }
            AuditRouteError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone())
            }
            AuditRouteError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            AuditRouteError::Db(err) => {
                tracing::error!("Database error in audit route: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Error interno en la base de datos".to_string(),
                )
            }
            AuditRouteError::Audit(err) => {
                tracing::error!("Audit core error in audit route: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_error",
                    err.to_string(),
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

/// Recursively inspects a JSON value to ensure no forbidden sensitive keys exist.
pub fn validate_security_details(value: &serde_json::Value) -> Result<(), AuditRouteError> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let lower = key.to_ascii_lowercase();
                if lower == "password"
                    || lower == "secret"
                    || lower == "private_key"
                    || lower == "token"
                    || lower.contains("password")
                    || lower.contains("secret")
                    || lower.contains("private_key")
                    || (lower.contains("token") && lower != "token_id")
                {
                    return Err(AuditRouteError::Validation(format!(
                        "Campo sensible prohibido detectado en details: '{}'",
                        key
                    )));
                }
                validate_security_details(val)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                validate_security_details(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Authenticates ingestion callers: admin session token, authenticated device, or internal key.
pub async fn authenticate_ingestion_caller(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(), AuditRouteError> {
    // 1. Check internal token header
    if let Some(internal_header) = headers
        .get("X-Cercano-Internal-Token")
        .or_else(|| headers.get("x-cercano-internal-token"))
        .and_then(|h| h.to_str().ok())
    {
        if internal_header == state.config.internal_token {
            return Ok(());
        }
    }

    // 2. Check device token/id header
    if let Some(device_id) = headers
        .get("X-Device-Id")
        .or_else(|| headers.get("x-device-id"))
        .or_else(|| headers.get("X-Cercano-Device-Token"))
        .or_else(|| headers.get("x-cercano-device-token"))
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let device_row = sqlx::query("SELECT 1 FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?;

        if device_row.is_some() {
            return Ok(());
        }
    }

    // 3. Check Bearer session token
    if let Some(auth_header) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty());

        if let Some(tok) = token {
            let session_row = sqlx::query(
                r#"
                SELECT u.role, u.is_active
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
                  AND s.revoked_at IS NULL
                  AND s.expires_at > datetime('now')
                "#,
            )
            .bind(tok)
            .fetch_optional(&state.db)
            .await?;

            if let Some(row) = session_row {
                use sqlx::Row;
                let is_active: i64 = row.get("is_active");
                if is_active == 1 {
                    return Ok(());
                }
            }
        }
    }

    Err(AuditRouteError::Unauthorized(
        "Autenticación requerida para la ingestión de eventos de auditoría".to_string(),
    ))
}

/// Enforces that the request comes from an authenticated administrator.
pub fn require_admin(user: &AuthenticatedUser) -> Result<(), AuditRouteError> {
    if user.role != "admin" {
        return Err(AuditRouteError::Forbidden(
            "Acceso restringido exclusivamente a administradores".to_string(),
        ));
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Request DTOs
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawEventRequest {
    #[serde(default)]
    pub event_id: Option<String>,
    pub trace_id: String,
    #[serde(default)]
    pub ts: Option<String>,
    pub source: Source,
    pub category: Category,
    pub action: String,
    pub actor: Actor,
    #[serde(default)]
    pub subject: Option<Subject>,
    pub outcome: Outcome,
    pub details: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SessionStartRequest {
    #[serde(default)]
    pub event_id: Option<String>,
    pub trace_id: String,
    pub controller_id: String,
    pub controlled_id: String,
    pub session_type: String,
    pub auth_method: String,
    #[serde(default)]
    pub actor_name: Option<String>,
    #[serde(default)]
    pub actor_ip: Option<String>,
    #[serde(default)]
    pub controlled_name: Option<String>,
    #[serde(default)]
    pub two_factor_verified: Option<bool>,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default)]
    pub rendezvous_server: Option<String>,
    #[serde(default)]
    pub relay_server: Option<String>,
    #[serde(default)]
    pub is_direct_lan: Option<bool>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SessionEndRequest {
    #[serde(default)]
    pub event_id: Option<String>,
    pub trace_id: String,
    pub duration_secs: u64,
    pub close_reason: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub actor_name: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub subject_name: Option<String>,
    #[serde(default)]
    pub session_notes: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileTransferRequest {
    #[serde(default)]
    pub event_id: Option<String>,
    pub trace_id: String,
    pub direction: String,
    pub remote_path: String,
    pub bytes: u64,
    pub file_sha256: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub transfer_mode: Option<String>,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub actor_name: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub subject_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AlarmRequest {
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    pub alarm_type: String,
    pub severity: String,
    #[serde(default)]
    pub actor_ip: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct QueryEventsParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub trace_id: Option<String>,
    pub category: Option<String>,
    pub action: Option<String>,
    pub actor_id: Option<String>,
    pub subject_id: Option<String>,
    pub outcome: Option<String>,
}

// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

/// `POST /api/audit/events`
///
/// Ingestion endpoint for arbitrary compliant audit events.
/// Enforces authentication, idempotent de-duplication, and security filtering.
pub async fn ingest_event_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RawEventRequest>,
) -> Result<(StatusCode, Json<AuditEvent>), AuditRouteError> {
    authenticate_ingestion_caller(&headers, &state).await?;
    validate_security_details(&payload.details)?;

    // Idempotency check: if an event with the same event_id exists, return 200 OK
    if let Some(ref eid) = payload.event_id {
        if let Some(existing) = state.audit.get_event_by_id(eid).await? {
            return Ok((StatusCode::OK, Json(existing)));
        }
    }

    let mut event_input = EventInput::new(
        payload.trace_id,
        payload.source,
        payload.category,
        payload.action,
        payload.actor,
        payload.outcome,
        payload.details,
    );

    if let Some(ref eid) = payload.event_id {
        event_input = event_input.with_event_id(eid.clone());
    }
    if let Some(ts) = payload.ts {
        event_input = event_input.with_ts(ts);
    }
    if let Some(subject) = payload.subject {
        event_input = event_input.with_subject(subject);
    }

    match state.audit.append(event_input).await {
        Ok(created) => Ok((StatusCode::CREATED, Json(created))),
        Err(e) => {
            if let Some(ref eid) = payload.event_id {
                if let Ok(Some(existing)) = state.audit.get_event_by_id(eid).await {
                    return Ok((StatusCode::OK, Json(existing)));
                }
            }
            Err(AuditRouteError::Audit(e))
        }
    }
}

/// `POST /api/audit/session/start`
///
/// Specialized endpoint for remote connection start (`conn.start`).
pub async fn session_start_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SessionStartRequest>,
) -> Result<(StatusCode, Json<AuditEvent>), AuditRouteError> {
    authenticate_ingestion_caller(&headers, &state).await?;

    if let Some(ref eid) = payload.event_id {
        if let Some(existing) = state.audit.get_event_by_id(eid).await? {
            return Ok((StatusCode::OK, Json(existing)));
        }
    }

    let mut details_map = serde_json::Map::new();
    details_map.insert("session_type".to_string(), json!(payload.session_type));
    details_map.insert("auth_method".to_string(), json!(payload.auth_method));
    details_map.insert(
        "two_factor_verified".to_string(),
        json!(payload.two_factor_verified.unwrap_or(false)),
    );
    if let Some(ref v) = payload.client_version {
        details_map.insert("client_version".to_string(), json!(v));
    }
    if let Some(ref s) = payload.rendezvous_server {
        details_map.insert("rendezvous_server".to_string(), json!(s));
    }
    if let Some(ref r) = payload.relay_server {
        details_map.insert("relay_server".to_string(), json!(r));
    }
    details_map.insert(
        "is_direct_lan".to_string(),
        json!(payload.is_direct_lan.unwrap_or(false)),
    );

    if let Some(serde_json::Value::Object(extra)) = payload.metadata {
        for (k, v) in extra {
            details_map.insert(k, v);
        }
    }

    let details = serde_json::Value::Object(details_map);
    validate_security_details(&details)?;

    let actor = Actor::with_details(
        payload.controller_id,
        "user",
        payload.actor_name,
        payload.actor_ip,
    );
    let subject = Subject::with_details(payload.controlled_id, "device", payload.controlled_name);

    let mut input = EventInput::new(
        payload.trace_id,
        Source::Client,
        Category::Conn,
        "conn.start",
        actor,
        Outcome::Success,
        details,
    )
    .with_subject(subject);

    if let Some(ref eid) = payload.event_id {
        input = input.with_event_id(eid.clone());
    }

    match state.audit.append(input).await {
        Ok(created) => Ok((StatusCode::CREATED, Json(created))),
        Err(e) => {
            if let Some(ref eid) = payload.event_id {
                if let Ok(Some(existing)) = state.audit.get_event_by_id(eid).await {
                    return Ok((StatusCode::OK, Json(existing)));
                }
            }
            Err(AuditRouteError::Audit(e))
        }
    }
}

/// `POST /api/audit/session/end`
///
/// Specialized endpoint for connection termination (`conn.end`).
pub async fn session_end_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SessionEndRequest>,
) -> Result<(StatusCode, Json<AuditEvent>), AuditRouteError> {
    authenticate_ingestion_caller(&headers, &state).await?;

    if let Some(ref eid) = payload.event_id {
        if let Some(existing) = state.audit.get_event_by_id(eid).await? {
            return Ok((StatusCode::OK, Json(existing)));
        }
    }

    let mut details_map = serde_json::Map::new();
    details_map.insert("duration_seconds".to_string(), json!(payload.duration_secs));
    details_map.insert("close_reason".to_string(), json!(payload.close_reason));
    details_map.insert("bytes_sent".to_string(), json!(payload.bytes_sent));
    details_map.insert("bytes_received".to_string(), json!(payload.bytes_received));
    if let Some(ref notes) = payload.session_notes {
        details_map.insert("session_notes".to_string(), json!(notes));
    }

    let details = serde_json::Value::Object(details_map);
    validate_security_details(&details)?;

    let actor_id = payload.actor_id.unwrap_or_else(|| "unknown".to_string());
    let actor = Actor::with_details(actor_id, "user", payload.actor_name, None);

    let mut input = EventInput::new(
        payload.trace_id,
        Source::Client,
        Category::Conn,
        "conn.end",
        actor,
        Outcome::Success,
        details,
    );

    if let Some(sub_id) = payload.subject_id {
        let subject = Subject::with_details(sub_id, "device", payload.subject_name);
        input = input.with_subject(subject);
    }

    if let Some(ref eid) = payload.event_id {
        input = input.with_event_id(eid.clone());
    }

    match state.audit.append(input).await {
        Ok(created) => Ok((StatusCode::CREATED, Json(created))),
        Err(e) => {
            if let Some(ref eid) = payload.event_id {
                if let Ok(Some(existing)) = state.audit.get_event_by_id(eid).await {
                    return Ok((StatusCode::OK, Json(existing)));
                }
            }
            Err(AuditRouteError::Audit(e))
        }
    }
}

/// `POST /api/audit/file-transfer`
///
/// Specialized endpoint for file transfers (`file.transfer`).
pub async fn file_transfer_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<FileTransferRequest>,
) -> Result<(StatusCode, Json<AuditEvent>), AuditRouteError> {
    authenticate_ingestion_caller(&headers, &state).await?;

    if payload.direction != "upload" && payload.direction != "download" {
        return Err(AuditRouteError::Validation(
            "El campo 'direction' debe ser 'upload' o 'download'".to_string(),
        ));
    }

    if let Some(ref eid) = payload.event_id {
        if let Some(existing) = state.audit.get_event_by_id(eid).await? {
            return Ok((StatusCode::OK, Json(existing)));
        }
    }

    let file_name = payload.file_name.unwrap_or_else(|| {
        std::path::Path::new(&payload.remote_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown")
            .to_string()
    });

    let mut details_map = serde_json::Map::new();
    details_map.insert("direction".to_string(), json!(payload.direction));
    details_map.insert("remote_path".to_string(), json!(payload.remote_path));
    details_map.insert("file_name".to_string(), json!(file_name));
    details_map.insert("bytes_transferred".to_string(), json!(payload.bytes));
    details_map.insert("sha256".to_string(), json!(payload.file_sha256));
    details_map.insert(
        "transfer_mode".to_string(),
        json!(payload
            .transfer_mode
            .unwrap_or_else(|| "dedicated_session".to_string())),
    );

    let details = serde_json::Value::Object(details_map);
    validate_security_details(&details)?;

    let actor_id = payload.actor_id.unwrap_or_else(|| "unknown".to_string());
    let actor = Actor::with_details(actor_id, "user", payload.actor_name, None);

    let mut input = EventInput::new(
        payload.trace_id,
        Source::Client,
        Category::File,
        "file.transfer",
        actor,
        Outcome::Success,
        details,
    );

    if let Some(sub_id) = payload.subject_id {
        let subject = Subject::with_details(sub_id, "device", payload.subject_name);
        input = input.with_subject(subject);
    }

    if let Some(ref eid) = payload.event_id {
        input = input.with_event_id(eid.clone());
    }

    match state.audit.append(input).await {
        Ok(created) => Ok((StatusCode::CREATED, Json(created))),
        Err(e) => {
            if let Some(ref eid) = payload.event_id {
                if let Ok(Some(existing)) = state.audit.get_event_by_id(eid).await {
                    return Ok((StatusCode::OK, Json(existing)));
                }
            }
            Err(AuditRouteError::Audit(e))
        }
    }
}

/// `POST /api/audit/alarm`
///
/// Specialized endpoint for alarm triggers (`alarm.*`).
pub async fn alarm_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AlarmRequest>,
) -> Result<(StatusCode, Json<AuditEvent>), AuditRouteError> {
    authenticate_ingestion_caller(&headers, &state).await?;

    if let Some(ref eid) = payload.event_id {
        if let Some(existing) = state.audit.get_event_by_id(eid).await? {
            return Ok((StatusCode::OK, Json(existing)));
        }
    }

    let action = if payload.alarm_type.starts_with("alarm.") {
        payload.alarm_type.clone()
    } else {
        format!("alarm.{}", payload.alarm_type)
    };

    let mut details_map = serde_json::Map::new();
    details_map.insert("alarm_name".to_string(), json!(payload.alarm_type));
    details_map.insert("severity".to_string(), json!(payload.severity));
    details_map.insert("reason".to_string(), json!(payload.reason));

    if let Some(serde_json::Value::Object(extra)) = payload.details {
        for (k, v) in extra {
            details_map.insert(k, v);
        }
    }

    let details = serde_json::Value::Object(details_map);
    validate_security_details(&details)?;

    let actor_id = payload
        .actor_id
        .unwrap_or_else(|| "sys_alarm_engine".to_string());
    let actor = Actor::with_details(
        actor_id,
        "system",
        Some("AlarmEngine".to_string()),
        payload.actor_ip,
    );

    let trace_id = payload
        .trace_id
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());

    let mut input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Alarm,
        action,
        actor,
        Outcome::Denied,
        details,
    );

    if let Some(sub_id) = payload.subject_id {
        let subject = Subject::new(sub_id);
        input = input.with_subject(subject);
    }

    if let Some(ref eid) = payload.event_id {
        input = input.with_event_id(eid.clone());
    }

    match state.audit.append(input).await {
        Ok(created) => Ok((StatusCode::CREATED, Json(created))),
        Err(e) => {
            if let Some(ref eid) = payload.event_id {
                if let Ok(Some(existing)) = state.audit.get_event_by_id(eid).await {
                    return Ok((StatusCode::OK, Json(existing)));
                }
            }
            Err(AuditRouteError::Audit(e))
        }
    }
}

/// `GET /api/audit/events`
///
/// Query audit events. Protected by admin session token.
pub async fn query_events_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(params): Query<QueryEventsParams>,
) -> Result<Json<Vec<AuditEvent>>, AuditRouteError> {
    require_admin(&user)?;

    let category = params
        .category
        .as_ref()
        .map(|c| Category::from_str(c).unwrap());
    let outcome = params
        .outcome
        .as_ref()
        .map(|o| Outcome::from_str(o).unwrap());

    let filter = EventFilter {
        trace_id: params.trace_id,
        category,
        action: params.action,
        actor_id: params.actor_id,
        subject_id: params.subject_id,
        outcome,
        from_ts: None,
        to_ts: None,
        from_seq: None,
        to_seq: None,
        limit: params.limit.or(Some(50)),
        offset: params.offset,
    };

    let events = state.audit.query_events(filter).await?;
    Ok(Json(events))
}

/// `GET /api/audit/verify`
///
/// Runs real-time cryptographic verification on the entire audit chain.
/// Protected by admin session token.
pub async fn verify_chain_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<(StatusCode, Json<serde_json::Value>), AuditRouteError> {
    require_admin(&user)?;

    let result = state.audit.verify_chain(None, None).await?;

    if result.is_valid {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "events_verified": result.total_verified,
                "chain_valid": true,
            })),
        ))
    } else {
        Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "corrupted",
                "error": "chain_corrupted",
                "events_verified": result.total_verified,
                "chain_valid": false,
                "details": result.error,
            })),
        ))
    }
}
