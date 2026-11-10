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

use std::net::SocketAddr;

use audit_core::{Actor, AuditError, Category, EventInput, Outcome, Source, Subject};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use thiserror::Error;

use crate::auth::{extract_client_ip, extract_trace_id};
use crate::revocation::RevocationStatus;
use crate::AppState;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Device not found: {0}")]
    NotFound(String),
    #[error("Role violation: {0}")]
    RoleViolation(String),
    #[error("Installer revoked: {0}")]
    InstallerRevoked(String),
    #[error("Installer expired: {0}")]
    InstallerExpired(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            SessionError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, "validation_error", msg.clone())
            }
            SessionError::NotFound(msg) => (StatusCode::NOT_FOUND, "device_not_found", msg.clone()),
            SessionError::RoleViolation(msg) => {
                (StatusCode::FORBIDDEN, "role_violation", msg.clone())
            }
            SessionError::InstallerRevoked(msg) => {
                (StatusCode::FORBIDDEN, "installer_revoked", msg.clone())
            }
            SessionError::InstallerExpired(msg) => {
                (StatusCode::FORBIDDEN, "installer_expired", msg.clone())
            }
            SessionError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            SessionError::Db(err) => {
                tracing::error!("Database error in session operation: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Error interno en la base de datos".to_string(),
                )
            }
            SessionError::Audit(err) => {
                tracing::error!("Audit error in session operation: {:?}", err);
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InitiateSessionRequest {
    pub device_id: String,
    pub target_device_id: String,
    #[serde(default)]
    pub installer_id: Option<String>,
    #[serde(default)]
    pub connection_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InitiateSessionResponse {
    pub status: &'static str,
    pub session_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ElevationRequest {
    pub device_id: String,
    pub target_device_id: String,
    pub reason: String,
    #[serde(default)]
    pub ticket: Option<String>,
    #[serde(default)]
    pub installer_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ElevationResponse {
    pub status: &'static str,
    pub elevation_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PolicyApplyRequest {
    pub device_id: String,
    pub policy_key: String,
    pub policy_value: serde_json::Value,
    #[serde(default)]
    pub installer_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PolicyApplyResponse {
    pub status: &'static str,
    pub message: String,
}

/// Helper to enforce technical role and installer validity according to ADR-008.
async fn enforce_technical_role(
    state: &AppState,
    device_id: &str,
    requested_installer_id: Option<&str>,
    operation: &str,
    headers: &HeaderMap,
    client_ip: &str,
) -> Result<(String, Option<String>), SessionError> {
    let trace_id = extract_trace_id(headers);

    // 1. Check device existence and registered role in database
    let device_row = sqlx::query("SELECT id, role, installer_id FROM devices WHERE id = ?")
        .bind(device_id)
        .fetch_optional(&state.db)
        .await?;

    let (registered_role, resolved_installer_id) = match device_row {
        Some(r) => {
            let role: String = r.get("role");
            let inst_id: Option<String> = r.get("installer_id");
            (
                role,
                inst_id.or_else(|| requested_installer_id.map(String::from)),
            )
        }
        None => {
            // Check if installer is in build_jobs
            if let Some(inst_id) = requested_installer_id {
                let job_row = sqlx::query("SELECT role FROM build_jobs WHERE id = ?")
                    .bind(inst_id)
                    .fetch_optional(&state.db)
                    .await?;
                if let Some(j) = job_row {
                    let role: String = j.get("role");
                    (role, Some(inst_id.to_string()))
                } else {
                    return Err(SessionError::NotFound(format!(
                        "Dispositivo '{}' no encontrado en el sistema",
                        device_id
                    )));
                }
            } else {
                return Err(SessionError::NotFound(format!(
                    "Dispositivo '{}' no encontrado en el sistema",
                    device_id
                )));
            }
        }
    };

    // 2. Enforce role: ONLY 'tecnico' is allowed to execute technical operations (ADR-008)
    if registered_role == "soporte" {
        let reason = format!(
            "Dispositivo '{}' con rol 'soporte' intentó ejecutar '{}' restringido a rol 'tecnico'",
            device_id, operation
        );

        let _ = state
            .alarms
            .record_role_violation(
                device_id,
                Some(client_ip),
                resolved_installer_id.as_deref(),
                "soporte",
                operation,
                &reason,
                Some(&trace_id),
            )
            .await;

        let actor = Actor::with_details(device_id, "device", None, Some(client_ip.to_string()));
        let subject = Subject::with_details(
            resolved_installer_id.as_deref().unwrap_or(device_id),
            "installer",
            Some("soporte".to_string()),
        );

        let audit_event = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.denied",
            actor,
            Outcome::Denied,
            json!({
                "reason": "role_violation",
                "device_id": device_id,
                "operation": operation,
                "registered_role": "soporte",
                "required_role": "tecnico",
                "installer_id": resolved_installer_id,
            }),
        )
        .with_subject(subject);

        let _ = state.audit.append(audit_event).await;

        return Err(SessionError::RoleViolation(format!(
            "Operación '{}' denegada: el dispositivo tiene rol 'soporte' y no tiene permisos de rol 'tecnico'",
            operation
        )));
    }

    if registered_role != "tecnico" {
        return Err(SessionError::RoleViolation(format!(
            "Rol '{}' no autorizado para la operación '{}'",
            registered_role, operation
        )));
    }

    // 3. For tecnico role, verify revocation status of installer if present
    if let Some(ref inst_id) = resolved_installer_id {
        match state.revocation_checker.check_installer(inst_id).await {
            Ok(RevocationStatus::InstallerRevoked {
                role,
                revoked_at,
                reason,
                ..
            }) => {
                return Err(SessionError::InstallerRevoked(format!(
                    "Instalador '{}' (rol {}) revocado en {}: {}",
                    inst_id,
                    role,
                    revoked_at,
                    reason.unwrap_or_default()
                )));
            }
            Ok(RevocationStatus::RoleRevoked {
                role, revoked_at, ..
            }) => {
                return Err(SessionError::InstallerRevoked(format!(
                    "El rol '{}' del instalador '{}' ha sido revocado en {}",
                    role, inst_id, revoked_at
                )));
            }
            Ok(RevocationStatus::InstallerExpired {
                expires_at, role, ..
            }) => {
                return Err(SessionError::InstallerExpired(format!(
                    "El instalador '{}' (rol {}) ha caducado en {}",
                    inst_id, role, expires_at
                )));
            }
            Ok(RevocationStatus::Valid { .. }) | Ok(RevocationStatus::NotFound) => {}
            Err(e) => {
                return Err(SessionError::Forbidden(format!(
                    "Error verificando revocación: {}",
                    e
                )));
            }
        }
    }

    Ok((device_id.to_string(), resolved_installer_id))
}

/// `POST /api/sessions/initiate`
///
/// Initiates an outgoing remote session. Strictly restricted to clients with role `tecnico`.
pub async fn initiate_session_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<InitiateSessionRequest>,
) -> Result<(StatusCode, Json<InitiateSessionResponse>), SessionError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    if payload.device_id.trim().is_empty() || payload.target_device_id.trim().is_empty() {
        return Err(SessionError::Validation(
            "device_id y target_device_id son obligatorios".to_string(),
        ));
    }

    let (dev_id, inst_id) = enforce_technical_role(
        &state,
        payload.device_id.trim(),
        payload.installer_id.as_deref(),
        "initiate_session",
        &headers,
        &client_ip,
    )
    .await?;

    let session_id = uuid::Uuid::now_v7().to_string();

    let actor = Actor::with_details(&dev_id, "device", None, Some(client_ip.clone()));
    let subject = Subject::with_details(
        &payload.target_device_id,
        "device",
        Some("target".to_string()),
    );

    let audit_event = EventInput::new(
        trace_id.clone(),
        Source::Api,
        Category::Conn,
        "conn.session_initiated",
        actor,
        Outcome::Success,
        json!({
            "session_id": session_id,
            "source_device": dev_id,
            "target_device": payload.target_device_id,
            "installer_id": inst_id,
            "role": "tecnico",
            "connection_type": payload.connection_type.unwrap_or_else(|| "remote_desktop".to_string())
        }),
    )
    .with_subject(subject);

    state.audit.append(audit_event).await?;

    Ok((
        StatusCode::OK,
        Json(InitiateSessionResponse {
            status: "success",
            session_id,
            source_device_id: dev_id,
            target_device_id: payload.target_device_id,
            message: "Sesión remota autorizada para rol técnico".to_string(),
        }),
    ))
}

/// `POST /api/elevation/request`
///
/// Requests privilege elevation. Strictly restricted to clients with role `tecnico`.
pub async fn request_elevation_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<ElevationRequest>,
) -> Result<(StatusCode, Json<ElevationResponse>), SessionError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    if payload.device_id.trim().is_empty() || payload.target_device_id.trim().is_empty() {
        return Err(SessionError::Validation(
            "device_id y target_device_id son obligatorios".to_string(),
        ));
    }

    if payload.reason.trim().is_empty() {
        return Err(SessionError::Validation(
            "El motivo de la elevación es obligatorio".to_string(),
        ));
    }

    let (dev_id, inst_id) = enforce_technical_role(
        &state,
        payload.device_id.trim(),
        payload.installer_id.as_deref(),
        "request_elevation",
        &headers,
        &client_ip,
    )
    .await?;

    let elevation_id = uuid::Uuid::now_v7().to_string();

    let actor = Actor::with_details(&dev_id, "device", None, Some(client_ip.clone()));
    let subject = Subject::with_details(
        &payload.target_device_id,
        "device",
        Some("target".to_string()),
    );

    let audit_event = EventInput::new(
        trace_id.clone(),
        Source::Api,
        Category::Console,
        "console.elevation_requested",
        actor,
        Outcome::Success,
        json!({
            "elevation_id": elevation_id,
            "source_device": dev_id,
            "target_device": payload.target_device_id,
            "reason": payload.reason,
            "ticket": payload.ticket,
            "installer_id": inst_id,
            "role": "tecnico"
        }),
    )
    .with_subject(subject);

    state.audit.append(audit_event).await?;

    Ok((
        StatusCode::OK,
        Json(ElevationResponse {
            status: "authorized",
            elevation_id,
            source_device_id: dev_id,
            target_device_id: payload.target_device_id,
            message: "Solicitud de elevación autorizada para rol técnico".to_string(),
        }),
    ))
}

/// `POST /api/policies/apply`
///
/// Applies restricted server policy adjustments. Strictly restricted to clients with role `tecnico`.
pub async fn apply_policy_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<PolicyApplyRequest>,
) -> Result<(StatusCode, Json<PolicyApplyResponse>), SessionError> {
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    if payload.device_id.trim().is_empty() || payload.policy_key.trim().is_empty() {
        return Err(SessionError::Validation(
            "device_id y policy_key son obligatorios".to_string(),
        ));
    }

    let (dev_id, inst_id) = enforce_technical_role(
        &state,
        payload.device_id.trim(),
        payload.installer_id.as_deref(),
        "apply_policy",
        &headers,
        &client_ip,
    )
    .await?;

    let actor = Actor::with_details(&dev_id, "device", None, Some(client_ip.clone()));
    let subject = Subject::with_details(&payload.policy_key, "server_policy", None);

    let audit_event = EventInput::new(
        trace_id.clone(),
        Source::Api,
        Category::Console,
        "console.policy_applied",
        actor,
        Outcome::Success,
        json!({
            "device_id": dev_id,
            "installer_id": inst_id,
            "policy_key": payload.policy_key,
            "policy_value": payload.policy_value,
            "role": "tecnico"
        }),
    )
    .with_subject(subject);

    state.audit.append(audit_event).await?;

    Ok((
        StatusCode::OK,
        Json(PolicyApplyResponse {
            status: "applied",
            message: "Política del servidor actualizada exitosamente".to_string(),
        }),
    ))
}
