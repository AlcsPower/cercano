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

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use std::net::SocketAddr;
use thiserror::Error;

use crate::auth::{extract_client_ip, extract_trace_id, AuthenticatedUser};
use crate::revocation::RevocationStatus;
use crate::AppState;

pub const DEVICE_STATUS_EXPR: &str = "CASE WHEN last_seen_at IS NOT NULL AND (strftime('%s', 'now') - strftime('%s', last_seen_at)) <= ? THEN 'online' ELSE 'offline' END";

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Device not found: {0}")]
    NotFound(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Role violation: {0}")]
    RoleViolation(String),
    #[error("Installer revoked: {0}")]
    InstallerRevoked(String),
    #[error("Installer expired: {0}")]
    InstallerExpired(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Rate limit exceeded: {0}")]
    RateLimited(String),
    #[error("Audit error: {0}")]
    Audit(#[from] audit_core::AuditError),
}

impl IntoResponse for DeviceError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            DeviceError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, "validation_error", msg.clone())
            }
            DeviceError::NotFound(msg) => (StatusCode::NOT_FOUND, "device_not_found", msg.clone()),
            DeviceError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            DeviceError::RoleViolation(msg) => {
                (StatusCode::FORBIDDEN, "role_violation", msg.clone())
            }
            DeviceError::InstallerRevoked(msg) => {
                (StatusCode::FORBIDDEN, "installer_revoked", msg.clone())
            }
            DeviceError::InstallerExpired(msg) => {
                (StatusCode::FORBIDDEN, "installer_expired", msg.clone())
            }
            DeviceError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone())
            }
            DeviceError::RateLimited(msg) => {
                (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg.clone())
            }
            DeviceError::Audit(err) => {
                tracing::error!("Audit error during device operation: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_error",
                    format!("Error interno registrando auditoría: {err}"),
                )
            }
            DeviceError::Db(err) => {
                tracing::error!("Database error during device operation: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Error interno en la base de datos.".to_string(),
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

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HeartbeatRequest {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub installer_id: Option<String>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

pub fn default_device_role() -> String {
    "soporte".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeviceResponse {
    pub id: String,
    pub name: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub version: Option<String>,
    pub ip_address: Option<String>,
    pub status: String,
    pub last_seen_at: Option<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default = "default_device_role")]
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeleteDeviceResponse {
    pub status: &'static str,
    pub message: String,
    pub id: String,
}

/// Validates device heartbeat input.
pub fn validate_heartbeat_input(req: &HeartbeatRequest) -> Result<(), DeviceError> {
    let trimmed_id = req.id.trim();
    if trimmed_id.is_empty() {
        return Err(DeviceError::Validation(
            "El ID del dispositivo es obligatorio.".to_string(),
        ));
    }
    if trimmed_id.len() > 128 {
        return Err(DeviceError::Validation(
            "El ID del dispositivo no puede exceder 128 caracteres.".to_string(),
        ));
    }
    if let Some(ref name) = req.name {
        if name.len() > 128 {
            return Err(DeviceError::Validation(
                "El nombre del dispositivo no puede exceder 128 caracteres.".to_string(),
            ));
        }
    }
    if let Some(ref hostname) = req.hostname {
        if hostname.len() > 128 {
            return Err(DeviceError::Validation(
                "El hostname no puede exceder 128 caracteres.".to_string(),
            ));
        }
    }
    if let Some(ref os) = req.os {
        if os.len() > 128 {
            return Err(DeviceError::Validation(
                "El sistema operativo no puede exceder 128 caracteres.".to_string(),
            ));
        }
    }
    if let Some(ref version) = req.version {
        if version.len() > 64 {
            return Err(DeviceError::Validation(
                "La versión no puede exceder 64 caracteres.".to_string(),
            ));
        }
    }
    if let Some(ref ip) = req.ip {
        if ip.len() > 64 {
            return Err(DeviceError::Validation(
                "La dirección IP no puede exceder 64 caracteres.".to_string(),
            ));
        }
    }
    if let Some(ref role) = req.role {
        let r = role.trim().to_lowercase();
        if r != "soporte" && r != "tecnico" {
            return Err(DeviceError::Validation(
                "El rol debe ser 'soporte' o 'tecnico'.".to_string(),
            ));
        }
    }
    Ok(())
}

/// Registers or updates a device heartbeat.
///
/// Records/updates device metadata (`id`, `name`/`hostname`, `os`, `version`, IP),
/// updates `last_seen_at` to the current timestamp and marks status as `online`.
/// Enforces socket-derived IP registration to prevent spoofing (H2) and preserves
/// existing user-assigned device name when subsequent heartbeats lack a name (H7).
pub async fn heartbeat_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<(StatusCode, Json<DeviceResponse>), DeviceError> {
    validate_heartbeat_input(&payload)?;

    let trimmed_id = payload.id.trim().to_string();

    // Rate limiting: throttle heartbeats if received within 1 second for the same device (H2)
    let recent = sqlx::query(
        r#"
        SELECT 1 FROM devices
        WHERE id = ?
          AND last_seen_at IS NOT NULL
          AND (strftime('%s', 'now') - strftime('%s', last_seen_at)) < 1
        "#,
    )
    .bind(&trimmed_id)
    .fetch_optional(&state.db)
    .await?;

    if recent.is_some() {
        return Err(DeviceError::RateLimited(
            "Frecuencia de latidos excedida. Espere al menos 1 segundo entre peticiones."
                .to_string(),
        ));
    }

    let provided_name = payload
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let resolved_hostname = payload
        .hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let resolved_os = payload
        .os
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let resolved_version = payload
        .version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    // H2: Use socket peer IP or trusted local proxy headers, never client-reported JSON IP
    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );

    if let Some(ref reported_ip) = payload.ip {
        if reported_ip != &client_ip {
            tracing::debug!(
                device_id = %trimmed_id,
                reported_ip = %reported_ip,
                socket_ip = %client_ip,
                "Device reported IP in payload differs from socket connection IP; recording verified connection IP"
            );
        }
    }

    // Resolver installer_id, profile_id y role de payload o cabeceras
    let incoming_installer_id = payload
        .installer_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            headers
                .get("x-installer-id")
                .and_then(|h| h.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
        });

    let incoming_profile_id = payload
        .profile_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            headers
                .get("x-profile-id")
                .and_then(|h| h.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
        });

    let incoming_role = payload
        .role
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .or_else(|| {
            headers
                .get("x-client-role")
                .or_else(|| headers.get("x-role"))
                .and_then(|h| h.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase)
        });

    // Consultar si el dispositivo ya tenía un instalador o rol asociado en base de datos
    let existing_device_row =
        sqlx::query("SELECT installer_id, profile_id, role FROM devices WHERE id = ?")
            .bind(&trimmed_id)
            .fetch_optional(&state.db)
            .await?;

    let (existing_installer_id, existing_profile_id, existing_role): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = match existing_device_row {
        Some(ref r) => (r.get("installer_id"), r.get("profile_id"), r.get("role")),
        None => (None, None, None),
    };

    let mut installer_profile_id: Option<String> = None;

    let assigned_role = if let Some(ref exist_role) = existing_role {
        // Dispositivo ya registrado: inmutabilidad estricta de installer_id y role (ADR-008)
        if let Some(ref exist_inst) = existing_installer_id {
            if let Some(ref inc_inst) = incoming_installer_id {
                if inc_inst != exist_inst {
                    return Err(DeviceError::Forbidden(format!(
                        "No se puede modificar el installer_id '{}' de un dispositivo ya registrado",
                        exist_inst
                    )));
                }
            }
        }

        if exist_role == "soporte" && incoming_role.as_deref() == Some("tecnico") {
            let trace_id = extract_trace_id(&headers);
            let reason_str = format!(
                "Dispositivo '{}' registrado con rol 'soporte' intentó identificarse como 'tecnico' (suplantación de rol)",
                trimmed_id
            );
            let _ = state
                .alarms
                .record_role_violation(
                    &trimmed_id,
                    Some(&client_ip),
                    existing_installer_id
                        .as_deref()
                        .or(incoming_installer_id.as_deref()),
                    "soporte",
                    "tecnico",
                    &reason_str,
                    Some(&trace_id),
                )
                .await;

            let actor = Actor::with_details(
                &trimmed_id,
                "device",
                provided_name.clone(),
                Some(client_ip.clone()),
            );
            let subject = Subject::with_details(
                existing_installer_id.as_deref().unwrap_or(&trimmed_id),
                "installer",
                Some("soporte".to_string()),
            );
            let audit_input = EventInput::new(
                trace_id.clone(),
                Source::Api,
                Category::Auth,
                "auth.denied",
                actor,
                Outcome::Denied,
                json!({
                    "reason": "role_violation",
                    "device_id": trimmed_id,
                    "registered_role": "soporte",
                    "claimed_role": "tecnico",
                    "installer_id": existing_installer_id
                }),
            )
            .with_subject(subject);
            let _ = state.audit.append(audit_input).await;

            return Err(DeviceError::RoleViolation(
                "Dispositivo registrado con rol 'soporte' no puede operar con rol 'tecnico'"
                    .to_string(),
            ));
        }

        exist_role.clone()
    } else {
        // Dispositivo nuevo: derivar rol canónico a partir del instalador firmado en build_jobs
        if let Some(ref inst_id) = incoming_installer_id {
            let job_row = sqlx::query("SELECT role, profile_id FROM build_jobs WHERE id = ?")
                .bind(inst_id)
                .fetch_optional(&state.db)
                .await?;

            if let Some(j) = job_row {
                let canonical_role: String = j.get("role");
                let p_id: String = j.get("profile_id");
                installer_profile_id = Some(p_id);

                if canonical_role == "soporte" && incoming_role.as_deref() == Some("tecnico") {
                    let trace_id = extract_trace_id(&headers);
                    let reason_str = format!(
                        "Instalador '{}' registrado como 'soporte' intentó reportar o registrarse con capacidades/rol de 'tecnico'",
                        inst_id
                    );
                    let _ = state
                        .alarms
                        .record_role_violation(
                            &trimmed_id,
                            Some(&client_ip),
                            Some(inst_id),
                            "soporte",
                            "tecnico",
                            &reason_str,
                            Some(&trace_id),
                        )
                        .await;

                    let actor = Actor::with_details(
                        &trimmed_id,
                        "device",
                        provided_name.clone(),
                        Some(client_ip.clone()),
                    );
                    let subject =
                        Subject::with_details(inst_id, "installer", Some("soporte".to_string()));
                    let audit_input = EventInput::new(
                        trace_id.clone(),
                        Source::Api,
                        Category::Auth,
                        "auth.denied",
                        actor,
                        Outcome::Denied,
                        json!({
                            "reason": "role_violation",
                            "device_id": trimmed_id,
                            "installer_id": inst_id,
                            "canonical_role": "soporte",
                            "claimed_role": "tecnico"
                        }),
                    )
                    .with_subject(subject);
                    let _ = state.audit.append(audit_input).await;

                    return Err(DeviceError::RoleViolation(format!(
                        "El instalador '{}' está registrado como 'soporte' y no puede operar con rol 'tecnico'",
                        inst_id
                    )));
                }

                canonical_role
            } else {
                if incoming_role.as_deref() == Some("tecnico") {
                    let trace_id = extract_trace_id(&headers);
                    let reason_str = format!(
                        "Intento no autorizado de registrar rol 'tecnico' con instalador no reconocido '{}'",
                        inst_id
                    );
                    let _ = state
                        .alarms
                        .record_role_violation(
                            &trimmed_id,
                            Some(&client_ip),
                            Some(inst_id),
                            "soporte",
                            "tecnico",
                            &reason_str,
                            Some(&trace_id),
                        )
                        .await;

                    return Err(DeviceError::RoleViolation(
                        "No se permite registrar rol 'tecnico' sin un instalador autorizado correspondiente".to_string(),
                    ));
                }
                incoming_role.unwrap_or_else(|| "soporte".to_string())
            }
        } else {
            if incoming_role.as_deref() == Some("tecnico") {
                let trace_id = extract_trace_id(&headers);
                let reason_str = "Intento no autorizado de registrar dispositivo con rol 'tecnico' sin instalador firmado".to_string();
                let _ = state
                    .alarms
                    .record_role_violation(
                        &trimmed_id,
                        Some(&client_ip),
                        None,
                        "soporte",
                        "tecnico",
                        &reason_str,
                        Some(&trace_id),
                    )
                    .await;

                return Err(DeviceError::RoleViolation(
                    "No se permite registrar rol 'tecnico' sin un instalador autorizado"
                        .to_string(),
                ));
            }
            incoming_role.unwrap_or_else(|| "soporte".to_string())
        }
    };

    let resolved_installer_id = incoming_installer_id.or(existing_installer_id);
    let resolved_profile_id = incoming_profile_id
        .or(existing_profile_id)
        .or(installer_profile_id);

    // Validación de revocación y caducidad del instalador
    if let Some(ref inst_id) = resolved_installer_id {
        match state.revocation_checker.check_installer(inst_id).await {
            Ok(RevocationStatus::InstallerRevoked {
                role,
                revoked_at,
                reason,
                ..
            }) => {
                let trace_id = extract_trace_id(&headers);
                let reason_str = reason
                    .unwrap_or_else(|| "Instalador revocado por el administrador".to_string());
                let actor = Actor::with_details(
                    &trimmed_id,
                    "device",
                    provided_name.clone(),
                    Some(client_ip.clone()),
                );
                let subject = Subject::with_details(inst_id, "installer", Some(role.clone()));

                let audit_event = EventInput::new(
                    trace_id,
                    Source::Api,
                    Category::Build,
                    "build.registration_rejected",
                    actor,
                    Outcome::Denied,
                    json!({
                        "device_id": trimmed_id,
                        "installer_id": inst_id,
                        "role": role,
                        "reason": reason_str,
                        "revoked_at": revoked_at,
                        "rejection_type": "installer_revoked"
                    }),
                )
                .with_subject(subject);

                let _ = state.audit.append(audit_event).await;

                return Err(DeviceError::InstallerRevoked(format!(
                    "Instalador '{}' revocado en {}: {}",
                    inst_id, revoked_at, reason_str
                )));
            }
            Ok(RevocationStatus::RoleRevoked {
                role,
                revoked_at,
                reason,
                ..
            }) => {
                let trace_id = extract_trace_id(&headers);
                let reason_str =
                    reason.unwrap_or_else(|| format!("Rol '{}' revocado globalmente", role));
                let actor = Actor::with_details(
                    &trimmed_id,
                    "device",
                    provided_name.clone(),
                    Some(client_ip.clone()),
                );
                let subject = Subject::with_details(inst_id, "installer", Some(role.clone()));

                let audit_event = EventInput::new(
                    trace_id,
                    Source::Api,
                    Category::Build,
                    "build.registration_rejected",
                    actor,
                    Outcome::Denied,
                    json!({
                        "device_id": trimmed_id,
                        "installer_id": inst_id,
                        "role": role,
                        "reason": reason_str,
                        "revoked_at": revoked_at,
                        "rejection_type": "role_revoked"
                    }),
                )
                .with_subject(subject);

                let _ = state.audit.append(audit_event).await;

                return Err(DeviceError::InstallerRevoked(format!(
                    "El rol '{}' del instalador '{}' ha sido revocado en {}: {}",
                    role, inst_id, revoked_at, reason_str
                )));
            }
            Ok(RevocationStatus::InstallerExpired {
                role, expires_at, ..
            }) => {
                let trace_id = extract_trace_id(&headers);
                let actor = Actor::with_details(
                    &trimmed_id,
                    "device",
                    provided_name.clone(),
                    Some(client_ip.clone()),
                );
                let subject = Subject::with_details(inst_id, "installer", Some(role.clone()));

                let audit_event = EventInput::new(
                    trace_id,
                    Source::Api,
                    Category::Build,
                    "build.registration_rejected",
                    actor,
                    Outcome::Denied,
                    json!({
                        "device_id": trimmed_id,
                        "installer_id": inst_id,
                        "role": role,
                        "expires_at": expires_at,
                        "rejection_type": "installer_expired"
                    }),
                )
                .with_subject(subject);

                let _ = state.audit.append(audit_event).await;

                return Err(DeviceError::InstallerExpired(format!(
                    "El instalador '{}' ha caducado en {}",
                    inst_id, expires_at
                )));
            }
            Err(e) => {
                let trace_id = extract_trace_id(&headers);
                let actor = Actor::with_details(
                    &trimmed_id,
                    "device",
                    provided_name.clone(),
                    Some(client_ip.clone()),
                );
                let subject = Subject::with_details(inst_id, "installer", None);

                let audit_event = EventInput::new(
                    trace_id,
                    Source::Api,
                    Category::Build,
                    "build.registration_rejected",
                    actor,
                    Outcome::Denied,
                    json!({
                        "device_id": trimmed_id,
                        "installer_id": inst_id,
                        "error": e,
                        "rejection_type": "revocation_check_failed"
                    }),
                )
                .with_subject(subject);

                let _ = state.audit.append(audit_event).await;

                return Err(DeviceError::Forbidden(format!(
                    "revocation_check_failed: {}",
                    e
                )));
            }
            Ok(RevocationStatus::Valid { .. }) | Ok(RevocationStatus::NotFound) => {
                // Instalador válido o no registrado en API (e.g. standalone/legacy)
            }
        }
    }

    // Check if device is registering for the first time
    let is_new_device = sqlx::query("SELECT 1 FROM devices WHERE id = ?")
        .bind(&trimmed_id)
        .fetch_optional(&state.db)
        .await?
        .is_none();

    // H7: On INSERT, use provided name or fallback to hostname or ID.
    // On UPDATE (conflict), preserve devices.name if provided_name is NULL or empty.
    sqlx::query(
        r#"
        INSERT INTO devices (id, name, hostname, os, version, ip_address, status, last_seen_at, installer_id, profile_id, role)
        VALUES (?1, COALESCE(?2, ?3, ?1), ?3, ?4, ?5, ?6, 'online', datetime('now'), ?7, ?8, ?9)
        ON CONFLICT(id) DO UPDATE SET
            name = CASE WHEN ?2 IS NOT NULL AND ?2 != '' THEN ?2 ELSE devices.name END,
            hostname = COALESCE(?3, devices.hostname),
            os = COALESCE(?4, devices.os),
            version = COALESCE(?5, devices.version),
            ip_address = ?6,
            status = 'online',
            last_seen_at = datetime('now'),
            installer_id = COALESCE(devices.installer_id, ?7),
            profile_id = COALESCE(devices.profile_id, ?8),
            role = devices.role;
        "#,
    )
    .bind(&trimmed_id)
    .bind(&provided_name)
    .bind(&resolved_hostname)
    .bind(&resolved_os)
    .bind(&resolved_version)
    .bind(&client_ip)
    .bind(&resolved_installer_id)
    .bind(&resolved_profile_id)
    .bind(&assigned_role)
    .execute(&state.db)
    .await?;

    let row = sqlx::query(
        r#"
        SELECT id, name, hostname, os, version, ip_address, status, last_seen_at, created_at, installer_id, profile_id, role
        FROM devices
        WHERE id = ?
        "#,
    )
    .bind(&trimmed_id)
    .fetch_one(&state.db)
    .await?;

    let device = DeviceResponse {
        id: row.get("id"),
        name: row.get("name"),
        hostname: row.get("hostname"),
        os: row.get("os"),
        version: row.get("version"),
        ip_address: row.get("ip_address"),
        status: row.get("status"),
        last_seen_at: row.get("last_seen_at"),
        created_at: row.get("created_at"),
        installer_id: row.get("installer_id"),
        profile_id: row.get("profile_id"),
        role: row.get("role"),
    };

    if is_new_device {
        let trace_id = extract_trace_id(&headers);
        let dev_name = device.name.clone();

        let audit_input = EventInput::new(
            trace_id,
            Source::Console,
            Category::Console,
            "console.device_register",
            Actor::with_details(
                &trimmed_id,
                "device",
                Some(dev_name.clone()),
                Some(client_ip.clone()),
            ),
            Outcome::Success,
            json!({
                "device_id": trimmed_id,
                "name": dev_name,
                "hostname": resolved_hostname,
                "os": resolved_os,
                "version": resolved_version,
                "client_ip": client_ip,
                "role": device.role,
                "installer_id": device.installer_id,
            }),
        )
        .with_subject(Subject::with_details(&trimmed_id, "device", Some(dev_name)));

        state.audit.append(audit_input).await?;
    }

    Ok((StatusCode::OK, Json(device)))
}

/// Lists all registered devices with their calculated status (`online` or `offline`)
/// according to the configured grace period.
///
/// Protected by Bearer token authentication.
pub async fn list_devices_handler(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<DeviceResponse>>, DeviceError> {
    let grace_secs = state.config.device_grace_period_secs as i64;

    let query_sql = format!(
        r#"
        SELECT
            id,
            name,
            hostname,
            os,
            version,
            ip_address,
            {} AS status,
            last_seen_at,
            created_at,
            installer_id,
            profile_id,
            role
        FROM devices
        ORDER BY created_at DESC
        "#,
        DEVICE_STATUS_EXPR
    );

    let rows = sqlx::query(&query_sql)
        .bind(grace_secs)
        .fetch_all(&state.db)
        .await?;

    let devices = rows
        .into_iter()
        .map(|row| DeviceResponse {
            id: row.get("id"),
            name: row.get("name"),
            hostname: row.get("hostname"),
            os: row.get("os"),
            version: row.get("version"),
            ip_address: row.get("ip_address"),
            status: row.get("status"),
            last_seen_at: row.get("last_seen_at"),
            created_at: row.get("created_at"),
            installer_id: row.get("installer_id"),
            profile_id: row.get("profile_id"),
            role: row.get("role"),
        })
        .collect();

    Ok(Json(devices))
}

/// Retrieves details for a specific device with calculated status.
///
/// Protected by Bearer token authentication.
pub async fn get_device_handler(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<DeviceResponse>, DeviceError> {
    let grace_secs = state.config.device_grace_period_secs as i64;

    let query_sql = format!(
        r#"
        SELECT
            id,
            name,
            hostname,
            os,
            version,
            ip_address,
            {} AS status,
            last_seen_at,
            created_at,
            installer_id,
            profile_id,
            role
        FROM devices
        WHERE id = ?
        "#,
        DEVICE_STATUS_EXPR
    );

    let row = sqlx::query(&query_sql)
        .bind(grace_secs)
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;

    match row {
        Some(row) => Ok(Json(DeviceResponse {
            id: row.get("id"),
            name: row.get("name"),
            hostname: row.get("hostname"),
            os: row.get("os"),
            version: row.get("version"),
            ip_address: row.get("ip_address"),
            status: row.get("status"),
            last_seen_at: row.get("last_seen_at"),
            created_at: row.get("created_at"),
            installer_id: row.get("installer_id"),
            profile_id: row.get("profile_id"),
            role: row.get("role"),
        })),
        None => Err(DeviceError::NotFound(format!(
            "Dispositivo con ID '{}' no encontrado",
            id
        ))),
    }
}

/// Deletes a registered device. Requires `admin` role.
///
/// Protected by Bearer token authentication.
pub async fn delete_device_handler(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<DeleteDeviceResponse>, DeviceError> {
    if user.role != "admin" {
        return Err(DeviceError::Forbidden(
            "Se requieren permisos de administrador para eliminar dispositivos.".to_string(),
        ));
    }

    let existing_device = sqlx::query("SELECT id, name FROM devices WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;

    let existing = match existing_device {
        Some(row) => row,
        None => {
            return Err(DeviceError::NotFound(format!(
                "Dispositivo con ID '{}' no encontrado",
                id
            )));
        }
    };

    let device_name: String = existing.get("name");

    let result = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(DeviceError::NotFound(format!(
            "Dispositivo con ID '{}' no encontrado",
            id
        )));
    }

    let client_ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0),
        &state.config.trusted_proxies,
    );
    let trace_id = extract_trace_id(&headers);

    let audit_input = EventInput::new(
        trace_id,
        Source::Console,
        Category::Console,
        "console.device_delete",
        Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip.clone()),
        ),
        Outcome::Success,
        json!({
            "device_id": id,
            "device_name": device_name,
            "client_ip": client_ip,
        }),
    )
    .with_subject(Subject::with_details(&id, "device", Some(device_name)));

    state.audit.append(audit_input).await?;

    Ok(Json(DeleteDeviceResponse {
        status: "ok",
        message: "Dispositivo eliminado correctamente".to_string(),
        id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_heartbeat_input_valid() {
        let req = HeartbeatRequest {
            id: "device-123".to_string(),
            name: Some("Mi Laptop".to_string()),
            hostname: Some("laptop-lan".to_string()),
            os: Some("Windows 11".to_string()),
            version: Some("0.1.0".to_string()),
            ip: Some("192.168.1.50".to_string()),
            installer_id: None,
            profile_id: None,
            role: None,
        };
        assert!(validate_heartbeat_input(&req).is_ok());
    }

    #[test]
    fn test_validate_heartbeat_input_empty_id() {
        let req = HeartbeatRequest {
            id: "   ".to_string(),
            name: None,
            hostname: None,
            os: None,
            version: None,
            ip: None,
            installer_id: None,
            profile_id: None,
            role: None,
        };
        assert!(validate_heartbeat_input(&req).is_err());
    }

    #[test]
    fn test_validate_heartbeat_input_too_long_id() {
        let req = HeartbeatRequest {
            id: "a".repeat(129),
            name: None,
            hostname: None,
            os: None,
            version: None,
            ip: None,
            installer_id: None,
            profile_id: None,
            role: None,
        };
        assert!(validate_heartbeat_input(&req).is_err());
    }

    #[test]
    fn test_validate_heartbeat_input_field_length_limits() {
        let mut req = HeartbeatRequest {
            id: "valid-id".to_string(),
            name: Some("n".repeat(129)),
            hostname: None,
            os: None,
            version: None,
            ip: None,
            installer_id: None,
            profile_id: None,
            role: None,
        };
        assert!(validate_heartbeat_input(&req).is_err());

        req.name = Some("valid-name".to_string());
        req.hostname = Some("h".repeat(129));
        assert!(validate_heartbeat_input(&req).is_err());

        req.hostname = Some("valid-host".to_string());
        req.os = Some("o".repeat(129));
        assert!(validate_heartbeat_input(&req).is_err());

        req.os = Some("Linux".to_string());
        req.version = Some("v".repeat(65));
        assert!(validate_heartbeat_input(&req).is_err());

        req.version = Some("1.0.0".to_string());
        req.ip = Some("i".repeat(65));
        assert!(validate_heartbeat_input(&req).is_err());

        req.ip = Some("192.168.1.1".to_string());
        assert!(validate_heartbeat_input(&req).is_ok());
    }
}
