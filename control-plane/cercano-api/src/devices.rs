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

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use thiserror::Error;

use crate::auth::{extract_client_ip, AuthenticatedUser};
use crate::AppState;

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
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl IntoResponse for DeviceError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            DeviceError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, "validation_error", msg.clone())
            }
            DeviceError::NotFound(msg) => (StatusCode::NOT_FOUND, "device_not_found", msg.clone()),
            DeviceError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            DeviceError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone())
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

#[derive(Debug, Deserialize, Serialize, Clone)]
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
    Ok(())
}

/// Registers or updates a device heartbeat.
///
/// Records/updates device metadata (`id`, `name`/`hostname`, `os`, `version`, IP),
/// updates `last_seen_at` to the current timestamp and marks status as `online`.
pub async fn heartbeat_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<(StatusCode, Json<DeviceResponse>), DeviceError> {
    validate_heartbeat_input(&payload)?;

    let trimmed_id = payload.id.trim().to_string();

    let resolved_name = payload
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            payload
                .hostname
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or(&trimmed_id)
        .to_string();

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

    let resolved_ip = payload
        .ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| extract_client_ip(&headers));

    sqlx::query(
        r#"
        INSERT INTO devices (id, name, hostname, os, version, ip_address, status, last_seen_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'online', datetime('now'))
        ON CONFLICT(id) DO UPDATE SET
            name = CASE WHEN ?2 IS NOT NULL AND ?2 != '' THEN ?2 ELSE devices.name END,
            hostname = COALESCE(?3, devices.hostname),
            os = COALESCE(?4, devices.os),
            version = COALESCE(?5, devices.version),
            ip_address = COALESCE(?6, devices.ip_address),
            status = 'online',
            last_seen_at = datetime('now');
        "#,
    )
    .bind(&trimmed_id)
    .bind(&resolved_name)
    .bind(&resolved_hostname)
    .bind(&resolved_os)
    .bind(&resolved_version)
    .bind(&resolved_ip)
    .execute(&state.db)
    .await?;

    let row = sqlx::query(
        r#"
        SELECT id, name, hostname, os, version, ip_address, status, last_seen_at, created_at
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
    };

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

    let rows = sqlx::query(
        r#"
        SELECT
            id,
            name,
            hostname,
            os,
            version,
            ip_address,
            CASE
                WHEN last_seen_at IS NOT NULL AND (strftime('%s', 'now') - strftime('%s', last_seen_at)) <= ? THEN 'online'
                ELSE 'offline'
            END AS status,
            last_seen_at,
            created_at
        FROM devices
        ORDER BY created_at DESC
        "#,
    )
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

    let row = sqlx::query(
        r#"
        SELECT
            id,
            name,
            hostname,
            os,
            version,
            ip_address,
            CASE
                WHEN last_seen_at IS NOT NULL AND (strftime('%s', 'now') - strftime('%s', last_seen_at)) <= ? THEN 'online'
                ELSE 'offline'
            END AS status,
            last_seen_at,
            created_at
        FROM devices
        WHERE id = ?
        "#,
    )
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
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<DeleteDeviceResponse>, DeviceError> {
    if user.role != "admin" {
        return Err(DeviceError::Forbidden(
            "Se requieren permisos de administrador para eliminar dispositivos.".to_string(),
        ));
    }

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
        };
        assert!(validate_heartbeat_input(&req).is_err());
    }
}
