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

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use audit_core::{
    Actor, AuditError, AuditEvent, Category, EventFilter, EventInput, Outcome, Source, Subject,
};

use crate::auth::AuthenticatedUser;
use crate::AppState;

/// Error type for alarm route handlers.
#[derive(Debug, thiserror::Error)]
pub enum AlarmRouteError {
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
    #[error("Not found: {0}")]
    NotFound(String),
}

impl IntoResponse for AlarmRouteError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AlarmRouteError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, "validation_error", msg.clone())
            }
            AlarmRouteError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone())
            }
            AlarmRouteError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            AlarmRouteError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            AlarmRouteError::Db(err) => {
                tracing::error!("Database error in alarm route: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Error interno en la base de datos".to_string(),
                )
            }
            AlarmRouteError::Audit(err) => {
                tracing::error!("Audit error in alarm route: {:?}", err);
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

/// Enforces that the caller has administrative privileges.
pub fn require_admin(user: &AuthenticatedUser) -> Result<(), AlarmRouteError> {
    if user.role != "admin" {
        return Err(AlarmRouteError::Forbidden(
            "Acceso restringido exclusivamente a administradores".to_string(),
        ));
    }
    Ok(())
}

/// Query parameters for filtering recorded alarms.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ListAlarmsParams {
    pub severity: Option<String>,
    pub action: Option<String>,
    pub from_ts: Option<String>,
    pub to_ts: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Optional payload for acknowledging an alarm.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AcknowledgeAlarmRequest {
    #[serde(default)]
    pub note: Option<String>,
}

/// `GET /api/audit/alarms`
///
/// Queries recorded alarms with optional filtering by severity, action, or date range.
/// Protected by admin session token.
pub async fn list_alarms_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(params): Query<ListAlarmsParams>,
) -> Result<Json<Vec<AuditEvent>>, AlarmRouteError> {
    require_admin(&user)?;

    let filter = EventFilter {
        category: Some(Category::Alarm),
        action: params.action,
        from_ts: params.from_ts,
        to_ts: params.to_ts,
        limit: params.limit.or(Some(50)),
        offset: params.offset,
        trace_id: None,
        actor_id: None,
        subject_id: None,
        outcome: None,
        from_seq: None,
        to_seq: None,
        after_sequence: None,
    };

    let mut events = state.audit.query_events(filter).await?;

    if let Some(ref severity) = params.severity {
        events.retain(|event| {
            event
                .details
                .get("severity")
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case(severity))
                .unwrap_or(false)
        });
    }

    Ok(Json(events))
}

/// `POST /api/audit/alarms/:id/acknowledge`
///
/// Allows an administrator to acknowledge a recorded alarm.
/// Appends a `console.alarm_ack` event directly to `AuditStore`.
pub async fn acknowledge_alarm_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(alarm_id): Path<String>,
    payload: Option<Json<AcknowledgeAlarmRequest>>,
) -> Result<(StatusCode, Json<AuditEvent>), AlarmRouteError> {
    require_admin(&user)?;

    // 1. Retrieve the existing alarm
    let alarm = state
        .audit
        .get_event_by_id(&alarm_id)
        .await?
        .ok_or_else(|| {
            AlarmRouteError::NotFound(format!("Alarma con ID '{}' no encontrada", alarm_id))
        })?;

    // 2. Validate that the event is actually an alarm
    if alarm.category != Category::Alarm && !alarm.action.starts_with("alarm.") {
        return Err(AlarmRouteError::Validation(
            "El evento especificado no corresponde a una alarma".to_string(),
        ));
    }

    // 3. Prepare details for the acknowledgment event
    let note = payload
        .as_ref()
        .and_then(|p| p.note.clone())
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());

    let mut details_map = serde_json::Map::new();
    details_map.insert("alarm_id".to_string(), json!(alarm.event_id));
    details_map.insert("alarm_action".to_string(), json!(alarm.action));
    details_map.insert("acknowledged_by".to_string(), json!(user.username));
    details_map.insert(
        "acknowledged_at".to_string(),
        json!(chrono::Utc::now().to_rfc3339()),
    );
    if let Some(n) = note {
        details_map.insert("note".to_string(), json!(n));
    }

    let actor = Actor::with_details(&user.id, "admin", Some(user.username.clone()), None);
    let subject =
        Subject::with_details(alarm.event_id.clone(), "alarm", Some(alarm.action.clone()));

    let ack_input = EventInput::new(
        alarm.trace_id.clone(),
        Source::Console,
        Category::Console,
        "console.alarm_ack",
        actor,
        Outcome::Success,
        serde_json::Value::Object(details_map),
    )
    .with_subject(subject);

    // 4. Append to append-only AuditStore
    let ack_event = state.audit.append(ack_input).await?;

    Ok((StatusCode::OK, Json(ack_event)))
}
