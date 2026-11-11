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

//! Chat branding endpoints (F4.5-16).
//!
//! Provides public read-access to support branding configuration and
//! administrative update with role and permission validation (`chat:manage_branding`).

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::chat::{
    validate_optional_text, ChatBranding, DEFAULT_ACCENT_COLOR, DEFAULT_SUPPORT_NAME,
    MAX_BRANDING_TEXT_LEN, MAX_CONTACT_NAME_LEN, MAX_OPTIONAL_TEXT_LEN,
};
use crate::permissions;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct UpdateBrandingRequest {
    pub organization_name: Option<String>,
    pub support_name: String,
    pub logo_url: Option<String>,
    pub accent_color: String,
    pub welcome_text: Option<String>,
    pub info_text: Option<String>,
    pub privacy_text: Option<String>,
}

#[derive(Debug)]
pub enum BrandingError {
    BadRequest(String),
    Forbidden(String),
    Internal(String),
}

impl IntoResponse for BrandingError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "validation_error", "message": msg })),
            )
                .into_response(),
            Self::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "forbidden", "message": msg })),
            )
                .into_response(),
            Self::Internal(msg) => {
                tracing::error!("Branding error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal_error", "message": "Error interno del servidor." })),
                )
                    .into_response()
            }
        }
    }
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

fn validate_hex_color(color: &str) -> Result<String, String> {
    let trimmed = color.trim();
    if trimmed.len() != 7 || !trimmed.starts_with('#') {
        return Err("El color de acento debe tener formato hexadecimal #RRGGBB.".to_string());
    }
    if !trimmed[1..].chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("El color de acento contiene caracteres hexadecimales inválidos.".to_string());
    }
    Ok(trimmed.to_ascii_uppercase())
}

fn validate_logo_url(url: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = url.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if !raw.starts_with("https://") {
        return Err("La URL del logo debe comenzar con https://.".to_string());
    }
    if raw.len() > 512 {
        return Err("La URL del logo no puede exceder 512 caracteres.".to_string());
    }
    Ok(Some(raw.to_string()))
}

pub async fn get_branding_handler(
    State(state): State<AppState>,
) -> Result<Response, BrandingError> {
    let row = sqlx::query("SELECT * FROM chat_branding WHERE id = 1")
        .fetch_optional(&state.db)
        .await
        .map_err(|e| BrandingError::Internal(e.to_string()))?;

    let branding = if let Some(r) = row {
        ChatBranding::from_row(&r).map_err(|e| BrandingError::Internal(e.to_string()))?
    } else {
        ChatBranding {
            id: 1,
            organization_name: None,
            support_name: DEFAULT_SUPPORT_NAME.to_string(),
            logo_url: None,
            accent_color: DEFAULT_ACCENT_COLOR.to_string(),
            welcome_text: None,
            info_text: None,
            privacy_text: None,
            updated_at: Utc::now().to_rfc3339(),
            updated_by: None,
        }
    };

    Ok((StatusCode::OK, Json(branding)).into_response())
}

pub async fn update_branding_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(payload): Json<UpdateBrandingRequest>,
) -> Result<Response, BrandingError> {
    // Permission check: chat:manage_branding (or admin)
    let has_perm = permissions::user_has_permission(
        &state.db,
        &user.id,
        &user.role,
        permissions::CHAT_MANAGE_BRANDING,
    )
    .await;

    if !has_perm && user.role != "admin" {
        return Err(BrandingError::Forbidden(
            "Se requiere permiso chat:manage_branding para modificar la marca del chat."
                .to_string(),
        ));
    }

    let support_name = payload.support_name.trim();
    if support_name.is_empty() {
        return Err(BrandingError::BadRequest(
            "support_name es obligatorio.".to_string(),
        ));
    }
    if support_name.chars().count() > MAX_CONTACT_NAME_LEN {
        return Err(BrandingError::BadRequest(format!(
            "support_name no puede exceder {MAX_CONTACT_NAME_LEN} caracteres."
        )));
    }

    let organization_name = validate_optional_text(
        payload.organization_name.as_deref(),
        "organization_name",
        MAX_OPTIONAL_TEXT_LEN,
    )
    .map_err(BrandingError::BadRequest)?;

    let logo_url =
        validate_logo_url(payload.logo_url.as_deref()).map_err(BrandingError::BadRequest)?;
    let accent_color =
        validate_hex_color(&payload.accent_color).map_err(BrandingError::BadRequest)?;

    let welcome_text = validate_optional_text(
        payload.welcome_text.as_deref(),
        "welcome_text",
        MAX_BRANDING_TEXT_LEN,
    )
    .map_err(BrandingError::BadRequest)?;

    let info_text = validate_optional_text(
        payload.info_text.as_deref(),
        "info_text",
        MAX_BRANDING_TEXT_LEN,
    )
    .map_err(BrandingError::BadRequest)?;

    let privacy_text = validate_optional_text(
        payload.privacy_text.as_deref(),
        "privacy_text",
        MAX_BRANDING_TEXT_LEN,
    )
    .map_err(BrandingError::BadRequest)?;

    let now_str = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO chat_branding (
            id, organization_name, support_name, logo_url, accent_color,
            welcome_text, info_text, privacy_text, updated_at, updated_by
         ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            organization_name = excluded.organization_name,
            support_name = excluded.support_name,
            logo_url = excluded.logo_url,
            accent_color = excluded.accent_color,
            welcome_text = excluded.welcome_text,
            info_text = excluded.info_text,
            privacy_text = excluded.privacy_text,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by",
    )
    .bind(organization_name.as_deref())
    .bind(support_name)
    .bind(logo_url.as_deref())
    .bind(&accent_color)
    .bind(welcome_text.as_deref())
    .bind(info_text.as_deref())
    .bind(privacy_text.as_deref())
    .bind(&now_str)
    .bind(&user.id)
    .execute(&state.db)
    .await
    .map_err(|e| BrandingError::Internal(e.to_string()))?;

    // Audit branding update
    let trace_id = extract_trace_id(&headers);
    let actor = Actor::with_type(&user.id, "user");
    let subject = Subject::with_type("branding", "system");
    let audit_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Chat,
        "chat.branding.updated",
        actor,
        Outcome::Success,
        json!({
            "updated_by": &user.id,
            "fields": [
                "organization_name",
                "support_name",
                "logo_url",
                "accent_color",
                "welcome_text",
                "info_text",
                "privacy_text"
            ]
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    let updated = ChatBranding {
        id: 1,
        organization_name,
        support_name: support_name.to_string(),
        logo_url,
        accent_color,
        welcome_text,
        info_text,
        privacy_text,
        updated_at: now_str,
        updated_by: Some(user.id),
    };

    Ok((StatusCode::OK, Json(updated)).into_response())
}
