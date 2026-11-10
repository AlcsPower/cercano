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

//! F4-03: users, roles and general settings API with fixed-role RBAC.

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::{extract_trace_id, hash_password, AuthenticatedUser};
use crate::permissions;
use crate::AppState;

const SETTING_ORGANIZATION: &str = "console.organization_name";
const SETTING_SUPPORT_EMAIL: &str = "console.support_email";

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Audit error: {0}")]
    Audit(#[from] audit_core::AuditError),
    #[error("Password hashing error: {0}")]
    Hash(String),
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            Self::Db(err) => {
                tracing::error!("Admin DB error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Error interno.".to_string(),
                )
            }
            Self::Validation(message) => {
                (StatusCode::BAD_REQUEST, "validation_error", message.clone())
            }
            Self::Unauthorized(message) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", message.clone())
            }
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message.clone()),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, "not_found", message.clone()),
            Self::Conflict(message) => (StatusCode::CONFLICT, "conflict", message.clone()),
            Self::Audit(err) => {
                tracing::error!("Admin audit error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_error",
                    "Error interno de auditoría.".to_string(),
                )
            }
            Self::Hash(err) => {
                tracing::error!("Admin password hash error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "hash_error",
                    "Error interno.".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub role: String,
    pub is_active: bool,
    pub totp_enabled: bool,
    pub is_2fa_required: bool,
    pub created_at: String,
}

impl UserView {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Self {
        Self {
            id: row.get("id"),
            username: row.get("username"),
            role: row.get("role"),
            is_active: row.get::<i64, _>("is_active") != 0,
            totp_enabled: row.get::<i64, _>("totp_enabled") != 0,
            is_2fa_required: row.get::<i64, _>("is_2fa_required") != 0,
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub password: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    pub organization_name: String,
    pub support_email: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub organization_name: Option<String>,
    pub support_email: Option<String>,
}

fn require_admin(user: &AuthenticatedUser) -> Result<(), AdminError> {
    if permissions::is_admin(&user.role) {
        Ok(())
    } else {
        Err(AdminError::Forbidden(
            "Se requiere rol administrador.".to_string(),
        ))
    }
}

fn require_permission(user: &AuthenticatedUser, permission: &str) -> Result<(), AdminError> {
    if permissions::has_permission(&user.role, permission) {
        Ok(())
    } else {
        Err(AdminError::Forbidden(format!(
            "Falta el permiso {permission}."
        )))
    }
}

fn validate_username(raw: &str) -> Result<String, AdminError> {
    let value = raw.trim();
    if value.len() < 3 || value.len() > 64 {
        return Err(AdminError::Validation(
            "El usuario debe tener entre 3 y 64 caracteres.".to_string(),
        ));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(AdminError::Validation(
            "El usuario no puede contener espacios.".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn validate_password(raw: &str) -> Result<(), AdminError> {
    if raw.len() < 8 || raw.len() > 128 {
        return Err(AdminError::Validation(
            "La contraseña debe tener entre 8 y 128 caracteres.".to_string(),
        ));
    }
    Ok(())
}

fn validate_role(raw: &str) -> Result<String, AdminError> {
    let value = raw.trim();
    if !permissions::valid_assignable_role(value) {
        return Err(AdminError::Validation(
            "Rol no válido. Use admin, operator o auditor.".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn map_constraint_error(err: sqlx::Error, conflict_message: &str) -> AdminError {
    if let sqlx::Error::Database(ref db) = err {
        if db.is_unique_violation() || db.is_foreign_key_violation() {
            return AdminError::Conflict(conflict_message.to_string());
        }
    }
    AdminError::Db(err)
}

async fn fetch_user(pool: &SqlitePool, id: &str) -> Result<UserView, AdminError> {
    let row = sqlx::query(
        "SELECT id, username, role, is_active, totp_enabled, is_2fa_required, created_at FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AdminError::NotFound("Usuario no encontrado.".to_string()))?;
    Ok(UserView::from_row(&row))
}

async fn active_admin_count(pool: &SqlitePool) -> Result<i64, AdminError> {
    let row =
        sqlx::query("SELECT count(*) as cnt FROM users WHERE role = 'admin' AND is_active = 1")
            .fetch_one(pool)
            .await?;
    Ok(row.get::<i64, _>("cnt"))
}

async fn append_user_audit(
    state: &AppState,
    headers: &HeaderMap,
    action: &str,
    actor: &AuthenticatedUser,
    subject_id: &str,
    details: Value,
) -> Result<(), AdminError> {
    let event = EventInput::new(
        extract_trace_id(headers),
        Source::Console,
        Category::Console,
        action,
        Actor::with_details(&actor.id, "user", Some(actor.username.clone()), None),
        Outcome::Success,
        details,
    )
    .with_subject(Subject::with_details(subject_id, "user", None));
    state.audit.append(event).await?;
    Ok(())
}

pub async fn list_users_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<UserView>>, AdminError> {
    require_permission(&user, permissions::USERS_READ)?;
    let rows = if permissions::is_admin(&user.role) {
        sqlx::query("SELECT id, username, role, is_active, totp_enabled, is_2fa_required, created_at FROM users ORDER BY username")
            .fetch_all(&state.db)
            .await?
    } else {
        sqlx::query("SELECT id, username, role, is_active, totp_enabled, is_2fa_required, created_at FROM users WHERE id = ?")
            .bind(&user.id)
            .fetch_all(&state.db)
            .await?
    };
    Ok(Json(rows.iter().map(UserView::from_row).collect()))
}

pub async fn get_user_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<UserView>, AdminError> {
    require_permission(&user, permissions::USERS_READ)?;
    if !permissions::is_admin(&user.role) && user.id != id {
        return Err(AdminError::Forbidden(
            "Solo puede consultar su propio usuario.".to_string(),
        ));
    }
    Ok(Json(fetch_user(&state.db, &id).await?))
}

pub async fn create_user_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(payload): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserView>), AdminError> {
    require_admin(&user)?;
    let username = validate_username(&payload.username)?;
    validate_password(&payload.password)?;
    let role = validate_role(&payload.role)?;
    let password_hash =
        hash_password(&payload.password).map_err(|e| AdminError::Hash(e.to_string()))?;
    let id = Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, ?, ?, ?, 1)",
    )
    .bind(&id)
    .bind(&username)
    .bind(&password_hash)
    .bind(&role)
    .execute(&state.db)
    .await
    .map_err(|e| map_constraint_error(e, "El nombre de usuario ya existe."))?;
    append_user_audit(
        &state,
        &headers,
        "console.user_create",
        &user,
        &id,
        json!({ "username": username, "role": role }),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(fetch_user(&state.db, &id).await?)))
}

pub async fn update_user_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserView>, AdminError> {
    require_permission(&user, permissions::USERS_READ)?;
    let is_admin = permissions::is_admin(&user.role);
    if !is_admin && user.id != id {
        return Err(AdminError::Forbidden(
            "Solo puede modificar su propio usuario.".to_string(),
        ));
    }
    if !is_admin && (payload.role.is_some() || payload.is_active.is_some()) {
        return Err(AdminError::Forbidden(
            "Solo un administrador puede cambiar rol o estado.".to_string(),
        ));
    }
    let current = fetch_user(&state.db, &id).await?;
    let mut changed_fields: Vec<&str> = Vec::new();

    if let Some(role) = payload.role.as_deref() {
        let role = validate_role(role)?;
        if current.role == permissions::ADMIN && role != permissions::ADMIN {
            if active_admin_count(&state.db).await? <= 1 {
                return Err(AdminError::Conflict(
                    "No se puede degradar al último administrador.".to_string(),
                ));
            }
        }
        if role != current.role {
            sqlx::query("UPDATE users SET role = ? WHERE id = ?")
                .bind(&role)
                .bind(&id)
                .execute(&state.db)
                .await?;
            changed_fields.push("role");
        }
    }

    if let Some(is_active) = payload.is_active {
        if current.role == permissions::ADMIN && !is_active {
            if active_admin_count(&state.db).await? <= 1 {
                return Err(AdminError::Conflict(
                    "No se puede desactivar al último administrador.".to_string(),
                ));
            }
        }
        if is_active != current.is_active {
            sqlx::query("UPDATE users SET is_active = ? WHERE id = ?")
                .bind(if is_active { 1 } else { 0 })
                .bind(&id)
                .execute(&state.db)
                .await?;
            if !is_active {
                sqlx::query("UPDATE sessions SET revoked_at = datetime('now') WHERE user_id = ? AND revoked_at IS NULL")
                    .bind(&id)
                    .execute(&state.db)
                    .await?;
            }
            changed_fields.push("is_active");
        }
    }

    if let Some(password) = payload.password.as_deref() {
        validate_password(password)?;
        let password_hash = hash_password(password).map_err(|e| AdminError::Hash(e.to_string()))?;
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(&password_hash)
            .bind(&id)
            .execute(&state.db)
            .await?;
        sqlx::query("UPDATE sessions SET revoked_at = datetime('now') WHERE user_id = ? AND revoked_at IS NULL")
            .bind(&id)
            .execute(&state.db)
            .await?;
        changed_fields.push("password");
    }

    append_user_audit(
        &state,
        &headers,
        "console.user_update",
        &user,
        &id,
        json!({ "fields": changed_fields }),
    )
    .await?;
    Ok(Json(fetch_user(&state.db, &id).await?))
}

pub async fn delete_user_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    require_admin(&user)?;
    if user.id == id {
        return Err(AdminError::Conflict(
            "No puede eliminar su propio usuario.".to_string(),
        ));
    }
    let target = fetch_user(&state.db, &id).await?;
    if target.role == permissions::ADMIN && active_admin_count(&state.db).await? <= 1 {
        return Err(AdminError::Conflict(
            "No se puede eliminar al último administrador.".to_string(),
        ));
    }
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| map_constraint_error(e, "El usuario tiene dependencias (build jobs u otras). Desactívelo en lugar de eliminarlo."))?;
    append_user_audit(
        &state,
        &headers,
        "console.user_delete",
        &user,
        &id,
        json!({ "username": target.username, "role": target.role }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_roles_handler(
    State(_state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, AdminError> {
    require_admin(&user)?;
    let roles = [
        ("admin", vec!["*"]),
        (
            "operator",
            permissions::role_permissions(permissions::OPERATOR).to_vec(),
        ),
        (
            "auditor",
            permissions::role_permissions(permissions::AUDITOR).to_vec(),
        ),
        (
            "user",
            permissions::role_permissions(permissions::LEGACY_USER).to_vec(),
        ),
    ];
    let payload: Vec<Value> = roles
        .into_iter()
        .map(|(role, perms)| json!({ "role": role, "permissions": perms }))
        .collect();
    Ok(Json(json!({ "roles": payload })))
}

async fn load_settings(pool: &SqlitePool) -> Result<SettingsResponse, AdminError> {
    let rows = sqlx::query("SELECT key, value FROM system_info WHERE key IN (?, ?)")
        .bind(SETTING_ORGANIZATION)
        .bind(SETTING_SUPPORT_EMAIL)
        .fetch_all(pool)
        .await?;
    let mut organization_name = String::new();
    let mut support_email = String::new();
    for row in rows {
        let key: String = row.get("key");
        let value: String = row.get("value");
        if key == SETTING_ORGANIZATION {
            organization_name = value;
        } else if key == SETTING_SUPPORT_EMAIL {
            support_email = value;
        }
    }
    Ok(SettingsResponse {
        organization_name,
        support_email,
    })
}

pub async fn get_settings_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<SettingsResponse>, AdminError> {
    require_permission(&user, permissions::SETTINGS_READ)?;
    Ok(Json(load_settings(&state.db).await?))
}

pub async fn update_settings_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(payload): Json<UpdateSettingsRequest>,
) -> Result<Json<SettingsResponse>, AdminError> {
    require_permission(&user, permissions::SETTINGS_MANAGE)?;
    if let Some(value) = payload.organization_name.as_deref() {
        let value = value.trim();
        if value.len() > 128 {
            return Err(AdminError::Validation(
                "La organización no puede exceder 128 caracteres.".to_string(),
            ));
        }
        upsert_setting(&state.db, SETTING_ORGANIZATION, value).await?;
    }
    if let Some(value) = payload.support_email.as_deref() {
        let value = value.trim();
        if value.len() > 254 || (!value.is_empty() && !value.contains('@')) {
            return Err(AdminError::Validation(
                "Correo de soporte no válido.".to_string(),
            ));
        }
        upsert_setting(&state.db, SETTING_SUPPORT_EMAIL, value).await?;
    }
    let settings = load_settings(&state.db).await?;
    let event = EventInput::new(
        extract_trace_id(&headers),
        Source::Console,
        Category::Console,
        "console.settings_update",
        Actor::with_details(&user.id, "user", Some(user.username.clone()), None),
        Outcome::Success,
        json!({ "fields": ["organization_name", "support_email"] }),
    )
    .with_subject(Subject::with_details("settings", "setting", None));
    state.audit.append(event).await?;
    Ok(Json(settings))
}

async fn upsert_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<(), AdminError> {
    sqlx::query(
        "INSERT INTO system_info (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}
