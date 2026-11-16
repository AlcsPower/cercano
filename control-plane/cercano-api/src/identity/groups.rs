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

//! Group and Group-Grant REST handlers for Phase 5 (F5-03, F5-04).
//!
//! Provides CRUD for user/device groups, group memberships, and group-to-group
//! grant relationships (`read`, `operate`) with RBAC, non-enumerative scoping, and audit logging.

use audit_core::{Actor, Category, EventInput, Outcome, Source};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::auth::{extract_client_ip, extract_trace_id, AuthenticatedUser};
use crate::identity::{
    is_group_in_scope, validate_group_name, Group, GroupGrant, GroupKind, GroupMember,
    GroupPermission, SubjectType,
};
use crate::permissions::{audit_scope_denied, check_permission, GROUPS_MANAGE, GROUPS_READ};
use crate::AppState;

macro_rules! db_or_500 {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };
}

const GROUPS_SCOPE_CLAUSE: &str = r#"
    (? = 'admin' OR ? = 'auditor' OR (
        EXISTS (
            SELECT 1 FROM group_members
            WHERE group_id = groups.id AND subject_type = 'user' AND subject_id = ?
        ) OR EXISTS (
            SELECT 1 FROM group_grants gg
            JOIN group_members gm_user ON gg.from_group_id = gm_user.group_id
            WHERE gg.to_group_id = groups.id
              AND gm_user.subject_type = 'user' AND gm_user.subject_id = ?
              AND gg.permission IN ('read', 'operate')
        )
    ))
"#;

#[derive(Debug, Deserialize)]
pub struct ListGroupsQuery {
    pub kind: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub kind: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    pub to_group_id: String,
    pub permission: String,
}

// ── Groups Handlers ──

pub async fn list_groups_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Query(params): Query<ListGroupsQuery>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);

    let (items, total) = if let Some(ref kind) = params.kind {
        let sql = format!(
            "SELECT id, kind, name, description, created_at, created_by, updated_at, updated_by
             FROM groups WHERE kind = ? AND ({}) ORDER BY name ASC LIMIT ? OFFSET ?",
            GROUPS_SCOPE_CLAUSE
        );

        let rows = db_or_500!(
            sqlx::query(&sql)
                .bind(kind)
                .bind(&user.role)
                .bind(&user.role)
                .bind(&user.id)
                .bind(&user.id)
                .bind(limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await
        );

        let items: Vec<Group> = rows
            .into_iter()
            .filter_map(|r| Group::from_row(&r).ok())
            .collect();

        let count_sql = format!(
            "SELECT count(*) FROM groups WHERE kind = ? AND ({})",
            GROUPS_SCOPE_CLAUSE
        );

        let total: i64 = db_or_500!(
            sqlx::query_scalar(&count_sql)
                .bind(kind)
                .bind(&user.role)
                .bind(&user.role)
                .bind(&user.id)
                .bind(&user.id)
                .fetch_one(&state.db)
                .await
        );

        (items, total)
    } else {
        let sql = format!(
            "SELECT id, kind, name, description, created_at, created_by, updated_at, updated_by
             FROM groups WHERE ({}) ORDER BY name ASC LIMIT ? OFFSET ?",
            GROUPS_SCOPE_CLAUSE
        );

        let rows = db_or_500!(
            sqlx::query(&sql)
                .bind(&user.role)
                .bind(&user.role)
                .bind(&user.id)
                .bind(&user.id)
                .bind(limit)
                .bind(offset)
                .fetch_all(&state.db)
                .await
        );

        let items: Vec<Group> = rows
            .into_iter()
            .filter_map(|r| Group::from_row(&r).ok())
            .collect();

        let count_sql = format!(
            "SELECT count(*) FROM groups WHERE ({})",
            GROUPS_SCOPE_CLAUSE
        );

        let total: i64 = db_or_500!(
            sqlx::query_scalar(&count_sql)
                .bind(&user.role)
                .bind(&user.role)
                .bind(&user.id)
                .bind(&user.id)
                .fetch_one(&state.db)
                .await
        );

        (items, total)
    };

    Json(json!({
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }))
    .into_response()
}

pub async fn create_group_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(payload): Json<CreateGroupRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let kind = match GroupKind::from_str_opt(&payload.kind) {
        Some(k) => k,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "bad_request",
                    "message": "Tipo de grupo inválido; debe ser 'user' o 'device'"
                })),
            )
                .into_response()
        }
    };

    if let Err(msg) = validate_group_name(&payload.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "bad_request", "message": msg })),
        )
            .into_response();
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let res = sqlx::query(
        "INSERT INTO groups (id, kind, name, description, created_at, created_by, updated_at, updated_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(kind.as_str())
    .bind(payload.name.trim())
    .bind(&payload.description)
    .bind(&now)
    .bind(&user.username)
    .bind(&now)
    .bind(&user.username)
    .execute(&state.db)
    .await;

    if let Err(e) = res {
        if let Some(db_err) = e.as_database_error() {
            if db_err.is_unique_violation() {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "conflict",
                        "message": "Ya existe un grupo con ese nombre para este tipo"
                    })),
                )
                    .into_response();
            }
        }
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.group.created",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "group_id": id,
                "kind": kind.as_str(),
                "name": payload.name.trim(),
            }),
        ))
        .await;

    (
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "kind": kind.as_str(),
            "name": payload.name.trim(),
            "description": payload.description,
            "created_at": now,
            "created_by": user.username,
            "updated_at": now,
            "updated_by": user.username,
        })),
    )
        .into_response()
}

pub async fn get_group_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let row = db_or_500!(
        sqlx::query(
            "SELECT id, kind, name, description, created_at, created_by, updated_at, updated_by
             FROM groups WHERE id = ?",
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
    );

    match row {
        Some(r) => match Group::from_row(&r) {
            Ok(group) => {
                if user.role != "admin" {
                    let in_scope = match is_group_in_scope(&state.db, &user, &id).await {
                        Ok(v) => v,
                        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    };
                    if !in_scope {
                        audit_scope_denied(
                            &state.audit,
                            &user,
                            "group",
                            &id,
                            &client_ip,
                            &trace_id,
                        )
                        .await;
                        return StatusCode::NOT_FOUND.into_response();
                    }
                }
                Json(group).into_response()
            }
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn update_group_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateGroupRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let current = db_or_500!(
        sqlx::query("SELECT id, kind, name, description FROM groups WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
    );

    let current = match current {
        Some(r) => r,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let new_name = match payload.name {
        Some(ref n) => {
            if let Err(msg) = validate_group_name(n) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "bad_request", "message": msg })),
                )
                    .into_response();
            }
            n.trim().to_string()
        }
        None => current.get::<String, _>("name"),
    };

    let new_desc = payload
        .description
        .or_else(|| current.get::<Option<String>, _>("description"));
    let now = Utc::now().to_rfc3339();

    let res = sqlx::query(
        "UPDATE groups SET name = ?, description = ?, updated_at = ?, updated_by = ? WHERE id = ?",
    )
    .bind(&new_name)
    .bind(&new_desc)
    .bind(&now)
    .bind(&user.username)
    .bind(&id)
    .execute(&state.db)
    .await;

    if let Err(e) = res {
        if let Some(db_err) = e.as_database_error() {
            if db_err.is_unique_violation() {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "conflict",
                        "message": "Ya existe un grupo con ese nombre para este tipo"
                    })),
                )
                    .into_response();
            }
        }
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.group.updated",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "group_id": id,
                "name": new_name,
            }),
        ))
        .await;

    Json(json!({
        "id": id,
        "name": new_name,
        "description": new_desc,
        "updated_at": now,
        "updated_by": user.username,
    }))
    .into_response()
}

pub async fn delete_group_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let res = db_or_500!(
        sqlx::query("DELETE FROM groups WHERE id = ?")
            .bind(&id)
            .execute(&state.db)
            .await
    );

    if res.rows_affected() == 0 {
        return StatusCode::NOT_FOUND.into_response();
    }

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.group.deleted",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({ "group_id": id }),
        ))
        .await;

    Json(json!({ "deleted": true })).into_response()
}

// ── Members Handlers ──

pub async fn list_group_members_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    if user.role != "admin" {
        let in_scope = match is_group_in_scope(&state.db, &user, &id).await {
            Ok(v) => v,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if !in_scope {
            let group_exists: bool = db_or_500!(
                sqlx::query_scalar("SELECT count(*) > 0 FROM groups WHERE id = ?")
                    .bind(&id)
                    .fetch_one(&state.db)
                    .await
            );
            if group_exists {
                audit_scope_denied(&state.audit, &user, "group", &id, &client_ip, &trace_id).await;
            }
            return StatusCode::NOT_FOUND.into_response();
        }
    }

    let rows = db_or_500!(
        sqlx::query(
            "SELECT group_id, subject_type, subject_id, added_at, added_by
             FROM group_members WHERE group_id = ? ORDER BY added_at ASC",
        )
        .bind(&id)
        .fetch_all(&state.db)
        .await
    );

    let items: Vec<GroupMember> = rows
        .into_iter()
        .filter_map(|r| GroupMember::from_row(&r).ok())
        .collect();

    Json(json!({ "items": items })).into_response()
}

pub async fn add_group_member_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path((id, subject_type, subject_id)): Path<(String, String, String)>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let st = match SubjectType::from_str_opt(&subject_type) {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "bad_request",
                    "message": "Tipo de miembro inválido; debe ser 'user' o 'device'"
                })),
            )
                .into_response()
        }
    };

    // Check group exists
    let group_exists = db_or_500!(
        sqlx::query("SELECT id, kind FROM groups WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
    );

    let group = match group_exists {
        Some(r) => r,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let group_kind: String = group.get("kind");
    if group_kind != st.as_str() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "bad_request",
                "message": format!("Un grupo de tipo '{group_kind}' solo puede contener miembros '{group_kind}'")
            })),
        )
            .into_response();
    }

    let now = Utc::now().to_rfc3339();
    let res = db_or_500!(
        sqlx::query(
            "INSERT OR IGNORE INTO group_members (group_id, subject_type, subject_id, added_at, added_by)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(st.as_str())
        .bind(&subject_id)
        .bind(&now)
        .bind(&user.username)
        .execute(&state.db)
        .await
    );

    if res.rows_affected() > 0 {
        let _ = state
            .audit
            .append(EventInput::new(
                trace_id,
                Source::Api,
                Category::Console,
                "console.group.member_added",
                Actor::with_details(
                    &user.id,
                    "user",
                    Some(user.username.clone()),
                    Some(client_ip),
                ),
                Outcome::Success,
                json!({
                    "group_id": id,
                    "subject_type": st.as_str(),
                    "subject_id": subject_id,
                }),
            ))
            .await;
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "group_id": id,
            "subject_type": st.as_str(),
            "subject_id": subject_id,
            "added_at": now,
        })),
    )
        .into_response()
}

pub async fn remove_group_member_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path((id, subject_type, subject_id)): Path<(String, String, String)>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let res = db_or_500!(
        sqlx::query(
            "DELETE FROM group_members WHERE group_id = ? AND subject_type = ? AND subject_id = ?",
        )
        .bind(&id)
        .bind(&subject_type)
        .bind(&subject_id)
        .execute(&state.db)
        .await
    );

    if res.rows_affected() == 0 {
        return StatusCode::NOT_FOUND.into_response();
    }

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.group.member_removed",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "group_id": id,
                "subject_type": subject_type,
                "subject_id": subject_id,
            }),
        ))
        .await;

    Json(json!({ "deleted": true })).into_response()
}

// ── Grants Handlers ──

pub async fn list_group_grants_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    if user.role != "admin" {
        let in_scope = match is_group_in_scope(&state.db, &user, &id).await {
            Ok(v) => v,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if !in_scope {
            let group_exists: bool = db_or_500!(
                sqlx::query_scalar("SELECT count(*) > 0 FROM groups WHERE id = ?")
                    .bind(&id)
                    .fetch_one(&state.db)
                    .await
            );
            if group_exists {
                audit_scope_denied(&state.audit, &user, "group", &id, &client_ip, &trace_id).await;
            }
            return StatusCode::NOT_FOUND.into_response();
        }
    }

    let rows = db_or_500!(
        sqlx::query(
            "SELECT from_group_id, to_group_id, permission, created_at, created_by
             FROM group_grants WHERE from_group_id = ? ORDER BY created_at ASC",
        )
        .bind(&id)
        .fetch_all(&state.db)
        .await
    );

    let items: Vec<GroupGrant> = rows
        .into_iter()
        .filter_map(|r| GroupGrant::from_row(&r).ok())
        .collect();

    Json(json!({ "items": items })).into_response()
}

pub async fn add_group_grant_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateGrantRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    if id == payload.to_group_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "bad_request",
                "message": "Un grupo no puede otorgarse una concesión a sí mismo"
            })),
        )
            .into_response();
    }

    let perm = match GroupPermission::from_str_opt(&payload.permission) {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "bad_request",
                    "message": "Permiso inválido; debe ser 'read' u 'operate'"
                })),
            )
                .into_response()
        }
    };

    // Check both groups exist
    let from_exists = db_or_500!(
        sqlx::query("SELECT id FROM groups WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
    );

    let to_exists = db_or_500!(
        sqlx::query("SELECT id FROM groups WHERE id = ?")
            .bind(&payload.to_group_id)
            .fetch_optional(&state.db)
            .await
    );

    if from_exists.is_none() || to_exists.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let now = Utc::now().to_rfc3339();
    let res = db_or_500!(
        sqlx::query(
            "INSERT OR IGNORE INTO group_grants (from_group_id, to_group_id, permission, created_at, created_by)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&payload.to_group_id)
        .bind(perm.as_str())
        .bind(&now)
        .bind(&user.username)
        .execute(&state.db)
        .await
    );

    if res.rows_affected() > 0 {
        let _ = state
            .audit
            .append(EventInput::new(
                trace_id,
                Source::Api,
                Category::Console,
                "console.group.grant_added",
                Actor::with_details(
                    &user.id,
                    "user",
                    Some(user.username.clone()),
                    Some(client_ip),
                ),
                Outcome::Success,
                json!({
                    "from_group_id": id,
                    "to_group_id": payload.to_group_id,
                    "permission": perm.as_str(),
                }),
            ))
            .await;
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "from_group_id": id,
            "to_group_id": payload.to_group_id,
            "permission": perm.as_str(),
            "created_at": now,
        })),
    )
        .into_response()
}

pub async fn remove_group_grant_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path((id, to, permission)): Path<(String, String, String)>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, GROUPS_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let res = db_or_500!(
        sqlx::query(
            "DELETE FROM group_grants WHERE from_group_id = ? AND to_group_id = ? AND permission = ?",
        )
        .bind(&id)
        .bind(&to)
        .bind(&permission)
        .execute(&state.db)
        .await
    );

    if res.rows_affected() == 0 {
        return StatusCode::NOT_FOUND.into_response();
    }

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.group.grant_removed",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "from_group_id": id,
                "to_group_id": to,
                "permission": permission,
            }),
        ))
        .await;

    Json(json!({ "deleted": true })).into_response()
}
