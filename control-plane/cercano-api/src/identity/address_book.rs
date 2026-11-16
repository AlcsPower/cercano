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

//! Address Book REST handlers for Phase 5 (F5-03).
//!
//! Provides CRUD for address book entries with RBAC (`book:read`, `book:manage`)
//! and comprehensive audit logging (`console.book.*`).

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
use crate::identity::{validate_address_book_name, AddressBookEntry, MAX_NOTES_LEN, MAX_TAGS_LEN};
use crate::permissions::{check_permission, BOOK_MANAGE, BOOK_READ};
use crate::AppState;

macro_rules! db_or_500 {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };
}

#[derive(Debug, Deserialize)]
pub struct ListAddressBookQuery {
    pub group_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAddressBookRequest {
    pub name: String,
    pub device_id: Option<String>,
    pub group_id: Option<String>,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub tags: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAddressBookRequest {
    pub name: Option<String>,
    pub device_id: Option<String>,
    pub group_id: Option<String>,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub tags: Option<String>,
    pub notes: Option<String>,
}

pub async fn list_address_book_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Query(params): Query<ListAddressBookQuery>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, BOOK_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);

    let (items, total) = if let Some(ref gid) = params.group_id {
        let rows = db_or_500!(
            sqlx::query(
                "SELECT id, name, device_id, group_id, host, port, tags, notes, created_at, created_by, updated_at, updated_by
                 FROM address_book WHERE group_id = ? ORDER BY name ASC LIMIT ? OFFSET ?",
            )
            .bind(gid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await
        );

        let items: Vec<AddressBookEntry> = rows
            .into_iter()
            .filter_map(|r| AddressBookEntry::from_row(&r).ok())
            .collect();

        let total: i64 = db_or_500!(
            sqlx::query_scalar("SELECT count(*) FROM address_book WHERE group_id = ?")
                .bind(gid)
                .fetch_one(&state.db)
                .await
        );

        (items, total)
    } else {
        let rows = db_or_500!(
            sqlx::query(
                "SELECT id, name, device_id, group_id, host, port, tags, notes, created_at, created_by, updated_at, updated_by
                 FROM address_book ORDER BY name ASC LIMIT ? OFFSET ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await
        );

        let items: Vec<AddressBookEntry> = rows
            .into_iter()
            .filter_map(|r| AddressBookEntry::from_row(&r).ok())
            .collect();

        let total: i64 = db_or_500!(
            sqlx::query_scalar("SELECT count(*) FROM address_book")
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

pub async fn create_address_book_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(payload): Json<CreateAddressBookRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, BOOK_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    if let Err(msg) = validate_address_book_name(&payload.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "bad_request", "message": msg })),
        )
            .into_response();
    }

    if let Some(ref tags) = payload.tags {
        if tags.len() > MAX_TAGS_LEN {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "bad_request", "message": "Tags demasiado largos" })),
            )
                .into_response();
        }
    }

    if let Some(ref notes) = payload.notes {
        if notes.len() > MAX_NOTES_LEN {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "bad_request", "message": "Notas demasiado largas" })),
            )
                .into_response();
        }
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    db_or_500!(
        sqlx::query(
            "INSERT INTO address_book (id, name, device_id, group_id, host, port, tags, notes, created_at, created_by, updated_at, updated_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(payload.name.trim())
        .bind(&payload.device_id)
        .bind(&payload.group_id)
        .bind(&payload.host)
        .bind(payload.port)
        .bind(&payload.tags)
        .bind(&payload.notes)
        .bind(&now)
        .bind(&user.username)
        .bind(&now)
        .bind(&user.username)
        .execute(&state.db)
        .await
    );

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.book.entry_created",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "entry_id": id,
                "name": payload.name.trim(),
                "device_id": payload.device_id,
                "group_id": payload.group_id,
            }),
        ))
        .await;

    (
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": payload.name.trim(),
            "device_id": payload.device_id,
            "group_id": payload.group_id,
            "host": payload.host,
            "port": payload.port,
            "tags": payload.tags,
            "notes": payload.notes,
            "created_at": now,
            "created_by": user.username,
            "updated_at": now,
            "updated_by": user.username,
        })),
    )
        .into_response()
}

pub async fn get_address_book_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, BOOK_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let row = db_or_500!(
        sqlx::query(
            "SELECT id, name, device_id, group_id, host, port, tags, notes, created_at, created_by, updated_at, updated_by
             FROM address_book WHERE id = ?",
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
    );

    match row {
        Some(r) => match AddressBookEntry::from_row(&r) {
            Ok(entry) => Json(entry).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn update_address_book_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateAddressBookRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, BOOK_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let current = db_or_500!(
        sqlx::query("SELECT id, name, device_id, group_id, host, port, tags, notes FROM address_book WHERE id = ?")
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
            if let Err(msg) = validate_address_book_name(n) {
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

    let new_dev = payload
        .device_id
        .or_else(|| current.get::<Option<String>, _>("device_id"));
    let new_grp = payload
        .group_id
        .or_else(|| current.get::<Option<String>, _>("group_id"));
    let new_host = payload
        .host
        .or_else(|| current.get::<Option<String>, _>("host"));
    let new_port = payload
        .port
        .or_else(|| current.get::<Option<i64>, _>("port"));
    let new_tags = payload
        .tags
        .or_else(|| current.get::<Option<String>, _>("tags"));
    let new_notes = payload
        .notes
        .or_else(|| current.get::<Option<String>, _>("notes"));

    let now = Utc::now().to_rfc3339();

    db_or_500!(
        sqlx::query(
            "UPDATE address_book SET name = ?, device_id = ?, group_id = ?, host = ?, port = ?, tags = ?, notes = ?, updated_at = ?, updated_by = ? WHERE id = ?",
        )
        .bind(&new_name)
        .bind(&new_dev)
        .bind(&new_grp)
        .bind(&new_host)
        .bind(new_port)
        .bind(&new_tags)
        .bind(&new_notes)
        .bind(&now)
        .bind(&user.username)
        .bind(&id)
        .execute(&state.db)
        .await
    );

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.book.entry_updated",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "entry_id": id,
                "name": new_name,
            }),
        ))
        .await;

    Json(json!({
        "id": id,
        "name": new_name,
        "device_id": new_dev,
        "group_id": new_grp,
        "host": new_host,
        "port": new_port,
        "tags": new_tags,
        "notes": new_notes,
        "updated_at": now,
        "updated_by": user.username,
    }))
    .into_response()
}

pub async fn delete_address_book_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, BOOK_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let res = db_or_500!(
        sqlx::query("DELETE FROM address_book WHERE id = ?")
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
            "console.book.entry_deleted",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({ "entry_id": id }),
        ))
        .await;

    Json(json!({ "deleted": true })).into_response()
}
