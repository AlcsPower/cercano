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

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use cercano_api::config::Config;
use cercano_api::db::init_db;
use cercano_api::{create_app, AppState};

async fn setup_app() -> (axum::Router, AppState) {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let state = AppState::new(Config::default(), db, audit);
    let app = create_app(state.clone());
    (app, state)
}

async fn create_user_with_token(state: &AppState, username: &str, role: &str) -> String {
    let user_id = uuid::Uuid::new_v4().to_string();
    let token = format!("test_tok_{username}");
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at)
         VALUES (?, ?, 'hash', ?, ?)",
    )
    .bind(&user_id)
    .bind(username)
    .bind(role)
    .bind(&now)
    .execute(&state.db)
    .await
    .unwrap();

    let expires = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(&user_id)
    .bind(&expires)
    .bind(&now)
    .execute(&state.db)
    .await
    .unwrap();

    token
}

async fn request_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    if let Some(t) = token {
        req_builder = req_builder.header("authorization", format!("Bearer {t}"));
    }

    let req_body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };

    let req = req_builder.body(req_body).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn test_tc_f5_001_groups_crud_and_permissions() {
    let (app, state) = setup_app().await;

    let admin_tok = create_user_with_token(&state, "admin_user", "admin").await;
    let operator_tok = create_user_with_token(&state, "op_user", "operator").await;
    let auditor_tok = create_user_with_token(&state, "aud_user", "auditor").await;

    // 1. Create group as Operator -> 403 Forbidden
    let (status, _) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&operator_tok),
        Some(json!({
            "kind": "user",
            "name": "Grupo No Permitido"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 2. Create group as Admin -> 201 Created
    let (status, body) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({
            "kind": "user",
            "name": "Soporte N1",
            "description": "Técnicos de nivel 1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let group_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["name"], "Soporte N1");
    assert_eq!(body["kind"], "user");

    // Duplicate name for same kind -> 409 Conflict
    let (status, _) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({
            "kind": "user",
            "name": "Soporte N1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // 3. List groups as Auditor -> 200 OK (groups:read)
    let (status, body) = request_json(&app, "GET", "/api/groups", Some(&auditor_tok), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["name"], "Soporte N1");

    // 4. Update group as Operator -> 403 Forbidden
    let (status, _) = request_json(
        &app,
        "PATCH",
        &format!("/api/groups/{group_id}"),
        Some(&operator_tok),
        Some(json!({ "description": "Actualizado por operador" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 5. Update group as Admin -> 200 OK
    let (status, body) = request_json(
        &app,
        "PATCH",
        &format!("/api/groups/{group_id}"),
        Some(&admin_tok),
        Some(json!({ "description": "Actualizado por admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["description"], "Actualizado por admin");

    // 6. Delete group as Admin -> 200 OK
    let (status, body) = request_json(
        &app,
        "DELETE",
        &format!("/api/groups/{group_id}"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);

    // Get deleted group -> 404 Not Found
    let (status, _) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{group_id}"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_tc_f5_002_group_members_and_grants() {
    let (app, state) = setup_app().await;
    let admin_tok = create_user_with_token(&state, "admin_user", "admin").await;

    // Create user group and device group
    let (_, g_user) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "user", "name": "Grupo Operadores" })),
    )
    .await;
    let u_group_id = g_user["id"].as_str().unwrap().to_string();

    let (_, g_dev) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "device", "name": "Grupo Servidores" })),
    )
    .await;
    let d_group_id = g_dev["id"].as_str().unwrap().to_string();

    // 1. Add member with mismatched subject_type -> 400 Bad Request
    let (status, _) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{u_group_id}/members/device/dev-123"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 2. Add valid user member -> 201 Created
    let (status, body) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{u_group_id}/members/user/usr-456"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["subject_id"], "usr-456");

    // List members
    let (status, body) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{u_group_id}/members"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    // 3. Grants: Self-grant rejected -> 400 Bad Request
    let (status, _) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{u_group_id}/grants"),
        Some(&admin_tok),
        Some(json!({
            "to_group_id": u_group_id,
            "permission": "read"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Valid grant -> 201 Created
    let (status, body) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{u_group_id}/grants"),
        Some(&admin_tok),
        Some(json!({
            "to_group_id": d_group_id,
            "permission": "operate"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["permission"], "operate");

    // Remove member
    let (status, _) = request_json(
        &app,
        "DELETE",
        &format!("/api/groups/{u_group_id}/members/user/usr-456"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Remove grant
    let (status, _) = request_json(
        &app,
        "DELETE",
        &format!("/api/groups/{u_group_id}/grants/{d_group_id}/operate"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_tc_f5_003_address_book_crud_and_permissions() {
    let (app, state) = setup_app().await;

    let admin_tok = create_user_with_token(&state, "admin_user", "admin").await;
    let operator_tok = create_user_with_token(&state, "op_user", "operator").await;
    let auditor_tok = create_user_with_token(&state, "aud_user", "auditor").await;

    // 1. Auditor cannot read address book -> 403 Forbidden (book:read is admin and operator only)
    let (status, _) =
        request_json(&app, "GET", "/api/address-book", Some(&auditor_tok), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 2. Operator cannot create entry -> 403 Forbidden (book:manage is admin only)
    let (status, _) = request_json(
        &app,
        "POST",
        "/api/address-book",
        Some(&operator_tok),
        Some(json!({ "name": "Servidor Intranet" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 3. Admin creates entry -> 201 Created
    let (status, body) = request_json(
        &app,
        "POST",
        "/api/address-book",
        Some(&admin_tok),
        Some(json!({
            "name": "Servidor Intranet",
            "host": "192.168.1.10",
            "port": 21116,
            "tags": "core,datacenter",
            "notes": "Servidor primario de red"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let entry_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["name"], "Servidor Intranet");

    // 4. Operator reads address book -> 200 OK
    let (status, body) =
        request_json(&app, "GET", "/api/address-book", Some(&operator_tok), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["name"], "Servidor Intranet");

    // 5. Admin updates entry -> 200 OK
    let (status, body) = request_json(
        &app,
        "PATCH",
        &format!("/api/address-book/{entry_id}"),
        Some(&admin_tok),
        Some(json!({ "notes": "Notas actualizadas" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["notes"], "Notas actualizadas");

    // 6. Admin deletes entry -> 200 OK
    let (status, body) = request_json(
        &app,
        "DELETE",
        &format!("/api/address-book/{entry_id}"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);
}
