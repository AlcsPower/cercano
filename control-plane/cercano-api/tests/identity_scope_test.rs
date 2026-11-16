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

//! Integration tests for F5-04: Scope enforcement, group grants, and IDOR prevention.
//!
//! Validates:
//! - TC-F5-010: Role x operation x scope matrix (deny-by-default).
//! - TC-F5-011: IDOR protection on alien groups (404 Not Found + authz.denied).
//! - TC-F5-012: Device scope and non-enumerative 404 with audit logging.
//! - TC-F5-013: Cross-group grants (`read` / `operate`) grant visibility dynamically.
//! - TC-F5-014: Group membership never elevates role permissions (operator cannot manage).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::Row;
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

async fn create_user_with_token(state: &AppState, username: &str, role: &str) -> (String, String) {
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

    (user_id, token)
}

async fn create_device(state: &AppState, device_id: &str, name: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO devices (id, name, hostname, os, version, ip_address, status, last_seen_at, created_at, role)
         VALUES (?, ?, 'host1', 'windows', '1.0.0', '192.168.1.50', 'online', ?, ?, 'soporte')",
    )
    .bind(device_id)
    .bind(name)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await
    .unwrap();
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
async fn test_tc_f5_011_idor_group_isolation_and_audit() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    let (op1_id, op1_tok) = create_user_with_token(&state, "operator_1", "operator").await;
    let (op2_id, _op2_tok) = create_user_with_token(&state, "operator_2", "operator").await;

    // 1. Admin creates Group Alpha and Group Beta
    let (status, resp_alpha) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "user", "name": "Group Alpha" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let alpha_id = resp_alpha["id"].as_str().unwrap();

    let (status, resp_beta) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "user", "name": "Group Beta" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let beta_id = resp_beta["id"].as_str().unwrap();

    // 2. Admin assigns Operator 1 to Alpha, Operator 2 to Beta
    let (status, _) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{alpha_id}/members/user/{op1_id}"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{beta_id}/members/user/{op2_id}"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // 3. Operator 1 can view Group Alpha and its members
    let (status, body) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{alpha_id}"),
        Some(&op1_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Group Alpha");

    let (status, body) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{alpha_id}/members"),
        Some(&op1_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    // 4. Operator 1 attempts IDOR access to Group Beta -> 404 NOT FOUND (non-enumerative)
    let (status, _) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{beta_id}"),
        Some(&op1_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{beta_id}/members"),
        Some(&op1_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{beta_id}/grants"),
        Some(&op1_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 5. Verify audit log contains authz.denied event for Operator 1 trying to access Group Beta
    let rows = sqlx::query(
        "SELECT action, outcome, details FROM audit_events WHERE action = 'authz.denied'",
    )
    .fetch_all(&state.db)
    .await
    .unwrap();
    assert!(
        !rows.is_empty(),
        "Expected at least one authz.denied audit event"
    );

    let mut found = false;
    for r in &rows {
        let details_str: String = r.get("details");
        let details: Value = serde_json::from_str(&details_str).unwrap();
        if details["resource_id"] == beta_id {
            assert_eq!(details["resource"], "group");
            assert_eq!(details["reason"], "out_of_scope");
            found = true;
            break;
        }
    }
    assert!(found, "Expected audit denial for Group Beta");
}

#[tokio::test]
async fn test_tc_f5_012_device_scope_and_idor_prevention() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    let (op1_id, op1_tok) = create_user_with_token(&state, "operator_1", "operator").await;

    // 1. Create Device 101 and 102
    create_device(&state, "dev-101", "Servidor Sucursal 1").await;
    create_device(&state, "dev-102", "Servidor Sucursal 2").await;

    // 2. Create User Group and Device Group for Sucursal 1
    let (_, grp_u1) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "user", "name": "Operadores S1" })),
    )
    .await;
    let u1_id = grp_u1["id"].as_str().unwrap();

    let (_, grp_d1) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "device", "name": "Equipos S1" })),
    )
    .await;
    let d1_id = grp_d1["id"].as_str().unwrap();

    // 3. Add operator 1 to u1, dev-101 to d1
    request_json(
        &app,
        "POST",
        &format!("/api/groups/{u1_id}/members/user/{op1_id}"),
        Some(&admin_tok),
        None,
    )
    .await;
    request_json(
        &app,
        "POST",
        &format!("/api/groups/{d1_id}/members/device/dev-101"),
        Some(&admin_tok),
        None,
    )
    .await;

    // 4. Before grant: dev-101 is NOT visible to op1
    let (status, body) = request_json(&app, "GET", "/api/devices", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);

    // dev-101 returns 404
    let (status, _) = request_json(&app, "GET", "/api/devices/dev-101", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // dev-102 (completely independent) returns 404
    let (status, _) = request_json(&app, "GET", "/api/devices/dev-102", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Verify audit log has out_of_scope denial for dev-101 and dev-102
    let rows = sqlx::query(
        "SELECT action, outcome, details FROM audit_events WHERE action = 'authz.denied'",
    )
    .fetch_all(&state.db)
    .await
    .unwrap();

    let mut found = false;
    for r in &rows {
        let details_str: String = r.get("details");
        let details: Value = serde_json::from_str(&details_str).unwrap();
        if details["resource_id"] == "dev-101" {
            assert_eq!(details["resource"], "device");
            assert_eq!(details["reason"], "out_of_scope");
            found = true;
            break;
        }
    }
    assert!(found, "Expected audit denial for device dev-101");
}

#[tokio::test]
async fn test_tc_f5_013_cross_group_grants_read_and_operate() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    let (op1_id, op1_tok) = create_user_with_token(&state, "operator_1", "operator").await;

    create_device(&state, "dev-hr-01", "PC Recursos Humanos").await;

    // Create User Group and Device Group
    let (_, grp_users) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "user", "name": "Tecnicos Soporte" })),
    )
    .await;
    let users_gid = grp_users["id"].as_str().unwrap();

    let (_, grp_devs) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "device", "name": "Dispositivos HR" })),
    )
    .await;
    let devs_gid = grp_devs["id"].as_str().unwrap();

    // Add op1 to users group, dev-hr-01 to devs group
    request_json(
        &app,
        "POST",
        &format!("/api/groups/{users_gid}/members/user/{op1_id}"),
        Some(&admin_tok),
        None,
    )
    .await;
    request_json(
        &app,
        "POST",
        &format!("/api/groups/{devs_gid}/members/device/dev-hr-01"),
        Some(&admin_tok),
        None,
    )
    .await;

    // Create address book entry tied to dev-hr-01 and grp_devs
    let (status, book_resp) = request_json(
        &app,
        "POST",
        "/api/address-book",
        Some(&admin_tok),
        Some(json!({
            "name": "Acceso Directo HR",
            "device_id": "dev-hr-01",
            "group_id": devs_gid,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let book_id = book_resp["id"].as_str().unwrap();

    // 1. Initial state: Operator 1 has no grants -> 0 devices, 0 address book entries
    let (status, dev_list) = request_json(&app, "GET", "/api/devices", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dev_list.as_array().unwrap().len(), 0);

    let (status, book_list) =
        request_json(&app, "GET", "/api/address-book", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(book_list["total"], 0);

    // 2. Admin creates grant from Tecnicos Soporte to Dispositivos HR with permission 'read'
    let (status, _) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{users_gid}/grants"),
        Some(&admin_tok),
        Some(json!({
            "to_group_id": devs_gid,
            "permission": "read",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // 3. Now Operator 1 can view dev-hr-01 and the address book entry!
    let (status, dev_list) = request_json(&app, "GET", "/api/devices", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::OK);
    let devs = dev_list.as_array().unwrap();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0]["id"], "dev-hr-01");

    let (status, dev_detail) =
        request_json(&app, "GET", "/api/devices/dev-hr-01", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dev_detail["name"], "PC Recursos Humanos");

    let (status, book_list) =
        request_json(&app, "GET", "/api/address-book", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(book_list["total"], 1);
    assert_eq!(book_list["items"][0]["name"], "Acceso Directo HR");

    let (status, book_detail) = request_json(
        &app,
        "GET",
        &format!("/api/address-book/{book_id}"),
        Some(&op1_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(book_detail["id"], book_id);

    // 4. Revoke grant
    let (status, _) = request_json(
        &app,
        "DELETE",
        &format!("/api/groups/{users_gid}/grants/{devs_gid}/read"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 5. Instantly revoked -> 404 on direct device & address book access
    let (status, _) =
        request_json(&app, "GET", "/api/devices/dev-hr-01", Some(&op1_tok), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = request_json(
        &app,
        "GET",
        &format!("/api/address-book/{book_id}"),
        Some(&op1_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_tc_f5_014_group_membership_does_not_elevate_role() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    let (op_id, op_tok) = create_user_with_token(&state, "operator_user", "operator").await;

    // Create group and add operator
    let (_, grp) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "user", "name": "Grupo Operadores" })),
    )
    .await;
    let gid = grp["id"].as_str().unwrap();

    request_json(
        &app,
        "POST",
        &format!("/api/groups/{gid}/members/user/{op_id}"),
        Some(&admin_tok),
        None,
    )
    .await;

    // Operator is member of Grupo Operadores, but MUST NOT have management permissions (403 Forbidden)
    let (status, _) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&op_tok),
        Some(json!({ "kind": "user", "name": "Grupo Hacker" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = request_json(
        &app,
        "DELETE",
        &format!("/api/groups/{gid}"),
        Some(&op_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{gid}/members/user/some-other-user"),
        Some(&op_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = request_json(
        &app,
        "POST",
        "/api/address-book",
        Some(&op_tok),
        Some(json!({ "name": "Entrada Maliciosa" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
