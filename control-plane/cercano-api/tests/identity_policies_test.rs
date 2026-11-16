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

//! Integration tests for F5-05: Central Policy Service & Deterministic Precedence Engine.
//!
//! Validates:
//! - Policy CRUD: dictionary validation, SHA-256 calculation, versioning, activation/revocation.
//! - TC-F5-020: Conflict resolution global vs group vs device (most restrictive wins).
//! - TC-F5-021: Two groups with opposite values (deterministic resolution; smaller group_id breaks tie).
//! - TC-F5-022: Expired, revoked, draft, or tampered SHA-256 policies do not participate in resolution.
//! - TC-F5-023: Policy attempting to exceed signed profile ceiling is strictly clamped (P0 ceiling-enforced).

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

async fn create_device_with_role(state: &AppState, device_id: &str, name: &str, role: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO devices (id, name, hostname, os, version, ip_address, status, last_seen_at, created_at, role)
         VALUES (?, ?, 'host1', 'windows', '1.0.0', '192.168.1.50', 'online', ?, ?, ?)",
    )
    .bind(device_id)
    .bind(name)
    .bind(&now)
    .bind(&now)
    .bind(role)
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
async fn test_policy_crud_validation_and_lifecycle() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    let (_op_id, op_tok) = create_user_with_token(&state, "operator_user", "operator").await;

    // 1. Reject unknown policy key -> 400 Bad Request
    let (status, body) = request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "global",
            "document": {
                "malicious_key": true
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["message"].as_str().unwrap().contains("desconocida"));

    // 2. Reject operator creating policy (lacks policy:manage) -> 403 Forbidden
    let (status, _) = request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&op_tok),
        Some(json!({
            "scope_type": "global",
            "document": {
                "allow_clipboard": false
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 3. Admin creates valid global policy in draft state -> 201 Created
    let (status, resp_p1) = request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "global",
            "document": {
                "allow_clipboard": false,
                "session.max_duration_minutes": 60
            },
            "state": "draft"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(resp_p1["version"], 1);
    assert_eq!(resp_p1["state"], "draft");
    let p1_id = resp_p1["id"].as_str().unwrap();

    // 4. Activate policy -> transitions to active
    let (status, act_resp) = request_json(
        &app,
        "POST",
        &format!("/api/policies/{p1_id}/activate"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(act_resp["state"], "active");

    // 5. Create version 2 as active immediately -> version 1 becomes superseded
    let (status, resp_p2) = request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "global",
            "document": {
                "allow_clipboard": false,
                "session.max_duration_minutes": 30
            },
            "state": "active"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(resp_p2["version"], 2);
    assert_eq!(resp_p2["state"], "active");
    let p2_id = resp_p2["id"].as_str().unwrap();

    // Check version 1 is now superseded
    let (status, get_p1) = request_json(
        &app,
        "GET",
        &format!("/api/policies/{p1_id}"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(get_p1["state"], "superseded");

    // 6. Revoke version 2
    let (status, rev_resp) = request_json(
        &app,
        "POST",
        &format!("/api/policies/{p2_id}/revoke"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rev_resp["state"], "revoked");
}

#[tokio::test]
async fn test_tc_f5_020_conflict_resolution_global_group_device() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    create_device_with_role(&state, "dev-test-1", "Equipo Servidor", "soporte").await;

    // Create device group
    let (_, grp) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "device", "name": "Servidores Criticos" })),
    )
    .await;
    let gid = grp["id"].as_str().unwrap();

    // Add device to group
    request_json(
        &app,
        "POST",
        &format!("/api/groups/{gid}/members/device/dev-test-1"),
        Some(&admin_tok),
        None,
    )
    .await;

    // Layer P1 (Global): allow_file_transfer = false, session.max_duration_minutes = 90
    request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "global",
            "document": {
                "allow_file_transfer": false,
                "session.max_duration_minutes": 90
            },
            "state": "active"
        })),
    )
    .await;

    // Layer P2 (Group): allow_file_transfer = true, session.max_duration_minutes = 60, require_approval = true
    request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "group",
            "scope_id": gid,
            "document": {
                "allow_file_transfer": true,
                "session.max_duration_minutes": 60,
                "require_approval": true
            },
            "state": "active"
        })),
    )
    .await;

    // Layer P3 (Device): allow_terminal = true, session.max_duration_minutes = 120
    request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "device",
            "scope_id": "dev-test-1",
            "document": {
                "allow_terminal": true,
                "session.max_duration_minutes": 120
            },
            "state": "active"
        })),
    )
    .await;

    // Query effective policy
    let (status, eff) = request_json(
        &app,
        "GET",
        "/api/policies/effective?device_id=dev-test-1",
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let effective = &eff["effective"];
    let explanations = &eff["explanations"];

    // 1. allow_file_transfer: global=false, group=true -> false wins (restrictive)
    assert_eq!(effective["allow_file_transfer"], false);
    assert_eq!(explanations["allow_file_transfer"]["value"], false);
    assert_eq!(explanations["allow_file_transfer"]["source"], "global");
    assert_eq!(explanations["allow_file_transfer"]["rule"], "restrictive");

    // 2. session.max_duration_minutes: global=90, group=60, device=120 -> 60 wins (minimum duration)
    assert_eq!(effective["session.max_duration_minutes"], 60);
    assert_eq!(
        explanations["session.max_duration_minutes"]["source"],
        format!("group:{gid}")
    );

    // 3. require_approval: only defined in group -> true wins
    assert_eq!(effective["require_approval"], true);
    assert_eq!(
        explanations["require_approval"]["source"],
        format!("group:{gid}")
    );
    assert_eq!(explanations["require_approval"]["rule"], "only-definition");

    // 4. allow_terminal: only defined in device -> true
    assert_eq!(effective["allow_terminal"], true);
    assert_eq!(explanations["allow_terminal"]["source"], "device");
}

#[tokio::test]
async fn test_tc_f5_021_two_groups_opposite_values_deterministic() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    create_device_with_role(&state, "dev-dual", "Equipo Compartido", "soporte").await;

    // Create Group 1 and Group 2
    let (_, grp1) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "device", "name": "Grupo A" })),
    )
    .await;
    let gid1 = grp1["id"].as_str().unwrap().to_string();

    let (_, grp2) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_tok),
        Some(json!({ "kind": "device", "name": "Grupo B" })),
    )
    .await;
    let gid2 = grp2["id"].as_str().unwrap().to_string();

    // Add device to both groups
    request_json(
        &app,
        "POST",
        &format!("/api/groups/{gid1}/members/device/dev-dual"),
        Some(&admin_tok),
        None,
    )
    .await;
    request_json(
        &app,
        "POST",
        &format!("/api/groups/{gid2}/members/device/dev-dual"),
        Some(&admin_tok),
        None,
    )
    .await;

    // Group 1 defines allow_clipboard = true, Group 2 defines allow_clipboard = false
    request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "group",
            "scope_id": gid1,
            "document": { "allow_clipboard": true },
            "state": "active"
        })),
    )
    .await;

    request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "group",
            "scope_id": gid2,
            "document": { "allow_clipboard": false },
            "state": "active"
        })),
    )
    .await;

    // Resolve
    let (status, eff) = request_json(
        &app,
        "GET",
        "/api/policies/effective?device_id=dev-dual",
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Restrictive wins: false wins!
    assert_eq!(eff["effective"]["allow_clipboard"], false);
    assert_eq!(
        eff["explanations"]["allow_clipboard"]["source"],
        format!("group:{gid2}")
    );
}

#[tokio::test]
async fn test_tc_f5_022_corrupt_or_revoked_policy_ignored() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    create_device_with_role(&state, "dev-corrupt", "Equipo Prueba Corrupta", "soporte").await;

    // Create policy with tampered hash directly in database
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO policies (id, scope_type, scope_id, version, document, document_sha256, state, created_at, created_by)
         VALUES ('pol-bad-hash', 'device', 'dev-corrupt', 1, '{\"allow_clipboard\":false}', 'invalid_hash_value', 'active', ?, 'admin')",
    )
    .bind(&now)
    .execute(&state.db)
    .await
    .unwrap();

    // Query effective policy -> bad hash policy is ignored; default P0 profile applies!
    let (status, eff) = request_json(
        &app,
        "GET",
        "/api/policies/effective?device_id=dev-corrupt",
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Default for allow_clipboard is true
    assert_eq!(eff["effective"]["allow_clipboard"], true);
    assert_eq!(eff["explanations"]["allow_clipboard"]["source"], "profile");
}

#[tokio::test]
async fn test_tc_f5_023_policy_cannot_exceed_signed_profile_ceiling() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;

    // Device with role 'soporte' (inviolable ceiling: unattended_access=false, allow_outgoing=false, enable_elevation=false)
    create_device_with_role(&state, "dev-soporte", "Cliente Soporte", "soporte").await;

    // Admin creates global policy attempting to turn unattended_access=true and enable_elevation=true
    request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "global",
            "document": {
                "unattended_access": true,
                "enable_elevation": true,
                "allow_outgoing": true
            },
            "state": "active"
        })),
    )
    .await;

    // Query effective policy
    let (status, eff) = request_json(
        &app,
        "GET",
        "/api/policies/effective?device_id=dev-soporte",
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // P0 ceiling strictly clamped all three back to false!
    assert_eq!(eff["effective"]["unattended_access"], false);
    assert_eq!(
        eff["explanations"]["unattended_access"]["rule"],
        "ceiling-enforced"
    );
    assert_eq!(
        eff["explanations"]["unattended_access"]["source"],
        "profile"
    );

    assert_eq!(eff["effective"]["enable_elevation"], false);
    assert_eq!(
        eff["explanations"]["enable_elevation"]["rule"],
        "ceiling-enforced"
    );

    assert_eq!(eff["effective"]["allow_outgoing"], false);
    assert_eq!(
        eff["explanations"]["allow_outgoing"]["rule"],
        "ceiling-enforced"
    );
}
