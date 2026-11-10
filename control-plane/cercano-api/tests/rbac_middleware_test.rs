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
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use cercano_api::permissions::{
    self, enforce_permission_middleware, PermChatClose, PermChatManageBranding, PermChatRead,
    PermChatWrite, RequirePermission, RoutePermission, ADMIN, AUDITOR, LEGACY_USER, OPERATOR,
};
use cercano_api::{config::Config, create_app, db::init_db, AppState};

struct TestEnv {
    app: Router,
    state: AppState,
}

async fn setup() -> TestEnv {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let state = AppState::new(Config::default(), db, audit);
    TestEnv {
        app: create_app(state.clone()),
        state,
    }
}

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = if let Some(body) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

async fn bootstrap_admin(env: &TestEnv) -> String {
    let (status, _) = request(
        &env.app,
        "POST",
        "/api/auth/bootstrap",
        None,
        Some(json!({ "username": "admin", "password": "AdminPassword123!" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = request(
        &env.app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": "admin", "password": "AdminPassword123!" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body["token"].as_str().unwrap().to_string()
}

async fn create_user_and_login(
    env: &TestEnv,
    admin_token: &str,
    username: &str,
    role: &str,
) -> String {
    let (status, _) = request(
        &env.app,
        "POST",
        "/api/users",
        Some(admin_token),
        Some(json!({
            "username": username,
            "password": "Password123!",
            "role": role
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, login) = request(
        &env.app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": username,
            "password": "Password123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    login["token"].as_str().unwrap().to_string()
}

#[test]
fn test_chat_permission_role_matrix() {
    // Admin has everything
    assert!(permissions::has_permission(ADMIN, permissions::CHAT_READ));
    assert!(permissions::has_permission(ADMIN, permissions::CHAT_WRITE));
    assert!(permissions::has_permission(ADMIN, permissions::CHAT_CLOSE));
    assert!(permissions::has_permission(
        ADMIN,
        permissions::CHAT_MANAGE_BRANDING
    ));

    // Operator has chat:read, chat:write, chat:close, but NOT chat:manage_branding
    assert!(permissions::has_permission(
        OPERATOR,
        permissions::CHAT_READ
    ));
    assert!(permissions::has_permission(
        OPERATOR,
        permissions::CHAT_WRITE
    ));
    assert!(permissions::has_permission(
        OPERATOR,
        permissions::CHAT_CLOSE
    ));
    assert!(!permissions::has_permission(
        OPERATOR,
        permissions::CHAT_MANAGE_BRANDING
    ));

    // Auditor has chat:read only
    assert!(permissions::has_permission(AUDITOR, permissions::CHAT_READ));
    assert!(!permissions::has_permission(
        AUDITOR,
        permissions::CHAT_WRITE
    ));
    assert!(!permissions::has_permission(
        AUDITOR,
        permissions::CHAT_CLOSE
    ));
    assert!(!permissions::has_permission(
        AUDITOR,
        permissions::CHAT_MANAGE_BRANDING
    ));

    // Legacy user has chat:read only
    assert!(permissions::has_permission(
        LEGACY_USER,
        permissions::CHAT_READ
    ));
    assert!(!permissions::has_permission(
        LEGACY_USER,
        permissions::CHAT_WRITE
    ));
    assert!(!permissions::has_permission(
        LEGACY_USER,
        permissions::CHAT_CLOSE
    ));
    assert!(!permissions::has_permission(
        LEGACY_USER,
        permissions::CHAT_MANAGE_BRANDING
    ));
}

// Handlers using the RequirePermission extractor
async fn chat_read_handler(
    RequirePermission(user, _): RequirePermission<PermChatRead>,
) -> Json<Value> {
    Json(json!({ "status": "read_ok", "user": user.username }))
}

async fn chat_write_handler(
    RequirePermission(user, _): RequirePermission<PermChatWrite>,
) -> Json<Value> {
    Json(json!({ "status": "write_ok", "user": user.username }))
}

async fn chat_close_handler(
    RequirePermission(user, _): RequirePermission<PermChatClose>,
) -> Json<Value> {
    Json(json!({ "status": "close_ok", "user": user.username }))
}

async fn chat_branding_handler(
    RequirePermission(user, _): RequirePermission<PermChatManageBranding>,
) -> Json<Value> {
    Json(json!({ "status": "branding_ok", "user": user.username }))
}

#[tokio::test]
async fn test_rbac_extractor_enforcement_and_audit_event() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;
    let operator_token =
        create_user_and_login(&env, &admin_token, "operator_rbac", "operator").await;
    let auditor_token = create_user_and_login(&env, &admin_token, "auditor_rbac", "auditor").await;

    // Build custom test router with extractor-guarded routes
    let test_router = Router::new()
        .route("/test/chat/read", get(chat_read_handler))
        .route("/test/chat/write", post(chat_write_handler))
        .route("/test/chat/close", post(chat_close_handler))
        .route("/test/chat/branding", post(chat_branding_handler))
        .with_state(env.state.clone());

    // 1. Operator: can read, write, close
    let (s, res) = request(
        &test_router,
        "GET",
        "/test/chat/read",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "read_ok");

    let (s, res) = request(
        &test_router,
        "POST",
        "/test/chat/write",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "write_ok");

    let (s, res) = request(
        &test_router,
        "POST",
        "/test/chat/close",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "close_ok");

    // Operator cannot manage branding -> 403 Forbidden
    let (s, res) = request(
        &test_router,
        "POST",
        "/test/chat/branding",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(res["error"], "forbidden");
    assert_eq!(res["code"], "authz_denied");

    // 2. Auditor: can read, but cannot write, close, or manage branding
    let (s, res) = request(
        &test_router,
        "GET",
        "/test/chat/read",
        Some(&auditor_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "read_ok");

    let (s, res) = request(
        &test_router,
        "POST",
        "/test/chat/write",
        Some(&auditor_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(res["code"], "authz_denied");

    let (s, res) = request(
        &test_router,
        "POST",
        "/test/chat/close",
        Some(&auditor_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(res["code"], "authz_denied");

    // 3. Admin: has access to all four endpoints
    let (s, res) = request(
        &test_router,
        "GET",
        "/test/chat/read",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "read_ok");

    let (s, res) = request(
        &test_router,
        "POST",
        "/test/chat/write",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "write_ok");

    let (s, res) = request(
        &test_router,
        "POST",
        "/test/chat/close",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "close_ok");

    let (s, res) = request(
        &test_router,
        "POST",
        "/test/chat/branding",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["status"], "branding_ok");

    // 4. Verify authz.denied audit event was recorded in the database
    let denied_events = sqlx::query(
        "SELECT event_id, action, outcome, category, details FROM audit_events WHERE action = 'authz.denied'",
    )
    .fetch_all(&env.state.db)
    .await
    .unwrap();

    assert!(
        !denied_events.is_empty(),
        "authz.denied audit events must be emitted"
    );
    for row in &denied_events {
        use sqlx::Row;
        let action: String = row.get("action");
        let outcome: String = row.get("outcome");
        let category: String = row.get("category");
        let details: String = row.get("details");

        assert_eq!(action, "authz.denied");
        assert_eq!(outcome, "denied");
        assert_eq!(category, "auth");
        assert!(details.contains("required_permission"));
    }
}

#[tokio::test]
async fn test_rbac_middleware_layer_enforcement() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;
    let auditor_token = create_user_and_login(&env, &admin_token, "auditor_mw", "auditor").await;

    async fn secret_admin_route() -> &'static str {
        "admin_secret_data"
    }

    // Build router with enforce_permission_middleware and RoutePermission extension.
    // In Tower, outer layer runs first on inbound request, so we place the middleware
    // inside the extension layer so the extension is present when middleware inspects it.
    let mw_router = Router::new()
        .route("/secret/branding", post(secret_admin_route))
        .layer(axum::middleware::from_fn_with_state(
            env.state.clone(),
            enforce_permission_middleware,
        ))
        .layer(Extension(RoutePermission(
            permissions::CHAT_MANAGE_BRANDING,
        )))
        .with_state(env.state.clone());

    // Auditor calling secret branding route -> rejected with 403
    let (status, body) = request(
        &mw_router,
        "POST",
        "/secret/branding",
        Some(&auditor_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "authz_denied");

    // Admin calling secret branding route -> succeeds 200
    let (status, _) = request(
        &mw_router,
        "POST",
        "/secret/branding",
        Some(&admin_token),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}
