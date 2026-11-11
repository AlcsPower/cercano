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

use cercano_api::{config::Config, create_app, db::init_db, AppState};

struct TestEnv {
    app: axum::Router,
}

async fn setup() -> TestEnv {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let state = AppState::new(Config::default(), db, audit);
    TestEnv {
        app: create_app(state),
    }
}

async fn request(
    env: &TestEnv,
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
    let response = env.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn generate_valid_totp_code(secret_base32: &str, username: &str) -> String {
    let secret_bytes = totp_rs::Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Cercano".to_string()),
        username.to_string(),
    )
    .unwrap();
    totp.generate_current().unwrap()
}

async fn bootstrap_and_login(env: &TestEnv) -> String {
    let (status, _) = request(
        env,
        "POST",
        "/api/auth/bootstrap",
        None,
        Some(json!({ "username": "admin", "password": "AdminPassword123!" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    login(env, "admin", "AdminPassword123!").await
}

async fn login(env: &TestEnv, username: &str, password: &str) -> String {
    let (status, body) = request(
        env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login {username}: {body}");
    let token = body["token"].as_str().unwrap().to_string();

    if body["mfa_enrollment_required"].as_bool().unwrap_or(false) {
        let (_, enroll_res) =
            request(env, "POST", "/api/auth/2fa/enroll", Some(&token), None).await;
        let secret = enroll_res["totp_secret_base32"].as_str().unwrap();
        let code = generate_valid_totp_code(secret, username);
        let (_, _) = request(
            env,
            "POST",
            "/api/auth/2fa/confirm",
            Some(&token),
            Some(json!({ "totp_code": code })),
        )
        .await;
    }

    token
}

#[tokio::test]
async fn test_users_roles_settings_rbac() {
    let env = setup().await;
    let admin_token = bootstrap_and_login(&env).await;

    let (status, created) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(
            json!({ "username": "operator1", "password": "OperatorPass123!", "role": "operator" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["username"], "operator1");
    assert_eq!(created["role"], "operator");
    assert!(created.get("password").is_none());
    assert!(created.get("password_hash").is_none());
    let operator_id = created["id"].as_str().unwrap().to_string();

    let operator_token = login(&env, "operator1", "OperatorPass123!").await;

    let (status, own) = request(&env, "GET", "/api/users", Some(&operator_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(own.as_array().unwrap().len(), 1);
    assert_eq!(own[0]["username"], "operator1");

    let (status, _) = request(
        &env,
        "POST",
        "/api/users",
        Some(&operator_token),
        Some(json!({ "username": "forbidden", "password": "AnotherPass123!", "role": "auditor" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, settings) =
        request(&env, "GET", "/api/settings", Some(&operator_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(settings.get("organization_name").is_some());

    let (status, _) = request(&env, "GET", "/api/roles", Some(&operator_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, roles) = request(&env, "GET", "/api/roles", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(roles["roles"].as_array().unwrap().len() >= 3);

    let (status, updated) = request(
        &env,
        "PATCH",
        &format!("/api/users/{operator_id}"),
        Some(&admin_token),
        Some(json!({ "role": "auditor" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["role"], "auditor");

    let (status, settings) = request(
        &env,
        "PATCH",
        "/api/settings",
        Some(&admin_token),
        Some(json!({ "organization_name": "Soporte interno", "support_email": "soporte@example.org" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(settings["organization_name"], "Soporte interno");

    let (status, _) = request(
        &env,
        "DELETE",
        &format!("/api/users/{operator_id}"),
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_last_admin_cannot_be_removed_or_demoted() {
    let env = setup().await;
    let admin_token = bootstrap_and_login(&env).await;

    let (status, me) = request(&env, "GET", "/api/auth/me", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let admin_id = me["id"].as_str().unwrap().to_string();

    let (status, _) = request(
        &env,
        "PATCH",
        &format!("/api/users/{admin_id}"),
        Some(&admin_token),
        Some(json!({ "role": "operator" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = request(
        &env,
        "DELETE",
        &format!("/api/users/{admin_id}"),
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
