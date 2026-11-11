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

//! Integration tests for F4-11 (Mandatory 2FA Policy), F4-12 (At-Rest TOTP Encryption),
//! and F4-13 (Final Permissions Matrix Reconciliation).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::Row;
use tower::ServiceExt;

use cercano_api::{
    auth::{decrypt_totp_secret, encrypt_totp_secret},
    config::Config,
    create_app,
    db::init_db,
    permissions::{self, ADMIN, AUDITOR, LEGACY_USER, OPERATOR},
    AppState,
};

struct TestEnv {
    app: axum::Router,
    db: sqlx::SqlitePool,
    #[allow(dead_code)]
    audit: Arc<audit_core::AuditStore>,
}

async fn setup() -> TestEnv {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let state = AppState::new(Config::default(), db.clone(), audit.clone());
    TestEnv {
        app: create_app(state),
        db,
        audit,
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

async fn bootstrap_admin(env: &TestEnv) -> String {
    let (status, _) = request(
        env,
        "POST",
        "/api/auth/bootstrap",
        None,
        Some(json!({ "username": "admin", "password": "AdminPassword123!" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = request(
        env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": "admin", "password": "AdminPassword123!" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = body["token"].as_str().unwrap().to_string();

    if body["mfa_enrollment_required"].as_bool().unwrap_or(false) {
        let (_, enroll_res) =
            request(env, "POST", "/api/auth/2fa/enroll", Some(&token), None).await;
        let secret = enroll_res["totp_secret_base32"].as_str().unwrap();
        let code = generate_valid_totp_code(secret, "admin");
        let (confirm_status, _) = request(
            env,
            "POST",
            "/api/auth/2fa/confirm",
            Some(&token),
            Some(json!({ "totp_code": code })),
        )
        .await;
        assert_eq!(confirm_status, StatusCode::OK);
    }

    token
}

#[tokio::test]
async fn test_tc_f4_008_mandatory_2fa_policy_blocks_until_enrolled() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // 1. Admin creates operator user
    let (status, user) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "tecnico_mandatorio",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(user["id"].as_str().is_some());

    // 2. Operator logs in without 2FA factor configured
    let (status, login) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "tecnico_mandatorio",
            "password": "Password123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(login["mfa_enrollment_required"], true);
    let limited_token = login["token"].as_str().unwrap();

    // 3. Attempting to call protected endpoint returns 403 mfa_enrollment_required
    let (status, err) = request(&env, "GET", "/api/devices", Some(limited_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["error"], "forbidden");
    assert_eq!(err["code"], "mfa_enrollment_required");

    // 4. Calling allowed endpoints succeeds (GET /api/auth/me, POST /api/auth/2fa/enroll)
    let (status, me) = request(&env, "GET", "/api/auth/me", Some(limited_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["username"], "tecnico_mandatorio");

    let (status, enroll) = request(
        &env,
        "POST",
        "/api/auth/2fa/enroll",
        Some(limited_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let secret_base32 = enroll["totp_secret_base32"].as_str().unwrap();

    // 5. Confirm 2FA
    let code = generate_valid_totp_code(secret_base32, "tecnico_mandatorio");
    let (status, confirm) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(limited_token),
        Some(json!({ "totp_code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(confirm["status"], "confirmed");

    // 6. After confirmation, session is now elevated (mfa_verified = 1), protected routes succeed
    let (status, devices) = request(&env, "GET", "/api/devices", Some(limited_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(devices.is_array());
}

#[tokio::test]
async fn test_tc_f4_009_self_revocation_denied_for_mandatory_roles() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // 1. Create operator user
    let (status, user) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "operador_revocacion",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = user["id"].as_str().unwrap();

    // 2. Login, enroll, and confirm
    let (_, login) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "operador_revocacion",
            "password": "Password123!"
        })),
    )
    .await;
    let token = login["token"].as_str().unwrap();

    let (_, enroll) = request(&env, "POST", "/api/auth/2fa/enroll", Some(token), None).await;
    let secret = enroll["totp_secret_base32"].as_str().unwrap();
    let code = generate_valid_totp_code(secret, "operador_revocacion");
    let (status, _) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(token),
        Some(json!({ "totp_code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 3. User attempts self-revocation -> denied 403 Forbidden
    let (status, err) = request(&env, "POST", "/api/auth/2fa/revoke", Some(token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["error"], "forbidden");

    // Also denied if explicitly passing own user_id
    let (status, err) = request(
        &env,
        "POST",
        "/api/auth/2fa/revoke",
        Some(token),
        Some(json!({ "user_id": user_id })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["error"], "forbidden");

    // 4. Admin revokes target user's 2FA -> 200 OK
    let (status, res) = request(
        &env,
        "POST",
        "/api/auth/2fa/revoke",
        Some(&admin_token),
        Some(json!({ "user_id": user_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["status"], "revoked");

    // 5. Target user's session was revoked
    let (status, _) = request(&env, "GET", "/api/auth/me", Some(token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 6. On next login, user is forced to re-enroll
    let (status, relogin) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "operador_revocacion",
            "password": "Password123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(relogin["mfa_enrollment_required"], true);
}

#[tokio::test]
async fn test_tc_f4_012_at_rest_encryption_aes_256_gcm() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // 1. Create a user and enroll 2FA
    let (status, user) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "cifrado_usuario",
            "password": "Password123!",
            "role": "auditor"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = user["id"].as_str().unwrap();

    let (_, login) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "cifrado_usuario",
            "password": "Password123!"
        })),
    )
    .await;
    let token = login["token"].as_str().unwrap();

    let (status, enroll) = request(&env, "POST", "/api/auth/2fa/enroll", Some(token), None).await;
    assert_eq!(status, StatusCode::OK);
    let plain_secret = enroll["totp_secret_base32"].as_str().unwrap();

    // 2. Query SQLite directly to verify stored value is encrypted with enc:v1:
    let row = sqlx::query("SELECT totp_secret FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&env.db)
        .await
        .unwrap();
    let stored_secret: String = row.get("totp_secret");

    assert!(
        stored_secret.starts_with("enc:v1:"),
        "Stored secret must have enc:v1: prefix, got: {stored_secret}"
    );
    assert_ne!(
        stored_secret, plain_secret,
        "Stored secret must NOT be plaintext"
    );

    // 3. Confirm 2FA verifies that decryption with server key succeeds
    let code = generate_valid_totp_code(plain_secret, "cifrado_usuario");
    let (status, confirm) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(token),
        Some(json!({ "totp_code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(confirm["status"], "confirmed");

    // 4. Test wrong key decryption fails
    let wrong_key = "wrong-totp-encryption-key-32bytes!";
    let decrypt_err = decrypt_totp_secret(&stored_secret, wrong_key);
    assert!(decrypt_err.is_err(), "Decryption with wrong key must fail");

    // 5. Test encrypt/decrypt roundtrip
    let test_secret = "JBSWY3DPEHPK3PXP";
    let encrypted = encrypt_totp_secret(test_secret, "correct-key-for-test-32bytes-len!").unwrap();
    assert!(encrypted.starts_with("enc:v1:"));
    let decrypted = decrypt_totp_secret(&encrypted, "correct-key-for-test-32bytes-len!").unwrap();
    assert_eq!(decrypted, test_secret);
}

#[tokio::test]
async fn test_tc_f4_013_permissions_matrix_reconciliation_and_grants() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // 1. GET /api/roles returns fixed roles and permissions matching permissions.rs
    let (status, roles_res) = request(&env, "GET", "/api/roles", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::OK);
    let roles = roles_res["roles"].as_array().unwrap();

    let admin_entry = roles.iter().find(|r| r["role"] == ADMIN).unwrap();
    assert_eq!(admin_entry["permissions"], json!(["*"]));

    let operator_entry = roles.iter().find(|r| r["role"] == OPERATOR).unwrap();
    let operator_perms = operator_entry["permissions"].as_array().unwrap();
    assert!(operator_perms.contains(&json!(permissions::CHAT_ATTEND)));
    assert!(operator_perms.contains(&json!(permissions::CHAT_READ)));
    assert!(operator_perms.contains(&json!(permissions::CHAT_WRITE)));
    assert!(operator_perms.contains(&json!(permissions::CHAT_CLOSE)));
    assert!(operator_perms.contains(&json!(permissions::BUILDER_SOPORTE)));
    assert!(operator_perms.contains(&json!(permissions::BUILDER_DOWNLOAD)));
    assert!(!operator_perms.contains(&json!(permissions::CHAT_MANAGE)));
    assert!(!operator_perms.contains(&json!(permissions::CHAT_MANAGE_BRANDING)));
    assert!(!operator_perms.contains(&json!(permissions::BUILDER_TECNICO)));

    let auditor_entry = roles.iter().find(|r| r["role"] == AUDITOR).unwrap();
    let auditor_perms = auditor_entry["permissions"].as_array().unwrap();
    assert!(auditor_perms.contains(&json!(permissions::AUDIT_READ)));
    assert!(auditor_perms.contains(&json!(permissions::AUDIT_EXPORT)));
    assert!(auditor_perms.contains(&json!(permissions::CHAT_READ)));
    assert!(!auditor_perms.contains(&json!(permissions::CHAT_WRITE)));
    assert!(!auditor_perms.contains(&json!(permissions::CHAT_CLOSE)));

    let legacy_entry = roles.iter().find(|r| r["role"] == LEGACY_USER).unwrap();
    let legacy_perms = legacy_entry["permissions"].as_array().unwrap();
    assert!(legacy_perms.contains(&json!(permissions::CHAT_READ)));
    assert!(!legacy_perms.contains(&json!(permissions::CHAT_WRITE)));

    // 2. Individual grant via user_permissions table allows builder:create:tecnico
    let (status, user) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "tecnico_con_grant",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = user["id"].as_str().unwrap();

    // Initially operator does NOT have builder:create:tecnico
    let has_perm_initially =
        permissions::user_has_permission(&env.db, user_id, OPERATOR, permissions::BUILDER_TECNICO)
            .await;
    assert!(!has_perm_initially);

    // Grant builder:create:tecnico in user_permissions
    sqlx::query("INSERT INTO user_permissions (user_id, permission) VALUES (?, ?)")
        .bind(user_id)
        .bind(permissions::BUILDER_TECNICO)
        .execute(&env.db)
        .await
        .unwrap();

    // Now operator HAS builder:create:tecnico
    let has_perm_after_grant =
        permissions::user_has_permission(&env.db, user_id, OPERATOR, permissions::BUILDER_TECNICO)
            .await;
    assert!(has_perm_after_grant);
}

#[tokio::test]
async fn test_tc_f4_014_mfa_verified_session_flag() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // Admin session was verified via TOTP -> mfa_verified = 1 in sessions table
    let row = sqlx::query("SELECT mfa_verified FROM sessions WHERE token = ?")
        .bind(&admin_token)
        .fetch_one(&env.db)
        .await
        .unwrap();
    let mfa_verified: i64 = row.get("mfa_verified");
    assert_eq!(mfa_verified, 1);

    // Create a non-mandatory user (role: auditor)
    let (status, _) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "auditor_sin_2fa",
            "password": "Password123!",
            "role": "auditor"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Login without 2FA
    let (_, login) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "auditor_sin_2fa",
            "password": "Password123!"
        })),
    )
    .await;
    let token = login["token"].as_str().unwrap();

    // Session has mfa_verified = 0
    let row = sqlx::query("SELECT mfa_verified FROM sessions WHERE token = ?")
        .bind(token)
        .fetch_one(&env.db)
        .await
        .unwrap();
    let mfa_verified: i64 = row.get("mfa_verified");
    assert_eq!(mfa_verified, 0);
}
