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
    body["token"].as_str().unwrap().to_string()
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

#[tokio::test]
async fn test_stress_challenge_expiration_5min() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // Create user and enroll 2FA
    let (status, user) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "expired_chal_user",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let _user_id = user["id"].as_str().unwrap();

    let (_, login_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "expired_chal_user",
            "password": "Password123!"
        })),
    )
    .await;
    let session = login_res["token"].as_str().unwrap();

    let (_, enroll_res) = request(&env, "POST", "/api/auth/2fa/enroll", Some(session), None).await;
    let secret_base32 = enroll_res["totp_secret_base32"].as_str().unwrap().to_string();

    let valid_code = generate_valid_totp_code(&secret_base32, "expired_chal_user");
    let (status, _) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(session),
        Some(json!({ "totp_code": valid_code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Login step 1 -> get challenge
    let (status, chal_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "expired_chal_user",
            "password": "Password123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let mfa_token = chal_res["mfa_token"].as_str().unwrap().to_string();

    // Expire challenge by setting expires_at to past time
    sqlx::query("UPDATE mfa_challenges SET expires_at = datetime('now', '-10 seconds') WHERE token = ?")
        .bind(&mfa_token)
        .execute(&env.state.db)
        .await
        .unwrap();

    // Verification attempt with valid code MUST fail with 401 "El desafío MFA ha expirado."
    let fresh_code = generate_valid_totp_code(&secret_base32, "expired_chal_user");
    let (status, err_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/verify",
        None,
        Some(json!({
            "mfa_token": mfa_token,
            "totp_code": fresh_code
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err_res["message"], "El desafío MFA ha expirado.");

    // Verify audit event auth.2fa_failed with expired_challenge was recorded
    let row = sqlx::query(
        "SELECT action, outcome, details FROM audit_events WHERE action = 'auth.2fa_failed' AND details LIKE '%expired_challenge%'",
    )
    .fetch_optional(&env.state.db)
    .await
    .unwrap();
    assert!(row.is_some(), "Expired challenge audit event must exist");
}

#[tokio::test]
async fn test_stress_recovery_code_format_insensitivity_and_exhaustion() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // Create user
    let (_, _) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "rec_stress_user",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;

    let (_, login_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "rec_stress_user",
            "password": "Password123!"
        })),
    )
    .await;
    let session = login_res["token"].as_str().unwrap();

    let (_, enroll_res) = request(&env, "POST", "/api/auth/2fa/enroll", Some(session), None).await;
    let secret = enroll_res["totp_secret_base32"].as_str().unwrap().to_string();
    let code = generate_valid_totp_code(&secret, "rec_stress_user");
    let (_, conf_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(session),
        Some(json!({ "totp_code": code })),
    )
    .await;
    let recovery_codes = conf_res["recovery_codes"].as_array().unwrap();
    let code0 = recovery_codes[0].as_str().unwrap().to_string();

    // Test case & dash insensitivity: lowercase without dashes should hash identically
    let code0_normalized = code0.to_lowercase().replace('-', "");

    let (_, chal) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "rec_stress_user",
            "password": "Password123!"
        })),
    )
    .await;
    let mfa_token = chal["mfa_token"].as_str().unwrap();

    // Verify using lowercase without dashes -> must succeed!
    let (status, ver_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/verify",
        None,
        Some(json!({
            "mfa_token": mfa_token,
            "recovery_code": code0_normalized
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ver_res["token"].as_str().unwrap().starts_with("cercano_sess_"));

    // Verify recovery code 0 is now consumed in DB
    let (_, chal2) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "rec_stress_user",
            "password": "Password123!"
        })),
    )
    .await;
    let mfa_token2 = chal2["mfa_token"].as_str().unwrap();

    // Trying code0 again (with dashes or without) -> 401
    let (status, _err_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/verify",
        None,
        Some(json!({
            "mfa_token": mfa_token2,
            "recovery_code": code0
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_stress_lockout_and_auto_unlock_after_15min() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    let (_, _) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "lockout_stress",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;

    let (_, login_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "lockout_stress",
            "password": "Password123!"
        })),
    )
    .await;
    let session = login_res["token"].as_str().unwrap();
    let (_, enroll_res) = request(&env, "POST", "/api/auth/2fa/enroll", Some(session), None).await;
    let secret = enroll_res["totp_secret_base32"].as_str().unwrap().to_string();
    let code = generate_valid_totp_code(&secret, "lockout_stress");
    let (_, _) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(session),
        Some(json!({ "totp_code": code })),
    )
    .await;

    // Trigger 5 failed 2FA verification attempts
    for _ in 1..=5 {
        let (s, chal) = request(
            &env,
            "POST",
            "/api/auth/login",
            None,
            Some(json!({
                "username": "lockout_stress",
                "password": "Password123!"
            })),
        )
        .await;

        if s == StatusCode::ACCEPTED {
            let mfa_token = chal["mfa_token"].as_str().unwrap();
            let _ = request(
                &env,
                "POST",
                "/api/auth/2fa/verify",
                None,
                Some(json!({
                    "mfa_token": mfa_token,
                    "totp_code": "999999"
                })),
            )
            .await;
        }
    }

    // Account is locked -> returns 429
    let (s, res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "lockout_stress",
            "password": "Password123!"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res["error"], "account_locked");

    // Age the failed login attempts past 15 minutes
    sqlx::query("UPDATE login_attempts SET attempted_at = datetime('now', '-16 minutes') WHERE username = 'lockout_stress'")
        .execute(&env.state.db)
        .await
        .unwrap();

    // Account should now be UNLOCKED and issue challenge (202)
    let (s, res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "lockout_stress",
            "password": "Password123!"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(res["mfa_required"], true);
}

#[tokio::test]
async fn test_stress_multiple_sessions_revocation_on_2fa_revoke() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    let (_, _) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "multi_sess_user",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;

    // Login 1
    let (_, l1) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "multi_sess_user",
            "password": "Password123!"
        })),
    )
    .await;
    let s1 = l1["token"].as_str().unwrap().to_string();

    // Login 2 (second active device/session)
    let (_, l2) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "multi_sess_user",
            "password": "Password123!"
        })),
    )
    .await;
    let s2 = l2["token"].as_str().unwrap().to_string();

    // Enroll 2FA with s1
    let (_, enroll_res) = request(&env, "POST", "/api/auth/2fa/enroll", Some(&s1), None).await;
    let secret = enroll_res["totp_secret_base32"].as_str().unwrap().to_string();
    let code = generate_valid_totp_code(&secret, "multi_sess_user");
    let (_, _) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(&s1),
        Some(json!({ "totp_code": code })),
    )
    .await;

    // Both s1 and s2 should work before revoke
    let (s, _) = request(&env, "GET", "/api/auth/me", Some(&s1), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = request(&env, "GET", "/api/auth/me", Some(&s2), None).await;
    assert_eq!(s, StatusCode::OK);

    // Revoke 2FA using s1
    let (status, rev_res) = request(&env, "POST", "/api/auth/2fa/revoke", Some(&s1), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rev_res["status"], "revoked");

    // CRITICAL: BOTH s1 and s2 MUST BE INVALIDATED
    let (s, _) = request(&env, "GET", "/api/auth/me", Some(&s1), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "Session s1 must be revoked");

    let (s, _) = request(&env, "GET", "/api/auth/me", Some(&s2), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "Session s2 must be revoked");

    // Clean login without 2FA succeeds and issues new session s3
    let (s, l3) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "multi_sess_user",
            "password": "Password123!"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let s3 = l3["token"].as_str().unwrap();
    let (s, me_res) = request(&env, "GET", "/api/auth/me", Some(s3), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me_res["username"], "multi_sess_user");
}
