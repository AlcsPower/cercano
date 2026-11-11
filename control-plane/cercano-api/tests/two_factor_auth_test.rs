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
async fn test_tc_f4_004_two_step_login_and_totp_lifecycle() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // 1. Create a regular user
    let (status, user_obj) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "operador_totp",
            "password": "InitialPassword123!",
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = user_obj["id"].as_str().unwrap().to_string();

    // 2. Login without 2FA required -> returns 200 OK directly
    let (status, login_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "operador_totp",
            "password": "InitialPassword123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let operator_token = login_res["token"].as_str().unwrap().to_string();

    // 3. Enroll 2FA
    let (status, enroll_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/enroll",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let otpauth_uri = enroll_res["otpauth_uri"].as_str().unwrap();
    let secret_base32 = enroll_res["totp_secret_base32"].as_str().unwrap();
    assert!(otpauth_uri.starts_with("otpauth://totp/Cercano:operador_totp?"));
    assert!(!secret_base32.is_empty());

    // 4. Confirm with an invalid code fails
    let (status, confirm_err) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(&operator_token),
        Some(json!({ "totp_code": "000000" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(confirm_err["error"], "validation_error");

    // 5. Confirm with genuine valid code succeeds and returns 8 recovery codes
    let valid_code = generate_valid_totp_code(secret_base32, "operador_totp");
    let (status, confirm_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(&operator_token),
        Some(json!({ "totp_code": valid_code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(confirm_res["status"], "confirmed");
    let recovery_codes = confirm_res["recovery_codes"].as_array().unwrap();
    assert_eq!(recovery_codes.len(), 8);

    // Verify recovery codes format XXXX-XXXX-XXXX
    for code_val in recovery_codes {
        let code_str = code_val.as_str().unwrap();
        assert_eq!(code_str.len(), 14);
        assert_eq!(&code_str[4..5], "-");
        assert_eq!(&code_str[9..10], "-");
    }

    // 6. Now login with 2FA required -> returns 202 Accepted with mfa_token
    let (status, login_2fa) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "operador_totp",
            "password": "InitialPassword123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(login_2fa["mfa_required"], true);
    let mfa_token = login_2fa["mfa_token"].as_str().unwrap().to_string();
    assert_eq!(mfa_token.len(), 64);
    assert!(login_2fa.get("token").is_none());

    // 7. Verify challenge using valid TOTP code -> returns 200 OK with full session
    let fresh_totp_code = generate_valid_totp_code(secret_base32, "operador_totp");
    let (status, verify_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/verify",
        None,
        Some(json!({
            "mfa_token": mfa_token,
            "totp_code": fresh_totp_code
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let final_token = verify_res["token"].as_str().unwrap();
    assert!(final_token.starts_with("cercano_sess_"));
    assert_eq!(verify_res["user"]["username"], "operador_totp");

    // 8. Re-using the same challenge token fails (single-use)
    let (status, reuse_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/verify",
        None,
        Some(json!({
            "mfa_token": mfa_token,
            "totp_code": fresh_totp_code
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(reuse_res["error"], "unauthorized");

    // 9. Self-revocation is denied for operator (mandatory 2FA role under F4-11)
    let (status, self_revoke_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/revoke",
        Some(final_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(self_revoke_res["error"], "forbidden");

    // Admin can revoke user's 2FA
    let (status, revoke_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/revoke",
        Some(&admin_token),
        Some(json!({ "user_id": user_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoke_res["status"], "revoked");

    // After revocation, session is invalidated
    let (status, _) = request(&env, "GET", "/api/auth/me", Some(final_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // After revocation, user can log in with 1 step again
    let (status, relogin) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "operador_totp",
            "password": "InitialPassword123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(relogin["token"].as_str().is_some());
}

#[tokio::test]
async fn test_tc_f4_006_recovery_code_single_use_and_exhaustion() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // Create user
    let (status, _) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "recovery_user",
            "password": "PasswordRecovery123!",
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Login and enroll 2FA
    let (_, login_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "recovery_user",
            "password": "PasswordRecovery123!"
        })),
    )
    .await;
    let session = login_res["token"].as_str().unwrap();

    let (_, enroll_res) = request(&env, "POST", "/api/auth/2fa/enroll", Some(session), None).await;
    let secret_base32 = enroll_res["totp_secret_base32"].as_str().unwrap();

    let valid_code = generate_valid_totp_code(secret_base32, "recovery_user");
    let (_, confirm_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(session),
        Some(json!({ "totp_code": valid_code })),
    )
    .await;
    let recovery_codes = confirm_res["recovery_codes"].as_array().unwrap();
    let first_recovery_code = recovery_codes[0].as_str().unwrap().to_string();

    // Initiate 2FA login to get challenge token
    let (status, challenge_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "recovery_user",
            "password": "PasswordRecovery123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let mfa_token1 = challenge_res["mfa_token"].as_str().unwrap();

    // Use recovery code first time -> succeeds!
    let (status, verify_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/verify",
        None,
        Some(json!({
            "mfa_token": mfa_token1,
            "recovery_code": first_recovery_code
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(verify_res["token"]
        .as_str()
        .unwrap()
        .starts_with("cercano_sess_"));

    // Second challenge
    let (status, challenge_res2) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "recovery_user",
            "password": "PasswordRecovery123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let mfa_token2 = challenge_res2["mfa_token"].as_str().unwrap();

    // Attempting to re-use the SAME recovery code -> rejected with 401
    let (status, fail_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/verify",
        None,
        Some(json!({
            "mfa_token": mfa_token2,
            "recovery_code": first_recovery_code
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(fail_res["error"], "unauthorized");

    // Using a different unused recovery code -> succeeds!
    let second_recovery_code = recovery_codes[1].as_str().unwrap().to_string();
    let (status, ok_res) = request(
        &env,
        "POST",
        "/api/auth/2fa/verify",
        None,
        Some(json!({
            "mfa_token": mfa_token2,
            "recovery_code": second_recovery_code
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ok_res["token"]
        .as_str()
        .unwrap()
        .starts_with("cercano_sess_"));
}

#[tokio::test]
async fn test_tc_f4_005_five_failed_attempts_lockout_429() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // Create user
    let (_, _) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "lockout_target",
            "password": "LockoutPass123!",
            "role": "operator"
        })),
    )
    .await;

    // Enroll 2FA
    let (_, login_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "lockout_target",
            "password": "LockoutPass123!"
        })),
    )
    .await;
    let session = login_res["token"].as_str().unwrap();

    let (_, enroll_res) = request(&env, "POST", "/api/auth/2fa/enroll", Some(session), None).await;
    let secret = enroll_res["totp_secret_base32"].as_str().unwrap();
    let code = generate_valid_totp_code(secret, "lockout_target");
    let (_, _) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(session),
        Some(json!({ "totp_code": code })),
    )
    .await;

    // Perform 5 failed 2FA verification attempts
    for attempt in 1..=5 {
        let (status, chal) = request(
            &env,
            "POST",
            "/api/auth/login",
            None,
            Some(json!({
                "username": "lockout_target",
                "password": "LockoutPass123!"
            })),
        )
        .await;

        if attempt < 5 {
            assert_eq!(status, StatusCode::ACCEPTED);
            let mfa_token = chal["mfa_token"].as_str().unwrap();
            let (v_status, v_res) = request(
                &env,
                "POST",
                "/api/auth/2fa/verify",
                None,
                Some(json!({
                    "mfa_token": mfa_token,
                    "totp_code": "000000"
                })),
            )
            .await;
            assert_eq!(v_status, StatusCode::UNAUTHORIZED, "Attempt {attempt}");
            assert_eq!(v_res["error"], "unauthorized");
        } else {
            // By attempt 5 or subsequent verification, account becomes locked out (429)
            if status == StatusCode::ACCEPTED {
                let mfa_token = chal["mfa_token"].as_str().unwrap();
                let (v_status, v_res) = request(
                    &env,
                    "POST",
                    "/api/auth/2fa/verify",
                    None,
                    Some(json!({
                        "mfa_token": mfa_token,
                        "totp_code": "000000"
                    })),
                )
                .await;
                assert_eq!(v_status, StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(v_res["error"], "account_locked");
            } else {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(chal["error"], "account_locked");
            }
        }
    }

    // Now all login or 2FA attempts return 429
    let (status, locked_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "lockout_target",
            "password": "LockoutPass123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(locked_res["error"], "account_locked");
}

#[tokio::test]
async fn test_cannot_require_2fa_without_enrollment() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    // Create user without 2FA
    let (_, user) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "no_2fa_user",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;
    let user_id = user["id"].as_str().unwrap();

    // Admin attempts to force is_2fa_required = true -> rejected with 400 Bad Request
    let (status, err_res) = request(
        &env,
        "PATCH",
        &format!("/api/users/{user_id}"),
        Some(&admin_token),
        Some(json!({ "is_2fa_required": true })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err_res["error"], "validation_error");
}

#[tokio::test]
async fn test_admin_can_revoke_other_user_2fa() {
    let env = setup().await;
    let admin_token = bootstrap_admin(&env).await;

    let (_, user) = request(
        &env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": "admin_revoke_target",
            "password": "Password123!",
            "role": "operator"
        })),
    )
    .await;
    let user_id = user["id"].as_str().unwrap().to_string();

    // Login and enroll
    let (_, login_res) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "admin_revoke_target",
            "password": "Password123!"
        })),
    )
    .await;
    let session = login_res["token"].as_str().unwrap();
    let (_, enroll_res) = request(&env, "POST", "/api/auth/2fa/enroll", Some(session), None).await;
    let secret = enroll_res["totp_secret_base32"].as_str().unwrap();
    let code = generate_valid_totp_code(secret, "admin_revoke_target");
    let (_, _) = request(
        &env,
        "POST",
        "/api/auth/2fa/confirm",
        Some(session),
        Some(json!({ "totp_code": code })),
    )
    .await;

    // Admin revokes user 2FA using user_id payload
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

    // User can now log in normally without 2FA
    let (status, relogin) = request(
        &env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "admin_revoke_target",
            "password": "Password123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(relogin["token"].as_str().is_some());
}
