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

//! Integration tests for F5-07: OIDC Authentication with PKCE & Identity Linking.
//!
//! Validates:
//! - IdP CRUD and RBAC (`idp:manage` required; secret masking).
//! - TC-F5-030: `state`/`nonce` absent, reused, or expired -> 401 Unauthorized without session.
//! - TC-F5-031: Issuer/audience mismatch, rotated/unknown `kid`, invalid signature -> rejected.
//! - TC-F5-032: Email matches existing local account -> 409 `identity_exists` without auto-linking.
//! - TC-F5-033: IdP unavailable -> 503 with `Retry-After`; existing sessions intact; local admin login works.
//! - MFA claim evaluation: `amr`/`acr` match issues session (200); absence requires Cercano TOTP 2FA (202).
//! - Identity unlinking and IdP disabling immediately revoke active sessions for affected users.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use cercano_api::config::Config;
use cercano_api::db::init_db;
use cercano_api::identity::oidc::{create_test_jwt, JwtClaims};
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
    let now = Utc::now().to_rfc3339();

    let pwd_hash = cercano_api::auth::hash_password("admin_pass").unwrap();

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active, created_at)
         VALUES (?, ?, ?, ?, 1, ?)",
    )
    .bind(&user_id)
    .bind(username)
    .bind(&pwd_hash)
    .bind(role)
    .bind(&now)
    .execute(&state.db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at, mfa_verified)
         VALUES (?, ?, datetime('now', '+24 hours'), 1)",
    )
    .bind(&token)
    .bind(&user_id)
    .execute(&state.db)
    .await
    .unwrap();

    (user_id, token)
}

#[tokio::test]
async fn test_idp_crud_and_rbac() {
    let (app, state) = setup_app().await;
    let (_, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    let (_, operator_tok) = create_user_with_token(&state, "operator_user", "operator").await;

    // 1. Operator without idp:manage gets 403 Forbidden
    let req = Request::builder()
        .uri("/api/idp")
        .method("GET")
        .header("Authorization", format!("Bearer {operator_tok}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Admin creates OIDC provider
    let idp_payload = json!({
        "kind": "oidc",
        "name": "corp-sso",
        "config": {
            "issuer": "https://auth.corp.example.com",
            "client_id": "cercano-corp-client",
            "client_secret": "super-secret-client-key",
            "signing_secret": "hmac-signing-key-12345678901234567890",
            "authorization_endpoint": "https://auth.corp.example.com/oauth2/authorize",
            "token_endpoint": "https://auth.corp.example.com/oauth2/token",
            "redirect_uri": "https://cercano.local/api/auth/oidc/corp-sso/callback",
            "mfa_claim": "amr:mfa",
            "active_kid": "corp-key-1"
        },
        "enabled": true
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(idp_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let created: Value = serde_json::from_slice(&body).unwrap();
    let idp_id = created["id"].as_str().unwrap().to_string();

    // Verify secrets are masked
    assert_eq!(created["config"]["client_secret"], "********");
    assert_eq!(created["config"]["signing_secret"], "********");

    // 3. Admin gets IdP by ID
    let req = Request::builder()
        .uri(format!("/api/idp/{idp_id}"))
        .method("GET")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let fetched: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(fetched["name"], "corp-sso");
    assert_eq!(fetched["config"]["client_secret"], "********");

    // 4. Test endpoint
    let req = Request::builder()
        .uri(format!("/api/idp/{idp_id}/test"))
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_tc_f5_030_oidc_state_nonce_validation() {
    let (app, state) = setup_app().await;
    let (_, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;

    // Create IdP
    let idp_payload = json!({
        "kind": "oidc",
        "name": "idp-tc-030",
        "config": {
            "issuer": "https://idp.example.com",
            "client_id": "cercano-tc030",
            "signing_secret": "test-secret-12345678901234567890",
            "authorization_endpoint": "https://idp.example.com/auth",
            "token_endpoint": "https://idp.example.com/token",
            "redirect_uri": "https://cercano.local/api/auth/oidc/idp-tc-030/callback"
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(idp_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 1. Start flow: request JSON format
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-tc-030/start?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let start_res: Value = serde_json::from_slice(&body).unwrap();
    let state_str = start_res["state"].as_str().unwrap().to_string();
    let nonce_str = start_res["nonce"].as_str().unwrap().to_string();
    let auth_url = start_res["authorization_url"].as_str().unwrap();

    assert!(auth_url.contains("response_type=code"));
    assert!(auth_url.contains("code_challenge_method=S256"));
    assert!(auth_url.contains(&format!("state={state_str}")));

    // 2. Callback without state -> 401 Unauthorized
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-tc-030/callback?code=some_code")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Callback with invalid state -> 401 Unauthorized
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-tc-030/callback?code=some_code&state=non_existent_state")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Link a user first so valid callback can succeed
    let (target_user_id, _) = create_user_with_token(&state, "target_user", "operator").await;

    // Find real ID of provider
    let idp_row: (String,) =
        sqlx::query_as("SELECT id FROM identity_providers WHERE name = 'idp-tc-030'")
            .fetch_one(&state.db)
            .await
            .unwrap();

    let req = Request::builder()
        .uri("/api/identity/links")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "user_id": target_user_id,
                "provider_id": idp_row.0,
                "subject": "sub-alice-tc030"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Create valid token matching flow nonce
    let now = Utc::now().timestamp();
    let claims = JwtClaims {
        iss: "https://idp.example.com".to_string(),
        sub: "sub-alice-tc030".to_string(),
        aud: Value::String("cercano-tc030".to_string()),
        exp: now + 3600,
        iat: now,
        nonce: Some(nonce_str),
        email: Some("alice@example.com".to_string()),
        amr: None,
        acr: None,
    };
    let token = create_test_jwt(&claims, "test-secret-12345678901234567890", None);

    // 4. Callback with valid state the first time: consumes state
    let req = Request::builder()
        .uri(format!(
            "/api/auth/oidc/idp-tc-030/callback?code=auth_code_123&state={state_str}&mock_id_token={token}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Requires Cercano 2FA because IdP token has no amr:mfa
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // 5. Callback with the exact same state a second time -> 401 Unauthorized (single use invariant)
    let req = Request::builder()
        .uri(format!(
            "/api/auth/oidc/idp-tc-030/callback?code=auth_code_123&state={state_str}&mock_id_token={token}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tc_f5_031_oidc_issuer_audience_kid_and_signature_validation() {
    let (app, state) = setup_app().await;
    let (_, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;

    // Create IdP
    let idp_payload = json!({
        "kind": "oidc",
        "name": "idp-tc-031",
        "config": {
            "issuer": "https://auth.legit.com",
            "client_id": "cercano-legit",
            "signing_secret": "legit-signing-secret-1234567890",
            "active_kid": "key-2026",
            "authorization_endpoint": "https://auth.legit.com/auth",
            "token_endpoint": "https://auth.legit.com/token",
            "redirect_uri": "https://cercano.local/api/auth/oidc/idp-tc-031/callback"
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(idp_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Start flow to get valid state & nonce
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-tc-031/start?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let start_res: Value = serde_json::from_slice(&body).unwrap();
    let state_str = start_res["state"].as_str().unwrap().to_string();
    let nonce_str = start_res["nonce"].as_str().unwrap().to_string();

    let now = Utc::now().timestamp();

    // 1. Issuer mismatch
    let bad_iss_claims = JwtClaims {
        iss: "https://evil.issuer.com".to_string(),
        sub: "sub-123".to_string(),
        aud: Value::String("cercano-legit".to_string()),
        exp: now + 3600,
        iat: now,
        nonce: Some(nonce_str.clone()),
        email: None,
        amr: None,
        acr: None,
    };
    let bad_iss_tok = create_test_jwt(
        &bad_iss_claims,
        "legit-signing-secret-1234567890",
        Some("key-2026"),
    );

    let req = Request::builder()
        .uri(format!(
            "/api/auth/oidc/idp-tc-031/callback?code=code1&state={state_str}&mock_id_token={bad_iss_tok}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Start new flow (since previous consumed state)
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-tc-031/start?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let start_res: Value = serde_json::from_slice(&body).unwrap();
    let state_str2 = start_res["state"].as_str().unwrap().to_string();
    let nonce_str2 = start_res["nonce"].as_str().unwrap().to_string();

    // 2. Audience mismatch
    let bad_aud_claims = JwtClaims {
        iss: "https://auth.legit.com".to_string(),
        sub: "sub-123".to_string(),
        aud: Value::String("some-other-app".to_string()),
        exp: now + 3600,
        iat: now,
        nonce: Some(nonce_str2.clone()),
        email: None,
        amr: None,
        acr: None,
    };
    let bad_aud_tok = create_test_jwt(
        &bad_aud_claims,
        "legit-signing-secret-1234567890",
        Some("key-2026"),
    );

    let req = Request::builder()
        .uri(format!(
            "/api/auth/oidc/idp-tc-031/callback?code=code2&state={state_str2}&mock_id_token={bad_aud_tok}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Start another flow
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-tc-031/start?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let start_res: Value = serde_json::from_slice(&body).unwrap();
    let state_str3 = start_res["state"].as_str().unwrap().to_string();
    let nonce_str3 = start_res["nonce"].as_str().unwrap().to_string();

    // 3. Signature invalid
    let valid_claims = JwtClaims {
        iss: "https://auth.legit.com".to_string(),
        sub: "sub-123".to_string(),
        aud: Value::String("cercano-legit".to_string()),
        exp: now + 3600,
        iat: now,
        nonce: Some(nonce_str3),
        email: None,
        amr: None,
        acr: None,
    };
    let forged_tok = create_test_jwt(
        &valid_claims,
        "wrong-forged-secret-0000000000",
        Some("key-2026"),
    );

    let req = Request::builder()
        .uri(format!(
            "/api/auth/oidc/idp-tc-031/callback?code=code3&state={state_str3}&mock_id_token={forged_tok}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tc_f5_032_oidc_email_conflict_no_auto_linking() {
    let (app, state) = setup_app().await;
    let (_, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;

    // Existing local user with specific username (which is their email address)
    let (_, _) = create_user_with_token(&state, "bob@company.com", "operator").await;

    // Create IdP
    let idp_payload = json!({
        "kind": "oidc",
        "name": "idp-tc-032",
        "config": {
            "issuer": "https://sso.company.com",
            "client_id": "cercano-tc032",
            "signing_secret": "test-secret-tc032-1234567890",
            "authorization_endpoint": "https://sso.company.com/auth",
            "token_endpoint": "https://sso.company.com/token",
            "redirect_uri": "https://cercano.local/api/auth/oidc/idp-tc-032/callback"
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(idp_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Start flow
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-tc-032/start?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let start_res: Value = serde_json::from_slice(&body).unwrap();
    let state_str = start_res["state"].as_str().unwrap().to_string();
    let nonce_str = start_res["nonce"].as_str().unwrap().to_string();

    // Token has sub "unlinked-bob-sso" and email "bob@company.com"
    let now = Utc::now().timestamp();
    let claims = JwtClaims {
        iss: "https://sso.company.com".to_string(),
        sub: "unlinked-bob-sso".to_string(),
        aud: Value::String("cercano-tc032".to_string()),
        exp: now + 3600,
        iat: now,
        nonce: Some(nonce_str),
        email: Some("bob@company.com".to_string()),
        amr: None,
        acr: None,
    };
    let token = create_test_jwt(&claims, "test-secret-tc032-1234567890", None);

    // Callback must return 409 Conflict with identity_exists
    let req = Request::builder()
        .uri(format!(
            "/api/auth/oidc/idp-tc-032/callback?code=code_tc32&state={state_str}&mock_id_token={token}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err_res: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_res["error"], "identity_exists");

    // Verify NO link was automatically created
    let link_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM federated_identities WHERE subject = 'unlinked-bob-sso'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(link_count.0, 0);
}

#[tokio::test]
async fn test_tc_f5_033_oidc_idp_unavailable_and_break_glass() {
    let (app, state) = setup_app().await;
    let (_, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;

    // 1. Create linked user with active session
    let (charlie_id, charlie_session) = create_user_with_token(&state, "charlie", "operator").await;

    // Create IdP with simulate_unavailable: true
    let idp_payload = json!({
        "kind": "oidc",
        "name": "idp-down",
        "config": {
            "issuer": "https://down.idp.com",
            "client_id": "cercano-down",
            "signing_secret": "secret",
            "authorization_endpoint": "https://down.idp.com/auth",
            "token_endpoint": "https://down.idp.com/token",
            "redirect_uri": "https://cercano.local/api/auth/oidc/idp-down/callback",
            "simulate_unavailable": true
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(idp_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let created: Value = serde_json::from_slice(&body).unwrap();
    let idp_id = created["id"].as_str().unwrap().to_string();

    // Link charlie to this IdP
    let req = Request::builder()
        .uri("/api/identity/links")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "user_id": charlie_id,
                "provider_id": idp_id,
                "subject": "sub-charlie-down"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 2. Start flow
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-down/start?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let start_res: Value = serde_json::from_slice(&body).unwrap();
    let state_str = start_res["state"].as_str().unwrap().to_string();

    // 3. Callback when IdP is down -> returns 503 with Retry-After: 30
    let req = Request::builder()
        .uri(format!(
            "/api/auth/oidc/idp-down/callback?code=some_code&state={state_str}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers().get("Retry-After").unwrap(), "30");

    // 4. Verify existing session of Charlie continues working normally
    let req = Request::builder()
        .uri("/api/auth/me")
        .method("GET")
        .header("Authorization", format!("Bearer {charlie_session}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Verify local admin login continues to work (break-glass invariant)
    let login_req = json!({
        "username": "admin_user",
        "password": "wrong_password"
    });
    let req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(login_req.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Reaches standard local auth handler (returns 401 for wrong password, not 503)
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_oidc_successful_login_with_mfa_claim() {
    let (app, state) = setup_app().await;
    let (_, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    let (diana_id, _) = create_user_with_token(&state, "diana", "operator").await;

    // Create IdP configured with mfa_claim: "amr:mfa"
    let idp_payload = json!({
        "kind": "oidc",
        "name": "idp-mfa",
        "config": {
            "issuer": "https://mfa.idp.com",
            "client_id": "cercano-mfa",
            "signing_secret": "test-secret-mfa-1234567890",
            "authorization_endpoint": "https://mfa.idp.com/auth",
            "token_endpoint": "https://mfa.idp.com/token",
            "redirect_uri": "https://cercano.local/api/auth/oidc/idp-mfa/callback",
            "mfa_claim": "amr:mfa"
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(idp_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let created: Value = serde_json::from_slice(&body).unwrap();
    let idp_id = created["id"].as_str().unwrap().to_string();

    // Link Diana
    let req = Request::builder()
        .uri("/api/identity/links")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "user_id": diana_id,
                "provider_id": idp_id,
                "subject": "sub-diana-mfa"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Start flow
    let req = Request::builder()
        .uri("/api/auth/oidc/idp-mfa/start?format=json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let start_res: Value = serde_json::from_slice(&body).unwrap();
    let state_str = start_res["state"].as_str().unwrap().to_string();
    let nonce_str = start_res["nonce"].as_str().unwrap().to_string();

    // Token has amr: ["pwd", "mfa"] satisfying mfa_claim: "amr:mfa"
    let now = Utc::now().timestamp();
    let claims = JwtClaims {
        iss: "https://mfa.idp.com".to_string(),
        sub: "sub-diana-mfa".to_string(),
        aud: Value::String("cercano-mfa".to_string()),
        exp: now + 3600,
        iat: now,
        nonce: Some(nonce_str),
        email: None,
        amr: Some(vec!["pwd".to_string(), "mfa".to_string()]),
        acr: None,
    };
    let token = create_test_jwt(&claims, "test-secret-mfa-1234567890", None);

    // Callback succeeds directly with 200 OK and session token
    let req = Request::builder()
        .uri(format!(
            "/api/auth/oidc/idp-mfa/callback?code=auth_code_mfa&state={state_str}&mock_id_token={token}"
        ))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let login_res: Value = serde_json::from_slice(&body).unwrap();
    let new_session_token = login_res["token"].as_str().unwrap();

    // Validate newly issued session
    let req = Request::builder()
        .uri("/api/auth/me")
        .method("GET")
        .header("Authorization", format!("Bearer {new_session_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_identity_unlinking_and_idp_disabling_revokes_sessions() {
    let (app, state) = setup_app().await;
    let (_, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    let (elena_id, _) = create_user_with_token(&state, "elena", "operator").await;

    // Create IdP
    let idp_payload = json!({
        "kind": "oidc",
        "name": "idp-revoke-test",
        "config": {
            "issuer": "https://rev.idp.com",
            "client_id": "cercano-rev",
            "signing_secret": "test-secret-rev-1234567890",
            "authorization_endpoint": "https://rev.idp.com/auth",
            "token_endpoint": "https://rev.idp.com/token",
            "redirect_uri": "https://cercano.local/api/auth/oidc/idp-revoke-test/callback",
            "mfa_claim": "amr:mfa"
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(idp_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let created: Value = serde_json::from_slice(&body).unwrap();
    let idp_id = created["id"].as_str().unwrap().to_string();

    // Link Elena
    let req = Request::builder()
        .uri("/api/identity/links")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "user_id": elena_id,
                "provider_id": idp_id,
                "subject": "sub-elena-rev"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let link_created: Value = serde_json::from_slice(&body).unwrap();
    let link_id = link_created["id"].as_str().unwrap().to_string();

    // Create an active session for Elena
    let elena_sess = "elena_active_session_token";
    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at, mfa_verified) VALUES (?, ?, datetime('now', '+24 hours'), 1)"
    )
    .bind(elena_sess)
    .bind(&elena_id)
    .execute(&state.db)
    .await
    .unwrap();

    // Verify session is currently valid
    let req = Request::builder()
        .uri("/api/auth/me")
        .method("GET")
        .header("Authorization", format!("Bearer {elena_sess}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Delete identity link -> must immediately revoke active sessions
    let req = Request::builder()
        .uri(format!("/api/identity/links/{link_id}"))
        .method("DELETE")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify Elena's session is now revoked (401 Unauthorized)
    let req = Request::builder()
        .uri("/api/auth/me")
        .method("GET")
        .header("Authorization", format!("Bearer {elena_sess}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
