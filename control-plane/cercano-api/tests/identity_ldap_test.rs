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

//! Integration tests for F5-08: LDAP Authentication over TLS & Explicit Group Mapping.
//!
//! Validates:
//! - TC-F5-040: LDAP without TLS (`ldap://` without `start_tls`) is rejected at config creation.
//! - TC-F5-041: Invalid credentials and nonexistent accounts return the exact same generic error (no enumeration).
//! - TC-F5-042: Server down or timeout yields 503 without creating sessions or elevating privileges.
//! - TC-F5-043: Allowlist group mapping: unlisted group denies access (or falls back); admin requires explicit entry.
//! - TC-F5-044: Successful LDAP login returns 202 Accepted requiring Cercano TOTP 2FA before issuing session.
//! - RFC 4515 filter escaping prevents LDAP injection.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use cercano_api::config::Config;
use cercano_api::db::init_db;
use cercano_api::identity::ldap::escape_rfc4515;
use cercano_api::{create_app, AppState};

async fn setup_app() -> (axum::Router, AppState) {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let state = AppState::new(Config::default(), db, audit);
    let app = create_app(state.clone());
    (app, state)
}

async fn create_admin_token(state: &AppState) -> String {
    let user_id = uuid::Uuid::new_v4().to_string();
    let token = "admin_test_token_f508".to_string();
    let now = Utc::now().to_rfc3339();
    let pwd_hash = cercano_api::auth::hash_password("admin_pass").unwrap();

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active, created_at)
         VALUES (?, 'admin_ldap_test', ?, 'admin', 1, ?)",
    )
    .bind(&user_id)
    .bind(&pwd_hash)
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

    token
}

#[tokio::test]
async fn test_tc_f5_040_ldap_without_tls_rejected() {
    let (app, state) = setup_app().await;
    let admin_tok = create_admin_token(&state).await;

    // 1. Plain ldap:// without start_tls must be rejected
    let insecure_payload = json!({
        "kind": "ldap",
        "name": "insecure-dir",
        "config": {
            "url": "ldap://ldap.corp.example.com:389",
            "start_tls": false,
            "base_dn": "dc=corp,dc=example,dc=com",
            "bind_dn": "cn=svc_cercano,ou=services,dc=corp,dc=example,dc=com",
            "bind_password": "svc_password_secret",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "group_attr": "memberOf",
            "default_role": "none",
            "timeout_ms": 3000
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(insecure_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "tls_required");

    // Verify it was NOT stored in the database
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM identity_providers WHERE name = 'insecure-dir'")
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(count.0, 0);

    // 2. ldaps:// must be accepted
    let secure_payload = json!({
        "kind": "ldap",
        "name": "secure-ldaps",
        "config": {
            "url": "ldaps://ldap.corp.example.com:636",
            "base_dn": "dc=corp,dc=example,dc=com",
            "bind_dn": "cn=svc_cercano,ou=services,dc=corp,dc=example,dc=com",
            "bind_password": "svc_password_secret",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "group_attr": "memberOf",
            "default_role": "none",
            "timeout_ms": 3000
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(secure_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 3. ldap:// with start_tls: true must be accepted
    let starttls_payload = json!({
        "kind": "ldap",
        "name": "starttls-ldap",
        "config": {
            "url": "ldap://ldap.corp.example.com:389",
            "start_tls": true,
            "base_dn": "dc=corp,dc=example,dc=com",
            "bind_dn": "cn=svc_cercano,ou=services,dc=corp,dc=example,dc=com",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "group_attr": "memberOf",
            "default_role": "none",
            "timeout_ms": 3000
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(starttls_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_tc_f5_041_ldap_invalid_credentials_and_nonexistent_user() {
    let (app, state) = setup_app().await;
    let admin_tok = create_admin_token(&state).await;

    // Create LDAP provider with a mock user
    let idp_payload = json!({
        "kind": "ldap",
        "name": "ldap-auth-test",
        "config": {
            "url": "ldaps://ldap.corp.example.com",
            "base_dn": "dc=corp,dc=example,dc=com",
            "bind_dn": "cn=svc,dc=corp,dc=example,dc=com",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "group_attr": "memberOf",
            "group_allowlist": {
                "cn=operators,ou=groups,dc=corp,dc=example,dc=com": {
                    "role": "operator"
                }
            },
            "default_role": "none",
            "timeout_ms": 3000,
            "mock_users": {
                "existing_user": {
                    "password": "correct_password_123",
                    "groups": ["cn=operators,ou=groups,dc=corp,dc=example,dc=com"]
                }
            }
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

    // 1. Nonexistent user
    let req = Request::builder()
        .uri("/api/auth/ldap/ldap-auth-test/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "username": "completely_nonexistent_user",
                "password": "some_password"
            })
            .to_string(),
        ))
        .unwrap();
    let resp_nonexistent = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp_nonexistent.status(), StatusCode::UNAUTHORIZED);
    let body_nonexistent = resp_nonexistent
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let err_nonexistent: Value = serde_json::from_slice(&body_nonexistent).unwrap();

    // 2. Existing user with wrong password
    let req = Request::builder()
        .uri("/api/auth/ldap/ldap-auth-test/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "username": "existing_user",
                "password": "wrong_password_999"
            })
            .to_string(),
        ))
        .unwrap();
    let resp_wrong_pwd = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp_wrong_pwd.status(), StatusCode::UNAUTHORIZED);
    let body_wrong_pwd = resp_wrong_pwd
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let err_wrong_pwd: Value = serde_json::from_slice(&body_wrong_pwd).unwrap();

    // Verify both errors are identical (no user enumeration)
    assert_eq!(err_nonexistent["error"], "invalid_credentials");
    assert_eq!(err_wrong_pwd["error"], "invalid_credentials");
    assert_eq!(err_nonexistent["message"], err_wrong_pwd["message"]);
}

#[tokio::test]
async fn test_tc_f5_042_ldap_server_unavailable_or_timeout() {
    let (app, state) = setup_app().await;
    let admin_tok = create_admin_token(&state).await;

    // Create LDAP provider with simulate_unavailable: true
    let idp_payload = json!({
        "kind": "ldap",
        "name": "ldap-down",
        "config": {
            "url": "ldaps://unreachable.ldap.corp.com",
            "base_dn": "dc=corp,dc=example,dc=com",
            "bind_dn": "cn=svc,dc=corp,dc=example,dc=com",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "default_role": "none",
            "timeout_ms": 3000,
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

    // Attempt LDAP login
    let req = Request::builder()
        .uri("/api/auth/ldap/ldap-down/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "username": "any_user",
                "password": "any_password"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers().get("Retry-After").unwrap(), "30");

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"], "ldap_unavailable");

    // Also verify timeout > 5000 is rejected at creation
    let high_timeout_payload = json!({
        "kind": "ldap",
        "name": "ldap-high-timeout",
        "config": {
            "url": "ldaps://ldap.corp.example.com",
            "base_dn": "dc=corp,dc=example,dc=com",
            "bind_dn": "cn=svc,dc=corp,dc=example,dc=com",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "timeout_ms": 10000 // exceeds 5000 ms limit
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(high_timeout_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_tc_f5_043_ldap_group_allowlist_and_explicit_admin() {
    let (app, state) = setup_app().await;
    let admin_tok = create_admin_token(&state).await;

    // 1. Attempting to set default_role to 'admin' is rejected
    let bad_default_payload = json!({
        "kind": "ldap",
        "name": "bad-admin-default",
        "config": {
            "url": "ldaps://ldap.corp.com",
            "base_dn": "dc=corp,dc=com",
            "bind_dn": "cn=svc,dc=corp,dc=com",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "default_role": "admin" // forbidden
        }
    });

    let req = Request::builder()
        .uri("/api/idp")
        .method("POST")
        .header("Authorization", format!("Bearer {admin_tok}"))
        .header("Content-Type", "application/json")
        .body(Body::from(bad_default_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 2. Create provider with explicit allowlist
    let idp_payload = json!({
        "kind": "ldap",
        "name": "ldap-allowlist-test",
        "config": {
            "url": "ldaps://ldap.corp.com",
            "base_dn": "dc=corp,dc=com",
            "bind_dn": "cn=svc,dc=corp,dc=com",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "default_role": "none",
            "group_allowlist": {
                "cn=helpdesk,ou=groups,dc=corp,dc=com": {
                    "role": "operator"
                },
                "cn=domain_admins,ou=groups,dc=corp,dc=com": {
                    "role": "admin"
                }
            },
            "mock_users": {
                "user_unlisted_group": {
                    "password": "pass",
                    "groups": ["cn=contractors,ou=groups,dc=corp,dc=com"]
                },
                "user_helpdesk": {
                    "password": "pass",
                    "groups": ["cn=helpdesk,ou=groups,dc=corp,dc=com"]
                },
                "user_admin": {
                    "password": "pass",
                    "groups": ["cn=domain_admins,ou=groups,dc=corp,dc=com"]
                }
            }
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

    // 3. User with unlisted group is rejected (403 Forbidden: no_authorized_role)
    let req = Request::builder()
        .uri("/api/auth/ldap/ldap-allowlist-test/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "username": "user_unlisted_group",
                "password": "pass"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4. User in helpdesk group receives 'operator' role
    let req = Request::builder()
        .uri("/api/auth/ldap/ldap-allowlist-test/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "username": "user_helpdesk",
                "password": "pass"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let res: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(res["role"], "operator");

    // 5. User in domain_admins receives 'admin' role
    let req = Request::builder()
        .uri("/api/auth/ldap/ldap-allowlist-test/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "username": "user_admin",
                "password": "pass"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let res: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(res["role"], "admin");
}

#[tokio::test]
async fn test_tc_f5_044_ldap_login_mandates_cercano_totp_2fa() {
    let (app, state) = setup_app().await;
    let admin_tok = create_admin_token(&state).await;

    // Create LDAP provider
    let idp_payload = json!({
        "kind": "ldap",
        "name": "ldap-2fa-test",
        "config": {
            "url": "ldaps://ldap.corp.com",
            "base_dn": "dc=corp,dc=com",
            "bind_dn": "cn=svc,dc=corp,dc=com",
            "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
            "group_allowlist": {
                "cn=staff,ou=groups,dc=corp,dc=com": {
                    "role": "auditor"
                }
            },
            "mock_users": {
                "frank": {
                    "password": "frank_secret_password",
                    "groups": ["cn=staff,ou=groups,dc=corp,dc=com"]
                }
            }
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

    // 1. Frank logs in with correct LDAP credentials: MUST receive 202 ACCEPTED with mfa_token
    let req = Request::builder()
        .uri("/api/auth/ldap/ldap-2fa-test/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "username": "frank",
                "password": "frank_secret_password"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let res: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(res["mfa_required"], true);
    let mfa_token = res["mfa_token"].as_str().unwrap().to_string();

    // Verify NO session token was issued directly
    assert!(res.get("token").is_none());

    // 2. Verify mfa_challenges table contains the pending challenge
    let challenge: Option<(String,)> = sqlx::query_as(
        "SELECT user_id FROM mfa_challenges WHERE token = ? AND expires_at > datetime('now')",
    )
    .bind(&mfa_token)
    .fetch_optional(&state.db)
    .await
    .unwrap();

    assert!(challenge.is_some());
}

#[test]
fn test_rfc4515_filter_escaping() {
    assert_eq!(escape_rfc4515("normal_user"), "normal_user");
    assert_eq!(escape_rfc4515("admin*"), "admin\\2a");
    assert_eq!(escape_rfc4515("user(with)parens"), "user\\28with\\29parens");
    assert_eq!(escape_rfc4515("back\\slash"), "back\\5cslash");
    assert_eq!(escape_rfc4515("null\0byte"), "null\\00byte");
    assert_eq!(
        escape_rfc4515("*)(|&(user=*)"),
        "\\2a\\29\\28|&\\28user=\\2a\\29"
    );
}
