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

//! Integration tests for Cercano Chat Device Authentication (F4.5-03).
//!
//! Covers test cases:
//! - TC-F4.5-001: Valid device registration & authentication
//! - TC-F4.5-002: Re-registration with key mismatch rejected (409 Conflict)
//! - TC-F4.5-003: Reused challenge nonce rejected (401 Unauthorized)
//! - TC-F4.5-004: Expired challenge nonce rejected (401 Unauthorized)
//! - TC-F4.5-005: Invalid signature rejected (401 Unauthorized)
//! - TC-F4.5-006: Expired or revoked chat token rejected
//! - Identity reset: POST /api/chat/devices/:id/reset

use std::sync::Arc;

use argon2::password_hash::rand_core::OsRng;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use cercano_api::{config::Config, create_app, db::init_db, AppState};

const TEST_INGEST_TOKEN: &str = "test-client-ingest-token-32bytes-secret!!";

struct TestEnv {
    app: axum::Router,
    db: sqlx::SqlitePool,
    #[allow(dead_code)]
    audit: Arc<audit_core::AuditStore>,
}

async fn setup() -> TestEnv {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let config = Config {
        client_ingest_token: TEST_INGEST_TOKEN.to_string(),
        chat_enabled: true,
        ..Default::default()
    };
    let state = AppState::new(config, db.clone(), audit.clone());
    TestEnv {
        app: create_app(state),
        db,
        audit,
    }
}

async fn request_with_headers(
    env: &TestEnv,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
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

fn generate_keypair() -> (SigningKey, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_base64 = base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
    (signing_key, pubkey_base64)
}

fn sign_nonce(signing_key: &SigningKey, nonce_base64: &str) -> String {
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(nonce_base64)
        .expect("Nonce must be valid base64");
    let signature = signing_key.sign(&nonce_bytes);
    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
}

#[tokio::test]
async fn test_tc_f4_5_001_valid_device_registration_and_auth() {
    let env = setup().await;
    let (signing_key, pubkey_base64) = generate_keypair();
    let device_id = "device_test_001";

    // 1. Register device with deployment token
    let (status, res) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey_base64,
            "display_name": "PC-TEST-001"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(res["status"], "registered");
    assert_eq!(res["device_id"], device_id);

    // 2. Register again with exact same key -> 200 already_registered
    let (status, res) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey_base64,
            "display_name": "PC-TEST-001"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["status"], "already_registered");

    // 3. Request challenge
    let (status, chal) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/challenge",
        &[("x-forwarded-proto", "https")],
        Some(json!({ "device_id": device_id })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let challenge_id = chal["challenge_id"].as_str().unwrap();
    let nonce = chal["nonce"].as_str().unwrap();
    assert!(!challenge_id.is_empty());
    assert!(!nonce.is_empty());

    // 4. Sign nonce and verify
    let signature_base64 = sign_nonce(&signing_key, nonce);

    let (status, ver) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/verify",
        &[],
        Some(json!({
            "challenge_id": challenge_id,
            "signature": signature_base64
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let token = ver["token"].as_str().unwrap();
    assert!(token.starts_with("cercano_chat_"));
    assert_eq!(token.len(), 13 + 64);

    // 5. Verify audit event was recorded
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'chat.device.registered'",
    )
    .fetch_one(&env.db)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_tc_f4_5_002_key_mismatch_rejected_with_409() {
    let env = setup().await;
    let (_sk1, pubkey1) = generate_keypair();
    let (_sk2, pubkey2) = generate_keypair();
    let device_id = "device_test_002";

    // Register with key 1
    let (status, _) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey1,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Attempt to register with key 2 for the same device_id -> 409 Conflict
    let (status, res) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey2,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(res["code"], "key_mismatch");

    // Verify key_mismatch audit event
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'chat.device.key_mismatch'",
    )
    .fetch_one(&env.db)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_tc_f4_5_003_reused_challenge_nonce_rejected() {
    let env = setup().await;
    let (signing_key, pubkey) = generate_keypair();
    let device_id = "device_test_003";

    // Register
    let (status, _) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Challenge
    let (_, chal) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/challenge",
        &[("x-forwarded-proto", "https")],
        Some(json!({ "device_id": device_id })),
    )
    .await;
    let challenge_id = chal["challenge_id"].as_str().unwrap();
    let nonce = chal["nonce"].as_str().unwrap();
    let signature = sign_nonce(&signing_key, nonce);

    // First verification -> 200 OK
    let (status, _) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/verify",
        &[],
        Some(json!({
            "challenge_id": challenge_id,
            "signature": signature
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second verification with same challenge_id -> 401 Unauthorized
    let (status, res) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/verify",
        &[],
        Some(json!({
            "challenge_id": challenge_id,
            "signature": signature
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(res["message"], "Reto ya utilizado.");

    // Verify audit
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE action = 'chat.auth.failed'")
            .fetch_one(&env.db)
            .await
            .unwrap();
    assert!(count >= 1);
}

#[tokio::test]
async fn test_tc_f4_5_004_expired_challenge_nonce_rejected() {
    let env = setup().await;
    let (signing_key, pubkey) = generate_keypair();
    let device_id = "device_test_004";

    // Register
    let (status, _) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Challenge
    let (_, chal) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/challenge",
        &[("x-forwarded-proto", "https")],
        Some(json!({ "device_id": device_id })),
    )
    .await;
    let challenge_id = chal["challenge_id"].as_str().unwrap();
    let nonce = chal["nonce"].as_str().unwrap();
    let signature = sign_nonce(&signing_key, nonce);

    // Manually expire the nonce in SQLite
    sqlx::query(
        "UPDATE chat_auth_nonces SET expires_at = datetime('now', '-5 minutes') WHERE id = ?",
    )
    .bind(challenge_id)
    .execute(&env.db)
    .await
    .unwrap();

    // Verify -> 401 Unauthorized
    let (status, res) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/verify",
        &[],
        Some(json!({
            "challenge_id": challenge_id,
            "signature": signature
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(res["message"], "Reto caducado.");
}

#[tokio::test]
async fn test_tc_f4_5_005_invalid_signature_rejected() {
    let env = setup().await;
    let (_sk1, pubkey1) = generate_keypair();
    let (sk2, _pubkey2) = generate_keypair(); // Different signing key
    let device_id = "device_test_005";

    // Register with key 1
    let (status, _) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey1,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Challenge
    let (_, chal) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/challenge",
        &[("x-forwarded-proto", "https")],
        Some(json!({ "device_id": device_id })),
    )
    .await;
    let challenge_id = chal["challenge_id"].as_str().unwrap();
    let nonce = chal["nonce"].as_str().unwrap();

    // Sign with key 2 (wrong key)
    let invalid_signature = sign_nonce(&sk2, nonce);

    let (status, res) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/verify",
        &[],
        Some(json!({
            "challenge_id": challenge_id,
            "signature": invalid_signature
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(res["message"], "Firma inválida.");
}

#[tokio::test]
async fn test_tc_f4_5_006_administrative_reset_invalidates_and_permits_new_key() {
    let env = setup().await;
    let (sk1, pubkey1) = generate_keypair();
    let (_sk2, pubkey2) = generate_keypair();
    let device_id = "device_test_006";

    // Seed admin user and session
    let admin_id = "admin_reset_user";
    sqlx::query("INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'admin', 'hash', 'admin', 1)")
        .bind(admin_id)
        .execute(&env.db)
        .await
        .unwrap();

    let admin_token = "cercano_sess_admin_test_reset_token";
    sqlx::query("INSERT INTO sessions (token, user_id, expires_at, mfa_verified) VALUES (?, ?, datetime('now', '+1 hour'), 1)")
        .bind(admin_token)
        .bind(admin_id)
        .execute(&env.db)
        .await
        .unwrap();

    // Register with key 1
    let (status, _) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey1,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Challenge and get session token with key 1
    let (_, chal) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/challenge",
        &[("x-forwarded-proto", "https")],
        Some(json!({ "device_id": device_id })),
    )
    .await;
    let challenge_id = chal["challenge_id"].as_str().unwrap();
    let nonce = chal["nonce"].as_str().unwrap();
    let signature = sign_nonce(&sk1, nonce);
    let (_, ver) = request_with_headers(
        &env,
        "POST",
        "/api/chat/auth/verify",
        &[],
        Some(json!({
            "challenge_id": challenge_id,
            "signature": signature
        })),
    )
    .await;
    let session_token = ver["token"].as_str().unwrap();

    // Reset device via admin
    let (status, res) = request_with_headers(
        &env,
        "POST",
        &format!("/api/chat/devices/{device_id}/reset"),
        &[("authorization", &format!("Bearer {admin_token}"))],
        Some(json!({ "reason": "Hardware change" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["status"], "reset");

    // Old session token is now deleted/invalidated by reset cascade
    let session_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_device_sessions WHERE token = ?")
            .bind(session_token)
            .fetch_one(&env.db)
            .await
            .unwrap();
    assert_eq!(session_count, 0);

    // Device can now register with new key 2 cleanly!
    let (status, res) = request_with_headers(
        &env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey2,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(res["status"], "registered");

    // Verify audit recorded chat.device.revoked
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'chat.device.revoked'",
    )
    .fetch_one(&env.db)
    .await
    .unwrap();
    assert_eq!(count, 1);
}
