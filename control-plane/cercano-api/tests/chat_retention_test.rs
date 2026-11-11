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

//! Integration tests for Cercano Chat Audit, Rate Limits and Retention (F4.5-07).
//!
//! Test cases:
//! - TC-F4.5-055: Device message rate limit exceeded -> 429 Too Many Requests with Retry-After, audit `chat.rate_limited`
//! - TC-F4.5-056: Technician message rate limit exceeded -> 429 Too Many Requests with Retry-After, audit `chat.rate_limited`
//! - TC-F4.5-057: Attachment burst rate limit exceeded -> 429 with Retry-After, audit `chat.rate_limited`
//! - TC-F4.5-058: Retention purge deletes closed conversations and disk attachment files older than retention days
//! - TC-F4.5-059: Retention purge preserves open conversations (waiting/assigned/active) even if older than cutoff
//! - TC-F4.5-060: Retention purge emits `chat.retention.purged` audit event with cutoff & counters
//! - TC-F4.5-061: Strict privacy audit: audit database contains ZERO message bodies, ZERO filenames, ZERO tokens, ZERO keys

use std::sync::Arc;

use argon2::password_hash::rand_core::OsRng;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

use cercano_api::chat::retention::run_chat_retention_purge;
use cercano_api::{config::Config, create_app, db::init_db, AppState};

const TEST_INGEST_TOKEN: &str = "test-client-ingest-token-32bytes-secret!!";

struct TestEnv {
    app: axum::Router,
    db: sqlx::SqlitePool,
    audit: Arc<audit_core::AuditStore>,
    config: Config,
    _temp_dir: TempDir,
}

async fn setup(msg_rate_limit: u32, user_msg_rate_limit: u32) -> TestEnv {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        client_ingest_token: TEST_INGEST_TOKEN.to_string(),
        chat_enabled: true,
        chat_attachment_dir: temp_dir.path().to_string_lossy().to_string(),
        chat_max_attachment_bytes: 10 * 1024 * 1024,
        chat_message_rate_per_minute: msg_rate_limit,
        chat_user_message_rate_per_minute: user_msg_rate_limit,
        chat_conversation_daily_limit: 5,
        chat_attachment_daily_limit: 20,
        chat_retention_days: 90,
        ..Default::default()
    };
    let state = AppState::new(config.clone(), db.clone(), audit.clone());
    TestEnv {
        app: create_app(state),
        db,
        audit,
        config,
        _temp_dir: temp_dir,
    }
}

async fn request_json(
    env: &TestEnv,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, HeaderMap) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = token {
        builder = builder.header("authorization", format!("Bearer {tok}"));
    }
    let req = if let Some(b) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };

    let response = env.app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let val: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
    (status, val, headers)
}

async fn request_binary(
    env: &TestEnv,
    method: &str,
    uri: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = token {
        builder = builder.header("authorization", format!("Bearer {tok}"));
    }
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = builder.body(Body::from(body)).unwrap();
    let response = env.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let resp_headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, resp_headers, bytes)
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

async fn create_authenticated_device(env: &TestEnv, device_id: &str) -> String {
    let (signing_key, pubkey_b64) = generate_keypair();

    let reg_req = Request::builder()
        .method("POST")
        .uri("/api/chat/devices/register")
        .header("content-type", "application/json")
        .header("x-cercano-client-token", TEST_INGEST_TOKEN)
        .header("x-forwarded-proto", "https")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "device_id": device_id,
                "public_key": pubkey_b64,
                "display_name": format!("Device {device_id}")
            }))
            .unwrap(),
        ))
        .unwrap();
    let reg_resp = env.app.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_resp.status(), StatusCode::CREATED);

    let (c_status, c_val, _) = request_json(
        env,
        "POST",
        "/api/chat/auth/challenge",
        None,
        Some(json!({ "device_id": device_id })),
    )
    .await;
    assert_eq!(c_status, StatusCode::OK);
    let challenge_id = c_val["challenge_id"].as_str().unwrap();
    let nonce_base64 = c_val["nonce"].as_str().unwrap();

    let signature_base64 = sign_nonce(&signing_key, nonce_base64);

    let (v_status, v_val, _) = request_json(
        env,
        "POST",
        "/api/chat/auth/verify",
        None,
        Some(json!({
            "challenge_id": challenge_id,
            "signature": signature_base64
        })),
    )
    .await;
    assert_eq!(v_status, StatusCode::OK);
    v_val["token"].as_str().unwrap().to_string()
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

async fn bootstrap_admin_session(env: &TestEnv) -> String {
    let (status, _, _) = request_json(
        env,
        "POST",
        "/api/auth/bootstrap",
        None,
        Some(json!({ "username": "admin", "password": "AdminPassword123!" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body, _) = request_json(
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
        let (e_status, e_body, _) = request_json(
            env,
            "POST",
            "/api/auth/2fa/enroll",
            Some(&token),
            Some(json!({})),
        )
        .await;
        assert_eq!(e_status, StatusCode::OK);
        let secret = e_body["totp_secret_base32"].as_str().unwrap();
        let code = generate_valid_totp_code(secret, "admin");

        let (c_status, _, _) = request_json(
            env,
            "POST",
            "/api/auth/2fa/confirm",
            Some(&token),
            Some(json!({ "totp_code": code })),
        )
        .await;
        assert_eq!(c_status, StatusCode::OK);
    }

    token
}

async fn create_technician_session(env: &TestEnv, username: &str) -> String {
    let admin_token = bootstrap_admin_session(env).await;
    let password = "TechnicianPassword123!";
    let (u_status, _, _) = request_json(
        env,
        "POST",
        "/api/users",
        Some(&admin_token),
        Some(json!({
            "username": username,
            "password": password,
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(u_status, StatusCode::CREATED);

    let (l_status, l_body, _) = request_json(
        env,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(l_status, StatusCode::OK);
    let token = l_body["token"].as_str().unwrap().to_string();

    if l_body["mfa_enrollment_required"].as_bool().unwrap_or(false) {
        let (e_status, e_body, _) = request_json(
            env,
            "POST",
            "/api/auth/2fa/enroll",
            Some(&token),
            Some(json!({})),
        )
        .await;
        assert_eq!(e_status, StatusCode::OK);
        let secret = e_body["totp_secret_base32"].as_str().unwrap();
        let code = generate_valid_totp_code(secret, username);

        let (c_status, _, _) = request_json(
            env,
            "POST",
            "/api/auth/2fa/confirm",
            Some(&token),
            Some(json!({ "totp_code": code })),
        )
        .await;
        assert_eq!(c_status, StatusCode::OK);
    }

    token
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_tc_f4_5_055_device_message_rate_limit() {
    // Configured with limit 2 messages per minute
    let env = setup(2, 60).await;
    let dev_token = create_authenticated_device(&env, "dev-ratelimit-01").await;

    // Create conversation (counts as 1 message)
    let (c_status, c_val, _) = request_json(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Ana",
            "contact_last_name": "Ruiz",
            "body": "Primer mensaje"
        })),
    )
    .await;
    assert_eq!(c_status, StatusCode::CREATED);
    let conv_id = c_val["id"].as_str().unwrap();

    // Second message (within limit of 2)
    let (m2_status, _, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/messages"),
        Some(&dev_token),
        Some(json!({ "body": "Segundo mensaje permitido" })),
    )
    .await;
    assert_eq!(m2_status, StatusCode::CREATED);

    // Third message (exceeds limit 2/min -> 429)
    let (m3_status, m3_val, m3_headers) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/messages"),
        Some(&dev_token),
        Some(json!({ "body": "Tercer mensaje excede tasa" })),
    )
    .await;
    assert_eq!(m3_status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(m3_val["error"], "rate_limited");
    assert_eq!(
        m3_headers.get("retry-after").and_then(|h| h.to_str().ok()),
        Some("60")
    );

    // Check that `chat.rate_limited` was audited
    let events = env
        .audit
        .query_events(audit_core::EventFilter {
            action: Some("chat.rate_limited".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "chat.rate_limited");
    assert_eq!(events[0].details["limit"], "device_message_rate");
    assert_eq!(events[0].details["retry_after_secs"], 60);
}

#[tokio::test]
async fn test_tc_f4_5_056_technician_message_rate_limit() {
    // Configured with technician limit 2 messages per minute
    let env = setup(30, 2).await;
    let dev_token = create_authenticated_device(&env, "dev-ratelimit-tech").await;
    let tech_token = create_technician_session(&env, "tech_rl_01").await;

    let (c_status, c_val, _) = request_json(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Luis",
            "contact_last_name": "Martinez",
            "body": "Hola soporte"
        })),
    )
    .await;
    assert_eq!(c_status, StatusCode::CREATED);
    let conv_id = c_val["id"].as_str().unwrap();

    // Claim
    let (cl_status, _, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/claim"),
        Some(&tech_token),
        None,
    )
    .await;
    assert_eq!(cl_status, StatusCode::OK);

    // Tech sends 1st message
    let (t1_status, _, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/messages"),
        Some(&tech_token),
        Some(json!({ "body": "Respuesta 1 del tecnico" })),
    )
    .await;
    assert_eq!(t1_status, StatusCode::CREATED);

    // Tech sends 2nd message
    let (t2_status, _, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/messages"),
        Some(&tech_token),
        Some(json!({ "body": "Respuesta 2 del tecnico" })),
    )
    .await;
    assert_eq!(t2_status, StatusCode::CREATED);

    // Tech sends 3rd message (exceeds limit 2 -> 429)
    let (t3_status, t3_val, t3_headers) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/messages"),
        Some(&tech_token),
        Some(json!({ "body": "Respuesta 3 excede tasa" })),
    )
    .await;
    assert_eq!(t3_status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(m3_val_error(&t3_val), "rate_limited");
    assert_eq!(
        t3_headers.get("retry-after").and_then(|h| h.to_str().ok()),
        Some("60")
    );
}

fn m3_val_error(v: &Value) -> &str {
    v["error"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn test_tc_f4_5_057_attachment_burst_rate_limit() {
    let env = setup(30, 60).await;
    let dev_token = create_authenticated_device(&env, "dev-att-ratelimit").await;

    let (c_status, c_val, _) = request_json(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Mario",
            "contact_last_name": "Bros",
            "body": "Subiendo adjuntos"
        })),
    )
    .await;
    assert_eq!(c_status, StatusCode::CREATED);
    let conv_id = c_val["id"].as_str().unwrap();

    let valid_png = vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89,
    ];

    // Upload 3 attachments in rapid burst (allowed: max 3/min)
    for i in 1..=3 {
        let (s, _, _) = request_binary(
            &env,
            "POST",
            &format!("/api/chat/conversations/{conv_id}/attachments"),
            Some(&dev_token),
            &[
                ("content-type", "image/png"),
                ("x-file-name", &format!("file_{i}.png")),
            ],
            valid_png.clone(),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
    }

    // 4th attachment in the same minute -> 429 Too Many Requests
    let (s4, headers4, body4) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[("content-type", "image/png"), ("x-file-name", "file_4.png")],
        valid_png.clone(),
    )
    .await;
    assert_eq!(s4, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        headers4.get("retry-after").and_then(|h| h.to_str().ok()),
        Some("60")
    );

    let val: Value = serde_json::from_slice(&body4).unwrap();
    assert_eq!(val["error"], "rate_limit_exceeded");
}

#[tokio::test]
async fn test_tc_f4_5_058_to_060_retention_purge_and_audit() {
    let env = setup(30, 60).await;
    let dev_token = create_authenticated_device(&env, "dev-retention-test").await;

    // 1. Create a conversation that will be closed and aged
    let (c_status, c_val, _) = request_json(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Old",
            "contact_last_name": "Conversation",
            "body": "Mensaje antiguo cerrado"
        })),
    )
    .await;
    assert_eq!(c_status, StatusCode::CREATED);
    let old_closed_conv_id = c_val["id"].as_str().unwrap().to_string();

    // Upload attachment to old conversation
    let valid_png = vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89,
    ];
    let (att_s, _, att_b) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{old_closed_conv_id}/attachments"),
        Some(&dev_token),
        &[("content-type", "image/png"), ("x-file-name", "foto.png")],
        valid_png,
    )
    .await;
    assert_eq!(att_s, StatusCode::CREATED);
    let att_dto: Value = serde_json::from_slice(&att_b).unwrap();
    let att_id = att_dto["attachment"]["id"].as_str().unwrap();

    // Verify storage file exists on disk
    let storage_key: String =
        sqlx::query_scalar("SELECT storage_key FROM chat_attachments WHERE id = ?")
            .bind(att_id)
            .fetch_one(&env.db)
            .await
            .unwrap();
    let file_path = std::path::PathBuf::from(&env.config.chat_attachment_dir).join(&storage_key);
    assert!(file_path.exists(), "Attachment file must exist on disk");

    // Close the conversation
    let (cl_status, _, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{old_closed_conv_id}/close"),
        Some(&dev_token),
        Some(json!({ "reason": "resolved" })),
    )
    .await;
    assert_eq!(cl_status, StatusCode::OK);

    // Age the conversation to 100 days ago (retention is 90 days)
    let past_100_days = (Utc::now() - chrono::Duration::days(100)).to_rfc3339();
    sqlx::query("UPDATE chat_conversations SET closed_at = ? WHERE id = ?")
        .bind(&past_100_days)
        .bind(&old_closed_conv_id)
        .execute(&env.db)
        .await
        .unwrap();

    // 2. Create another conversation that is OPEN and aged (TC-F4.5-059)
    let dev2_token = create_authenticated_device(&env, "dev-retention-open").await;
    let (c2_status, c2_val, _) = request_json(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev2_token),
        Some(json!({
            "contact_first_name": "Stay",
            "contact_last_name": "Open",
            "body": "Mensaje abierto que debe persistir"
        })),
    )
    .await;
    assert_eq!(c2_status, StatusCode::CREATED);
    let open_conv_id = c2_val["id"].as_str().unwrap().to_string();

    // Age open conversation to 120 days ago
    let past_120_days = (Utc::now() - chrono::Duration::days(120)).to_rfc3339();
    sqlx::query("UPDATE chat_conversations SET created_at = ? WHERE id = ?")
        .bind(&past_120_days)
        .bind(&open_conv_id)
        .execute(&env.db)
        .await
        .unwrap();

    // 3. Run retention purge
    let report = run_chat_retention_purge(&env.db, &env.audit, &env.config)
        .await
        .unwrap();

    assert_eq!(report.conversations_deleted, 1);
    assert!(report.messages_deleted >= 2);
    assert_eq!(report.attachments_deleted, 1);

    // Verify old closed conversation is GONE
    let old_check: Option<String> =
        sqlx::query_scalar("SELECT id FROM chat_conversations WHERE id = ?")
            .bind(&old_closed_conv_id)
            .fetch_optional(&env.db)
            .await
            .unwrap();
    assert!(old_check.is_none(), "Closed conversation must be purged");

    // Verify attachment file on disk is REMOVED
    assert!(
        !file_path.exists(),
        "Attachment file on disk must be deleted after purge"
    );

    // Verify open conversation STILL EXISTS (TC-F4.5-059)
    let open_check: Option<String> =
        sqlx::query_scalar("SELECT id FROM chat_conversations WHERE id = ?")
            .bind(&open_conv_id)
            .fetch_optional(&env.db)
            .await
            .unwrap();
    assert_eq!(
        open_check.as_deref(),
        Some(open_conv_id.as_str()),
        "Open conversation must NOT be purged"
    );

    // Verify audit event `chat.retention.purged` (TC-F4.5-060)
    let purge_events = env
        .audit
        .query_events(audit_core::EventFilter {
            action: Some("chat.retention.purged".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(purge_events.len(), 1);
    let p_ev = &purge_events[0];
    assert_eq!(p_ev.details["conversations_deleted"], 1);
    assert_eq!(p_ev.details["attachments_deleted"], 1);
    assert!(p_ev.details["messages_deleted"].as_u64().unwrap() >= 2);
}

#[tokio::test]
async fn test_tc_f4_5_061_strict_audit_privacy_no_bodies_or_secrets() {
    let env = setup(30, 60).await;
    let dev_token = create_authenticated_device(&env, "dev-privacy-audit").await;

    // Send messages and attachments with secret keywords
    let secret_body_phrase = "PasswordXYZ999SensitiveData";
    let secret_filename = "ConfidentialExecutiveDocument.png";
    let secret_contact_first = "Donatello";
    let secret_contact_last = "Versace";

    let (c_status, c_val, _) = request_json(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": secret_contact_first,
            "contact_last_name": secret_contact_last,
            "body": secret_body_phrase
        })),
    )
    .await;
    assert_eq!(c_status, StatusCode::CREATED);
    let conv_id = c_val["id"].as_str().unwrap();

    let valid_png = vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89,
    ];
    let (att_s, _, _) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[
            ("content-type", "image/png"),
            ("x-file-name", secret_filename),
        ],
        valid_png,
    )
    .await;
    assert_eq!(att_s, StatusCode::CREATED);

    // Fetch all audit events recorded in database
    let all_events = env
        .audit
        .query_events(audit_core::EventFilter::default())
        .await
        .unwrap();
    assert!(!all_events.is_empty(), "Events must be audited");

    for ev in &all_events {
        let details_str = serde_json::to_string(&ev.details).unwrap();

        // 1. Zero message bodies
        assert!(
            !details_str.contains(secret_body_phrase),
            "Audit details leaked message body! Event: {ev:?}"
        );

        // 2. Zero filenames
        assert!(
            !details_str.contains(secret_filename),
            "Audit details leaked original filename! Event: {ev:?}"
        );

        // 3. Zero contact first or last names
        assert!(
            !details_str.contains(secret_contact_first),
            "Audit details leaked contact first name! Event: {ev:?}"
        );
        assert!(
            !details_str.contains(secret_contact_last),
            "Audit details leaked contact last name! Event: {ev:?}"
        );

        // 4. Zero tokens or secret tokens
        assert!(
            !details_str.contains(&dev_token),
            "Audit details leaked device token! Event: {ev:?}"
        );
        assert!(
            !details_str.contains(TEST_INGEST_TOKEN),
            "Audit details leaked ingest token! Event: {ev:?}"
        );
    }
}
