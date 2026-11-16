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

//! Integration tests for Cercano Chat Conversations, Messages & Branding (F4.5-04 & F4.5-16).
//!
//! Test cases:
//! - TC-F4.5-010: Create conversation with initial message (201 Created)
//! - TC-F4.5-011: Join existing open conversation (200 OK, message appended, no duplicate)
//! - TC-F4.5-012: Message pagination (limit, before, next_before)
//! - TC-F4.5-013: Concurrent claim race (first succeeds, second gets 409 already_assigned)
//! - TC-F4.5-014: Conversation lifecycle: assign, release, reassign
//! - TC-F4.5-015: Close and reopen (closed conversation rejects messages with 409)
//! - TC-F4.5-016: IDOR prevention between devices (device A cannot read device B's conversation)
//! - TC-F4.5-017: Permission enforcement for technician operations
//! - TC-F4.5-018: Input validation on contact names and empty message body (400 Bad Request)
//! - TC-F4.5-019: Read receipts marking
//! - TC-F4.5-020: Chat summary and active agents listing
//! - TC-F4.5-096: Chat branding public GET endpoint (defaults and persistence)
//! - TC-F4.5-097: Chat branding PUT validation (hex color, https logo, permissions)

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

async fn request_raw(
    env: &TestEnv,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut headers = Vec::new();
    let auth_val;
    if let Some(tok) = token {
        auth_val = format!("Bearer {tok}");
        headers.push(("authorization", auth_val.as_str()));
    }
    request_with_headers(env, method, uri, &headers, body).await
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

async fn create_authenticated_device(env: &TestEnv, device_id: &str) -> (String, SigningKey) {
    let (signing_key, pubkey_base64) = generate_keypair();

    let (reg_status, _) = request_with_headers(
        env,
        "POST",
        "/api/chat/devices/register",
        &[
            ("x-cercano-client-token", TEST_INGEST_TOKEN),
            ("x-forwarded-proto", "https"),
        ],
        Some(json!({
            "device_id": device_id,
            "public_key": pubkey_base64,
            "display_name": format!("Device {device_id}")
        })),
    )
    .await;
    assert_eq!(reg_status, StatusCode::CREATED);

    let (ch_status, ch_body) = request_raw(
        env,
        "POST",
        "/api/chat/auth/challenge",
        None,
        Some(json!({ "device_id": device_id })),
    )
    .await;
    assert_eq!(ch_status, StatusCode::OK);
    let challenge_id = ch_body["challenge_id"].as_str().unwrap();
    let nonce = ch_body["nonce"].as_str().unwrap();

    let sig = sign_nonce(&signing_key, nonce);

    let (v_status, v_body) = request_raw(
        env,
        "POST",
        "/api/chat/auth/verify",
        None,
        Some(json!({
            "challenge_id": challenge_id,
            "signature": sig
        })),
    )
    .await;
    assert_eq!(v_status, StatusCode::OK);
    let session_token = v_body["token"].as_str().unwrap().to_string();

    (session_token, signing_key)
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
    let (status, _) = request_raw(
        env,
        "POST",
        "/api/auth/bootstrap",
        None,
        Some(json!({ "username": "admin", "password": "AdminPassword123!" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = request_raw(
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
        let (e_status, e_body) = request_raw(
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

        let (c_status, _) = request_raw(
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

async fn create_technician_session(env: &TestEnv, admin_token: &str, username: &str) -> String {
    let password = "TechnicianPassword123!";
    let (u_status, _) = request_raw(
        env,
        "POST",
        "/api/users",
        Some(admin_token),
        Some(json!({
            "username": username,
            "password": password,
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(u_status, StatusCode::CREATED);

    let (l_status, l_body) = request_raw(
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
        let (e_status, e_body) = request_raw(
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

        let (c_status, _) = request_raw(
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

#[tokio::test]
async fn test_tc_f4_5_010_create_conversation_with_initial_message() {
    let env = setup().await;
    let (dev_token, _) = create_authenticated_device(&env, "device_c_010").await;

    let (status, body) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Carlos",
            "contact_last_name": "Mendoza",
            "body": "Hola, necesito asistencia con el sistema contable.",
            "client_message_id": "msg-001-carlos"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert!(body["id"].is_string());
    assert_eq!(body["device_id"], "device_c_010");
    assert_eq!(body["contact_first_name"], "Carlos");
    assert_eq!(body["contact_last_name"], "Mendoza");
    assert_eq!(body["status"], "waiting");
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0]["body"],
        "Hola, necesito asistencia con el sistema contable."
    );
    assert_eq!(messages[0]["sender_type"], "client");
}

#[tokio::test]
async fn test_tc_f4_5_011_join_existing_open_conversation() {
    let env = setup().await;
    let (dev_token, _) = create_authenticated_device(&env, "device_c_011").await;

    // 1. First call creates conversation
    let (s1, b1) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Lucia",
            "contact_last_name": "Gomez",
            "body": "Primer mensaje de prueba."
        })),
    )
    .await;
    assert_eq!(s1, StatusCode::CREATED);
    let conv_id = b1["id"].as_str().unwrap().to_string();

    // 2. Second call while open reuses the conversation
    let (s2, b2) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Lucia",
            "contact_last_name": "Gomez",
            "body": "Segundo mensaje en la misma conversación."
        })),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2["id"], conv_id);
    let messages = b2["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages[0]["body"],
        "Segundo mensaje en la misma conversación."
    );

    // Verify there is only 1 conversation for this device in DB
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_conversations WHERE device_id = 'device_c_011'",
    )
    .fetch_one(&env.db)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_tc_f4_5_012_message_pagination() {
    let env = setup().await;
    let (dev_token, _) = create_authenticated_device(&env, "device_c_012").await;

    let (_, create_body) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Test",
            "contact_last_name": "Paginator",
            "body": "Mensaje 1"
        })),
    )
    .await;
    let conv_id = create_body["id"].as_str().unwrap();

    // Send 4 more messages
    for i in 2..=5 {
        let (s, _) = request_raw(
            &env,
            "POST",
            &format!("/api/chat/conversations/{conv_id}/messages"),
            Some(&dev_token),
            Some(json!({ "body": format!("Mensaje {i}") })),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
    }

    // Fetch conversation with limit = 2
    let (s, page1) = request_raw(
        &env,
        "GET",
        &format!("/api/chat/conversations/{conv_id}?limit=2"),
        Some(&dev_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let messages = page1["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    // Should be newest first: Mensaje 5, Mensaje 4
    assert_eq!(messages[0]["body"], "Mensaje 5");
    assert_eq!(messages[1]["body"], "Mensaje 4");
    assert!(page1["next_before"].is_string());
    let next_before = page1["next_before"].as_str().unwrap();

    // Fetch page 2 using next_before
    let (s2, page2) = request_raw(
        &env,
        "GET",
        &format!("/api/chat/conversations/{conv_id}?limit=2&before={next_before}"),
        Some(&dev_token),
        None,
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    let messages2 = page2["messages"].as_array().unwrap();
    assert_eq!(messages2.len(), 2);
    assert_eq!(messages2[0]["body"], "Mensaje 3");
    assert_eq!(messages2[1]["body"], "Mensaje 2");
}

#[tokio::test]
async fn test_tc_f4_5_013_concurrent_claim_race() {
    let env = setup().await;
    let admin_tok = bootstrap_admin_session(&env).await;
    let tech1_tok = create_technician_session(&env, &admin_tok, "tech1").await;
    let tech2_tok = create_technician_session(&env, &admin_tok, "tech2").await;

    let (dev_token, _) = create_authenticated_device(&env, "device_c_013").await;
    let (_, create_body) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Race",
            "contact_last_name": "Condition",
            "body": "Ayuda con reclamo"
        })),
    )
    .await;
    let conv_id = create_body["id"].as_str().unwrap();

    // Tech 1 claims conversation -> 200 OK
    let (s1, b1) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/claim"),
        Some(&tech1_tok),
        None,
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(b1["status"], "assigned");

    // Tech 2 attempts to claim the same conversation -> 409 Conflict
    let (s2, b2) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/claim"),
        Some(&tech2_tok),
        None,
    )
    .await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(b2["code"], "already_assigned");
}

#[tokio::test]
async fn test_tc_f4_5_014_conversation_lifecycle_assign_release() {
    let env = setup().await;
    let admin_tok = bootstrap_admin_session(&env).await;
    let tech1_tok = create_technician_session(&env, &admin_tok, "tech_life1").await;
    let _tech2_tok = create_technician_session(&env, &admin_tok, "tech_life2").await;

    let (dev_token, _) = create_authenticated_device(&env, "device_c_014").await;
    let (_, create_body) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Life",
            "contact_last_name": "Cycle",
            "body": "Prueba de ciclo de vida"
        })),
    )
    .await;
    let conv_id = create_body["id"].as_str().unwrap();

    // 1. Claim by tech 1
    let (s, b) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/claim"),
        Some(&tech1_tok),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["status"], "assigned");

    // 2. Release by tech 1 back to queue
    let (s_rel, b_rel) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/release"),
        Some(&tech1_tok),
        None,
    )
    .await;
    assert_eq!(s_rel, StatusCode::OK);
    assert_eq!(b_rel["status"], "waiting");
    assert!(b_rel["assigned_user_id"].is_null());

    // 3. Admin reassigns directly to tech 2
    // Retrieve tech 2's user id
    let tech2_id: String = sqlx::query_scalar("SELECT id FROM users WHERE username = 'tech_life2'")
        .fetch_one(&env.db)
        .await
        .unwrap();

    let (s_asg, b_asg) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/assign"),
        Some(&admin_tok),
        Some(json!({ "user_id": tech2_id })),
    )
    .await;
    assert_eq!(s_asg, StatusCode::OK);
    assert_eq!(b_asg["assigned_user_id"], tech2_id);
    assert_eq!(b_asg["status"], "assigned");
}

#[tokio::test]
async fn test_tc_f4_5_015_close_and_reopen() {
    let env = setup().await;
    let admin_tok = bootstrap_admin_session(&env).await;
    let (dev_token, _) = create_authenticated_device(&env, "device_c_015").await;

    let (_, create_body) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Cierre",
            "contact_last_name": "Prueba",
            "body": "Mensaje para cerrar"
        })),
    )
    .await;
    let conv_id = create_body["id"].as_str().unwrap();

    // Close conversation as admin
    let (s_close, b_close) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/close"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(s_close, StatusCode::OK);
    assert_eq!(b_close["status"], "closed");

    // Client attempts to send message to closed conversation -> 409 Conflict
    let (s_fail, b_fail) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/messages"),
        Some(&dev_token),
        Some(json!({ "body": "Intento de escribir en conversación cerrada" })),
    )
    .await;
    assert_eq!(s_fail, StatusCode::CONFLICT);
    assert_eq!(b_fail["code"], "conversation_closed");

    // Reopen conversation
    let (s_reopen, b_reopen) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/reopen"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(s_reopen, StatusCode::OK);
    assert_eq!(b_reopen["status"], "waiting");

    // Now client can message again
    let (s_msg, _) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/messages"),
        Some(&dev_token),
        Some(json!({ "body": "Mensaje tras reapertura exitosa" })),
    )
    .await;
    assert_eq!(s_msg, StatusCode::CREATED);
}

#[tokio::test]
async fn test_tc_f4_5_016_idor_prevention_between_devices() {
    let env = setup().await;
    let (dev_a_token, _) = create_authenticated_device(&env, "device_a_idor").await;
    let (dev_b_token, _) = create_authenticated_device(&env, "device_b_idor").await;

    // Device A creates conversation
    let (_, create_body) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_a_token),
        Some(json!({
            "contact_first_name": "Device",
            "contact_last_name": "A",
            "body": "Datos confidenciales de A"
        })),
    )
    .await;
    let conv_id_a = create_body["id"].as_str().unwrap();

    // Device B attempts to GET conversation of Device A -> 403 Forbidden
    let (s_get, b_get) = request_raw(
        &env,
        "GET",
        &format!("/api/chat/conversations/{conv_id_a}"),
        Some(&dev_b_token),
        None,
    )
    .await;
    assert_eq!(s_get, StatusCode::FORBIDDEN);
    assert_eq!(b_get["error"], "forbidden");

    // Device B attempts to send message to Device A's conversation -> 403 Forbidden
    let (s_post, b_post) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id_a}/messages"),
        Some(&dev_b_token),
        Some(json!({ "body": "Intrusión de B" })),
    )
    .await;
    assert_eq!(s_post, StatusCode::FORBIDDEN);
    assert_eq!(b_post["error"], "forbidden");
}

#[tokio::test]
async fn test_tc_f4_5_018_input_validation() {
    let env = setup().await;
    let (dev_token, _) = create_authenticated_device(&env, "device_c_018").await;

    // Empty first name
    let (s1, b1) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "",
            "contact_last_name": "Valido",
            "body": "Mensaje válido"
        })),
    )
    .await;
    assert_eq!(s1, StatusCode::BAD_REQUEST);
    assert_eq!(b1["error"], "validation_error");

    // Empty message body
    let (s2, b2) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Valido",
            "contact_last_name": "Valido",
            "body": "   "
        })),
    )
    .await;
    assert_eq!(s2, StatusCode::BAD_REQUEST);
    assert_eq!(b2["error"], "validation_error");
}

#[tokio::test]
async fn test_tc_f4_5_019_read_receipts() {
    let env = setup().await;
    let (dev_token, _) = create_authenticated_device(&env, "device_c_019").await;

    let (_, create_body) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Read",
            "contact_last_name": "Receipt",
            "body": "Verificando leídos"
        })),
    )
    .await;
    let conv_id = create_body["id"].as_str().unwrap();

    let (s, _b) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/read"),
        Some(&dev_token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_tc_f4_5_020_chat_summary_and_agents() {
    let env = setup().await;
    let admin_tok = bootstrap_admin_session(&env).await;
    let (dev_token, _) = create_authenticated_device(&env, "device_c_020").await;

    request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_token),
        Some(json!({
            "contact_first_name": "Summary",
            "contact_last_name": "Agent",
            "body": "Mensaje en cola"
        })),
    )
    .await;

    // Chat summary as admin
    let (s_sum, b_sum) =
        request_raw(&env, "GET", "/api/chat/summary", Some(&admin_tok), None).await;
    assert_eq!(s_sum, StatusCode::OK);
    assert_eq!(b_sum["waiting"], 1);

    // List agents as admin
    let (s_agents, b_agents) =
        request_raw(&env, "GET", "/api/chat/agents", Some(&admin_tok), None).await;
    assert_eq!(s_agents, StatusCode::OK);
    assert!(!b_agents["agents"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_tc_f4_5_096_branding_get_defaults_and_public_access() {
    let env = setup().await;

    // Public GET without any token
    let (status, body) = request_raw(&env, "GET", "/api/chat/branding", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], 1);
    assert_eq!(body["support_name"], "Cercano Soporte");
    assert_eq!(body["accent_color"], "#3B5BFF");
}

#[tokio::test]
async fn test_tc_f4_5_097_branding_put_validation_and_permissions() {
    let env = setup().await;
    let admin_tok = bootstrap_admin_session(&env).await;

    // 1. Invalid color format -> 400
    let (s_bad_color, b_bad_color) = request_raw(
        &env,
        "PUT",
        "/api/chat/branding",
        Some(&admin_tok),
        Some(json!({
            "support_name": "Soporte TI",
            "accent_color": "blue", // Not hex #RRGGBB
            "logo_url": "https://example.com/logo.png"
        })),
    )
    .await;
    assert_eq!(s_bad_color, StatusCode::BAD_REQUEST);
    assert_eq!(b_bad_color["error"], "validation_error");

    // 2. Non-https logo URL -> 400
    let (s_bad_url, b_bad_url) = request_raw(
        &env,
        "PUT",
        "/api/chat/branding",
        Some(&admin_tok),
        Some(json!({
            "support_name": "Soporte TI",
            "accent_color": "#112233",
            "logo_url": "http://insecure.com/logo.png" // Not https
        })),
    )
    .await;
    assert_eq!(s_bad_url, StatusCode::BAD_REQUEST);
    assert_eq!(b_bad_url["error"], "validation_error");

    // 3. Valid update with admin token -> 200 OK
    let (s_ok, b_ok) = request_raw(
        &env,
        "PUT",
        "/api/chat/branding",
        Some(&admin_tok),
        Some(json!({
            "organization_name": "Institución de Ejemplo",
            "support_name": "Mesa de Ayuda Cercano",
            "logo_url": "https://cercano.local/logo.svg",
            "accent_color": "#0055AA",
            "welcome_text": "Bienvenido al soporte técnico.",
            "info_text": "Horario: 8am - 5pm",
            "privacy_text": "Sus conversaciones están protegidas."
        })),
    )
    .await;
    assert_eq!(s_ok, StatusCode::OK);
    assert_eq!(b_ok["organization_name"], "Institución de Ejemplo");
    assert_eq!(b_ok["support_name"], "Mesa de Ayuda Cercano");
    assert_eq!(b_ok["accent_color"], "#0055AA");

    // 4. Verify public GET now reflects the persisted changes
    let (s_get, b_get) = request_raw(&env, "GET", "/api/chat/branding", None, None).await;
    assert_eq!(s_get, StatusCode::OK);
    assert_eq!(b_get["organization_name"], "Institución de Ejemplo");
    assert_eq!(b_get["accent_color"], "#0055AA");
}

#[tokio::test]
async fn test_tc_f4_5_086_remote_session_escalation() {
    let env = setup().await;
    let (dev_tok, _sk) = create_authenticated_device(&env, "dev-escalate-1").await;
    let admin_tok = bootstrap_admin_session(&env).await;
    let op_tok = create_technician_session(&env, &admin_tok, "tech_escalate").await;
    let other_op_tok = create_technician_session(&env, &admin_tok, "other_tech").await;

    // 1. Device creates conversation
    let (status, conv) = request_raw(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev_tok),
        Some(json!({
            "contact_first_name": "Luis",
            "contact_last_name": "Gómez",
            "body": "Necesito ayuda remota con el sistema.",
            "client_message_id": "msg-esc-1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let conv_id = conv["id"].as_str().unwrap();

    // 2. Device cannot escalate -> 403 Forbidden
    let (s_dev, _) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/escalate"),
        Some(&dev_tok),
        None,
    )
    .await;
    assert_eq!(s_dev, StatusCode::FORBIDDEN);

    // 3. Technician claims conversation
    let (s_claim, _) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/claim"),
        Some(&op_tok),
        None,
    )
    .await;
    assert_eq!(s_claim, StatusCode::OK);

    // 4. Another technician without manage/admin cannot escalate assigned conversation -> 403 Forbidden
    let (s_other, _) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/escalate"),
        Some(&other_op_tok),
        None,
    )
    .await;
    assert_eq!(s_other, StatusCode::FORBIDDEN);

    // 5. Assigned technician escalates conversation -> 200 OK
    let (s_esc, esc_res) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/escalate"),
        Some(&op_tok),
        Some(json!({
            "trace_id": conv_id
        })),
    )
    .await;
    assert_eq!(s_esc, StatusCode::OK);
    assert_eq!(esc_res["device_id"], "dev-escalate-1");
    assert_eq!(esc_res["trace_id"], conv_id);
    let expected_url = format!("cercano://connect?device=dev-escalate-1&trace={conv_id}");
    assert_eq!(esc_res["url"], expected_url);

    // 6. Admin can also escalate -> 200 OK
    let (s_admin, admin_esc) = request_raw(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/escalate"),
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(s_admin, StatusCode::OK);
    assert_eq!(admin_esc["device_id"], "dev-escalate-1");
    assert!(admin_esc["url"]
        .as_str()
        .unwrap()
        .starts_with("cercano://connect"));
}
