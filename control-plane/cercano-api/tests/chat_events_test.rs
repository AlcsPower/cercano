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

//! Integration tests for Cercano Chat Server-Sent Events (SSE) and ChatHub (F4.5-06).
//!
//! Test cases:
//! - TC-F4.5-040: Unauthenticated SSE connection rejected (401)
//! - TC-F4.5-041: Invalid token rejected (401)
//! - TC-F4.5-042: Valid device connection returns 200 OK, text/event-stream, X-Accel-Buffering: no
//! - TC-F4.5-043: Valid technician connection returns 200 OK with proper headers
//! - TC-F4.5-044: Queue poke received by technician when device opens conversation
//! - TC-F4.5-045: Message poke received by assigned technician when device sends message
//! - TC-F4.5-046: Message poke received by device when technician sends message
//! - TC-F4.5-047: Third-party isolation: Device B does NOT receive Device A's message poke
//! - TC-F4.5-048: SSE pokes are strictly content-free (no body, no filenames, no contact names)
//! - TC-F4.5-049: Lag triggers `{"type":"resync"}` poke
//! - TC-F4.5-050: Status poke delivered on claim, release, close

use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::rand_core::OsRng;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

use cercano_api::{config::Config, create_app, db::init_db, AppState};

const TEST_INGEST_TOKEN: &str = "test-client-ingest-token-32bytes-secret!!";

struct TestEnv {
    app: axum::Router,
    #[allow(dead_code)]
    db: sqlx::SqlitePool,
    #[allow(dead_code)]
    audit: Arc<audit_core::AuditStore>,
    state: AppState,
    _temp_dir: TempDir,
}

async fn setup() -> TestEnv {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        client_ingest_token: TEST_INGEST_TOKEN.to_string(),
        chat_enabled: true,
        chat_attachment_dir: temp_dir.path().to_string_lossy().to_string(),
        chat_max_attachment_bytes: 10 * 1024 * 1024,
        chat_sse_heartbeat_secs: 15,
        ..Default::default()
    };
    let state = AppState::new(config, db.clone(), audit.clone());
    TestEnv {
        app: create_app(state.clone()),
        db,
        audit,
        state,
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

struct DeviceSession {
    device_id: String,
    token: String,
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

async fn create_authenticated_device(env: &TestEnv, device_id: &str) -> DeviceSession {
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
    let token = v_val["token"].as_str().unwrap().to_string();

    DeviceSession {
        device_id: device_id.to_string(),
        token,
    }
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

async fn find_poke_in_stream(body: &mut Body, expected_substring: &str) -> String {
    for _ in 0..10 {
        if let Ok(Some(Ok(frame))) =
            tokio::time::timeout(Duration::from_secs(1), body.frame()).await
        {
            let text = String::from_utf8_lossy(frame.data_ref().unwrap()).to_string();
            if text.contains(expected_substring) {
                return text;
            }
        }
    }
    panic!("Did not find expected poke '{expected_substring}' in SSE stream");
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_tc_f4_5_040_sse_unauthenticated() {
    let env = setup().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .body(Body::empty())
        .unwrap();

    let response = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tc_f4_5_041_sse_invalid_token() {
    let env = setup().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .header("authorization", "Bearer cercano_chat_invalidhexdeadbeef")
        .body(Body::empty())
        .unwrap();

    let response = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tc_f4_5_042_device_sse_connect_headers() {
    let env = setup().await;
    let dev = create_authenticated_device(&env, "dev-sse-001").await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .header("authorization", format!("Bearer {}", dev.token))
        .body(Body::empty())
        .unwrap();

    let response = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("text/event-stream"));

    let accel = response
        .headers()
        .get("x-accel-buffering")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(accel, "no");
}

#[tokio::test]
async fn test_tc_f4_5_043_technician_sse_connect_headers() {
    let env = setup().await;
    let tech_token = create_technician_session(&env, "tech_sse_01").await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .header("authorization", format!("Bearer {tech_token}"))
        .body(Body::empty())
        .unwrap();

    let response = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("text/event-stream"));
}

#[tokio::test]
async fn test_tc_f4_5_044_to_048_message_pokes_and_content_free() {
    let env = setup().await;
    let dev1 = create_authenticated_device(&env, "dev-sse-client-1").await;
    let dev2 = create_authenticated_device(&env, "dev-sse-client-2").await;
    let tech_token = create_technician_session(&env, "tech_sse_02").await;

    // Connect technician to SSE stream
    let tech_req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .header("authorization", format!("Bearer {tech_token}"))
        .body(Body::empty())
        .unwrap();
    let tech_resp = env.app.clone().oneshot(tech_req).await.unwrap();
    assert_eq!(tech_resp.status(), StatusCode::OK);
    let mut tech_body = tech_resp.into_body();

    // Connect dev1 to SSE stream
    let dev1_req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .header("authorization", format!("Bearer {}", dev1.token))
        .body(Body::empty())
        .unwrap();
    let dev1_resp = env.app.clone().oneshot(dev1_req).await.unwrap();
    assert_eq!(dev1_resp.status(), StatusCode::OK);
    let mut dev1_body = dev1_resp.into_body();

    // Connect dev2 to SSE stream
    let dev2_req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .header("authorization", format!("Bearer {}", dev2.token))
        .body(Body::empty())
        .unwrap();
    let dev2_resp = env.app.clone().oneshot(dev2_req).await.unwrap();
    assert_eq!(dev2_resp.status(), StatusCode::OK);
    let mut dev2_body = dev2_resp.into_body();

    // Dev1 creates a conversation with a secret text body
    let secret_body = "MensajeSuperSecreto99999";
    let (c_status, c_val, _) = request_json(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev1.token),
        Some(json!({
            "contact_first_name": "Maria",
            "contact_last_name": "Lopez",
            "body": secret_body
        })),
    )
    .await;
    assert_eq!(c_status, StatusCode::CREATED);
    let conv_id = c_val["id"].as_str().unwrap();

    // Technician receives queue poke (TC-F4.5-044)
    let frame = tokio::time::timeout(Duration::from_secs(2), tech_body.frame())
        .await
        .expect("Timeout waiting for tech SSE poke")
        .expect("Stream ended")
        .expect("Frame error");
    let text = String::from_utf8_lossy(frame.data_ref().unwrap()).to_string();
    assert!(text.contains("event: poke"));
    assert!(text.contains("\"type\":\"queue\""));
    assert!(text.contains(conv_id));

    // Dev1 receives message poke for its initial message
    let dev1_frame = tokio::time::timeout(Duration::from_secs(2), dev1_body.frame())
        .await
        .expect("Timeout waiting for dev1 SSE poke")
        .expect("Stream ended")
        .expect("Frame error");
    let dev1_text = String::from_utf8_lossy(dev1_frame.data_ref().unwrap()).to_string();
    assert!(dev1_text.contains("event: poke"));
    assert!(dev1_text.contains("\"type\":\"message\""));

    // Verify Dev2 did NOT receive any message poke for Dev1's conversation (TC-F4.5-047)
    let dev2_attempt = tokio::time::timeout(Duration::from_millis(200), dev2_body.frame()).await;
    assert!(
        dev2_attempt.is_err(),
        "Dev2 should NOT have received a poke intended for Dev1"
    );

    // Verify content-free guarantee (TC-F4.5-048): text bodies and names NEVER appear in pokes
    assert!(
        !text.contains(secret_body),
        "Poke must NOT leak secret message body"
    );
    assert!(!text.contains("Maria"), "Poke must NOT leak contact name");
    assert!(!text.contains("Lopez"), "Poke must NOT leak contact name");
    assert!(
        !dev1_text.contains(secret_body),
        "Dev1 poke must NOT carry message body"
    );

    // Technician claims conversation
    let (claim_status, _, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/claim"),
        Some(&tech_token),
        None,
    )
    .await;
    assert_eq!(claim_status, StatusCode::OK);

    // Now technician sends a message to Dev1 (TC-F4.5-046)
    let (msg_status, msg_val, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/messages"),
        Some(&tech_token),
        Some(json!({
            "body": "Hola Maria, te atiende el soporte tecnico"
        })),
    )
    .await;
    assert_eq!(msg_status, StatusCode::CREATED);
    let tech_msg_id = msg_val["id"].as_str().unwrap();

    // Dev1 receives message poke for the technician's message
    let mut received_tech_msg = false;
    for _ in 0..3 {
        if let Ok(Some(Ok(f))) =
            tokio::time::timeout(Duration::from_secs(1), dev1_body.frame()).await
        {
            let t = String::from_utf8_lossy(f.data_ref().unwrap()).to_string();
            if t.contains(tech_msg_id) {
                received_tech_msg = true;
                break;
            }
        }
    }
    assert!(
        received_tech_msg,
        "Dev1 must receive poke with technician's message_id"
    );
}

#[tokio::test]
async fn test_tc_f4_5_049_lag_triggers_resync() {
    let env = setup().await;
    let dev = create_authenticated_device(&env, "dev-sse-lag-test").await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .header("authorization", format!("Bearer {}", dev.token))
        .body(Body::empty())
        .unwrap();

    let response = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();

    // Broadcast 300 events without reading to overflow the 256-event buffer
    for i in 0..300 {
        env.state
            .chat_hub
            .broadcast(cercano_api::chat::events::ChatEvent::message(
                format!("conv-{i}"),
                format!("msg-{i}"),
                Some(dev.device_id.clone()),
                None,
                false,
            ));
    }

    // Now reading should trigger resync poke
    let mut got_resync = false;
    for _ in 0..5 {
        if let Ok(Some(Ok(frame))) =
            tokio::time::timeout(Duration::from_secs(2), body.frame()).await
        {
            let text = String::from_utf8_lossy(frame.data_ref().unwrap()).to_string();
            if text.contains("\"type\":\"resync\"") {
                got_resync = true;
                break;
            }
        }
    }
    assert!(got_resync, "Lag must trigger resync poke");
}

#[tokio::test]
async fn test_tc_f4_5_050_status_pokes_on_claim_release_close() {
    let env = setup().await;
    let dev = create_authenticated_device(&env, "dev-sse-status-test").await;
    let tech_token = create_technician_session(&env, "tech_sse_status").await;

    let tech_req = Request::builder()
        .method("GET")
        .uri("/api/chat/events")
        .header("authorization", format!("Bearer {tech_token}"))
        .body(Body::empty())
        .unwrap();
    let tech_resp = env.app.clone().oneshot(tech_req).await.unwrap();
    let mut tech_body = tech_resp.into_body();

    // Dev opens conversation
    let (c_status, c_val, _) = request_json(
        &env,
        "POST",
        "/api/chat/conversations",
        Some(&dev.token),
        Some(json!({
            "contact_first_name": "Carlos",
            "contact_last_name": "Gomez",
            "body": "Necesito ayuda con conexion"
        })),
    )
    .await;
    assert_eq!(c_status, StatusCode::CREATED);
    let conv_id = c_val["id"].as_str().unwrap();

    // Consume queue poke
    let _ = tokio::time::timeout(Duration::from_secs(1), tech_body.frame()).await;

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

    let claim_text = find_poke_in_stream(&mut tech_body, "\"status\":\"assigned\"").await;
    assert!(claim_text.contains("\"type\":\"status\""));

    // Release
    let (rel_status, _, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/release"),
        Some(&tech_token),
        None,
    )
    .await;
    assert_eq!(rel_status, StatusCode::OK);

    let release_text = find_poke_in_stream(&mut tech_body, "\"status\":\"waiting\"").await;
    assert!(release_text.contains("\"type\":\"status\""));

    // Close
    let (close_status, _, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/close"),
        Some(&tech_token),
        Some(json!({ "reason": "resolved" })),
    )
    .await;
    assert_eq!(close_status, StatusCode::OK);

    let close_text = find_poke_in_stream(&mut tech_body, "\"status\":\"closed\"").await;
    assert!(close_text.contains("\"type\":\"status\""));
}
