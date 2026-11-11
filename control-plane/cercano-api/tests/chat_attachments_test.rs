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

//! Integration tests for Cercano Chat Secure Attachments (F4.5-05).
//!
//! Test cases:
//! - TC-F4.5-030: Valid PNG upload & authenticated download with security headers
//! - TC-F4.5-031: Valid JPEG, WebP and PDF uploads
//! - TC-F4.5-032: Disallowed types (SVG, ZIP, EXE) and magic bytes mismatch rejected with 415
//! - TC-F4.5-033: Size boundary (>10 MiB -> 413, empty -> 400)
//! - TC-F4.5-034: Filename sanitization against path traversal
//! - TC-F4.5-035: IDOR prevention on download between devices (403 Forbidden)
//! - TC-F4.5-036: Attachment to closed conversation rejected (409 Conflict)

use std::sync::Arc;

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
        ..Default::default()
    };
    let state = AppState::new(config, db.clone(), audit.clone());
    TestEnv {
        app: create_app(state),
        db,
        audit,
        _temp_dir: temp_dir,
    }
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

async fn request_json(
    env: &TestEnv,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = token {
        builder = builder.header("authorization", format!("Bearer {tok}"));
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

async fn create_authenticated_device(env: &TestEnv, device_id: &str) -> String {
    let (signing_key, pubkey_base64) = generate_keypair();

    let reg_req = Request::builder()
        .method("POST")
        .uri("/api/chat/devices/register")
        .header("content-type", "application/json")
        .header("x-cercano-client-token", TEST_INGEST_TOKEN)
        .header("x-forwarded-proto", "https")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "device_id": device_id,
                "public_key": pubkey_base64,
                "display_name": format!("Device {device_id}")
            }))
            .unwrap(),
        ))
        .unwrap();
    let reg_res = env.app.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    let (ch_status, ch_body) = request_json(
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

    let (v_status, v_body) = request_json(
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
    v_body["token"].as_str().unwrap().to_string()
}

async fn create_test_conversation(env: &TestEnv, dev_token: &str) -> String {
    let (s, b) = request_json(
        env,
        "POST",
        "/api/chat/conversations",
        Some(dev_token),
        Some(json!({
            "contact_first_name": "Attach",
            "contact_last_name": "Tester",
            "body": "Iniciando conversación para adjuntos."
        })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    b["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_tc_f4_5_030_valid_png_upload_and_download() {
    let env = setup().await;
    let dev_token = create_authenticated_device(&env, "dev_att_030").await;
    let conv_id = create_test_conversation(&env, &dev_token).await;

    // Minimal 1x1 PNG bytes
    let png_bytes = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG magic
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15,
        0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01,
        0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
        0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    let filename_b64 = base64::engine::general_purpose::STANDARD.encode("captura_pantalla.png");

    // 1. Upload PNG
    let (status, _, body_vec) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[
            ("content-type", "image/png"),
            ("x-file-name-b64", &filename_b64),
            ("x-client-message-id", "msg-att-001"),
        ],
        png_bytes.clone(),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let body_json: Value = serde_json::from_slice(&body_vec).unwrap();
    assert!(body_json["attachment"].is_object());
    assert_eq!(body_json["attachment"]["mime"], "image/png");
    assert_eq!(body_json["attachment"]["name"], "captura_pantalla.png");
    assert_eq!(
        body_json["attachment"]["size_bytes"],
        png_bytes.len() as i64
    );

    let att_id = body_json["attachment"]["id"].as_str().unwrap();

    // 2. Download attachment
    let (dl_status, dl_headers, dl_bytes) = request_binary(
        &env,
        "GET",
        &format!("/api/chat/attachments/{att_id}"),
        Some(&dev_token),
        &[],
        Vec::new(),
    )
    .await;

    assert_eq!(dl_status, StatusCode::OK);
    assert_eq!(dl_bytes, png_bytes);
    assert_eq!(dl_headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(
        dl_headers.get("cache-control").unwrap(),
        "private, no-store, max-age=0"
    );
    assert_eq!(dl_headers.get("content-type").unwrap(), "image/png");
}

#[tokio::test]
async fn test_tc_f4_5_031_valid_jpeg_webp_pdf_uploads() {
    let env = setup().await;
    let dev_token = create_authenticated_device(&env, "dev_att_031").await;
    let conv_id = create_test_conversation(&env, &dev_token).await;

    // 1. JPEG
    let mut jpeg_bytes = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    jpeg_bytes.extend(vec![0x00; 50]);
    let (s_jpg, _, b_jpg) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[("content-type", "image/jpeg"), ("x-file-name", "foto.jpg")],
        jpeg_bytes,
    )
    .await;
    assert_eq!(s_jpg, StatusCode::CREATED);
    let j_jpg: Value = serde_json::from_slice(&b_jpg).unwrap();
    assert_eq!(j_jpg["attachment"]["mime"], "image/jpeg");

    // 2. WebP
    let mut webp_bytes = Vec::new();
    webp_bytes.extend_from_slice(b"RIFF");
    webp_bytes.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]); // 32 bytes size
    webp_bytes.extend_from_slice(b"WEBP");
    webp_bytes.extend(vec![0x00; 24]);
    let (s_webp, _, b_webp) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[
            ("content-type", "image/webp"),
            ("x-file-name", "banner.webp"),
        ],
        webp_bytes,
    )
    .await;
    assert_eq!(s_webp, StatusCode::CREATED);
    let j_webp: Value = serde_json::from_slice(&b_webp).unwrap();
    assert_eq!(j_webp["attachment"]["mime"], "image/webp");

    // 3. PDF
    let mut pdf_bytes = Vec::new();
    pdf_bytes.extend_from_slice(b"%PDF-1.7\n");
    pdf_bytes.extend_from_slice(b"%%EOF\n");
    let (s_pdf, _, b_pdf) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[
            ("content-type", "application/pdf"),
            ("x-file-name", "manual.pdf"),
        ],
        pdf_bytes,
    )
    .await;
    assert_eq!(s_pdf, StatusCode::CREATED);
    let j_pdf: Value = serde_json::from_slice(&b_pdf).unwrap();
    assert_eq!(j_pdf["attachment"]["mime"], "application/pdf");
}

#[tokio::test]
async fn test_tc_f4_5_032_disallowed_types_and_magic_mismatch_rejected() {
    let env = setup().await;
    let dev_token = create_authenticated_device(&env, "dev_att_032").await;
    let conv_id = create_test_conversation(&env, &dev_token).await;

    // 1. SVG rejected -> 415
    let svg_bytes =
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>".to_vec();
    let (s_svg, _, _) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[
            ("content-type", "image/svg+xml"),
            ("x-file-name", "malicious.svg"),
        ],
        svg_bytes,
    )
    .await;
    assert_eq!(s_svg, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // 2. ZIP rejected -> 415
    let zip_bytes = b"PK\x03\x04\x14\x00\x00\x00".to_vec();
    let (s_zip, _, _) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[
            ("content-type", "application/zip"),
            ("x-file-name", "archive.zip"),
        ],
        zip_bytes,
    )
    .await;
    assert_eq!(s_zip, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // 3. EXE rejected -> 415
    let exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    let (s_exe, _, _) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[
            ("content-type", "application/x-msdownload"),
            ("x-file-name", "setup.exe"),
        ],
        exe_bytes,
    )
    .await;
    assert_eq!(s_exe, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // 4. Magic bytes mismatch: claims image/png but payload is plaintext
    let fake_png = b"THIS IS NOT A REAL PNG FILE".to_vec();
    let (s_mismatch, _, _) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[("content-type", "image/png"), ("x-file-name", "fake.png")],
        fake_png,
    )
    .await;
    assert_eq!(s_mismatch, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_tc_f4_5_033_size_boundaries() {
    let env = setup().await;
    let dev_token = create_authenticated_device(&env, "dev_att_033").await;
    let conv_id = create_test_conversation(&env, &dev_token).await;

    // 1. Empty body -> 400 Bad Request
    let (s_empty, _, _) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[("content-type", "image/png"), ("x-file-name", "empty.png")],
        Vec::new(),
    )
    .await;
    assert_eq!(s_empty, StatusCode::BAD_REQUEST);

    // 2. Body exceeding 10 MiB -> 413 Payload Too Large
    let mut huge_png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    huge_png.resize(10 * 1024 * 1024 + 1024, 0x00); // 10 MiB + 1 KiB
    let (s_huge, _, _) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[("content-type", "image/png"), ("x-file-name", "huge.png")],
        huge_png,
    )
    .await;
    assert_eq!(s_huge, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_tc_f4_5_034_filename_sanitization() {
    let env = setup().await;
    let dev_token = create_authenticated_device(&env, "dev_att_034").await;
    let conv_id = create_test_conversation(&env, &dev_token).await;

    let png_bytes = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00,
    ];

    // Traversal filename with directory paths and null bytes
    let dirty_name = "../../../../Windows/System32/cmd.exe\0.png";
    let b64_dirty = base64::engine::general_purpose::STANDARD.encode(dirty_name);

    let (status, _, body_vec) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[
            ("content-type", "image/png"),
            ("x-file-name-b64", &b64_dirty),
        ],
        png_bytes,
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let body_json: Value = serde_json::from_slice(&body_vec).unwrap();
    let sanitized_name = body_json["attachment"]["name"].as_str().unwrap();

    // Must not contain slashes, backslashes, or relative path sequences
    assert!(!sanitized_name.contains('/'));
    assert!(!sanitized_name.contains('\\'));
    assert!(!sanitized_name.contains(".."));
    assert_eq!(sanitized_name, "cmd.exe.png");
}

#[tokio::test]
async fn test_tc_f4_5_035_idor_prevention_on_download() {
    let env = setup().await;
    let dev_a_tok = create_authenticated_device(&env, "dev_a_035").await;
    let dev_b_tok = create_authenticated_device(&env, "dev_b_035").await;
    let conv_id = create_test_conversation(&env, &dev_a_tok).await;

    let png_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
    let (status, _, body_vec) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_a_tok),
        &[
            ("content-type", "image/png"),
            ("x-file-name", "private_a.png"),
        ],
        png_bytes,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let body_json: Value = serde_json::from_slice(&body_vec).unwrap();
    let att_id = body_json["attachment"]["id"].as_str().unwrap();

    // 1. Device B tries to download Device A's attachment -> 403 Forbidden
    let (s_b, _, _) = request_binary(
        &env,
        "GET",
        &format!("/api/chat/attachments/{att_id}"),
        Some(&dev_b_tok),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(s_b, StatusCode::FORBIDDEN);

    // 2. Unauthenticated user tries to download -> 401 Unauthorized
    let (s_unauth, _, _) = request_binary(
        &env,
        "GET",
        &format!("/api/chat/attachments/{att_id}"),
        None,
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(s_unauth, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tc_f4_5_036_attachment_to_closed_conversation_rejected() {
    let env = setup().await;
    let dev_token = create_authenticated_device(&env, "dev_att_036").await;
    let conv_id = create_test_conversation(&env, &dev_token).await;

    // Close the conversation as client
    let (s_close, _) = request_json(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/close"),
        Some(&dev_token),
        None,
    )
    .await;
    assert_eq!(s_close, StatusCode::OK);

    // Attempt to upload attachment -> 409 Conflict
    let png_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let (status, _, b_vec) = request_binary(
        &env,
        "POST",
        &format!("/api/chat/conversations/{conv_id}/attachments"),
        Some(&dev_token),
        &[("content-type", "image/png"), ("x-file-name", "closed.png")],
        png_bytes,
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    let b_json: Value = serde_json::from_slice(&b_vec).unwrap();
    assert_eq!(b_json["code"], "conversation_closed");
}
