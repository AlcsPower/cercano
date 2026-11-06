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

use audit_core::GENESIS_HASH;
use cercano_api::{config::Config, create_app, db::init_db, AppState};

struct TestContext {
    app: axum::Router,
    state: AppState,
    admin_token: String,
    device_id: String,
    internal_token: String,
}

async fn setup_test_context() -> TestContext {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let internal_token = "cercano_internal_token_secret".to_string();

    let config = Config {
        internal_token: internal_token.clone(),
        ..Default::default()
    };

    let state = AppState::new(config, db.clone(), audit);

    let app = create_app(state.clone());

    // 1. Seed admin directly into DB to avoid polluting the audit chain
    let admin_id = uuid::Uuid::now_v7().to_string();
    let admin_token = format!("admin_tok_{}", uuid::Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'admin_audit_test', 'hash', 'admin', 1)",
    )
    .bind(&admin_id)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))",
    )
    .bind(&admin_token)
    .bind(&admin_id)
    .execute(&db)
    .await
    .unwrap();

    // 3. Register a test device
    let device_id = "dev_test_001".to_string();
    sqlx::query("INSERT INTO devices (id, name, status) VALUES (?, 'Test Device', 'online')")
        .bind(&device_id)
        .execute(&db)
        .await
        .unwrap();

    TestContext {
        app,
        state,
        admin_token,
        device_id,
        internal_token,
    }
}

#[tokio::test]
async fn test_tc_f2_010_ingestion_authentication_methods() {
    let ctx = setup_test_context().await;

    let payload = json!({
        "trace_id": "0192e2fb-3d5a-7182-9654-2c7da197824b",
        "source": "client",
        "category": "conn",
        "action": "conn.start",
        "actor": {
            "id": "usr_01",
            "actor_type": "user",
            "name": "operador"
        },
        "outcome": "success",
        "details": {
            "session_type": "desktop",
            "token_id": "tok_allowed_id"
        }
    });

    // 1. Unauthenticated request should be rejected with 401
    let req = Request::builder()
        .uri("/api/audit/events")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 2. Authenticated via Admin Bearer token -> 201 Created
    let req = Request::builder()
        .uri("/api/audit/events")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let event: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(event["sequence"], 1);
    assert_eq!(event["prev_hash"], GENESIS_HASH);

    // 3. Authenticated via X-Device-Id -> 201 Created
    let req = Request::builder()
        .uri("/api/audit/events")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Device-Id", &ctx.device_id)
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let event: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(event["sequence"], 2);

    // 4. Authenticated via X-Cercano-Internal-Token -> 201 Created
    let req = Request::builder()
        .uri("/api/audit/events")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Cercano-Internal-Token", &ctx.internal_token)
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let event: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(event["sequence"], 3);
}

#[tokio::test]
async fn test_tc_f2_011_idempotent_deduplication() {
    let ctx = setup_test_context().await;
    let fixed_event_id = "0192e2fb-3d5a-7182-9654-2c7da197824c";

    let payload = json!({
        "event_id": fixed_event_id,
        "trace_id": "0192e2fb-3d5a-7182-9654-2c7da197824b",
        "source": "client",
        "category": "conn",
        "action": "conn.start",
        "actor": {
            "id": "usr_01",
            "actor_type": "user"
        },
        "outcome": "success",
        "details": {
            "session_type": "desktop"
        }
    });

    // First call: creates event -> 201 Created
    let req = Request::builder()
        .uri("/api/audit/events")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let first_res: Value = serde_json::from_slice(&bytes).unwrap();
    let first_seq = first_res["sequence"].as_i64().unwrap();
    let first_hash = first_res["hash"].as_str().unwrap().to_string();

    // Second call: same event_id -> 200 OK with identical event
    let req2 = Request::builder()
        .uri("/api/audit/events")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let res2 = ctx.app.clone().oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::OK);
    let bytes2 = res2.into_body().collect().await.unwrap().to_bytes();
    let second_res: Value = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(second_res["sequence"].as_i64().unwrap(), first_seq);
    assert_eq!(second_res["hash"].as_str().unwrap(), first_hash);

    // Verify chain: exactly 1 event recorded, valid chain
    let verify_res = ctx.state.audit.verify_chain(None, None).await.unwrap();
    assert!(verify_res.is_valid);
    assert_eq!(verify_res.total_verified, 1);
}

#[tokio::test]
async fn test_tc_f2_012_security_filter_rejects_sensitive_keys() {
    let ctx = setup_test_context().await;

    let sensitive_cases = vec![
        json!({ "password": "PlainTextPassword" }),
        json!({ "user_password": "123" }),
        json!({ "secret": "super_secret" }),
        json!({ "client_secret": "my_secret" }),
        json!({ "private_key": "-----BEGIN PRIVATE KEY-----" }),
        json!({ "token": "sensitive_session_token" }),
        json!({ "auth_token": "bearer_secret" }),
        json!({ "nested": { "deep_secret": { "password": "abc" } } }),
    ];

    for sensitive_details in sensitive_cases {
        let payload = json!({
            "trace_id": "0192e2fb-3d5a-7182-9654-2c7da197824b",
            "source": "client",
            "category": "conn",
            "action": "conn.start",
            "actor": { "id": "usr_01", "actor_type": "user" },
            "outcome": "success",
            "details": sensitive_details
        });

        let req = Request::builder()
            .uri("/api/audit/events")
            .method("POST")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", ctx.admin_token))
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        let res = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "Failed for payload: {:?}",
            payload["details"]
        );
    }
}

#[tokio::test]
async fn test_tc_f2_013_specialized_endpoints_and_chain() {
    let ctx = setup_test_context().await;
    let trace_id = "0192e2fb-3d5a-7182-9654-2c7da197824b";

    // 1. POST /api/audit/session/start
    let start_payload = json!({
        "trace_id": trace_id,
        "controller_id": "usr_tech_01",
        "controlled_id": "dev_pc_contabilidad",
        "session_type": "desktop",
        "auth_method": "password_preset",
        "actor_name": "soporte_tecnico",
        "actor_ip": "192.168.1.100",
        "two_factor_verified": true,
        "client_version": "1.3.0",
        "rendezvous_server": "hbbs.lan:21116",
        "is_direct_lan": false
    });

    let req = Request::builder()
        .uri("/api/audit/session/start")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(serde_json::to_vec(&start_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let ev1: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ev1["sequence"], 1);
    assert_eq!(ev1["action"], "conn.start");
    assert_eq!(ev1["prev_hash"], GENESIS_HASH);

    // 2. POST /api/audit/file-transfer
    let file_payload = json!({
        "trace_id": trace_id,
        "direction": "upload",
        "remote_path": "C:\\Sistemas\\Update.msi",
        "bytes": 48924160,
        "file_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "transfer_mode": "dedicated_session",
        "actor_id": "usr_tech_01"
    });

    let req = Request::builder()
        .uri("/api/audit/file-transfer")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Cercano-Internal-Token", &ctx.internal_token)
        .body(Body::from(serde_json::to_vec(&file_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let ev2: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ev2["sequence"], 2);
    assert_eq!(ev2["action"], "file.transfer");
    assert_eq!(ev2["prev_hash"], ev1["hash"]);

    // 3. POST /api/audit/alarm
    let alarm_payload = json!({
        "trace_id": trace_id,
        "alarm_type": "ip_burst",
        "severity": "critical",
        "actor_ip": "10.0.0.88",
        "reason": "180 attempts per minute exceeded threshold 60"
    });

    let req = Request::builder()
        .uri("/api/audit/alarm")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Device-Id", &ctx.device_id)
        .body(Body::from(serde_json::to_vec(&alarm_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let ev3: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ev3["sequence"], 3);
    assert_eq!(ev3["action"], "alarm.ip_burst");
    assert_eq!(ev3["prev_hash"], ev2["hash"]);

    // 4. POST /api/audit/session/end
    let end_payload = json!({
        "trace_id": trace_id,
        "duration_secs": 930,
        "close_reason": "user_disconnected",
        "bytes_sent": 14502800,
        "bytes_received": 3829000,
        "actor_id": "usr_tech_01",
        "session_notes": "Soporte mensual finalizado"
    });

    let req = Request::builder()
        .uri("/api/audit/session/end")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(serde_json::to_vec(&end_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let ev4: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ev4["sequence"], 4);
    assert_eq!(ev4["action"], "conn.end");
    assert_eq!(ev4["prev_hash"], ev3["hash"]);

    // 5. GET /api/audit/verify confirms the entire chain is valid
    let req = Request::builder()
        .uri("/api/audit/verify")
        .method("GET")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let verify_res: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(verify_res["status"], "ok");
    assert_eq!(verify_res["events_verified"], 4);
    assert_eq!(verify_res["chain_valid"], true);
}

#[tokio::test]
async fn test_f2_12_session_note_is_authenticated_immutable_and_trace_linked() {
    let ctx = setup_test_context().await;
    let trace_id = "trace-note-001";
    let payload = json!({"trace_id": trace_id, "note": "Incidente resuelto por soporte", "event_id": "note-001"});
    let req = Request::builder()
        .uri("/api/audit/session/note")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let event: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(event["action"], "session.note");
    assert_eq!(event["trace_id"], trace_id);
    assert_eq!(event["details"]["note"], payload["note"]);
    let req = Request::builder()
        .uri("/api/audit/session/note")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    assert_eq!(
        ctx.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let bad = json!({"trace_id": trace_id, "note": "   "});
    let req = Request::builder()
        .uri("/api/audit/session/note")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(serde_json::to_vec(&bad).unwrap()))
        .unwrap();
    assert_eq!(
        ctx.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn test_tc_f2_014_query_events_with_filters() {
    let ctx = setup_test_context().await;
    let trace1 = "0192e2fb-3d5a-7182-9654-2c7da1978241";
    let trace2 = "0192e2fb-3d5a-7182-9654-2c7da1978242";

    // Insert 2 conn events and 1 file event
    let req1 = Request::builder()
        .uri("/api/audit/session/start")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "trace_id": trace1,
                "controller_id": "usr_01",
                "controlled_id": "dev_01",
                "session_type": "desktop",
                "auth_method": "password_preset"
            }))
            .unwrap(),
        ))
        .unwrap();
    ctx.app.clone().oneshot(req1).await.unwrap();

    let req2 = Request::builder()
        .uri("/api/audit/file-transfer")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "trace_id": trace1,
                "direction": "upload",
                "remote_path": "test.txt",
                "bytes": 500,
                "file_sha256": "dummy_hash"
            }))
            .unwrap(),
        ))
        .unwrap();
    ctx.app.clone().oneshot(req2).await.unwrap();

    let req3 = Request::builder()
        .uri("/api/audit/session/start")
        .method("POST")
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "trace_id": trace2,
                "controller_id": "usr_02",
                "controlled_id": "dev_02",
                "session_type": "terminal",
                "auth_method": "manual_confirm"
            }))
            .unwrap(),
        ))
        .unwrap();
    ctx.app.clone().oneshot(req3).await.unwrap();

    // 1. Query by category=file
    let req = Request::builder()
        .uri("/api/audit/events?category=file")
        .method("GET")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    let events = response["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["category"], "file");

    // 2. Query by trace_id=trace1
    let req = Request::builder()
        .uri(format!("/api/audit/events?trace_id={}", trace1))
        .method("GET")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    let events = response["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);

    // 3. Query with limit=1, offset=1
    let req = Request::builder()
        .uri("/api/audit/events?limit=1&offset=1")
        .method("GET")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    let events = response["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["sequence"], 2);
}
