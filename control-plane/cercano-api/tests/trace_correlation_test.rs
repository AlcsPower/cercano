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

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
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

    // 1. Bootstrap admin
    let bootstrap_req = Request::builder()
        .uri("/api/auth/bootstrap")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "admin_trace_test",
                "password": "AdminPassword123!"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.clone().oneshot(bootstrap_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 2. Login to obtain admin session token
    let login_req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "admin_trace_test",
                "password": "AdminPassword123!"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let login_json: Value = serde_json::from_slice(&bytes).unwrap();
    let admin_token = login_json["token"].as_str().unwrap().to_string();

    // 3. Register test device
    let device_id = "dev_trace_target".to_string();
    sqlx::query("INSERT INTO devices (id, name, status) VALUES (?, 'Target Machine', 'online')")
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
async fn test_unknown_or_inactive_trace_returns_404() {
    let ctx = setup_test_context().await;
    let nonexistent_trace = uuid::Uuid::now_v7().to_string();

    let req = Request::builder()
        .uri(format!("/api/audit/traces/{}", nonexistent_trace))
        .method("GET")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let err_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(err_json["error"], "not_found");
}

#[tokio::test]
async fn test_unauthenticated_or_non_admin_access_rejected() {
    let ctx = setup_test_context().await;
    let trace_id = uuid::Uuid::now_v7().to_string();

    // 1. Missing Authorization header -> 401 Unauthorized
    let req = Request::builder()
        .uri(format!("/api/audit/traces/{}", trace_id))
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 2. Non-admin user -> 403 Forbidden
    let operator_id = uuid::Uuid::now_v7().to_string();
    let op_token = format!("op_tok_{}", uuid::Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'operator_test', 'hash', 'operator', 1)",
    )
    .bind(&operator_id)
    .execute(&ctx.state.db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))",
    )
    .bind(&op_token)
    .bind(&operator_id)
    .execute(&ctx.state.db)
    .await
    .unwrap();

    let req = Request::builder()
        .uri(format!("/api/audit/traces/{}", trace_id))
        .method("GET")
        .header("authorization", format!("Bearer {}", op_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_coherent_trace_timeline_and_session_metrics() {
    let ctx = setup_test_context().await;
    let trace_id = uuid::Uuid::now_v7().to_string();

    // 1. Ingest session start
    let start_payload = json!({
        "trace_id": trace_id,
        "controller_id": "technician_01",
        "controlled_id": ctx.device_id,
        "session_type": "desktop",
        "auth_method": "permanent_password",
        "actor_name": "Senior Technician",
        "actor_ip": "192.168.1.50",
        "two_factor_verified": true,
        "is_direct_lan": true
    });

    let req = Request::builder()
        .uri("/api/audit/session/start")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Cercano-Internal-Token", &ctx.internal_token)
        .body(Body::from(serde_json::to_vec(&start_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 2. Ingest file transfer (upload)
    let file1_payload = json!({
        "trace_id": trace_id,
        "direction": "upload",
        "remote_path": "C:\\temp\\hotfix.dll",
        "bytes": 2048,
        "file_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "actor_id": "technician_01",
        "subject_id": ctx.device_id
    });

    let req = Request::builder()
        .uri("/api/audit/file-transfer")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Cercano-Internal-Token", &ctx.internal_token)
        .body(Body::from(serde_json::to_vec(&file1_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 3. Ingest file transfer (download)
    let file2_payload = json!({
        "trace_id": trace_id,
        "direction": "download",
        "remote_path": "C:\\logs\\crashdump.dmp",
        "bytes": 8192,
        "file_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "actor_id": "technician_01",
        "subject_id": ctx.device_id
    });

    let req = Request::builder()
        .uri("/api/audit/file-transfer")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Cercano-Internal-Token", &ctx.internal_token)
        .body(Body::from(serde_json::to_vec(&file2_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 4. Ingest an alarm during the session
    let alarm_payload = json!({
        "trace_id": trace_id,
        "alarm_type": "clipboard_burst",
        "severity": "medium",
        "actor_ip": "192.168.1.50",
        "reason": "Excessive clipboard synchronizations per second",
        "actor_id": "technician_01",
        "subject_id": ctx.device_id
    });

    let req = Request::builder()
        .uri("/api/audit/alarm")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Cercano-Internal-Token", &ctx.internal_token)
        .body(Body::from(serde_json::to_vec(&alarm_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 5. Ingest session end
    let end_payload = json!({
        "trace_id": trace_id,
        "duration_secs": 640,
        "close_reason": "user_normal_disconnect",
        "bytes_sent": 125000,
        "bytes_received": 350000,
        "actor_id": "technician_01",
        "subject_id": ctx.device_id,
        "session_notes": "Applied security patch and collected logs"
    });

    let req = Request::builder()
        .uri("/api/audit/session/end")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Cercano-Internal-Token", &ctx.internal_token)
        .body(Body::from(serde_json::to_vec(&end_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 6. Query GET /api/audit/traces/:trace_id
    let req = Request::builder()
        .uri(format!("/api/audit/traces/{}", trace_id))
        .method("GET")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    // Verify session overview
    assert_eq!(body["trace_id"], trace_id);
    assert_eq!(body["status"], "completed");
    assert_eq!(body["session_type"], "desktop");
    assert_eq!(body["auth_method"], "permanent_password");
    assert_eq!(body["two_factor_verified"], true);
    assert_eq!(body["is_direct_lan"], true);
    assert_eq!(body["duration_seconds"], 640);
    assert_eq!(body["close_reason"], "user_normal_disconnect");
    assert_eq!(
        body["session_notes"],
        "Applied security patch and collected logs"
    );

    // Verify participants
    assert_eq!(body["controller"]["id"], "technician_01");
    assert_eq!(body["controlled"]["id"], ctx.device_id);

    // Verify metrics
    let metrics = &body["metrics"];
    assert_eq!(metrics["duration_seconds"], 640);
    assert_eq!(metrics["bytes_sent"], 125000);
    assert_eq!(metrics["bytes_received"], 350000);
    assert_eq!(metrics["total_bytes"], 475000);
    assert_eq!(metrics["file_count"], 2);
    assert_eq!(metrics["alarm_count"], 1);
    assert_eq!(metrics["event_count"], 5);

    // Verify timeline
    let timeline = body["timeline"].as_array().unwrap();
    assert_eq!(timeline.len(), 5);

    assert_eq!(timeline[0]["action"], "conn.start");
    assert_eq!(timeline[0]["correlation_method"], "trace_id");

    assert_eq!(timeline[1]["action"], "file.transfer");
    assert_eq!(timeline[1]["details"]["direction"], "upload");
    assert_eq!(timeline[1]["details"]["bytes_transferred"], 2048);

    assert_eq!(timeline[2]["action"], "file.transfer");
    assert_eq!(timeline[2]["details"]["direction"], "download");
    assert_eq!(timeline[2]["details"]["bytes_transferred"], 8192);

    assert_eq!(timeline[3]["action"], "alarm.clipboard_burst");

    assert_eq!(timeline[4]["action"], "conn.end");
    assert_eq!(timeline[4]["details"]["duration_seconds"], 640);
}

#[tokio::test]
async fn test_active_session_assembly() {
    let ctx = setup_test_context().await;
    let trace_id = uuid::Uuid::now_v7().to_string();

    // 1. Ingest session start without conn.end
    let start_payload = json!({
        "trace_id": trace_id,
        "controller_id": "technician_live",
        "controlled_id": ctx.device_id,
        "session_type": "terminal",
        "auth_method": "manual_confirm"
    });

    let req = Request::builder()
        .uri("/api/audit/session/start")
        .method("POST")
        .header("content-type", "application/json")
        .header("X-Cercano-Internal-Token", &ctx.internal_token)
        .body(Body::from(serde_json::to_vec(&start_payload).unwrap()))
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 2. Ingest single file transfer
    let file_payload = json!({
        "trace_id": trace_id,
        "direction": "upload",
        "remote_path": "/tmp/script.sh",
        "bytes": 512,
        "file_sha256": "5555555555555555555555555555555555555555555555555555555555555555",
        "actor_id": "technician_live",
        "subject_id": ctx.device_id
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

    // 3. Query trace endpoint
    let req = Request::builder()
        .uri(format!("/api/audit/traces/{}", trace_id))
        .method("GET")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body["trace_id"], trace_id);
    assert_eq!(body["status"], "active");
    assert_eq!(body["session_type"], "terminal");
    assert!(body["ended_at"].is_null());
    assert_eq!(body["metrics"]["file_count"], 1);
    assert_eq!(body["metrics"]["bytes_sent"], 512);
    assert_eq!(body["metrics"]["event_count"], 2);
}

#[tokio::test]
async fn test_deterministic_fallback_correlation_window() {
    let ctx = setup_test_context().await;
    let trace_id = uuid::Uuid::now_v7().to_string();
    let controller_id = "agent_lan_ctrl";
    let controlled_id = ctx.device_id.clone();

    let base_time = chrono::Utc::now();
    let t_start = (base_time - chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let t_unlinked_match = (base_time - chrono::Duration::minutes(8))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let t_outside_window = (base_time - chrono::Duration::minutes(25))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let t_end = (base_time - chrono::Duration::minutes(6))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // 1. Ingest conn.start with trace_id
    let start_input = EventInput::new(
        trace_id.clone(),
        Source::Client,
        Category::Conn,
        "conn.start",
        Actor::new(controller_id),
        Outcome::Success,
        json!({
            "session_type": "desktop",
            "auth_method": "manual"
        }),
    )
    .with_subject(Subject::new(&controlled_id))
    .with_ts(t_start);

    ctx.state.audit.append(start_input).await.unwrap();

    // 2. Ingest unlinked event with empty trace_id within +/- 5 minutes window
    let unlinked_matching = EventInput::new(
        "", // lacks trace_id
        Source::Hbbr,
        Category::Conn,
        "relay.handshake",
        Actor::new(controller_id),
        Outcome::Success,
        json!({
            "packet_count": 42,
            "relay_server": "relay-lan.internal:21117"
        }),
    )
    .with_subject(Subject::new(&controlled_id))
    .with_ts(t_unlinked_match);

    ctx.state.audit.append(unlinked_matching).await.unwrap();

    // 3. Ingest unlinked event OUTSIDE window (-25 minutes, > 5m before start)
    let unlinked_outside = EventInput::new(
        "", // lacks trace_id
        Source::Hbbr,
        Category::Conn,
        "relay.stale_handshake",
        Actor::new(controller_id),
        Outcome::Success,
        json!({
            "packet_count": 999
        }),
    )
    .with_subject(Subject::new(&controlled_id))
    .with_ts(t_outside_window);

    ctx.state.audit.append(unlinked_outside).await.unwrap();

    // 4. Ingest unlinked event with DIFFERENT participants within window
    let unlinked_diff_participant = EventInput::new(
        "", // lacks trace_id
        Source::Client,
        Category::Conn,
        "conn.probe",
        Actor::new("other_user"),
        Outcome::Success,
        json!({}),
    )
    .with_subject(Subject::new("other_device"))
    .with_ts(
        (base_time - chrono::Duration::minutes(7))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    );

    ctx.state
        .audit
        .append(unlinked_diff_participant)
        .await
        .unwrap();

    // 5. Ingest conn.end with trace_id
    let end_input = EventInput::new(
        trace_id.clone(),
        Source::Client,
        Category::Conn,
        "conn.end",
        Actor::new(controller_id),
        Outcome::Success,
        json!({
            "duration_seconds": 240,
            "close_reason": "user_disconnect",
            "bytes_sent": 5000,
            "bytes_received": 15000
        }),
    )
    .with_subject(Subject::new(&controlled_id))
    .with_ts(t_end);

    ctx.state.audit.append(end_input).await.unwrap();

    // 6. Query GET /api/audit/traces/:trace_id
    let req = Request::builder()
        .uri(format!("/api/audit/traces/{}", trace_id))
        .method("GET")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    let timeline = body["timeline"].as_array().unwrap();

    // Should include conn.start, relay.handshake (correlated), conn.end -> exactly 3 events
    assert_eq!(timeline.len(), 3);

    // Event 1: conn.start (direct)
    assert_eq!(timeline[0]["action"], "conn.start");
    assert_eq!(timeline[0]["correlation_method"], "trace_id");

    // Event 2: relay.handshake (fallback correlated)
    assert_eq!(timeline[1]["action"], "relay.handshake");
    assert_eq!(timeline[1]["correlation_method"], "fallback_window");
    assert_eq!(timeline[1]["details"]["packet_count"], 42);

    // Event 3: conn.end (direct)
    assert_eq!(timeline[2]["action"], "conn.end");
    assert_eq!(timeline[2]["correlation_method"], "trace_id");

    // Metrics check
    assert_eq!(body["metrics"]["packet_count"], 42);
    assert_eq!(body["metrics"]["event_count"], 3);
}
