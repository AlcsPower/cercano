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

use audit_core::{Category, EventFilter};
use cercano_api::{
    alarms::{AlarmConfig, AlarmEngine},
    config::Config,
    create_app,
    db::init_db,
    AppState,
};

struct TestContext {
    app: axum::Router,
    state: AppState,
    admin_token: String,
}

async fn setup_test_context(whitelist: Vec<String>) -> TestContext {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let internal_token = "cercano_internal_token_secret".to_string();

    let config = Config {
        internal_token: internal_token.clone(),
        ip_whitelist: whitelist,
        ..Default::default()
    };

    let state = AppState::new(config, db, audit);
    let app = create_app(state.clone());

    // 1. Bootstrap admin
    let bootstrap_req = Request::builder()
        .uri("/api/auth/bootstrap")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "admin_alarm_test",
                "password": "AdminPassword123!"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.clone().oneshot(bootstrap_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 2. Login to get admin token
    let login_req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "admin_alarm_test",
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

    TestContext {
        app,
        state,
        admin_token,
    }
}

#[tokio::test]
async fn test_tc_f2_020_brute_force_rule_triggers_and_emits_audit_event() {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db).await.unwrap());
    let config = AlarmConfig {
        brute_force_threshold: 5,
        brute_force_window_secs: 900,
        ..Default::default()
    };
    let engine = AlarmEngine::with_config(config, audit.clone());

    let subject = "victim_user";
    let ip = "192.168.1.10";

    // 1..5 failed attempts: should not trigger alarm
    for i in 1..=5 {
        let res = engine
            .record_login_failure(subject, Some(ip), None)
            .await
            .unwrap();
        assert!(
            res.is_none(),
            "Attempt {} should not have triggered alarm",
            i
        );
    }

    // 6th attempt (> 5 within 15 minutes): triggers alarm.brute_force
    let alarm_event = engine
        .record_login_failure(subject, Some(ip), None)
        .await
        .unwrap()
        .expect("6th failed login must trigger alarm.brute_force");

    assert_eq!(alarm_event.action, "alarm.brute_force");
    assert_eq!(alarm_event.category, Category::Alarm);
    assert_eq!(alarm_event.subject.as_ref().unwrap().id, subject);
    assert_eq!(alarm_event.details["severity"], "high");
    assert_eq!(alarm_event.details["failed_attempts"], 6);

    // Verify stored in AuditStore and cryptographic chain is valid
    let stored = audit.get_event_by_id(&alarm_event.event_id).await.unwrap();
    assert!(stored.is_some());
    let verification = audit.verify_chain(None, None).await.unwrap();
    assert!(verification.is_valid);
}

#[tokio::test]
async fn test_tc_f2_021_ip_burst_rule_triggers_and_emits_audit_event() {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db).await.unwrap());
    let config = AlarmConfig {
        ip_burst_threshold: 30,
        ip_burst_window_secs: 60,
        ..Default::default()
    };
    let engine = AlarmEngine::with_config(config, audit.clone());

    let ip = "198.51.100.42";

    // 1..30 attempts within 1 minute: should not trigger alarm
    for i in 1..=30 {
        let res = engine.record_ip_attempt(ip, None, None).await.unwrap();
        assert!(
            res.is_none(),
            "Attempt {} should not have triggered alarm",
            i
        );
    }

    // 31st attempt (> 30 in 1 minute): triggers alarm.ip_burst
    let alarm_event = engine
        .record_ip_attempt(ip, None, None)
        .await
        .unwrap()
        .expect("31st attempt must trigger alarm.ip_burst");

    assert_eq!(alarm_event.action, "alarm.ip_burst");
    assert_eq!(alarm_event.category, Category::Alarm);
    assert_eq!(alarm_event.subject.as_ref().unwrap().id, ip);
    assert_eq!(alarm_event.details["severity"], "critical");
    assert_eq!(alarm_event.details["attempts"], 31);

    // Verify stored and verified
    let verification = audit.verify_chain(None, None).await.unwrap();
    assert!(verification.is_valid);
}

#[tokio::test]
async fn test_tc_f2_022_ip_whitelist_enforcement_and_violations() {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db).await.unwrap());
    let config = AlarmConfig {
        ip_whitelist: vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
        ..Default::default()
    };
    let engine = AlarmEngine::with_config(config, audit.clone());

    // 1. Authorized IPs in CIDR ranges -> return None
    assert!(engine
        .check_ip_whitelist("10.1.2.3", None, None)
        .await
        .unwrap()
        .is_none());
    assert!(engine
        .check_ip_whitelist("192.168.1.150:4321", None, None)
        .await
        .unwrap()
        .is_none());

    // 2. Unauthorized IP outside CIDR ranges -> triggers alarm.ip_whitelist_violation
    let violation = engine
        .check_ip_whitelist("203.0.113.88", None, Some("attacker"))
        .await
        .unwrap()
        .expect("Unauthorized IP must trigger alarm.ip_whitelist_violation");

    assert_eq!(violation.action, "alarm.ip_whitelist_violation");
    assert_eq!(violation.category, Category::Alarm);
    assert_eq!(violation.subject.as_ref().unwrap().id, "203.0.113.88");
    assert_eq!(violation.details["severity"], "high");

    // 3. If whitelist is empty, any IP is authorized
    let open_config = AlarmConfig {
        ip_whitelist: Vec::new(),
        ..Default::default()
    };
    let open_engine = AlarmEngine::with_config(open_config, audit.clone());
    assert!(open_engine
        .check_ip_whitelist("203.0.113.88", None, None)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_tc_f2_023_scope_violation_triggers_alarm() {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db).await.unwrap());
    let engine = AlarmEngine::new(Config::default(), audit.clone());

    let allowed_scopes = vec!["finance-dept".to_string(), "accounting".to_string()];

    // 1. In-scope target
    let in_scope = engine
        .check_session_scope(
            "operator_01",
            Some("10.0.0.5"),
            "finance-dept",
            &allowed_scopes,
            None,
        )
        .await
        .unwrap();
    assert!(in_scope.is_none());

    // 2. Out-of-scope target
    let violation = engine
        .check_session_scope(
            "operator_01",
            Some("10.0.0.5"),
            "hr-confidential",
            &allowed_scopes,
            None,
        )
        .await
        .unwrap()
        .expect("Out-of-scope session attempt must trigger alarm.scope_violation");

    assert_eq!(violation.action, "alarm.scope_violation");
    assert_eq!(violation.category, Category::Alarm);
    assert_eq!(violation.subject.as_ref().unwrap().id, "hr-confidential");
    assert_eq!(violation.details["severity"], "high");
}

#[tokio::test]
async fn test_tc_f2_024_get_alarms_filtering_and_security() {
    let ctx = setup_test_context(vec!["10.0.0.0/8".to_string(), "127.0.0.1".to_string()]).await;

    // Trigger three distinct alarms
    let _ = ctx
        .state
        .alarms
        .check_ip_whitelist("198.51.100.1", None, Some("bad_actor"))
        .await
        .unwrap();

    for _ in 0..6 {
        let _ = ctx
            .state
            .alarms
            .record_login_failure("victim_acc", Some("10.0.0.1"), None)
            .await
            .unwrap();
    }

    for _ in 0..31 {
        let _ = ctx
            .state
            .alarms
            .record_ip_attempt("10.0.0.99", None, None)
            .await
            .unwrap();
    }

    // 1. Query all alarms
    let req = Request::builder()
        .uri("/api/audit/alarms")
        .method("GET")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let alarms: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(alarms.len(), 3);

    // 2. Filter by severity=critical (should only return alarm.ip_burst)
    let req = Request::builder()
        .uri("/api/audit/alarms?severity=critical")
        .method("GET")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let alarms: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0]["action"], "alarm.ip_burst");

    // 3. Filter by action=alarm.brute_force
    let req = Request::builder()
        .uri("/api/audit/alarms?action=alarm.brute_force")
        .method("GET")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let alarms: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0]["action"], "alarm.brute_force");

    // 4. Unauthorized request without token rejected with 401
    let unauth_req = Request::builder()
        .uri("/api/audit/alarms")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(unauth_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tc_f2_025_acknowledge_alarm_records_verifiable_audit_event() {
    let ctx = setup_test_context(vec![]).await;

    // 1. Generate an alarm
    let alarm = ctx
        .state
        .alarms
        .record_scope_violation(
            "rogue_user",
            Some("10.0.0.7"),
            "critical_infra_group",
            "Attempted session without clearance",
            None,
        )
        .await
        .unwrap();

    let alarm_id = alarm.event_id.clone();

    // 2. Acknowledge the alarm via API
    let ack_req = Request::builder()
        .uri(format!("/api/audit/alarms/{}/acknowledge", alarm_id))
        .method("POST")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "note": "Investigated by SecOps: simulated red-team exercise"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = ctx.app.clone().oneshot(ack_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let ack_event: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(ack_event["action"], "console.alarm_ack");
    assert_eq!(ack_event["category"], "console");
    assert_eq!(ack_event["subject"]["id"], alarm_id);
    assert_eq!(ack_event["details"]["alarm_id"], alarm_id);
    assert_eq!(
        ack_event["details"]["alarm_action"],
        "alarm.scope_violation"
    );
    assert_eq!(
        ack_event["details"]["note"],
        "Investigated by SecOps: simulated red-team exercise"
    );

    // 3. Cryptographic chain verification
    let verify_req = Request::builder()
        .uri("/api/audit/verify")
        .method("GET")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(verify_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let verify_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(verify_json["status"], "ok");
    assert_eq!(verify_json["chain_valid"], true);

    // 4. Query events to confirm console.alarm_ack is present
    let events = ctx
        .state
        .audit
        .query_events(EventFilter {
            action: Some("console.alarm_ack".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "console.alarm_ack");

    // 5. Non-existent alarm ID returns 404
    let not_found_req = Request::builder()
        .uri("/api/audit/alarms/01920000-0000-7000-8000-000000000000/acknowledge")
        .method("POST")
        .header("authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();

    let res = ctx.app.clone().oneshot(not_found_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_alarms_validates_limit() {
    let ctx = setup_test_context(vec![]).await;

    for bad in ["0", "-1", "1001"] {
        let req = Request::builder()
            .uri(format!("/api/audit/alarms?limit={bad}"))
            .method("GET")
            .header("Authorization", format!("Bearer {}", ctx.admin_token))
            .body(Body::empty())
            .unwrap();
        let res = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "limit={bad}");
    }
}

#[tokio::test]
async fn test_list_alarms_filters_severity_in_sql() {
    let ctx = setup_test_context(vec![]).await;

    // Low is appended first: a post-LIMIT filter would see only "low" with limit=1.
    for (action, severity) in [("alarm.test_low", "low"), ("alarm.test_high", "high")] {
        let input = audit_core::EventInput::new(
            "trace-alarm-filter",
            audit_core::Source::Api,
            Category::Alarm,
            action,
            audit_core::Actor::new("sys_alarm_engine"),
            audit_core::Outcome::Denied,
            json!({ "severity": severity, "reason": "test" }),
        );
        ctx.state.audit.append(input).await.unwrap();
    }

    let req = Request::builder()
        .uri("/api/audit/alarms?severity=high&limit=1")
        .method("GET")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();
    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let events = body.as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "alarm.test_high");
}

#[tokio::test]
async fn test_login_outside_ip_whitelist_is_forbidden() {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let config = Config {
        ip_whitelist: vec!["10.0.0.0/8".to_string()],
        ..Default::default()
    };
    let state = AppState::new(config, db, audit);
    let app = create_app(state);

    let bootstrap = Request::builder()
        .uri("/api/auth/bootstrap")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "admin_whitelist_test",
                "password": "AdminPassword123!"
            }))
            .unwrap(),
        ))
        .unwrap();
    let res = app.clone().oneshot(bootstrap).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Loopback (127.0.0.1) is outside 10.0.0.0/8, so login must be rejected, not just alarmed.
    let login = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "admin_whitelist_test",
                "password": "AdminPassword123!"
            }))
            .unwrap(),
        ))
        .unwrap();
    let res = app.clone().oneshot(login).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_list_alarms_rejects_negative_offset() {
    let ctx = setup_test_context(vec![]).await;
    let req = Request::builder()
        .uri("/api/audit/alarms?offset=-1")
        .method("GET")
        .header("Authorization", format!("Bearer {}", ctx.admin_token))
        .body(Body::empty())
        .unwrap();
    let res = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
