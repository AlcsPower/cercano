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
use std::time::Duration;

use audit_core::{Category, EventFilter, Outcome};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::tempdir;
use tower::ServiceExt;
use uuid::Uuid;

use cercano_api::{config::Config, create_app, db::init_db, AppState};

struct TestEnv {
    app: axum::Router,
    state: AppState,
    _builds_dir: tempfile::TempDir,
    admin_token: String,
    revoker_token: String,
    regular_token: String,
}

async fn setup_test_env() -> TestEnv {
    let builds_dir = tempdir().expect("Failed to create tempdir for builds");
    let db = init_db("sqlite::memory:")
        .await
        .expect("Failed to init in-memory db");
    let audit = Arc::new(
        audit_core::AuditStore::new(db.clone())
            .await
            .expect("Failed to init audit store"),
    );

    let config = Config {
        builds_dir: builds_dir.path().to_str().unwrap().to_string(),
        build_concurrency: 2,
        build_retention_secs: 3600,
        internal_token: "test_internal_token".to_string(),
        client_ingest_token: "test_client_token".to_string(),
        revocation_cache_ttl_secs: 60,
        revocation_fail_closed: true,
        ..Default::default()
    };

    let state = AppState::new(config, db.clone(), audit);
    let app = create_app(state.clone());

    // 1. Admin
    let admin_id = Uuid::now_v7().to_string();
    let admin_token = format!("tok_admin_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'admin_rev', 'hash', 'admin', 1)",
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

    // 2. User with builder:revoke permission
    let revoker_id = Uuid::now_v7().to_string();
    let revoker_token = format!("tok_revoker_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'user_revoker', 'hash', 'user', 1)",
    )
    .bind(&revoker_id)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))",
    )
    .bind(&revoker_token)
    .bind(&revoker_id)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query("INSERT INTO user_permissions (user_id, permission) VALUES (?, 'builder:revoke')")
        .bind(&revoker_id)
        .execute(&db)
        .await
        .unwrap();

    // 3. Regular user without permissions
    let regular_id = Uuid::now_v7().to_string();
    let regular_token = format!("tok_regular_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'user_regular', 'hash', 'user', 1)",
    )
    .bind(&regular_id)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))",
    )
    .bind(&regular_token)
    .bind(&regular_id)
    .execute(&db)
    .await
    .unwrap();

    TestEnv {
        app,
        state,
        _builds_dir: builds_dir,
        admin_token,
        revoker_token,
        regular_token,
    }
}

async fn insert_dummy_build(
    state: &AppState,
    id: &str,
    role: &str,
    profile_id: &str,
    status: &str,
    expires_at: Option<&str>,
) {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role, is_active) VALUES ('u-system', 'sys_builder', 'h', 'admin', 1)",
    )
    .execute(&state.db)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO build_jobs (id, user_id, role, profile_id, status, created_at, expires_at)
        VALUES (?, 'u-system', ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(role)
    .bind(profile_id)
    .bind(status)
    .bind(&now)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .unwrap();
}

#[tokio::test]
async fn test_tc_f3_090_single_installer_revocation_and_public_list() {
    let env = setup_test_env().await;

    let installer_id = format!("inst-{}", Uuid::now_v7());
    insert_dummy_build(
        &env.state,
        &installer_id,
        "soporte",
        "prof-soporte-1",
        "completed",
        None,
    )
    .await;

    // 1. Initial GET /api/builds/revocations
    let req = Request::builder()
        .uri("/api/builds/revocations")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "public, max-age=60"
    );
    let etag1 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body["revoked_installers"].as_array().unwrap().is_empty());
    assert!(body["revoked_roles"].as_array().unwrap().is_empty());

    // 2. Conditional request with If-None-Match returns 304 Not Modified
    let req_cond = Request::builder()
        .uri("/api/builds/revocations")
        .method("GET")
        .header("if-none-match", &etag1)
        .body(Body::empty())
        .unwrap();

    let resp_cond = env.app.clone().oneshot(req_cond).await.unwrap();
    assert_eq!(resp_cond.status(), StatusCode::NOT_MODIFIED);

    // 3. Revoke installer via POST /api/builds/{id}/revoke
    let req_revoke = Request::builder()
        .uri(format!("/api/builds/{}/revoke", installer_id))
        .method("POST")
        .header("authorization", format!("Bearer {}", env.admin_token))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "reason": "Clave privada del cliente sospechosa"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_revoke = env.app.clone().oneshot(req_revoke).await.unwrap();
    assert_eq!(resp_revoke.status(), StatusCode::OK);
    let rev_body: Value =
        serde_json::from_slice(&resp_revoke.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(rev_body["id"], installer_id);
    assert_eq!(rev_body["status"], "revoked");
    assert_eq!(rev_body["role"], "soporte");
    assert_eq!(rev_body["reason"], "Clave privada del cliente sospechosa");

    // 4. Verify public GET /api/revocations alias reflects revocation immediately (< 60s)
    let req_list2 = Request::builder()
        .uri("/api/revocations")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp_list2 = env.app.clone().oneshot(req_list2).await.unwrap();
    assert_eq!(resp_list2.status(), StatusCode::OK);
    let etag2 = resp_list2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(etag1, etag2);

    let bytes2 = resp_list2.into_body().collect().await.unwrap().to_bytes();
    let body2: Value = serde_json::from_slice(&bytes2).unwrap();
    let revoked = body2["revoked_installers"].as_array().unwrap();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0]["id"], installer_id);
    assert_eq!(revoked[0]["role"], "soporte");
    assert_eq!(revoked[0]["reason"], "Clave privada del cliente sospechosa");

    // 5. Verify audit event build.revoked
    let events = env
        .state
        .audit
        .query_events(EventFilter {
            action: Some("build.revoked".to_string()),
            category: Some(Category::Build),
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(!events.is_empty());
    let ev = &events[0];
    assert_eq!(ev.outcome, Outcome::Success);
    assert_eq!(ev.subject.as_ref().unwrap().id, installer_id);
}

#[tokio::test]
async fn test_tc_f3_091_role_revocation_and_rbac() {
    let env = setup_test_env().await;

    let inst_soporte1 = format!("inst-sop1-{}", Uuid::now_v7());
    let inst_soporte2 = format!("inst-sop2-{}", Uuid::now_v7());
    let inst_tecnico1 = format!("inst-tec1-{}", Uuid::now_v7());

    insert_dummy_build(
        &env.state,
        &inst_soporte1,
        "soporte",
        "prof-1",
        "completed",
        None,
    )
    .await;
    insert_dummy_build(
        &env.state,
        &inst_soporte2,
        "soporte",
        "prof-2",
        "completed",
        None,
    )
    .await;
    insert_dummy_build(
        &env.state,
        &inst_tecnico1,
        "tecnico",
        "prof-3",
        "completed",
        None,
    )
    .await;

    // 1. Regular user receives 403 Forbidden attempting role revocation
    let req_reg = Request::builder()
        .uri("/api/builds/revoke-role/soporte")
        .method("POST")
        .header("authorization", format!("Bearer {}", env.regular_token))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "reason": "No autorizado" }).to_string()))
        .unwrap();

    let resp_reg = env.app.clone().oneshot(req_reg).await.unwrap();
    assert_eq!(resp_reg.status(), StatusCode::FORBIDDEN);

    // 2. User with builder:revoke can revoke role
    let req_rev = Request::builder()
        .uri("/api/builds/revoke-role/soporte")
        .method("POST")
        .header("authorization", format!("Bearer {}", env.revoker_token))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "reason": "Rotación masiva de instaladores de soporte" }).to_string(),
        ))
        .unwrap();

    let resp_rev = env.app.clone().oneshot(req_rev).await.unwrap();
    assert_eq!(resp_rev.status(), StatusCode::OK);
    let rev_body: Value =
        serde_json::from_slice(&resp_rev.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(rev_body["role"], "soporte");
    assert_eq!(rev_body["status"], "revoked");
    assert_eq!(rev_body["affected_installers"], 2);

    // 3. Verify public revocations endpoint shows revoked role and installers
    let req_list = Request::builder()
        .uri("/api/builds/revocations")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp_list = env.app.clone().oneshot(req_list).await.unwrap();
    assert_eq!(resp_list.status(), StatusCode::OK);
    let list_body: Value =
        serde_json::from_slice(&resp_list.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let roles = list_body["revoked_roles"].as_array().unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0]["role"], "soporte");
    assert_eq!(
        roles[0]["reason"],
        "Rotación masiva de instaladores de soporte"
    );

    let installers = list_body["revoked_installers"].as_array().unwrap();
    assert_eq!(installers.len(), 2);
}

#[tokio::test]
async fn test_tc_f3_092_rejection_of_device_with_revoked_installer() {
    let env = setup_test_env().await;

    let installer_id = format!("inst-dev-{}", Uuid::now_v7());
    insert_dummy_build(
        &env.state,
        &installer_id,
        "soporte",
        "prof-dev-1",
        "completed",
        None,
    )
    .await;

    let device_id = format!("dev-{}", Uuid::now_v7());

    // 1. Initial heartbeat succeeds
    let req_init = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": device_id,
                "name": "Equipo Recepción",
                "installer_id": installer_id,
                "profile_id": "prof-dev-1"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_init = env.app.clone().oneshot(req_init).await.unwrap();
    assert_eq!(resp_init.status(), StatusCode::OK);

    // 2. Revoke the installer
    let req_rev = Request::builder()
        .uri(format!("/api/builds/{}/revoke", installer_id))
        .method("POST")
        .header("authorization", format!("Bearer {}", env.admin_token))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "reason": "Instalador comprometido" }).to_string(),
        ))
        .unwrap();

    let resp_rev = env.app.clone().oneshot(req_rev).await.unwrap();
    assert_eq!(resp_rev.status(), StatusCode::OK);

    // Reset last_seen_at to avoid rate limiting (< 1s between heartbeats)
    sqlx::query("UPDATE devices SET last_seen_at = datetime('now', '-5 seconds') WHERE id = ?")
        .bind(&device_id)
        .execute(&env.state.db)
        .await
        .unwrap();

    // 3. Heartbeat from device with that installer_id is immediately rejected with 403 Forbidden
    let req_hb2 = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": device_id,
                "installer_id": installer_id
            })
            .to_string(),
        ))
        .unwrap();

    let resp_hb2 = env.app.clone().oneshot(req_hb2).await.unwrap();
    assert_eq!(resp_hb2.status(), StatusCode::FORBIDDEN);
    let hb2_body: Value =
        serde_json::from_slice(&resp_hb2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(hb2_body["error"], "installer_revoked");

    // 4. Also rejected if device omits installer_id because it was already associated in DB
    sqlx::query("UPDATE devices SET last_seen_at = datetime('now', '-5 seconds') WHERE id = ?")
        .bind(&device_id)
        .execute(&env.state.db)
        .await
        .unwrap();
    let req_hb3 = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": device_id
            })
            .to_string(),
        ))
        .unwrap();

    let resp_hb3 = env.app.clone().oneshot(req_hb3).await.unwrap();
    assert_eq!(resp_hb3.status(), StatusCode::FORBIDDEN);
    let hb3_body: Value =
        serde_json::from_slice(&resp_hb3.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(hb3_body["error"], "installer_revoked");

    // 5. Verify audit event build.registration_rejected
    let rejected_events = env
        .state
        .audit
        .query_events(EventFilter {
            action: Some("build.registration_rejected".to_string()),
            category: Some(Category::Build),
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(!rejected_events.is_empty());
    let ev = &rejected_events[0];
    assert_eq!(ev.outcome, Outcome::Denied);
    assert_eq!(ev.details["device_id"], device_id);
    assert_eq!(ev.details["installer_id"], installer_id);
    assert_eq!(ev.details["rejection_type"], "installer_revoked");
}

#[tokio::test]
async fn test_tc_f3_093_rejection_of_device_with_revoked_role() {
    let env = setup_test_env().await;

    let installer_id = format!("inst-role-{}", Uuid::now_v7());
    insert_dummy_build(
        &env.state,
        &installer_id,
        "tecnico",
        "prof-tec-role",
        "completed",
        None,
    )
    .await;

    // Revoke role "tecnico"
    let req_rev_role = Request::builder()
        .uri("/api/builds/revoke-role/tecnico")
        .method("POST")
        .header("authorization", format!("Bearer {}", env.admin_token))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "reason": "Revocación global de técnicos" }).to_string(),
        ))
        .unwrap();

    let resp_rev = env.app.clone().oneshot(req_rev_role).await.unwrap();
    assert_eq!(resp_rev.status(), StatusCode::OK);

    // Heartbeat from device with this installer is rejected with installer_revoked
    let dev_id = format!("dev-tec-{}", Uuid::now_v7());
    let req_hb = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": dev_id,
                "installer_id": installer_id
            })
            .to_string(),
        ))
        .unwrap();

    let resp_hb = env.app.clone().oneshot(req_hb).await.unwrap();
    assert_eq!(resp_hb.status(), StatusCode::FORBIDDEN);
    let hb_body: Value =
        serde_json::from_slice(&resp_hb.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(hb_body["error"], "installer_revoked");
}

#[tokio::test]
async fn test_tc_f3_094_rejection_of_device_with_expired_installer() {
    let env = setup_test_env().await;

    let expired_at = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let installer_id = format!("inst-exp-{}", Uuid::now_v7());
    insert_dummy_build(
        &env.state,
        &installer_id,
        "soporte",
        "prof-exp-1",
        "completed",
        Some(&expired_at),
    )
    .await;

    let dev_id = format!("dev-exp-{}", Uuid::now_v7());
    let req_hb = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": dev_id,
                "installer_id": installer_id
            })
            .to_string(),
        ))
        .unwrap();

    let resp_hb = env.app.clone().oneshot(req_hb).await.unwrap();
    assert_eq!(resp_hb.status(), StatusCode::FORBIDDEN);
    let hb_body: Value =
        serde_json::from_slice(&resp_hb.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(hb_body["error"], "installer_expired");

    // Verify audit event
    let events = env
        .state
        .audit
        .query_events(EventFilter {
            action: Some("build.registration_rejected".to_string()),
            category: Some(Category::Build),
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(!events.is_empty());
    assert_eq!(events[0].details["rejection_type"], "installer_expired");
}

#[tokio::test]
async fn test_tc_f3_095_valid_installer_header_and_persistence() {
    let env = setup_test_env().await;

    let future_exp = (Utc::now() + chrono::Duration::days(30)).to_rfc3339();
    let installer_id = format!("inst-ok-{}", Uuid::now_v7());
    insert_dummy_build(
        &env.state,
        &installer_id,
        "soporte",
        "prof-valid",
        "completed",
        Some(&future_exp),
    )
    .await;

    let dev_id = format!("dev-hdr-{}", Uuid::now_v7());

    // Register via x-installer-id and x-profile-id headers
    let req_hb = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-installer-id", &installer_id)
        .header("x-profile-id", "prof-valid")
        .body(Body::from(
            json!({
                "id": dev_id,
                "name": "Equipo Cabecera"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_hb = env.app.clone().oneshot(req_hb).await.unwrap();
    assert_eq!(resp_hb.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp_hb.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["installer_id"], installer_id);
    assert_eq!(body["profile_id"], "prof-valid");
}

#[tokio::test]
async fn test_tc_f3_096_safe_degradation_and_cache_ttl() {
    let pool = init_db("sqlite::memory:").await.unwrap();
    let checker = cercano_api::revocation::RevocationChecker::new(
        pool.clone(),
        Duration::from_millis(150),
        true, // fail-closed
    );

    // Initial get
    let (res1, etag1) = checker.get_revocations().await.unwrap();
    assert!(res1.revoked_installers.is_empty());

    // Insert revoked build
    let job_id = Uuid::now_v7().to_string();
    sqlx::query(
        r#"
        INSERT INTO users (id, username, password_hash, role) VALUES ('u-deg', 'adm-deg', 'h', 'admin');
        INSERT INTO build_jobs (id, user_id, role, profile_id, status, revoked_at)
        VALUES (?, 'u-deg', 'soporte', 'prof-deg', 'revoked', datetime('now'));
        "#,
    )
    .bind(&job_id)
    .execute(&pool)
    .await
    .unwrap();

    // Query within 150ms should return cached empty response
    let (res_cached, etag_cached) = checker.get_revocations().await.unwrap();
    assert_eq!(etag1, etag_cached);
    assert!(res_cached.revoked_installers.is_empty());

    // Sleep past TTL (200ms)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Next query refreshes from DB automatically
    let (res_refreshed, etag_refreshed) = checker.get_revocations().await.unwrap();
    assert_ne!(etag1, etag_refreshed);
    assert_eq!(res_refreshed.revoked_installers.len(), 1);

    // Fail-safe checker test
    let checker_failsafe = cercano_api::revocation::RevocationChecker::new(
        pool.clone(),
        Duration::from_secs(60),
        false, // fail-safe
    );
    assert!(!checker_failsafe.fail_closed());
}
