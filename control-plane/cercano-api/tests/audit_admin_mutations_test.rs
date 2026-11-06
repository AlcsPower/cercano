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

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::tempdir;
use tower::ServiceExt;

use audit_core::{Category, EventFilter, Outcome, Source};
use cercano_api::{
    config::Config, create_app, db::init_db, server_keys::generate_server_keypair, AppState,
};

struct TestEnv {
    app: axum::Router,
    state: AppState,
    _key_dir: tempfile::TempDir,
}

async fn setup_test_env() -> TestEnv {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let key_dir = tempdir().unwrap();
    let key_path = key_dir.path().join("id_ed25519.pub");
    let priv_path = key_dir.path().join("id_ed25519");

    // Initialize initial server key pair
    let initial_keys = generate_server_keypair().unwrap();
    fs::write(&key_path, &initial_keys.public_key_base64).unwrap();
    fs::write(&priv_path, &initial_keys.private_key_base64).unwrap();

    let config = Config {
        server_key_path: key_path.to_str().unwrap().to_string(),
        internal_token: "test_internal_token_secret".to_string(),
        ..Default::default()
    };

    let state = AppState::new(config, db, audit);
    let app = create_app(state.clone());

    TestEnv {
        app,
        state,
        _key_dir: key_dir,
    }
}

fn action_filter(action: &str) -> EventFilter {
    EventFilter {
        action: Some(action.to_string()),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_f2_08_full_administrative_mutation_audit_lifecycle() {
    let env = setup_test_env().await;

    // ------------------------------------------------------------------------
    // 1. Administrative Bootstrap emits `auth.bootstrap`
    // ------------------------------------------------------------------------
    let bootstrap_req = Request::builder()
        .uri("/api/auth/bootstrap")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-trace-id", "0192e2fb-0001-7000-8000-000000000001")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "superadmin",
                "password": "SuperAdminPassword123!"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(bootstrap_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let bootstrap_res: Value = serde_json::from_slice(&body_bytes).unwrap();
    let admin_id = bootstrap_res["id"].as_str().unwrap().to_string();

    let bootstrap_events = env
        .state
        .audit
        .query_events(action_filter("auth.bootstrap"))
        .await
        .unwrap();
    assert_eq!(bootstrap_events.len(), 1);
    let b_ev = &bootstrap_events[0];
    assert_eq!(b_ev.action, "auth.bootstrap");
    assert_eq!(b_ev.category, Category::Auth);
    assert_eq!(b_ev.source, Source::Api);
    assert_eq!(b_ev.outcome, Outcome::Success);
    assert_eq!(b_ev.actor.id, admin_id);
    assert_eq!(b_ev.actor.name.as_deref(), Some("superadmin"));
    assert_eq!(b_ev.subject.as_ref().unwrap().id, admin_id);
    assert_eq!(b_ev.details["role"], "admin");
    assert_eq!(b_ev.details["username"], "superadmin");
    // Ensure zero secrets/passwords in details
    assert!(b_ev.details.get("password").is_none());

    // ------------------------------------------------------------------------
    // 2. Failed logins emit `auth.failed` (without recording passwords!)
    // ------------------------------------------------------------------------
    // Attempt 1: wrong password
    let failed_login_req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "superadmin",
                "password": "WrongPassword999!"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(failed_login_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Attempt 2: unknown user
    let unknown_user_req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "ghost_user",
                "password": "AnyPassword123!"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(unknown_user_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let failed_events = env
        .state
        .audit
        .query_events(action_filter("auth.failed"))
        .await
        .unwrap();
    assert_eq!(failed_events.len(), 2);

    for ev in &failed_events {
        assert_eq!(ev.action, "auth.failed");
        assert_eq!(ev.category, Category::Auth);
        assert_eq!(ev.source, Source::Api);
        assert_eq!(ev.outcome, Outcome::Failure);
        // Absolute verification: no password field anywhere in details
        assert!(ev.details.get("password").is_none());
        assert!(ev.details.get("target_username").is_some());
    }

    // ------------------------------------------------------------------------
    // 3. Successful login emits `auth.login`
    // ------------------------------------------------------------------------
    let login_req = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "superadmin",
                "password": "SuperAdminPassword123!"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let login_res: Value = serde_json::from_slice(&body_bytes).unwrap();
    let admin_token = login_res["token"].as_str().unwrap().to_string();

    let login_events = env
        .state
        .audit
        .query_events(action_filter("auth.login"))
        .await
        .unwrap();
    assert_eq!(login_events.len(), 1);
    let l_ev = &login_events[0];
    assert_eq!(l_ev.action, "auth.login");
    assert_eq!(l_ev.category, Category::Auth);
    assert_eq!(l_ev.outcome, Outcome::Success);
    assert_eq!(l_ev.actor.id, admin_id);
    assert_eq!(l_ev.actor.name.as_deref(), Some("superadmin"));
    assert_eq!(l_ev.subject.as_ref().unwrap().id, admin_id);
    assert_eq!(l_ev.details["role"], "admin");
    assert_eq!(l_ev.details["username"], "superadmin");
    assert!(l_ev.details.get("password").is_none());

    // ------------------------------------------------------------------------
    // 4. Device registration via heartbeat emits `console.device_register`
    // ------------------------------------------------------------------------
    let device_id = "test-device-workstation-01";
    let hb_req = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "id": device_id,
                "name": "Workstation Contabilidad",
                "hostname": "ws-cont-01",
                "os": "Windows 11 Pro",
                "version": "1.3.0"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(hb_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let dev_reg_events = env
        .state
        .audit
        .query_events(action_filter("console.device_register"))
        .await
        .unwrap();
    assert_eq!(dev_reg_events.len(), 1);
    let d_ev = &dev_reg_events[0];
    assert_eq!(d_ev.action, "console.device_register");
    assert_eq!(d_ev.category, Category::Console);
    assert_eq!(d_ev.outcome, Outcome::Success);
    assert_eq!(d_ev.actor.id, device_id);
    assert_eq!(d_ev.actor.actor_type, "device");
    assert_eq!(d_ev.subject.as_ref().unwrap().id, device_id);
    assert_eq!(d_ev.details["hostname"], "ws-cont-01");
    assert_eq!(d_ev.details["os"], "Windows 11 Pro");

    // Second heartbeat from the same device must NOT duplicate registration event
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let hb_repeat = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "id": device_id,
                "name": "Workstation Contabilidad",
                "hostname": "ws-cont-01",
                "os": "Windows 11 Pro",
                "version": "1.3.0"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(hb_repeat).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let dev_reg_events_after = env
        .state
        .audit
        .query_events(action_filter("console.device_register"))
        .await
        .unwrap();
    assert_eq!(dev_reg_events_after.len(), 1);

    // ------------------------------------------------------------------------
    // 5. Server Key Rotation emits `console.rotate_key`
    // ------------------------------------------------------------------------
    let rotate_req = Request::builder()
        .uri("/api/server/keys/rotate")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", admin_token))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "reason": "periodic_scheduled_rotation"
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(rotate_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let rotate_res: Value = serde_json::from_slice(&body_bytes).unwrap();
    let new_pub_key = rotate_res["public_key"].as_str().unwrap();

    let rotate_events = env
        .state
        .audit
        .query_events(action_filter("console.rotate_key"))
        .await
        .unwrap();
    assert_eq!(rotate_events.len(), 1);
    let r_ev = &rotate_events[0];
    assert_eq!(r_ev.action, "console.rotate_key");
    assert_eq!(r_ev.category, Category::Console);
    assert_eq!(r_ev.source, Source::Console);
    assert_eq!(r_ev.outcome, Outcome::Success);
    assert_eq!(r_ev.actor.id, admin_id);
    assert_eq!(r_ev.actor.name.as_deref(), Some("superadmin"));
    assert_eq!(r_ev.subject.as_ref().unwrap().id, "server_keys");
    assert_eq!(r_ev.details["key_type"], "ed25519");
    assert_eq!(r_ev.details["new_public_key"], new_pub_key);
    assert!(r_ev.details["old_key_fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));
    assert!(r_ev.details["new_key_fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));
    // Absolute rule: NEVER log private keys
    assert!(r_ev.details.get("private_key").is_none());
    assert!(r_ev.details.get("secret").is_none());

    // ------------------------------------------------------------------------
    // 6. Device Deletion emits `console.device_delete`
    // ------------------------------------------------------------------------
    let delete_req = Request::builder()
        .uri(format!("/api/devices/{}", device_id))
        .method("DELETE")
        .header("authorization", format!("Bearer {}", admin_token))
        .body(Body::empty())
        .unwrap();

    let res = env.app.clone().oneshot(delete_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let delete_events = env
        .state
        .audit
        .query_events(action_filter("console.device_delete"))
        .await
        .unwrap();
    assert_eq!(delete_events.len(), 1);
    let del_ev = &delete_events[0];
    assert_eq!(del_ev.action, "console.device_delete");
    assert_eq!(del_ev.category, Category::Console);
    assert_eq!(del_ev.source, Source::Console);
    assert_eq!(del_ev.outcome, Outcome::Success);
    assert_eq!(del_ev.actor.id, admin_id);
    assert_eq!(del_ev.actor.name.as_deref(), Some("superadmin"));
    assert_eq!(del_ev.subject.as_ref().unwrap().id, device_id);
    assert_eq!(del_ev.details["device_id"], device_id);

    // ------------------------------------------------------------------------
    // 7. Logout emits `auth.logout`
    // ------------------------------------------------------------------------
    let logout_req = Request::builder()
        .uri("/api/auth/logout")
        .method("POST")
        .header("authorization", format!("Bearer {}", admin_token))
        .body(Body::empty())
        .unwrap();

    let res = env.app.clone().oneshot(logout_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let logout_events = env
        .state
        .audit
        .query_events(action_filter("auth.logout"))
        .await
        .unwrap();
    assert_eq!(logout_events.len(), 1);
    let lo_ev = &logout_events[0];
    assert_eq!(lo_ev.action, "auth.logout");
    assert_eq!(lo_ev.category, Category::Auth);
    assert_eq!(lo_ev.outcome, Outcome::Success);
    assert_eq!(lo_ev.actor.id, admin_id);
    assert_eq!(lo_ev.actor.name.as_deref(), Some("superadmin"));

    // ------------------------------------------------------------------------
    // 8. Cryptographic Hash Chain Verification across 100% of mutations
    // ------------------------------------------------------------------------
    // Total events:
    // 1 auth.bootstrap
    // 2 auth.failed
    // 1 auth.login
    // 1 console.device_register
    // 1 console.rotate_key
    // 1 console.device_delete
    // 1 auth.logout
    // = 8 events in sequence
    let verification = env.state.audit.verify_chain(None, None).await.unwrap();
    assert!(
        verification.is_valid,
        "Audit chain must be completely valid and unbroken: {:?}",
        verification.error
    );
    assert_eq!(verification.total_verified, 8);
    assert!(verification.error.is_none());
}
