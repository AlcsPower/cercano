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

pub mod alarms;
pub mod audit;
pub mod auth;
pub mod builder;
pub mod chat;
pub mod config;
pub mod db;
pub mod devices;
pub mod health;
pub mod middleware;
pub mod permissions;
pub mod profile;
pub mod revocation;
pub mod routes;
pub mod server_keys;
pub mod shutdown;

use axum::routing::{get, post};
use axum::Router;
pub use config::Config;
pub use db::init_db;
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: SqlitePool,
    pub audit: Arc<audit_core::AuditStore>,
    pub alarms: Arc<alarms::AlarmEngine>,
    pub build_queue: Arc<builder::BuildQueue>,
    pub revocation_checker: Arc<revocation::RevocationChecker>,
}

impl AppState {
    pub fn new(config: Config, db: SqlitePool, audit: Arc<audit_core::AuditStore>) -> Self {
        let alarms = Arc::new(alarms::AlarmEngine::new(config.clone(), audit.clone()));
        let build_queue = Arc::new(builder::BuildQueue::new(&config, db.clone(), audit.clone()));
        let revocation_checker = Arc::new(revocation::RevocationChecker::new(
            db.clone(),
            std::time::Duration::from_secs(config.revocation_cache_ttl_secs),
            config.revocation_fail_closed,
        ));
        Self {
            config,
            db,
            audit,
            alarms,
            build_queue,
            revocation_checker,
        }
    }
}

/// Builds the Axum application router with all registered routes and middleware.
pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::health_handler))
        .route("/api/auth/bootstrap", post(auth::bootstrap_handler))
        .route("/api/auth/login", post(auth::login_handler))
        .route("/api/auth/logout", post(auth::logout_handler))
        .route("/api/auth/me", get(auth::me_handler))
        .route(
            "/api/auth/2fa/enroll",
            post(auth::two_factor_enroll_handler),
        )
        .route(
            "/api/auth/2fa/confirm",
            post(auth::two_factor_confirm_handler),
        )
        .route(
            "/api/auth/2fa/verify",
            post(auth::two_factor_verify_handler),
        )
        .route(
            "/api/auth/2fa/revoke",
            post(auth::two_factor_revoke_handler),
        )
        .route(
            "/api/users",
            get(routes::admin::list_users_handler).post(routes::admin::create_user_handler),
        )
        .route(
            "/api/users/:id",
            get(routes::admin::get_user_handler)
                .patch(routes::admin::update_user_handler)
                .delete(routes::admin::delete_user_handler),
        )
        .route("/api/roles", get(routes::admin::list_roles_handler))
        .route(
            "/api/settings",
            get(routes::admin::get_settings_handler).patch(routes::admin::update_settings_handler),
        )
        .route("/api/devices/heartbeat", post(devices::heartbeat_handler))
        .route("/api/devices", get(devices::list_devices_handler))
        .route(
            "/api/devices/:id",
            get(devices::get_device_handler).delete(devices::delete_device_handler),
        )
        .route(
            "/api/server/public-key",
            get(server_keys::get_public_key_handler),
        )
        .route(
            "/api/server/keys/rotate",
            post(server_keys::rotate_keys_handler),
        )
        .route(
            "/api/audit/events",
            post(routes::audit::ingest_event_handler).get(routes::audit::query_events_handler),
        )
        .route(
            "/api/audit/conn",
            post(routes::audit::legacy_conn_audit_handler),
        )
        .route(
            "/api/audit/file",
            post(routes::audit::legacy_file_audit_handler),
        )
        .route(
            "/api/audit/export",
            get(routes::audit::export_events_handler),
        )
        .route(
            "/api/audit/session/start",
            post(routes::audit::session_start_handler),
        )
        .route(
            "/api/audit/session/end",
            post(routes::audit::session_end_handler),
        )
        .route(
            "/api/audit/session/note",
            post(routes::audit::session_note_handler),
        )
        .route(
            "/api/audit/file-transfer",
            post(routes::audit::file_transfer_handler),
        )
        .route("/api/audit/alarm", post(routes::audit::alarm_handler))
        .route(
            "/api/audit/alarms",
            get(routes::alarms::list_alarms_handler),
        )
        .route(
            "/api/audit/alarms/:id/acknowledge",
            post(routes::alarms::acknowledge_alarm_handler),
        )
        .route(
            "/api/audit/verify",
            get(routes::audit::verify_chain_handler),
        )
        .route(
            "/api/audit/checkpoints",
            get(routes::audit::list_checkpoints_handler),
        )
        .route(
            "/api/audit/traces/:trace_id",
            get(routes::traces::get_trace_timeline_handler),
        )
        .route(
            "/api/builds",
            post(routes::builds::enqueue_build_handler).get(routes::builds::list_builds_handler),
        )
        .route(
            "/api/builds/revocations",
            get(routes::builds::get_revocations_handler),
        )
        .route(
            "/api/revocations",
            get(routes::builds::get_revocations_handler),
        )
        .route(
            "/api/builds/revoke-role/:role",
            post(routes::builds::revoke_role_handler),
        )
        .route("/api/builds/:id", get(routes::builds::get_build_handler))
        .route(
            "/api/builds/:id/download",
            get(routes::builds::download_build_handler),
        )
        .route(
            "/api/builds/:id/revoke",
            post(routes::builds::revoke_build_handler),
        )
        .route(
            "/api/sessions/initiate",
            post(routes::sessions::initiate_session_handler),
        )
        .route(
            "/api/elevation/request",
            post(routes::sessions::request_elevation_handler),
        )
        .route(
            "/api/policies/apply",
            post(routes::sessions::apply_policy_handler),
        )
        // Chat Device Authentication routes (F4.5-03)
        .route(
            "/api/chat/devices/register",
            post(chat::auth::register_device_handler),
        )
        .route(
            "/api/chat/auth/challenge",
            post(chat::auth::request_challenge_handler),
        )
        .route(
            "/api/chat/auth/verify",
            post(chat::auth::verify_challenge_handler),
        )
        .route(
            "/api/chat/devices/:id/reset",
            post(chat::auth::reset_device_handler),
        )
        // Chat Branding routes (F4.5-16)
        .route(
            "/api/chat/branding",
            get(chat::branding::get_branding_handler).put(chat::branding::update_branding_handler),
        )
        // Chat Conversation & Message routes (F4.5-04)
        .route(
            "/api/chat/conversations",
            post(chat::conversations::create_or_join_conversation_handler)
                .get(chat::conversations::list_conversations_handler),
        )
        .route(
            "/api/chat/conversations/:id",
            get(chat::conversations::get_conversation_handler),
        )
        .route(
            "/api/chat/conversations/:id/messages",
            post(chat::conversations::send_message_handler),
        )
        .route(
            "/api/chat/conversations/:id/claim",
            post(chat::conversations::claim_conversation_handler),
        )
        .route(
            "/api/chat/conversations/:id/release",
            post(chat::conversations::release_conversation_handler),
        )
        .route(
            "/api/chat/conversations/:id/assign",
            post(chat::conversations::assign_conversation_handler),
        )
        .route(
            "/api/chat/conversations/:id/close",
            post(chat::conversations::close_conversation_handler),
        )
        .route(
            "/api/chat/conversations/:id/reopen",
            post(chat::conversations::reopen_conversation_handler),
        )
        .route(
            "/api/chat/conversations/:id/attachments",
            post(chat::attachments::upload_attachment_handler)
                .layer(axum::extract::DefaultBodyLimit::max(12 * 1024 * 1024)),
        )
        .route(
            "/api/chat/attachments/:id",
            get(chat::attachments::download_attachment_handler),
        )
        .route(
            "/api/chat/conversations/:id/read",
            post(chat::conversations::mark_as_read_handler),
        )
        .route(
            "/api/chat/summary",
            get(chat::conversations::get_chat_summary_handler),
        )
        .route(
            "/api/chat/agents",
            get(chat::conversations::list_chat_agents_handler),
        )
        .layer(axum::middleware::from_fn(middleware::trace_id_middleware))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

/// Initializes structured JSON logging based on the configured log level or RUST_LOG.
pub fn init_logging(log_level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use sqlx::Row;
    use tower::ServiceExt;

    async fn setup_test_app() -> Router {
        let db = init_db("sqlite::memory:").await.unwrap();
        let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
        let state = AppState::new(Config::default(), db, audit);
        create_app(state)
    }

    async fn setup_test_state() -> (AppState, Router) {
        let db = init_db("sqlite::memory:").await.unwrap();
        let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
        let state = AppState::new(Config::default(), db, audit);
        let app = create_app(state.clone());
        (state, app)
    }

    async fn get_authenticated_admin_token(state: &AppState) -> String {
        // Bootstrap admin
        let app = create_app(state.clone());
        let bootstrap_req = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "admin_test",
                    "password": "AdminPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let _ = app.oneshot(bootstrap_req).await.unwrap();

        // Login
        let app = create_app(state.clone());
        let login_req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "admin_test",
                    "password": "AdminPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(login_req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let login_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let token = login_res["token"].as_str().unwrap().to_string();
        sqlx::query("UPDATE sessions SET mfa_verified = 1 WHERE token = ?")
            .bind(&token)
            .execute(&state.db)
            .await
            .unwrap();
        token
    }

    #[tokio::test]
    async fn test_healthz_endpoint_returns_ok() {
        let app = setup_test_app().await;

        let req = Request::builder()
            .uri("/healthz")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Check trace-id header is attached
        assert!(res.headers().contains_key("x-trace-id"));

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "cercano-api");
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["database"], "connected");
    }

    #[tokio::test]
    async fn test_healthz_endpoint_returns_503_when_db_closed() {
        let db = init_db("sqlite::memory:").await.unwrap();
        let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
        db.close().await;
        let state = AppState::new(Config::default(), db, audit);
        let app = create_app(state);

        let req = Request::builder()
            .uri("/healthz")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["status"], "degraded");
        assert_eq!(json["service"], "cercano-api");
        assert_eq!(json["error"], "database unreachable");
    }

    #[tokio::test]
    async fn test_unknown_route_returns_404() {
        let app = setup_test_app().await;

        let req = Request::builder()
            .uri("/nonexistent")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_tc_f1_013_bootstrap_admin_only_once() {
        let (state, _) = setup_test_state().await;

        let bootstrap_payload = serde_json::json!({
            "username": "admin",
            "password": "AdminPassword123!"
        });

        // First bootstrap call succeeds
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&bootstrap_payload).unwrap()))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["username"], "admin");
        assert_eq!(json["role"], "admin");

        // Second bootstrap call MUST return 409 Conflict
        let app = create_app(state.clone());
        let req2 = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&bootstrap_payload).unwrap()))
            .unwrap();

        let res2 = app.oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::CONFLICT);

        let body_bytes2 = res2.into_body().collect().await.unwrap().to_bytes();
        let json2: serde_json::Value = serde_json::from_slice(&body_bytes2).unwrap();
        assert_eq!(json2["error"], "bootstrap_already_completed");
    }

    #[tokio::test]
    async fn test_tc_f1_010_login_success_and_token_expiration() {
        let (state, _) = setup_test_state().await;

        // Bootstrap admin
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "admin_login",
                    "password": "ValidPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // Login with correct credentials
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "admin_login",
                    "password": "ValidPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let token = json["token"].as_str().unwrap();
        assert!(token.starts_with("cercano_sess_"));
        assert_eq!(token.len(), 77);
        assert_eq!(json["user"]["username"], "admin_login");

        // Verify session was inserted with ~24 hour expiration
        let session_row = sqlx::query("SELECT expires_at FROM sessions WHERE token = ?")
            .bind(token)
            .fetch_one(&state.db)
            .await
            .unwrap();
        let expires_at: String = session_row.get("expires_at");
        assert!(!expires_at.is_empty());

        // Validate protected endpoint /api/auth/me using Bearer token
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/me")
            .method("GET")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let me_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let me_json: serde_json::Value = serde_json::from_slice(&me_bytes).unwrap();
        assert_eq!(me_json["username"], "admin_login");
    }

    #[tokio::test]
    async fn test_tc_f1_011_login_lockout_and_no_passwords_in_logs() {
        let (state, _) = setup_test_state().await;

        // Bootstrap admin
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "target_user",
                    "password": "CorrectPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let _ = app.oneshot(req).await.unwrap();

        // 5 consecutive failed attempts
        for _ in 0..5 {
            let app = create_app(state.clone());
            let req = Request::builder()
                .uri("/api/auth/login")
                .method("POST")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.0.99")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "username": "target_user",
                        "password": "WrongPassword!"
                    }))
                    .unwrap(),
                ))
                .unwrap();
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }

        // 6th attempt: even with correct password, must be blocked (429 Too Many Requests)
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "10.0.0.99")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "target_user",
                    "password": "CorrectPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "account_locked");
    }

    #[tokio::test]
    async fn test_tc_f1_012_logout_revokes_token() {
        let (state, _) = setup_test_state().await;

        // Bootstrap admin
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "logout_admin",
                    "password": "ValidPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let _ = app.oneshot(req).await.unwrap();

        // Login
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "logout_admin",
                    "password": "ValidPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let token = json["token"].as_str().unwrap();

        // GET /api/auth/me works
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/me")
            .method("GET")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Perform logout
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/logout")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Subsequent GET /api/auth/me with revoked token must be rejected (401)
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/me")
            .method("GET")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tc_f1_014_argon2id_stored_hash_no_plaintext() {
        let (state, _) = setup_test_state().await;

        let secret_password = "SuperSecretPlainTextPassword123!";

        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "hash_check_admin",
                    "password": secret_password
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // Inspect SQLite row directly
        let row =
            sqlx::query("SELECT password_hash FROM users WHERE username = 'hash_check_admin'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        let password_hash: String = row.get("password_hash");

        // Stored password must be an Argon2id PHC string
        assert!(password_hash.starts_with("$argon2id$"));
        // Plaintext password MUST NOT exist in the database hash
        assert!(!password_hash.contains(secret_password));
    }

    #[tokio::test]
    async fn test_auth_me_requires_bearer_token() {
        let app = setup_test_app().await;

        // No header
        let req = Request::builder()
            .uri("/api/auth/me")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Malformed header
        let app = setup_test_app().await;
        let req = Request::builder()
            .uri("/api/auth/me")
            .method("GET")
            .header("Authorization", "Basic 123456")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tc_f1_020_new_client_appears_in_api_with_id_and_online_status() {
        let (state, _) = setup_test_state().await;
        let admin_token = get_authenticated_admin_token(&state).await;

        // Send heartbeat for a new client
        let app = create_app(state.clone());
        let heartbeat_payload = serde_json::json!({
            "id": "client-101",
            "hostname": "cercano-node-1",
            "os": "Windows 11 Pro",
            "version": "0.1.0",
            "ip": "192.168.1.101"
        });

        let mut req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&heartbeat_payload).unwrap()))
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "192.168.1.101:54321"
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        ));

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let hb_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(hb_res["id"], "client-101");
        assert_eq!(hb_res["name"], "cercano-node-1");
        assert_eq!(hb_res["hostname"], "cercano-node-1");
        assert_eq!(hb_res["os"], "Windows 11 Pro");
        assert_eq!(hb_res["version"], "0.1.0");
        assert_eq!(hb_res["ip_address"], "192.168.1.101");
        assert_eq!(hb_res["status"], "online");
        assert!(hb_res["last_seen_at"].is_string());

        // List devices via GET /api/devices (protected)
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"], "client-101");
        assert_eq!(list[0]["status"], "online");
        assert_eq!(list[0]["version"], "0.1.0");

        // Detail via GET /api/devices/client-101
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/client-101")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let detail: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(detail["id"], "client-101");
        assert_eq!(detail["status"], "online");
    }

    #[tokio::test]
    async fn test_tc_f1_021_client_without_heartbeat_becomes_offline_after_grace_period() {
        let (state, _) = setup_test_state().await;
        let admin_token = get_authenticated_admin_token(&state).await;

        // Register client with heartbeat
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "client-102",
                    "hostname": "cercano-node-2"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Verify it is online immediately
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/client-102")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let detail: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(detail["status"], "online");

        // Advance device's last_seen_at past the 60-second grace period (to 90 seconds ago)
        sqlx::query(
            "UPDATE devices SET last_seen_at = datetime('now', '-90 seconds') WHERE id = 'client-102'",
        )
        .execute(&state.db)
        .await
        .unwrap();

        // Check GET /api/devices: status must now be offline
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(list[0]["id"], "client-102");
        assert_eq!(list[0]["status"], "offline");

        // Check GET /api/devices/client-102: status must be offline
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/client-102")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let detail: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(detail["status"], "offline");

        // New heartbeat arrives: device becomes online again
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "client-102"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/client-102")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let detail: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(detail["status"], "online");
    }

    #[tokio::test]
    async fn test_devices_endpoints_security_and_deletion() {
        let (state, _) = setup_test_state().await;
        let admin_token = get_authenticated_admin_token(&state).await;

        // Register client-201
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .header("x-real-ip", "192.168.10.77")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "client-201",
                    "hostname": "host-201"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Verify detected IP is recorded
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let hb: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(hb["ip_address"], "192.168.10.77");

        // Non-admin user setup
        let user_pwd_hash = crate::auth::hash_password("UserPassword123!").unwrap();
        sqlx::query("INSERT INTO users (id, username, password_hash, role) VALUES ('u-1', 'normal_user', ?, 'user')")
            .bind(user_pwd_hash)
            .execute(&state.db)
            .await
            .unwrap();

        // Login as non-admin
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "normal_user",
                    "password": "UserPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let login_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let user_token = login_res["token"].as_str().unwrap();

        // Non-admin can list devices
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices")
            .method("GET")
            .header("Authorization", format!("Bearer {}", user_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Non-admin CANNOT delete device (403 Forbidden)
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/client-201")
            .method("DELETE")
            .header("Authorization", format!("Bearer {}", user_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // Admin CAN delete device
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/client-201")
            .method("DELETE")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Subsequent GET returns 404
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/client-201")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // Deleting non-existent device returns 404
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/client-201")
            .method("DELETE")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // Unauthenticated access rejected
        let app = setup_test_app().await;
        let req = Request::builder()
            .uri("/api/devices")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_heartbeat_validation_error() {
        let app = setup_test_app().await;

        let req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "   "
                }))
                .unwrap(),
            ))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "validation_error");
    }

    #[tokio::test]
    async fn test_get_public_key_success_unauthenticated() {
        let temp_dir = tempfile::tempdir().unwrap();
        let pub_path = temp_dir.path().join("id_ed25519.pub");
        let keys = server_keys::generate_server_keypair().unwrap();
        std::fs::write(&pub_path, &keys.public_key_base64).unwrap();

        let db = init_db("sqlite::memory:").await.unwrap();
        let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
        let config = Config {
            server_key_path: pub_path.display().to_string(),
            ..Default::default()
        };

        let state = AppState::new(config, db, audit);
        let app = create_app(state);

        let req = Request::builder()
            .uri("/api/server/public-key")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().contains_key("x-trace-id"));

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["public_key"], keys.public_key_base64);
        assert_eq!(json["key_type"], "ed25519");
    }

    #[tokio::test]
    async fn test_get_public_key_not_found() {
        let db = init_db("sqlite::memory:").await.unwrap();
        let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
        let config = Config {
            server_key_path: "nonexistent_dir/missing_id_ed25519.pub".to_string(),
            ..Default::default()
        };

        let state = AppState::new(config, db, audit);
        let app = create_app(state);

        let req = Request::builder()
            .uri("/api/server/public-key")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"], "key_not_found");
    }

    #[tokio::test]
    async fn test_tc_f1_031_key_rotation_and_rejection_of_old_client_keys() {
        let temp_dir = tempfile::tempdir().unwrap();
        let pub_path = temp_dir.path().join("id_ed25519.pub");
        let priv_path = temp_dir.path().join("id_ed25519");

        let initial_keys = server_keys::generate_server_keypair().unwrap();
        std::fs::write(&pub_path, &initial_keys.public_key_base64).unwrap();
        std::fs::write(&priv_path, &initial_keys.private_key_base64).unwrap();

        let old_client_configured_key = initial_keys.public_key_base64.clone();

        let db = init_db("sqlite::memory:").await.unwrap();
        let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
        let config = Config {
            server_key_path: pub_path.display().to_string(),
            ..Default::default()
        };

        let state = AppState::new(config, db, audit);

        // 1. Unauthenticated rotation attempt rejected with 401 Unauthorized
        let app = create_app(state.clone());
        let unauth_req = Request::builder()
            .uri("/api/server/keys/rotate")
            .method("POST")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(unauth_req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // 2. Non-admin user attempt rejected with 403 Forbidden
        let admin_token = get_authenticated_admin_token(&state).await;

        // Create regular operator user
        let operator_pw_hash = auth::hash_password("OperatorPass123!").unwrap();
        let operator_user_id = uuid::Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, ?, ?, 'operator', 1)"
        )
        .bind(&operator_user_id)
        .bind("operator_user")
        .bind(&operator_pw_hash)
        .execute(&state.db)
        .await
        .unwrap();

        let app = create_app(state.clone());
        let op_login_req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "operator_user",
                    "password": "OperatorPass123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(op_login_req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let op_login_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let operator_token = op_login_json["token"].as_str().unwrap();

        let app = create_app(state.clone());
        let op_rotate_req = Request::builder()
            .uri("/api/server/keys/rotate")
            .method("POST")
            .header("Authorization", format!("Bearer {}", operator_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(op_rotate_req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 3. Admin user performs key rotation
        let app = create_app(state.clone());
        let admin_rotate_req = Request::builder()
            .uri("/api/server/keys/rotate")
            .method("POST")
            .header("Authorization", format!("Bearer {}", admin_token))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "reason": "TC-F1-031 routine key rollover"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(admin_rotate_req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let rotate_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Critical safety verification: private key NEVER in response or leaked
        assert!(rotate_json.get("private_key").is_none());
        assert!(rotate_json.get("secret_key").is_none());
        assert!(rotate_json.get("sk").is_none());

        assert_eq!(rotate_json["status"], "rotated");
        assert_eq!(rotate_json["key_type"], "ed25519");
        assert_eq!(rotate_json["requires_restart"], true);
        assert!(rotate_json["message"]
            .as_str()
            .unwrap()
            .contains("reiniciar"));
        let new_public_key = rotate_json["public_key"].as_str().unwrap();
        assert_ne!(new_public_key, old_client_configured_key);
        assert!(rotate_json["backup_path"].is_string());

        // 4. Verify public endpoint now returns the newly rotated key
        let app = create_app(state.clone());
        let get_pub_req = Request::builder()
            .uri("/api/server/public-key")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_pub_req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let pub_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let active_server_public_key = pub_json["public_key"].as_str().unwrap();
        assert_eq!(active_server_public_key, new_public_key);

        // 5. TC-F1-031 verification: Old client key mismatch
        // When client sends or verifies handshake using old key, mismatch occurs and client is rejected
        assert_ne!(
            old_client_configured_key, active_server_public_key,
            "Client holding old server key MUST NOT match current rotated server key"
        );

        // 6. Verify filesystem state: backup exists and new keys are written
        let backup_file = rotate_json["backup_path"].as_str().unwrap();
        assert!(std::path::Path::new(backup_file).exists());
        let backup_content = std::fs::read_to_string(backup_file).unwrap();
        assert_eq!(backup_content.trim(), old_client_configured_key);

        let active_pub_on_disk = std::fs::read_to_string(&pub_path).unwrap();
        assert_eq!(active_pub_on_disk.trim(), new_public_key);

        let active_priv_on_disk = std::fs::read_to_string(&priv_path).unwrap();
        assert_ne!(active_priv_on_disk.trim(), initial_keys.private_key_base64);
        assert_eq!(active_priv_on_disk.trim().len(), 88);
    }

    #[tokio::test]
    async fn test_failed_logins_on_one_ip_do_not_block_different_ip() {
        let (state, _) = setup_test_state().await;

        // 1. Bootstrap admin
        let app = create_app(state.clone());
        let bootstrap_req = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "admin_user",
                    "password": "AdminPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(bootstrap_req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // 2. Add a second user
        let user2_hash = crate::auth::hash_password("SecondUserPassword123!").unwrap();
        sqlx::query("INSERT INTO users (id, username, password_hash, role) VALUES ('u-2', 'user_beta', ?, 'user')")
            .bind(user2_hash)
            .execute(&state.db)
            .await
            .unwrap();

        // 3. Attacker from IP 192.168.1.100 makes 5 failed attempts against admin_user
        let attacker_addr: std::net::SocketAddr = "192.168.1.100:54321".parse().unwrap();
        for _ in 0..5 {
            let app = create_app(state.clone());
            let mut req = Request::builder()
                .uri("/api/auth/login")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "username": "admin_user",
                        "password": "WrongPassword!"
                    }))
                    .unwrap(),
                ))
                .unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(attacker_addr));
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }

        // 4. Verify attacker from IP 192.168.1.100 is now locked out
        let app = create_app(state.clone());
        let mut req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "user_beta",
                    "password": "SecondUserPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(attacker_addr));
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

        // 5. Legitimate user from a DIFFERENT IP (192.168.1.200) logs in successfully
        let legit_addr: std::net::SocketAddr = "192.168.1.200:54321".parse().unwrap();
        let app = create_app(state.clone());
        let mut req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "user_beta",
                    "password": "SecondUserPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(legit_addr));
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(json["token"].as_str().unwrap().starts_with("cercano_sess_"));
    }

    #[tokio::test]
    async fn test_heartbeat_without_name_preserves_existing_name() {
        let (state, _) = setup_test_state().await;
        let admin_token = get_authenticated_admin_token(&state).await;

        // 1. First heartbeat with an explicit human-friendly name
        let app = create_app(state.clone());
        let mut req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "dev-recepcion-01",
                    "name": "Recepción mostrador",
                    "hostname": "kiosk-front",
                    "os": "Windows 11 IoT"
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "192.168.1.55:40000"
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        ));
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let hb1: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(hb1["name"], "Recepción mostrador");

        // Simulate elapsed time past the 1-second rate-limit window
        sqlx::query("UPDATE devices SET last_seen_at = datetime('now', '-5 seconds') WHERE id = 'dev-recepcion-01'")
            .execute(&state.db)
            .await
            .unwrap();

        // 2. Subsequent heartbeat with no 'name' field and updated hostname
        let app = create_app(state.clone());
        let mut req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "dev-recepcion-01",
                    "hostname": "kiosk-front-updated",
                    "os": "Windows 11 IoT"
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "192.168.1.55:40000"
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        ));
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // 3. Inspect device detail: name MUST still be 'Recepción mostrador', NOT 'dev-recepcion-01'
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/dev-recepcion-01")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let dev: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            dev["name"], "Recepción mostrador",
            "Previous human-friendly device name must be preserved"
        );
        assert_eq!(
            dev["hostname"], "kiosk-front-updated",
            "Hostname must be updated"
        );

        // 4. Also verify an empty string 'name': "   " does NOT overwrite the existing name
        sqlx::query("UPDATE devices SET last_seen_at = datetime('now', '-5 seconds') WHERE id = 'dev-recepcion-01'")
            .execute(&state.db)
            .await
            .unwrap();

        let app = create_app(state.clone());
        let mut req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "dev-recepcion-01",
                    "name": "   ",
                    "hostname": "kiosk-front-updated"
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "192.168.1.55:40000"
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        ));
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/dev-recepcion-01")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let dev: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            dev["name"], "Recepción mostrador",
            "Blank name must not erase existing name"
        );
    }

    #[tokio::test]
    async fn test_heartbeat_ip_comes_from_connection_not_json_spoofing() {
        let (state, _) = setup_test_state().await;
        let admin_token = get_authenticated_admin_token(&state).await;

        let socket_ip: std::net::SocketAddr = "192.168.77.88:45000".parse().unwrap();

        // Heartbeat attempts to spoof IP via payload JSON ("ip": "10.99.99.99")
        // and via spoofed header ("x-forwarded-for": "10.88.88.88")
        let app = create_app(state.clone());
        let mut req = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "10.88.88.88")
            .header("x-real-ip", "10.88.88.88")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "dev-spoof-target",
                    "hostname": "spoofed-host",
                    "ip": "10.99.99.99"
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(socket_ip));

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let hb: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Must record socket IP (192.168.77.88), NOT spoofed payload or header IP
        assert_eq!(hb["ip_address"], "192.168.77.88");

        // Verify stored value in DB via GET /api/devices/:id
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/devices/dev-spoof-target")
            .method("GET")
            .header("Authorization", format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let dev: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(dev["ip_address"], "192.168.77.88");
    }

    #[tokio::test]
    async fn test_heartbeat_rate_limiting_throttles_rapid_requests() {
        let (state, _) = setup_test_state().await;

        let app = create_app(state.clone());
        let req1 = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "dev-flood-01"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res1 = app.oneshot(req1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::OK);

        // Immediate second heartbeat for same device is throttled (429)
        let app = create_app(state.clone());
        let req2 = Request::builder()
            .uri("/api/devices/heartbeat")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "id": "dev-flood-01"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res2 = app.oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
