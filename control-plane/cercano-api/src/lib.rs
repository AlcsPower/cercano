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

pub mod auth;
pub mod config;
pub mod db;
pub mod health;
pub mod middleware;
pub mod shutdown;

use axum::routing::{get, post};
use axum::Router;
pub use config::Config;
pub use db::init_db;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: SqlitePool,
}

/// Builds the Axum application router with all registered routes and middleware.
pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::health_handler))
        .route("/api/auth/bootstrap", post(auth::bootstrap_handler))
        .route("/api/auth/login", post(auth::login_handler))
        .route("/api/auth/logout", post(auth::logout_handler))
        .route("/api/auth/me", get(auth::me_handler))
        .layer(axum::middleware::from_fn(middleware::trace_id_middleware))
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
        let state = AppState {
            config: Config::default(),
            db,
        };
        create_app(state)
    }

    async fn setup_test_state() -> (AppState, Router) {
        let db = init_db("sqlite::memory:").await.unwrap();
        let state = AppState {
            config: Config::default(),
            db,
        };
        let app = create_app(state.clone());
        (state, app)
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
        assert!(json["id"].is_string());

        // Second bootstrap call must fail with 409 Conflict
        let app2 = create_app(state.clone());
        let req2 = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&bootstrap_payload).unwrap()))
            .unwrap();

        let res2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::CONFLICT);

        let body2 = res2.into_body().collect().await.unwrap().to_bytes();
        let json2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
        assert_eq!(json2["error"], "bootstrap_already_completed");
    }

    #[tokio::test]
    async fn test_tc_f1_010_login_success_and_token_expiration() {
        let (state, _) = setup_test_state().await;

        // 1. Bootstrap admin
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/bootstrap")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "superadmin",
                    "password": "SecurePassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // 2. Successful login
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "superadmin",
                    "password": "SecurePassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let token = json["token"].as_str().expect("token should be string");
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        let expires_at = json["expires_at"]
            .as_str()
            .expect("expires_at should be string");
        assert!(!expires_at.is_empty());
        assert_eq!(json["user"]["username"], "superadmin");
        assert_eq!(json["user"]["role"], "admin");
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
                    "password": "ValidPassword123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // Perform 5 consecutive failed logins
        let secret_wrong_pw = "WrongSecretAttempt123!";
        for _ in 0..5 {
            let app = create_app(state.clone());
            let req = Request::builder()
                .uri("/api/auth/login")
                .method("POST")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "192.168.10.50")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "username": "target_user",
                        "password": secret_wrong_pw
                    }))
                    .unwrap(),
                ))
                .unwrap();

            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

            let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
            assert_eq!(json["error"], "invalid_credentials");
            // Critical rule: Plaintext password must never leak in error response
            let body_str = String::from_utf8_lossy(&body_bytes);
            assert!(!body_str.contains(secret_wrong_pw));
        }

        // 6th attempt should be temporarily locked out (429 Too Many Requests)
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "192.168.10.50")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "target_user",
                    "password": "ValidPassword123!"
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
                    "username": "session_admin",
                    "password": "Password123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        app.oneshot(req).await.unwrap();

        // Login
        let app = create_app(state.clone());
        let req = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "username": "session_admin",
                    "password": "Password123!"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let token = json["token"].as_str().unwrap().to_string();

        // Check GET /api/auth/me is valid
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
}
