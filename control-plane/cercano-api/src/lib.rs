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

pub mod config;
pub mod db;
pub mod health;
pub mod middleware;
pub mod shutdown;

use axum::routing::get;
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
    use tower::ServiceExt;

    async fn setup_test_app() -> Router {
        let db = init_db("sqlite::memory:").await.unwrap();
        let state = AppState {
            config: Config::default(),
            db,
        };
        create_app(state)
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
}
