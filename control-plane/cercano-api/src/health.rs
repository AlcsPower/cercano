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

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn health_handler(State(state): State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok".to_string(),
                service: "cercano-api".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                database: Some("connected".to_string()),
                error: None,
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!("Health check database ping failed: {:?}", err);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "degraded",
                    "service": "cercano-api",
                    "error": "database unreachable"
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::init_db;

    #[tokio::test]
    async fn test_health_response_values() {
        let response = HealthResponse {
            status: "ok".to_string(),
            service: "cercano-api".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database: Some("connected".to_string()),
            error: None,
        };

        assert_eq!(response.status, "ok");
        assert_eq!(response.service, "cercano-api");
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(response.database.as_deref(), Some("connected"));
    }

    #[tokio::test]
    async fn test_health_handler_execution() {
        let db = init_db("sqlite::memory:").await.unwrap();
        let audit = std::sync::Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
        let state = AppState {
            config: Config::default(),
            db,
            audit,
        };
        let resp = health_handler(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_handler_db_unreachable() {
        let db = init_db("sqlite::memory:").await.unwrap();
        let audit = std::sync::Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
        db.close().await;
        let state = AppState {
            config: Config::default(),
            db,
            audit,
        };
        let resp = health_handler(State(state)).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
