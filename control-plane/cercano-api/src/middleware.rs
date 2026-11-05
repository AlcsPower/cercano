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

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;
use uuid::Uuid;

pub static TRACE_ID_HEADER: HeaderName = HeaderName::from_static("x-trace-id");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceId(pub String);

/// Middleware that extracts or generates a UUIDv7 trace_id for every HTTP request.
/// - If `x-trace-id` (or `x-request-id`) header is provided by caller, it is preserved.
/// - Otherwise, a new UUIDv7 is generated.
/// - Injects `TraceId` into request extensions.
/// - Sets `x-trace-id` on the response header.
/// - Wraps request execution inside an instrumented tracing span containing the `trace_id`.
pub async fn trace_id_middleware(mut req: Request, next: Next) -> Response {
    let trace_id = req
        .headers()
        .get(&TRACE_ID_HEADER)
        .or_else(|| req.headers().get("x-request-id"))
        .and_then(|val| val.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| Uuid::now_v7().to_string());

    req.extensions_mut().insert(TraceId(trace_id.clone()));

    let method = req.method().clone();
    let uri = req.uri().clone();

    let span = tracing::info_span!(
        "http_request",
        trace_id = %trace_id,
        method = %method,
        uri = %uri,
    );

    let mut res = next.run(req).instrument(span).await;

    if let Ok(val) = HeaderValue::from_str(&trace_id) {
        res.headers_mut().insert(TRACE_ID_HEADER.clone(), val);
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn dummy_handler() -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn test_generates_new_trace_id_if_missing() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(middleware::from_fn(trace_id_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let trace_header = res.headers().get("x-trace-id");
        assert!(trace_header.is_some());
        let val = trace_header.unwrap().to_str().unwrap();
        assert!(Uuid::parse_str(val).is_ok());
    }

    #[tokio::test]
    async fn test_propagates_existing_trace_id() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(middleware::from_fn(trace_id_middleware));

        let custom_trace = "custom-trace-12345";
        let req = Request::builder()
            .uri("/test")
            .header("x-trace-id", custom_trace)
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let trace_header = res.headers().get("x-trace-id").unwrap().to_str().unwrap();
        assert_eq!(trace_header, custom_trace);
    }

    #[tokio::test]
    async fn test_fallback_to_x_request_id() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(middleware::from_fn(trace_id_middleware));

        let req_id = "req-id-abcde";
        let req = Request::builder()
            .uri("/test")
            .header("x-request-id", req_id)
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let trace_header = res.headers().get("x-trace-id").unwrap().to_str().unwrap();
        assert_eq!(trace_header, req_id);
    }

    #[tokio::test]
    async fn test_empty_trace_id_header_generates_fresh_uuid() {
        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(middleware::from_fn(trace_id_middleware));

        let req = Request::builder()
            .uri("/test")
            .header("x-trace-id", "   ")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let val = res.headers().get("x-trace-id").unwrap().to_str().unwrap();
        assert!(!val.trim().is_empty());
        assert!(Uuid::parse_str(val).is_ok());
    }
}
