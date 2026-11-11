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

//! Server-Sent Events (SSE) and real-time event broadcasting (`ChatHub`) for Cercano Chat (F4.5-06).
//!
//! Provides `GET /api/chat/events`, which streams content-free pokes to devices and technicians.
//! Audiences:
//! - `Device(device_id)`: receives events for its conversation.
//! - `User(user_id)`: receives events for conversations assigned to this user.
//! - `Queue`: receives queue events for technicians (`chat:attend`, `chat:read`, `chat:manage`).
//!
//! Safety guarantee: Pokes never contain message bodies or attachment names.
//! Lag triggers `{"type":"resync"}`. Revoked tokens cause stream termination.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::permissions;
use crate::AppState;

const BROADCAST_CAPACITY: usize = 256;
const TOKEN_REVALIDATION_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatPoke {
    Message {
        conversation_id: String,
        message_id: String,
    },
    Status {
        conversation_id: String,
        status: String,
    },
    Queue {
        conversation_id: String,
        status: String,
    },
    Resync,
}

#[derive(Debug, Clone)]
pub struct ChatEvent {
    pub id: String,
    pub audience_device: Option<String>,
    pub audience_user: Option<String>,
    pub is_queue: bool,
    pub poke: ChatPoke,
}

impl ChatEvent {
    pub fn message(
        conversation_id: impl Into<String>,
        message_id: impl Into<String>,
        device_id: Option<String>,
        user_id: Option<String>,
        is_queue: bool,
    ) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            audience_device: device_id,
            audience_user: user_id,
            is_queue,
            poke: ChatPoke::Message {
                conversation_id: conversation_id.into(),
                message_id: message_id.into(),
            },
        }
    }

    pub fn status(
        conversation_id: impl Into<String>,
        status: impl Into<String>,
        device_id: Option<String>,
        user_id: Option<String>,
        is_queue: bool,
    ) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            audience_device: device_id,
            audience_user: user_id,
            is_queue,
            poke: ChatPoke::Status {
                conversation_id: conversation_id.into(),
                status: status.into(),
            },
        }
    }

    pub fn queue(conversation_id: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            audience_device: None,
            audience_user: None,
            is_queue: true,
            poke: ChatPoke::Queue {
                conversation_id: conversation_id.into(),
                status: status.into(),
            },
        }
    }
}

/// In-memory broadcast hub distributing real-time chat notifications.
#[derive(Clone)]
pub struct ChatHub {
    sender: broadcast::Sender<ChatEvent>,
}

impl ChatHub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self { sender }
    }

    pub fn broadcast(&self, event: ChatEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ChatEvent> {
        self.sender.subscribe()
    }
}

impl Default for ChatHub {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub token: Option<String>,
}

enum SseCaller {
    Device {
        device_id: String,
        raw_token: String,
    },
    User {
        user_id: String,
        raw_token: String,
    },
}

async fn authenticate_sse_caller(
    state: &AppState,
    headers: &HeaderMap,
    query: &EventsQuery,
) -> Result<SseCaller, (StatusCode, Json<serde_json::Value>)> {
    let raw_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| query.token.clone())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized", "message": "Autenticación requerida para SSE." })),
            )
        })?;

    if raw_token.starts_with("cercano_chat_") {
        let row = sqlx::query(
            "SELECT s.device_id FROM chat_device_sessions s
             JOIN chat_devices d ON s.device_id = d.device_id
             WHERE s.token = ? AND s.expires_at > datetime('now')",
        )
        .bind(&raw_token)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error", "message": e.to_string() })),
            )
        })?;

        match row {
            Some(r) => {
                use sqlx::Row;
                let device_id: String = r.get("device_id");
                Ok(SseCaller::Device {
                    device_id,
                    raw_token,
                })
            }
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({ "error": "unauthorized", "message": "Sesión de chat inválida o expirada." }),
                ),
            )),
        }
    } else if raw_token.starts_with("cercano_sess_") {
        let row = sqlx::query(
            "SELECT s.user_id, u.role, u.is_active FROM sessions s
             JOIN users u ON s.user_id = u.id
             WHERE s.token = ? AND s.revoked_at IS NULL AND s.expires_at > datetime('now')",
        )
        .bind(&raw_token)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal_error", "message": e.to_string() })),
            )
        })?;

        match row {
            Some(r) => {
                use sqlx::Row;
                let is_active: i64 = r.try_get("is_active").unwrap_or(0);
                if is_active == 0 {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(json!({ "error": "forbidden", "message": "Usuario inactivo." })),
                    ));
                }
                let user_id: String = r.get("user_id");
                let role: String = r.get("role");

                // Check technician/admin/auditor chat permissions
                let has_attend = permissions::user_has_permission(
                    &state.db,
                    &user_id,
                    &role,
                    permissions::CHAT_ATTEND,
                )
                .await;
                let has_read = permissions::user_has_permission(
                    &state.db,
                    &user_id,
                    &role,
                    permissions::CHAT_READ,
                )
                .await;
                let has_manage = permissions::user_has_permission(
                    &state.db,
                    &user_id,
                    &role,
                    permissions::CHAT_MANAGE,
                )
                .await;

                if !has_attend && !has_read && !has_manage {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(
                            json!({ "error": "forbidden", "message": "Permisos insuficientes para eventos de chat." }),
                        ),
                    ));
                }

                Ok(SseCaller::User { user_id, raw_token })
            }
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({ "error": "unauthorized", "message": "Sesión de usuario inválida o expirada." }),
                ),
            )),
        }
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized", "message": "Formato de token no soportado." })),
        ))
    }
}

async fn is_token_still_valid(state: &AppState, caller: &SseCaller) -> bool {
    match caller {
        SseCaller::Device { raw_token, .. } => {
            let res = sqlx::query(
                "SELECT 1 FROM chat_device_sessions WHERE token = ? AND expires_at > datetime('now')",
            )
            .bind(raw_token)
            .fetch_optional(&state.db)
            .await;
            matches!(res, Ok(Some(_)))
        }
        SseCaller::User { raw_token, .. } => {
            let res = sqlx::query(
                "SELECT 1 FROM sessions s JOIN users u ON s.user_id = u.id
                 WHERE s.token = ? AND s.revoked_at IS NULL AND u.is_active = 1 AND s.expires_at > datetime('now')",
            )
            .bind(raw_token)
            .fetch_optional(&state.db)
            .await;
            matches!(res, Ok(Some(_)))
        }
    }
}

/// GET /api/chat/events
///
/// Streams SSE events to connected devices and technicians.
pub async fn chat_events_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    if !state.config.chat_enabled {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                json!({ "error": "forbidden", "message": "El servicio de chat está desactivado." }),
            ),
        ));
    }

    let caller = authenticate_sse_caller(&state, &headers, &query).await?;
    let mut rx = state.chat_hub.subscribe();

    let (tx, stream_rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(32);

    let heartbeat_secs = state.config.chat_sse_heartbeat_secs.max(1);
    let state_clone = state.clone();

    tokio::spawn(async move {
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(heartbeat_secs));
        let mut revalidate_interval =
            tokio::time::interval(Duration::from_secs(TOKEN_REVALIDATION_INTERVAL_SECS));

        // Consume initial instant ticks from intervals
        heartbeat_interval.tick().await;
        revalidate_interval.tick().await;

        loop {
            tokio::select! {
                _ = heartbeat_interval.tick() => {
                    let ping_event = Event::default().comment("ping");
                    if tx.send(Ok(ping_event)).await.is_err() {
                        // Client disconnected
                        break;
                    }
                }
                _ = revalidate_interval.tick() => {
                    if !is_token_still_valid(&state_clone, &caller).await {
                        tracing::info!("SSE stream terminated: token has expired or was revoked");
                        break;
                    }
                }
                msg = rx.recv() => {
                    match msg {
                        Ok(event) => {
                            let should_deliver = match &caller {
                                SseCaller::Device { device_id, .. } => {
                                    event.audience_device.as_deref() == Some(device_id.as_str())
                                }
                                SseCaller::User { user_id, .. } => {
                                    event.is_queue || event.audience_user.as_deref() == Some(user_id.as_str())
                                }
                            };

                            if should_deliver {
                                if let Ok(data_str) = serde_json::to_string(&event.poke) {
                                    let sse_event = Event::default()
                                        .event("poke")
                                        .id(event.id)
                                        .data(data_str);
                                    if tx.send(Ok(sse_event)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!("SSE subscriber lagged: skipped {skipped} events, sending resync poke");
                            let resync_poke = ChatPoke::Resync;
                            if let Ok(data_str) = serde_json::to_string(&resync_poke) {
                                let sse_event = Event::default()
                                    .event("poke")
                                    .id(Uuid::now_v7().to_string())
                                    .data(data_str);
                                if tx.send(Ok(sse_event)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    });

    let sse = Sse::new(ReceiverStream::new(stream_rx));
    let mut response = sse.into_response();
    response.headers_mut().insert(
        header::HeaderName::from_static("x-accel-buffering"),
        header::HeaderValue::from_static("no"),
    );

    Ok(response)
}
