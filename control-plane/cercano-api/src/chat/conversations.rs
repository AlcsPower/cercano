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

//! REST API for Chat Conversations and Messages (F4.5-04).
//!
//! Handles conversation lifecycle (creation, queuing, claim, release, assignment,
//! closure, reopening), messaging with idempotency, read receipts, and technician queues.

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::chat::auth::{AuthenticatedChatDevice, ChatAuthError};
use crate::chat::events::ChatEvent;
use crate::chat::{validate_contact_name, validate_message_body, ReaderType, SenderType};
use crate::permissions;
use crate::AppState;

const PREVIEW_MAX_CHARS: usize = 160;

#[derive(Debug, Clone)]
pub enum ChatCaller {
    Device(AuthenticatedChatDevice),
    User(AuthenticatedUser),
}

#[axum::async_trait]
impl FromRequestParts<AppState> for ChatCaller {
    type Rejection = ChatConvError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                ChatConvError::Unauthorized("Cabecera Authorization ausente.".to_string())
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(str::trim)
            .unwrap_or_default();

        if token.starts_with("cercano_chat_") {
            let dev = AuthenticatedChatDevice::from_request_parts(parts, state)
                .await
                .map_err(|e| match e {
                    ChatAuthError::Unauthorized(m) => ChatConvError::Unauthorized(m),
                    ChatAuthError::Forbidden(m) => ChatConvError::Forbidden(m),
                    _ => {
                        ChatConvError::Unauthorized("Sesión de dispositivo no válida.".to_string())
                    }
                })?;
            Ok(ChatCaller::Device(dev))
        } else if token.starts_with("cercano_sess_") {
            let user = AuthenticatedUser::from_request_parts(parts, state)
                .await
                .map_err(|e| {
                    ChatConvError::Unauthorized(format!("Error de autenticación: {e:?}"))
                })?;
            Ok(ChatCaller::User(user))
        } else {
            Err(ChatConvError::Unauthorized(
                "Formato de token no reconocido.".to_string(),
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateConversationRequest {
    pub contact_first_name: String,
    pub contact_last_name: String,
    pub body: String,
    pub client_message_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateMessageRequest {
    pub body: String,
    pub client_message_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssignRequest {
    pub user_id: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct CloseRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ConversationListQuery {
    pub status: Option<String>,
    pub assigned: Option<String>,
    pub q: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MessageListQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentDto {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub size_bytes: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDto {
    pub id: String,
    pub conversation_id: String,
    pub sender_type: String,
    pub sender_id: Option<String>,
    pub sender_name: Option<String>,
    pub body: String,
    pub attachment: Option<AttachmentDto>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub id: String,
    pub device_id: String,
    pub device_name: Option<String>,
    pub device_hostname: Option<String>,
    pub device_os: Option<String>,
    pub status: String,
    pub assigned_user_id: Option<String>,
    pub assigned_username: Option<String>,
    pub contact_first_name: Option<String>,
    pub contact_last_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_message_at: Option<String>,
    pub last_message_preview: Option<String>,
    pub unread_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationDetail {
    #[serde(flatten)]
    pub summary: ConversationSummary,
    pub closed_at: Option<String>,
    pub closed_by: Option<String>,
    pub messages: Vec<MessageDto>,
    pub next_before: Option<String>,
    pub other_last_read_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConversationListResponse {
    pub conversations: Vec<ConversationSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChatSummaryResponse {
    pub waiting: i64,
    pub assigned_to_me: i64,
    pub active: i64,
    pub unread: i64,
}

#[derive(Debug, Serialize)]
pub struct AgentDto {
    pub id: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct AgentsResponse {
    pub agents: Vec<AgentDto>,
}

#[derive(Debug)]
pub enum ChatConvError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    ConflictAlreadyAssigned,
    ConflictClosed,
    RateLimited(u64),
    Internal(String),
}

impl IntoResponse for ChatConvError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "validation_error", "message": msg })),
            )
                .into_response(),
            Self::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized", "message": msg })),
            )
                .into_response(),
            Self::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "forbidden", "message": msg })),
            )
                .into_response(),
            Self::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "not_found", "message": msg })),
            )
                .into_response(),
            Self::ConflictAlreadyAssigned => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "conflict",
                    "code": "already_assigned",
                    "message": "La conversación ya está asignada a otro técnico."
                })),
            )
                .into_response(),
            Self::ConflictClosed => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "conflict",
                    "code": "conversation_closed",
                    "message": "La conversación está cerrada."
                })),
            )
                .into_response(),
            Self::RateLimited(retry_after) => {
                let mut resp = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": "rate_limited", "message": "Límite de tasa excedido." })),
                )
                    .into_response();
                resp.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    retry_after.to_string().parse().unwrap(),
                );
                resp
            }
            Self::Internal(msg) => {
                tracing::error!("Chat conversation error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal_error", "message": "Error interno del servidor." })),
                )
                    .into_response()
            }
        }
    }
}

fn extract_trace_id(headers: &HeaderMap, conv_id: Option<&str>) -> String {
    if let Some(id) = conv_id {
        return id.to_string();
    }
    headers
        .get("x-trace-id")
        .or_else(|| headers.get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

fn make_preview(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.chars().count() > PREVIEW_MAX_CHARS {
        let mut s: String = trimmed.chars().take(PREVIEW_MAX_CHARS).collect();
        s.push_str("...");
        s
    } else {
        trimmed.to_string()
    }
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations
// ----------------------------------------------------------------------------
pub async fn create_or_join_conversation_handler(
    State(state): State<AppState>,
    device: AuthenticatedChatDevice,
    headers: HeaderMap,
    Json(payload): Json<CreateConversationRequest>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let first_name = validate_contact_name(&payload.contact_first_name, "Nombre")
        .map_err(ChatConvError::BadRequest)?;
    let last_name = validate_contact_name(&payload.contact_last_name, "Apellido")
        .map_err(ChatConvError::BadRequest)?;
    let body = validate_message_body(&payload.body).map_err(ChatConvError::BadRequest)?;

    let now_str = Utc::now().to_rfc3339();

    // Check for open conversation for this device (waiting, assigned, active)
    let open_conv = sqlx::query(
        "SELECT id, status, contact_first_name, contact_last_name, assigned_user_id FROM chat_conversations
         WHERE device_id = ? AND status IN ('waiting', 'assigned', 'active')
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&device.device_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    if let Some(row) = open_conv {
        let conv_id: String = row.try_get("id").unwrap_or_default();
        let assigned_user_id: Option<String> = row.try_get("assigned_user_id").ok();
        let trace_id = conv_id.clone();

        // Idempotency check with client_message_id
        if let Some(ref client_msg_id) = payload.client_message_id {
            let existing_msg = sqlx::query(
                "SELECT id FROM chat_messages WHERE conversation_id = ? AND sender_type = 'client' AND sender_id = ? AND client_message_id = ?"
            )
            .bind(&conv_id)
            .bind(&device.device_id)
            .bind(client_msg_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ChatConvError::Internal(e.to_string()))?;

            if existing_msg.is_some() {
                let detail = fetch_conversation_detail(
                    &state.db,
                    &conv_id,
                    Some(&device.device_id),
                    None,
                    50,
                    None,
                )
                .await?;
                return Ok((StatusCode::OK, Json(detail)).into_response());
            }
        }

        // Add message to open conversation
        let msg_id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO chat_messages (id, conversation_id, sender_type, sender_id, sender_name, body, client_message_id, created_at)
             VALUES (?, ?, 'client', ?, ?, ?, ?, ?)"
        )
        .bind(&msg_id)
        .bind(&conv_id)
        .bind(&device.device_id)
        .bind(&device.device_id)
        .bind(&body)
        .bind(payload.client_message_id.as_deref())
        .bind(&now_str)
        .execute(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

        sqlx::query(
            "UPDATE chat_conversations SET last_message_at = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&now_str)
        .bind(&now_str)
        .bind(&conv_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

        // Audit message created
        let actor = Actor::with_type(&device.device_id, "device");
        let subject = Subject::with_type(&conv_id, "conversation");
        let audit_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Chat,
            "chat.message.created",
            actor,
            Outcome::Success,
            json!({
                "conversation_id": &conv_id,
                "message_id": &msg_id,
                "sender_type": "client",
                "length": body.chars().count(),
                "has_attachment": false
            }),
        )
        .with_subject(subject);
        let _ = state.audit.append(audit_input).await;

        let is_queue = assigned_user_id.is_none();
        state.chat_hub.broadcast(ChatEvent::message(
            &conv_id,
            &msg_id,
            Some(device.device_id.clone()),
            assigned_user_id,
            is_queue,
        ));

        let detail =
            fetch_conversation_detail(&state.db, &conv_id, Some(&device.device_id), None, 50, None)
                .await?;
        return Ok((StatusCode::OK, Json(detail)).into_response());
    }

    // Daily limit check for new conversations
    let count_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_conversations
         WHERE device_id = ? AND created_at > datetime('now', '-24 hours')",
    )
    .bind(&device.device_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if count_today >= state.config.chat_conversation_daily_limit as i64 {
        let trace_id = extract_trace_id(&headers, None);
        let actor = Actor::with_type(&device.device_id, "device");
        let subject = Subject::with_type(&device.device_id, "device");
        let audit_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Chat,
            "chat.rate_limited",
            actor,
            Outcome::Denied,
            json!({
                "device_id": &device.device_id,
                "limit": "conversation_daily_limit",
                "retry_after_secs": 3600
            }),
        )
        .with_subject(subject);
        let _ = state.audit.append(audit_input).await;

        return Err(ChatConvError::RateLimited(3600));
    }

    // Query device snapshot from `devices` and `chat_devices`
    let dev_info = sqlx::query(
        "SELECT d.name, d.hostname, d.os, c.installer_id
         FROM devices d
         LEFT JOIN chat_devices c ON d.id = c.device_id
         WHERE d.id = ?",
    )
    .bind(&device.device_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let (device_name, device_hostname, device_os, installer_id) = if let Some(row) = dev_info {
        (
            row.try_get::<String, _>("name").ok(),
            row.try_get::<String, _>("hostname").ok(),
            row.try_get::<String, _>("os").ok(),
            row.try_get::<String, _>("installer_id").ok(),
        )
    } else {
        (Some(device.device_id.clone()), None, None, None)
    };

    let conv_id = Uuid::now_v7().to_string();
    let msg_id = Uuid::now_v7().to_string();

    sqlx::query(
        "INSERT INTO chat_conversations (
            id, device_id, device_name, device_hostname, device_os, installer_id,
            status, contact_first_name, contact_last_name, created_at, updated_at, last_message_at
         ) VALUES (?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?, ?, ?)",
    )
    .bind(&conv_id)
    .bind(&device.device_id)
    .bind(&device_name)
    .bind(&device_hostname)
    .bind(&device_os)
    .bind(&installer_id)
    .bind(&first_name)
    .bind(&last_name)
    .bind(&now_str)
    .bind(&now_str)
    .bind(&now_str)
    .execute(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO chat_messages (
            id, conversation_id, sender_type, sender_id, sender_name, body, client_message_id, created_at
         ) VALUES (?, ?, 'client', ?, ?, ?, ?, ?)"
    )
    .bind(&msg_id)
    .bind(&conv_id)
    .bind(&device.device_id)
    .bind(device_name.as_deref().unwrap_or(&device.device_id))
    .bind(&body)
    .bind(payload.client_message_id.as_deref())
    .bind(&now_str)
    .execute(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    // Audit events (trace_id = conversation_id)
    let actor = Actor::with_type(&device.device_id, "device");
    let subject = Subject::with_type(&conv_id, "conversation");

    let open_audit = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.opened",
        actor.clone(),
        Outcome::Success,
        json!({
            "conversation_id": &conv_id,
            "device_id": &device.device_id,
            "installer_id": &installer_id
        }),
    )
    .with_subject(subject.clone());
    let _ = state.audit.append(open_audit).await;

    let msg_audit = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.message.created",
        actor,
        Outcome::Success,
        json!({
            "conversation_id": &conv_id,
            "message_id": &msg_id,
            "sender_type": "client",
            "length": body.chars().count(),
            "has_attachment": false
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(msg_audit).await;

    state
        .chat_hub
        .broadcast(ChatEvent::queue(&conv_id, "waiting"));
    state.chat_hub.broadcast(ChatEvent::message(
        &conv_id,
        &msg_id,
        Some(device.device_id.clone()),
        None,
        true,
    ));

    let detail =
        fetch_conversation_detail(&state.db, &conv_id, Some(&device.device_id), None, 50, None)
            .await?;
    Ok((StatusCode::CREATED, Json(detail)).into_response())
}

// ----------------------------------------------------------------------------
// GET /api/chat/conversations/:id
// ----------------------------------------------------------------------------
pub async fn get_conversation_handler(
    State(state): State<AppState>,
    caller: ChatCaller,
    Path(conv_id): Path<String>,
    Query(query): Query<MessageListQuery>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 100);

    let (caller_device, caller_user) = match caller {
        ChatCaller::Device(dev) => (Some(dev.device_id), None),
        ChatCaller::User(u) => (None, Some(u)),
    };

    let detail = fetch_conversation_detail(
        &state.db,
        &conv_id,
        caller_device.as_deref(),
        caller_user.as_ref(),
        limit,
        query.before.as_deref(),
    )
    .await?;

    Ok((StatusCode::OK, Json(detail)).into_response())
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations/:id/messages
// ----------------------------------------------------------------------------
pub async fn send_message_handler(
    State(state): State<AppState>,
    caller: ChatCaller,
    Path(conv_id): Path<String>,
    Json(payload): Json<CreateMessageRequest>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let body = validate_message_body(&payload.body).map_err(ChatConvError::BadRequest)?;

    // Fetch conversation status and authorization
    let conv_row = sqlx::query(
        "SELECT device_id, status, assigned_user_id FROM chat_conversations WHERE id = ?",
    )
    .bind(&conv_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(row) = conv_row else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };

    let device_id: String = row.try_get("device_id").unwrap_or_default();
    let status_str: String = row.try_get("status").unwrap_or_default();
    let assigned_user_id: Option<String> = row.try_get("assigned_user_id").ok().flatten();

    if status_str == "closed" {
        return Err(ChatConvError::ConflictClosed);
    }

    let (sender_type, sender_id, sender_name) = match caller {
        ChatCaller::Device(dev) => {
            if dev.device_id != device_id {
                return Err(ChatConvError::Forbidden(
                    "No autorizado para escribir en esta conversación.".to_string(),
                ));
            }
            (SenderType::Client, dev.device_id.clone(), dev.device_id)
        }
        ChatCaller::User(user) => {
            let has_attend = permissions::user_has_permission(
                &state.db,
                &user.id,
                &user.role,
                permissions::CHAT_ATTEND,
            )
            .await;
            let has_manage = permissions::user_has_permission(
                &state.db,
                &user.id,
                &user.role,
                permissions::CHAT_MANAGE,
            )
            .await;

            if !has_attend && !has_manage && user.role != "admin" {
                return Err(ChatConvError::Forbidden(
                    "Permiso insuficiente para atender el chat.".to_string(),
                ));
            }

            // Technician can only write if assigned to them or if they have manage/admin
            if let Some(ref assigned) = assigned_user_id {
                if assigned != &user.id && !has_manage && user.role != "admin" {
                    return Err(ChatConvError::Forbidden(
                        "Conversación asignada a otro técnico.".to_string(),
                    ));
                }
            }

            (SenderType::Technician, user.id, user.username)
        }
    };

    // Idempotency check with client_message_id
    if let Some(ref client_msg_id) = payload.client_message_id {
        let existing = sqlx::query(
            "SELECT id, conversation_id, sender_type, sender_id, sender_name, body, created_at
             FROM chat_messages
             WHERE conversation_id = ? AND sender_type = ? AND sender_id = ? AND client_message_id = ?"
        )
        .bind(&conv_id)
        .bind(sender_type.as_str())
        .bind(&sender_id)
        .bind(client_msg_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

        if let Some(r) = existing {
            let msg = MessageDto {
                id: r.try_get("id").unwrap_or_default(),
                conversation_id: r.try_get("conversation_id").unwrap_or_default(),
                sender_type: r.try_get("sender_type").unwrap_or_default(),
                sender_id: r.try_get("sender_id").ok(),
                sender_name: r.try_get("sender_name").ok(),
                body: r.try_get("body").unwrap_or_default(),
                attachment: None,
                created_at: r.try_get("created_at").unwrap_or_default(),
            };
            return Ok((StatusCode::OK, Json(msg)).into_response());
        }
    }

    // Message rate limit check (device: chat_message_rate_per_minute, tech: chat_user_message_rate_per_minute)
    let (rate_limit, limit_name) = match sender_type {
        SenderType::Client => (
            state.config.chat_message_rate_per_minute as i64,
            "device_message_rate",
        ),
        SenderType::Technician => (
            state.config.chat_user_message_rate_per_minute as i64,
            "user_message_rate",
        ),
        SenderType::System => (1000, "system_rate"),
    };

    let count_last_minute: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_messages
         WHERE sender_type = ? AND sender_id = ? AND created_at > datetime('now', '-60 seconds')",
    )
    .bind(sender_type.as_str())
    .bind(&sender_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if count_last_minute >= rate_limit {
        let actor = Actor::with_type(&sender_id, sender_type.as_str());
        let subject = Subject::with_type(&conv_id, "conversation");
        let audit_input = EventInput::new(
            conv_id.clone(),
            Source::Api,
            Category::Chat,
            "chat.rate_limited",
            actor,
            Outcome::Denied,
            json!({
                "conversation_id": &conv_id,
                "limit": limit_name,
                "retry_after_secs": 60
            }),
        )
        .with_subject(subject);
        let _ = state.audit.append(audit_input).await;

        return Err(ChatConvError::RateLimited(60));
    }

    let msg_id = Uuid::now_v7().to_string();
    let now_str = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO chat_messages (id, conversation_id, sender_type, sender_id, sender_name, body, client_message_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&msg_id)
    .bind(&conv_id)
    .bind(sender_type.as_str())
    .bind(&sender_id)
    .bind(&sender_name)
    .bind(&body)
    .bind(payload.client_message_id.as_deref())
    .bind(&now_str)
    .execute(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    // Update conversation status if assigned and technician replies -> active
    let new_status = if sender_type == SenderType::Technician && status_str == "assigned" {
        "active"
    } else {
        &status_str
    };

    sqlx::query("UPDATE chat_conversations SET status = ?, last_message_at = ?, updated_at = ? WHERE id = ?")
        .bind(new_status)
        .bind(&now_str)
        .bind(&now_str)
        .bind(&conv_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let actor = Actor::with_type(&sender_id, sender_type.as_str());
    let subject = Subject::with_type(&conv_id, "conversation");
    let audit_input = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.message.created",
        actor,
        Outcome::Success,
        json!({
            "conversation_id": &conv_id,
            "message_id": &msg_id,
            "sender_type": sender_type.as_str(),
            "length": body.chars().count(),
            "has_attachment": false
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    let audience_device = Some(device_id.clone());
    let audience_user = match sender_type {
        SenderType::Client => assigned_user_id.clone(),
        SenderType::Technician => Some(sender_id.clone()),
        SenderType::System => assigned_user_id.clone(),
    };
    let is_queue = assigned_user_id.is_none();
    state.chat_hub.broadcast(ChatEvent::message(
        &conv_id,
        &msg_id,
        audience_device,
        audience_user,
        is_queue,
    ));

    if new_status != status_str {
        state.chat_hub.broadcast(ChatEvent::status(
            &conv_id,
            new_status,
            Some(device_id.clone()),
            assigned_user_id.clone(),
            is_queue,
        ));
    }

    let response_dto = MessageDto {
        id: msg_id,
        conversation_id: conv_id,
        sender_type: sender_type.as_str().to_string(),
        sender_id: Some(sender_id),
        sender_name: Some(sender_name),
        body,
        attachment: None,
        created_at: now_str,
    };

    Ok((StatusCode::CREATED, Json(response_dto)).into_response())
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations/:id/claim
// ----------------------------------------------------------------------------
pub async fn claim_conversation_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(conv_id): Path<String>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let has_attend =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_ATTEND)
            .await;

    if !has_attend && user.role != "admin" {
        return Err(ChatConvError::Forbidden(
            "Permiso insuficiente para reclamar conversaciones.".to_string(),
        ));
    }

    let conv = sqlx::query(
        "SELECT status, assigned_user_id, device_id FROM chat_conversations WHERE id = ?",
    )
    .bind(&conv_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(row) = conv else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };

    let device_id: String = row.try_get("device_id").unwrap_or_default();
    let assigned: Option<String> = row.try_get("assigned_user_id").ok().flatten();
    if let Some(ref current) = assigned {
        if current != &user.id {
            return Err(ChatConvError::ConflictAlreadyAssigned);
        }
    }

    let now_str = Utc::now().to_rfc3339();
    sqlx::query("UPDATE chat_conversations SET assigned_user_id = ?, status = 'assigned', updated_at = ? WHERE id = ?")
        .bind(&user.id)
        .bind(&now_str)
        .bind(&conv_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let actor = Actor::with_type(&user.id, "user");
    let subject = Subject::with_type(&conv_id, "conversation");
    let audit_input = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.assigned",
        actor,
        Outcome::Success,
        json!({
            "conversation_id": &conv_id,
            "to_user_id": &user.id
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    state.chat_hub.broadcast(ChatEvent::status(
        &conv_id,
        "assigned",
        Some(device_id),
        Some(user.id.clone()),
        true,
    ));

    let summary = fetch_conversation_summary(&state.db, &conv_id).await?;
    Ok((StatusCode::OK, Json(summary)).into_response())
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations/:id/release
// ----------------------------------------------------------------------------
pub async fn release_conversation_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(conv_id): Path<String>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let conv =
        sqlx::query("SELECT assigned_user_id, device_id FROM chat_conversations WHERE id = ?")
            .bind(&conv_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(row) = conv else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };

    let device_id: String = row.try_get("device_id").unwrap_or_default();
    let assigned: Option<String> = row.try_get("assigned_user_id").ok().flatten();
    let has_manage =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_MANAGE)
            .await;

    if assigned.as_deref() != Some(&user.id) && !has_manage && user.role != "admin" {
        return Err(ChatConvError::Forbidden(
            "No puedes liberar una conversación que no tienes asignada.".to_string(),
        ));
    }

    let now_str = Utc::now().to_rfc3339();
    sqlx::query("UPDATE chat_conversations SET assigned_user_id = NULL, status = 'waiting', updated_at = ? WHERE id = ?")
        .bind(&now_str)
        .bind(&conv_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let actor = Actor::with_type(&user.id, "user");
    let subject = Subject::with_type(&conv_id, "conversation");
    let audit_input = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.released",
        actor,
        Outcome::Success,
        json!({
            "conversation_id": &conv_id,
            "previous_user_id": assigned
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    state.chat_hub.broadcast(ChatEvent::status(
        &conv_id,
        "waiting",
        Some(device_id),
        assigned.clone(),
        true,
    ));

    let summary = fetch_conversation_summary(&state.db, &conv_id).await?;
    Ok((StatusCode::OK, Json(summary)).into_response())
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations/:id/assign
// ----------------------------------------------------------------------------
pub async fn assign_conversation_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(conv_id): Path<String>,
    Json(payload): Json<AssignRequest>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let has_manage =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_MANAGE)
            .await;

    if !has_manage && user.role != "admin" {
        return Err(ChatConvError::Forbidden(
            "Se requiere permiso chat:manage para asignar conversaciones.".to_string(),
        ));
    }

    let target_user = sqlx::query("SELECT id FROM users WHERE id = ?")
        .bind(&payload.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    if target_user.is_none() {
        return Err(ChatConvError::BadRequest(
            "Usuario de destino no existe.".to_string(),
        ));
    }

    let conv = sqlx::query("SELECT device_id FROM chat_conversations WHERE id = ?")
        .bind(&conv_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(conv_row) = conv else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };
    let device_id: String = conv_row.try_get("device_id").unwrap_or_default();

    let now_str = Utc::now().to_rfc3339();
    sqlx::query("UPDATE chat_conversations SET assigned_user_id = ?, status = 'assigned', updated_at = ? WHERE id = ?")
        .bind(&payload.user_id)
        .bind(&now_str)
        .bind(&conv_id)
        .execute(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let actor = Actor::with_type(&user.id, "user");
    let subject = Subject::with_type(&conv_id, "conversation");
    let audit_input = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.assigned",
        actor,
        Outcome::Success,
        json!({
            "conversation_id": &conv_id,
            "assigned_by": &user.id,
            "to_user_id": &payload.user_id
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    state.chat_hub.broadcast(ChatEvent::status(
        &conv_id,
        "assigned",
        Some(device_id),
        Some(payload.user_id.clone()),
        true,
    ));

    let summary = fetch_conversation_summary(&state.db, &conv_id).await?;
    Ok((StatusCode::OK, Json(summary)).into_response())
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations/:id/close
// ----------------------------------------------------------------------------
pub async fn close_conversation_handler(
    State(state): State<AppState>,
    caller: ChatCaller,
    Path(conv_id): Path<String>,
    payload: Option<Json<CloseRequest>>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let conv = sqlx::query(
        "SELECT device_id, status, assigned_user_id FROM chat_conversations WHERE id = ?",
    )
    .bind(&conv_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(row) = conv else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };

    let device_id: String = row.try_get("device_id").unwrap_or_default();
    let current_status: String = row.try_get("status").unwrap_or_default();
    let assigned: Option<String> = row.try_get("assigned_user_id").ok().flatten();

    // Idempotent: already closed returns summary immediately
    if current_status == "closed" {
        let summary = fetch_conversation_summary(&state.db, &conv_id).await?;
        return Ok((StatusCode::OK, Json(summary)).into_response());
    }

    let closed_by_str = match caller {
        ChatCaller::Device(ref dev) => {
            if dev.device_id != device_id {
                return Err(ChatConvError::Forbidden(
                    "No autorizado para cerrar esta conversación.".to_string(),
                ));
            }
            format!("device:{}", dev.device_id)
        }
        ChatCaller::User(ref user) => {
            let has_attend = permissions::user_has_permission(
                &state.db,
                &user.id,
                &user.role,
                permissions::CHAT_ATTEND,
            )
            .await;
            let has_manage = permissions::user_has_permission(
                &state.db,
                &user.id,
                &user.role,
                permissions::CHAT_MANAGE,
            )
            .await;

            if !has_attend && !has_manage && user.role != "admin" {
                return Err(ChatConvError::Forbidden(
                    "Permiso insuficiente para cerrar conversaciones.".to_string(),
                ));
            }

            if let Some(ref current_user) = assigned {
                if current_user != &user.id && !has_manage && user.role != "admin" {
                    return Err(ChatConvError::Forbidden(
                        "Conversación asignada a otro técnico.".to_string(),
                    ));
                }
            }

            format!("user:{}", user.id)
        }
    };

    let now_str = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE chat_conversations SET status = 'closed', closed_at = ?, closed_by = ?, updated_at = ? WHERE id = ?"
    )
    .bind(&now_str)
    .bind(&closed_by_str)
    .bind(&now_str)
    .bind(&conv_id)
    .execute(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let actor = match caller {
        ChatCaller::Device(ref dev) => Actor::with_type(&dev.device_id, "device"),
        ChatCaller::User(ref u) => Actor::with_type(&u.id, "user"),
    };
    let subject = Subject::with_type(&conv_id, "conversation");
    let audit_input = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.closed",
        actor,
        Outcome::Success,
        json!({
            "conversation_id": &conv_id,
            "closed_by": &closed_by_str,
            "reason": payload.and_then(|p| p.0.reason).unwrap_or_else(|| "resolved".to_string())
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    state.chat_hub.broadcast(ChatEvent::status(
        &conv_id,
        "closed",
        Some(device_id),
        assigned,
        true,
    ));

    let summary = fetch_conversation_summary(&state.db, &conv_id).await?;
    Ok((StatusCode::OK, Json(summary)).into_response())
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations/:id/reopen
// ----------------------------------------------------------------------------
pub async fn reopen_conversation_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(conv_id): Path<String>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let has_manage =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_MANAGE)
            .await;

    if !has_manage && user.role != "admin" {
        return Err(ChatConvError::Forbidden(
            "Se requiere permiso chat:manage para reabrir conversaciones.".to_string(),
        ));
    }

    let conv = sqlx::query("SELECT device_id FROM chat_conversations WHERE id = ?")
        .bind(&conv_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(conv_row) = conv else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };
    let device_id: String = conv_row.try_get("device_id").unwrap_or_default();

    let now_str = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE chat_conversations SET status = 'waiting', assigned_user_id = NULL, closed_at = NULL, closed_by = NULL, updated_at = ?
         WHERE id = ?"
    )
    .bind(&now_str)
    .bind(&conv_id)
    .execute(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let actor = Actor::with_type(&user.id, "user");
    let subject = Subject::with_type(&conv_id, "conversation");
    let audit_input = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.reopened",
        actor,
        Outcome::Success,
        json!({ "conversation_id": &conv_id }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    state.chat_hub.broadcast(ChatEvent::status(
        &conv_id,
        "waiting",
        Some(device_id),
        None,
        true,
    ));

    let summary = fetch_conversation_summary(&state.db, &conv_id).await?;
    Ok((StatusCode::OK, Json(summary)).into_response())
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations/:id/read
// ----------------------------------------------------------------------------
pub async fn mark_as_read_handler(
    State(state): State<AppState>,
    caller: ChatCaller,
    Path(conv_id): Path<String>,
) -> Result<StatusCode, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let (reader_type, reader_id) = match caller {
        ChatCaller::Device(dev) => (ReaderType::Device, dev.device_id),
        ChatCaller::User(u) => (ReaderType::User, u.id),
    };

    let now_str = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO chat_reads (conversation_id, reader_type, reader_id, last_read_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(conversation_id, reader_type, reader_id) DO UPDATE SET last_read_at = excluded.last_read_at"
    )
    .bind(&conv_id)
    .bind(reader_type.as_str())
    .bind(&reader_id)
    .bind(&now_str)
    .execute(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

// ----------------------------------------------------------------------------
// GET /api/chat/conversations (Technician queue)
// ----------------------------------------------------------------------------
pub async fn list_conversations_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<ConversationListQuery>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let has_attend =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_ATTEND)
            .await;
    let has_read =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_READ)
            .await;
    let has_manage =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_MANAGE)
            .await;

    if !has_attend && !has_read && !has_manage && user.role != "admin" {
        return Err(ChatConvError::Forbidden(
            "Permiso insuficiente para consultar conversaciones.".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 100);

    // Build dynamic query
    let mut sql = String::from(
        "SELECT c.id, c.device_id, c.device_name, c.device_hostname, c.device_os, c.status,
                c.assigned_user_id, u.username as assigned_username,
                c.contact_first_name, c.contact_last_name, c.created_at, c.updated_at, c.last_message_at
         FROM chat_conversations c
         LEFT JOIN users u ON c.assigned_user_id = u.id
         WHERE 1=1"
    );

    // Filter by status
    if let Some(ref st) = query.status {
        match st.as_str() {
            "open" => sql.push_str(" AND c.status IN ('waiting', 'assigned', 'active')"),
            "waiting" | "assigned" | "active" | "closed" => {
                sql.push_str(&format!(" AND c.status = '{st}'"));
            }
            _ => {
                return Err(ChatConvError::BadRequest(
                    "Estado de filtro inválido.".to_string(),
                ))
            }
        }
    }

    // Filter by assigned
    if let Some(ref ass) = query.assigned {
        if ass == "me" {
            sql.push_str(&format!(" AND c.assigned_user_id = '{}'", user.id));
        } else {
            sql.push_str(&format!(" AND c.assigned_user_id = '{ass}'"));
        }
    }

    // Search by q
    if let Some(ref q) = query.q {
        let pattern = format!("%{}%", q.replace('\'', "''"));
        sql.push_str(&format!(
            " AND (c.device_name LIKE '{pattern}' OR c.device_hostname LIKE '{pattern}' OR c.contact_first_name LIKE '{pattern}' OR c.contact_last_name LIKE '{pattern}')"
        ));
    }

    // Cursor pagination (by last_message_at DESC, created_at DESC)
    if let Some(ref cur) = query.cursor {
        sql.push_str(&format!(" AND c.last_message_at < '{cur}'"));
    }

    sql.push_str(&format!(
        " ORDER BY c.last_message_at DESC LIMIT {}",
        limit + 1
    ));

    let rows = sqlx::query(&sql)
        .fetch_all(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let mut summaries = Vec::new();
    let mut next_cursor = None;

    for (idx, r) in rows.iter().enumerate() {
        if idx == limit as usize {
            next_cursor = r.try_get("last_message_at").ok();
            break;
        }

        let conv_id: String = r.try_get("id").unwrap_or_default();
        let preview: Option<String> = sqlx::query_scalar(
            "SELECT body FROM chat_messages WHERE conversation_id = ? ORDER BY created_at DESC, id DESC LIMIT 1"
        )
        .bind(&conv_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|b: String| make_preview(&b));

        summaries.push(ConversationSummary {
            id: conv_id,
            device_id: r.try_get("device_id").unwrap_or_default(),
            device_name: opt_string(r, "device_name"),
            device_hostname: opt_string(r, "device_hostname"),
            device_os: opt_string(r, "device_os"),
            status: r.try_get("status").unwrap_or_default(),
            assigned_user_id: opt_string(r, "assigned_user_id"),
            assigned_username: opt_string(r, "assigned_username"),
            contact_first_name: opt_string(r, "contact_first_name"),
            contact_last_name: opt_string(r, "contact_last_name"),
            created_at: r.try_get("created_at").unwrap_or_default(),
            updated_at: r.try_get("updated_at").unwrap_or_default(),
            last_message_at: opt_string(r, "last_message_at"),
            last_message_preview: preview,
            unread_count: 0,
        });
    }

    Ok((
        StatusCode::OK,
        Json(ConversationListResponse {
            conversations: summaries,
            next_cursor,
        }),
    )
        .into_response())
}

// ----------------------------------------------------------------------------
// GET /api/chat/summary
// ----------------------------------------------------------------------------
pub async fn get_chat_summary_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let waiting: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_conversations WHERE status = 'waiting'")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let assigned_to_me: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat_conversations WHERE assigned_user_id = ? AND status IN ('assigned', 'active')")
        .bind(&user.id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let active: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_conversations WHERE status = 'active'")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    Ok((
        StatusCode::OK,
        Json(ChatSummaryResponse {
            waiting,
            assigned_to_me,
            active,
            unread: 0,
        }),
    )
        .into_response())
}

// ----------------------------------------------------------------------------
// GET /api/chat/agents
// ----------------------------------------------------------------------------
pub async fn list_chat_agents_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let has_manage =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_MANAGE)
            .await;

    if !has_manage && user.role != "admin" {
        return Err(ChatConvError::Forbidden(
            "Se requiere permiso chat:manage para consultar agentes.".to_string(),
        ));
    }

    let rows = sqlx::query("SELECT id, username, role FROM users WHERE is_active = 1 AND role IN ('admin', 'operator')")
        .fetch_all(&state.db)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let agents = rows
        .into_iter()
        .map(|r| AgentDto {
            id: r.try_get("id").unwrap_or_default(),
            username: r.try_get("username").unwrap_or_default(),
            role: r.try_get("role").unwrap_or_default(),
        })
        .collect();

    Ok((StatusCode::OK, Json(AgentsResponse { agents })).into_response())
}

fn opt_string(r: &sqlx::sqlite::SqliteRow, col: &str) -> Option<String> {
    r.try_get::<Option<String>, _>(col)
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
}

// ----------------------------------------------------------------------------
// Helper database fetchers
// ----------------------------------------------------------------------------
async fn fetch_conversation_summary(
    pool: &sqlx::SqlitePool,
    conv_id: &str,
) -> Result<ConversationSummary, ChatConvError> {
    let row = sqlx::query(
        "SELECT c.id, c.device_id, c.device_name, c.device_hostname, c.device_os, c.status,
                c.assigned_user_id, u.username as assigned_username,
                c.contact_first_name, c.contact_last_name, c.created_at, c.updated_at, c.last_message_at
         FROM chat_conversations c
         LEFT JOIN users u ON c.assigned_user_id = u.id
         WHERE c.id = ?"
    )
    .bind(conv_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(r) = row else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };

    let preview: Option<String> = sqlx::query_scalar(
        "SELECT body FROM chat_messages WHERE conversation_id = ? ORDER BY created_at DESC, id DESC LIMIT 1"
    )
    .bind(conv_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|b: String| make_preview(&b));

    Ok(ConversationSummary {
        id: r.try_get("id").unwrap_or_default(),
        device_id: r.try_get("device_id").unwrap_or_default(),
        device_name: opt_string(&r, "device_name"),
        device_hostname: opt_string(&r, "device_hostname"),
        device_os: opt_string(&r, "device_os"),
        status: r.try_get("status").unwrap_or_default(),
        assigned_user_id: opt_string(&r, "assigned_user_id"),
        assigned_username: opt_string(&r, "assigned_username"),
        contact_first_name: opt_string(&r, "contact_first_name"),
        contact_last_name: opt_string(&r, "contact_last_name"),
        created_at: r.try_get("created_at").unwrap_or_default(),
        updated_at: r.try_get("updated_at").unwrap_or_default(),
        last_message_at: opt_string(&r, "last_message_at"),
        last_message_preview: preview,
        unread_count: 0,
    })
}

async fn fetch_conversation_detail(
    pool: &sqlx::SqlitePool,
    conv_id: &str,
    caller_device: Option<&str>,
    caller_user: Option<&AuthenticatedUser>,
    limit: i64,
    before: Option<&str>,
) -> Result<ConversationDetail, ChatConvError> {
    let row = sqlx::query(
        "SELECT c.id, c.device_id, c.device_name, c.device_hostname, c.device_os, c.status,
                c.assigned_user_id, u.username as assigned_username,
                c.contact_first_name, c.contact_last_name, c.created_at, c.updated_at, c.last_message_at,
                c.closed_at, c.closed_by
         FROM chat_conversations c
         LEFT JOIN users u ON c.assigned_user_id = u.id
         WHERE c.id = ?"
    )
    .bind(conv_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(r) = row else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };

    let device_id: String = r.try_get("device_id").unwrap_or_default();
    let assigned_user_id: Option<String> = r.try_get("assigned_user_id").ok().flatten();

    // IDOR checks
    if let Some(calling_dev) = caller_device {
        if calling_dev != device_id {
            return Err(ChatConvError::Forbidden(
                "No autorizado para consultar esta conversación.".to_string(),
            ));
        }
    } else if let Some(user) = caller_user {
        let has_attend =
            permissions::user_has_permission(pool, &user.id, &user.role, permissions::CHAT_ATTEND)
                .await;
        let has_read =
            permissions::user_has_permission(pool, &user.id, &user.role, permissions::CHAT_READ)
                .await;
        let has_manage =
            permissions::user_has_permission(pool, &user.id, &user.role, permissions::CHAT_MANAGE)
                .await;

        if !has_attend && !has_read && !has_manage && user.role != "admin" {
            return Err(ChatConvError::Forbidden(
                "Permiso insuficiente para consultar conversaciones.".to_string(),
            ));
        }

        // Technician cannot view conversation assigned to another technician unless they have read/manage/admin
        if let Some(ref current_assigned) = assigned_user_id {
            if current_assigned != &user.id && !has_read && !has_manage && user.role != "admin" {
                return Err(ChatConvError::Forbidden(
                    "Conversación asignada a otro técnico.".to_string(),
                ));
            }
        }
    }

    // Fetch messages: newest first, cursor by before
    let mut msg_sql = String::from(
        "SELECT id, conversation_id, sender_type, sender_id, sender_name, body, created_at
         FROM chat_messages
         WHERE conversation_id = ?",
    );
    if let Some(before_id) = before {
        msg_sql.push_str(&format!(
            " AND (created_at < (SELECT created_at FROM chat_messages WHERE id = '{before_id}') \
              OR (created_at = (SELECT created_at FROM chat_messages WHERE id = '{before_id}') AND id < '{before_id}'))"
        ));
    }
    msg_sql.push_str(&format!(
        " ORDER BY created_at DESC, id DESC LIMIT {}",
        limit + 1
    ));

    let msg_rows = sqlx::query(&msg_sql)
        .bind(conv_id)
        .fetch_all(pool)
        .await
        .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let mut messages = Vec::new();
    let mut next_before = None;

    let has_more = msg_rows.len() > limit as usize;
    let take_count = if has_more {
        limit as usize
    } else {
        msg_rows.len()
    };

    for m in &msg_rows[..take_count] {
        let m_id: String = m.try_get("id").unwrap_or_default();
        let att_row = sqlx::query(
            "SELECT id, original_name, mime, size_bytes, sha256 FROM chat_attachments WHERE message_id = ?"
        )
        .bind(&m_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

        let attachment = att_row.map(|ar| AttachmentDto {
            id: ar.try_get("id").unwrap_or_default(),
            name: ar.try_get("original_name").unwrap_or_default(),
            mime: ar.try_get("mime").unwrap_or_default(),
            size_bytes: ar.try_get("size_bytes").unwrap_or_default(),
            sha256: ar.try_get("sha256").unwrap_or_default(),
        });

        messages.push(MessageDto {
            id: m_id,
            conversation_id: m.try_get("conversation_id").unwrap_or_default(),
            sender_type: m.try_get("sender_type").unwrap_or_default(),
            sender_id: m.try_get("sender_id").ok(),
            sender_name: m.try_get("sender_name").ok(),
            body: m.try_get("body").unwrap_or_default(),
            attachment,
            created_at: m.try_get("created_at").unwrap_or_default(),
        });
    }

    if has_more {
        if let Some(last) = messages.last() {
            next_before = Some(last.id.clone());
        }
    }

    // Read other participant's last read timestamp for double check
    let other_read_query = if caller_device.is_some() {
        // Look for technician's last read
        "SELECT last_read_at FROM chat_reads WHERE conversation_id = ? AND reader_type = 'user' ORDER BY last_read_at DESC LIMIT 1"
    } else {
        // Look for device's last read
        "SELECT last_read_at FROM chat_reads WHERE conversation_id = ? AND reader_type = 'device' ORDER BY last_read_at DESC LIMIT 1"
    };

    let other_last_read_at: Option<String> = sqlx::query_scalar(other_read_query)
        .bind(conv_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    let summary = ConversationSummary {
        id: r.try_get("id").unwrap_or_default(),
        device_id,
        device_name: opt_string(&r, "device_name"),
        device_hostname: opt_string(&r, "device_hostname"),
        device_os: opt_string(&r, "device_os"),
        status: r.try_get("status").unwrap_or_default(),
        assigned_user_id,
        assigned_username: opt_string(&r, "assigned_username"),
        contact_first_name: opt_string(&r, "contact_first_name"),
        contact_last_name: opt_string(&r, "contact_last_name"),
        created_at: r.try_get("created_at").unwrap_or_default(),
        updated_at: r.try_get("updated_at").unwrap_or_default(),
        last_message_at: opt_string(&r, "last_message_at"),
        last_message_preview: messages.last().map(|m| make_preview(&m.body)),
        unread_count: 0,
    };

    Ok(ConversationDetail {
        summary,
        closed_at: opt_string(&r, "closed_at"),
        closed_by: opt_string(&r, "closed_by"),
        messages,
        next_before,
        other_last_read_at,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct EscalatePayload {
    #[serde(default)]
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EscalateResponse {
    pub device_id: String,
    pub trace_id: String,
    pub url: String,
}

/// Escalates a conversation to an active remote support session (F4.5-12).
///
/// Emits audit event `chat.escalated` and generates deep link `cercano://connect?device=<device_id>&trace=<trace_id>`.
pub async fn escalate_conversation_handler(
    State(state): State<AppState>,
    caller: ChatCaller,
    Path(conv_id): Path<String>,
    payload: Option<Json<EscalatePayload>>,
) -> Result<Response, ChatConvError> {
    if !state.config.chat_enabled {
        return Err(ChatConvError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    let user = match caller {
        ChatCaller::User(u) => u,
        ChatCaller::Device(_) => {
            return Err(ChatConvError::Forbidden(
                "Solo los técnicos o administradores pueden escalar conversaciones.".to_string(),
            ));
        }
    };

    let has_attend =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_ATTEND)
            .await;
    let has_manage =
        permissions::user_has_permission(&state.db, &user.id, &user.role, permissions::CHAT_MANAGE)
            .await;

    if !has_attend && !has_manage && user.role != "admin" {
        return Err(ChatConvError::Forbidden(
            "Permiso insuficiente para escalar la conversación.".to_string(),
        ));
    }

    let row = sqlx::query(
        "SELECT id, device_id, assigned_user_id, status FROM chat_conversations WHERE id = ?",
    )
    .bind(&conv_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ChatConvError::Internal(e.to_string()))?;

    let Some(r) = row else {
        return Err(ChatConvError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };

    let device_id: String = r.try_get("device_id").unwrap_or_default();
    let assigned_user_id: Option<String> = r.try_get("assigned_user_id").ok().flatten();

    if let Some(ref assigned) = assigned_user_id {
        if assigned != &user.id && !has_manage && user.role != "admin" {
            return Err(ChatConvError::Forbidden(
                "Conversación asignada a otro técnico.".to_string(),
            ));
        }
    }

    let trace_id = payload
        .and_then(|p| p.0.trace_id)
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| conv_id.clone());

    let actor = Actor::with_type(&user.id, "user");
    let subject = Subject::with_type(&conv_id, "conversation");
    let audit_input = EventInput::new(
        conv_id.clone(),
        Source::Api,
        Category::Chat,
        "chat.escalated",
        actor,
        Outcome::Success,
        json!({
            "device_id": &device_id,
            "trace_id": &trace_id,
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    let url = format!("cercano://connect?device={}&trace={}", device_id, trace_id);

    Ok((
        StatusCode::OK,
        Json(EscalateResponse {
            device_id,
            trace_id,
            url,
        }),
    )
        .into_response())
}
