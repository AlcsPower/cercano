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

//! Secure Attachment Management for Cercano Chat (F4.5-05).
//!
//! Provides binary upload (`POST /api/chat/conversations/:id/attachments`) with:
//! - Strict MIME and magic-bytes inspection (PNG, JPEG, WebP, PDF)
//! - Disallowance of executable/script types (SVG, EXE, ZIP)
//! - 10 MiB payload cap (413 Payload Too Large)
//! - Filename sanitization against path-traversal attacks
//! - Atomic filesystem persistence with zero-orphan cleanup on failure
//! - Authenticated download (`GET /api/chat/attachments/:id`) with security headers
//!   (`nosniff`, `no-store`) and IDOR protection.

use std::path::{Path, PathBuf};

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::header::{HeaderMap, HeaderValue};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::chat::events::ChatEvent;

use crate::chat::conversations::{AttachmentDto, ChatCaller, MessageDto};
use crate::chat::SenderType;
use crate::permissions;
use crate::AppState;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG_MAGIC: &[u8] = b"\xff\xd8\xff";
const PDF_MAGIC: &[u8] = b"%PDF-";

#[derive(Debug)]
pub enum AttachmentError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    ConflictClosed,
    PayloadTooLarge,
    UnsupportedMediaType(String),
    TooManyRequests,
    Internal(String),
}

impl IntoResponse for AttachmentError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "bad_request", "message": msg })),
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
            Self::ConflictClosed => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "conflict",
                    "code": "conversation_closed",
                    "message": "La conversación está cerrada."
                })),
            )
                .into_response(),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({
                    "error": "payload_too_large",
                    "message": "El archivo excede el tamaño máximo permitido de 10 MiB."
                })),
            )
                .into_response(),
            Self::UnsupportedMediaType(msg) => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(json!({
                    "error": "unsupported_media_type",
                    "message": msg
                })),
            )
                .into_response(),
            Self::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "rate_limit_exceeded",
                    "message": "Límite de adjuntos excedido para este período."
                })),
            )
                .into_response(),
            Self::Internal(msg) => {
                tracing::error!("Attachment internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal_error", "message": "Error interno del servidor." })),
                )
                    .into_response()
            }
        }
    }
}

/// Validates file bytes against declared MIME type using magic bytes.
/// Returns normalized MIME on success or an error with details.
pub fn validate_mime_and_magic(
    declared_mime: &str,
    bytes: &[u8],
) -> Result<String, AttachmentError> {
    if bytes.is_empty() {
        return Err(AttachmentError::BadRequest(
            "El archivo adjunto no puede estar vacío.".to_string(),
        ));
    }

    let norm = declared_mime.trim().to_lowercase();
    match norm.as_str() {
        "image/png" => {
            if bytes.len() >= 8 && &bytes[..8] == PNG_MAGIC {
                Ok("image/png".to_string())
            } else {
                Err(AttachmentError::UnsupportedMediaType(
                    "Contenido no coincide con magic bytes de PNG.".to_string(),
                ))
            }
        }
        "image/jpeg" | "image/jpg" => {
            if bytes.len() >= 3 && &bytes[..3] == JPEG_MAGIC {
                Ok("image/jpeg".to_string())
            } else {
                Err(AttachmentError::UnsupportedMediaType(
                    "Contenido no coincide con magic bytes de JPEG.".to_string(),
                ))
            }
        }
        "image/webp" => {
            if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
                Ok("image/webp".to_string())
            } else {
                Err(AttachmentError::UnsupportedMediaType(
                    "Contenido no coincide con magic bytes de WebP.".to_string(),
                ))
            }
        }
        "application/pdf" => {
            if bytes.len() >= 5 && &bytes[..5] == PDF_MAGIC {
                Ok("application/pdf".to_string())
            } else {
                Err(AttachmentError::UnsupportedMediaType(
                    "Contenido no coincide con magic bytes de PDF.".to_string(),
                ))
            }
        }
        "image/svg+xml"
        | "application/zip"
        | "application/x-msdownload"
        | "application/x-executable" => Err(AttachmentError::UnsupportedMediaType(
            "Tipo de archivo no permitido por razones de seguridad.".to_string(),
        )),
        other => Err(AttachmentError::UnsupportedMediaType(format!(
            "Tipo MIME no permitido: {other}. Solo se admiten PNG, JPEG, WebP y PDF."
        ))),
    }
}

/// Sanitizes a raw client filename, preventing path traversal and control characters.
pub fn sanitize_filename(raw: &str) -> String {
    let basename = Path::new(raw)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("attachment")
        .trim();

    let cleaned: String = basename
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\' && *c != '\0')
        .collect();

    let trimmed = cleaned.trim().trim_matches('.');
    if trimmed.is_empty() {
        "attachment".to_string()
    } else if trimmed.chars().count() > 255 {
        trimmed.chars().take(255).collect()
    } else {
        trimmed.to_string()
    }
}

/// Extracts filename from headers, prioritizing `X-File-Name-B64` then `X-File-Name`.
fn extract_filename(headers: &HeaderMap) -> String {
    if let Some(b64_val) = headers.get("x-file-name-b64").and_then(|h| h.to_str().ok()) {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64_val.trim()) {
            if let Ok(s) = String::from_utf8(decoded) {
                let sanitized = sanitize_filename(&s);
                if !sanitized.is_empty() && sanitized != "attachment" {
                    return sanitized;
                }
            }
        }
    }

    if let Some(name_val) = headers.get("x-file-name").and_then(|h| h.to_str().ok()) {
        let sanitized = sanitize_filename(name_val);
        if !sanitized.is_empty() {
            return sanitized;
        }
    }

    "attachment".to_string()
}

// ----------------------------------------------------------------------------
// POST /api/chat/conversations/:id/attachments
// ----------------------------------------------------------------------------
pub async fn upload_attachment_handler(
    State(state): State<AppState>,
    caller: ChatCaller,
    AxumPath(conv_id): AxumPath<String>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Response, AttachmentError> {
    if !state.config.chat_enabled {
        return Err(AttachmentError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    // 1. Verify file size
    if body_bytes.is_empty() {
        return Err(AttachmentError::BadRequest(
            "El archivo adjunto no puede estar vacío.".to_string(),
        ));
    }
    if body_bytes.len() > state.config.chat_max_attachment_bytes {
        return Err(AttachmentError::PayloadTooLarge);
    }

    // 2. Validate declared MIME & magic bytes
    let declared_mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let mime = validate_mime_and_magic(declared_mime, &body_bytes)?;
    let original_name = extract_filename(&headers);

    // 3. Conversation check & authorization
    let conv = sqlx::query(
        "SELECT device_id, status, assigned_user_id FROM chat_conversations WHERE id = ?",
    )
    .bind(&conv_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AttachmentError::Internal(e.to_string()))?;

    let Some(row) = conv else {
        return Err(AttachmentError::NotFound(
            "Conversación no encontrada.".to_string(),
        ));
    };

    let conv_device_id: String = row.try_get("device_id").unwrap_or_default();
    let status: String = row.try_get("status").unwrap_or_default();
    let assigned_user_id: Option<String> = row.try_get("assigned_user_id").ok().flatten();

    if status == "closed" {
        return Err(AttachmentError::ConflictClosed);
    }

    let (sender_type, sender_id, sender_name) = match caller {
        ChatCaller::Device(ref dev) => {
            if dev.device_id != conv_device_id {
                return Err(AttachmentError::Forbidden(
                    "No autorizado para enviar adjuntos en esta conversación.".to_string(),
                ));
            }
            (
                SenderType::Client,
                dev.device_id.clone(),
                dev.device_id.clone(),
            )
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
                return Err(AttachmentError::Forbidden(
                    "Permiso insuficiente para enviar adjuntos.".to_string(),
                ));
            }

            if let Some(ref current) = assigned_user_id {
                if current != &user.id && !has_manage && user.role != "admin" {
                    return Err(AttachmentError::Forbidden(
                        "Conversación asignada a otro técnico.".to_string(),
                    ));
                }
            }

            (
                SenderType::Technician,
                user.id.clone(),
                user.username.clone(),
            )
        }
    };

    // 4. Rate limit check for attachments
    let count_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_attachments a
         JOIN chat_messages m ON a.message_id = m.id
         WHERE m.conversation_id = ? AND a.created_at > datetime('now', '-24 hours')",
    )
    .bind(&conv_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if count_today >= state.config.chat_attachment_daily_limit as i64 {
        return Err(AttachmentError::TooManyRequests);
    }

    // 5. Idempotency check with client_message_id
    let client_msg_id = headers
        .get("x-client-message-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(cid) = client_msg_id {
        let existing = sqlx::query(
            "SELECT m.id, m.conversation_id, m.sender_type, m.sender_id, m.sender_name, m.body, m.created_at,
                    a.id as att_id, a.original_name, a.mime, a.size_bytes, a.sha256
             FROM chat_messages m
             JOIN chat_attachments a ON m.id = a.message_id
             WHERE m.conversation_id = ? AND m.sender_type = ? AND m.sender_id = ? AND m.client_message_id = ?",
        )
        .bind(&conv_id)
        .bind(sender_type.as_str())
        .bind(&sender_id)
        .bind(cid)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AttachmentError::Internal(e.to_string()))?;

        if let Some(r) = existing {
            let res = MessageDto {
                id: r.try_get("id").unwrap_or_default(),
                conversation_id: r.try_get("conversation_id").unwrap_or_default(),
                sender_type: r.try_get("sender_type").unwrap_or_default(),
                sender_id: r.try_get("sender_id").ok(),
                sender_name: r.try_get("sender_name").ok(),
                body: r.try_get("body").unwrap_or_default(),
                attachment: Some(AttachmentDto {
                    id: r.try_get("att_id").unwrap_or_default(),
                    name: r.try_get("original_name").unwrap_or_default(),
                    mime: r.try_get("mime").unwrap_or_default(),
                    size_bytes: r.try_get("size_bytes").unwrap_or_default(),
                    sha256: r.try_get("sha256").unwrap_or_default(),
                }),
                created_at: r.try_get("created_at").unwrap_or_default(),
            };
            return Ok((StatusCode::OK, Json(res)).into_response());
        }
    }

    // 6. Compute SHA-256 and prepare atomic file write
    let mut hasher = Sha256::new();
    hasher.update(&body_bytes);
    let sha256_hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let attachment_id = Uuid::now_v7().to_string();
    let message_id = Uuid::now_v7().to_string();
    let storage_key = format!("{attachment_id}-{}.bin", &sha256_hex[..8]);

    let target_dir = PathBuf::from(&state.config.chat_attachment_dir);
    tokio::fs::create_dir_all(&target_dir).await.map_err(|e| {
        AttachmentError::Internal(format!("Error creando directorio de adjuntos: {e}"))
    })?;

    let target_path = target_dir.join(&storage_key);
    let temp_path = target_dir.join(format!("{storage_key}.tmp"));

    // Write to temporary file first
    if let Err(e) = tokio::fs::write(&temp_path, &body_bytes).await {
        return Err(AttachmentError::Internal(format!(
            "Error escribiendo archivo temporal: {e}"
        )));
    }

    // Rename atomically to target path
    if let Err(e) = tokio::fs::rename(&temp_path, &target_path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AttachmentError::Internal(format!(
            "Error guardando archivo adjunto: {e}"
        )));
    }

    // 7. Atomic DB insertion (message + attachment)
    let now_str = Utc::now().to_rfc3339();
    let size_bytes = body_bytes.len() as i64;

    let new_status = if sender_type == SenderType::Technician && status == "assigned" {
        "active"
    } else {
        &status
    };

    let insert_result = async {
        let mut tx = state.db.begin().await?;

        sqlx::query(
            "INSERT INTO chat_messages (id, conversation_id, sender_type, sender_id, sender_name, body, client_message_id, created_at)
             VALUES (?, ?, ?, ?, ?, '', ?, ?)",
        )
        .bind(&message_id)
        .bind(&conv_id)
        .bind(sender_type.as_str())
        .bind(&sender_id)
        .bind(&sender_name)
        .bind(client_msg_id)
        .bind(&now_str)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO chat_attachments (id, message_id, original_name, mime, size_bytes, sha256, storage_key, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&attachment_id)
        .bind(&message_id)
        .bind(&original_name)
        .bind(&mime)
        .bind(size_bytes)
        .bind(&sha256_hex)
        .bind(&storage_key)
        .bind(&now_str)
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE chat_conversations SET status = ?, last_message_at = ?, updated_at = ? WHERE id = ?")
            .bind(new_status)
            .bind(&now_str)
            .bind(&now_str)
            .bind(&conv_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok::<(), sqlx::Error>(())
    }
    .await;

    // Fail-close: if DB fails, remove written file from disk (zero orphans)
    if let Err(e) = insert_result {
        let _ = tokio::fs::remove_file(&target_path).await;
        return Err(AttachmentError::Internal(format!(
            "Error en base de datos: {e}"
        )));
    }

    // 8. Audit event
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
            "message_id": &message_id,
            "sender_type": sender_type.as_str(),
            "has_attachment": true,
            "attachment_id": &attachment_id,
            "size_bytes": size_bytes,
            "mime": &mime
        }),
    )
    .with_subject(subject);
    let _ = state.audit.append(audit_input).await;

    let audience_device = Some(conv_device_id.clone());
    let audience_user = match sender_type {
        SenderType::Client => assigned_user_id.clone(),
        SenderType::Technician => Some(sender_id.clone()),
        SenderType::System => assigned_user_id.clone(),
    };
    let is_queue = assigned_user_id.is_none();
    state.chat_hub.broadcast(ChatEvent::message(
        &conv_id,
        &message_id,
        audience_device,
        audience_user,
        is_queue,
    ));

    if new_status != status {
        state.chat_hub.broadcast(ChatEvent::status(
            &conv_id,
            new_status,
            Some(conv_device_id.clone()),
            assigned_user_id.clone(),
            is_queue,
        ));
    }

    let response_dto = MessageDto {
        id: message_id,
        conversation_id: conv_id,
        sender_type: sender_type.as_str().to_string(),
        sender_id: Some(sender_id),
        sender_name: Some(sender_name),
        body: String::new(),
        attachment: Some(AttachmentDto {
            id: attachment_id,
            name: original_name,
            mime,
            size_bytes,
            sha256: sha256_hex,
        }),
        created_at: now_str,
    };

    Ok((StatusCode::CREATED, Json(response_dto)).into_response())
}

// ----------------------------------------------------------------------------
// GET /api/chat/attachments/:id
// ----------------------------------------------------------------------------
pub async fn download_attachment_handler(
    State(state): State<AppState>,
    caller: ChatCaller,
    AxumPath(att_id): AxumPath<String>,
) -> Result<Response, AttachmentError> {
    if !state.config.chat_enabled {
        return Err(AttachmentError::Forbidden(
            "El servicio de chat está desactivado.".to_string(),
        ));
    }

    // Join to check access rights
    let row = sqlx::query(
        "SELECT a.id, a.original_name, a.mime, a.size_bytes, a.storage_key,
                c.id as conv_id, c.device_id, c.assigned_user_id
         FROM chat_attachments a
         JOIN chat_messages m ON a.message_id = m.id
         JOIN chat_conversations c ON m.conversation_id = c.id
         WHERE a.id = ?",
    )
    .bind(&att_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AttachmentError::Internal(e.to_string()))?;

    let Some(r) = row else {
        return Err(AttachmentError::NotFound(
            "Adjunto no encontrado.".to_string(),
        ));
    };

    let conv_device_id: String = r.try_get("device_id").unwrap_or_default();
    let assigned_user_id: Option<String> = r.try_get("assigned_user_id").ok().flatten();
    let original_name: String = r.try_get("original_name").unwrap_or_default();
    let mime: String = r.try_get("mime").unwrap_or_default();
    let storage_key: String = r.try_get("storage_key").unwrap_or_default();

    // Verify access rights
    match caller {
        ChatCaller::Device(ref dev) => {
            if dev.device_id != conv_device_id {
                return Err(AttachmentError::Forbidden(
                    "No autorizado para descargar este adjunto.".to_string(),
                ));
            }
        }
        ChatCaller::User(ref user) => {
            let has_attend = permissions::user_has_permission(
                &state.db,
                &user.id,
                &user.role,
                permissions::CHAT_ATTEND,
            )
            .await;
            let has_read = permissions::user_has_permission(
                &state.db,
                &user.id,
                &user.role,
                permissions::CHAT_READ,
            )
            .await;
            let has_manage = permissions::user_has_permission(
                &state.db,
                &user.id,
                &user.role,
                permissions::CHAT_MANAGE,
            )
            .await;

            if !has_attend && !has_read && !has_manage && user.role != "admin" {
                return Err(AttachmentError::Forbidden(
                    "Permiso insuficiente para descargar adjuntos.".to_string(),
                ));
            }

            if let Some(ref current) = assigned_user_id {
                if current != &user.id && !has_read && !has_manage && user.role != "admin" {
                    return Err(AttachmentError::Forbidden(
                        "Conversación asignada a otro técnico.".to_string(),
                    ));
                }
            }
        }
    }

    let file_path = PathBuf::from(&state.config.chat_attachment_dir).join(&storage_key);
    let bytes = tokio::fs::read(&file_path)
        .await
        .map_err(|e| AttachmentError::Internal(format!("Error leyendo archivo de disco: {e}")))?;

    let mut res = Response::new(bytes.into());
    *res.status_mut() = StatusCode::OK;

    let headers = res.headers_mut();
    if let Ok(mime_val) = HeaderValue::from_str(&mime) {
        headers.insert(header::CONTENT_TYPE, mime_val);
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );

    let disposition = format!("attachment; filename=\"{original_name}\"");
    if let Ok(disp_val) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, disp_val);
    }

    Ok(res)
}
