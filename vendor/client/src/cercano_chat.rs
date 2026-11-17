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

//! Cercano Chat client module (F4.5-10).
//!
//! Handles device registration, Ed25519 challenge-response authentication,
//! REST communications, real-time SSE stream processing, and Windows desktop toasts.
//!
//! Security and Privacy:
//! - TLS is strictly mandatory: plaintext HTTP endpoints are rejected immediately.
//! - Tokens are kept strictly in-memory and never written to disk or logs.
//! - Message bodies, contact names, and attachment contents are never logged or included in toasts.

use hbb_common::{
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    config::Config,
    log,
    sodiumoxide::crypto::sign::{self, SecretKey},
    tokio,
};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::time::Duration;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatBranding {
    pub support_name: String,
    pub organization_name: String,
    pub logo_url: Option<String>,
    pub accent_color: String,
    pub welcome_text: String,
    pub info_text: String,
    pub privacy_text: String,
}

impl Default for ChatBranding {
    fn default() -> Self {
        Self {
            support_name: "Cercano Soporte".to_string(),
            organization_name: "Soporte interno".to_string(),
            logo_url: None,
            accent_color: "#3B5BFF".to_string(),
            welcome_text: "Cuéntanos qué necesitas y un técnico te atenderá.".to_string(),
            info_text: "Está conversando con el equipo de soporte.".to_string(),
            privacy_text: "Su conversación es privada y se guarda para seguimiento.".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatAttachment {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub size_bytes: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_type: String,
    pub sender_id: String,
    pub sender_name: Option<String>,
    pub body: String,
    pub attachment: Option<ChatAttachment>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatConversation {
    pub id: String,
    pub device_id: String,
    pub status: String,
    pub contact_first_name: String,
    pub contact_last_name: String,
    pub assigned_user_id: Option<String>,
    pub assigned_username: Option<String>,
    pub other_last_read_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub messages: Vec<ChatMessage>,
}

lazy_static::lazy_static! {
    static ref CHAT_SESSION_TOKEN: RwLock<Option<String>> = RwLock::new(None);
    static ref LISTENER_STARTED: RwLock<bool> = RwLock::new(false);
}

pub fn check_https_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("TLS obligatorio: el chat de Cercano solo funciona sobre HTTPS.".to_string());
    }
    Ok(())
}

pub fn get_chat_api_server() -> String {
    #[cfg(feature = "flutter")]
    {
        let api = crate::flutter_ffi::main_get_api_server();
        if !api.is_empty() {
            return api;
        }
    }
    "https://127.0.0.1:21114".to_string()
}

pub fn sign_challenge_nonce(raw_nonce: &[u8], sk_bytes: &[u8]) -> Result<String, String> {
    let sk = SecretKey::from_slice(sk_bytes)
        .ok_or_else(|| "Clave secreta inválida: se esperan 64 bytes.".to_string())?;
    let sig = sign::sign_detached(raw_nonce, &sk);
    Ok(BASE64.encode(sig.as_ref()))
}

pub fn register_device_if_needed(api_server: &str, ingest_token: &str) -> Result<(), String> {
    check_https_url(api_server)?;

    let device_id = Config::get_id();
    let keypair = Config::get_key_pair();
    let pubkey_b64 = BASE64.encode(&keypair.1);
    let display_name = crate::common::hostname();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{}/api/chat/devices/register", api_server.trim_end_matches('/'));
    let payload = serde_json::json!({
        "device_id": device_id,
        "public_key": pubkey_b64,
        "display_name": display_name,
    });

    let mut req = client.post(&url).json(&payload);
    if !ingest_token.is_empty() {
        req = req.header("X-Cercano-Client-Token", ingest_token);
    }

    let resp = req.send().map_err(|e| format!("Error conectando con registro de chat: {}", e))?;
    if resp.status().is_success() || resp.status() == reqwest::StatusCode::CONFLICT {
        Ok(())
    } else {
        Err(format!("Error en registro de dispositivo (código: {})", resp.status()))
    }
}

pub fn authenticate_device(api_server: &str) -> Result<String, String> {
    check_https_url(api_server)?;

    let device_id = Config::get_id();
    let keypair = Config::get_key_pair();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    // 1. Challenge
    let challenge_url = format!("{}/api/chat/auth/challenge", api_server.trim_end_matches('/'));
    let challenge_resp = client
        .post(&challenge_url)
        .json(&serde_json::json!({ "device_id": device_id }))
        .send()
        .map_err(|e| format!("Error en solicitud de reto: {}", e))?;

    if !challenge_resp.status().is_success() {
        return Err(format!("Reto de autenticación fallido: {}", challenge_resp.status()));
    }

    let challenge_data: serde_json::Value = challenge_resp
        .json()
        .map_err(|e| format!("Respuesta de reto inválida: {}", e))?;

    let challenge_id = challenge_data["challenge_id"]
        .as_str()
        .ok_or_else(|| "challenge_id ausente en respuesta".to_string())?;
    let nonce_b64 = challenge_data["nonce"]
        .as_str()
        .ok_or_else(|| "nonce ausente en respuesta".to_string())?;

    let raw_nonce = BASE64
        .decode(nonce_b64)
        .map_err(|e| format!("Nonce base64 inválido: {}", e))?;

    // 2. Sign raw nonce bytes with device Ed25519 secret key
    let sig_b64 = sign_challenge_nonce(&raw_nonce, &keypair.0)?;

    // 3. Verify
    let verify_url = format!("{}/api/chat/auth/verify", api_server.trim_end_matches('/'));
    let verify_resp = client
        .post(&verify_url)
        .json(&serde_json::json!({
            "challenge_id": challenge_id,
            "signature": sig_b64
        }))
        .send()
        .map_err(|e| format!("Error en verificación de reto: {}", e))?;

    if !verify_resp.status().is_success() {
        return Err(format!("Verificación de firma fallida: {}", verify_resp.status()));
    }

    let verify_data: serde_json::Value = verify_resp
        .json()
        .map_err(|e| format!("Respuesta de verificación inválida: {}", e))?;

    let token = verify_data["token"]
        .as_str()
        .ok_or_else(|| "token ausente en verificación".to_string())?
        .to_string();

    let mut lock = CHAT_SESSION_TOKEN.write().unwrap();
    *lock = Some(token.clone());
    Ok(token)
}

pub fn get_or_ensure_token(api_server: &str) -> Result<String, String> {
    {
        let lock = CHAT_SESSION_TOKEN.read().unwrap();
        if let Some(ref token) = *lock {
            return Ok(token.clone());
        }
    }
    // shortcut: registro con token por defecto si el dispositivo aún no está fijado
    let _ = register_device_if_needed(api_server, "");
    authenticate_device(api_server)
}

pub fn invalidate_cached_token() {
    let mut lock = CHAT_SESSION_TOKEN.write().unwrap();
    *lock = None;
}

pub fn chat_get_branding(api_server: &str) -> Result<ChatBranding, String> {
    check_https_url(api_server)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{}/api/chat/branding", api_server.trim_end_matches('/'));
    let resp = client.get(&url).send().map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        resp.json::<ChatBranding>().map_err(|e| e.to_string())
    } else {
        Ok(ChatBranding::default())
    }
}

pub fn chat_create_conversation(
    api_server: &str,
    first_name: &str,
    last_name: &str,
    initial_message: &str,
) -> Result<ChatConversation, String> {
    check_https_url(api_server)?;
    let token = get_or_ensure_token(api_server)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{}/api/chat/conversations", api_server.trim_end_matches('/'));
    let payload = serde_json::json!({
        "contact_first_name": first_name.trim(),
        "contact_last_name": last_name.trim(),
        "initial_message": initial_message.trim(),
    });

    let resp = client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
        .json(&payload)
        .send()
        .map_err(|e| e.to_string())?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        invalidate_cached_token();
        return Err("Sesión caducada; reintentando autenticación.".to_string());
    }

    if !resp.status().is_success() {
        return Err(format!("Error creando conversación (código: {})", resp.status()));
    }

    resp.json::<ChatConversation>().map_err(|e| e.to_string())
}

pub fn chat_get_conversation(api_server: &str, id: &str) -> Result<ChatConversation, String> {
    check_https_url(api_server)?;
    let token = get_or_ensure_token(api_server)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{}/api/chat/conversations/{}", api_server.trim_end_matches('/'), id);
    let resp = client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
        .send()
        .map_err(|e| e.to_string())?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        invalidate_cached_token();
        return Err("Sesión caducada.".to_string());
    }

    if !resp.status().is_success() {
        return Err(format!("Error obteniendo conversación: {}", resp.status()));
    }

    resp.json::<ChatConversation>().map_err(|e| e.to_string())
}

pub fn chat_send_message(
    api_server: &str,
    conversation_id: &str,
    body: &str,
) -> Result<ChatMessage, String> {
    check_https_url(api_server)?;
    let token = get_or_ensure_token(api_server)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!(
        "{}/api/chat/conversations/{}/messages",
        api_server.trim_end_matches('/'),
        conversation_id
    );
    let client_msg_id = uuid::Uuid::new_v4().to_string();

    let resp = client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
        .json(&serde_json::json!({
            "body": body,
            "client_message_id": client_msg_id,
        }))
        .send()
        .map_err(|e| e.to_string())?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        invalidate_cached_token();
        return Err("Sesión caducada.".to_string());
    }

    if !resp.status().is_success() {
        return Err(format!("Error enviando mensaje: {}", resp.status()));
    }

    resp.json::<ChatMessage>().map_err(|e| e.to_string())
}

pub fn chat_send_attachment(
    api_server: &str,
    conversation_id: &str,
    file_name: &str,
    mime: &str,
    data: &[u8],
) -> Result<ChatMessage, String> {
    check_https_url(api_server)?;
    let token = get_or_ensure_token(api_server)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!(
        "{}/api/chat/conversations/{}/attachments",
        api_server.trim_end_matches('/'),
        conversation_id
    );
    let filename_b64 = BASE64.encode(file_name.as_bytes());
    let client_msg_id = uuid::Uuid::new_v4().to_string();

    let resp = client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
        .header("Content-Type", mime)
        .header("X-File-Name-B64", filename_b64)
        .header("X-Client-Message-Id", client_msg_id)
        .body(data.to_vec())
        .send()
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("Error subiendo adjunto: {}", resp.status()));
    }

    resp.json::<ChatMessage>().map_err(|e| e.to_string())
}

pub fn chat_mark_read(api_server: &str, conversation_id: &str) -> Result<(), String> {
    check_https_url(api_server)?;
    let token = get_or_ensure_token(api_server)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!(
        "{}/api/chat/conversations/{}/read",
        api_server.trim_end_matches('/'),
        conversation_id
    );

    let resp = client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
        .send()
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Error marcando lectura: {}", resp.status()))
    }
}

pub fn chat_close_conversation(
    api_server: &str,
    conversation_id: &str,
    reason: &str,
) -> Result<(), String> {
    check_https_url(api_server)?;
    let token = get_or_ensure_token(api_server)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!(
        "{}/api/chat/conversations/{}/close",
        api_server.trim_end_matches('/'),
        conversation_id
    );

    let resp = client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
        .json(&serde_json::json!({ "reason": reason }))
        .send()
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Error cerrando conversación: {}", resp.status()))
    }
}

#[cfg(windows)]
pub fn show_chat_toast() {
    // Toast genérico sin cuerpo ni nombres de contacto por privacidad (F4.5-09/10)
    use tauri_winrt_notification::Toast;
    let _ = Toast::new(Toast::POWERSHELL_APP_ID)
        .title("Cercano Soporte")
        .text1("Nuevo mensaje del equipo de soporte.")
        .show();
}

#[cfg(not(windows))]
pub fn show_chat_toast() {
    log::info!("Chat notification received");
}

pub fn start_chat_events_listener(api_server: &str) {
    {
        let mut started = LISTENER_STARTED.write().unwrap();
        if *started {
            return;
        }
        *started = true;
    }

    let api_server = api_server.to_string();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                log::error!("No se pudo inicializar runtime tokio para chat SSE: {}", e);
                return;
            }
        };

        rt.block_on(async move {
            let mut backoff_secs = 1u64;
            loop {
                let token = match get_or_ensure_token(&api_server) {
                    Ok(t) => t,
                    Err(e) => {
                        log::debug!("Error obteniendo token para SSE chat: {}", e);
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(30);
                        continue;
                    }
                };

                let sse_url = format!("{}/api/chat/events", api_server.trim_end_matches('/'));
                let client = match reqwest::Client::builder().build() {
                    Ok(c) => c,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };

                let resp = client
                    .get(&sse_url)
                    .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
                    .send()
                    .await;

                let mut resp = match resp {
                    Ok(r) if r.status().is_success() => {
                        backoff_secs = 1;
                        r
                    }
                    Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                        invalidate_cached_token();
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    _ => {
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(30);
                        continue;
                    }
                };

                let mut buffer = String::new();
                while let Ok(Some(chunk)) = resp.chunk().await {
                    if let Ok(text) = std::str::from_utf8(&chunk) {
                        buffer.push_str(text);
                        while let Some(pos) = buffer.find("\n\n") {
                            let frame = buffer[..pos].to_string();
                            buffer = buffer[pos + 2..].to_string();

                            for line in frame.lines() {
                                if let Some(data) = line.strip_prefix("data:") {
                                    let trimmed = data.trim();
                                    if let Ok(poke) = serde_json::from_str::<ChatPoke>(trimmed) {
                                        if let ChatPoke::Message { .. } = poke {
                                            show_chat_toast();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(30);
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_rejection() {
        assert!(check_https_url("http://cercano.local:21114").is_err());
        assert!(check_https_url("http://127.0.0.1:21114").is_err());
        assert!(check_https_url("https://cercano.local:21114").is_ok());
    }

    #[test]
    fn test_nonce_signing_and_verification() {
        use hbb_common::sodiumoxide::crypto::sign;

        let (pk, sk) = sign::gen_keypair();
        let raw_nonce = b"cercano_test_nonce_32_bytes_len!";
        let sig_b64 = sign_challenge_nonce(raw_nonce, sk.as_ref()).expect("Firma válida");

        let sig_bytes = BASE64.decode(sig_b64).expect("Base64 decoding");
        let signature = sign::Signature::from_slice(&sig_bytes).expect("Valid signature length");

        assert!(sign::verify_detached(&signature, raw_nonce, &pk));
    }

    #[test]
    fn test_poke_parsing() {
        let msg_json = r#"{"type":"message","conversation_id":"c-123","message_id":"m-456"}"#;
        let poke: ChatPoke = serde_json::from_str(msg_json).unwrap();
        assert_eq!(
            poke,
            ChatPoke::Message {
                conversation_id: "c-123".to_string(),
                message_id: "m-456".to_string(),
            }
        );

        let resync_json = r#"{"type":"resync"}"#;
        let resync_poke: ChatPoke = serde_json::from_str(resync_json).unwrap();
        assert_eq!(resync_poke, ChatPoke::Resync);
    }
}
