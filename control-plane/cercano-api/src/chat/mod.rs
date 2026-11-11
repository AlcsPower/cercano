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

//! Domain models and validation for Cercano Chat (F4.5).
//!
//! HTTP handlers live in `chat::auth` (F4.5-03) and later in
//! `chat::conversations` (F4.5-04). Keeping the schema-aligned structs and
//! input validation here lets every handler share the same rules.

pub mod auth;
pub mod branding;
pub mod conversations;

use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteRow;
use sqlx::Row;

pub const MAX_DEVICE_ID_LEN: usize = 128;
pub const MAX_CONTACT_NAME_LEN: usize = 64;
pub const MAX_MESSAGE_BODY_LEN: usize = 4_000;
pub const MAX_OPTIONAL_TEXT_LEN: usize = 128;
pub const MAX_BRANDING_TEXT_LEN: usize = 512;
pub const DEFAULT_SUPPORT_NAME: &str = "Cercano Soporte";
pub const DEFAULT_ACCENT_COLOR: &str = "#3B5BFF";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConversationStatus {
    Waiting,
    Assigned,
    Active,
    Closed,
}

impl ConversationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Assigned => "assigned",
            Self::Active => "active",
            Self::Closed => "closed",
        }
    }

    pub fn from_db(value: &str) -> Result<Self, String> {
        match value {
            "waiting" => Ok(Self::Waiting),
            "assigned" => Ok(Self::Assigned),
            "active" => Ok(Self::Active),
            "closed" => Ok(Self::Closed),
            other => Err(format!("estado de conversación desconocido: {other}")),
        }
    }

    pub fn is_open(self) -> bool {
        !matches!(self, Self::Closed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SenderType {
    Client,
    Technician,
    System,
}

impl SenderType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Technician => "technician",
            Self::System => "system",
        }
    }

    pub fn from_db(value: &str) -> Result<Self, String> {
        match value {
            "client" => Ok(Self::Client),
            "technician" => Ok(Self::Technician),
            "system" => Ok(Self::System),
            other => Err(format!("tipo de remitente desconocido: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReaderType {
    Device,
    User,
}

impl ReaderType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::User => "user",
        }
    }

    pub fn from_db(value: &str) -> Result<Self, String> {
        match value {
            "device" => Ok(Self::Device),
            "user" => Ok(Self::User),
            other => Err(format!("tipo de lector desconocido: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatDevice {
    pub device_id: String,
    pub public_key: String,
    pub installer_id: Option<String>,
    pub display_name: Option<String>,
    pub last_auth_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

impl ChatDevice {
    pub fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            device_id: row.try_get("device_id")?,
            public_key: row.try_get("public_key")?,
            installer_id: row.try_get("installer_id")?,
            display_name: row.try_get("display_name")?,
            last_auth_at: row.try_get("last_auth_at")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatConversation {
    pub id: String,
    pub device_id: String,
    pub device_name: Option<String>,
    pub device_hostname: Option<String>,
    pub device_os: Option<String>,
    pub installer_id: Option<String>,
    pub status: ConversationStatus,
    pub assigned_user_id: Option<String>,
    pub contact_first_name: Option<String>,
    pub contact_last_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_message_at: Option<String>,
    pub closed_at: Option<String>,
    pub closed_by: Option<String>,
}

impl ChatConversation {
    pub fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        let status = ConversationStatus::from_db(&row.try_get::<String, _>("status")?)
            .map_err(decode_error)?;
        Ok(Self {
            id: row.try_get("id")?,
            device_id: row.try_get("device_id")?,
            device_name: row.try_get("device_name")?,
            device_hostname: row.try_get("device_hostname")?,
            device_os: row.try_get("device_os")?,
            installer_id: row.try_get("installer_id")?,
            status,
            assigned_user_id: row.try_get("assigned_user_id")?,
            contact_first_name: row.try_get("contact_first_name")?,
            contact_last_name: row.try_get("contact_last_name")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            last_message_at: row.try_get("last_message_at")?,
            closed_at: row.try_get("closed_at")?,
            closed_by: row.try_get("closed_by")?,
        })
    }

    /// Human-readable contact name; the console falls back to the device name when absent.
    pub fn contact_name(&self) -> Option<String> {
        match (&self.contact_first_name, &self.contact_last_name) {
            (Some(first), Some(last)) => Some(format!("{first} {last}")),
            (Some(first), None) => Some(first.clone()),
            (None, Some(last)) => Some(last.clone()),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_type: SenderType,
    pub sender_id: Option<String>,
    pub sender_name: Option<String>,
    pub body: String,
    pub client_message_id: Option<String>,
    pub created_at: String,
}

impl ChatMessage {
    pub fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        let sender_type =
            SenderType::from_db(&row.try_get::<String, _>("sender_type")?).map_err(decode_error)?;
        Ok(Self {
            id: row.try_get("id")?,
            conversation_id: row.try_get("conversation_id")?,
            sender_type,
            sender_id: row.try_get("sender_id")?,
            sender_name: row.try_get("sender_name")?,
            body: row.try_get("body")?,
            client_message_id: row.try_get("client_message_id")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatAttachment {
    pub id: String,
    pub message_id: String,
    pub original_name: String,
    pub mime: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub storage_key: String,
    pub created_at: String,
}

impl ChatAttachment {
    pub fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            message_id: row.try_get("message_id")?,
            original_name: row.try_get("original_name")?,
            mime: row.try_get("mime")?,
            size_bytes: row.try_get("size_bytes")?,
            sha256: row.try_get("sha256")?,
            storage_key: row.try_get("storage_key")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatRead {
    pub conversation_id: String,
    pub reader_type: ReaderType,
    pub reader_id: String,
    pub last_read_at: String,
}

impl ChatRead {
    pub fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        let reader_type =
            ReaderType::from_db(&row.try_get::<String, _>("reader_type")?).map_err(decode_error)?;
        Ok(Self {
            conversation_id: row.try_get("conversation_id")?,
            reader_type,
            reader_id: row.try_get("reader_id")?,
            last_read_at: row.try_get("last_read_at")?,
        })
    }
}

/// Single-row configuration for the chat window brand (F4.5-16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatBranding {
    pub id: i64,
    pub organization_name: Option<String>,
    pub support_name: String,
    pub logo_url: Option<String>,
    pub accent_color: String,
    pub welcome_text: Option<String>,
    pub info_text: Option<String>,
    pub privacy_text: Option<String>,
    pub updated_at: String,
    pub updated_by: Option<String>,
}

impl ChatBranding {
    pub fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            organization_name: row.try_get("organization_name")?,
            support_name: row.try_get("support_name")?,
            logo_url: row.try_get("logo_url")?,
            accent_color: row.try_get("accent_color")?,
            welcome_text: row.try_get("welcome_text")?,
            info_text: row.try_get("info_text")?,
            privacy_text: row.try_get("privacy_text")?,
            updated_at: row.try_get("updated_at")?,
            updated_by: row.try_get("updated_by")?,
        })
    }
}

fn decode_error(message: String) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    )))
}

/// Trims and validates a device ID. Internal whitespace and control characters are rejected.
pub fn validate_device_id(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("El ID del dispositivo es obligatorio.".to_string());
    }
    if value.chars().count() > MAX_DEVICE_ID_LEN {
        return Err(format!(
            "El ID del dispositivo no puede exceder {MAX_DEVICE_ID_LEN} caracteres."
        ));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("El ID del dispositivo no puede contener espacios.".to_string());
    }
    Ok(value.to_string())
}

/// Trims and validates a contact first/last name (1..=64 chars, no control characters).
pub fn validate_contact_name(raw: &str, label: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!("{label} es obligatorio."));
    }
    if value.chars().count() > MAX_CONTACT_NAME_LEN {
        return Err(format!(
            "{label} no puede exceder {MAX_CONTACT_NAME_LEN} caracteres."
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} contiene caracteres no válidos."));
    }
    Ok(value.to_string())
}

/// Validates a chat message body (1..=4000 chars, newline/tab allowed, no other controls).
pub fn validate_message_body(raw: &str) -> Result<String, String> {
    if raw.trim().is_empty() {
        return Err("El mensaje no puede estar vacío.".to_string());
    }
    if raw.chars().count() > MAX_MESSAGE_BODY_LEN {
        return Err(format!(
            "El mensaje no puede exceder {MAX_MESSAGE_BODY_LEN} caracteres."
        ));
    }
    if raw
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err("El mensaje contiene caracteres no válidos.".to_string());
    }
    Ok(raw.to_string())
}

/// Trims an optional short text field; an empty value becomes `None`.
pub fn validate_optional_text(
    raw: Option<&str>,
    label: &str,
    max_len: usize,
) -> Result<Option<String>, String> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > max_len {
        return Err(format!("{label} no puede exceder {max_len} caracteres."));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} contiene caracteres no válidos."));
    }
    Ok(Some(value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_status_round_trips() {
        for status in [
            ConversationStatus::Waiting,
            ConversationStatus::Assigned,
            ConversationStatus::Active,
            ConversationStatus::Closed,
        ] {
            assert_eq!(
                ConversationStatus::from_db(status.as_str()).unwrap(),
                status
            );
        }
        assert!(ConversationStatus::Waiting.is_open());
        assert!(!ConversationStatus::Closed.is_open());
        assert!(ConversationStatus::from_db("bogus").is_err());
    }

    #[test]
    fn sender_and_reader_types_round_trip() {
        for sender in [
            SenderType::Client,
            SenderType::Technician,
            SenderType::System,
        ] {
            assert_eq!(SenderType::from_db(sender.as_str()).unwrap(), sender);
        }
        for reader in [ReaderType::Device, ReaderType::User] {
            assert_eq!(ReaderType::from_db(reader.as_str()).unwrap(), reader);
        }
        assert!(SenderType::from_db("other").is_err());
    }

    #[test]
    fn device_id_validation() {
        assert_eq!(validate_device_id(" 123456789 ").unwrap(), "123456789");
        assert!(validate_device_id("").is_err());
        assert!(validate_device_id("   ").is_err());
        assert!(validate_device_id("12 34").is_err());
        assert!(validate_device_id(&"a".repeat(MAX_DEVICE_ID_LEN + 1)).is_err());
    }

    #[test]
    fn contact_name_validation() {
        assert_eq!(
            validate_contact_name("  Ana  ", "El nombre").unwrap(),
            "Ana"
        );
        assert!(validate_contact_name("", "El nombre").is_err());
        assert!(validate_contact_name("   ", "El apellido").is_err());
        assert!(validate_contact_name(&"a".repeat(MAX_CONTACT_NAME_LEN + 1), "El nombre").is_err());
        assert!(validate_contact_name("Ana\u{0}", "El nombre").is_err());
        assert!(validate_contact_name("María José", "El nombre").is_ok());
    }

    #[test]
    fn message_body_validation() {
        assert_eq!(
            validate_message_body("Hola\nsegunda línea").unwrap(),
            "Hola\nsegunda línea"
        );
        assert!(validate_message_body("").is_err());
        assert!(validate_message_body("   ").is_err());
        assert!(validate_message_body(&"a".repeat(MAX_MESSAGE_BODY_LEN + 1)).is_err());
        assert!(validate_message_body("Hola\u{0}").is_err());
        assert!(validate_message_body(&"a".repeat(MAX_MESSAGE_BODY_LEN)).is_ok());
    }

    #[test]
    fn optional_text_validation() {
        assert_eq!(
            validate_optional_text(Some("  PC-01  "), "El nombre", 128).unwrap(),
            Some("PC-01".to_string())
        );
        assert_eq!(
            validate_optional_text(Some("   "), "El nombre", 128).unwrap(),
            None
        );
        assert_eq!(
            validate_optional_text(None, "El nombre", 128).unwrap(),
            None
        );
        assert!(validate_optional_text(Some(&"a".repeat(129)), "El nombre", 128).is_err());
    }

    #[test]
    fn contact_name_concatenates_available_parts() {
        let mut conversation = ChatConversation {
            id: "c".into(),
            device_id: "d".into(),
            device_name: Some("PC".into()),
            device_hostname: None,
            device_os: None,
            installer_id: None,
            status: ConversationStatus::Waiting,
            assigned_user_id: None,
            contact_first_name: Some("Ana".into()),
            contact_last_name: Some("Pérez".into()),
            created_at: "now".into(),
            updated_at: "now".into(),
            last_message_at: None,
            closed_at: None,
            closed_by: None,
        };
        assert_eq!(conversation.contact_name().as_deref(), Some("Ana Pérez"));
        conversation.contact_last_name = None;
        assert_eq!(conversation.contact_name().as_deref(), Some("Ana"));
        conversation.contact_first_name = None;
        assert_eq!(conversation.contact_name(), None);
    }
}
