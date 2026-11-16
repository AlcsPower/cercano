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

//! Domain models and types for Identity, Groups, Address Book and Central Policies (F5).

use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteRow;
use sqlx::{FromRow, Row};

pub const MAX_NAME_LEN: usize = 128;
pub const MAX_DESC_LEN: usize = 512;
pub const MAX_TAGS_LEN: usize = 256;
pub const MAX_NOTES_LEN: usize = 1_024;
pub const MAX_DOC_LEN: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupKind {
    User,
    Device,
}

impl GroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "device" => Some(Self::Device),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub kind: GroupKind,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub created_by: Option<String>,
    pub updated_at: String,
    pub updated_by: Option<String>,
}

impl<'r> FromRow<'r, SqliteRow> for Group {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let kind_str: String = row.try_get("kind")?;
        let kind = GroupKind::from_str_opt(&kind_str)
            .ok_or_else(|| sqlx::Error::Decode(format!("Invalid group kind: {kind_str}").into()))?;
        Ok(Self {
            id: row.try_get("id")?,
            kind,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            created_at: row.try_get("created_at")?,
            created_by: row.try_get("created_by")?,
            updated_at: row.try_get("updated_at")?,
            updated_by: row.try_get("updated_by")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    User,
    Device,
}

impl SubjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "device" => Some(Self::Device),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMember {
    pub group_id: String,
    pub subject_type: SubjectType,
    pub subject_id: String,
    pub added_at: String,
    pub added_by: Option<String>,
}

impl<'r> FromRow<'r, SqliteRow> for GroupMember {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let type_str: String = row.try_get("subject_type")?;
        let subject_type = SubjectType::from_str_opt(&type_str).ok_or_else(|| {
            sqlx::Error::Decode(format!("Invalid subject_type: {type_str}").into())
        })?;
        Ok(Self {
            group_id: row.try_get("group_id")?,
            subject_type,
            subject_id: row.try_get("subject_id")?,
            added_at: row.try_get("added_at")?,
            added_by: row.try_get("added_by")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupPermission {
    Read,
    Operate,
}

impl GroupPermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Operate => "operate",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "operate" => Some(Self::Operate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupGrant {
    pub from_group_id: String,
    pub to_group_id: String,
    pub permission: GroupPermission,
    pub created_at: String,
    pub created_by: Option<String>,
}

impl<'r> FromRow<'r, SqliteRow> for GroupGrant {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let perm_str: String = row.try_get("permission")?;
        let permission = GroupPermission::from_str_opt(&perm_str).ok_or_else(|| {
            sqlx::Error::Decode(format!("Invalid group permission: {perm_str}").into())
        })?;
        Ok(Self {
            from_group_id: row.try_get("from_group_id")?,
            to_group_id: row.try_get("to_group_id")?,
            permission,
            created_at: row.try_get("created_at")?,
            created_by: row.try_get("created_by")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressBookEntry {
    pub id: String,
    pub name: String,
    pub device_id: Option<String>,
    pub group_id: Option<String>,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub tags: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub created_by: Option<String>,
    pub updated_at: String,
    pub updated_by: Option<String>,
}

impl<'r> FromRow<'r, SqliteRow> for AddressBookEntry {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            device_id: row.try_get("device_id")?,
            group_id: row.try_get("group_id")?,
            host: row.try_get("host")?,
            port: row.try_get("port")?,
            tags: row.try_get("tags")?,
            notes: row.try_get("notes")?,
            created_at: row.try_get("created_at")?,
            created_by: row.try_get("created_by")?,
            updated_at: row.try_get("updated_at")?,
            updated_by: row.try_get("updated_by")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyScopeType {
    Global,
    Group,
    Device,
}

impl PolicyScopeType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Group => "group",
            Self::Device => "device",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "global" => Some(Self::Global),
            "group" => Some(Self::Group),
            "device" => Some(Self::Device),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyState {
    Draft,
    Active,
    Superseded,
    Revoked,
}

impl PolicyState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "active" => Some(Self::Active),
            "superseded" => Some(Self::Superseded),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub scope_type: PolicyScopeType,
    pub scope_id: String,
    pub version: i64,
    pub document: String,
    pub document_sha256: String,
    pub state: PolicyState,
    pub effective_from: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub created_by: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_by: Option<String>,
}

impl<'r> FromRow<'r, SqliteRow> for Policy {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let scope_str: String = row.try_get("scope_type")?;
        let scope_type = PolicyScopeType::from_str_opt(&scope_str).ok_or_else(|| {
            sqlx::Error::Decode(format!("Invalid scope_type: {scope_str}").into())
        })?;

        let state_str: String = row.try_get("state")?;
        let state = PolicyState::from_str_opt(&state_str).ok_or_else(|| {
            sqlx::Error::Decode(format!("Invalid policy state: {state_str}").into())
        })?;

        Ok(Self {
            id: row.try_get("id")?,
            scope_type,
            scope_id: row.try_get("scope_id")?,
            version: row.try_get("version")?,
            document: row.try_get("document")?,
            document_sha256: row.try_get("document_sha256")?,
            state,
            effective_from: row.try_get("effective_from")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
            created_by: row.try_get("created_by")?,
            revoked_at: row.try_get("revoked_at")?,
            revoked_by: row.try_get("revoked_by")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdpKind {
    Oidc,
    Ldap,
}

impl IdpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Ldap => "ldap",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "oidc" => Some(Self::Oidc),
            "ldap" => Some(Self::Ldap),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityProvider {
    pub id: String,
    pub kind: IdpKind,
    pub name: String,
    pub config: String,
    pub secret_ref: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub created_by: Option<String>,
    pub updated_at: String,
    pub updated_by: Option<String>,
}

impl<'r> FromRow<'r, SqliteRow> for IdentityProvider {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let kind_str: String = row.try_get("kind")?;
        let kind = IdpKind::from_str_opt(&kind_str)
            .ok_or_else(|| sqlx::Error::Decode(format!("Invalid idp kind: {kind_str}").into()))?;
        let enabled_int: i64 = row.try_get("enabled")?;
        Ok(Self {
            id: row.try_get("id")?,
            kind,
            name: row.try_get("name")?,
            config: row.try_get("config")?,
            secret_ref: row.try_get("secret_ref")?,
            enabled: enabled_int == 1,
            created_at: row.try_get("created_at")?,
            created_by: row.try_get("created_by")?,
            updated_at: row.try_get("updated_at")?,
            updated_by: row.try_get("updated_by")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederatedIdentity {
    pub id: String,
    pub provider_id: String,
    pub subject: String,
    pub user_id: String,
    pub created_at: String,
    pub last_login_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl<'r> FromRow<'r, SqliteRow> for FederatedIdentity {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            provider_id: row.try_get("provider_id")?,
            subject: row.try_get("subject")?,
            user_id: row.try_get("user_id")?,
            created_at: row.try_get("created_at")?,
            last_login_at: row.try_get("last_login_at")?,
            revoked_at: row.try_get("revoked_at")?,
        })
    }
}

pub fn validate_group_name(name: &str) -> Result<(), &'static str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("El nombre de grupo no puede estar vacío");
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err("El nombre de grupo excede la longitud máxima (128 caracteres)");
    }
    Ok(())
}

pub fn validate_address_book_name(name: &str) -> Result<(), &'static str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("El nombre de la entrada no puede estar vacío");
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err("El nombre de la entrada excede la longitud máxima (128 caracteres)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_kind_round_trip() {
        assert_eq!(GroupKind::from_str_opt("user"), Some(GroupKind::User));
        assert_eq!(GroupKind::from_str_opt("device"), Some(GroupKind::Device));
        assert_eq!(GroupKind::from_str_opt("unknown"), None);
        assert_eq!(GroupKind::User.as_str(), "user");
        assert_eq!(GroupKind::Device.as_str(), "device");
    }

    #[test]
    fn test_subject_type_round_trip() {
        assert_eq!(SubjectType::from_str_opt("user"), Some(SubjectType::User));
        assert_eq!(
            SubjectType::from_str_opt("device"),
            Some(SubjectType::Device)
        );
        assert_eq!(SubjectType::from_str_opt("admin"), None);
        assert_eq!(SubjectType::User.as_str(), "user");
        assert_eq!(SubjectType::Device.as_str(), "device");
    }

    #[test]
    fn test_group_permission_round_trip() {
        assert_eq!(
            GroupPermission::from_str_opt("read"),
            Some(GroupPermission::Read)
        );
        assert_eq!(
            GroupPermission::from_str_opt("operate"),
            Some(GroupPermission::Operate)
        );
        assert_eq!(GroupPermission::from_str_opt("write"), None);
        assert_eq!(GroupPermission::Read.as_str(), "read");
        assert_eq!(GroupPermission::Operate.as_str(), "operate");
    }

    #[test]
    fn test_policy_scope_and_state_round_trip() {
        assert_eq!(
            PolicyScopeType::from_str_opt("global"),
            Some(PolicyScopeType::Global)
        );
        assert_eq!(
            PolicyScopeType::from_str_opt("group"),
            Some(PolicyScopeType::Group)
        );
        assert_eq!(
            PolicyScopeType::from_str_opt("device"),
            Some(PolicyScopeType::Device)
        );
        assert_eq!(PolicyScopeType::from_str_opt("user"), None);

        assert_eq!(PolicyState::from_str_opt("draft"), Some(PolicyState::Draft));
        assert_eq!(
            PolicyState::from_str_opt("active"),
            Some(PolicyState::Active)
        );
        assert_eq!(
            PolicyState::from_str_opt("superseded"),
            Some(PolicyState::Superseded)
        );
        assert_eq!(
            PolicyState::from_str_opt("revoked"),
            Some(PolicyState::Revoked)
        );
        assert_eq!(PolicyState::from_str_opt("invalid"), None);
    }

    #[test]
    fn test_idp_kind_round_trip() {
        assert_eq!(IdpKind::from_str_opt("oidc"), Some(IdpKind::Oidc));
        assert_eq!(IdpKind::from_str_opt("ldap"), Some(IdpKind::Ldap));
        assert_eq!(IdpKind::from_str_opt("saml"), None);
    }

    #[test]
    fn test_validations() {
        assert!(validate_group_name("Soporte Nivel 1").is_ok());
        assert!(validate_group_name("").is_err());
        assert!(validate_group_name(&"a".repeat(129)).is_err());

        assert!(validate_address_book_name("Servidor Core").is_ok());
        assert!(validate_address_book_name("   ").is_err());
        assert!(validate_address_book_name(&"b".repeat(129)).is_err());
    }
}
