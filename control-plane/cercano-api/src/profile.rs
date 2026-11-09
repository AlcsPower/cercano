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

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileRole {
    Soporte,
    Tecnico,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub rendezvous_server: String,
    pub relay_server: String,
    pub api_server: String,
    pub server_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub about_text: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub allow_incoming: bool,
    pub allow_outgoing: bool,
    pub unattended_access: bool,
    pub require_approval: bool,
    #[serde(default = "default_true")]
    pub allow_file_transfer: bool,
    #[serde(default = "default_true")]
    pub allow_clipboard: bool,
    #[serde(default = "default_true")]
    pub allow_audio: bool,
    #[serde(default)]
    pub allow_terminal: bool,
    #[serde(default)]
    pub allow_port_forward: bool,
    #[serde(default = "default_true")]
    pub hide_network_settings: bool,
    #[serde(default)]
    pub enable_elevation: bool,
    #[serde(default)]
    pub unattended_elevation: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallMode {
    Installed,
    Portable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationConfig {
    pub mode: InstallMode,
    #[serde(default)]
    pub install_path: Option<String>,
    pub auto_start: bool,
    pub create_desktop_shortcut: bool,
    pub silent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct IdentificationConfig {
    #[serde(default)]
    pub device_group: Option<String>,
    #[serde(default)]
    pub default_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ExpirationConfig {
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CercanoProfile {
    pub schema_version: String,
    pub profile_id: String,
    #[serde(default)]
    pub created_at: Option<String>,
    pub role: ProfileRole,
    pub server: ServerConfig,
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    pub policy: PolicyConfig,
    pub installation: InstallationConfig,
    #[serde(default)]
    pub identification: Option<IdentificationConfig>,
    #[serde(default)]
    pub expiration: Option<ExpirationConfig>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileValidationError {
    #[error("La versión de esquema '{0}' es inválida")]
    InvalidSchemaVersion(String),
    #[error("El profile_id '{0}' no es un UUID válido")]
    InvalidProfileId(String),
    #[error("La clave pública del servidor no es válida: {0}")]
    InvalidServerPublicKey(String),
    #[error("El servidor rendezvous_server está vacío")]
    EmptyRendezvousServer,
    #[error("El servidor relay_server está vacío")]
    EmptyRelayServer,
    #[error("El servidor api_server debe iniciar con http:// o https://")]
    InvalidApiServerUrl,
    #[error("Conflicto de rol Soporte: allow_outgoing debe ser falso")]
    SoporteCannotHaveOutgoing,
    #[error("Conflicto de rol Soporte: allow_incoming debe ser verdadero")]
    SoporteMustHaveIncoming,
    #[error("Conflicto de rol Técnico: allow_outgoing debe ser verdadero")]
    TecnicoMustHaveOutgoing,
    #[error("Conflicto de rol Técnico: unattended_access no está permitido")]
    TecnicoCannotHaveUnattendedAccess,
    #[error("Conflicto de rol Técnico: unattended_elevation no está permitido")]
    TecnicoCannotHaveUnattendedElevation,
}

impl CercanoProfile {
    /// Validates the profile against the constraints defined in F3-01.
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        // 1. Schema version
        let parts: Vec<&str> = self.schema_version.split('.').collect();
        if parts.len() != 3 || !parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())) {
            return Err(ProfileValidationError::InvalidSchemaVersion(
                self.schema_version.clone(),
            ));
        }

        // 2. Profile ID must be valid UUID
        if uuid::Uuid::parse_str(&self.profile_id).is_err() {
            return Err(ProfileValidationError::InvalidProfileId(
                self.profile_id.clone(),
            ));
        }

        // 3. Server constraints
        if self.server.rendezvous_server.trim().is_empty() {
            return Err(ProfileValidationError::EmptyRendezvousServer);
        }
        if self.server.relay_server.trim().is_empty() {
            return Err(ProfileValidationError::EmptyRelayServer);
        }
        if !self.server.api_server.starts_with("http://")
            && !self.server.api_server.starts_with("https://")
        {
            return Err(ProfileValidationError::InvalidApiServerUrl);
        }

        // Server public key must be valid Ed25519 (32 bytes when decoded)
        let key_bytes = BASE64_STANDARD
            .decode(&self.server.server_public_key)
            .map_err(|e| ProfileValidationError::InvalidServerPublicKey(e.to_string()))?;
        if key_bytes.len() != 32 {
            return Err(ProfileValidationError::InvalidServerPublicKey(
                "La clave Ed25519 debe tener exactamente 32 bytes".to_string(),
            ));
        }

        // 4. Role-specific invariants (F3-01 / ADR-008)
        match self.role {
            ProfileRole::Soporte => {
                if !self.policy.allow_incoming {
                    return Err(ProfileValidationError::SoporteMustHaveIncoming);
                }
                if self.policy.allow_outgoing {
                    return Err(ProfileValidationError::SoporteCannotHaveOutgoing);
                }
            }
            ProfileRole::Tecnico => {
                if !self.policy.allow_outgoing {
                    return Err(ProfileValidationError::TecnicoMustHaveOutgoing);
                }
                if self.policy.unattended_access {
                    return Err(ProfileValidationError::TecnicoCannotHaveUnattendedAccess);
                }
                if self.policy.unattended_elevation {
                    return Err(ProfileValidationError::TecnicoCannotHaveUnattendedElevation);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_soporte_profile() {
        let json_str = include_str!("../../../docs/specs/examples/profile-soporte-valido.json");
        let profile: CercanoProfile = serde_json::from_str(json_str).expect("Valid JSON");
        assert_eq!(profile.role, ProfileRole::Soporte);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_valid_tecnico_profile() {
        let json_str = include_str!("../../../docs/specs/examples/profile-tecnico-valido.json");
        let profile: CercanoProfile = serde_json::from_str(json_str).expect("Valid JSON");
        assert_eq!(profile.role, ProfileRole::Tecnico);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_soporte_with_outgoing_capability_is_rejected() {
        let json_str = include_str!(
            "../../../docs/specs/examples/profile-soporte-invalido-capacidades-tecnico.json"
        );
        let profile: CercanoProfile = serde_json::from_str(json_str).expect("Valid JSON syntax");
        let res = profile.validate();
        assert_eq!(res, Err(ProfileValidationError::SoporteCannotHaveOutgoing));
    }

    #[test]
    fn test_unknown_fields_rejected_by_deserializer() {
        let json_str =
            include_str!("../../../docs/specs/examples/profile-invalido-campos-desconocidos.json");
        let res: Result<CercanoProfile, _> = serde_json::from_str(json_str);
        assert!(res.is_err(), "Unknown fields must be rejected");
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("unknown field `unknown_extra_property`"));
    }

    #[test]
    fn test_tecnico_with_unattended_access_is_rejected() {
        let mut profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-tecnico-valido.json"
        ))
        .unwrap();
        profile.policy.unattended_access = true;
        assert_eq!(
            profile.validate(),
            Err(ProfileValidationError::TecnicoCannotHaveUnattendedAccess)
        );
    }
}
