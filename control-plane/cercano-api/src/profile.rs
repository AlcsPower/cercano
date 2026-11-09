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

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ed25519_dalek::Signer;
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

/// Serializa el perfil en un `serde_json::Value` sanitizado para registrar en auditoría,
/// garantizando que no expone claves privadas ni secretos.
pub fn sanitize_profile(profile: &CercanoProfile) -> serde_json::Value {
    serde_json::to_value(profile).unwrap_or(serde_json::json!({}))
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileVerificationError {
    #[error("Error de deserialización del sobre de perfil firmado: {0}")]
    EnvelopeDeserialization(String),
    #[error("Algoritmo de firma no soportado: '{0}', se espera 'ed25519'")]
    UnsupportedAlgorithm(String),
    #[error("Firma faltante o vacía")]
    MissingSignature,
    #[error("Formato o longitud inválida de firma Ed25519: {0}")]
    InvalidSignatureFormat(String),
    #[error("Firma Ed25519 inválida: el perfil fue alterado o firmado con otra clave")]
    InvalidSignature,
    #[error("El perfil ha caducado: fecha límite {expires_at}, hora de referencia {now}")]
    ProfileExpired { expires_at: String, now: String },
    #[error("Error de validación del perfil: {0}")]
    ValidationError(#[from] ProfileValidationError),
    #[error("Error de canonicalización JSON: {0}")]
    CanonicalizationError(String),
}

fn default_algorithm() -> String {
    "ed25519".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedCercanoProfile {
    pub profile: CercanoProfile,
    pub signature: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub key_id: Option<String>,
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

    /// Computes canonical JSON bytes for deterministic Ed25519 signing.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProfileVerificationError> {
        let val = serde_json::to_value(self)
            .map_err(|e| ProfileVerificationError::CanonicalizationError(e.to_string()))?;
        audit_core::canonical::to_canonical_json_bytes(&val)
            .map_err(|e| ProfileVerificationError::CanonicalizationError(e.to_string()))
    }

    /// Signs the profile with an Ed25519 signing key, producing a SignedCercanoProfile envelope.
    pub fn sign(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        key_id: Option<String>,
    ) -> Result<SignedCercanoProfile, ProfileVerificationError> {
        self.validate()?;
        let canonical_bytes = self.to_canonical_bytes()?;
        let sig = signing_key.sign(&canonical_bytes);
        Ok(SignedCercanoProfile {
            profile: self.clone(),
            signature: BASE64_STANDARD.encode(sig.to_bytes()),
            algorithm: default_algorithm(),
            key_id,
        })
    }

    /// Converts the validated profile into the client settings map.
    pub fn to_client_settings_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert(
            "custom-rendezvous-server".to_string(),
            self.server.rendezvous_server.clone(),
        );
        map.insert("relay-server".to_string(), self.server.relay_server.clone());
        map.insert("api-server".to_string(), self.server.api_server.clone());
        map.insert("key".to_string(), self.server.server_public_key.clone());
        map.insert(
            "role".to_string(),
            match self.role {
                ProfileRole::Soporte => "soporte".to_string(),
                ProfileRole::Tecnico => "tecnico".to_string(),
            },
        );
        if let Some(id) = &self.identity {
            if let Some(name) = &id.app_name {
                map.insert("app-name".to_string(), name.clone());
            }
        }
        map.insert(
            "allow-incoming".to_string(),
            self.policy.allow_incoming.to_string(),
        );
        map.insert(
            "allow-outgoing".to_string(),
            self.policy.allow_outgoing.to_string(),
        );
        map.insert(
            "allow-file-transfer".to_string(),
            self.policy.allow_file_transfer.to_string(),
        );
        map.insert(
            "allow-clipboard".to_string(),
            self.policy.allow_clipboard.to_string(),
        );
        map.insert(
            "allow-audio".to_string(),
            self.policy.allow_audio.to_string(),
        );
        map.insert(
            "unattended-access".to_string(),
            self.policy.unattended_access.to_string(),
        );
        map.insert(
            "hide-network-settings".to_string(),
            self.policy.hide_network_settings.to_string(),
        );
        map
    }
}

impl SignedCercanoProfile {
    /// Verifies the cryptographic signature, expiration, and invariants of the signed profile.
    pub fn verify(
        &self,
        verifying_key: &ed25519_dalek::VerifyingKey,
        now: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), ProfileVerificationError> {
        // 1. Algorithm check
        if self.algorithm != "ed25519" {
            return Err(ProfileVerificationError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }

        // 2. Signature presence
        if self.signature.trim().is_empty() {
            return Err(ProfileVerificationError::MissingSignature);
        }

        // 3. Signature decode
        let sig_bytes = BASE64_STANDARD
            .decode(self.signature.trim())
            .map_err(|e| ProfileVerificationError::InvalidSignatureFormat(e.to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(ProfileVerificationError::InvalidSignatureFormat(
                "La firma Ed25519 debe tener exactamente 64 bytes".to_string(),
            ));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        // 4. Validate profile internal rules & role invariants
        self.profile.validate()?;

        // 5. Expiration check (TC-F3-003, TC-F3-008)
        if let Some(exp) = &self.profile.expiration {
            if let Some(expires_at_str) = &exp.expires_at {
                if let Ok(exp_time) = chrono::DateTime::parse_from_rfc3339(expires_at_str) {
                    let current_time = now.unwrap_or_else(chrono::Utc::now);
                    if current_time > exp_time {
                        return Err(ProfileVerificationError::ProfileExpired {
                            expires_at: expires_at_str.clone(),
                            now: current_time.to_rfc3339(),
                        });
                    }
                }
            }
        }

        // 6. Signature cryptographic verification against canonical bytes (TC-F3-002, TC-F3-004, TC-F3-062)
        let canonical_bytes = self.profile.to_canonical_bytes()?;
        verifying_key
            .verify_strict(&canonical_bytes, &signature)
            .map_err(|_| ProfileVerificationError::InvalidSignature)?;

        Ok(())
    }

    /// Deserializes a SignedCercanoProfile from a JSON string, enforcing deny_unknown_fields.
    pub fn from_json_str(s: &str) -> Result<Self, ProfileVerificationError> {
        serde_json::from_str(s)
            .map_err(|e| ProfileVerificationError::EnvelopeDeserialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_keys() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

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

    // --- Tests específicos de aceptación F3-02 (TC-F3-001..008 y TC-F3-062) ---

    #[test]
    fn test_tc_f3_001_valid_profile_and_applied_settings() {
        let (signing_key, verifying_key) = generate_test_keys();
        let profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-soporte-valido.json"
        ))
        .unwrap();

        let signed = profile
            .sign(&signing_key, Some("builder-v1".to_string()))
            .expect("Signing must succeed");
        assert!(signed.verify(&verifying_key, None).is_ok());

        let settings = signed.profile.to_client_settings_map();
        assert_eq!(settings["custom-rendezvous-server"], "cercano.lan:21116");
        assert_eq!(settings["relay-server"], "relay.lan:21117");
        assert_eq!(settings["api-server"], "https://cercano.lan:21114");
        assert_eq!(settings["role"], "soporte");
        assert_eq!(settings["allow-incoming"], "true");
        assert_eq!(settings["allow-outgoing"], "false");
    }

    #[test]
    fn test_tc_f3_002_single_byte_tamper_rejected() {
        let (signing_key, verifying_key) = generate_test_keys();
        let profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-soporte-valido.json"
        ))
        .unwrap();

        let mut signed = profile.sign(&signing_key, None).unwrap();

        // 1. Modificar un byte en el host
        signed.profile.server.rendezvous_server = "dercano.lan:21116".to_string();
        assert_eq!(
            signed.verify(&verifying_key, None),
            Err(ProfileVerificationError::InvalidSignature)
        );

        // 2. Modificar un byte en la firma base64
        let mut corrupted_sig = signed.signature.clone();
        let first_char = corrupted_sig.chars().next().unwrap();
        let replacement_char = if first_char == 'A' { 'B' } else { 'A' };
        corrupted_sig.replace_range(0..1, &replacement_char.to_string());
        signed.signature = corrupted_sig;
        assert_eq!(
            signed.verify(&verifying_key, None),
            Err(ProfileVerificationError::InvalidSignature)
        );
    }

    #[test]
    fn test_tc_f3_003_expired_profile_rejected() {
        let (signing_key, verifying_key) = generate_test_keys();
        let mut profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-soporte-valido.json"
        ))
        .unwrap();

        profile.expiration = Some(ExpirationConfig {
            expires_at: Some("2026-01-01T00:00:00Z".to_string()),
            max_uses: None,
        });

        let signed = profile.sign(&signing_key, None).unwrap();
        // Verificar con fecha posterior (noviembre 2026)
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-09T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let err = signed.verify(&verifying_key, Some(now)).unwrap_err();
        match err {
            ProfileVerificationError::ProfileExpired { expires_at, .. } => {
                assert_eq!(expires_at, "2026-01-01T00:00:00Z");
            }
            other => panic!("Expected ProfileExpired, got {:?}", other),
        }
    }

    #[test]
    fn test_tc_f3_004_wrong_key_signature_rejected() {
        let (signing_key_a, _) = generate_test_keys();
        let signing_key_b = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        let verifying_key_b = signing_key_b.verifying_key();

        let profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-soporte-valido.json"
        ))
        .unwrap();

        let signed_with_a = profile.sign(&signing_key_a, None).unwrap();
        assert_eq!(
            signed_with_a.verify(&verifying_key_b, None),
            Err(ProfileVerificationError::InvalidSignature)
        );
    }

    #[test]
    fn test_tc_f3_005_invalid_schema_profile_rejected() {
        let (signing_key, verifying_key) = generate_test_keys();
        let mut profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-soporte-valido.json"
        ))
        .unwrap();

        // Soporte intentando habilitar conexiones salientes
        profile.policy.allow_outgoing = true;

        // Intentar firmar un perfil inválido debe fallar en validación
        let sign_res = profile.sign(&signing_key, None);
        assert_eq!(
            sign_res,
            Err(ProfileVerificationError::ValidationError(
                ProfileValidationError::SoporteCannotHaveOutgoing
            ))
        );

        // Si se construye el envelope manualmente, verify debe rechazarlo antes de verificar firma
        let envelope = SignedCercanoProfile {
            profile,
            signature: BASE64_STANDARD.encode([0u8; 64]),
            algorithm: "ed25519".to_string(),
            key_id: None,
        };
        assert_eq!(
            envelope.verify(&verifying_key, None),
            Err(ProfileVerificationError::ValidationError(
                ProfileValidationError::SoporteCannotHaveOutgoing
            ))
        );
    }

    #[test]
    fn test_tc_f3_006_missing_signature_rejected() {
        let (_, verifying_key) = generate_test_keys();
        let profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-soporte-valido.json"
        ))
        .unwrap();

        let envelope = SignedCercanoProfile {
            profile,
            signature: "".to_string(),
            algorithm: "ed25519".to_string(),
            key_id: None,
        };

        assert_eq!(
            envelope.verify(&verifying_key, None),
            Err(ProfileVerificationError::MissingSignature)
        );
    }

    #[test]
    fn test_tc_f3_007_unknown_fields_in_signed_envelope_rejected() {
        let raw_json = r#"{
            "profile": {
                "schema_version": "1.0.0",
                "profile_id": "a0000000-0000-0000-0000-000000000001",
                "role": "soporte",
                "server": {
                    "rendezvous_server": "cercano.lan:21116",
                    "relay_server": "relay.lan:21117",
                    "api_server": "https://cercano.lan:21114",
                    "server_public_key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
                },
                "policy": {
                    "allow_incoming": true,
                    "allow_outgoing": false,
                    "unattended_access": false,
                    "require_approval": true
                },
                "installation": {
                    "mode": "installed",
                    "auto_start": true,
                    "create_desktop_shortcut": true,
                    "silent": false
                }
            },
            "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "algorithm": "ed25519",
            "malicious_extra_field": 12345
        }"#;

        let res = SignedCercanoProfile::from_json_str(raw_json);
        assert!(res.is_err(), "Unknown fields in envelope must be rejected");
        match res.unwrap_err() {
            ProfileVerificationError::EnvelopeDeserialization(msg) => {
                assert!(msg.contains("unknown field `malicious_extra_field`"));
            }
            other => panic!("Expected EnvelopeDeserialization, got {:?}", other),
        }
    }

    #[test]
    fn test_tc_f3_008_clock_skew_and_expiration_boundary() {
        let (signing_key, verifying_key) = generate_test_keys();
        let mut profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-tecnico-valido.json"
        ))
        .unwrap();

        profile.expiration = Some(ExpirationConfig {
            expires_at: Some("2026-12-31T23:59:59Z".to_string()),
            max_uses: None,
        });

        let signed = profile.sign(&signing_key, None).unwrap();

        // 1 segundo antes de expirar: VÁLIDO
        let just_before = chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:58Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(signed.verify(&verifying_key, Some(just_before)).is_ok());

        // 1 segundo después de expirar: RECHAZADO
        let just_after = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(signed.verify(&verifying_key, Some(just_after)).is_err());
    }

    #[test]
    fn test_tc_f3_062_tampered_role_without_resign_rejected() {
        let (signing_key, verifying_key) = generate_test_keys();
        let profile: CercanoProfile = serde_json::from_str(include_str!(
            "../../../docs/specs/examples/profile-soporte-valido.json"
        ))
        .unwrap();

        let mut signed = profile.sign(&signing_key, None).unwrap();

        // Atacante modifica el rol en el JSON de soporte a tecnico
        signed.profile.role = ProfileRole::Tecnico;
        // Modifica además policy para que sea sintácticamente válido para tecnico
        signed.profile.policy.allow_outgoing = true;

        // La firma ya no corresponde al perfil alterado
        let res = signed.verify(&verifying_key, None);
        assert_eq!(res, Err(ProfileVerificationError::InvalidSignature));
    }
}
