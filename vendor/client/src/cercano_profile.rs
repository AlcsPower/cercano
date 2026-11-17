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

use hbb_common::{
    anyhow::{anyhow, Context},
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    config, log,
    sodiumoxide::crypto::sign::{verify_detached, PublicKey, Signature},
    ResultType,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub const DEFAULT_PROFILE_FILENAME: &str = "cercano-profile.signed.json";

// Clave pública de compilación para verificación de perfil (32 bytes Ed25519)
// Por defecto clave de desarrollo/laboratorio; sobreescribible en compilación via CERCANO_PROFILE_PUBLIC_KEY
pub const DEFAULT_PROFILE_PUBLIC_KEY_BASE64: &str =
    "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";

lazy_static::lazy_static! {
    pub static ref ACTIVE_PROFILE: RwLock<Option<VerifiedProfileInfo>> = RwLock::new(None);
    pub static ref TECHNICIAN_SESSION: RwLock<Option<TechnicianSession>> = RwLock::new(None);
    pub static ref PENDING_ELEVATION_REQUEST: RwLock<Option<ElevationRequestNotification>> = RwLock::new(None);
    pub static ref ELEVATION_TRACKER: RwLock<ElevationSessionTracker> = RwLock::new(ElevationSessionTracker::new());
    pub static ref CACHED_POLICY: RwLock<Option<CachedEffectivePolicy>> = RwLock::new(None);
    pub static ref POLICY_OFFLINE_FAIL_CLOSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
}

pub const MAX_FAILED_ELEVATION_ATTEMPTS: u32 = 3;
pub const ELEVATION_CONSENT_TIMEOUT_SECS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveElevationConsent {
    pub request_id: String,
    pub response: ElevationConsentResponse,
    pub granted_at_epoch_secs: i64,
    pub consumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevationSessionTracker {
    failed_attempts: u32,
    is_locked_out: bool,
    active_consent: Option<ActiveElevationConsent>,
}

impl ElevationSessionTracker {
    pub fn new() -> Self {
        Self {
            failed_attempts: 0,
            is_locked_out: false,
            active_consent: None,
        }
    }

    pub fn is_locked_out(&self) -> bool {
        self.is_locked_out
    }

    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    pub fn remaining_attempts(&self) -> u32 {
        MAX_FAILED_ELEVATION_ATTEMPTS.saturating_sub(self.failed_attempts)
    }

    pub fn record_failure(&mut self) -> bool {
        self.failed_attempts += 1;
        if self.failed_attempts >= MAX_FAILED_ELEVATION_ATTEMPTS {
            self.is_locked_out = true;
            self.active_consent = None;
            true
        } else {
            false
        }
    }

    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
    }

    pub fn record_consent(
        &mut self,
        request_id: String,
        response: ElevationConsentResponse,
        now_epoch: i64,
    ) {
        self.active_consent = Some(ActiveElevationConsent {
            request_id,
            response,
            granted_at_epoch_secs: now_epoch,
            consumed: false,
        });
    }

    pub fn has_valid_consent(&self, request_id: &str, now_epoch: i64) -> bool {
        if self.is_locked_out {
            return false;
        }
        if let Some(consent) = &self.active_consent {
            if consent.request_id == request_id
                && consent.response == ElevationConsentResponse::Approved
                && !consent.consumed
                && (now_epoch - consent.granted_at_epoch_secs) <= ELEVATION_CONSENT_TIMEOUT_SECS
            {
                return true;
            }
        }
        false
    }

    pub fn consume_consent(&mut self, request_id: &str, now_epoch: i64) -> ResultType<()> {
        if self.is_locked_out {
            return Err(anyhow!(
                "Máximo de 3 intentos fallidos alcanzado. Sesión bloqueada para elevación."
            ));
        }
        match &mut self.active_consent {
            Some(consent) => {
                if consent.request_id != request_id {
                    return Err(anyhow!("Identificador de solicitud de elevación no coincide"));
                }
                if consent.response == ElevationConsentResponse::Denied {
                    return Err(anyhow!(
                        "Consentimiento de usuario requerido: la elevación fue rechazada"
                    ));
                }
                if consent.consumed {
                    return Err(anyhow!(
                        "La elevación ya fue utilizada (mínimo privilegio: un solo uso permitido)"
                    ));
                }
                if (now_epoch - consent.granted_at_epoch_secs) > ELEVATION_CONSENT_TIMEOUT_SECS {
                    return Err(anyhow!("La solicitud de elevación ha caducado (> 60 s)"));
                }
                consent.consumed = true;
                Ok(())
            }
            None => Err(anyhow!(
                "Consentimiento de usuario requerido: no hay consentimiento registrado"
            )),
        }
    }

    pub fn reset(&mut self) {
        self.failed_attempts = 0;
        self.is_locked_out = false;
        self.active_consent = None;
    }
}

pub struct SecureElevationCredential {
    pub username: String,
    pub domain: Option<String>,
    password: Vec<u8>,
}

impl SecureElevationCredential {
    pub fn new(account: impl Into<String>, password: impl AsRef<[u8]>) -> Self {
        let raw_account = account.into();
        let (username, domain) = Self::parse_account(&raw_account);
        Self {
            username,
            domain,
            password: password.as_ref().to_vec(),
        }
    }

    pub fn parse_account(account: &str) -> (String, Option<String>) {
        let trimmed = account.trim();
        if let Some(pos) = trimmed.find('\\') {
            let domain = &trimmed[..pos];
            let user = &trimmed[pos + 1..];
            (user.to_string(), Some(domain.to_string()))
        } else if let Some(pos) = trimmed.find('@') {
            let user = &trimmed[..pos];
            let domain = &trimmed[pos + 1..];
            (user.to_string(), Some(domain.to_string()))
        } else {
            (trimmed.to_string(), None)
        }
    }

    pub fn password_bytes(&self) -> &[u8] {
        &self.password
    }

    pub fn password_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.password)
    }

    pub fn is_zeroized(&self) -> bool {
        self.password.is_empty() || self.password.iter().all(|&b| b == 0)
    }

    pub fn zeroize(&mut self) {
        for b in self.password.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        self.password.clear();
    }
}

impl Drop for SecureElevationCredential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for SecureElevationCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureElevationCredential")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Display for SecureElevationCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SecureElevationCredential({}{})",
            self.domain
                .as_deref()
                .map(|d| format!("{}\\", d))
                .unwrap_or_default(),
            self.username
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TechnicianSession {
    pub token: String,
    pub username: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElevationRequestNotification {
    pub request_id: String,
    pub requester_name: String,
    pub reason: String,
    pub ticket: Option<String>,
    pub timestamp_rfc3339: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ElevationConsentResponse {
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedProfileInfo {
    pub profile_id: String,
    pub role: String,
    pub rendezvous_server: String,
    pub relay_server: String,
    pub api_server: String,
    pub allow_outgoing: bool,
    pub allow_incoming: bool,
    pub unattended_access: bool,
    pub allow_file_transfer: bool,
    pub allow_clipboard: bool,
    pub allow_audio: bool,
    pub hide_network_settings: bool,
    pub chat_enabled: bool,
    pub chat_allow_attachments: bool,
    pub chat_allow_remote_escalation: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEnvelope {
    profile: Value,
    signature: String,
    #[serde(default = "default_algorithm")]
    algorithm: String,
    #[serde(default)]
    _key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDto {
    schema_version: String,
    profile_id: String,
    #[serde(default)]
    _created_at: Option<String>,
    role: String,
    server: ServerDto,
    #[serde(default)]
    identity: Option<IdentityDto>,
    policy: PolicyDto,
    _installation: InstallationDto,
    #[serde(default)]
    _identification: Option<IdentificationDto>,
    #[serde(default)]
    expiration: Option<ExpirationDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerDto {
    rendezvous_server: String,
    relay_server: String,
    api_server: String,
    server_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDto {
    #[serde(default)]
    app_name: Option<String>,
    #[serde(default)]
    _about_text: Option<String>,
    #[serde(default)]
    _icon: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDto {
    allow_incoming: bool,
    allow_outgoing: bool,
    unattended_access: bool,
    _require_approval: bool,
    #[serde(default = "default_true")]
    allow_file_transfer: bool,
    #[serde(default = "default_true")]
    allow_clipboard: bool,
    #[serde(default = "default_true")]
    allow_audio: bool,
    #[serde(default)]
    _allow_terminal: bool,
    #[serde(default)]
    _allow_port_forward: bool,
    #[serde(default = "default_true")]
    hide_network_settings: bool,
    #[serde(default)]
    _enable_elevation: bool,
    #[serde(default)]
    _unattended_elevation: bool,
    #[serde(default)]
    chat: Option<ChatPolicyDto>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatPolicyDto {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default = "default_true")]
    pub allow_attachments: bool,
    #[serde(default = "default_true")]
    pub allow_remote_escalation: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationDto {
    _mode: String,
    #[serde(default)]
    _install_path: Option<String>,
    _auto_start: bool,
    _create_desktop_shortcut: bool,
    _silent: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentificationDto {
    #[serde(default)]
    _device_group: Option<String>,
    #[serde(default)]
    _default_owner: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpirationDto {
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    _max_uses: Option<u32>,
}

fn default_algorithm() -> String {
    "ed25519".to_string()
}

pub fn get_trusted_verification_key() -> [u8; 32] {
    if let Some(env_key) = std::option_env!("CERCANO_PROFILE_PUBLIC_KEY") {
        if let Ok(decoded) = BASE64.decode(env_key.trim()) {
            if decoded.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded);
                return arr;
            }
        }
    }
    let decoded = BASE64
        .decode(DEFAULT_PROFILE_PUBLIC_KEY_BASE64)
        .expect("Valid default public key base64");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    arr
}

pub fn locate_profile_path() -> Option<PathBuf> {
    if let Ok(path_str) = std::env::var("CERCANO_PROFILE_PATH") {
        let p = PathBuf::from(path_str);
        if p.is_file() {
            return Some(p);
        }
    }

    if let Some(exe_dir) =
        std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf()))
    {
        let p = exe_dir.join(DEFAULT_PROFILE_FILENAME);
        if p.is_file() {
            return Some(p);
        }
    }

    let local = Path::new(DEFAULT_PROFILE_FILENAME);
    if local.is_file() {
        return Some(local.to_path_buf());
    }

    None
}

pub fn canonical_json_bytes(val: &Value) -> ResultType<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical(val, &mut out)?;
    Ok(out)
}

fn write_canonical(val: &Value, out: &mut Vec<u8>) -> ResultType<()> {
    match val {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            let escaped = serde_json::to_string(s)?;
            out.extend_from_slice(escaped.as_bytes());
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(elem, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let escaped_key = serde_json::to_string(k)?;
                out.extend_from_slice(escaped_key.as_bytes());
                out.push(b':');
                write_canonical(&map[*k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

pub fn verify_signed_profile_bytes(
    envelope_bytes: &[u8],
    trusted_public_key_bytes: &[u8; 32],
    now_rfc3339: Option<&str>,
) -> ResultType<(VerifiedProfileInfo, String, Option<String>)> {
    let envelope: SignedEnvelope = serde_json::from_slice(envelope_bytes)
        .context("invalid signed profile envelope JSON or unknown fields")?;

    if envelope.algorithm != "ed25519" {
        return Err(anyhow!(
            "unsupported signature algorithm: {}",
            envelope.algorithm
        ));
    }
    if envelope.signature.trim().is_empty() {
        return Err(anyhow!("missing profile signature"));
    }

    let sig_raw = BASE64
        .decode(envelope.signature.trim())
        .context("invalid signature base64")?;
    if sig_raw.len() != 64 {
        return Err(anyhow!("signature must be 64 bytes"));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_raw);
    let signature = Signature::from_bytes(&sig_arr)
        .map_err(|_| anyhow!("invalid signature bytes"))?;

    // Canonicalize profile JSON for deterministic verification
    let canonical_bytes = canonical_json_bytes(&envelope.profile)?;

    // Verify Ed25519 signature
    let pub_key = PublicKey(*trusted_public_key_bytes);
    if !verify_detached(&signature, &canonical_bytes, &pub_key) {
        return Err(anyhow!(
            "invalid profile signature: profile was tampered or signed with different key"
        ));
    }

    // Deserialize into typed DTO with deny_unknown_fields to reject unknown properties inside profile
    let profile: ProfileDto = serde_json::from_value(envelope.profile)
        .context("invalid profile structure or unexpected fields inside profile")?;

    let role = &profile.role;
    if role != "soporte" && role != "tecnico" {
        return Err(anyhow!("invalid role: {}", role));
    }

    // Invariants (F3-01 / ADR-008)
    if role == "soporte" {
        if profile.policy.allow_outgoing {
            return Err(anyhow!(
                "soporte profile invariant violated: allow_outgoing must be false"
            ));
        }
        if !profile.policy.allow_incoming {
            return Err(anyhow!(
                "soporte profile invariant violated: allow_incoming must be true"
            ));
        }
    } else if role == "tecnico" {
        if !profile.policy.allow_outgoing {
            return Err(anyhow!(
                "tecnico profile invariant violated: allow_outgoing must be true"
            ));
        }
        if profile.policy.unattended_access {
            return Err(anyhow!(
                "tecnico profile invariant violated: unattended_access forbidden"
            ));
        }
        if profile.policy._unattended_elevation {
            return Err(anyhow!(
                "tecnico profile invariant violated: unattended_elevation forbidden"
            ));
        }
    }

    // Expiration check (TC-F3-003, TC-F3-008)
    if let Some(exp) = &profile.expiration {
        if let Some(exp_str) = &exp.expires_at {
            let exp_time = chrono::DateTime::parse_from_rfc3339(exp_str)
                .map_err(|e| anyhow!("invalid expires_at format: {}", e))?;
            let current_time = match now_rfc3339 {
                Some(s) => chrono::DateTime::parse_from_rfc3339(s)
                    .map_err(|e| anyhow!("invalid now_rfc3339 format: {}", e))?
                    .with_timezone(&chrono::Utc),
                None => chrono::Utc::now(),
            };
            if current_time > exp_time {
                return Err(anyhow!(
                    "profile expired: {} is past {}",
                    current_time.to_rfc3339(),
                    exp_str
                ));
            }
        }
    }

    let app_name = profile.identity.and_then(|id| id.app_name);

    let (chat_enabled, chat_allow_attachments, chat_allow_remote_escalation) =
        match profile.policy.chat {
            Some(ref c) => (
                c.enabled.unwrap_or(profile.role == "soporte"),
                c.allow_attachments,
                c.allow_remote_escalation,
            ),
            None => (profile.role == "soporte", true, true),
        };

    Ok((
        VerifiedProfileInfo {
            profile_id: profile.profile_id,
            role: profile.role,
            rendezvous_server: profile.server.rendezvous_server,
            relay_server: profile.server.relay_server,
            api_server: profile.server.api_server,
            allow_outgoing: profile.policy.allow_outgoing,
            allow_incoming: profile.policy.allow_incoming,
            unattended_access: profile.policy.unattended_access,
            allow_file_transfer: profile.policy.allow_file_transfer,
            allow_clipboard: profile.policy.allow_clipboard,
            allow_audio: profile.policy.allow_audio,
            hide_network_settings: profile.policy.hide_network_settings,
            chat_enabled,
            chat_allow_attachments,
            chat_allow_remote_escalation,
        },
        profile.server.server_public_key,
        app_name,
    ))
}

fn apply_profile_to_config(
    info: &VerifiedProfileInfo,
    server_public_key: &str,
    app_name: Option<&str>,
) {
    let mut overwrite = config::OVERWRITE_SETTINGS.write().unwrap();
    if !info.rendezvous_server.is_empty() {
        overwrite.insert(
            "custom-rendezvous-server".to_string(),
            info.rendezvous_server.clone(),
        );
    }
    if !info.relay_server.is_empty() {
        overwrite.insert("relay-server".to_string(), info.relay_server.clone());
    }
    if !info.api_server.is_empty() {
        overwrite.insert("api-server".to_string(), info.api_server.clone());
    }
    if !server_public_key.is_empty() {
        overwrite.insert("key".to_string(), server_public_key.to_string());
    }
    overwrite.insert("role".to_string(), info.role.clone());
    overwrite.insert(
        "allow-incoming".to_string(),
        info.allow_incoming.to_string(),
    );
    overwrite.insert(
        "allow-outgoing".to_string(),
        info.allow_outgoing.to_string(),
    );
    overwrite.insert(
        "unattended-access".to_string(),
        info.unattended_access.to_string(),
    );
    overwrite.insert(
        "allow-file-transfer".to_string(),
        info.allow_file_transfer.to_string(),
    );
    overwrite.insert(
        "allow-clipboard".to_string(),
        info.allow_clipboard.to_string(),
    );
    overwrite.insert("allow-audio".to_string(), info.allow_audio.to_string());
    overwrite.insert(
        "hide-network-settings".to_string(),
        info.hide_network_settings.to_string(),
    );

    if let Some(name) = app_name {
        if !name.trim().is_empty() {
            *config::APP_NAME.write().unwrap() = name.to_string();
        }
    }
}

pub fn load_and_apply_profile() -> bool {
    let path = match locate_profile_path() {
        Some(p) => p,
        None => return false,
    };

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("No se pudo leer archivo de perfil {}: {}", path.display(), e);
            return false;
        }
    };

    let trusted_key = get_trusted_verification_key();

    match verify_signed_profile_bytes(&data, &trusted_key, None) {
        Ok((info, s_pubkey, app_name)) => {
            log::info!(
                "Perfil firmado Cercano verificado exitosamente (rol: {}, ID: {})",
                info.role,
                info.profile_id
            );
            apply_profile_to_config(&info, &s_pubkey, app_name.as_deref());
            *ACTIVE_PROFILE.write().unwrap() = Some(info);
            true
        }
        Err(e) => {
            log::error!(
                "RECHAZADO: Fallo en verificación criptográfica de perfil Cercano: {}",
                e
            );
            false
        }
    }
}

pub fn is_support_mode() -> bool {
    ACTIVE_PROFILE
        .read()
        .ok()
        .and_then(|p| p.as_ref().map(|prof| prof.role == "soporte"))
        .unwrap_or(false)
}

pub fn is_technician_mode() -> bool {
    ACTIVE_PROFILE
        .read()
        .ok()
        .and_then(|p| p.as_ref().map(|prof| prof.role == "tecnico"))
        .unwrap_or(false)
}

pub fn can_initiate_outgoing_connections() -> bool {
    if is_support_mode() {
        return false;
    }
    if is_technician_mode() {
        return get_technician_session_token().is_some();
    }
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(profile) = guard.as_ref() {
            return profile.allow_outgoing;
        }
    }
    true
}

pub fn validate_outgoing_connection() -> ResultType<()> {
    if is_support_mode() {
        return Err(anyhow!(
            "Cercano Soporte está configurado exclusivamente para recibir asistencia técnica"
        ));
    }
    if is_technician_mode() {
        if get_technician_session_token().is_none() {
            return Err(anyhow!(
                "Debe iniciar sesión con su cuenta técnica antes de iniciar conexiones"
            ));
        }
    }
    Ok(())
}

pub fn is_address_book_enabled() -> bool {
    if is_support_mode() {
        return false;
    }
    if is_technician_mode() {
        return get_technician_session_token().is_some();
    }
    true
}

pub fn is_network_settings_locked() -> bool {
    if is_support_mode() || is_technician_mode() {
        return true;
    }
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(profile) = guard.as_ref() {
            return profile.hide_network_settings;
        }
    }
    false
}

pub fn requires_session_approval() -> bool {
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(profile) = guard.as_ref() {
            return !profile.unattended_access;
        }
    }
    true
}

pub fn is_chat_enabled() -> bool {
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(profile) = guard.as_ref() {
            return profile.chat_enabled;
        }
    }
    is_support_mode()
}

pub fn is_chat_allow_attachments() -> bool {
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(profile) = guard.as_ref() {
            return profile.chat_allow_attachments;
        }
    }
    true
}

pub fn is_chat_allow_remote_escalation() -> bool {
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(profile) = guard.as_ref() {
            return profile.chat_allow_remote_escalation;
        }
    }
    true
}

pub fn get_technician_session_token() -> Option<String> {
    TECHNICIAN_SESSION
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(|s| s.token.clone()))
}

pub fn get_technician_session() -> Option<TechnicianSession> {
    TECHNICIAN_SESSION
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

pub fn set_technician_session(token: String, username: String, permissions: Vec<String>) {
    if let Ok(mut guard) = TECHNICIAN_SESSION.write() {
        *guard = Some(TechnicianSession {
            token,
            username,
            permissions,
        });
    }
}

pub fn clear_technician_session() {
    if let Ok(mut guard) = TECHNICIAN_SESSION.write() {
        *guard = None;
    }
}

pub fn set_active_profile(profile: Option<VerifiedProfileInfo>) {
    if let Ok(mut guard) = ACTIVE_PROFILE.write() {
        *guard = profile;
    }
}

pub fn active_session_count() -> usize {
    #[cfg(not(any(target_os = "ios")))]
    {
        crate::ui_cm_interface::get_clients_length()
    }
    #[cfg(any(target_os = "ios"))]
    {
        0
    }
}

pub fn user_terminate_session(conn_id: i32) {
    #[cfg(not(any(target_os = "ios")))]
    {
        crate::ui_cm_interface::close(conn_id);
    }
}

impl ElevationRequestNotification {
    pub fn new(
        request_id: impl Into<String>,
        requester_name: impl Into<String>,
        reason: impl Into<String>,
        ticket: Option<String>,
    ) -> ResultType<Self> {
        let r = reason.into();
        if r.trim().is_empty() {
            return Err(anyhow!("El motivo de la solicitud de elevación es obligatorio"));
        }
        let req = requester_name.into();
        if req.trim().is_empty() {
            return Err(anyhow!("El solicitante de la elevación es obligatorio"));
        }
        Ok(Self {
            request_id: request_id.into(),
            requester_name: req,
            reason: r,
            ticket,
            timestamp_rfc3339: chrono::Utc::now().to_rfc3339(),
        })
    }
}

pub fn can_request_elevation() -> bool {
    if is_support_mode() {
        return false;
    }
    if is_technician_mode() {
        if let Some(session) = get_technician_session() {
            return session.permissions.iter().any(|p| p == "elev:use" || p == "admin");
        }
    }
    false
}

pub fn handle_incoming_elevation_request(
    request: ElevationRequestNotification,
) -> ResultType<()> {
    if !is_support_mode() {
        return Err(anyhow!("Las solicitudes de elevación solo se reciben en modo soporte"));
    }
    if let Ok(mut guard) = PENDING_ELEVATION_REQUEST.write() {
        *guard = Some(request);
    }
    Ok(())
}

pub fn get_pending_elevation_request() -> Option<ElevationRequestNotification> {
    PENDING_ELEVATION_REQUEST
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

pub fn respond_to_elevation_request(
    request_id: &str,
    response: ElevationConsentResponse,
) -> ResultType<ElevationConsentResponse> {
    let mut pending = PENDING_ELEVATION_REQUEST
        .write()
        .map_err(|e| anyhow!("Lock error: {}", e))?;
    if let Some(req) = pending.as_ref() {
        if req.request_id != request_id {
            return Err(anyhow!("Identificador de solicitud de elevación no coincide"));
        }
    } else {
        return Err(anyhow!("No hay ninguna solicitud de elevación pendiente"));
    }
    *pending = None;

    if let Ok(mut tracker) = ELEVATION_TRACKER.write() {
        tracker.record_consent(
            request_id.to_string(),
            response,
            chrono::Utc::now().timestamp(),
        );
    }

    Ok(response)
}

pub fn execute_elevation_action<F, R>(
    request_id: &str,
    mut credential: SecureElevationCredential,
    action: F,
) -> ResultType<R>
where
    F: FnOnce(&str, Option<&str>, &[u8]) -> ResultType<R>,
{
    let now = chrono::Utc::now().timestamp();
    // 1. Validar y consumir consentimiento previo obligatorio
    {
        let mut tracker = ELEVATION_TRACKER
            .write()
            .map_err(|e| anyhow!("Lock error: {}", e))?;
        if tracker.is_locked_out() {
            credential.zeroize();
            return Err(anyhow!(
                "Máximo de 3 intentos fallidos alcanzado. Sesión bloqueada para elevación."
            ));
        }
        if let Err(e) = tracker.consume_consent(request_id, now) {
            credential.zeroize();
            return Err(e);
        }
    }

    // 2. Ejecutar la acción administrativa con credenciales en memoria protegida
    let res = action(
        &credential.username,
        credential.domain.as_deref(),
        credential.password_bytes(),
    );

    // 3. Borrado seguro de memoria RAM (zeroize) inmediato tras la invocación
    credential.zeroize();

    // 4. Actualizar contador de fallos/éxitos en el tracker de sesión
    let mut tracker = ELEVATION_TRACKER
        .write()
        .map_err(|e| anyhow!("Lock error: {}", e))?;
    match &res {
        Ok(_) => {
            tracker.record_success();
        }
        Err(err) => {
            let locked = tracker.record_failure();
            if locked {
                return Err(anyhow!(
                    "Fallo de elevación: {}. Máximo de 3 intentos fallidos alcanzado, sesión bloqueada.",
                    err
                ));
            } else {
                return Err(anyhow!(
                    "Fallo de elevación: {}. Intentos restantes: {}",
                    err,
                    tracker.remaining_attempts()
                ));
            }
        }
    }

    res
}

pub fn reset_elevation_tracker() {
    if let Ok(mut tracker) = ELEVATION_TRACKER.write() {
        tracker.reset();
    }
}

// ── F5-06: Cacheo, Evaluación y Aplicación de Política Efectiva Central ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedEffectivePolicy {
    pub device_id: String,
    pub role: String,
    pub effective: std::collections::BTreeMap<String, Value>,
    pub cache_ttl_seconds: i64,
    pub issued_at: String,
    pub expires_at: String,
}

impl CachedEffectivePolicy {
    pub fn is_expired(&self, now_rfc3339: Option<&str>) -> bool {
        let exp_time = match chrono::DateTime::parse_from_rfc3339(&self.expires_at) {
            Ok(dt) => dt.with_timezone(&chrono::Utc),
            Err(_) => return true,
        };
        let now = match now_rfc3339 {
            Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
                Ok(dt) => dt.with_timezone(&chrono::Utc),
                Err(_) => chrono::Utc::now(),
            },
            None => chrono::Utc::now(),
        };
        now > exp_time
    }

    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        self.effective
            .get(key)
            .and_then(|v| v.as_bool())
            .unwrap_or(default)
    }

    pub fn get_i64(&self, key: &str, default: i64) -> i64 {
        self.effective
            .get(key)
            .and_then(|v| v.as_i64())
            .unwrap_or(default)
    }
}

pub fn update_cached_policy(
    policy_json_str: &str,
    now_rfc3339: Option<&str>,
) -> ResultType<CachedEffectivePolicy> {
    let mut policy: CachedEffectivePolicy = serde_json::from_str(policy_json_str)
        .context("JSON de política efectiva inválido")?;

    // Comprobación de expiración
    if policy.is_expired(now_rfc3339) {
        return Err(anyhow!("La política recibida ya ha caducado"));
    }

    // Invariante frente a perfil firmado P0 (regla 5 de docs/specs/identidad.md / TC-F5-025):
    // La política central o modificaciones locales no pueden superar el techo del perfil P0.
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(profile) = guard.as_ref() {
            if profile.role == "soporte" {
                policy.effective.insert("unattended_access".to_string(), serde_json::json!(false));
                policy.effective.insert("allow_outgoing".to_string(), serde_json::json!(false));
                policy.effective.insert("enable_elevation".to_string(), serde_json::json!(false));
                policy.effective.insert("unattended_elevation".to_string(), serde_json::json!(false));
            } else if profile.role == "tecnico" {
                policy.effective.insert("unattended_access".to_string(), serde_json::json!(false));
                policy.effective.insert("allow_incoming".to_string(), serde_json::json!(false));
                policy.effective.insert("unattended_elevation".to_string(), serde_json::json!(false));
                policy.effective.insert("chat.enabled".to_string(), serde_json::json!(false));
            }

            if !profile.allow_file_transfer {
                policy.effective.insert("allow_file_transfer".to_string(), serde_json::json!(false));
            }
            if !profile.allow_clipboard {
                policy.effective.insert("allow_clipboard".to_string(), serde_json::json!(false));
            }
            if !profile.allow_audio {
                policy.effective.insert("allow_audio".to_string(), serde_json::json!(false));
            }
            if profile.hide_network_settings {
                policy.effective.insert("hide_network_settings".to_string(), serde_json::json!(true));
            }
        }
    }

    apply_effective_policy_to_config(&policy);

    POLICY_OFFLINE_FAIL_CLOSED.store(false, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut guard) = CACHED_POLICY.write() {
        *guard = Some(policy.clone());
    }

    Ok(policy)
}

fn apply_effective_policy_to_config(policy: &CachedEffectivePolicy) {
    let mut overwrite = config::OVERWRITE_SETTINGS.write().unwrap();
    for (k, v) in &policy.effective {
        match v {
            Value::Bool(b) => {
                overwrite.insert(k.clone(), b.to_string());
            }
            Value::Number(n) => {
                overwrite.insert(k.clone(), n.to_string());
            }
            _ => {}
        }
    }
}

pub fn get_cached_policy() -> Option<CachedEffectivePolicy> {
    CACHED_POLICY.read().ok().and_then(|g| g.clone())
}

pub fn clear_cached_policy() {
    if let Ok(mut g) = CACHED_POLICY.write() {
        *g = None;
    }
    POLICY_OFFLINE_FAIL_CLOSED.store(false, std::sync::atomic::Ordering::SeqCst);
}

pub fn is_policy_fail_closed() -> bool {
    POLICY_OFFLINE_FAIL_CLOSED.load(std::sync::atomic::Ordering::SeqCst)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyStatus {
    Valid,
    CachedValid,
    ExpiredFailClosed,
    NoPolicyUseP0,
}

pub fn evaluate_policy_status(
    now_rfc3339: Option<&str>,
    is_network_offline: bool,
) -> PolicyStatus {
    let cached = get_cached_policy();
    match cached {
        Some(policy) => {
            if policy.is_expired(now_rfc3339) {
                POLICY_OFFLINE_FAIL_CLOSED.store(true, std::sync::atomic::Ordering::SeqCst);
                PolicyStatus::ExpiredFailClosed
            } else if is_network_offline {
                PolicyStatus::CachedValid
            } else {
                PolicyStatus::Valid
            }
        }
        None => PolicyStatus::NoPolicyUseP0,
    }
}

pub fn can_accept_incoming_connection(
    now_rfc3339: Option<&str>,
    is_network_offline: bool,
) -> ResultType<()> {
    let status = evaluate_policy_status(now_rfc3339, is_network_offline);
    if status == PolicyStatus::ExpiredFailClosed {
        return Err(anyhow!(
            "Conexión entrante bloqueada: la política central ha caducado sin conectividad de red (fail-closed)"
        ));
    }

    if let Some(policy) = get_cached_policy() {
        if !policy.get_bool("allow_incoming", true) {
            return Err(anyhow!(
                "Conexiones entrantes deshabilitadas por política central"
            ));
        }
    } else if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(prof) = guard.as_ref() {
            if !prof.allow_incoming {
                return Err(anyhow!("Conexiones entrantes deshabilitadas por perfil"));
            }
        }
    }

    Ok(())
}

pub fn can_accept_outgoing_connection(
    now_rfc3339: Option<&str>,
    is_network_offline: bool,
) -> ResultType<()> {
    if is_support_mode() {
        return Err(anyhow!(
            "Cercano Soporte está configurado exclusivamente para recibir asistencia técnica"
        ));
    }

    let status = evaluate_policy_status(now_rfc3339, is_network_offline);
    if status == PolicyStatus::ExpiredFailClosed {
        return Err(anyhow!(
            "Conexión saliente bloqueada: la política central ha caducado sin conectividad de red (fail-closed)"
        ));
    }

    if let Some(policy) = get_cached_policy() {
        if !policy.get_bool("allow_outgoing", true) {
            return Err(anyhow!(
                "Conexiones salientes deshabilitadas por política central"
            ));
        }
    } else if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(prof) = guard.as_ref() {
            if !prof.allow_outgoing {
                return Err(anyhow!("Conexiones salientes deshabilitadas por perfil"));
            }
        }
    }

    if is_technician_mode() && get_technician_session_token().is_none() {
        return Err(anyhow!(
            "Debe iniciar sesión con su cuenta técnica antes de iniciar conexiones"
        ));
    }

    Ok(())
}

pub fn is_effective_file_transfer_allowed() -> bool {
    if let Some(policy) = get_cached_policy() {
        if !policy.get_bool("allow_file_transfer", true) {
            return false;
        }
    }
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(prof) = guard.as_ref() {
            return prof.allow_file_transfer;
        }
    }
    true
}

pub fn is_effective_clipboard_allowed() -> bool {
    if let Some(policy) = get_cached_policy() {
        if !policy.get_bool("allow_clipboard", true) {
            return false;
        }
    }
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(prof) = guard.as_ref() {
            return prof.allow_clipboard;
        }
    }
    true
}

pub fn is_effective_audio_allowed() -> bool {
    if let Some(policy) = get_cached_policy() {
        if !policy.get_bool("allow_audio", true) {
            return false;
        }
    }
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(prof) = guard.as_ref() {
            return prof.allow_audio;
        }
    }
    true
}

pub fn get_effective_session_max_duration_minutes() -> i64 {
    if let Some(policy) = get_cached_policy() {
        policy.get_i64("session.max_duration_minutes", 120)
    } else {
        120
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_soporte_profile(unattended: bool) -> VerifiedProfileInfo {
        VerifiedProfileInfo {
            profile_id: "test-soporte-id".to_string(),
            role: "soporte".to_string(),
            rendezvous_server: "cercano.lan:21116".to_string(),
            relay_server: "relay.lan:21117".to_string(),
            api_server: "https://cercano.lan:21114".to_string(),
            allow_outgoing: false,
            allow_incoming: true,
            unattended_access: unattended,
            allow_file_transfer: true,
            allow_clipboard: true,
            allow_audio: true,
            hide_network_settings: true,
        }
    }

    fn sample_tecnico_profile() -> VerifiedProfileInfo {
        VerifiedProfileInfo {
            profile_id: "test-tecnico-id".to_string(),
            role: "tecnico".to_string(),
            rendezvous_server: "cercano.lan:21116".to_string(),
            relay_server: "relay.lan:21117".to_string(),
            api_server: "https://cercano.lan:21114".to_string(),
            allow_outgoing: true,
            allow_incoming: true,
            unattended_access: false,
            allow_file_transfer: true,
            allow_clipboard: true,
            allow_audio: true,
            hide_network_settings: true,
        }
    }

    #[test]
    fn test_soporte_mode_restrictions() {
        set_active_profile(Some(sample_soporte_profile(false)));
        clear_technician_session();

        assert!(is_support_mode());
        assert!(!is_technician_mode());

        // Rechazo de conexión saliente
        assert!(!can_initiate_outgoing_connections());
        let err = validate_outgoing_connection().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cercano Soporte está configurado exclusivamente para recibir asistencia técnica"
        );

        // Bloqueo de libreta
        assert!(!is_address_book_enabled());

        // Bloqueo de ajustes de red y servidor
        assert!(is_network_settings_locked());

        // Aprobación requerida por defecto si unattended_access es false
        assert!(requires_session_approval());

        // Soporte no puede solicitar elevación
        assert!(!can_request_elevation());
    }

    #[test]
    fn test_soporte_mode_unattended_approval() {
        set_active_profile(Some(sample_soporte_profile(true)));
        assert!(!requires_session_approval());
    }

    #[test]
    fn test_soporte_elevation_notification() {
        set_active_profile(Some(sample_soporte_profile(false)));

        let notif = ElevationRequestNotification::new(
            "elev-123",
            "Carlos TI",
            "Instalar certificado raíz",
            Some("INC-4001".to_string()),
        )
        .unwrap();

        assert!(handle_incoming_elevation_request(notif.clone()).is_ok());
        assert_eq!(get_pending_elevation_request(), Some(notif));

        let res = respond_to_elevation_request("elev-123", ElevationConsentResponse::Approved).unwrap();
        assert_eq!(res, ElevationConsentResponse::Approved);
        assert_eq!(get_pending_elevation_request(), None);
    }

    #[test]
    fn test_tecnico_mode_lifecycle_and_capabilities() {
        set_active_profile(Some(sample_tecnico_profile()));
        clear_technician_session();

        assert!(!is_support_mode());
        assert!(is_technician_mode());

        // Sin login: conexión rechazada
        assert!(!can_initiate_outgoing_connections());
        let err = validate_outgoing_connection().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Debe iniciar sesión con su cuenta técnica antes de iniciar conexiones"
        );

        // Sin login: libreta no accesible
        assert!(!is_address_book_enabled());

        // Ajustes de red bloqueados (fijados por el perfil)
        assert!(is_network_settings_locked());

        // Login exitoso
        set_technician_session(
            "tok_tech_secret_123".to_string(),
            "tecnico_alberto".to_string(),
            vec!["remote:connect".to_string(), "elev:use".to_string()],
        );

        assert_eq!(
            get_technician_session_token(),
            Some("tok_tech_secret_123".to_string())
        );
        assert!(can_initiate_outgoing_connections());
        assert!(validate_outgoing_connection().is_ok());
        assert!(is_address_book_enabled());
        assert!(can_request_elevation());

        // Logout: limpia completamente el estado local
        clear_technician_session();
        assert_eq!(get_technician_session_token(), None);
        assert!(!can_initiate_outgoing_connections());
        assert!(!is_address_book_enabled());
        assert!(!can_request_elevation());
    }

    #[test]
    fn test_elevation_user_denial_blocks_credential_use() {
        reset_elevation_tracker();
        set_active_profile(Some(sample_soporte_profile(false)));

        let notif = ElevationRequestNotification::new(
            "elev-deny-1",
            "Tecnico Soporte",
            "Mantenimiento programado",
            None,
        )
        .unwrap();

        handle_incoming_elevation_request(notif).unwrap();
        let res = respond_to_elevation_request("elev-deny-1", ElevationConsentResponse::Denied).unwrap();
        assert_eq!(res, ElevationConsentResponse::Denied);

        let cred = SecureElevationCredential::new("Administrator", "SecretPassword123!");
        let action_result = execute_elevation_action("elev-deny-1", cred, |_user, _dom, _pwd| {
            Ok(())
        });

        assert!(action_result.is_err());
        assert!(action_result
            .unwrap_err()
            .to_string()
            .contains("la elevación fue rechazada"));
    }

    #[test]
    fn test_elevation_credential_zeroize_on_drop_and_manual() {
        let mut cred = SecureElevationCredential::new("CORP\\admin_user", "MyVerySecretPass!");
        assert_eq!(cred.username, "admin_user");
        assert_eq!(cred.domain, Some("CORP".to_string()));
        assert!(!cred.is_zeroized());
        assert_eq!(cred.password_str().unwrap(), "MyVerySecretPass!");

        cred.zeroize();
        assert!(cred.is_zeroized());
        assert_eq!(cred.password_bytes().len(), 0);
    }

    #[test]
    fn test_elevation_three_failed_attempts_locks_out_session() {
        reset_elevation_tracker();
        set_active_profile(Some(sample_soporte_profile(false)));

        for i in 1..=3 {
            let req_id = format!("elev-fail-{}", i);
            let notif = ElevationRequestNotification::new(
                &req_id,
                "Tecnico",
                "Reinicio servicio",
                None,
            )
            .unwrap();
            handle_incoming_elevation_request(notif).unwrap();
            respond_to_elevation_request(&req_id, ElevationConsentResponse::Approved).unwrap();

            let cred = SecureElevationCredential::new("Administrator", "WrongPassword");
            let result = execute_elevation_action(&req_id, cred, |_u, _d, _p| {
                Err(anyhow!("LogonUserW failed: ERROR_LOGON_FAILURE"))
            });

            assert!(result.is_err());
            if i < 3 {
                assert!(result.unwrap_err().to_string().contains("Intentos restantes"));
            } else {
                assert!(result.unwrap_err().to_string().contains("sesión bloqueada"));
            }
        }

        let notif4 = ElevationRequestNotification::new("elev-fail-4", "Tecnico", "Otro intento", None).unwrap();
        handle_incoming_elevation_request(notif4).unwrap();
        respond_to_elevation_request("elev-fail-4", ElevationConsentResponse::Approved).unwrap();

        let cred4 = SecureElevationCredential::new("Administrator", "AnyPassword");
        let result4 = execute_elevation_action("elev-fail-4", cred4, |_u, _d, _p| Ok(()));
        assert!(result4.is_err());
        assert!(result4.unwrap_err().to_string().contains("Sesión bloqueada para elevación"));

        reset_elevation_tracker();
    }

    #[test]
    fn test_elevation_credential_debug_display_redaction() {
        let cred = SecureElevationCredential::new("admin_root", "UltraSecret999!");
        let debug_str = format!("{:?}", cred);
        let display_str = format!("{}", cred);

        assert!(!debug_str.contains("UltraSecret999!"));
        assert!(!display_str.contains("UltraSecret999!"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_elevation_account_parsing_local_and_domain() {
        let (u1, d1) = SecureElevationCredential::parse_account("Administrator");
        assert_eq!(u1, "Administrator");
        assert_eq!(d1, None);

        let (u2, d2) = SecureElevationCredential::parse_account(".\\LocalAdmin");
        assert_eq!(u2, "LocalAdmin");
        assert_eq!(d2, Some(".".to_string()));

        let (u3, d3) = SecureElevationCredential::parse_account("CONTOSO\\admin_svc");
        assert_eq!(u3, "admin_svc");
        assert_eq!(d3, Some("CONTOSO".to_string()));

        let (u4, d4) = SecureElevationCredential::parse_account("admin_svc@contoso.lan");
        assert_eq!(u4, "admin_svc");
        assert_eq!(d4, Some("contoso.lan".to_string()));
    }

    #[test]
    fn test_elevation_single_use_enforcement() {
        reset_elevation_tracker();
        set_active_profile(Some(sample_soporte_profile(false)));

        let notif = ElevationRequestNotification::new(
            "elev-single-1",
            "Tecnico Soporte",
            "Ajustar cortafuegos",
            Some("INC-888".to_string()),
        )
        .unwrap();

        handle_incoming_elevation_request(notif).unwrap();
        respond_to_elevation_request("elev-single-1", ElevationConsentResponse::Approved).unwrap();

        let cred1 = SecureElevationCredential::new("Administrator", "GoodPass");
        let res1 = execute_elevation_action("elev-single-1", cred1, |_u, _d, _p| Ok(()));
        assert!(res1.is_ok());

        let cred2 = SecureElevationCredential::new("Administrator", "GoodPass");
        let res2 = execute_elevation_action("elev-single-1", cred2, |_u, _d, _p| Ok(()));
        assert!(res2.is_err());
        assert!(res2.unwrap_err().to_string().contains("un solo uso permitido"));

        reset_elevation_tracker();
    }

    #[test]
    fn test_tc_f5_024_client_offline_cache_valid_and_expired_fail_closed() {
        clear_cached_policy();
        set_active_profile(Some(sample_soporte_profile(false)));

        let issued = "2026-11-16T12:00:00Z";
        let expires = "2026-11-16T12:05:00Z";

        let policy_json = serde_json::json!({
            "device_id": "dev-offline-test",
            "role": "soporte",
            "effective": {
                "allow_incoming": true,
                "allow_outgoing": false,
                "allow_file_transfer": false,
                "session.max_duration_minutes": 45
            },
            "cache_ttl_seconds": 300,
            "issued_at": issued,
            "expires_at": expires
        })
        .to_string();

        let before_expiry = "2026-11-16T12:02:00Z";
        let pol = update_cached_policy(&policy_json, Some(before_expiry)).unwrap();
        assert_eq!(pol.cache_ttl_seconds, 300);

        // 1. Con red activa antes de expirar -> Valid
        let status_online = evaluate_policy_status(Some(before_expiry), false);
        assert_eq!(status_online, PolicyStatus::Valid);
        assert!(!is_policy_fail_closed());

        // 2. Sin red (offline) antes de expirar -> CachedValid (aplica copia de caché)
        let status_offline_valid = evaluate_policy_status(Some(before_expiry), true);
        assert_eq!(status_offline_valid, PolicyStatus::CachedValid);
        assert!(!is_policy_fail_closed());
        assert!(can_accept_incoming_connection(Some(before_expiry), true).is_ok());
        assert!(!is_effective_file_transfer_allowed());
        assert_eq!(get_effective_session_max_duration_minutes(), 45);

        // 3. Sin red (offline) después de expirar -> ExpiredFailClosed (falla cerrado)
        let after_expiry = "2026-11-16T12:06:00Z";
        let status_offline_expired = evaluate_policy_status(Some(after_expiry), true);
        assert_eq!(status_offline_expired, PolicyStatus::ExpiredFailClosed);
        assert!(is_policy_fail_closed());

        // Conexiones entrantes y salientes son bloqueadas en fail-closed
        let in_err = can_accept_incoming_connection(Some(after_expiry), true).unwrap_err();
        assert!(in_err.to_string().contains("fail-closed"));

        let out_err = can_accept_outgoing_connection(Some(after_expiry), true).unwrap_err();
        assert!(
            out_err
                .to_string()
                .contains("exclusivamente para recibir asistencia técnica")
                || out_err.to_string().contains("fail-closed")
        );

        clear_cached_policy();
    }

    #[test]
    fn test_tc_f5_025_client_local_tampering_rejected_and_p0_ceiling_enforced() {
        clear_cached_policy();
        set_active_profile(Some(sample_soporte_profile(false)));

        let issued = "2026-11-16T12:00:00Z";
        let expires = "2026-11-16T13:00:00Z";

        // Intento de alteración local: habilitar unattended_access y allow_outgoing en soporte
        let tampered_json = serde_json::json!({
            "device_id": "dev-tamper-test",
            "role": "soporte",
            "effective": {
                "allow_incoming": true,
                "allow_outgoing": true,
                "unattended_access": true,
                "enable_elevation": true
            },
            "cache_ttl_seconds": 3600,
            "issued_at": issued,
            "expires_at": expires
        })
        .to_string();

        let applied = update_cached_policy(&tampered_json, Some("2026-11-16T12:10:00Z")).unwrap();

        // Techo de P0 firmado neutralizó la alteración forzando false en valores sensibles
        assert_eq!(applied.get_bool("unattended_access", true), false);
        assert_eq!(applied.get_bool("allow_outgoing", true), false);
        assert_eq!(applied.get_bool("enable_elevation", true), false);

        assert!(!can_initiate_outgoing_connections());
        clear_cached_policy();
    }
}
