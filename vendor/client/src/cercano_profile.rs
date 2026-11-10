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
    let signature = Signature(sig_arr);

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
    Ok(response)
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
}
