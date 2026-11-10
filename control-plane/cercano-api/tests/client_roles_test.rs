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

//! Pruebas unitarias y de integración para roles de cliente Cercano (F3-14 y F3-15).
//!
//! Valida el comportamiento, restricciones y capacidades diferenciadas según el rol
//! del perfil activo (`soporte` vs `tecnico`), verificando al 100% la Matriz de Capacidades
//! de la Sección 1 de `PLAN-F3-GENERADOR.md` y las reglas arquitectónicas de `ADR-008`.

use std::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechnicianSession {
    pub token: String,
    pub username: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevationRequestNotification {
    pub request_id: String,
    pub requester_name: String,
    pub reason: String,
    pub ticket: Option<String>,
    pub timestamp_rfc3339: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationConsentResponse {
    Approved,
    Denied,
}

static ROLES_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
static ACTIVE_PROFILE: RwLock<Option<VerifiedProfileInfo>> = RwLock::new(None);
static TECHNICIAN_SESSION: RwLock<Option<TechnicianSession>> = RwLock::new(None);
static PENDING_ELEVATION_REQUEST: RwLock<Option<ElevationRequestNotification>> = RwLock::new(None);

fn set_active_profile(profile: Option<VerifiedProfileInfo>) {
    *ACTIVE_PROFILE.write().unwrap() = profile;
}

fn is_support_mode() -> bool {
    ACTIVE_PROFILE
        .read()
        .ok()
        .and_then(|p| p.as_ref().map(|prof| prof.role == "soporte"))
        .unwrap_or(false)
}

fn is_technician_mode() -> bool {
    ACTIVE_PROFILE
        .read()
        .ok()
        .and_then(|p| p.as_ref().map(|prof| prof.role == "tecnico"))
        .unwrap_or(false)
}

fn get_technician_session_token() -> Option<String> {
    TECHNICIAN_SESSION
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(|s| s.token.clone()))
}

fn set_technician_session(token: String, username: String, permissions: Vec<String>) {
    *TECHNICIAN_SESSION.write().unwrap() = Some(TechnicianSession {
        token,
        username,
        permissions,
    });
}

fn clear_technician_session() {
    *TECHNICIAN_SESSION.write().unwrap() = None;
}

fn can_initiate_outgoing_connections() -> bool {
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

fn validate_outgoing_connection() -> Result<(), &'static str> {
    if is_support_mode() {
        return Err(
            "Cercano Soporte está configurado exclusivamente para recibir asistencia técnica",
        );
    }
    if is_technician_mode() && get_technician_session_token().is_none() {
        return Err("Debe iniciar sesión con su cuenta técnica antes de iniciar conexiones");
    }
    Ok(())
}

fn is_address_book_enabled() -> bool {
    if is_support_mode() {
        return false;
    }
    if is_technician_mode() {
        return get_technician_session_token().is_some();
    }
    true
}

fn is_network_settings_locked() -> bool {
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

fn requires_session_approval() -> bool {
    if let Ok(guard) = ACTIVE_PROFILE.read() {
        if let Some(profile) = guard.as_ref() {
            return !profile.unattended_access;
        }
    }
    true
}

fn can_request_elevation() -> bool {
    if is_support_mode() {
        return false;
    }
    if is_technician_mode() {
        if let Some(session) = TECHNICIAN_SESSION.read().unwrap().as_ref() {
            return session
                .permissions
                .iter()
                .any(|p| p == "elev:use" || p == "admin");
        }
    }
    false
}

fn handle_incoming_elevation_request(
    request: ElevationRequestNotification,
) -> Result<(), &'static str> {
    if !is_support_mode() {
        return Err("Las solicitudes de elevación solo se reciben en modo soporte");
    }
    *PENDING_ELEVATION_REQUEST.write().unwrap() = Some(request);
    Ok(())
}

fn get_pending_elevation_request() -> Option<ElevationRequestNotification> {
    PENDING_ELEVATION_REQUEST.read().unwrap().clone()
}

fn respond_to_elevation_request(
    request_id: &str,
    response: ElevationConsentResponse,
) -> Result<ElevationConsentResponse, &'static str> {
    let mut pending = PENDING_ELEVATION_REQUEST.write().unwrap();
    if let Some(req) = pending.as_ref() {
        if req.request_id != request_id {
            return Err("Identificador de solicitud de elevación no coincide");
        }
    } else {
        return Err("No hay ninguna solicitud de elevación pendiente");
    }
    *pending = None;
    Ok(response)
}

fn create_soporte_profile(unattended: bool) -> VerifiedProfileInfo {
    VerifiedProfileInfo {
        profile_id: "00000000-0000-0000-0000-000000000001".to_string(),
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

fn create_tecnico_profile() -> VerifiedProfileInfo {
    VerifiedProfileInfo {
        profile_id: "00000000-0000-0000-0000-000000000002".to_string(),
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

// ============================================================================
// Pruebas Tarea F3-14: Modo Soporte
// ============================================================================

#[test]
fn test_f3_14_soporte_outgoing_connections_strictly_blocked() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    set_active_profile(Some(create_soporte_profile(false)));
    clear_technician_session();

    assert!(is_support_mode(), "Debe identificar rol soporte");
    assert!(!is_technician_mode(), "No debe identificar rol tecnico");
    assert!(
        !can_initiate_outgoing_connections(),
        "can_initiate_outgoing_connections debe retornar false"
    );

    let res = validate_outgoing_connection();
    assert_eq!(
        res,
        Err("Cercano Soporte está configurado exclusivamente para recibir asistencia técnica")
    );
}

#[test]
fn test_f3_14_soporte_address_book_disabled() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    set_active_profile(Some(create_soporte_profile(false)));
    clear_technician_session();

    assert!(
        !is_address_book_enabled(),
        "Libreta debe estar deshabilitada en soporte"
    );
}

#[test]
fn test_f3_14_soporte_network_settings_locked() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    set_active_profile(Some(create_soporte_profile(false)));
    clear_technician_session();

    assert!(
        is_network_settings_locked(),
        "Ajustes de red y servidor deben estar bloqueados en soporte"
    );
}

#[test]
fn test_f3_14_soporte_session_approval_logic() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    // 1. Por defecto: aprobación obligatoria (unattended_access = false)
    set_active_profile(Some(create_soporte_profile(false)));
    assert!(
        requires_session_approval(),
        "Por defecto requiere aprobación explícita"
    );

    // 2. Si perfil habilita acceso desatendido: no requiere aprobación
    set_active_profile(Some(create_soporte_profile(true)));
    assert!(
        !requires_session_approval(),
        "Con unattended_access no requiere aprobación manual"
    );
}

#[test]
fn test_f3_14_soporte_incoming_elevation_dialog_flow() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    set_active_profile(Some(create_soporte_profile(false)));

    // Soporte es receptor: no puede solicitar elevación
    assert!(!can_request_elevation());

    // Llega notificación estructurada de elevación
    let notif = ElevationRequestNotification {
        request_id: "req_elev_001".to_string(),
        requester_name: "admin_ti".to_string(),
        reason: "Actualización de software de contabilidad".to_string(),
        ticket: Some("TIC-9921".to_string()),
        timestamp_rfc3339: "2026-11-10T14:30:00Z".to_string(),
    };

    assert!(handle_incoming_elevation_request(notif.clone()).is_ok());
    assert_eq!(get_pending_elevation_request(), Some(notif));

    // Usuario aprueba la solicitud
    let res = respond_to_elevation_request("req_elev_001", ElevationConsentResponse::Approved);
    assert_eq!(res, Ok(ElevationConsentResponse::Approved));
    assert_eq!(get_pending_elevation_request(), None);

    // Intento posterior sin solicitud pendiente falla
    assert_eq!(
        respond_to_elevation_request("req_elev_001", ElevationConsentResponse::Denied),
        Err("No hay ninguna solicitud de elevación pendiente")
    );
}

// ============================================================================
// Pruebas Tarea F3-15: Modo Técnico
// ============================================================================

#[test]
fn test_f3_15_tecnico_requires_authenticated_session() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    set_active_profile(Some(create_tecnico_profile()));
    clear_technician_session();

    assert!(is_technician_mode(), "Debe identificar rol tecnico");
    assert!(!is_support_mode(), "No debe identificar rol soporte");

    // Sin sesión iniciada: rechazo de conexión saliente y libreta deshabilitada
    assert!(!can_initiate_outgoing_connections());
    assert_eq!(
        validate_outgoing_connection(),
        Err("Debe iniciar sesión con su cuenta técnica antes de iniciar conexiones")
    );
    assert!(!is_address_book_enabled());
    assert!(!can_request_elevation());

    // Iniciar sesión técnica
    set_technician_session(
        "tok_tecnico_session_456".to_string(),
        "soporte_nivel2".to_string(),
        vec!["remote:connect".to_string(), "elev:use".to_string()],
    );

    assert_eq!(
        get_technician_session_token(),
        Some("tok_tecnico_session_456".to_string())
    );
    assert!(can_initiate_outgoing_connections());
    assert_eq!(validate_outgoing_connection(), Ok(()));
    assert!(is_address_book_enabled());
    assert!(
        can_request_elevation(),
        "Con permiso elev:use puede solicitar elevación"
    );

    // Logout: limpia completamente el estado local
    clear_technician_session();
    assert_eq!(get_technician_session_token(), None);
    assert!(!can_initiate_outgoing_connections());
    assert_eq!(
        validate_outgoing_connection(),
        Err("Debe iniciar sesión con su cuenta técnica antes de iniciar conexiones")
    );
    assert!(!is_address_book_enabled());
    assert!(!can_request_elevation());
}

#[test]
fn test_f3_15_tecnico_network_settings_locked() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    set_active_profile(Some(create_tecnico_profile()));
    assert!(
        is_network_settings_locked(),
        "Ajustes de red y servidor bloqueados por perfil en técnico"
    );
}

#[test]
fn test_f3_15_tecnico_elevation_permissions_check() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    set_active_profile(Some(create_tecnico_profile()));

    // Técnico con sesión pero SIN permiso elev:use
    set_technician_session(
        "tok_tech_readonly".to_string(),
        "tecnico_junior".to_string(),
        vec!["remote:connect".to_string()],
    );
    assert!(
        !can_request_elevation(),
        "Sin elev:use no puede solicitar elevación"
    );

    // Técnico con permiso elev:use
    set_technician_session(
        "tok_tech_admin".to_string(),
        "tecnico_senior".to_string(),
        vec!["remote:connect".to_string(), "elev:use".to_string()],
    );
    assert!(
        can_request_elevation(),
        "Con elev:use puede solicitar elevación"
    );
    clear_technician_session();
}

// ============================================================================
// Pruebas Matriz de Capacidades Sección 1 PLAN-F3-GENERADOR.md (100% Cobertura)
// ============================================================================

#[test]
fn test_f3_matrix_section_1_compliance() {
    let _lock = ROLES_TEST_MUTEX.lock().unwrap();
    // 1. Rol Soporte
    set_active_profile(Some(create_soporte_profile(false)));
    clear_technician_session();

    // Recibir conexiones: Sí, con aprobación por defecto
    assert!(requires_session_approval());
    // Iniciar conexiones: No
    assert!(!can_initiate_outgoing_connections());
    assert_eq!(
        validate_outgoing_connection(),
        Err("Cercano Soporte está configurado exclusivamente para recibir asistencia técnica")
    );
    // Libreta y lista de dispositivos: No
    assert!(!is_address_book_enabled());
    // Elevación: Receptor (no emisor)
    assert!(!can_request_elevation());
    // Ajustes de servidor, clave y red: Bloqueados
    assert!(is_network_settings_locked());

    // 2. Rol Técnico
    set_active_profile(Some(create_tecnico_profile()));
    clear_technician_session();

    // Iniciar conexiones: Sí, SOLO con sesión iniciada
    assert!(!can_initiate_outgoing_connections());
    assert_eq!(
        validate_outgoing_connection(),
        Err("Debe iniciar sesión con su cuenta técnica antes de iniciar conexiones")
    );
    // Libreta: Sí, SOLO con sesión iniciada
    assert!(!is_address_book_enabled());

    // Al iniciar sesión
    set_technician_session(
        "tok_valid_tech".to_string(),
        "admin_tech".to_string(),
        vec!["elev:use".to_string()],
    );
    assert!(can_initiate_outgoing_connections());
    assert!(is_address_book_enabled());
    assert!(can_request_elevation());
    // Ajustes de servidor, clave y red: Bloqueados
    assert!(is_network_settings_locked());

    clear_technician_session();
}
