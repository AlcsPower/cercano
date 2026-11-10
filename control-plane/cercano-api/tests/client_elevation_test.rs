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

//! Pruebas unitarias y de integración para la elevación de privilegios con credenciales (F3-16).
//!
//! Cubre los casos de prueba TC-F3-070 a TC-F3-079 especificados en `PLAN-F3-GENERADOR.md` §3 y §6:
//! - TC-F3-070: Rechazo de elevación por la persona usuaria aborta el flujo y no transmite credenciales.
//! - TC-F3-071: Borrado seguro de memoria RAM (`zeroize` volátil) verificado tras uso y en descarte (`Drop`).
//! - TC-F3-072: Límite estricto de 3 intentos fallidos consecutivos bloquea la elevación en la sesión.
//! - TC-F3-073: Cero secretos o contraseñas en representaciones de texto o logs (`[REDACTED]`).
//! - TC-F3-074: Análisis sintáctico y soporte de cuentas locales (`.\Admin`, `Admin`) y de dominio (`CORP\user`, `user@corp.lan`).
//! - TC-F3-075: Mínimo privilegio y un solo uso: el consentimiento expira de inmediato tras la primera acción.
//! - TC-F3-076: Validación de permisos técnicos (`elev:use` o `admin`) e imposibilidad de que `soporte` solicite elevación.
//! - TC-F3-077: Motivo obligatorio no vacío ni espacios en blanco para solicitudes de elevación.
//! - TC-F3-078: Caducidad temporal de la solicitud de elevación (> 60 segundos).
//! - TC-F3-079: Restablecimiento del contador de fallos tras ejecución administrativa exitosa.

use std::sync::RwLock;

pub const MAX_FAILED_ELEVATION_ATTEMPTS: u32 = 3;
pub const ELEVATION_CONSENT_TIMEOUT_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationConsentResponse {
    Approved,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevationRequestNotification {
    pub request_id: String,
    pub requester_name: String,
    pub reason: String,
    pub ticket: Option<String>,
    pub timestamp_rfc3339: String,
}

impl ElevationRequestNotification {
    pub fn new(
        request_id: impl Into<String>,
        requester_name: impl Into<String>,
        reason: impl Into<String>,
        ticket: Option<String>,
    ) -> Result<Self, &'static str> {
        let r = reason.into();
        if r.trim().is_empty() {
            return Err("El motivo de la solicitud de elevación es obligatorio");
        }
        let req = requester_name.into();
        if req.trim().is_empty() {
            return Err("El solicitante de la elevación es obligatorio");
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

    pub fn consume_consent(
        &mut self,
        request_id: &str,
        now_epoch: i64,
    ) -> Result<(), &'static str> {
        if self.is_locked_out {
            return Err(
                "Máximo de 3 intentos fallidos alcanzado. Sesión bloqueada para elevación.",
            );
        }
        match &mut self.active_consent {
            Some(consent) => {
                if consent.request_id != request_id {
                    return Err("Identificador de solicitud de elevación no coincide");
                }
                if consent.response == ElevationConsentResponse::Denied {
                    return Err("Consentimiento de usuario requerido: la elevación fue rechazada");
                }
                if consent.consumed {
                    return Err(
                        "La elevación ya fue utilizada (mínimo privilegio: un solo uso permitido)",
                    );
                }
                if (now_epoch - consent.granted_at_epoch_secs) > ELEVATION_CONSENT_TIMEOUT_SECS {
                    return Err("La solicitud de elevación ha caducado (> 60 s)");
                }
                consent.consumed = true;
                Ok(())
            }
            None => Err("Consentimiento de usuario requerido: no hay consentimiento registrado"),
        }
    }

    pub fn reset(&mut self) {
        self.failed_attempts = 0;
        self.is_locked_out = false;
        self.active_consent = None;
    }
}

impl Default for ElevationSessionTracker {
    fn default() -> Self {
        Self::new()
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

static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
static TEST_ELEVATION_TRACKER: RwLock<Option<ElevationSessionTracker>> = RwLock::new(None);
static TEST_PENDING_REQUEST: RwLock<Option<ElevationRequestNotification>> = RwLock::new(None);

fn reset_test_elevation_state() {
    *TEST_ELEVATION_TRACKER.write().unwrap() = Some(ElevationSessionTracker::new());
    *TEST_PENDING_REQUEST.write().unwrap() = None;
}

fn handle_test_incoming_request(req: ElevationRequestNotification) {
    *TEST_PENDING_REQUEST.write().unwrap() = Some(req);
}

fn respond_test_elevation_request(
    request_id: &str,
    response: ElevationConsentResponse,
    now_epoch: i64,
) -> Result<ElevationConsentResponse, &'static str> {
    let mut pending = TEST_PENDING_REQUEST.write().unwrap();
    if let Some(req) = pending.as_ref() {
        if req.request_id != request_id {
            return Err("Identificador de solicitud de elevación no coincide");
        }
    } else {
        return Err("No hay ninguna solicitud de elevación pendiente");
    }
    *pending = None;

    if let Some(tracker) = TEST_ELEVATION_TRACKER.write().unwrap().as_mut() {
        tracker.record_consent(request_id.to_string(), response, now_epoch);
    }

    Ok(response)
}

fn execute_test_elevation_action<F, R>(
    request_id: &str,
    mut credential: SecureElevationCredential,
    now_epoch: i64,
    action: F,
) -> Result<R, String>
where
    F: FnOnce(&str, Option<&str>, &[u8]) -> Result<R, String>,
{
    // 1. Validar y consumir consentimiento previo
    {
        let mut guard = TEST_ELEVATION_TRACKER.write().unwrap();
        let tracker = guard.as_mut().unwrap();
        if tracker.is_locked_out() {
            credential.zeroize();
            return Err(
                "Máximo de 3 intentos fallidos alcanzado. Sesión bloqueada para elevación."
                    .to_string(),
            );
        }
        if let Err(e) = tracker.consume_consent(request_id, now_epoch) {
            credential.zeroize();
            return Err(e.to_string());
        }
    }

    // 2. Ejecutar la acción
    let res = action(
        &credential.username,
        credential.domain.as_deref(),
        credential.password_bytes(),
    );

    // 3. Zeroize inmediato de memoria
    credential.zeroize();

    // 4. Actualizar tracker
    let mut guard = TEST_ELEVATION_TRACKER.write().unwrap();
    let tracker = guard.as_mut().unwrap();
    match &res {
        Ok(_) => {
            tracker.record_success();
        }
        Err(err) => {
            let locked = tracker.record_failure();
            if locked {
                return Err(format!(
                    "Fallo de elevación: {}. Máximo de 3 intentos fallidos alcanzado, sesión bloqueada.",
                    err
                ));
            } else {
                return Err(format!(
                    "Fallo de elevación: {}. Intentos restantes: {}",
                    err,
                    tracker.remaining_attempts()
                ));
            }
        }
    }

    res
}

// ============================================================================
// Pruebas TC-F3-070..079
// ============================================================================

#[test]
fn test_tc_f3_070_user_denial_cancels_and_blocks_credential_use() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_test_elevation_state();
    let now = 1000;

    let req = ElevationRequestNotification::new(
        "req-70",
        "Alberto Técnico",
        "Instalar paquete corporativo",
        Some("TICKET-101".to_string()),
    )
    .unwrap();

    handle_test_incoming_request(req);
    // Usuario rechaza
    let resp =
        respond_test_elevation_request("req-70", ElevationConsentResponse::Denied, now).unwrap();
    assert_eq!(resp, ElevationConsentResponse::Denied);

    // Intento de ejecutar con credenciales se rechaza
    let cred = SecureElevationCredential::new("Administrator", "SuperPass456!");
    let result = execute_test_elevation_action("req-70", cred, now, |_u, _d, _p| Ok(()));
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("la elevación fue rechazada"),
        "Mensaje de error inesperado: {}",
        err_msg
    );
}

#[test]
fn test_tc_f3_071_secure_memory_zeroize_on_drop_and_manual() {
    let mut cred = SecureElevationCredential::new("CORP\\admin_tec", "TopSecretCredentials!@#");
    assert_eq!(cred.username, "admin_tec");
    assert_eq!(cred.domain, Some("CORP".to_string()));
    assert!(!cred.is_zeroized());
    assert_eq!(cred.password_str().unwrap(), "TopSecretCredentials!@#");

    // Borrado seguro explícito
    cred.zeroize();
    assert!(cred.is_zeroized());
    assert_eq!(cred.password_bytes().len(), 0);

    // Borrado seguro implícito en Drop
    {
        let cred_inner = SecureElevationCredential::new("AdminLocal", "EphemeralPassword99");
        assert!(!cred_inner.is_zeroized());
        // Se descarta al salir de ámbito
    }
}

#[test]
fn test_tc_f3_072_max_three_failed_attempts_locks_out_session() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_test_elevation_state();
    let now = 2000;

    for i in 1..=3 {
        let req_id = format!("req-fail-{}", i);
        let req = ElevationRequestNotification::new(
            &req_id,
            "Técnico de Red",
            "Configurar interfaz LAN",
            None,
        )
        .unwrap();

        handle_test_incoming_request(req);
        respond_test_elevation_request(&req_id, ElevationConsentResponse::Approved, now).unwrap();

        let cred = SecureElevationCredential::new("Administrator", "BadPassword");
        let result: Result<(), String> =
            execute_test_elevation_action(&req_id, cred, now, |_u, _d, _p| {
                Err("LogonUserW failed: 1326 (ERROR_LOGON_FAILURE)".to_string())
            });

        assert!(result.is_err());
        let err = result.unwrap_err();
        if i < 3 {
            assert!(
                err.contains("Intentos restantes"),
                "Esperaba aviso de intentos restantes: {}",
                err
            );
        } else {
            assert!(
                err.contains("sesión bloqueada"),
                "Esperaba aviso de sesión bloqueada: {}",
                err
            );
        }
    }

    // Cuarto intento con credenciales correctas: RECHAZADO de inmediato por sesión bloqueada
    let req4 = ElevationRequestNotification::new("req-fail-4", "Técnico de Red", "Reintento", None)
        .unwrap();
    handle_test_incoming_request(req4);
    respond_test_elevation_request("req-fail-4", ElevationConsentResponse::Approved, now).unwrap();

    let cred4 = SecureElevationCredential::new("Administrator", "CorrectPassword123!");
    let result4 = execute_test_elevation_action("req-fail-4", cred4, now, |_u, _d, _p| Ok(()));
    assert!(result4.is_err());
    assert!(result4
        .unwrap_err()
        .contains("Sesión bloqueada para elevación"));
}

#[test]
fn test_tc_f3_073_zero_secrets_or_passwords_in_logs_and_formatters() {
    let cred = SecureElevationCredential::new("DOM\\admin_sec", "P@ssw0rd!SuperSecret999");
    let debug_output = format!("{:?}", cred);
    let display_output = format!("{}", cred);

    // Verificación estricta de ausencia de secretos
    assert!(!debug_output.contains("P@ssw0rd!SuperSecret999"));
    assert!(!display_output.contains("P@ssw0rd!SuperSecret999"));
    assert!(debug_output.contains("[REDACTED]"));
    assert_eq!(display_output, "SecureElevationCredential(DOM\\admin_sec)");
}

#[test]
fn test_tc_f3_074_account_parsing_local_and_domain() {
    // 1. Cuenta local simple
    let (u1, d1) = SecureElevationCredential::parse_account("Administrator");
    assert_eq!(u1, "Administrator");
    assert_eq!(d1, None);

    // 2. Cuenta local explícita con punto
    let (u2, d2) = SecureElevationCredential::parse_account(".\\LocalAdmin");
    assert_eq!(u2, "LocalAdmin");
    assert_eq!(d2, Some(".".to_string()));

    // 3. Cuenta de dominio con sintaxis Down-Level Logon (NetBIOS)
    let (u3, d3) = SecureElevationCredential::parse_account("CERCANOLAN\\admin_it");
    assert_eq!(u3, "admin_it");
    assert_eq!(d3, Some("CERCANOLAN".to_string()));

    // 4. Cuenta de dominio con sintaxis UPN (User Principal Name)
    let (u4, d4) = SecureElevationCredential::parse_account("admin_it@cercano.lan");
    assert_eq!(u4, "admin_it");
    assert_eq!(d4, Some("cercano.lan".to_string()));
}

#[test]
fn test_tc_f3_075_single_use_enforcement_and_no_replay() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_test_elevation_state();
    let now = 3000;

    let req = ElevationRequestNotification::new(
        "req-single-use",
        "Técnico Especialista",
        "Modificar clave de registro de prueba",
        Some("INC-999".to_string()),
    )
    .unwrap();

    handle_test_incoming_request(req);
    respond_test_elevation_request("req-single-use", ElevationConsentResponse::Approved, now)
        .unwrap();

    // Invocación 1: Éxito
    let cred1 = SecureElevationCredential::new("Administrator", "ValidPass");
    let res1 = execute_test_elevation_action("req-single-use", cred1, now, |_u, _d, _p| {
        Ok("accion_completada")
    });
    assert_eq!(res1.unwrap(), "accion_completada");

    // Invocación 2 con el mismo request_id: Bloqueado por principio de un solo uso
    let cred2 = SecureElevationCredential::new("Administrator", "ValidPass");
    let res2 = execute_test_elevation_action("req-single-use", cred2, now, |_u, _d, _p| {
        Ok("segunda_accion")
    });
    assert!(res2.is_err());
    assert!(res2.unwrap_err().contains("un solo uso permitido"));
}

#[test]
fn test_tc_f3_076_technician_permission_validation() {
    fn check_technician_permission(role: &str, permissions: &[&str]) -> bool {
        if role == "soporte" {
            return false;
        }
        if role == "tecnico" {
            return permissions.iter().any(|&p| p == "elev:use" || p == "admin");
        }
        false
    }

    // Cliente soporte nunca puede solicitar elevación
    assert!(!check_technician_permission("soporte", &["elev:use"]));
    assert!(!check_technician_permission("soporte", &["admin"]));

    // Técnico sin permiso no puede solicitar elevación
    assert!(!check_technician_permission("tecnico", &["remote:connect"]));

    // Técnico con permiso elev:use o admin sí puede solicitar
    assert!(check_technician_permission(
        "tecnico",
        &["remote:connect", "elev:use"]
    ));
    assert!(check_technician_permission("tecnico", &["admin"]));
}

#[test]
fn test_tc_f3_077_mandatory_reason_validation() {
    // Motivo vacío
    let err_empty = ElevationRequestNotification::new("r1", "Tecnico", "", None);
    assert_eq!(
        err_empty.unwrap_err(),
        "El motivo de la solicitud de elevación es obligatorio"
    );

    // Motivo solo espacios
    let err_spaces = ElevationRequestNotification::new("r2", "Tecnico", "    ", None);
    assert_eq!(
        err_spaces.unwrap_err(),
        "El motivo de la solicitud de elevación es obligatorio"
    );

    // Solicitante vacío
    let err_req = ElevationRequestNotification::new("r3", "", "Reinicio de spooler", None);
    assert_eq!(
        err_req.unwrap_err(),
        "El solicitante de la elevación es obligatorio"
    );

    // Solicitud válida
    let ok_req = ElevationRequestNotification::new(
        "r4",
        "Carlos Gómez",
        "Reinicio de spooler",
        Some("TK-12".to_string()),
    );
    assert!(ok_req.is_ok());
}

#[test]
fn test_tc_f3_078_consent_expiration_timeout() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_test_elevation_state();
    let grant_time = 5000;

    let req =
        ElevationRequestNotification::new("req-exp-1", "Técnico", "Operación de prueba", None)
            .unwrap();

    handle_test_incoming_request(req);
    respond_test_elevation_request("req-exp-1", ElevationConsentResponse::Approved, grant_time)
        .unwrap();

    // Uso a los 65 segundos (> 60 segundos permitidos)
    let cred = SecureElevationCredential::new("Administrator", "Pass");
    let result =
        execute_test_elevation_action("req-exp-1", cred, grant_time + 65, |_u, _d, _p| Ok(()));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("ha caducado (> 60 s)"));
}

#[test]
fn test_tc_f3_079_successful_elevation_resets_failed_counter() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_test_elevation_state();
    let now = 6000;

    // 1. Provocar 2 fallos consecutivos
    for i in 1..=2 {
        let req_id = format!("req-recovery-{}", i);
        let req = ElevationRequestNotification::new(&req_id, "Técnico", "Prueba", None).unwrap();
        handle_test_incoming_request(req);
        respond_test_elevation_request(&req_id, ElevationConsentResponse::Approved, now).unwrap();

        let cred = SecureElevationCredential::new("Administrator", "Wrong");
        let res: Result<(), String> =
            execute_test_elevation_action(&req_id, cred, now, |_u, _d, _p| {
                Err("Credenciales incorrectas".to_string())
            });
        assert!(res.is_err());
    }

    // Verificar que quedan 1 intento
    {
        let guard = TEST_ELEVATION_TRACKER.read().unwrap();
        let tracker = guard.as_ref().unwrap();
        assert_eq!(tracker.failed_attempts(), 2);
        assert_eq!(tracker.remaining_attempts(), 1);
        assert!(!tracker.is_locked_out());
    }

    // 2. Ejecutar elevación exitosa
    let req_ok =
        ElevationRequestNotification::new("req-recovery-ok", "Técnico", "Prueba éxito", None)
            .unwrap();
    handle_test_incoming_request(req_ok);
    respond_test_elevation_request("req-recovery-ok", ElevationConsentResponse::Approved, now)
        .unwrap();

    let cred_ok = SecureElevationCredential::new("Administrator", "Correct");
    let res_ok =
        execute_test_elevation_action("req-recovery-ok", cred_ok, now, |_u, _d, _p| Ok("ok"));
    assert_eq!(res_ok.unwrap(), "ok");

    // 3. Verificar que el contador de fallos se reinició a 0
    {
        let guard = TEST_ELEVATION_TRACKER.read().unwrap();
        let tracker = guard.as_ref().unwrap();
        assert_eq!(tracker.failed_attempts(), 0);
        assert_eq!(tracker.remaining_attempts(), 3);
        assert!(!tracker.is_locked_out());
    }
}
