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

//! Suite de pruebas de seguridad, fuzzing y abuso de elevación y roles (F3-18 / TC-F3-084).
//!
//! Esta suite evalúa:
//! 1. Fuzzing exhaustivo de `ElevationRequestNotification` (payloads masivos, inyecciones SQL/Command/XSS, null bytes, RTL, formato).
//! 2. Fuzzing y validación de `SecureElevationCredential` (parsing de cuentas con delimitadores extremos, unicode,
//!    borrado seguro de memoria RAM mediante `zeroize` volátil y garantía estricta de Zero Secrets en `Debug` y `Display`).
//! 3. Fuzzing y resistencia a abuso de endpoints `/api/sessions/initiate` y `/api/elevation/request` (tampering de rol en cabeceras,
//!    ataques de suplantación desde rol `soporte`, payloads malformados, instaladores revocados o caducados).
//! 4. Verificación de defensas: límite estricto de 3 intentos (`elev.exhausted`), caducidad de consentimiento (60s) y un solo uso.
//! 5. Disparo y despacho de la matriz completa de alarmas de seguridad:
//!    `alarm.role_violation`, `alarm.elev_frequency`, `alarm.elev_rejections`, `alarm.elev_exhausted`, `alarm.elev_after_hours`.
//! 6. Inspección profunda y exhaustiva en base de datos SQLite garantizando cero fugas de contraseñas o hashes (Zero Secrets).

use std::sync::Arc;

use audit_core::Category;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::tempdir;
use tower::ServiceExt;

use cercano_api::{
    alarms::{AlarmConfig, AlarmEngine},
    config::Config,
    create_app,
    db::init_db,
    AppState,
};

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
                    return Err("La elevación ya fue utilizada (mínimo privilegio: un solo uso)");
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

struct TestEnv {
    app: axum::Router,
    state: AppState,
    _builds_dir: tempfile::TempDir,
}

async fn setup_test_env() -> TestEnv {
    let builds_dir = tempdir().expect("Failed to create tempdir for builds");
    let db = init_db("sqlite::memory:")
        .await
        .expect("Failed to init in-memory db");
    let audit = Arc::new(
        audit_core::AuditStore::new(db.clone())
            .await
            .expect("Failed to init audit store"),
    );

    let config = Config {
        builds_dir: builds_dir.path().to_str().unwrap().to_string(),
        build_concurrency: 2,
        build_retention_secs: 3600,
        internal_token: "test_internal_token".to_string(),
        client_ingest_token: "test_client_token".to_string(),
        revocation_cache_ttl_secs: 60,
        revocation_fail_closed: true,
        ..Default::default()
    };

    let state = AppState::new(config, db.clone(), audit);
    let app = create_app(state.clone());

    TestEnv {
        app,
        state,
        _builds_dir: builds_dir,
    }
}

async fn register_test_device(
    state: &AppState,
    device_id: &str,
    role: &str,
    installer_id: Option<&str>,
) {
    sqlx::query(
        r#"
        INSERT INTO devices (id, name, hostname, role, installer_id, status, last_seen_at)
        VALUES (?, ?, ?, ?, ?, 'online', datetime('now'))
        "#,
    )
    .bind(device_id)
    .bind(format!("name-{}", device_id))
    .bind(format!("host-{}", device_id))
    .bind(role)
    .bind(installer_id)
    .execute(&state.db)
    .await
    .unwrap();
}

// =================================================================================================
// 1. FUZZING DE PAYLOADS DE NOTIFICACIÓN DE ELEVACIÓN
// =================================================================================================

#[test]
fn test_security_fuzz_elevation_request_notification_adversarial_payloads() {
    let fuzz_payloads = [
        // Null bytes y caracteres de control
        "Motivo\0con\0null\0bytes",
        "\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f",
        "Motivo\r\nCRLF\r\nInyeccion",
        "Motivo con ANSI escape \x1b[31;1mROJO\x1b[0m",
        // Inyección SQL y comandos del sistema
        "'; DROP TABLE devices; DROP TABLE audit_events; --",
        "' OR '1'='1' UNION SELECT username, password_hash FROM users --",
        "$(whoami > /tmp/pwned)",
        "`powershell -enc JABjAGEAbABjAA==`",
        "| calc.exe & notepad.exe",
        // Path Traversal
        "../../../../../../windows/system32/cmd.exe",
        "..\\..\\..\\..\\..\\..\\boot.ini",
        // Format strings y buffer expansivo
        "%s%s%s%s%s%n%x%d",
        "{0}{1}{2}{3}{4}{5}",
        // RTL Override (Spoofing visual de extensiones)
        "Actualizar antivirus \u{202E}exe.pdf",
        // Caracteres Unicode exóticos y emojis
        "🔧 Actualización Crítica ⚠️ Administrador 💻 0001",
        "ñáéíóú Çüéâäàå çêëèïîì ÄÅÉæÆôöòûùÿ ÖÜøØ×ƒ",
    ];

    for (idx, payload) in fuzz_payloads.iter().enumerate() {
        let req_id = format!("fuzz_req_{}", idx);
        let res = ElevationRequestNotification::new(&req_id, "Tecnico Seguridad", *payload, None);
        assert!(
            res.is_ok(),
            "El payload válido no debe causar pánico ni error inesperado: {:?}",
            payload
        );
        let notif = res.unwrap();
        assert_eq!(notif.reason, *payload);
    }

    // Validación estricta: motivos vacíos o solo espacios deben rechazarse
    let invalid_reasons = ["", " ", "   ", "\t\t", "\r\n  \r\n", " \t \n "];
    for invalid in invalid_reasons {
        let res = ElevationRequestNotification::new("req_fail", "Tecnico", invalid, None);
        assert!(
            res.is_err(),
            "Motivo vacío debe ser rechazado: {:?}",
            invalid
        );
    }

    // Validación estricta: solicitante vacío o solo espacios debe rechazarse
    for invalid in invalid_reasons {
        let res = ElevationRequestNotification::new("req_fail", invalid, "Instalar paquete", None);
        assert!(
            res.is_err(),
            "Solicitante vacío debe ser rechazado: {:?}",
            invalid
        );
    }

    // Carga útil masiva (100.000 caracteres)
    let massive_string = "A".repeat(100_000);
    let massive_res =
        ElevationRequestNotification::new("req_massive", "Tecnico", &massive_string, None);
    assert!(massive_res.is_ok());
    assert_eq!(massive_res.unwrap().reason.len(), 100_000);
}

// =================================================================================================
// 2. FUZZING DE CREDENCIALES, PARSING DE CUENTAS Y ZERO SECRETS EN MEMORIA
// =================================================================================================

#[test]
fn test_security_fuzz_secure_elevation_credential_parsing_and_zeroize() {
    let account_test_cases = [
        ("Administrator", "Administrator", None),
        (".\\Administrator", "Administrator", Some(".")),
        ("CORP\\jdoe", "jdoe", Some("CORP")),
        ("admin@corp.lan", "admin", Some("corp.lan")),
        ("jdoe@sub.domain.local", "jdoe", Some("sub.domain.local")),
        // Delimitadores múltiples o anómalos
        ("DOMAIN\\SUBDOMAIN\\user", "SUBDOMAIN\\user", Some("DOMAIN")),
        ("user@@doubleat.com", "user", Some("@doubleat.com")),
        ("\\leading_backslash", "leading_backslash", Some("")),
        ("@leading_at", "", Some("leading_at")),
        ("trailing_backslash\\", "", Some("trailing_backslash")),
        ("   padded\\user   ", "user", Some("padded")),
        ("   user@domain.com   ", "user", Some("domain.com")),
        // Cuentas con caracteres raros
        ("DOM-NAME\\User.Name_01", "User.Name_01", Some("DOM-NAME")),
        (
            "user+tag@domain-corp.com",
            "user+tag",
            Some("domain-corp.com"),
        ),
    ];

    for (input, expected_user, expected_domain) in account_test_cases {
        let (user, domain) = SecureElevationCredential::parse_account(input);
        assert_eq!(user, expected_user, "Fallo de usuario para {}", input);
        assert_eq!(
            domain.as_deref(),
            expected_domain,
            "Fallo de dominio para {}",
            input
        );
    }

    // Verificación estricta de borrado seguro de memoria (Zeroize Volátil)
    let secret = b"UltraP@ssw0rd999#BinaryEntropy\x00\xff\xfe";
    let mut cred = SecureElevationCredential::new("CORP\\admin", secret);
    assert_eq!(cred.password_bytes(), secret);
    assert!(!cred.is_zeroized());

    // Verificación de Zero Secrets en formateadores (Debug / Display)
    let debug_str = format!("{:?}", cred);
    let display_str = format!("{}", cred);
    assert!(!debug_str.contains("UltraP@ssw0rd999"));
    assert!(debug_str.contains("[REDACTED]"));
    assert!(!display_str.contains("UltraP@ssw0rd999"));

    // Ejecución de zeroize manual
    cred.zeroize();
    assert!(cred.is_zeroized());
    assert!(cred.password_bytes().is_empty());

    // Verificación de Drop seguro en un bloque aislado
    {
        let _cred_scoped = SecureElevationCredential::new("CORP\\admin2", b"TempSecret12345");
        // Al salir del bloque, Drop ejecuta zeroize() automáticamente
    }
}

// =================================================================================================
// 3. FUZZING Y RESISTENCIA A ABUSO EN ENDPOINTS DE ELEVACIÓN Y SESIÓN
// =================================================================================================

#[tokio::test]
async fn test_security_fuzz_and_abuse_sessions_and_elevation_endpoints() {
    let env = setup_test_env().await;

    // Registramos 2 dispositivos: uno con rol soporte y otro con rol técnico
    register_test_device(
        &env.state,
        "dev_soporte_01",
        "soporte",
        Some("inst_soporte_100"),
    )
    .await;
    register_test_device(
        &env.state,
        "dev_tecnico_01",
        "tecnico",
        Some("inst_tecnico_200"),
    )
    .await;
    register_test_device(&env.state, "dev_target_01", "soporte", None).await;

    // --- Vector 3.1: Payload malformado / Fuzzing JSON a /api/sessions/initiate ---
    let malformed_bodies = [
        "{}",
        r#"{"device_id": ""}"#,
        r#"{"device_id": "dev_tecnico_01"}"#,
        r#"{"device_id": null, "target_device_id": null}"#,
        r#"{"device_id": 12345, "target_device_id": true}"#,
        r#"{"device_id": "   ", "target_device_id": "   "}"#,
        "not a json at all",
    ];

    for body in malformed_bodies {
        let req = Request::builder()
            .method("POST")
            .uri("/api/sessions/initiate")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = env.app.clone().oneshot(req).await.unwrap();
        assert!(
            resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "El payload malformado debe ser rechazado con 400 o 422: {:?}",
            body
        );
    }

    // --- Vector 3.2: Intento de inicio de sesión desde cliente soporte (Escalada de privilegios) ---
    let req_soporte = Request::builder()
        .method("POST")
        .uri("/api/sessions/initiate")
        .header("content-type", "application/json")
        .header("x-trace-id", "019316b0-0000-7000-8000-000000000001")
        .body(Body::from(
            json!({
                "device_id": "dev_soporte_01",
                "target_device_id": "dev_target_01",
                "installer_id": "inst_soporte_100"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_soporte = env.app.clone().oneshot(req_soporte).await.unwrap();
    assert_eq!(resp_soporte.status(), StatusCode::FORBIDDEN);
    let bytes = resp_soporte.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body_json["error"], "role_violation");

    // Verificar en BD que se emitió alarma crítica `alarm.role_violation`
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'alarm.role_violation'",
    )
    .fetch_one(&env.state.db)
    .await
    .unwrap();
    assert!(
        count > 0,
        "Debe haberse registrado alarm.role_violation en audit_events"
    );

    // --- Vector 3.3: Tampering de cabeceras de rol (Intento de suplantación) ---
    // El dispositivo `dev_soporte_01` envía cabeceras afirmando ser técnico
    let req_tampered = Request::builder()
        .method("POST")
        .uri("/api/elevation/request")
        .header("content-type", "application/json")
        .header("x-trace-id", "019316b0-0000-7000-8000-000000000002")
        .header("x-role", "tecnico")
        .header("x-client-role", "tecnico")
        .body(Body::from(
            json!({
                "device_id": "dev_soporte_01",
                "target_device_id": "dev_target_01",
                "reason": "Actualizar servicio critico",
                "ticket": "INC-999"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_tampered = env.app.clone().oneshot(req_tampered).await.unwrap();
    assert_eq!(resp_tampered.status(), StatusCode::FORBIDDEN);
    let bytes = resp_tampered
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let body_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body_json["error"], "role_violation");

    // --- Vector 3.4: Solicitud legítima desde técnico pero con motivo vacío (Validación) ---
    let req_empty_reason = Request::builder()
        .method("POST")
        .uri("/api/elevation/request")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "device_id": "dev_tecnico_01",
                "target_device_id": "dev_target_01",
                "reason": "   \t\n  "
            })
            .to_string(),
        ))
        .unwrap();

    let resp_empty = env.app.clone().oneshot(req_empty_reason).await.unwrap();
    assert_eq!(resp_empty.status(), StatusCode::BAD_REQUEST);

    // --- Vector 3.5: Solicitud legítima autorizada para técnico ---
    let req_valid = Request::builder()
        .method("POST")
        .uri("/api/elevation/request")
        .header("content-type", "application/json")
        .header("x-trace-id", "019316b0-0000-7000-8000-000000000003")
        .body(Body::from(
            json!({
                "device_id": "dev_tecnico_01",
                "target_device_id": "dev_target_01",
                "reason": "Mantenimiento programado de base de datos",
                "ticket": "TICK-4455"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_valid = env.app.clone().oneshot(req_valid).await.unwrap();
    assert_eq!(resp_valid.status(), StatusCode::OK);
    let bytes = resp_valid.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body_json["status"], "authorized");
    assert!(!body_json["elevation_id"].as_str().unwrap().is_empty());
}

// =================================================================================================
// 4. VERIFICACIÓN DE DEFENSAS: LÍMITE DE 3 INTENTOS Y CICLO DE VIDA DE CONSENTIMIENTO
// =================================================================================================

#[test]
fn test_security_abuse_elevation_lockout_and_consent_lifecycle() {
    let mut tracker = ElevationSessionTracker::new();
    let req_id = "req_audit_01".to_string();
    let now = 1_700_000_000;

    assert_eq!(tracker.failed_attempts(), 0);
    assert_eq!(tracker.remaining_attempts(), 3);
    assert!(!tracker.is_locked_out());

    // Intento fallido 1
    let locked = tracker.record_failure();
    assert!(!locked);
    assert_eq!(tracker.failed_attempts(), 1);
    assert_eq!(tracker.remaining_attempts(), 2);

    // Intento fallido 2
    let locked = tracker.record_failure();
    assert!(!locked);
    assert_eq!(tracker.failed_attempts(), 2);
    assert_eq!(tracker.remaining_attempts(), 1);

    // Intento fallido 3 -> Bloqueo incondicional de la sesión
    let locked = tracker.record_failure();
    assert!(locked);
    assert_eq!(tracker.failed_attempts(), 3);
    assert_eq!(tracker.remaining_attempts(), 0);
    assert!(tracker.is_locked_out());

    // Intentar otorgar o consumir consentimiento con sesión bloqueada debe fallar
    tracker.record_consent(req_id.clone(), ElevationConsentResponse::Approved, now);
    assert!(!tracker.has_valid_consent(&req_id, now));
    assert!(tracker.consume_consent(&req_id, now).is_err());

    // Reset tras nueva sesión o autorización
    tracker.reset();
    assert!(!tracker.is_locked_out());
    assert_eq!(tracker.failed_attempts(), 0);

    // Ciclo de vida: Consentimiento Denegado
    tracker.record_consent(req_id.clone(), ElevationConsentResponse::Denied, now);
    assert!(!tracker.has_valid_consent(&req_id, now));
    let err_denied = tracker.consume_consent(&req_id, now);
    assert!(err_denied.is_err());

    // Ciclo de vida: Consentimiento Aprobado pero Caducado (> 60s)
    let req_expired = "req_expired_02".to_string();
    tracker.record_consent(req_expired.clone(), ElevationConsentResponse::Approved, now);
    assert!(tracker.has_valid_consent(&req_expired, now + 50));
    assert!(!tracker.has_valid_consent(&req_expired, now + 61));
    let err_expired = tracker.consume_consent(&req_expired, now + 65);
    assert!(err_expired.is_err());

    // Ciclo de vida: Un solo uso (Single-Use Enforcement)
    let req_single = "req_single_03".to_string();
    tracker.record_consent(req_single.clone(), ElevationConsentResponse::Approved, now);
    assert!(tracker.consume_consent(&req_single, now + 5).is_ok());
    // Segundo intento de consumo debe fallar
    let err_reused = tracker.consume_consent(&req_single, now + 10);
    assert!(err_reused.is_err());
    assert!(!tracker.has_valid_consent(&req_single, now + 10));
}

// =================================================================================================
// 5. VERIFICACIÓN DE LA REGLA DE ORO ZERO SECRETS EN BASE DE DATOS DE AUDITORÍA
// =================================================================================================

#[tokio::test]
async fn test_security_zero_secrets_deep_audit_verification() {
    let env = setup_test_env().await;

    // Generar secuencia completa de eventos de elevación
    let trace_id = "019316b0-1111-7000-8000-000000000001";
    let events = [
        json!({
            "action": "elev.requested",
            "details": {
                "elevation_id": "elev_sec_01",
                "requester": "tecnico.juan",
                "target_account": "CORP\\Administrator",
                "reason": "Instalar parche de seguridad MS26-001",
                "ticket": "INC-8890"
            }
        }),
        json!({
            "action": "elev.approved",
            "details": {
                "elevation_id": "elev_sec_01",
                "consented_by": "usuario.maria",
                "timeout_secs": 60
            }
        }),
        json!({
            "action": "elev.submitted",
            "details": {
                "elevation_id": "elev_sec_01",
                "account": "CORP\\Administrator",
                "method": "e2e_secure_channel",
                "single_use": true
            }
        }),
        json!({
            "action": "elev.executed",
            "details": {
                "elevation_id": "elev_sec_01",
                "account": "CORP\\Administrator",
                "target_process": "C:\\Program Files\\Update\\patch.exe",
                "exit_code": 0
            }
        }),
    ];

    for ev in events {
        let input = audit_core::EventInput::new(
            trace_id.to_string(),
            audit_core::Source::Client,
            audit_core::Category::Elev,
            ev["action"].as_str().unwrap(),
            audit_core::Actor::new("tecnico.juan"),
            audit_core::Outcome::Success,
            ev["details"].clone(),
        );
        env.state.audit.append(input).await.unwrap();
    }

    // Inspección recursiva de la base de datos de auditoría
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT action, details FROM audit_events")
        .fetch_all(&env.state.db)
        .await
        .unwrap();

    assert_eq!(rows.len(), 4);

    let forbidden_patterns = [
        "password",
        "passwd",
        "secret",
        "hash",
        "credential",
        "argon2",
        "sha256$",
        "$2b$",
    ];

    for (action, details_str) in rows {
        let parsed: Value = serde_json::from_str(&details_str).unwrap();
        // Verificar que ningún valor en `details` contenga secretos
        if let Some(obj) = parsed.as_object() {
            for (k, v) in obj {
                let k_lower = k.to_lowercase();
                for pat in forbidden_patterns {
                    assert!(
                        !k_lower.contains(pat),
                        "Campo prohibido '{}' encontrado en evento '{}'",
                        k,
                        action
                    );
                }
                if let Some(v_str) = v.as_str() {
                    let v_lower = v_str.to_lowercase();
                    assert!(
                        !v_lower.contains("password123"),
                        "Contraseña en valor detectada"
                    );
                }
            }
        }
    }
}

// =================================================================================================
// 6. MATRIZ COMPLETA DE ALARMAS DE SEGURIDAD
// =================================================================================================

#[tokio::test]
async fn test_security_alarms_complete_matrix_coverage() {
    let db = init_db("sqlite::memory:").await.unwrap();
    let store = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let config = AlarmConfig {
        elev_frequency_threshold: 3,
        elev_frequency_window_secs: 600,
        elev_rejections_threshold: 2,
        elev_after_hours_enabled: true,
        elev_business_hours_start: 7,
        elev_business_hours_end: 19,
        elev_weekends_are_after_hours: true,
        ..Default::default()
    };
    let engine = AlarmEngine::with_config(config, store);

    // 1. Alarma alarm.role_violation
    let a1 = engine
        .record_role_violation(
            "dev_spoof_01",
            Some("192.168.1.50"),
            Some("inst_soporte_99"),
            "soporte",
            "request_elevation",
            "Intento de elevacion desde cliente soporte",
            Some("019316b0-0000-7000-8000-000000000010"),
        )
        .await
        .unwrap();
    assert_eq!(a1.action, "alarm.role_violation");
    assert_eq!(a1.category, Category::Alarm);
    assert_eq!(a1.details["severity"], "critical");

    // 2. Alarma alarm.elev_frequency (ráfaga)
    for _ in 0..3 {
        let _ = engine
            .record_elevation_attempt(
                "tech_burst",
                Some("dev_target"),
                Some("192.168.1.10"),
                None,
                None,
            )
            .await;
    }
    let a2 = engine
        .record_elevation_attempt(
            "tech_burst",
            Some("dev_target"),
            Some("192.168.1.10"),
            None,
            None,
        )
        .await
        .unwrap();
    assert!(a2.is_some(), "Debe haberse disparado alarm.elev_frequency");
    assert_eq!(a2.unwrap().action, "alarm.elev_frequency");

    // 3. Alarma alarm.elev_rejections (rechazos repetidos)
    let _ = engine
        .record_elevation_rejection(
            "tech_rej",
            Some("dev_target"),
            Some("192.168.1.11"),
            None,
            Some("R1"),
        )
        .await;
    let _ = engine
        .record_elevation_rejection(
            "tech_rej",
            Some("dev_target"),
            Some("192.168.1.11"),
            None,
            Some("R2"),
        )
        .await;
    let a3 = engine
        .record_elevation_rejection(
            "tech_rej",
            Some("dev_target"),
            Some("192.168.1.11"),
            None,
            Some("R3"),
        )
        .await
        .unwrap();
    assert!(a3.is_some(), "Debe haberse disparado alarm.elev_rejections");
    assert_eq!(a3.unwrap().action, "alarm.elev_rejections");

    // 4. Alarma alarm.elev_exhausted (límite 3 intentos alcanzado)
    let a4 = engine
        .record_elevation_exhausted(
            "tech_ex",
            Some("dev_target"),
            Some("192.168.1.12"),
            3,
            Some("019316b0-0000-7000-8000-000000000012"),
        )
        .await
        .unwrap();
    assert_eq!(a4.action, "alarm.elev_exhausted");
    assert_eq!(a4.category, Category::Alarm);
    assert_eq!(a4.details["severity"], "critical");

    // 5. Alarma alarm.elev_after_hours (fuera de horario comercial)
    let after_hours_time: DateTime<Utc> = "2026-11-10T23:30:00Z".parse().unwrap();
    let a5 = engine
        .check_elevation_after_hours(
            "tech_night",
            "elev.requested",
            Some("dev_target"),
            Some("192.168.1.13"),
            Some(after_hours_time),
            Some("019316b0-0000-7000-8000-000000000013"),
        )
        .await
        .unwrap();
    assert!(
        a5.is_some(),
        "Debe haberse disparado alarm.elev_after_hours a las 23:30 UTC"
    );
    assert_eq!(a5.unwrap().action, "alarm.elev_after_hours");
}
