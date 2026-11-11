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

//! Pruebas de integración y verificación para auditoría `elev.*` y alarmas de elevación (F3-17).
//!
//! Cubre TC-F3-080 hasta TC-F3-087:
//! - TC-F3-080: Validación de JSON Schema de auditoría contra eventos `elev.*`.
//! - TC-F3-081: Cadena criptográfica SHA-256 inmutable y firmas Ed25519 con eventos mezclados.
//! - TC-F3-082: Inspección exhaustiva de base de datos confirmando política Zero Secrets.
//! - TC-F3-083: Disparo de alarma de ráfaga/frecuencia de elevaciones (`alarm.elev_frequency`).
//! - TC-F3-084: Disparo de alarma de intentos de elevación agotados (`alarm.elev_exhausted`).
//! - TC-F3-085: Disparo de alarma por rechazos consecutivos y reinicio ante aprobación (`alarm.elev_rejections`).
//! - TC-F3-086: Disparo de alarma fuera de horario laboral (`alarm.elev_after_hours`).
//! - TC-F3-087: Evaluación reactiva automática en ingestión (`evaluate_event`).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use uuid::Uuid;

use audit_core::{
    verify_checkpoint, Actor, AuditStore, Category, EventInput, Outcome, Source, Subject,
    GENESIS_HASH,
};
use cercano_api::{
    alarms::{AlarmConfig, AlarmEngine},
    db::init_db,
};

/// Helper que inicializa un `AuditStore` en memoria SQLite para pruebas.
async fn setup_test_audit() -> (sqlx::SqlitePool, Arc<AuditStore>) {
    let db = init_db("sqlite::memory:")
        .await
        .expect("Fallo al inicializar base de datos en memoria");
    let store = Arc::new(
        AuditStore::new(db.clone())
            .await
            .expect("Fallo al inicializar AuditStore"),
    );
    (db, store)
}

/// Valida si una acción cumple con el patrón jerárquico del schema:
/// `^(conn|file|alarm|console|auth|build|chat|elev)(\.[a-z0-9_]+)+$`
fn matches_action_pattern(action: &str) -> bool {
    let allowed_prefixes = [
        "conn", "file", "alarm", "console", "auth", "build", "chat", "elev",
    ];
    if let Some((prefix, rest)) = action.split_once('.') {
        if !allowed_prefixes.contains(&prefix) {
            return false;
        }
        if rest.is_empty() {
            return false;
        }
        for part in rest.split('.') {
            if part.is_empty()
                || !part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                return false;
            }
        }
        true
    } else {
        false
    }
}

// ============================================================================
// TC-F3-080: Validación de JSON Schema contra eventos `elev.*`
// ============================================================================

#[tokio::test]
async fn test_tc_f3_080_schema_validates_elev_events() {
    let schema_str = include_str!("../../../docs/specs/audit-events.schema.json");
    let schema_json: Value =
        serde_json::from_str(schema_str).expect("El schema JSON debe ser válido");

    // 1. Verificar categoría enum
    let categories = schema_json["properties"]["category"]["enum"]
        .as_array()
        .expect("properties.category.enum debe ser un arreglo");
    let category_strings: Vec<&str> = categories.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        category_strings.contains(&"elev"),
        "El enum de category debe incluir 'elev'"
    );
    assert!(
        category_strings.contains(&"conn"),
        "El enum de category debe mantener 'conn'"
    );
    assert!(
        category_strings.contains(&"alarm"),
        "El enum de category debe mantener 'alarm'"
    );

    // 2. Verificar regex del action pattern
    let action_pattern_raw = schema_json["properties"]["action"]["pattern"]
        .as_str()
        .expect("properties.action.pattern debe ser una cadena");
    assert_eq!(
        action_pattern_raw, "^(conn|file|alarm|console|auth|build|chat|elev|db)(\\.[a-z0-9_]+)+$",
        "El patrón de action en el schema debe cubrir elev y las demás categorías"
    );

    let valid_elev_actions = [
        "elev.requested",
        "elev.approved",
        "elev.rejected",
        "elev.submitted",
        "elev.executed",
        "elev.failed",
        "elev.exhausted",
    ];

    for action in &valid_elev_actions {
        assert!(
            matches_action_pattern(action),
            "La acción '{}' debe coincidir con el regex del schema: {}",
            action,
            action_pattern_raw
        );
    }

    // Acciones inválidas deben ser rechazadas por el patrón
    let invalid_actions = [
        "elev",
        "elev.",
        "elev..requested",
        "elev-requested",
        "ELEV.REQUESTED",
        "other.requested",
        "elev.action with spaces",
        "elev.action#symbol",
    ];

    for invalid in &invalid_actions {
        assert!(
            !matches_action_pattern(invalid),
            "La acción inválida '{}' NO debe coincidir con el schema",
            invalid
        );
    }

    // 3. Validar estructuralmente los 7 eventos prototipo
    let (_db, store) = setup_test_audit().await;
    let trace_id = Uuid::now_v7().to_string();

    let prototypes = vec![
        EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.requested",
            Actor::with_details(
                "usr_tech_01",
                "user",
                Some("Técnico Soporte".to_string()),
                Some("192.168.1.100".to_string()),
            ),
            Outcome::Success,
            json!({
                "reason": "Mantenimiento preventivo mensual",
                "ticket": "INC-2026-1001",
                "target_username": "Administrator",
                "target_domain": "CORP"
            }),
        )
        .with_subject(Subject::with_details(
            "dev_client_01",
            "device",
            Some("PC-FINANZAS".to_string()),
        )),
        EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.approved",
            Actor::with_details(
                "usr_local_user",
                "user",
                Some("Usuario Local".to_string()),
                None,
            ),
            Outcome::Success,
            json!({
                "dialog_response": "approved",
                "prompt_duration_ms": 4200
            }),
        )
        .with_subject(Subject::with_details("dev_client_01", "device", None)),
        EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.rejected",
            Actor::with_details(
                "usr_local_user",
                "user",
                Some("Usuario Local".to_string()),
                None,
            ),
            Outcome::Denied,
            json!({
                "dialog_response": "rejected",
                "rejection_reason": "Usuario declinó la elevación"
            }),
        )
        .with_subject(Subject::with_details("dev_client_01", "device", None)),
        EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.submitted",
            Actor::with_details(
                "usr_tech_01",
                "user",
                None,
                Some("192.168.1.100".to_string()),
            ),
            Outcome::Success,
            json!({
                "requester_id": "usr_tech_01",
                "target_username": "Administrator",
                "target_domain": "CORP"
            }),
        )
        .with_subject(Subject::with_details("dev_client_01", "device", None)),
        EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.executed",
            Actor::with_details("usr_tech_01", "user", None, None),
            Outcome::Success,
            json!({
                "target_username": "Administrator",
                "elevation_type": "uac",
                "command": "powershell.exe -ExecutionPolicy Bypass",
                "duration_ms": 1500
            }),
        )
        .with_subject(Subject::with_details("dev_client_01", "device", None)),
        EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.failed",
            Actor::with_details("usr_tech_01", "user", None, None),
            Outcome::Failure,
            json!({
                "target_username": "Administrator",
                "error": "Logon failure: unknown user name or bad password",
                "attempt_number": 1
            }),
        )
        .with_subject(Subject::with_details("dev_client_01", "device", None)),
        EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.exhausted",
            Actor::with_details("usr_tech_01", "user", None, None),
            Outcome::Denied,
            json!({
                "target_username": "Administrator",
                "attempts": 3,
                "lockout_action": "session_elevation_disabled"
            }),
        )
        .with_subject(Subject::with_details("dev_client_01", "device", None)),
    ];

    for input in prototypes {
        let action_name = input.action.clone();
        let appended = store
            .append(input)
            .await
            .expect("Debe insertar evento prototipo");
        assert_eq!(appended.category, Category::Elev);
        assert_eq!(appended.category.as_str(), "elev");
        assert_eq!(appended.action, action_name);
        assert!(!appended.event_id.is_empty());
        assert!(!appended.prev_hash.is_empty());
        assert!(!appended.hash.is_empty());
    }

    let verification = store.verify_chain(None, None).await.unwrap();
    assert!(
        verification.is_valid,
        "Los 7 eventos elev prototipo deben encadenarse válidamente"
    );
    assert_eq!(verification.total_verified, 7);
}

// ============================================================================
// TC-F3-081: Cadena criptográfica con eventos `elev.*` y checkpoints Ed25519
// ============================================================================

#[tokio::test]
async fn test_tc_f3_081_audit_chain_with_elev_events() {
    let (db, store) = setup_test_audit().await;
    let trace_id = Uuid::now_v7().to_string();

    // 1. Insertar secuencia mezclada de eventos heredados (conn) y nuevos (elev)
    let ev1 = store
        .append(EventInput::new(
            &trace_id,
            Source::Client,
            Category::Conn,
            "conn.start",
            Actor::new("tech_alice"),
            Outcome::Success,
            json!({"session_type": "desktop", "client_version": "1.3.0"}),
        ))
        .await
        .unwrap();

    assert_eq!(ev1.sequence, 1);
    assert_eq!(ev1.prev_hash, GENESIS_HASH);

    let ev2 = store
        .append(EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.requested",
            Actor::new("tech_alice"),
            Outcome::Success,
            json!({"reason": "Actualizar driver de pantalla", "ticket": "T-551"}),
        ))
        .await
        .unwrap();

    assert_eq!(ev2.sequence, 2);
    assert_eq!(ev2.prev_hash, ev1.hash);

    let ev3 = store
        .append(EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.approved",
            Actor::new("user_bob"),
            Outcome::Success,
            json!({"dialog_response": "approved"}),
        ))
        .await
        .unwrap();

    assert_eq!(ev3.sequence, 3);
    assert_eq!(ev3.prev_hash, ev2.hash);

    let ev4 = store
        .append(EventInput::new(
            &trace_id,
            Source::Client,
            Category::Elev,
            "elev.executed",
            Actor::new("tech_alice"),
            Outcome::Success,
            json!({"target_username": "Administrator", "duration_ms": 820}),
        ))
        .await
        .unwrap();

    assert_eq!(ev4.sequence, 4);
    assert_eq!(ev4.prev_hash, ev3.hash);

    let ev5 = store
        .append(EventInput::new(
            &trace_id,
            Source::Client,
            Category::Conn,
            "conn.end",
            Actor::new("tech_alice"),
            Outcome::Success,
            json!({"duration_seconds": 120, "close_reason": "user_disconnected"}),
        ))
        .await
        .unwrap();

    assert_eq!(ev5.sequence, 5);
    assert_eq!(ev5.prev_hash, ev4.hash);

    // 2. Verificar integridad total de la cadena en base de datos
    let verification = store.verify_chain(None, None).await.unwrap();
    assert!(
        verification.is_valid,
        "La cadena mezclada debe ser 100% válida"
    );
    assert_eq!(verification.total_verified, 5);
    assert_eq!(verification.first_sequence, Some(1));
    assert_eq!(verification.last_sequence, Some(5));

    // 3. Crear checkpoint firmado con clave Ed25519
    let secret_bytes = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let checkpoint = store
        .create_checkpoint(&signing_key, "key_audit_2026")
        .await
        .unwrap();
    assert_eq!(checkpoint.event_count, 5);
    assert_eq!(checkpoint.last_hash, ev5.hash);

    // Verificar firma criptográfica del checkpoint
    let sig_valid = verify_checkpoint(&verifying_key, &checkpoint).expect("Firma válida");
    assert!(
        sig_valid,
        "La firma Ed25519 del checkpoint debe ser matemáticamente válida"
    );

    // 4. Prueba de inmutabilidad: el trigger de BD bloquea UPDATE
    let blocked_update = sqlx::query(
        "UPDATE audit_events SET details = json('{\"target_username\":\"AttackerRoot\"}') WHERE sequence = 4"
    )
    .execute(&db)
    .await;
    assert!(
        blocked_update.is_err(),
        "La base de datos debe prohibir UPDATE en audit_events por trigger append-only"
    );

    // 5. Prueba de resistencia contra manipulación: alterar 1 byte en ev4 (elev.executed) tras bypass de trigger
    sqlx::query("DROP TRIGGER IF EXISTS trg_audit_events_no_update")
        .execute(&db)
        .await
        .unwrap();

    sqlx::query(
        "UPDATE audit_events SET details = json('{\"target_username\":\"AttackerRoot\",\"duration_ms\":820}') WHERE sequence = 4"
    )
    .execute(&db)
    .await
    .unwrap();

    let tampered_verification = store.verify_chain(None, None).await.unwrap();
    assert!(
        !tampered_verification.is_valid,
        "La verificación debe detectar inmediatamente la manipulación de datos en evento elev.*"
    );
    assert_eq!(tampered_verification.corrupted_sequence(), Some(4));
}

// ============================================================================
// TC-F3-082: Regla de oro Zero Secrets (cero contraseñas ni hashes en elevación)
// ============================================================================

#[tokio::test]
async fn test_tc_f3_082_zero_secrets_in_elev_details() {
    let (db, store) = setup_test_audit().await;
    let trace_id = Uuid::now_v7().to_string();

    // Registrar flujo completo de elevación
    let events_to_record = vec![
        (
            "elev.requested",
            json!({
                "requester_id": "usr_tech_admin",
                "target_username": "AdminLocal",
                "target_domain": "WORKGROUP",
                "reason": "Instalación de software contable",
                "ticket": "TICKET-7788"
            }),
        ),
        (
            "elev.submitted",
            json!({
                "requester_id": "usr_tech_admin",
                "target_username": "AdminLocal",
                "target_domain": "WORKGROUP",
                "transport": "channel_e2e_authenticated",
                "credential_type": "manual_prompt"
            }),
        ),
        (
            "elev.executed",
            json!({
                "target_username": "AdminLocal",
                "elevation_type": "runas",
                "process_id": 4892,
                "duration_ms": 3200
            }),
        ),
        (
            "elev.failed",
            json!({
                "target_username": "AdminLocal",
                "attempt_number": 1,
                "error_code": 1326,
                "error_message": "Logon failure: bad username or password"
            }),
        ),
    ];

    for (action, details) in events_to_record {
        store
            .append(EventInput::new(
                &trace_id,
                Source::Client,
                Category::Elev,
                action,
                Actor::with_details(
                    "usr_tech_admin",
                    "user",
                    Some("Técnico Cercano".to_string()),
                    Some("10.0.0.50".to_string()),
                ),
                if action == "elev.failed" {
                    Outcome::Failure
                } else {
                    Outcome::Success
                },
                details,
            ))
            .await
            .unwrap();
    }

    // Inspección directa y exhaustiva de todas las filas y columnas de la BD
    let rows: Vec<(i64, String, String, String, String, String)> = sqlx::query_as(
        "SELECT sequence, action, category, actor, details, hash FROM audit_events ORDER BY sequence ASC"
    )
    .fetch_all(&db)
    .await
    .unwrap();

    assert_eq!(rows.len(), 4);

    let forbidden_substrings = [
        "password",
        "passwd",
        "contraseña",
        "secret",
        "private_key",
        "argon2",
        "bcrypt",
        "$argon2id$",
        "$2b$",
        "p@ssword",
        "admin123",
        "supersecret",
    ];

    fn assert_no_forbidden_recursively(val: &Value, forbidden: &[&str], path: &str) {
        match val {
            Value::Object(map) => {
                for (k, v) in map {
                    let k_lower = k.to_lowercase();
                    for f in forbidden {
                        assert!(
                            !k_lower.contains(f),
                            "Clave prohibida detectada en {}: '{}'",
                            path,
                            k
                        );
                    }
                    assert_no_forbidden_recursively(v, forbidden, &format!("{}.{}", path, k));
                }
            }
            Value::Array(arr) => {
                for (i, elem) in arr.iter().enumerate() {
                    assert_no_forbidden_recursively(elem, forbidden, &format!("{}[{}]", path, i));
                }
            }
            Value::String(s) => {
                let s_lower = s.to_lowercase();
                for f in forbidden {
                    // Permitir únicamente el mensaje de error del SO "bad username or password"
                    if s.contains("Logon failure: bad username or password") && *f == "password" {
                        continue;
                    }
                    assert!(
                        !s_lower.contains(f),
                        "Contenido secreto/prohibido detectado en {}: '{}' contiene '{}'",
                        path,
                        s,
                        f
                    );
                }
            }
            _ => {}
        }
    }

    for (seq, action, category, actor_raw, details_raw, _hash) in rows {
        assert_eq!(category, "elev");
        let actor_val: Value = serde_json::from_str(&actor_raw).unwrap();
        let details_val: Value = serde_json::from_str(&details_raw).unwrap();

        assert_no_forbidden_recursively(
            &actor_val,
            &forbidden_substrings,
            &format!("seq_{}.actor", seq),
        );
        assert_no_forbidden_recursively(
            &details_val,
            &forbidden_substrings,
            &format!("seq_{}.details({})", seq, action),
        );
    }
}

// ============================================================================
// TC-F3-083: Alarma por frecuencia excesiva de elevaciones (`alarm.elev_frequency`)
// ============================================================================

#[tokio::test]
async fn test_tc_f3_083_alarm_elev_frequency_triggered() {
    let (_db, store) = setup_test_audit().await;
    let config = AlarmConfig {
        elev_frequency_threshold: 3,
        elev_frequency_window_secs: 600, // 10 minutos
        ..Default::default()
    };
    let engine = AlarmEngine::with_config(config, store.clone());

    let tech_id = "usr_tech_frequency_test";
    let target_device = "dev_target_accounting";
    let ip = "10.0.1.25";

    // Intentos 1..3 dentro de la ventana de 10 minutos: no disparan alarma
    for i in 1..=3 {
        let res = engine
            .record_elevation_attempt(tech_id, Some(target_device), Some(ip), None, None)
            .await
            .unwrap();
        assert!(
            res.is_none(),
            "Intento {} no debe disparar la alarma de frecuencia",
            i
        );
    }

    // 4to intento (> 3 en 10 minutos): dispara alarm.elev_frequency
    let alarm = engine
        .record_elevation_attempt(tech_id, Some(target_device), Some(ip), None, None)
        .await
        .unwrap()
        .expect("El 4to intento debe disparar alarm.elev_frequency");

    assert_eq!(alarm.action, "alarm.elev_frequency");
    assert_eq!(alarm.category, Category::Alarm);
    assert_eq!(alarm.actor.id, tech_id);
    assert_eq!(alarm.subject.as_ref().unwrap().id, target_device);
    assert_eq!(alarm.details["severity"], "high");
    assert_eq!(alarm.details["attempts"], 4);
    assert_eq!(alarm.details["threshold"], 3);

    // Verificar que otro técnico independiente NO hereda la frecuencia
    let other_tech_res = engine
        .record_elevation_attempt("usr_other_tech", Some(target_device), Some(ip), None, None)
        .await
        .unwrap();
    assert!(
        other_tech_res.is_none(),
        "Otro técnico no debe disparar alarma en su primer intento"
    );

    // Verificar que la cadena de auditoría permanece válida
    let verification = store.verify_chain(None, None).await.unwrap();
    assert!(
        verification.is_valid,
        "La cadena debe ser válida tras alarma de frecuencia"
    );
}

// ============================================================================
// TC-F3-084: Alarma por intentos fallidos de elevación agotados (`alarm.elev_exhausted`)
// ============================================================================

#[tokio::test]
async fn test_tc_f3_084_alarm_elev_exhausted_triggered() {
    let (_db, store) = setup_test_audit().await;
    let engine = AlarmEngine::new(cercano_api::config::Config::default(), store.clone());

    let tech_id = "usr_tech_exhausted_test";
    let target_device = "dev_target_vault";
    let ip = "192.168.1.80";

    // Disparar alarma de límite alcanzado
    let alarm = engine
        .record_elevation_exhausted(tech_id, Some(target_device), Some(ip), 3, None)
        .await
        .expect("Debe registrar la alarma elev_exhausted");

    assert_eq!(alarm.action, "alarm.elev_exhausted");
    assert_eq!(alarm.category, Category::Alarm);
    assert_eq!(alarm.actor.id, tech_id);
    assert_eq!(alarm.subject.as_ref().unwrap().id, target_device);
    assert_eq!(alarm.details["severity"], "critical");
    assert_eq!(alarm.details["attempts"], 3);
    assert_eq!(
        alarm.details["lockout_action"],
        "session_elevation_disabled"
    );

    // Verificar persistencia en AuditStore y cadena
    let stored = store.get_event_by_id(&alarm.event_id).await.unwrap();
    assert!(
        stored.is_some(),
        "La alarma debe estar guardada en AuditStore"
    );

    let verification = store.verify_chain(None, None).await.unwrap();
    assert!(verification.is_valid);
}

// ============================================================================
// TC-F3-085: Alarma por rechazos consecutivos y reinicio ante aprobación
// ============================================================================

#[tokio::test]
async fn test_tc_f3_085_alarm_elev_rejections_and_approval_reset() {
    let (_db, store) = setup_test_audit().await;
    let config = AlarmConfig {
        elev_rejections_threshold: 2, // Más de 2 rechazos seguidos (a partir del 3ero)
        ..Default::default()
    };
    let engine = AlarmEngine::with_config(config, store.clone());

    let tech_id = "usr_tech_rejections";
    let target_device = "dev_target_pc";

    // Rechazo 1 y 2: sin alarma
    assert!(engine
        .record_elevation_rejection(tech_id, Some(target_device), None, None, Some("Motivo 1"))
        .await
        .unwrap()
        .is_none());

    assert!(engine
        .record_elevation_rejection(tech_id, Some(target_device), None, None, Some("Motivo 2"))
        .await
        .unwrap()
        .is_none());

    // Rechazo 3 (> 2 rechazos consecutivos): dispara alarm.elev_rejections
    let alarm = engine
        .record_elevation_rejection(
            tech_id,
            Some(target_device),
            None,
            None,
            Some("Usuario denegó"),
        )
        .await
        .unwrap()
        .expect("3er rechazo debe disparar alarm.elev_rejections");

    assert_eq!(alarm.action, "alarm.elev_rejections");
    assert_eq!(alarm.details["consecutive_rejections"], 3);
    assert_eq!(alarm.details["severity"], "high");

    // Una aprobación posterior reinicia el contador
    engine.record_elevation_approval(tech_id, Some(target_device));

    // El siguiente rechazo vuelve a ser el primero (no dispara)
    assert!(engine
        .record_elevation_rejection(
            tech_id,
            Some(target_device),
            None,
            None,
            Some("Nuevo rechazo")
        )
        .await
        .unwrap()
        .is_none());
}

// ============================================================================
// TC-F3-086: Alarma por elevación fuera de horario laboral (`alarm.elev_after_hours`)
// ============================================================================

#[tokio::test]
async fn test_tc_f3_086_alarm_elev_after_hours() {
    let (_db, store) = setup_test_audit().await;
    let config = AlarmConfig {
        elev_after_hours_enabled: true,
        elev_business_hours_start: 8, // 08:00 UTC
        elev_business_hours_end: 18,  // 18:00 UTC
        elev_weekends_are_after_hours: true,
        ..Default::default()
    };
    let engine = AlarmEngine::with_config(config, store.clone());

    let tech_id = "usr_tech_night";
    let target_device = "dev_client_01";

    // 1. Operación durante horario laboral (Martes 10:00 UTC): sin alarma
    let workday_noon: DateTime<Utc> = "2026-11-10T10:00:00Z".parse().unwrap();
    let res_day = engine
        .check_elevation_after_hours(
            tech_id,
            "elev.requested",
            Some(target_device),
            None,
            Some(workday_noon),
            None,
        )
        .await
        .unwrap();
    assert!(
        res_day.is_none(),
        "Elevación en horario laboral no debe alertar"
    );

    // 2. Operación nocturna (Martes 22:30 UTC): dispara alarm.elev_after_hours
    let workday_night: DateTime<Utc> = "2026-11-10T22:30:00Z".parse().unwrap();
    let alarm_night = engine
        .check_elevation_after_hours(
            tech_id,
            "elev.executed",
            Some(target_device),
            Some("10.0.0.1"),
            Some(workday_night),
            None,
        )
        .await
        .unwrap()
        .expect("Elevación nocturna debe disparar alarm.elev_after_hours");

    assert_eq!(alarm_night.action, "alarm.elev_after_hours");
    assert_eq!(alarm_night.details["action"], "elev.executed");
    assert_eq!(alarm_night.details["severity"], "medium");

    // 3. Operación en fin de semana (Domingo 14:00 UTC): dispara alarm.elev_after_hours
    let weekend_dt: DateTime<Utc> = "2026-11-15T14:00:00Z".parse().unwrap();
    let alarm_weekend = engine
        .check_elevation_after_hours(
            tech_id,
            "elev.requested",
            Some(target_device),
            None,
            Some(weekend_dt),
            None,
        )
        .await
        .unwrap()
        .expect("Elevación en fin de semana debe disparar alarm.elev_after_hours");

    assert_eq!(alarm_weekend.action, "alarm.elev_after_hours");
}

// ============================================================================
// TC-F3-087: Evaluación reactiva automática en ingestión (`evaluate_event`)
// ============================================================================

#[tokio::test]
async fn test_tc_f3_087_evaluate_event_ingestion_dispatches_elev_alarms() {
    let (_db, store) = setup_test_audit().await;
    let config = AlarmConfig {
        elev_frequency_threshold: 2,
        elev_rejections_threshold: 1,
        elev_after_hours_enabled: true,
        elev_business_hours_start: 8,
        elev_business_hours_end: 18,
        ..Default::default()
    };
    let engine = AlarmEngine::with_config(config, store.clone());

    let trace_id = Uuid::now_v7().to_string();

    // 1. Ingestar evento elev.exhausted -> debe generar alarma automáticamente
    let exhausted_event = store
        .append(
            EventInput::new(
                &trace_id,
                Source::Client,
                Category::Elev,
                "elev.exhausted",
                Actor::new("usr_eval_tech"),
                Outcome::Denied,
                json!({"attempts": 3, "target_username": "Admin"}),
            )
            .with_subject(Subject::new("dev_target")),
        )
        .await
        .unwrap();

    let alarms = engine.evaluate_event(&exhausted_event).await.unwrap();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].action, "alarm.elev_exhausted");

    // 2. Ingestar evento elev.requested en fin de semana -> debe generar alarm.elev_after_hours
    let mut weekend_input = EventInput::new(
        &trace_id,
        Source::Client,
        Category::Elev,
        "elev.requested",
        Actor::new("usr_eval_tech"),
        Outcome::Success,
        json!({"reason": "Soporte fin de semana"}),
    );
    weekend_input.ts = Some("2026-11-15T10:00:00Z".to_string()); // Domingo

    let weekend_event = store.append(weekend_input).await.unwrap();
    let alarms_weekend = engine.evaluate_event(&weekend_event).await.unwrap();
    assert!(
        alarms_weekend
            .iter()
            .any(|a| a.action == "alarm.elev_after_hours"),
        "evaluate_event debe disparar alarm.elev_after_hours"
    );

    // 3. Cadena completa intacta y verificada
    let verification = store.verify_chain(None, None).await.unwrap();
    assert!(verification.is_valid);
}
