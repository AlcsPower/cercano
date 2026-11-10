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

use std::sync::Arc;

use audit_core::{Category, EventFilter, Outcome};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::tempdir;
use tower::ServiceExt;
use uuid::Uuid;

use cercano_api::{config::Config, create_app, db::init_db, AppState};

struct TestEnv {
    app: axum::Router,
    state: AppState,
    _builds_dir: tempfile::TempDir,
    _admin_token: String,
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

    // Create admin user and session
    let admin_id = "admin_user".to_string();
    let admin_token = format!("tok_admin_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'admin_roles', 'hash', 'admin', 1)",
    )
    .bind(&admin_id)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))",
    )
    .bind(&admin_token)
    .bind(&admin_id)
    .execute(&db)
    .await
    .unwrap();

    TestEnv {
        app,
        state,
        _builds_dir: builds_dir,
        _admin_token: admin_token,
    }
}

async fn insert_build_job(
    state: &AppState,
    job_id: &str,
    role: &str,
    profile_id: &str,
    status: &str,
) {
    sqlx::query(
        r#"
        INSERT INTO build_jobs (id, user_id, role, profile_id, status, created_at)
        VALUES (?, 'admin_user', ?, ?, ?, datetime('now'))
        "#,
    )
    .bind(job_id)
    .bind(role)
    .bind(profile_id)
    .bind(status)
    .execute(&state.db)
    .await
    .unwrap();
}

async fn register_device_via_heartbeat(
    app: &axum::Router,
    device_id: &str,
    installer_id: Option<&str>,
    role_header: Option<&str>,
) -> (StatusCode, Value) {
    let mut req_builder = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json");

    if let Some(h) = role_header {
        req_builder = req_builder.header("x-client-role", h);
    }
    if let Some(inst) = installer_id {
        req_builder = req_builder.header("x-installer-id", inst);
    }

    let payload = json!({
        "id": device_id,
        "name": format!("Device-{}", device_id),
        "hostname": format!("host-{}", device_id),
        "os": "Windows 11 Pro",
        "version": "0.1.0",
        "ip": "192.168.1.100",
        "installer_id": installer_id
    });

    let req = req_builder
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// TC-F3-060: intento de cliente `soporte` de iniciar conexión remota retorna 403 y dispara `alarm.role_violation`.
#[tokio::test]
async fn test_tc_f3_060_soporte_cannot_initiate_connection() {
    let env = setup_test_env().await;

    // 1. Crear instalador soporte en build_jobs
    let inst_id = "inst-soporte-tc060";
    insert_build_job(&env.state, inst_id, "soporte", "prof-soporte", "completed").await;

    // 2. Registrar cliente con el instalador soporte
    let dev_id = "client-soporte-060";
    let (reg_status, reg_body) =
        register_device_via_heartbeat(&env.app, dev_id, Some(inst_id), None).await;
    assert_eq!(reg_status, StatusCode::OK);
    assert_eq!(reg_body["role"], "soporte");

    // 3. Intentar iniciar conexión remota saliente desde el cliente soporte
    let initiate_payload = json!({
        "device_id": dev_id,
        "target_device_id": "target-remote-pc",
        "installer_id": inst_id,
        "connection_type": "remote_desktop"
    });

    let req = Request::builder()
        .uri("/api/sessions/initiate")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&initiate_payload).unwrap()))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "role_violation");

    // 4. Verificar que se disparó la alarma crítica alarm.role_violation
    let alarms = env
        .state
        .audit
        .query_events(EventFilter {
            category: Some(Category::Alarm),
            action: Some("alarm.role_violation".to_string()),
            actor_id: Some(dev_id.to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        alarms.len(),
        1,
        "Debe registrarse exactamente 1 alarma role_violation"
    );
    assert_eq!(alarms[0].details["alarm_name"], "alarm.role_violation");
    assert_eq!(alarms[0].details["severity"], "critical");
    assert_eq!(alarms[0].outcome, Outcome::Denied);
}

/// TC-F3-061: cliente `tecnico` autorizado procede exitosamente al iniciar conexión remota.
#[tokio::test]
async fn test_tc_f3_061_tecnico_can_initiate_connection() {
    let env = setup_test_env().await;

    // 1. Crear instalador técnico en build_jobs
    let inst_id = "inst-tecnico-tc061";
    insert_build_job(&env.state, inst_id, "tecnico", "prof-tecnico", "completed").await;

    // 2. Registrar cliente con el instalador técnico
    let dev_id = "client-tecnico-061";
    let (reg_status, reg_body) =
        register_device_via_heartbeat(&env.app, dev_id, Some(inst_id), None).await;
    assert_eq!(reg_status, StatusCode::OK);
    assert_eq!(reg_body["role"], "tecnico");

    // 3. Iniciar conexión remota saliente
    let initiate_payload = json!({
        "device_id": dev_id,
        "target_device_id": "target-client-pc",
        "installer_id": inst_id,
        "connection_type": "remote_desktop"
    });

    let req = Request::builder()
        .uri("/api/sessions/initiate")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&initiate_payload).unwrap()))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "success");
    assert!(body["session_id"].as_str().is_some());
    assert_eq!(body["source_device_id"], dev_id);
    assert_eq!(body["target_device_id"], "target-client-pc");

    // 4. Verificar que quedó registrado el evento conn.session_initiated exitoso
    let conn_events = env
        .state
        .audit
        .query_events(EventFilter {
            category: Some(Category::Conn),
            action: Some("conn.session_initiated".to_string()),
            actor_id: Some(dev_id.to_string()),
            outcome: Some(Outcome::Success),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(conn_events.len(), 1);
    assert_eq!(conn_events[0].details["role"], "tecnico");
}

/// TC-F3-062: intento de enviar elevación desde un cliente `soporte` es rechazado y auditado con alarma.
#[tokio::test]
async fn test_tc_f3_062_soporte_cannot_request_elevation() {
    let env = setup_test_env().await;

    // 1. Crear instalador soporte y registrar dispositivo
    let inst_id = "inst-soporte-tc062";
    insert_build_job(&env.state, inst_id, "soporte", "prof-soporte", "completed").await;

    let dev_id = "client-soporte-062";
    let (reg_status, _) =
        register_device_via_heartbeat(&env.app, dev_id, Some(inst_id), None).await;
    assert_eq!(reg_status, StatusCode::OK);

    // 2. Intentar solicitar elevación de privilegios desde cliente soporte
    let elevation_payload = json!({
        "device_id": dev_id,
        "target_device_id": "target-dest-pc",
        "reason": "Reinstalar software contable",
        "ticket": "TICK-8842",
        "installer_id": inst_id
    });

    let req = Request::builder()
        .uri("/api/elevation/request")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&elevation_payload).unwrap()))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "role_violation");

    // 3. Verificar que se disparó la alarma alarm.role_violation
    let alarms = env
        .state
        .audit
        .query_events(EventFilter {
            category: Some(Category::Alarm),
            action: Some("alarm.role_violation".to_string()),
            actor_id: Some(dev_id.to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].details["actual_role"], "soporte");
    assert_eq!(
        alarms[0].details["attempted_role_or_operation"],
        "request_elevation"
    );
    assert_eq!(alarms[0].details["severity"], "critical");
}

/// TC-F3-063: cliente que falsifica el rol en cabecera/payload cuando su `installer_id` está registrado como `soporte` es rechazado de inmediato.
#[tokio::test]
async fn test_tc_f3_063_tampered_role_spoofing_rejected() {
    let env = setup_test_env().await;

    // 1. Crear instalador registrado canónicamente como soporte
    let inst_id = "inst-soporte-tc063";
    insert_build_job(&env.state, inst_id, "soporte", "prof-soporte", "completed").await;

    // 2. Caso A: Intento de spoofing en el primer arranque / registro
    // Cliente envía installer_id soporte pero declara rol 'tecnico' en cabecera y payload
    let spoofed_payload = json!({
        "id": "client-spoof-first-boot",
        "name": "Spoofed Client",
        "hostname": "host-spoof",
        "role": "tecnico",
        "installer_id": inst_id
    });

    let req_a = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-client-role", "tecnico")
        .header("x-installer-id", inst_id)
        .body(Body::from(serde_json::to_vec(&spoofed_payload).unwrap()))
        .unwrap();

    let res_a = env.app.clone().oneshot(req_a).await.unwrap();
    assert_eq!(res_a.status(), StatusCode::FORBIDDEN);

    let bytes_a = res_a.into_body().collect().await.unwrap().to_bytes();
    let body_a: Value = serde_json::from_slice(&bytes_a).unwrap();
    assert_eq!(body_a["error"], "role_violation");

    // 3. Caso B: Dispositivo ya registrado como soporte intenta mutar su rol en heartbeat posterior
    let legit_soporte_dev = "dev-soporte-legit";
    let (status_reg, _) =
        register_device_via_heartbeat(&env.app, legit_soporte_dev, Some(inst_id), None).await;
    assert_eq!(status_reg, StatusCode::OK);

    // Ajustar last_seen_at para evitar el límite de tasa de 1 segundo entre latidos
    sqlx::query("UPDATE devices SET last_seen_at = datetime('now', '-5 seconds') WHERE id = ?")
        .bind(legit_soporte_dev)
        .execute(&env.state.db)
        .await
        .unwrap();

    // Latido posterior intentando declarar rol técnico (tampering local)
    let tamper_payload = json!({
        "id": legit_soporte_dev,
        "name": "Tampered Client",
        "role": "tecnico",
        "installer_id": inst_id
    });

    let req_b = Request::builder()
        .uri("/api/devices/heartbeat")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-client-role", "tecnico")
        .body(Body::from(serde_json::to_vec(&tamper_payload).unwrap()))
        .unwrap();

    let res_b = env.app.clone().oneshot(req_b).await.unwrap();
    assert_eq!(res_b.status(), StatusCode::FORBIDDEN);

    let bytes_b = res_b.into_body().collect().await.unwrap().to_bytes();
    let body_b: Value = serde_json::from_slice(&bytes_b).unwrap();
    assert_eq!(body_b["error"], "role_violation");

    // 4. Verificar que ambos intentos de falsificación generaron alarma crítica
    let alarms = env
        .state
        .audit
        .query_events(EventFilter {
            category: Some(Category::Alarm),
            action: Some("alarm.role_violation".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(alarms.len(), 2, "Deben existir 2 alarmas de falsificación");
    for alarm in alarms {
        assert_eq!(alarm.details["severity"], "critical");
        assert_eq!(alarm.outcome, Outcome::Denied);
    }
}

/// TC-F3-064: verificar que `AlarmEngine` y `audit_core` persistan la alarma y el evento criptográficamente encadenado.
#[tokio::test]
async fn test_tc_f3_064_role_violation_alarm_and_audit_emitted() {
    let env = setup_test_env().await;

    // 1. Dispositivo soporte intenta aplicar políticas restringidas
    let inst_id = "inst-soporte-tc064";
    insert_build_job(&env.state, inst_id, "soporte", "prof-soporte", "completed").await;

    let dev_id = "client-soporte-064";
    let (status_reg, _) =
        register_device_via_heartbeat(&env.app, dev_id, Some(inst_id), None).await;
    assert_eq!(status_reg, StatusCode::OK);

    let policy_payload = json!({
        "device_id": dev_id,
        "policy_key": "server.allow_unattended",
        "policy_value": true,
        "installer_id": inst_id
    });

    let req = Request::builder()
        .uri("/api/policies/apply")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&policy_payload).unwrap()))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 2. Verificar la persistencia de la alarma en AuditStore a través de AlarmEngine
    let alarms = env
        .state
        .audit
        .query_events(EventFilter {
            category: Some(Category::Alarm),
            action: Some("alarm.role_violation".to_string()),
            actor_id: Some(dev_id.to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(alarms.len(), 1);
    let alarm_event = &alarms[0];

    assert_eq!(alarm_event.action, "alarm.role_violation");
    assert_eq!(alarm_event.category, Category::Alarm);
    assert_eq!(alarm_event.outcome, Outcome::Denied);
    assert_eq!(alarm_event.actor.id, dev_id);
    assert_eq!(alarm_event.actor.actor_type, "device");
    assert_eq!(alarm_event.details["alarm_name"], "alarm.role_violation");
    assert_eq!(alarm_event.details["severity"], "critical");

    // 3. Verificar la integridad de la cadena de hashes criptográfica
    assert_eq!(
        alarm_event.hash.len(),
        64,
        "El hash SHA-256 debe tener 64 caracteres hex"
    );
    assert!(
        !alarm_event.prev_hash.is_empty(),
        "Debe poseer hash previo encadenado"
    );

    // Verificar la cadena completa en AuditStore
    let result = env.state.audit.verify_chain(None, None).await.unwrap();
    assert!(
        result.is_valid,
        "La cadena de hashes de auditoría debe ser 100% válida y coherente"
    );
}
