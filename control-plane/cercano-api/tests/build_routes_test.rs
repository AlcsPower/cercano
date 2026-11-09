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

use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::Duration;

use audit_core::{Category, EventFilter, Outcome};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::tempdir;
use tower::ServiceExt;
use uuid::Uuid;
use zip::ZipArchive;

use cercano_api::{config::Config, create_app, db::init_db, AppState};

struct TestEnv {
    app: axum::Router,
    state: AppState,
    _builds_dir: tempfile::TempDir,
    admin_token: String,
    soporte_user_id: String,
    soporte_token: String,
    other_user_id: String,
    other_token: String,
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
        ..Default::default()
    };

    let state = AppState::new(config, db.clone(), audit);
    let app = create_app(state.clone());

    // 1. Crear usuario Admin
    let admin_id = Uuid::now_v7().to_string();
    let admin_token = format!("tok_admin_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'admin_build', 'hash', 'admin', 1)",
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

    // 2. Crear usuario Soporte con permiso builder:create:soporte
    let soporte_user_id = Uuid::now_v7().to_string();
    let soporte_token = format!("tok_soporte_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'user_soporte', 'hash', 'soporte', 1)",
    )
    .bind(&soporte_user_id)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))",
    )
    .bind(&soporte_token)
    .bind(&soporte_user_id)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission) VALUES (?, 'builder:create:soporte')",
    )
    .bind(&soporte_user_id)
    .execute(&db)
    .await
    .unwrap();

    // 3. Crear usuario regular sin permisos de técnico
    let other_user_id = Uuid::now_v7().to_string();
    let other_token = format!("tok_other_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, 'regular_user', 'hash', 'user', 1)",
    )
    .bind(&other_user_id)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))",
    )
    .bind(&other_token)
    .bind(&other_user_id)
    .execute(&db)
    .await
    .unwrap();

    TestEnv {
        app,
        state,
        _builds_dir: builds_dir,
        admin_token,
        soporte_user_id,
        soporte_token,
        other_user_id,
        other_token,
    }
}

fn valid_soporte_profile_json() -> Value {
    json!({
        "schema_version": "1.0.0",
        "profile_id": "0192e300-1111-7111-8111-000000000001",
        "created_at": "2026-11-09T10:00:00.000Z",
        "role": "soporte",
        "server": {
            "rendezvous_server": "cercano.lan:21116",
            "relay_server": "relay.lan:21117",
            "api_server": "https://cercano.lan:21114",
            "server_public_key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
        },
        "identity": {
            "app_name": "Cercano Soporte",
            "about_text": "Cercano Soporte - Asistencia remota segura. Licenciado bajo AGPL-3.0.",
            "icon": "branding/png/cercano-icon.ico"
        },
        "policy": {
            "allow_incoming": true,
            "allow_outgoing": false,
            "unattended_access": false,
            "require_approval": true,
            "allow_file_transfer": true,
            "allow_clipboard": true,
            "allow_audio": true,
            "allow_terminal": false,
            "allow_port_forward": false,
            "hide_network_settings": true,
            "enable_elevation": false,
            "unattended_elevation": false
        },
        "installation": {
            "mode": "installed",
            "install_path": "C:\\Program Files\\Cercano Soporte",
            "auto_start": true,
            "create_desktop_shortcut": true,
            "silent": false
        },
        "identification": {
            "device_group": "Contabilidad",
            "default_owner": "soporte@cercano.lan"
        },
        "expiration": {
            "expires_at": "2027-11-09T10:00:00.000Z",
            "max_uses": 50
        }
    })
}

fn valid_tecnico_profile_json() -> Value {
    json!({
        "schema_version": "1.0.0",
        "profile_id": "0192e300-2222-7222-8222-000000000002",
        "created_at": "2026-11-09T10:00:00.000Z",
        "role": "tecnico",
        "server": {
            "rendezvous_server": "cercano.lan:21116",
            "relay_server": "relay.lan:21117",
            "api_server": "https://cercano.lan:21114",
            "server_public_key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
        },
        "identity": {
            "app_name": "Cercano Técnico",
            "about_text": "Cercano Técnico - Consola TI. Licenciado bajo AGPL-3.0.",
            "icon": "branding/png/cercano-icon.ico"
        },
        "policy": {
            "allow_incoming": false,
            "allow_outgoing": true,
            "unattended_access": false,
            "require_approval": false,
            "allow_file_transfer": true,
            "allow_clipboard": true,
            "allow_audio": true,
            "allow_terminal": true,
            "allow_port_forward": true,
            "hide_network_settings": true,
            "enable_elevation": true,
            "unattended_elevation": false
        },
        "installation": {
            "mode": "portable",
            "auto_start": false,
            "create_desktop_shortcut": true,
            "silent": true
        },
        "identification": {
            "device_group": "Equipo-TI",
            "default_owner": "admin@cercano.lan"
        },
        "expiration": {
            "expires_at": "2027-02-09T10:00:00.000Z",
            "max_uses": 5
        }
    })
}

#[tokio::test]
async fn test_tc_f3_070_enqueue_and_query_status() {
    let env = setup_test_env().await;

    // 1. Encolar job de rol soporte con usuario soporte
    let req = Request::builder()
        .uri("/api/builds")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", env.soporte_token))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "profile": valid_soporte_profile_json()
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();

    let job_id = body["id"].as_str().expect("job id missing").to_string();
    assert_eq!(body["status"], "queued");
    assert_eq!(body["role"], "soporte");
    assert_eq!(body["user_id"], env.soporte_user_id);
    assert_eq!(body["profile_id"], "0192e300-1111-7111-8111-000000000001");

    // 2. Esperar a que el worker asíncrono complete el job (polling)
    let mut completed = false;
    let mut final_status_body: Option<Value> = None;

    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;

        let get_req = Request::builder()
            .uri(format!("/api/builds/{}", job_id))
            .method("GET")
            .header("authorization", format!("Bearer {}", env.soporte_token))
            .body(Body::empty())
            .unwrap();

        let get_res = env.app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);

        let get_bytes = get_res.into_body().collect().await.unwrap().to_bytes();
        let status_json: Value = serde_json::from_slice(&get_bytes).unwrap();

        let status = status_json["status"].as_str().unwrap();
        if status == "completed" {
            completed = true;
            final_status_body = Some(status_json);
            break;
        } else if status == "failed" {
            panic!(
                "Job failed: {}",
                status_json["error_message"].as_str().unwrap_or("unknown")
            );
        }
    }

    assert!(completed, "El job no completó en el tiempo esperado");
    let status_data = final_status_body.unwrap();
    assert_eq!(status_data["id"], job_id);
    assert_eq!(status_data["status"], "completed");
    assert!(status_data["artifact_path"].as_str().is_some());
    assert!(status_data["logs"]
        .as_str()
        .unwrap()
        .contains("Generación exitosa completada"));
    assert!(status_data["started_at"].as_str().is_some());
    assert!(status_data["completed_at"].as_str().is_some());
}

#[tokio::test]
async fn test_tc_f3_071_reject_unauthorized_tecnico_build() {
    let env = setup_test_env().await;

    // Usuario 'regular_user' intenta solicitar build de rol 'tecnico'
    let req = Request::builder()
        .uri("/api/builds")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", env.other_token))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "profile": valid_tecnico_profile_json()
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "forbidden");

    // Verificar que quedó registrado el evento auth.denied en el almacén de auditoría
    let denied_events = env
        .state
        .audit
        .query_events(EventFilter {
            action: Some("auth.denied".to_string()),
            category: Some(Category::Auth),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(denied_events.len(), 1);
    let event = &denied_events[0];
    assert_eq!(event.action, "auth.denied");
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.actor.id, env.other_user_id);
    assert_eq!(event.details["requested_role"], "tecnico");
    assert_eq!(
        event.details["required_permission"],
        "builder:create:tecnico"
    );
}

#[tokio::test]
async fn test_tc_f3_072_admin_can_enqueue_tecnico_build() {
    let env = setup_test_env().await;

    // Administrador solicita build de rol 'tecnico'
    let req = Request::builder()
        .uri("/api/builds")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", env.admin_token))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "profile": valid_tecnico_profile_json()
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    let job_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["role"], "tecnico");

    // Esperar a completado
    let mut completed = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let get_req = Request::builder()
            .uri(format!("/api/builds/{}", job_id))
            .method("GET")
            .header("authorization", format!("Bearer {}", env.admin_token))
            .body(Body::empty())
            .unwrap();

        let get_res = env.app.clone().oneshot(get_req).await.unwrap();
        let get_bytes = get_res.into_body().collect().await.unwrap().to_bytes();
        let status_json: Value = serde_json::from_slice(&get_bytes).unwrap();

        if status_json["status"] == "completed" {
            completed = true;
            break;
        }
    }
    assert!(completed, "El job tecnico no completó a tiempo");
}

#[tokio::test]
async fn test_tc_f3_073_download_artifact() {
    let env = setup_test_env().await;

    // 1. Encolar y esperar a que complete
    let req = Request::builder()
        .uri("/api/builds")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", env.soporte_token))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "profile": valid_soporte_profile_json()
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    let job_id = body["id"].as_str().unwrap().to_string();

    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let check_req = Request::builder()
            .uri(format!("/api/builds/{}", job_id))
            .method("GET")
            .header("authorization", format!("Bearer {}", env.soporte_token))
            .body(Body::empty())
            .unwrap();
        let check_res = env.app.clone().oneshot(check_req).await.unwrap();
        let bytes = check_res.into_body().collect().await.unwrap().to_bytes();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        if parsed["status"] == "completed" {
            break;
        }
    }

    // 2. Descargar artefacto
    let dl_req = Request::builder()
        .uri(format!("/api/builds/{}/download", job_id))
        .method("GET")
        .header("authorization", format!("Bearer {}", env.soporte_token))
        .body(Body::empty())
        .unwrap();

    let dl_res = env.app.clone().oneshot(dl_req).await.unwrap();
    assert_eq!(dl_res.status(), StatusCode::OK);

    assert_eq!(
        dl_res.headers().get("content-type").unwrap(),
        "application/zip"
    );
    assert!(dl_res
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("attachment; filename=\"cercano-soporte-1.0.0.zip\""));
    assert_eq!(
        dl_res.headers().get("cache-control").unwrap(),
        "no-cache, no-store, must-revalidate"
    );

    let zip_bytes = dl_res.into_body().collect().await.unwrap().to_bytes();
    assert!(!zip_bytes.is_empty());

    // 3. Inspeccionar contenido del ZIP
    let reader = Cursor::new(zip_bytes);
    let mut zip = ZipArchive::new(reader).expect("Debe ser un ZIP válido");

    let expected_files = [
        "cercano-profile.signed.json",
        "build-manifest.json",
        "SHA256SUMS",
    ];

    for file_name in &expected_files {
        let mut file = zip
            .by_name(file_name)
            .unwrap_or_else(|_| panic!("El ZIP debe contener '{}'", file_name));
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(!content.is_empty());
    }
}

#[tokio::test]
async fn test_tc_f3_074_download_expired_artifact() {
    let env = setup_test_env().await;

    // Crear un job completado directamente en DB pero caducado
    let job_id = Uuid::now_v7().to_string();
    let temp_file = env
        ._builds_dir
        .path()
        .join(format!("test_expired_{}.zip", job_id));
    std::fs::write(&temp_file, b"dummy zip").unwrap();

    let past_time = "2020-01-01T00:00:00Z";
    sqlx::query(
        r#"
        INSERT INTO build_jobs (id, user_id, role, profile_id, status, artifact_path, created_at, completed_at, expires_at)
        VALUES (?, ?, 'soporte', 'prof_expired', 'completed', ?, datetime('now', '-10 hours'), datetime('now', '-9 hours'), ?)
        "#
    )
    .bind(&job_id)
    .bind(&env.soporte_user_id)
    .bind(temp_file.to_str().unwrap())
    .bind(past_time)
    .execute(&env.state.db)
    .await
    .unwrap();

    let dl_req = Request::builder()
        .uri(format!("/api/builds/{}/download", job_id))
        .method("GET")
        .header("authorization", format!("Bearer {}", env.soporte_token))
        .body(Body::empty())
        .unwrap();

    let dl_res = env.app.clone().oneshot(dl_req).await.unwrap();
    assert_eq!(dl_res.status(), StatusCode::GONE);

    let bytes = dl_res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "artifact_expired");
}

#[tokio::test]
async fn test_tc_f3_075_download_unauthorized() {
    let env = setup_test_env().await;

    // Crear job para soporte_user_id
    let job_id = Uuid::now_v7().to_string();
    let temp_file = env
        ._builds_dir
        .path()
        .join(format!("test_unauth_{}.zip", job_id));
    std::fs::write(&temp_file, b"dummy zip").unwrap();

    sqlx::query(
        r#"
        INSERT INTO build_jobs (id, user_id, role, profile_id, status, artifact_path, created_at, completed_at, expires_at)
        VALUES (?, ?, 'soporte', 'prof_unauth', 'completed', ?, datetime('now'), datetime('now'), datetime('now', '+1 hour'))
        "#
    )
    .bind(&job_id)
    .bind(&env.soporte_user_id)
    .bind(temp_file.to_str().unwrap())
    .execute(&env.state.db)
    .await
    .unwrap();

    // other_token intenta descargarlo sin ser admin, sin ser owner y sin builder:download
    let dl_req = Request::builder()
        .uri(format!("/api/builds/{}/download", job_id))
        .method("GET")
        .header("authorization", format!("Bearer {}", env.other_token))
        .body(Body::empty())
        .unwrap();

    let dl_res = env.app.clone().oneshot(dl_req).await.unwrap();
    assert_eq!(dl_res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_tc_f3_076_list_builds_filtering() {
    let env = setup_test_env().await;

    let req_soporte = Request::builder()
        .uri("/api/builds")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", env.soporte_token))
        .body(Body::from(
            serde_json::to_vec(&json!({ "profile": valid_soporte_profile_json() })).unwrap(),
        ))
        .unwrap();
    let _ = env.app.clone().oneshot(req_soporte).await.unwrap();

    let req_admin = Request::builder()
        .uri("/api/builds")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", env.admin_token))
        .body(Body::from(
            serde_json::to_vec(&json!({ "profile": valid_tecnico_profile_json() })).unwrap(),
        ))
        .unwrap();
    let _ = env.app.clone().oneshot(req_admin).await.unwrap();

    // 1. Soporte lista: solo debe ver su propio build
    let list_soporte_req = Request::builder()
        .uri("/api/builds")
        .method("GET")
        .header("authorization", format!("Bearer {}", env.soporte_token))
        .body(Body::empty())
        .unwrap();
    let res = env.app.clone().oneshot(list_soporte_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let list: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["user_id"], env.soporte_user_id);

    // 2. Admin lista: debe ver ambos builds
    let list_admin_req = Request::builder()
        .uri("/api/builds")
        .method("GET")
        .header("authorization", format!("Bearer {}", env.admin_token))
        .body(Body::empty())
        .unwrap();
    let res = env.app.clone().oneshot(list_admin_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let list: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list.len(), 2);
}

#[tokio::test]
async fn test_tc_f3_077_invalid_profile_rejected() {
    let env = setup_test_env().await;

    // Perfil inválido: soporte con allow_outgoing = true
    let mut invalid_profile = valid_soporte_profile_json();
    invalid_profile["policy"]["allow_outgoing"] = json!(true);

    let req = Request::builder()
        .uri("/api/builds")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", env.soporte_token))
        .body(Body::from(serde_json::to_vec(&invalid_profile).unwrap()))
        .unwrap();

    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "validation_error");
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("allow_outgoing debe ser falso"));
}
