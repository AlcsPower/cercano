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

//! Integration tests for F5-06: Client policy download, caching, offline fail-closed and ceiling enforcement.
//!
//! Validates:
//! - TC-F5-024: Cliente sin red: caché vigente (aplica copia) y caché caducada (falla cerrado para conexiones nuevas).
//! - TC-F5-025: Cliente edita la política localmente (sin efecto; el servidor y el perfil firmado mandan).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower::ServiceExt;

use cercano_api::config::Config;
use cercano_api::db::init_db;
use cercano_api::{create_app, AppState};

// ── Client Mock Model for Policy Caching & Enforcement (mirrors vendor/client/src/cercano_profile.rs) ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedEffectivePolicy {
    pub device_id: String,
    pub role: String,
    pub effective: BTreeMap<String, Value>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyStatus {
    Valid,
    CachedValid,
    ExpiredFailClosed,
    NoPolicyUseP0,
}

pub struct ClientPolicyManager {
    pub role: String,
    pub cached_policy: RwLock<Option<CachedEffectivePolicy>>,
    pub fail_closed: std::sync::atomic::AtomicBool,
}

impl ClientPolicyManager {
    pub fn new(role: &str) -> Self {
        Self {
            role: role.to_string(),
            cached_policy: RwLock::new(None),
            fail_closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn update_cached_policy(
        &self,
        policy_json: &str,
        now_rfc3339: Option<&str>,
    ) -> Result<CachedEffectivePolicy, String> {
        let mut policy: CachedEffectivePolicy = serde_json::from_str(policy_json)
            .map_err(|e| format!("JSON de política inválido: {e}"))?;

        if policy.is_expired(now_rfc3339) {
            return Err("La política ya ha caducado.".to_string());
        }

        // Enforce P0 immutable ceiling (Rule 5 & ADR-008 / TC-F5-025)
        if self.role == "soporte" {
            policy
                .effective
                .insert("unattended_access".to_string(), json!(false));
            policy
                .effective
                .insert("allow_outgoing".to_string(), json!(false));
            policy
                .effective
                .insert("enable_elevation".to_string(), json!(false));
            policy
                .effective
                .insert("unattended_elevation".to_string(), json!(false));
        } else if self.role == "tecnico" {
            policy
                .effective
                .insert("unattended_access".to_string(), json!(false));
            policy
                .effective
                .insert("allow_incoming".to_string(), json!(false));
            policy
                .effective
                .insert("unattended_elevation".to_string(), json!(false));
            policy
                .effective
                .insert("chat.enabled".to_string(), json!(false));
        }

        self.fail_closed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        *self.cached_policy.write().unwrap() = Some(policy.clone());
        Ok(policy)
    }

    pub fn evaluate_policy_status(
        &self,
        now_rfc3339: Option<&str>,
        is_network_offline: bool,
    ) -> PolicyStatus {
        let guard = self.cached_policy.read().unwrap();
        match guard.as_ref() {
            Some(policy) => {
                if policy.is_expired(now_rfc3339) {
                    self.fail_closed
                        .store(true, std::sync::atomic::Ordering::SeqCst);
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
        &self,
        now_rfc3339: Option<&str>,
        is_network_offline: bool,
    ) -> Result<(), String> {
        let status = self.evaluate_policy_status(now_rfc3339, is_network_offline);
        if status == PolicyStatus::ExpiredFailClosed {
            return Err("Conexión entrante bloqueada: la política central ha caducado sin conectividad de red (fail-closed)".to_string());
        }

        let guard = self.cached_policy.read().unwrap();
        if let Some(ref policy) = *guard {
            if !policy.get_bool("allow_incoming", true) {
                return Err("Conexiones entrantes deshabilitadas por política".to_string());
            }
        }
        Ok(())
    }

    pub fn can_accept_outgoing_connection(
        &self,
        now_rfc3339: Option<&str>,
        is_network_offline: bool,
    ) -> Result<(), String> {
        if self.role == "soporte" {
            return Err("Cercano Soporte no puede iniciar conexiones salientes".to_string());
        }

        let status = self.evaluate_policy_status(now_rfc3339, is_network_offline);
        if status == PolicyStatus::ExpiredFailClosed {
            return Err("Conexión saliente bloqueada: la política central ha caducado sin conectividad de red (fail-closed)".to_string());
        }

        let guard = self.cached_policy.read().unwrap();
        if let Some(ref policy) = *guard {
            if !policy.get_bool("allow_outgoing", true) {
                return Err("Conexiones salientes deshabilitadas por política".to_string());
            }
        }
        Ok(())
    }
}

// ── Test Helpers ──

async fn setup_app() -> (axum::Router, AppState) {
    let db = init_db("sqlite::memory:").await.unwrap();
    let audit = Arc::new(audit_core::AuditStore::new(db.clone()).await.unwrap());
    let state = AppState::new(Config::default(), db, audit);
    let app = create_app(state.clone());
    (app, state)
}

async fn create_user_with_token(state: &AppState, username: &str, role: &str) -> (String, String) {
    let user_id = uuid::Uuid::new_v4().to_string();
    let token = format!("test_tok_{username}");
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at)
         VALUES (?, ?, 'hash', ?, ?)",
    )
    .bind(&user_id)
    .bind(username)
    .bind(role)
    .bind(&now)
    .execute(&state.db)
    .await
    .unwrap();

    let expires = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(&user_id)
    .bind(&expires)
    .bind(&now)
    .execute(&state.db)
    .await
    .unwrap();

    (user_id, token)
}

async fn create_device_with_role(state: &AppState, device_id: &str, name: &str, role: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO devices (id, name, hostname, os, version, ip_address, status, last_seen_at, created_at, role)
         VALUES (?, ?, 'host1', 'windows', '1.0.0', '192.168.1.50', 'online', ?, ?, ?)",
    )
    .bind(device_id)
    .bind(name)
    .bind(&now)
    .bind(&now)
    .bind(role)
    .execute(&state.db)
    .await
    .unwrap();
}

async fn request_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    if let Some(t) = token {
        req_builder = req_builder.header("authorization", format!("Bearer {t}"));
    }

    let req_body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };

    let req = req_builder.body(req_body).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
    (status, parsed)
}

// ── Tests ──

#[tokio::test]
async fn test_tc_f5_024_client_offline_cache_and_expired_fail_closed() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_tok) = create_user_with_token(&state, "admin_user", "admin").await;
    create_device_with_role(&state, "dev-client-1", "Equipo Cliente", "soporte").await;

    // 1. Central policy created on server: allow_file_transfer=false, cache_ttl=180s
    let (status, _p) = request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_tok),
        Some(json!({
            "scope_type": "device",
            "scope_id": "dev-client-1",
            "document": {
                "allow_file_transfer": false,
                "policy.cache_ttl_seconds": 180
            },
            "state": "active"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // 2. Client downloads effective policy from server
    let (status, eff_resp) = request_json(
        &app,
        "GET",
        "/api/policies/effective?device_id=dev-client-1",
        Some(&admin_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(eff_resp["effective"]["allow_file_transfer"], false);
    assert_eq!(eff_resp["cache_ttl_seconds"], 180);

    let eff_json_str = serde_json::to_string(&eff_resp).unwrap();

    // 3. Client initializes its local manager and caches the policy
    let client = ClientPolicyManager::new("soporte");
    let now = chrono::Utc::now().to_rfc3339();
    let cached = client
        .update_cached_policy(&eff_json_str, Some(&now))
        .unwrap();
    assert_eq!(cached.cache_ttl_seconds, 180);

    // 4. Client without network (offline) within valid TTL:
    // Uses cached copy! Incoming connection permitted, file transfer disabled by policy.
    let status_offline_valid = client.evaluate_policy_status(Some(&now), true);
    assert_eq!(status_offline_valid, PolicyStatus::CachedValid);
    assert!(client
        .can_accept_incoming_connection(Some(&now), true)
        .is_ok());

    // 5. Client without network after cache expiration (> 180s):
    // Fails closed! Incoming connections blocked with descriptive error.
    let future_time = (chrono::Utc::now() + chrono::Duration::seconds(200)).to_rfc3339();
    let status_offline_expired = client.evaluate_policy_status(Some(&future_time), true);
    assert_eq!(status_offline_expired, PolicyStatus::ExpiredFailClosed);

    let err = client
        .can_accept_incoming_connection(Some(&future_time), true)
        .unwrap_err();
    assert!(err.contains("fail-closed"));
}

#[tokio::test]
async fn test_tc_f5_025_client_local_tampering_rejected_and_p0_ceiling_enforced() {
    let client = ClientPolicyManager::new("soporte");

    let now_dt = chrono::Utc::now();
    let exp_dt = now_dt + chrono::Duration::seconds(300);

    // Attacker tries to inject local JSON setting unattended_access=true and allow_outgoing=true
    let forged_json = json!({
        "device_id": "dev-forged",
        "role": "soporte",
        "effective": {
            "allow_incoming": true,
            "allow_outgoing": true,
            "unattended_access": true,
            "enable_elevation": true
        },
        "cache_ttl_seconds": 300,
        "issued_at": now_dt.to_rfc3339(),
        "expires_at": exp_dt.to_rfc3339()
    })
    .to_string();

    let applied = client
        .update_cached_policy(&forged_json, Some(&now_dt.to_rfc3339()))
        .unwrap();

    // P0 Ceiling clamped all sensitive fields back to false
    assert_eq!(applied.get_bool("unattended_access", true), false);
    assert_eq!(applied.get_bool("allow_outgoing", true), false);
    assert_eq!(applied.get_bool("enable_elevation", true), false);

    // Outgoing connection is rejected for soporte regardless of forged JSON
    let out_err = client
        .can_accept_outgoing_connection(Some(&now_dt.to_rfc3339()), false)
        .unwrap_err();
    assert!(out_err.contains("Cercano Soporte no puede iniciar conexiones salientes"));
}
