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

//! Central Policies REST API and deterministic resolution engine (F5-05).
//!
//! Implements:
//! - Policy CRUD, versioning, canonical SHA-256 computation, activation and revocation.
//! - Closed key dictionary validation (rejecting any unknown keys).
//! - Multi-layer resolution: P0 (signed profile/role ceiling) -> P1 (global) -> P2 (groups) -> P3 (device).
//! - Strict restrictive direction evaluation and explainability per key.

use std::collections::{BTreeMap, HashMap};

use audit_core::{Actor, Category, EventInput, Outcome, Source};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Row, SqlitePool};
use uuid::Uuid;

use crate::auth::{extract_client_ip, extract_trace_id, AuthenticatedUser};
use crate::identity::{is_device_in_scope, Policy, PolicyScopeType, PolicyState, MAX_DOC_LEN};
use crate::permissions::{audit_scope_denied, check_permission, POLICY_MANAGE, POLICY_READ};
use crate::AppState;

macro_rules! db_or_500 {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };
}

/// Known closed list of policy keys and their restrictive rules.
pub const ALLOWED_POLICY_KEYS: &[&str] = &[
    "allow_incoming",
    "allow_outgoing",
    "unattended_access",
    "require_approval",
    "allow_file_transfer",
    "allow_clipboard",
    "allow_audio",
    "allow_terminal",
    "allow_port_forward",
    "hide_network_settings",
    "enable_elevation",
    "unattended_elevation",
    "chat.enabled",
    "chat.attachments",
    "session.max_duration_minutes",
    "policy.cache_ttl_seconds",
];

/// Validates policy document against the closed dictionary of allowed keys and types.
pub fn validate_policy_document(doc: &Value) -> Result<BTreeMap<String, Value>, String> {
    let map = match doc.as_object() {
        Some(m) => m,
        None => return Err("El documento de política debe ser un objeto JSON.".to_string()),
    };

    let mut canonical = BTreeMap::new();

    for (k, v) in map {
        if !ALLOWED_POLICY_KEYS.contains(&k.as_str()) {
            return Err(format!(
                "Clave de política desconocida o no permitida: '{k}'."
            ));
        }

        match k.as_str() {
            "session.max_duration_minutes" => {
                let mins = v
                    .as_i64()
                    .ok_or_else(|| format!("'{k}' debe ser un entero."))?;
                if mins < 1 {
                    return Err(format!("'{k}' debe ser al menos 1 minuto."));
                }
                canonical.insert(k.clone(), json!(mins));
            }
            "policy.cache_ttl_seconds" => {
                let ttl = v
                    .as_i64()
                    .ok_or_else(|| format!("'{k}' debe ser un entero."))?;
                if !(60..=3600).contains(&ttl) {
                    return Err(format!("'{k}' debe estar entre 60 y 3600 segundos."));
                }
                canonical.insert(k.clone(), json!(ttl));
            }
            _ => {
                // All other keys are boolean
                let b = v
                    .as_bool()
                    .ok_or_else(|| format!("'{k}' debe ser un valor booleano."))?;
                canonical.insert(k.clone(), json!(b));
            }
        }
    }

    Ok(canonical)
}

/// Calculates canonical SHA-256 hash in lowercase hex for a JSON string.
pub fn compute_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Deserialize)]
pub struct ListPoliciesQuery {
    pub scope_type: Option<String>,
    pub scope_id: Option<String>,
    pub state: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub scope_type: String,
    pub scope_id: Option<String>,
    pub document: Value,
    pub state: Option<String>,
    pub effective_from: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EffectivePolicyQuery {
    pub device_id: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PolicyExplanation {
    pub value: Value,
    pub source: String,
    pub rule: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct EffectivePolicyResponse {
    pub device_id: String,
    pub role: String,
    pub effective: BTreeMap<String, Value>,
    pub explanations: BTreeMap<String, PolicyExplanation>,
    pub cache_ttl_seconds: i64,
    pub issued_at: String,
    pub expires_at: String,
}

// ── REST Handlers ──

pub async fn list_policies_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Query(params): Query<ListPoliciesQuery>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, POLICY_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);

    let rows = db_or_500!(
        sqlx::query(
            "SELECT id, scope_type, scope_id, version, document, document_sha256, state, effective_from, expires_at, created_at, created_by, revoked_at, revoked_by
             FROM policies
             WHERE (? IS NULL OR scope_type = ?)
               AND (? IS NULL OR scope_id = ?)
               AND (? IS NULL OR state = ?)
             ORDER BY scope_type ASC, scope_id ASC, version DESC
             LIMIT ? OFFSET ?",
        )
        .bind(&params.scope_type)
        .bind(&params.scope_type)
        .bind(&params.scope_id)
        .bind(&params.scope_id)
        .bind(&params.state)
        .bind(&params.state)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    );

    let items: Vec<Policy> = rows
        .into_iter()
        .filter_map(|r| Policy::from_row(&r).ok())
        .collect();

    let total: i64 = db_or_500!(
        sqlx::query_scalar(
            "SELECT count(*) FROM policies
             WHERE (? IS NULL OR scope_type = ?)
               AND (? IS NULL OR scope_id = ?)
               AND (? IS NULL OR state = ?)",
        )
        .bind(&params.scope_type)
        .bind(&params.scope_type)
        .bind(&params.scope_id)
        .bind(&params.scope_id)
        .bind(&params.state)
        .bind(&params.state)
        .fetch_one(&state.db)
        .await
    );

    Json(json!({
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }))
    .into_response()
}

pub async fn create_policy_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(payload): Json<CreatePolicyRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, POLICY_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let scope_type = match PolicyScopeType::from_str_opt(&payload.scope_type) {
        Some(st) => st,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "bad_request",
                    "message": "Tipo de ámbito inválido; debe ser 'global', 'group' o 'device'."
                })),
            )
                .into_response()
        }
    };

    let scope_id = match scope_type {
        PolicyScopeType::Global => "".to_string(),
        PolicyScopeType::Group => match payload.scope_id {
            Some(id) if !id.trim().is_empty() => {
                let exists: bool = db_or_500!(
                    sqlx::query_scalar("SELECT count(*) > 0 FROM groups WHERE id = ?")
                        .bind(id.trim())
                        .fetch_one(&state.db)
                        .await
                );
                if !exists {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "not_found", "message": "Grupo no encontrado." })),
                    )
                        .into_response();
                }
                id.trim().to_string()
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "bad_request", "message": "scope_id es obligatorio para ámbito 'group'." })),
                )
                    .into_response()
            }
        },
        PolicyScopeType::Device => match payload.scope_id {
            Some(id) if !id.trim().is_empty() => {
                let exists: bool = db_or_500!(
                    sqlx::query_scalar("SELECT count(*) > 0 FROM devices WHERE id = ?")
                        .bind(id.trim())
                        .fetch_one(&state.db)
                        .await
                );
                if !exists {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "not_found", "message": "Dispositivo no encontrado." })),
                    )
                        .into_response();
                }
                id.trim().to_string()
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "bad_request", "message": "scope_id es obligatorio para ámbito 'device'." })),
                )
                    .into_response()
            }
        },
    };

    let canonical_doc = match validate_policy_document(&payload.document) {
        Ok(d) => d,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "bad_request", "message": msg })),
            )
                .into_response()
        }
    };

    let doc_str = match serde_json::to_string(&canonical_doc) {
        Ok(s) => s,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if doc_str.len() > MAX_DOC_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "bad_request", "message": "Documento excede el tamaño máximo permitido." })),
        )
            .into_response();
    }

    let doc_hash = compute_sha256_hex(&doc_str);

    let state_str = payload.state.as_deref().unwrap_or("draft");
    let initial_state = match PolicyState::from_str_opt(state_str) {
        Some(s) if s == PolicyState::Draft || s == PolicyState::Active => s,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "bad_request", "message": "El estado inicial debe ser 'draft' o 'active'." })),
            )
                .into_response()
        }
    };

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Calculate next version
    let next_version: i64 = db_or_500!(
        sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM policies WHERE scope_type = ? AND scope_id = ?"
        )
        .bind(scope_type.as_str())
        .bind(&scope_id)
        .fetch_one(&state.db)
        .await
    );

    // If activating immediately, supersede any existing active policy
    if initial_state == PolicyState::Active {
        db_or_500!(
            sqlx::query(
                "UPDATE policies SET state = 'superseded' WHERE scope_type = ? AND scope_id = ? AND state = 'active'"
            )
            .bind(scope_type.as_str())
            .bind(&scope_id)
            .execute(&state.db)
            .await
        );
    }

    db_or_500!(
        sqlx::query(
            "INSERT INTO policies (id, scope_type, scope_id, version, document, document_sha256, state, effective_from, expires_at, created_at, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(scope_type.as_str())
        .bind(&scope_id)
        .bind(next_version)
        .bind(&doc_str)
        .bind(&doc_hash)
        .bind(initial_state.as_str())
        .bind(&payload.effective_from)
        .bind(&payload.expires_at)
        .bind(&now)
        .bind(&user.username)
        .execute(&state.db)
        .await
    );

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.policy.created",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "policy_id": id,
                "scope_type": scope_type.as_str(),
                "scope_id": scope_id,
                "version": next_version,
                "state": initial_state.as_str(),
                "sha256": doc_hash,
            }),
        ))
        .await;

    (
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "scope_type": scope_type.as_str(),
            "scope_id": scope_id,
            "version": next_version,
            "document": canonical_doc,
            "document_sha256": doc_hash,
            "state": initial_state.as_str(),
            "effective_from": payload.effective_from,
            "expires_at": payload.expires_at,
            "created_at": now,
            "created_by": user.username,
        })),
    )
        .into_response()
}

pub async fn get_policy_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, POLICY_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let row = db_or_500!(
        sqlx::query(
            "SELECT id, scope_type, scope_id, version, document, document_sha256, state, effective_from, expires_at, created_at, created_by, revoked_at, revoked_by
             FROM policies WHERE id = ?",
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
    );

    match row {
        Some(r) => match Policy::from_row(&r) {
            Ok(p) => Json(p).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn activate_policy_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, POLICY_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let policy_row = db_or_500!(
        sqlx::query("SELECT id, scope_type, scope_id, state FROM policies WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
    );

    let row = match policy_row {
        Some(r) => r,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let cur_state: String = row.get("state");
    if cur_state == "active" {
        return Json(json!({ "id": id, "state": "active" })).into_response();
    }

    if cur_state == "revoked" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "bad_request", "message": "Una política revocada no puede reactivarse; cree una nueva versión." })),
        )
            .into_response();
    }

    let scope_type: String = row.get("scope_type");
    let scope_id: String = row.get("scope_id");

    // Transition existing active policy to superseded
    db_or_500!(
        sqlx::query(
            "UPDATE policies SET state = 'superseded' WHERE scope_type = ? AND scope_id = ? AND state = 'active'"
        )
        .bind(&scope_type)
        .bind(&scope_id)
        .execute(&state.db)
        .await
    );

    // Set this policy to active
    db_or_500!(
        sqlx::query("UPDATE policies SET state = 'active' WHERE id = ?")
            .bind(&id)
            .execute(&state.db)
            .await
    );

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.policy.activated",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "policy_id": id,
                "scope_type": scope_type,
                "scope_id": scope_id,
            }),
        ))
        .await;

    Json(json!({ "id": id, "state": "active" })).into_response()
}

pub async fn revoke_policy_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, POLICY_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let policy_row = db_or_500!(
        sqlx::query("SELECT id, scope_type, scope_id, state FROM policies WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
    );

    let row = match policy_row {
        Some(r) => r,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let scope_type: String = row.get("scope_type");
    let scope_id: String = row.get("scope_id");
    let now = Utc::now().to_rfc3339();

    db_or_500!(
        sqlx::query(
            "UPDATE policies SET state = 'revoked', revoked_at = ?, revoked_by = ? WHERE id = ?"
        )
        .bind(&now)
        .bind(&user.username)
        .bind(&id)
        .execute(&state.db)
        .await
    );

    let _ = state
        .audit
        .append(EventInput::new(
            trace_id,
            Source::Api,
            Category::Console,
            "console.policy.revoked",
            Actor::with_details(
                &user.id,
                "user",
                Some(user.username.clone()),
                Some(client_ip),
            ),
            Outcome::Success,
            json!({
                "policy_id": id,
                "scope_type": scope_type,
                "scope_id": scope_id,
            }),
        ))
        .await;

    Json(json!({ "id": id, "state": "revoked", "revoked_at": now })).into_response()
}

pub async fn effective_policy_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Query(params): Query<EffectivePolicyQuery>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    if let Err(e) = check_permission(&state, &user, POLICY_READ, &client_ip, &trace_id).await {
        return e.into_response();
    }

    // Check scope for non-admin
    if user.role != "admin" {
        let in_scope = match is_device_in_scope(&state.db, &user, &params.device_id).await {
            Ok(v) => v,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if !in_scope {
            let exists: bool = db_or_500!(
                sqlx::query_scalar("SELECT count(*) > 0 FROM devices WHERE id = ?")
                    .bind(&params.device_id)
                    .fetch_one(&state.db)
                    .await
            );
            if exists {
                audit_scope_denied(
                    &state.audit,
                    &user,
                    "device_policy",
                    &params.device_id,
                    &client_ip,
                    &trace_id,
                )
                .await;
            }
            return StatusCode::NOT_FOUND.into_response();
        }
    }

    match resolve_effective_policy(&state.db, &params.device_id).await {
        Ok(eff) => Json(eff).into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "not_found", "message": e })),
        )
            .into_response(),
    }
}

// ── Deterministic Policy Resolution Engine ──

/// Resolves the effective policy for `device_id` across all active layers:
/// P0 (Signed profile / role ceiling)
/// P1 (Global active)
/// P2 (Device groups active, restrictive resolution across groups)
/// P3 (Device active)
pub async fn resolve_effective_policy(
    pool: &SqlitePool,
    device_id: &str,
) -> Result<EffectivePolicyResponse, String> {
    // 1. Fetch device role and profile
    let dev_row = sqlx::query("SELECT id, role, profile_id FROM devices WHERE id = ?")
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| format!("Dispositivo '{device_id}' no encontrado."))?;

    let dev_role: String = dev_row.get("role");

    // 2. Fetch P0 defaults and ceilings according to role
    let mut p0_ceilings: HashMap<&'static str, Value> = HashMap::new();
    let mut p0_defaults: HashMap<&'static str, Value> = HashMap::new();

    // Default base profile values
    p0_defaults.insert("allow_incoming", json!(true));
    p0_defaults.insert("allow_outgoing", json!(true));
    p0_defaults.insert("unattended_access", json!(false));
    p0_defaults.insert("require_approval", json!(true));
    p0_defaults.insert("allow_file_transfer", json!(true));
    p0_defaults.insert("allow_clipboard", json!(true));
    p0_defaults.insert("allow_audio", json!(true));
    p0_defaults.insert("allow_terminal", json!(false));
    p0_defaults.insert("allow_port_forward", json!(false));
    p0_defaults.insert("hide_network_settings", json!(false));
    p0_defaults.insert("enable_elevation", json!(false));
    p0_defaults.insert("unattended_elevation", json!(false));
    p0_defaults.insert("chat.enabled", json!(true));
    p0_defaults.insert("chat.attachments", json!(true));
    p0_defaults.insert("session.max_duration_minutes", json!(120));
    p0_defaults.insert("policy.cache_ttl_seconds", json!(300));

    // Role-specific immutable security ceilings (ADR-008 & docs/specs/identidad.md §4.2 rule 5)
    if dev_role == "soporte" {
        p0_ceilings.insert("unattended_access", json!(false));
        p0_ceilings.insert("allow_outgoing", json!(false));
        p0_ceilings.insert("enable_elevation", json!(false));
        p0_ceilings.insert("unattended_elevation", json!(false));
    } else if dev_role == "tecnico" {
        p0_ceilings.insert("unattended_access", json!(false));
        p0_ceilings.insert("allow_incoming", json!(false));
        p0_ceilings.insert("unattended_elevation", json!(false));
        p0_ceilings.insert("chat.enabled", json!(false)); // tecnico does not host inbound chat
    }

    // 3. Fetch P1: Active Global Policy
    let p1_global = fetch_valid_active_policy(pool, "global", "").await?;

    // 4. Fetch P2: Active Policies of all groups the device belongs to
    let group_ids: Vec<String> = sqlx::query_scalar(
        "SELECT group_id FROM group_members WHERE subject_type = 'device' AND subject_id = ? ORDER BY group_id ASC",
    )
    .bind(device_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("DB error: {e}"))?;

    let mut p2_groups = Vec::new();
    for gid in &group_ids {
        if let Some(p) = fetch_valid_active_policy(pool, "group", gid).await? {
            p2_groups.push((gid.clone(), p));
        }
    }

    // 5. Fetch P3: Active Device Policy
    let p3_device = fetch_valid_active_policy(pool, "device", device_id).await?;

    // 6. Resolve key by key across layers
    let mut effective = BTreeMap::new();
    let mut explanations = BTreeMap::new();

    for &key in ALLOWED_POLICY_KEYS {
        // Collect candidate values from layers P1, P2, P3
        let mut candidates: Vec<(String, Value)> = Vec::new();

        if let Some(ref pol) = p1_global {
            if let Some(val) = pol.get(key) {
                candidates.push(("global".to_string(), val.clone()));
            }
        }

        for (gid, pol) in &p2_groups {
            if let Some(val) = pol.get(key) {
                candidates.push((format!("group:{gid}"), val.clone()));
            }
        }

        if let Some(ref pol) = p3_device {
            if let Some(val) = pol.get(key) {
                candidates.push(("device".to_string(), val.clone()));
            }
        }

        let (mut chosen_val, mut chosen_src, mut rule) = if candidates.is_empty() {
            let def_val = p0_defaults.get(key).cloned().unwrap_or(Value::Null);
            (def_val, "profile".to_string(), "default".to_string())
        } else if candidates.len() == 1 {
            let (src, val) = candidates.remove(0);
            (val, src, "only-definition".to_string())
        } else {
            // Multiple layers define this key: apply restrictive direction
            let (best_src, best_val) = pick_most_restrictive(key, candidates);
            (best_val, best_src, "restrictive".to_string())
        };

        // Enforce P0 ceiling (inviolable)
        if let Some(ceiling_val) = p0_ceilings.get(key) {
            let violates_ceiling = matches!(
                (ceiling_val.as_bool(), chosen_val.as_bool()),
                (Some(false), Some(true))
            );

            if violates_ceiling {
                chosen_val = ceiling_val.clone();
                chosen_src = "profile".to_string();
                rule = "ceiling-enforced".to_string();
            }
        }

        effective.insert(key.to_string(), chosen_val.clone());
        explanations.insert(
            key.to_string(),
            PolicyExplanation {
                value: chosen_val,
                source: chosen_src,
                rule,
            },
        );
    }

    let cache_ttl = effective
        .get("policy.cache_ttl_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(300);

    let now_dt = Utc::now();
    let exp_dt = now_dt + Duration::seconds(cache_ttl);

    Ok(EffectivePolicyResponse {
        device_id: device_id.to_string(),
        role: dev_role,
        effective,
        explanations,
        cache_ttl_seconds: cache_ttl,
        issued_at: now_dt.to_rfc3339(),
        expires_at: exp_dt.to_rfc3339(),
    })
}

/// Fetches an active policy, validating that:
/// - state is 'active'
/// - not expired
/// - document_sha256 matches actual SHA-256 of document
/// - document is valid JSON
///
/// Skips corrupt or expired policies (docs/specs/identidad.md §4.2 rule 6).
async fn fetch_valid_active_policy(
    pool: &SqlitePool,
    scope_type: &str,
    scope_id: &str,
) -> Result<Option<BTreeMap<String, Value>>, String> {
    let now = Utc::now().to_rfc3339();

    let row = sqlx::query(
        "SELECT id, document, document_sha256, expires_at FROM policies
         WHERE scope_type = ? AND scope_id = ? AND state = 'active'
           AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY version DESC LIMIT 1",
    )
    .bind(scope_type)
    .bind(scope_id)
    .bind(&now)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB error: {e}"))?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let doc_str: String = row.get("document");
    let doc_sha: String = row.get("document_sha256");

    // Verify SHA-256 integrity
    if compute_sha256_hex(&doc_str) != doc_sha {
        tracing::warn!("Corrupt policy document SHA-256 mismatch; skipping");
        return Ok(None);
    }

    let parsed: Value = match serde_json::from_str(&doc_str) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    match validate_policy_document(&parsed) {
        Ok(map) => Ok(Some(map)),
        Err(_) => Ok(None),
    }
}

/// Selects the most restrictive value among competing candidates for `key`.
fn pick_most_restrictive(key: &str, candidates: Vec<(String, Value)>) -> (String, Value) {
    match key {
        "require_approval" | "hide_network_settings" => {
            // For these, true is more restrictive than false
            for (src, val) in &candidates {
                if val.as_bool() == Some(true) {
                    return (src.clone(), json!(true));
                }
            }
            candidates.into_iter().next().unwrap()
        }
        "session.max_duration_minutes" | "policy.cache_ttl_seconds" => {
            // Smaller integer is more restrictive
            candidates
                .into_iter()
                .min_by_key(|(_, val)| val.as_i64().unwrap_or(i64::MAX))
                .unwrap()
        }
        _ => {
            // Standard boolean: false is more restrictive than true
            for (src, val) in &candidates {
                if val.as_bool() == Some(false) {
                    return (src.clone(), json!(false));
                }
            }
            candidates.into_iter().next().unwrap()
        }
    }
}
