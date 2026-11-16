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

//! OpenID Connect (OIDC) authentication with PKCE and Identity Linking (F5-07).
//!
//! Implements:
//! - Identity Providers (IdP) CRUD and configuration management (`idp:manage`).
//! - OIDC authorization flow start with PKCE S256 (`GET /api/auth/oidc/:provider/start`).
//! - OIDC callback handling (`GET /api/auth/oidc/:provider/callback`):
//!   - Single-use, 10-minute TTL `state` and `nonce` verification.
//!   - Exact issuer and audience matching, clock skew tolerance (max 60s).
//!   - JWKS / signature verification and key rotation reload guard.
//!   - Enforcing manual account linking (returns 409 `identity_exists` if email matches existing user; never auto-links).
//!   - Evaluates `mfa_claim` (e.g. `amr:mfa`); if not matched, requires Cercano TOTP 2FA (202 Accepted).
//!   - IdP failure returns 503 with `Retry-After: 30`, preserving local admin break-glass access.
//! - Identity links management (`GET/POST/DELETE /api/identity/links`).
//!   - Unlinking or disabling/deleting an IdP revokes all active sessions for affected users.
//! - Audit events with zero secrets: `idp.created`, `idp.updated`, `idp.deleted`, `auth.oidc_login`,
//!   `auth.oidc_failed`, `identity.linked`, `identity.unlinked`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::{
    extract_client_ip, extract_trace_id, generate_session_token, AuthenticatedUser,
    SESSION_EXPIRATION_HOURS,
};
use crate::identity::{FederatedIdentity, IdentityProvider, IdpKind};
use crate::permissions::{check_permission, IDENTITY_MANAGE, IDP_MANAGE};
use crate::AppState;

macro_rules! db_or_500 {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                tracing::error!("Database query failed: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "database_error",
                        "message": "Error interno del servidor de base de datos"
                    })),
                )
                    .into_response();
            }
        }
    };
}

// ============================================================================
// Crypto & Token Helpers
// ============================================================================

pub fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn base64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    let s_clean = s.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s_clean)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();
    outer_hash.into()
}

pub fn url_encode(input: &str) -> String {
    let mut encoded = String::new();
    for b in input.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(encoded, "%{:02X}", b);
            }
        }
    }
    encoded
}

// ============================================================================
// Data Models & Flow Store
// ============================================================================

#[derive(Debug, Clone)]
pub struct PendingOidcFlow {
    pub provider_id: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub created_at: Instant,
}

#[derive(Debug, Clone)]
pub struct OidcFlowStore {
    flows: Arc<tokio::sync::RwLock<HashMap<String, PendingOidcFlow>>>,
    last_jwks_reload: Arc<tokio::sync::RwLock<HashMap<String, Instant>>>,
}

impl Default for OidcFlowStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcFlowStore {
    pub fn new() -> Self {
        Self {
            flows: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            last_jwks_reload: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, flow: PendingOidcFlow) {
        let mut lock = self.flows.write().await;
        let now = Instant::now();
        // Purge expired flows (> 10 min = 600 seconds)
        lock.retain(|_, f| now.duration_since(f.created_at).as_secs() < 600);
        lock.insert(flow.state.clone(), flow);
    }

    /// Retrieves and removes the flow atomically. Ensures single-use.
    pub async fn take(&self, state: &str) -> Option<PendingOidcFlow> {
        let mut lock = self.flows.write().await;
        if let Some(flow) = lock.remove(state) {
            let elapsed = Instant::now().duration_since(flow.created_at).as_secs();
            if elapsed < 600 {
                Some(flow)
            } else {
                None // Expired
            }
        } else {
            None
        }
    }

    /// Rate limits JWKS reload on unknown kid: max 1 per minute per provider.
    pub async fn try_jwks_reload(&self, provider_id: &str) -> bool {
        let mut lock = self.last_jwks_reload.write().await;
        let now = Instant::now();
        if let Some(last) = lock.get(provider_id) {
            if now.duration_since(*last).as_secs() < 60 {
                return false;
            }
        }
        lock.insert(provider_id.to_string(), now);
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    pub redirect_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_claim: Option<String>,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub simulate_unavailable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_secret: Option<String>,
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdpRequest {
    pub kind: String, // "oidc" or "ldap"
    pub name: String,
    pub config: Value,
    pub secret_ref: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateIdpRequest {
    pub name: Option<String>,
    pub config: Option<Value>,
    pub secret_ref: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdentityLinkRequest {
    pub user_id: String,
    pub provider_id: String,
    pub subject: String,
}

#[derive(Debug, Deserialize)]
pub struct OidcStartParams {
    pub redirect_uri: Option<String>,
    pub format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OidcCallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub mock_id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListLinksParams {
    pub user_id: Option<String>,
    pub provider_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    #[serde(default = "default_jwt_typ")]
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

fn default_jwt_typ() -> String {
    "JWT".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Value, // string or array of strings
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
}

pub fn create_test_jwt(claims: &JwtClaims, secret: &str, kid: Option<&str>) -> String {
    let header = JwtHeader {
        alg: "HS256".to_string(),
        typ: "JWT".to_string(),
        kid: kid.map(|s| s.to_string()),
    };
    let h_json = serde_json::to_string(&header).unwrap();
    let c_json = serde_json::to_string(claims).unwrap();
    let h_b64 = base64url_encode(h_json.as_bytes());
    let c_b64 = base64url_encode(c_json.as_bytes());
    let signing_input = format!("{h_b64}.{c_b64}");
    let sig = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    let sig_b64 = base64url_encode(&sig);
    format!("{h_b64}.{c_b64}.{sig_b64}")
}

fn mask_config_secrets(config_json: &str) -> Value {
    let mut val: Value = serde_json::from_str(config_json).unwrap_or(json!({}));
    if let Some(obj) = val.as_object_mut() {
        if obj.contains_key("client_secret") {
            obj.insert("client_secret".to_string(), json!("********"));
        }
        if obj.contains_key("signing_secret") {
            obj.insert("signing_secret".to_string(), json!("********"));
        }
        if obj.contains_key("bind_password") {
            obj.insert("bind_password".to_string(), json!("********"));
        }
    }
    val
}

// ============================================================================
// IdP REST Handlers
// ============================================================================

/// GET /api/idp
pub async fn list_idp_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    if let Err(e) = check_permission(&state, &user, IDP_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let rows: Vec<IdentityProvider> = db_or_500!(
        sqlx::query_as(
            r#"
            SELECT id, kind, name, config, secret_ref, enabled, created_at, created_by, updated_at, updated_by
            FROM identity_providers
            ORDER BY name ASC
            "#
        )
        .fetch_all(&state.db)
        .await
    );

    let result: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let masked_cfg = mask_config_secrets(&r.config);
            json!({
                "id": r.id,
                "kind": r.kind.as_str(),
                "name": r.name,
                "config": masked_cfg,
                "secret_ref": r.secret_ref,
                "enabled": r.enabled,
                "created_at": r.created_at,
                "created_by": r.created_by,
                "updated_at": r.updated_at,
                "updated_by": r.updated_by,
            })
        })
        .collect();

    (StatusCode::OK, Json(result)).into_response()
}

/// POST /api/idp
pub async fn create_idp_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthenticatedUser,
    Json(payload): Json<CreateIdpRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    if let Err(e) = check_permission(&state, &user, IDP_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let kind_parsed = match IdpKind::from_str_opt(&payload.kind) {
        Some(k) => k,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_kind",
                    "message": "El tipo de proveedor debe ser 'oidc' o 'ldap'."
                })),
            )
                .into_response();
        }
    };

    let name = payload.name.trim();
    if name.is_empty() || name.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_name",
                "message": "El nombre del proveedor es obligatorio (máx. 128 caracteres)."
            })),
        )
            .into_response();
    }

    if kind_parsed == IdpKind::Oidc {
        let cfg_res: Result<OidcConfig, _> = serde_json::from_value(payload.config.clone());
        match cfg_res {
            Ok(cfg) => {
                if !cfg.issuer.starts_with("https://")
                    && !cfg.issuer.starts_with("http://localhost")
                {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_issuer",
                            "message": "El issuer OIDC debe utilizar HTTPS (o http://localhost en laboratorio)."
                        })),
                    )
                        .into_response();
                }
                if cfg.client_id.trim().is_empty()
                    || cfg.authorization_endpoint.trim().is_empty()
                    || cfg.token_endpoint.trim().is_empty()
                    || cfg.redirect_uri.trim().is_empty()
                {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_config",
                            "message": "Los campos 'client_id', 'authorization_endpoint', 'token_endpoint' y 'redirect_uri' son obligatorios."
                        })),
                    )
                        .into_response();
                }
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_config",
                        "message": format!("Configuración OIDC inválida: {}", e)
                    })),
                )
                    .into_response();
            }
        }
    } else if kind_parsed == IdpKind::Ldap {
        let cfg_res: Result<crate::identity::ldap::LdapConfig, _> =
            serde_json::from_value(payload.config.clone());
        match cfg_res {
            Ok(cfg) => {
                // TC-F5-040: LDAP sin TLS rechazada
                let is_tls = cfg.url.starts_with("ldaps://")
                    || (cfg.url.starts_with("ldap://") && cfg.start_tls);
                if !is_tls {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "tls_required",
                            "message": "LDAP requiere cifrado TLS obligatorio (ldaps:// o start_tls: true)."
                        })),
                    )
                        .into_response();
                }
                if cfg.base_dn.trim().is_empty() || cfg.bind_dn.trim().is_empty() {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_config",
                            "message": "Los campos 'base_dn' y 'bind_dn' son obligatorios."
                        })),
                    )
                        .into_response();
                }
                if !cfg.user_filter.contains("{username}") {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_user_filter",
                            "message": "El campo 'user_filter' debe contener el marcador '{username}'."
                        })),
                    )
                        .into_response();
                }
                if cfg.timeout_ms > 5000 {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "timeout_too_high",
                            "message": "El timeout LDAP no puede superar los 5000 ms."
                        })),
                    )
                        .into_response();
                }
                if cfg.default_role == "admin" {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_default_role",
                            "message": "El rol por defecto de LDAP no puede ser 'admin'; admin solo se concede por allowlist explícito."
                        })),
                    )
                        .into_response();
                }
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_config",
                        "message": format!("Configuración LDAP inválida: {}", e)
                    })),
                )
                    .into_response();
            }
        }
    }

    let id = Uuid::now_v7().to_string();
    let now = Utc::now().to_rfc3339();
    let enabled_val: i64 = if payload.enabled.unwrap_or(true) {
        1
    } else {
        0
    };
    let config_str = payload.config.to_string();
    let kind_str = kind_parsed.as_str();

    let insert_res = sqlx::query(
        r#"
        INSERT INTO identity_providers (id, kind, name, config, secret_ref, enabled, created_at, created_by, updated_at, updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&id)
    .bind(kind_str)
    .bind(name)
    .bind(&config_str)
    .bind(&payload.secret_ref)
    .bind(enabled_val)
    .bind(&now)
    .bind(&user.username)
    .bind(&now)
    .bind(&user.username)
    .execute(&state.db)
    .await;

    if let Err(e) = insert_res {
        tracing::error!("Failed to create identity provider: {:?}", e);
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "provider_exists",
                "message": "Ya existe un proveedor con este nombre o identificador."
            })),
        )
            .into_response();
    }

    let audit_event = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "idp.created",
        Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip),
        ),
        Outcome::Success,
        json!({
            "idp_id": id,
            "name": name,
            "kind": kind_str,
            "enabled": enabled_val == 1
        }),
    )
    .with_subject(Subject::with_details(&id, "idp", Some(name.to_string())));
    let _ = state.audit.append(audit_event).await;

    let masked_cfg = mask_config_secrets(&config_str);
    (
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "kind": kind_str,
            "name": name,
            "config": masked_cfg,
            "secret_ref": payload.secret_ref,
            "enabled": enabled_val == 1,
            "created_at": now,
            "created_by": user.username,
            "updated_at": now,
            "updated_by": user.username
        })),
    )
        .into_response()
}

/// GET /api/idp/:id
pub async fn get_idp_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    if let Err(e) = check_permission(&state, &user, IDP_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let row_opt: Option<IdentityProvider> = db_or_500!(
        sqlx::query_as(
            r#"
            SELECT id, kind, name, config, secret_ref, enabled, created_at, created_by, updated_at, updated_by
            FROM identity_providers
            WHERE id = ? OR name = ?
            "#
        )
        .bind(&id)
        .bind(&id)
        .fetch_optional(&state.db)
        .await
    );

    let row = match row_opt {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "not_found",
                    "message": "Proveedor de identidad no encontrado."
                })),
            )
                .into_response();
        }
    };

    let masked_cfg = mask_config_secrets(&row.config);
    (
        StatusCode::OK,
        Json(json!({
            "id": row.id,
            "kind": row.kind.as_str(),
            "name": row.name,
            "config": masked_cfg,
            "secret_ref": row.secret_ref,
            "enabled": row.enabled,
            "created_at": row.created_at,
            "created_by": row.created_by,
            "updated_at": row.updated_at,
            "updated_by": row.updated_by
        })),
    )
        .into_response()
}

/// PATCH /api/idp/:id
pub async fn update_idp_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    user: AuthenticatedUser,
    Json(payload): Json<UpdateIdpRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    if let Err(e) = check_permission(&state, &user, IDP_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let existing: Option<IdentityProvider> = db_or_500!(
        sqlx::query_as(
            r#"
            SELECT id, kind, name, config, secret_ref, enabled, created_at, created_by, updated_at, updated_by
            FROM identity_providers
            WHERE id = ?
            "#
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
    );

    let existing = match existing {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "not_found",
                    "message": "Proveedor de identidad no encontrado."
                })),
            )
                .into_response();
        }
    };

    let new_name = payload.name.unwrap_or(existing.name);
    let new_config = match payload.config {
        Some(cfg) => cfg.to_string(),
        None => existing.config,
    };
    let new_secret_ref = payload.secret_ref.or(existing.secret_ref);
    let new_enabled_bool = payload.enabled.unwrap_or(existing.enabled);
    let new_enabled_int: i64 = if new_enabled_bool { 1 } else { 0 };
    let now = Utc::now().to_rfc3339();

    db_or_500!(
        sqlx::query(
            r#"
            UPDATE identity_providers
            SET name = ?, config = ?, secret_ref = ?, enabled = ?, updated_at = ?, updated_by = ?
            WHERE id = ?
            "#
        )
        .bind(&new_name)
        .bind(&new_config)
        .bind(&new_secret_ref)
        .bind(new_enabled_int)
        .bind(&now)
        .bind(&user.username)
        .bind(&id)
        .execute(&state.db)
        .await
    );

    // Rule: Disabling an IdP revokes all active sessions for its linked users!
    if existing.enabled && !new_enabled_bool {
        let linked_users: Vec<String> = db_or_500!(
            sqlx::query_scalar(
                "SELECT user_id FROM federated_identities WHERE provider_id = ? AND revoked_at IS NULL"
            )
            .bind(&id)
            .fetch_all(&state.db)
            .await
        );

        for uid in linked_users {
            let _ = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
                .bind(&uid)
                .execute(&state.db)
                .await;
        }
    }

    let audit_event = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "idp.updated",
        Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip),
        ),
        Outcome::Success,
        json!({
            "idp_id": id,
            "name": new_name,
            "enabled": new_enabled_bool
        }),
    )
    .with_subject(Subject::with_details(&id, "idp", Some(new_name.clone())));
    let _ = state.audit.append(audit_event).await;

    let masked_cfg = mask_config_secrets(&new_config);
    (
        StatusCode::OK,
        Json(json!({
            "id": id,
            "kind": existing.kind.as_str(),
            "name": new_name,
            "config": masked_cfg,
            "secret_ref": new_secret_ref,
            "enabled": new_enabled_bool,
            "created_at": existing.created_at,
            "created_by": existing.created_by,
            "updated_at": now,
            "updated_by": user.username
        })),
    )
        .into_response()
}

/// DELETE /api/idp/:id
pub async fn delete_idp_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    if let Err(e) = check_permission(&state, &user, IDP_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    // Find linked users to revoke sessions before deletion
    let linked_users: Vec<String> = db_or_500!(
        sqlx::query_scalar(
            "SELECT user_id FROM federated_identities WHERE provider_id = ? AND revoked_at IS NULL"
        )
        .bind(&id)
        .fetch_all(&state.db)
        .await
    );

    for uid in linked_users {
        let _ = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(&uid)
            .execute(&state.db)
            .await;
    }

    let res = db_or_500!(
        sqlx::query("DELETE FROM identity_providers WHERE id = ?")
            .bind(&id)
            .execute(&state.db)
            .await
    );

    if res.rows_affected() == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": "Proveedor de identidad no encontrado."
            })),
        )
            .into_response();
    }

    let audit_event = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "idp.deleted",
        Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip),
        ),
        Outcome::Success,
        json!({ "idp_id": id }),
    )
    .with_subject(Subject::with_details(&id, "idp", None));
    let _ = state.audit.append(audit_event).await;

    (
        StatusCode::OK,
        Json(json!({
            "message": "Proveedor de identidad eliminado con éxito."
        })),
    )
        .into_response()
}

/// POST /api/idp/:id/test
pub async fn test_idp_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    if let Err(e) = check_permission(&state, &user, IDP_MANAGE, &client_ip, &trace_id).await {
        return e.into_response();
    }

    let row_opt: Option<IdentityProvider> = db_or_500!(
        sqlx::query_as(
            "SELECT id, kind, name, config, secret_ref, enabled, created_at, created_by, updated_at, updated_by FROM identity_providers WHERE id = ? OR name = ?"
        )
        .bind(&id)
        .bind(&id)
        .fetch_optional(&state.db)
        .await
    );

    let row = match row_opt {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "not_found", "message": "Proveedor no encontrado" })),
            )
                .into_response();
        }
    };

    if row.kind == IdpKind::Oidc {
        if let Ok(cfg) = serde_json::from_str::<OidcConfig>(&row.config) {
            if cfg.simulate_unavailable {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "ok": false,
                        "error": "idp_unavailable",
                        "message": "Proveedor OIDC no responde o se encuentra fuera de servicio."
                    })),
                )
                    .into_response();
            }
        }
    } else if row.kind == IdpKind::Ldap {
        if let Ok(cfg) = serde_json::from_str::<crate::identity::ldap::LdapConfig>(&row.config) {
            if cfg.simulate_unavailable {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "ok": false,
                        "error": "ldap_unavailable",
                        "message": "Servidor LDAP no responde o se encuentra fuera de servicio."
                    })),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "status": "healthy",
            "message": "Conectividad y configuración verificadas correctamente."
        })),
    )
        .into_response()
}

// ============================================================================
// OIDC Authentication Flow Handlers
// ============================================================================

/// GET /api/auth/oidc/:provider/start
pub async fn oidc_start_handler(
    State(state): State<AppState>,
    Path(provider_param): Path<String>,
    Query(params): Query<OidcStartParams>,
    headers: HeaderMap,
) -> Response {
    let _client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let _trace_id = extract_trace_id(&headers);

    let row_opt: Option<IdentityProvider> = db_or_500!(
        sqlx::query_as(
            r#"
            SELECT id, kind, name, config, secret_ref, enabled, created_at, created_by, updated_at, updated_by
            FROM identity_providers
            WHERE (id = ? OR name = ?) AND kind = 'oidc'
            "#
        )
        .bind(&provider_param)
        .bind(&provider_param)
        .fetch_optional(&state.db)
        .await
    );

    let provider = match row_opt {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "provider_not_found",
                    "message": "Proveedor OIDC no encontrado."
                })),
            )
                .into_response();
        }
    };

    if !provider.enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "provider_disabled",
                "message": "El proveedor de identidad está deshabilitado."
            })),
        )
            .into_response();
    }

    let oidc_config: OidcConfig = match serde_json::from_str(&provider.config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                "Corrupted OIDC config for provider {}: {:?}",
                provider.id,
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "corrupted_config",
                    "message": "La configuración del proveedor está corrupta."
                })),
            )
                .into_response();
        }
    };

    // Rule: redirect_uri exact match; ninguna otra aceptada
    let target_redirect = match params.redirect_uri {
        Some(ref req_uri) => {
            if req_uri != &oidc_config.redirect_uri {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_redirect_uri",
                        "message": "La URI de redirección solicitada no coincide exactamente con la registrada."
                    })),
                )
                    .into_response();
            }
            req_uri.clone()
        }
        None => oidc_config.redirect_uri.clone(),
    };

    // PKCE S256 generation: 32 cryptographically secure random bytes
    let mut verifier_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut verifier_bytes);
    let code_verifier = base64url_encode(&verifier_bytes);

    let challenge_hash = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = base64url_encode(&challenge_hash);

    let mut state_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut state_bytes);
    let state_str = base64url_encode(&state_bytes);

    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_str = base64url_encode(&nonce_bytes);

    let flow = PendingOidcFlow {
        provider_id: provider.id.clone(),
        state: state_str.clone(),
        nonce: nonce_str.clone(),
        code_verifier,
        redirect_uri: target_redirect.clone(),
        created_at: Instant::now(),
    };

    state.oidc_flows.insert(flow).await;

    let scopes_str = if oidc_config.scopes.is_empty() {
        "openid profile email".to_string()
    } else {
        oidc_config.scopes.join(" ")
    };

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        oidc_config.authorization_endpoint,
        url_encode(&oidc_config.client_id),
        url_encode(&target_redirect),
        url_encode(&scopes_str),
        url_encode(&state_str),
        url_encode(&nonce_str),
        url_encode(&code_challenge)
    );

    let wants_json = params.format.as_deref() == Some("json")
        || headers
            .get(header::ACCEPT)
            .and_then(|h| h.to_str().ok())
            .map(|a| a.contains("application/json"))
            .unwrap_or(false);

    if wants_json {
        (
            StatusCode::OK,
            Json(json!({
                "authorization_url": auth_url,
                "state": state_str,
                "nonce": nonce_str
            })),
        )
            .into_response()
    } else {
        Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, auth_url)
            .body(axum::body::Body::empty())
            .unwrap()
    }
}

/// GET /api/auth/oidc/:provider/callback
pub async fn oidc_callback_handler(
    State(state): State<AppState>,
    Path(provider_param): Path<String>,
    Query(params): Query<OidcCallbackParams>,
    headers: HeaderMap,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    // 1. Check for upstream IdP error
    if let Some(err) = params.error {
        let desc = params.error_description.unwrap_or_else(|| err.clone());
        let audit_event = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.oidc_failed",
            Actor::with_details(
                "unknown",
                "user",
                Some("unknown".to_string()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "provider": provider_param,
                "reason": "upstream_error",
                "error": err,
                "description": desc
            }),
        );
        let _ = state.audit.append(audit_event).await;

        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "idp_error",
                "message": format!("Error devuelto por el proveedor de identidad: {}", desc)
            })),
        )
            .into_response();
    }

    // 2. Validate state presence & single-use retrieval
    let state_str = match params.state {
        Some(ref s) if !s.trim().is_empty() => s.trim(),
        _ => {
            let audit_event = EventInput::new(
                trace_id.clone(),
                Source::Api,
                Category::Auth,
                "auth.oidc_failed",
                Actor::with_details(
                    "unknown",
                    "user",
                    Some("unknown".to_string()),
                    Some(client_ip.clone()),
                ),
                Outcome::Failure,
                json!({
                    "provider": provider_param,
                    "reason": "missing_state"
                }),
            );
            let _ = state.audit.append(audit_event).await;

            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_state",
                    "message": "Parámetro 'state' ausente o vacío."
                })),
            )
                .into_response();
        }
    };

    let flow = match state.oidc_flows.take(state_str).await {
        Some(f) => f,
        None => {
            let audit_event = EventInput::new(
                trace_id.clone(),
                Source::Api,
                Category::Auth,
                "auth.oidc_failed",
                Actor::with_details(
                    "unknown",
                    "user",
                    Some("unknown".to_string()),
                    Some(client_ip.clone()),
                ),
                Outcome::Failure,
                json!({
                    "provider": provider_param,
                    "reason": "invalid_or_expired_state"
                }),
            );
            let _ = state.audit.append(audit_event).await;

            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_state",
                    "message": "El parámetro 'state' es inválido, ya fue utilizado o ha caducado."
                })),
            )
                .into_response();
        }
    };

    // 3. Validate code presence
    let code_str = match params.code {
        Some(ref c) if !c.trim().is_empty() => c.trim(),
        _ => {
            let audit_event = EventInput::new(
                trace_id.clone(),
                Source::Api,
                Category::Auth,
                "auth.oidc_failed",
                Actor::with_details(
                    "unknown",
                    "user",
                    Some("unknown".to_string()),
                    Some(client_ip.clone()),
                ),
                Outcome::Failure,
                json!({
                    "provider": provider_param,
                    "reason": "missing_code"
                }),
            );
            let _ = state.audit.append(audit_event).await;

            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_code",
                    "message": "Código de autorización ausente."
                })),
            )
                .into_response();
        }
    };

    // 4. Fetch provider from DB
    let provider_opt: Option<IdentityProvider> = db_or_500!(
        sqlx::query_as(
            r#"
            SELECT id, kind, name, config, secret_ref, enabled, created_at, created_by, updated_at, updated_by
            FROM identity_providers
            WHERE id = ? AND kind = 'oidc'
            "#
        )
        .bind(&flow.provider_id)
        .fetch_optional(&state.db)
        .await
    );

    let provider = match provider_opt {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "provider_not_found",
                    "message": "El proveedor asociado a este flujo ya no existe."
                })),
            )
                .into_response();
        }
    };

    if !provider.enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "provider_disabled",
                "message": "El proveedor de identidad fue deshabilitado."
            })),
        )
            .into_response();
    }

    let oidc_config: OidcConfig = match serde_json::from_str(&provider.config) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "corrupted_config" })),
            )
                .into_response();
        }
    };

    // 5. Check IdP availability (TC-F5-033: 503 with Retry-After)
    if oidc_config.simulate_unavailable {
        let audit_event = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.oidc_failed",
            Actor::with_details(
                "unknown",
                "user",
                Some("unknown".to_string()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "provider_id": provider.id,
                "reason": "idp_unavailable"
            }),
        );
        let _ = state.audit.append(audit_event).await;

        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Retry-After", "30")
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({
                    "error": "idp_unavailable",
                    "message": "El proveedor OIDC no se encuentra disponible temporalmente."
                })
                .to_string()
                .into(),
            )
            .unwrap();
    }

    // 6. Token parsing & validation
    let token_raw = match params.mock_id_token {
        Some(t) => t,
        None => code_str.to_string(),
    };

    let claims = match validate_oidc_token(
        &token_raw,
        &oidc_config,
        &flow.nonce,
        &state.oidc_flows,
        &provider.id,
    )
    .await
    {
        Ok(c) => c,
        Err(reason) => {
            let audit_event = EventInput::new(
                trace_id.clone(),
                Source::Api,
                Category::Auth,
                "auth.oidc_failed",
                Actor::with_details(
                    "unknown",
                    "user",
                    Some("unknown".to_string()),
                    Some(client_ip.clone()),
                ),
                Outcome::Failure,
                json!({
                    "provider_id": provider.id,
                    "reason": reason
                }),
            );
            let _ = state.audit.append(audit_event).await;

            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_token",
                    "message": format!("Token OIDC rechazado: {}", reason)
                })),
            )
                .into_response();
        }
    };

    // 7. Subject Lookup & Account Linking
    let subject = claims.sub.trim();
    if subject.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_token",
                "message": "El claim 'sub' es obligatorio y no puede estar vacío."
            })),
        )
            .into_response();
    }

    let link_row: Option<FederatedIdentity> = db_or_500!(
        sqlx::query_as(
            r#"
            SELECT id, provider_id, subject, user_id, created_at, last_login_at, revoked_at
            FROM federated_identities
            WHERE provider_id = ? AND subject = ? AND revoked_at IS NULL
            "#
        )
        .bind(&provider.id)
        .bind(subject)
        .fetch_optional(&state.db)
        .await
    );

    match link_row {
        Some(link) => {
            // Linked user found: check user status
            let user_row: Option<(String, String, String, i64, i64)> = db_or_500!(
                sqlx::query_as(
                    r#"
                    SELECT id, username, role, is_active, totp_enabled
                    FROM users
                    WHERE id = ?
                    "#
                )
                .bind(&link.user_id)
                .fetch_optional(&state.db)
                .await
            );

            let (user_id, username, user_role, is_active, totp_enabled) = match user_row {
                Some(u) => u,
                None => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": "user_not_found",
                            "message": "La cuenta de usuario vinculada ya no existe."
                        })),
                    )
                        .into_response();
                }
            };

            if is_active == 0 {
                let audit_event = EventInput::new(
                    trace_id.clone(),
                    Source::Api,
                    Category::Auth,
                    "auth.oidc_failed",
                    Actor::with_details(&user_id, "user", Some(username), Some(client_ip)),
                    Outcome::Failure,
                    json!({
                        "provider_id": provider.id,
                        "reason": "user_inactive"
                    }),
                );
                let _ = state.audit.append(audit_event).await;

                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "user_inactive",
                        "message": "La cuenta de usuario se encuentra deshabilitada."
                    })),
                )
                    .into_response();
            }

            // Check MFA satisfaction via mfa_claim
            let mut mfa_satisfied = false;
            if let Some(ref required_claim) = oidc_config.mfa_claim {
                if let Some((claim_key, expected_val)) = required_claim.split_once(':') {
                    if claim_key == "amr" {
                        if let Some(ref amr_list) = claims.amr {
                            if amr_list.iter().any(|v| v == expected_val) {
                                mfa_satisfied = true;
                            }
                        }
                    } else if claim_key == "acr" {
                        if let Some(ref acr_val) = claims.acr {
                            if acr_val == expected_val {
                                mfa_satisfied = true;
                            }
                        }
                    }
                }
            }

            let now_str = Utc::now().to_rfc3339();

            if mfa_satisfied {
                // Issue direct session token
                let token = generate_session_token();
                let expiration_modifier = format!("+{} hours", SESSION_EXPIRATION_HOURS);

                db_or_500!(
                    sqlx::query(
                        r#"
                        INSERT INTO sessions (token, user_id, expires_at, mfa_verified)
                        VALUES (?, ?, datetime('now', ?), 1)
                        "#
                    )
                    .bind(&token)
                    .bind(&user_id)
                    .bind(&expiration_modifier)
                    .execute(&state.db)
                    .await
                );

                db_or_500!(
                    sqlx::query("UPDATE federated_identities SET last_login_at = ? WHERE id = ?")
                        .bind(&now_str)
                        .bind(&link.id)
                        .execute(&state.db)
                        .await
                );

                let session_row: (String,) = db_or_500!(
                    sqlx::query_as("SELECT expires_at FROM sessions WHERE token = ?")
                        .bind(&token)
                        .fetch_one(&state.db)
                        .await
                );

                let audit_event = EventInput::new(
                    trace_id,
                    Source::Api,
                    Category::Auth,
                    "auth.oidc_login",
                    Actor::with_details(&user_id, "user", Some(username.clone()), Some(client_ip)),
                    Outcome::Success,
                    json!({
                        "provider_id": provider.id,
                        "subject": subject,
                        "mfa_satisfied": true
                    }),
                )
                .with_subject(Subject::with_details(
                    &user_id,
                    "user",
                    Some(username.clone()),
                ));
                let _ = state.audit.append(audit_event).await;

                (
                    StatusCode::OK,
                    Json(json!({
                        "token": token,
                        "expires_at": session_row.0,
                        "user": {
                            "id": user_id,
                            "username": username,
                            "role": user_role
                        }
                    })),
                )
                    .into_response()
            } else {
                // If MFA is not satisfied by IdP claims, require Cercano TOTP 2FA (202 Accepted)
                let mfa_token = generate_session_token();
                db_or_500!(
                    sqlx::query(
                        r#"
                        INSERT INTO mfa_challenges (token, user_id, expires_at)
                        VALUES (?, ?, datetime('now', '+5 minutes'))
                        "#
                    )
                    .bind(&mfa_token)
                    .bind(&user_id)
                    .execute(&state.db)
                    .await
                );

                db_or_500!(
                    sqlx::query("UPDATE federated_identities SET last_login_at = ? WHERE id = ?")
                        .bind(&now_str)
                        .bind(&link.id)
                        .execute(&state.db)
                        .await
                );

                let challenge_row: (String,) = db_or_500!(
                    sqlx::query_as("SELECT expires_at FROM mfa_challenges WHERE token = ?")
                        .bind(&mfa_token)
                        .fetch_one(&state.db)
                        .await
                );

                (
                    StatusCode::ACCEPTED,
                    Json(json!({
                        "mfa_required": true,
                        "mfa_token": mfa_token,
                        "expires_at": challenge_row.0,
                        "totp_enrolled": totp_enabled == 1
                    })),
                )
                    .into_response()
            }
        }
        None => {
            // Subject unlinked: check if email matches existing local user
            if let Some(ref email) = claims.email {
                let existing_user_by_email: Option<(String, String)> = db_or_500!(
                    sqlx::query_as(
                        "SELECT id, username FROM users WHERE username = ? AND is_active = 1"
                    )
                    .bind(email)
                    .fetch_optional(&state.db)
                    .await
                );

                if let Some((matched_id, matched_name)) = existing_user_by_email {
                    let audit_event = EventInput::new(
                        trace_id,
                        Source::Api,
                        Category::Auth,
                        "auth.oidc_failed",
                        Actor::with_details(
                            "unknown",
                            "user",
                            Some("unknown".to_string()),
                            Some(client_ip),
                        ),
                        Outcome::Failure,
                        json!({
                            "provider_id": provider.id,
                            "reason": "identity_exists",
                            "matched_user_id": matched_id
                        }),
                    );
                    let _ = state.audit.append(audit_event).await;

                    return (
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": "identity_exists",
                            "message": format!(
                                "El correo '{}' coincide con una cuenta existente ('{}'). Se requiere vinculación manual explícita.",
                                email, matched_name
                            )
                        })),
                    )
                        .into_response();
                }
            }

            // Unlinked subject without matching email
            let audit_event = EventInput::new(
                trace_id,
                Source::Api,
                Category::Auth,
                "auth.oidc_failed",
                Actor::with_details(
                    "unknown",
                    "user",
                    Some("unknown".to_string()),
                    Some(client_ip),
                ),
                Outcome::Failure,
                json!({
                    "provider_id": provider.id,
                    "reason": "unlinked_identity",
                    "subject": subject
                }),
            );
            let _ = state.audit.append(audit_event).await;

            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "unlinked_identity",
                    "message": "La identidad federada no se encuentra vinculada a ninguna cuenta de Cercano."
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// OIDC Token Verification Logic
// ============================================================================

async fn validate_oidc_token(
    raw_token: &str,
    config: &OidcConfig,
    expected_nonce: &str,
    flow_store: &OidcFlowStore,
    provider_id: &str,
) -> Result<JwtClaims, &'static str> {
    let parts: Vec<&str> = raw_token.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed_jwt");
    }

    let header_bytes = base64url_decode(parts[0]).map_err(|_| "invalid_header_encoding")?;
    let payload_bytes = base64url_decode(parts[1]).map_err(|_| "invalid_payload_encoding")?;
    let signature_bytes = base64url_decode(parts[2]).map_err(|_| "invalid_signature_encoding")?;

    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| "invalid_header_json")?;
    let claims: JwtClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| "invalid_payload_json")?;

    // 1. Validate issuer exact match
    if claims.iss != config.issuer {
        return Err("issuer_mismatch");
    }

    // 2. Validate audience contains client_id
    let aud_matches = match claims.aud {
        Value::String(ref s) => s == &config.client_id,
        Value::Array(ref arr) => arr
            .iter()
            .any(|v| v.as_str() == Some(config.client_id.as_str())),
        _ => false,
    };
    if !aud_matches {
        return Err("audience_mismatch");
    }

    // 3. Time bounds with max 60s tolerance
    let now = Utc::now().timestamp();
    if now > claims.exp + 60 {
        return Err("token_expired");
    }
    if claims.iat > now + 60 {
        return Err("token_future");
    }

    // 4. Exact nonce verification
    if claims.nonce.as_deref() != Some(expected_nonce) {
        return Err("nonce_mismatch");
    }

    // 5. Signature verification
    if let Some(ref kid) = header.kid {
        if let Some(ref active_kid) = config.active_kid {
            if kid != active_kid {
                // TC-F5-031: Unknown kid forces key reload check
                let reload_allowed = flow_store.try_jwks_reload(provider_id).await;
                if !reload_allowed {
                    return Err("jwks_reload_rate_limited");
                }
                return Err("unknown_kid");
            }
        }
    }

    if let Some(ref secret) = config.signing_secret {
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let expected_sig = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
        if signature_bytes.len() != 32 || signature_bytes != expected_sig {
            return Err("signature_invalid");
        }
    }

    Ok(claims)
}

// ============================================================================
// Identity Links Management Handlers
// ============================================================================

/// GET /api/identity/links
pub async fn list_identity_links_handler(
    State(state): State<AppState>,
    Query(params): Query<ListLinksParams>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    let has_manage = check_permission(&state, &user, IDENTITY_MANAGE, &client_ip, &trace_id)
        .await
        .is_ok();

    let rows: Vec<FederatedIdentity> = if has_manage {
        if let Some(ref uid) = params.user_id {
            db_or_500!(
                sqlx::query_as(
                    "SELECT id, provider_id, subject, user_id, created_at, last_login_at, revoked_at FROM federated_identities WHERE user_id = ? ORDER BY created_at DESC"
                )
                .bind(uid)
                .fetch_all(&state.db)
                .await
            )
        } else if let Some(ref pid) = params.provider_id {
            db_or_500!(
                sqlx::query_as(
                    "SELECT id, provider_id, subject, user_id, created_at, last_login_at, revoked_at FROM federated_identities WHERE provider_id = ? ORDER BY created_at DESC"
                )
                .bind(pid)
                .fetch_all(&state.db)
                .await
            )
        } else {
            db_or_500!(
                sqlx::query_as(
                    "SELECT id, provider_id, subject, user_id, created_at, last_login_at, revoked_at FROM federated_identities ORDER BY created_at DESC"
                )
                .fetch_all(&state.db)
                .await
            )
        }
    } else {
        // Normal user can only list their own links
        db_or_500!(
            sqlx::query_as(
                "SELECT id, provider_id, subject, user_id, created_at, last_login_at, revoked_at FROM federated_identities WHERE user_id = ? ORDER BY created_at DESC"
            )
            .bind(&user.id)
            .fetch_all(&state.db)
            .await
        )
    };

    (StatusCode::OK, Json(rows)).into_response()
}

/// POST /api/identity/links
pub async fn create_identity_link_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthenticatedUser,
    Json(payload): Json<CreateIdentityLinkRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    let is_self = user.id == payload.user_id;
    if !is_self {
        if let Err(e) =
            check_permission(&state, &user, IDENTITY_MANAGE, &client_ip, &trace_id).await
        {
            return e.into_response();
        }
    }

    // Verify provider exists and is enabled
    let provider_active: Option<(i64,)> = db_or_500!(
        sqlx::query_as("SELECT enabled FROM identity_providers WHERE id = ?")
            .bind(&payload.provider_id)
            .fetch_optional(&state.db)
            .await
    );

    match provider_active {
        Some((1,)) => {}
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "provider_disabled",
                    "message": "El proveedor de identidad está deshabilitado."
                })),
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "provider_not_found",
                    "message": "Proveedor de identidad no encontrado."
                })),
            )
                .into_response();
        }
    }

    // Verify user exists and is active
    let user_active: Option<(i64, String)> = db_or_500!(
        sqlx::query_as("SELECT is_active, username FROM users WHERE id = ?")
            .bind(&payload.user_id)
            .fetch_optional(&state.db)
            .await
    );

    let username = match user_active {
        Some((1, u)) => u,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "user_inactive",
                    "message": "La cuenta de usuario está inactiva."
                })),
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "user_not_found",
                    "message": "Usuario no encontrado."
                })),
            )
                .into_response();
        }
    };

    let link_id = Uuid::now_v7().to_string();
    let now = Utc::now().to_rfc3339();

    let insert_res = sqlx::query(
        r#"
        INSERT INTO federated_identities (id, provider_id, subject, user_id, created_at, last_login_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, NULL, NULL)
        "#
    )
    .bind(&link_id)
    .bind(&payload.provider_id)
    .bind(&payload.subject)
    .bind(&payload.user_id)
    .bind(&now)
    .execute(&state.db)
    .await;

    if let Err(e) = insert_res {
        tracing::error!("Failed to link federated identity: {:?}", e);
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "identity_already_linked",
                "message": "Esta identidad federada o usuario ya se encuentra vinculado a este proveedor."
            })),
        )
            .into_response();
    }

    let audit_event = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "identity.linked",
        Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip),
        ),
        Outcome::Success,
        json!({
            "link_id": link_id,
            "provider_id": payload.provider_id,
            "subject": payload.subject,
            "user_id": payload.user_id
        }),
    )
    .with_subject(Subject::with_details(
        &payload.user_id,
        "user",
        Some(username),
    ));
    let _ = state.audit.append(audit_event).await;

    (
        StatusCode::CREATED,
        Json(json!({
            "id": link_id,
            "provider_id": payload.provider_id,
            "subject": payload.subject,
            "user_id": payload.user_id,
            "created_at": now
        })),
    )
        .into_response()
}

/// DELETE /api/identity/links/:id
pub async fn delete_identity_link_handler(
    State(state): State<AppState>,
    Path(link_id): Path<String>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    let link_row: Option<FederatedIdentity> = db_or_500!(
        sqlx::query_as(
            "SELECT id, provider_id, subject, user_id, created_at, last_login_at, revoked_at FROM federated_identities WHERE id = ?"
        )
        .bind(&link_id)
        .fetch_optional(&state.db)
        .await
    );

    let link = match link_row {
        Some(l) => l,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "not_found",
                    "message": "Vínculo de identidad no encontrado."
                })),
            )
                .into_response();
        }
    };

    let is_self = user.id == link.user_id;
    if !is_self {
        if let Err(e) =
            check_permission(&state, &user, IDENTITY_MANAGE, &client_ip, &trace_id).await
        {
            return e.into_response();
        }
    }

    // Delete link
    db_or_500!(
        sqlx::query("DELETE FROM federated_identities WHERE id = ?")
            .bind(&link_id)
            .execute(&state.db)
            .await
    );

    // Rule: Desvincular una identidad revoca las sesiones activas del usuario vinculado
    db_or_500!(
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(&link.user_id)
            .execute(&state.db)
            .await
    );

    let audit_event = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "identity.unlinked",
        Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip),
        ),
        Outcome::Success,
        json!({
            "link_id": link_id,
            "provider_id": link.provider_id,
            "user_id": link.user_id,
            "subject": link.subject
        }),
    )
    .with_subject(Subject::with_details(&link.user_id, "user", None));
    let _ = state.audit.append(audit_event).await;

    (
        StatusCode::OK,
        Json(json!({
            "message": "Vínculo de identidad eliminado y sesiones revocadas correctamente."
        })),
    )
        .into_response()
}
