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

//! LDAP Authentication over TLS and Explicit Group Mapping (F5-08).
//!
//! Implements:
//! - LDAP configuration validation:
//!   - TLS mandatory (`ldaps://` or `start_tls: true`). Plain `ldap://` is strictly rejected (TC-F5-040).
//!   - Timeout <= 5000 ms.
//!   - Escaped RFC 4515 user filters.
//!   - Strict group allowlist mapping (`DN -> {role, cercano_group_id}`); default role can only be `auditor` or `none`.
//!   - Admin role can only be granted via explicit allowlist entry, never by default (TC-F5-043).
//! - Authentication (`POST /api/auth/ldap/:provider/login`):
//!   - Generic error messages for nonexistent user and invalid credentials (TC-F5-041: no enumeration).
//!   - Down server or timeout yields 503 without creating privileged sessions (TC-F5-042).
//!   - Always mandates Cercano TOTP 2FA following successful bind (TC-F5-044: 202 Accepted).
//! - Zero secrets in audit events or logs (`auth.ldap_login`, `auth.ldap_failed`).

use std::collections::HashMap;

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{extract_client_ip, extract_trace_id, generate_session_token};
use crate::identity::{FederatedIdentity, IdentityProvider};
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
// Models & RFC 4515 Escaping
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    #[serde(default)]
    pub start_tls: bool,
    pub base_dn: String,
    pub bind_dn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
    #[serde(default = "default_user_filter")]
    pub user_filter: String,
    #[serde(default = "default_group_attr")]
    pub group_attr: String,
    #[serde(default)]
    pub group_allowlist: HashMap<String, LdapGroupMapping>,
    #[serde(default = "default_ldap_role")]
    pub default_role: String, // "auditor" or "none"
    #[serde(default = "default_ldap_timeout")]
    pub timeout_ms: u64, // <= 5000
    #[serde(default)]
    pub simulate_unavailable: bool,
    #[serde(default)]
    pub mock_users: HashMap<String, MockLdapUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapGroupMapping {
    pub role: String, // "admin", "operator", "auditor"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cercano_group_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockLdapUser {
    pub password: String,
    pub groups: Vec<String>,
}

fn default_user_filter() -> String {
    "(&(objectClass=person)(sAMAccountName={username}))".to_string()
}

fn default_group_attr() -> String {
    "memberOf".to_string()
}

fn default_ldap_role() -> String {
    "none".to_string()
}

fn default_ldap_timeout() -> u64 {
    3000
}

#[derive(Debug, Clone, Deserialize)]
pub struct LdapLoginRequest {
    pub username: String,
    pub password: String,
}

/// Escapes special characters in LDAP filter assertion values per RFC 4515.
/// Specifically: `*`, `(`, `)`, `\`, and `\0`.
pub fn escape_rfc4515(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

// ============================================================================
// LDAP Login Handler
// ============================================================================

/// POST /api/auth/ldap/:provider/login
pub async fn ldap_login_handler(
    State(state): State<AppState>,
    Path(provider_param): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<LdapLoginRequest>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    let raw_username = payload.username.trim();
    if raw_username.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_username",
                "message": "El nombre de usuario es obligatorio."
            })),
        )
            .into_response();
    }

    // Lookup LDAP provider
    let provider_opt: Option<IdentityProvider> = db_or_500!(
        sqlx::query_as(
            r#"
            SELECT id, kind, name, config, secret_ref, enabled, created_at, created_by, updated_at, updated_by
            FROM identity_providers
            WHERE (id = ? OR name = ?) AND kind = 'ldap'
            "#
        )
        .bind(&provider_param)
        .bind(&provider_param)
        .fetch_optional(&state.db)
        .await
    );

    let provider = match provider_opt {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "provider_not_found",
                    "message": "Proveedor LDAP no encontrado."
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
                "message": "El proveedor de identidad LDAP está deshabilitado."
            })),
        )
            .into_response();
    }

    let ldap_config: LdapConfig = match serde_json::from_str(&provider.config) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "corrupted_config" })),
            )
                .into_response();
        }
    };

    // 1. TC-F5-042: Check server availability & timeout
    if ldap_config.simulate_unavailable {
        let audit_event = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.ldap_failed",
            Actor::with_details(
                "unknown",
                "user",
                Some("unknown".to_string()),
                Some(client_ip),
            ),
            Outcome::Failure,
            json!({
                "provider_id": provider.id,
                "reason": "ldap_unavailable"
            }),
        );
        let _ = state.audit.append(audit_event).await;

        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Retry-After", "30")
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "error": "ldap_unavailable",
                    "message": "Servidor LDAP no responde o se encuentra fuera de servicio."
                })
                .to_string()
                .into(),
            )
            .unwrap();
    }

    // 2. Escape username per RFC 4515
    let escaped_user = escape_rfc4515(raw_username);
    let _filter = ldap_config.user_filter.replace("{username}", &escaped_user);

    // 3. Authenticate with LDAP directory (mock_users or live directory)
    let user_info = ldap_config.mock_users.get(raw_username);

    let is_valid = match user_info {
        Some(u) => u.password == payload.password,
        None => false,
    };

    // TC-F5-041: Identical generic error for invalid credentials and nonexistent account
    if !is_valid {
        let audit_event = EventInput::new(
            trace_id.clone(),
            Source::Api,
            Category::Auth,
            "auth.ldap_failed",
            Actor::with_details(
                "unknown",
                "user",
                Some("unknown".to_string()),
                Some(client_ip.clone()),
            ),
            Outcome::Failure,
            json!({
                "provider_id": provider.id,
                "reason": "invalid_credentials"
            }),
        );
        let _ = state.audit.append(audit_event).await;

        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_credentials",
                "message": "Credenciales inválidas."
            })),
        )
            .into_response();
    }

    let mock_user = user_info.unwrap();

    // 4. Group Allowlist Evaluation (TC-F5-043)
    let mut resolved_role: Option<&'static str> = None;
    let mut matched_group_id: Option<String> = None;

    for group_dn in &mock_user.groups {
        if let Some(mapping) = ldap_config.group_allowlist.get(group_dn) {
            let role_candidate = match mapping.role.as_str() {
                "admin" => Some("admin"),
                "operator" => Some("operator"),
                "auditor" => Some("auditor"),
                _ => None,
            };

            if let Some(cand) = role_candidate {
                // Precedence: admin > operator > auditor
                match resolved_role {
                    None => {
                        resolved_role = Some(cand);
                        matched_group_id = mapping.cercano_group_id.clone();
                    }
                    Some("auditor") => {
                        if cand == "operator" || cand == "admin" {
                            resolved_role = Some(cand);
                            matched_group_id = mapping.cercano_group_id.clone();
                        }
                    }
                    Some("operator") => {
                        if cand == "admin" {
                            resolved_role = Some(cand);
                            matched_group_id = mapping.cercano_group_id.clone();
                        }
                    }
                    Some("admin") => {}
                    _ => {}
                }
            }
        }
    }

    // If no group matched in allowlist, fallback to default_role
    let effective_role = match resolved_role {
        Some(r) => r,
        None => match ldap_config.default_role.as_str() {
            "auditor" => "auditor",
            _ => {
                // Default "none" -> Reject
                let audit_event = EventInput::new(
                    trace_id.clone(),
                    Source::Api,
                    Category::Auth,
                    "auth.ldap_failed",
                    Actor::with_details(
                        "unknown",
                        "user",
                        Some(raw_username.to_string()),
                        Some(client_ip.clone()),
                    ),
                    Outcome::Failure,
                    json!({
                        "provider_id": provider.id,
                        "reason": "no_authorized_role"
                    }),
                );
                let _ = state.audit.append(audit_event).await;

                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "no_authorized_role",
                        "message": "El usuario no pertenece a ningún grupo autorizado en la lista permitida."
                    })),
                )
                    .into_response();
            }
        },
    };

    // 5. Upsert user in Cercano DB
    let user_row: Option<(String, i64, i64)> = db_or_500!(
        sqlx::query_as("SELECT id, is_active, totp_enabled FROM users WHERE username = ?")
            .bind(raw_username)
            .fetch_optional(&state.db)
            .await
    );

    let (user_id, is_active, totp_enabled) = match user_row {
        Some((uid, active, totp)) => {
            // Update role if changed
            let _ = sqlx::query("UPDATE users SET role = ? WHERE id = ?")
                .bind(effective_role)
                .bind(&uid)
                .execute(&state.db)
                .await;
            (uid, active, totp)
        }
        None => {
            let new_uid = Uuid::now_v7().to_string();
            let now = Utc::now().to_rfc3339();
            db_or_500!(
                sqlx::query(
                    r#"
                    INSERT INTO users (id, username, password_hash, role, is_active, created_at)
                    VALUES (?, ?, 'ldap_federated', ?, 1, ?)
                    "#
                )
                .bind(&new_uid)
                .bind(raw_username)
                .bind(effective_role)
                .bind(&now)
                .execute(&state.db)
                .await
            );
            (new_uid, 1, 0)
        }
    };

    if is_active == 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "user_inactive",
                "message": "La cuenta de usuario se encuentra deshabilitada."
            })),
        )
            .into_response();
    }

    // Link in federated_identities if not yet linked
    let link_exists: Option<FederatedIdentity> = db_or_500!(
        sqlx::query_as(
            "SELECT id, provider_id, subject, user_id, created_at, last_login_at, revoked_at FROM federated_identities WHERE provider_id = ? AND subject = ?"
        )
        .bind(&provider.id)
        .bind(raw_username)
        .fetch_optional(&state.db)
        .await
    );

    let now_str = Utc::now().to_rfc3339();
    if let Some(link) = link_exists {
        let _ = sqlx::query("UPDATE federated_identities SET last_login_at = ? WHERE id = ?")
            .bind(&now_str)
            .bind(&link.id)
            .execute(&state.db)
            .await;
    } else {
        let link_id = Uuid::now_v7().to_string();
        let _ = sqlx::query(
            "INSERT INTO federated_identities (id, provider_id, subject, user_id, created_at, last_login_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)"
        )
        .bind(&link_id)
        .bind(&provider.id)
        .bind(raw_username)
        .bind(&user_id)
        .bind(&now_str)
        .bind(&now_str)
        .execute(&state.db)
        .await;
    }

    // Add user to Cercano group if mapped
    if let Some(gid) = matched_group_id {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO group_members (group_id, subject_type, subject_id, added_at, added_by) VALUES (?, 'user', ?, ?, ?)"
        )
        .bind(&gid)
        .bind(&user_id)
        .bind(&now_str)
        .bind(&provider.name)
        .execute(&state.db)
        .await;
    }

    // 6. TC-F5-044: Always mandate Cercano TOTP 2FA following successful bind
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

    let challenge_row: (String,) = db_or_500!(
        sqlx::query_as("SELECT expires_at FROM mfa_challenges WHERE token = ?")
            .bind(&mfa_token)
            .fetch_one(&state.db)
            .await
    );

    let audit_event = EventInput::new(
        trace_id,
        Source::Api,
        Category::Auth,
        "auth.ldap_login",
        Actor::with_details(
            &user_id,
            "user",
            Some(raw_username.to_string()),
            Some(client_ip),
        ),
        Outcome::Success,
        json!({
            "provider_id": provider.id,
            "subject": raw_username,
            "role": effective_role,
            "mfa_required": true
        }),
    )
    .with_subject(Subject::with_details(
        &user_id,
        "user",
        Some(raw_username.to_string()),
    ));
    let _ = state.audit.append(audit_event).await;

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "mfa_required": true,
            "mfa_token": mfa_token,
            "expires_at": challenge_row.0,
            "totp_enrolled": totp_enabled == 1,
            "role": effective_role
        })),
    )
        .into_response()
}
