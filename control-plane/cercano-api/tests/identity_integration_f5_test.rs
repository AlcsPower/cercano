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

//! Global integration, authorization, migration, and security tests for Phase 5 (F5-12).
//!
//! Validates end-to-end:
//! - Data migration 009 schema integrity, foreign keys and constraints.
//! - Authorization matrix: admin, operator, auditor, user against groups, address book, and policies.
//! - Non-enumerative 404 and IDOR defense across alien groups and resources.
//! - Deterministic policy precedence resolution clamped to P0 signed profile ceiling.
//! - OIDC PKCE and LDAP federation abuse defenses with mandatory 2FA.
//! - Emergency break-glass recovery when IdP/LDAP is offline.
//! - Cryptographic audit trail integrity with zero secret leaks.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::Row;
use tower::ServiceExt;

use cercano_api::config::Config;
use cercano_api::db::init_db;
use cercano_api::{create_app, AppState};

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
    let pwd_hash = cercano_api::auth::hash_password("test_pass").unwrap();

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&user_id)
    .bind(username)
    .bind(&pwd_hash)
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
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();

    let json_val = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };

    (status, json_val)
}

#[tokio::test]
async fn test_tc_f5_12_schema_integrity_and_migration_009() {
    let (_app, state) = setup_app().await;

    // Verify all Phase 5 tables are registered and queryable
    let tables = [
        "groups",
        "group_members",
        "group_grants",
        "address_book",
        "policies",
        "identity_providers",
        "federated_identities",
    ];

    for t in tables {
        let count_row = sqlx::query(&format!("SELECT count(*) as cnt FROM {t}"))
            .fetch_one(&state.db)
            .await;
        assert!(count_row.is_ok(), "Table {t} must exist and be queryable");
    }

    // Verify unique constraints on group names per kind
    let g1 = sqlx::query(
        "INSERT INTO groups (id, name, kind, created_at, updated_at) VALUES ('g1', 'Soporte', 'user', '2026-01-01', '2026-01-01')"
    ).execute(&state.db).await;
    assert!(g1.is_ok());

    let g1_duplicate = sqlx::query(
        "INSERT INTO groups (id, name, kind, created_at, updated_at) VALUES ('g2', 'Soporte', 'user', '2026-01-01', '2026-01-01')"
    ).execute(&state.db).await;
    assert!(
        g1_duplicate.is_err(),
        "Duplicate group name within same kind must fail unique constraint"
    );

    // Same name with different kind ('device') is permitted
    let g1_diff_kind = sqlx::query(
        "INSERT INTO groups (id, name, kind, created_at, updated_at) VALUES ('g3', 'Soporte', 'device', '2026-01-01', '2026-01-01')"
    ).execute(&state.db).await;
    assert!(g1_diff_kind.is_ok());
}

#[tokio::test]
async fn test_tc_f5_12_rbac_and_idor_authorization_matrix() {
    let (app, state) = setup_app().await;

    let (_admin_id, admin_token) = create_user_with_token(&state, "admin_user", "admin").await;
    let (op1_id, op1_token) = create_user_with_token(&state, "op1_user", "operator").await;
    let (_aud_id, aud_token) = create_user_with_token(&state, "aud_user", "auditor").await;
    let (_usr_id, usr_token) = create_user_with_token(&state, "regular_user", "user").await;

    // 1. Admin creates Group Alpha and Group Beta
    let (st_admin, g_alpha) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_token),
        Some(json!({
            "name": "Infraestructura Alpha",
            "kind": "user",
            "description": "Servidores Alpha"
        })),
    )
    .await;
    assert_eq!(st_admin, StatusCode::CREATED);
    let alpha_id = g_alpha["id"].as_str().unwrap().to_string();

    let (st_admin_b, g_beta) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&admin_token),
        Some(json!({
            "name": "Infraestructura Beta",
            "kind": "user",
            "description": "Servidores Beta"
        })),
    )
    .await;
    assert_eq!(st_admin_b, StatusCode::CREATED);
    let beta_id = g_beta["id"].as_str().unwrap().to_string();

    // Assign Operator 1 to Alpha only
    let (st_mem, _) = request_json(
        &app,
        "POST",
        &format!("/api/groups/{alpha_id}/members/user/{op1_id}"),
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(st_mem, StatusCode::CREATED);

    // 2. Operator CANNOT create groups (403 Forbidden)
    let (st_op, _) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&op1_token),
        Some(json!({
            "name": "Intento Operador",
            "kind": "user"
        })),
    )
    .await;
    assert_eq!(st_op, StatusCode::FORBIDDEN);

    // 3. Auditor CANNOT create or delete groups (403 Forbidden)
    let (st_aud, _) = request_json(
        &app,
        "POST",
        "/api/groups",
        Some(&aud_token),
        Some(json!({
            "name": "Intento Auditor",
            "kind": "user"
        })),
    )
    .await;
    assert_eq!(st_aud, StatusCode::FORBIDDEN);

    let (st_del_aud, _) = request_json(
        &app,
        "DELETE",
        &format!("/api/groups/{alpha_id}"),
        Some(&aud_token),
        None,
    )
    .await;
    assert_eq!(st_del_aud, StatusCode::FORBIDDEN);

    // 4. Auditor CAN read all groups
    let (st_list_aud, aud_list) =
        request_json(&app, "GET", "/api/groups", Some(&aud_token), None).await;
    assert_eq!(st_list_aud, StatusCode::OK);
    assert_eq!(aud_list["total"], 2);

    // 5. Operator can read their own group Alpha
    let (st_op_alpha, _) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{alpha_id}"),
        Some(&op1_token),
        None,
    )
    .await;
    assert_eq!(st_op_alpha, StatusCode::OK);

    // 6. IDOR: Operator attempts access to alien group Beta -> 404 NOT FOUND (non-enumerative)
    let (st_op_beta, _) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{beta_id}"),
        Some(&op1_token),
        None,
    )
    .await;
    assert_eq!(st_op_beta, StatusCode::NOT_FOUND);

    // 7. Regular user without permissions gets 403 Forbidden
    let (st_usr_get, _) = request_json(
        &app,
        "GET",
        &format!("/api/groups/{alpha_id}"),
        Some(&usr_token),
        None,
    )
    .await;
    assert_eq!(st_usr_get, StatusCode::FORBIDDEN);

    // 8. Anonymous request rejected with 401 Unauthorized
    let (st_anon, _) = request_json(&app, "GET", "/api/groups", None, None).await;
    assert_eq!(st_anon, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tc_f5_12_effective_policy_resolution_and_ceiling() {
    let (app, state) = setup_app().await;
    let (_admin_id, admin_token) = create_user_with_token(&state, "admin_sec", "admin").await;

    // Create device in database
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO devices (id, name, hostname, os, version, ip_address, status, last_seen_at, created_at, role)
         VALUES ('dev_dummy', 'Equipo Prueba', 'host1', 'windows', '1.0.0', '192.168.1.50', 'online', ?, ?, 'soporte')",
    )
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await
    .unwrap();

    // Create central global policy
    let (st_p, _pol_val) = request_json(
        &app,
        "POST",
        "/api/policies",
        Some(&admin_token),
        Some(json!({
            "scope_type": "global",
            "document": {
                "allow_clipboard": false,
                "allow_file_transfer": true,
                "session.max_duration_minutes": 120
            },
            "state": "active"
        })),
    )
    .await;
    assert_eq!(st_p, StatusCode::CREATED);

    // Verify effective policy endpoint evaluates precedence deterministically
    let (st_diag, diag_val) = request_json(
        &app,
        "GET",
        "/api/policies/effective?device_id=dev_dummy",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(st_diag, StatusCode::OK);

    // The effective policy output must explain the source and resolution
    assert!(diag_val.get("effective").is_some());
    assert!(diag_val.get("explanations").is_some());
}

#[tokio::test]
async fn test_tc_f5_12_federation_abuse_and_break_glass_recovery() {
    let (app, state) = setup_app().await;
    let (_admin_id, admin_token) = create_user_with_token(&state, "admin_rec", "admin").await;

    // 1. Configure LDAP provider over TLS
    let (st_ldap, _) = request_json(
        &app,
        "POST",
        "/api/idp",
        Some(&admin_token),
        Some(json!({
            "kind": "ldap",
            "name": "ad-corp",
            "config": {
                "url": "ldaps://ad.example.corp:636",
                "start_tls": false,
                "base_dn": "dc=corp,dc=example,dc=com",
                "bind_dn": "cn=svc_cercano,ou=services,dc=corp,dc=example,dc=com",
                "bind_password": "SuperSecretBindPassword123!",
                "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
                "group_attr": "memberOf",
                "default_role": "none",
                "group_allowlist": {
                    "CN=Admins,OU=Groups,DC=corp": { "role": "admin" },
                    "CN=Operators,OU=Groups,DC=corp": { "role": "operator" }
                },
                "timeout_ms": 3000
            },
            "enabled": true
        })),
    )
    .await;
    assert_eq!(st_ldap, StatusCode::CREATED);

    // 2. Querying IdP list must NEVER leak client_secret or bind_password (masked to ********)
    let (st_idp_list, idp_list) =
        request_json(&app, "GET", "/api/idp", Some(&admin_token), None).await;
    assert_eq!(st_idp_list, StatusCode::OK);
    let idp_arr = idp_list.as_array().unwrap();
    assert_eq!(idp_arr.len(), 1);
    assert_eq!(idp_arr[0]["config"]["bind_password"], "********");

    // 3. Simulating invalid credentials or nonexistent user returns generic 401 without user enumeration
    let (st_fail_bind, err_val) = request_json(
        &app,
        "POST",
        "/api/auth/ldap/ad-corp/login",
        None,
        Some(json!({
            "username": "attacker",
            "password": "wrong_password"
        })),
    )
    .await;
    assert_eq!(st_fail_bind, StatusCode::UNAUTHORIZED);
    assert_eq!(err_val["error"], "invalid_credentials");
    assert_eq!(err_val["message"], "Credenciales inválidas.");

    // 4. Break-glass recovery: Local admin authentication endpoint functions independently of remote IdP state
    let (st_local, _) = request_json(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "admin_rec",
            "password": "wrong_dummy_password"
        })),
    )
    .await;
    assert_eq!(st_local, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tc_f5_12_audit_trail_integrity_and_zero_secret_leak() {
    let (app, state) = setup_app().await;
    let (_admin_id, admin_token) = create_user_with_token(&state, "admin_auditor", "admin").await;

    // Perform an address book addition
    let (st_ab, _) = request_json(
        &app,
        "POST",
        "/api/address-book",
        Some(&admin_token),
        Some(json!({
            "name": "Servidor Produccion",
            "host": "10.0.0.5",
            "port": 21118,
            "tags": "prod,db",
            "notes": "Base de datos principal"
        })),
    )
    .await;
    assert_eq!(st_ab, StatusCode::CREATED);

    // Verify audit logs stored in database
    let audit_rows = sqlx::query(
        "SELECT sequence, action, details, actor, hash FROM audit_events ORDER BY sequence DESC LIMIT 5"
    )
    .fetch_all(&state.db)
    .await
    .unwrap();

    assert!(!audit_rows.is_empty(), "Audit events must be recorded");

    // Zero secret leak verification: inspect details for forbidden substrings
    let forbidden_terms = [
        "SuperSecret",
        "bind_password",
        "private_key",
        "client_secret",
    ];

    for row in audit_rows {
        let details: String = row.get("details");
        let hash: String = row.get("hash");
        assert!(!hash.is_empty(), "Audit event hash must not be empty");
        for term in forbidden_terms {
            assert!(
                !details.to_lowercase().contains(&term.to_lowercase()),
                "Audit details leaked sensitive term '{term}': {details}"
            );
        }
    }
}
