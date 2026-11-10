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

//! Fixed role-to-permission map and Axum RBAC middleware/extractor for F4/F4.5.

use std::marker::PhantomData;
use std::net::SocketAddr;

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::auth::AuthenticatedUser;
use crate::AppState;

pub const ADMIN: &str = "admin";
pub const OPERATOR: &str = "operator";
pub const AUDITOR: &str = "auditor";
pub const LEGACY_USER: &str = "user";

pub const USERS_READ: &str = "users:read";
pub const USERS_MANAGE: &str = "users:manage";
pub const ROLES_READ: &str = "roles:read";
pub const ROLES_MANAGE: &str = "roles:manage";
pub const DEVICES_READ: &str = "devices:read";
pub const DEVICES_MANAGE: &str = "devices:manage";
pub const AUDIT_READ: &str = "audit:read";
pub const AUDIT_EXPORT: &str = "audit:export";
pub const SETTINGS_READ: &str = "settings:read";
pub const SETTINGS_MANAGE: &str = "settings:manage";
pub const BUILDER_SOPORTE: &str = "builder:create:soporte";
pub const BUILDER_TECNICO: &str = "builder:create:tecnico";
pub const BUILDER_DOWNLOAD: &str = "builder:download";
pub const CHAT_ATTEND: &str = "chat:attend";
pub const CHAT_MANAGE: &str = "chat:manage";
pub const CHAT_READ: &str = "chat:read";
pub const CHAT_WRITE: &str = "chat:write";
pub const CHAT_CLOSE: &str = "chat:close";
pub const CHAT_MANAGE_BRANDING: &str = "chat:manage_branding";
pub const TWOFA_ENROLL: &str = "2fa:enroll";
pub const TWOFA_REVOKE: &str = "2fa:revoke";

const OPERATOR_PERMISSIONS: &[&str] = &[
    USERS_READ,
    DEVICES_READ,
    SETTINGS_READ,
    BUILDER_SOPORTE,
    BUILDER_DOWNLOAD,
    CHAT_ATTEND,
    CHAT_READ,
    CHAT_WRITE,
    CHAT_CLOSE,
    TWOFA_ENROLL,
    TWOFA_REVOKE,
];

const AUDITOR_PERMISSIONS: &[&str] = &[
    USERS_READ,
    DEVICES_READ,
    AUDIT_READ,
    AUDIT_EXPORT,
    SETTINGS_READ,
    CHAT_READ,
    TWOFA_ENROLL,
];

const LEGACY_PERMISSIONS: &[&str] = &[
    USERS_READ,
    DEVICES_READ,
    SETTINGS_READ,
    CHAT_READ,
    TWOFA_ENROLL,
];

pub fn is_admin(role: &str) -> bool {
    role == ADMIN
}

/// Returns the permissions granted to a role. `admin` is handled separately.
pub fn role_permissions(role: &str) -> &'static [&'static str] {
    match role {
        OPERATOR => OPERATOR_PERMISSIONS,
        AUDITOR => AUDITOR_PERMISSIONS,
        LEGACY_USER => LEGACY_PERMISSIONS,
        _ => &[],
    }
}

pub fn has_permission(role: &str, permission: &str) -> bool {
    is_admin(role) || role_permissions(role).contains(&permission)
}

pub fn valid_assignable_role(role: &str) -> bool {
    matches!(role, ADMIN | OPERATOR | AUDITOR)
}

/// Audit unauthorized access attempt. Emits `authz.denied` event under category `auth`.
pub async fn audit_authz_denied(
    audit: &audit_core::AuditStore,
    user: &AuthenticatedUser,
    permission: &str,
    client_ip: &str,
    trace_id: &str,
) {
    let audit_input = EventInput::new(
        trace_id.to_string(),
        Source::Api,
        Category::Auth,
        "authz.denied",
        Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip.to_string()),
        ),
        Outcome::Denied,
        json!({
            "username": user.username,
            "role": user.role,
            "required_permission": permission,
            "client_ip": client_ip,
        }),
    )
    .with_subject(Subject::with_details(
        &user.id,
        "user",
        Some(user.username.clone()),
    ));

    let _ = audit.append(audit_input).await;
}

#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("Authentication error: {0}")]
    Auth(#[from] crate::auth::AuthError),
    #[error("Forbidden: falta el permiso '{permission}'")]
    Forbidden {
        permission: &'static str,
        message: String,
    },
}

impl IntoResponse for RbacError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(err) => err.into_response(),
            Self::Forbidden {
                permission: _,
                message,
            } => (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "forbidden",
                    "code": "authz_denied",
                    "message": message,
                })),
            )
                .into_response(),
        }
    }
}

/// Checks whether `user` has `permission`. On denial, emits `authz.denied` and returns `RbacError::Forbidden`.
pub async fn check_permission(
    state: &AppState,
    user: &AuthenticatedUser,
    permission: &'static str,
    client_ip: &str,
    trace_id: &str,
) -> Result<(), RbacError> {
    if !has_permission(&user.role, permission) {
        audit_authz_denied(&state.audit, user, permission, client_ip, trace_id).await;
        return Err(RbacError::Forbidden {
            permission,
            message: format!("Acceso denegado: se requiere el permiso '{permission}'."),
        });
    }
    Ok(())
}

/// Trait implemented by compile-time permission tags.
pub trait PermissionTag: Send + Sync + 'static {
    fn permission() -> &'static str;
}

macro_rules! define_permission_tag {
    ($struct_name:ident, $perm_const:expr) => {
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $struct_name;
        impl PermissionTag for $struct_name {
            fn permission() -> &'static str {
                $perm_const
            }
        }
    };
}

define_permission_tag!(PermUsersRead, USERS_READ);
define_permission_tag!(PermUsersManage, USERS_MANAGE);
define_permission_tag!(PermRolesRead, ROLES_READ);
define_permission_tag!(PermRolesManage, ROLES_MANAGE);
define_permission_tag!(PermDevicesRead, DEVICES_READ);
define_permission_tag!(PermDevicesManage, DEVICES_MANAGE);
define_permission_tag!(PermAuditRead, AUDIT_READ);
define_permission_tag!(PermAuditExport, AUDIT_EXPORT);
define_permission_tag!(PermSettingsRead, SETTINGS_READ);
define_permission_tag!(PermSettingsManage, SETTINGS_MANAGE);
define_permission_tag!(PermBuilderSoporte, BUILDER_SOPORTE);
define_permission_tag!(PermBuilderTecnico, BUILDER_TECNICO);
define_permission_tag!(PermBuilderDownload, BUILDER_DOWNLOAD);
define_permission_tag!(PermChatRead, CHAT_READ);
define_permission_tag!(PermChatWrite, CHAT_WRITE);
define_permission_tag!(PermChatClose, CHAT_CLOSE);
define_permission_tag!(PermChatManageBranding, CHAT_MANAGE_BRANDING);
define_permission_tag!(PermChatAttend, CHAT_ATTEND);
define_permission_tag!(PermChatManage, CHAT_MANAGE);
define_permission_tag!(PermTwofaEnroll, TWOFA_ENROLL);
define_permission_tag!(PermTwofaRevoke, TWOFA_REVOKE);

/// Axum extractor that authenticates the caller session AND validates the required permission.
///
/// If unauthorized, automatically emits `authz.denied` and returns HTTP 403 Forbidden.
#[derive(Debug, Clone)]
pub struct RequirePermission<T: PermissionTag>(pub AuthenticatedUser, pub PhantomData<T>);

impl<T: PermissionTag> std::ops::Deref for RequirePermission<T> {
    type Target = AuthenticatedUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<T: PermissionTag> FromRequestParts<AppState> for RequirePermission<T> {
    type Rejection = RbacError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;
        let permission = T::permission();

        if !has_permission(&user.role, permission) {
            let client_ip = crate::auth::extract_client_ip(
                &parts.headers,
                parts
                    .extensions
                    .get::<axum::extract::ConnectInfo<SocketAddr>>()
                    .map(|ci| ci.0),
                &state.config.trusted_proxies,
            );
            let trace_id = crate::auth::extract_trace_id(&parts.headers);

            audit_authz_denied(&state.audit, &user, permission, &client_ip, &trace_id).await;

            return Err(RbacError::Forbidden {
                permission,
                message: format!("Acceso denegado: se requiere el permiso '{permission}'."),
            });
        }

        Ok(RequirePermission(user, PhantomData))
    }
}

/// Extension marker for route-level permission checks.
#[derive(Clone, Copy, Debug)]
pub struct RoutePermission(pub &'static str);

/// Axum middleware that inspects `RoutePermission` extension on the request.
pub async fn enforce_permission_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, RbacError> {
    let required_permission = req.extensions().get::<RoutePermission>().copied();
    if let Some(RoutePermission(permission)) = required_permission {
        let (mut parts, body) = req.into_parts();
        let user = AuthenticatedUser::from_request_parts(&mut parts, &state).await?;

        if !has_permission(&user.role, permission) {
            let client_ip = crate::auth::extract_client_ip(
                &parts.headers,
                parts
                    .extensions
                    .get::<axum::extract::ConnectInfo<SocketAddr>>()
                    .map(|ci| ci.0),
                &state.config.trusted_proxies,
            );
            let trace_id = crate::auth::extract_trace_id(&parts.headers);

            audit_authz_denied(&state.audit, &user, permission, &client_ip, &trace_id).await;

            return Err(RbacError::Forbidden {
                permission,
                message: format!("Acceso denegado: se requiere el permiso '{permission}'."),
            });
        }

        let req = axum::extract::Request::from_parts(parts, body);
        Ok(next.run(req).await)
    } else {
        Ok(next.run(req).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_every_permission() {
        assert!(has_permission(ADMIN, USERS_MANAGE));
        assert!(has_permission(ADMIN, ROLES_MANAGE));
        assert!(has_permission(ADMIN, SETTINGS_MANAGE));
        assert!(has_permission(ADMIN, CHAT_READ));
        assert!(has_permission(ADMIN, CHAT_WRITE));
        assert!(has_permission(ADMIN, CHAT_CLOSE));
        assert!(has_permission(ADMIN, CHAT_MANAGE_BRANDING));
    }

    #[test]
    fn operator_and_auditor_are_scoped() {
        assert!(has_permission(OPERATOR, USERS_READ));
        assert!(!has_permission(OPERATOR, USERS_MANAGE));
        assert!(!has_permission(OPERATOR, AUDIT_READ));
        assert!(has_permission(OPERATOR, CHAT_READ));
        assert!(has_permission(OPERATOR, CHAT_WRITE));
        assert!(has_permission(OPERATOR, CHAT_CLOSE));
        assert!(!has_permission(OPERATOR, CHAT_MANAGE_BRANDING));

        assert!(has_permission(AUDITOR, AUDIT_READ));
        assert!(has_permission(AUDITOR, CHAT_READ));
        assert!(!has_permission(AUDITOR, CHAT_WRITE));
        assert!(!has_permission(AUDITOR, CHAT_CLOSE));
        assert!(!has_permission(AUDITOR, CHAT_MANAGE_BRANDING));
        assert!(!has_permission(AUDITOR, USERS_MANAGE));

        assert!(has_permission(LEGACY_USER, CHAT_READ));
        assert!(!has_permission(LEGACY_USER, CHAT_WRITE));
        assert!(!has_permission(LEGACY_USER, SETTINGS_MANAGE));
    }

    #[test]
    fn only_known_roles_can_be_assigned() {
        assert!(valid_assignable_role(ADMIN));
        assert!(valid_assignable_role(OPERATOR));
        assert!(valid_assignable_role(AUDITOR));
        assert!(!valid_assignable_role(LEGACY_USER));
    }
}
