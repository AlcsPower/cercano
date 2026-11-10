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

//! Fixed role-to-permission map for F4 (no per-user permission table in v1).

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_every_permission() {
        assert!(has_permission(ADMIN, USERS_MANAGE));
        assert!(has_permission(ADMIN, ROLES_MANAGE));
        assert!(has_permission(ADMIN, SETTINGS_MANAGE));
    }

    #[test]
    fn operator_and_auditor_are_scoped() {
        assert!(has_permission(OPERATOR, USERS_READ));
        assert!(!has_permission(OPERATOR, USERS_MANAGE));
        assert!(!has_permission(OPERATOR, AUDIT_READ));
        assert!(has_permission(AUDITOR, AUDIT_READ));
        assert!(!has_permission(AUDITOR, USERS_MANAGE));
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
