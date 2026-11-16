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

//! Scope enforcement for devices, groups, and address book entries (F5-04).
//!
//! Implements strict non-enumerative authorization checks:
//! - An operator only sees devices in groups they belong to or granted via `read`/`operate`.
//! - Out-of-scope resources respond with 404 and log an `authz.denied` audit event.
//! - Role permissions are not elevated by group membership (deny-by-default).

use sqlx::SqlitePool;

use crate::auth::AuthenticatedUser;
use crate::identity::AddressBookEntry;

/// Checks if a device is within the visibility/access scope of the given user.
///
/// Returns true if:
/// 1. User is `admin`.
/// 2. Device belongs to a group that the user also belongs to.
/// 3. Device belongs to a group for which a user group has an explicit `read` or `operate` grant.
pub async fn is_device_in_scope(
    pool: &SqlitePool,
    user: &AuthenticatedUser,
    device_id: &str,
) -> Result<bool, sqlx::Error> {
    if user.role == "admin" {
        return Ok(true);
    }

    let in_scope: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM group_members gm_dev
            JOIN group_members gm_user ON gm_dev.group_id = gm_user.group_id
            WHERE gm_dev.subject_type = 'device' AND gm_dev.subject_id = ?
              AND gm_user.subject_type = 'user' AND gm_user.subject_id = ?
        ) OR EXISTS (
            SELECT 1 FROM group_grants gg
            JOIN group_members gm_user ON gg.from_group_id = gm_user.group_id
            JOIN group_members gm_dev ON gg.to_group_id = gm_dev.group_id
            WHERE gm_dev.subject_type = 'device' AND gm_dev.subject_id = ?
              AND gm_user.subject_type = 'user' AND gm_user.subject_id = ?
              AND gg.permission IN ('read', 'operate')
        )
        "#,
    )
    .bind(device_id)
    .bind(&user.id)
    .bind(device_id)
    .bind(&user.id)
    .fetch_one(pool)
    .await?;

    Ok(in_scope)
}

/// Checks if a group is within the visibility scope of the given user.
///
/// Returns true if:
/// 1. User is `admin`.
/// 2. User is a member of the group.
/// 3. A group to which the user belongs has a `read` or `operate` grant towards this group.
pub async fn is_group_in_scope(
    pool: &SqlitePool,
    user: &AuthenticatedUser,
    group_id: &str,
) -> Result<bool, sqlx::Error> {
    if user.role == "admin" || user.role == "auditor" {
        return Ok(true);
    }

    let in_scope: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM group_members
            WHERE group_id = ? AND subject_type = 'user' AND subject_id = ?
        ) OR EXISTS (
            SELECT 1 FROM group_grants gg
            JOIN group_members gm_user ON gg.from_group_id = gm_user.group_id
            WHERE gg.to_group_id = ?
              AND gm_user.subject_type = 'user' AND gm_user.subject_id = ?
              AND gg.permission IN ('read', 'operate')
        )
        "#,
    )
    .bind(group_id)
    .bind(&user.id)
    .bind(group_id)
    .bind(&user.id)
    .fetch_one(pool)
    .await?;

    Ok(in_scope)
}

/// Checks if an address book entry is within the visibility scope of the given user.
///
/// Rules (docs/specs/identidad.md §3):
/// 1. `admin` sees all entries.
/// 2. If both `device_id` and `group_id` are absent, only `admin` can see it.
/// 3. If `device_id` is present and in scope, it is visible.
/// 4. If `group_id` is present and in scope, it is visible.
pub async fn is_address_book_in_scope(
    pool: &SqlitePool,
    user: &AuthenticatedUser,
    entry: &AddressBookEntry,
) -> Result<bool, sqlx::Error> {
    if user.role == "admin" {
        return Ok(true);
    }

    if entry.device_id.is_none() && entry.group_id.is_none() {
        return Ok(false);
    }

    if let Some(ref dev_id) = entry.device_id {
        if is_device_in_scope(pool, user, dev_id).await? {
            return Ok(true);
        }
    }

    if let Some(ref grp_id) = entry.group_id {
        if is_group_in_scope(pool, user, grp_id).await? {
            return Ok(true);
        }
    }

    Ok(false)
}
