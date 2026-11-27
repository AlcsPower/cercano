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

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Executor, Row, SqlitePool};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    Connection(#[from] sqlx::Error),
    #[error("Migration failed at version {version} ({name}): {source}")]
    Migration {
        version: i64,
        name: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("IO error preparing database path: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "001_initial_schema",
        sql: r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS system_info (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            hostname TEXT,
            os TEXT,
            status TEXT NOT NULL DEFAULT 'offline',
            last_seen_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        "#,
    },
    Migration {
        version: 2,
        name: "002_auth_schema",
        sql: r#"
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attempted_at TEXT NOT NULL DEFAULT (datetime('now')),
            success INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username, attempted_at);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, attempted_at);
        "#,
    },
    Migration {
        version: 3,
        name: "003_device_metadata",
        sql: r#"
        ALTER TABLE devices ADD COLUMN version TEXT;
        ALTER TABLE devices ADD COLUMN ip_address TEXT;
        CREATE INDEX IF NOT EXISTS idx_devices_last_seen_at ON devices(last_seen_at);
        "#,
    },
    Migration {
        version: 4,
        name: "004_build_jobs_schema",
        sql: r#"
        CREATE TABLE IF NOT EXISTS build_jobs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            role TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            artifact_path TEXT,
            error_message TEXT,
            logs TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            started_at TEXT,
            completed_at TEXT,
            expires_at TEXT
        );

        CREATE TABLE IF NOT EXISTS user_permissions (
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            permission TEXT NOT NULL,
            PRIMARY KEY (user_id, permission)
        );

        CREATE INDEX IF NOT EXISTS idx_build_jobs_user_id ON build_jobs(user_id);
        CREATE INDEX IF NOT EXISTS idx_build_jobs_status ON build_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_build_jobs_created_at ON build_jobs(created_at);
        CREATE INDEX IF NOT EXISTS idx_user_permissions_user_id ON user_permissions(user_id);
        "#,
    },
    Migration {
        version: 5,
        name: "005_revocations_schema",
        sql: r#"
        ALTER TABLE build_jobs ADD COLUMN revoked_at TEXT;
        ALTER TABLE build_jobs ADD COLUMN revocation_reason TEXT;

        CREATE TABLE IF NOT EXISTS revoked_roles (
            role TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL,
            revocation_reason TEXT,
            revoked_by TEXT REFERENCES users(id)
        );

        ALTER TABLE devices ADD COLUMN installer_id TEXT;
        ALTER TABLE devices ADD COLUMN profile_id TEXT;

        CREATE INDEX IF NOT EXISTS idx_build_jobs_role ON build_jobs(role);
        CREATE INDEX IF NOT EXISTS idx_devices_installer_id ON devices(installer_id);
        "#,
    },
    Migration {
        version: 6,
        name: "006_device_roles_schema",
        sql: r#"
        ALTER TABLE devices ADD COLUMN role TEXT NOT NULL DEFAULT 'soporte';
        CREATE INDEX IF NOT EXISTS idx_devices_role ON devices(role);
        "#,
    },
    Migration {
        version: 7,
        name: "007_console_rbac_2fa",
        sql: r#"
        ALTER TABLE users ADD COLUMN totp_secret TEXT;
        ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE users ADD COLUMN is_2fa_required INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE users ADD COLUMN totp_confirmed_at TEXT;
        ALTER TABLE users ADD COLUMN recovery_codes TEXT;
        ALTER TABLE sessions ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT 1;

        CREATE TABLE IF NOT EXISTS mfa_challenges (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            used_at    TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at ON mfa_challenges(expires_at);
        "#,
    },
    Migration {
        version: 8,
        name: "008_chat_schema",
        sql: r#"
        CREATE TABLE IF NOT EXISTS chat_devices (
            device_id    TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            public_key   TEXT NOT NULL,
            installer_id TEXT,
            display_name TEXT,
            last_auth_at TEXT,
            revoked_at   TEXT,
            created_at   TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS chat_auth_nonces (
            id         TEXT PRIMARY KEY,
            device_id  TEXT NOT NULL REFERENCES chat_devices(device_id) ON DELETE CASCADE,
            nonce      TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at    TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS chat_device_sessions (
            token      TEXT PRIMARY KEY,
            device_id  TEXT NOT NULL REFERENCES chat_devices(device_id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS chat_conversations (
            id                 TEXT PRIMARY KEY,
            device_id          TEXT NOT NULL,
            device_name        TEXT,
            device_hostname    TEXT,
            device_os          TEXT,
            installer_id       TEXT,
            status             TEXT NOT NULL DEFAULT 'waiting'
                               CHECK (status IN ('waiting','assigned','active','closed')),
            assigned_user_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
            contact_first_name TEXT,
            contact_last_name  TEXT,
            created_at         TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at         TEXT NOT NULL DEFAULT (datetime('now')),
            last_message_at    TEXT,
            closed_at          TEXT,
            closed_by          TEXT
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
            id                TEXT PRIMARY KEY,
            conversation_id   TEXT NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
            sender_type       TEXT NOT NULL CHECK (sender_type IN ('client','technician','system')),
            sender_id         TEXT,
            sender_name       TEXT,
            body              TEXT NOT NULL DEFAULT '',
            client_message_id TEXT,
            created_at        TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS chat_attachments (
            id            TEXT PRIMARY KEY,
            message_id    TEXT NOT NULL UNIQUE REFERENCES chat_messages(id) ON DELETE CASCADE,
            original_name TEXT NOT NULL,
            mime          TEXT NOT NULL,
            size_bytes    INTEGER NOT NULL,
            sha256        TEXT NOT NULL,
            storage_key   TEXT NOT NULL UNIQUE,
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS chat_reads (
            conversation_id TEXT NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
            reader_type     TEXT NOT NULL CHECK (reader_type IN ('device','user')),
            reader_id       TEXT NOT NULL,
            last_read_at    TEXT NOT NULL,
            PRIMARY KEY (conversation_id, reader_type, reader_id)
        );

        CREATE TABLE IF NOT EXISTS chat_branding (
            id                INTEGER PRIMARY KEY CHECK (id = 1),
            organization_name TEXT,
            support_name      TEXT NOT NULL DEFAULT 'Cercano Soporte',
            logo_url          TEXT,
            accent_color      TEXT NOT NULL DEFAULT '#3B5BFF',
            welcome_text      TEXT,
            info_text         TEXT,
            privacy_text      TEXT,
            updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
            updated_by        TEXT
        );
        INSERT OR IGNORE INTO chat_branding (id) VALUES (1);

        CREATE INDEX IF NOT EXISTS idx_chat_conversations_status
            ON chat_conversations(status, last_message_at DESC);
        CREATE INDEX IF NOT EXISTS idx_chat_conversations_assignee
            ON chat_conversations(assigned_user_id, status);
        CREATE INDEX IF NOT EXISTS idx_chat_conversations_device
            ON chat_conversations(device_id, status);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation
            ON chat_messages(conversation_id, created_at, id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_messages_client_id
            ON chat_messages(conversation_id, sender_type, sender_id, client_message_id)
            WHERE client_message_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_chat_attachments_message
            ON chat_attachments(message_id);
        CREATE INDEX IF NOT EXISTS idx_chat_device_sessions_expiry
            ON chat_device_sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_chat_nonces_expiry
            ON chat_auth_nonces(expires_at);
        CREATE INDEX IF NOT EXISTS idx_chat_reads_reader
            ON chat_reads(reader_type, reader_id);
        "#,
    },
    Migration {
        version: 9,
        name: "009_identity_groups_policies_idp",
        sql: r#"
        CREATE TABLE IF NOT EXISTS groups (
            id          TEXT PRIMARY KEY,
            kind        TEXT NOT NULL CHECK (kind IN ('user','device')),
            name        TEXT NOT NULL,
            description TEXT,
            created_at  TEXT NOT NULL,
            created_by  TEXT,
            updated_at  TEXT NOT NULL,
            updated_by  TEXT,
            UNIQUE (kind, name)
        );

        CREATE TABLE IF NOT EXISTS group_members (
            group_id     TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            subject_type TEXT NOT NULL CHECK (subject_type IN ('user','device')),
            subject_id   TEXT NOT NULL,
            added_at     TEXT NOT NULL,
            added_by     TEXT,
            PRIMARY KEY (group_id, subject_type, subject_id)
        );

        CREATE TABLE IF NOT EXISTS group_grants (
            from_group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            to_group_id   TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            permission    TEXT NOT NULL CHECK (permission IN ('read','operate')),
            created_at    TEXT NOT NULL,
            created_by    TEXT,
            PRIMARY KEY (from_group_id, to_group_id, permission),
            CHECK (from_group_id <> to_group_id)
        );

        CREATE TABLE IF NOT EXISTS address_book (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            device_id  TEXT REFERENCES devices(id) ON DELETE CASCADE,
            group_id   TEXT REFERENCES groups(id) ON DELETE SET NULL,
            host       TEXT,
            port       INTEGER,
            tags       TEXT,
            notes      TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT,
            updated_at TEXT NOT NULL,
            updated_by TEXT
        );

        CREATE TABLE IF NOT EXISTS policies (
            id              TEXT PRIMARY KEY,
            scope_type      TEXT NOT NULL CHECK (scope_type IN ('global','group','device')),
            scope_id        TEXT NOT NULL,
            version         INTEGER NOT NULL,
            document        TEXT NOT NULL,
            document_sha256 TEXT NOT NULL,
            state           TEXT NOT NULL CHECK (state IN ('draft','active','superseded','revoked')),
            effective_from  TEXT,
            expires_at      TEXT,
            created_at      TEXT NOT NULL,
            created_by      TEXT,
            revoked_at      TEXT,
            revoked_by      TEXT,
            UNIQUE (scope_type, scope_id, version),
            CHECK (scope_type <> 'global' OR scope_id = '')
        );

        CREATE TABLE IF NOT EXISTS identity_providers (
            id         TEXT PRIMARY KEY,
            kind       TEXT NOT NULL CHECK (kind IN ('oidc','ldap')),
            name       TEXT NOT NULL UNIQUE,
            config     TEXT NOT NULL,
            secret_ref TEXT,
            enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            created_at TEXT NOT NULL,
            created_by TEXT,
            updated_at TEXT NOT NULL,
            updated_by TEXT
        );

        CREATE TABLE IF NOT EXISTS federated_identities (
            id            TEXT PRIMARY KEY,
            provider_id   TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
            subject       TEXT NOT NULL,
            user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at    TEXT NOT NULL,
            last_login_at TEXT,
            revoked_at    TEXT,
            UNIQUE (provider_id, subject),
            UNIQUE (provider_id, user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_group_members_subject
            ON group_members(subject_type, subject_id);
        CREATE INDEX IF NOT EXISTS idx_group_grants_to
            ON group_grants(to_group_id, permission);
        CREATE INDEX IF NOT EXISTS idx_address_book_device
            ON address_book(device_id);
        CREATE INDEX IF NOT EXISTS idx_address_book_group
            ON address_book(group_id);
        CREATE INDEX IF NOT EXISTS idx_policies_scope
            ON policies(scope_type, scope_id, version);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_active
            ON policies(scope_type, scope_id)
            WHERE state = 'active';
        CREATE INDEX IF NOT EXISTS idx_federated_identities_user
            ON federated_identities(user_id);
        "#,
    },
    Migration {
        version: 10,
        name: "010_user_display_name",
        // F4.5-17: nombre visible del técnico (el login nunca llega al dispositivo).
        sql: r#"
        ALTER TABLE users ADD COLUMN display_name TEXT;
        ALTER TABLE chat_messages ADD COLUMN sender_display_name TEXT;
        "#,
    },
];

/// Initializes SQLite database pool and ensures parent directory exists.
pub async fn init_db(database_url: &str) -> Result<SqlitePool, DbError> {
    ensure_parent_dir(database_url)?;

    let mut opts = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);

    // Apply WAL mode and synchronous normal only when not in memory
    if !database_url.contains(":memory:") {
        opts = opts
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await?;

    run_migrations(&pool).await?;

    if let Err(e) = purge_stale_records(&pool).await {
        tracing::warn!("Failed to purge stale records during init_db: {:?}", e);
    }

    Ok(pool)
}

/// Applies all pending migrations within SQLite transactions.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), DbError> {
    // 1. Ensure migrations tracking table exists
    pool.execute(
        r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        "#,
    )
    .await?;

    // 2. Fetch already applied migration versions
    let applied_rows = sqlx::query("SELECT version FROM schema_migrations ORDER BY version ASC")
        .fetch_all(pool)
        .await?;

    let applied_versions: std::collections::HashSet<i64> = applied_rows
        .into_iter()
        .map(|row| row.get::<i64, _>("version"))
        .collect();

    // 3. Apply missing migrations in order
    for migration in MIGRATIONS {
        if !applied_versions.contains(&migration.version) {
            tracing::info!(
                version = migration.version,
                name = migration.name,
                "Applying database migration"
            );

            let mut tx = pool.begin().await.map_err(|source| DbError::Migration {
                version: migration.version,
                name: migration.name,
                source,
            })?;

            tx.execute(migration.sql)
                .await
                .map_err(|source| DbError::Migration {
                    version: migration.version,
                    name: migration.name,
                    source,
                })?;

            sqlx::query("INSERT INTO schema_migrations (version, name) VALUES (?, ?)")
                .bind(migration.version)
                .bind(migration.name)
                .execute(&mut *tx)
                .await
                .map_err(|source| DbError::Migration {
                    version: migration.version,
                    name: migration.name,
                    source,
                })?;

            tx.commit().await.map_err(|source| DbError::Migration {
                version: migration.version,
                name: migration.name,
                source,
            })?;

            tracing::info!(
                version = migration.version,
                name = migration.name,
                "Migration applied successfully"
            );
        }
    }

    // Ensure sessions table has mfa_verified even on existing pre-v0.2 databases
    let _ = sqlx::query("ALTER TABLE sessions ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT 1")
        .execute(pool)
        .await;

    Ok(())
}

/// Purges expired sessions and login attempts older than 24 hours.
pub async fn purge_stale_records(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let deleted_attempts =
        sqlx::query("DELETE FROM login_attempts WHERE attempted_at < datetime('now', '-24 hours')")
            .execute(pool)
            .await?
            .rows_affected();

    let deleted_sessions = sqlx::query("DELETE FROM sessions WHERE expires_at < datetime('now')")
        .execute(pool)
        .await?
        .rows_affected();

    let total = deleted_attempts + deleted_sessions;
    if total > 0 {
        tracing::info!(
            deleted_attempts = deleted_attempts,
            deleted_sessions = deleted_sessions,
            total = total,
            "Purged stale sessions and login attempts"
        );
    }

    Ok(total)
}

fn ensure_parent_dir(database_url: &str) -> Result<(), std::io::Error> {
    if database_url.starts_with("sqlite:") && !database_url.contains(":memory:") {
        let clean = database_url
            .trim_start_matches("sqlite://")
            .trim_start_matches("sqlite:");
        let path_part = clean.split('?').next().unwrap_or(clean);
        let path = Path::new(path_part);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_in_memory_db_and_migrations() {
        let pool = init_db("sqlite::memory:").await.unwrap();

        // Verify schema_migrations table
        let rows = sqlx::query("SELECT version, name FROM schema_migrations ORDER BY version ASC")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 10);
        assert_eq!(rows[0].get::<i64, _>("version"), 1);
        assert_eq!(rows[0].get::<String, _>("name"), "001_initial_schema");
        assert_eq!(rows[1].get::<i64, _>("version"), 2);
        assert_eq!(rows[1].get::<String, _>("name"), "002_auth_schema");
        assert_eq!(rows[2].get::<i64, _>("version"), 3);
        assert_eq!(rows[2].get::<String, _>("name"), "003_device_metadata");
        assert_eq!(rows[3].get::<i64, _>("version"), 4);
        assert_eq!(rows[3].get::<String, _>("name"), "004_build_jobs_schema");
        assert_eq!(rows[4].get::<i64, _>("version"), 5);
        assert_eq!(rows[4].get::<String, _>("name"), "005_revocations_schema");
        assert_eq!(rows[5].get::<i64, _>("version"), 6);
        assert_eq!(rows[5].get::<String, _>("name"), "006_device_roles_schema");
        assert_eq!(rows[6].get::<i64, _>("version"), 7);
        assert_eq!(rows[6].get::<String, _>("name"), "007_console_rbac_2fa");
        assert_eq!(rows[7].get::<i64, _>("version"), 8);
        assert_eq!(rows[7].get::<String, _>("name"), "008_chat_schema");
        assert_eq!(rows[8].get::<i64, _>("version"), 9);
        assert_eq!(
            rows[8].get::<String, _>("name"),
            "009_identity_groups_policies_idp"
        );
        assert_eq!(rows[9].get::<String, _>("name"), "010_user_display_name");

        // Verify build_jobs table exists
        let build_jobs = sqlx::query("SELECT count(*) as cnt FROM build_jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(build_jobs.get::<i64, _>("cnt"), 0);

        // Verify devices table exists and columns can be queried
        let devices = sqlx::query("SELECT count(*) as cnt FROM devices")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(devices.get::<i64, _>("cnt"), 0);

        // Verify users table exists
        let users = sqlx::query("SELECT count(*) as cnt FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users.get::<i64, _>("cnt"), 0);

        // Verify sessions table exists
        let sessions = sqlx::query("SELECT count(*) as cnt FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sessions.get::<i64, _>("cnt"), 0);

        // Verify login_attempts table exists
        let attempts = sqlx::query("SELECT count(*) as cnt FROM login_attempts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(attempts.get::<i64, _>("cnt"), 0);

        // Verify the F4 2FA challenge table exists
        let challenges = sqlx::query("SELECT count(*) as cnt FROM mfa_challenges")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(challenges.get::<i64, _>("cnt"), 0);

        // Verify the chat schema and its singleton branding seed
        for table in [
            "chat_devices",
            "chat_auth_nonces",
            "chat_device_sessions",
            "chat_conversations",
            "chat_messages",
            "chat_attachments",
            "chat_reads",
        ] {
            let count = sqlx::query(&format!("SELECT count(*) as cnt FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(count.get::<i64, _>("cnt"), 0, "tabla {table} vacía");
        }

        let branding = sqlx::query("SELECT id, support_name, accent_color FROM chat_branding")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(branding.get::<i64, _>("id"), 1);
        assert_eq!(branding.get::<String, _>("support_name"), "Cercano Soporte");
        assert_eq!(branding.get::<String, _>("accent_color"), "#3B5BFF");

        // Verify F5 identity, groups, policies and idp tables
        for table in [
            "groups",
            "group_members",
            "group_grants",
            "address_book",
            "policies",
            "identity_providers",
            "federated_identities",
        ] {
            let count = sqlx::query(&format!("SELECT count(*) as cnt FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(count.get::<i64, _>("cnt"), 0, "tabla {table} vacía");
        }

        // Verify idempotency of run_migrations
        let second_run = run_migrations(&pool).await;
        assert!(second_run.is_ok());
    }

    #[tokio::test]
    async fn test_file_db_creation_with_nested_dir() {
        let dir = tempdir().unwrap();
        let db_file = dir.path().join("nested").join("sub").join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_file.display());

        let pool = init_db(&db_url).await.unwrap();
        assert!(db_file.parent().unwrap().exists());

        let rows = sqlx::query("SELECT version FROM schema_migrations")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 10);
    }

    #[tokio::test]
    async fn test_f4_02_2fa_schema_columns_and_cascade() {
        let pool = init_db("sqlite::memory:").await.unwrap();

        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, is_active, totp_secret, totp_enabled, is_2fa_required, totp_confirmed_at, recovery_codes) VALUES (?, ?, ?, ?, 1, ?, 1, 1, ?, ?)",
        )
        .bind("u-2fa")
        .bind("twofa")
        .bind("hash")
        .bind("admin")
        .bind("JBSWY3DPEHPK3PXP")
        .bind("2026-11-10T00:00:00Z")
        .bind(r#"[{"hash":"abc","used":false}]"#)
        .execute(&pool)
        .await
        .unwrap();

        let row = sqlx::query(
            "SELECT totp_secret, totp_enabled, is_2fa_required, totp_confirmed_at, recovery_codes FROM users WHERE id = 'u-2fa'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("totp_secret"), "JBSWY3DPEHPK3PXP");
        assert_eq!(row.get::<i64, _>("totp_enabled"), 1);
        assert_eq!(row.get::<i64, _>("is_2fa_required"), 1);
        assert_eq!(
            row.get::<String, _>("totp_confirmed_at"),
            "2026-11-10T00:00:00Z"
        );
        assert_eq!(
            row.get::<String, _>("recovery_codes"),
            r#"[{"hash":"abc","used":false}]"#
        );

        sqlx::query(
            "INSERT INTO mfa_challenges (token, user_id, expires_at) VALUES ('ch-1', 'u-2fa', datetime('now', '+5 minutes'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM users WHERE id = 'u-2fa'")
            .execute(&pool)
            .await
            .unwrap();

        let remaining = sqlx::query("SELECT count(*) as cnt FROM mfa_challenges")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining.get::<i64, _>("cnt"), 0);
    }

    #[tokio::test]
    async fn test_f4_5_02_chat_schema_constraints_and_relations() {
        let pool = init_db("sqlite::memory:").await.unwrap();

        sqlx::query("INSERT INTO devices (id, name) VALUES ('dev-1', 'PC-RECEPCION')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, is_active) VALUES ('u-1', 'tech', 'hash', 'admin', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO chat_conversations (id, device_id, device_name, status, assigned_user_id, contact_first_name, contact_last_name) VALUES ('c-1', 'dev-1', 'PC-RECEPCION', 'waiting', 'u-1', 'Ana', 'Pérez')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_messages (id, conversation_id, sender_type, sender_id, sender_name, body) VALUES ('m-1', 'c-1', 'client', 'dev-1', 'PC-RECEPCION', 'Hola')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_attachments (id, message_id, original_name, mime, size_bytes, sha256, storage_key) VALUES ('a-1', 'm-1', 'captura.png', 'image/png', 1234, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'k-1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_reads (conversation_id, reader_type, reader_id, last_read_at) VALUES ('c-1', 'device', 'dev-1', datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO chat_devices (device_id, public_key) VALUES ('dev-1', 'key')")
            .execute(&pool)
            .await
            .unwrap();

        // Status CHECK
        assert!(sqlx::query(
            "INSERT INTO chat_conversations (id, device_id, status) VALUES ('c-bad', 'dev-1', 'bogus')"
        )
        .execute(&pool)
        .await
        .is_err());

        // Foreign key on messages
        assert!(sqlx::query(
            "INSERT INTO chat_messages (id, conversation_id, sender_type) VALUES ('m-bad', 'missing', 'client')"
        )
        .execute(&pool)
        .await
        .is_err());

        // Deleting the assigned user sets the conversation assignee to NULL.
        sqlx::query("DELETE FROM users WHERE id = 'u-1'")
            .execute(&pool)
            .await
            .unwrap();
        let assigned =
            sqlx::query("SELECT assigned_user_id FROM chat_conversations WHERE id = 'c-1'")
                .fetch_one(&pool)
                .await
                .unwrap()
                .get::<Option<String>, _>("assigned_user_id");
        assert!(assigned.is_none());

        // Deleting the device cascades the chat identity but preserves the conversation snapshot.
        sqlx::query("DELETE FROM devices WHERE id = 'dev-1'")
            .execute(&pool)
            .await
            .unwrap();
        let identities = sqlx::query("SELECT count(*) as cnt FROM chat_devices")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get::<i64, _>("cnt");
        assert_eq!(identities, 0);
        let conversations = sqlx::query("SELECT count(*) as cnt FROM chat_conversations")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get::<i64, _>("cnt");
        assert_eq!(conversations, 1);
    }
    #[tokio::test]
    async fn test_purge_stale_records() {
        let pool = init_db("sqlite::memory:").await.unwrap();

        // Insert a user for foreign key constraint on sessions
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, is_active) VALUES (?, ?, ?, 'user', 1)",
        )
        .bind("user-test-purge")
        .bind("purge_user")
        .bind("hash")
        .execute(&pool)
        .await
        .unwrap();

        // 1. Insert an expired session (yesterday) and an active session (tomorrow)
        sqlx::query(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES ('expired_tok', 'user-test-purge', datetime('now', '-2 hours'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES ('active_tok', 'user-test-purge', datetime('now', '+2 hours'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        // 2. Insert an old login attempt (> 24 hours ago) and a fresh login attempt
        sqlx::query(
            "INSERT INTO login_attempts (username, ip_address, attempted_at, success) VALUES ('purge_user', '127.0.0.1', datetime('now', '-25 hours'), 0)",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO login_attempts (username, ip_address, attempted_at, success) VALUES ('purge_user', '127.0.0.1', datetime('now', '-1 hour'), 0)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // 3. Run purge
        let purged = purge_stale_records(&pool).await.unwrap();
        assert_eq!(purged, 2);

        // 4. Verify expired session deleted, active preserved
        let remaining_sessions = sqlx::query("SELECT token FROM sessions")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(remaining_sessions.len(), 1);
        assert_eq!(
            remaining_sessions[0].get::<String, _>("token"),
            "active_tok"
        );

        // 5. Verify old attempt deleted, fresh preserved
        let remaining_attempts = sqlx::query("SELECT count(*) as cnt FROM login_attempts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining_attempts.get::<i64, _>("cnt"), 1);
    }

    #[tokio::test]
    async fn test_f5_02_identity_groups_policies_idp_schema() {
        let pool = init_db("sqlite::memory:").await.unwrap();

        // 1. Groups & Constraints
        sqlx::query("INSERT INTO groups (id, kind, name, created_at, updated_at) VALUES ('grp-u1', 'user', 'Soporte N1', '2026-11-16T12:00:00Z', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query("INSERT INTO groups (id, kind, name, created_at, updated_at) VALUES ('grp-d1', 'device', 'Servidores Core', '2026-11-16T12:00:00Z', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        // Check constraint kind IN ('user', 'device')
        let invalid_kind = sqlx::query("INSERT INTO groups (id, kind, name, created_at, updated_at) VALUES ('grp-x', 'other', 'Invalido', '2026-11-16T12:00:00Z', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await;
        assert!(invalid_kind.is_err());

        // Unique constraint (kind, name)
        let dup_group = sqlx::query("INSERT INTO groups (id, kind, name, created_at, updated_at) VALUES ('grp-u2', 'user', 'Soporte N1', '2026-11-16T12:00:00Z', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await;
        assert!(dup_group.is_err());

        // 2. Group Members & Cascading Delete
        sqlx::query("INSERT INTO group_members (group_id, subject_type, subject_id, added_at) VALUES ('grp-u1', 'user', 'usr-123', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        // 3. Group Grants
        sqlx::query("INSERT INTO group_grants (from_group_id, to_group_id, permission, created_at) VALUES ('grp-u1', 'grp-d1', 'read', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        // Self-grant rejected (CHECK from_group_id <> to_group_id)
        let self_grant = sqlx::query("INSERT INTO group_grants (from_group_id, to_group_id, permission, created_at) VALUES ('grp-u1', 'grp-u1', 'read', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await;
        assert!(self_grant.is_err());

        // 4. Address Book
        sqlx::query("INSERT INTO address_book (id, name, group_id, created_at, updated_at) VALUES ('ab-1', 'Server Alpha', 'grp-d1', '2026-11-16T12:00:00Z', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        // 5. Policies & Constraints
        // Global policy (scope_id MUST be '')
        sqlx::query("INSERT INTO policies (id, scope_type, scope_id, version, document, document_sha256, state, created_at) VALUES ('pol-1', 'global', '', 1, '{}', 'sha', 'active', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        // Global policy with non-empty scope_id rejected
        let invalid_global = sqlx::query("INSERT INTO policies (id, scope_type, scope_id, version, document, document_sha256, state, created_at) VALUES ('pol-x', 'global', 'not-empty', 1, '{}', 'sha', 'active', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await;
        assert!(invalid_global.is_err());

        // Partial unique index: second active policy for (global, '') rejected
        let dup_active_global = sqlx::query("INSERT INTO policies (id, scope_type, scope_id, version, document, document_sha256, state, created_at) VALUES ('pol-2', 'global', '', 2, '{}', 'sha', 'active', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await;
        assert!(dup_active_global.is_err());

        // 6. Identity Providers & Federated Identities
        sqlx::query("INSERT INTO identity_providers (id, kind, name, config, created_at, updated_at) VALUES ('idp-1', 'oidc', 'Keycloak Corporate', '{}', '2026-11-16T12:00:00Z', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        // Check kind IN ('oidc', 'ldap')
        let invalid_idp = sqlx::query("INSERT INTO identity_providers (id, kind, name, config, created_at, updated_at) VALUES ('idp-x', 'saml', 'Invalid IdP', '{}', '2026-11-16T12:00:00Z', '2026-11-16T12:00:00Z')")
            .execute(&pool)
            .await;
        assert!(invalid_idp.is_err());

        // 7. Test Cascade Delete on Group
        sqlx::query("DELETE FROM groups WHERE id = 'grp-u1'")
            .execute(&pool)
            .await
            .unwrap();

        let remaining_members =
            sqlx::query("SELECT count(*) as cnt FROM group_members WHERE group_id = 'grp-u1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining_members.get::<i64, _>("cnt"), 0);

        let remaining_grants =
            sqlx::query("SELECT count(*) as cnt FROM group_grants WHERE from_group_id = 'grp-u1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining_grants.get::<i64, _>("cnt"), 0);

        // Address book group_id set to null on delete
        sqlx::query("DELETE FROM groups WHERE id = 'grp-d1'")
            .execute(&pool)
            .await
            .unwrap();

        let ab_entry = sqlx::query("SELECT group_id FROM address_book WHERE id = 'ab-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(ab_entry.get::<Option<String>, _>("group_id").is_none());
    }
}
