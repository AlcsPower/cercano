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
        assert_eq!(rows.len(), 6);
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
        assert_eq!(rows.len(), 6);
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
}
