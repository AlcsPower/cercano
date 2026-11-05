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

pub const MIGRATIONS: &[Migration] = &[Migration {
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
}];

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
        let rows = sqlx::query("SELECT version, name FROM schema_migrations")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<i64, _>("version"), 1);
        assert_eq!(rows[0].get::<String, _>("name"), "001_initial_schema");

        // Verify devices table exists
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
        assert_eq!(rows.len(), 1);
    }
}
