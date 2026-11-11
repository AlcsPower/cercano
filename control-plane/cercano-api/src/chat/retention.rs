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

//! Chat Retention and Purge Service (F4.5-07).
//!
//! Purges messages, attachments, and closed conversations older than
//! `CERCANO_CHAT_RETENTION_DAYS` (default 90 days).
//! Open conversations (`waiting`, `assigned`, `active`) are strictly preserved.
//! Disk files corresponding to purged attachments are removed immediately.
//! Emits `chat.retention.purged` audit event without leaking content.

use std::path::PathBuf;
use std::time::Duration;

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::config::Config;
use crate::AppState;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionPurgeReport {
    pub cutoff: String,
    pub conversations_deleted: u64,
    pub messages_deleted: u64,
    pub attachments_deleted: u64,
}

/// Executes a retention purge run on closed conversations older than `chat_retention_days`.
pub async fn run_chat_retention_purge(
    db: &SqlitePool,
    audit: &audit_core::AuditStore,
    config: &Config,
) -> Result<RetentionPurgeReport, sqlx::Error> {
    if !config.chat_enabled {
        return Ok(RetentionPurgeReport::default());
    }

    let retention_days = config.chat_retention_days.max(1);
    let cutoff = Utc::now() - chrono::Duration::days(retention_days);
    let cutoff_str = cutoff.to_rfc3339();

    // 1. Find all attachment storage keys in closed conversations before cutoff
    let storage_keys: Vec<String> = sqlx::query_scalar(
        "SELECT a.storage_key FROM chat_attachments a
         JOIN chat_messages m ON a.message_id = m.id
         JOIN chat_conversations c ON m.conversation_id = c.id
         WHERE c.status = 'closed' AND c.closed_at < ?",
    )
    .bind(&cutoff_str)
    .fetch_all(db)
    .await?;

    // 2. Count messages and closed conversations before deleting
    let messages_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_messages m
         JOIN chat_conversations c ON m.conversation_id = c.id
         WHERE c.status = 'closed' AND c.closed_at < ?",
    )
    .bind(&cutoff_str)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    // 3. Delete closed conversations from DB (ON DELETE CASCADE removes messages, attachments, reads)
    let rows_affected =
        sqlx::query("DELETE FROM chat_conversations WHERE status = 'closed' AND closed_at < ?")
            .bind(&cutoff_str)
            .execute(db)
            .await?
            .rows_affected();

    // 4. Remove attachment files from disk
    let attachment_dir = PathBuf::from(&config.chat_attachment_dir);
    for key in &storage_keys {
        let file_path = attachment_dir.join(key);
        let _ = tokio::fs::remove_file(file_path).await;
    }

    let report = RetentionPurgeReport {
        cutoff: cutoff_str.clone(),
        conversations_deleted: rows_affected,
        messages_deleted: messages_count as u64,
        attachments_deleted: storage_keys.len() as u64,
    };

    // 5. Append audit event
    let actor = Actor::with_type("cercano-retention", "system");
    let subject = Subject::with_type("chat_retention", "system");
    let audit_input = EventInput::new(
        Uuid::now_v7().to_string(),
        Source::Api,
        Category::Chat,
        "chat.retention.purged",
        actor,
        Outcome::Success,
        json!({
            "cutoff": &report.cutoff,
            "conversations_deleted": report.conversations_deleted,
            "messages_deleted": report.messages_deleted,
            "attachments_deleted": report.attachments_deleted
        }),
    )
    .with_subject(subject);
    let _ = audit.append(audit_input).await;

    Ok(report)
}

/// Spawns a background task running chat retention purge daily.
pub fn spawn_chat_retention_task(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Run once on startup
        if let Err(e) = run_chat_retention_purge(&state.db, &state.audit, &state.config).await {
            tracing::error!("Chat retention initial purge failed: {e}");
        }

        // Run every 24 hours
        let mut interval = tokio::time::interval(Duration::from_secs(24 * 3600));
        interval.tick().await; // consume initial tick

        loop {
            interval.tick().await;
            if let Err(e) = run_chat_retention_purge(&state.db, &state.audit, &state.config).await {
                tracing::error!("Periodic chat retention purge failed: {e}");
            }
        }
    })
}
