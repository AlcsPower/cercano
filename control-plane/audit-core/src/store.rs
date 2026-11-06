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

use crate::canonical::to_canonical_json_string;
use crate::checkpoint::{AuditCheckpoint, CheckpointPayload};
use crate::error::AuditError;
use crate::hash::compute_hash;
use crate::model::{
    Actor, AuditEvent, Category, ChainVerificationError, EventFilter, EventInput, EventPayload,
    Outcome, Source, Subject, VerificationResult, GENESIS_HASH,
};
use ed25519_dalek::SigningKey;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Executor, Row, SqlitePool};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Append-only audit store backed by SQLite with cryptographic hash chaining and write serialization.
#[derive(Clone)]
pub struct AuditStore {
    pool: SqlitePool,
    append_lock: Arc<Mutex<()>>,
}

impl AuditStore {
    /// Creates a new `AuditStore` wrapping an existing `SqlitePool` and runs initial migrations/triggers.
    pub async fn new(pool: SqlitePool) -> Result<Self, AuditError> {
        let store = Self {
            pool,
            append_lock: Arc::new(Mutex::new(())),
        };
        store.init_schema().await?;
        Ok(store)
    }

    /// Connects to a SQLite database by connection string/path and initializes schema.
    pub async fn open_url(database_url: &str) -> Result<Self, AuditError> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);

        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;

        Self::new(pool).await
    }

    /// Access the underlying `SqlitePool`.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Initializes tables, indexes, and anti-tamper triggers.
    pub async fn init_schema(&self) -> Result<(), AuditError> {
        let schema_sql = r#"
        CREATE TABLE IF NOT EXISTS audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            trace_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            subject TEXT,
            outcome TEXT NOT NULL,
            details TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_audit_events_trace_id ON audit_events(trace_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_category ON audit_events(category);
        CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
        CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);

        CREATE TRIGGER IF NOT EXISTS trg_audit_events_no_update
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'AUDIT VIOLATION: Updates strictly prohibited on audit_events');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_audit_events_no_delete
        BEFORE DELETE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'AUDIT VIOLATION: Deletions strictly prohibited on audit_events');
        END;

        CREATE TABLE IF NOT EXISTS audit_checkpoints (
            sequence INTEGER PRIMARY KEY,
            checkpoint_id TEXT NOT NULL UNIQUE,
            last_hash TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            ts TEXT NOT NULL,
            key_id TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_ts ON audit_checkpoints(ts);
        CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_key_id ON audit_checkpoints(key_id);

        CREATE TABLE IF NOT EXISTS audit_export_checkpoint (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            sequence INTEGER NOT NULL DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TRIGGER IF NOT EXISTS trg_audit_checkpoints_no_update
        BEFORE UPDATE ON audit_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'AUDIT VIOLATION: Updates strictly prohibited on audit_checkpoints');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_audit_checkpoints_no_delete
        BEFORE DELETE ON audit_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'AUDIT VIOLATION: Deletions strictly prohibited on audit_checkpoints');
        END;
        "#;

        self.pool.execute(schema_sql).await?;
        Ok(())
    }

    /// Appends an event to the append-only audit store.
    ///
    /// Serialization of appends is guaranteed via memory lock and atomic transaction.
    pub async fn append(&self, event_input: EventInput) -> Result<AuditEvent, AuditError> {
        let _guard = self.append_lock.lock().await;

        let mut tx = self.pool.begin().await?;

        // 1. Determine prev_hash from the last event
        let prev_hash = {
            let last_row =
                sqlx::query("SELECT hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
                    .fetch_optional(&mut *tx)
                    .await?;

            match last_row {
                Some(row) => row.try_get::<String, _>("hash")?,
                None => GENESIS_HASH.to_string(),
            }
        };

        // 2. Prepare payload fields
        let event_id = event_input
            .event_id
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());

        let ts = event_input.ts.unwrap_or_else(|| {
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });

        let payload = EventPayload {
            event_id: event_id.clone(),
            trace_id: event_input.trace_id,
            ts,
            source: event_input.source,
            category: event_input.category,
            action: event_input.action,
            actor: event_input.actor,
            subject: event_input.subject,
            outcome: event_input.outcome,
            details: event_input.details,
        };

        // 3. Compute hash: SHA256(prev_hash + canonical_json(payload))
        let hash = compute_hash(&prev_hash, &payload)?;

        // 4. Serialize JSON fields for DB storage
        let actor_json = to_canonical_json_string(&payload.actor)?;
        let subject_json = match &payload.subject {
            Some(s) => Some(to_canonical_json_string(s)?),
            None => None,
        };
        let details_json = to_canonical_json_string(&payload.details)?;

        // 5. Insert event into DB
        sqlx::query(
            r#"
            INSERT INTO audit_events (
                event_id, trace_id, ts, source, category, action,
                actor, subject, outcome, details, prev_hash, hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&payload.event_id)
        .bind(&payload.trace_id)
        .bind(&payload.ts)
        .bind(payload.source.as_str())
        .bind(payload.category.as_str())
        .bind(&payload.action)
        .bind(&actor_json)
        .bind(&subject_json)
        .bind(payload.outcome.as_str())
        .bind(&details_json)
        .bind(&prev_hash)
        .bind(&hash)
        .execute(&mut *tx)
        .await?;

        // 6. Fetch inserted row
        let row = sqlx::query(
            r#"
            SELECT sequence, event_id, trace_id, ts, source, category, action,
                   actor, subject, outcome, details, prev_hash, hash, created_at
            FROM audit_events
            WHERE event_id = ?
            "#,
        )
        .bind(&payload.event_id)
        .fetch_one(&mut *tx)
        .await?;

        let event = Self::row_to_event(row)?;
        tx.commit().await?;

        Ok(event)
    }

    /// Verifies the cryptographic integrity of the hash chain across a sequence range.
    pub async fn verify_chain(
        &self,
        from_seq: Option<i64>,
        to_seq: Option<i64>,
    ) -> Result<VerificationResult, AuditError> {
        let mut query_builder = String::from(
            r#"
            SELECT sequence, event_id, trace_id, ts, source, category, action,
                   actor, subject, outcome, details, prev_hash, hash, created_at
            FROM audit_events
            WHERE 1=1
            "#,
        );

        if from_seq.is_some() {
            query_builder.push_str(" AND sequence >= ?");
        }
        if to_seq.is_some() {
            query_builder.push_str(" AND sequence <= ?");
        }
        query_builder.push_str(" ORDER BY sequence ASC");

        let mut query = sqlx::query(&query_builder);
        if let Some(f) = from_seq {
            query = query.bind(f);
        }
        if let Some(t) = to_seq {
            query = query.bind(t);
        }

        let rows = query.fetch_all(&self.pool).await?;
        if rows.is_empty() {
            return Ok(VerificationResult {
                is_valid: true,
                total_verified: 0,
                first_sequence: None,
                last_sequence: None,
                error: None,
            });
        }

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(Self::row_to_event(row)?);
        }

        let first_seq = events[0].sequence;
        let last_seq = events[events.len() - 1].sequence;

        // If checking from beginning or sequence 1, genesis block prev_hash must be GENESIS_HASH
        if (from_seq.is_none() || from_seq == Some(1))
            && first_seq == 1
            && events[0].prev_hash != GENESIS_HASH
        {
            return Ok(VerificationResult {
                is_valid: false,
                total_verified: 0,
                first_sequence: Some(first_seq),
                last_sequence: Some(last_seq),
                error: Some(ChainVerificationError {
                    sequence: 1,
                    event_id: events[0].event_id.clone(),
                    reason: format!(
                        "Genesis block prev_hash is '{}', expected '{}'",
                        events[0].prev_hash, GENESIS_HASH
                    ),
                    expected_hash: Some(GENESIS_HASH.to_string()),
                    actual_hash: Some(events[0].prev_hash.clone()),
                }),
            });
        }

        let mut prev_event: Option<&AuditEvent> = None;

        for (expected_seq, (idx, event)) in (first_seq..).zip(events.iter().enumerate()) {
            // Check sequence continuity
            if event.sequence != expected_seq {
                return Ok(VerificationResult {
                    is_valid: false,
                    total_verified: idx,
                    first_sequence: Some(first_seq),
                    last_sequence: Some(last_seq),
                    error: Some(ChainVerificationError {
                        sequence: event.sequence,
                        event_id: event.event_id.clone(),
                        reason: format!(
                            "Sequence gap detected: expected {}, found {}",
                            expected_seq, event.sequence
                        ),
                        expected_hash: None,
                        actual_hash: None,
                    }),
                });
            }

            // Check chain link with previous event in slice
            if let Some(prev) = prev_event {
                if event.prev_hash != prev.hash {
                    return Ok(VerificationResult {
                        is_valid: false,
                        total_verified: idx,
                        first_sequence: Some(first_seq),
                        last_sequence: Some(last_seq),
                        error: Some(ChainVerificationError {
                            sequence: event.sequence,
                            event_id: event.event_id.clone(),
                            reason: format!(
                                "Chain link broken: prev_hash '{}' does not match previous hash '{}'",
                                event.prev_hash, prev.hash
                            ),
                            expected_hash: Some(prev.hash.clone()),
                            actual_hash: Some(event.prev_hash.clone()),
                        }),
                    });
                }
            }

            // Check cryptographic hash computation
            let expected_hash = compute_hash(&event.prev_hash, &event.payload())?;
            if event.hash != expected_hash {
                return Ok(VerificationResult {
                    is_valid: false,
                    total_verified: idx,
                    first_sequence: Some(first_seq),
                    last_sequence: Some(last_seq),
                    error: Some(ChainVerificationError {
                        sequence: event.sequence,
                        event_id: event.event_id.clone(),
                        reason: format!(
                            "Hash mismatch: computed '{}', recorded '{}'",
                            expected_hash, event.hash
                        ),
                        expected_hash: Some(expected_hash),
                        actual_hash: Some(event.hash.clone()),
                    }),
                });
            }

            prev_event = Some(event);
        }

        Ok(VerificationResult {
            is_valid: true,
            total_verified: events.len(),
            first_sequence: Some(first_seq),
            last_sequence: Some(last_seq),
            error: None,
        })
    }

    /// Loads the persisted SIEM export cursor, defaulting to zero.
    pub async fn load_export_cursor(&self) -> Result<i64, AuditError> {
        let row = sqlx::query("SELECT sequence FROM audit_export_checkpoint WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.try_get("sequence")).transpose()?.unwrap_or(0))
    }

    /// Persists the SIEM export cursor atomically.
    pub async fn save_export_cursor(&self, sequence: i64) -> Result<(), AuditError> {
        sqlx::query(
            "INSERT INTO audit_export_checkpoint (id, sequence) VALUES (1, ?)\n             ON CONFLICT(id) DO UPDATE SET sequence = excluded.sequence, updated_at = CURRENT_TIMESTAMP",
        )
        .bind(sequence)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Retrieves the most recent event in the store.
    pub async fn get_last_event(&self) -> Result<Option<AuditEvent>, AuditError> {
        let row = sqlx::query(
            r#"
            SELECT sequence, event_id, trace_id, ts, source, category, action,
                   actor, subject, outcome, details, prev_hash, hash, created_at
            FROM audit_events
            ORDER BY sequence DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(Self::row_to_event).transpose()
    }

    /// Retrieves an audit event by its unique `event_id`.
    pub async fn get_event_by_id(&self, event_id: &str) -> Result<Option<AuditEvent>, AuditError> {
        let row = sqlx::query(
            r#"
            SELECT sequence, event_id, trace_id, ts, source, category, action,
                   actor, subject, outcome, details, prev_hash, hash, created_at
            FROM audit_events
            WHERE event_id = ?
            "#,
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(Self::row_to_event).transpose()
    }

    /// Queries events matching given filter criteria.
    pub async fn query_events(&self, filter: EventFilter) -> Result<Vec<AuditEvent>, AuditError> {
        let mut query_builder = String::from(
            r#"
            SELECT sequence, event_id, trace_id, ts, source, category, action,
                   actor, subject, outcome, details, prev_hash, hash, created_at
            FROM audit_events
            WHERE 1=1
            "#,
        );

        if filter.trace_id.is_some() {
            query_builder.push_str(" AND trace_id = ?");
        }
        if filter.category.is_some() {
            query_builder.push_str(" AND category = ?");
        }
        if filter.action.is_some() {
            query_builder.push_str(" AND action = ?");
        }
        if filter.actor_id.is_some() {
            query_builder.push_str(" AND json_extract(actor, '$.id') = ?");
        }
        if filter.subject_id.is_some() {
            query_builder.push_str(" AND json_extract(subject, '$.id') = ?");
        }
        if filter.outcome.is_some() {
            query_builder.push_str(" AND outcome = ?");
        }
        if filter.from_ts.is_some() {
            query_builder.push_str(" AND ts >= ?");
        }
        if filter.to_ts.is_some() {
            query_builder.push_str(" AND ts <= ?");
        }
        if filter.from_seq.is_some() {
            query_builder.push_str(" AND sequence >= ?");
        }
        if filter.after_sequence.is_some() {
            query_builder.push_str(" AND sequence > ?");
        }
        if filter.to_seq.is_some() {
            query_builder.push_str(" AND sequence <= ?");
        }

        query_builder.push_str(" ORDER BY sequence ASC");

        if filter.limit.is_some() {
            query_builder.push_str(" LIMIT ?");
            if filter.offset.is_some() {
                query_builder.push_str(" OFFSET ?");
            }
        }

        let mut query = sqlx::query(&query_builder);

        if let Some(v) = &filter.trace_id {
            query = query.bind(v);
        }
        if let Some(v) = &filter.category {
            query = query.bind(v.as_str());
        }
        if let Some(v) = &filter.action {
            query = query.bind(v);
        }
        if let Some(v) = &filter.actor_id {
            query = query.bind(v);
        }
        if let Some(v) = &filter.subject_id {
            query = query.bind(v);
        }
        if let Some(v) = &filter.outcome {
            query = query.bind(v.as_str());
        }
        if let Some(v) = &filter.from_ts {
            query = query.bind(v);
        }
        if let Some(v) = &filter.to_ts {
            query = query.bind(v);
        }
        if let Some(v) = filter.from_seq {
            query = query.bind(v);
        }
        if let Some(v) = filter.after_sequence {
            query = query.bind(v);
        }
        if let Some(v) = filter.to_seq {
            query = query.bind(v);
        }
        if let Some(v) = filter.limit {
            query = query.bind(v);
            if let Some(o) = filter.offset {
                query = query.bind(o);
            }
        }

        let rows = query.fetch_all(&self.pool).await?;
        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(Self::row_to_event(row)?);
        }

        Ok(results)
    }

    /// Queries unlinked candidate events for fallback correlation matching participant IDs within a time window.
    pub async fn query_unlinked_events(
        &self,
        participant_a: &str,
        participant_b: &str,
        from_ts: &str,
        to_ts: &str,
    ) -> Result<Vec<AuditEvent>, AuditError> {
        let query_str = r#"
            SELECT sequence, event_id, trace_id, ts, source, category, action,
                   actor, subject, outcome, details, prev_hash, hash, created_at
            FROM audit_events
            WHERE (trace_id = '' OR trace_id = 'unknown' OR trace_id = 'none' OR trace_id = '-' OR trace_id = 'unlinked')
              AND (
                  (
                      (json_extract(actor, '$.id') = ? OR json_extract(details, '$.controller_id') = ?)
                      AND
                      (json_extract(subject, '$.id') = ? OR json_extract(details, '$.controlled_id') = ?)
                  )
                  OR
                  (
                      (json_extract(actor, '$.id') = ? OR json_extract(details, '$.controlled_id') = ?)
                      AND
                      (json_extract(subject, '$.id') = ? OR json_extract(details, '$.controller_id') = ?)
                  )
              )
              AND ts >= ? AND ts <= ?
            ORDER BY sequence ASC
        "#;

        let rows = sqlx::query(query_str)
            .bind(participant_a)
            .bind(participant_a)
            .bind(participant_b)
            .bind(participant_b)
            .bind(participant_b)
            .bind(participant_b)
            .bind(participant_a)
            .bind(participant_a)
            .bind(from_ts)
            .bind(to_ts)
            .fetch_all(&self.pool)
            .await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(Self::row_to_event(row)?);
        }

        Ok(results)
    }

    pub fn row_to_event(row: sqlx::sqlite::SqliteRow) -> Result<AuditEvent, AuditError> {
        let sequence: i64 = row.try_get("sequence")?;
        let event_id: String = row.try_get("event_id")?;
        let trace_id: String = row.try_get("trace_id")?;
        let ts: String = row.try_get("ts")?;
        let source_str: String = row.try_get("source")?;
        let category_str: String = row.try_get("category")?;
        let action: String = row.try_get("action")?;
        let actor_str: String = row.try_get("actor")?;
        let subject_str: Option<String> = row.try_get("subject")?;
        let outcome_str: String = row.try_get("outcome")?;
        let details_str: String = row.try_get("details")?;
        let prev_hash: String = row.try_get("prev_hash")?;
        let hash: String = row.try_get("hash")?;
        let created_at: String = row.try_get("created_at")?;

        let source = Source::from_str(&source_str).unwrap_or(Source::Other(source_str));
        let category = Category::from_str(&category_str).unwrap_or(Category::Other(category_str));
        let outcome = Outcome::from_str(&outcome_str).unwrap_or(Outcome::Other(outcome_str));

        let actor: Actor = serde_json::from_str(&actor_str)?;
        let subject: Option<Subject> = match subject_str {
            Some(s) if !s.trim().is_empty() => Some(serde_json::from_str(&s)?),
            _ => None,
        };
        let details: serde_json::Value = serde_json::from_str(&details_str)?;

        Ok(AuditEvent {
            sequence,
            event_id,
            trace_id,
            ts,
            source,
            category,
            action,
            actor,
            subject,
            outcome,
            details,
            prev_hash,
            hash,
            created_at,
        })
    }

    /// Creates and persists a signed audit checkpoint committing to the current head of the audit chain.
    pub async fn create_checkpoint(
        &self,
        signing_key: &SigningKey,
        key_id: &str,
    ) -> Result<AuditCheckpoint, AuditError> {
        let _guard = self.append_lock.lock().await;

        let mut tx = self.pool.begin().await?;

        // 1. Determine last event sequence and hash
        let last_event_row =
            sqlx::query("SELECT sequence, hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?;

        let (event_count, last_hash) = match last_event_row {
            Some(row) => (
                row.try_get::<i64, _>("sequence")?,
                row.try_get::<String, _>("hash")?,
            ),
            None => (0, GENESIS_HASH.to_string()),
        };

        // 2. Determine next checkpoint sequence
        let last_cp_row =
            sqlx::query("SELECT sequence FROM audit_checkpoints ORDER BY sequence DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?;

        let next_sequence = match last_cp_row {
            Some(row) => row.try_get::<i64, _>("sequence")? + 1,
            None => 1,
        };

        let checkpoint_id = uuid::Uuid::now_v7().to_string();
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let payload = CheckpointPayload::new(
            checkpoint_id,
            next_sequence,
            last_hash,
            event_count,
            ts,
            key_id,
        );

        let checkpoint = payload.sign(signing_key)?;

        // 3. Insert checkpoint into DB
        sqlx::query(
            r#"
            INSERT INTO audit_checkpoints (
                sequence, checkpoint_id, last_hash, event_count, ts, key_id, signature
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(checkpoint.sequence)
        .bind(&checkpoint.checkpoint_id)
        .bind(&checkpoint.last_hash)
        .bind(checkpoint.event_count)
        .bind(&checkpoint.ts)
        .bind(&checkpoint.key_id)
        .bind(&checkpoint.signature)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(checkpoint)
    }

    /// Retrieves the most recent checkpoint in the store.
    pub async fn get_last_checkpoint(&self) -> Result<Option<AuditCheckpoint>, AuditError> {
        let row = sqlx::query(
            r#"
            SELECT sequence, checkpoint_id, last_hash, event_count, ts, key_id, signature
            FROM audit_checkpoints
            ORDER BY sequence DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(Self::row_to_checkpoint).transpose()
    }

    /// Queries all checkpoints in ascending sequence order.
    pub async fn list_checkpoints(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<AuditCheckpoint>, AuditError> {
        let mut sql = String::from(
            r#"
            SELECT sequence, checkpoint_id, last_hash, event_count, ts, key_id, signature
            FROM audit_checkpoints
            ORDER BY sequence ASC
            "#,
        );
        if limit.is_some() {
            sql.push_str(" LIMIT ?");
        }
        let mut query = sqlx::query(&sql);
        if let Some(l) = limit {
            query = query.bind(l);
        }
        let rows = query.fetch_all(&self.pool).await?;
        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(Self::row_to_checkpoint(row)?);
        }
        Ok(results)
    }

    fn row_to_checkpoint(row: sqlx::sqlite::SqliteRow) -> Result<AuditCheckpoint, AuditError> {
        Ok(AuditCheckpoint {
            sequence: row.try_get("sequence")?,
            checkpoint_id: row.try_get("checkpoint_id")?,
            last_hash: row.try_get("last_hash")?,
            event_count: row.try_get("event_count")?,
            ts: row.try_get("ts")?,
            key_id: row.try_get("key_id")?,
            signature: row.try_get("signature")?,
        })
    }
}
