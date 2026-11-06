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

use audit_core::{
    verify_checkpoint, Actor, AuditStore, Category, EventFilter, EventInput, Outcome, Source,
    Subject, GENESIS_HASH,
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;

async fn create_test_store() -> (AuditStore, tempfile::TempDir) {
    let dir = tempdir().expect("Failed to create tempdir");
    let db_path = dir.path().join("test_audit.sqlite");
    let url = format!("sqlite://{}", db_path.to_str().unwrap());
    let store = AuditStore::open_url(&url)
        .await
        .expect("Failed to open test audit store");
    (store, dir)
}

#[tokio::test]
async fn test_genesis_to_sequential_chain() {
    let (store, _dir) = create_test_store().await;

    // Append 1st event
    let event1 = store
        .append(EventInput::new(
            "trace-001",
            Source::Client,
            Category::Auth,
            "auth.login",
            Actor::new("user-admin"),
            Outcome::Success,
            json!({"method": "password"}),
        ))
        .await
        .expect("Append event1 failed");

    assert_eq!(event1.sequence, 1);
    assert_eq!(event1.prev_hash, GENESIS_HASH);
    assert!(!event1.hash.is_empty());

    // Append 2nd event
    let event2 = store
        .append(
            EventInput::new(
                "trace-001",
                Source::Client,
                Category::Conn,
                "conn.start",
                Actor::new("user-admin"),
                Outcome::Success,
                json!({"client_ip": "10.0.0.1"}),
            )
            .with_subject(Subject::new("device-win11")),
        )
        .await
        .expect("Append event2 failed");

    assert_eq!(event2.sequence, 2);
    assert_eq!(event2.prev_hash, event1.hash);

    // Append 3rd event
    let event3 = store
        .append(EventInput::new(
            "trace-001",
            Source::Client,
            Category::File,
            "file.transfer",
            Actor::new("user-admin"),
            Outcome::Success,
            json!({"file_count": 3, "total_bytes": 1048576}),
        ))
        .await
        .expect("Append event3 failed");

    assert_eq!(event3.sequence, 3);
    assert_eq!(event3.prev_hash, event2.hash);

    // Verify entire chain
    let verification = store
        .verify_chain(None, None)
        .await
        .expect("Verification query failed");
    assert!(verification.is_valid);
    assert_eq!(verification.total_verified, 3);
    assert_eq!(verification.first_sequence, Some(1));
    assert_eq!(verification.last_sequence, Some(3));
    assert!(verification.error.is_none());

    // Query events with filter
    let file_events = store
        .query_events(EventFilter {
            category: Some(Category::File),
            ..Default::default()
        })
        .await
        .expect("Query failed");
    assert_eq!(file_events.len(), 1);
    assert_eq!(file_events[0].action, "file.transfer");
}

#[tokio::test]
async fn test_tamper_detection() {
    let (store, _dir) = create_test_store().await;

    // Append 3 events
    for i in 1..=3 {
        store
            .append(EventInput::new(
                format!("trace-{:03}", i),
                Source::Console,
                Category::Console,
                format!("action-{}", i),
                Actor::new(format!("admin-{}", i)),
                Outcome::Success,
                json!({"index": i}),
            ))
            .await
            .expect("Append failed");
    }

    // Verify baseline passes
    let valid_check = store.verify_chain(None, None).await.unwrap();
    assert!(valid_check.is_valid);
    assert_eq!(valid_check.total_verified, 3);

    // Bypass trigger to tamper row 2 directly in SQLite
    let pool = store.pool();
    sqlx::query("DROP TRIGGER IF EXISTS trg_audit_events_no_update")
        .execute(pool)
        .await
        .expect("Drop trigger failed");

    // Tamper row 2 action
    sqlx::query("UPDATE audit_events SET action = 'tampered_action' WHERE sequence = 2")
        .execute(pool)
        .await
        .expect("Tampering UPDATE failed");

    // Verify chain detects corruption at sequence 2
    let tamper_check = store.verify_chain(None, None).await.unwrap();
    assert!(!tamper_check.is_valid);
    assert_eq!(tamper_check.corrupted_sequence(), Some(2));

    let err = tamper_check.error.expect("Expected verification error");
    assert_eq!(err.sequence, 2);
    assert!(err.reason.contains("Hash mismatch"));
}

#[tokio::test]
async fn test_triggers_prevent_update_and_delete() {
    let (store, _dir) = create_test_store().await;

    store
        .append(EventInput::new(
            "trace-lock-001",
            Source::Api,
            Category::Auth,
            "auth.login",
            Actor::new("superadmin"),
            Outcome::Success,
            json!({}),
        ))
        .await
        .expect("Append failed");

    let pool = store.pool();

    // 1. Attempt raw UPDATE
    let update_res =
        sqlx::query("UPDATE audit_events SET action = 'illegal_update' WHERE sequence = 1")
            .execute(pool)
            .await;

    assert!(
        update_res.is_err(),
        "Expected UPDATE to be blocked by trigger"
    );
    let err_str = update_res.unwrap_err().to_string();
    assert!(
        err_str.contains("AUDIT VIOLATION: Updates strictly prohibited on audit_events"),
        "Unexpected error: {}",
        err_str
    );

    // 2. Attempt raw DELETE
    let delete_res = sqlx::query("DELETE FROM audit_events WHERE sequence = 1")
        .execute(pool)
        .await;

    assert!(
        delete_res.is_err(),
        "Expected DELETE to be blocked by trigger"
    );
    let err_str = delete_res.unwrap_err().to_string();
    assert!(
        err_str.contains("AUDIT VIOLATION: Deletions strictly prohibited on audit_events"),
        "Unexpected error: {}",
        err_str
    );

    // Verify event is untouched
    let last = store.get_last_event().await.unwrap().unwrap();
    assert_eq!(last.action, "auth.login");
}

#[tokio::test]
async fn test_concurrent_appends() {
    let (store, _dir) = create_test_store().await;
    let store_arc = Arc::new(store);

    let concurrent_tasks = 40;
    let mut handles = Vec::new();

    for i in 0..concurrent_tasks {
        let store_clone = Arc::clone(&store_arc);
        let handle = tokio::spawn(async move {
            store_clone
                .append(EventInput::new(
                    format!("concurrent-trace-{:03}", i),
                    Source::Client,
                    Category::Conn,
                    format!("conn.test.{}", i),
                    Actor::with_details(
                        format!("worker-{}", i),
                        "device",
                        Some(format!("Worker {}", i)),
                        Some(format!("192.168.1.{}", 10 + i)),
                    ),
                    Outcome::Success,
                    json!({"task_id": i}),
                ))
                .await
        });
        handles.push(handle);
    }

    for handle in handles {
        let res = handle.await.expect("Task panicked");
        assert!(res.is_ok(), "Concurrent append failed: {:?}", res.err());
    }

    // Verify whole chain
    let verification = store_arc
        .verify_chain(None, None)
        .await
        .expect("Verification failed");

    assert!(
        verification.is_valid,
        "Verification failed after concurrent appends: {:?}",
        verification.error
    );
    assert_eq!(verification.total_verified, concurrent_tasks);
    assert_eq!(verification.first_sequence, Some(1));
    assert_eq!(verification.last_sequence, Some(concurrent_tasks as i64));

    // Verify no sequence gaps exist
    let all_events = store_arc
        .query_events(EventFilter::default())
        .await
        .expect("Query failed");
    assert_eq!(all_events.len(), concurrent_tasks);
    for (i, event) in all_events.iter().enumerate() {
        assert_eq!(event.sequence, (i + 1) as i64);
    }
}

#[tokio::test]
async fn test_checkpoint_creation_and_retrieval() {
    let (store, _dir) = create_test_store().await;
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Checkpoint on empty store
    let cp0 = store
        .create_checkpoint(&signing_key, "key-test-1")
        .await
        .expect("create checkpoint 0");
    assert_eq!(cp0.sequence, 1);
    assert_eq!(cp0.event_count, 0);
    assert_eq!(cp0.last_hash, GENESIS_HASH);
    assert!(verify_checkpoint(&verifying_key, &cp0).unwrap());

    // Append 2 events
    let _ev1 = store
        .append(EventInput::new(
            "trace-cp-1",
            Source::Client,
            Category::Auth,
            "auth.login",
            Actor::new("user-1"),
            Outcome::Success,
            json!({}),
        ))
        .await
        .expect("append 1");

    let ev2 = store
        .append(EventInput::new(
            "trace-cp-1",
            Source::Client,
            Category::Conn,
            "conn.start",
            Actor::new("user-1"),
            Outcome::Success,
            json!({}),
        ))
        .await
        .expect("append 2");

    // Create 2nd checkpoint
    let cp1 = store
        .create_checkpoint(&signing_key, "key-test-1")
        .await
        .expect("create checkpoint 1");

    assert_eq!(cp1.sequence, 2);
    assert_eq!(cp1.event_count, 2);
    assert_eq!(cp1.last_hash, ev2.hash);
    assert!(verify_checkpoint(&verifying_key, &cp1).unwrap());

    // Test get_last_checkpoint
    let last = store
        .get_last_checkpoint()
        .await
        .expect("get last checkpoint")
        .expect("checkpoint exists");
    assert_eq!(last.sequence, 2);
    assert_eq!(last.checkpoint_id, cp1.checkpoint_id);

    // Test list_checkpoints
    let all = store
        .list_checkpoints(None)
        .await
        .expect("list checkpoints");
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].sequence, 1);
    assert_eq!(all[1].sequence, 2);
}

#[tokio::test]
async fn test_checkpoint_triggers_prevent_update_and_delete() {
    let (store, _dir) = create_test_store().await;
    let signing_key = SigningKey::generate(&mut OsRng);

    let cp = store
        .create_checkpoint(&signing_key, "key-test-1")
        .await
        .expect("create checkpoint");

    // Direct UPDATE attempt on audit_checkpoints table
    let update_res =
        sqlx::query("UPDATE audit_checkpoints SET last_hash = 'tampered' WHERE sequence = ?")
            .bind(cp.sequence)
            .execute(store.pool())
            .await;

    assert!(
        update_res.is_err(),
        "Direct UPDATE on audit_checkpoints should have been rejected by trigger"
    );
    let err_msg = update_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("AUDIT VIOLATION: Updates strictly prohibited on audit_checkpoints"),
        "Unexpected error message: {}",
        err_msg
    );

    // Direct DELETE attempt on audit_checkpoints table
    let delete_res = sqlx::query("DELETE FROM audit_checkpoints WHERE sequence = ?")
        .bind(cp.sequence)
        .execute(store.pool())
        .await;

    assert!(
        delete_res.is_err(),
        "Direct DELETE on audit_checkpoints should have been rejected by trigger"
    );
    let err_msg = delete_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("AUDIT VIOLATION: Deletions strictly prohibited on audit_checkpoints"),
        "Unexpected error message: {}",
        err_msg
    );
}
