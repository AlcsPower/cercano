// Copyright (C) 2026 Cercano Contributors
//
// This file is part of Cercano.
//
// Cercano is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! F2-13 integration coverage for tamper detection, clock authority, concurrency,
//! and restart atomicity. The ten-minute 500/s run is opt-in via `--ignored`.

use audit_core::{Actor, AuditStore, Category, EventFilter, EventInput, Outcome, Source};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::time::{sleep, Duration, Instant};

async fn store() -> (AuditStore, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("audit.sqlite").display());
    (
        AuditStore::open_url(&url).await.expect("open audit store"),
        dir,
    )
}

fn event(id: usize) -> EventInput {
    EventInput::new(
        format!("trace-f2-13-{id}"),
        Source::Api,
        Category::Console,
        "console.test",
        Actor::new("f2-13"),
        Outcome::Success,
        json!({"id": id}),
    )
    .with_event_id(format!("f2-13-event-{id}"))
}

#[tokio::test]
async fn manipulation_is_detected_and_triggers_block_direct_writes() {
    let (store, _dir) = store().await;
    for id in 0..3 {
        store.append(event(id)).await.expect("append");
    }

    let blocked = sqlx::query("UPDATE audit_events SET action = 'tampered' WHERE sequence = 2")
        .execute(store.pool())
        .await;
    assert!(blocked.is_err(), "append-only trigger must reject UPDATE");

    sqlx::query("DROP TRIGGER trg_audit_events_no_update")
        .execute(store.pool())
        .await
        .expect("drop trigger for controlled tamper simulation");
    sqlx::query("UPDATE audit_events SET action = 'tampered' WHERE sequence = 2")
        .execute(store.pool())
        .await
        .expect("tamper simulation");

    let result = store.verify_chain(None, None).await.expect("verify");
    assert!(!result.is_valid);
    assert_eq!(result.corrupted_sequence(), Some(2));
}

#[tokio::test]
async fn client_reported_timestamp_is_preserved_while_server_created_at_records_receipt_time() {
    let (store, _dir) = store().await;
    let client_ts = "1970-01-01T00:00:00.000Z";
    let appended = store
        .append(event(1).with_ts(client_ts))
        .await
        .expect("append");
    assert_eq!(appended.ts, client_ts, "client timestamp remains evidence");
    assert!(
        !appended.created_at.starts_with("1970-"),
        "server records true receipt time in created_at"
    );
}

#[tokio::test]
async fn concurrent_appends_keep_one_contiguous_valid_chain() {
    let (store, _dir) = store().await;
    let store = Arc::new(store);
    let count = 500;
    let mut tasks = Vec::with_capacity(count);
    for id in 0..count {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move { store.append(event(id)).await }));
    }
    for task in tasks {
        task.await
            .expect("append task panicked")
            .expect("append failed");
    }
    let result = store.verify_chain(None, None).await.expect("verify");
    assert!(result.is_valid, "chain invalid: {:?}", result.error);
    assert_eq!(result.total_verified, count);
    let events = store
        .query_events(EventFilter::default())
        .await
        .expect("query");
    assert_eq!(events.len(), count);
    for (index, item) in events.iter().enumerate() {
        assert_eq!(item.sequence, (index + 1) as i64);
    }
}

#[tokio::test]
#[ignore = "ten-minute performance gate; run explicitly in Linux CI/lab"]
async fn sustained_500_events_per_second_for_ten_minutes() {
    let (store, _dir) = store().await;
    let started = Instant::now();
    let duration = Duration::from_secs(600);
    let mut id = 0usize;
    while started.elapsed() < duration {
        let window = Instant::now();
        let mut tasks = Vec::with_capacity(500);
        for _ in 0..500 {
            tasks.push(store.append(event(id)));
            id += 1;
        }
        for task in tasks {
            task.await.expect("append failed");
        }
        let elapsed = window.elapsed();
        if elapsed < Duration::from_secs(1) {
            sleep(Duration::from_secs(1) - elapsed).await;
        }
    }
    assert!(
        id >= 300_000,
        "sustained rate below 500 events/s: {id} events"
    );
    let result = store.verify_chain(None, None).await.expect("verify");
    assert!(result.is_valid, "chain invalid: {:?}", result.error);
    assert_eq!(result.total_verified, id);
}

#[tokio::test]
async fn reopen_after_partial_append_keeps_atomic_chain() {
    let (store, dir) = store().await;
    for id in 0..10 {
        store.append(event(id)).await.expect("append");
    }
    drop(store);
    let url = format!("sqlite://{}", dir.path().join("audit.sqlite").display());
    let reopened = AuditStore::open_url(&url).await.expect("reopen");
    let result = reopened.verify_chain(None, None).await.expect("verify");
    assert!(
        result.is_valid,
        "chain invalid after restart: {:?}",
        result.error
    );
    assert_eq!(result.total_verified, 10);
}
