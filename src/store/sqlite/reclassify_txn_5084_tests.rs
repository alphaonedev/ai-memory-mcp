// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5084 (the #2250 class) — `reclassify_memory_kind` reads the current kind,
//! then writes the new kind and appends a signed event. It must open
//! `BEGIN IMMEDIATE`: a DEFERRED read-then-write fails the lock upgrade with
//! `SQLITE_BUSY_SNAPSHOT` (not retried by `busy_timeout`) when a second
//! connection commits between the read and the write. The interloper is fired
//! from a `trace` callback armed on the store's own connection, so the window
//! is hit deterministically (no sleeps); see
//! `crate::storage::txn_immediate_5084_tests` for the harness.

use super::SqliteStore;
use crate::models::{Memory, MemoryKind, Tier};
use crate::storage::txn_immediate_5084_tests::{arm_interleaved_writer_5084, disarm_5084};
use crate::store::{CallerContext, MemoryStore};

fn memory(kind: MemoryKind) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "reclassify-5084".to_string(),
        title: format!("reclassify-5084 {}", uuid::Uuid::new_v4()),
        content: "body".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        memory_kind: kind,
        ..Memory::default()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reclassify_memory_kind_is_immediate_5084() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reclassify-5084.db");
    let store = SqliteStore::open(&path).expect("open store");
    let id = {
        let conn = store.state.lock().await;
        crate::storage::insert(&conn, &memory(MemoryKind::Observation)).expect("seed memory")
    };
    let committed = {
        let mut conn = store.state.lock().await;
        arm_interleaved_writer_5084(&mut conn, &path)
    };
    let ctx = CallerContext::for_admin("ai:reclassify-5084");
    let out = store
        .reclassify_memory_kind(&ctx, &id, MemoryKind::Decision)
        .await;
    {
        let mut conn = store.state.lock().await;
        disarm_5084(&mut conn);
    }
    assert!(
        matches!(out, Ok(true)),
        "#5084: reclassify_memory_kind must open BEGIN IMMEDIATE and not fail the lock \
         upgrade (base returns SQLITE_BUSY_SNAPSHOT): {out:?}"
    );
    assert!(
        !committed.get(),
        "#5084: a concurrent writer must not commit inside the read-then-write window"
    );
    let events: i64 = {
        let conn = store.state.lock().await;
        conn.query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'memory.reclassified'",
            [],
            |r| r.get(0),
        )
        .expect("count events")
    };
    assert_eq!(
        events, 1,
        "the signed event lands atomically with the write"
    );
}
