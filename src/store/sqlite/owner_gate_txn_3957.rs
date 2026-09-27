// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3957 — the sqlite SAL ownership gate and the write it authorises must be
//! ONE transaction, so a SECOND OS PROCESS on the same database file cannot
//! commit an ownership change between the gate's read and the write.
//!
//! The in-process mutex (`SqliteStore::state`) is exactly the thing a second
//! process routes around, so these cells model the interloper as a SEPARATE
//! `rusqlite::Connection` on the same file, fired from the test-only hook
//! that sits between `assert_caller_owns_for_mutation` and the write. The
//! invariant pinned is the security property, not the mechanism: a row whose
//! owner changed to someone else must never receive a write authorised
//! against the previous owner. Before #3957 the interloper committed and the
//! caller's write landed on the other principal's row (RED); with the gate
//! and the write under one `BEGIN IMMEDIATE`, the interloper cannot take the
//! write lock and the row keeps its owner (GREEN).

use super::{OWNER_GATE_TEST_HOOK, SqliteStore};
use crate::models::{ConfidenceSource, Memory, Tier};
use crate::store::{CallerContext, MemoryStore, UpdatePatch};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const OWNER: &str = "alice-3957";
const INTERLOPER: &str = "mallory-3957";
const OWNER_EDIT: &str = "content written by the owner after the gate passed";
/// Short, so a blocked interloper fails fast instead of stalling the cell.
const INTERLOPER_BUSY_TIMEOUT: Duration = Duration::from_millis(100);

fn owned_memory(owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "owner-gate-3957".to_string(),
        title: format!("owner-gate-3957 {}", uuid::Uuid::new_v4()),
        content: "original content".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        reflection_depth: 0,
        memory_kind: crate::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    }
}

/// Arm the hook for `id`: when the gate has passed, a second connection on
/// the same file tries to hand the row to the interloper. Returns whether
/// that ownership change COMMITTED.
fn arm_interloper(path: std::path::PathBuf, id: &str) -> Arc<Mutex<Option<bool>>> {
    let committed = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&committed);
    let target = id.to_string();
    let hook: Box<dyn FnOnce() + Send> = Box::new(move || {
        let other = rusqlite::Connection::open(&path).expect("interloper connection");
        other
            .busy_timeout(INTERLOPER_BUSY_TIMEOUT)
            .expect("set the interloper busy timeout");
        let outcome = other.execute(
            "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', ?1) WHERE id = ?2",
            rusqlite::params![INTERLOPER, target],
        );
        *slot.lock().unwrap() = Some(matches!(outcome, Ok(1)));
    });
    OWNER_GATE_TEST_HOOK
        .lock()
        .unwrap()
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(id.to_string(), hook);
    committed
}

fn row_state(path: &std::path::Path, id: &str) -> Option<(String, String)> {
    let conn = rusqlite::Connection::open(path).expect("reader");
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_id'), content FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .ok()
}

#[tokio::test]
async fn update_cannot_land_on_a_row_whose_owner_changed_after_the_gate_3957() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("owner-gate-3957.db");
    let store = SqliteStore::open(&path).expect("open");
    let owner = OWNER;
    let ctx = CallerContext::for_agent(owner);
    let id = store.store(&ctx, &owned_memory(owner)).await.expect("seed");

    let interloper_committed = arm_interloper(path.clone(), &id);
    let patch = UpdatePatch {
        content: Some(OWNER_EDIT.to_string()),
        ..UpdatePatch::default()
    };
    let result = store.update(&ctx, &id, patch).await;

    let fired = *interloper_committed.lock().unwrap();
    assert!(
        fired.is_some(),
        "the interleave hook must have fired (non-vacuous)"
    );
    let (final_owner, final_content) = row_state(&path, &id).expect("row survives");
    assert!(
        !(final_owner == INTERLOPER && final_content == OWNER_EDIT),
        "#3957: the owner's write landed on a row now owned by {final_owner} — \
         authorised against a stale owner (interloper committed: {fired:?}, update: {result:?})"
    );
    // The mechanism, stated positively: the write lock was held from the
    // gate to the write, so the interloper could not commit, and the owner's
    // authorised edit applied to the owner's row.
    assert_eq!(fired, Some(false), "the interloper must be locked out");
    assert!(
        result.is_ok(),
        "the owner's update must succeed: {result:?}"
    );
    assert_eq!(final_owner, OWNER);
    assert_eq!(final_content, OWNER_EDIT);
}

#[tokio::test]
async fn delete_cannot_remove_a_row_whose_owner_changed_after_the_gate_3957() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("owner-gate-3957-delete.db");
    let store = SqliteStore::open(&path).expect("open");
    let owner = OWNER;
    let ctx = CallerContext::for_agent(owner);
    let id = store.store(&ctx, &owned_memory(owner)).await.expect("seed");

    let interloper_committed = arm_interloper(path.clone(), &id);
    let result = store.delete(&ctx, &id).await;

    let fired = *interloper_committed.lock().unwrap();
    assert!(
        fired.is_some(),
        "the interleave hook must have fired (non-vacuous)"
    );
    let after = row_state(&path, &id);
    assert!(
        !(fired == Some(true) && after.is_none()),
        "#3957: the owner deleted a row that another principal owned by then \
         (interloper committed, row gone, delete: {result:?})"
    );
    assert_eq!(fired, Some(false), "the interloper must be locked out");
    assert!(
        result.is_ok(),
        "the owner's delete must succeed: {result:?}"
    );
    assert!(after.is_none(), "the owner's own row is deleted");
}
