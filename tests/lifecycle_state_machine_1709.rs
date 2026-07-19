// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 2 (#1709) — `lifecycle_state` typed state machine
//! (schema v64) integration tests.
//!
//! Covers the LOAD-BEARING contract end-to-end against the sqlite store:
//!   * a stored memory defaults to `open` (the schema `DEFAULT 'open'`),
//!   * a fresh store can pin a non-default initial state,
//!   * an advanced lifecycle survives a re-store (sticky on upsert),
//!   * a row survives the v64 column add (probe-then-add round-trip),
//!   * the transition state machine enforces legal / illegal edges.

use ai_memory::db;
use ai_memory::models::{LifecycleState, Memory, MemoryKind, Tier};

fn fresh_conn() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(title: &str, state: LifecycleState) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: "lc-test".to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        tags: vec!["lifecycle".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Goal,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: state,
    }
}

#[test]
fn stored_memory_defaults_to_open() {
    let conn = fresh_conn();
    let mem = make_mem("default-open", LifecycleState::Open);
    let id = db::insert(&conn, &mem).expect("insert");
    let got = db::get(&conn, &id).expect("get").expect("row exists");
    assert_eq!(got.lifecycle_state, LifecycleState::Open);
}

#[test]
fn fresh_store_can_pin_active_state() {
    let conn = fresh_conn();
    let mem = make_mem("pin-active", LifecycleState::Active);
    let id = db::insert(&conn, &mem).expect("insert");
    let got = db::get(&conn, &id).expect("get").expect("row exists");
    assert_eq!(
        got.lifecycle_state,
        LifecycleState::Active,
        "a caller-set initial lifecycle_state must round-trip through the write path"
    );
}

#[test]
fn advanced_lifecycle_survives_restore_via_set_helper() {
    let conn = fresh_conn();
    let mem = make_mem("advance", LifecycleState::Open);
    let id = db::insert(&conn, &mem).expect("insert");
    // open -> active (legal) via the storage primitive.
    assert!(db::set_lifecycle_state(&conn, &id, LifecycleState::Active).expect("set active"));
    assert_eq!(
        db::get(&conn, &id).unwrap().unwrap().lifecycle_state,
        LifecycleState::Active
    );
    // A re-store of the SAME (title, namespace) must NOT reset the advanced
    // state back to the incoming `open` (sticky-preserve on upsert).
    let restore = make_mem("advance", LifecycleState::Open);
    db::insert(&conn, &restore).expect("re-store");
    assert_eq!(
        db::get(&conn, &id).unwrap().unwrap().lifecycle_state,
        LifecycleState::Active,
        "upsert must preserve the stored lifecycle_state, not reset to incoming open"
    );
}

#[test]
fn set_lifecycle_state_bumps_version() {
    let conn = fresh_conn();
    let mem = make_mem("bump", LifecycleState::Open);
    let id = db::insert(&conn, &mem).expect("insert");
    let v0 = db::get(&conn, &id).unwrap().unwrap().version;
    db::set_lifecycle_state(&conn, &id, LifecycleState::Active).expect("set");
    let v1 = db::get(&conn, &id).unwrap().unwrap().version;
    assert!(
        v1 > v0,
        "a lifecycle advance is a mutation; version must bump"
    );
}

#[test]
fn set_lifecycle_state_missing_row_returns_false() {
    let conn = fresh_conn();
    assert!(!db::set_lifecycle_state(&conn, "no-such-id", LifecycleState::Active).expect("set"));
}

#[test]
fn pre_existing_row_survives_v64_column_add() {
    // Simulate the v64 probe-then-add on a `memories` table that already
    // has a row but lacks the column, then assert the row survives and the
    // column reads back as the DEFAULT 'open'. This exercises the exact
    // ALTER the v64 migration arm emits (SQLite has no ADD COLUMN IF NOT
    // EXISTS, so the probe-then-add is the contract).
    let conn = rusqlite::Connection::open_in_memory().expect("open");
    conn.execute_batch(
        "CREATE TABLE memories (id TEXT PRIMARY KEY, title TEXT NOT NULL);
         INSERT INTO memories (id, title) VALUES ('legacy-1', 'pre-v64 row');",
    )
    .expect("seed legacy table");

    // Probe-then-add (the v64 recipe).
    let has_col = conn
        .prepare("SELECT lifecycle_state FROM memories LIMIT 0")
        .is_ok();
    assert!(!has_col, "column must be absent before the add");
    conn.execute(
        "ALTER TABLE memories ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'open'",
        [],
    )
    .expect("v64 ALTER");

    // Pre-existing row survives and defaults to 'open'.
    let (title, lc): (String, String) = conn
        .query_row(
            "SELECT title, lifecycle_state FROM memories WHERE id = 'legacy-1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("legacy row survives v64 add");
    assert_eq!(title, "pre-v64 row");
    assert_eq!(lc, "open");
    assert_eq!(LifecycleState::from_str(&lc), Some(LifecycleState::Open));

    // Idempotent: a second probe sees the column (no double-add).
    assert!(
        conn.prepare("SELECT lifecycle_state FROM memories LIMIT 0")
            .is_ok(),
        "column present after add"
    );
}

#[test]
fn set_lifecycle_state_rejects_illegal_transition() {
    // #1726 — the storage primitive now SELF-VALIDATES the edge. open → done
    // skips `active` and must be rejected with the typed InvalidTransition,
    // NOT silently written.
    let conn = fresh_conn();
    let mem = make_mem("illegal-skip", LifecycleState::Open);
    let id = db::insert(&conn, &mem).expect("insert");
    let err = db::set_lifecycle_state(&conn, &id, LifecycleState::Done)
        .expect_err("open -> done must be rejected");
    assert!(
        err.downcast_ref::<ai_memory::db::InvalidTransition>()
            .is_some(),
        "expected a typed InvalidTransition, got: {err}"
    );
    assert!(err.to_string().contains("illegal lifecycle transition"));
    // The row must be untouched (still open, version not bumped).
    let got = db::get(&conn, &id).unwrap().unwrap();
    assert_eq!(got.lifecycle_state, LifecycleState::Open);
    assert_eq!(
        got.version, mem.version,
        "rejected transition must not bump version"
    );
}

#[test]
fn set_lifecycle_state_rejects_move_out_of_terminal() {
    // #1726 — a terminal state accepts no outbound edge. Advance to done
    // (legal: open -> active -> done) then try done -> active.
    let conn = fresh_conn();
    let mem = make_mem("terminal-exit", LifecycleState::Open);
    let id = db::insert(&conn, &mem).expect("insert");
    db::set_lifecycle_state(&conn, &id, LifecycleState::Active).expect("open->active");
    db::set_lifecycle_state(&conn, &id, LifecycleState::Done).expect("active->done");
    let err = db::set_lifecycle_state(&conn, &id, LifecycleState::Active)
        .expect_err("done -> active must be rejected");
    assert!(
        err.downcast_ref::<ai_memory::db::InvalidTransition>()
            .is_some(),
        "expected a typed InvalidTransition, got: {err}"
    );
    assert_eq!(
        db::get(&conn, &id).unwrap().unwrap().lifecycle_state,
        LifecycleState::Done,
        "the row must remain in its terminal state"
    );
}

#[test]
fn set_lifecycle_state_noop_is_idempotent_ok() {
    // #1726 — a request equal to the stored state is a no-op success (NOT a
    // self-loop InvalidTransition) and must NOT bump the version.
    let conn = fresh_conn();
    let mem = make_mem("noop", LifecycleState::Open);
    let id = db::insert(&conn, &mem).expect("insert");
    let v0 = db::get(&conn, &id).unwrap().unwrap().version;
    assert!(
        db::set_lifecycle_state(&conn, &id, LifecycleState::Open).expect("noop ok"),
        "no-op transition returns Ok(true)"
    );
    let v1 = db::get(&conn, &id).unwrap().unwrap().version;
    assert_eq!(v1, v0, "a no-op lifecycle request must not bump version");
}

#[test]
fn transition_machine_legal_and_illegal_pairs() {
    use LifecycleState::{Abandoned, Active, Blocked, Done, Open};
    // Legal.
    assert!(Open.can_transition_to(Active));
    assert!(Active.can_transition_to(Done));
    assert!(Active.can_transition_to(Blocked));
    assert!(Blocked.can_transition_to(Active));
    // Illegal: skipping / terminal / self-loop.
    assert!(!Open.can_transition_to(Done));
    assert!(!Done.can_transition_to(Active));
    assert!(!Abandoned.can_transition_to(Active));
    assert!(!Active.can_transition_to(Active));
    assert!(Done.is_terminal() && Abandoned.is_terminal());
}
