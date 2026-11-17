// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9273 — the sqlite versioned-update funnel
//! (`db::update_with_expected_version`) refuses under the #1955
//! record-stop, refuses on an unreadable stop state, leaves a
//! caller-held transaction open, and runs its gate before the write lock
//! is requested. The structural shape check of the gate (same fn span as
//! the write SQL) is not pinned in this file and is tracked under #9414.
//!
//! - Behaviour: a stopped store refuses the versioned update with the
//!   exact `RecordStopped` text, zero rows changed and no transaction left
//!   open; an unreadable stop state refuses with the exact
//!   `RecordStopIndeterminate` text the same way.
//! - Caller-held transaction (the synthesis merge shape): the refusal
//!   leaves the caller's transaction open, neither committed nor rolled
//!   back; the caller's rollback leaves the row and its version unchanged.
//! - Order: with a second connection holding the write lock, a stopped
//!   store still refuses with `RecordStopped` (not a busy / lock error
//!   after the busy timeout), so the gate cannot have moved inside the
//!   transaction.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ai_memory::models::{Memory, Tier};
use ai_memory::storage::StorageError;
use ai_memory::storage::record_stop::{SCOPE_RECORD_PLANE, actuate_sqlite};
use rusqlite::{OpenFlags, params};
use serde_json::json;
use tempfile::{NamedTempFile, TempDir};

const NS: &str = "versioned-update-9273";
const OPERATOR: &str = "ai:operator";
const SEED_CONTENT: &str = "seed content";
const HOSTILE_CONTENT: &str = "write attempted under record-stop";
const SEED_VERSION: i64 = 1;
const SEED_PRIORITY: i64 = 5;
/// Priority the caller writes inside its own transaction before the call.
const CALLER_PRIORITY: i64 = 9;
/// Exact `RecordStopped` Display text for the engage call below.
const STOPPED_TEXT: &str = "substrate record plane stopped by ai:operator (scope=record-plane); mutating operations refused until resume";
/// Exact `RecordStopIndeterminate` Display text when `signed_events` cannot
/// be read (the reason is the outer context of `read_state_sqlite`).
const INDETERMINATE_TEXT: &str = "substrate record-stop state could not be read (fail-closed; mutating operation refused, retry): record_stop::read_state_sqlite";
/// The caller's own error, returned to roll its transaction back.
const CALLER_ROLLBACK: &str = "caller rolls its transaction back after the refusal (9273)";
/// Name `signed_events` is moved to so the stop state cannot be read.
const UNREADABLE_CHAIN_TABLE: &str = "signed_events_unreadable_9273";
/// The gate is a read of the stop flag; it must answer well inside the
/// 5 s sqlite busy timeout a gate behind `BEGIN IMMEDIATE` would wait.
const GATE_BEFORE_LOCK_CEILING: Duration = Duration::from_secs(3);

fn seed_memory() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: "versioned-update-9273".to_string(),
        content: SEED_CONTENT.to_string(),
        tags: vec!["r9273".to_string()],
        priority: i32::try_from(SEED_PRIORITY).expect("seed priority fits i32"),
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": OPERATOR}),
        version: SEED_VERSION,
        ..Memory::default()
    }
}

/// Fresh file store with one seeded row, then the record-stop engaged.
fn stopped_store_with_row() -> (rusqlite::Connection, NamedTempFile, String) {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("open");
    let id = ai_memory::db::insert(&conn, &seed_memory()).expect("seed row");
    assert!(
        actuate_sqlite(&conn, true, OPERATOR, SCOPE_RECORD_PLANE).expect("engage record-stop"),
        "first engage must report a state change"
    );
    (conn, f, id)
}

/// A store at a path this process never gated, whose `signed_events`
/// table is moved away so the record-stop state cannot be read. The row is
/// seeded through a first store and copied with `VACUUM INTO`, so the copy's
/// path has no cached stop flag and the gate's first touch reads the chain.
fn unreadable_stop_store_with_row() -> (rusqlite::Connection, TempDir, PathBuf, String) {
    let dir = TempDir::new().expect("tempdir");
    let seed_path = dir.path().join("seed-9273.db");
    let copy_path = dir.path().join("unreadable-stop-9273.db");
    let seed = ai_memory::db::open(&seed_path).expect("open seed store");
    let id = ai_memory::db::insert(&seed, &seed_memory()).expect("seed row");
    seed.execute(
        "VACUUM INTO ?1",
        params![copy_path.to_str().expect("utf-8 path")],
    )
    .expect("copy the seeded store");
    drop(seed);
    let conn = ai_memory::db::open(&copy_path).expect("open the copy");
    conn.execute_batch(&format!(
        "ALTER TABLE signed_events RENAME TO {UNREADABLE_CHAIN_TABLE}"
    ))
    .expect("move the record-stop chain away");
    (conn, dir, copy_path, id)
}

fn versioned_update(conn: &rusqlite::Connection, id: &str) -> anyhow::Result<(bool, bool)> {
    ai_memory::db::update_with_expected_version(
        conn,
        id,
        None,
        Some(HOSTILE_CONTENT),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(SEED_VERSION),
        None,
    )
}

fn storage_error(err: &anyhow::Error) -> &StorageError {
    err.downcast_ref::<StorageError>()
        .unwrap_or_else(|| panic!("typed StorageError in the anyhow chain, got {err:#}"))
}

fn assert_record_stopped(err: &anyhow::Error) {
    let se = storage_error(err);
    assert!(
        matches!(se, StorageError::RecordStopped { .. }),
        "versioned update must refuse with RecordStopped, got {se:?}"
    );
    assert_eq!(se.to_string(), STOPPED_TEXT, "exact RecordStopped text");
}

fn assert_record_stop_indeterminate(err: &anyhow::Error) {
    let se = storage_error(err);
    assert!(
        matches!(se, StorageError::RecordStopIndeterminate { .. }),
        "an unreadable stop state must refuse with RecordStopIndeterminate, got {se:?}"
    );
    assert_eq!(
        se.to_string(),
        INDETERMINATE_TEXT,
        "exact RecordStopIndeterminate text"
    );
}

/// `(content, version, priority)` of the row.
fn row_state(conn: &rusqlite::Connection, id: &str) -> (String, i64, i64) {
    conn.query_row(
        "SELECT content, version, priority FROM memories WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .expect("read row")
}

fn assert_row_unchanged(conn: &rusqlite::Connection, id: &str) {
    let (content, version, priority) = row_state(conn, id);
    assert_eq!(
        content, SEED_CONTENT,
        "stopped update must not change content"
    );
    assert_eq!(
        version, SEED_VERSION,
        "stopped update must not bump version"
    );
    assert_eq!(priority, SEED_PRIORITY, "the row's priority is the seed");
}

fn assert_refused_in_autocommit(conn: &rusqlite::Connection, id: &str, check: fn(&anyhow::Error)) {
    assert!(conn.is_autocommit(), "no transaction before the call");
    let changes_before = conn.total_changes();
    let err = versioned_update(conn, id).expect_err("the gate must refuse");
    check(&err);
    assert!(
        conn.is_autocommit(),
        "a refusal must leave no transaction open on the connection"
    );
    assert_eq!(
        conn.total_changes(),
        changes_before,
        "a refused versioned update changes zero rows"
    );
    assert_row_unchanged(conn, id);
}

/// The synthesis merge shape: the caller holds a write transaction (and has
/// written in it) when it calls the update. The refusal must neither commit
/// nor roll back the caller's transaction; the caller's rollback then leaves
/// the row and its version unchanged.
fn assert_refused_inside_caller_txn(
    conn: &rusqlite::Connection,
    path: &Path,
    id: &str,
    check: fn(&anyhow::Error),
) {
    let out: anyhow::Result<()> = ai_memory::db::in_write_txn(conn, || {
        assert!(
            !conn.is_autocommit(),
            "the caller holds a write transaction"
        );
        conn.execute(
            "UPDATE memories SET priority = ?1 WHERE id = ?2",
            params![CALLER_PRIORITY, id],
        )?;
        let err = versioned_update(conn, id).expect_err("the gate must refuse");
        check(&err);
        assert!(
            !conn.is_autocommit(),
            "the refusal must leave the caller's transaction open"
        );
        assert_eq!(
            row_state(conn, id).2,
            CALLER_PRIORITY,
            "the caller's own write survives the refusal: nothing was rolled back"
        );
        let reader = rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert_eq!(
            row_state(&reader, id).2,
            SEED_PRIORITY,
            "nothing was committed: a second connection still reads the seed row"
        );
        Err(anyhow::anyhow!(CALLER_ROLLBACK))
    });
    let err = out.expect_err("the caller rolls back");
    assert_eq!(err.to_string(), CALLER_ROLLBACK, "the caller's own error");
    assert!(
        conn.is_autocommit(),
        "the caller's rollback ends its transaction"
    );
    assert_row_unchanged(conn, id);
}

#[test]
fn versioned_update_refuses_under_record_stop_9273() {
    let (conn, _f, id) = stopped_store_with_row();
    assert_refused_in_autocommit(&conn, &id, assert_record_stopped);
}

#[test]
fn versioned_update_refusal_keeps_caller_txn_open_9273() {
    let (conn, f, id) = stopped_store_with_row();
    assert_refused_inside_caller_txn(&conn, f.path(), &id, assert_record_stopped);
}

#[test]
fn versioned_update_refuses_on_unreadable_stop_state_9273() {
    let (conn, _dir, _path, id) = unreadable_stop_store_with_row();
    assert_refused_in_autocommit(&conn, &id, assert_record_stop_indeterminate);
    // The error path caches nothing, so the caller-held shape re-probes and
    // refuses the same way.
    let (conn, _dir, path, id) = unreadable_stop_store_with_row();
    assert_refused_inside_caller_txn(&conn, &path, &id, assert_record_stop_indeterminate);
}

#[test]
fn versioned_update_gate_runs_before_write_lock_9273() {
    let (conn, f, id) = stopped_store_with_row();
    let holder = ai_memory::db::open(f.path()).expect("open lock holder");
    holder
        .execute_batch("BEGIN IMMEDIATE")
        .expect("holder takes the write lock");
    let started = Instant::now();
    let result = versioned_update(&conn, &id);
    let elapsed = started.elapsed();
    holder.execute_batch("ROLLBACK").expect("holder releases");
    let err = result.expect_err("stopped store must refuse while the lock is held");
    assert_record_stopped(&err);
    assert!(
        conn.is_autocommit(),
        "a refusal must leave no transaction open on the connection"
    );
    assert!(
        elapsed < GATE_BEFORE_LOCK_CEILING,
        "gate must answer before the write lock is requested; took {elapsed:?}"
    );
    assert_row_unchanged(&conn, &id);
}
