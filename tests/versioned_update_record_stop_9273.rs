// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9273 — the sqlite versioned-update funnel
//! (`db::update_with_expected_version`) keeps its #1955 record-stop gate
//! in the SAME fn span as its write SQL, and the gate runs BEFORE the
//! write transaction opens.
//!
//! - Behaviour: a stopped store refuses the versioned update with the
//!   exact `RecordStopped` text and zero rows changed.
//! - Order: with a second connection holding the write lock, a stopped
//!   store still refuses with `RecordStopped` (not a busy / lock error
//!   after the busy timeout), so the gate cannot have moved inside the
//!   transaction.
//! - Structure: in `src/storage/versioned_update_txn.rs` the gate call
//!   precedes `in_write_txn(` and the `UPDATE memories`, and the
//!   `storage/mod.rs` funnel delegates to that fn (the
//!   `qual_pg_record_stop_gate_parity_3175` ssot pair reads mod.rs only).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ai_memory::models::{Memory, Tier};
use ai_memory::storage::StorageError;
use ai_memory::storage::record_stop::{SCOPE_RECORD_PLANE, actuate_sqlite};
use serde_json::json;
use tempfile::NamedTempFile;

const NS: &str = "versioned-update-9273";
const OPERATOR: &str = "ai:operator";
const SEED_CONTENT: &str = "seed content";
const HOSTILE_CONTENT: &str = "write attempted under record-stop";
const SEED_VERSION: i64 = 1;
/// Exact `RecordStopped` Display text for the engage call below.
const STOPPED_TEXT: &str = "substrate record plane stopped by ai:operator (scope=record-plane); mutating operations refused until resume";
/// The gate is a read of the stop flag; it must answer well inside the
/// 5 s sqlite busy timeout a gate behind `BEGIN IMMEDIATE` would wait.
const GATE_BEFORE_LOCK_CEILING: Duration = Duration::from_secs(3);
const CHILD_SRC: &str = "src/storage/versioned_update_txn.rs";
const ROOT_SRC: &str = "src/storage/mod.rs";
const CHILD_FN: &str = "fn update_with_expected_version_in_txn(";
const ROOT_FN: &str = "pub fn update_with_expected_version(";
const GATE_CALL: &str = "gate_storage_conn(conn)?";
const TXN_CALL: &str = "in_write_txn(";
const WRITE_SQL: &str = "UPDATE memories";
const DELEGATE_CALL: &str = "versioned_update_txn::update_with_expected_version_in_txn(";

fn seed_memory() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: "versioned-update-9273".to_string(),
        content: SEED_CONTENT.to_string(),
        tags: vec!["r9273".to_string()],
        priority: 5,
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

fn assert_record_stopped(err: &anyhow::Error) {
    let se = err
        .downcast_ref::<StorageError>()
        .unwrap_or_else(|| panic!("typed StorageError in the anyhow chain, got {err:#}"));
    assert!(
        matches!(se, StorageError::RecordStopped { .. }),
        "versioned update must refuse with RecordStopped, got {se:?}"
    );
    assert_eq!(se.to_string(), STOPPED_TEXT, "exact RecordStopped text");
}

fn assert_row_unchanged(conn: &rusqlite::Connection, id: &str) {
    let (content, version): (String, i64) = conn
        .query_row(
            "SELECT content, version FROM memories WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read row");
    assert_eq!(
        content, SEED_CONTENT,
        "stopped update must not change content"
    );
    assert_eq!(
        version, SEED_VERSION,
        "stopped update must not bump version"
    );
}

#[test]
fn versioned_update_refuses_under_record_stop_9273() {
    let (conn, _f, id) = stopped_store_with_row();
    let changes_before = conn.total_changes();
    let err = versioned_update(&conn, &id).expect_err("stopped store must refuse");
    assert_record_stopped(&err);
    assert_eq!(
        conn.total_changes(),
        changes_before,
        "a refused versioned update changes zero rows"
    );
    assert_row_unchanged(&conn, &id);
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
        elapsed < GATE_BEFORE_LOCK_CEILING,
        "gate must answer before the write lock is requested; took {elapsed:?}"
    );
    assert_row_unchanged(&conn, &id);
}

fn read_src(rel: &str) -> String {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), rel].iter().collect();
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Body of the fn whose signature starts with `sig`: from the signature to
/// the first column-0 `}` line after it (both files keep the fn at column 0).
fn fn_span<'a>(src: &'a str, sig: &str) -> &'a str {
    let start = src
        .find(sig)
        .unwrap_or_else(|| panic!("signature {sig} present"));
    let rest = &src[start..];
    let end = rest.find("\n}\n").unwrap_or_else(|| panic!("end of {sig}"));
    &rest[..end]
}

fn offset(span: &str, needle: &str, what: &str) -> usize {
    span.find(needle)
        .unwrap_or_else(|| panic!("{what}: `{needle}` must appear in the fn span"))
}

#[test]
fn versioned_update_gate_precedes_txn_and_write_sql_in_one_span_9273() {
    let child = read_src(CHILD_SRC);
    let span = fn_span(&child, CHILD_FN);
    let gate = offset(span, GATE_CALL, CHILD_SRC);
    let txn = offset(span, TXN_CALL, CHILD_SRC);
    let write = offset(span, WRITE_SQL, CHILD_SRC);
    assert!(
        gate < txn,
        "{CHILD_SRC}: gate must run before the transaction opens"
    );
    assert!(
        gate < write,
        "{CHILD_SRC}: gate must run before the write SQL"
    );

    let root = read_src(ROOT_SRC);
    let root_span = fn_span(&root, ROOT_FN);
    offset(root_span, DELEGATE_CALL, ROOT_SRC);
    assert!(
        !root_span.contains(TXN_CALL),
        "{ROOT_SRC}: the funnel must not open the transaction ahead of the gated child"
    );
}
