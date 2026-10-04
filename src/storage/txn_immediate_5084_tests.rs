// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5084 (the #2250 class) — a production writer that READS and then WRITES
//! must open `BEGIN IMMEDIATE`. Under WAL a DEFERRED transaction that has read
//! and then upgrades to a write fails at once with `SQLITE_BUSY_SNAPSHOT` when
//! another connection committed in between; `busy_timeout` does not retry it.
//!
//! Determinism: no sleeps. The harness arms a `trace` callback on the function
//! under test's connection. The callback fires as the FIRST write statement of
//! the function begins to run, i.e. after its read has established the
//! snapshot and before its write takes the lock. At that exact point a second
//! connection (`B`) tries to commit a row.
//!
//! * DEFERRED (base): `B` commits, the function's lock upgrade then fails with
//!   `SQLITE_BUSY_SNAPSHOT` (extended code 517).
//! * IMMEDIATE (tip): the function already holds the write lock from `BEGIN`,
//!   so `B` is refused (busy) and the function succeeds.
//!
//! Each test asserts the tip outcome AND that `B` was excluded, so a function
//! that regresses to DEFERRED fails on both counts.

use super::*;
use crate::models::{Memory, Tier};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

thread_local! {
    static HOOK_5084: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

fn is_write_statement(sql: &str) -> bool {
    let s = sql.trim_start();
    ["UPDATE", "INSERT", "DELETE", "REPLACE"]
        .iter()
        .any(|p| s.starts_with(p))
}

fn trace_cb_5084(sql: &str) {
    if is_write_statement(sql) {
        if let Some(hook) = HOOK_5084.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
}

fn memory_5084(title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "txn-5084".to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    }
}

/// Arm the interleaving on `conn_a` (the connection the function under test
/// runs on). Returns a cell that is `true` iff the second connection managed to
/// commit its row during the function's read-then-write window.
pub(crate) fn arm_interleaved_writer_5084(
    conn_a: &mut Connection,
    path: &std::path::Path,
) -> Rc<Cell<bool>> {
    let committed = Rc::new(Cell::new(false));
    let flag = Rc::clone(&committed);
    let path = path.to_path_buf();
    HOOK_5084.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            let Ok(b) = open(&path) else { return };
            // A short timeout: on the fixed tip the function holds the write
            // lock, so B must be refused rather than wait out the default.
            if b.busy_timeout(Duration::from_millis(150)).is_err() {
                return;
            }
            flag.set(insert(&b, &memory_5084("interleaved-writer-5084")).is_ok());
        }));
    });
    conn_a.trace(Some(trace_cb_5084));
    committed
}

/// Disarm: remove the trace callback and any hook that never fired.
pub(crate) fn disarm_5084(conn_a: &mut Connection) {
    conn_a.trace(None);
    HOOK_5084.with(|h| h.borrow_mut().take());
}

/// Run `f` on a fresh file-backed connection with the interleaver armed.
/// `seed` prepares the database (and returns fixture ids) on a separate,
/// already-closed connection.
fn run_race<S, T>(
    seed: impl FnOnce(&Connection) -> S,
    f: impl FnOnce(&mut Connection, &S) -> Result<T>,
) -> (Result<T>, bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("race-5084.db");
    let fixture = {
        let conn = open(&path).expect("seed open");
        seed(&conn)
    };
    let mut a = open(&path).expect("open A");
    let committed = arm_interleaved_writer_5084(&mut a, &path);
    let out = f(&mut a, &fixture);
    disarm_5084(&mut a);
    (out, committed.get())
}

fn assert_immediate<T: std::fmt::Debug>(label: &str, out: &Result<T>, b_committed: bool) {
    assert!(
        out.is_ok(),
        "#5084 {label}: a read-then-write must open BEGIN IMMEDIATE and not fail the lock \
         upgrade (base returns SQLITE_BUSY_SNAPSHOT): {out:?}"
    );
    assert!(
        !b_committed,
        "#5084 {label}: the writer must hold the write lock from BEGIN, so a concurrent \
         writer cannot commit inside its read-then-write window"
    );
}

#[test]
fn stamp_contaminated_descendants_as_is_immediate_5084() {
    let (out, b_committed) = run_race(
        |conn| {
            let root = insert(conn, &memory_5084("root")).expect("root");
            let child = insert(conn, &memory_5084("child")).expect("child");
            create_link(conn, &child, &root, "derived_from").expect("link");
            assert!(
                !lineage_descendants(conn, &root, 3)
                    .expect("descendants")
                    .is_empty(),
                "fixture must give the root a descendant so the sweep reads then writes"
            );
            root
        },
        |a, root| stamp_contaminated_descendants_as(a, root, 3, StampAuthority::Admin),
    );
    assert_immediate("stamp_contaminated_descendants_as", &out, b_committed);
    assert_eq!(out.expect("report").stamped, 1);
}

#[test]
fn rekey_peer_is_immediate_5084() {
    const RAW: &str = "https://alice:s3cr3t@peer.example:9077/mesh?token=qpw";
    const RENDERED: &str = "https://peer.example:9077/mesh";
    let (out, b_committed) = run_race(
        |conn| {
            sync_state_observe(conn, "me", RAW, "2026-09-01T00:00:00Z").expect("observe");
        },
        |a, ()| sync_state_rekey::rekey_peer(a, "me", RAW, RENDERED),
    );
    assert_immediate("rekey_peer", &out, b_committed);
    assert!(out.expect("moved"), "the raw row must have been folded");
}

#[test]
fn set_embeddings_batch_is_immediate_5084() {
    let space = crate::embeddings::embedding_space_fingerprint("test-space");
    let (out, b_committed) = run_race(
        |conn| insert(conn, &memory_5084("embed")).expect("memory"),
        |a, id| set_embeddings_batch(a, &[(id.clone(), vec![0.5_f32; 4])], &space),
    );
    assert_immediate("set_embeddings_batch", &out, b_committed);
    assert_eq!(out.expect("written"), 1);
}

#[test]
fn set_embeddings_batch_reembed_is_immediate_5084() {
    let space = crate::embeddings::embedding_space_fingerprint("test-space");
    let (out, b_committed) = run_race(
        |conn| insert(conn, &memory_5084("reembed")).expect("memory"),
        |a, id| set_embeddings_batch_reembed(a, &[(id.clone(), vec![0.5_f32; 4])], &space),
    );
    assert_immediate("set_embeddings_batch_reembed", &out, b_committed);
    assert_eq!(out.expect("written"), 1);
}
