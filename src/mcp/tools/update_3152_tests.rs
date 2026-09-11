// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3152 — MCP `memory_update` applies the content patch and the
//! lifecycle transition in ONE transaction. Before #3152 the patch committed
//! first, so an illegal edge returned an error while the patch — and the
//! storage-growth charge for it — stayed persisted.
//!
//! Every test here runs its body in a child of the test binary started from
//! a CLEAN environment. `handle_update` consults `AI_MEMORY_AGENT_ID` (the
//! caller-owns gate fires only when it is set), and a child is the one place
//! that variable is provably unset without writing this process's
//! environment, which every concurrently running test in the lib binary
//! shares (#3523).

#![cfg(test)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::json;

use super::handle_update;
use crate::models::{LifecycleState, Memory};
use crate::recover::in_tx_fault;
use crate::recover::in_tx_fault::{
    CHILD_DB_ENV, CHILD_ID_ENV, CHILD_MARKER_ENV, child_role_is, child_var,
};
use crate::storage as db;

const OWNER: &str = "ai:mcp-atomicity-3152";
const NAMESPACE: &str = "mcp-atomicity-3152";
const ORIGINAL_CONTENT: &str = "mcp atomicity 3152 original body";
const PATCHED_CONTENT: &str = "patched body";
/// This module's path inside the lib test binary, for `--exact` filters.
#[cfg(unix)]
const MODULE_PATH: &str = "mcp::update::update_3152_tests";
/// The role the re-executed crash child plays.
const ROLE_MCP_UPDATE: &str = "mcp-update";

fn fixture() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: NAMESPACE.to_string(),
        title: "mcp atomicity 3152".to_string(),
        content: ORIGINAL_CONTENT.to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": OWNER }),
        ..Memory::default()
    }
}

fn storage_bytes(conn: &rusqlite::Connection) -> i64 {
    crate::quotas::get_status(conn, OWNER, NAMESPACE)
        .expect("quota status")
        .current_storage_bytes
}

/// Run `body` in a clean-environment child executing `test` (this module's
/// test of that name), then require the child to have passed AND to have
/// actually run `body`: a filter that matched nothing exits 0 too, so the
/// child writes a done-marker only after `body` returns.
fn in_clean_child(test: &str, body: fn()) {
    if child_role_is(test) {
        body();
        std::fs::write(child_var(CHILD_MARKER_ENV), test).expect("write the #3152 done marker");
        return;
    }
    #[cfg(unix)]
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("done-3152");
        let out = crate::test_support::spawn_test_child(
            &format!("{MODULE_PATH}::{test}"),
            &[
                (in_tx_fault::CHILD_ROLE_ENV, test),
                (CHILD_MARKER_ENV, &marker.to_string_lossy()),
            ],
        );
        let detail = format!(
            "status={:?}\nstdout={}\nstderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "the {test} child failed: {detail}");
        assert_eq!(
            std::fs::read_to_string(&marker).ok().as_deref(),
            Some(test),
            "the child must have run {test}: {detail}"
        );
    }
    // No re-exec helper off unix (and no CI runner either): run in-process.
    #[cfg(not(unix))]
    body();
}

/// An illegal edge refuses the whole update: the patch rolls back, and the
/// FBL-12 growth charge is refunded because the bytes never landed.
#[test]
fn mcp_illegal_edge_rolls_the_patch_back_and_refunds_the_growth_3152() {
    in_clean_child(
        "mcp_illegal_edge_rolls_the_patch_back_and_refunds_the_growth_3152",
        illegal_edge_body,
    );
}

fn illegal_edge_body() {
    let conn = db::open(std::path::Path::new(":memory:")).expect("open");
    let id = db::insert(&conn, &fixture()).expect("insert");
    let before = storage_bytes(&conn);

    let err = handle_update(
        &conn,
        &json!({ "id": id, "content": "x".repeat(20_000), "lifecycle_state": "done" }),
        None,
        None,
        None,
    )
    .expect_err("open -> done must refuse the whole update");
    assert!(err.contains("illegal lifecycle transition"), "got: {err}");

    let row = db::get(&conn, &id).expect("read").expect("row");
    assert_eq!(row.content, ORIGINAL_CONTENT, "the patch must roll back");
    assert_eq!(row.lifecycle_state, LifecycleState::Open);
    assert_eq!(row.version, 1, "no version bump may survive the refusal");
    let snapshots: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            [&id],
            |r| r.get(0),
        )
        .expect("count snapshots");
    assert_eq!(snapshots, 0, "the in_place_edit snapshot rolls back too");
    assert_eq!(
        storage_bytes(&conn),
        before,
        "the growth charge must be refunded for bytes that never landed"
    );

    // Control: the same growth on a LEGAL edge is charged to OWNER, so the
    // equality above is a refund, not a charge that never happened.
    handle_update(
        &conn,
        &json!({ "id": id, "content": "x".repeat(20_000), "lifecycle_state": "active" }),
        None,
        None,
        None,
    )
    .expect("open -> active is legal");
    assert!(
        storage_bytes(&conn) > before,
        "a landed growth patch must be charged to the row owner"
    );
}

/// At the fault point the patch has executed but a second connection still
/// reads the original row.
#[test]
fn mcp_patch_is_uncommitted_at_the_fault_point_3152() {
    in_clean_child(
        "mcp_patch_is_uncommitted_at_the_fault_point_3152",
        uncommitted_at_fault_point_body,
    );
}

fn uncommitted_at_fault_point_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp-atomicity-3152.db");
    let conn = db::open(&path).expect("open");
    let id = db::insert(&conn, &fixture()).expect("insert");

    let seen: Arc<Mutex<Option<Memory>>> = Arc::new(Mutex::new(None));
    let (seen_in, path_in, id_in) = (Arc::clone(&seen), path.clone(), id.clone());
    in_tx_fault::arm(
        &id,
        in_tx_fault::Action::Observe(Box::new(move || {
            let reader = db::open_read_only(&path_in).expect("open read-only");
            let row = db::get(&reader, &id_in).expect("read").expect("row");
            *seen_in.lock().unwrap_or_else(PoisonError::into_inner) = Some(row);
        })),
    );
    let res = handle_update(
        &conn,
        &json!({ "id": id, "content": PATCHED_CONTENT, "lifecycle_state": "active" }),
        None,
        None,
        None,
    );
    in_tx_fault::disarm(&id);
    res.expect("open -> active is legal");

    let observed = seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .expect("the fault point must be reached between patch and transition");
    assert_eq!(
        observed.content, ORIGINAL_CONTENT,
        "nothing is committed yet"
    );
    assert_eq!(observed.lifecycle_state, LifecycleState::Open);
    let row = db::get(&conn, &id).expect("read").expect("row");
    assert_eq!(row.content, PATCHED_CONTENT);
    assert_eq!(row.lifecycle_state, LifecycleState::Active);
}

/// Child half of the MCP crash test: a no-op unless re-executed. It also
/// makes the default build construct [`in_tx_fault::Action::Abort`]: the
/// store crash tests only compile under `--features sal`.
#[test]
fn mcp_crash_child_3152() {
    if !child_role_is(ROLE_MCP_UPDATE) {
        return;
    }
    let path = PathBuf::from(child_var(CHILD_DB_ENV));
    let id = child_var(CHILD_ID_ENV);
    let conn = db::open(&path).expect("child open");
    in_tx_fault::arm(
        &id,
        in_tx_fault::Action::Abort {
            marker: PathBuf::from(child_var(CHILD_MARKER_ENV)),
        },
    );
    let res = handle_update(
        &conn,
        &json!({ "id": id, "content": PATCHED_CONTENT, "lifecycle_state": "active" }),
        None,
        None,
        None,
    );
    panic!("the #3152 fault point was never reached; update returned {res:?}");
}

/// A crash between the patch and the transition leaves the row exactly as
/// it was: the child aborts inside the one uncommitted transaction.
#[cfg(unix)]
#[test]
fn mcp_crash_between_patch_and_transition_leaves_row_unchanged_3152() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp-atomicity-3152-crash.db");
    let id = {
        let conn = db::open(&path).expect("open");
        db::insert(&conn, &fixture()).expect("insert")
    };
    let marker = dir.path().join("reached-3152");

    let out = crate::test_support::spawn_test_child(
        &format!("{MODULE_PATH}::mcp_crash_child_3152"),
        &[
            (in_tx_fault::CHILD_ROLE_ENV, ROLE_MCP_UPDATE),
            (CHILD_DB_ENV, &path.to_string_lossy()),
            (CHILD_ID_ENV, &id),
            (CHILD_MARKER_ENV, &marker.to_string_lossy()),
        ],
    );
    in_tx_fault::assert_aborted_at_fault_point(&out, &marker, &id);

    let conn = db::open(&path).expect("reopen");
    let row = db::get(&conn, &id).expect("read").expect("row");
    assert_eq!(row.content, ORIGINAL_CONTENT, "the patch must not survive");
    assert_eq!(row.lifecycle_state, LifecycleState::Open);
    assert_eq!(row.version, 1, "no version bump may survive the crash");
    assert!(
        crate::recover::durability::integrity_ok(&conn).expect("integrity check"),
        "the database must be sound after the crash"
    );
}
