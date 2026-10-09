// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4147 — MCP `memory_update` and `memory_delete` must run the ownership
//! gate and the write it authorises in ONE `BEGIN IMMEDIATE`, so a SECOND OS
//! PROCESS on the same database file cannot commit an ownership change
//! between the gate's read and the write (the #3957 property, on the two
//! MCP funnels that bypass the SAL trait).
//!
//! The MCP owner gate is keyed on `AI_MEMORY_AGENT_ID` (the multi-tenant
//! opt-in), so each cell runs its body in a CLEAN CHILD of the test binary
//! (the #3152 shape) whose `Command` carries that variable — this process's
//! shared environment is never written. The interloper is a separate
//! `rusqlite::Connection` on the same file, fired from the
//! `in_tx_fault::owner_gate_passed` point; the child reports whether that
//! re-own COMMITTED (RED: yes — the owner's write then lands on mallory's
//! row, or erases it) plus the row's final owner, and the parent asserts.

#![cfg(test)]

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::json;

use super::handle_update;
use crate::mcp::delete::handle_delete;
use crate::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use crate::recover::in_tx_fault;
use crate::recover::in_tx_fault::{
    CHILD_DB_ENV, CHILD_ID_ENV, CHILD_MARKER_ENV, CHILD_ROLE_ENV, child_role_is, child_var,
};
use crate::storage as db;

const OWNER: &str = "ai:alice-mcp-4147";
const INTERLOPER: &str = "ai:mallory-mcp-4147";
const OWNER_EDIT: &str = "content written by the owner after the gate passed";
const INTERLOPER_BUSY_TIMEOUT: Duration = Duration::from_millis(100);
/// This module's path inside the lib test binary, for `--exact` filters.
#[cfg(unix)]
const MODULE_PATH: &str = "mcp::update::owner_gate_txn_4147_tests";
const ROLE_UPDATE: &str = "mcp-owner-gate-update-4147";
const ROLE_DELETE: &str = "mcp-owner-gate-delete-4147";

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("owner-gate-txn-4147-mcp-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("tempdir under .local-runs")
}

fn owned_memory() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "owner-gate-mcp-4147".to_string(),
        title: format!("owner-gate-mcp-4147 {}", uuid::Uuid::new_v4()),
        content: "original content".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": OWNER }),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// Arm the point for `id` (in the CHILD): a second connection tries to hand
/// the row to the interloper. Returns whether that re-own COMMITTED.
fn arm_interloper(path: std::path::PathBuf, id: &str) -> Arc<Mutex<Option<bool>>> {
    let committed = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&committed);
    let target = id.to_string();
    in_tx_fault::arm_owner_gate(
        id,
        Box::new(move || {
            let other = rusqlite::Connection::open(&path).expect("interloper connection");
            other
                .busy_timeout(INTERLOPER_BUSY_TIMEOUT)
                .expect("set the interloper busy timeout");
            let outcome = other.execute(
                "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', ?1) WHERE id = ?2",
                rusqlite::params![INTERLOPER, target],
            );
            *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome.is_ok());
        }),
    );
    committed
}

fn owner_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_id') FROM memories WHERE id = ?1",
        [id],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .expect("owner read")
}

fn content_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    use rusqlite::OptionalExtension as _;
    conn.query_row("SELECT content FROM memories WHERE id = ?1", [id], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .expect("content read")
}

/// The child's report: `committed=<bool>;result=<ok|err:text>`.
fn report(committed: Option<bool>, result: &Result<serde_json::Value, String>) -> String {
    let outcome = match result {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("err:{e}"),
    };
    format!("committed={committed:?};result={outcome}")
}

/// Spawn the child for `role` against a fresh db holding one owned row;
/// returns `(db path, id, child report)`.
#[cfg(unix)]
fn run_child(role: &str, test: &str) -> (std::path::PathBuf, String, String) {
    let dir = scratch();
    let path = dir.path().join("mcp-owner-gate-4147.db");
    let id = {
        let conn = db::open(&path).expect("open");
        db::insert(&conn, &owned_memory()).expect("insert")
    };
    let marker = dir.path().join("report-4147");
    let out = crate::test_support::spawn_test_child(
        &format!("{MODULE_PATH}::{test}"),
        &[
            (CHILD_ROLE_ENV, role),
            (CHILD_DB_ENV, &path.to_string_lossy()),
            (CHILD_ID_ENV, &id),
            (CHILD_MARKER_ENV, &marker.to_string_lossy()),
            // The multi-tenant opt-in: the MCP owner gate fires for alice.
            ("AI_MEMORY_AGENT_ID", OWNER),
        ],
    );
    let detail = format!(
        "status={:?}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "the #4147 child failed: {detail}");
    let report = std::fs::read_to_string(&marker)
        .unwrap_or_else(|e| panic!("the #4147 child wrote no report ({e}): {detail}"));
    std::mem::forget(dir);
    (path, id, report)
}

/// CHILD body — runs only when re-executed with the update role.
#[test]
fn mcp_update_owner_gate_child_4147() {
    if !child_role_is(ROLE_UPDATE) {
        return;
    }
    let path = std::path::PathBuf::from(child_var(CHILD_DB_ENV));
    let id = child_var(CHILD_ID_ENV);
    let conn = db::open(&path).expect("open");
    let committed = arm_interloper(path, &id);
    let res = handle_update(
        &conn,
        &json!({ "id": id, "content": OWNER_EDIT }),
        None,
        None,
        None,
    );
    in_tx_fault::disarm_owner_gate(&id);
    let fired = *committed.lock().unwrap_or_else(PoisonError::into_inner);
    std::fs::write(child_var(CHILD_MARKER_ENV), report(fired, &res)).expect("write report");
}

/// CHILD body — runs only when re-executed with the delete role.
#[test]
fn mcp_delete_owner_gate_child_4147() {
    if !child_role_is(ROLE_DELETE) {
        return;
    }
    let path = std::path::PathBuf::from(child_var(CHILD_DB_ENV));
    let id = child_var(CHILD_ID_ENV);
    let conn = db::open(&path).expect("open");
    let committed = arm_interloper(path.clone(), &id);
    let res = handle_delete(&conn, &path, &json!({ "id": id }), None, None);
    in_tx_fault::disarm_owner_gate(&id);
    let fired = *committed.lock().unwrap_or_else(PoisonError::into_inner);
    std::fs::write(child_var(CHILD_MARKER_ENV), report(fired, &res)).expect("write report");
}

#[cfg(unix)]
#[test]
fn mcp_update_gate_and_write_share_one_write_transaction_4147() {
    let (path, id, report) = run_child(ROLE_UPDATE, "mcp_update_owner_gate_child_4147");
    let conn = db::open(&path).expect("reopen");
    let owner = owner_of(&conn, &id);
    assert!(
        report.contains("committed=Some(false)"),
        "#4147: the gate and the write share one BEGIN IMMEDIATE, so a second process \
         cannot commit a re-own in between: {report} (owner={owner:?})"
    );
    assert!(
        report.contains("result=ok"),
        "the owner's update succeeds: {report}"
    );
    assert_eq!(owner.as_deref(), Some(OWNER), "the row keeps its owner");
    assert_eq!(
        content_of(&conn, &id).as_deref(),
        Some(OWNER_EDIT),
        "the owner's write lands"
    );
}

#[cfg(unix)]
#[test]
fn mcp_delete_gate_and_write_share_one_write_transaction_4147() {
    let (path, id, report) = run_child(ROLE_DELETE, "mcp_delete_owner_gate_child_4147");
    assert!(
        report.contains("committed=Some(false)"),
        "#4147: a re-own cannot commit between the delete gate and the erase: {report}"
    );
    assert!(
        report.contains("result=ok"),
        "the owner's delete succeeds: {report}"
    );
    let conn = db::open(&path).expect("reopen");
    assert!(content_of(&conn, &id).is_none(), "the owner's delete lands");
}
