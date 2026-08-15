// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 §22 Policy-Engine PE-8 (#697 / EPIC #1709) — end-to-end
//! tests for [`ai_memory::signed_events::verify_audit_trail`].
//!
//! Lives in `tests/` (not in `src/`) because the tamper / gap cases
//! need raw `UPDATE` / `DELETE signed_events` statements, which would
//! trip the `append_only_invariant_no_mutators_in_src` H5 guard if
//! written from a `src/` file. Same split rationale as
//! `tests/signed_events_chain_v34.rs`.
//!
//! Pins:
//! 1. A clean multi-row chain → intact, no gaps, correct total/head.
//! 2. A content TAMPER (UPDATE row N's payload) → not intact,
//!    `first_break_sequence == N + 1`.
//! 3. A sequence GAP (DELETE a middle row) → `sequence_gaps` surfaces
//!    the hole, exit-not-clean.
//! 4. `--since` filters `total_events` AND verifies the boundary (no
//!    false break at the window edge).
//! 5. An empty chain → intact, total 0.

use ai_memory::signed_events::{
    SignedEvent, append_signed_event, payload_hash, verify_audit_trail,
};
use rusqlite::Connection;
use std::path::PathBuf;

fn fresh_db_path(label: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("ai-memory-pe8-")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join(format!("{label}.db"));
    drop(ai_memory::db::open(&path).expect("init db"));
    (dir, path)
}

fn open_conn(path: &std::path::Path) -> Connection {
    ai_memory::db::open(path).expect("open db")
}

/// Append an event carrying an explicit RFC3339 timestamp so the
/// `--since` boundary cases are deterministic (instead of racing on
/// `Utc::now()` second-precision collisions).
fn append_at(conn: &Connection, payload: &[u8], ts: &str) {
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "alice".to_string(),
        event_type: "memory_link.created".to_string(),
        payload_hash: payload_hash(payload),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: ts.to_string(),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append");
}

// -----------------------------------------------------------------
// 1. Clean multi-row chain
// -----------------------------------------------------------------

#[test]
fn clean_chain_is_intact_with_no_gaps() {
    let (_dir, path) = fresh_db_path("clean");
    let conn = open_conn(&path);
    for i in 0..5 {
        append_at(
            &conn,
            format!("payload-{i}").as_bytes(),
            &format!("2026-06-17T00:00:0{i}+00:00"),
        );
    }

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert!(report.chain_intact, "report = {report:?}");
    assert!(report.is_clean(), "report = {report:?}");
    assert_eq!(report.total_events, 5);
    assert_eq!(report.head_sequence, 5);
    assert_eq!(report.first_break_sequence, None);
    assert!(report.sequence_gaps.is_empty(), "report = {report:?}");
    assert_eq!(report.since, None);
}

// -----------------------------------------------------------------
// 2. Content tamper → first_break_sequence = N + 1
// -----------------------------------------------------------------

#[test]
fn content_tamper_breaks_chain_at_next_row() {
    let (_dir, path) = fresh_db_path("tamper");
    let conn = open_conn(&path);
    for i in 0..5 {
        append_at(
            &conn,
            format!("payload-{i}").as_bytes(),
            &format!("2026-06-17T00:00:0{i}+00:00"),
        );
    }

    // Tamper row 3's payload via raw SQL (what an attacker would do —
    // the append-only invariant is enforced at the Rust API surface).
    conn.execute(
        "UPDATE signed_events SET payload_hash = X'deadbeefdeadbeef' WHERE sequence = 3",
        [],
    )
    .expect("tamper row 3");

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert!(!report.chain_intact, "report = {report:?}");
    assert!(!report.is_clean(), "report = {report:?}");
    assert_eq!(
        report.first_break_sequence,
        Some(4),
        "row 4's prev_hash no longer matches tampered row 3; report = {report:?}"
    );
    // Content tamper does NOT delete a row, so there is no contiguity
    // gap — the break is a prev_hash mismatch, not a missing sequence.
    assert!(report.sequence_gaps.is_empty(), "report = {report:?}");
    assert_eq!(report.total_events, 5);
}

// -----------------------------------------------------------------
// 3. Sequence gap (deleted middle row) → sequence_gaps surfaces it
// -----------------------------------------------------------------

#[test]
fn deleted_middle_row_surfaces_sequence_gap() {
    let (_dir, path) = fresh_db_path("gap");
    let conn = open_conn(&path);
    for i in 0..5 {
        append_at(
            &conn,
            format!("payload-{i}").as_bytes(),
            &format!("2026-06-17T00:00:0{i}+00:00"),
        );
    }

    // Delete the row at sequence 3 — sequences become 1,2,4,5.
    conn.execute("DELETE FROM signed_events WHERE sequence = 3", [])
        .expect("delete row 3");

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert!(
        !report.is_clean(),
        "a gap is not clean; report = {report:?}"
    );
    assert_eq!(
        report.sequence_gaps,
        vec![(3, 3)],
        "sequence 3 is the missing hole; report = {report:?}"
    );
    // verify_chain also flags the contiguity break (row 4 arrived
    // where 3 was expected).
    assert!(!report.chain_intact, "report = {report:?}");
    assert_eq!(report.total_events, 4, "four rows remain");
    assert_eq!(report.head_sequence, 5);
}

#[test]
fn multiple_deleted_rows_surface_multiple_gaps() {
    let (_dir, path) = fresh_db_path("multi-gap");
    let conn = open_conn(&path);
    for i in 0..8 {
        append_at(
            &conn,
            format!("payload-{i}").as_bytes(),
            &format!("2026-06-17T00:00:0{i}+00:00"),
        );
    }
    // Delete sequences 2,3 (a two-wide hole) and 6 (a one-wide hole).
    conn.execute("DELETE FROM signed_events WHERE sequence IN (2, 3, 6)", [])
        .expect("delete rows");

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(
        report.sequence_gaps,
        vec![(2, 3), (6, 6)],
        "both holes surfaced as inclusive ranges; report = {report:?}"
    );
    assert!(!report.is_clean(), "report = {report:?}");
}

// -----------------------------------------------------------------
// 4. --since filters total_events + handles the boundary
// -----------------------------------------------------------------

#[test]
fn since_filters_window_without_false_boundary_break() {
    let (_dir, path) = fresh_db_path("since");
    let conn = open_conn(&path);
    // Rows 1..=3 are "before" the window, 4..=6 are "in" the window.
    for i in 0..3 {
        append_at(
            &conn,
            format!("old-{i}").as_bytes(),
            &format!("2026-06-16T00:00:0{i}+00:00"),
        );
    }
    for i in 0..3 {
        append_at(
            &conn,
            format!("new-{i}").as_bytes(),
            &format!("2026-06-17T00:00:0{i}+00:00"),
        );
    }

    // since at the window edge: only rows with timestamp >= 06-17 are
    // in-window (sequences 4,5,6). The boundary link (row 4's prev_hash
    // against out-of-window row 3) MUST be verified, not falsely
    // flagged as a break.
    let report =
        verify_audit_trail(&conn, Some("2026-06-17T00:00:00+00:00"), None).expect("verify");
    assert!(
        report.chain_intact,
        "the window edge MUST NOT be a false break; report = {report:?}"
    );
    assert!(report.is_clean(), "report = {report:?}");
    assert_eq!(
        report.total_events, 3,
        "only the 3 in-window rows are counted; report = {report:?}"
    );
    assert_eq!(
        report.head_sequence, 6,
        "head is table-wide, independent of the window; report = {report:?}"
    );
    assert_eq!(report.since.as_deref(), Some("2026-06-17T00:00:00+00:00"));
    assert!(report.sequence_gaps.is_empty(), "report = {report:?}");
}

#[test]
fn since_window_still_detects_in_window_tamper() {
    let (_dir, path) = fresh_db_path("since-tamper");
    let conn = open_conn(&path);
    for i in 0..3 {
        append_at(
            &conn,
            format!("old-{i}").as_bytes(),
            &format!("2026-06-16T00:00:0{i}+00:00"),
        );
    }
    for i in 0..3 {
        append_at(
            &conn,
            format!("new-{i}").as_bytes(),
            &format!("2026-06-17T00:00:0{i}+00:00"),
        );
    }
    // Tamper row 5 (in-window) — row 6's prev_hash will mismatch.
    conn.execute(
        "UPDATE signed_events SET payload_hash = X'deadbeef' WHERE sequence = 5",
        [],
    )
    .expect("tamper");

    let report =
        verify_audit_trail(&conn, Some("2026-06-17T00:00:00+00:00"), None).expect("verify");
    assert!(
        !report.chain_intact,
        "an in-window tamper MUST still be detected; report = {report:?}"
    );
    assert_eq!(report.first_break_sequence, Some(6), "report = {report:?}");
}

// -----------------------------------------------------------------
// 5. Empty chain → intact, total 0
// -----------------------------------------------------------------

#[test]
fn empty_chain_is_trivially_intact() {
    let (_dir, path) = fresh_db_path("empty");
    let conn = open_conn(&path);

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert!(
        report.chain_intact,
        "empty chain is intact; report = {report:?}"
    );
    assert!(report.is_clean(), "report = {report:?}");
    assert_eq!(report.total_events, 0);
    assert_eq!(report.head_sequence, 0);
    assert_eq!(report.first_break_sequence, None);
    assert!(report.sequence_gaps.is_empty());
}
