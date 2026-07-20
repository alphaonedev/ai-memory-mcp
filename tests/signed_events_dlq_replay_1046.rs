// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1046 + #1116 — `signed_events_dlq` durable evidence pins.
//!
//! When chain insertion fails but DLQ insertion succeeds, the event lands in
//! `signed_events_dlq` with its identity, payload hash, and failure reason
//! preserved. On the journal-backed production path, if both writes fail, the
//! already-admitted durable spool record remains for recovery. v1.0.0 ships
//! neither an automatic replay sweep nor a replay CLI, so these tests
//! deliberately make no replay-and-delete claim.
//!
//! This file pins:
//!
//! 1. The DLQ table exists in the schema (so a future migration
//!    that drops the table fails the pin).
//! 2. The durable evidence columns remain present.
//! 3. A representative row round-trips through those columns without loss.

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use rusqlite::params;

fn fresh_db() -> rusqlite::Connection {
    ai_memory::db::open(std::path::Path::new(":memory:")).expect("db::open")
}

/// v0.7.0 #1046 + #1116 pin 1 — the `signed_events_dlq` table MUST
/// exist after the migration ladder runs. A future migration that
/// drops the table without an explicit operator-visible deprecation
/// fails this pin.
#[test]
fn signed_events_dlq_table_exists_after_migrate_1046() {
    let conn = fresh_db();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='signed_events_dlq'",
            [],
            |r| r.get(0),
        )
        .expect("query sqlite_master");
    assert_eq!(
        count, 1,
        "#1046: signed_events_dlq table MUST exist after migration ladder; \
         durable observation of successful DLQ landings depends on it"
    );
}

/// v0.7.0 #1046 + #1116 pin 2 — the DLQ table accepts the operator-
/// visible durable-evidence row shape. A schema drift (column renamed /
/// dropped) fails this pin.
#[test]
fn signed_events_dlq_accepts_documented_row_shape_1046() {
    let conn = fresh_db();
    // Inspect the schema directly so a missing evidence column fails loudly.
    let pragma_cols: Vec<String> = conn
        .prepare("PRAGMA table_info(signed_events_dlq)")
        .expect("PRAGMA prepare")
        .query_map([], |r| r.get::<_, String>(1))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("collect");
    for required in [
        "id",
        "agent_id",
        "event_type",
        "payload_hash",
        "signature",
        "attest_level",
        "timestamp",
        "failure_reason",
        "failed_at",
    ] {
        assert!(
            pragma_cols.iter().any(|column| column == required),
            "#1046: signed_events_dlq missing durable-evidence column {required}: {pragma_cols:?}"
        );
    }
}

/// #1046 + #1116 pin 3 — a representative DLQ row round-trips every
/// recovery-relevant field without implying that replay tooling exists.
#[test]
fn signed_events_dlq_evidence_row_roundtrips_1046() {
    #[derive(Debug, PartialEq, Eq)]
    struct EvidenceRow {
        id: String,
        agent_id: String,
        event_type: String,
        payload_hash: Vec<u8>,
        signature: Option<Vec<u8>>,
        attest_level: String,
        timestamp: String,
        failure_reason: String,
        failed_at: String,
    }

    let conn = fresh_db();
    // Step 1: synthesize a DLQ row (in production this lands when
    // the chain-write fails). The shape mirrors
    // `deferred_audit.rs::record_dlq`.
    //
    // #1136: column names updated to match the actual signed_events_dlq
    // schema (PRAGMA table_info: dlq_id, id, agent_id, event_type,
    // payload_hash, signature, attest_level, timestamp, failure_reason,
    // failed_at). The original pin used pre-rename column names
    // (kind/payload/created_at); the rename landed when the chain
    // primitives were unified with signed_events.
    let payload_hash = vec![0xde, 0xad, 0xbe, 0xef, 0x10, 0x46];
    let signature = Some(vec![0x10, 0x46, 0xaa, 0x55]);
    let inserted = conn.execute(
        "INSERT INTO signed_events_dlq \
            (id, agent_id, event_type, payload_hash, signature, attest_level, \
             timestamp, failure_reason, failed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            // Synthetic deterministic values pin the storage classes and
            // lossless evidence shape, not cryptographic validity.
            "synth-event-1046",
            "ai:operator-test",
            "governance.check",
            &payload_hash,
            &signature,
            "unsigned",
            "2026-05-22T10:00:00Z",
            "lock_contention",
            "2026-05-22T10:05:00Z",
        ],
    );
    // If the insert failed because of a column name mismatch, surface the
    // actual columns for evidence-contract drift.
    if let Err(e) = &inserted {
        let pragma_cols: Vec<String> = conn
            .prepare("PRAGMA table_info(signed_events_dlq)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        panic!(
            "#1046: signed_events_dlq INSERT failed ({e}); columns: {pragma_cols:?}. \
             The durable-evidence contract must match the actual schema."
        );
    }

    let evidence: EvidenceRow = conn
        .query_row(
            "SELECT id, agent_id, event_type, payload_hash, signature, \
                    attest_level, timestamp, failure_reason, failed_at \
             FROM signed_events_dlq WHERE id = ?1",
            ["synth-event-1046"],
            |row| {
                Ok(EvidenceRow {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    event_type: row.get(2)?,
                    payload_hash: row.get(3)?,
                    signature: row.get(4)?,
                    attest_level: row.get(5)?,
                    timestamp: row.get(6)?,
                    failure_reason: row.get(7)?,
                    failed_at: row.get(8)?,
                })
            },
        )
        .expect("query durable DLQ evidence");
    assert_eq!(
        evidence,
        EvidenceRow {
            id: "synth-event-1046".to_string(),
            agent_id: "ai:operator-test".to_string(),
            event_type: "governance.check".to_string(),
            payload_hash,
            signature,
            attest_level: "unsigned".to_string(),
            timestamp: "2026-05-22T10:00:00Z".to_string(),
            failure_reason: "lock_contention".to_string(),
            failed_at: "2026-05-22T10:05:00Z".to_string(),
        }
    );
}
