// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! V-4 closeout (#698) — `signed_events` cross-row hash chain tests.
//!
//! Pins the schema v34 behaviour:
//!
//! 1. Fresh DB's first row carries `prev_hash == [0u8; 32]` and
//!    `sequence == 1`.
//! 2. Subsequent rows chain correctly — row N's `prev_hash` equals
//!    `SHA-256(canonical_chain_bytes(row N-1))`; sequences are
//!    contiguous 1, 2, 3, …
//! 3. Tampering a middle row's `payload_hash` breaks the chain at
//!    row N+1 (because that row's `prev_hash` no longer matches the
//!    recomputed canonical-bytes digest).
//! 4. Tampering a row's `sequence` column (gap / duplicate / non-
//!    monotonic jump) is caught by [`verify_chain`].
//! 5. Concurrent inserts from the deferred-audit drainer (PE-3
//!    pattern) leave the chain GREEN end-to-end.
//! 6. Re-running the v34 backfill migration on an already-backfilled
//!    DB is a no-op (idempotent on replay).
//!
//! Per-row Ed25519 signatures remain as defense-in-depth (the chain
//! is the LOAD-BEARING property); this test suite focuses on the
//! chain itself.
//!
//! #10195: since #10108 a fresh database opens with the daemon-signed
//! agent cut-over marker at sequence 1, so the chain under test is the
//! marker followed by the fixture rows. The fixture rows use an event type
//! that is not agent-attributed: an unsigned agent-kind row above the
//! marker is a `PreCutoverWriter` defect by design (pinned in
//! `tests/agent_cutover_v103_10108.rs`), and this suite pins the chain, not
//! that rule.

use ai_memory::governance::agent_action::{AgentAction, Decision};
use ai_memory::governance::deferred_audit::{
    DeferredAuditEvent, GOVERNANCE_REFUSAL_EVENT_TYPE, close_and_flush,
    install_deferred_audit_drainer,
};
use ai_memory::signed_events::{
    AGENT_CUTOVER_EVENT_TYPE, ChainVerificationReport, SignedEvent, ZERO_HASH, append_signed_event,
    canonical_chain_bytes, list_signed_events, payload_hash, verify_chain,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn fresh_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ai-memory-v34-chain-")
        .tempdir()
        .expect("tempdir")
}

fn fresh_db_path(label: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = fresh_tempdir();
    let path = dir.path().join(format!("{label}.db"));
    drop(ai_memory::db::open(&path).expect("init db"));
    (dir, path)
}

/// #10195 — the rows a fresh database holds before any fixture row: the
/// signed agent cut-over marker (#10108) at sequence 1.
const FRESH_DB_MARKER_ROWS: u64 = 1;

/// The number of listed rows, in the unit of `rows_checked`.
fn row_count(rows: &[SignedEvent]) -> u64 {
    u64::try_from(rows.len()).expect("row count fits u64")
}

/// #10195 — the sequence of the first fixture row on a fresh database.
const FIRST_FIXTURE_SEQUENCE: i64 = 2;

/// #10195 — the fixture event type: a type that is not agent-attributed
/// (`AgentEventKind::of_event_type` is `None`), so an unsigned fixture row
/// keeps the plain daemon-row check after the cut-over marker.
const FIXTURE_EVENT_TYPE: &str = "test.chain_v34_fixture";

/// #10195 — asserts `rows` (ordered by sequence) start with the fresh-DB
/// marker at sequence 1 with the zero `prev_hash`, and that every later row
/// links to its predecessor with contiguous sequences.
fn assert_marker_then_linked(rows: &[SignedEvent]) {
    let marker = rows.first().expect("fresh database holds the marker");
    assert_eq!(
        marker.event_type, AGENT_CUTOVER_EVENT_TYPE,
        "row 1 of a fresh database MUST be the #10108 cut-over marker"
    );
    assert_eq!(marker.sequence, 1, "the marker MUST hold sequence 1");
    assert_eq!(
        marker.prev_hash,
        ZERO_HASH.to_vec(),
        "the first row's prev_hash MUST be 32 zero bytes"
    );
    for pair in rows.windows(2) {
        let (prev, row) = (&pair[0], &pair[1]);
        assert_eq!(row.sequence, prev.sequence + 1, "sequences contiguous");
        let digest = Sha256::digest(canonical_chain_bytes(prev)).to_vec();
        assert_eq!(
            row.prev_hash, digest,
            "row {}'s prev_hash MUST equal SHA-256(canonical_chain_bytes(row {}))",
            row.sequence, prev.sequence
        );
    }
}

/// #10195 — no row of the walk fails its signature check: the marker
/// with no verifier in the process is unchecked (never a failure), and the
/// unsigned non-agent fixture rows keep the plain daemon-row check.
fn assert_no_agent_defects(report: &ChainVerificationReport) {
    assert!(
        report.agent_signature_defects.is_empty(),
        "no agent-era defect expected; report = {report:?}"
    );
    assert!(
        report.signature_failures.is_empty(),
        "no signature failure expected; report = {report:?}"
    );
}

fn fixture(agent: &str, event_type: &str, payload: &[u8]) -> SignedEvent {
    SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        event_type: event_type.to_string(),
        payload_hash: payload_hash(payload),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    }
}

fn open_conn(path: &std::path::Path) -> Connection {
    ai_memory::db::open(path).expect("open db")
}

// -----------------------------------------------------------------
// 1. Fresh DB first row
// -----------------------------------------------------------------

#[test]
fn fresh_db_first_row_has_zero_prev_hash() {
    let (_dir, path) = fresh_db_path("first-row");
    let conn = open_conn(&path);
    let event = fixture("alice", FIXTURE_EVENT_TYPE, b"first-payload");
    append_signed_event(&conn, &event).expect("append first event");

    let mut listed = list_signed_events(&conn, None, 10, 0).expect("list");
    listed.sort_by_key(|e| e.sequence);
    assert_eq!(
        row_count(&listed),
        FRESH_DB_MARKER_ROWS + 1,
        "exactly the marker and one fixture row expected"
    );
    let row = &listed[0];
    assert_eq!(
        row.prev_hash,
        ZERO_HASH.to_vec(),
        "v34 first row's prev_hash MUST be 32 zero bytes; got len={} bytes={:02x?}",
        row.prev_hash.len(),
        row.prev_hash,
    );
    assert_eq!(
        row.sequence, 1,
        "v34 first row's sequence MUST be 1 (monotonic from 1)"
    );
    assert_marker_then_linked(&listed);
    assert_eq!(listed[1].id, event.id, "the fixture row follows the marker");
    assert_eq!(listed[1].sequence, FIRST_FIXTURE_SEQUENCE);

    // verify_chain reports the chain holds.
    let report = verify_chain(&conn, None, None).expect("verify_chain");
    assert!(
        report.chain_holds(),
        "marker plus one row chain MUST hold; report = {report:?}"
    );
    assert_eq!(report.rows_checked, FRESH_DB_MARKER_ROWS + 1);
    assert_no_agent_defects(&report);
}

// -----------------------------------------------------------------
// 2. Multi-row chaining
// -----------------------------------------------------------------

#[test]
fn subsequent_rows_chain_correctly() {
    let (_dir, path) = fresh_db_path("multi-row");
    let conn = open_conn(&path);

    for i in 0..3 {
        let ev = fixture(
            "alice",
            FIXTURE_EVENT_TYPE,
            format!("payload-{i}").as_bytes(),
        );
        append_signed_event(&conn, &ev).expect("append");
    }

    let listed = list_signed_events(&conn, None, 100, 0).expect("list");
    assert_eq!(row_count(&listed), FRESH_DB_MARKER_ROWS + 3);

    // Pull rows back ordered by sequence, since `list` orders by
    // timestamp ASC, id ASC — for a chain test we need
    // sequence-order. We re-prepare here so we don't depend on
    // timestamp-order matching insert-order under fast inserts (two
    // RFC3339-second-precision rows might share a timestamp).
    let mut by_seq: Vec<SignedEvent> = listed;
    by_seq.sort_by_key(|e| e.sequence);
    assert_marker_then_linked(&by_seq);
    // The three fixture rows follow the marker.
    let by_seq = &by_seq[1..];
    assert_eq!(by_seq[0].sequence, FIRST_FIXTURE_SEQUENCE);
    assert_eq!(by_seq[1].sequence, FIRST_FIXTURE_SEQUENCE + 1);
    assert_eq!(by_seq[2].sequence, FIRST_FIXTURE_SEQUENCE + 2);
    // Row 1's prev_hash is SHA-256(canonical_chain_bytes(row 0)).
    let h0 = {
        let mut hasher = Sha256::new();
        hasher.update(canonical_chain_bytes(&by_seq[0]));
        hasher.finalize().to_vec()
    };
    assert_eq!(
        by_seq[1].prev_hash, h0,
        "row 1's prev_hash MUST equal SHA-256(canonical_chain_bytes(row 0))"
    );
    // Row 2's prev_hash is SHA-256(canonical_chain_bytes(row 1)).
    let h1 = {
        let mut hasher = Sha256::new();
        hasher.update(canonical_chain_bytes(&by_seq[1]));
        hasher.finalize().to_vec()
    };
    assert_eq!(
        by_seq[2].prev_hash, h1,
        "row 2's prev_hash MUST equal SHA-256(canonical_chain_bytes(row 1))"
    );

    let report = verify_chain(&conn, None, None).expect("verify_chain");
    assert!(report.chain_holds(), "report = {report:?}");
    assert_eq!(report.rows_checked, FRESH_DB_MARKER_ROWS + 3);
    assert_eq!(report.chain_break, None);
    assert_no_agent_defects(&report);
}

// -----------------------------------------------------------------
// 3. Payload tamper detection
// -----------------------------------------------------------------

#[test]
fn tamper_in_middle_row_breaks_chain() {
    let (_dir, path) = fresh_db_path("tamper-payload");
    let conn = open_conn(&path);
    for i in 0..5 {
        let ev = fixture(
            "alice",
            FIXTURE_EVENT_TYPE,
            format!("payload-{i}").as_bytes(),
        );
        append_signed_event(&conn, &ev).expect("append");
    }

    // Pre-tamper: chain holds.
    let report = verify_chain(&conn, None, None).expect("verify_chain");
    assert!(
        report.chain_holds(),
        "baseline 5-row chain MUST hold pre-tamper; report = {report:?}"
    );

    // Tamper row 3's payload_hash with a raw UPDATE (the
    // append-only invariant is enforced at the Rust API surface;
    // raw SQL bypasses it which is exactly what an attacker would
    // do).
    conn.execute(
        "UPDATE signed_events SET payload_hash = X'deadbeefdeadbeef' WHERE sequence = 3",
        [],
    )
    .expect("UPDATE row 3 payload");

    // verify_chain should detect the break at row 4 (because row
    // 4's stored prev_hash no longer equals the recomputed
    // canonical-bytes digest of the tampered row 3).
    let report = verify_chain(&conn, None, None).expect("verify_chain post-tamper");
    assert!(
        !report.chain_holds(),
        "chain MUST be detected as broken after row-3 payload tamper; report = {report:?}"
    );
    assert_eq!(
        report.chain_break,
        Some(4),
        "first detected break MUST be at row 4 (the row immediately after the tampered row 3); report = {report:?}"
    );
}

// -----------------------------------------------------------------
// 4. Sequence tamper detection
// -----------------------------------------------------------------

#[test]
fn tamper_in_sequence_column_caught() {
    let (_dir, path) = fresh_db_path("tamper-seq");
    let conn = open_conn(&path);
    for i in 0..5 {
        let ev = fixture(
            "alice",
            FIXTURE_EVENT_TYPE,
            format!("payload-{i}").as_bytes(),
        );
        append_signed_event(&conn, &ev).expect("append");
    }

    // Raw UPDATE: re-stamp row 3's sequence to 99 (gap +
    // non-monotonic jump). The UNIQUE INDEX still permits this
    // because no other row carries sequence=99.
    conn.execute(
        "UPDATE signed_events SET sequence = 99 WHERE sequence = 3",
        [],
    )
    .expect("UPDATE row 3 sequence to 99");

    let report = verify_chain(&conn, None, None).expect("verify_chain");
    assert!(
        !report.chain_holds(),
        "sequence gap MUST be reported; report = {report:?}"
    );
}

// -----------------------------------------------------------------
// 5. Concurrent inserts from the deferred-audit drainer
// -----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chain_holds_across_drainer_writes() {
    let (_dir, path) = fresh_db_path("drainer-chain");

    let (queue, supervisor) = install_deferred_audit_drainer(&path);
    let queued = Arc::new(AtomicU64::new(0));

    // 8 producers × 50 refusals = 400 events. Smaller volume than
    // the PE-3 soak (5K) — we only need enough rows to confirm the
    // chain stitches together across concurrent producers writing
    // through the same single-consumer drainer.
    let producers: u64 = 8;
    let per_producer: u64 = 50;
    let expected = producers * per_producer;

    let mut tasks = Vec::with_capacity(usize::try_from(producers).expect("fits"));
    for p in 0..producers {
        let q = queue.clone();
        let queued = queued.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..per_producer {
                let action = AgentAction::Custom {
                    custom_kind: "memory_write".to_string(),
                    payload: serde_json::json!({
                        "namespace": format!("chain/r{p}-{i}"),
                    }),
                };
                let decision = Decision::Refuse {
                    rule_id: "R001".to_string(),
                    reason: "chain test: synthetic refusal".to_string(),
                };
                let event = DeferredAuditEvent::from_refusal(
                    &format!("agent:chain-{p}"),
                    &action,
                    &decision,
                )
                .expect("event builds");
                if q.submit(event) {
                    queued.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for t in tasks {
        t.await.expect("producer join");
    }
    assert_eq!(queued.load(Ordering::Relaxed), expected);

    close_and_flush(queue, supervisor)
        .await
        .expect("drainer drains cleanly");

    // Re-open and verify the chain end-to-end.
    let conn = open_conn(&path);
    let appended: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE],
            |r| r.get(0),
        )
        .expect("count refusals");
    assert_eq!(
        appended,
        i64::try_from(expected).expect("fits"),
        "every queued event MUST have landed (chain doesn't help if rows are missing)"
    );

    let report = verify_chain(&conn, None, None).expect("verify_chain");
    assert!(
        report.chain_holds(),
        "chain MUST hold after {expected} concurrent drainer inserts; report = {report:?}"
    );
    assert_eq!(report.rows_checked, FRESH_DB_MARKER_ROWS + expected);
    assert_eq!(report.chain_break, None);
    assert_no_agent_defects(&report);
    let mut by_seq = list_signed_events(&conn, None, 1000, 0).expect("list");
    by_seq.sort_by_key(|e| e.sequence);
    assert_eq!(row_count(&by_seq), FRESH_DB_MARKER_ROWS + expected);
    assert_marker_then_linked(&by_seq);
}

// -----------------------------------------------------------------
// 6. Backfill idempotency on replay
// -----------------------------------------------------------------

#[test]
fn backfill_migration_idempotent_on_replay() {
    let (_dir, path) = fresh_db_path("idempotent-backfill");
    let conn = open_conn(&path);

    // Seed 5 events through the production writer (so they already
    // have prev_hash + sequence).
    for i in 0..5 {
        let ev = fixture(
            "alice",
            FIXTURE_EVENT_TYPE,
            format!("payload-{i}").as_bytes(),
        );
        append_signed_event(&conn, &ev).expect("append");
    }

    // Snapshot the chain.
    let pre: Vec<SignedEvent> = {
        let mut v = list_signed_events(&conn, None, 100, 0).expect("list pre");
        v.sort_by_key(|e| e.sequence);
        v
    };
    assert_eq!(row_count(&pre), FRESH_DB_MARKER_ROWS + 5);
    assert_marker_then_linked(&pre);

    // Replay the backfill function. Because every row already has
    // `sequence` non-NULL, the backfill's `WHERE sequence IS NULL`
    // filter returns zero pending rows and the function exits a
    // no-op.
    ai_memory::storage::migrations::migrate_v34_backfill_chain(&conn).expect("replay backfill");

    let post: Vec<SignedEvent> = {
        let mut v = list_signed_events(&conn, None, 100, 0).expect("list post");
        v.sort_by_key(|e| e.sequence);
        v
    };
    assert_eq!(pre, post, "backfill replay MUST be a no-op");

    let report = verify_chain(&conn, None, None).expect("verify_chain");
    assert!(
        report.chain_holds(),
        "chain MUST still hold after a no-op replay; report = {report:?}"
    );
    assert_no_agent_defects(&report);
}

// -----------------------------------------------------------------
// 7. verify_chain with `since` resumes mid-chain
// -----------------------------------------------------------------

#[test]
fn verify_chain_with_since_resumes_correctly() {
    let (_dir, path) = fresh_db_path("verify-since");
    let conn = open_conn(&path);
    for i in 0..6 {
        let ev = fixture(
            "alice",
            FIXTURE_EVENT_TYPE,
            format!("payload-{i}").as_bytes(),
        );
        append_signed_event(&conn, &ev).expect("append");
    }

    // The six fixture rows hold sequences 2..=7 after the marker. Resume
    // after the third fixture row: walk only the fourth, fifth and sixth.
    let third_fixture_sequence = FIRST_FIXTURE_SEQUENCE + 2;
    let report = verify_chain(&conn, Some(third_fixture_sequence), None).expect("verify");
    assert!(
        report.chain_holds(),
        "since-resume chain MUST hold; report = {report:?}"
    );
    assert_eq!(
        report.rows_checked, 3,
        "fixture rows 4,5,6 walked; report = {report:?}"
    );
    assert_eq!(report.chain_break, None);
    assert_no_agent_defects(&report);
}

#[test]
fn verify_chain_with_since_detects_break_in_resumed_range() {
    let (_dir, path) = fresh_db_path("verify-since-tamper");
    let conn = open_conn(&path);
    for i in 0..6 {
        let ev = fixture(
            "alice",
            FIXTURE_EVENT_TYPE,
            format!("payload-{i}").as_bytes(),
        );
        append_signed_event(&conn, &ev).expect("append");
    }
    // Tamper row 5's payload — row 6's prev_hash will mismatch.
    conn.execute(
        "UPDATE signed_events SET payload_hash = X'deadbeef' WHERE sequence = 5",
        [],
    )
    .expect("tamper");

    // since=4: walk rows 5, 6. Row 6's prev_hash check fails because
    // row 5 was tampered AFTER the chain stamp.
    let report = verify_chain(&conn, Some(4), None).expect("verify");
    assert!(
        !report.chain_holds(),
        "since-resume MUST detect downstream break; report = {report:?}"
    );
}

// -----------------------------------------------------------------
// 8. Backfill correctness on rows inserted WITHOUT a sequence
// -----------------------------------------------------------------

/// Simulate the pre-v34 deployment shape: rows that exist with
/// NULL `prev_hash` + NULL `sequence`. Re-run the backfill and
/// assert every row picks up a contiguous sequence + a chain that
/// passes [`verify_chain`].
#[test]
fn backfill_stamps_pre_existing_rows() {
    let (_dir, path) = fresh_db_path("backfill-pre");
    let conn = open_conn(&path);

    // Insert 4 rows WITHOUT chain columns (raw INSERT — mimics a
    // pre-v34 binary writing into a v34 schema). The UNIQUE INDEX
    // on sequence permits multiple NULLs (SQLite treats NULL as
    // distinct under UNIQUE), so all 4 inserts succeed.
    for i in 0..4 {
        conn.execute(
            "INSERT INTO signed_events \
             (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp) \
             VALUES (?1, 'alice', ?4, ?2, NULL, 'unsigned', ?3)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                payload_hash(format!("payload-{i}").as_bytes()),
                format!("2026-05-14T00:00:0{i}+00:00"),
                FIXTURE_EVENT_TYPE,
            ],
        )
        .expect("raw insert");
    }

    // Pre-backfill: every raw row has NULL sequence, so verify_chain
    // (which filters on `COALESCE(sequence, 0) > 0`) sees only the
    // fresh-DB marker — the raw rows are invisible to the walk, but the
    // row count gap surfaces the gap. We check the gap-detection by
    // comparing rows_checked against the raw count.
    let pre = verify_chain(&conn, None, None).expect("verify pre");
    let raw_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM signed_events", [], |r| r.get(0))
        .expect("count");
    assert_eq!(
        pre.rows_checked, FRESH_DB_MARKER_ROWS,
        "pre-backfill rows with NULL sequence are excluded from the chain walk; got {pre:?}"
    );
    assert_eq!(
        raw_count,
        i64::try_from(FRESH_DB_MARKER_ROWS).expect("fits") + 4,
        "the marker plus four raw inserted rows"
    );

    // Run backfill.
    ai_memory::storage::migrations::migrate_v34_backfill_chain(&conn).expect("backfill");

    // Post-backfill: the marker keeps sequence 1, the raw rows carry
    // sequence 2..=5, and the chain is valid.
    let listed: Vec<SignedEvent> = {
        let mut v = list_signed_events(&conn, None, 100, 0).expect("list");
        v.sort_by_key(|e| e.sequence);
        v
    };
    assert_eq!(row_count(&listed), FRESH_DB_MARKER_ROWS + 4);
    assert_marker_then_linked(&listed);
    for (i, row) in listed.iter().enumerate() {
        assert_eq!(
            row.sequence,
            i64::try_from(i + 1).expect("fits"),
            "row {i} sequence"
        );
        assert_eq!(
            row.prev_hash.len(),
            32,
            "row {i} prev_hash MUST be 32 bytes"
        );
    }
    let post = verify_chain(&conn, None, None).expect("verify post");
    assert!(
        post.chain_holds(),
        "chain MUST hold post-backfill; report = {post:?}"
    );
    assert_eq!(post.rows_checked, FRESH_DB_MARKER_ROWS + 4);
    assert_no_agent_defects(&post);
}

// -----------------------------------------------------------------
// 9. Backfill mixed state (partial pre-stamp + un-stamped rows)
// -----------------------------------------------------------------

/// Simulate a database where the first half of rows already have
/// chain columns (e.g., from a previous partial v34 run) and the
/// second half is un-stamped. `migrate_v34_backfill_chain` MUST
/// resume from the correct sequence and chain-link the new rows to
/// the existing tail.
#[test]
fn backfill_resumes_from_mixed_state() {
    let (_dir, path) = fresh_db_path("backfill-mixed");
    let conn = open_conn(&path);
    // Two stamped rows via the production writer.
    for i in 0..2 {
        let ev = fixture(
            "alice",
            FIXTURE_EVENT_TYPE,
            format!("stamped-{i}").as_bytes(),
        );
        append_signed_event(&conn, &ev).expect("append stamped");
    }
    // Three un-stamped rows via raw INSERT.
    for i in 0..3 {
        conn.execute(
            "INSERT INTO signed_events \
             (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp) \
             VALUES (?1, 'alice', ?4, ?2, NULL, 'unsigned', ?3)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                payload_hash(format!("unstamped-{i}").as_bytes()),
                format!("2026-05-14T01:00:0{i}+00:00"),
                FIXTURE_EVENT_TYPE,
            ],
        )
        .expect("raw insert");
    }

    // Run the backfill — it should pick up exactly the 3 un-stamped
    // rows and assign sequences 4, 5, 6 chained to the stamped tail
    // (the marker holds 1, the stamped rows 2 and 3).
    ai_memory::storage::migrations::migrate_v34_backfill_chain(&conn).expect("backfill");

    // Verify post-state: marker plus 5 rows, sequence 1..=6, chain holds.
    let listed: Vec<SignedEvent> = {
        let mut v = list_signed_events(&conn, None, 100, 0).expect("list");
        v.sort_by_key(|e| e.sequence);
        v
    };
    assert_eq!(row_count(&listed), FRESH_DB_MARKER_ROWS + 5);
    assert_marker_then_linked(&listed);
    for (i, row) in listed.iter().enumerate() {
        assert_eq!(
            row.sequence,
            i64::try_from(i + 1).expect("fits"),
            "row {i} sequence"
        );
    }
    let report = verify_chain(&conn, None, None).expect("verify");
    assert!(
        report.chain_holds(),
        "mixed-state backfill MUST produce a valid chain; report = {report:?}"
    );
    assert_eq!(report.rows_checked, FRESH_DB_MARKER_ROWS + 5);
    assert_no_agent_defects(&report);
}
