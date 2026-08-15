// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 #1850 (CWE-354) — end-to-end tests for the off-table
//! audit-trail truncation anchor wired into
//! [`ai_memory::signed_events::verify_audit_trail`].
//!
//! Context: `verify_audit_trail` recomputes the chain head from the
//! surviving `MAX(sequence)` with no in-table high-water mark, so deleting
//! the trailing N `signed_events` rows leaves a contiguous chain and the
//! verifier reports `chain_intact = true` — a false all-clear. The fix
//! (5-agent vote `4d3ea1c5`, T4) stamps the chain head into the #697
//! append-only forensic JSONL chain and compares the in-DB head against
//! that off-table anchor.
//!
//! Pins:
//! - (a) trailing-rows DELETE after a watermark → truncation `Detected`.
//! - (b) no forensic anchor present → `Unknown` (NOT a false positive,
//!   NOT intact-because-of-anchor — `is_clean()` stays true).
//! - (c) intact chain with a current watermark → `NotDetected`.
//! - (d) the watermark is carried INSIDE the forensic `payload` and does
//!   NOT add a `ForensicDecision` struct field — a canonical-bytes /
//!   signature round-trip of a pre-existing non-watermark row still
//!   verifies (the T4 signed-bytes invariant).
//!
//! The forensic sink is process-global, so these tests serialise via a
//! module-local lock (the same discipline as
//! `tests/admin_audit_chain_913.rs`).

#![allow(clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ai_memory::governance::audit as forensic;
use ai_memory::signed_events::{
    HeadHashCheck, SignedEvent, TruncationCheck, append_signed_event, canonical_chain_bytes,
    payload_hash, verify_audit_trail,
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

/// Process-global serialisation for the shared forensic SINK.
fn forensic_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE).
fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1850-truncation-anchor")
}

fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn open_db(dir: &Path) -> (PathBuf, Connection) {
    let path = dir.join("audit.db");
    drop(ai_memory::db::open(&path).expect("init db"));
    let conn = ai_memory::db::open(&path).expect("open db");
    (path, conn)
}

fn append_row(conn: &Connection, payload: &[u8]) {
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "alice".to_string(),
        event_type: "memory_link.created".to_string(),
        payload_hash: payload_hash(payload),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append");
}

// -----------------------------------------------------------------
// (a) trailing-rows DELETE after a watermark → Detected
// -----------------------------------------------------------------

#[test]
fn trailing_delete_after_watermark_is_detected() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("a-forensic");
    let ddir = fresh_dir("a-db");
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    // Anchor the head (5) into the off-table forensic chain.
    forensic::record_audit_watermark(5, "anchor-hash-head-5");
    forensic::flush_blocking();

    // Truncate the trailing two rows (sequences 4,5) — the surviving
    // 1..=3 chain stays contiguous, so chain_intact alone can't see it.
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(
        report.head_sequence, 3,
        "in-DB head dropped; report={report:?}"
    );
    assert!(
        report.chain_intact,
        "surviving 1..=3 chain is still internally contiguous; report={report:?}"
    );
    assert!(
        report.sequence_gaps.is_empty(),
        "a tail truncation leaves NO gap; report={report:?}"
    );
    assert_eq!(
        report.truncation,
        TruncationCheck::Detected {
            anchored_head: 5,
            db_head: 3,
        },
        "off-table anchor must flag the tail truncation; report={report:?}"
    );
    assert!(
        !report.is_clean(),
        "a detected truncation is NOT a clean all-clear; report={report:?}"
    );

    forensic::shutdown();
}

// -----------------------------------------------------------------
// (b) no forensic anchor → Unknown (not a false positive)
// -----------------------------------------------------------------

#[test]
fn no_anchor_present_is_unknown_not_false_positive() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("b-forensic");
    let ddir = fresh_dir("b-db");
    // Sink is live but NO watermark is ever written → anchor ABSENT.
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..4 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    forensic::flush_blocking();

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(
        report.truncation,
        TruncationCheck::Unknown,
        "no anchor → verdict withheld, never a false alarm; report={report:?}"
    );
    assert!(
        report.chain_intact && report.is_clean(),
        "Unknown must NOT make an otherwise-clean report dirty; report={report:?}"
    );

    forensic::shutdown();
}

// -----------------------------------------------------------------
// (c) intact chain with a current watermark → NotDetected
// -----------------------------------------------------------------

#[test]
fn intact_chain_with_current_watermark_is_not_detected() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("c-forensic");
    let ddir = fresh_dir("c-db");
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    // v1.0.0 #1873 — anchor the REAL head hash (a fake hash would now trip the
    // head-hash mismatch check on an intact chain). The truncation-lane
    // assertion below is unchanged.
    anchor_real_head(&conn);

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(report.head_sequence, 5);
    assert_eq!(
        report.truncation,
        TruncationCheck::NotDetected,
        "in-DB head >= anchored head → no truncation evidence; report={report:?}"
    );
    assert_eq!(
        report.head_hash,
        HeadHashCheck::NotDetected,
        "an intact chain vs its real anchor hash must match; report={report:?}"
    );
    assert!(report.is_clean(), "report={report:?}");

    forensic::shutdown();
}

// -----------------------------------------------------------------
// (d) T4 invariant — watermark lives in `payload`, not a new field
// -----------------------------------------------------------------

#[test]
fn watermark_is_payload_only_and_canonical_bytes_unchanged() {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use rand_core::OsRng;

    // A pre-existing NON-watermark forensic row signs + verifies over its
    // canonical bytes — pins that the signed-bytes layout is undisturbed.
    let key = SigningKey::generate(&mut OsRng);
    let vk = key.verifying_key();
    let normal = forensic::ForensicDecision {
        ts: "2026-06-28T00:00:00.000Z".to_string(),
        actor: "ai:t".to_string(),
        decision: "allow".to_string(),
        kind: "bash".to_string(),
        rule_id: "R001".to_string(),
        payload: serde_json::json!({"command": "ls"}),
        prev_hash: ai_memory::governance::audit::CHAIN_HEAD_PREV_HASH.to_string(),
        sig: String::new(),
    };
    let canonical = normal.canonical_bytes();
    let sig = key.sign(&canonical);
    assert!(
        vk.verify(&canonical, &sig).is_ok(),
        "non-watermark row canonical-bytes signature must verify"
    );

    // The fixed forensic field set (8 keys). A watermark row MUST carry its
    // data INSIDE `payload` and add NONE of its own keys to the object.
    let expected_keys = [
        "ts",
        "actor",
        "decision",
        "kind",
        "rule_id",
        "payload",
        "prev_hash",
        "sig",
    ];
    let normal_obj = serde_json::to_value(&normal).expect("serialise");
    let normal_keys: std::collections::BTreeSet<String> = normal_obj
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect();
    let expected_set: std::collections::BTreeSet<String> =
        expected_keys.iter().map(ToString::to_string).collect();
    assert_eq!(normal_keys, expected_set, "baseline field set drifted");

    // A watermark-bearing row built through the SAME struct: the only
    // difference is the `kind` + `payload` contents — the key set is byte-
    // identical, proving the watermark added no struct field (the T4 trap).
    let watermark = forensic::ForensicDecision {
        kind: forensic::AUDIT_WATERMARK_KIND.to_string(),
        payload: serde_json::json!({
            "v": 1,
            "head_sequence": 42,
            "head_canonical_hash": "deadbeef",
        }),
        ..normal.clone()
    };
    let watermark_obj = serde_json::to_value(&watermark).expect("serialise");
    let watermark_keys: std::collections::BTreeSet<String> = watermark_obj
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        watermark_keys, expected_set,
        "watermark row added a struct field — the T4 signed-bytes invariant is broken"
    );
    // And the watermark data is reachable from the free-form payload only.
    assert_eq!(
        watermark
            .payload
            .get("head_sequence")
            .and_then(serde_json::Value::as_i64),
        Some(42)
    );
}

// -----------------------------------------------------------------
// v1.0.0 #1873 (CWE-354) — audit-head HASH anchor: a SAME-LENGTH suffix
// rewrite (recomputed prev_hash, equal row count) that the seq-only
// TruncationCheck + the chain-intact walk both miss on an unsigned daemon.
// -----------------------------------------------------------------

/// Read the surviving head row, recompute its canonical hash EXACTLY as the
/// verifier does (`SHA-256(canonical_chain_bytes(head))` → lowercase hex), and
/// anchor that REAL hash into the off-table forensic watermark. Returns the
/// head sequence. (The truncation tests above anchor a FAKE hash because they
/// only exercise the sequence compare; the head-hash lane needs the real one.)
fn anchor_real_head(conn: &Connection) -> i64 {
    let (seq, hash_hex) = conn
        .query_row(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, sequence, cause_hash \
             FROM signed_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| {
                let ev = SignedEvent {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    event_type: row.get(2)?,
                    payload_hash: row.get(3)?,
                    signature: row.get(4)?,
                    attest_level: row.get(5)?,
                    timestamp: row.get(6)?,
                    sequence: row.get(7)?,
                    cause_hash: row.get::<_, Option<Vec<u8>>>(8)?,
                    prev_hash: Vec::new(),
                };
                let mut h = Sha256::new();
                h.update(canonical_chain_bytes(&ev));
                Ok((ev.sequence, hex::encode(h.finalize())))
            },
        )
        .expect("read head row");
    forensic::record_audit_watermark(seq, &hash_hex);
    forensic::flush_blocking();
    seq
}

#[test]
fn same_length_head_rewrite_is_head_hash_mismatch() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("d-forensic");
    let ddir = fresh_dir("d-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    let head_seq = anchor_real_head(&conn);

    // Baseline: a clean chain with a REAL anchor → head hash matches.
    let clean = verify_audit_trail(&conn, None, None).expect("verify clean");
    assert_eq!(
        clean.head_hash,
        HeadHashCheck::NotDetected,
        "clean chain vs its real anchor must match; report={clean:?}"
    );
    assert!(clean.is_clean(), "clean baseline; report={clean:?}");

    // SAME-LENGTH rewrite: flip the HEAD row's payload_hash in place. Row count
    // and every sequence are unchanged, and nothing links FROM the head, so the
    // chain walk stays intact and the seq-only truncation check reads clean —
    // ONLY the head-hash anchor catches it.
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        params![vec![0xFFu8; 32], head_seq],
    )
    .expect("rewrite head payload in place");

    let report = verify_audit_trail(&conn, None, None).expect("verify rewritten");
    assert_eq!(
        report.head_sequence, head_seq,
        "same-length rewrite leaves the head sequence + row count unchanged; report={report:?}"
    );
    assert!(
        report.chain_intact,
        "nothing links from the head, so the chain walk stays intact; report={report:?}"
    );
    assert_eq!(
        report.truncation,
        TruncationCheck::NotDetected,
        "the seq-only truncation check cannot see a same-length rewrite; report={report:?}"
    );
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "signed_events"),
        other => panic!("expected head_hash Mismatch, got {other:?}; report={report:?}"),
    }
    assert!(
        !report.is_clean(),
        "a head-hash mismatch (same-length rewrite) must dirty is_clean → exit-1; report={report:?}"
    );

    forensic::shutdown();
}

#[test]
fn head_hash_withholds_when_no_anchor() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("e-forensic");
    let ddir = fresh_dir("e-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let (_path, conn) = open_db(ddir.path());
    for i in 0..3 {
        append_row(&conn, format!("p-{i}").as_bytes());
    }
    // No watermark recorded → the head-hash check withholds (never a false
    // alarm on a deployment without a forensic anchor).
    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(
        report.head_hash,
        HeadHashCheck::Unknown,
        "no anchor → withhold; report={report:?}"
    );
    assert!(
        report.is_clean(),
        "withhold keeps a clean report clean; report={report:?}"
    );

    forensic::shutdown();
}

// -----------------------------------------------------------------
// v1.0.0 #2202 (CWE-354) — the #1873 residual-1 the equal-sequence gate MISSED:
// the anchored row is NOT the current head. The watermark is interval-throttled
// with no shutdown flush, so in the steady state the daemon has appended k>=1
// rows since the last watermark (~63/64 of the time) — the equal-sequence gate
// then NEVER consults the anchor. These reproduce BOTH constructions the audit
// named; they FAIL on the equal-sequence gate and pass on the at-anchored-seq
// compare.
// -----------------------------------------------------------------

/// Recompute + write row `seq`'s `prev_hash` from its predecessor's canonical
/// bytes — the faithful "attacker recomputes `prev_hash`" step that keeps a
/// same-length whole-suffix rewrite's chain walk intact (so ONLY the head-hash
/// anchor can convict).
fn relink_prev_hash(conn: &Connection, seq: i64) {
    let prev_hash: Vec<u8> = conn
        .query_row(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, sequence, cause_hash \
             FROM signed_events WHERE sequence = ?1",
            params![seq - 1],
            |row| {
                let ev = SignedEvent {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    event_type: row.get(2)?,
                    payload_hash: row.get(3)?,
                    signature: row.get(4)?,
                    attest_level: row.get(5)?,
                    timestamp: row.get(6)?,
                    sequence: row.get(7)?,
                    cause_hash: row.get::<_, Option<Vec<u8>>>(8)?,
                    prev_hash: Vec::new(),
                };
                let mut h = Sha256::new();
                h.update(canonical_chain_bytes(&ev));
                Ok(h.finalize().to_vec())
            },
        )
        .expect("read predecessor row");
    conn.execute(
        "UPDATE signed_events SET prev_hash = ?1 WHERE sequence = ?2",
        params![prev_hash, seq],
    )
    .expect("relink prev_hash");
}

/// (PASSIVE) — watermark anchors row W (=5); the daemon appends 3 more rows
/// (`db_head` = 8 > W); a same-length whole-suffix rewrite then spans row W. The
/// equal-sequence gate skips the anchor (8 != 5) → clean; the at-anchored-seq
/// compare recomputes row W and convicts.
#[test]
fn same_length_rewrite_below_head_after_appends_is_head_hash_mismatch() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("f-forensic");
    let ddir = fresh_dir("f-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    let anchored = anchor_real_head(&conn); // watermark W = 5
    // Daemon appends 3 rows AFTER the watermark → db_head = 8, anchored = 5.
    for i in 5..8 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }

    // Baseline: the anchored row (5) is intact, so it MATCHES its anchor even
    // though the head (8) has moved past it. The equal-sequence gate returns
    // Unknown here; the #2202 at-anchored-seq compare returns NotDetected.
    let base = verify_audit_trail(&conn, None, None).expect("verify baseline");
    assert_eq!(base.head_sequence, 8, "base={base:?}");
    assert_eq!(
        base.head_hash,
        HeadHashCheck::NotDetected,
        "the intact anchored row must MATCH its anchor even past the head \
         (the #2202 at-anchored-seq compare); base={base:?}"
    );
    assert!(base.is_clean(), "base={base:?}");

    // SAME-LENGTH whole-suffix rewrite spanning row W: flip the anchored row's
    // payload in place, then relink the next row so the chain walk stays intact.
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        params![vec![0xABu8; 32], anchored],
    )
    .expect("rewrite anchored row payload in place");
    relink_prev_hash(&conn, anchored + 1);

    let report = verify_audit_trail(&conn, None, None).expect("verify rewritten");
    assert!(
        report.chain_intact,
        "whole-suffix rewrite recomputes prev_hash → chain walk stays intact; report={report:?}"
    );
    assert_eq!(
        report.truncation,
        TruncationCheck::NotDetected,
        "db_head (8) >= anchored (5) → the seq-only truncation reads clean; report={report:?}"
    );
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "signed_events"),
        other => panic!(
            "expected head_hash Mismatch AT the anchored sequence, got {other:?}; report={report:?}"
        ),
    }
    assert!(
        !report.is_clean(),
        "a same-length rewrite of the anchored row must dirty is_clean; report={report:?}"
    );

    forensic::shutdown();
}

/// (ACTIVE) — even at head == W, the attacker rewrites row W and appends ONE
/// self-made linked row → head = W+1, so the equal-sequence gate withholds →
/// clean. The at-anchored-seq compare recomputes row W and convicts.
#[test]
fn same_length_rewrite_then_append_one_row_is_head_hash_mismatch() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("g-forensic");
    let ddir = fresh_dir("g-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    let anchored = anchor_real_head(&conn); // W = 5, head == W at anchor time

    // Rewrite the anchored (head) row same-length, then append ONE self-made
    // linked row: `append_signed_event` reads the now-rewritten head and links
    // the new row to it, so the chain stays intact and the head advances to W+1.
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        params![vec![0xCDu8; 32], anchored],
    )
    .expect("rewrite anchored head row in place");
    append_row(&conn, b"attacker-appended-linked-row");

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(
        report.head_sequence,
        anchored + 1,
        "the attacker-appended row pushes the head past the anchor; report={report:?}"
    );
    assert!(report.chain_intact, "report={report:?}");
    assert_eq!(
        report.truncation,
        TruncationCheck::NotDetected,
        "db_head (W+1) >= anchored (W) → the seq-only truncation reads clean; report={report:?}"
    );
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "signed_events"),
        other => panic!("expected head_hash Mismatch, got {other:?}; report={report:?}"),
    }
    assert!(
        !report.is_clean(),
        "append-one-to-evade must NOT read clean; report={report:?}"
    );

    forensic::shutdown();
}
