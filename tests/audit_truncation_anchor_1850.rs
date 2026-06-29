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
//!       NOT intact-because-of-anchor — `is_clean()` stays true).
//! - (c) intact chain with a current watermark → `NotDetected`.
//! - (d) the watermark is carried INSIDE the forensic `payload` and does
//!       NOT add a `ForensicDecision` struct field — a canonical-bytes /
//!       signature round-trip of a pre-existing non-watermark row still
//!       verifies (the T4 signed-bytes invariant).
//!
//! The forensic sink is process-global, so these tests serialise via a
//! module-local lock (the same discipline as
//! `tests/admin_audit_chain_913.rs`).

#![allow(clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ai_memory::governance::audit as forensic;
use ai_memory::signed_events::{
    SignedEvent, TruncationCheck, append_signed_event, payload_hash, verify_audit_trail,
};
use rusqlite::Connection;

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
    let _g = forensic_lock().lock().unwrap_or_else(|e| e.into_inner());
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

    let report = verify_audit_trail(&conn, None).expect("verify");
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
    let _g = forensic_lock().lock().unwrap_or_else(|e| e.into_inner());
    let fdir = fresh_dir("b-forensic");
    let ddir = fresh_dir("b-db");
    // Sink is live but NO watermark is ever written → anchor ABSENT.
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..4 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    forensic::flush_blocking();

    let report = verify_audit_trail(&conn, None).expect("verify");
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
    let _g = forensic_lock().lock().unwrap_or_else(|e| e.into_inner());
    let fdir = fresh_dir("c-forensic");
    let ddir = fresh_dir("c-db");
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    forensic::record_audit_watermark(5, "anchor-hash-head-5");
    forensic::flush_blocking();

    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(report.head_sequence, 5);
    assert_eq!(
        report.truncation,
        TruncationCheck::NotDetected,
        "in-DB head >= anchored head → no truncation evidence; report={report:?}"
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
            .and_then(|v| v.as_i64()),
        Some(42)
    );
}
