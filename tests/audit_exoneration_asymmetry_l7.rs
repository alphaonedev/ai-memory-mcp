// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 L7 (PR-4, forensic-audit-trail wave) — the audit-trail verifier's
//! EXONERATION-asymmetry rule: it must STOP EXONERATING on an UNAUTHENTICATED
//! forensic watermark while still CONVICTING on it.
//!
//! Context: `verify_audit_trail`'s off-table watermark feeds BOTH directions —
//! `TruncationCheck::{Detected,NotDetected}` and the forensic-watermark
//! `HeadHashCheck::{Mismatch,NotDetected}`. On an UNSIGNED daemon (a hostile
//! host that strips the daemon signature) the watermark is unauthenticated, so
//! trusting it to render `NotDetected` / a clean bill of health is a forged
//! all-clear. The L7 control (the
//! [`ai_memory::governance::audit::audit_watermark_exoneration_authenticated`]
//! guard plus the pure
//! [`ai_memory::signed_events::exoneration_gated_head_hash`]) gates ONLY the
//! exonerating direction on an out-of-band-pinned, signature+chain
//! authenticated watermark, while the convicting direction keeps reading the
//! raw unauthenticated anchor.
//!
//! Pins:
//!
//! - `(auth)` pin enrolled + watermark signed by the pin + clean chain →
//!   `NotDetected` (the control does NOT over-withhold).
//! - `(withhold)` pin enrolled + UNSIGNED watermark + clean chain → `Unknown`
//!   (BOTH lanes withheld). This is the §5.4.5 removal-proof lane test:
//!   mutating the guard to `return true` flips it to `NotDetected` (RED).
//! - `(convict1)` pin enrolled + UNSIGNED watermark + truncated DB →
//!   `Detected` (a stripped signature can NEVER suppress a truncation
//!   conviction).
//! - `(convict2)` pin enrolled + UNSIGNED watermark + same-length head rewrite
//!   → `Mismatch` (conviction survives on unauthenticated evidence).
//! - `(legacy)` NO pin + UNSIGNED watermark + clean chain → `NotDetected`
//!   (enrollment-gated: with no authority the pre-L7 trust-the-anchor
//!   behaviour is byte-preserved — the `audit_truncation_anchor_1850`
//!   acceptance posture).
//!
//! The forensic sink is process-global, so these tests serialise via a
//! module-local lock (the `audit_truncation_anchor_1850` discipline).

#![allow(clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ai_memory::governance::audit as forensic;
use ai_memory::signed_events::{
    HeadHashCheck, SignedEvent, TruncationCheck, append_signed_event, canonical_chain_bytes,
    payload_hash, verify_audit_trail,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
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
        .join("l7-exoneration-asymmetry")
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

/// Recompute the surviving head row's canonical hash EXACTLY as the verifier
/// does and anchor that REAL hash into the off-table forensic watermark
/// (mirrors `audit_truncation_anchor_1850::anchor_real_head`). Returns the head
/// sequence. Signs with whatever key `forensic::init` installed on the sink.
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
    forensic::record_audit_watermark(seq, &hash_hex, None);
    forensic::flush_blocking();
    seq
}

fn fresh_pin() -> (SigningKey, VerifyingKey) {
    let key = SigningKey::generate(&mut OsRng);
    let vk = key.verifying_key();
    (key, vk)
}

// -----------------------------------------------------------------
// (auth) pin + SIGNED watermark + clean chain → NotDetected.
// Proves the control does NOT over-withhold: an authenticated anchor still
// exonerates. The sink is signed by the SAME key the pin verifies against.
// -----------------------------------------------------------------

#[test]
fn authenticated_watermark_under_pin_exonerates_l7() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("auth-forensic");
    let ddir = fresh_dir("auth-db");
    let (sink_key, pin) = fresh_pin();
    // The forensic sink signs its watermark rows with `sink_key`; the verifier
    // is handed `pin` = its public half → the watermark AUTHENTICATES.
    forensic::init(fdir.path(), Some(sink_key)).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    anchor_real_head(&conn);

    let report = verify_audit_trail(&conn, None, Some(&pin)).expect("verify");
    assert_eq!(report.head_sequence, 5);
    assert_eq!(
        report.truncation,
        TruncationCheck::NotDetected,
        "an AUTHENTICATED watermark (signed by the pinned key) must still \
         exonerate the truncation lane; report={report:?}"
    );
    assert_eq!(
        report.head_hash,
        HeadHashCheck::NotDetected,
        "an AUTHENTICATED watermark must still exonerate the head-hash lane; \
         report={report:?}"
    );

    forensic::shutdown();
}

// -----------------------------------------------------------------
// (withhold) pin + UNSIGNED watermark + clean chain → Unknown (BOTH lanes).
// §5.4.5 REMOVAL-PROOF LANE TEST — registered in check-cert-removal-proof.sh.
// Mutating `audit_watermark_exoneration_authenticated` to `return true` flips
// both verdicts to NotDetected → this test goes RED.
// -----------------------------------------------------------------

#[test]
fn unauthenticated_watermark_under_pin_withholds_exoneration_l7() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("withhold-forensic");
    let ddir = fresh_dir("withhold-db");
    let (_unused_key, pin) = fresh_pin();
    // Sink is UNSIGNED (None) → the watermark row carries no signature, so it
    // cannot authenticate against the enrolled `pin`.
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    // Anchor the REAL head hash: the DB is CLEAN, so a watermark-trusting
    // verifier WOULD render NotDetected on both lanes — the exact forged
    // all-clear the L7 control refuses on unauthenticated evidence.
    anchor_real_head(&conn);

    let report = verify_audit_trail(&conn, None, Some(&pin)).expect("verify");
    assert_eq!(report.head_sequence, 5);
    assert_eq!(
        report.truncation,
        TruncationCheck::Unknown,
        "a pin is enrolled but the watermark is UNAUTHENTICATED — the \
         truncation lane must WITHHOLD (Unknown), never exonerate on \
         unauthenticated evidence; report={report:?}"
    );
    assert_eq!(
        report.head_hash,
        HeadHashCheck::Unknown,
        "a pin is enrolled but the watermark is UNAUTHENTICATED — the \
         head-hash lane must WITHHOLD (Unknown), never render a clean \
         head-hash bill of health; report={report:?}"
    );

    forensic::shutdown();
}

// -----------------------------------------------------------------
// (convict1) pin + UNSIGNED watermark + truncated DB → Detected.
// A stripped signature must NEVER suppress a truncation conviction.
// -----------------------------------------------------------------

#[test]
fn unauthenticated_watermark_still_convicts_truncation_l7() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("convict1-forensic");
    let ddir = fresh_dir("convict1-db");
    let (_unused_key, pin) = fresh_pin();
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    forensic::record_audit_watermark(5, "anchor-hash-head-5", None);
    forensic::flush_blocking();

    // Truncate the trailing two rows — surviving 1..=3 stays contiguous.
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");

    let report = verify_audit_trail(&conn, None, Some(&pin)).expect("verify");
    assert_eq!(
        report.truncation,
        TruncationCheck::Detected {
            anchored_head: 5,
            db_head: 3,
        },
        "conviction must fire on the UNAUTHENTICATED anchor — the L7 asymmetry \
         gates only the exonerating direction; report={report:?}"
    );
    assert!(
        !report.is_clean(),
        "a detected truncation is NOT clean regardless of authentication; \
         report={report:?}"
    );

    forensic::shutdown();
}

// -----------------------------------------------------------------
// (convict2) pin + UNSIGNED watermark + same-length head rewrite → Mismatch.
// The head-hash conviction survives on unauthenticated evidence too.
// -----------------------------------------------------------------

#[test]
fn unauthenticated_watermark_still_convicts_head_rewrite_l7() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("convict2-forensic");
    let ddir = fresh_dir("convict2-db");
    let (_unused_key, pin) = fresh_pin();
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    let head_seq = anchor_real_head(&conn);

    // SAME-LENGTH rewrite of the head row's payload_hash — chain stays intact,
    // seq-only truncation reads clean, only the head-hash anchor catches it.
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        params![vec![0xFFu8; 32], head_seq],
    )
    .expect("rewrite head payload in place");

    let report = verify_audit_trail(&conn, None, Some(&pin)).expect("verify");
    assert_eq!(
        report.truncation,
        TruncationCheck::Unknown,
        "the seq-only truncation lane cannot see a same-length rewrite, and the \
         UNAUTHENTICATED anchor cannot exonerate it → Unknown; report={report:?}"
    );
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "signed_events"),
        other => panic!(
            "head-hash conviction must fire on the UNAUTHENTICATED anchor, \
             got {other:?}; report={report:?}"
        ),
    }
    assert!(
        !report.is_clean(),
        "a head-hash mismatch is NOT clean regardless of authentication; \
         report={report:?}"
    );

    forensic::shutdown();
}

// -----------------------------------------------------------------
// (legacy) NO pin + UNSIGNED watermark + clean chain → NotDetected.
// Enrollment-gated: with no out-of-band authority the pre-L7 trust-the-anchor
// behaviour is byte-preserved (the audit_truncation_anchor_1850 posture).
// -----------------------------------------------------------------

#[test]
fn no_pin_preserves_legacy_exoneration_l7() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("legacy-forensic");
    let ddir = fresh_dir("legacy-db");
    forensic::init(fdir.path(), None).expect("forensic init");

    let (_path, conn) = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    anchor_real_head(&conn);

    // No pin threaded (`None`) → the asymmetry does not engage; an unsigned
    // watermark on a clean chain exonerates exactly as it did pre-L7.
    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(
        report.truncation,
        TruncationCheck::NotDetected,
        "no pin → legacy trust-the-anchor exoneration preserved; report={report:?}"
    );
    assert_eq!(
        report.head_hash,
        HeadHashCheck::NotDetected,
        "no pin → legacy head-hash exoneration preserved; report={report:?}"
    );
    assert!(
        report.is_clean(),
        "no pin + clean chain + matching anchor is a clean all-clear; report={report:?}"
    );

    forensic::shutdown();
}
