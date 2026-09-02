// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3354 — the `signed_events` ledger must never be SILENTLY unsigned.
//!
//! **The defect.** `init_forensic_audit` resolves this process's identity and
//! loads a signing key named after THAT id. When none exists,
//! `load_daemon_signing_key` returned `Ok(None)` on a DEBUG-level log,
//! `DAEMON_AUDIT_KEY` was never installed, and `with_daemon_signature` tagged
//! every row `unsigned`. On the reporting host 109,396 of 109,552 rows were
//! unsigned while `doctor` said `signing: ready` (it stat-ed `daemon.pub` /
//! `daemon.priv`, never the resolved id) and BOTH verifiers printed OK/exit 0.
//!
//! **The control under test.** One shared decision fn,
//! [`refuse_unsigned_append_when_required`], called from the sqlite append
//! chokepoint AND the postgres twin, plus the shared
//! [`compute_signature_verdict`] fold that both backends' `verify_audit_trail`
//! routes through. Under `AI_MEMORY_REQUIRE_SIGNED_AUDIT` an unsigned append is
//! REFUSED and an unsigned chain is CONVICTED; by default both are permitted
//! but loud.
//!
//! Every assertion below FAILS against the pre-#3354 code: the append always
//! succeeded and the verdict was always the informational `Unenforced`.

use ai_memory::governance::audit::REQUIRE_SIGNED_AUDIT_ENV;
use ai_memory::signed_events::{
    SignatureCheck, SignedEvent, append_signed_event, compute_signature_verdict, payload_hash,
};
use rusqlite::Connection;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// File-local serialisation for the process-global env mutation, mirroring
/// `tests/audit_witness_truncation_1822.rs`.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock() -> MutexGuard<'static, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn clear_env() {
    unsafe {
        std::env::remove_var(REQUIRE_SIGNED_AUDIT_ENV);
    }
}

fn fresh_db(label: &str) -> (tempfile::TempDir, Connection) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("ai-memory-3354-{label}-"))
        .tempdir()
        .expect("tempdir");
    let db_path = dir.path().join("chain.db");
    drop(ai_memory::db::open(&db_path).expect("init db"));
    let conn = ai_memory::db::open(&db_path).expect("open db");
    (dir, conn)
}

/// Build a row with an EXPLICIT attest level, so the gate is exercised
/// independently of whatever process-wide signer state a sibling test installed
/// (`DAEMON_AUDIT_KEY` is a `OnceLock` — set once per test binary).
fn row(attest: &str, n: u8) -> SignedEvent {
    SignedEvent {
        agent_id: "ai:test-3354".to_string(),
        event_type: "test.event".to_string(),
        payload_hash: payload_hash(&[n]),
        signature: None,
        attest_level: attest.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    }
}

fn head_sequence(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM signed_events",
        [],
        |r| r.get(0),
    )
    .expect("read chain head")
}

const UNSIGNED: &str = "unsigned";
const DAEMON_SIGNED: &str = "daemon_signed";

// ── DENIED ────────────────────────────────────────────────────────────────

/// THE regression. Under require-mode an unsigned append is REFUSED **and the
/// chain head does not move** — the refusal must not half-write a row or
/// consume a sequence number, or the ledger would develop a gap that
/// `verify_audit_trail` reports as a chain break.
#[test]
fn unsigned_append_refused_under_require_mode_leaves_head_unchanged_3354() {
    let _g = lock();
    let (_dir, conn) = fresh_db("denied");
    // Seed one legitimate row so the head is non-zero and a regression that
    // wrote-then-failed would be visible as a moved head.
    append_signed_event(&conn, &row(DAEMON_SIGNED, 1)).expect("seed row appends");
    let before = head_sequence(&conn);
    assert_eq!(before, 1, "seed row must occupy sequence 1");

    unsafe {
        std::env::set_var(REQUIRE_SIGNED_AUDIT_ENV, "1");
    }
    let err = append_signed_event(&conn, &row(UNSIGNED, 2))
        .expect_err("an unsigned append MUST be refused under require-mode");
    let msg = format!("{err:#}");
    clear_env();

    assert!(
        msg.contains("#3354") && msg.contains("UNSIGNED"),
        "refusal must name the control and the condition; got: {msg}"
    );
    assert!(
        msg.contains(REQUIRE_SIGNED_AUDIT_ENV),
        "refusal must name the knob that caused it so it is actionable; got: {msg}"
    );
    assert_eq!(
        head_sequence(&conn),
        before,
        "a REFUSED append must not move the chain head (no gap, no half-write)"
    );
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM signed_events", [], |r| r.get(0))
        .expect("count rows");
    assert_eq!(rows, 1, "the refused row must not be persisted");
}

/// Require-mode refuses regardless of which producer built the row: the gate
/// keys on the row's `attest_level`, not on the call site.
#[test]
fn require_mode_refuses_every_unsigned_producer_3354() {
    let _g = lock();
    let (_dir, conn) = fresh_db("producers");
    unsafe {
        std::env::set_var(REQUIRE_SIGNED_AUDIT_ENV, "1");
    }
    for n in 0..3u8 {
        assert!(
            append_signed_event(&conn, &row(UNSIGNED, n)).is_err(),
            "unsigned row {n} must be refused"
        );
    }
    clear_env();
    assert_eq!(head_sequence(&conn), 0, "nothing may have been written");
}

// ── ALLOWED ───────────────────────────────────────────────────────────────

/// The gate must not be satisfiable by refusing everything: a row that IS
/// attested still appends under require-mode, and the head advances.
#[test]
fn signed_append_still_succeeds_under_require_mode_3354() {
    let _g = lock();
    let (_dir, conn) = fresh_db("allowed-signed");
    unsafe {
        std::env::set_var(REQUIRE_SIGNED_AUDIT_ENV, "1");
    }
    append_signed_event(&conn, &row(DAEMON_SIGNED, 1))
        .expect("a daemon-signed row must still append under require-mode");
    clear_env();
    assert_eq!(head_sequence(&conn), 1, "the signed row must be persisted");
}

/// Default posture is byte-identical to pre-#3354: an unsigned row still
/// appends when the operator has NOT opted in. The silence is closed by the
/// boot WARN / doctor / verifier qualifier, not by dropping audit evidence —
/// refusing by default would destroy the very rows the ledger exists to keep.
#[test]
fn unsigned_append_still_succeeds_by_default_3354() {
    let _g = lock();
    clear_env();
    let (_dir, conn) = fresh_db("allowed-default");
    append_signed_event(&conn, &row(UNSIGNED, 1))
        .expect("without require-mode an unsigned row still appends (legacy posture)");
    assert_eq!(head_sequence(&conn), 1);
}

// ── the SHARED verdict fold (both backends route through this) ────────────

/// `compute_signature_verdict` is called by BOTH `verify_audit_trail`
/// implementations (sqlite `signed_events.rs` and the postgres twin in
/// `store/postgres.rs`), so pinning it here pins the verdict on both backends.
#[test]
fn unsigned_chain_is_convicted_only_under_require_mode_3354() {
    // No pin enrolled + unverified rows + require-mode ⇒ Unsigned (dirty).
    assert_eq!(
        compute_signature_verdict(17, 5, false, true),
        SignatureCheck::Unsigned {
            checked: 17,
            unverified: 12,
        },
        "require-mode must CONVICT an unsigned ledger"
    );
    // Same facts without require-mode ⇒ the historical informational withhold.
    assert_eq!(
        compute_signature_verdict(17, 5, false, false),
        SignatureCheck::Unenforced {
            checked: 17,
            unverified: 12,
        },
        "default posture must stay byte-identical to pre-#3354"
    );
    // Fully-attested chain is never convicted, even under require-mode.
    assert_eq!(
        compute_signature_verdict(17, 17, false, true),
        SignatureCheck::Unenforced {
            checked: 17,
            unverified: 0,
        },
        "a chain with nothing unverified is not an unsigned ledger"
    );
    // A pin enrolled keeps the pre-existing Verified / Unverified split.
    assert_eq!(
        compute_signature_verdict(3, 3, true, true),
        SignatureCheck::Verified { checked: 3 }
    );
    assert_eq!(
        compute_signature_verdict(3, 1, true, false),
        SignatureCheck::Unverified {
            checked: 3,
            unverified: 2,
        }
    );
}
