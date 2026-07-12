// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1946 (A1 · decision 5 · `aeb891a4`) — ROLLBACK-EVIDENCE anchor tests.
//!
//! Covers the net-new open-time head check, the OFF-TABLE witness-signed
//! head-anchor log, the `WitnessResolutionWire` v1→v2 additive rollback
//! sub-object, and the operator-signed sanctioned-restore ceremony:
//!
//! - the PURE verdict + refuse-decision fns
//!   (`compute_rollback_verdict` / `rollback_refuse_reason`) — no env, so the
//!   require-mode refuse is tested without the process-global env hazard;
//!   - anchor ABSENT / unpinnable ⇒ WITHHOLD (Unknown), never a false all-clear;
//!   - OFF-TABLE rollback detection: a rollback that ALSO wipes the in-DB
//!     witness checkpoint is STILL caught by the surviving off-table anchor
//!     (`RollbackCheck::Evidence`, `is_clean() == false`, CLI exit 1);
//!   - a valid OPERATOR-signed sanction CLEARS the evidence
//!     (`RollbackCheck::Sanctioned`, back to `is_clean() == true`);
//!   - the open-time check CONTINUES in the default posture (no self-DOS).
//!
//! The witness / operator env vars are process-global, so every test that
//! sets them serialises via a module-local lock and clears the env on exit.

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::governance::audit as witness;
use ai_memory::signed_events::{
    RollbackCheck, SignedEvent, append_signed_event, compute_rollback_verdict,
    force_emit_audit_head_witness, payload_hash, verify_audit_trail,
};
use rusqlite::Connection;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock() -> MutexGuard<'static, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1946-rollback");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn open_db(dir: &std::path::Path) -> (PathBuf, Connection) {
    let path = dir.join("audit.db");
    drop(ai_memory::db::open(&path).expect("init db"));
    let conn = ai_memory::db::open(&path).expect("open db");
    (path, conn)
}

/// Enrol a fresh witness keypair into a temp custody dir + the out-of-band
/// pubkey env (K1 pin). Caller MUST already hold [`lock`].
fn enrol_witness(dir: &std::path::Path) -> ai_memory::identity::keypair::AgentKeypair {
    let kp = ai_memory::identity::keypair::generate(witness::WITNESS_KEY_LABEL).expect("gen");
    ai_memory::identity::keypair::save(&kp, dir).expect("save witness key");
    unsafe {
        std::env::set_var(witness::WITNESS_KEY_DIR_ENV, dir);
        std::env::set_var(witness::WITNESS_PUBKEY_ENV, kp.public_base64());
    }
    kp
}

fn clear_env() {
    unsafe {
        std::env::remove_var(witness::WITNESS_KEY_DIR_ENV);
        std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
        std::env::remove_var(witness::REQUIRE_ROLLBACK_CHECK_ENV);
        std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY");
    }
}

fn append_rows(conn: &Connection, n: usize) {
    for i in 0..n {
        let ev = SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "alice".to_string(),
            event_type: "memory_link.created".to_string(),
            payload_hash: payload_hash(format!("payload-{i}").as_bytes()),
            signature: None,
            attest_level: "unsigned".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..SignedEvent::default()
        };
        append_signed_event(conn, &ev).expect("append");
    }
}

// ── (1) PURE verdict cases — no env, no I/O ─────────────────────────────────

#[test]
fn compute_rollback_verdict_covers_every_arm() {
    // Anchor absent → withhold by default; fail-closed Missing under require.
    assert_eq!(
        compute_rollback_verdict(10, None, false, false),
        RollbackCheck::Unknown
    );
    assert_eq!(
        compute_rollback_verdict(10, None, false, true),
        RollbackCheck::Missing
    );
    // DB head at/above the anchor → no evidence.
    assert_eq!(
        compute_rollback_verdict(10, Some(5), false, false),
        RollbackCheck::NotDetected
    );
    // DB head below the anchor, unsanctioned → evidence.
    assert_eq!(
        compute_rollback_verdict(3, Some(5), false, false),
        RollbackCheck::Evidence {
            anchored_head: 5,
            db_head: 3
        }
    );
    // DB head below the anchor but operator-sanctioned → cleared.
    assert_eq!(
        compute_rollback_verdict(3, Some(5), true, false),
        RollbackCheck::Sanctioned {
            anchored_head: 5,
            db_head: 3
        }
    );
}

// ── (2) PURE refuse decision — require-mode without the global-env hazard ────

#[test]
fn rollback_refuse_reason_only_refuses_under_require() {
    let evidence = RollbackCheck::Evidence {
        anchored_head: 5,
        db_head: 3,
    };
    // Default posture: evidence never refuses (no self-DOS on legit DR).
    assert!(witness::rollback_refuse_reason(&evidence, false).is_none());
    // Require-mode: evidence refuses the open.
    assert!(witness::rollback_refuse_reason(&evidence, true).is_some());
    // Missing is inherently require-mode → always refuses.
    assert!(witness::rollback_refuse_reason(&RollbackCheck::Missing, true).is_some());
    // Clean verdicts never refuse.
    assert!(witness::rollback_refuse_reason(&RollbackCheck::NotDetected, true).is_none());
    assert!(
        witness::rollback_refuse_reason(
            &RollbackCheck::Sanctioned {
                anchored_head: 5,
                db_head: 3
            },
            true
        )
        .is_none()
    );
}

// ── (3) Anchor absent / unpinnable ⇒ WITHHOLD (never a false all-clear) ─────

#[test]
fn anchor_absent_withholds_unknown() {
    let _g = lock();
    let kdir = fresh_dir("absent-keys");
    // Witness custody dir exists but holds NO key + no pubkey enrolled ⇒
    // load_enrolled_witness_pubkey → None ⇒ unpinnable ⇒ high-water None.
    unsafe {
        std::env::set_var(witness::WITNESS_KEY_DIR_ENV, kdir.path());
        std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
    }
    assert_eq!(witness::read_head_anchor_high_water(), None);
    assert_eq!(
        witness::compute_rollback_verdict_for_report(42),
        RollbackCheck::Unknown,
        "no pinnable anchor ⇒ withhold, never a false all-clear"
    );
    clear_env();
}

// ── (4) OFF-TABLE rollback detection survives an in-DB-witness wipe ─────────

#[test]
fn off_table_anchor_catches_rollback_that_also_wiped_the_in_db_witness() {
    let _g = lock();
    let kdir = fresh_dir("evi-keys");
    let ddir = fresh_dir("evi-db");
    let _kp = enrol_witness(kdir.path());
    let (path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    // Deterministic witness of head 5 → writes the in-DB checkpoint AND the
    // OFF-TABLE head-anchor.log (#1946 B).
    force_emit_audit_head_witness(&conn);
    assert!(
        kdir.path().join(witness::HEAD_ANCHOR_LOG_FILENAME).exists(),
        "witness emission must write the off-table head-anchor log"
    );

    // Attacker rolls back the DB FILE: delete the trailing rows AND the in-DB
    // witness checkpoint (so the in-table G5b witness cannot see it).
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");
    conn.execute(
        "DELETE FROM checkpoints WHERE condition_type = 'audit_head_witness'",
        [],
    )
    .expect("delete in-DB witness cp");
    drop(conn);

    // Reopen — the open-time check runs in the DEFAULT posture and CONTINUES
    // (no self-DOS): db::open must succeed.
    let conn = ai_memory::db::open(&path).expect("reopen continues in default posture");
    assert!(
        witness::enforce_rollback_check_at_open(&conn).is_ok(),
        "default posture emits evidence + continues"
    );

    let report = verify_audit_trail(&conn, None).expect("verify");
    // The in-DB witness is GONE (Unknown), but the OFF-TABLE anchor survives
    // and catches the rollback.
    assert_eq!(
        report.rollback,
        RollbackCheck::Evidence {
            anchored_head: 5,
            db_head: 3,
        },
        "off-table anchor catches the rollback; report={report:?}"
    );
    assert!(
        !report.is_clean(),
        "rollback Evidence ⇒ dirty; report={report:?}"
    );
    drop(conn);

    // CLI exit 1.
    let args = ai_memory::cli::verify_audit_trail::VerifyAuditTrailArgs {
        since: None,
        json: false,
    };
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    let code = ai_memory::cli::verify_audit_trail::run(&path, &args, &mut out).expect("cli run");
    assert_eq!(code, 1, "CLI must exit 1 on rollback evidence");

    clear_env();
}

// ── (5) Operator-signed sanction CLEARS the evidence (DR vs attack) ─────────

#[test]
fn operator_sanction_clears_rollback_evidence() {
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let _g = lock();
    let kdir = fresh_dir("sanc-keys");
    let ddir = fresh_dir("sanc-db");
    let _kp = enrol_witness(kdir.path());
    let (path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    force_emit_audit_head_witness(&conn);
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");
    conn.execute(
        "DELETE FROM checkpoints WHERE condition_type = 'audit_head_witness'",
        [],
    )
    .expect("delete in-DB witness cp");
    drop(conn);

    // Before the sanction: evidence.
    assert_eq!(
        witness::compute_rollback_verdict_for_report(3),
        RollbackCheck::Evidence {
            anchored_head: 5,
            db_head: 3
        }
    );

    // Operator ceremony: enrol the operator pubkey (K1 pin for the sanction),
    // sign {old_head=5, new_head=3} and append it to the off-table log.
    let operator = SigningKey::generate(&mut OsRng);
    let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(operator.verifying_key().to_bytes());
    unsafe {
        std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", &pub_b64);
    }
    let line =
        witness::sign_restore_sanction(5, 3, 1_800_000_000, &operator).expect("sign sanction");
    witness::append_restore_sanction(&line).expect("append sanction");

    // After the sanction: cleared (DR restore attested; NOT an attack).
    assert_eq!(
        witness::compute_rollback_verdict_for_report(3),
        RollbackCheck::Sanctioned {
            anchored_head: 5,
            db_head: 3
        },
        "operator signature is the DR-vs-attack discriminator"
    );

    // The reopened DB verifies CLEAN on the rollback axis (witness is Unknown,
    // rollback is Sanctioned — both clean).
    let conn = ai_memory::db::open(&path).expect("reopen");
    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        report.rollback,
        RollbackCheck::Sanctioned {
            anchored_head: 5,
            db_head: 3
        }
    );
    assert!(
        report.is_clean(),
        "sanctioned restore is not dirty; report={report:?}"
    );

    // A FORGED sanction (wrong operator key) must NOT clear: swap the enrolled
    // pubkey to a different key so the recorded signature no longer pins.
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(attacker.verifying_key().to_bytes());
    unsafe {
        std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", &attacker_b64);
    }
    assert_eq!(
        witness::compute_rollback_verdict_for_report(3),
        RollbackCheck::Evidence {
            anchored_head: 5,
            db_head: 3
        },
        "a sanction not signed by the enrolled operator key must NOT clear"
    );

    clear_env();
}
