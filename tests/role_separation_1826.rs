// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G9 (#1826) — three-key Recorder / Judge / Stopper signing-layer
//! SEPARATION teeth tests.
//!
//! Proves the additive/opt-in signing-layer separation of the three governance
//! roles: the RECORDER row signature (domain-separated, per-row-pinned), the
//! JUDGE `governance_verdict` checkpoint pin, and the STOPPER
//! `governance_enforcement` checkpoint pin. The role keys are held BY THE TEST
//! (fresh keypairs + the out-of-band pubkey envs), so the pins catch a
//! wrong-key forgery rather than a verbatim-reused verify.
//!
//! Coverage (accepted-design conditions C1-C7 + §26.5 cross-role gate):
//! - `legacy_bytes_unchanged_without_role_keys` — AC1 opt-in: no role keys →
//!   the governance row is NOT `recorder_signed` and NO judge checkpoint is
//!   emitted (byte-identical legacy emission);
//! - `recorder_row_pins` — a valid recorder row is clean; a wrong-preimage one
//!   is `Forged`;
//! - `judge_verdict_checkpoint_pins` / `stopper_enforcement_checkpoint_pins` —
//!   K1 pin of the judge/stopper anchors;
//! - `cross_role_forgery_is_rejected` — the §26.5 gate: all FOUR legs `Forged`;
//! - `require_role_separation_fails_closed` — require-mode `Missing`;
//! - `domain_separation_holds` — a recorder-domain signature ≠ a bare
//!   `payload_hash` signature (C1 domain fold);
//! - `daemon_signed_row_rejected_post_recorder_enrollment` — C2 demotion;
//! - `same_pubkey_two_roles_rejected` — C3 pairwise-distinctness;
//! - `recorder_key_alone_allow_for_refused_scope` — C4 (allow verdicts are
//!   judge-attested too; the strict row-level join is documented out-of-scope);
//! - `recorder_signed_rows_skipped_without_recorder_pubkey` — C6 withhold;
//! - `backend_parity_role_separation` — C7 postgres parity (live-gated).
//!
//! The role key-dir / pubkey / require env vars are process-global, so every
//! test serialises via a module-local lock and clears the env on exit.

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::governance::agent_action::{AgentAction, GOVERNANCE_CHECK_EVENT_TYPE};
use ai_memory::governance::audit as roles;
use ai_memory::identity::keypair::{AgentKeypair, generate};
use ai_memory::signed_events::{
    RoleSeparationCheck, SignedEvent, append_signed_event, payload_hash, verify_audit_trail,
};
use ed25519_dalek::Signer;
use rusqlite::Connection;

/// Process-global serialisation for the role ENV + statics.
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
        .join("issue-1826-role-separation");
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

fn clear_role_env() {
    unsafe {
        for v in [
            roles::RECORDER_PUBKEY_ENV,
            roles::RECORDER_KEY_DIR_ENV,
            roles::JUDGE_PUBKEY_ENV,
            roles::JUDGE_KEY_DIR_ENV,
            roles::STOPPER_PUBKEY_ENV,
            roles::STOPPER_KEY_DIR_ENV,
            roles::REQUIRE_ROLE_SEPARATION_ENV,
        ] {
            std::env::remove_var(v);
        }
    }
}

fn enrol_pubkey(env: &str, kp: &AgentKeypair) {
    unsafe { std::env::set_var(env, kp.public_base64()) }
}

fn sign_with(kp: &AgentKeypair, msg: &[u8]) -> Vec<u8> {
    kp.private
        .as_ref()
        .expect("signing key present")
        .sign(msg)
        .to_bytes()
        .to_vec()
}

/// The RECORDER domain preimage for a no-cause row: `DOMAIN_RECORDER || ph`.
fn recorder_preimage(ph: &[u8]) -> Vec<u8> {
    let mut p = roles::DOMAIN_RECORDER.to_vec();
    p.extend_from_slice(ph);
    p
}

/// Build a `recorder_signed` governance row whose signature is over `signable`
/// (pass `recorder_preimage(ph)` for a VALID row, or a wrong buffer to forge).
fn recorder_row(kp: &AgentKeypair, payload: &[u8], signable: &[u8]) -> SignedEvent {
    SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "agent:test".to_string(),
        event_type: GOVERNANCE_CHECK_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(payload),
        signature: Some(sign_with(kp, signable)),
        attest_level: "recorder_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    }
}

fn daemon_governance_row(payload: &[u8]) -> SignedEvent {
    SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "agent:test".to_string(),
        event_type: GOVERNANCE_CHECK_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(payload),
        // A daemon-class signature blob (shape-valid but never recorder-domain).
        signature: Some(vec![7u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    }
}

// ── AC1: opt-in — no role keys ⇒ legacy emission bytes unchanged ──

#[test]
fn legacy_bytes_unchanged_without_role_keys() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("ac1-db");
    let (_path, conn) = open_db(ddir.path());

    // No role keys enrolled → the governance.check row must NOT be
    // recorder_signed, and NO judge verdict checkpoint may be emitted.
    let action = AgentAction::Bash {
        command: "echo hi".to_string(),
        cwd: None,
    };
    let _ = ai_memory::governance::agent_action::check_agent_action(&conn, "agent:test", &action)
        .expect("check");

    let attest: String = conn
        .query_row(
            "SELECT attest_level FROM signed_events WHERE event_type = ?1 LIMIT 1",
            rusqlite::params![GOVERNANCE_CHECK_EVENT_TYPE],
            |r| r.get(0),
        )
        .expect("row present");
    assert_ne!(
        attest, "recorder_signed",
        "no recorder key ⇒ row must fall back to legacy attest_level, got {attest}"
    );

    let verdicts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM checkpoints WHERE condition_type = 'governance_verdict'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        verdicts, 0,
        "no judge key ⇒ no governance_verdict checkpoint (opt-in emission)"
    );

    // And the report withholds (Unknown) — byte-identical clean verdict.
    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(report.role_separation, RoleSeparationCheck::Unknown);
    assert!(report.is_clean(), "unconfigured ⇒ clean; report={report:?}");
    clear_role_env();
}

// ── recorder row pins ──

#[test]
fn recorder_row_pins() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("rec-db");
    let (_path, conn) = open_db(ddir.path());
    let recorder = generate(roles::RECORDER_KEY_LABEL).expect("gen recorder");
    enrol_pubkey(roles::RECORDER_PUBKEY_ENV, &recorder);

    let ph = payload_hash(b"good");
    let good = recorder_row(&recorder, b"good", &recorder_preimage(&ph));
    append_signed_event(&conn, &good).expect("append good");

    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        report.role_separation,
        RoleSeparationCheck::NotDetected,
        "a valid recorder row over the domain preimage verifies clean; report={report:?}"
    );
    assert!(report.is_clean());

    // A recorder row whose signature is over the BARE payload_hash (no domain)
    // must be rejected — proves the per-row pin + the domain fold (C1).
    let bad = recorder_row(&recorder, b"bad", &payload_hash(b"bad"));
    append_signed_event(&conn, &bad).expect("append bad");
    let report = verify_audit_trail(&conn, None).expect("verify");
    assert!(
        matches!(report.role_separation, RoleSeparationCheck::Forged { .. }),
        "a wrong-preimage recorder row ⇒ Forged; report={report:?}"
    );
    assert!(!report.is_clean());
    clear_role_env();
}

#[test]
fn domain_separation_holds() {
    let _g = lock();
    // A recorder-domain signature and a bare payload_hash signature by the SAME
    // key over the SAME payload are DIFFERENT byte strings (C1 domain fold).
    let recorder = generate(roles::RECORDER_KEY_LABEL).expect("gen");
    let ph = payload_hash(b"same-payload");
    let domain_sig = sign_with(&recorder, &recorder_preimage(&ph));
    let bare_sig = sign_with(&recorder, &ph);
    assert_ne!(
        domain_sig, bare_sig,
        "the DOMAIN_RECORDER prefix must change the signed preimage (no cross-domain replay)"
    );
}

// ── judge / stopper checkpoint pins ──

#[test]
fn judge_verdict_checkpoint_pins() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("judge-db");
    let (_path, conn) = open_db(ddir.path());
    let judge = generate(roles::JUDGE_KEY_LABEL).expect("gen judge");
    enrol_pubkey(roles::JUDGE_PUBKEY_ENV, &judge);

    let now = chrono::Utc::now().timestamp();
    let cp = roles::build_signed_verdict_checkpoint(
        "agent:test",
        "bash",
        "abcd",
        "allow",
        "",
        "",
        now,
        &judge,
    )
    .expect("build verdict cp");
    ai_memory::checkpoints::insert(&conn, &cp).expect("insert verdict cp");

    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        report.role_separation,
        RoleSeparationCheck::NotDetected,
        "pinned + valid judge verdict ⇒ clean; report={report:?}"
    );

    // Wrong-key judge anchor ⇒ K1 pin failure ⇒ Forged.
    let attacker = generate("attacker").expect("gen");
    let forged = roles::build_signed_verdict_checkpoint(
        "agent:test",
        "bash",
        "abcd",
        "allow",
        "",
        "",
        now + 5,
        &attacker,
    )
    .expect("build forged cp");
    ai_memory::checkpoints::insert(&conn, &forged).expect("insert forged cp");
    let report = verify_audit_trail(&conn, None).expect("verify");
    assert!(
        matches!(report.role_separation, RoleSeparationCheck::Forged { .. }),
        "wrong-key judge anchor ⇒ Forged; report={report:?}"
    );
    assert!(!report.is_clean());
    clear_role_env();
}

#[test]
fn stopper_enforcement_checkpoint_pins() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("stop-db");
    let (_path, conn) = open_db(ddir.path());
    let stopper = generate(roles::STOPPER_KEY_LABEL).expect("gen stopper");
    enrol_pubkey(roles::STOPPER_PUBKEY_ENV, &stopper);

    let now = chrono::Utc::now().timestamp();
    let cp = roles::build_signed_enforcement_checkpoint(
        "agent:test",
        "bash",
        "abcd",
        "deny",
        "R001",
        "blocked",
        now,
        &stopper,
    )
    .expect("build enforcement cp");
    ai_memory::checkpoints::insert(&conn, &cp).expect("insert enforcement cp");

    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        report.role_separation,
        RoleSeparationCheck::NotDetected,
        "pinned + valid stopper enforcement ⇒ clean; report={report:?}"
    );

    let attacker = generate("attacker").expect("gen");
    let forged = roles::build_signed_enforcement_checkpoint(
        "agent:test",
        "bash",
        "abcd",
        "deny",
        "R001",
        "blocked",
        now + 5,
        &attacker,
    )
    .expect("build forged cp");
    ai_memory::checkpoints::insert(&conn, &forged).expect("insert forged cp");
    let report = verify_audit_trail(&conn, None).expect("verify");
    assert!(
        matches!(report.role_separation, RoleSeparationCheck::Forged { .. }),
        "wrong-key stopper anchor ⇒ Forged; report={report:?}"
    );
    clear_role_env();
}

// ── §26.5 gate: cross-role forgery — all four legs Forged ──

#[test]
fn cross_role_forgery_is_rejected() {
    let _g = lock();

    // Leg 1 — a recorder row signed by the JUDGE key, verified vs the enrolled
    // RECORDER pubkey (different) ⇒ Forged (a judge key cannot forge a recorder
    // row).
    {
        clear_role_env();
        let ddir = fresh_dir("x1-db");
        let (_p, conn) = open_db(ddir.path());
        let recorder = generate(roles::RECORDER_KEY_LABEL).expect("gen");
        let judge = generate(roles::JUDGE_KEY_LABEL).expect("gen");
        enrol_pubkey(roles::RECORDER_PUBKEY_ENV, &recorder);
        let ph = payload_hash(b"leg1");
        // Judge signs the recorder domain preimage — still the WRONG key.
        let row = recorder_row(&judge, b"leg1", &recorder_preimage(&ph));
        append_signed_event(&conn, &row).expect("append");
        let r = verify_audit_trail(&conn, None).expect("verify");
        assert!(
            matches!(r.role_separation, RoleSeparationCheck::Forged { .. }),
            "leg1 (judge forging recorder) must be Forged; r={r:?}"
        );
    }

    // Leg 2 — a judge verdict anchor signed by the STOPPER key ⇒ pin Forged.
    {
        clear_role_env();
        let ddir = fresh_dir("x2-db");
        let (_p, conn) = open_db(ddir.path());
        let judge = generate(roles::JUDGE_KEY_LABEL).expect("gen");
        let stopper = generate(roles::STOPPER_KEY_LABEL).expect("gen");
        enrol_pubkey(roles::JUDGE_PUBKEY_ENV, &judge);
        let cp = roles::build_signed_verdict_checkpoint(
            "a",
            "bash",
            "h",
            "refuse",
            "R",
            "x",
            chrono::Utc::now().timestamp(),
            &stopper,
        )
        .expect("cp");
        ai_memory::checkpoints::insert(&conn, &cp).expect("insert");
        let r = verify_audit_trail(&conn, None).expect("verify");
        assert!(
            matches!(r.role_separation, RoleSeparationCheck::Forged { .. }),
            "leg2 (stopper forging judge) must be Forged; r={r:?}"
        );
    }

    // Leg 3 — a stopper enforcement anchor signed by the RECORDER key ⇒ Forged.
    {
        clear_role_env();
        let ddir = fresh_dir("x3-db");
        let (_p, conn) = open_db(ddir.path());
        let recorder = generate(roles::RECORDER_KEY_LABEL).expect("gen");
        let stopper = generate(roles::STOPPER_KEY_LABEL).expect("gen");
        enrol_pubkey(roles::STOPPER_PUBKEY_ENV, &stopper);
        let cp = roles::build_signed_enforcement_checkpoint(
            "a",
            "bash",
            "h",
            "deny",
            "R",
            "x",
            chrono::Utc::now().timestamp(),
            &recorder,
        )
        .expect("cp");
        ai_memory::checkpoints::insert(&conn, &cp).expect("insert");
        let r = verify_audit_trail(&conn, None).expect("verify");
        assert!(
            matches!(r.role_separation, RoleSeparationCheck::Forged { .. }),
            "leg3 (recorder forging stopper) must be Forged; r={r:?}"
        );
    }

    // Leg 4 — a daemon-signed governance row survives recorder enrollment ⇒
    // demoted to Forged (C2).
    {
        clear_role_env();
        let ddir = fresh_dir("x4-db");
        let (_p, conn) = open_db(ddir.path());
        let recorder = generate(roles::RECORDER_KEY_LABEL).expect("gen");
        enrol_pubkey(roles::RECORDER_PUBKEY_ENV, &recorder);
        append_signed_event(&conn, &daemon_governance_row(b"leg4")).expect("append");
        let r = verify_audit_trail(&conn, None).expect("verify");
        assert!(
            matches!(r.role_separation, RoleSeparationCheck::Forged { .. }),
            "leg4 (daemon governance row post recorder-enroll) must be Forged; r={r:?}"
        );
    }
    clear_role_env();
}

// ── C2: daemon_signed governance row rejected once a recorder is enrolled ──

#[test]
fn daemon_signed_row_rejected_post_recorder_enrollment() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("c2-db");
    let (_p, conn) = open_db(ddir.path());
    append_signed_event(&conn, &daemon_governance_row(b"c2")).expect("append");

    // Before recorder enrollment: no role keys ⇒ withheld/clean.
    let r = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(r.role_separation, RoleSeparationCheck::Unknown);
    assert!(
        r.is_clean(),
        "pre-enrollment daemon row is legacy-clean; r={r:?}"
    );

    // After recorder enrollment: the daemon governance row is demoted ⇒ Forged.
    let recorder = generate(roles::RECORDER_KEY_LABEL).expect("gen");
    enrol_pubkey(roles::RECORDER_PUBKEY_ENV, &recorder);
    let r = verify_audit_trail(&conn, None).expect("verify");
    assert!(
        matches!(r.role_separation, RoleSeparationCheck::Forged { .. }),
        "C2 demotion ⇒ Forged; r={r:?}"
    );
    assert!(!r.is_clean());
    clear_role_env();
}

// ── C3: two roles sharing one pubkey ⇒ Misconfigured ──

#[test]
fn same_pubkey_two_roles_rejected() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("c3-db");
    let (_p, conn) = open_db(ddir.path());
    // Enroll the SAME pubkey for judge AND stopper.
    let shared = generate("shared").expect("gen");
    enrol_pubkey(roles::JUDGE_PUBKEY_ENV, &shared);
    enrol_pubkey(roles::STOPPER_PUBKEY_ENV, &shared);

    let r = verify_audit_trail(&conn, None).expect("verify");
    assert!(
        matches!(r.role_separation, RoleSeparationCheck::Misconfigured { .. }),
        "C3: non-pairwise-distinct role pubkeys ⇒ Misconfigured; r={r:?}"
    );
    assert!(!r.is_clean());
    clear_role_env();
}

// ── C4: allow verdicts are judge-attested too (favorable-allow laundering) ──

#[test]
fn recorder_key_alone_allow_for_refused_scope() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("c4-db");
    let (_p, conn) = open_db(ddir.path());
    // C4 closes favorable-allow laundering by emitting a judge GovernanceVerdict
    // on EVERY verdict, INCLUDING allow — so a served allow is judge-attested,
    // not silently unattested. Assert an `allow` verdict anchor pins clean.
    // (The strict recorder-row↔judge action_hash JOIN is documented
    // out-of-scope: the recorder row commits to sha256({action,decision}) while
    // the judge anchor commits to sha256(action) for external forensic join.)
    let judge = generate(roles::JUDGE_KEY_LABEL).expect("gen");
    enrol_pubkey(roles::JUDGE_PUBKEY_ENV, &judge);
    let action_hash = roles::action_hash_hex(b"{\"kind\":\"bash\",\"command\":\"ls\"}");
    let cp = roles::build_signed_verdict_checkpoint(
        "agent:test",
        "bash",
        &action_hash,
        "allow",
        "",
        "",
        chrono::Utc::now().timestamp(),
        &judge,
    )
    .expect("cp");
    ai_memory::checkpoints::insert(&conn, &cp).expect("insert");
    let r = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        r.role_separation,
        RoleSeparationCheck::NotDetected,
        "an allow verdict is judge-attested + pins clean; r={r:?}"
    );
    clear_role_env();
}

// ── C6: recorder rows skipped (not false-failed) when no recorder pubkey ──

#[test]
fn recorder_signed_rows_skipped_without_recorder_pubkey() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("c6-db");
    let (_p, conn) = open_db(ddir.path());
    // A recorder_signed row exists but NO recorder pubkey is enrolled: the
    // daemon verifier must NOT false-fail it.
    let orphan = generate(roles::RECORDER_KEY_LABEL).expect("gen");
    let ph = payload_hash(b"c6");
    let row = recorder_row(&orphan, b"c6", &recorder_preimage(&ph));
    append_signed_event(&conn, &row).expect("append");

    let r = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        r.role_separation,
        RoleSeparationCheck::Unknown,
        "C6: no recorder pubkey ⇒ withhold (not Forged); r={r:?}"
    );
    assert!(
        r.signature_failures.is_empty(),
        "C6: a recorder row must NOT be counted as a daemon signature failure; r={r:?}"
    );
    assert!(r.is_clean(), "C6: withheld ⇒ clean; r={r:?}");
    clear_role_env();
}

// ── K2: require-mode fails closed with no enrolled role separation ──

#[test]
fn require_role_separation_fails_closed() {
    let _g = lock();
    clear_role_env();
    let ddir = fresh_dir("req-db");
    let (_p, conn) = open_db(ddir.path());
    unsafe { std::env::set_var(roles::REQUIRE_ROLE_SEPARATION_ENV, "1") }

    let r = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        r.role_separation,
        RoleSeparationCheck::Missing,
        "require-mode + no role keys ⇒ Missing (fail-closed); r={r:?}"
    );
    assert!(!r.is_clean());
    clear_role_env();
}

// ── C7: postgres parity (live-gated) ──

#[cfg(feature = "sal-postgres")]
mod postgres_parity {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: postgres connect failed: {e}");
                None
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn backend_parity_role_separation() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let recorder = generate(roles::RECORDER_KEY_LABEL).expect("gen");
        enrol_pubkey(roles::RECORDER_PUBKEY_ENV, &recorder);

        // Insert a FORGED recorder row (signature over the bare payload_hash, no
        // domain) directly into pg. The pg verify twin's from-scratch per-row
        // recorder verification (C7) must catch it identically to sqlite.
        let id = uuid::Uuid::new_v4().to_string();
        let agent = format!("ai:1826-{}", uuid::Uuid::new_v4());
        let ph = payload_hash(b"pg-forged");
        let ts = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                 prev_hash, sequence, cause_hash) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&id)
        .bind(&agent)
        .bind(GOVERNANCE_CHECK_EVENT_TYPE)
        .bind(ph.clone())
        .bind(Some(sign_with(&recorder, &ph))) // WRONG preimage (no domain)
        .bind("recorder_signed")
        .bind(ts)
        .bind(ai_memory::signed_events::ZERO_HASH.to_vec())
        .bind(1_i64)
        .bind(Option::<Vec<u8>>::None)
        .execute(pg.pool())
        .await
        .expect("insert pg recorder row");

        let report = pg.verify_audit_trail(None).await.expect("pg verify");
        assert!(
            matches!(report.role_separation, RoleSeparationCheck::Forged { .. }),
            "pg verify twin must catch the forged recorder row (C7 parity); report={report:?}"
        );
        assert!(!report.is_clean());

        sqlx::query("DELETE FROM signed_events WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await
            .ok();
        clear_role_env();
    }
}
