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
//! v1.0.0 #2370 (2x3 vote `9e369e74` + `4d3ea1c5`) — PER-DATABASE anchor
//! scoping via the signed v3 `db_id`:
//!
//! - two DBs sharing one witness mount never cross-contaminate Evidence
//!   (both directions), and a sibling with no anchor history opens clean
//!   (`RollbackCheck::NotApplicable`) even under require-mode;
//! - a fresh/empty-chain opener bootstraps clean under require-mode ONLY
//!   when the anchor log has NO pinned lines; against a pinned-line log a
//!   head-0 opener stays Evidence (the wipe-to-empty regression guard);
//! - genuine same-DB rollback is STILL Evidence and refuses under require;
//! - legacy id-less v1/v2 anchor lines count CONSERVATIVELY for every
//!   opener (one-release window — over-detect, never suppress);
//! - a db_id-bound operator sanction clears ONLY its own database (the
//!   cross-DB integer-collision replay hole), a legacy id-less sanction
//!   still clears for one release;
//! - emission binds the genesis `db_id` on BOTH backends (sqlite here; the
//!   `#[ignore]` live-postgres twin below).
//!
//! v1.0.0 #2942 (5-agent vote, #3089 Vote A) — asi-hard COLD-BOOT read-time
//! carve-out:
//!
//! - a brand-new asi-hard node whose witness pin is NOT YET enrolled
//!   (`AnchorScan::Unpinnable`) and that has NO surviving off-table head anchor
//!   BOOTS CLEAN under require-mode (so it can run its own witness-enrollment
//!   ceremony — the cold-boot chicken-and-egg), while a wiped node (head-0 /
//!   genesis-less, pin stripped) with a SURVIVING off-table anchor stays
//!   fail-closed (`Missing`) and refuses the open. No genesis row is minted on
//!   first open (the witness-mount write-authority invariant is preserved).
//!
//! The witness / operator env vars are process-global, so every test that
//! sets them serialises via a module-local lock and clears the env on exit.

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::governance::audit as witness;
use ai_memory::signed_events::{
    RollbackCheck, SignedEvent, append_signed_event, compute_rollback_verdict,
    db_id_from_genesis_parts, force_emit_audit_head_witness, genesis_db_id, payload_hash,
    verify_audit_trail,
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

/// This database's genesis-derived id (#2370) — `expect`s a non-empty chain.
fn db_id_of(conn: &Connection) -> String {
    genesis_db_id(conn)
        .expect("read genesis db-id")
        .expect("non-empty chain has a genesis db-id")
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
    // #2370 — NotApplicable (no anchor history for THIS database) never
    // refuses, even under require-mode: the second-healthy-DB boot-DoS fix.
    assert!(witness::rollback_refuse_reason(&RollbackCheck::NotApplicable, true).is_none());
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
    assert_eq!(witness::read_head_anchor_high_water(None), None);
    assert_eq!(
        witness::compute_rollback_verdict_for_report(42, None),
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

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    // The in-DB witness is GONE (Unknown), but the OFF-TABLE anchor survives
    // and catches the rollback — #2370: the anchor is a v3 db_id line for
    // THIS database (genesis intact), so per-DB filtering keeps it counted.
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
        store_url: None,
        audit_pubkey: None,
    };
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    let code =
        ai_memory::cli::verify_audit_trail::run(&path, &args, None, &mut out).expect("cli run");
    assert_eq!(code, 1, "CLI must exit 1 on rollback evidence");

    // #2370 matrix (3) — under REQUIRE-MODE the SAME genuine same-DB rollback
    // still refuses the open (the per-DB filter must never suppress it).
    unsafe {
        std::env::set_var(witness::REQUIRE_ROLLBACK_CHECK_ENV, "1");
    }
    assert!(
        ai_memory::db::open(&path).is_err(),
        "require-mode refuses the open on genuine same-DB rollback evidence"
    );

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
    let db_id = db_id_of(&conn);
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
        witness::compute_rollback_verdict_for_report(3, Some(&db_id)),
        RollbackCheck::Evidence {
            anchored_head: 5,
            db_head: 3
        }
    );

    // Operator ceremony: enrol the operator pubkey (K1 pin for the sanction),
    // sign {old_head=5, new_head=3, db_id} and append it to the off-table log.
    let operator = SigningKey::generate(&mut OsRng);
    let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(operator.verifying_key().to_bytes());
    unsafe {
        std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", &pub_b64);
    }

    // #2370 — a sanction bound to a DIFFERENT database (same integers — the
    // cross-DB replay shape) must NOT clear this database's evidence.
    let alien_id = db_id_from_genesis_parts("alien-genesis", "ai:alien", &[0x42; 32]);
    let alien_line =
        witness::sign_restore_sanction(5, 3, 1_800_000_000, &operator, Some(&alien_id))
            .expect("sign alien sanction");
    witness::append_restore_sanction(&alien_line).expect("append alien sanction");
    assert_eq!(
        witness::compute_rollback_verdict_for_report(3, Some(&db_id)),
        RollbackCheck::Evidence {
            anchored_head: 5,
            db_head: 3
        },
        "a sanction bound to a different db_id must never clear (integer-collision hole)"
    );

    // The correctly-bound sanction clears.
    let line = witness::sign_restore_sanction(5, 3, 1_800_000_000, &operator, Some(&db_id))
        .expect("sign sanction");
    witness::append_restore_sanction(&line).expect("append sanction");

    // After the sanction: cleared (DR restore attested; NOT an attack).
    assert_eq!(
        witness::compute_rollback_verdict_for_report(3, Some(&db_id)),
        RollbackCheck::Sanctioned {
            anchored_head: 5,
            db_head: 3
        },
        "operator signature is the DR-vs-attack discriminator"
    );

    // The reopened DB verifies CLEAN on the rollback axis (witness is Unknown,
    // rollback is Sanctioned — both clean).
    let conn = ai_memory::db::open(&path).expect("reopen");
    let report = verify_audit_trail(&conn, None, None).expect("verify");
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
        witness::compute_rollback_verdict_for_report(3, Some(&db_id)),
        RollbackCheck::Evidence {
            anchored_head: 5,
            db_head: 3
        },
        "a sanction not signed by the enrolled operator key must NOT clear"
    );

    clear_env();
}

// ── (6) #2370 — LEGACY id-less sanction clears for one release ──────────────

#[test]
fn legacy_id_less_sanction_still_clears_for_one_release() {
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let _g = lock();
    let kdir = fresh_dir("lsanc-keys");
    let ddir = fresh_dir("lsanc-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    force_emit_audit_head_witness(&conn);
    let db_id = db_id_of(&conn);
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");
    drop(conn);

    let operator = SigningKey::generate(&mut OsRng);
    let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(operator.verifying_key().to_bytes());
    unsafe {
        std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", &pub_b64);
    }
    // Pre-#2370 ceremony shape: NO db_id inside the signed record. Upgrade
    // continuity: an already-attested DR restore must not flip back to
    // Evidence (a boot DoS under require-mode) — one-release window, WARN'd.
    let legacy_line = witness::sign_restore_sanction(5, 3, 1_800_000_000, &operator, None)
        .expect("sign legacy sanction");
    witness::append_restore_sanction(&legacy_line).expect("append legacy sanction");
    assert_eq!(
        witness::compute_rollback_verdict_for_report(3, Some(&db_id)),
        RollbackCheck::Sanctioned {
            anchored_head: 5,
            db_head: 3
        },
        "legacy id-less sanction keeps clearing for one release (upgrade continuity)"
    );

    clear_env();
}

// ── (7) #2370 matrix (1) — two DBs, one anchor log, no cross-Evidence ───────

#[test]
fn two_dbs_sharing_one_anchor_log_do_not_cross_contaminate() {
    let _g = lock();
    let kdir = fresh_dir("twodb-keys");
    let dir_a = fresh_dir("twodb-a");
    let dir_b = fresh_dir("twodb-b");
    let _kp = enrol_witness(kdir.path());

    // DB A: head 5, v3 anchor at 5.
    let (path_a, conn_a) = open_db(dir_a.path());
    append_rows(&conn_a, 5);
    force_emit_audit_head_witness(&conn_a);
    let id_a = db_id_of(&conn_a);

    // DB B: healthy sibling at head 3, genesis present, NO own anchor yet —
    // the log holds only A's v3 lines. Pre-#2370 this was the boot-DoS false
    // positive (3 < 5 ⇒ Evidence); with per-DB filtering it is NotApplicable.
    let (path_b, conn_b) = open_db(dir_b.path());
    append_rows(&conn_b, 3);
    let id_b = db_id_of(&conn_b);
    assert_ne!(id_a, id_b, "distinct genesis rows mint distinct db-ids");
    assert_eq!(
        witness::compute_rollback_verdict_for_report(3, Some(&id_b)),
        RollbackCheck::NotApplicable,
        "a v3-only log of ALIEN lines is no anchor history for this DB"
    );

    // B emits its own (lower) anchor — both directions must stay clean.
    force_emit_audit_head_witness(&conn_b);
    assert_eq!(
        witness::compute_rollback_verdict_for_report(5, Some(&id_a)),
        RollbackCheck::NotDetected,
        "A at its own anchor: B's lower anchor (3) must not lower A's high-water"
    );
    assert_eq!(
        witness::compute_rollback_verdict_for_report(3, Some(&id_b)),
        RollbackCheck::NotDetected,
        "B at its own anchor: A's higher anchor (5) must not convict B"
    );

    // Filtered high-waters: per-DB when scoped, conservative max when not.
    assert_eq!(witness::read_head_anchor_high_water(Some(&id_a)), Some(5));
    assert_eq!(witness::read_head_anchor_high_water(Some(&id_b)), Some(3));
    assert_eq!(
        witness::read_head_anchor_high_water(None),
        Some(5),
        "an id-less opener counts EVERY pinned line (conservative max)"
    );
    drop(conn_a);
    drop(conn_b);

    // Both DBs reopen clean even under REQUIRE-MODE (the #2370 fix).
    unsafe {
        std::env::set_var(witness::REQUIRE_ROLLBACK_CHECK_ENV, "1");
    }
    drop(ai_memory::db::open(&path_a).expect("A reopens clean under require-mode"));
    drop(ai_memory::db::open(&path_b).expect("B reopens clean under require-mode"));

    clear_env();
}

// ── (8) #2370 matrix (2) — fresh-chain bootstrap vs head-0 regression guard ─

#[test]
fn fresh_chain_bootstraps_under_require_only_when_log_has_no_pinned_lines() {
    let _g = lock();
    let kdir = fresh_dir("boot-keys");
    let dir_1 = fresh_dir("boot-db1");
    let dir_2 = fresh_dir("boot-db2");
    let _kp = enrol_witness(kdir.path());
    unsafe {
        std::env::set_var(witness::REQUIRE_ROLLBACK_CHECK_ENV, "1");
    }

    // (a) Anchor log has NO pinned lines: a fresh (head-0, genesis-less)
    // database bootstraps CLEAN even under require-mode (NotApplicable).
    let path_1 = dir_1.path().join("audit.db");
    let conn_1 = ai_memory::db::open(&path_1)
        .expect("fresh DB bootstraps under require-mode when the log has no pinned lines");
    assert_eq!(
        witness::compute_rollback_verdict_for_report(0, None),
        RollbackCheck::NotApplicable,
        "bootstrap carve-out: empty chain + empty log"
    );

    // Seed a pinned v3 anchor from DB 1.
    append_rows(&conn_1, 5);
    force_emit_audit_head_witness(&conn_1);
    drop(conn_1);

    // (b) C2 REGRESSION GUARD — a head-0 / genesis-less opener against a log
    // that DOES contain pinned lines is EVIDENCE (a rollback that wipes
    // `signed_events` to empty must never become undetectable), and under
    // require-mode the open refuses.
    assert_eq!(
        witness::compute_rollback_verdict_for_report(0, None),
        RollbackCheck::Evidence {
            anchored_head: 5,
            db_head: 0
        },
        "head-0 opener vs a pinned-line log stays Evidence"
    );
    let path_2 = dir_2.path().join("audit.db");
    assert!(
        ai_memory::db::open(&path_2).is_err(),
        "an empty-chain opener against a pinned-line log refuses under require-mode"
    );

    clear_env();
}

// ── (9) #2370 matrix (4) — legacy v1/v2 anchor lines stay conservative ──────

#[test]
fn legacy_id_less_anchor_lines_count_conservatively_for_every_db() {
    let _g = lock();
    let kdir = fresh_dir("legacy-keys");
    let ddir = fresh_dir("legacy-db");
    let kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());
    append_rows(&conn, 5);
    let db_id = db_id_of(&conn);

    // Craft a LEGACY v2 (id-less) anchor line claiming head 9 — the shape a
    // pre-#2370 daemon wrote — and append it to the off-table log.
    let dual = witness::WitnessDualHead {
        signed_head_sequence: 9,
        signed_head_hash: "aa".repeat(32),
        revisions_head_sequence: 0,
        revisions_head_hash: "00".repeat(32),
    };
    let legacy_cp = witness::build_signed_witness_checkpoint(
        &dual,
        Some(witness::rollback_counter_for(9)),
        None, // pre-#2370: no db_id ⇒ v2
        chrono::Utc::now().timestamp(),
        &kp,
    )
    .expect("build legacy v2 anchor");
    witness::append_head_anchor(&legacy_cp);

    // C3 — the id-less line counts against an opener WITH a db_id (over-
    // detect toward Evidence; the WARN names the re-emit remediation)…
    assert_eq!(
        witness::compute_rollback_verdict_for_report(5, Some(&db_id)),
        RollbackCheck::Evidence {
            anchored_head: 9,
            db_head: 5
        },
        "legacy id-less anchor lines are never used to suppress"
    );
    // …and against an id-less opener too.
    assert_eq!(
        witness::compute_rollback_verdict_for_report(0, None),
        RollbackCheck::Evidence {
            anchored_head: 9,
            db_head: 0
        }
    );

    clear_env();
}

// ── (10) #2370 — sqlite emission binds the v3 genesis db_id ─────────────────

#[test]
fn sqlite_witness_emission_binds_v3_genesis_db_id() {
    let _g = lock();
    let kdir = fresh_dir("emit-keys");
    let ddir = fresh_dir("emit-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());
    append_rows(&conn, 5);
    force_emit_audit_head_witness(&conn);
    let db_id = db_id_of(&conn);

    let log = std::fs::read_to_string(kdir.path().join(witness::HEAD_ANCHOR_LOG_FILENAME))
        .expect("read off-table anchor log");
    let last = log.lines().last().expect("anchor line present");
    let cp: ai_memory::models::Checkpoint =
        serde_json::from_str(last).expect("anchor line is a checkpoint");
    assert!(
        ai_memory::checkpoints::verify(&cp),
        "emitted anchor verifies"
    );
    let res = cp.resolution.as_deref().expect("resolution present");
    assert!(res.contains("\"v\":3"), "emission stamps v3: {res}");
    assert!(
        res.contains(&format!("\"db_id\":\"{db_id}\"")),
        "emission binds THIS database's genesis db-id: {res}"
    );

    clear_env();
}

// ── (11b) #2942 — asi-hard cold-boot: fresh node boots, wiped node refuses ──

#[test]
fn asi_hard_cold_node_boots_fresh_but_refuses_wiped_with_surviving_anchor() {
    let _g = lock();
    unsafe {
        std::env::set_var(witness::REQUIRE_ROLLBACK_CHECK_ENV, "1");
    }

    // (a) NET-NEW #2942 — a brand-new asi-hard node whose witness pin is NOT yet
    // enrolled (`Unpinnable`) and that has NO off-table head anchor on the mount
    // is a genuinely fresh DB: it BOOTS CLEAN under require-mode so the operator
    // can then run the witness-enrollment ceremony (the cold-boot chicken-and-
    // egg). Point the witness key dir at an EMPTY dir: no pubkey → Unpinnable,
    // no anchor log → nothing to roll back FROM.
    let fresh_kdir = fresh_dir("cold-fresh-keys");
    unsafe {
        std::env::set_var(witness::WITNESS_KEY_DIR_ENV, fresh_kdir.path());
        std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
    }
    assert_eq!(
        witness::compute_rollback_verdict_for_report(0, None),
        RollbackCheck::NotApplicable,
        "#2942 cold-boot carve-out: unenrolled pin + head-0 + no surviving anchor is NotApplicable"
    );
    let fresh_db = fresh_dir("cold-fresh-db");
    let fresh_path = fresh_db.path().join("audit.db");
    drop(
        ai_memory::db::open(&fresh_path)
            .expect("#2942 — a fresh asi-hard node must boot under require-mode to self-enrol"),
    );

    // (b) REGRESSION — a wiped node: head-0 / genesis-less, its witness pin ALSO
    // stripped (`Unpinnable`), but a SURVIVING off-table head anchor remains on
    // the mount from a prior require-mode run. The discriminator
    // (`off_table_head_anchor_present`) keeps it FAIL-CLOSED (`Missing`) → the
    // open REFUSES under require-mode. (A truly fresh node has no such line.)
    let wiped_kdir = fresh_dir("cold-wiped-keys");
    std::fs::write(
        wiped_kdir.path().join(witness::HEAD_ANCHOR_LOG_FILENAME),
        "{\"surviving\":\"anchor-line-from-a-prior-require-mode-run\"}\n",
    )
    .expect("write surviving off-table anchor");
    unsafe {
        std::env::set_var(witness::WITNESS_KEY_DIR_ENV, wiped_kdir.path());
        std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
    }
    assert_eq!(
        witness::compute_rollback_verdict_for_report(0, None),
        RollbackCheck::Missing,
        "#2942 — a surviving off-table anchor keeps a wiped node fail-closed (not carved out)"
    );
    let wiped_db = fresh_dir("cold-wiped-db");
    let wiped_path = wiped_db.path().join("audit.db");
    assert!(
        ai_memory::db::open(&wiped_path).is_err(),
        "#2942 — a wiped node with a surviving off-table anchor must refuse under require-mode"
    );

    clear_env();
}

// ── (11) #2370 — postgres emission twin (live-pg, #[ignore]) ────────────────

#[cfg(feature = "sal-postgres")]
mod postgres_emission {
    use super::{clear_env, enrol_witness, fresh_dir, payload_hash};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    /// The pg witness EMISSION must stamp the same v3 `db_id` shape as the
    /// sqlite twin, derived from the SAME stable genesis columns. Drives ONE
    /// real append through the production chokepoint
    /// (`pg_append_signed_event_with_chain` via the record-stop attestation)
    /// after seeding the sequence far enough that the `WATERMARK_INTERVAL`
    /// throttle fires.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn pg_witness_emission_binds_v3_genesis_db_id() {
        // No module lock: #[ignore] + live-pg (never races the sync tests),
        // and a MutexGuard must not be held across an await (the #1822
        // precedent). Env is set/cleared inline.
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            return;
        };
        let pg = match PostgresStore::connect(&url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skip: postgres connect failed: {e}");
                return;
            }
        };
        let kdir = fresh_dir("pg-emit-keys");
        let _kp = enrol_witness(kdir.path());

        // Genesis (sequence = 1): reuse the shared test DB's row when one
        // exists, else insert one (and remove it on the way out).
        let existing: Option<(String, String, Vec<u8>)> =
            sqlx::query_as(ai_memory::signed_events::GENESIS_ROW_SQL)
                .fetch_optional(pg.pool())
                .await
                .expect("probe genesis row");
        let mut inserted_genesis = false;
        let (gid, gagent, gpayload) = if let Some(g) = existing {
            g
        } else {
            {
                let gid = uuid::Uuid::new_v4().to_string();
                let gagent = format!("ai:2370-genesis-{}", uuid::Uuid::new_v4());
                let gpayload = payload_hash(b"pg-2370-genesis");
                sqlx::query(
                    "INSERT INTO signed_events \
                        (id, agent_id, event_type, payload_hash, signature, attest_level, \
                         timestamp, prev_hash, sequence, cause_hash) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                )
                .bind(&gid)
                .bind(&gagent)
                .bind("memory_link.created")
                .bind(&gpayload)
                .bind(Option::<Vec<u8>>::None)
                .bind("unsigned")
                .bind(chrono::Utc::now())
                .bind(ai_memory::signed_events::ZERO_HASH.to_vec())
                .bind(1_i64)
                .bind(Option::<Vec<u8>>::None)
                .execute(pg.pool())
                .await
                .expect("insert genesis row");
                inserted_genesis = true;
                (gid, gagent, gpayload)
            }
        };
        let expected_db_id =
            ai_memory::signed_events::db_id_from_genesis_parts(&gid, &gagent, &gpayload);

        // Filler row far above the current head AND any witness slot this
        // process already claimed, so the next real append crosses the
        // interval boundary and the chokepoint emits.
        let cur_max: i64 = sqlx::query_scalar(ai_memory::signed_events::CHAIN_HEAD_SQL)
            .fetch_one(pg.pool())
            .await
            .expect("read chain head");
        let filler_seq = cur_max + 10 * ai_memory::governance::audit::WATERMARK_INTERVAL;
        let filler_agent = format!("ai:2370-filler-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, \
                 timestamp, prev_hash, sequence, cause_hash) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&filler_agent)
        .bind("memory_link.created")
        .bind(payload_hash(b"pg-2370-filler"))
        .bind(Option::<Vec<u8>>::None)
        .bind("unsigned")
        .bind(chrono::Utc::now())
        .bind(ai_memory::signed_events::ZERO_HASH.to_vec())
        .bind(filler_seq)
        .bind(Option::<Vec<u8>>::None)
        .execute(pg.pool())
        .await
        .expect("insert filler row");

        // ONE real append through the production chokepoint (the record-stop
        // attestation event). If the in-memory record-stop was already in the
        // requested state, toggle to force an append.
        let ctx = CallerContext::for_admin("ai:2370-pg-emit");
        let appended = pg
            .record_stop(&ctx, true, "ai:2370-pg-emit", "test")
            .await
            .expect("record-stop append");
        if !appended {
            pg.record_stop(&ctx, false, "ai:2370-pg-emit", "test")
                .await
                .expect("record-stop release");
            pg.record_stop(&ctx, true, "ai:2370-pg-emit", "test")
                .await
                .expect("record-stop re-engage");
        }

        // The newest witness checkpoint must be a v3 record binding the
        // genesis-derived db_id — SAME shape as the sqlite twin.
        let resolution: String = sqlx::query_scalar(
            "SELECT resolution FROM checkpoints \
             WHERE condition_type = 'audit_head_witness' \
             ORDER BY resolved_at DESC, created_at DESC LIMIT 1",
        )
        .fetch_one(pg.pool())
        .await
        .expect("read latest pg witness checkpoint");
        let val: serde_json::Value =
            serde_json::from_str(&resolution).expect("witness resolution is JSON");
        assert_eq!(val["v"], 3, "pg emission stamps v3: {resolution}");
        assert_eq!(
            val["db_id"],
            serde_json::Value::String(expected_db_id),
            "pg emission binds the genesis db-id: {resolution}"
        );

        // Cleanup (append-only table — test-scoped direct SQL, the #1822
        // precedent): release the record stop, drop our rows + checkpoint.
        pg.record_stop(&ctx, false, "ai:2370-pg-emit", "test")
            .await
            .ok();
        sqlx::query("DELETE FROM signed_events WHERE sequence >= $1")
            .bind(filler_seq)
            .execute(pg.pool())
            .await
            .ok();
        if inserted_genesis {
            sqlx::query("DELETE FROM signed_events WHERE sequence = 1 AND id = $1")
                .bind(&gid)
                .execute(pg.pool())
                .await
                .ok();
        }
        sqlx::query(
            "DELETE FROM checkpoints WHERE condition_type = 'audit_head_witness' \
             AND resolution = $1",
        )
        .bind(&resolution)
        .execute(pg.pool())
        .await
        .ok();
        clear_env();
    }
}
