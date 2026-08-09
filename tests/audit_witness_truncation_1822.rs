// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G5b (#1822) — audit-WITNESS tier teeth tests.
//!
//! Covers the INDEPENDENT dual-chain audit-head witness anchor
//! (accepted-design items 6-12): the
//! [`ai_memory::models::ConditionType::AuditHeadWitness`] checkpoint signed by
//! a DISTINCT witness key, the K1 out-of-band pubkey pin, the K2 require-mode
//! fail-closed knobs, and the dual-chain (`signed_events` +
//! `memory_revisions`) tail-truncation detection.
//!
//! The SECOND witness key is held BY THE TEST (a temp custody dir + the
//! enrolled pubkey env), so these tests prove the pin catches a head
//! re-signed under a DIFFERENT key rather than a verbatim-reused verify.
//!
//! Pins:
//! - (a) row-only trailing DELETE → old oracle `chain_intact == true` but the
//!   new witness verdict is `Detected` + `is_clean() == false` + CLI exit 1;
//! - (b) DELETE-BOTH (rows + latest witness checkpoint) under
//!   `AI_MEMORY_REQUIRE_WITNESS` → `Unknown` flips to dirty `Missing` (K2);
//! - (c) K1 forgery — head re-signed by a DAEMON-class key with its OWN pubkey
//!   → `Forged` (proves the PIN, not a reused-verbatim verify);
//! - (d) dual-chain `memory_revisions` truncation is caught;
//! - (e) `Unknown` withholds in non-required mode (no false alarm);
//! - (f) `#[cfg(feature = "sal-postgres")]` postgres parity repeating
//!   truncation + witness + verify (proves K3);
//! - (g) a grep-guard asserting the pg append chokepoint references the
//!   witness + watermark emitters;
//! - (h) the #1822-follow-up daemon graceful-shutdown wire
//!   (`daemon_runtime::shutdown_witness_flush_and_checkpoint`): a clean
//!   shutdown emits EXACTLY ONE witness when a key is enrolled and ZERO
//!   when not (byte-identical legacy), and `daemon_runtime::serve`'s post-quiesce
//!   block is grep-pinned to call it.
//!
//! The witness key-dir / pubkey / require env vars are process-global, so
//! every test serialises via a module-local lock and clears the env on exit.

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::governance::audit as witness;
use ai_memory::models::ConditionType;
use ai_memory::signed_events::{
    CauseBinding, HeadHashCheck, SignedEvent, TruncationCheck, WitnessCheck, append_signed_event,
    canonical_chain_bytes, force_emit_audit_head_witness, payload_hash,
    try_force_emit_audit_head_witness, verify_audit_trail,
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

/// Process-global serialisation for the witness ENV + throttle static.
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
        .join("issue-1822-witness");
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
/// pubkey env. Returns the witness keypair (private held by the test).
/// Caller MUST already hold [`lock`]. Paired with [`clear_witness_env`].
fn enrol_witness(dir: &std::path::Path) -> ai_memory::identity::keypair::AgentKeypair {
    let kp = ai_memory::identity::keypair::generate(witness::WITNESS_KEY_LABEL).expect("gen");
    ai_memory::identity::keypair::save(&kp, dir).expect("save witness key");
    unsafe {
        std::env::set_var(witness::WITNESS_KEY_DIR_ENV, dir);
        std::env::set_var(witness::WITNESS_PUBKEY_ENV, kp.public_base64());
    }
    kp
}

fn clear_witness_env() {
    unsafe {
        std::env::remove_var(witness::WITNESS_KEY_DIR_ENV);
        std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
        std::env::remove_var(witness::REQUIRE_WITNESS_ENV);
        std::env::remove_var("AI_MEMORY_REQUIRE_CAUSE_BINDING");
    }
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

fn append_rows(conn: &Connection, n: usize) {
    for i in 0..n {
        append_row(conn, format!("payload-{i}").as_bytes());
    }
}

fn append_rev_leaf(conn: &Connection, memory_id: &str) {
    let leaf = ai_memory::revisions::RevisionLeaf {
        id: uuid::Uuid::new_v4().to_string(),
        memory_id: memory_id.to_string(),
        kind: ai_memory::revisions::RecordKind::Supersede,
        prior_version: Some(1),
        namespace: "_ns".to_string(),
        agent_id: Some("alice".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
    };
    ai_memory::revisions::append_revision_leaf(conn, &leaf).expect("append revision leaf");
}

// ── (a) row-only delete: old oracle clean, new witness Detected, CLI exit 1 ──

#[test]
fn row_only_delete_is_caught_by_witness_but_not_the_old_oracle() {
    let _g = lock();
    let kdir = fresh_dir("a-keys");
    let ddir = fresh_dir("a-db");
    let _kp = enrol_witness(kdir.path());
    let (path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    // Deterministic witness of the head (also exercises the graceful-shutdown
    // force path); binds signed_events head 5.
    force_emit_audit_head_witness(&conn);

    // Row-only trailing DELETE: the surviving 1..=3 chain stays contiguous.
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");
    drop(conn);

    let conn = ai_memory::db::open(&path).expect("reopen");
    let report = verify_audit_trail(&conn, None).expect("verify");
    // The OLD oracle still reads clean: no gap, chain contiguous.
    assert!(
        report.chain_intact && report.sequence_gaps.is_empty(),
        "old oracle sees a contiguous surviving chain; report={report:?}"
    );
    // The NEW witness verdict catches it.
    assert_eq!(
        report.witness,
        WitnessCheck::Detected {
            chain: "signed_events".to_string(),
            witness_head: 5,
            db_head: 3,
        },
        "witness must detect the tail truncation; report={report:?}"
    );
    assert!(
        !report.is_clean(),
        "detected witness ⇒ dirty; report={report:?}"
    );
    drop(conn);

    // CLI exit code 1.
    let args = ai_memory::cli::verify_audit_trail::VerifyAuditTrailArgs {
        since: None,
        json: false,
        store_url: None,
    };
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    let code = ai_memory::cli::verify_audit_trail::run(&path, &args, &mut out).expect("cli run");
    assert_eq!(code, 1, "CLI must exit 1 on a witnessed truncation");

    clear_witness_env();
}

// ── (b) DELETE-BOTH under REQUIRE_WITNESS ⇒ Unknown→Missing (K2) ──

#[test]
fn delete_both_under_require_flips_unknown_to_dirty() {
    let _g = lock();
    let kdir = fresh_dir("b-keys");
    let ddir = fresh_dir("b-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    force_emit_audit_head_witness(&conn);
    // Attacker deletes BOTH the trailing rows AND the witness checkpoint.
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");
    conn.execute(
        "DELETE FROM checkpoints WHERE condition_type = 'audit_head_witness'",
        [],
    )
    .expect("delete witness cp");
    // v1.0.0 #1946 — this test isolates the WITNESS tier ("no anchor ⇒
    // Unknown"). force_emit also wrote the OFF-TABLE #1946 head-anchor log,
    // which independently catches this rollback (RollbackCheck::Evidence). To
    // model the "no anchor at all" scope this witness test asserts, wipe the
    // off-table anchor too (its dedicated teeth are in `rollback_evidence_1946`).
    std::fs::remove_file(kdir.path().join(witness::HEAD_ANCHOR_LOG_FILENAME)).ok();

    // Without require-mode: no witness anchor ⇒ Unknown ⇒ withheld (clean).
    let report = verify_audit_trail(&conn, None).expect("verify permissive");
    assert_eq!(
        report.witness,
        WitnessCheck::Unknown,
        "no anchor ⇒ withhold by default; report={report:?}"
    );
    assert!(
        report.is_clean(),
        "Unknown must not dirty an otherwise-clean report; report={report:?}"
    );

    // With require-mode: Unknown flips to fail-closed Missing (dirty).
    unsafe {
        std::env::set_var(witness::REQUIRE_WITNESS_ENV, "1");
    }
    let report = verify_audit_trail(&conn, None).expect("verify required");
    assert_eq!(
        report.witness,
        WitnessCheck::Missing,
        "require-mode ⇒ a missing anchor is Missing (fail-closed); report={report:?}"
    );
    assert!(
        !report.is_clean(),
        "require-mode Missing ⇒ dirty; report={report:?}"
    );

    clear_witness_env();
}

// ── (c) K1 forgery: head re-signed by a DAEMON-class key ⇒ Forged ──

#[test]
fn head_resigned_under_daemon_key_is_forged_by_the_pin() {
    let _g = lock();
    let kdir = fresh_dir("c-keys");
    let ddir = fresh_dir("c-db");
    let _witness_kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    force_emit_audit_head_witness(&conn);

    // Attacker truncates rows 4,5 AND replaces the witness checkpoint with one
    // signed by a DIFFERENT (daemon-class) key, claiming a LOWERED head (3)
    // that MATCHES the surviving db head — so a naive head-compare (without
    // the pin) would read NotDetected/clean. The K1 pubkey pin must reject it.
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");
    conn.execute(
        "DELETE FROM checkpoints WHERE condition_type = 'audit_head_witness'",
        [],
    )
    .expect("delete legit witness cp");

    let daemon_kp = ai_memory::identity::keypair::generate("daemon").expect("gen daemon-class key");
    let forged_dual = witness::WitnessDualHead {
        signed_head_sequence: 3, // lowered to match the truncated db head
        signed_head_hash: "deadbeef".to_string(),
        revisions_head_sequence: 0,
        revisions_head_hash: "00".to_string(),
    };
    let forged = witness::build_signed_witness_checkpoint(
        &forged_dual,
        None,
        None,
        chrono::Utc::now().timestamp() + 10, // ensure it is the "latest"
        &daemon_kp,
    )
    .expect("build forged cp");
    // The forged cp is internally self-consistent (verifies against its OWN
    // resolver_pubkey) — the whole point is that verbatim verify would PASS.
    assert!(
        ai_memory::checkpoints::verify(&forged),
        "forged cp self-verifies under the daemon key (verbatim verify would pass)"
    );
    ai_memory::checkpoints::insert(&conn, &forged).expect("insert forged cp");

    let report = verify_audit_trail(&conn, None).expect("verify");
    assert!(
        matches!(report.witness, WitnessCheck::Forged { .. }),
        "the K1 pin must reject the wrong-key anchor as Forged (NOT NotDetected); \
         report={report:?}"
    );
    assert!(!report.is_clean(), "Forged ⇒ dirty; report={report:?}");

    clear_witness_env();
}

// ── (d) dual-chain memory_revisions truncation is caught ──

#[test]
fn memory_revisions_tail_truncation_is_caught() {
    let _g = lock();
    let kdir = fresh_dir("d-keys");
    let ddir = fresh_dir("d-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    // signed_events chain stays intact; the memory_revisions chain is truncated.
    append_rows(&conn, 3);
    for i in 0..3 {
        append_rev_leaf(&conn, &format!("mem-{i}"));
    }
    force_emit_audit_head_witness(&conn); // binds signed head 3 + mem head 3

    conn.execute("DELETE FROM memory_revisions WHERE sequence IN (2, 3)", [])
        .expect("truncate memory_revisions tail");

    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        report.witness,
        WitnessCheck::Detected {
            chain: "memory_revisions".to_string(),
            witness_head: 3,
            db_head: 1,
        },
        "dual-chain witness must catch the memory_revisions truncation; report={report:?}"
    );
    assert!(!report.is_clean(), "report={report:?}");

    clear_witness_env();
}

// ── (e) Unknown withholds in non-required mode (no false alarm) ──

#[test]
fn unknown_withholds_without_require_mode() {
    let _g = lock();
    let kdir = fresh_dir("e-keys");
    let ddir = fresh_dir("e-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    // A clean chain with NO witness anchor ever emitted.
    append_rows(&conn, 4);

    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(
        report.witness,
        WitnessCheck::Unknown,
        "no anchor + not required ⇒ verdict withheld; report={report:?}"
    );
    // Cause-binding is also withheld by default (unsigned rows carry no cause).
    assert_eq!(
        report.cause_binding,
        CauseBinding::Unknown,
        "unbound rows + not required ⇒ withheld; report={report:?}"
    );
    assert!(
        report.chain_intact && report.is_clean(),
        "withheld verdicts never dirty a clean report; report={report:?}"
    );
    assert_eq!(report.truncation, TruncationCheck::Unknown);

    clear_witness_env();
}

// ── the WATERMARK_INTERVAL throttle fires exactly once per boundary ──

#[test]
fn witness_throttle_fires_once_per_interval() {
    let _g = lock();
    // Force a known baseline high above any db-head value the other tests set
    // (force-claim mirrors the graceful-shutdown emit).
    assert!(witness::witness_claim_slot(1_000_000, true));
    assert!(
        !witness::witness_interval_reached(1_000_063),
        "63 < WATERMARK_INTERVAL ⇒ not yet due"
    );
    assert!(
        witness::witness_interval_reached(1_000_064),
        "64 == WATERMARK_INTERVAL ⇒ due"
    );
    assert!(
        witness::witness_claim_slot(1_000_064, false),
        "first crosser wins the slot"
    );
    assert!(
        !witness::witness_claim_slot(1_000_064, false),
        "the same boundary must not double-emit"
    );
}

// ── (h) #1822 follow-up: daemon graceful-shutdown witness wire ──

/// Count the audit-head witness checkpoints in the reserved namespace.
fn witness_checkpoint_count(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM checkpoints WHERE namespace = ?1",
        [witness::WITNESS_CHECKPOINT_NAMESPACE],
        |r| r.get(0),
    )
    .expect("count witness checkpoints")
}

/// Wrap a fresh DB connection into the daemon's shared [`ai_memory::handlers::Db`]
/// tuple (the shape `daemon_runtime::serve`'s `checkpoint_state` carries at shutdown).
fn daemon_db(path: &std::path::Path) -> ai_memory::handlers::Db {
    let conn = ai_memory::db::open(path).expect("reopen for daemon Db");
    std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )))
}

/// Drive the async shutdown flush from these sync (env-lock-holding) tests.
fn run_shutdown_flush(db: &ai_memory::handlers::Db) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(ai_memory::daemon_runtime::shutdown_witness_flush_and_checkpoint(db))
        .unwrap();
}

#[test]
fn graceful_shutdown_flush_emits_exactly_one_witness_when_enrolled() {
    let _g = lock();
    let kdir = fresh_dir("h-keys");
    let ddir = fresh_dir("h-db");
    let _kp = enrol_witness(kdir.path());
    let (path, conn) = open_db(ddir.path());

    // 3 appends — far below WATERMARK_INTERVAL, so the throttled per-append
    // emitter never fires and the final head is UNWITNESSED until shutdown.
    append_rows(&conn, 3);
    assert_eq!(
        witness_checkpoint_count(&conn),
        0,
        "precondition: sub-interval head must be unwitnessed before shutdown"
    );
    drop(conn);

    let db = daemon_db(&path);
    run_shutdown_flush(&db);

    let conn = ai_memory::db::open(&path).expect("reopen");
    assert_eq!(
        witness_checkpoint_count(&conn),
        1,
        "a graceful shutdown must emit exactly one audit-head witness"
    );

    clear_witness_env();
}

#[test]
fn graceful_shutdown_flush_emits_zero_witness_when_not_enrolled() {
    let _g = lock();
    let kdir = fresh_dir("h2-keys");
    let ddir = fresh_dir("h2-db");
    // Pin the custody dir to an EMPTY tempdir (no enrolled key) so the test
    // cannot pick up a real key from the developer's default custody dir.
    unsafe {
        std::env::set_var(witness::WITNESS_KEY_DIR_ENV, kdir.path());
        std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
    }
    let (path, conn) = open_db(ddir.path());
    append_rows(&conn, 3);
    drop(conn);

    let db = daemon_db(&path);
    run_shutdown_flush(&db);

    let conn = ai_memory::db::open(&path).expect("reopen");
    assert_eq!(
        witness_checkpoint_count(&conn),
        0,
        "no witness key enrolled → a graceful shutdown emits NOTHING \
         (byte-identical legacy shutdown)"
    );

    clear_witness_env();
}

/// Grep-pin the wire itself: `daemon_runtime::serve`'s post-quiesce shutdown block must
/// call the flush helper, and the helper must force-emit the witness before
/// the final WAL checkpoint (the #1822 follow-up this suite exists for).
#[test]
fn daemon_shutdown_path_wires_the_witness_flush() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/daemon_runtime.rs"
    ))
    .expect("read daemon_runtime.rs");
    assert!(
        src.contains("shutdown_witness_flush_and_checkpoint(&certification_state)"),
        "serve()'s post-quiesce shutdown block must call \
         shutdown_witness_flush_and_checkpoint"
    );
    assert!(
        src.contains("try_force_emit_audit_head_witness(&lock.0)"),
        "the shutdown flush helper must force-emit the audit-head witness \
         before the final WAL checkpoint"
    );
}

#[test]
fn strict_shutdown_witness_rejects_corrupt_enrolled_custody() {
    let _g = lock();
    let kdir = fresh_dir("strict-corrupt-keys");
    let ddir = fresh_dir("strict-corrupt-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());
    append_rows(&conn, 1);

    std::fs::write(
        kdir.path()
            .join(format!("{}.priv", witness::WITNESS_KEY_LABEL)),
        b"corrupt",
    )
    .expect("corrupt enrolled witness private key");

    let error = try_force_emit_audit_head_witness(&conn)
        .expect_err("strict shutdown certification must reject corrupt custody");
    assert!(
        error
            .to_string()
            .contains("custody is enrolled but unloadable"),
        "unexpected error: {error:#}"
    );
    clear_witness_env();
}

#[test]
fn strict_shutdown_witness_propagates_anchor_append_failure() {
    let _g = lock();
    let kdir = fresh_dir("strict-anchor-keys");
    let ddir = fresh_dir("strict-anchor-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());
    append_rows(&conn, 1);

    // A directory at the log path deterministically makes OpenOptions fail,
    // including when tests run with elevated filesystem privileges.
    std::fs::create_dir(kdir.path().join(witness::HEAD_ANCHOR_LOG_FILENAME))
        .expect("install anchor-path fault");

    let error = try_force_emit_audit_head_witness(&conn)
        .expect_err("strict shutdown certification must propagate anchor failure");
    assert!(
        error.to_string().contains("open head-anchor log"),
        "unexpected error: {error:#}"
    );
    clear_witness_env();
}

// ── (g) grep-guard: the pg append chokepoint references the emitters ──

#[test]
fn pg_append_chokepoint_references_witness_and_watermark_emitters() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/store/postgres.rs"
    ))
    .expect("read postgres.rs");
    // The pg chokepoint must wire the #1850 watermark (item 7) ...
    assert!(
        src.contains("maybe_record_audit_watermark"),
        "pg chokepoint must call maybe_record_audit_watermark (item 7 parity)"
    );
    // ... and the #1822 dual-chain witness emitter (item 6).
    assert!(
        src.contains("pg_emit_audit_head_witness_in_tx"),
        "pg chokepoint must call the witness emitter (item 6 parity)"
    );
    // And a Postgres verify twin must exist (item 10 / K3).
    assert!(
        src.contains("pub async fn verify_audit_trail"),
        "postgres must expose a verify_audit_trail twin (K3)"
    );
    // The emitter/verify must reference the AuditHeadWitness condition type.
    assert_eq!(
        ConditionType::AuditHeadWitness.as_str(),
        "audit_head_witness"
    );
}

// ── (f) postgres parity: truncation + witness + verify (proves K3) ──

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
    async fn pg_verify_audit_trail_surfaces_witness_and_cause_verdicts() {
        // No module lock here: this test is #[ignore] + live-pg, so it never
        // races the sync tests, and a MutexGuard must not be held across an
        // await. Env is set/cleared inline.
        let Some(pg) = live_pg().await else {
            return;
        };
        let kdir = fresh_dir("f-keys");
        let kp = enrol_witness(kdir.path());

        // Insert a signed-events row + a dual-head witness checkpoint directly,
        // then confirm the pg verify twin surfaces a witness verdict from the
        // SAME shared verdict fn (K3). Cleanup is direct-SQL (append-only).
        let id = uuid::Uuid::new_v4().to_string();
        let agent = format!("ai:1822-{}", uuid::Uuid::new_v4());
        let ts = chrono::Utc::now();
        // ISOLATION-SAFETY: `sequence` is UNIQUE and the shared postgres DB
        // accumulates audit rows across the whole suite, so a hardcoded
        // `sequence = 1` collides. Compute the next free sequence from the head.
        let base_seq: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM signed_events")
                .fetch_one(pg.pool())
                .await
                .expect("read signed_events head");
        sqlx::query(
            "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                 prev_hash, sequence, cause_hash) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&id)
        .bind(&agent)
        .bind("memory_link.created")
        .bind(payload_hash(b"pg-witness"))
        .bind(Option::<Vec<u8>>::None)
        .bind("unsigned")
        .bind(ts)
        .bind(ai_memory::signed_events::ZERO_HASH.to_vec())
        .bind(base_seq + 1)
        .bind(Option::<Vec<u8>>::None)
        .execute(pg.pool())
        .await
        .expect("insert pg signed row");

        // A witness anchoring a HIGHER head than survives ⇒ Detected.
        let dual = witness::WitnessDualHead {
            signed_head_sequence: 9_999,
            signed_head_hash: "deadbeef".to_string(),
            revisions_head_sequence: 0,
            revisions_head_hash: "00".to_string(),
        };
        let cp = witness::build_signed_witness_checkpoint(&dual, None, None, ts.timestamp(), &kp)
            .expect("build cp");
        sqlx::query(
            "INSERT INTO checkpoints \
                (id, namespace, title, condition_type, condition, state, created_by, \
                 resolved_by, resolution, resolution_note, signature, resolver_pubkey, \
                 created_at, deadline_at, resolved_at, metadata) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(&cp.id)
        .bind(&cp.namespace)
        .bind(&cp.title)
        .bind(cp.condition_type.as_str())
        .bind(cp.condition.to_string())
        .bind(cp.state.as_str())
        .bind(&cp.created_by)
        .bind(&cp.resolved_by)
        .bind(&cp.resolution)
        .bind(&cp.resolution_note)
        .bind(&cp.signature)
        .bind(&cp.resolver_pubkey)
        .bind(cp.created_at)
        .bind(cp.deadline_at)
        .bind(cp.resolved_at)
        .bind(cp.metadata.to_string())
        .execute(pg.pool())
        .await
        .expect("insert pg witness cp");

        let report = pg.verify_audit_trail(None).await.expect("pg verify");
        assert!(
            matches!(report.witness, WitnessCheck::Detected { .. }),
            "pg verify twin must surface the witness Detected verdict (K3); report={report:?}"
        );
        assert!(!report.is_clean());

        // Cleanup.
        sqlx::query("DELETE FROM checkpoints WHERE id = $1")
            .bind(&cp.id)
            .execute(pg.pool())
            .await
            .ok();
        sqlx::query("DELETE FROM signed_events WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await
            .ok();
        clear_witness_env();
    }

    /// v1.0.0 #2203 F2 (CWE-354) — the pg head-hash test the gap that hid the
    /// bug LACKED. The pg append chokepoint anchors the head hash from the
    /// in-memory NANOSECOND `Utc::now()`, while the verifier recomputes from the
    /// MICRO-precision `TIMESTAMPTZ` readback — before the fix the two differed on
    /// nearly every row → a FALSE `HeadHashCheck::Mismatch` on a CLEAN pg chain.
    /// This drives the REAL pg append path (`emit_spawn_audit` → nanosecond ts),
    /// forces a REAL off-table watermark, and asserts the clean chain reads
    /// `NotDetected`; a real same-length rewrite of the anchored (head) row then
    /// reads `Mismatch` (#2202, at the anchored sequence). No enrolled witness —
    /// the forensic-watermark lane is the #1873 headline.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn pg_head_hash_clean_chain_not_detected_and_rewrite_mismatch() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let fdir = fresh_dir("pg-hh-forensic");
        // Live forensic sink so `maybe_record_audit_watermark` writes and
        // `last_audit_watermark` reads (process-global; torn down at the end).
        witness::init(fdir.path(), None).expect("forensic init");

        let base_seq: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM signed_events")
                .fetch_one(pg.pool())
                .await
                .expect("read base head");

        // Drive the REAL pg append path until a watermark is anchored. Each
        // `emit_spawn_audit` stamps `Utc::now()` (nanoseconds) — the exact F2 skew
        // surface — and appends through `pg_append_signed_event_with_chain`.
        let mut anchored: Option<i64> = None;
        for i in 0..300 {
            pg.emit_spawn_audit(&format!("argv0-{i}"), "1822-f2-headhash")
                .await;
            if let Some((seq, _)) = witness::last_audit_watermark() {
                anchored = Some(seq); // fired on the just-appended head → anchored == head
                break;
            }
        }
        let Some(anchored) = anchored else {
            eprintln!("skip: no watermark fired within 300 pg appends (shared-DB throttle state)");
            sqlx::query("DELETE FROM signed_events WHERE sequence > $1")
                .bind(base_seq)
                .execute(pg.pool())
                .await
                .ok();
            witness::shutdown();
            return;
        };

        // CLEAN chain: the anchored row survives intact → the micros-readback
        // recompute MATCHES the anchor (also micros, post-#2203) → NotDetected.
        let report = pg.verify_audit_trail(None).await.expect("pg verify clean");
        assert_eq!(
            report.head_hash,
            HeadHashCheck::NotDetected,
            "a CLEAN pg chain must read NotDetected — the #2203 anchor/recompute precision \
             skew (nanos vs micros) is fixed; report={report:?}"
        );
        assert!(report.is_clean(), "clean pg chain; report={report:?}");

        // SAME-LENGTH rewrite of the anchored (head) row → the at-anchored-seq
        // recompute differs from the anchor → Mismatch (#2202 on pg).
        sqlx::query("UPDATE signed_events SET payload_hash = $1 WHERE sequence = $2")
            .bind(vec![0x11u8; 32])
            .bind(anchored)
            .execute(pg.pool())
            .await
            .expect("rewrite anchored row");
        let report2 = pg
            .verify_audit_trail(None)
            .await
            .expect("pg verify rewritten");
        match &report2.head_hash {
            HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "signed_events"),
            other => {
                panic!("expected pg head_hash Mismatch after rewrite, got {other:?}; {report2:?}")
            }
        }
        assert!(
            !report2.is_clean(),
            "rewrite must dirty; report={report2:?}"
        );

        // Cleanup: delete our tail rows (removes the tamper + the appended rows),
        // and tear down the process-global forensic sink so no watermark leaks.
        sqlx::query("DELETE FROM signed_events WHERE sequence > $1")
            .bind(base_seq)
            .execute(pg.pool())
            .await
            .ok();
        witness::shutdown();
    }
}

// ── (#1873) witness-anchor head-hash lane: SAME-LENGTH suffix rewrite ──
// The witness checkpoint records the REAL head hashes of BOTH chains, so a
// same-length rewrite (equal row count, recomputed prev_hash) of either head
// row — which the seq-only WitnessCheck cannot see — is caught by the
// #1873 head-hash anchor folded into `report.head_hash`.

#[test]
fn witness_signed_events_same_length_rewrite_is_head_hash_mismatch() {
    let _g = lock();
    let kdir = fresh_dir("h-keys");
    let ddir = fresh_dir("h-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    for i in 0..3 {
        append_rev_leaf(&conn, &format!("mem-{i}"));
    }
    force_emit_audit_head_witness(&conn); // binds the REAL signed + mem heads

    // Baseline: both heads match their witnessed hashes.
    let clean = verify_audit_trail(&conn, None).expect("verify clean");
    assert_eq!(
        clean.head_hash,
        HeadHashCheck::NotDetected,
        "clean={clean:?}"
    );
    assert!(clean.is_clean(), "clean={clean:?}");

    // SAME-LENGTH rewrite of the signed_events head row (row count + sequences
    // unchanged; nothing links from the head → chain walk + seq-only witness
    // stay clean; only the head-hash anchor catches it).
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 \
         WHERE sequence = (SELECT MAX(sequence) FROM signed_events)",
        params![vec![0xEEu8; 32]],
    )
    .expect("rewrite signed head in place");

    let report = verify_audit_trail(&conn, None).expect("verify rewritten");
    assert!(report.chain_intact, "report={report:?}");
    assert_eq!(
        report.witness,
        WitnessCheck::NotDetected,
        "report={report:?}"
    );
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "signed_events"),
        other => panic!("expected signed_events head-hash Mismatch, got {other:?}; {report:?}"),
    }
    assert!(
        !report.is_clean(),
        "same-length rewrite must dirty; report={report:?}"
    );

    clear_witness_env();
}

#[test]
fn witness_memory_revisions_same_length_rewrite_is_head_hash_mismatch() {
    let _g = lock();
    let kdir = fresh_dir("i-keys");
    let ddir = fresh_dir("i-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 3);
    for i in 0..4 {
        append_rev_leaf(&conn, &format!("mem-{i}"));
    }
    force_emit_audit_head_witness(&conn); // binds the REAL signed + mem heads

    let clean = verify_audit_trail(&conn, None).expect("verify clean");
    assert_eq!(
        clean.head_hash,
        HeadHashCheck::NotDetected,
        "clean={clean:?}"
    );

    // SAME-LENGTH rewrite of the memory_revisions head row: flip a field the
    // canonical revision bytes commit (`namespace`) at MAX(sequence).
    conn.execute(
        "UPDATE memory_revisions SET namespace = 'tampered' \
         WHERE sequence = (SELECT MAX(sequence) FROM memory_revisions)",
        [],
    )
    .expect("rewrite memory_revisions head in place");

    let report = verify_audit_trail(&conn, None).expect("verify rewritten");
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "memory_revisions"),
        other => {
            panic!("expected memory_revisions head-hash Mismatch, got {other:?}; {report:?}")
        }
    }
    assert!(
        !report.is_clean(),
        "a memory_revisions same-length rewrite must dirty; report={report:?}"
    );

    clear_witness_env();
}

// ── (#2202) witness head-hash lane: rewrite BELOW the head after appends ──
// The #1873 residual-1 the equal-sequence gate missed also applies to the
// witness lane: after the witness binds head W the daemon appends more rows, so
// db_head > W and the equal-sequence gate never consults the witnessed head
// hash. The at-anchored-sequence compare (#2202) catches it. The witness
// anchor is consumed through the K1 pin + signature gate (#2203 F3), which the
// enrolled+force-emitted checkpoint satisfies.

/// Recompute + write `signed_events` row `seq`'s `prev_hash` from its
/// predecessor's canonical bytes (the faithful whole-suffix-rewrite step that
/// keeps the chain walk intact so only the head-hash anchor convicts).
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

/// (PASSIVE) — witness binds signed head W (=5); the daemon appends 3 rows
/// (`db_head` = 8 > W); a same-length whole-suffix rewrite then spans row W. The
/// equal-sequence gate skips the witnessed hash (8 != 5) → clean; the
/// at-anchored-seq compare recomputes row W and convicts.
#[test]
fn witness_signed_events_rewrite_below_head_after_appends_is_head_hash_mismatch() {
    let _g = lock();
    let kdir = fresh_dir("j-keys");
    let ddir = fresh_dir("j-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    for i in 0..3 {
        append_rev_leaf(&conn, &format!("mem-{i}"));
    }
    force_emit_audit_head_witness(&conn); // binds signed head = 5
    let anchored = 5i64;
    // Daemon appends 3 more signed rows AFTER the witness → db_head = 8.
    append_rows(&conn, 3);

    // Baseline: the witnessed row (5) is intact → MATCHES its witnessed hash
    // even though the head (8) has moved past it (the #2202 at-anchored-seq
    // compare; the equal-sequence gate returned Unknown here).
    let base = verify_audit_trail(&conn, None).expect("verify baseline");
    assert_eq!(base.head_sequence, 8, "base={base:?}");
    assert_eq!(base.head_hash, HeadHashCheck::NotDetected, "base={base:?}");
    assert!(base.is_clean(), "base={base:?}");

    // SAME-LENGTH rewrite of the WITNESSED signed_events row + relink.
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        params![vec![0xEEu8; 32], anchored],
    )
    .expect("rewrite witnessed row payload in place");
    relink_prev_hash(&conn, anchored + 1);

    let report = verify_audit_trail(&conn, None).expect("verify rewritten");
    assert!(report.chain_intact, "report={report:?}");
    assert_eq!(
        report.witness,
        WitnessCheck::NotDetected,
        "db_head (8) >= witnessed (5) → the seq-only witness reads clean; report={report:?}"
    );
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "signed_events"),
        other => panic!("expected signed_events head-hash Mismatch, got {other:?}; {report:?}"),
    }
    assert!(!report.is_clean(), "report={report:?}");

    clear_witness_env();
}

/// (ACTIVE) — even at head == witnessed W, rewrite row W and append ONE linked
/// row → head = W+1, so the equal-sequence gate withholds. The at-anchored-seq
/// compare convicts.
#[test]
fn witness_signed_events_rewrite_then_append_one_row_is_head_hash_mismatch() {
    let _g = lock();
    let kdir = fresh_dir("l-keys");
    let ddir = fresh_dir("l-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    force_emit_audit_head_witness(&conn); // binds signed head = 5, head == W
    let anchored = 5i64;

    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        params![vec![0xDDu8; 32], anchored],
    )
    .expect("rewrite witnessed head row in place");
    append_row(&conn, b"attacker-appended-linked-row"); // head → 6

    let report = verify_audit_trail(&conn, None).expect("verify");
    assert_eq!(report.head_sequence, anchored + 1, "report={report:?}");
    assert!(report.chain_intact, "report={report:?}");
    assert_eq!(
        report.witness,
        WitnessCheck::NotDetected,
        "report={report:?}"
    );
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "signed_events"),
        other => panic!("expected signed_events head-hash Mismatch, got {other:?}; {report:?}"),
    }
    assert!(!report.is_clean(), "report={report:?}");

    clear_witness_env();
}

/// (PASSIVE, revisions lane) — witness binds `memory_revisions` head W (=4); more
/// revision leaves are appended (rev `db_head` = 7 > W); a same-length rewrite of
/// the witnessed revision row is caught only at the anchored sequence.
#[test]
fn witness_memory_revisions_rewrite_below_head_after_appends_is_head_hash_mismatch() {
    let _g = lock();
    let kdir = fresh_dir("m-keys");
    let ddir = fresh_dir("m-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 3);
    for i in 0..4 {
        append_rev_leaf(&conn, &format!("mem-{i}"));
    }
    force_emit_audit_head_witness(&conn); // binds memory_revisions head = 4
    let anchored_rev = 4i64;
    // Append 3 more revision leaves AFTER the witness → rev db_head = 7.
    for i in 4..7 {
        append_rev_leaf(&conn, &format!("mem-{i}"));
    }

    let base = verify_audit_trail(&conn, None).expect("verify baseline");
    assert_eq!(base.head_hash, HeadHashCheck::NotDetected, "base={base:?}");

    // SAME-LENGTH rewrite of the WITNESSED memory_revisions row (flip a field
    // its canonical bytes commit — `namespace`).
    conn.execute(
        "UPDATE memory_revisions SET namespace = 'tampered' WHERE sequence = ?1",
        params![anchored_rev],
    )
    .expect("rewrite witnessed memory_revisions row in place");

    let report = verify_audit_trail(&conn, None).expect("verify rewritten");
    match &report.head_hash {
        HeadHashCheck::Mismatch { chain, .. } => assert_eq!(chain, "memory_revisions"),
        other => {
            panic!("expected memory_revisions head-hash Mismatch, got {other:?}; {report:?}")
        }
    }
    assert!(!report.is_clean(), "report={report:?}");

    clear_witness_env();
}
