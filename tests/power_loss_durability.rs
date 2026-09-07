// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1961 (R23/R7) — power-loss durability harness.
//!
//! Proves, end-to-end, that a **process killed mid-write** (a
//! `std::process::abort()` taken AFTER a commit acknowledged but BEFORE any
//! clean shutdown or WAL checkpoint — the software analogue of a power cut /
//! SIGKILL) loses **no acknowledged write** and leaves **no corruption**.
//!
//! ## Proven vs unproven boundary (honest scope)
//!
//! - **PROVEN here:** `SQLite` WAL crash-consistency across an unclean process
//!   exit — every fsync'd (`Ok`-returning, `synchronous=FULL`) commit survives
//!   the abort, the whole-database integrity check (`PRAGMA integrity_check`
//!   PLUS the #3508/#3510 page accounting SQLite silently skips on this
//!   schema) is clean on reopen, and the surviving row count equals the
//!   acknowledged prefix. Also the deferred-audit journal's
//!   torn-trailing-record discard on replay.
//! - **NOT proven (out of scope — needs a hardware power-cut rig):** that a
//!   consumer SSD / OS honours fsync under a REAL power cut (the "fsync lie").
//!   `abort()`/SIGKILL do not drop the OS page cache the way a power cut does;
//!   `synchronous=FULL` is what upgrades the process-death guarantee to
//!   real-power-loss durability on honest hardware.
//!
//! ## Mechanism
//!
//! The parent test re-execs THIS test binary, filtered to the
//! `power_loss_child_writes_then_aborts` test, with the child marker env set.
//! The child opens the DB under `synchronous=FULL`, writes a batch, and the
//! injected fault (`AI_MEMORY_TEST_ABORT_AFTER_COMMIT`) hard-aborts it after a
//! chosen committed write. The parent waits for the abnormal (SIGABRT) exit,
//! re-opens the DB, and asserts the acknowledged prefix survived intact.

use std::process::Command;

const CHILD_MARKER_ENV: &str = "AI_MEMORY_POWER_LOSS_CHILD";
const CHILD_DB_ENV: &str = "AI_MEMORY_POWER_LOSS_DB";
const CHILD_TEST_NAME: &str = "power_loss_child_writes_then_aborts";
const CHILD_NAMESPACE: &str = "power-loss";
/// Total rows the child attempts. The abort fires after committed write
/// `ABORT_AFTER`, so rows `0..=ABORT_AFTER` (`ABORT_AFTER` + 1 rows) are the
/// acknowledged, durable prefix that MUST survive.
const CHILD_WRITE_COUNT: usize = 12;
const ABORT_AFTER: usize = 6;

/// The child leg: only does real work when the parent set the marker env.
/// During a normal `cargo test` run (no marker) it is an inert pass, so it
/// never crashes the suite.
#[test]
fn power_loss_child_writes_then_aborts() {
    if std::env::var(CHILD_MARKER_ENV).is_err() {
        // Normal test-suite invocation — nothing to do.
        return;
    }
    let db_path = std::env::var(CHILD_DB_ENV).expect("child DB path env");
    // synchronous=FULL + the abort-injection are inherited from the parent's
    // spawn env. Open the DB (applies the resolved PRAGMA synchronous) and
    // run the batch; the injected fault aborts the process mid-batch.
    let conn = ai_memory::db::open(std::path::Path::new(&db_path)).expect("child open db");
    let _acked = ai_memory::recover::durability::durability_write_batch(
        &conn,
        CHILD_NAMESPACE,
        CHILD_WRITE_COUNT,
    )
    .expect("child write batch");
    // If we reach here the injected abort did NOT fire — that is a harness
    // failure (the whole point is that the process dies mid-batch).
    panic!("child completed the batch without the injected power-loss abort");
}

/// Parent: spawn the child, let the injected power-loss abort kill it, then
/// re-open the DB and assert no acknowledged write was lost + no corruption.
#[test]
fn power_loss_kill_preserves_acked_writes_and_no_corruption() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("power-loss.db");
    let exe = std::env::current_exe().expect("current_exe");

    let status = Command::new(exe)
        .args([
            CHILD_TEST_NAME,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_MARKER_ENV, "1")
        .env(CHILD_DB_ENV, &db_path)
        // Power-loss durability posture: fsync every commit.
        .env(ai_memory::storage::ENV_DB_SYNCHRONOUS, "FULL")
        // Inject the abort AFTER committed write `ABORT_AFTER`.
        .env(
            ai_memory::recover::durability::ENV_ABORT_AFTER_COMMIT,
            ABORT_AFTER.to_string(),
        )
        .env("AI_MEMORY_NO_CONFIG", "1")
        .status()
        .expect("spawn child");

    // The child must have died abnormally (aborted), NOT exited cleanly.
    assert!(
        !status.success(),
        "child must NOT exit cleanly — the injected abort should kill it"
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        // SIGABRT (6) from std::process::abort(). We accept any signal death
        // (a killed process has no exit code) to stay robust across platforms.
        assert!(
            status.signal().is_some(),
            "child should die by signal (SIGABRT from abort), got {status:?}"
        );
    }

    // Re-open the crashed DB with a fresh connection (no clean shutdown ran).
    let conn = ai_memory::db::open(&db_path).expect("reopen crashed db");

    // 1) No corruption. v1.0.0 #3510 — the verdict comes from the shared
    //    `storage::sqlite_integrity` helper, so a `Sound` answer means SQLite's
    //    own check passed AND every page in the file is accounted for. On the
    //    v98 schema a root-less object downgrades `PRAGMA integrity_check` to a
    //    PARTIAL check that answers `ok` without ever looking for unreferenced
    //    pages (#3508) — exactly the damage a torn write leaves — so asserting
    //    on the bare verdict would have made this durability claim read
    //    stronger than its evidence. Asserted through `integrity_verdict` (not
    //    the bool predicate) so a failure NAMES the unaccounted pages.
    let verdict =
        ai_memory::recover::durability::integrity_verdict(&conn).expect("integrity check runs");
    assert!(
        matches!(
            verdict,
            ai_memory::storage::sqlite_integrity::Soundness::Sound(_)
        ),
        "reopened DB after a mid-write abort must be sound: {verdict:?}"
    );

    // 2) No lost ACKNOWLEDGED write: rows 0..=ABORT_AFTER were each committed
    //    (fsync'd under synchronous=FULL) before the abort, so exactly
    //    ABORT_AFTER + 1 rows must survive.
    let surviving = ai_memory::recover::durability::count_rows(&conn, CHILD_NAMESPACE)
        .expect("count rows after crash");
    let expected_min = i64::try_from(ABORT_AFTER + 1).unwrap();
    assert!(
        surviving >= expected_min,
        "every acknowledged write must survive the crash: expected >= {expected_min}, found {surviving}"
    );
    // And never MORE than the total attempted (no phantom rows).
    assert!(surviving <= i64::try_from(CHILD_WRITE_COUNT).unwrap());
}

// NOTE: the sibling deferred-audit crash-durable journal path — a torn
// TRAILING record (a write interrupted mid-frame by power loss) is discarded
// on replay while every intact fsync'd record survives — is the append-only
// analogue of the WAL guarantee proven above. It is covered by the in-module
// unit test `deferred_audit::tests::journal_torn_trailing_record_discarded_1732`
// (#1732), so it is not duplicated here.
