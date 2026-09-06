// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3521 — the daemon's periodic maintenance loops, driven for real.
//!
//! `serve()` spawns four unattended sqlite maintenance tasks that run for the
//! life of the process: the K2 pending-action timeout sweep, the transcript
//! archive→prune sweep, the daily agent-quota reset, and the WAL checkpoint.
//! Their bodies had never executed under test — only the spawn call sites
//! were reached — so a regression that made any of them panic, deadlock on
//! the shared connection mutex, or leave the database unusable would have
//! surfaced first on an operator's long-running daemon.
//!
//! What is pinned here is the fleet-manageability contract these loops carry:
//! each tick is BEST EFFORT and must never take the substrate down. A sweep
//! that finds nothing continues quietly; a sweep that errors WARNs and keeps
//! looping; and after several ticks of all four running concurrently against
//! ONE shared connection the database is still open, still readable, and
//! still writable. Degrade, never corrupt.
//!
//! Intervals are milliseconds here so several ticks land inside the test;
//! production cadences are minutes to hours.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ai_memory::config::{ResolvedTtl, TranscriptsConfig};
use ai_memory::daemon_runtime::{
    spawn_agent_quota_reset_loop, spawn_pending_timeout_sweep_loop,
    spawn_transcript_lifecycle_sweep_loop, spawn_wal_checkpoint_loop,
};
use ai_memory::handlers::Db;

const TICK: Duration = Duration::from_millis(10);
/// Long enough for every loop to tick several times, including the WAL
/// checkpoint's deliberate half-interval cold-start stagger.
const SETTLE: Duration = Duration::from_millis(400);

fn open_db(path: &Path) -> Db {
    let conn = ai_memory::db::open(path).expect("db::open");
    Arc::new(tokio::sync::Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )))
}

/// All four maintenance loops tick repeatedly against ONE shared connection
/// and leave the substrate fully usable. Nothing here should ever be a fault
/// on an empty corpus: "no expired pendings / no transcripts to sweep / no
/// quotas to reset" is the normal steady state of a healthy daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_loops_tick_without_taking_the_substrate_down() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("maintenance-3521.db");
    let db = open_db(&path);

    let handles = vec![
        spawn_pending_timeout_sweep_loop(db.clone(), path.clone(), 3600, TICK),
        spawn_transcript_lifecycle_sweep_loop(db.clone(), TranscriptsConfig::default(), TICK),
        spawn_agent_quota_reset_loop(db.clone(), TICK),
        spawn_wal_checkpoint_loop(db.clone(), TICK),
    ];

    tokio::time::sleep(SETTLE).await;
    for h in &handles {
        assert!(
            !h.is_finished(),
            "a maintenance loop exited early — these tasks must run for the life of the daemon"
        );
        h.abort();
    }

    // The substrate survived several concurrent ticks: still open, still
    // readable, and still WRITABLE (a checkpoint loop that left the WAL or
    // the write lock in a bad state would surface here).
    let guard = db.lock().await;
    let n: i64 = guard
        .0
        .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("the corpus is still readable after the maintenance ticks");
    assert_eq!(n, 0, "the loops must not have invented rows");
    guard
        .0
        .execute_batch(
            "CREATE TABLE cov_3521_probe (id INTEGER PRIMARY KEY); DROP TABLE cov_3521_probe;",
        )
        .expect("the database is still writable after the maintenance ticks");
}

/// The WAL checkpoint loop is the one that touches the durable file on every
/// tick. Run it alone, longer, and confirm the corpus written BEFORE the
/// loop started is still exactly there afterwards — a checkpoint that lost
/// committed pages would be the worst failure this substrate can have.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wal_checkpoint_loop_preserves_committed_rows() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("wal-3521.db");
    let db = open_db(&path);
    {
        let guard = db.lock().await;
        guard
            .0
            .execute_batch(
                "CREATE TABLE cov_3521_durable (id INTEGER PRIMARY KEY, body TEXT NOT NULL); \
                 INSERT INTO cov_3521_durable (id, body) VALUES (1, 'durable-source-of-truth');",
            )
            .expect("seed a committed row");
    }

    let handle = spawn_wal_checkpoint_loop(db.clone(), TICK);
    tokio::time::sleep(SETTLE).await;
    assert!(
        !handle.is_finished(),
        "the checkpoint loop must keep running"
    );
    handle.abort();

    let guard = db.lock().await;
    let body: String = guard
        .0
        .query_row("SELECT body FROM cov_3521_durable WHERE id = 1", [], |r| {
            r.get(0)
        })
        .expect("the committed row survives repeated checkpoints");
    assert_eq!(body, "durable-source-of-truth");
}
