// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3745 / #3940 — a `spawn_blocking` task must never sit queued behind a
//! RUNNING blocking task while the pool still has room for a thread.
//!
//! Root cause of both issues. `Cargo.lock` pinned tokio 1.52.0, the one
//! release whose blocking pool used the sharded queue of tokio#7757. That
//! pool decided "an idle thread exists, just notify it" by reading the idle
//! counter WITHOUT reserving the thread: the idle thread only decrements the
//! counter after it wakes. Two `spawn_blocking` calls that land while exactly
//! one thread is idle both see `idle == 1`, both only notify, and no second
//! thread is started. The idle thread runs the first task; the second task
//! stays in the queue until some running blocking task RETURNS. Upstream
//! calls this "a regression that causes `spawn_blocking` to hang"
//! (tokio#8056) and reverted #7757 in 1.52.1 (tokio#8057). 1.53.x reserves
//! the idle thread under the pool lock at spawn time, so the second call
//! starts a thread.
//!
//! What it did to the webhook dispatcher: every delivery runs its retry
//! ladder (up to ~26 s) on a blocking thread, and the fire-and-forget worker
//! of a sibling delivery (or a refused one, whose DLQ write takes
//! milliseconds) could queue behind it for the whole ladder. In the old test
//! harnesses the competing blocking task was the DLQ poll loop itself — a
//! `spawn_blocking` that ran for the entire observation window — so the
//! refusal's DLQ write could not start until the window had already expired:
//! #3940's "worker never dispatched AND never wrote the DLQ row in 60 s" and
//! #3745's "the other workers never reach the audit INSERT; one delivery
//! never starts at all". The drain-based observation on the carrier removed
//! the competing blocking task from those tests, which is why they went green
//! without the pool being fixed.
//!
//! This cell pins the pool contract directly, through the tokio the crate
//! actually links. The shape is the minimal one that trips the 1.52.0 race:
//! exactly one idle blocking thread, then two back-to-back `spawn_blocking`
//! calls, where the first task can only finish early once the second has
//! RUN. On a correct pool the second task always gets its own thread and the
//! first returns immediately. On tokio 1.52.0 the pattern starved in 330 of
//! 600 standalone trials (a ~55 % per-trial rate), so the cell reds on its
//! first few trials; on 1.53.1 it starved in 0 of 600.
//!
//! [`HANG_DETECTOR`] is not an observation window: on a correct pool the
//! first task returns as soon as the second is scheduled (microseconds). The
//! detector only bounds how long a STARVED trial takes to report, so the red
//! is loud instead of a hung test binary.

use std::sync::mpsc;
use std::time::Duration;

/// Trials per run. At the measured 1.52.0 starvation rate the chance that
/// every trial dodges the race is below 1e-20; a correct pool passes every
/// trial by construction.
const TRIALS: usize = 64;

/// Upper bound on how long the first task waits for the second to run.
const HANG_DETECTOR: Duration = Duration::from_secs(10);

/// Runs one trial and returns `true` when the second blocking task was left
/// queued behind the first.
fn second_task_was_starved() -> bool {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("multi-thread runtime");
    rt.block_on(async {
        // Leave exactly one IDLE blocking thread in the pool: run one
        // trivial blocking task, then yield long enough for its thread to
        // park. The pause only shapes the pool so the race is reachable; a
        // correct pool passes whether or not the thread has parked yet.
        tokio::task::spawn_blocking(|| ())
            .await
            .expect("warm-up blocking task");
        tokio::time::sleep(Duration::from_millis(5)).await;

        let (tx, rx) = mpsc::channel::<()>();
        // The long-running task (a delivery's retry ladder, or a poll loop).
        // It finishes early only if the second task has run.
        let slow = tokio::task::spawn_blocking(move || rx.recv_timeout(HANG_DETECTOR).is_err());
        // The short task (a refusal plus its DLQ write).
        let fast = tokio::task::spawn_blocking(move || {
            // A send error means `slow` already gave up and dropped the
            // receiver; the starvation is reported through `slow`, so the
            // discard is deliberate.
            let _ = tx.send(());
        });
        let starved = slow.await.expect("first blocking task");
        fast.await.expect("second blocking task");
        starved
    })
}

#[test]
fn a_blocking_task_never_queues_behind_a_running_one_3745_3940() {
    for trial in 1..=TRIALS {
        assert!(
            !second_task_was_starved(),
            "#3745/#3940: trial {trial}/{TRIALS} — a spawn_blocking task stayed queued \
             behind a running blocking task for {HANG_DETECTOR:?} although the pool had room \
             for another thread. This is the tokio 1.52.0 blocking-pool regression \
             (tokio#8056, reverted by tokio#8057); check the tokio version in Cargo.lock",
        );
    }
}
