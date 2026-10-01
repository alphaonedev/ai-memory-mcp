// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4332 — `audit verify` holds the trail's shared lock only for a
//! consistent snapshot (length + high-water mark), never for the walk.
//!
//! #4299 held it across the whole walk, so a verify of a large trail stalled
//! every audited operation in the daemon, and back-to-back verifies starved
//! the writer (r2 measured 3000 emits taking ~13 minutes under a verify
//! loop). The seam runs between the snapshot and the walk, i.e. while a real
//! verify is in progress.

use std::sync::{Arc, Mutex as StdMutex};

use super::tail_loss_4086_tests::{one, sequences};
use super::*;

/// Install the seam for one verify, and always clear it.
struct AfterSnapshot;

impl AfterSnapshot {
    fn run(hook: impl FnMut() + Send + 'static) -> Self {
        *VERIFY_AFTER_SNAPSHOT_FOR_TEST.lock().expect("seam") = Some(Box::new(hook));
        Self
    }
}

impl Drop for AfterSnapshot {
    fn drop(&mut self) {
        if let Ok(mut g) = VERIFY_AFTER_SNAPSHOT_FOR_TEST.lock() {
            *g = None;
        }
    }
}

/// Audited writes that must complete while one verify is paused mid-walk.
const WRITES_DURING_VERIFY: u64 = 100;

/// The issue's cell, a structural pin (no timing): while a verify is walking,
/// the trail lock is free and `WRITES_DURING_VERIFY` audited events are
/// written; the verify still reports exactly what its snapshot held, with
/// no false gap. Red on 95c974ecf on every platform: the exclusive lock
/// could not be taken while the verify held its shared lock, so 0 writes.
#[test]
fn an_emit_completes_while_verify_walks_the_trail_4332() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    one();
    one();

    let free = Arc::new(StdMutex::new(None::<bool>));
    let seen = Arc::clone(&free);
    let probe_path = path.clone();
    let seam = AfterSnapshot::run(move || {
        let probe = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&probe_path)
            .expect("open trail");
        let locked = probe.try_lock().is_ok();
        if locked {
            let _ = probe.unlock();
            drop(probe);
            // Real audited events, written while the verify is in progress.
            for _ in 0..WRITES_DURING_VERIFY {
                one();
            }
        }
        *seen.lock().expect("flag") = Some(locked);
    });
    let report = verify_chain(&path).expect("verify");
    drop(seam);
    shutdown_for_test();

    assert_eq!(
        *free.lock().expect("flag"),
        Some(true),
        "the trail lock was still held while verify walked the trail"
    );
    assert_eq!(report.total_lines, 3, "the verify covers its snapshot only");
    assert!(report.first_failure.is_none(), "{:?}", report.first_failure);
    assert!(
        report.gaps.is_empty(),
        "a write during verify is no gap: {:?}",
        report.gaps
    );
    assert_eq!(
        sequences(&path),
        (1..=3 + WRITES_DURING_VERIFY).collect::<Vec<u64>>(),
        "every event written during the verify landed"
    );
    let after = verify_chain(&path).expect("verify");
    assert!(after.into_result().is_ok());
}

/// Audited writes per measurement.
const WRITES: u32 = 3000;

/// A hang guard only: a starved writer stops here instead of hanging the
/// test binary (r2 measured ~13 minutes at 95c974ecf on Linux).
const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(120);

/// `WRITES` audited events on the installed trail; the elapsed time, and
/// whether the hang guard stopped it.
fn timed_writes() -> (std::time::Duration, bool) {
    let started = std::time::Instant::now();
    for _ in 0..WRITES {
        if started.elapsed() > HANG_GUARD {
            return (started.elapsed(), true);
        }
        one();
    }
    (started.elapsed(), false)
}

/// A MEASUREMENT, not a correctness pin (GOD ruling on #4332, 2026-10-01):
/// `#[ignore]`d, run on demand with `--ignored`. The CI pin for #4332 is the
/// structural seam cell above.
///
/// Built from ai:code_reviewer-r2's concurrency cell for #4299
/// (`concurrent_verify_during_live_appends_reports_no_false_gap_r2`): a
/// verifier loops `verify_chain` while `WRITES` audited events are written,
/// and the writes are timed against a no-verifier baseline from the same run.
/// It asserts only what is deterministic (no false gap or failure from any
/// concurrent verify, the final line count, and the hang guard) and PRINTS
/// the slowdown. A timing bound was measured and rejected as a gate:
/// - Linux, old code, with forced overlap: 3000 writes in 22 s, under a
///   120 s bound (not red); without forced overlap r2 measured ~13 min.
/// - macOS, old code: 27.6x in one run, 1.12x with no overlapping verify in
///   the next (scheduling noise, and a red for the wrong reason).
/// - macOS, fixed code: 0.89x..1.18x with only 1-4 verifies overlapping the
///   writes, so an overlap guard would flake on a fast host.
/// Data: /ai-scratch/conductor/handoff/4332-PIN-DECISION-f2h.md.
#[ignore = "measurement, not a correctness pin; run with --ignored"]
#[test]
fn verify_in_a_loop_never_starves_audited_writes_4332() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as AtomicOrdering};
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");

    let quiet = tmp.path().join("quiet.log");
    init(&quiet, true, false).expect("init");
    one();
    let (baseline, _) = timed_writes();
    shutdown_for_test();

    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    let stop = Arc::new(AtomicBool::new(false));
    let verifies = Arc::new(AtomicU32::new(0));
    let bad = Arc::new(StdMutex::new(Vec::<String>::new()));
    let verifier = {
        let (stop, verifies, bad, path) = (
            Arc::clone(&stop),
            Arc::clone(&verifies),
            Arc::clone(&bad),
            path.clone(),
        );
        std::thread::spawn(move || {
            while !stop.load(AtomicOrdering::SeqCst) {
                match verify_chain(&path) {
                    Ok(r) if r.first_failure.is_none() && r.gaps.is_empty() => {}
                    Ok(r) => bad.lock().expect("bad").push(format!(
                        "lines={} failure={:?} gaps={:?}",
                        r.total_lines, r.first_failure, r.gaps
                    )),
                    Err(e) => bad.lock().expect("bad").push(format!("err {e:#}")),
                }
                verifies.fetch_add(1, AtomicOrdering::SeqCst);
            }
        })
    };
    while verifies.load(AtomicOrdering::SeqCst) == 0 {
        std::thread::yield_now();
    }
    let before = verifies.load(AtomicOrdering::SeqCst);
    let (loaded, hung) = timed_writes();
    let during = verifies.load(AtomicOrdering::SeqCst) - before;
    stop.store(true, AtomicOrdering::SeqCst);
    verifier.join().expect("verifier");
    shutdown_for_test();

    let floor = std::time::Duration::from_millis(1);
    let slowdown = loaded.as_secs_f64() / baseline.max(floor).as_secs_f64();
    eprintln!(
        "#4332: baseline {baseline:?}, under verify {loaded:?}, slowdown {slowdown:.2}x, \
         {during} verifies during the writes, hung {hung}"
    );
    assert!(
        !hung,
        "the writer was starved past {HANG_GUARD:?} ({during} verifies)"
    );
    let bad = bad.lock().expect("bad");
    assert!(
        bad.is_empty(),
        "false findings under concurrency: {:?}",
        &bad[..bad.len().min(3)]
    );
    let r = verify_chain(&path).expect("final verify");
    assert!(r.first_failure.is_none() && r.gaps.is_empty());
    assert_eq!(r.total_lines, u64::from(WRITES) + 1);
}
