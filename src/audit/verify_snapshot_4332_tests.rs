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

/// The issue's cell: while a verify is walking, the trail lock is free and an
/// audited event is written; the verify still reports exactly what its
/// snapshot held, with no false gap. Red on 95c974ecf: the exclusive lock
/// could not be taken while the verify held its shared lock.
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
            // A real audited event, written while the verify is in progress.
            one();
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
    assert_eq!(sequences(&path), vec![1, 2, 3, 4], "the event was written");
    let after = verify_chain(&path).expect("verify");
    assert!(after.into_result().is_ok());
}

/// How long 3000 audited writes may take while verifies loop on the trail.
/// r2 measured ~13 minutes on Linux at 95c974ecf (verify held the shared lock
/// for its whole walk, and Linux flock lets back-to-back shared holders
/// starve an exclusive waiter); the fixed code takes well under a second.
const STARVATION_BOUND: std::time::Duration = std::time::Duration::from_secs(120);

/// Events between the writer's checkpoints.
const EVENTS_PER_CHECKPOINT: u32 = 100;

/// ai:code_reviewer-r2's concurrency cell for #4299
/// (`concurrent_verify_during_live_appends_reports_no_false_gap_r2`), with
/// the timing bound GOD asked for: verifies running back-to-back must
/// neither report a false gap NOR starve the writer.
///
/// Overlap is guaranteed by construction, not by speed: every
/// `EVENTS_PER_CHECKPOINT` writes the writer waits until one more verify has
/// completed, so at least 3000 / 100 = 30 verifies interleave with the
/// writes. On a timeout both loops stop, so a red run fails at the bound
/// instead of hanging. Red on Linux at 95c974ecf (writer starved); on macOS
/// the old code does not starve (its flock does not), so this cell's red
/// is Linux-only and the seam cell above is the all-platform pin.
#[test]
fn verify_in_a_loop_never_starves_audited_writes_4332() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as AtomicOrdering};
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    let started = std::time::Instant::now();
    let done = Arc::new(AtomicBool::new(false));
    let verifies = Arc::new(AtomicU32::new(0));
    let (finished, seen) = (Arc::clone(&done), Arc::clone(&verifies));
    let writer = std::thread::spawn(move || {
        for i in 1..=3000_u32 {
            one();
            if i % EVENTS_PER_CHECKPOINT == 0 {
                let target = i / EVENTS_PER_CHECKPOINT;
                while seen.load(AtomicOrdering::SeqCst) < target
                    && started.elapsed() < STARVATION_BOUND
                {
                    std::thread::yield_now();
                }
            }
        }
        finished.store(true, AtomicOrdering::SeqCst);
    });
    let mut bad: Vec<String> = Vec::new();
    while !done.load(AtomicOrdering::SeqCst) && started.elapsed() < STARVATION_BOUND {
        match verify_chain(&path) {
            Ok(r) if r.first_failure.is_none() && r.gaps.is_empty() => {}
            Ok(r) => bad.push(format!(
                "lines={} failure={:?} gaps={:?}",
                r.total_lines, r.first_failure, r.gaps
            )),
            Err(e) => bad.push(format!("err {e:#}")),
        }
        verifies.fetch_add(1, AtomicOrdering::SeqCst);
    }
    let elapsed = started.elapsed();
    let starved = !done.load(AtomicOrdering::SeqCst);
    writer.join().expect("writer");
    shutdown_for_test();
    let count = verifies.load(AtomicOrdering::SeqCst);
    eprintln!("#4332: {count} concurrent verifies in {elapsed:?}; writer starved: {starved}");
    assert!(
        !starved,
        "3000 audited writes did not finish within {STARVATION_BOUND:?} while verify ran ({count} verifies)"
    );
    assert!(
        count >= 30,
        "only {count} verifies interleaved with the writes"
    );
    assert!(
        bad.is_empty(),
        "false findings under concurrency: {:?}",
        &bad[..bad.len().min(3)]
    );
    let r = verify_chain(&path).expect("final verify");
    assert!(r.first_failure.is_none() && r.gaps.is_empty());
    assert_eq!(r.total_lines, 3001);
}
