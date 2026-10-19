// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! PERF-3 (fix campaign 2026-05-26, FX-10) — regression test pinning
//! the bounded-concurrency invariant on webhook dispatch.
//!
//! Pre-fix posture at `src/subscriptions.rs:717`: every matching
//! subscriber span on every store event minted a fresh
//! `std::thread::spawn` worker that opened its own `SQLite` handle. At
//! 1000 subscribers this peaked at 1000 OS threads (~1 MB stack each)
//! plus 1000 `SQLite` handles per write event, bypassing the existing
//! Tokio runtime entirely.
//!
//! Post-fix posture: each delivery is enqueued on a shared
//! `tokio::sync::Semaphore` (default 32 permits, operator-tunable via
//! `AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY`) and dispatched via
//! `tokio::task::spawn_blocking`. This test sets the bound to 8 BEFORE
//! the first dispatch runs, fires 50 simultaneous deliveries at a
//! slow `wiremock` receiver, and asserts that at every sampled point
//! during the fan-out the in-flight delivery count (which equals
//! `bound - available_permits`) NEVER exceeds the configured bound.
//!
//! The bound is exposed for the test via the module-private
//! `override_dispatch_concurrency_for_tests` plus the diagnostic
//! `dispatch_semaphore_available_permits` accessor.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ai_memory::config::set_allow_loopback_webhooks;
use ai_memory::subscriptions::{
    self, NewSubscription, dispatch_semaphore_available_permits,
    override_dispatch_concurrency_for_tests,
};
use common::tls_receiver::{TlsReceiver, ack_echo_slow};
use rusqlite::Connection;

mod common;
use common::fresh_db_tempfile_path as fresh_db;

const BOUND: usize = 8;
const SUBSCRIBERS: usize = 50;

/// #1475 — upper bound on how long the post-dispatch semaphore drain
/// may take. Generous so a slow CI host under full-suite HTTP
/// contention still drains within it; a genuine permit leak never
/// drains and trips this deadline (the assert then FAILs correctly).
const DRAIN_DEADLINE: Duration = Duration::from_secs(30);

/// #6794 — after the deadline a drain that has not finished is a stall only
/// when the receiver served no request in this final window. It exceeds
/// the longest idle gap of a healthy retry ladder (5 s last backoff plus one
/// 5 s `ACK_TIMEOUT` is the worst case before the next request lands).
const STALL_WINDOW: Duration = Duration::from_secs(11);

/// #6912 — hard upper bound on the whole drain wait. The retry ladder
/// (`ACK_TIMEOUT` x 4 plus the backoffs, ~190 s worst case for the last
/// queued delivery) bounds a healthy drain, so progress past
/// [`DRAIN_DEADLINE`] keeps the loop polling, and this cap guarantees a
/// regression can never spin the test forever.
const DRAIN_HARD_CAP: Duration = Duration::from_secs(240);

/// #1475 — poll cadence while waiting for the semaphore to drain.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispatch_to_50_subscribers_caps_inflight_at_semaphore_bound() {
    // Pin the bound BEFORE any dispatch fires. The override is a
    // `OnceLock::set`, so if a prior test in this binary already
    // initialised it the call is a no-op (returns Err) — that's fine
    // because the bound assertion below is robust regardless of which
    // value we ended up with (we read it back via the accessor).
    let _ = override_dispatch_concurrency_for_tests(BOUND);

    // The receiver binds on 127.0.0.1; the SSRF guard rejects loopback
    // by default. Opt in for the duration of the test (the project
    // already documents this opt-in at `src/subscriptions.rs:1638`).
    set_allow_loopback_webhooks(true);

    // Spin up the receiver — TLS (#3705: every `http://` target is refused,
    // loopback included), one shared receiver for all 50 subs, ACKing with
    // the dispatched correlation id after ~150 ms so every worker holds its
    // semaphore permit long enough for the sampler (10 ms cadence) to catch
    // the in-flight peak.
    let tls = common::tls_receiver::dispatch_tls(&std::env::temp_dir());
    let server = TlsReceiver::start_with(tls, ack_echo_slow(Duration::from_millis(150))).await;

    let (_keep, db_path) = fresh_db();
    let receiver_url = format!("{}/hook", server.uri());

    // Register SUBSCRIBERS subscriptions all pointing at the same
    // receiver. Wildcard event so every dispatch fires.
    {
        let conn = Connection::open(&db_path).unwrap();
        for _ in 0..SUBSCRIBERS {
            subscriptions::insert(
                &conn,
                &NewSubscription {
                    url: &receiver_url,
                    events: "*",
                    secret: Some("test-secret"),
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .expect("insert");
        }
    }

    // Sampler: parallel task that polls `available_permits` every
    // 10 ms and tracks the minimum observed permit count + max
    // observed in-flight. We assert the in-flight count never
    // exceeds the bound.
    let max_inflight = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicUsize::new(0));
    let sampler_max = Arc::clone(&max_inflight);
    let sampler_stop = Arc::clone(&stop);
    let sampler = tokio::spawn(async move {
        while sampler_stop.load(Ordering::SeqCst) == 0 {
            let avail = dispatch_semaphore_available_permits();
            // In-flight count = bound - available. The semaphore may
            // start with a higher bound if a previous test in this
            // binary set it first; pull the effective bound from the
            // semaphore's starting state at boot. We approximate by
            // saturating-sub against BOUND; if the actual bound is
            // higher, `avail` will be larger and `inflight` zero.
            let inflight = BOUND.saturating_sub(avail);
            let prev = sampler_max.load(Ordering::SeqCst);
            if inflight > prev {
                sampler_max.store(inflight, Ordering::SeqCst);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // Fire ONE dispatch_event against the SUBSCRIBERS pool. Each
    // matching subscriber becomes one delivery — so a single
    // dispatch fans out to SUBSCRIBERS in-flight workers, each held
    // ~150 ms by the slow receiver. If the bound failed, max_inflight
    // would climb to SUBSCRIBERS (50). With the bound engaged it
    // must stay <= BOUND.
    let path_for_dispatch = db_path.clone();
    tokio::task::spawn_blocking(move || {
        let conn = Connection::open(&path_for_dispatch).unwrap();
        subscriptions::dispatch_event(
            &conn,
            "memory_store",
            "perf3-mem",
            "perf3-ns",
            None,
            &path_for_dispatch,
        );
    })
    .await
    .unwrap();

    // Drain: with BOUND=8 and SUBSCRIBERS=50 each taking ~150 ms,
    // total drain is ~50/8 * 150 ms ≈ 1 s. Allow generous slack to
    // tolerate slow test hosts.
    tokio::time::sleep(Duration::from_secs(5)).await;
    stop.store(1, Ordering::SeqCst);
    let _ = sampler.await;

    // #6915 — primary check: the receiver counts requests concurrently in
    // flight with an atomic high-water mark, independent of the semaphore's
    // own permit count, so it can fail when the cap leaks.
    let high_water = server.high_water();
    assert!(
        high_water <= BOUND,
        "PERF-3 invariant violated: the receiver saw {high_water} concurrent \
         requests, exceeding bound = {BOUND}. The semaphore is not pinning \
         in-flight deliveries."
    );
    assert!(
        high_water >= 1,
        "PERF-3 receiver high-water mark is 0: no request was observed in flight"
    );
    // Secondary: the permit-derived sample (`BOUND - available`, which holds
    // by construction and cannot fail on its own; see #6915).
    let peak = max_inflight.load(Ordering::SeqCst);
    assert!(
        peak <= BOUND,
        "PERF-3 invariant violated: peak in-flight deliveries = {peak}, \
         exceeds bound = {BOUND}. The dispatch fan-out is minting \
         workers without honouring the semaphore."
    );
    assert!(
        peak >= 1,
        "PERF-3 sampling did not observe ANY in-flight work — the test \
         is not actually exercising the dispatch path (peak={peak})"
    );
    // #6794 — the semaphore must drain, or at least keep making progress.
    // A delivery that hits a per-attempt failure on a saturated host holds
    // its permit through the whole retry ladder (`ACK_TIMEOUT` x 4 plus the
    // backoffs, ~26 s by design, see `SHUTDOWN_DRAIN_TIMEOUT`), so with 50
    // deliveries over 8 permits a fixed deadline cannot tell "slow" from
    // "leaked" (#1475 widened the deadline, #6794 hit it again: 0 of 8 permits
    // free after 35 s at host load ~85). The permit snapshot cannot show
    // progress either, because a freed permit is re-taken by the next queued
    // delivery at once. The receiver's served-request count is monotone and
    // moves on every attempt, so: poll until drained. Past `DRAIN_DEADLINE`
    // progress is only a reason to keep polling (#6912): other deliveries
    // retrying inside the window must not mask a leaked permit, so the loop
    // ends on drained, on the stall detector firing (the receiver served
    // nothing in the final `STALL_WINDOW`), or on `DRAIN_HARD_CAP`. The
    // timeline is printed on the stall path.
    let started = std::time::Instant::now();
    let mut timeline: Vec<(u128, usize, usize)> = Vec::new();
    let mut idle_avail = dispatch_semaphore_available_permits();
    let mut deadline_noted = false;
    let mut stalled = false;
    while idle_avail != BOUND && started.elapsed() < DRAIN_HARD_CAP {
        tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
        idle_avail = dispatch_semaphore_available_permits();
        let elapsed_ms = started.elapsed().as_millis();
        timeline.push((elapsed_ms, idle_avail, server.received_count().await));
        if idle_avail != BOUND && started.elapsed() >= DRAIN_DEADLINE {
            if !deadline_noted {
                deadline_noted = true;
                eprintln!(
                    "PERF-3: drain still in progress at the deadline (available={idle_avail}, \
                     bound={BOUND}); polling to drained-or-stalled."
                );
            }
            if drain_stalled(&timeline, elapsed_ms, STALL_WINDOW.as_millis()) {
                stalled = true;
                break;
            }
        }
    }
    if idle_avail != BOUND {
        let latest = timeline.last().map_or(0, |&(_, _, served)| served);
        let timeline_text = describe_timeline(&timeline);
        let why = if stalled {
            "the receiver served no request in the last stall window"
        } else {
            "the hard cap elapsed with permits still held"
        };
        panic!(
            "PERF-3 invariant violated: semaphore did not drain and {why} \
             (stall window {STALL_WINDOW:?}, hard cap {DRAIN_HARD_CAP:?}, \
             available={idle_avail}, bound={BOUND}, served={latest}). \
             A permit leak would block subsequent dispatches. \
             Timeline (ms, available, served): {timeline_text}"
        );
    }
}

/// #6794 — true when the receiver's served count did not grow during the
/// last `window_ms` of the drain. `timeline` is `(elapsed_ms, available,
/// served)` in time order.
fn drain_stalled(timeline: &[(u128, usize, usize)], elapsed_ms: u128, window_ms: u128) -> bool {
    let latest = timeline.last().map_or(0, |&(_, _, served)| served);
    let before = timeline
        .iter()
        .rev()
        .find(|&&(at_ms, _, _)| at_ms.saturating_add(window_ms) <= elapsed_ms)
        // #6913 — no sample is old enough: baseline from the FIRST observed
        // sample, never 0 (a 0 baseline read any late sample as progress).
        .or_else(|| timeline.first())
        .map_or(0, |&(_, _, served)| served);
    latest <= before
}

#[test]
fn drain_stall_detector_separates_slow_from_leaked_6794() {
    // Slow host: permits stay at 0 but the receiver keeps serving requests.
    let slow: Vec<(u128, usize, usize)> = (0..40u128)
        .map(|i| (i * 1_000, 0, 10 + usize::try_from(i).unwrap_or(0)))
        .collect();
    assert!(
        !drain_stalled(&slow, 40_000, 11_000),
        "progressing drain flagged as a leak"
    );
    // Leak: all 50 requests served long ago, permits still held.
    let leaked: Vec<(u128, usize, usize)> = (0..40u128).map(|i| (i * 1_000, 0, 50)).collect();
    assert!(
        drain_stalled(&leaked, 40_000, 11_000),
        "stalled drain not flagged"
    );
    // No samples at all is a stall, not a pass.
    assert!(drain_stalled(&[], 40_000, 11_000));
    // #6913 — progress that stops partway through the run: served climbs to
    // 30 by t=20 s, then freezes; the final 11 s window saw nothing.
    let stops_midway: Vec<(u128, usize, usize)> = (0..40u128)
        .map(|i| (i * 1_000, 0, 10 + usize::try_from(i.min(20)).unwrap_or(0)))
        .collect();
    assert!(
        drain_stalled(&stops_midway, 40_000, 11_000),
        "progress that stopped partway through the window read as a pass"
    );
    // #6913 — a single sample newer than the window start, with requests
    // served: nothing older exists to prove growth, so it must read STALLED
    // (the baseline is the first observed sample, not 0).
    assert!(
        drain_stalled(&[(39_000, 0, 5)], 40_000, 11_000),
        "single late sample with served > 0 failed open"
    );
    // #6913 — the exact window boundary. A sample at `elapsed - window` is
    // old enough (`<=`): baseline 12 equals the latest 12 -> stalled.
    assert!(
        drain_stalled(
            &[(20_000, 0, 5), (29_000, 0, 12), (40_000, 0, 12)],
            40_000,
            11_000
        ),
        "sample exactly one window old was not used as the baseline"
    );
    // One millisecond inside the window it is NOT old enough, so the older
    // sample (served 5) is the baseline and growth to 12 reads as progress.
    assert!(
        !drain_stalled(
            &[(20_000, 0, 5), (29_001, 0, 12), (40_000, 0, 12)],
            40_000,
            11_000
        ),
        "sample just inside the window was used as the baseline"
    );
}

/// #6794 — compress the drain timeline to at most ~24 evenly spaced points
/// plus the last one, so the assertion message stays readable.
fn describe_timeline(timeline: &[(u128, usize, usize)]) -> String {
    let step = (timeline.len() / 24).max(1);
    let mut points: Vec<String> = timeline
        .iter()
        .step_by(step)
        .map(|&(at_ms, avail, served)| format!("({at_ms},{avail},{served})"))
        .collect();
    if let Some(&(at_ms, avail, served)) = timeline.last() {
        points.push(format!("({at_ms},{avail},{served})"));
    }
    points.join(" ")
}
