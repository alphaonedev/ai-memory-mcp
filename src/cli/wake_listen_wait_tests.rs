// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4058 — `wait_on`, the one-shot wait behind `ai-memory inbox --wait`,
//! driven with PAUSED Tokio time against the production backstop loop.
//! Hub-shaped signals are injected; nothing here fakes the clock the
//! backstop runs on.

use std::time::Duration;

use tokio::time::Instant;

use super::{settle_catch_up, wait_on};
use crate::wake_client::{WakeClientConfig, WakeReason, WakeSignal, WakeStream};

const POLL: Duration = Duration::from_secs(10);

fn cfg() -> WakeClientConfig {
    WakeClientConfig {
        poll_interval: POLL,
        ..WakeClientConfig::default()
    }
}

fn empty_welcome() -> WakeSignal {
    WakeSignal::bare(WakeReason::Welcome)
}

/// RED before #4058: an empty welcome called `note_read()` without a read,
/// restarting the backstop clock, so a welcome at t=9 s moved the backstop to
/// t=19 s. The wait must return `Backstop` by the ORIGINAL deadline.
#[tokio::test(start_paused = true)]
async fn an_empty_welcome_does_not_postpone_the_backstop_4058() {
    let (mut stream, inject) = WakeStream::start_injectable(cfg()).expect("start");
    let started = Instant::now();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(9)).await;
        let _ = inject.send(empty_welcome()).await;
    });
    let signal = wait_on(&mut stream, None)
        .await
        .expect("the backstop must fire");
    assert_eq!(signal.reason, WakeReason::Backstop);
    let elapsed = started.elapsed();
    assert!(
        elapsed <= POLL,
        "an empty welcome must not postpone the backstop past one interval: returned at \
         {elapsed:?}, bound {POLL:?}"
    );
}

/// Repeated empty welcomes (a flapping hub: reconnect, welcome, drop) inside
/// every window must not starve the backstop either.
#[tokio::test(start_paused = true)]
async fn repeated_empty_welcomes_cannot_starve_the_backstop_4058() {
    let (mut stream, inject) = WakeStream::start_injectable(cfg()).expect("start");
    let started = Instant::now();
    tokio::spawn(async move {
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if inject.send(empty_welcome()).await.is_err() {
                return;
            }
        }
    });
    let signal = wait_on(&mut stream, None)
        .await
        .expect("the backstop must fire");
    assert_eq!(signal.reason, WakeReason::Backstop);
    assert!(
        started.elapsed() <= POLL,
        "starved: {:?}",
        started.elapsed()
    );
}

/// Controls: a NON-empty welcome and a lagged welcome return at once (there
/// is mail), and an explicit timeout tighter than the poll still bounds the
/// wait.
#[tokio::test(start_paused = true)]
async fn a_non_empty_or_lagged_welcome_returns_and_a_timeout_still_bounds_4058() {
    let (mut stream, inject) = WakeStream::start_injectable(cfg()).expect("start");
    let mut pending = empty_welcome();
    pending.pending_count = 2;
    inject.send(pending.clone()).await.expect("inject");
    let got = wait_on(&mut stream, None).await.expect("mail");
    assert_eq!(got, pending);

    inject
        .send(WakeSignal::bare(WakeReason::Lagged))
        .await
        .expect("inject");
    let got = wait_on(&mut stream, None).await.expect("lagged");
    assert_eq!(got.reason, WakeReason::Lagged);

    let started = Instant::now();
    let got = wait_on(&mut stream, Some(Duration::from_secs(2))).await;
    assert!(got.is_none(), "the explicit timeout expires first");
    assert!(started.elapsed() <= Duration::from_secs(2));
}

/// A real catch-up read (`note_read`) DOES restart the clock: that is the
/// contract #4058 keeps, and the one the empty welcome wrongly borrowed.
#[tokio::test(start_paused = true)]
async fn a_real_read_still_restarts_the_backstop_clock_4058() {
    let (mut stream, _inject) = WakeStream::start_injectable(cfg()).expect("start");
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(9)).await;
    stream.note_read();
    let signal = wait_on(&mut stream, None)
        .await
        .expect("the backstop must fire");
    assert_eq!(signal.reason, WakeReason::Backstop);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(19) && elapsed <= Duration::from_secs(9) + POLL,
        "a completed read restarts the interval: returned at {elapsed:?}"
    );
}

/// RED before #6233: a FAILED catch-up read still called `note_read()`, so a
/// failure at t=9 s moved the backstop to t=19 s and a persistently failing
/// read postponed the retry forever. Only a completed read restarts the clock.
#[tokio::test(start_paused = true)]
async fn a_failed_catch_up_read_does_not_postpone_the_backstop_6233() {
    let (mut stream, _inject) = WakeStream::start_injectable(cfg()).expect("start");
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(9)).await;
    let settled = settle_catch_up(
        &mut stream,
        Err(anyhow::anyhow!("inbox: database is locked")),
    );
    assert!(settled.is_none(), "a failed read yields no envelope");
    let signal = wait_on(&mut stream, None)
        .await
        .expect("the backstop must fire");
    assert_eq!(signal.reason, WakeReason::Backstop);
    let elapsed = started.elapsed();
    assert!(
        elapsed <= POLL,
        "a failed read must not postpone the backstop past one interval: returned at \
         {elapsed:?}, bound {POLL:?}"
    );
}

/// The completed-read half of the contract stays: a successful read restarts
/// the backstop clock (the read just proved the inbox state).
#[tokio::test(start_paused = true)]
async fn a_completed_catch_up_read_restarts_the_backstop_6233() {
    let (mut stream, _inject) = WakeStream::start_injectable(cfg()).expect("start");
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(9)).await;
    let settled = settle_catch_up(&mut stream, Ok(serde_json::json!({"count": 0})));
    assert!(settled.is_some());
    let signal = wait_on(&mut stream, None)
        .await
        .expect("the backstop must fire");
    assert_eq!(signal.reason, WakeReason::Backstop);
    assert!(
        started.elapsed() > POLL,
        "a completed read restarts the clock"
    );
}
