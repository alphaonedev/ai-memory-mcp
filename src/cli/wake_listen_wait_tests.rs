// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4058 / #4087 — `wait_on`, the one-shot wait behind `ai-memory inbox
//! --wait`, driven with PAUSED Tokio time against the production backstop
//! loop. Hub-shaped signals are injected; nothing here fakes the clock the
//! backstop runs on.

use std::time::Duration;

use tokio::time::Instant;

use super::{HubLink, WaitDegraded, wait_on};
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
    let (mut stream, inject, _link) = WakeStream::start_injectable(cfg()).expect("start");
    let started = Instant::now();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(9)).await;
        let _ = inject.send(empty_welcome()).await;
    });
    let signal = wait_on(&mut stream, None, &mut |_| {})
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
    let (mut stream, inject, _link) = WakeStream::start_injectable(cfg()).expect("start");
    let started = Instant::now();
    tokio::spawn(async move {
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if inject.send(empty_welcome()).await.is_err() {
                return;
            }
        }
    });
    let signal = wait_on(&mut stream, None, &mut |_| {})
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
    let (mut stream, inject, _link) = WakeStream::start_injectable(cfg()).expect("start");
    let mut pending = empty_welcome();
    pending.pending_count = 2;
    inject.send(pending.clone()).await.expect("inject");
    let got = wait_on(&mut stream, None, &mut |_| {}).await.expect("mail");
    assert_eq!(got, pending);

    inject
        .send(WakeSignal::bare(WakeReason::Lagged))
        .await
        .expect("inject");
    let got = wait_on(&mut stream, None, &mut |_| {})
        .await
        .expect("lagged");
    assert_eq!(got.reason, WakeReason::Lagged);

    let started = Instant::now();
    let got = wait_on(&mut stream, Some(Duration::from_secs(2)), &mut |_| {}).await;
    assert!(got.is_none(), "the explicit timeout expires first");
    assert!(started.elapsed() <= Duration::from_secs(2));
}

/// #4087 — a hub that REFUSES this agent is reported to the caller the
/// moment it is known, instead of the wait silently riding out its timeout.
#[tokio::test(start_paused = true)]
async fn a_hub_refusal_is_reported_while_the_wait_stays_bounded_4087() {
    let (mut stream, _inject, link) = WakeStream::start_injectable(cfg()).expect("start");
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        link.send_replace(HubLink::Down {
            cause: "the hub refused the handshake: 401 unauthorized".into(),
            refused: true,
        });
        // Keep the sender alive for the rest of the wait.
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(link);
    });
    let mut seen = Vec::new();
    let signal = wait_on(&mut stream, None, &mut |s| seen.push(s.clone()))
        .await
        .expect("the backstop still bounds the wait");
    assert_eq!(signal.reason, WakeReason::Backstop);
    assert_eq!(seen.len(), 1, "reported exactly once: {seen:?}");
    assert!(matches!(&seen[0], HubLink::Down { refused: true, .. }));
}

/// The operator-facing line names the agent, the hub, the bound and BOTH
/// halves of the admission remediation.
#[test]
fn the_refusal_explanation_names_the_remediation_4087() {
    let resolved = super::Resolved {
        agent_id: "ai:codex-f2".into(),
        socket: Some("/run/user/1000/ai-memory-team/wake-hub.sock".into()),
        hub_id: "ai-memory-team-f2".into(),
        key_dir: "/k".into(),
        bundle: "/k/ai:codex-f2.a2a-hub.json".into(),
        client: WakeClientConfig::default(),
    };
    for degraded in [
        WaitDegraded::Refused {
            cause: "401".into(),
        },
        WaitDegraded::Credential {
            cause: "no bundle".into(),
        },
    ] {
        let line = degraded.explain(&resolved);
        for needle in [
            "ai:codex-f2",
            "CANNOT receive hub wakes",
            "identity delegate --scope a2a-hub --agent-id ai:codex-f2 --hub-id ai-memory-team-f2",
            "hub-cache --include-agent ai:codex-f2",
            "doctor --agent-id ai:codex-f2",
            "60s",
        ] {
            assert!(line.contains(needle), "missing {needle:?} in: {line}");
        }
        assert!(!line.contains('\n'), "one line: {line}");
    }
}
