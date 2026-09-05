// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` OPS surface — metrics, health probe, SIGTERM drain
//! (issue [#3471](https://github.com/alphaonedev/ai-memory-mcp/issues/3471),
//! EPIC [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! Each property is asserted in BOTH directions, per the charter's both-paths
//! bar: the health probe against a live hub AND against a stopped one; a
//! delivery that succeeds AND one the byte cap refuses (with the CAUSE named);
//! a drain that completes inside its deadline AND leaves nothing behind.
//!
//! The unit-level halves live beside the code they pin — the `DirBuilder` leaf
//! mode and the fd-budget refusals in `src/wake_hub/startup.rs`, the socket
//! ownership rules in `src/wake_hub/server.rs`, the histogram bounds in
//! `src/wake_hub/histogram.rs`, and the doctor posture verdicts in
//! `src/cli/doctor_wake_hub.rs`.

mod wake_hub_harness;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ai_memory::wake_hub::frame::{Frame, Kind, WakeMeta};
use ai_memory::wake_hub::health::{self, HealthStatus};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use ai_memory::wake_hub::limits::{DRAIN_DEADLINE_MS, SLOW_CONSUMER_PERCENT};
use ai_memory::wake_hub::{HubConfig, startup};
use ed25519_dalek::SigningKey;
use wake_hub_harness::{Harness, TestVerifier};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn verifier_allowing(agents: &[(&str, &SigningKey)]) -> TestVerifier {
    let mut verifier = TestVerifier::new();
    for (id, signing_key) in agents {
        verifier.allow(id, signing_key);
    }
    verifier
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_millis(),
    )
    .expect("epoch millis fit u64")
}

// ---------------------------------------------------------------------------
// Health probe — the ALLOWED half
// ---------------------------------------------------------------------------

/// A live hub answers the probe with its challenge, and the probe reports the
/// filesystem posture the hub actually enforced.
#[tokio::test]
async fn health_probe_reports_a_live_hub_as_reachable() {
    let hub = Harness::with_verifier(verifier_allowing(&[]));

    let report = health::probe(&hub.socket).await;
    assert_eq!(report.status, HealthStatus::Reachable, "{}", report.status);
    assert_eq!(report.exit_code(), 0);
    assert!(
        report.latency_ms.is_some(),
        "a reachable hub must report how long the challenge took"
    );
    assert_eq!(report.posture.socket_mode, Some(startup::SOCKET_MODE));
    assert!(
        report.posture.is_hardened(),
        "a hub the probe reached must be 0600 in a 0700 directory it owns: {:?}",
        report.posture
    );

    // The probe is an ORDINARY client: it is accepted, counted, and reaped like
    // any other peer — no privileged side channel.
    let mut settled = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let s = hub.metrics.snapshot(0);
        if s.accepted >= 1 && s.connections_current == 0 {
            settled = true;
            break;
        }
    }
    assert!(
        settled,
        "the probe must be accepted like any peer and release its slot on close"
    );
    // It presented NO hello, so it can never have been admitted as an agent.
    assert_eq!(
        hub.metrics.snapshot(0).denied_hello,
        0,
        "the probe sends no hello at all, so it must not even reach the verifier"
    );

    hub.stop().await;
}

/// The DENIED half: a hub that is not running is `unreachable` and exits
/// non-zero. This is the property a supervisor depends on.
#[tokio::test]
async fn health_probe_exits_non_zero_once_the_hub_is_stopped() {
    let hub = Harness::with_verifier(verifier_allowing(&[]));
    let socket = hub.socket.clone();
    assert_eq!(health::probe(&socket).await.exit_code(), 0);

    hub.stop().await;

    let report = health::probe(&socket).await;
    assert!(
        !report.status.is_reachable(),
        "a stopped hub must never read as reachable, got {}",
        report.status
    );
    assert_eq!(report.exit_code(), health::EXIT_UNREACHABLE);
    assert!(
        !report.status.remedy().is_empty(),
        "an unreachable verdict must name the remedy"
    );
}

// ---------------------------------------------------------------------------
// SIGTERM drain
// ---------------------------------------------------------------------------

/// The drain closes every established session INSIDE its bounded deadline,
/// unlinks the socket it created, and leaves the connection gauge at zero.
#[tokio::test]
async fn the_drain_closes_every_session_inside_its_deadline() {
    let ids: Vec<String> = (0..4).map(|i| format!("drain-agent-{i}")).collect();
    let keys: Vec<SigningKey> = (0..4)
        .map(|i| key(40 + u8::try_from(i).expect("fits")))
        .collect();
    let pairs: Vec<(&str, &SigningKey)> = ids.iter().map(String::as_str).zip(keys.iter()).collect();
    let hub = Harness::with_verifier(verifier_allowing(&pairs));
    let socket = hub.socket.clone();

    let mut clients = Vec::new();
    for (id, k) in ids.iter().zip(keys.iter()) {
        let mut c = hub.connect().await;
        c.hello(id, k, &[]).await;
        assert_eq!(c.expect_frame().await.kind, Kind::Welcome);
        clients.push(c);
    }
    assert_eq!(hub.metrics.snapshot(0).connections_current, ids.len());
    let metrics = Arc::clone(&hub.metrics);

    let started = Instant::now();
    hub.stop().await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(DRAIN_DEADLINE_MS) + Duration::from_secs(3),
        "the drain must be BOUNDED; took {elapsed:?} against a {DRAIN_DEADLINE_MS} ms deadline"
    );
    assert_eq!(
        metrics.snapshot(0).connections_current,
        0,
        "every session must be reaped by the end of the drain"
    );
    // Every client observes a clean close, not a hang.
    for c in &mut clients {
        c.expect_closed().await;
    }
    // A probe against the drained path is honestly unreachable. (That the hub
    // unlinks only the socket IT created is pinned unit-side in
    // `src/wake_hub/server.rs`, where the harness's tempdir teardown cannot
    // make the assertion vacuous.)
    assert_eq!(
        health::probe(&socket).await.exit_code(),
        health::EXIT_UNREACHABLE
    );
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// A routed wake records fan-out latency, mint-to-delivery latency, and the
/// per-recipient queue census — the four ops questions #3471 exists to answer.
#[tokio::test]
async fn a_routed_wake_records_latency_and_the_queue_census() {
    let key_a = key(11);
    let key_b = key(12);
    let hub = Harness::with_verifier(verifier_allowing(&[
        ("agent-a", &key_a),
        ("agent-b", &key_b),
    ]));

    let mut receiver = hub.connect().await;
    receiver.hello("agent-b", &key_b, &[]).await;
    assert_eq!(receiver.expect_frame().await.kind, Kind::Welcome);

    let mut sender = hub.connect().await;
    sender.hello("agent-a", &key_a, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);

    // Stamp the mint time a second in the past so the wake-latency histogram
    // records a POSITIVE, checkable value rather than a sub-millisecond blur.
    let meta = WakeMeta {
        inbox_row_id: "row-3471".into(),
        namespace: "hive".into(),
        sender: "agent-a".into(),
        digest: vec![7u8; 32],
        seq_high_watermark: 1,
    }
    .encode()
    .expect("wake meta");
    let mut frame = Frame::new(Kind::Wake, "agent-a", "agent-b", meta);
    frame.ts_ms = now_ms() - 1_000;
    sender.send(frame).await;

    let delivered = receiver.expect_frame().await;
    assert_eq!(delivered.kind, Kind::Wake);

    let snap = hub.metrics.snapshot(0);
    assert_eq!(snap.wakes_routed, 1);
    assert_eq!(snap.fanout_deliveries, 1);
    assert_eq!(
        snap.fanout_latency.count, 1,
        "every routed wake must record its fan-out span"
    );
    assert_eq!(
        snap.wake_latency.count, 1,
        "a delivered wake carrying a mint stamp must record mint-to-delivery"
    );
    assert!(
        snap.wake_latency.max_us >= 1_000_000,
        "a wake minted one second ago must record at least one second, got {} us",
        snap.wake_latency.max_us
    );
    assert!(
        snap.fanout_latency.quantile_us(99) > 0,
        "a p99 with observations behind it must be a real number"
    );
    // Nothing was dropped, so every per-cause counter stays at zero.
    assert_eq!(snap.overflow, 0);
    assert_eq!(snap.drop_recipient_queue_full, 0);
    assert_eq!(snap.drop_global_egress_full, 0);
    assert_eq!(snap.drop_channel_full, 0);

    // The census is COMPUTED from the routing table: two authenticated
    // sessions, nothing backed up, nobody slow.
    let census = hub.router().queue_census();
    assert_eq!(census.recipients, 2, "both hellos installed a route");
    assert_eq!(census.slow_consumers, 0);
    assert!(census.queued_frames <= census.recipients);

    hub.stop().await;
}

/// The DENIED half of the metrics work: when a recipient stops reading, the
/// refusal is counted against the SPECIFIC bound that refused it — not one
/// undifferentiated `overflow` — and the slow-consumer signal fires BEFORE
/// anything is lost.
#[tokio::test]
async fn an_overflowing_recipient_names_the_bound_that_refused_it() {
    // Long ids + a full wake payload make each queued frame ~500 B, so the byte
    // cap is reached in a bounded number of sends.
    let sender_id = "s".repeat(120);
    let deaf_id = "d".repeat(120);
    let key_sender = key(21);
    let key_deaf = key(22);
    let hub = Harness::start(
        |cfg: &mut HubConfig| {
            // Take the rate limiter out of the picture: what is measured here
            // is unambiguously the BYTE budget.
            cfg.rate_per_sec = 1_000_000;
            cfg.rate_burst = 1_000_000;
            cfg.queue_bytes = 8 * 1_024;
            cfg.global_egress_bytes = 32 * 1_024;
        },
        Arc::new(verifier_allowing(&[
            (sender_id.as_str(), &key_sender),
            (deaf_id.as_str(), &key_deaf),
        ])),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    let mut deaf = hub.connect().await;
    deaf.hello(&deaf_id, &key_deaf, &[]).await;
    assert_eq!(deaf.expect_frame().await.kind, Kind::Welcome);

    let mut sender = hub.connect().await;
    sender.hello(&sender_id, &key_sender, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);

    let big_row = "r".repeat(80);
    let mut refused = false;
    'flood: for _round in 0..200 {
        for _ in 0..50 {
            sender.wake(&deaf_id, &big_row).await;
        }
        // Drain our own error queue so it cannot fill and mask the signal.
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(20), sender.read_frame()).await
        {
            if hub.metrics.snapshot(0).overflow >= 1 {
                refused = true;
                break 'flood;
            }
        }
        if hub.metrics.snapshot(0).overflow >= 1 {
            refused = true;
            break;
        }
    }
    assert!(
        refused,
        "a deaf recipient must eventually refuse a delivery"
    );

    let snap = hub.metrics.snapshot(0);
    let by_cause =
        snap.drop_recipient_queue_full + snap.drop_global_egress_full + snap.drop_channel_full;
    assert!(
        by_cause >= 1,
        "every overflow must be attributed to the bound that refused it, not left \
         as an undifferentiated total: {snap:?}"
    );
    assert!(
        by_cause <= snap.overflow,
        "the per-cause counters are a partition of the aggregate"
    );
    assert!(
        snap.slow_consumer_events >= 1,
        "the slow-consumer signal must fire BEFORE the drop it predicts"
    );

    // The census sees the backed-up recipient while it is still backed up.
    let census = hub.router().queue_census();
    assert!(
        census.queued_bytes > 0,
        "a deaf recipient's queue must be visible in the census"
    );
    assert!(
        census.slow_consumers >= 1,
        "a recipient at or above {SLOW_CONSUMER_PERCENT}% of its cap is a slow consumer: {census:?}"
    );
    assert!(
        census.queued_frames > 0,
        "the FRAME gauge must move too — bytes and frames are different bounds"
    );

    // Let the deaf peer go so the hub can reap it, then drain.
    deaf.shutdown_write().await;
    hub.stop().await;
}
