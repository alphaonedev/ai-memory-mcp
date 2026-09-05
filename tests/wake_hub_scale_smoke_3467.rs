// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` — 256-connection scale smoke (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! The adversarial vote sized this hub for 128-256 agents per instance and
//! found four defects that only show at that scale: frame-counted (not
//! byte-counted) queues, unbounded online egress, fan-out amplification the
//! rate cap could not see, and macOS's 256-fd default landing `EMFILE` at
//! exactly the design target. This suite is the standing check that those stay
//! fixed.
//!
//! It asserts BOUNDEDNESS, not a magic number:
//!
//! * file descriptors return to their baseline after the connections close, and
//!   never exceed a two-per-connection envelope;
//! * the hub-wide egress reservation never crosses its configured cap, and
//!   reaches zero once every connection is reaped;
//! * `connections_current` never exceeds the ceiling, during the ramp as well
//!   as at the end;
//! * on Linux (where `/proc/self/statm` gives a cheap, portable-enough RSS),
//!   resident-set growth across the run stays inside an envelope derived from
//!   the hub's OWN configured caps rather than a hand-tuned constant.
//!
//! The fd counter uses `fcntl(F_GETFD)` rather than `/proc/self/fd`, so the
//! same assertion runs on the `linux-fed` and `macos-fed` legs.

mod wake_hub_harness;

use std::sync::Arc;
use std::time::Duration;

use ai_memory::wake_hub::frame::Kind;
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use ai_memory::wake_hub::{HubConfig, limits};
use ed25519_dalek::SigningKey;
use wake_hub_harness::{Harness, TestVerifier};

/// The design target from the EPIC.
const TARGET_CONNECTIONS: usize = 256;

fn agent(index: usize) -> String {
    format!("a{index:03}")
}

fn agent_key(index: usize) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[0] = u8::try_from(index % 251).expect("fits");
    seed[1] = u8::try_from(index / 251).expect("fits");
    seed[2] = 0x5C;
    SigningKey::from_bytes(&seed)
}

fn verifier_for(count: usize) -> TestVerifier {
    let mut verifier = TestVerifier::new();
    for index in 0..count {
        let signing_key = agent_key(index);
        verifier.allow(&agent(index), &signing_key);
    }
    verifier
}

/// Count this process's open file descriptors, portably across Linux and
/// macOS, by probing each slot up to the soft `RLIMIT_NOFILE`.
fn count_open_fds() -> usize {
    let mut limit_pair = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes into a fully-owned, correctly-typed local.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit_pair) } != 0 {
        return 0;
    }
    let ceiling = i32::try_from(limit_pair.rlim_cur.min(65_536)).unwrap_or(i32::MAX);
    (0..ceiling)
        .filter(|slot| {
            // SAFETY: `fcntl(F_GETFD)` only reads a descriptor flag; on a
            // closed slot it returns -1 and sets EBADF.
            let rc = unsafe { libc::fcntl(*slot, libc::F_GETFD) };
            rc != -1
        })
        .count()
}

/// Resident set size in KiB, where it is cheap to read. `None` elsewhere.
fn rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        // SAFETY: `sysconf` reads a static system parameter.
        let page_kib = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()? / 1_024;
        Some(pages * page_kib)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scale_smoke_256_connections_keeps_memory_and_fds_bounded() {
    let hub = Harness::start(
        |hub_cfg: &mut HubConfig| {
            hub_cfg.max_connections = TARGET_CONNECTIONS;
        },
        Arc::new(verifier_for(TARGET_CONNECTIONS)),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    // The hub clamps its own ceiling to whatever `RLIMIT_NOFILE` actually
    // allows, so honour that rather than assuming 256 is reachable — the macOS
    // 256-fd default is the exact case the vote flagged, and a hub that clamps
    // and SAYS SO is behaving correctly.
    let ceiling = hub.connection_ceiling;
    assert!(
        ceiling >= limits::MIN_CONNECTION_CEILING,
        "the hub must refuse to start rather than serve a useless ceiling"
    );
    let target = TARGET_CONNECTIONS.min(ceiling);
    assert!(
        target >= 64,
        "this host's fd budget ({ceiling}) is too small to smoke-test scale"
    );

    let fds_before = count_open_fds();
    let rss_before = rss_kib();

    let mut clients = Vec::with_capacity(target);
    for index in 0..target {
        let mut client = hub.connect().await;
        client
            .hello(&agent(index), &agent_key(index), &["#hive".to_string()])
            .await;
        assert_eq!(
            client.expect_frame().await.kind,
            Kind::Welcome,
            "connection {index} of {target} must be welcomed"
        );
        clients.push(client);

        // Invariants must hold DURING the ramp, not only at the end.
        let counters = hub.metrics.snapshot(0);
        assert!(
            counters.connections_current <= ceiling,
            "connections_current {} exceeded the ceiling {ceiling}",
            counters.connections_current
        );
        assert!(
            hub.snapshot_egress() <= limits::DEFAULT_GLOBAL_EGRESS_BYTES,
            "queued egress crossed the hub-wide cap during the ramp"
        );
    }

    let peak_fds = count_open_fds();
    assert_eq!(
        hub.metrics.snapshot(0).connections_current,
        target,
        "every connection must be established"
    );

    // One fan-out across the whole fleet, to put the byte budgets under load.
    // Client 0 is subscribed too, so it is excluded from its own wake.
    clients[0].wake("#hive", "row-scale").await;
    for (index, client) in clients.iter_mut().enumerate().skip(1) {
        assert_eq!(
            client.expect_frame().await.kind,
            Kind::Wake,
            "recipient {index} must receive the fleet-wide wake"
        );
    }

    let counters = hub.metrics.snapshot(0);
    assert_eq!(
        counters.overflow, 0,
        "the default budgets must absorb one fleet-wide fan-out"
    );
    assert_eq!(
        counters.fanout_deliveries,
        u64::try_from(target - 1).expect("fits"),
        "the sender is excluded from its own broadcast"
    );
    assert_eq!(
        counters.rate_limited,
        0,
        "a single {target}-way fan-out must fit the {} burst",
        limits::DEFAULT_RATE_BURST
    );

    // --- fd boundedness ----------------------------------------------------
    // Each connection costs the test process TWO descriptors (the client end
    // and the hub's accepted end), plus the listener and a little slack.
    let fd_growth = peak_fds.saturating_sub(fds_before);
    assert!(
        fd_growth <= (2 * target) + 16,
        "fd growth {fd_growth} exceeds the 2-per-connection envelope for {target} connections"
    );

    // --- teardown returns the descriptors AND the byte budget ---------------
    drop(clients);
    let mut settled = peak_fds;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        settled = count_open_fds();
        if hub.metrics.snapshot(0).connections_current == 0 && settled <= fds_before + 16 {
            break;
        }
    }
    assert_eq!(
        hub.metrics.snapshot(0).connections_current,
        0,
        "every connection must be reaped"
    );
    assert!(
        settled <= fds_before + 16,
        "fds did not return to baseline: {fds_before} -> {settled} \
         (leak across {target} connections)"
    );
    assert_eq!(
        hub.snapshot_egress(),
        0,
        "every egress reservation must be released on teardown, or the hub-wide \
         budget leaks and eventually refuses everything"
    );

    // --- rss boundedness (Linux only; see module docs) ---------------------
    if let (Some(before), Some(after)) = (rss_before, rss_kib()) {
        let growth_kib = after.saturating_sub(before);
        // Envelope: the hub's own per-recipient byte cap for every connection,
        // plus the global egress cap, plus 64 MiB of allocator and task-stack
        // slack. Derived from the configured caps, not hand-tuned.
        let envelope_kib = u64::try_from(
            (target * limits::DEFAULT_RECIPIENT_QUEUE_BYTES + limits::DEFAULT_GLOBAL_EGRESS_BYTES)
                / 1_024,
        )
        .expect("fits")
            + 64 * 1_024;
        assert!(
            growth_kib <= envelope_kib,
            "RSS grew {growth_kib} KiB across {target} connections, past the \
             {envelope_kib} KiB envelope implied by the hub's own configured caps"
        );
    }

    hub.stop().await;
}

#[tokio::test]
async fn scale_smoke_the_connection_ceiling_refuses_rather_than_growing() {
    // A deliberately tiny ceiling: the (ceiling + 1)-th peer must be refused
    // and COUNTED, not admitted "just this once".
    let ceiling = limits::MIN_CONNECTION_CEILING;
    let hub = Harness::start(
        |hub_cfg: &mut HubConfig| {
            hub_cfg.max_connections = ceiling;
        },
        Arc::new(verifier_for(ceiling + 1)),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );
    assert_eq!(hub.connection_ceiling, ceiling);

    let mut held = Vec::new();
    for index in 0..ceiling {
        let mut client = hub.connect().await;
        client.hello(&agent(index), &agent_key(index), &[]).await;
        assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
        held.push(client);
    }

    // A raw connect: a refused peer receives an error, never the challenge the
    // harness `Client` waits for.
    let over_the_line = tokio::net::UnixStream::connect(&hub.socket)
        .await
        .expect("the listener still accepts");
    // Keep the peer alive until the credential gate has observed it. On macOS
    // an already-closed peer may no longer expose LOCAL_PEERPID, correctly
    // producing a credential refusal before capacity is considered.
    for _ in 0..100 {
        if hub.metrics.snapshot(0).denied_ceiling > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let counters = hub.metrics.snapshot(0);
    assert!(
        counters.denied_ceiling >= 1,
        "past the ceiling the hub must refuse and COUNT it, not grow"
    );
    assert!(counters.connections_current <= ceiling);
    drop(over_the_line);
    hub.stop().await;
}
