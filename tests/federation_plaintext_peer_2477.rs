// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! #2477 → #3705 (SECURITY) — a federation peer URL must never carry
//! PLAINTEXT memory content. Anywhere.
//!
//! ## History
//!
//! #2477 closed the door `FederationConfig::build` and
//! `cli::sync::build_sync_client` left open (no scheme validation at all:
//! `http://peer.example:9077` shipped tenant memory in the clear), but it
//! EXEMPTED literal loopback peers and shipped an acknowledgement hatch
//! (`AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS`). The operator mandate behind
//! #3705 — *"only encrypted data in transit … anywhere"* — removes both:
//! loopback is shared by every local process on a multi-agent host (*peer
//! is loopback* is not *peer is trusted*, the #2502 ruling), and a reachable
//! downgrade path is a defect even when never taken.
//!
//! ## What this file pins now
//!
//! * every `http://` peer is REFUSED — non-loopback, literal loopback,
//!   decimal/hex loopback, spoofed-loopback shapes — on BOTH doors;
//! * the refusal names the #3705 mandate and steers to `https://`, and
//!   never offers a hatch;
//! * the hatch itself is closed for good: no token opens it, and a truthy
//!   value is a boot refusal in its own right (pinned in
//!   `tests/transit_encryption_3705.rs`);
//! * `https://` builds; a scheme-less / foreign-scheme peer still refuses;
//!   one plaintext peer refuses the WHOLE build (never a silent quorum
//!   shrink); `asi-hard` keeps the hatch pinned unset.
//!
//! Every `_3705` refusal test FAILS on the #3700 parent commit `4b7ddb963`,
//! where `validate_peer_url_scheme` accepts `http://127.0.0.1:9077` (the
//! loopback exemption) and honours the hatch for non-loopback peers.

use std::time::Duration;
use tokio::sync::Mutex;

use ai_memory::federation::FederationConfig;

/// Process-global lock — these tests mutate the process-wide hatch env var.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const HATCH: &str = "AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS";

fn clear_hatch() {
    // SAFETY: serialised by ENV_LOCK; no other thread reads the hatch here.
    unsafe { std::env::remove_var(HATCH) };
}

fn set_hatch(v: &str) {
    // SAFETY: serialised by ENV_LOCK; no other thread reads the hatch here.
    unsafe { std::env::set_var(HATCH, v) };
}

/// Build a one-peer quorum config the way `bootstrap_serve` does.
fn build_one(peer: &str) -> anyhow::Result<Option<FederationConfig>> {
    FederationConfig::build(
        1,
        &[peer.to_string()],
        Duration::from_secs(5),
        None,
        None,
        None,
        "ai:scheme-guard-test".to_string(),
        None,
    )
}

fn refusal_of(peer: &str) -> String {
    match build_one(peer) {
        Err(e) => format!("{e}"),
        Ok(_) => panic!(
            "#3705: a plaintext peer must be REFUSED at boot; build() accepted {peer:?} \
             and would replicate memory content in the clear"
        ),
    }
}

// ---------------------------------------------------------------------------
// The refusal — door #1 (`serve --quorum-peers`)
// ---------------------------------------------------------------------------

/// A plaintext NON-loopback peer is refused (unchanged from #2477); the
/// refusal now names the mandate and offers no hatch.
///
/// FAILS ON THE PARENT: the message names `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS`
/// as the escape path (`assert!(!msg.contains(HATCH))`).
#[tokio::test]
async fn quorum_build_refuses_plaintext_non_loopback_peer_3705() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    let msg = refusal_of("http://peer.example:9077");
    assert!(
        msg.contains("peer.example"),
        "refusal must name the offending peer: {msg}"
    );
    assert!(
        msg.contains("#3705"),
        "refusal must name the mandate: {msg}"
    );
    assert!(
        msg.contains("https://"),
        "refusal must steer to https: {msg}"
    );
    assert!(
        !msg.contains(HATCH),
        "no downgrade path may be offered any more: {msg}"
    );
}

/// LITERAL loopback plaintext peers are REFUSED — the #2477 exemption is
/// gone. Loopback is shared by every local process.
///
/// FAILS ON THE PARENT: `build_one("http://127.0.0.1:9077")` is `Ok`.
#[tokio::test]
async fn loopback_plaintext_peers_are_refused_3705() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    for peer in [
        "http://127.0.0.1:9077",
        "http://localhost:9077",
        "http://[::1]:9077",
        // url/reqwest normalise decimal/hex IPv4 forms to 127.0.0.1 — still
        // plaintext, still refused.
        "http://2130706433:9077",
        "http://0x7f000001:9077",
    ] {
        let msg = refusal_of(peer);
        assert!(
            msg.contains("#3705") && msg.contains("loopback included"),
            "#3705: loopback plaintext peer {peer} must be refused with the mandate text: {msg}"
        );
    }
}

/// #2677 spoof shapes stay refused (they never were loopback).
#[tokio::test]
async fn loopback_spoof_shapes_are_refused_2677() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    for peer in [
        "http://127.0.0.1.evil.com:9077",
        "http://localhost.evil.com:9077",
        "http://evil.com/?x=127.0.0.1",
        "http://127.0.0.2:9077",
    ] {
        assert!(
            build_one(peer).is_err(),
            "#2677: spoof loopback peer must be REFUSED: {peer}"
        );
    }
}

/// A container-bridge hostname was never loopback; still refused.
#[tokio::test]
async fn container_hostname_is_refused_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    assert!(
        build_one("http://ic-bob:19077").is_err(),
        "#2477: a container-bridge hostname must be refused"
    );
}

// ---------------------------------------------------------------------------
// The refusal — door #2 (`ai-memory sync-daemon --peers`)
// ---------------------------------------------------------------------------

/// The sync-daemon door refuses plaintext peers too — loopback included.
///
/// FAILS ON THE PARENT: `http://127.0.0.1:9077` builds a sync client.
#[tokio::test]
async fn sync_daemon_refuses_every_plaintext_peer_3705() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    for peer in ["http://peer.example:9077", "http://127.0.0.1:9077"] {
        let args = ai_memory::cli::sync::SyncDaemonArgs {
            peers: vec![peer.to_string()],
            interval: 2,
            api_key: None,
            batch_size: 500,
            client_cert: None,
            client_key: None,
            insecure_skip_server_verify: false,
            ca_cert: None,
        };
        let got = ai_memory::cli::sync::build_sync_client(&args).await;
        let msg = match got {
            Err(e) => format!("{e}"),
            Ok(_) => panic!("#3705: the sync-daemon door must refuse plaintext peer {peer}"),
        };
        assert!(msg.contains("#3705"), "{peer}: {msg}");
    }
}

// ---------------------------------------------------------------------------
// The hatch is closed for good
// ---------------------------------------------------------------------------

/// No token opens the plaintext-peer hatch any more — truthy, falsy,
/// empty or garbage, the refusal stands. (A TRUTHY value is additionally a
/// boot refusal in its own right — `tests/transit_encryption_3705.rs`.)
///
/// FAILS ON THE PARENT: `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS=1` opens the
/// refusal for `http://peer.example:9077`.
#[tokio::test]
async fn hatch_never_opens_the_refusal_3705() {
    let _g = ENV_LOCK.lock().await;
    for tok in ["1", "true", "yes", "on", "ON", "0", "false", "", "maybe"] {
        set_hatch(tok);
        assert!(
            build_one("http://peer.example:9077").is_err(),
            "#3705: hatch token {tok:?} must NOT open plaintext federation"
        );
        assert!(
            build_one("http://127.0.0.1:9077").is_err(),
            "#3705: hatch token {tok:?} must NOT open plaintext loopback federation"
        );
    }
    clear_hatch();
    assert!(
        !ai_memory::tls::plaintext_peers_allowed(),
        "the resolver is pinned closed"
    );
}

// ---------------------------------------------------------------------------
// Posture guards (unchanged contracts)
// ---------------------------------------------------------------------------

/// `https://` is always fine.
#[tokio::test]
async fn https_peer_is_always_accepted_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    let cfg = build_one("https://peer.example:9077").expect("https must build");
    assert_eq!(cfg.expect("Some for quorum_writes=1").peer_count(), 1);
    let cfg = build_one("https://127.0.0.1:9077").expect("https loopback must build");
    assert_eq!(cfg.expect("Some for quorum_writes=1").peer_count(), 1);
}

/// A scheme-less peer and a foreign scheme are refused at boot.
#[tokio::test]
async fn quorum_build_refuses_schemeless_and_foreign_scheme_peers_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    assert!(
        build_one("peer.example:9077").is_err(),
        "#2477: a scheme-less peer must be refused at boot"
    );
    assert!(
        build_one("ws://peer.example:9077").is_err(),
        "#2477: a non-HTTP(S) scheme must be refused at boot"
    );
}

/// Refusal is WHOLE-BOOT, never per-peer skip-and-continue.
#[tokio::test]
async fn one_plaintext_peer_refuses_the_whole_build_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    let got = FederationConfig::build(
        2,
        &[
            "https://good.example:9077".to_string(),
            "http://bad.example:9077".to_string(),
        ],
        Duration::from_secs(5),
        None,
        None,
        None,
        "ai:scheme-guard-test".to_string(),
        None,
    );
    assert!(
        got.is_err(),
        "#2477: a mixed list must refuse the whole build, not silently drop \
         the plaintext peer and shrink the quorum denominator"
    );
}

/// `asi-hard` keeps the (now inert) hatch pinned unset.
#[test]
fn asi_hard_pins_the_plaintext_hatch_off_2477() {
    let pins = ai_memory::security_profile::pinned_knobs();
    let (_, hard) = pins
        .iter()
        .find(|(e, _)| *e == HATCH)
        .expect("#2477: asi-hard must pin the plaintext-peer hatch");
    assert!(
        hard.is_empty(),
        "the hard floor is 'hatch not in force', got {hard:?}"
    );
}
