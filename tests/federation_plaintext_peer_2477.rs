// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! #2477 (SECURITY) — a federation peer URL must not carry PLAINTEXT
//! memory content off-host.
//!
//! ## The defect
//!
//! `FederationConfig::build` (`src/federation/peer.rs`) formatted the raw
//! operator-supplied `--quorum-peers` string straight into
//! `PeerEndpoint::sync_push_url` with **no scheme validation whatsoever**,
//! and `cli::sync::build_sync_client` (`ai-memory sync-daemon --peers`) —
//! a second, fully independent peer-URL door — did the same. Federation
//! replicates memory content that is NOT end-to-end encrypted
//! (`src/encryption/mod.rs`; #1968 open), so `http://peer.example:9077`
//! shipped tenant memory in the clear to anyone on the path.
//!
//! That trivially bypassed the four-condition opt-in ceremony #2448 built
//! for the strictly WEAKER "accept ANY server cert" case
//! (`--insecure-skip-server-verify` + `--client-cert` + `--client-key` +
//! an explicit falsy `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY`): plain
//! `http://` needed none of them. `docs/encryption.html` meanwhile asserted
//! unqualified that peer traffic "travels over mutual TLS ... TLS 1.3 only
//! (no fallback)".
//!
//! ## R-203
//!
//! Parent commit `03bbd556`. The refusal tests below FAIL there — `build`
//! and `build_sync_client` both return `Ok` for an `http://` non-loopback
//! peer. Observed failure at the parent:
//!
//! ```text
//! thread 'quorum_build_refuses_plaintext_non_loopback_peer_2477' panicked:
//!   #2477: a plaintext non-loopback peer must be REFUSED at boot; build()
//!   accepted it and would replicate memory content in the clear
//! ```
//!
//! The loopback-exemption and hatch tests are posture guards: they pass at
//! the parent for the wrong reason (nothing was ever refused), and exist to
//! block an over-broad fix that would brick every dev mesh and CI fixture
//! in this repo (dozens of `http://127.0.0.1:PORT` peers).
//!
//! Design: 3x3 adversarial vote (9 lenses, option D 6/9), citing the
//! 5-agent vote `4d3ea1c5`.

use std::time::Duration;
use tokio::sync::Mutex;

use ai_memory::federation::FederationConfig;

/// Process-global lock — these tests mutate the process-wide hatch env var.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const HATCH: &str = "AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS";

fn clear_hatch() {
    unsafe { std::env::remove_var(HATCH) };
}

fn set_hatch(v: &str) {
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

// ---------------------------------------------------------------------------
// R-203 — the refusal
// ---------------------------------------------------------------------------

/// R-203. THE defect on door #1 (`serve --quorum-peers`).
#[tokio::test]
async fn quorum_build_refuses_plaintext_non_loopback_peer_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    let got = build_one("http://peer.example:9077");
    assert!(
        got.is_err(),
        "#2477: a plaintext non-loopback peer must be REFUSED at boot; \
         build() accepted it and would replicate memory content in the clear"
    );
    let msg = match got {
        Err(e) => format!("{e}"),
        Ok(_) => unreachable!("asserted Err above"),
    };
    assert!(
        msg.contains("peer.example"),
        "refusal must name the offending peer: {msg}"
    );
    // The refusal must steer the operator to FIX the posture, naming the
    // secure remedies BEFORE the escape hatch (the #2448 ordering rule —
    // a control whose message leads with "here's how to turn me off" is
    // a control that gets turned off).
    let https_at = msg.find("https://").expect("names https:// remedy");
    let hatch_at = msg.find(HATCH).expect("names the escape hatch");
    assert!(
        https_at < hatch_at,
        "secure remedies must be named BEFORE the escape hatch: {msg}"
    );
}

/// R-203. The SECOND door — `ai-memory sync-daemon --peers`. A fix scoped
/// only to `federation/peer.rs` would leave this one wide open, so the
/// refusal is theatre without it.
#[tokio::test]
async fn sync_daemon_refuses_plaintext_non_loopback_peer_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    let args = ai_memory::cli::sync::SyncDaemonArgs {
        peers: vec!["http://peer.example:9077".to_string()],
        interval: 2,
        api_key: None,
        batch_size: 500,
        client_cert: None,
        client_key: None,
        insecure_skip_server_verify: false,
        ca_cert: None,
    };
    let got = ai_memory::cli::sync::build_sync_client(&args).await;
    assert!(
        got.is_err(),
        "#2477: the sync-daemon peer door must refuse plaintext non-loopback \
         peers too — it is an independent path from FederationConfig::build"
    );
}

/// R-203. A scheme-less peer (`peer.example:9077`) was silently accepted
/// and produced a `sync_push_url` that could only fail opaquely at request
/// time. Refusing at boot is strictly clearer — and closes the door on a
/// non-`http`/`https` transport slipping in.
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

// ---------------------------------------------------------------------------
// Posture guards — an over-broad fix must NOT brick these
// ---------------------------------------------------------------------------

/// GUARD. `https://` is always fine, hatch or no hatch.
#[tokio::test]
async fn https_peer_is_always_accepted_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    let cfg = build_one("https://peer.example:9077").expect("https must build");
    assert_eq!(cfg.expect("Some for quorum_writes=1").peer_count(), 1);
}

/// GUARD. LITERAL loopback plaintext is exempt UNCONDITIONALLY — no hatch,
/// no warning-driven config churn. Dozens of this repo's own fixtures and
/// every single-host dev mesh use `http://127.0.0.1:PORT`; the bytes never
/// leave the kernel, so none of the disclosure risk applies. Mirrors the
/// inbound `tls_bind_guard`'s silent loopback exemption.
#[tokio::test]
async fn loopback_plaintext_peers_are_exempt_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    for peer in [
        "http://127.0.0.1:9077",
        "http://localhost:9077",
        "http://[::1]:9077",
    ] {
        assert!(
            build_one(peer).is_ok(),
            "#2477: loopback plaintext peer {peer} must stay exempt"
        );
    }
}

/// GUARD. A container-bridge hostname is NOT loopback. `http://ic-bob:9077`
/// crosses an interceptable virtual NIC, so treating "feels local" as "is
/// local" would be the exact category error this control exists to prevent
/// — this repo's own `infra/plan-c` fleet uses that shape and therefore
/// carries the explicit hatch.
#[tokio::test]
async fn container_hostname_is_not_treated_as_loopback_2477() {
    let _g = ENV_LOCK.lock().await;
    clear_hatch();
    assert!(
        build_one("http://ic-bob:19077").is_err(),
        "#2477: a container-bridge hostname must NOT be exempted as loopback"
    );
}

/// #2677 — pin EXACTNESS of the loopback exemption. Happy-path loopback tests
/// would still pass if `host_is_loopback` were weakened to `starts_with("127.")`
/// or `contains("localhost")`, which would accept plaintext peers on attacker
/// hosts. Spoof shapes must stay refused without the hatch.
#[tokio::test]
async fn loopback_spoof_shapes_are_refused_not_exempt_2677() {
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
            "#2677: spoof loopback peer must be REFUSED (exact host match only): {peer}"
        );
    }
    // url crate normalises decimal/hex IPv4 to 127.0.0.1 — true loopback;
    // pin acceptance so a behaviour flip is deliberate.
    for peer in ["http://2130706433:9077", "http://0x7f000001:9077"] {
        assert!(
            build_one(peer).is_ok(),
            "#2677: decimal/hex IPv4 loopback forms must stay exempt after URL \
             normalisation: {peer}"
        );
    }
}

/// GUARD. The staged-rollout hatch works, and only on an explicit truthy
/// token: an unrecognised value must never silently widen the control
/// (the FBL-14 rule).
#[tokio::test]
async fn hatch_opens_only_on_an_explicit_truthy_token_2477() {
    let _g = ENV_LOCK.lock().await;
    for tok in ["1", "true", "yes", "on", "ON"] {
        set_hatch(tok);
        assert!(
            build_one("http://peer.example:9077").is_ok(),
            "#2477: hatch token {tok:?} must open the refusal"
        );
    }
    for tok in ["0", "false", "no", "off", "", "maybe", "sure"] {
        set_hatch(tok);
        assert!(
            build_one("http://peer.example:9077").is_err(),
            "#2477: non-truthy hatch token {tok:?} must KEEP the refusal \
             (an unrecognised token must never widen a security control)"
        );
    }
    clear_hatch();
}

/// GUARD. Refusal is WHOLE-BOOT, never per-peer skip-and-continue: one bad
/// peer in a list must not silently shrink `n = 1 + peer_urls.len()` (which
/// feeds `QuorumPolicy::new`) and thereby change the quorum guarantee
/// without saying so.
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

/// GUARD. The `asi-hard` posture pins the hatch OFF, so a hardened
/// procurement deployment cannot re-open plaintext federation — the
/// no-disable contract that #2448 established one door over.
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
