// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on a test binary.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
//! #3806 x #3822 / #3823 — the `[decision]` clients honour the SAME
//! transport rules the carrier's inference egress plane applies to the
//! `[llm]` and embedding lanes.
//!
//! Two properties, each with its control on the same sink:
//!
//! 1. **No redirect is ever followed.** The per-call outbound check
//!    approves the ORIGIN of the request URL the client builds; a `307`
//!    / `308` answered by that origin would make reqwest re-POST the
//!    same body (memory content) to wherever `Location` points, AFTER
//!    the check ran. Refusing to follow is the only way the approved
//!    origin stays the whole of the destination set. A redirect is not
//!    an answer: the seam is told `Unavailable` (case 2), never a
//!    verdict.
//! 2. **The `internal-only` pin reaches the socket.** Under
//!    `AI_MEMORY_INFERENCE_EGRESS=internal-only` the boot chokepoint
//!    resolves the endpoint once and hands the admitted addresses to the
//!    client (`construct_pinned`); the client must connect to THOSE
//!    addresses and nothing else (closing the DNS-rebind window, #3822).
//!
//! Every endpoint is a local mock; nothing here touches a real network.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::AppConfig;
use ai_memory::decision::AbstainReason;
use ai_memory::decision_clients::{OutboundCheck, construct_pinned};
use ai_memory::decision_config::{
    DecisionFallback, DecisionSection, ResolvedDecision, resolve_decision,
};
use ai_memory::egress::PinnedTarget;

fn permit() -> OutboundCheck {
    Arc::new(|_| Ok(()))
}

fn resolve_for(provider: &str, base_url: &str) -> ResolvedDecision {
    let cfg = AppConfig {
        decision: Some(DecisionSection {
            provider: Some(provider.to_string()),
            model: Some("vendor/decision-1".to_string()),
            base_url: Some(base_url.to_string()),
            api_key_env: None,
            api_key_file: None,
            api_key: None,
            timeout_secs: Some(2),
            fallback: Some(DecisionFallback::Abstain),
        }),
        ..AppConfig::default()
    };
    resolve_decision(&cfg).expect("a complete [decision] section must resolve")
}

async fn hits(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .len()
}

/// A chat body the openai-compatible client reads as a decided `yes`.
fn yes_chat() -> serde_json::Value {
    serde_json::json!({"choices": [{"message": {"role": "assistant",
        "content": "{\"verdict\":\"yes\"}"}}]})
}

// ---------------------------------------------------------------------
// 1. A redirect never carries a decision body to a second origin.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_never_carries_the_decision_body_to_a_second_origin() {
    for (provider, status) in [
        ("openai-compatible", 307_u16),
        ("openai-compatible", 308),
        ("systemone", 307),
    ] {
        // The destination the redirect points at. It would answer.
        let elsewhere = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(yes_chat()))
            .mount(&elsewhere)
            .await;
        // The approved origin answers every POST with a redirect.
        let approved = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", format!("{}/elsewhere", elsewhere.uri())),
            )
            .mount(&approved)
            .await;

        let resolved = resolve_for(provider, &approved.uri());
        let decider = construct_pinned(&resolved, permit(), None, None).expect("client constructs");
        let judgement = decider.judge("do these two records conflict?").await;

        // ABSENCE — the second origin never saw the body.
        assert_eq!(
            hits(&elsewhere).await,
            0,
            "{provider}/{status}: a redirect must never re-send the decision body to an \
             origin the egress gate did not approve"
        );
        // PRESENCE control — the approved origin WAS asked, exactly once,
        // so the absence above is not a client that never sent anything.
        assert_eq!(hits(&approved).await, 1, "{provider}/{status}");
        // A redirect is not an answer: an OUTAGE (case 2), never a verdict
        // and never a decline.
        assert_eq!(judgement.verdict(), None, "{provider}/{status}");
        assert_eq!(
            judgement.abstain_reason(),
            Some(AbstainReason::Unavailable),
            "{provider}/{status}"
        );
    }
}

// ---------------------------------------------------------------------
// 2. The internal-only pin reaches the socket.
// ---------------------------------------------------------------------

/// A mock bound to `ip:0` that answers every POST with a decided `yes`,
/// or `Err` when this host cannot bind `ip` (macOS has no `127.0.0.2`
/// unless an alias is installed: `AddrNotAvailable`, f1 delta N3).
async fn server_on(ip: [u8; 4]) -> std::io::Result<(MockServer, u16)> {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0)))?;
    let port = listener.local_addr()?.port();
    let server = MockServer::builder().listener(listener).start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(yes_chat()))
        .mount(&server)
        .await;
    Ok((server, port))
}

const PROMPT: &str = "do these two records conflict?";

/// PORTABLE half (every platform, f1 delta N3). The mock listens on
/// `127.0.0.1`, which the system resolver reaches for `localhost`:
///
/// * CONTROL — the UNPINNED client reaches it through the resolver;
/// * the pin OVERRIDES resolution — the same section pinned to `[::1]`
///   (nothing listens on `[::1]:<port>`; the mock is IPv4-only) does NOT
///   reach it, although the resolver would have: the client dialled the
///   pinned address and only that;
/// * PRESENCE — pinned to `127.0.0.1`, it reaches the mock.
#[tokio::test(flavor = "multi_thread")]
async fn the_internal_only_pin_overrides_resolution_portable() {
    let (server, port) = server_on([127, 0, 0, 1]).await.expect("bind 127.0.0.1");
    let resolved = resolve_for("openai-compatible", &format!("http://localhost:{port}"));

    let unpinned = construct_pinned(&resolved, permit(), None, None).expect("unpinned");
    assert_eq!(unpinned.judge(PROMPT).await.verdict(), Some(true));
    assert_eq!(
        hits(&server).await,
        1,
        "control: the resolver reaches 127.0.0.1"
    );

    let elsewhere = PinnedTarget {
        host: "localhost".to_string(),
        addrs: vec![SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))],
    };
    let pinned_away =
        construct_pinned(&resolved, permit(), None, Some(&elsewhere)).expect("pinned");
    let judgement = pinned_away.judge(PROMPT).await;
    assert_eq!(judgement.verdict(), None, "pinned elsewhere: no answer");
    assert_eq!(
        hits(&server).await,
        1,
        "a client pinned to [::1] must not fall back to the resolver's 127.0.0.1"
    );

    let here = PinnedTarget {
        host: "localhost".to_string(),
        addrs: vec![SocketAddr::from(([127, 0, 0, 1], port))],
    };
    let pinned = construct_pinned(&resolved, permit(), None, Some(&here)).expect("pinned");
    assert_eq!(pinned.judge(PROMPT).await.verdict(), Some(true));
    assert_eq!(hits(&server).await, 2);
}

/// SECOND-LOOPBACK half: the pin reaches an address the resolver NEVER
/// yields for `localhost` (`127.0.0.2`). The cell is compiled for Linux ONLY,
/// where every `127.0.0.0/8` address is bindable. #4177: it used to print
/// `skip:` and `return` on other platforms, so it reported ok on macOS
/// without testing anything. The portable half,
/// `the_internal_only_pin_overrides_resolution_portable`, still asserts the
/// pin on every platform.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn the_internal_only_pin_is_what_the_client_connects_to() {
    let (server, port) = server_on([127, 0, 0, 2])
        .await
        .unwrap_or_else(|e| panic!("bind 127.0.0.2: {e}"));
    let resolved = resolve_for("openai-compatible", &format!("http://localhost:{port}"));

    // PRESENCE — pinned to 127.0.0.2, the client reaches the server and
    // the answer decides.
    let pin = PinnedTarget {
        host: "localhost".to_string(),
        addrs: vec![SocketAddr::from(([127, 0, 0, 2], port))],
    };
    let pinned = construct_pinned(&resolved, permit(), None, Some(&pin)).expect("pinned");
    let judgement = pinned.judge(PROMPT).await;
    assert_eq!(
        judgement.verdict(),
        Some(true),
        "a pinned client must connect to the pinned address ({:?})",
        judgement.abstain_reason()
    );
    assert_eq!(hits(&server).await, 1);

    // ABSENCE control on the same sink — the SAME resolved section with
    // NO pin resolves `localhost` through the system resolver, which
    // never yields 127.0.0.2, so the server is not reached: the presence
    // above is the pin's doing and not a resolver accident.
    let unpinned = construct_pinned(&resolved, permit(), None, None).expect("unpinned");
    let judgement = unpinned.judge(PROMPT).await;
    assert_eq!(judgement.verdict(), None);
    assert_eq!(
        hits(&server).await,
        1,
        "without the pin the 127.0.0.2 server must not be reached"
    );
}
