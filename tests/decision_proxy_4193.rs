// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4193 — outside the `allow` posture, the decision client never routes
//! through an environment proxy.
//!
//! `AI_MEMORY_INFERENCE_EGRESS=loopback-only` admits a loopback decision
//! endpoint. Before #4193 the decision client applied `.no_proxy()` only under
//! the internal-only pin, so `HTTP_PROXY` / `ALL_PROXY` in the environment sent
//! the admitted call (the Bearer key plus memory content) to an off-host proxy
//! the egress gate never approved. Redirects are already refused in every
//! posture (`a_redirect_never_carries_the_decision_body_to_a_second_origin`).

mod common;

use std::sync::Arc;

use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::AppConfig;
use ai_memory::decision_clients::{OutboundCheck, construct_pinned};
use ai_memory::decision_config::{DecisionFallback, DecisionSection, resolve_decision};

fn yes_chat() -> serde_json::Value {
    serde_json::json!({"choices": [{"message": {"role": "assistant",
        "content": "{\"verdict\":\"yes\"}"}}]})
}

async fn answering_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(yes_chat()))
        .mount(&server)
        .await;
    server
}

async fn hits(server: &MockServer) -> usize {
    server.received_requests().await.expect("recorded").len()
}

/// RED on 65642b3cf: the proxy receives the decision POST. GREEN: the
/// approved loopback endpoint receives it and the proxy receives nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_restricted_posture_never_routes_the_decision_call_through_a_proxy_4193() {
    let approved = answering_server().await;
    let proxy = answering_server().await;
    let proxy_url = proxy.uri();
    let _env = common::MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_INFERENCE_EGRESS", Some("loopback-only")),
        ("HTTP_PROXY", Some(proxy_url.as_str())),
        ("http_proxy", Some(proxy_url.as_str())),
        ("ALL_PROXY", Some(proxy_url.as_str())),
        ("all_proxy", Some(proxy_url.as_str())),
        ("NO_PROXY", None),
        ("no_proxy", None),
    ]);

    let cfg = AppConfig {
        decision: Some(DecisionSection {
            provider: Some("openai-compatible".to_string()),
            model: Some("vendor/decision-1".to_string()),
            base_url: Some(approved.uri()),
            api_key_env: None,
            api_key_file: None,
            api_key: None,
            timeout_secs: Some(2),
            fallback: Some(DecisionFallback::Abstain),
        }),
        ..AppConfig::default()
    };
    let resolved = resolve_decision(&cfg).expect("resolves");
    let permit: OutboundCheck = Arc::new(|_| Ok(()));
    let decider = construct_pinned(&resolved, permit, None, None).expect("constructs");
    let judgement = decider.judge("do these two records conflict?").await;

    assert_eq!(
        hits(&proxy).await,
        0,
        "a loopback-only decision call must never reach an environment proxy"
    );
    assert_eq!(
        hits(&approved).await,
        1,
        "the approved endpoint answers directly"
    );
    assert_eq!(judgement.verdict(), Some(true));
}

/// #4193 amendment (vote 753506d9), lifted from SECPROG L1's
/// `l1_system_proxy_never_carries_a_loopback_decision_call`: under the
/// DEFAULT `allow` posture a loopback plaintext decision endpoint must never
/// go through an environment proxy (it would leave the host in cleartext).
/// RED on e8532dc16, which honoured the proxy under `allow` (proxy 1, target 0).
#[tokio::test(flavor = "multi_thread")]
async fn under_allow_a_loopback_decision_call_never_uses_a_proxy_4193() {
    let approved = answering_server().await;
    let proxy = answering_server().await;
    let proxy_url = proxy.uri();
    let _env = common::MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_INFERENCE_EGRESS", None),
        ("HTTP_PROXY", Some(proxy_url.as_str())),
        ("http_proxy", Some(proxy_url.as_str())),
        ("ALL_PROXY", Some(proxy_url.as_str())),
        ("all_proxy", Some(proxy_url.as_str())),
        ("NO_PROXY", None),
        ("no_proxy", None),
    ]);
    let cfg = AppConfig {
        decision: Some(DecisionSection {
            provider: Some("openai-compatible".to_string()),
            model: Some("vendor/decision-1".to_string()),
            base_url: Some(approved.uri()),
            api_key_env: None,
            api_key_file: None,
            api_key: None,
            timeout_secs: Some(2),
            fallback: Some(DecisionFallback::Abstain),
        }),
        ..AppConfig::default()
    };
    let resolved = resolve_decision(&cfg).expect("resolves");
    let permit: OutboundCheck = Arc::new(|_| Ok(()));
    let decider = construct_pinned(&resolved, permit, None, None).expect("constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(
        hits(&proxy).await,
        0,
        "loopback under allow must not use the proxy"
    );
    assert_eq!(
        hits(&approved).await,
        1,
        "the approved endpoint answers directly"
    );
    assert_eq!(judgement.verdict(), Some(true));
}
