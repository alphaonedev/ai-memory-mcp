// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4193 (WP-EGRESS #6053) — the ONE posture-aware composition point every
//! `[llm]` inference client is built through (child module of `llm` so the
//! parent stays under its QUAL-10 ceiling).
//!
//! Before #4193, `.no_proxy()` and `redirect::Policy::none()` were applied
//! only by the `internal-only` pinned constructors (#3822, A3). Under
//! `loopback-only` — and `deny`, for the clients a CLI verb still
//! constructs — a process-wide `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`
//! routed a loopback-admitted inference call (bearer token plus memory
//! content) through an off-host proxy the posture never admitted, and a
//! 307/308 from the admitted endpoint re-POSTed the prompt to an origin the
//! gate never checked.
//!
//! The rule: the `allow` posture is byte-identical legacy (proxies honoured,
//! redirects followed — an operator who never opted in is unchanged); EVERY
//! other posture builds its client with proxies refused and redirects
//! disabled, because a restricted posture is a statement about which
//! origins may see memory content, and a proxy or a redirect is a second
//! origin the gate did not admit. The `internal-only` pin
//! (`OllamaClient::apply_internal_egress_pin`) layers its address pin on top
//! of this; re-applying `Policy::none()` / `.no_proxy()` there is idempotent.
//!
//! The posture is read once per client construction via
//! [`crate::egress::resolve_inference_egress_mode`] — the same resolver the
//! boot chokepoints and `reload` consult — so a client and its gate decision
//! are made under one posture value.

use crate::egress::{InferenceEgressMode, resolve_inference_egress_mode};

use super::{CONNECT_TIMEOUT, GENERATE_TIMEOUT};

/// Apply the #4193 proxy / redirect policy for `mode` to `builder`.
///
/// `Allow` returns the builder untouched (legacy); every other posture
/// disables redirects and proxies (explicit `.proxy(..)` entries and the
/// system / environment proxies alike).
#[must_use]
pub(super) fn apply_inference_egress_policy(
    builder: reqwest::ClientBuilder,
    mode: InferenceEgressMode,
) -> reqwest::ClientBuilder {
    match mode {
        InferenceEgressMode::Allow => builder,
        InferenceEgressMode::LoopbackOnly
        | InferenceEgressMode::Deny
        | InferenceEgressMode::InternalOnly => builder
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy(),
    }
}

/// The reqwest builder every inference client starts from: the F6 timeouts
/// plus the #4193 policy for the CURRENTLY resolved posture. Callers add
/// per-constructor extras (the `internal-only` address pin) on top.
#[must_use]
pub(super) fn inference_client_builder() -> reqwest::ClientBuilder {
    apply_inference_egress_policy(
        reqwest::Client::builder()
            .timeout(GENERATE_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT),
        resolve_inference_egress_mode(),
    )
}

#[cfg(test)]
mod tests {
    //! Env-free behavioural pins: the policy is exercised with the mode
    //! INJECTED (no `set_var`, per the #3822 pin contract) and a proxy
    //! injected on the builder, against in-process wiremock servers.

    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const RESTRICTED: [InferenceEgressMode; 3] = [
        InferenceEgressMode::LoopbackOnly,
        InferenceEgressMode::Deny,
        InferenceEgressMode::InternalOnly,
    ];

    async fn hits(server: &MockServer, p: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == p)
            .count()
    }

    fn with_proxy(proxy: &MockServer) -> reqwest::ClientBuilder {
        reqwest::Client::builder().proxy(reqwest::Proxy::all(proxy.uri()).expect("proxy url"))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restricted_postures_clear_an_injected_proxy_4193() {
        let proxy = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&proxy)
            .await;
        let target = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/models"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&target)
            .await;
        let url = format!("{}/models", target.uri());

        for mode in RESTRICTED {
            let client = apply_inference_egress_policy(with_proxy(&proxy), mode)
                .build()
                .expect("client builds");
            let resp = client.get(&url).send().await.expect("direct request");
            assert!(resp.status().is_success(), "{mode:?}: direct to target");
        }
        assert_eq!(
            proxy.received_requests().await.unwrap_or_default().len(),
            0,
            "#4193: a restricted posture must never route through a proxy"
        );
        assert_eq!(hits(&target, "/models").await, RESTRICTED.len());

        // Control: `allow` keeps the injected proxy (the proxy mock answers,
        // the target sees nothing new).
        let client = apply_inference_egress_policy(with_proxy(&proxy), InferenceEgressMode::Allow)
            .build()
            .expect("client builds");
        let resp = client.get(&url).send().await.expect("proxied request");
        assert!(resp.status().is_success());
        assert_eq!(proxy.received_requests().await.unwrap_or_default().len(), 1);
        assert_eq!(hits(&target, "/models").await, RESTRICTED.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restricted_postures_do_not_follow_redirects_4193() {
        let target = MockServer::start().await;
        let leaked = format!("{}/leaked", target.uri());
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", leaked.as_str()))
            .mount(&target)
            .await;
        Mock::given(method("GET"))
            .and(path("/leaked"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&target)
            .await;
        let url = format!("{}/start", target.uri());

        for mode in RESTRICTED {
            let client = apply_inference_egress_policy(reqwest::Client::builder(), mode)
                .build()
                .expect("client builds");
            let resp = client.get(&url).send().await.expect("request");
            assert_eq!(
                resp.status().as_u16(),
                307,
                "{mode:?}: the 3xx surfaces, it is not followed"
            );
        }
        assert_eq!(
            hits(&target, "/leaked").await,
            0,
            "#4193: a restricted posture must never follow a redirect"
        );

        // Control: `allow` follows it.
        let client =
            apply_inference_egress_policy(reqwest::Client::builder(), InferenceEgressMode::Allow)
                .build()
                .expect("client builds");
        let resp = client.get(&url).send().await.expect("request");
        assert!(resp.status().is_success());
        assert_eq!(hits(&target, "/leaked").await, 1);
    }
}
