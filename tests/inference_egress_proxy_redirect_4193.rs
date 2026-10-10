// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4193 (WP-EGRESS #6053) — outside the `allow` posture every `[llm]`
//! inference client refuses proxies and redirects.
//!
//! Before this fix `.no_proxy()` and `redirect::Policy::none()` were applied
//! ONLY by the `internal-only` pinned constructors (#3822). Under
//! `loopback-only` (and `deny`, for the clients a CLI verb still builds) a
//! process-wide `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` routed a
//! loopback-admitted inference call — bearer token plus memory content —
//! through an off-host proxy the posture never admitted, and the client
//! followed a 307/308 from the admitted endpoint to an origin that was never
//! checked. Both legs are pinned here on the PUBLIC constructors:
//!
//! 1. redirect: a 307 from the admitted endpoint is NOT followed (the probe
//!    reports the 3xx as not-available; the redirect target sees no request);
//! 2. proxy: an `HTTP_PROXY` in the environment receives ZERO requests under
//!    `loopback-only`; the admitted loopback endpoint is contacted directly.
//!
//! Each leg has an `allow` control that proves the fixture can detect the
//! leak (the legacy posture follows the redirect / honours the proxy), so a
//! green here is never an accident of the mock setup.
//!
//! This is an OWN-BINARY test on purpose: it mutates `HTTP_PROXY` and
//! `AI_MEMORY_INFERENCE_EGRESS`, which must never happen inside the shared
//! lib test binary (the `tests/hf_cache_staged_3788.rs` own-binary
//! precedent). A file-local mutex serialises the cells of this binary.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use ai_memory::llm::OllamaClient;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Serialises every env-mutating cell in this binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII scope: sets the given vars (`None` = unset) and restores the prior
/// values on drop, so a failing assertion cannot leak a proxy into a sibling.
struct EnvScope {
    _guard: MutexGuard<'static, ()>,
    prior: Vec<(&'static str, Option<String>)>,
}

impl EnvScope {
    fn new(vars: &[(&'static str, Option<&str>)]) -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut prior = Vec::with_capacity(vars.len());
        for (name, value) in vars {
            prior.push((*name, std::env::var(name).ok()));
            // SAFETY: serialised by `ENV_LOCK`; this binary's cells are the
            // only readers of these vars (own-binary test, see module doc).
            unsafe {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
        Self {
            _guard: guard,
            prior,
        }
    }
}

impl Drop for EnvScope {
    fn drop(&mut self) {
        for (name, value) in self.prior.drain(..) {
            // SAFETY: still serialised by the held `ENV_LOCK` guard.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

/// The env vars reqwest's system-proxy matcher reads, plus the posture knob.
const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];
const NO_PROXY_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];
const POSTURE_VAR: &str = "AI_MEMORY_INFERENCE_EGRESS";

/// Build the env table for one cell: the posture (or unset = `allow`), the
/// proxy vars all pointed at `proxy` (or all unset), and NO_PROXY cleared so
/// a sandbox-level loopback exemption cannot mask the control.
fn cell_env<'a>(
    posture: Option<&'a str>,
    proxy: Option<&'a str>,
) -> Vec<(&'static str, Option<&'a str>)> {
    let mut vars: Vec<(&'static str, Option<&str>)> = vec![(POSTURE_VAR, posture)];
    for name in PROXY_VARS {
        vars.push((name, proxy));
    }
    for name in NO_PROXY_VARS {
        vars.push((name, None));
    }
    vars
}

async fn hits(server: &MockServer, p: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == p)
        .count()
}

/// A target whose health route answers 307 to `/leaked`, which answers 200
/// with a well-formed models listing (so a FOLLOWED redirect reads as
/// "available").
async fn redirecting_target(health_path: &str) -> MockServer {
    let target = MockServer::start().await;
    let leaked = format!("{}/leaked", target.uri());
    Mock::given(method("GET"))
        .and(path(health_path))
        .respond_with(ResponseTemplate::new(307).insert_header("location", leaked.as_str()))
        .mount(&target)
        .await;
    Mock::given(method("GET"))
        .and(path("/leaked"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": [], "data": []})))
        .mount(&target)
        .await;
    target
}

fn build(openai: bool, base: &str) -> OllamaClient {
    if openai {
        OllamaClient::new_openai_compatible(base, "m", "k").expect("openai-compatible client")
    } else {
        OllamaClient::new_with_url_no_health_check(base, "m").expect("ollama client")
    }
}

// ─── Leg 1: redirects are not followed outside `allow` ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_only_client_does_not_follow_redirect_4193() {
    for (openai, health_path) in [(false, "/api/tags"), (true, "/models")] {
        let target = redirecting_target(health_path).await;
        // The constructor reads the posture, so the scope wraps construction.
        let available = {
            let _env = EnvScope::new(&cell_env(Some("loopback-only"), None));
            let client = build(openai, &target.uri());
            client.is_available_async().await
        };
        assert!(
            !available,
            "#4193 (openai={openai}): a 307 from the admitted endpoint must NOT be \
             followed under loopback-only; the probe must report the 3xx as not available"
        );
        assert_eq!(
            hits(&target, "/leaked").await,
            0,
            "#4193 (openai={openai}): the redirect target must see no request"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_control_follows_redirect_4193() {
    // Control: the legacy posture follows the redirect, so the fixture can
    // tell "followed" from "refused".
    for (openai, health_path) in [(false, "/api/tags"), (true, "/models")] {
        let target = redirecting_target(health_path).await;
        let available = {
            let _env = EnvScope::new(&cell_env(None, None));
            let client = build(openai, &target.uri());
            client.is_available_async().await
        };
        assert!(
            available,
            "control (openai={openai}): allow follows the 307"
        );
        assert_eq!(hits(&target, "/leaked").await, 1);
    }
}

// ─── Leg 2: the environment proxy receives nothing outside `allow` ───────

/// A catch-all proxy mock plus a direct target with a healthy route.
async fn proxy_and_target(health_path: &str) -> (MockServer, MockServer) {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": [], "data": []})))
        .mount(&proxy)
        .await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(health_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": [], "data": []})))
        .mount(&target)
        .await;
    (proxy, target)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_only_client_sends_nothing_to_env_proxy_4193() {
    for (openai, health_path) in [(false, "/api/tags"), (true, "/models")] {
        let (proxy, target) = proxy_and_target(health_path).await;
        let available = {
            let _env = EnvScope::new(&cell_env(Some("loopback-only"), Some(&proxy.uri())));
            let client = build(openai, &target.uri());
            client.is_available_async().await
        };
        assert!(
            available,
            "#4193 (openai={openai}): the admitted loopback endpoint is reached directly"
        );
        let proxied = proxy.received_requests().await.unwrap_or_default().len();
        assert_eq!(
            proxied, 0,
            "#4193 (openai={openai}): HTTP_PROXY must receive ZERO requests under loopback-only"
        );
        assert_eq!(hits(&target, health_path).await, 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_control_honours_env_proxy_4193() {
    // Control: under `allow` the legacy client honours HTTP_PROXY, so the
    // proxy mock sees the request and the direct target sees none.
    for (openai, health_path) in [(false, "/api/tags"), (true, "/models")] {
        let (proxy, target) = proxy_and_target(health_path).await;
        let available = {
            let _env = EnvScope::new(&cell_env(None, Some(&proxy.uri())));
            let client = build(openai, &target.uri());
            client.is_available_async().await
        };
        assert!(
            available,
            "control (openai={openai}): the proxy answers 200"
        );
        let proxied = proxy.received_requests().await.unwrap_or_default().len();
        assert_eq!(
            proxied, 1,
            "control (openai={openai}): allow routes the probe through HTTP_PROXY"
        );
        assert_eq!(hits(&target, health_path).await, 0);
    }
}

// ─── Leg 3: structural pin — one composition point, every base ctor ──────

fn read_src(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Extract the body of a `fn <name>(` … matching-brace region (the
/// `tests/inference_egress_pin_builder_3822.rs` precedent).
fn fn_body(src: &str, sig_prefix: &str) -> String {
    let start = src
        .find(sig_prefix)
        .unwrap_or_else(|| panic!("fn not found: {sig_prefix}"));
    let brace = src[start..]
        .find('{')
        .map(|i| start + i)
        .expect("fn body brace");
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut end = brace;
    for (i, &b) in bytes.iter().enumerate().skip(brace) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    src[brace..end].to_string()
}

#[test]
fn every_base_constructor_routes_through_the_posture_policy_4193() {
    let llm = read_src("src/llm.rs");
    for ctor in [
        "fn new_openai_compatible(",
        "fn new_with_url_no_health_check(",
        "fn new_openai_compatible_pinned(",
        "fn new_with_url_no_health_check_pinned(",
    ] {
        let body = fn_body(&llm, ctor);
        assert!(
            body.contains("inference_client_builder("),
            "#4193: {ctor} must build its reqwest client through \
             `egress_policy::inference_client_builder` (the ONE posture-aware \
             composition point); body:\n{body}"
        );
        assert!(
            !body.contains("reqwest::Client::builder()"),
            "#4193: {ctor} must not start from a bare reqwest builder; body:\n{body}"
        );
    }
    let policy = read_src("src/llm/egress_policy.rs");
    let body = fn_body(&policy, "fn apply_inference_egress_policy(");
    assert!(
        body.contains(".redirect(reqwest::redirect::Policy::none())"),
        "#4193: the policy must disable redirects outside allow; body:\n{body}"
    );
    assert!(
        body.contains(".no_proxy()"),
        "#4193: the policy must disable proxies outside allow; body:\n{body}"
    );
    assert!(
        body.contains("InferenceEgressMode::Allow"),
        "#4193: the policy is keyed on the posture, allow stays byte-identical; body:\n{body}"
    );
}
