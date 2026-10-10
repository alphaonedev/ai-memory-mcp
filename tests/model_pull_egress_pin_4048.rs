// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4048 (WP-EGRESS #6053, #3822 residual) — the Ollama model pulls
//! (`ensure_model_async` for the chat model, `ensure_embed_model_async` for
//! the embedding model) must send `/api/pull` through the SAME admitted
//! client as every other request of the `OllamaClient`, so the admission
//! policy that client carries — the `internal-only` address pin (#3822), and
//! the proxy / redirect refusal every restricted posture applies (#4193) —
//! governs the pull too.
//!
//! Before this fix both pulls built a FRESH `reqwest::Client` carrying no
//! policy at all: it re-resolved the host itself (escaping the pin), honoured
//! a process-wide `HTTP_PROXY` (sending the pull to an address the posture
//! never admitted), and followed a 307 from the admitted endpoint to an
//! origin the gate never checked. Three behavioural legs pin each escape,
//! each with a positive control so a green is never an accident of the mock:
//!
//! 1. DNS pin: the pinned constructor admits ONLY a loopback listener for a
//!    hostname the system resolver cannot resolve (`.invalid`, RFC 2606). A
//!    pull that carries the pin reaches that listener; a pull built outside
//!    the pin cannot even resolve the host, so the admitted listener sees no
//!    pull and the call errors.
//! 2. Proxy: under `loopback-only` an `HTTP_PROXY` listener on 127.0.0.1 is
//!    an address the posture excluded; it must receive ZERO requests while
//!    the admitted endpoint receives the pull directly.
//! 3. Redirect: under `loopback-only` a 307 from the admitted endpoint's
//!    `/api/pull` is NOT followed; the redirect target sees no request and
//!    the pull fails closed.
//!
//! A fourth, structural leg pins the shape: neither pull body builds a bare
//! `reqwest::Client`; both send through `self.client` with the per-request
//! `PULL_TIMEOUT` (reqwest documents a request timeout as overriding the
//! client's for that request), and the only bare builder left in the
//! production half of `src/llm.rs` is the `#[cfg(test)]`-only constructor.
//!
//! This is an OWN-BINARY test on purpose: it mutates `HTTP_PROXY` and
//! `AI_MEMORY_INFERENCE_EGRESS`, which must never happen inside the shared
//! lib test binary (the `tests/inference_egress_proxy_redirect_4193.rs`
//! precedent). A file-local mutex serialises the cells of this binary.

use std::net::SocketAddr;
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
        let guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

/// The chat model under test and the embedding model the Nomic lane pulls.
const CHAT_MODEL: &str = "pull-4048";
const EMBED_MODEL: &str = "nomic-embed-text";

/// Build the env table for one cell: the posture (or unset = `allow`), the
/// proxy vars all pointed at `proxy` (or all unset), and `NO_PROXY` cleared so
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

/// Mount the "model is missing" listing so every cell reaches the pull.
async fn mount_empty_tags(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(server)
        .await;
}

/// Mount a succeeding `/api/pull`.
async fn mount_pull_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/pull"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "success"})))
        .mount(server)
        .await;
}

/// Run the pull under test: the chat pull (`embed = false`) or the
/// embedding pull (`embed = true`).
async fn run_pull(client: &OllamaClient, embed: bool) -> anyhow::Result<()> {
    if embed {
        client.ensure_embed_model_async(EMBED_MODEL).await
    } else {
        client.ensure_model_async().await
    }
}

// ─── Leg 1: the internal-only address pin governs the pull ───────────────

/// A hostname the system resolver cannot resolve (RFC 2606 reserves
/// `.invalid`); only the pin can map it to the admitted listener.
const PINNED_HOST: &str = "pinned-4048.invalid";

fn pinned_client(admitted: &MockServer) -> OllamaClient {
    let addr: SocketAddr = admitted
        .address()
        .to_string()
        .parse()
        .expect("wiremock address parses");
    let base = format!("http://{PINNED_HOST}:{}", addr.port());
    OllamaClient::new_with_url_no_health_check_pinned(&base, CHAT_MODEL, PINNED_HOST, &[addr])
        .expect("pinned client builds")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_client_sends_the_pull_only_to_the_admitted_address_4048() {
    for embed in [false, true] {
        let admitted = MockServer::start().await;
        mount_empty_tags(&admitted).await;
        mount_pull_ok(&admitted).await;
        let result = {
            // No posture (allow) and no environment proxy: the pin is the ONLY
            // policy in play, so a pull that escapes it has nowhere to go.
            let _env = EnvScope::new(&cell_env(None, None));
            let client = pinned_client(&admitted);
            run_pull(&client, embed).await
        };
        assert_eq!(
            hits(&admitted, "/api/tags").await,
            1,
            "fixture (embed={embed}): the listing reached the admitted listener through the pin"
        );
        assert!(
            result.is_ok(),
            "#4048 (embed={embed}): the pull must carry the internal-only pin and reach the \
             admitted listener; got {result:?}"
        );
        assert_eq!(
            hits(&admitted, "/api/pull").await,
            1,
            "#4048 (embed={embed}): the admitted listener must receive the pull"
        );
    }
}

// ─── Leg 2: the environment proxy receives nothing outside `allow` ───────

/// A catch-all proxy mock plus a direct target that lists no model and
/// accepts the pull.
async fn proxy_and_target() -> (MockServer, MockServer) {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&proxy)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "success"})))
        .mount(&proxy)
        .await;
    let target = MockServer::start().await;
    mount_empty_tags(&target).await;
    mount_pull_ok(&target).await;
    (proxy, target)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_only_pull_sends_nothing_to_env_proxy_4048() {
    for embed in [false, true] {
        let (proxy, target) = proxy_and_target().await;
        let result = {
            let _env = EnvScope::new(&cell_env(Some("loopback-only"), Some(&proxy.uri())));
            let client = OllamaClient::new_with_url_no_health_check(&target.uri(), CHAT_MODEL)
                .expect("client builds");
            run_pull(&client, embed).await
        };
        assert!(result.is_ok(), "#4048 (embed={embed}): the pull succeeds directly");
        let proxied = proxy.received_requests().await.unwrap_or_default().len();
        assert_eq!(
            proxied, 0,
            "#4048 (embed={embed}): HTTP_PROXY is an address the posture excluded — it must \
             receive ZERO requests, the pull included"
        );
        assert_eq!(
            hits(&target, "/api/pull").await,
            1,
            "#4048 (embed={embed}): the admitted endpoint receives the pull directly"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_control_routes_the_pull_through_env_proxy_4048() {
    // Control: under `allow` the legacy client honours HTTP_PROXY for every
    // request, so the fixture can tell "proxied" from "direct".
    for embed in [false, true] {
        let (proxy, target) = proxy_and_target().await;
        let result = {
            let _env = EnvScope::new(&cell_env(None, Some(&proxy.uri())));
            let client = OllamaClient::new_with_url_no_health_check(&target.uri(), CHAT_MODEL)
                .expect("client builds");
            run_pull(&client, embed).await
        };
        assert!(result.is_ok(), "control (embed={embed}): the proxy answers 200");
        let proxied = proxy.received_requests().await.unwrap_or_default().len();
        assert_eq!(
            proxied, 2,
            "control (embed={embed}): allow routes the listing AND the pull through HTTP_PROXY"
        );
        assert_eq!(hits(&target, "/api/pull").await, 0);
    }
}

// ─── Leg 3: a redirect off the admitted endpoint is not followed ─────────

/// A target whose `/api/pull` answers 307 to `/leaked`, which answers 200
/// (so a FOLLOWED redirect reads as a successful pull).
async fn redirecting_target() -> MockServer {
    let target = MockServer::start().await;
    mount_empty_tags(&target).await;
    let leaked = format!("{}/leaked", target.uri());
    Mock::given(method("POST"))
        .and(path("/api/pull"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", leaked.as_str()))
        .mount(&target)
        .await;
    Mock::given(path("/leaked"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "success"})))
        .mount(&target)
        .await;
    target
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_only_pull_does_not_follow_redirect_4048() {
    for embed in [false, true] {
        let target = redirecting_target().await;
        let result = {
            let _env = EnvScope::new(&cell_env(Some("loopback-only"), None));
            let client = OllamaClient::new_with_url_no_health_check(&target.uri(), CHAT_MODEL)
                .expect("client builds");
            run_pull(&client, embed).await
        };
        assert!(
            result.is_err(),
            "#4048 (embed={embed}): a 307 from the admitted endpoint must NOT be followed under \
             loopback-only; the pull fails closed on the 3xx"
        );
        assert_eq!(
            hits(&target, "/leaked").await,
            0,
            "#4048 (embed={embed}): the redirect target must see no request"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_control_follows_redirect_4048() {
    // Control: the legacy posture follows the redirect, so the fixture can
    // tell "followed" from "refused".
    for embed in [false, true] {
        let target = redirecting_target().await;
        let result = {
            let _env = EnvScope::new(&cell_env(None, None));
            let client = OllamaClient::new_with_url_no_health_check(&target.uri(), CHAT_MODEL)
                .expect("client builds");
            run_pull(&client, embed).await
        };
        assert!(result.is_ok(), "control (embed={embed}): allow follows the 307");
        assert_eq!(hits(&target, "/leaked").await, 1);
    }
}

// ─── Leg 4: structural pin — the pulls send through the admitted client ──

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
fn both_pulls_send_through_the_admitted_client_4048() {
    let llm = read_src("src/llm.rs");
    for pull in ["fn ensure_model_async(", "fn ensure_embed_model_async("] {
        let body = fn_body(&llm, pull);
        assert!(
            !body.contains("reqwest::Client::builder()"),
            "#4048: {pull} must not build a bare reqwest client for the pull (it would carry \
             no admission policy); body:\n{body}"
        );
        // rustfmt may break `self.client` across lines: compare whitespace-free.
        let compact: String = body.split_whitespace().collect();
        assert!(
            compact.contains("self.client") && compact.contains(".timeout(PULL_TIMEOUT)"),
            "#4048: {pull} must send the pull through `self.client` (the admitted client) with \
             the per-request PULL_TIMEOUT; body:\n{body}"
        );
    }
    // The only bare builder left in the production half of the file is the
    // `#[cfg(test)]`-only constructor; every production client goes through
    // `egress_policy::inference_client_builder` (#4193) or the pin on top.
    let production = llm
        .split("\n#[cfg(test)]\n")
        .next()
        .expect("llm.rs has a production half");
    let test_only = fn_body(production, "fn new_for_testing(");
    let bare_total = production.matches("reqwest::Client::builder()").count();
    let bare_in_test_ctor = test_only.matches("reqwest::Client::builder()").count();
    assert_eq!(
        bare_total, bare_in_test_ctor,
        "#4048: a bare `reqwest::Client::builder()` outside `new_for_testing` bypasses the \
         admission policy (production half of src/llm.rs)"
    );
}
