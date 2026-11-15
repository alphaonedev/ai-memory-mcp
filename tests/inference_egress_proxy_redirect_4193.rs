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
    // Control (current behaviour, tracked #9314): under `allow` the client
    // still honours HTTP_PROXY, so the proxy mock sees the request and the
    // direct target sees none. This proves the fixture detects a proxied
    // request; it does not make the `allow` behaviour permanent.
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

// ─── Leg 4: break-it table — redirect targets over the address classes ──

/// Redirect `Location` targets the policy never admitted, one per address
/// class (#4193 / #6053 SSRF classes). Under every restricted posture the
/// 3xx is returned to the caller as `http_status=<code>`, never followed.
const REDIRECT_TARGETS: [(&str, &str); 7] = [
    ("loopback-v4-other-port", "http://127.0.0.1:9/leak"),
    ("loopback-v6", "http://[::1]:9/leak"),
    ("link-local-v4", "http://169.254.10.10/leak"),
    ("cloud-metadata", "http://169.254.169.254/latest/meta-data/"),
    ("ipv4-mapped-v6", "http://[::ffff:169.254.169.254]/leak"),
    ("scheme-downgrade", "http://example.invalid/leak"),
    ("link-local-v6", "http://[fe80::1]/leak"),
];

/// The RFC 1918 class (the 10/8 block), built from its octets so the fixture
/// is explicit about the class rather than looking like a real host address.
const RFC1918_OCTETS: [u8; 4] = [10, 0, 0, 1];

/// Every redirect target of the table plus the RFC 1918 entry.
fn redirect_targets() -> Vec<(&'static str, String)> {
    let rfc1918 = std::net::Ipv4Addr::from(RFC1918_OCTETS);
    let mut all: Vec<(&'static str, String)> = REDIRECT_TARGETS
        .iter()
        .map(|(class, loc)| (*class, (*loc).to_string()))
        .collect();
    all.push(("rfc1918", format!("http://{rfc1918}/leak")));
    all
}

/// Redirect status codes a provider can answer (307/308 keep the POST body,
/// the leak this issue is about; 301/302/303 are the GET-rewriting forms).
const REDIRECT_CODES: [u16; 5] = [301, 302, 303, 307, 308];

/// Restricted postures: every one of them must refuse redirects + proxies
/// (`deny` included: a CLI verb still builds an inference client under it).
const RESTRICTED_POSTURES: [&str; 3] = ["loopback-only", "deny", "internal-only"];

/// The exact provider-failure token the caller sees for an unfollowed 3xx.
fn http_status_token(code: u16) -> String {
    format!("http_status={code}")
}

async fn redirect_to(location: &str, code: u16) -> MockServer {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(code).insert_header("location", location))
        .mount(&target)
        .await;
    target
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generate_refuses_redirect_to_every_address_class_4193() {
    for posture in RESTRICTED_POSTURES {
        for (class, location) in redirect_targets() {
            for code in REDIRECT_CODES {
                for openai in [false, true] {
                    let target = redirect_to(&location, code).await;
                    let err = {
                        let _env = EnvScope::new(&cell_env(Some(posture), None));
                        let client = build(openai, &target.uri());
                        client
                            .generate_async("p", None)
                            .await
                            .expect_err("a 3xx is never a completion")
                    };
                    let rendered = format!("{err:#}");
                    assert!(
                        rendered.contains(&http_status_token(code)),
                        "#4193 {posture}/{class}/{code}/openai={openai}: the redirect must be \
                         returned as {}, never followed; got: {rendered}",
                        http_status_token(code)
                    );
                    assert_eq!(
                        target.received_requests().await.unwrap_or_default().len(),
                        1,
                        "#4193 {posture}/{class}/{code}: exactly one request, to the admitted origin"
                    );
                }
            }
        }
    }
}

/// `Location` SPELLINGS (not address classes): each must come back to the
/// caller as the unfollowed 3xx under every restricted posture. A followed
/// relative or scheme-relative form would re-enter the admitted mock (a
/// second request), so the exact one-request count catches it.
const LOCATION_FORMS: [(&str, &str); 6] = [
    ("relative-path", "/leak"),
    ("scheme-relative", "//127.0.0.1:9/leak"),
    ("ula-v6", "http://[fd00::1]/leak"),
    ("ipv4-mapped-loopback", "http://[::ffff:127.0.0.1]:9/leak"),
    ("malformed-bracket", "http://[::1/leak"),
    ("malformed-scheme", "ht tp://x/leak"),
];

/// The redirect codes of the Location-form table (307/308 keep the body).
const LOCATION_FORM_CODES: [u16; 3] = [302, 307, 308];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generate_refuses_every_location_form_4193() {
    for posture in RESTRICTED_POSTURES {
        for (form, location) in LOCATION_FORMS {
            for code in LOCATION_FORM_CODES {
                let target = redirect_to(location, code).await;
                let err = {
                    let _env = EnvScope::new(&cell_env(Some(posture), None));
                    build(true, &target.uri())
                        .generate_async("p", None)
                        .await
                        .expect_err("a 3xx is never a completion")
                };
                let rendered = format!("{err:#}");
                assert!(
                    rendered.contains(&http_status_token(code)),
                    "#4193 {posture}/{form}/{code}: the redirect must be returned as {}, \
                     never followed; got: {rendered}",
                    http_status_token(code)
                );
                assert!(
                    !rendered.contains("Bearer"),
                    "#4193 {posture}/{form}/{code}: the error never carries the bearer"
                );
                assert_eq!(
                    target.received_requests().await.unwrap_or_default().len(),
                    1,
                    "#4193 {posture}/{form}/{code}: exactly one request, to the admitted origin"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_chain_of_two_is_not_entered_4193() {
    // hop0 -> hop1 -> hop2 on a second loopback server: neither hop may be
    // reached under a restricted posture.
    for posture in RESTRICTED_POSTURES {
        let second = MockServer::start().await;
        let hop2 = format!("{}/hop2", second.uri());
        Mock::given(path("/hop1"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", hop2.as_str()))
            .mount(&second)
            .await;
        Mock::given(path("/hop2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&second)
            .await;
        let hop1 = format!("{}/hop1", second.uri());
        let target = redirecting_to_path("/api/tags", &hop1).await;
        let available = {
            let _env = EnvScope::new(&cell_env(Some(posture), None));
            build(false, &target.uri()).is_available_async().await
        };
        assert!(
            !available,
            "#4193 {posture}: a redirect chain is not followed"
        );
        assert_eq!(
            hits(&second, "/hop1").await,
            0,
            "#4193 {posture}: hop1 unreached"
        );
        assert_eq!(
            hits(&second, "/hop2").await,
            0,
            "#4193 {posture}: hop2 unreached"
        );
    }
}

async fn redirecting_to_path(health_path: &str, location: &str) -> MockServer {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(health_path))
        .respond_with(ResponseTemplate::new(307).insert_header("location", location))
        .mount(&target)
        .await;
    target
}

// ─── Leg 5: each proxy variable alone, every restricted posture ──────────

/// Each env proxy variable reqwest's system matcher honours, set ALONE.
const SINGLE_PROXY_VARS: [&str; 3] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"];

fn single_proxy_env<'a>(
    posture: &'a str,
    var: &'static str,
    proxy: &'a str,
) -> Vec<(&'static str, Option<&'a str>)> {
    let mut vars = cell_env(Some(posture), None);
    for entry in &mut vars {
        if entry.0 == var {
            entry.1 = Some(proxy);
        }
    }
    vars
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_proxy_var_alone_is_refused_4193() {
    for posture in ["loopback-only", "deny", "internal-only"] {
        for var in SINGLE_PROXY_VARS {
            let (proxy, target) = proxy_and_target("/api/tags").await;
            let available = {
                let _env = EnvScope::new(&single_proxy_env(posture, var, &proxy.uri()));
                build(false, &target.uri()).is_available_async().await
            };
            assert!(
                available,
                "#4193 {posture}/{var}: direct reach of the admitted endpoint"
            );
            assert_eq!(
                proxy.received_requests().await.unwrap_or_default().len(),
                0,
                "#4193 {posture}/{var}: the proxy must receive ZERO requests"
            );
            assert_eq!(hits(&target, "/api/tags").await, 1);
        }
    }
}

/// The lower-case proxy variables reqwest's system matcher also reads.
const LOWER_CASE_PROXY_VARS: [&str; 3] = ["http_proxy", "https_proxy", "all_proxy"];

/// A `NO_PROXY` value that covers neither the loopback target nor the proxy:
/// it must not change the outcome in any posture.
const UNRELATED_NO_PROXY: &str = "example.invalid,.corp.invalid";

/// The env table with ONLY the lower-case proxy variables set to `proxy`.
fn lower_case_proxy_env<'a>(
    posture: Option<&'a str>,
    proxy: &'a str,
) -> Vec<(&'static str, Option<&'a str>)> {
    let mut vars = cell_env(posture, None);
    for entry in &mut vars {
        if LOWER_CASE_PROXY_VARS.contains(&entry.0) {
            entry.1 = Some(proxy);
        }
    }
    vars
}

/// The env table with every proxy variable set and `NO_PROXY` / `no_proxy`
/// set to [`UNRELATED_NO_PROXY`].
fn unrelated_no_proxy_env<'a>(
    posture: Option<&'a str>,
    proxy: &'a str,
) -> Vec<(&'static str, Option<&'a str>)> {
    let mut vars = cell_env(posture, Some(proxy));
    for entry in &mut vars {
        if NO_PROXY_VARS.contains(&entry.0) {
            entry.1 = Some(UNRELATED_NO_PROXY);
        }
    }
    vars
}

/// Expected proxy hits per posture: `allow` is the control (current
/// behaviour, tracked #9314) that proves the fixture sees a proxied request.
fn expected_proxy_hits(posture: Option<&str>) -> usize {
    usize::from(posture.is_none())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lower_case_proxy_vars_only_are_refused_4193() {
    for posture in [
        None,
        Some("loopback-only"),
        Some("deny"),
        Some("internal-only"),
    ] {
        let (proxy, target) = proxy_and_target("/api/tags").await;
        let available = {
            let _env = EnvScope::new(&lower_case_proxy_env(posture, &proxy.uri()));
            build(false, &target.uri()).is_available_async().await
        };
        assert!(available, "#4193 {posture:?}: the probe answers 200");
        let want = expected_proxy_hits(posture);
        assert_eq!(
            proxy.received_requests().await.unwrap_or_default().len(),
            want,
            "#4193 {posture:?}: lower-case proxy vars only; proxy hits"
        );
        assert_eq!(
            hits(&target, "/api/tags").await,
            1 - want,
            "#4193 {posture:?}: direct hits"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_proxy_set_to_a_value_does_not_change_the_refusal_4193() {
    for posture in [
        None,
        Some("loopback-only"),
        Some("deny"),
        Some("internal-only"),
    ] {
        let (proxy, target) = proxy_and_target("/api/tags").await;
        let available = {
            let _env = EnvScope::new(&unrelated_no_proxy_env(posture, &proxy.uri()));
            build(false, &target.uri()).is_available_async().await
        };
        assert!(available, "#4193 {posture:?}: the probe answers 200");
        let want = expected_proxy_hits(posture);
        assert_eq!(
            proxy.received_requests().await.unwrap_or_default().len(),
            want,
            "#4193 {posture:?}: NO_PROXY={UNRELATED_NO_PROXY}; proxy hits"
        );
        assert_eq!(
            hits(&target, "/api/tags").await,
            1 - want,
            "#4193 {posture:?}: direct hits"
        );
    }
}

// ─── Leg 6: the pinned constructors under every proxy variable ───────────

/// A host name that never resolves: only the #3822 address pin reaches it.
const PINNED_HOST: &str = "pinned-internal.invalid";

fn pinned_base(target: &MockServer) -> (String, std::net::SocketAddr) {
    let addr = *target.address();
    (format!("http://{PINNED_HOST}:{}", addr.port()), addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_client_ignores_every_proxy_var_3822_4193() {
    for var in SINGLE_PROXY_VARS {
        let (proxy, target) = proxy_and_target("/api/tags").await;
        let (base, addr) = pinned_base(&target);
        let available = {
            let _env = EnvScope::new(&single_proxy_env("internal-only", var, &proxy.uri()));
            OllamaClient::new_with_url_no_health_check_pinned(&base, "m", PINNED_HOST, &[addr])
                .expect("pinned client")
                .is_available_async()
                .await
        };
        assert!(
            available,
            "#3822 {var}: the pin reaches the admitted address"
        );
        assert_eq!(
            proxy.received_requests().await.unwrap_or_default().len(),
            0,
            "#3822/#4193 {var}: a pinned client must never use an env proxy"
        );
    }
}

// ─── Leg 7: the model-pull client (sibling of the base constructors) ─────

/// `/api/tags` lists no model so `ensure_model_async` goes on to pull.
async fn pull_target() -> MockServer {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&target)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/pull"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "success"})))
        .mount(&target)
        .await;
    target
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn model_pull_sends_nothing_to_env_proxy_4193() {
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "success"})))
        .mount(&proxy)
        .await;
    let target = pull_target().await;
    let outcome = {
        let _env = EnvScope::new(&cell_env(Some("loopback-only"), Some(&proxy.uri())));
        let client = build(false, &target.uri());
        let model = client.ensure_model_async().await;
        let embed = client.ensure_embed_model_async("e").await;
        (model, embed)
    };
    assert!(
        outcome.0.is_ok(),
        "#4193: pull reaches the admitted endpoint: {:?}",
        outcome.0
    );
    assert!(
        outcome.1.is_ok(),
        "#4193: embed pull reaches it: {:?}",
        outcome.1
    );
    assert_eq!(
        proxy.received_requests().await.unwrap_or_default().len(),
        0,
        "#4193: the model-pull client must never route through HTTP_PROXY"
    );
    assert_eq!(hits(&target, "/api/pull").await, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_model_pull_uses_the_pin_3822() {
    // The pull must reuse the pinned client: a fresh client would resolve
    // the never-resolving host again (a second DNS answer, the #3822 class).
    let target = pull_target().await;
    let (base, addr) = pinned_base(&target);
    let outcome = {
        let _env = EnvScope::new(&cell_env(Some("internal-only"), None));
        let client =
            OllamaClient::new_with_url_no_health_check_pinned(&base, "m", PINNED_HOST, &[addr])
                .expect("pinned client");
        (
            client.ensure_model_async().await,
            client.ensure_embed_model_async("e").await,
        )
    };
    assert!(
        outcome.0.is_ok(),
        "#3822: pinned pull reaches the pinned address: {:?}",
        outcome.0
    );
    assert!(
        outcome.1.is_ok(),
        "#3822: pinned embed pull: {:?}",
        outcome.1
    );
    assert_eq!(hits(&target, "/api/pull").await, 2);
}

/// Bound: a pathological 100K-byte `Location` is returned, not followed,
/// and the refusal is fast (no resolution or connect of the target).
const LONG_LOCATION_BYTES: usize = 100_000;
/// A long `Location` that a client WOULD follow: under the http crate's URI
/// length limit (about 64 KiB), so a 100K form alone cannot tell "refused"
/// from "unparseable"; this one points at a live sink.
const FOLLOWABLE_LONG_LOCATION_BYTES: usize = 60_000;
const LONG_LOCATION_CEILING: std::time::Duration = std::time::Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn huge_location_header_is_refused_fast_4193() {
    let sink = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"choices": []})))
        .mount(&sink)
        .await;
    let followable = format!(
        "{}/sink?pad={}",
        sink.uri(),
        "a".repeat(FOLLOWABLE_LONG_LOCATION_BYTES)
    );
    let oversized = format!(
        "{}/sink?pad={}",
        sink.uri(),
        "a".repeat(LONG_LOCATION_BYTES)
    );
    for (shape, location) in [
        ("followable-60k", followable),
        ("oversized-100k", oversized),
    ] {
        let target = redirect_to(&location, 307).await;
        let started = std::time::Instant::now();
        let err = {
            let _env = EnvScope::new(&cell_env(Some("loopback-only"), None));
            build(true, &target.uri())
                .generate_async("p", None)
                .await
                .expect_err("a 3xx is never a completion")
        };
        assert!(
            started.elapsed() < LONG_LOCATION_CEILING,
            "#4193 {shape}: refusal is bounded"
        );
        assert!(
            format!("{err:#}").contains(&http_status_token(307)),
            "#4193 {shape}: got: {err:#}"
        );
        assert_eq!(
            hits(&sink, "/sink").await,
            0,
            "#4193 {shape}: the long Location is refused, never followed to the sink"
        );
    }
}

// ─── Leg 8: the pull bodies keep their own ceiling ───────────────────────

/// Both pull bodies reuse the posture-policy client AND override its
/// generate timeout with `PULL_TIMEOUT` (a removed override would cap a model
/// pull at the 30 s generate ceiling).
#[test]
fn both_pull_bodies_pin_the_pull_timeout_4193() {
    const PULL_CALL: &str = "self.client.post(&pull_url).timeout(PULL_TIMEOUT)";
    let llm = read_src("src/llm.rs");
    for pull_fn in ["fn ensure_model_async(", "fn ensure_embed_model_async("] {
        let compact: String = fn_body(&llm, pull_fn)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert!(
            compact.contains(PULL_CALL),
            "#4193: {pull_fn} must call `{PULL_CALL}` (whitespace ignored)"
        );
    }
}
