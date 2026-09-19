// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2502 — per-source auth-failure backoff pins, driven through the real
//! `api_key_auth` middleware.
//!
//! The source is the TCP peer address (`ConnectInfo<SocketAddr>`), injected
//! into the request extensions exactly where `axum::serve` / `axum-server`
//! put it in production. No header is read (ruling 3).
//!
//! These pins use only the production-default policy (constants, no knob),
//! so they compile on the base tree: there every wrong key is a bare 401
//! forever and the refusal pins go RED; on the fixed tree they go GREEN.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use ai_memory::config::HttpIdentityMode;
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, api_key_auth};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::{Router, routing::get};
use tower::ServiceExt as _;

const SHARED_KEY: &str = "test-2502-right-key";
const AGENT_TOKEN: &str = "test-2502-agent-token";
const AGENT_ID: &str = "agent-2502";
const WRONG_KEY: &str = "test-2502-wrong-key";

async fn dummy_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

fn test_router(api_key: Option<&str>, enrolled: EnrolledAgentKeys) -> Router {
    let auth_state = ApiKeyState {
        key: api_key.map(String::from),
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(enrolled),
        identity_mode: HttpIdentityMode::Off,
        ..Default::default()
    };
    Router::new()
        .route("/api/v1/memories", get(dummy_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            api_key_auth,
        ))
}

fn enrolled_agent_keys() -> EnrolledAgentKeys {
    let mut map = HashMap::new();
    map.insert(api_key_sha256_hex(AGENT_TOKEN), AGENT_ID.to_string());
    EnrolledAgentKeys::from_map(map)
}

struct Outcome {
    status: StatusCode,
    retry_after: Option<String>,
    body: Vec<u8>,
}

async fn attempt(router: &Router, ip: IpAddr, key: Option<&str>) -> Outcome {
    let mut builder = Request::builder().method("GET").uri("/api/v1/memories");
    if let Some(k) = key {
        builder = builder.header("x-api-key", k);
    }
    let mut req = builder.body(Body::empty()).expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 41234)));
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    Outcome {
        status,
        retry_after,
        body,
    }
}

fn ip(n: u8) -> IpAddr {
    IpAddr::from([10, 250, 2, n])
}

/// (a) N failures from one source -> the next attempt is 429 with
/// Retry-After. The 429 body is the closed vocabulary constant.
#[tokio::test]
async fn failures_from_one_source_earn_a_429_with_retry_after() {
    let router = test_router(Some(SHARED_KEY), EnrolledAgentKeys::empty());
    let source = ip(11);
    for i in 0..5 {
        let out = attempt(&router, source, Some(WRONG_KEY)).await;
        assert_eq!(
            out.status,
            StatusCode::UNAUTHORIZED,
            "failure {i} stays 401"
        );
        assert!(out.retry_after.is_none(), "no Retry-After before refusal");
    }
    let out = attempt(&router, source, Some(WRONG_KEY)).await;
    assert_eq!(
        out.status,
        StatusCode::TOO_MANY_REQUESTS,
        "6th attempt refused"
    );
    let retry = out.retry_after.expect("Retry-After on 429");
    assert_eq!(
        retry, "1",
        "first backoff step is the 1s base, got {retry:?}"
    );
    assert_eq!(
        out.body, b"{\"error\":\"auth_backoff\"}",
        "closed-vocabulary body"
    );
}

/// (b) control: a different source at the same moment is admitted (401 for a
/// wrong key, 200 for the right key — never 429).
#[tokio::test]
async fn a_different_source_is_unaffected_by_anothers_backoff() {
    let router = test_router(Some(SHARED_KEY), EnrolledAgentKeys::empty());
    let hot = ip(21);
    for _ in 0..6 {
        let _ = attempt(&router, hot, Some(WRONG_KEY)).await;
    }
    let refused = attempt(&router, hot, Some(WRONG_KEY)).await;
    assert_eq!(
        refused.status,
        StatusCode::TOO_MANY_REQUESTS,
        "hot source is backed off"
    );
    let cold_wrong = attempt(&router, ip(22), Some(WRONG_KEY)).await;
    assert_eq!(
        cold_wrong.status,
        StatusCode::UNAUTHORIZED,
        "cold source wrong key is 401, not 429"
    );
    let cold_right = attempt(&router, ip(22), Some(SHARED_KEY)).await;
    assert_eq!(
        cold_right.status,
        StatusCode::OK,
        "cold source right key is admitted"
    );
}

/// (c) one success resets: failures below the threshold, then a success,
/// then a full fresh budget of failures that all stay 401.
#[tokio::test]
async fn one_success_resets_the_sources_failure_count() {
    let router = test_router(Some(SHARED_KEY), EnrolledAgentKeys::empty());
    let source = ip(31);
    for _ in 0..4 {
        let out = attempt(&router, source, Some(WRONG_KEY)).await;
        assert_eq!(out.status, StatusCode::UNAUTHORIZED);
    }
    let ok = attempt(&router, source, Some(SHARED_KEY)).await;
    assert_eq!(
        ok.status,
        StatusCode::OK,
        "success admitted below threshold"
    );
    for i in 0..5 {
        let out = attempt(&router, source, Some(WRONG_KEY)).await;
        assert_eq!(
            out.status,
            StatusCode::UNAUTHORIZED,
            "post-success failure {i} stays 401"
        );
    }
}

/// (f) shared-key and per-agent refusal bodies are byte-identical, and name
/// neither the key nor the path.
#[tokio::test]
async fn shared_and_per_agent_refusals_are_byte_identical() {
    let router = test_router(Some(SHARED_KEY), enrolled_agent_keys());
    let shared_source = ip(41);
    for _ in 0..5 {
        let _ = attempt(&router, shared_source, Some(WRONG_KEY)).await;
    }
    let shared_refusal = attempt(&router, shared_source, Some(WRONG_KEY)).await;
    assert_eq!(shared_refusal.status, StatusCode::TOO_MANY_REQUESTS);
    let agent_source = ip(42);
    for _ in 0..5 {
        let _ = attempt(&router, agent_source, Some(WRONG_KEY)).await;
    }
    let agent_refusal = attempt(&router, agent_source, Some(WRONG_KEY)).await;
    assert_eq!(agent_refusal.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        shared_refusal.body, agent_refusal.body,
        "uniform refusal bodies"
    );
    assert_eq!(shared_refusal.body, b"{\"error\":\"auth_backoff\"}");
    let text = String::from_utf8_lossy(&shared_refusal.body);
    assert!(!text.contains("agent"), "body names no path: {text}");
    assert!(!text.contains("key"), "body names no credential: {text}");
}

/// (d) the bounded table evicts the oldest source: a source evicted by
/// filling the table restarts at a fresh count, while a retained source
/// still refuses on schedule.
#[tokio::test]
async fn the_oldest_source_is_evicted_at_capacity() {
    let router = test_router(Some(SHARED_KEY), EnrolledAgentKeys::empty());
    let evicted = IpAddr::from([10, 251, 0, 1]);
    let retained = IpAddr::from([10, 251, 0, 2]);
    for _ in 0..5 {
        let out = attempt(&router, evicted, Some(WRONG_KEY)).await;
        assert_eq!(out.status, StatusCode::UNAUTHORIZED);
        let out = attempt(&router, retained, Some(WRONG_KEY)).await;
        assert_eq!(out.status, StatusCode::UNAUTHORIZED);
    }
    for i in 0..1023u16 {
        let filler = IpAddr::from([10, 252, (i >> 8) as u8, (i & 0xff) as u8]);
        let out = attempt(&router, filler, Some(WRONG_KEY)).await;
        assert_eq!(out.status, StatusCode::UNAUTHORIZED, "filler {i} stays 401");
    }
    let retained_next = attempt(&router, retained, Some(WRONG_KEY)).await;
    assert_eq!(
        retained_next.status,
        StatusCode::TOO_MANY_REQUESTS,
        "retained source still refuses"
    );
    let evicted_next = attempt(&router, evicted, Some(WRONG_KEY)).await;
    assert_eq!(
        evicted_next.status,
        StatusCode::UNAUTHORIZED,
        "evicted source restarts fresh"
    );
}

/// Allowed path without any peer address (a router driven with no TCP
/// listener): the middleware passes through to normal auth.
#[tokio::test]
async fn requests_without_peer_address_fall_through_to_normal_auth() {
    let router = test_router(Some(SHARED_KEY), EnrolledAgentKeys::empty());
    for _ in 0..20 {
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/memories")
            .header("x-api-key", WRONG_KEY)
            .body(Body::empty())
            .expect("request");
        let resp = router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "no peer -> plain 401, never 429"
        );
    }
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/memories")
        .header("x-api-key", SHARED_KEY)
        .body(Body::empty())
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "no peer -> right key admitted"
    );
}

/// (g) amend F1 BLOCKER pin — the headline claim: a backed-off source is
/// refused BEFORE its key is compared, so the CORRECT shared key AND the
/// correct per-agent key presented from that same source are still refused
/// with 429 + Retry-After + the closed-vocabulary body (no key oracle);
/// the same correct keys from a DIFFERENT source are admitted at the same
/// moment (allowed-path control). Non-vacuity: forcing `pre_check` to
/// `Admit` turns this cell red.
#[tokio::test]
async fn correct_keys_during_backoff_are_still_refused() {
    let router = test_router(Some(SHARED_KEY), enrolled_agent_keys());
    let hot = ip(51);
    let cold = ip(52);
    for i in 0..5 {
        let out = attempt(&router, hot, Some(WRONG_KEY)).await;
        assert_eq!(
            out.status,
            StatusCode::UNAUTHORIZED,
            "failure {i} stays 401"
        );
    }
    let sixth = attempt(&router, hot, Some(WRONG_KEY)).await;
    assert_eq!(
        sixth.status,
        StatusCode::TOO_MANY_REQUESTS,
        "6th wrong attempt refuses"
    );
    let shared_during = attempt(&router, hot, Some(SHARED_KEY)).await;
    assert_eq!(
        shared_during.status,
        StatusCode::TOO_MANY_REQUESTS,
        "correct shared key during backoff is still refused, not admitted"
    );
    assert!(
        shared_during.retry_after.is_some(),
        "refusal carries Retry-After"
    );
    assert_eq!(
        shared_during.body, b"{\"error\":\"auth_backoff\"}",
        "refusal body is the closed vocabulary"
    );
    let agent_during = attempt(&router, hot, Some(AGENT_TOKEN)).await;
    assert_eq!(
        agent_during.status,
        StatusCode::TOO_MANY_REQUESTS,
        "correct per-agent key during backoff is still refused, not admitted"
    );
    assert!(
        agent_during.retry_after.is_some(),
        "per-agent refusal carries Retry-After"
    );
    assert_eq!(
        agent_during.body, b"{\"error\":\"auth_backoff\"}",
        "per-agent refusal body is the closed vocabulary"
    );
    let shared_cold = attempt(&router, cold, Some(SHARED_KEY)).await;
    assert_eq!(
        shared_cold.status,
        StatusCode::OK,
        "correct shared key from a different source is admitted at the same moment"
    );
    let agent_cold = attempt(&router, cold, Some(AGENT_TOKEN)).await;
    assert_eq!(
        agent_cold.status,
        StatusCode::OK,
        "correct per-agent key from a different source is admitted at the same moment"
    );
}
