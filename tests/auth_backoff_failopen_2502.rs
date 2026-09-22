// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2502 pin (e) — fail-open on counter error, through the real middleware.
//!
//! Uses the fix-tree test seam (`AuthFailurePolicy::break_for_test`), so
//! this file is RED (does not compile) on the base tree and GREEN on the
//! fixed tree: a broken counter must admit, never deny.

use std::net::{IpAddr, SocketAddr};

use ai_memory::config::HttpIdentityMode;
use ai_memory::handlers::auth_backoff::AuthFailurePolicy;
use ai_memory::handlers::identity_binding::EnrolledAgentKeys;
use ai_memory::handlers::{ApiKeyState, api_key_auth};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::{Router, routing::get};
use tower::ServiceExt as _;

const SHARED_KEY: &str = "test-2502-right-key";
const WRONG_KEY: &str = "test-2502-wrong-key";

async fn dummy_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[tokio::test]
async fn broken_counter_admits_instead_of_denying() {
    let policy = AuthFailurePolicy::new();
    let auth_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(EnrolledAgentKeys::empty()),
        identity_mode: HttpIdentityMode::Off,
        auth_backoff: policy.clone(),
    };
    let router = Router::new()
        .route("/api/v1/memories", get(dummy_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            api_key_auth,
        ));
    policy.break_for_test();
    let source = IpAddr::from([10, 250, 9, 9]);
    for i in 0..20 {
        let mut req = Request::builder()
            .method("GET")
            .uri("/api/v1/memories")
            .header("x-api-key", WRONG_KEY)
            .body(Body::empty())
            .expect("request");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(source, 41234)));
        let resp = router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "broken counter admits as plain 401 (attempt {i}), never 429"
        );
    }
    let mut req = Request::builder()
        .method("GET")
        .uri("/api/v1/memories")
        .header("x-api-key", SHARED_KEY)
        .body(Body::empty())
        .expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(source, 41234)));
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK, "allowed path stays open");
}
