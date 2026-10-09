// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3653 — `ai_memory_store_total` must count real HTTP writes.
//!
//! The series was registered with the HELP "Total memory_store calls,
//! labeled by tier and result" but no production code path ever
//! incremented it, so a dashboard read a flat zero while the daemon was
//! writing (or failing to write). These cells drive the real
//! `POST /api/v1/memories` handler and read the process registry the
//! `/metrics` route renders; they never call a metric helper directly.
//!
//! The registry is process-global and other lib tests also create
//! memories over HTTP, so each cell asserts a DELTA of at least one on
//! its own label pair (counters only rise), never an absolute value.

use super::*;
use axum::Router;
use axum::body::Body;
use axum::routing::post as axum_post;

/// Namespace and caller id for every write these cells make.
const LANE: &str = "store-metrics-3653";

fn store_count(tier: Tier, result: &str) -> u64 {
    crate::metrics::registry()
        .store_total
        .with_label_values(&[tier.as_str(), result])
        .get()
}

async fn post_create(body: &serde_json::Value) -> StatusCode {
    let app = Router::new()
        .route("/api/v1/memories", axum_post(create_memory))
        .with_state(test_app_state(test_state()));
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/memories")
                .method("POST")
                .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
                .header("x-agent-id", LANE)
                .body(Body::from(serde_json::to_vec(body).expect("encode body")))
                .expect("build request"),
        )
        .await
        .expect("route request");
    resp.status()
}

#[tokio::test]
async fn a_successful_http_create_counts_as_ok_3653() {
    let before = store_count(Tier::Long, "ok");
    let status = post_create(&json!({
        "tier": Tier::Long.as_str(),
        "namespace": LANE,
        "title": "counted write 3653",
        "content": "an HTTP create must move ai_memory_store_total",
        "metadata": {}
    }))
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let after = store_count(Tier::Long, "ok");
    assert!(
        after > before,
        "a 201 create left ai_memory_store_total{{tier=long,result=ok}} at {after} (was {before})"
    );
}

#[tokio::test]
async fn a_refused_http_create_counts_as_err_3653() {
    let before = store_count(Tier::Mid, "err");
    // An empty title fails request validation: the write is refused.
    let status = post_create(&json!({
        "tier": Tier::Mid.as_str(),
        "namespace": LANE,
        "title": "",
        "content": "refused",
        "metadata": {}
    }))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let after = store_count(Tier::Mid, "err");
    assert!(
        after > before,
        "a refused create left ai_memory_store_total{{tier=mid,result=err}} at {after} (was {before})"
    );
}
