// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4079 — on a Postgres-backed daemon `DELETE /api/v1/subscriptions` must
//! fan the subscription's withdrawal out to federation peers.
//!
//! `subscribe` replicates the `_subscriptions/<agent>` row to every peer
//! through the quorum store lane, but `unsubscribe` deleted ONLY the local
//! row and answered `removed: true`: every peer with its own store kept the
//! replica and kept dispatching to the withdrawn endpoint, indefinitely.
//!
//! The origin runs the POSTGRES handler arm (`StorageBackend::Postgres`)
//! over the SAL `SqliteStore` — the exact code a Postgres daemon runs — and
//! the peer is a recording receiver; how a receiver applies `deletions[]` is
//! covered by its own suites.

#![cfg(feature = "sal")]

use axum::http::StatusCode;
use serde_json::json;
use std::sync::atomic::Ordering;

mod common;
use common::pg_arm_origin::{Peer, call, origin, router, scratch, spawn_peer, withdrawals_for};

fn subscribe_body(tag: &str) -> serde_json::Value {
    json!({
        "url": format!("https://example.com/hook-4079-{tag}"),
        "events": "store",
        "secret": "per-sub-secret-4079",
    })
}

/// The withdrawal reaches the peer on the federation delete lane
/// (`deletions: [id]`) and the route still answers 200.
#[tokio::test]
async fn unsubscribe_fans_out_withdrawal_4079() {
    let peer = Peer::default();
    let peer_url = spawn_peer(peer.clone()).await;
    let dir = scratch("unsubscribe-4079-");
    let (app, _store) = origin(dir.path(), &peer_url);
    let router = router(app);

    let (status, created) = call(
        &router,
        "POST",
        "/api/v1/subscriptions",
        Some(subscribe_body("up")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let sub_id = created["id"].as_str().expect("subscription id").to_owned();
    assert_eq!(
        withdrawals_for(&peer, &sub_id).await,
        0,
        "nothing is withdrawn before the unsubscribe"
    );

    let (status, removed) = call(
        &router,
        "DELETE",
        &format!("/api/v1/subscriptions?id={sub_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["removed"], json!(true), "{removed}");
    assert_eq!(
        withdrawals_for(&peer, &sub_id).await,
        1,
        "#4079: the postgres unsubscribe must send the deletion to the peer \
         (pre-fix: the replica was never withdrawn)"
    );
}

/// A peer that misses the withdrawal is reported as a quorum miss (the
/// W3/G12 `202` shape carrying `removed: true`), never a bare success.
#[tokio::test]
async fn unsubscribe_while_peer_down_reports_quorum_miss_4079() {
    let peer = Peer::default();
    let peer_url = spawn_peer(peer.clone()).await;
    let dir = scratch("unsubscribe-4079-down-");
    let (app, _store) = origin(dir.path(), &peer_url);
    let router = router(app);

    let (status, created) = call(
        &router,
        "POST",
        "/api/v1/subscriptions",
        Some(subscribe_body("down")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let sub_id = created["id"].as_str().expect("subscription id").to_owned();

    peer.down.store(true, Ordering::Relaxed);
    let (status, body) = call(
        &router,
        "DELETE",
        &format!("/api/v1/subscriptions?id={sub_id}"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "#4079: a withdrawal the peer missed is under-replicated (202), not a bare 200: {body}"
    );
    assert_eq!(body["quorum_met"], json!(false), "{body}");
    assert_eq!(body["removed"], json!(true), "the local row IS gone: {body}");
    assert!(
        withdrawals_for(&peer, &sub_id).await >= 1,
        "the withdrawal was attempted against the down peer (the lane retries a 500)"
    );
}
