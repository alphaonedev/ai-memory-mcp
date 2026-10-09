// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4153 — on a Postgres-backed daemon `DELETE /api/v1/memories/{id}` must
//! fan the deletion out to federation peers, as the SQLite arm of the same
//! handler has always done (`broadcast_delete_quorum`, with the W3/G12 `202`
//! on a quorum miss). The Postgres arm erased the LOCAL row, answered
//! `deleted: true`, and sent nothing on the delete lane: every
//! independently-stored peer kept the erased row and a later catch-up could
//! re-replicate it.
//!
//! The origin runs the POSTGRES handler arm (`StorageBackend::Postgres`)
//! over the SAL `SqliteStore`; the peer is a recording receiver.

#![cfg(feature = "sal")]

use ai_memory::store::CallerContext;
use axum::http::StatusCode;
use serde_json::json;

mod common;
use common::pg_arm_origin::{
    ALICE, Peer, call, origin, owned_memory, router, scratch, spawn_peer, withdrawals_for,
};

const NS: &str = "delete-fanout-4153";

/// An owner-authorized delete sends `deletions: [id]` to the peer.
#[tokio::test]
async fn memory_delete_fans_out_withdrawal_4153() {
    let peer = Peer::default();
    let peer_url = spawn_peer(peer.clone()).await;
    let dir = scratch("memory-delete-4153-");
    let (app, store) = origin(dir.path(), &peer_url);
    let router = router(app);

    let id = store
        .store(&CallerContext::for_agent(ALICE), &owned_memory(ALICE, NS))
        .await
        .expect("store the owned row");

    let (status, body) = call(&router, "DELETE", &format!("/api/v1/memories/{id}"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], json!(true), "{body}");
    assert_eq!(
        withdrawals_for(&peer, &id).await,
        1,
        "#4153: the postgres DELETE /memories/{{id}} must fan the deletion out \
         (pre-fix: replicas kept the erased row)"
    );
}

/// A non-owner's delete is refused locally AND nothing is fanned out: an id
/// the SAL owner gate did not accept never reaches the peer.
#[tokio::test]
async fn memory_delete_refused_locally_fans_out_nothing_4153() {
    let peer = Peer::default();
    let peer_url = spawn_peer(peer.clone()).await;
    let dir = scratch("memory-delete-4153-refused-");
    let (app, store) = origin(dir.path(), &peer_url);
    let router = router(app);

    let bob = "ai:bob-4153";
    let id = store
        .store(&CallerContext::for_agent(bob), &owned_memory(bob, NS))
        .await
        .expect("store bob's row");

    let (status, body) = call(&router, "DELETE", &format!("/api/v1/memories/{id}"), None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "alice may not delete bob's row: {body}"
    );
    assert_eq!(
        withdrawals_for(&peer, &id).await,
        0,
        "a refused local delete must never be fanned out"
    );
}
