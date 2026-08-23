// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2717 regression suite — the federated DELETE lane's push-DLQ landing pass
//! MUST run on the **DEFAULT (non-sal) build**, exactly as the #2678/#2681
//! store lane does.
//!
//! ## Why this test exists (and why it is NOT `#[cfg(feature = "sal")]`)
//!
//! #2681 made `async-trait` non-optional and #2678/#2681 un-gated the STORE
//! lane's push-DLQ landing pass so a federated STORE miss lands in
//! `federation_push_dlq` and replays on the DEFAULT binary. The DELETE lane
//! (`broadcast_delete_quorum`) was left the lone survivor of the same class:
//! its DLQ landing pass — the `dispatched_peer_ids` binding, the
//! `explicit_failures` binding + push, and the `if let Some(sink) = …` block —
//! were still `#[cfg(feature = "sal")]`, on the stale rationale that "the sink
//! trait is a sal-only surface". So on `cargo install ai-memory` /
//! Homebrew-from-source / the iOS+Android static libs a federated DELETE miss
//! was a `tracing::warn!`-only event and was then silently dropped: the higher
//! -integrity erasure lane leaking the very GDPR-erased content a down peer
//! could later LWW-resurrect (the #2498 defect, re-opened on the default build).
//!
//! `SqliteDlqSink`, the `FederationDlqSink` trait, and the `push_dlq` types are
//! all available on the default build — only `PostgresDlqSink` is
//! `sal-postgres`-gated. The existing `federation_delete_dlq_2498.rs` proves the
//! landing pass under `--features sal`; this file is its DEFAULT-BUILD twin, so
//! the un-gating is pinned on the exact configuration the defect shipped on.
//!
//! Each assertion lands ZERO rows before #2717 (the pass was compiled out) and
//! exactly the right row after.

// Deliberately NOT `#![cfg(feature = "sal")]` — this suite MUST compile and run
// on the default (non-sal) build, which is the whole point of #2717.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use ai_memory::federation::push_dlq::{FederationDlqSink, SqliteDlqSink};
use ai_memory::federation::{FederationConfig, PeerEndpoint, broadcast_delete_quorum};
use ai_memory::replication::QuorumPolicy;

/// Peer is DOWN — every POST answers 500.
const MODE_FAIL: usize = 1;
/// Peer answers 200 with a fully-applied receiver report (a healthy ack).
const MODE_OK: usize = 0;

#[derive(Clone, Default)]
struct PeerState {
    mode: Arc<AtomicUsize>,
    last_body: Arc<Mutex<Option<serde_json::Value>>>,
}

impl PeerState {
    fn with_mode(mode: usize) -> Self {
        Self {
            mode: Arc::new(AtomicUsize::new(mode)),
            ..Default::default()
        }
    }
}

async fn push_handler(
    State(state): State<PeerState>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    *state.last_body.lock().await = Some(body);
    match state.mode.load(Ordering::Relaxed) {
        MODE_FAIL => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": "stub down"})),
        ),
        _ => (
            StatusCode::OK,
            axum::Json(serde_json::json!({"applied": 1, "noop": 0, "skipped": 0})),
        ),
    }
}

async fn spawn_mock_peer(state: PeerState) -> String {
    let app = Router::new()
        .route("/api/v1/sync/push", post(push_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

/// On-disk sqlite `Db` migrated past v48 so `federation_push_dlq` exists.
/// Scratch lives under `.local-runs/` per the project no-`/tmp` hard rule.
fn fresh_dlq_db() -> (tempfile::TempDir, ai_memory::handlers::Db) {
    let tmp = tempfile::Builder::new()
        .prefix("v100-2717-delete-dlq-default-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("create local-runs tempdir");
    let db_path = tmp.path().join("dlq.db");
    let conn = ai_memory::storage::open(&db_path).expect("open sqlite");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle = Arc::new(tokio::sync::Mutex::new((conn, db_path, ttl, true)));
    (tmp, handle)
}

/// Build a config whose quorum W equals N so every configured peer is required —
/// the fanout can never early-exit before the failing peer is observed.
fn build_cfg(
    peers: &[(&str, &str)],
    sink: Arc<dyn FederationDlqSink>,
    ack_timeout_ms: u64,
    client_timeout_ms: u64,
) -> FederationConfig {
    let _ = ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION
        .set(Box::new(|_action| Ok(())));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(client_timeout_ms))
        .build()
        .expect("build reqwest client");
    let n = peers.len() + 1;
    FederationConfig {
        policy: QuorumPolicy::new(
            n,
            n,
            Duration::from_millis(ack_timeout_ms),
            Duration::from_secs(30),
        )
        .unwrap(),
        peers: peers
            .iter()
            .map(|(id, url)| PeerEndpoint {
                id: (*id).to_string(),
                sync_push_url: format!("{url}/api/v1/sync/push"),
            })
            .collect(),
        client,
        sender_agent_id: "ai:delete-dlq-2717".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: Some(sink),
    }
}

/// Assert the enqueued payload is the verbatim delete body the lane built, so
/// the existing replay worker re-POSTs a correct deletion with no replay-side
/// change.
fn assert_delete_payload(payload: &serde_json::Value, memory_id: &str) {
    assert_eq!(
        payload["deletions"],
        serde_json::json!([memory_id]),
        "payload must carry the tombstone target: {payload}"
    );
    assert_eq!(
        payload["memories"],
        serde_json::json!([]),
        "delete body carries no memories: {payload}"
    );
    assert_eq!(
        payload["dry_run"],
        serde_json::json!(false),
        "delete body is not a dry run: {payload}"
    );
}

/// A DOWN peer leaves exactly one pending delete DLQ row carrying the right
/// `memory_id` / `peer_id` / delete payload — ON THE DEFAULT BUILD. Pre-#2717
/// the delete-lane landing pass was `#[cfg(feature = "sal")]`, so the default
/// binary this test compiles under enqueued ZERO rows here.
#[tokio::test]
async fn peer_down_leaves_pending_delete_dlq_row_default_build_2717() {
    let peer = PeerState::with_mode(MODE_FAIL);
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    let cfg = build_cfg(&[("peer-down", &peer_url)], sink.clone(), 2000, 500);

    let tracker = broadcast_delete_quorum(&cfg, "del-2717-down")
        .await
        .expect("broadcast returns the tracker");
    assert!(
        !tracker.is_quorum_met(std::time::Instant::now()),
        "W=N=2 with the peer down cannot reach quorum"
    );

    let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "#2717: a failed federated DELETE must land exactly one DLQ row on the \
         DEFAULT build (pre-fix the delete-lane landing pass was sal-gated, so \
         the shipped binary enqueued nothing at all and silently dropped the \
         erasure)"
    );
    let row = &pending[0];
    assert_eq!(row.memory_id, "del-2717-down");
    assert_eq!(row.peer_id, "peer-down");
    assert_eq!(row.attempt_count, 1);
    assert!(
        !row.last_error.is_empty(),
        "last_error MUST capture the peer's failure reason"
    );
    assert_delete_payload(&row.payload_json, "del-2717-down");
}

/// A peer that acks leaves NO row. Deliberately paired with a failing sibling
/// peer so the test is not vacuously green at the parent commit: it asserts BOTH
/// that exactly one row exists AND that it belongs to the DOWN peer, so it fails
/// pre-fix (zero rows) for the right reason. ON THE DEFAULT BUILD.
#[tokio::test(flavor = "multi_thread")]
async fn acking_peer_leaves_no_delete_dlq_row_default_build_2717() {
    let healthy = PeerState::with_mode(MODE_OK);
    let down = PeerState::with_mode(MODE_FAIL);
    let healthy_url = spawn_mock_peer(healthy.clone()).await;
    let down_url = spawn_mock_peer(down.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    let cfg = build_cfg(
        &[("peer-healthy", &healthy_url), ("peer-down", &down_url)],
        sink.clone(),
        3000,
        1000,
    );

    let _ = broadcast_delete_quorum(&cfg, "del-2717-mixed")
        .await
        .expect("broadcast returns the tracker");

    let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "#2717: exactly one row — the ACKing peer converged and must NOT be \
         enqueued; got {:?}",
        pending
            .iter()
            .map(|r| r.peer_id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        pending[0].peer_id, "peer-down",
        "the row must belong to the peer that did not ack"
    );
    assert!(
        !pending.iter().any(|r| r.peer_id == "peer-healthy"),
        "an ACKing peer must never leave a DLQ row"
    );
    assert_delete_payload(&pending[0].payload_json, "del-2717-mixed");
}
