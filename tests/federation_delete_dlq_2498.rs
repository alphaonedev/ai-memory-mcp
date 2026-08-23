// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2498 regression suite — the federated DELETE lane MUST land a
//! `federation_push_dlq` row for every dispatched peer that does not ack,
//! exactly as the #933 store lane does.
//!
//! ## Why this test exists
//!
//! Pre-#2498 `enqueue_push_failure` had exactly ONE production caller: the
//! #933 landing pass at the bottom of `broadcast_store_quorum`. The delete
//! lane (`broadcast_delete_quorum`) had no DLQ enqueue at all — its per-peer
//! failure arm did nothing but `tracing::warn!`. So a federated deletion that
//! failed to reach a peer — because the peer was DOWN, because its deadline
//! elapsed, or because the receiver REFUSED it and reported `skipped > 0`
//! inside an HTTP 200 (converted to a non-ack by #2341's
//! `success_report_non_ack_reason`) — was logged once and then vanished.
//! Nothing retried it. The replica kept a row the origin erased, permanently,
//! and could later LWW-resurrect it: a GDPR-adjacent correctness failure and a
//! silent, permanent replica divergence.
//!
//! ## Coverage (each assertion FAILS at parent 03bbd556, PASSES after)
//!
//! - `peer_down_leaves_pending_delete_dlq_row_2498` — a peer returning 500
//!   leaves exactly one pending row carrying the right `memory_id`, `peer_id`
//!   and the verbatim delete body (`memories: []`, `deletions: [id]`).
//! - `peer_200_with_skipped_leaves_pending_delete_dlq_row_2498` — the
//!   "invisible refusal" the issue is named for: an HTTP 200 whose receiver
//!   report counts `skipped > 0` ALSO lands a row.
//! - `deadline_evicted_peer_leaves_pending_delete_dlq_row_2498` — a peer whose
//!   task never reports inside the deadline lands a row with the
//!   `deadline_exceeded` reason (the bucket that only the
//!   `dispatched ∖ acked` subtraction can see).
//! - `acking_peer_leaves_no_delete_dlq_row_2498` — two peers, one healthy and
//!   one down: exactly ONE row, and it belongs to the DOWN peer. (Written with
//!   a failing sibling on purpose so it is not vacuously green at the parent
//!   commit — a bare "no row" assertion would pass pre-fix.)
//! - `replay_redelivers_deletion_and_clears_row_2498` — `replay_once` against a
//!   recovered peer re-POSTs `deletions: [id]` and clears the row, with NO
//!   replay-side change (`expected_id` only matters for the `ids` echo, which a
//!   delete response does not carry).
//! - `pg_delete_lane_dlq_parity_2498` (`sal-postgres`, `#[ignore]`) — the same
//!   delete-lane landing pass driven through `PostgresDlqSink`, proving the
//!   enqueue is backend-blind trait dispatch rather than a sqlite-only path.

#![cfg(feature = "sal")]
#![allow(clippy::needless_update)]

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use ai_memory::federation::push_dlq::{FederationDlqSink, SqliteDlqSink, replay_once};
use ai_memory::federation::{FederationConfig, PeerEndpoint, broadcast_delete_quorum};
use ai_memory::replication::QuorumPolicy;

/// Peer behaviours the mock receiver can be switched between mid-test.
const MODE_OK: usize = 0;
/// Peer is DOWN — every POST answers 500.
const MODE_FAIL: usize = 1;
/// Peer answers HTTP **200** but its receiver report counts `skipped > 0` —
/// the #1934/#2488 namespace-refusal shape. #2341's
/// `success_report_non_ack_reason` converts this into `AckOutcome::Fail`.
const MODE_SKIPPED: usize = 2;
/// Peer stalls past the sender's ack deadline so its fanout task never reports.
const MODE_SLOW: usize = 3;

/// How long `MODE_SLOW` stalls. Comfortably beyond `ACK_TIMEOUT_MS` so the
/// deadline arm is deterministic rather than timing-raced.
const SLOW_PEER_STALL: Duration = Duration::from_secs(2);
/// Ack deadline used by the deadline-eviction test.
const ACK_TIMEOUT_MS: u64 = 300;

#[derive(Clone, Default)]
struct PeerState {
    mode: Arc<AtomicUsize>,
    hit_count: Arc<AtomicUsize>,
    last_body: Arc<Mutex<Option<serde_json::Value>>>,
}

impl PeerState {
    fn with_mode(mode: usize) -> Self {
        Self {
            mode: Arc::new(AtomicUsize::new(mode)),
            ..Default::default()
        }
    }
    fn set_mode(&self, mode: usize) {
        self.mode.store(mode, Ordering::Relaxed);
    }
    fn hits(&self) -> usize {
        self.hit_count.load(Ordering::Relaxed)
    }
}

async fn push_handler(
    State(state): State<PeerState>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    state.hit_count.fetch_add(1, Ordering::Relaxed);
    *state.last_body.lock().await = Some(body);
    match state.mode.load(Ordering::Relaxed) {
        MODE_FAIL => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": "stub down"})),
        ),
        MODE_SKIPPED => (
            // The invisible refusal: 200 OK, nothing applied.
            StatusCode::OK,
            axum::Json(serde_json::json!({"applied": 0, "noop": 0, "skipped": 1})),
        ),
        MODE_SLOW => {
            tokio::time::sleep(SLOW_PEER_STALL).await;
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({"applied": 1, "noop": 0, "skipped": 0})),
            )
        }
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
        .prefix("v100-2498-delete-dlq-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("create local-runs tempdir");
    let db_path = tmp.path().join("dlq.db");
    let conn = ai_memory::storage::open(&db_path).expect("open sqlite");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle = Arc::new(tokio::sync::Mutex::new((conn, db_path, ttl, true)));
    (tmp, handle)
}

/// Build a config whose quorum W equals N so every configured peer is
/// required — the fanout can never early-exit before the failing peer is
/// observed.
fn build_cfg(
    peers: &[(&str, &str)],
    sink: Arc<dyn FederationDlqSink>,
    ack_timeout_ms: u64,
    client_timeout_ms: u64,
) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
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
        sender_agent_id: "ai:delete-dlq-2498".to_string(),
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
    assert_eq!(
        payload["sender_agent_id"], "ai:delete-dlq-2498",
        "delete body carries the sender attribution: {payload}"
    );
}

/// (a) A peer that is DOWN leaves a pending delete DLQ row with the right
/// `memory_id` / `peer_id` / payload. Pre-#2498 the delete lane had no
/// enqueue at all, so this landed ZERO rows.
#[tokio::test]
async fn peer_down_leaves_pending_delete_dlq_row_2498() {
    let peer = PeerState::with_mode(MODE_FAIL);
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    let cfg = build_cfg(&[("peer-down", &peer_url)], sink.clone(), 2000, 500);

    let tracker = broadcast_delete_quorum(&cfg, "del-2498-down")
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
        "#2498: a failed federated DELETE must land exactly one DLQ row \
         (pre-fix the delete lane enqueued nothing at all)"
    );
    let row = &pending[0];
    assert_eq!(row.memory_id, "del-2498-down");
    assert_eq!(row.peer_id, "peer-down");
    assert_eq!(row.attempt_count, 1);
    assert!(
        !row.last_error.is_empty(),
        "last_error MUST capture the peer's failure reason"
    );
    assert_delete_payload(&row.payload_json, "del-2498-down");
}

/// (b) The "invisible refusal" the issue is named for: the peer answers HTTP
/// **200** carrying `skipped > 0` (the #1934/#2488 namespace-refusal shape).
/// #2341 already turns that into a non-ack; #2498 is what makes it DURABLE.
#[tokio::test]
async fn peer_200_with_skipped_leaves_pending_delete_dlq_row_2498() {
    let peer = PeerState::with_mode(MODE_SKIPPED);
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    let cfg = build_cfg(&[("peer-refuses", &peer_url)], sink.clone(), 2000, 1000);

    let _ = broadcast_delete_quorum(&cfg, "del-2498-refused")
        .await
        .expect("broadcast returns the tracker");

    let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "#2498: a receiver refusal reported as `skipped` inside an HTTP 200 \
         must ALSO land a DLQ row — pre-fix it was a warn line and nothing else"
    );
    let row = &pending[0];
    assert_eq!(row.memory_id, "del-2498-refused");
    assert_eq!(row.peer_id, "peer-refuses");
    assert!(
        row.last_error.contains("skipped"),
        "last_error must carry the #2341 non-ack reason; got: {}",
        row.last_error
    );
    assert_delete_payload(&row.payload_json, "del-2498-refused");
}

/// (a', the deadline bucket) A peer whose fanout task never reports inside the
/// deadline is invisible to the per-outcome arm and only reachable via the
/// `dispatched ∖ acked` subtraction — the exact bucket the #933 store lane
/// added `dispatched_peer_ids` for.
#[tokio::test(flavor = "multi_thread")]
async fn deadline_evicted_peer_leaves_pending_delete_dlq_row_2498() {
    let peer = PeerState::with_mode(MODE_SLOW);
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    // Client timeout is generous; the ACK DEADLINE is what evicts the task.
    let cfg = build_cfg(
        &[("peer-slow", &peer_url)],
        sink.clone(),
        ACK_TIMEOUT_MS,
        10_000,
    );

    let _ = broadcast_delete_quorum(&cfg, "del-2498-deadline")
        .await
        .expect("broadcast returns the tracker");

    let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "#2498: a deadline-evicted delete peer must land a DLQ row"
    );
    assert_eq!(pending[0].peer_id, "peer-slow");
    assert_eq!(
        pending[0].last_error, "deadline_exceeded",
        "an unobserved outcome must record the deadline reason verbatim, \
         matching the store lane"
    );
    assert_delete_payload(&pending[0].payload_json, "del-2498-deadline");
}

/// (c) A peer that acks leaves NO row. Deliberately paired with a failing
/// sibling peer so the test is not vacuously green at the parent commit: it
/// asserts BOTH that exactly one row exists AND that it belongs to the DOWN
/// peer, so it fails pre-fix (zero rows) for the right reason.
#[tokio::test(flavor = "multi_thread")]
async fn acking_peer_leaves_no_delete_dlq_row_2498() {
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

    let _ = broadcast_delete_quorum(&cfg, "del-2498-mixed")
        .await
        .expect("broadcast returns the tracker");

    let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "#2498: exactly one row — the ACKing peer converged and must NOT be \
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
}

/// (d) `replay_once` against a recovered peer actually re-delivers
/// `deletions: [id]` and clears the row — with NO replay-side change. The
/// replay passes `row.memory_id` as `expected_id`, which `post_once` uses only
/// for the `ids` echo; a delete response carries no `ids`, so the ack path is
/// unaffected.
#[tokio::test(flavor = "multi_thread")]
async fn replay_redelivers_deletion_and_clears_row_2498() {
    let peer = PeerState::with_mode(MODE_FAIL);
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    let cfg = build_cfg(&[("peer-0", &peer_url)], sink.clone(), 2000, 500);

    // Step 1: peer down → the erasure lands in the DLQ.
    let _ = broadcast_delete_quorum(&cfg, "del-2498-replay")
        .await
        .expect("broadcast returns the tracker");
    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        1,
        "#2498: the failed erasure must be pending before the replay tick"
    );
    let hits_after_broadcast = peer.hits();

    // Step 2: peer recovers.
    peer.set_mode(MODE_OK);

    // Step 3: one replay tick.
    replay_once(&cfg, sink.as_ref()).await;

    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        0,
        "the delete DLQ row must drain once the peer is healthy"
    );
    assert_eq!(
        peer.hits(),
        hits_after_broadcast + 1,
        "replay_once must re-POST exactly once per DLQ row"
    );

    // Step 4: the re-POSTed body is a correct deletion, not a store.
    let last = peer
        .last_body
        .lock()
        .await
        .clone()
        .expect("peer received the replayed push");
    assert_delete_payload(&last, "del-2498-replay");
}

/// (both backends) The enqueue is TRAIT dispatch through `FederationDlqSink`,
/// so the delete-lane landing pass is backend-blind by construction. This
/// drives the SAME `broadcast_delete_quorum` code path with a
/// `PostgresDlqSink` instead of `SqliteDlqSink` and asserts the identical row.
/// Ignored by default; run against a SCRATCH database with
/// `AI_MEMORY_TEST_POSTGRES_URL` set:
/// `cargo test --features sal-postgres --test federation_delete_dlq_2498 -- --ignored`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL pointing at a live scratch instance"]
async fn pg_delete_lane_dlq_parity_2498() {
    use ai_memory::federation::push_dlq::PostgresDlqSink;
    use ai_memory::store::postgres::PostgresStore;

    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("test skipped: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = match PostgresStore::connect(&url).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("test skipped: PostgresStore::connect failed: {e}");
            return;
        }
    };
    let sink: Arc<dyn FederationDlqSink> = Arc::new(PostgresDlqSink::new(store));

    let peer = PeerState::with_mode(MODE_FAIL);
    let peer_url = spawn_mock_peer(peer.clone()).await;
    // Unique id so re-runs against a shared DB cannot collide.
    let mem_id = format!("del-2498-pg-{}", uuid::Uuid::new_v4());
    let cfg = build_cfg(&[("peer-2498-pg", &peer_url)], sink.clone(), 2000, 500);

    let _ = broadcast_delete_quorum(&cfg, &mem_id)
        .await
        .expect("broadcast returns the tracker");

    let pending = sink.take_pending_dlq_rows(256).await.expect("pg take");
    let row = pending
        .iter()
        .find(|r| r.memory_id == mem_id)
        .expect("#2498: the delete lane must land a DLQ row on the postgres sink too");
    assert_eq!(row.peer_id, "peer-2498-pg");
    assert_eq!(row.attempt_count, 1);
    assert!(!row.last_error.is_empty());
    assert_delete_payload(&row.payload_json, &mem_id);

    // Leave zero residue: clear the row we created.
    assert!(
        sink.mark_dlq_row_replayed(row.id, row.attempt_count)
            .await
            .expect("pg clear"),
        "the parity row must clear cleanly"
    );
}
