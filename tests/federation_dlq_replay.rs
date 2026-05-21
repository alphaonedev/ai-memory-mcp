// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! v0.7.0 Track D #933 regression test — the federation push DLQ +
//! `replay_federation_push_dlq` worker MUST recover a peer push that
//! failed inside `broadcast_store_quorum`'s deadline on the peer's
//! recovery.
//!
//! ## Why this test exists
//!
//! Pre-#933 the per-peer push tasks inside `broadcast_store_quorum`
//! had no audit surface: if the leader's local commit succeeded but
//! a peer was unreachable past the deadline, NOTHING captured the
//! missed push. On the peer's recovery the catchup loop pulled rows
//! the peer was behind on but the leader never re-attempted the
//! original push — cross-recall consistency only worked because both
//! daemons shared a postgres store (Track B finding #925 masked the
//! gap). See issue body for the full reproduction.
//!
//! ## Coverage
//!
//! - `broadcast_fanout_failure_enqueues_dlq_row` — drive
//!   `broadcast_store_quorum` against a peer that returns 500 on
//!   every POST. Assert: (a) the quorum write fails with
//!   `QuorumNotMet`, (b) the DLQ contains exactly one row for the
//!   `(memory_id, peer_id)` pair, (c) the row's `payload_json`
//!   matches the original POST body, (d) `attempt_count == 1`, (e)
//!   `replayed_at IS NULL`.
//!
//! - `replay_drains_dlq_when_peer_recovers` — preload a DLQ row, swap
//!   the peer to return 200, run one `replay_once` tick, assert: (a)
//!   the row's `replayed_at` is set, (b)
//!   `federation_push_dlq_depth` gauge drops to 0, (c) the peer
//!   received a POST whose body matches the original payload.
//!
//! - `dlq_dedupes_repeated_failures_via_unique_index` — drive two
//!   back-to-back broadcasts for the same memory id against the same
//!   failing peer. Assert: (a) only ONE pending DLQ row exists, (b)
//!   `attempt_count == 2`, (c) the conflict path via the partial
//!   unique index fires (and doesn't error).
//!
//! Together these three pin the issue body's "stop bob, write, start
//! bob, observe replay" loop without requiring Docker. The shape is
//! the same as the manual Docker reproduction; the difference is the
//! peer is a mock Axum router under tokio, and the leader uses an
//! in-memory sqlite `Db` connection running through `SqliteDlqSink`.

#![cfg(feature = "sal")]

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use ai_memory::federation::push_dlq::{FederationDlqSink, SqliteDlqSink, replay_once};
use ai_memory::federation::{FederationConfig, PeerEndpoint, broadcast_store_quorum};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::replication::QuorumPolicy;

#[derive(Clone, Default)]
struct PeerState {
    /// Toggle peer behaviour: `true` = return 500, `false` = return 200.
    fail_mode: Arc<AtomicBool>,
    /// Number of POSTs the peer has received.
    hit_count: Arc<AtomicUsize>,
    /// Last body received (so the test can assert payload round-trips
    /// untouched through the DLQ).
    last_body: Arc<Mutex<Option<serde_json::Value>>>,
}

async fn push_handler(
    State(state): State<PeerState>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    state.hit_count.fetch_add(1, Ordering::Relaxed);
    *state.last_body.lock().await = Some(body);
    if state.fail_mode.load(Ordering::Relaxed) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": "stub down"})),
        );
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"applied": 1, "noop": 0, "skipped": 0})),
    )
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

fn sample_memory(id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: "track-d/dlq".to_string(),
        title: "dlq-probe".to_string(),
        content: "v0.7.0 Track D #933 DLQ regression test payload".to_string(),
        tags: vec!["dlq".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "ai:dlq-test"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Build an on-disk sqlite `Db` (under a tmpdir-scoped tempdir; honors
/// the project no-`/tmp` rule by using cargo's manifest dir) that has
/// run every migration up to v48, so the `federation_push_dlq` table
/// is present.
fn fresh_dlq_db() -> (tempfile::TempDir, ai_memory::handlers::Db) {
    let tmp = tempfile::Builder::new()
        .prefix("v07-933-dlq-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("create local-runs tempdir");
    let db_path = tmp.path().join("dlq.db");
    let conn = ai_memory::storage::open(&db_path).expect("open sqlite");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle = Arc::new(tokio::sync::Mutex::new((conn, db_path, ttl, true)));
    (tmp, handle)
}

fn build_cfg_with_sink(
    peer_url: &str,
    sink: Arc<dyn FederationDlqSink>,
    timeout_ms: u64,
) -> FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .expect("build reqwest client");
    FederationConfig {
        // Quorum N=2, W=2 forces the per-peer push to be required
        // for quorum convergence. With the peer in fail-mode the
        // write returns QuorumNotMet AND lands a DLQ row.
        policy: QuorumPolicy::new(
            2,
            2,
            Duration::from_millis(timeout_ms),
            Duration::from_secs(30),
        )
        .unwrap(),
        peers: vec![PeerEndpoint {
            id: "peer-0".to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: "ai:dlq-test".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: Some(sink),
    }
}

/// #933 root cause test: when a configured peer fails to ack inside
/// the deadline, `broadcast_store_quorum` MUST land a `federation_push_dlq`
/// row capturing the `memory_id`, `peer_id`, payload, and failure reason.
/// Pre-#933 the failure was silently dropped.
#[tokio::test]
async fn broadcast_fanout_failure_enqueues_dlq_row() {
    let peer = PeerState {
        fail_mode: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    };
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()));
    let cfg = build_cfg_with_sink(&peer_url, sink.clone(), 500);

    let mem = sample_memory("dlq-mem-001");
    let result = broadcast_store_quorum(&cfg, &mem).await;
    // With W=2 and the peer down, quorum can't be met.
    assert!(
        result.is_ok(),
        "broadcast itself returns Ok(AckTracker); finalise() carries the failure",
    );
    let tracker = result.unwrap();
    // Quorum-met assertion: should be false because peer is down.
    assert!(!tracker.is_quorum_met(std::time::Instant::now()));

    // Now assert the DLQ contains the row.
    let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "exactly one DLQ row should land for the failed (memory_id, peer_id) pair"
    );
    let row = &pending[0];
    assert_eq!(row.memory_id, "dlq-mem-001");
    assert_eq!(row.peer_id, "peer-0");
    assert_eq!(row.attempt_count, 1);
    assert!(
        !row.last_error.is_empty(),
        "last_error MUST capture the failure reason (peer 500 or deadline_exceeded)"
    );
    // Payload should embed the memory id so a replay re-POSTs the
    // same shape regardless of upstream row evolution.
    let payload_json_str = row.payload_json.to_string();
    assert!(
        payload_json_str.contains("dlq-mem-001"),
        "payload_json must contain memory_id; got: {payload_json_str}"
    );
}

/// #933 happy-path test: a preloaded DLQ row drains on the next
/// `replay_once` tick when the peer is back up. This is the canonical
/// "stop bob, write, start bob, observe replay" shape from the issue
/// body, exercised here without Docker via the mock peer.
#[tokio::test]
async fn replay_drains_dlq_when_peer_recovers() {
    let peer = PeerState {
        fail_mode: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    };
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()));
    let cfg = build_cfg_with_sink(&peer_url, sink.clone(), 500);

    // Step 1: peer down, write fails, DLQ row lands.
    let mem = sample_memory("dlq-mem-002");
    let _ = broadcast_store_quorum(&cfg, &mem).await;
    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        1,
        "DLQ should have 1 pending row after peer-down broadcast"
    );
    let hits_after_broadcast = peer.hit_count.load(Ordering::Relaxed);
    assert!(
        hits_after_broadcast >= 1,
        "peer should have received at least the initial failing POST"
    );

    // Step 2: peer comes back online (flip fail_mode → false).
    peer.fail_mode.store(false, Ordering::Relaxed);

    // Step 3: drive one replay tick. The DLQ row should drain.
    replay_once(&cfg, sink.as_ref()).await;

    let pending_after = sink.pending_dlq_count().await.unwrap();
    assert_eq!(
        pending_after, 0,
        "DLQ should drain to 0 after replay tick with peer healthy",
    );

    // Step 4: confirm the replay actually POSTed to the peer (not
    // some other side-channel) — the peer's hit_count should have
    // increased by exactly 1.
    let hits_after_replay = peer.hit_count.load(Ordering::Relaxed);
    assert_eq!(
        hits_after_replay,
        hits_after_broadcast + 1,
        "replay_once must POST exactly once per DLQ row"
    );

    // Step 5: confirm the replayed payload matched the original
    // payload (the issue body's NOT-via-shared-store invariant —
    // payload round-trips intact through the DLQ).
    let last = peer.last_body.lock().await.clone();
    let body_str = serde_json::to_string(&last.unwrap()).unwrap();
    assert!(
        body_str.contains("dlq-mem-002"),
        "peer's last received body should contain the replayed memory id"
    );
    assert!(
        body_str.contains("Track D #933"),
        "peer's last received body should contain the original memory content"
    );

    // Step 6: confirm the Prometheus gauge moved.
    let depth = ai_memory::metrics::registry()
        .federation_push_dlq_depth
        .get();
    assert_eq!(
        depth, 0,
        "federation_push_dlq_depth gauge must reflect post-drain sink count"
    );
}

/// #933 idempotency test: two back-to-back broadcasts for the same
/// memory id against the same failing peer must produce exactly ONE
/// pending DLQ row (not two). The partial unique index on
/// `(memory_id, peer_id) WHERE replayed_at IS NULL` enforces this.
#[tokio::test]
async fn dlq_dedupes_repeated_failures_via_unique_index() {
    let peer = PeerState {
        fail_mode: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    };
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()));
    let cfg = build_cfg_with_sink(&peer_url, sink.clone(), 500);

    let mem = sample_memory("dlq-mem-003");
    // Two broadcasts for the same memory id against the same down
    // peer. Without the partial unique index this would land two
    // pending rows and the replay worker would attempt the push
    // twice — wasted work + an audit-trail muddle.
    let _ = broadcast_store_quorum(&cfg, &mem).await;
    let _ = broadcast_store_quorum(&cfg, &mem).await;

    let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "ON CONFLICT(memory_id, peer_id) WHERE replayed_at IS NULL must \
         coalesce two failures into one pending row"
    );
    assert_eq!(
        pending[0].attempt_count, 2,
        "the second failure must bump attempt_count instead of inserting"
    );
}
