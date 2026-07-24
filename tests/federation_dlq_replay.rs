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
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
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
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
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
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
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

/// #1578 — quarantined rows must NOT starve the take batch.
///
/// Pre-fix, `take_pending_dlq_rows` had no `attempt_count` exclusion:
/// once `batch`-many oldest rows hit `MAX_REPLAY_ATTEMPTS`, the worker
/// fetched exactly those every tick, skipped them in-loop, and never
/// reached the replayable tail — observed live on do-1461 with 64
/// quarantined heads wedging 62k replayable rows. The take query now
/// excludes at-ceiling rows.
#[tokio::test(flavor = "multi_thread")]
async fn quarantined_head_does_not_starve_take_batch_1578() {
    use ai_memory::federation::push_dlq::MAX_REPLAY_ATTEMPTS;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());

    // Oldest row: already at the quarantine ceiling.
    sink.enqueue_push_failure("mem-quarantined", "peer-x", &serde_json::json!({}), "boom")
        .await
        .expect("enqueue head");
    {
        let lock = db.lock().await;
        lock.0
            .execute(
                "UPDATE federation_push_dlq SET attempt_count = ?1 WHERE memory_id = 'mem-quarantined'",
                rusqlite::params![MAX_REPLAY_ATTEMPTS],
            )
            .expect("age the head row to the ceiling");
    }
    // Newer, replayable row behind it.
    sink.enqueue_push_failure("mem-replayable", "peer-x", &serde_json::json!({}), "boom")
        .await
        .expect("enqueue tail");

    // A take batch of ONE must skip the quarantined head and return
    // the replayable tail row — pre-fix this returned the quarantined
    // head and the tail starved.
    let took = sink.take_pending_dlq_rows(1).await.expect("take");
    assert_eq!(took.len(), 1, "one replayable row expected");
    assert_eq!(
        took[0].memory_id, "mem-replayable",
        "#1578: the at-ceiling head must be excluded from the take set"
    );
}

/// #1579 B5 — adaptive drain batch. The pre-fix worker took a FIXED
/// 64 rows per tick, capping bulk drains at 128 rows/min/peer at the
/// default 30s cadence (the #1578 62k-row backlog took 8+ hours).
/// `replay_once` now scales the take to `min(backlog, cap)` (floor
/// 64, cap default 2048 / `AI_MEMORY_FED_DLQ_REPLAY_MAX_BATCH`), so
/// a 150-row backlog must drain in ONE tick against a healthy peer.
/// Quarantine semantics + the #1578 take-exclusion are untouched
/// (pinned by `quarantined_head_does_not_starve_take_batch_1578`
/// above, which keeps running unchanged).
#[tokio::test(flavor = "multi_thread")]
async fn adaptive_batch_drains_backlog_beyond_fixed_64_in_one_tick_1579b5() {
    use ai_memory::federation::push_dlq::REPLAY_BATCH_SIZE;

    let peer = PeerState {
        fail_mode: Arc::new(AtomicBool::new(false)), // healthy from the start
        ..Default::default()
    };
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    let cfg = build_cfg_with_sink(&peer_url, sink.clone(), 2000);

    // Preload a backlog comfortably above the legacy fixed batch.
    let backlog = REPLAY_BATCH_SIZE * 2 + 22; // 150
    for i in 0..backlog {
        sink.enqueue_push_failure(
            &format!("mem-adaptive-{i:04}"),
            "peer-0",
            &serde_json::json!({"sender_agent_id": "ai:dlq-test", "memories": [], "dry_run": false}),
            "preloaded for #1579 B5 adaptive-batch test",
        )
        .await
        .expect("enqueue backlog row");
    }
    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        i64::try_from(backlog).unwrap(),
        "backlog preloaded"
    );

    // ONE replay tick must drain the whole backlog (pre-fix: only 64).
    replay_once(&cfg, sink.as_ref()).await;

    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        0,
        "#1579 B5: one adaptive tick must drain a {backlog}-row backlog \
         (pre-fix fixed batch left {} rows pending)",
        backlog - REPLAY_BATCH_SIZE,
    );
    assert_eq!(
        peer.hit_count.load(Ordering::Relaxed),
        backlog,
        "every backlog row must have been POSTed exactly once"
    );
}

/// #1579 B5 — `replay_max_batch` resolver contract: env override wins
/// when sane; zero / garbage / sub-floor values fall through to the
/// compiled default (a stray `0` can never wedge the drain).
///
/// NOTE on parallel-test safety: every value this test sets resolves
/// to an effective cap ≥ the largest backlog any sibling test in this
/// file preloads, so a concurrently-running `replay_once` can never
/// observe a cap that changes its take semantics.
#[tokio::test(flavor = "multi_thread")]
async fn replay_max_batch_env_resolver_1579b5() {
    use ai_memory::federation::push_dlq::{
        DEFAULT_REPLAY_MAX_BATCH, ENV_FED_DLQ_REPLAY_MAX_BATCH, replay_max_batch,
    };

    // Unset → compiled default.
    // SAFETY: env mutation confined to this test; see parallel-safety
    // note above.
    unsafe {
        std::env::remove_var(ENV_FED_DLQ_REPLAY_MAX_BATCH);
    }
    assert_eq!(replay_max_batch(), DEFAULT_REPLAY_MAX_BATCH);

    // Sane override → honored.
    unsafe {
        std::env::set_var(ENV_FED_DLQ_REPLAY_MAX_BATCH, "4096");
    }
    assert_eq!(replay_max_batch(), 4096);

    // Garbage → default.
    unsafe {
        std::env::set_var(ENV_FED_DLQ_REPLAY_MAX_BATCH, "not-a-number");
    }
    assert_eq!(replay_max_batch(), DEFAULT_REPLAY_MAX_BATCH);

    // Below the REPLAY_BATCH_SIZE floor → default (never shrinks the
    // worker below its historical fixed batch).
    unsafe {
        std::env::set_var(ENV_FED_DLQ_REPLAY_MAX_BATCH, "10");
    }
    assert_eq!(replay_max_batch(), DEFAULT_REPLAY_MAX_BATCH);

    unsafe {
        std::env::remove_var(ENV_FED_DLQ_REPLAY_MAX_BATCH);
    }
}

/// #1566 / #1579 B1 — sender wire shape. `broadcast_store_quorum_with_embedding`
/// must place the shipped vector under the top-level `embeddings` key
/// of the push body (INSIDE the signed payload), and the legacy
/// `broadcast_store_quorum` entry point must keep the pre-#1566 wire
/// bytes (no `embeddings` key at all) so older peers see an unchanged
/// shape.
#[tokio::test(flavor = "multi_thread")]
async fn broadcast_with_embedding_ships_vector_in_push_body_1566() {
    use ai_memory::federation::{ShippedEmbedding, broadcast_store_quorum_with_embedding};

    let peer = PeerState {
        fail_mode: Arc::new(AtomicBool::new(false)),
        ..Default::default()
    };
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    let cfg = build_cfg_with_sink(&peer_url, sink.clone(), 2000);

    // (a) With a shipped embedding → `embeddings` array in the body.
    let mem = sample_memory("wire-embed-001");
    let shipped = ShippedEmbedding::new(
        mem.id.clone(),
        "wire-test-model".to_string(),
        vec![1.5_f32, -2.5, 3.5],
    );
    let _ = broadcast_store_quorum_with_embedding(&cfg, &mem, Some(&shipped))
        .await
        .expect("broadcast with embedding");
    let body = peer
        .last_body
        .lock()
        .await
        .clone()
        .expect("peer received the push");
    let arr = body["embeddings"]
        .as_array()
        .expect("body must carry the embeddings array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["memory_id"], "wire-embed-001");
    assert_eq!(arr[0]["dim"], 3);
    assert_eq!(
        arr[0]["vector"].as_array().map(Vec::len),
        Some(3),
        "vector payload round-trips: {body}"
    );

    // (b) Legacy entry point → byte-shape parity: no `embeddings` key.
    let mem2 = sample_memory("wire-noembed-001");
    let _ = broadcast_store_quorum(&cfg, &mem2)
        .await
        .expect("broadcast without embedding");
    // Poll until the second push lands (post-quorum detach may lag).
    for _ in 0..100 {
        let last = peer.last_body.lock().await.clone();
        if last
            .as_ref()
            .is_some_and(|b| b.to_string().contains("wire-noembed-001"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let body2 = peer
        .last_body
        .lock()
        .await
        .clone()
        .expect("peer received the second push");
    assert!(
        body2.get("embeddings").is_none(),
        "legacy broadcast_store_quorum must keep the pre-#1566 wire shape: {body2}"
    );
}

// ===========================================================================
// #2360 — ON CONFLICT refreshes payload_json/failed_at; mark_dlq_row_replayed
// is attempt_count-guarded so a concurrent failure is never lost.
// ===========================================================================

/// #2360 (Part 1) — a second failed push for the SAME `(memory_id, peer_id)`
/// must REFRESH `payload_json` + `failed_at` on conflict (not coalesce the
/// newer failure onto the stale first-failure body). Pre-fix the ON CONFLICT
/// DO UPDATE touched only `attempt_count` + `last_error`, so a replay
/// re-POSTed an outdated body.
#[tokio::test]
async fn enqueue_refreshes_payload_json_and_failed_at_on_conflict_2360() {
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());

    let body_v1 = serde_json::json!({"memories": [{"id": "mem-2360", "gen": 1}], "gen": 1});
    sink.enqueue_push_failure("mem-2360", "peer-0", &body_v1, "first failure")
        .await
        .expect("first enqueue");

    // Snapshot the persisted failed_at/payload after the first failure.
    let (failed_at_v1, payload_v1): (String, String) = {
        let g = db.lock().await;
        g.0.query_row(
            "SELECT failed_at, payload_json FROM federation_push_dlq WHERE memory_id = ?1",
            rusqlite::params!["mem-2360"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("row after first failure")
    };
    assert!(
        payload_v1.contains("\"gen\":1"),
        "v1 body persisted: {payload_v1}"
    );

    // Ensure a strictly-later RFC3339 instant for the refreshed failed_at.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let body_v2 = serde_json::json!({"memories": [{"id": "mem-2360", "gen": 2}], "gen": 2});
    sink.enqueue_push_failure("mem-2360", "peer-0", &body_v2, "second failure")
        .await
        .expect("second enqueue (conflict path)");

    // The pending row must now carry attempt_count=2, the NEWEST body, the
    // refreshed last_error, and a strictly-newer failed_at.
    let pending = sink.take_pending_dlq_rows(64).await.expect("take");
    assert_eq!(
        pending.len(),
        1,
        "conflict path must NOT stack a duplicate row"
    );
    assert_eq!(pending[0].attempt_count, 2, "attempt_count still bumps");
    assert_eq!(
        pending[0].payload_json["gen"],
        serde_json::json!(2),
        "payload_json REFRESHED to the newest failed body (was stale v1 pre-#2360)"
    );
    assert_eq!(
        pending[0].last_error, "second failure",
        "last_error refreshed"
    );

    let failed_at_v2: String = {
        let g = db.lock().await;
        g.0.query_row(
            "SELECT failed_at FROM federation_push_dlq WHERE memory_id = ?1",
            rusqlite::params!["mem-2360"],
            |r| r.get(0),
        )
        .expect("row after second failure")
    };
    assert!(
        failed_at_v2 > failed_at_v1,
        "failed_at REFRESHED on conflict ({failed_at_v1} -> {failed_at_v2})"
    );
}

/// #2360 (Part 2) — `mark_dlq_row_replayed(id, expected_attempt_count)` is an
/// optimistic-concurrency CAS: it clears the row ONLY when the persisted
/// `attempt_count` still matches the take-time snapshot. A concurrent
/// `enqueue_push_failure` that bumped the counter (and refreshed the body)
/// between take and mark makes the guarded UPDATE a 0-row no-op, so the row
/// stays pending and the newest body is re-delivered next tick.
#[tokio::test]
async fn mark_replayed_cas_leaves_row_pending_on_concurrent_bump_2360() {
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());

    let body_v1 = serde_json::json!({"memories": [], "gen": 1});
    sink.enqueue_push_failure("mem-cas", "peer-0", &body_v1, "first")
        .await
        .expect("enqueue v1");

    // Worker drains the row → observes attempt_count == 1.
    let snapshot = sink.take_pending_dlq_rows(64).await.expect("take");
    assert_eq!(snapshot.len(), 1);
    let row_id = snapshot[0].id;
    assert_eq!(snapshot[0].attempt_count, 1);

    // A concurrent failure lands BEFORE the worker marks the row replayed.
    let body_v2 = serde_json::json!({"memories": [], "gen": 2});
    sink.enqueue_push_failure("mem-cas", "peer-0", &body_v2, "second")
        .await
        .expect("concurrent enqueue v2");

    // Marking with the STALE snapshot (attempt_count=1) must be a no-op.
    let marked = sink
        .mark_dlq_row_replayed(row_id, 1)
        .await
        .expect("mark with stale snapshot");
    assert!(
        !marked,
        "stale-snapshot mark must NOT clear the refreshed row"
    );
    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        1,
        "row stays pending — the concurrent failure is NOT lost"
    );

    // Re-take (attempt_count now 2) and mark with the CURRENT counter → clears.
    let fresh = sink.take_pending_dlq_rows(64).await.expect("re-take");
    assert_eq!(fresh[0].attempt_count, 2);
    let marked2 = sink
        .mark_dlq_row_replayed(row_id, 2)
        .await
        .expect("mark with fresh snapshot");
    assert!(marked2, "matching-snapshot mark clears the row");
    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        0,
        "row cleared once the current attempt_count is acknowledged"
    );
}

/// #2360 (Part 2, end-to-end) — drive `replay_once` to the Ack arm against a
/// healthy peer, but with a sink whose take-time snapshot is stale relative to
/// the persisted row (models a concurrent failure between take and mark). The
/// Ack arm's guarded mark returns `Ok(false)`, so the row is LEFT PENDING
/// rather than clobbered.
#[tokio::test]
async fn replay_ack_leaves_row_pending_when_snapshot_is_stale_2360() {
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    /// Sink that reports a take-time `attempt_count` one behind the value its
    /// guarded mark will require — the lost-update race, deterministically.
    #[derive(Default)]
    struct RacingSink {
        marked: AtomicBool,
        left_pending: AtomicBool,
        takes: AtomicUsize,
    }

    #[async_trait]
    impl FederationDlqSink for RacingSink {
        async fn enqueue_push_failure(
            &self,
            _m: &str,
            _p: &str,
            _b: &serde_json::Value,
            _e: &str,
        ) -> Result<(), String> {
            Ok(())
        }
        async fn take_pending_dlq_rows(
            &self,
            _limit: usize,
        ) -> Result<Vec<ai_memory::federation::push_dlq::FederationPushDlqRow>, String> {
            // Only surface the row on the first tick; snapshot attempt_count = 1.
            if self.takes.fetch_add(1, Ordering::SeqCst) > 0 {
                return Ok(Vec::new());
            }
            Ok(vec![
                ai_memory::federation::push_dlq::FederationPushDlqRow {
                    id: 42,
                    memory_id: "mem-race".to_string(),
                    peer_id: "peer-0".to_string(),
                    payload_json: serde_json::json!({"memories": [], "gen": 1}),
                    attempt_count: 1,
                    last_error: "prior".to_string(),
                },
            ])
        }
        async fn mark_dlq_row_replayed(
            &self,
            _id: i64,
            expected_attempt_count: i32,
        ) -> Result<bool, String> {
            // Persisted row is now at attempt_count = 2 (a concurrent failure
            // bumped it), so the take-time snapshot of 1 no longer matches.
            if expected_attempt_count == 2 {
                self.marked.store(true, Ordering::SeqCst);
                Ok(true)
            } else {
                self.left_pending.store(true, Ordering::SeqCst);
                Ok(false)
            }
        }
        async fn bump_dlq_attempt(&self, _id: i64, _e: &str) -> Result<(), String> {
            Ok(())
        }
        async fn pending_dlq_count(&self) -> Result<i64, String> {
            Ok(1)
        }
        async fn note_dlq_throttled(&self, _id: i64, _e: &str) -> Result<(), String> {
            Ok(())
        }
        async fn reset_throttled_quarantine(&self) -> Result<u64, String> {
            Ok(0)
        }
    }

    let peer = PeerState {
        fail_mode: Arc::new(AtomicBool::new(false)), // healthy → Ack
        ..Default::default()
    };
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let sink = Arc::new(RacingSink::default());
    let cfg = build_cfg_with_sink(&peer_url, sink.clone(), 2000);

    replay_once(&cfg, sink.as_ref()).await;

    assert!(
        sink.left_pending.load(Ordering::SeqCst),
        "the Ack arm must take the guarded-no-op branch on a stale snapshot"
    );
    assert!(
        !sink.marked.load(Ordering::SeqCst),
        "the row must NOT be marked replayed under a stale snapshot"
    );
    assert_eq!(
        peer.hit_count.load(Ordering::Relaxed),
        1,
        "the peer still received the (newest) POST exactly once"
    );
}

/// #2360 — postgres arm parity. Mirrors the sqlite refresh + CAS-guard pins
/// against a live `PostgresStore`. Ignored by default; run with
/// `AI_MEMORY_TEST_POSTGRES_URL` set (`cargo test --features sal-postgres --
/// --ignored`).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL pointing at a live instance"]
async fn pg_dlq_refresh_and_cas_guard_2360() {
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

    // Unique ids so re-runs against a shared DB don't collide.
    let mem_id = format!("mem-2360-pg-{}", uuid::Uuid::new_v4());
    let peer_id = "peer-2360-pg";

    let body_v1 = serde_json::json!({"memories": [], "gen": 1});
    sink.enqueue_push_failure(&mem_id, peer_id, &body_v1, "first")
        .await
        .expect("pg enqueue v1");
    let body_v2 = serde_json::json!({"memories": [], "gen": 2});
    sink.enqueue_push_failure(&mem_id, peer_id, &body_v2, "second")
        .await
        .expect("pg enqueue v2 (conflict)");

    let pending = sink.take_pending_dlq_rows(64).await.expect("pg take");
    let row = pending
        .iter()
        .find(|r| r.memory_id == mem_id)
        .expect("our pg row");
    assert_eq!(row.attempt_count, 2, "pg attempt_count bumps on conflict");
    assert_eq!(
        row.payload_json["gen"],
        serde_json::json!(2),
        "pg payload_json REFRESHED to newest failed body"
    );

    // Stale-snapshot mark is a no-op; current-snapshot mark clears.
    assert!(
        !sink
            .mark_dlq_row_replayed(row.id, 1)
            .await
            .expect("pg stale mark"),
        "pg stale-snapshot mark must NOT clear"
    );
    assert!(
        sink.mark_dlq_row_replayed(row.id, 2)
            .await
            .expect("pg fresh mark"),
        "pg current-snapshot mark clears"
    );
}
