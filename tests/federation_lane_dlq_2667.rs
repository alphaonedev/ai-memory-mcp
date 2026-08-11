// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2667 regression suite — EVERY federation fanout lane MUST land a
//! `federation_push_dlq` row for a dispatched peer that does not ack, so a
//! failed fanout is durably retried by the replay worker instead of a lost
//! `tracing::warn!`.
//!
//! ## Why this test exists
//!
//! Pre-#2667 only `broadcast_store_quorum` (#933) and `broadcast_delete_quorum`
//! (#2498) enqueued a DLQ row on a non-acking peer. The other 11
//! `broadcast_*_quorum` lanes emitted a lone `tracing::warn!` and then dropped
//! the failure — permanent, silent replica divergence, INCLUDING governance
//! (`namespace_meta`) and authority (`pending` / `pending_decision` /
//! checkpoint-resolution / action-transition) state that the anti-entropy
//! catch-up loop — which pulls MEMORY rows only — never reconciles.
//!
//! ## Coverage
//!
//! - one `*_lands_prefixed_dlq_row_2667` test per lane: a peer returning 500
//!   leaves exactly ONE pending row carrying the lane-PREFIXED DLQ key
//!   (`archive:{id}`, `link:{s}:{t}:{rel}`, `namespace_meta:{ns}`,
//!   `action_transition:{id}:{to}:{ts}`, …) and the verbatim subcollection
//!   body. The exact-key assertion is the load-bearing regression guard — a
//!   copy-paste that keyed the wrong lane, or reverted a prefix to a bare
//!   memory id, still lands exactly one row and would pass a count-only test.
//! - `namespace_meta_lane_replays_and_clears_2667` — a governance lane row is
//!   re-driven by `replay_once` once the peer recovers, and the `sync_push`
//!   200 (no `ids` echo) acks it (never a spurious `id_drift`).
//! - `consolidate_prefixed_key_replays_and_never_supersedes_2667` — the
//!   load-bearing prefix proof: a legacy-mode consolidate body carries
//!   `deletions[]`, so it is delete-shaped and the replay restore-race guard
//!   fires on the KEY. The `consolidate:` prefix makes the guard's live-memory
//!   lookup MISS, so the consolidation replays; a BARE `new_mem.id` key would
//!   trip the guard against the LIVE consolidated row (inserted here with a
//!   FUTURE `updated_at` so `restore_supersedes` returns true) and SUPERSEDE
//!   the replay — never re-POSTing.

#![cfg(feature = "sal")]

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use ai_memory::federation::push_dlq::{
    FederationDlqSink, FederationPushDlqRow, SqliteDlqSink, replay_once,
};
use ai_memory::federation::{
    ActionTransitionOp, FederationConfig, PeerEndpoint, broadcast_action_transition_quorum,
    broadcast_archive_quorum, broadcast_checkpoint_resolution_quorum, broadcast_consolidate_quorum,
    broadcast_link_quorum, broadcast_namespace_meta_clear_quorum, broadcast_namespace_meta_quorum,
    broadcast_pending_decision_quorum, broadcast_pending_quorum, broadcast_restore_quorum,
    broadcast_signal_create_quorum,
};
use ai_memory::models::action::ActionState;
use ai_memory::models::checkpoint::{CheckpointState, ConditionType};
use ai_memory::models::signal::{Signal, SignalType};
use ai_memory::models::{
    Checkpoint, ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink,
    MemoryLinkRelation, NamespaceMetaEntry, PendingAction, PendingDecision, Tier,
};
use ai_memory::replication::QuorumPolicy;

/// Peer is DOWN — every POST answers 500.
const MODE_FAIL: usize = 1;
/// Peer answers HTTP 200 with a clean apply report (used after recovery).
const MODE_OK: usize = 0;

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
        // A clean apply report with NO `ids` array — the shape every
        // sync_push receiver returns, so `post_once` acks (lens-2 killer:
        // a synthetic DLQ key can never mint a spurious `id_drift`).
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
        .prefix("v100-2667-lane-dlq-")
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
fn build_cfg(peer_url: &str, sink: Arc<dyn FederationDlqSink>) -> FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .expect("build reqwest client");
    FederationConfig {
        policy: QuorumPolicy::new(2, 2, Duration::from_secs(2), Duration::from_secs(30)).unwrap(),
        peers: vec![PeerEndpoint {
            id: "peer-down".to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: "ai:lane-dlq-2667".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: Some(sink),
    }
}

/// Stand up a single DOWN peer + a fresh sqlite DLQ sink + a W=N config.
async fn down_peer() -> (
    tempfile::TempDir,
    PeerState,
    Arc<dyn FederationDlqSink>,
    FederationConfig,
) {
    let peer = PeerState::with_mode(MODE_FAIL);
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db).await.unwrap());
    let cfg = build_cfg(&peer_url, sink.clone());
    (tmp, peer, sink, cfg)
}

/// Assert exactly one pending DLQ row exists, keyed by the EXACT lane-prefixed
/// `expected_key`, belonging to the down peer, carrying a non-empty failure
/// reason. Returns the row so the caller can assert its subcollection payload.
async fn assert_single_row(
    sink: &Arc<dyn FederationDlqSink>,
    expected_key: &str,
) -> FederationPushDlqRow {
    let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "#2667: a failed fanout must land exactly ONE DLQ row keyed {expected_key}; got {:?}",
        pending
            .iter()
            .map(|r| r.memory_id.clone())
            .collect::<Vec<_>>()
    );
    let row = pending.into_iter().next().unwrap();
    assert_eq!(
        row.memory_id, expected_key,
        "#2667: the DLQ key must be the lane-prefixed key (a bare-id or wrong-lane \
         regression still lands one row and would pass a count-only test)"
    );
    assert_eq!(row.peer_id, "peer-down");
    assert_eq!(row.attempt_count, 1);
    assert!(
        !row.last_error.is_empty(),
        "last_error MUST capture the peer's failure reason"
    );
    row
}

// --- fixtures (mirrors of the `src/federation/mod.rs` unit-test samples) ---

fn sample_memory() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: "fed-test".to_string(),
        tier: Tier::Mid,
        namespace: "app".to_string(),
        title: "hello".to_string(),
        content: "world for federation test".to_string(),
        tags: vec!["t".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id":"ai:test"}),
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
        lifecycle_state: LifecycleState::Open,
    }
}

fn sample_link() -> MemoryLink {
    MemoryLink {
        source_id: "mem-a".to_string(),
        target_id: "mem-b".to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

fn sample_pending() -> PendingAction {
    PendingAction {
        id: "pa-1".to_string(),
        action_type: "delete".to_string(),
        memory_id: Some("mem-x".to_string()),
        namespace: "app".to_string(),
        payload: serde_json::json!({}),
        requested_by: "ai:test".to_string(),
        requested_at: chrono::Utc::now().to_rfc3339(),
        status: "pending".to_string(),
        decided_by: None,
        decided_at: None,
        approvals: vec![],
    }
}

fn sample_decision() -> PendingDecision {
    PendingDecision {
        id: "pa-1".to_string(),
        approved: true,
        decider: "ai:approver".to_string(),
    }
}

fn sample_action_transition() -> ActionTransitionOp {
    ActionTransitionOp {
        action_id: "act-1".to_string(),
        from_state: ActionState::Pending,
        to_state: ActionState::Claimed,
        claimed_by: Some("ai:worker".to_string()),
        vector_clock: serde_json::json!({}),
        updated_at: 0,
        signature: Vec::new(),
        signer_pubkey: Vec::new(),
        nonce: Vec::new(),
    }
}

fn sample_checkpoint() -> Checkpoint {
    Checkpoint {
        id: "cp-1".to_string(),
        namespace: "_cp".to_string(),
        title: "needs approval".to_string(),
        condition_type: ConditionType::Approval,
        condition: serde_json::json!({}),
        state: CheckpointState::Pending,
        created_by: "agent-creator".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: None,
        metadata: serde_json::json!({}),
    }
}

fn sample_signal() -> Signal {
    Signal {
        id: "sig-1".to_string(),
        namespace: "app".to_string(),
        from_agent: "ai:sender".to_string(),
        to_agent: None,
        subject: "s".to_string(),
        body: serde_json::json!({}),
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: serde_json::json!([]),
        created_at: 0,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: vec![],
        sender_pubkey: vec![],
    }
}

fn sample_namespace_meta() -> NamespaceMetaEntry {
    NamespaceMetaEntry {
        namespace: "app/team".to_string(),
        standard_id: "mem-std-1".to_string(),
        parent_namespace: Some("app".to_string()),
        updated_at: chrono::Utc::now().to_rfc3339(),
    }
}

// --- per-lane "peer down -> exactly one prefixed DLQ row" tests ---

#[tokio::test]
async fn archive_lane_lands_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_archive_quorum(&cfg, "mem-arch").await.unwrap();
    let row = assert_single_row(&sink, "archive:mem-arch").await;
    assert_eq!(
        row.payload_json["archives"],
        serde_json::json!(["mem-arch"])
    );
}

#[tokio::test]
async fn restore_lane_lands_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_restore_quorum(&cfg, "mem-rest").await.unwrap();
    let row = assert_single_row(&sink, "restore:mem-rest").await;
    assert_eq!(
        row.payload_json["restores"],
        serde_json::json!(["mem-rest"])
    );
}

#[tokio::test]
async fn link_lane_lands_composite_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_link_quorum(&cfg, &sample_link()).await.unwrap();
    // Composite key includes the relation so two links between the same pair
    // with different relations do not collide (last-wins) in the DLQ.
    let row = assert_single_row(&sink, "link:mem-a:mem-b:related_to").await;
    assert_eq!(row.payload_json["links"][0]["source_id"], "mem-a");
    assert_eq!(row.payload_json["links"][0]["target_id"], "mem-b");
}

#[tokio::test]
async fn pending_lane_lands_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_pending_quorum(&cfg, &sample_pending())
        .await
        .unwrap();
    let row = assert_single_row(&sink, "pending:pa-1").await;
    assert_eq!(row.payload_json["pendings"][0]["id"], "pa-1");
}

#[tokio::test]
async fn pending_decision_lane_lands_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_pending_decision_quorum(&cfg, &sample_decision())
        .await
        .unwrap();
    let row = assert_single_row(&sink, "pending_decision:pa-1").await;
    assert_eq!(row.payload_json["pending_decisions"][0]["id"], "pa-1");
}

#[tokio::test]
async fn action_transition_lane_lands_per_transition_key_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_action_transition_quorum(&cfg, &sample_action_transition())
        .await
        .unwrap();
    // Per-transition key (action_id:to_state:updated_at) — a last-wins
    // action_id key would drop an intermediate CAS transition and strand a peer.
    let row = assert_single_row(&sink, "action_transition:act-1:claimed:0").await;
    assert_eq!(
        row.payload_json["action_transitions"][0]["action_id"],
        "act-1"
    );
}

#[tokio::test]
async fn checkpoint_resolution_lane_lands_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_checkpoint_resolution_quorum(&cfg, &sample_checkpoint())
        .await
        .unwrap();
    let row = assert_single_row(&sink, "checkpoint:cp-1").await;
    assert_eq!(row.payload_json["checkpoints"][0]["id"], "cp-1");
}

#[tokio::test]
async fn signal_create_lane_lands_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_signal_create_quorum(&cfg, &sample_signal())
        .await
        .unwrap();
    let row = assert_single_row(&sink, "signal:sig-1").await;
    assert_eq!(row.payload_json["signals"][0]["id"], "sig-1");
}

#[tokio::test]
async fn namespace_meta_lane_lands_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_namespace_meta_quorum(&cfg, &sample_namespace_meta())
        .await
        .unwrap();
    let row = assert_single_row(&sink, "namespace_meta:app/team").await;
    assert_eq!(
        row.payload_json["namespace_meta"][0]["namespace"],
        "app/team"
    );
}

#[tokio::test]
async fn namespace_meta_clear_lane_lands_prefixed_dlq_row_2667() {
    let (_tmp, _peer, sink, cfg) = down_peer().await;
    broadcast_namespace_meta_clear_quorum(&cfg, &["app/team".to_string(), "app/ops".to_string()])
        .await
        .unwrap();
    let row = assert_single_row(&sink, "namespace_meta_clear:app/team,app/ops").await;
    assert_eq!(
        row.payload_json["namespace_meta_clears"],
        serde_json::json!(["app/team", "app/ops"])
    );
}

// --- replay re-drive (governance lane) ---

#[tokio::test(flavor = "multi_thread")]
async fn namespace_meta_lane_replays_and_clears_2667() {
    let (_tmp, peer, sink, cfg) = down_peer().await;
    broadcast_namespace_meta_quorum(&cfg, &sample_namespace_meta())
        .await
        .unwrap();
    assert_eq!(sink.pending_dlq_count().await.unwrap(), 1);
    let hits_before = peer.hits();

    peer.set_mode(MODE_OK);
    replay_once(&cfg, sink.as_ref()).await;

    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        0,
        "the governance namespace_meta row must drain once the peer recovers"
    );
    assert_eq!(
        peer.hits(),
        hits_before + 1,
        "replay re-POSTs the namespace_meta body once — the 200 has no `ids` echo, \
         so it acks (never a spurious id_drift)"
    );
}

// --- the load-bearing prefix proof: consolidate must NOT self-supersede ---

#[tokio::test(flavor = "multi_thread")]
async fn consolidate_prefixed_key_replays_and_never_supersedes_2667() {
    let peer = PeerState::with_mode(MODE_FAIL);
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let (_tmp, db) = fresh_dlq_db();

    // Make the consolidated row LIVE with a FAR-FUTURE updated_at: under a bare
    // `new_mem.id` key the replay restore-race guard would find it live-and-
    // newer (`restore_supersedes(future, failed_at) == true`) and SUPERSEDE the
    // replay. The `consolidate:` prefix makes the guard's lookup miss.
    let mut new_mem = sample_memory();
    new_mem.id = "cons-new".to_string();
    new_mem.updated_at = "2099-01-01T00:00:00+00:00".to_string();
    {
        let guard = db.lock().await;
        ai_memory::storage::insert(&guard.0, &new_mem).expect("seed live consolidated row");
    }

    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());
    let cfg = build_cfg(&peer_url, sink.clone());

    // Legacy-mode consolidate: non-empty `deletions[]` makes the payload
    // delete-shaped, which is exactly what arms the replay restore-race guard.
    broadcast_consolidate_quorum(&cfg, &new_mem, &["src-1".to_string()], &[], &[])
        .await
        .unwrap();

    let row = assert_single_row(&sink, "consolidate:cons-new").await;
    assert!(
        row.payload_json["deletions"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "legacy consolidate carries a non-empty deletions[] (arms the guard)"
    );

    let hits_before = peer.hits();
    peer.set_mode(MODE_OK);
    replay_once(&cfg, sink.as_ref()).await;

    assert_eq!(
        sink.pending_dlq_count().await.unwrap(),
        0,
        "the consolidation must DRAIN (not be superseded) once the peer is healthy"
    );
    assert_eq!(
        peer.hits(),
        hits_before + 1,
        "#2667: replay MUST re-POST the consolidation — a bare-`new_mem.id` key \
         regression would supersede it against the live row and never re-POST"
    );
}

// --- postgres parity (both backends) ---

/// The landing pass is TRAIT dispatch through `FederationDlqSink`, so it is
/// backend-blind by construction. This drives a GOVERNANCE lane
/// (`broadcast_namespace_meta_quorum`) through `PostgresDlqSink` and asserts the
/// identical lane-prefixed row lands on the postgres sink. Ignored by default;
/// run against a SCRATCH database with `AI_MEMORY_TEST_POSTGRES_URL` set:
/// `cargo test --features sal-postgres --test federation_lane_dlq_2667 -- --ignored`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL pointing at a live scratch instance"]
async fn pg_namespace_meta_lane_dlq_parity_2667() {
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
    let peer_url = spawn_mock_peer(peer).await;
    let cfg = build_cfg(&peer_url, sink.clone());
    // Unique namespace so re-runs against a shared DB cannot collide.
    let ns = format!("pg-2667/{}", uuid::Uuid::new_v4());
    let entry = NamespaceMetaEntry {
        namespace: ns.clone(),
        standard_id: "mem-std-pg".to_string(),
        parent_namespace: None,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    broadcast_namespace_meta_quorum(&cfg, &entry).await.unwrap();

    let expected_key = format!("namespace_meta:{ns}");
    let pending = sink.take_pending_dlq_rows(256).await.expect("pg take");
    let row = pending
        .iter()
        .find(|r| r.memory_id == expected_key)
        .expect("#2667: the namespace_meta lane must land a DLQ row on the postgres sink too");
    assert_eq!(row.peer_id, "peer-down");
    assert!(!row.last_error.is_empty());
    assert_eq!(row.payload_json["namespace_meta"][0]["namespace"], ns);

    // Leave zero residue: clear the row we created.
    assert!(
        sink.mark_dlq_row_replayed(row.id, row.attempt_count)
            .await
            .expect("pg clear"),
        "the parity row must clear cleanly"
    );
}
