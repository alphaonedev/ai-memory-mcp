// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

//! Coverage backfill for `src/federation/sync.rs` fanout arms (post-76c650cc
//! boundary drift on the `federation/sync.rs` 86% floor).
//!
//! Drives the quorum broadcast variants against LIVE loopback mock peers so
//! the previously-unexercised arms run under behavioral assertions (never
//! test-theater — every case asserts an observable quorum verdict, DLQ row,
//! metric delta, wire header, or returned error):
//!
//! - `post_once` outbound headers: `X-Memory-Sig` + `X-Memory-Nonce`
//!   (signing-key branch), `x-api-key`, `x-peer-id`, `Idempotency-Key`.
//! - `post_once` 2xx-with-unparseable-body ⇒ still an Ack.
//! - `post_once` id-drift (`ids` array disagrees) ⇒ NOT an ack.
//! - `post_and_classify` retry-once recovering a transient 500.
//! - Per-variant `AckOutcome::Fail` warn arms (peer 500 at W=2 ⇒ quorum
//!   unmet) for delete / restore / consolidate / pending / pending-decision /
//!   action-transition / signal / checkpoint-resolution (FED-RQ-01 #1936) /
//!   namespace-meta / namespace-meta-clear.
//! - `broadcast_store_quorum*` #933 DLQ landing: explicit-failure reason,
//!   the `deadline_exceeded` fallback for deadline-evicted peers, and the
//!   sink-error non-fatal arm.
//! - The post-quorum detached drain (id-drift + peer-fail arms) via the
//!   `federation_fanout_dropped_total` metric deltas.
//! - `bulk_catchup_push`: header set (incl. `X-Catchup`), http-status error
//!   reporting, and network-error reporting.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use ed25519_dalek::SigningKey;

use ai_memory::federation::push_dlq::{FederationDlqSink, FederationPushDlqRow};
use ai_memory::federation::{FederationConfig, PeerEndpoint, ShippedEmbedding, sync};
use ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION;
use ai_memory::models::{Memory, MemoryKind, MemoryLinkRelation, Tier};
use ai_memory::replication::QuorumPolicy;

// ---------------------------------------------------------------------------
// Mock loopback peer
// ---------------------------------------------------------------------------

/// Response plan for a mock peer: given the 0-based hit index, return
/// `(status, body, delay_ms)`.
type Plan = dyn Fn(usize) -> (u16, String, u64) + Send + Sync;

#[derive(Clone)]
struct PeerState {
    hits: Arc<AtomicUsize>,
    headers: Arc<std::sync::Mutex<Vec<HeaderMap>>>,
    plan: Arc<Plan>,
}

async fn peer_handler(
    State(st): State<PeerState>,
    headers: HeaderMap,
    _body: String,
) -> impl IntoResponse {
    let n = st.hits.fetch_add(1, Ordering::SeqCst);
    st.headers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(headers);
    let (status, body, delay_ms) = (st.plan)(n);
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    (
        StatusCode::from_u16(status).expect("valid mock status"),
        body,
    )
}

/// Bind a real loopback HTTP peer serving `POST /api/v1/sync/push` per
/// `plan`. Returns the full sync-push URL + shared state for header /
/// hit-count assertions.
async fn spawn_peer<F>(plan: F) -> (String, PeerState)
where
    F: Fn(usize) -> (u16, String, u64) + Send + Sync + 'static,
{
    let st = PeerState {
        hits: Arc::new(AtomicUsize::new(0)),
        headers: Arc::new(std::sync::Mutex::new(Vec::new())),
        plan: Arc::new(plan),
    };
    let app = Router::new()
        .route("/api/v1/sync/push", post(peer_handler))
        .with_state(st.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback mock peer");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/api/v1/sync/push"), st)
}

fn peer(id: &str, url: &str) -> PeerEndpoint {
    PeerEndpoint {
        id: id.to_string(),
        sync_push_url: url.to_string(),
    }
}

/// An unreachable peer (closed loopback port 1) — connection refused fast.
fn dead_peer(id: &str) -> PeerEndpoint {
    PeerEndpoint {
        id: id.to_string(),
        sync_push_url: "http://127.0.0.1:1/api/v1/sync/push".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Config + fixtures
// ---------------------------------------------------------------------------

const SENDER: &str = "ai:cov-sync-arms-sender";

/// Coverage tests drive fanout against loopback mock peers without
/// `bootstrap_serve`. `check_governed` (daemon-only) refuses when the
/// hook is unset, so the HTTP fail/ack arms never run. Install an
/// Allow-all hook once per process — first-writer-wins, same shape as
/// `tests/governance_wire_points.rs`.
fn install_allow_pre_action_hook() {
    let _ = GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
}

fn config(peers: Vec<PeerEndpoint>, w: usize, ack_timeout_ms: u64) -> FederationConfig {
    install_allow_pre_action_hook();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    FederationConfig {
        policy: QuorumPolicy::new(
            std::cmp::max(w, peers.len() + 1),
            w,
            Duration::from_millis(ack_timeout_ms),
            Duration::from_secs(30),
        )
        .expect("valid quorum policy"),
        peers,
        client,
        sender_agent_id: SENDER.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

fn fixture_memory(id: &str) -> Memory {
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: "cov-sync-arms".to_string(),
        title: format!("sync-arms fixture {id}"),
        content: "coverage fixture body for the federation sync fanout arms".to_string(),
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: "2026-07-10T00:00:00+00:00".to_string(),
        updated_at: "2026-07-10T00:00:00+00:00".to_string(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    }
}

fn fixture_link() -> ai_memory::models::MemoryLink {
    ai_memory::models::MemoryLink {
        source_id: "cov-sync-src".to_string(),
        target_id: "cov-sync-dst".to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: "2026-07-10T00:00:00+00:00".to_string(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

fn fixture_signal() -> ai_memory::models::signal::Signal {
    ai_memory::models::signal::Signal {
        id: "cov-sync-signal-1".to_string(),
        namespace: "cov-sync-arms".to_string(),
        from_agent: SENDER.to_string(),
        to_agent: None,
        subject: "cov".to_string(),
        body: serde_json::json!({}),
        signal_type: ai_memory::models::signal::SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: serde_json::json!([]),
        created_at: 1_700_000_000,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    }
}

fn fixture_pending() -> ai_memory::models::PendingAction {
    ai_memory::models::PendingAction {
        id: "cov-sync-pending-1".to_string(),
        action_type: "store".to_string(),
        memory_id: None,
        namespace: "cov-sync-arms".to_string(),
        payload: serde_json::json!({}),
        requested_by: SENDER.to_string(),
        requested_at: "2026-07-10T00:00:00+00:00".to_string(),
        status: "pending".to_string(),
        decided_by: None,
        decided_at: None,
        approvals: Vec::new(),
    }
}

fn fixture_decision() -> ai_memory::models::PendingDecision {
    ai_memory::models::PendingDecision {
        id: "cov-sync-pending-1".to_string(),
        approved: true,
        decider: SENDER.to_string(),
    }
}

fn fixture_meta() -> ai_memory::models::NamespaceMetaEntry {
    ai_memory::models::NamespaceMetaEntry {
        namespace: "cov-sync-arms".to_string(),
        standard_id: "std-1".to_string(),
        parent_namespace: None,
        updated_at: "2026-07-10T00:00:00+00:00".to_string(),
    }
}

fn fixture_transition() -> sync::ActionTransitionOp {
    sync::ActionTransitionOp {
        action_id: "cov-sync-action-1".to_string(),
        from_state: ai_memory::models::action::ActionState::Pending,
        to_state: ai_memory::models::action::ActionState::Claimed,
        claimed_by: Some(SENDER.to_string()),
        vector_clock: serde_json::json!({}),
        updated_at: 1_700_000_000,
        signature: Vec::new(),
        signer_pubkey: Vec::new(),
        nonce: Vec::new(),
    }
}

/// FED-RQ-01 (#1936) — a resolved commit-checkpoint for the outbound
/// `broadcast_checkpoint_resolution_quorum` fanout arm.
fn fixture_checkpoint() -> ai_memory::models::Checkpoint {
    ai_memory::models::Checkpoint {
        id: "cov-sync-checkpoint-1".to_string(),
        namespace: "_epoch".to_string(),
        title: "epoch advance 7".to_string(),
        condition_type: ai_memory::models::ConditionType::EpochAdvance,
        condition: serde_json::Value::Null,
        state: ai_memory::models::CheckpointState::Resolved,
        created_by: SENDER.to_string(),
        resolved_by: Some(SENDER.to_string()),
        resolution: Some("deadbeef".to_string()),
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: Some(1_700_000_900),
        metadata: serde_json::Value::Null,
    }
}

/// A 200-`{}` acking plan (no per-memory `ids` echo ⇒ unconditional ack).
fn ok_plan() -> impl Fn(usize) -> (u16, String, u64) + Send + Sync + 'static {
    |_| (200, "{}".to_string(), 0)
}

/// A 500 plan — `post_and_classify` retries once then reports `Fail`.
fn err_plan() -> impl Fn(usize) -> (u16, String, u64) + Send + Sync + 'static {
    |_| (500, "{\"error\":\"boom\"}".to_string(), 0)
}

// ---------------------------------------------------------------------------
// Recording / failing DLQ sinks (#933 landing pass)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RecordingDlqSink {
    rows: std::sync::Mutex<Vec<(String, String, String)>>,
    fail_enqueue: bool,
}

#[async_trait::async_trait]
impl FederationDlqSink for RecordingDlqSink {
    async fn enqueue_push_failure(
        &self,
        memory_id: &str,
        peer_id: &str,
        _payload_json: &serde_json::Value,
        last_error: &str,
    ) -> Result<(), String> {
        if self.fail_enqueue {
            return Err("sink deliberately failing for coverage".to_string());
        }
        self.rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((
                memory_id.to_string(),
                peer_id.to_string(),
                last_error.to_string(),
            ));
        Ok(())
    }

    async fn take_pending_dlq_rows(
        &self,
        _limit: usize,
    ) -> Result<Vec<FederationPushDlqRow>, String> {
        Ok(Vec::new())
    }

    async fn mark_dlq_row_replayed(
        &self,
        _id: i64,
        _expected_attempt_count: i32,
    ) -> Result<bool, String> {
        Ok(true)
    }

    async fn bump_dlq_attempt(&self, _id: i64, _last_error: &str) -> Result<(), String> {
        Ok(())
    }

    async fn pending_dlq_count(&self) -> Result<i64, String> {
        Ok(0)
    }

    async fn note_dlq_throttled(&self, _id: i64, _last_error: &str) -> Result<(), String> {
        Ok(())
    }

    async fn reset_throttled_quarantine(&self) -> Result<u64, String> {
        Ok(0)
    }

    /// #2446 — never exercised by this harness (it drives the store-lane
    /// landing pass, which never queues an erasure sentinel). `Contended`
    /// is the no-op-and-retry outcome, so a stub can never silently claim
    /// a fan-out that did not happen.
    async fn expand_erasure_sentinel(
        &self,
        _row_id: i64,
        _expected_attempt_count: i32,
        _memory_id: &str,
        _peer_ids: &[String],
        _per_peer_payload: &serde_json::Value,
        _per_peer_last_error: &str,
    ) -> Result<ai_memory::federation::SentinelExpansion, String> {
        Ok(ai_memory::federation::SentinelExpansion::Contended)
    }

    // #2716 — this harness drives the store-lane landing pass and never a
    // delete/erasure, so the restore-race guard is never consulted.
    async fn erasure_delete_superseded_by_restore(
        &self,
        _memory_id: &str,
        _erasure_failed_at: &str,
    ) -> Result<bool, String> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// post_once wire-shape + classification arms (store fanout carrier)
// ---------------------------------------------------------------------------

/// W=2 with a signing key + api key: quorum is only met when the mock peer's
/// ack lands, and the peer must have received the full outbound header set —
/// `X-Memory-Sig`, `X-Memory-Nonce`, `x-api-key`, `x-peer-id`, and the
/// `Idempotency-Key` (= memory id).
#[tokio::test]
async fn store_fanout_signed_w2_attaches_full_header_set() {
    let (url, st) = spawn_peer(ok_plan()).await;
    let mut cfg = config(vec![peer("peer-signed", &url)], 2, 2_000);
    cfg.api_key = Some("cov-sync-api-key".to_string());
    cfg.signing_key = Some(Arc::new(SigningKey::from_bytes(&[7u8; 32])));

    let mem = fixture_memory("mem-signed-w2");
    let tracker = sync::broadcast_store_quorum(&cfg, &mem)
        .await
        .expect("store quorum tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_ok(),
        "peer ack must satisfy W=2"
    );

    let headers = st
        .headers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let h = headers.first().expect("peer received one POST");
    assert!(
        h.get(ai_memory::federation::signing::SIGNATURE_HEADER)
            .is_some(),
        "signing-key branch must attach the signature header"
    );
    assert!(
        h.get(ai_memory::federation::signing::NONCE_HEADER)
            .is_some(),
        "signing-key branch must attach the nonce header"
    );
    assert_eq!(
        h.get(ai_memory::HEADER_API_KEY)
            .and_then(|v| v.to_str().ok()),
        Some("cov-sync-api-key"),
        "configured api key must be forwarded"
    );
    assert_eq!(
        h.get(ai_memory::federation::peer_attestation::PEER_ID_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some(SENDER),
        "x-peer-id must carry the body's sender_agent_id"
    );
    assert_eq!(
        h.get("Idempotency-Key").and_then(|v| v.to_str().ok()),
        Some("mem-signed-w2"),
        "idempotency key must be the memory id"
    );
}

/// A 2xx response whose body is not JSON still counts as an ack (the
/// `Err(_) => Ack` arm): W=2 quorum must be met by that peer.
#[tokio::test]
async fn store_fanout_2xx_unparseable_body_still_acks() {
    let (url, _st) = spawn_peer(|_| (200, "definitely-not-json{{".to_string(), 0)).await;
    let cfg = config(vec![peer("peer-notjson", &url)], 2, 2_000);
    let mem = fixture_memory("mem-notjson");
    let tracker = sync::broadcast_store_quorum(&cfg, &mem)
        .await
        .expect("store quorum tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_ok(),
        "2xx with unparseable body must count as an ack"
    );
}

/// A 2xx whose `ids` array disagrees with the pushed id is id-drift, NOT an
/// ack: W=2 quorum must fail.
#[tokio::test]
async fn store_fanout_id_drift_does_not_count_toward_quorum() {
    let (url, _st) = spawn_peer(|_| (200, "{\"ids\":[\"some-other-id\"]}".to_string(), 0)).await;
    let cfg = config(vec![peer("peer-drift", &url)], 2, 900);
    let mem = fixture_memory("mem-drift");
    let tracker = sync::broadcast_store_quorum(&cfg, &mem)
        .await
        .expect("store quorum tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_err(),
        "id-drift must not satisfy quorum"
    );
}

/// `post_and_classify` retry-once: first attempt 500, retry 200 ⇒ the peer
/// ack lands and W=2 quorum is met (the retry-success arm).
#[tokio::test]
async fn store_fanout_retry_recovers_transient_500() {
    let (url, st) = spawn_peer(|n| {
        if n == 0 {
            (500, "{\"error\":\"transient\"}".to_string(), 0)
        } else {
            (200, "{}".to_string(), 0)
        }
    })
    .await;
    let cfg = config(vec![peer("peer-flaky", &url)], 2, 3_000);
    let mem = fixture_memory("mem-flaky");
    let tracker = sync::broadcast_store_quorum(&cfg, &mem)
        .await
        .expect("store quorum tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_ok(),
        "retry must recover the transient 500 and meet W=2"
    );
    assert_eq!(
        st.hits.load(Ordering::SeqCst),
        2,
        "exactly one retry after the transient failure"
    );
}

/// The `shipped` embedding rides inside the signed body
/// (`broadcast_store_quorum_with_embedding` Some-branch) and the peer still
/// acks at W=2.
#[tokio::test]
async fn store_fanout_with_shipped_embedding_meets_w2() {
    let (url, _st) = spawn_peer(ok_plan()).await;
    let cfg = config(vec![peer("peer-embed", &url)], 2, 2_000);
    let mem = fixture_memory("mem-embed");
    let shipped = ShippedEmbedding {
        memory_id: mem.id.clone(),
        model: "cov-test-embedder".to_string(),
        dim: 3,
        vector: vec![0.1, 0.2, 0.3],
    };
    let tracker = sync::broadcast_store_quorum_with_embedding(&cfg, &mem, Some(&shipped))
        .await
        .expect("store quorum tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

// ---------------------------------------------------------------------------
// #933 DLQ landing pass (store fanout)
// ---------------------------------------------------------------------------

/// A peer that answers 500 twice (attempt + retry) at W=2: quorum is unmet
/// AND the DLQ sink receives exactly one row carrying the explicit
/// `http 500`-class failure reason.
#[tokio::test]
async fn store_fanout_peer_500_lands_dlq_row_with_http_reason() {
    let (url, _st) = spawn_peer(err_plan()).await;
    let sink = Arc::new(RecordingDlqSink::default());
    let mut cfg = config(vec![peer("peer-500", &url)], 2, 2_000);
    cfg.dlq_sink = Some(sink.clone());

    let mem = fixture_memory("mem-dlq-500");
    let tracker = sync::broadcast_store_quorum(&cfg, &mem)
        .await
        .expect("store quorum tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_err(),
        "500 peer must not satisfy W=2"
    );

    let rows = sink
        .rows
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(rows.len(), 1, "exactly one DLQ row for the failing peer");
    assert_eq!(rows[0].0, "mem-dlq-500");
    assert_eq!(rows[0].1, "peer-500");
    assert!(
        rows[0].2.contains("http 500"),
        "DLQ reason must carry the explicit http failure; got: {}",
        rows[0].2
    );
}

/// A peer that hangs past the ack deadline at W=1: quorum is met by the
/// local commit, the partial-quorum WARN path runs, and the DLQ row lands
/// with the `deadline_exceeded` fallback reason (no explicit outcome was
/// ever observed for the peer).
#[tokio::test]
async fn store_fanout_deadline_evicted_peer_lands_deadline_exceeded_dlq() {
    let (url, _st) = spawn_peer(|_| (200, "{}".to_string(), 3_000)).await;
    let sink = Arc::new(RecordingDlqSink::default());
    let mut cfg = config(vec![peer("peer-hang", &url)], 1, 200);
    cfg.dlq_sink = Some(sink.clone());

    let mem = fixture_memory("mem-dlq-deadline");
    let tracker = sync::broadcast_store_quorum(&cfg, &mem)
        .await
        .expect("store quorum tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_ok(),
        "local commit meets W=1"
    );

    let rows = sink
        .rows
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(rows.len(), 1, "hanging peer must land one DLQ row");
    assert_eq!(rows[0].1, "peer-hang");
    assert_eq!(
        rows[0].2, "deadline_exceeded",
        "deadline-evicted peers use the fallback reason"
    );
}

/// A sink that errors on enqueue is non-fatal: the broadcast still returns
/// its tracker and the quorum verdict is unaffected.
#[tokio::test]
async fn store_fanout_dlq_sink_error_is_nonfatal() {
    let sink = Arc::new(RecordingDlqSink {
        rows: std::sync::Mutex::new(Vec::new()),
        fail_enqueue: true,
    });
    let mut cfg = config(vec![dead_peer("peer-dead-sinkerr")], 1, 900);
    cfg.dlq_sink = Some(sink);

    let mem = fixture_memory("mem-dlq-sinkerr");
    let tracker = sync::broadcast_store_quorum(&cfg, &mem)
        .await
        .expect("sink error must not fail the broadcast");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_ok(),
        "local commit meets W=1 despite the sink error"
    );
}

// ---------------------------------------------------------------------------
// Post-quorum detached drain (store fanout) — metric-asserted
// ---------------------------------------------------------------------------

/// W=1 with one instant-ack peer plus one delayed id-drift peer and one
/// delayed 500 peer: the broadcast returns as soon as quorum is met (the
/// stragglers are DETACHED, not awaited), and the detached drain later
/// classifies the straggler outcomes into the
/// `federation_fanout_dropped_total{id_drift|peer_fail}` counters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_fanout_post_quorum_drain_classifies_stragglers_via_metrics() {
    let metrics = ai_memory::metrics::registry();
    let drift_before = metrics
        .federation_fanout_dropped_total
        .with_label_values(&["id_drift"])
        .get();
    let fail_before = metrics
        .federation_fanout_dropped_total
        .with_label_values(&["peer_fail"])
        .get();

    let (ok_url, _ok_st) = spawn_peer(ok_plan()).await;
    let (drift_url, _drift_st) =
        spawn_peer(|_| (200, "{\"ids\":[\"who-is-this\"]}".to_string(), 400)).await;
    let (err_url, _err_st) = spawn_peer(|_| (500, "{}".to_string(), 400)).await;
    let cfg = config(
        vec![
            peer("peer-ok", &ok_url),
            peer("peer-slow-drift", &drift_url),
            peer("peer-slow-500", &err_url),
        ],
        1,
        5_000,
    );

    let mem = fixture_memory("mem-drain");
    let started = std::time::Instant::now();
    let tracker = sync::broadcast_store_quorum(&cfg, &mem)
        .await
        .expect("store quorum tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
    assert!(
        started.elapsed() < Duration::from_millis(350),
        "stragglers must be detached, not awaited (elapsed {:?})",
        started.elapsed()
    );

    // Let the detached drain observe both stragglers (the 500 peer pays the
    // 250ms retry backoff on top of its 400ms delay).
    tokio::time::sleep(Duration::from_millis(1_800)).await;

    let drift_after = metrics
        .federation_fanout_dropped_total
        .with_label_values(&["id_drift"])
        .get();
    let fail_after = metrics
        .federation_fanout_dropped_total
        .with_label_values(&["peer_fail"])
        .get();
    assert!(
        drift_after > drift_before,
        "post-quorum id-drift straggler must increment the id_drift counter"
    );
    assert!(
        fail_after > fail_before,
        "post-quorum failing straggler must increment the peer_fail counter"
    );
}

// ---------------------------------------------------------------------------
// Per-variant Fail/Ack arms: peer 500 at W=2 ⇒ quorum unmet; peer 200 ⇒ met.
// ---------------------------------------------------------------------------

/// Assert the shared behavioral contract of a broadcast variant: an acking
/// peer satisfies W=2, a 500 peer does not. The `$cfg` identifier is bound
/// twice (ack config, then 500 config) and `$call` is evaluated inline
/// against each binding — avoids closure-captured-borrow lifetime issues
/// with the async broadcast futures.
macro_rules! assert_variant_quorum_arms {
    (|$cfg:ident| $call:expr) => {{
        let (ok_url, _s1) = spawn_peer(ok_plan()).await;
        let $cfg = config(vec![peer("peer-var-ok", &ok_url)], 2, 2_000);
        let t_ok = $call.await.expect("variant tracker (ack peer)");
        assert!(
            t_ok.finalise(std::time::Instant::now()).is_ok(),
            "acking peer must satisfy W=2"
        );

        let (err_url, _s2) = spawn_peer(err_plan()).await;
        let $cfg = config(vec![peer("peer-var-500", &err_url)], 2, 2_000);
        let t_err = $call.await.expect("variant tracker (500 peer)");
        assert!(
            t_err.finalise(std::time::Instant::now()).is_err(),
            "a 500 peer must leave W=2 unmet"
        );
    }};
}

#[tokio::test]
async fn delete_quorum_ack_and_fail_arms() {
    assert_variant_quorum_arms!(|cfg| sync::broadcast_delete_quorum(&cfg, "del-var-1"));
}

#[tokio::test]
async fn restore_quorum_ack_and_fail_arms() {
    assert_variant_quorum_arms!(|cfg| sync::broadcast_restore_quorum(&cfg, "restore-var-1"));
}

#[tokio::test]
async fn consolidate_quorum_ack_and_fail_arms() {
    let mem = fixture_memory("consol-var-1");
    let sources = vec!["src-1".to_string(), "src-2".to_string()];
    assert_variant_quorum_arms!(|cfg| sync::broadcast_consolidate_quorum(
        &cfg,
        &mem,
        &sources,
        &[],
        &[]
    ));
}

#[tokio::test]
async fn link_quorum_ack_and_fail_arms() {
    let link = fixture_link();
    assert_variant_quorum_arms!(|cfg| sync::broadcast_link_quorum(&cfg, &link));
}

#[tokio::test]
async fn archive_quorum_ack_and_fail_arms() {
    assert_variant_quorum_arms!(|cfg| sync::broadcast_archive_quorum(&cfg, "arch-var-1"));
}

#[tokio::test]
async fn pending_quorum_ack_and_fail_arms() {
    let pending = fixture_pending();
    assert_variant_quorum_arms!(|cfg| sync::broadcast_pending_quorum(&cfg, &pending));
}

#[tokio::test]
async fn pending_decision_quorum_ack_and_fail_arms() {
    let decision = fixture_decision();
    assert_variant_quorum_arms!(|cfg| sync::broadcast_pending_decision_quorum(&cfg, &decision));
}

#[tokio::test]
async fn action_transition_quorum_ack_and_fail_arms() {
    let op = fixture_transition();
    assert_variant_quorum_arms!(|cfg| sync::broadcast_action_transition_quorum(&cfg, &op));
}

#[tokio::test]
async fn signal_create_quorum_ack_and_fail_arms() {
    let signal = fixture_signal();
    assert_variant_quorum_arms!(|cfg| sync::broadcast_signal_create_quorum(&cfg, &signal));
}

#[tokio::test]
async fn checkpoint_resolution_quorum_ack_and_fail_arms() {
    // FED-RQ-01 (#1936) — the checkpoint-resolution fanout arm satisfies the
    // same W-of-N quorum contract as every sibling broadcast variant.
    let cp = fixture_checkpoint();
    assert_variant_quorum_arms!(|cfg| sync::broadcast_checkpoint_resolution_quorum(&cfg, &cp));
}

#[tokio::test]
async fn namespace_meta_quorum_ack_and_fail_arms() {
    let entry = fixture_meta();
    assert_variant_quorum_arms!(|cfg| sync::broadcast_namespace_meta_quorum(&cfg, &entry));
}

#[tokio::test]
async fn namespace_meta_clear_quorum_ack_and_fail_arms() {
    let namespaces = vec!["cov-sync-arms".to_string()];
    assert_variant_quorum_arms!(|cfg| sync::broadcast_namespace_meta_clear_quorum(
        &cfg,
        &namespaces
    ));
}

// ---------------------------------------------------------------------------
// bulk_catchup_push
// ---------------------------------------------------------------------------

/// Happy path with signing + api key: no errors reported, and the catchup
/// POST carries `X-Catchup: bulk` plus the signature / nonce / api-key /
/// peer-id headers.
#[tokio::test]
async fn bulk_catchup_ok_attaches_catchup_header_set() {
    let (url, st) = spawn_peer(ok_plan()).await;
    let mut cfg = config(vec![peer("peer-catchup", &url)], 1, 2_000);
    cfg.api_key = Some("cov-catchup-api-key".to_string());
    cfg.signing_key = Some(Arc::new(SigningKey::from_bytes(&[9u8; 32])));

    let memories = vec![
        fixture_memory("mem-catchup-1"),
        fixture_memory("mem-catchup-2"),
    ];
    let errors = sync::bulk_catchup_push(&cfg, &memories).await;
    assert!(
        errors.is_empty(),
        "successful catchup reports no errors: {errors:?}"
    );

    let headers = st
        .headers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let h = headers.first().expect("peer received the catchup POST");
    assert_eq!(
        h.get("X-Catchup").and_then(|v| v.to_str().ok()),
        Some("bulk"),
        "catchup batches are marked X-Catchup: bulk"
    );
    assert!(
        h.get(ai_memory::federation::signing::SIGNATURE_HEADER)
            .is_some()
    );
    assert!(
        h.get(ai_memory::federation::signing::NONCE_HEADER)
            .is_some()
    );
    assert_eq!(
        h.get(ai_memory::HEADER_API_KEY)
            .and_then(|v| v.to_str().ok()),
        Some("cov-catchup-api-key")
    );
    assert_eq!(
        h.get(ai_memory::federation::peer_attestation::PEER_ID_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some(SENDER)
    );
}

/// A peer answering 500 lands in the returned error map with the http
/// status reason.
#[tokio::test]
async fn bulk_catchup_500_reports_http_error() {
    let (url, _st) = spawn_peer(err_plan()).await;
    let cfg = config(vec![peer("peer-catchup-500", &url)], 1, 2_000);
    let memories = vec![fixture_memory("mem-catchup-500")];
    let errors = sync::bulk_catchup_push(&cfg, &memories).await;
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, "peer-catchup-500");
    assert!(
        errors[0].1.contains("http 500"),
        "error must carry the http status; got: {}",
        errors[0].1
    );
}

/// An unreachable peer lands in the error map with a network-class reason.
#[tokio::test]
async fn bulk_catchup_unreachable_reports_network_error() {
    let cfg = config(vec![dead_peer("peer-catchup-dead")], 1, 2_000);
    let memories = vec![fixture_memory("mem-catchup-dead")];
    let errors = sync::bulk_catchup_push(&cfg, &memories).await;
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, "peer-catchup-dead");
    assert!(
        !errors[0].1.is_empty(),
        "network failure must carry a reason"
    );
}

/// Empty inputs short-circuit with no wire traffic and no errors.
#[tokio::test]
async fn bulk_catchup_empty_inputs_are_noops() {
    let cfg_no_peers = config(Vec::new(), 1, 500);
    assert!(
        sync::bulk_catchup_push(&cfg_no_peers, &[fixture_memory("mem-x")])
            .await
            .is_empty()
    );
    let (url, st) = spawn_peer(ok_plan()).await;
    let cfg = config(vec![peer("peer-noop", &url)], 1, 500);
    assert!(sync::bulk_catchup_push(&cfg, &[]).await.is_empty());
    assert_eq!(
        st.hits.load(Ordering::SeqCst),
        0,
        "no POST for an empty batch"
    );
}
