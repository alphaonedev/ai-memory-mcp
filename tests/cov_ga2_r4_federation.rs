// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage agent GA round-4 — third-pass federation backfill driving the
//! `broadcast_*_quorum` fan-out variants, the `bulk_catchup_push` batch path,
//! the `cli::schema_init` live-Postgres dim-migration arm, and the
//! `federation_signing_check::sync_push_via_store` batch-cap + per-agent
//! quota-refusal arms that the first two GA waves
//! (`tests/cov_ga2_federation.rs`, `tests/cov_ga2_pg_adapter2.rs`,
//! `tests/cov_ga2_pg_federation.rs`) deliberately left dark.
//!
//! Targets, by source module:
//!
//! - **`src/federation/sync.rs`** — the prior wave
//!   (`cov_ga2_pg_adapter2.rs`) covered the live-peer
//!   [`AckOutcome::Ack`] / [`AckOutcome::IdDrift`] arms of only
//!   `broadcast_{archive,delete,link,consolidate}_quorum`. This suite
//!   copies the same loopback [`tokio::net::TcpListener`] mock-peer
//!   harness and covers the REMAINING fan-out variants end-to-end:
//!   `broadcast_store_quorum_with_embedding` (both the shipped-vector
//!   body branch AND the partial-quorum WARN path), `broadcast_restore_quorum`,
//!   `broadcast_pending_quorum`, `broadcast_pending_decision_quorum`,
//!   `broadcast_namespace_meta_quorum`, `broadcast_namespace_meta_clear_quorum`,
//!   and `bulk_catchup_push` (success + per-peer error arms). It also drives
//!   the `AckOutcome::Fail` http-status-error classifier + the
//!   `post_and_classify` retry path via a peer that replies `500`.
//! - **`src/handlers/federation_signing_check.rs`** — drives a REAL
//!   [`PostgresStore`]-backed `build_router` through `tower::oneshot`
//!   (same fixture as `cov_ga2_pg_federation.rs`) to reach the
//!   `sync_push_via_store` arms the prior wave skipped: the
//!   batch-size-cap `400` refusal, and the per-agent quota-refusal `429`
//!   short-circuit (a pre-seeded `agent_quotas` row with
//!   `max_memories_per_day = 0` trips `QuotaError::Quota`, exercising the
//!   quota WARN, the signed-event emit, and the `429` envelope).
//! - **`src/cli/schema_init.rs`** — the live-Postgres `embedding_dim`
//!   in-place conversion arm (`init_and_enumerate_postgres` →
//!   `migrate_embedding_dim` returning `true`) + the AGE-bootstrap branch
//!   when the `age` extension is present, via the public
//!   [`ai_memory::cli::schema_init::run`] entry-point.
//!
//! Postgres-dependent tests are gated on `AI_MEMORY_TEST_POSTGRES_URL` and
//! skip cleanly when unset. The pure-loopback `broadcast_*` tests need no
//! Postgres and always run. Every id / namespace / peer-id is
//! uuid-randomised so the suite is rerunnable against a shared persistent
//! DB; assertions filter by the suite's own ids and NEVER assert
//! global-table emptiness. Env-mutating Postgres tests serialise on a
//! file-local `FED_ENV_LOCK`.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{
    ConfidenceSource, Memory, MemoryKind, NamespaceMetaEntry, PendingAction, PendingDecision, Tier,
};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

// ───────────────────────────────────────────────────────────────────
// Shared fixtures
// ───────────────────────────────────────────────────────────────────

/// Serialises the Postgres router tests that touch the process-global
/// federation env (none here flip env, but the quota-defaults OnceLock +
/// the shared scratch DB connection are best kept off the parallel path).
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn mem(id: &str, ns: &str, title: &str, content: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["covtest".to_string(), "ga2-r4".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "ga2-r4".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
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
    }
}

// ===================================================================
// federation::sync — loopback mock-peer harness (copied from
// cov_ga2_pg_adapter2.rs) + the REMAINING broadcast fan-out variants.
// ===================================================================

/// A loopback mock peer that accepts a bounded number of HTTP requests,
/// drains each request body, and replies with a canned status + JSON body.
/// Returns the bound `127.0.0.1:<port>/api/v1/sync/push` URL once up. The
/// accept loop runs detached on the tokio runtime.
async fn spawn_mock_peer(status_line: &'static str, body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock peer");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let status_line = status_line.to_string();
            let body = body.to_string();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    format!("http://{addr}/api/v1/sync/push")
}

/// W=2 quorum config: local commit alone does NOT meet quorum, so a peer
/// ack is REQUIRED to satisfy it.
fn quorum_config_w2(
    peers: Vec<ai_memory::federation::PeerEndpoint>,
) -> ai_memory::federation::FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    ai_memory::federation::FederationConfig {
        policy: ai_memory::replication::QuorumPolicy::new(
            2,
            2,
            Duration::from_secs(2),
            Duration::from_secs(30),
        )
        .unwrap(),
        peers,
        client,
        sender_agent_id: "ai:ga2-r4-sender".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

fn peer(id: &str, url: String) -> ai_memory::federation::PeerEndpoint {
    ai_memory::federation::PeerEndpoint {
        id: id.to_string(),
        sync_push_url: url,
    }
}

fn r4_memory(id: &str) -> Memory {
    mem(
        id,
        "ga2-r4-fed-ns",
        "ga2 r4 fed mem",
        "fed body",
        "ai:ga2-r4-sender",
    )
}

// --- broadcast_store_quorum_with_embedding ----------------------------

#[tokio::test]
async fn broadcast_store_with_embedding_ships_vector_and_meets_quorum() {
    // A `Some(shipped)` vector drives the conditional `body[EMBEDDINGS] = …`
    // insertion branch; a 200 + `{}` peer acks → quorum met (local + 1 == W=2).
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-emb-ack", url)]);
    let m = r4_memory("store-emb-ack");
    let shipped = ai_memory::federation::ShippedEmbedding {
        memory_id: m.id.clone(),
        model: "nomic-embed-text-v1.5".to_string(),
        dim: 4,
        vector: vec![0.5_f32, 0.5, 0.5, 0.5],
    };
    let tracker = ai_memory::federation::sync::broadcast_store_quorum_with_embedding(
        &cfg,
        &m,
        Some(&shipped),
    )
    .await
    .expect("store-with-embedding quorum returns tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_ok(),
        "local + acking peer meet W=2 quorum on the embedding-bearing push"
    );
}

#[tokio::test]
async fn broadcast_store_no_embedding_meets_quorum_plain_body() {
    // `None` shipped → the no-embeddings-key body shape (pre-#1566 bytes).
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-plain-ack", url)]);
    let m = r4_memory("store-plain-ack");
    let tracker = ai_memory::federation::sync::broadcast_store_quorum(&cfg, &m)
        .await
        .expect("plain store quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_store_partial_quorum_warns_when_one_of_two_peers_silent() {
    // W=2, two peers: one acks (200), one fails (500 → AckOutcome::Fail).
    // local + acking-peer == W=2 → quorum MET, but the failing peer never
    // ack-ed → the partial-quorum WARN + configured∖acked subtraction path
    // (sync.rs:520-541) fires. finalise() still succeeds.
    let ack_url = spawn_mock_peer("200 OK", "{}").await;
    let fail_url = spawn_mock_peer("500 Internal Server Error", "{\"error\":\"boom\"}").await;
    let cfg = quorum_config_w2(vec![
        peer("peer-ack-of-two", ack_url),
        peer("peer-fail-of-two", fail_url),
    ]);
    let m = r4_memory("store-partial");
    let tracker = ai_memory::federation::sync::broadcast_store_quorum(&cfg, &m)
        .await
        .expect("partial-quorum store returns tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_ok(),
        "local + one acking peer meet W=2 even though the other peer 500s"
    );
}

// --- broadcast_restore_quorum -----------------------------------------

#[tokio::test]
async fn broadcast_restore_quorum_peer_ack_meets_quorum() {
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-restore-ack", url)]);
    let tracker = ai_memory::federation::sync::broadcast_restore_quorum(&cfg, "restore-ack")
        .await
        .expect("restore quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_restore_quorum_id_drift_does_not_meet_quorum() {
    let url = spawn_mock_peer("200 OK", "{\"ids\":[\"some-other-id\"]}").await;
    let cfg = quorum_config_w2(vec![peer("peer-restore-drift", url)]);
    let tracker = ai_memory::federation::sync::broadcast_restore_quorum(&cfg, "restore-drift")
        .await
        .expect("restore quorum returns tracker on id-drift");
    assert!(matches!(
        tracker.finalise(std::time::Instant::now()),
        Err(ai_memory::replication::QuorumError::QuorumNotMet { .. })
    ));
}

// --- broadcast_pending_quorum -----------------------------------------

fn pending_action(id: &str) -> PendingAction {
    PendingAction {
        id: id.to_string(),
        action_type: "store".to_string(),
        memory_id: None,
        namespace: "ga2-r4-fed-ns".to_string(),
        payload: json!({"title": "pending"}),
        requested_by: "ai:ga2-r4-sender".to_string(),
        requested_at: chrono::Utc::now().to_rfc3339(),
        status: "pending".to_string(),
        decided_by: None,
        decided_at: None,
        approvals: Vec::new(),
    }
}

#[tokio::test]
async fn broadcast_pending_quorum_peer_ack_meets_quorum() {
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-pending-ack", url)]);
    let pa = pending_action("pa-ack");
    let tracker = ai_memory::federation::sync::broadcast_pending_quorum(&cfg, &pa)
        .await
        .expect("pending quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_pending_quorum_id_drift_does_not_meet_quorum() {
    let url = spawn_mock_peer("200 OK", "{\"ids\":[\"not-this-pending\"]}").await;
    let cfg = quorum_config_w2(vec![peer("peer-pending-drift", url)]);
    let pa = pending_action("pa-drift");
    let tracker = ai_memory::federation::sync::broadcast_pending_quorum(&cfg, &pa)
        .await
        .expect("pending quorum returns tracker on id-drift");
    assert!(matches!(
        tracker.finalise(std::time::Instant::now()),
        Err(ai_memory::replication::QuorumError::QuorumNotMet { .. })
    ));
}

// --- broadcast_pending_decision_quorum --------------------------------

#[tokio::test]
async fn broadcast_pending_decision_quorum_peer_ack_meets_quorum() {
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-decision-ack", url)]);
    let decision = PendingDecision {
        id: "pd-ack".to_string(),
        approved: true,
        decider: "ai:ga2-r4-sender".to_string(),
    };
    let tracker = ai_memory::federation::sync::broadcast_pending_decision_quorum(&cfg, &decision)
        .await
        .expect("pending-decision quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_pending_decision_quorum_peer_fail_does_not_meet_quorum() {
    // A single 500-replying peer → AckOutcome::Fail on both the first POST
    // and the retry → quorum NOT met (only the local write counted).
    let url = spawn_mock_peer("500 Internal Server Error", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-decision-fail", url)]);
    let decision = PendingDecision {
        id: "pd-fail".to_string(),
        approved: false,
        decider: "ai:ga2-r4-sender".to_string(),
    };
    let tracker = ai_memory::federation::sync::broadcast_pending_decision_quorum(&cfg, &decision)
        .await
        .expect("pending-decision quorum returns tracker even when peer 500s");
    assert!(matches!(
        tracker.finalise(std::time::Instant::now()),
        Err(ai_memory::replication::QuorumError::QuorumNotMet { .. })
    ));
}

// --- broadcast_namespace_meta_quorum ----------------------------------

#[tokio::test]
async fn broadcast_namespace_meta_quorum_peer_ack_meets_quorum() {
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-nsmeta-ack", url)]);
    let entry = NamespaceMetaEntry {
        namespace: "ga2-r4-fed-ns".to_string(),
        standard_id: uid("std"),
        parent_namespace: Some("ga2-r4".to_string()),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    let tracker = ai_memory::federation::sync::broadcast_namespace_meta_quorum(&cfg, &entry)
        .await
        .expect("namespace_meta quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_namespace_meta_quorum_id_drift_does_not_meet_quorum() {
    let url = spawn_mock_peer("200 OK", "{\"ids\":[\"other-ns\"]}").await;
    let cfg = quorum_config_w2(vec![peer("peer-nsmeta-drift", url)]);
    let entry = NamespaceMetaEntry {
        namespace: "ga2-r4-fed-ns".to_string(),
        standard_id: uid("std"),
        parent_namespace: None,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    let tracker = ai_memory::federation::sync::broadcast_namespace_meta_quorum(&cfg, &entry)
        .await
        .expect("namespace_meta quorum returns tracker on id-drift");
    assert!(matches!(
        tracker.finalise(std::time::Instant::now()),
        Err(ai_memory::replication::QuorumError::QuorumNotMet { .. })
    ));
}

// --- broadcast_namespace_meta_clear_quorum ----------------------------

#[tokio::test]
async fn broadcast_namespace_meta_clear_quorum_peer_ack_meets_quorum() {
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-nsclear-ack", url)]);
    let namespaces = vec!["ga2-r4-fed-ns".to_string(), "ga2-r4-other".to_string()];
    let tracker =
        ai_memory::federation::sync::broadcast_namespace_meta_clear_quorum(&cfg, &namespaces)
            .await
            .expect("namespace_meta_clear quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_namespace_meta_clear_quorum_id_drift_does_not_meet_quorum() {
    let url = spawn_mock_peer("200 OK", "{\"ids\":[\"unrelated\"]}").await;
    let cfg = quorum_config_w2(vec![peer("peer-nsclear-drift", url)]);
    let namespaces = vec!["ga2-r4-fed-ns".to_string()];
    let tracker =
        ai_memory::federation::sync::broadcast_namespace_meta_clear_quorum(&cfg, &namespaces)
            .await
            .expect("namespace_meta_clear quorum returns tracker on id-drift");
    assert!(matches!(
        tracker.finalise(std::time::Instant::now()),
        Err(ai_memory::replication::QuorumError::QuorumNotMet { .. })
    ));
}

// --- bulk_catchup_push ------------------------------------------------

#[tokio::test]
async fn bulk_catchup_push_empty_inputs_short_circuit() {
    // memories empty → early `return Vec::new()` (sync.rs:1523) without any
    // network IO.
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-catchup-empty", url)]);
    let errs = ai_memory::federation::sync::bulk_catchup_push(&cfg, &[]).await;
    assert!(errs.is_empty(), "no memories ⇒ no catchup POST ⇒ no errors");
}

#[tokio::test]
async fn bulk_catchup_push_success_returns_no_errors() {
    // A 200-replying peer drains the success body (the keep-alive drain arm)
    // and returns Ok(()) → no error rows.
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-catchup-ok", url)]);
    let memories = vec![r4_memory("catchup-a"), r4_memory("catchup-b")];
    let errs = ai_memory::federation::sync::bulk_catchup_push(&cfg, &memories).await;
    assert!(
        errs.is_empty(),
        "successful catchup batch reports no per-peer errors: {errs:?}"
    );
}

#[tokio::test]
async fn bulk_catchup_push_peer_http_error_is_collected() {
    // A 503-replying peer drives the `Ok(resp) => Err(http …)` error arm +
    // the keep-alive drain on the error branch; the error is collected into
    // the returned Vec.
    let url = spawn_mock_peer("503 Service Unavailable", "{\"error\":\"down\"}").await;
    let cfg = quorum_config_w2(vec![peer("peer-catchup-503", url)]);
    let memories = vec![r4_memory("catchup-err")];
    let errs = ai_memory::federation::sync::bulk_catchup_push(&cfg, &memories).await;
    assert_eq!(
        errs.len(),
        1,
        "the 503 peer surfaces one error row: {errs:?}"
    );
    assert_eq!(errs[0].0, "peer-catchup-503");
    assert!(
        errs[0].1.contains("503") || errs[0].1.contains("http"),
        "error string carries the http status: {:?}",
        errs[0].1
    );
}

#[tokio::test]
async fn bulk_catchup_push_unreachable_peer_is_collected() {
    // A non-routable port → reqwest connect error → the `Err(e)` network arm
    // of bulk_catchup_push. Tight client timeout keeps the test fast.
    let cfg = quorum_config_w2(vec![peer(
        "peer-catchup-unreachable",
        "http://127.0.0.1:1/api/v1/sync/push".to_string(),
    )]);
    let memories = vec![r4_memory("catchup-net-err")];
    let errs = ai_memory::federation::sync::bulk_catchup_push(&cfg, &memories).await;
    assert_eq!(
        errs.len(),
        1,
        "unreachable peer surfaces one error: {errs:?}"
    );
    assert_eq!(errs[0].0, "peer-catchup-unreachable");
}

// ===================================================================
// federation_signing_check::sync_push_via_store — batch-cap + quota arms
// (REAL PostgresStore-backed router via tower::oneshot).
// ===================================================================

/// Build a `Db` handle over a fresh `:memory:` sqlite metadata DB. Returned
/// separately so the caller can pre-seed `agent_quotas` rows before wiring
/// the router (the postgres receive path consults this same conn for the
/// per-agent quota gate).
fn fresh_metadata_db() -> Db {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )))
}

/// Build a production router backed by a live `PostgresStore` over the given
/// metadata `Db`. The embedder is `None` (keyword-only): the receiver_dim is
/// `None`, so any shipped vector defers and the deferred-embed spawn guard
/// short-circuits.
async fn pg_router_with_db(url: &str, db: Db) -> axum::Router {
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["ai:cov-ga2-r4".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn push_req(body: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .body(Body::from(body.to_vec()))
        .unwrap()
}

fn memory_json(id: &str, ns: &str, peer: &str) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "id": id,
        "tier": "mid",
        "namespace": ns,
        "title": format!("ga2 r4 deep-body row {id}"),
        "content": "non-empty federation batch drives the postgres apply loop",
        "tags": ["cov-ga2-r4"],
        "priority": 5,
        "confidence": 1.0,
        "source": "nhi",
        "access_count": 0,
        "created_at": now,
        "updated_at": now,
        "metadata": {"agent_id": peer}
    })
}

#[tokio::test]
async fn pg_sync_push_oversized_batch_rejected_400() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = postgres_url() else {
        eprintln!("SKIP pg_sync_push_oversized_batch_rejected_400: env unset");
        return;
    };
    // SAFETY: the env mutation is serialised on FED_ENV_LOCK and reverted.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let db = fresh_metadata_db();
    let r = pg_router_with_db(&url, db).await;
    let peer = uid("ai:cov-ga2-r4-big");
    let ns = uid("cov-ga2-r4-big");
    // The default MAX_BULK_SIZE cap is 1000; a deletions array of 1001 entries
    // trips the subcollection-cap guard (federation_signing_check.rs:61-84)
    // and returns 400 BEFORE any apply work.
    let deletions: Vec<String> = (0..=ai_memory::handlers::MAX_BULK_SIZE)
        .map(|i| format!("{ns}-del-{i}"))
        .collect();
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": [],
        "deletions": deletions
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body)).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "oversized subcollection must be refused; body={b}"
    );
    assert!(
        b["error"]
            .as_str()
            .unwrap_or_default()
            .contains("limited to"),
        "400 carries the cap error; body={b}"
    );
}

#[tokio::test]
async fn pg_sync_push_quota_refusal_returns_429() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = postgres_url() else {
        eprintln!("SKIP pg_sync_push_quota_refusal_returns_429: env unset");
        return;
    };
    // SAFETY: env mutation serialised on FED_ENV_LOCK and reverted at end.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let peer = uid("ai:cov-ga2-r4-quota");
    let ns = uid("cov-ga2-r4-quota");

    // Pre-seed a zero-budget agent_quotas row for (attribute_agent, ns) on the
    // sqlite metadata DB. `ensure_row` short-circuits on an existing row, so
    // the daily-memory cap stays 0 → the first apply trips
    // QuotaError::Quota → the quota-refusal WARN + signed-event + 429.
    // `attribute_agent_for_quota` resolves to the memory's metadata.agent_id
    // (== peer here), so the seeded row keys on (peer, ns).
    let db = fresh_metadata_db();
    {
        let conn = db.lock().await;
        let now = chrono::Utc::now().to_rfc3339();
        let day = now.split('T').next().unwrap_or(&now).to_string();
        conn.0
            .execute(
                "INSERT INTO agent_quotas
                   (agent_id, namespace,
                    max_memories_per_day, max_storage_bytes, max_links_per_day,
                    current_memories_today, current_storage_bytes, current_links_today,
                    day_started_at, created_at, updated_at)
                 VALUES (?1, ?2, 0, 104857600, 5000, 0, 0, 0, ?3, ?4, ?4)",
                rusqlite::params![peer, ns, day, now],
            )
            .expect("seed zero-budget quota row");
    }

    let r = pg_router_with_db(&url, db).await;
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": [memory_json(&uid("ga2r4-quota-m"), &ns, &peer)]
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body)).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "zero-budget quota must refuse with 429; body={b}"
    );
    assert_eq!(b["error"], "QUOTA_EXCEEDED", "body={b}");
    assert_eq!(b["limit"], "memories_per_day", "body={b}");
    assert_eq!(
        b["applied_before_refusal"].as_i64().unwrap_or(-1),
        0,
        "nothing applied before the very-first-row refusal; body={b}"
    );
    assert_eq!(b["storage_backend"], "postgres", "body={b}");
}

// ===================================================================
// cli::schema_init — live-postgres embedding-dim in-place conversion arm
// (init_and_enumerate_postgres → migrate_embedding_dim returning `true`).
// ===================================================================

#[tokio::test]
async fn schema_init_postgres_embedding_dim_conversion_round_trip() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = postgres_url() else {
        eprintln!("SKIP schema_init_postgres_embedding_dim_conversion_round_trip: env unset");
        return;
    };

    // Step 1 — init at 384 (idempotent no-op if already 384, conversion
    // otherwise). Either way the report comes back with embedding_dim=384.
    let run_at = |dim: u32| {
        let url = url.clone();
        async move {
            let mut stdout = Vec::<u8>::new();
            let mut stderr = Vec::<u8>::new();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ai_memory::cli::schema_init::SchemaInitArgs {
                store_url: url,
                json: true,
                embedding_dim: dim,
            };
            ai_memory::cli::schema_init::run(&args, &mut out)
                .await
                .expect("schema-init run");
            let raw = String::from_utf8(stdout).expect("utf-8 stdout");
            serde_json::from_str::<serde_json::Value>(&raw)
                .unwrap_or_else(|e| panic!("parseable JSON, got {raw}: {e}"))
        }
    };

    let v0 = run_at(384).await;
    assert_eq!(v0["embedding_dim"].as_i64(), Some(384), "init at 384: {v0}");

    // Step 2 — convert to 768. migrate_embedding_dim alters the column,
    // NULLs embeddings, and returns true → embedding_dim_migrated=true
    // (the live-conversion arm init_and_enumerate_postgres:413-425). When the
    // DB was already at 768 from a prior run this is a no-op (false); accept
    // both so the test is order-independent on the shared scratch DB.
    let v768 = run_at(768).await;
    assert_eq!(
        v768["embedding_dim"].as_i64(),
        Some(768),
        "post-conv: {v768}"
    );

    // Step 3 — re-run at 768: idempotent no-op (embedding_dim_migrated=false),
    // exercising the migrate_embedding_dim Ok(false) arm.
    let v768b = run_at(768).await;
    assert_eq!(
        v768b["embedding_dim"].as_i64(),
        Some(768),
        "idempotent: {v768b}"
    );
    assert_eq!(
        v768b["embedding_dim_migrated"], false,
        "second run at the same dim must be a no-op: {v768b}"
    );

    // Restore the shared scratch DB to the 384 baseline the other suites
    // (cov_ga2_pg_adapter2) assert against — leave no cross-suite drift.
    let _ = run_at(384).await;
}

#[tokio::test]
async fn schema_init_postgres_reports_age_projection_field() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = postgres_url() else {
        eprintln!("SKIP schema_init_postgres_reports_age_projection_field: env unset");
        return;
    };
    // Drives enumerate_postgres → the `age` extension probe + (when present)
    // bootstrap_memory_graph. age_projection_created is true only when AGE is
    // installed; either way the field is present and the extensions list is
    // surfaced. Run at 384 to avoid disturbing the dim baseline.
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
    let args = ai_memory::cli::schema_init::SchemaInitArgs {
        store_url: url,
        json: true,
        embedding_dim: 384,
    };
    ai_memory::cli::schema_init::run(&args, &mut out)
        .await
        .expect("schema-init run for age probe");
    let raw = String::from_utf8(stdout).expect("utf-8 stdout");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parseable JSON");
    assert_eq!(v["kind"], "postgres", "{v}");
    assert!(
        v.get("age_projection_created").is_some(),
        "report carries age_projection_created: {v}"
    );
    assert!(
        v["extensions"].is_array(),
        "report carries extensions list: {v}"
    );
}
