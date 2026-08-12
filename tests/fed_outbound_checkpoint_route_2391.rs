// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]

//! #2391 — the checkpoint-resolution OUTBOUND leg actually fires in production.
//!
//! `broadcast_checkpoint_resolution_quorum` shipped at v1.0.0 with the FED-RQ-01
//! (#1936) receive leg, but had ZERO production callers: checkpoints were the one
//! coordination primitive #1718 never gave an HTTP route, and federation fanout is
//! only reachable from a handler holding `AppState::federation`. The fn was
//! "dead-but-covered" — the integration suite called it directly, so the coverage
//! floor read GREEN while two real nodes could never exchange a checkpoint
//! resolution (the §25.2 epoch-freeze contract's only cross-node mechanism).
//!
//! `tests/qual_fed_broadcast_reachability.rs` is the structural gate. THIS file is
//! the behavioural proof: it drives the REAL router
//! (`POST /api/v1/checkpoints/{id}/resolve`) against a capturing mock peer and
//! asserts the resolution lands in the peer's `/sync/push` body.
//!
//! The quorum policy is deliberately **W=2 over N=2** so the local write alone
//! CANNOT satisfy quorum: a `200` with `quorum_acks == 2` is only reachable if the
//! handler genuinely fanned out and the peer acked. If the outbound leg regressed
//! to unwired, this returns `503 under-replicated` instead — the assertion is
//! load-bearing on the fanout, not merely on the handler existing.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

const CHECKPOINT_ID: &str = "cp-2391-outbound";
const RESOLVE_ROUTE: &str = "/api/v1/checkpoints/cp-2391-outbound/resolve";

/// Capturing mock peer — records each raw `/sync/push` body and 200s.
#[derive(Clone)]
struct Cap(Arc<StdMutex<Vec<String>>>);

async fn capture_push(State(cap): State<Cap>, body: String) -> impl IntoResponse {
    cap.0.lock().expect("cap lock").push(body);
    (StatusCode::OK, "{}")
}

/// Bring up the mock peer; returns its `/sync/push` URL and the capture handle.
async fn spawn_mock_peer() -> (String, Cap) {
    let cap = Cap(Arc::new(StdMutex::new(Vec::new())));
    let app = axum::Router::new()
        .route("/api/v1/sync/push", post(capture_push))
        .with_state(cap.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}/api/v1/sync/push"), cap)
}

/// W-of-N config over the single mock peer. `w = 2` means local + peer.
fn federation_config(push_url: &str) -> ai_memory::federation::FederationConfig {
    ai_memory::federation::FederationConfig {
        policy: ai_memory::replication::QuorumPolicy::new(
            2,
            2,
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .expect("quorum policy"),
        peers: vec![ai_memory::federation::PeerEndpoint {
            id: "peer-2391".to_string(),
            sync_push_url: push_url.to_string(),
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client"),
        sender_agent_id: "ai:sender-2391".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

/// Sqlite-backed router carrying `federation`, with one PENDING checkpoint
/// (`CHECKPOINT_ID`) already inserted.
fn build_router_with_pending_checkpoint(
    federation: Option<ai_memory::federation::FederationConfig>,
) -> axum::Router {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    std::mem::forget(f);

    let cp = ai_memory::models::Checkpoint {
        id: CHECKPOINT_ID.to_string(),
        namespace: "_cp".to_string(),
        title: "epoch freeze".to_string(),
        condition_type: ai_memory::models::ConditionType::default(),
        condition: json!({}),
        state: ai_memory::models::CheckpointState::Pending,
        created_by: "ai:creator-2391".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: None,
        metadata: json!({}),
    };
    ai_memory::checkpoints::insert(&conn, &cp).expect("insert checkpoint");

    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(federation),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn resolve_request(path: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header(ai_memory::HEADER_AGENT_ID, "ai:resolver-2391")
        .body(Body::from(body.to_string()))
        .expect("request")
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

// ---------------------------------------------------------------------------
// A — the outbound leg fires: the resolution reaches the peer's /sync/push.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_route_fans_the_resolution_out_to_peers() {
    let (push_url, cap) = spawn_mock_peer().await;
    let router = build_router_with_pending_checkpoint(Some(federation_config(&push_url)));

    let resp = router
        .oneshot(resolve_request(
            RESOLVE_ROUTE,
            &json!({"state": "resolved", "resolution": "shipped"}),
        ))
        .await
        .expect("route response");

    // W=2 over N=2: a 200 is unreachable without a real peer ack, so this
    // status alone proves the fanout happened.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "W=2 quorum can only be met if the handler fanned out to the peer; \
         a 503 here means the #2391 outbound leg is unwired again"
    );
    let body = body_json(resp).await;
    assert_eq!(
        body["quorum_acks"],
        json!(2),
        "expected local + peer ack, got: {body}"
    );
    assert_eq!(body["state"], json!("resolved"));
    assert_eq!(body["resolved_by"], json!("ai:resolver-2391"));

    let pushes = cap.0.lock().expect("cap lock").clone();
    assert_eq!(pushes.len(), 1, "peer must receive exactly one /sync/push");
    let parsed: Value = serde_json::from_str(&pushes[0]).expect("push body json");
    assert_eq!(
        parsed["checkpoints"][0]["id"],
        json!(CHECKPOINT_ID),
        "the resolved checkpoint must ride the /sync/push body: {parsed}"
    );
    assert_eq!(parsed["checkpoints"][0]["state"], json!("resolved"));
    assert_eq!(parsed["checkpoints"][0]["resolution"], json!("shipped"));
    assert_eq!(
        parsed["checkpoints"][0]["resolved_by"],
        json!("ai:resolver-2391"),
        "resolved_by must be the NODE identity so the receiver's fail-closed \
         checkpoint-sig gate can bind it to an enrolled key"
    );
}

// ---------------------------------------------------------------------------
// B — single-node fast path: no federation configured, no fanout, still 200.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_route_single_node_fast_path_has_no_quorum_field() {
    let router = build_router_with_pending_checkpoint(None);

    let resp = router
        .oneshot(resolve_request(
            RESOLVE_ROUTE,
            &json!({"state": "rejected", "resolution_note": "superseded"}),
        ))
        .await
        .expect("route response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["state"], json!("rejected"));
    assert!(
        body.get("quorum_acks").is_none(),
        "an unfederated daemon must not advertise a quorum: {body}"
    );
}

// ---------------------------------------------------------------------------
// C — input guards: unknown id is 404, non-terminal state is 400.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_route_unknown_checkpoint_is_404() {
    let router = build_router_with_pending_checkpoint(None);
    let resp = router
        .oneshot(resolve_request(
            "/api/v1/checkpoints/cp-does-not-exist/resolve",
            &json!({"state": "resolved"}),
        ))
        .await
        .expect("route response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn resolve_route_non_terminal_state_is_400() {
    let router = build_router_with_pending_checkpoint(None);
    let resp = router
        .oneshot(resolve_request(RESOLVE_ROUTE, &json!({"state": "pending"})))
        .await
        .expect("route response");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "only the terminal resolved/rejected states may be federated as a resolution"
    );
}
