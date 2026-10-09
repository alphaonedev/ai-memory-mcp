// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4079 / #4153 — a Postgres-ARM origin node for the HTTP delete fan-out
//! suites: `StorageBackend::Postgres` over the SAL `SqliteStore` (the
//! `tests/agent_attestation_postgres.rs` shape), so the cells exercise the
//! exact handler arms a Postgres daemon runs without a live Postgres, plus a
//! recording federation peer (the #2498 harness pattern) that can be switched
//! DOWN mid-test.

#![allow(dead_code)]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::replication::QuorumPolicy;
use ai_memory::store::MemoryStore;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

pub const ALICE: &str = "ai:alice-pg-arm";
pub const API_KEY: &str = "pg-arm-origin-4079-4153";

/// The recording peer: every `/sync/push` body, in arrival order, plus a
/// switch that turns it into a DOWN peer (every POST answers 500).
#[derive(Clone, Default)]
pub struct Peer {
    pub bodies: Arc<Mutex<Vec<Value>>>,
    pub down: Arc<AtomicBool>,
}

async fn push_handler(
    State(peer): State<Peer>,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> (StatusCode, axum::Json<Value>) {
    peer.bodies.lock().await.push(body);
    if peer.down.load(Ordering::Relaxed) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "peer down"})),
        );
    }
    (
        StatusCode::OK,
        axum::Json(json!({"applied": 1, "noop": 0, "skipped": 0})),
    )
}

pub async fn spawn_peer(peer: Peer) -> String {
    let app = Router::new()
        .route("/api/v1/sync/push", post(push_handler))
        .with_state(peer);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

/// Every push whose `deletions` names `id`.
pub async fn withdrawals_for(peer: &Peer, id: &str) -> usize {
    peer.bodies
        .lock()
        .await
        .iter()
        .filter(|b| {
            b["deletions"]
                .as_array()
                .is_some_and(|d| d.iter().any(|v| v == id))
        })
        .count()
}

fn federation(peer_url: &str) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .expect("reqwest client");
    // W = N = 2: the single peer is REQUIRED, so a miss is a quorum miss.
    FederationConfig {
        policy: QuorumPolicy::new(
            2,
            2,
            Duration::from_millis(2000),
            Duration::from_secs(30),
        )
        .unwrap(),
        peers: vec![PeerEndpoint {
            id: "peer-pg-arm".to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: "ai:origin-pg-arm".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

/// The origin `AppState` (Postgres arm over `SqliteStore`), federated to
/// `peer_url`, plus the store handle for seeding rows directly.
pub fn origin(dir: &std::path::Path, peer_url: &str) -> (AppState, Arc<dyn MemoryStore>) {
    let path = dir.join("origin.db");
    let conn = ai_memory::db::open(&path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path).expect("open SqliteStore"),
    );
    let app = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(Some(federation(peer_url))),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store: Arc::clone(&store),
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
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (app, store)
}

pub fn router(app: AppState) -> Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: Some(API_KEY.into()),
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
            ..Default::default()
        },
        app,
    )
}

/// One request as `ALICE` with the api key; the parsed JSON body (or Null).
pub async fn call(
    router: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", API_KEY)
        .header("x-agent-id", ALICE);
    let req = if let Some(b) = body {
        req.header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        req.header("content-length", "0")
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Scratch under `.local-runs/` (the project no-`/tmp` rule).
pub fn scratch(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("tempdir under .local-runs")
}

/// A row owned by `owner` in `namespace`.
pub fn owned_memory(owner: &str, namespace: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("pg-arm-origin {}", uuid::Uuid::new_v4()),
        content: "a row that replicated to the peer and must be withdrawn".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner }),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}
