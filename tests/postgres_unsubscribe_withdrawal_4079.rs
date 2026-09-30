// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::too_many_lines, clippy::missing_panics_doc)]

//! #4079 / #4153 — a Postgres-backed withdrawal MUST reach the peers that
//! hold a replica.
//!
//! On a Postgres-backed daemon a subscription is a memory under
//! `_subscriptions/<agent_id>`, and `subscribe` fans it out to every peer
//! through the quorum store lane so peer dispatchers match it too. Pre-fix,
//! `DELETE /api/v1/subscriptions` (#4079) and the generic
//! `DELETE /api/v1/memories/{id}` (#4153) only deleted the LOCAL row and
//! answered success: nothing was sent on the federation delete lane, so
//! every independently-stored peer kept the replica, kept matching it in its
//! `_subscriptions/` dispatch scan, and kept sending signed event POSTs to the
//! withdrawn endpoint.
//!
//! Node A is the daemon under test (a real `PostgresStore` when
//! `AI_MEMORY_TEST_POSTGRES_URL` is set under `sal-postgres`, otherwise the
//! in-tree SAL `SqliteStore` driven through the SAME Postgres handler arms).
//! The peer is an in-process `sync_push` receiver that records every body,
//! the `tests/federation_delete_dlq_2498.rs` harness: how a receiver applies
//! `deletions[]` (scope gate, `apply_remote_deletion`) is pinned by its own
//! suites; what this suite pins is that the origin SENDS the withdrawal, and
//! that a missed one is queued durably and re-delivered.
//!
//! - `unsubscribe_fans_out_withdrawal_4079` — subscribe, unsubscribe: the
//!   peer receives `deletions: [id]`; the answer is a plain 200.
//! - `unsubscribe_while_peer_down_withdraws_on_return_4079` — peer DOWN at
//!   unsubscribe: 202 with replication state, a push-DLQ row carrying the
//!   deletion, and one replay tick after the peer recovers re-delivers it.
//! - `memory_delete_fans_out_withdrawal_4153` — the generic memory route.

#![cfg(feature = "sal")]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::push_dlq::{FederationDlqSink, SqliteDlqSink, replay_once};
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::sqlite::SqliteStore;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex, Notify, RwLock};

mod common;
use common::{DAEMON_READY_TIMEOUT, free_port, wait_for_http_ready};

/// Scratch root under the repo's gitignored `.local-runs/` (no `/tmp`).
fn scratch() -> tempfile::TempDir {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("issue-4079-unsubscribe-withdrawal");
    std::fs::create_dir_all(&root).expect("mkdir scratch root");
    tempfile::tempdir_in(root).expect("tempdir")
}

fn scratch_db(dir: &std::path::Path, name: &str) -> Db {
    let path = dir.join(name);
    let conn = ai_memory::db::open(&path).expect("open scratch sqlite");
    Arc::new(Mutex::new((conn, path, ResolvedTtl::default(), true)))
}

/// A Postgres-mode `AppState` over `store`. Same field set as
/// `tests/federation_postgres_fanout.rs::build_postgres_app_state`.
fn postgres_mode_state(
    db: Db,
    store: Arc<dyn MemoryStore>,
    federation: Option<FederationConfig>,
) -> AppState {
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(federation),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
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
    }
}

/// Node A's store: a real `PostgresStore` when the Postgres tier is
/// configured, else the in-tree SAL `SqliteStore` (the Postgres HANDLER arms
/// are selected by `storage_backend`, not by the concrete store).
// Awaits only on the `sal-postgres` arm.
#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn node_a_store(dir: &std::path::Path) -> Arc<dyn MemoryStore> {
    #[cfg(feature = "sal-postgres")]
    if let Some(url) = common::postgres_url() {
        return Arc::new(
            ai_memory::store::postgres::PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        );
    }
    Arc::new(SqliteStore::open(dir.join("node-a-store.db")).expect("open node A store"))
}

fn federation_to(peer_base: &str, sink: Option<Arc<dyn FederationDlqSink>>) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let timeout = Duration::from_secs(2);
    FederationConfig {
        // N = 2 (A + B), W = 2: B's ack is REQUIRED, so a miss is observable.
        policy: ai_memory::replication::QuorumPolicy::new(2, 2, timeout, Duration::from_secs(30))
            .expect("quorum policy"),
        peers: vec![PeerEndpoint {
            id: "peer-b".to_string(),
            sync_push_url: format!("{peer_base}/api/v1/sync/push"),
        }],
        client: reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .build()
            .expect("reqwest client"),
        sender_agent_id: "ai:node-a-4079".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: sink,
    }
}

struct Daemon {
    base: String,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Daemon {
    async fn spawn(addr: String, state: AppState) -> Self {
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
            ..Default::default()
        };
        let shutdown = Arc::new(Notify::new());
        let (sd, a) = (shutdown.clone(), addr.clone());
        let handle = tokio::spawn(async move {
            ai_memory::daemon_runtime::serve_http_with_shutdown(&a, api_key_state, state, sd).await
        });
        wait_for_http_ready(&addr, DAEMON_READY_TIMEOUT)
            .await
            .expect("daemon never became ready");
        Self {
            base: format!("http://{addr}"),
            shutdown,
            handle,
        }
    }

    async fn stop(self) {
        self.shutdown.notify_one();
        let _ = self.handle.await;
    }
}

async fn unsubscribe(client: &reqwest::Client, base: &str, owner: &str, id: &str) -> (u16, Value) {
    let resp = client
        .delete(format!("{base}/api/v1/subscriptions?id={id}"))
        .header("x-agent-id", owner)
        .send()
        .await
        .expect("unsubscribe");
    let status = resp.status().as_u16();
    (status, resp.json().await.expect("unsubscribe body"))
}

/// Recording `sync_push` peer. `down` switches it to answering 500.
#[derive(Clone, Default)]
struct Peer {
    down: Arc<AtomicBool>,
    bodies: Arc<Mutex<Vec<Value>>>,
}

impl Peer {
    async fn spawn() -> (Self, String) {
        async fn push(
            axum::extract::State(peer): axum::extract::State<Peer>,
            axum::Json(body): axum::Json<Value>,
        ) -> (axum::http::StatusCode, axum::Json<Value>) {
            peer.bodies.lock().await.push(body);
            if peer.down.load(Ordering::SeqCst) {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({"error": "peer down"})),
                )
            } else {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(json!({"applied": 1, "noop": 0, "skipped": 0})),
                )
            }
        }
        let peer = Self::default();
        let app = axum::Router::new()
            .route("/api/v1/sync/push", axum::routing::post(push))
            .with_state(peer.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind peer");
        let addr = listener.local_addr().expect("peer addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        (peer, format!("http://{addr}"))
    }

    /// How many pushes carried `deletions: [id]`.
    async fn deletions_of(&self, id: &str) -> usize {
        self.bodies
            .lock()
            .await
            .iter()
            .filter(|b| b["deletions"] == json!([id]))
            .count()
    }

    /// `true` once a push carrying the subscription row `id` arrived.
    async fn saw_store_of(&self, id: &str) -> bool {
        self.bodies.lock().await.iter().any(|b| {
            b["memories"]
                .as_array()
                .is_some_and(|ms| ms.iter().any(|m| m["id"] == json!(id)))
        })
    }
}

async fn subscribe(client: &reqwest::Client, base: &str, owner: &str) -> String {
    let resp = client
        .post(format!("{base}/api/v1/subscriptions"))
        .header("x-agent-id", owner)
        .json(&json!({
            "url": "https://hooks.example.com/withdrawn-4079",
            "events": "*",
            "secret": "withdrawal-probe-secret",
        }))
        .send()
        .await
        .expect("subscribe");
    let status = resp.status();
    let body: Value = resp.json().await.expect("subscribe body");
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "subscribe must land: {body}"
    );
    assert_eq!(body["storage_backend"], "postgres");
    body["id"].as_str().expect("subscription id").to_string()
}

/// Node A: a Postgres-mode daemon federated to `peer_base` (N = 2, W = 2, so
/// the peer's ack is required and a miss is observable).
async fn node_a(
    dir: &std::path::Path,
    peer_base: &str,
    sink: Option<Arc<dyn FederationDlqSink>>,
) -> (Daemon, FederationConfig) {
    let fed = federation_to(peer_base, sink);
    let daemon = Daemon::spawn(
        format!("127.0.0.1:{}", free_port()),
        postgres_mode_state(
            scratch_db(dir, "a.db"),
            node_a_store(dir).await,
            Some(fed.clone()),
        ),
    )
    .await;
    (daemon, fed)
}

fn owner() -> String {
    format!("ai:owner-4079-{}", uuid::Uuid::new_v4())
}

#[tokio::test(flavor = "multi_thread")]
async fn unsubscribe_fans_out_withdrawal_4079() {
    let dir = scratch();
    let (peer, peer_base) = Peer::spawn().await;
    let (node, _) = node_a(dir.path(), &peer_base, None).await;
    let client = common::bounded_test_client();
    let owner = owner();

    let id = subscribe(&client, &node.base, &owner).await;
    assert!(
        peer.saw_store_of(&id).await,
        "precondition: subscribe replicates the row to the peer"
    );

    let (status, body) = unsubscribe(&client, &node.base, &owner, &id).await;
    assert_eq!(status, 200, "quorum-met withdrawal is a plain 200: {body}");
    assert_eq!(body["removed"], true, "{body}");
    assert_eq!(
        peer.deletions_of(&id).await,
        1,
        "#4079: unsubscribe must send the withdrawal (`deletions: [id]`) to the peer that \
         holds the replica; without it the peer keeps dispatching to the withdrawn endpoint"
    );

    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsubscribe_while_peer_down_withdraws_on_return_4079() {
    let dir = scratch();
    let (peer, peer_base) = Peer::spawn().await;
    let sink: Arc<dyn FederationDlqSink> = Arc::new(
        SqliteDlqSink::new(scratch_db(dir.path(), "a-dlq.db"))
            .await
            .expect("dlq sink"),
    );
    let (node, fed) = node_a(dir.path(), &peer_base, Some(sink.clone())).await;
    let client = common::bounded_test_client();
    let owner = owner();

    let id = subscribe(&client, &node.base, &owner).await;
    assert!(peer.saw_store_of(&id).await, "precondition: replicated");

    // The peer goes DOWN before the owner withdraws.
    peer.down.store(true, Ordering::SeqCst);
    let (status, body) = unsubscribe(&client, &node.base, &owner, &id).await;
    assert_eq!(
        status, 202,
        "#4079: a withdrawal that missed quorum must say so (202), not a bare 200: {body}"
    );
    assert_eq!(
        body["removed"], true,
        "the LOCAL withdrawal is durable: {body}"
    );
    assert_eq!(body["quorum_met"], false, "{body}");

    let pending = sink.take_pending_dlq_rows(64).await.expect("read push DLQ");
    let row = pending
        .iter()
        .find(|r| r.memory_id == id && r.peer_id == "peer-b")
        .unwrap_or_else(|| {
            panic!("#4079: the missed peer withdrawal must be queued in the push DLQ: {pending:?}")
        });
    assert_eq!(
        row.payload_json["deletions"],
        json!([id]),
        "{:?}",
        row.payload_json
    );

    // The peer recovers: one replay tick re-delivers the withdrawal and
    // clears the row.
    peer.down.store(false, Ordering::SeqCst);
    let before = peer.deletions_of(&id).await;
    replay_once(&fed, sink.as_ref()).await;
    assert_eq!(
        peer.deletions_of(&id).await,
        before + 1,
        "#4079: the queued withdrawal must be re-delivered once the peer is back"
    );
    let left = sink.take_pending_dlq_rows(64).await.expect("read push DLQ");
    assert!(
        !left.iter().any(|r| r.memory_id == id),
        "the delivered withdrawal must leave the push DLQ: {left:?}"
    );

    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn memory_delete_fans_out_withdrawal_4153() {
    let dir = scratch();
    let (peer, peer_base) = Peer::spawn().await;
    let (node, _) = node_a(dir.path(), &peer_base, None).await;
    let client = common::bounded_test_client();
    let owner = owner();

    // The #4079 sibling funnel: a subscription row removed through the
    // GENERIC memory route.
    let id = subscribe(&client, &node.base, &owner).await;
    assert!(peer.saw_store_of(&id).await, "precondition: replicated");

    let resp = client
        .delete(format!("{}/api/v1/memories/{id}", node.base))
        .header("x-agent-id", owner.as_str())
        .send()
        .await
        .expect("delete memory");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.expect("delete body");
    assert_eq!(status, 200, "quorum-met delete is a plain 200: {body}");
    assert_eq!(body["deleted"], true, "{body}");
    assert_eq!(
        peer.deletions_of(&id).await,
        1,
        "#4153: a Postgres DELETE /api/v1/memories/{{id}} must send `deletions: [id]` to peers"
    );

    node.stop().await;
}
