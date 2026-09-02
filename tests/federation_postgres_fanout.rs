// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::missing_panics_doc
)]
//! v0.7.0 fold-A2A1.1 (#700, F-A2A1.1) — postgres federation fanout.
//!
//! Regression tests that pin the behaviour landed by the postgres-branch
//! fanout patch in `handlers::hook_subscribers` (S32/S33/S58 below), plus
//! coverage for the federated `POST /api/v1/consolidate` postgres arms
//! (`consolidate_fanout_postgres_*`, #2860/#2861):
//!
//! 1. `notify_fanout_postgres_reaches_W_of_N_peers` (S32 equivalent) —
//!    a postgres-backed daemon configured with three in-process mock
//!    peers fans the just-written inbox memory out via the same
//!    `broadcast_store_quorum` contract the sqlite branch uses. Each
//!    peer's sync_push endpoint must observe at least one POST for the
//!    notify-generated memory.
//!
//! 2. `subscribe_postgres_replays_history` (S33 equivalent) —
//!    registering a subscription on the postgres daemon writes a
//!    subscription memory under `_subscriptions/<aid>` AND fans it out
//!    to peers so subscribers attached AFTER an event become visible
//!    cluster-wide. Verified by inspecting the wire-shape POST that
//!    lands on each mock peer.
//!
//! 3. `cross_namespace_dispatch_on_postgres` (S58 equivalent) —
//!    registering a subscription scoped to a NAMESPACE different from
//!    the namespace where the matching event later lands. The mock
//!    peers observe both the subscription registration AND the event
//!    memory across the cluster — the substrate's cross-namespace
//!    dispatch contract is satisfied by the shared `_subscriptions/<aid>`
//!    namespace replication.
//!
//! ## Gating
//!
//! Skipped without `AI_MEMORY_TEST_POSTGRES_URL` — same convention as
//! the other postgres findings tests (`g1_postgres_…`, `sal_v07_…`).
//! The `sal-postgres` feature must be enabled at the cargo level.

#![cfg(feature = "sal-postgres")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify, RwLock};

mod common;
use common::{
    DAEMON_READY_TIMEOUT, FANOUT_OBSERVED_TIMEOUT, free_port, postgres_url, wait_for_http_ready,
};

#[derive(Clone)]
struct MockPeer {
    url: String,
    count: Arc<AtomicUsize>,
    recorded: Arc<Mutex<Vec<Value>>>,
}

async fn spawn_inproc_mock_peer() -> MockPeer {
    use axum::{Json as AxumJson, Router, extract::State, http::StatusCode, routing::post};

    #[derive(Clone)]
    struct PeerState {
        count: Arc<AtomicUsize>,
        recorded: Arc<Mutex<Vec<Value>>>,
    }

    async fn handler(
        State(state): State<PeerState>,
        AxumJson(payload): AxumJson<Value>,
    ) -> (StatusCode, AxumJson<Value>) {
        state.count.fetch_add(1, Ordering::Relaxed);
        state.recorded.lock().await.push(payload);
        (
            StatusCode::OK,
            AxumJson(json!({"applied":1,"noop":0,"skipped":0})),
        )
    }

    let count = Arc::new(AtomicUsize::new(0));
    let recorded: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/api/v1/sync/push", post(handler))
        .with_state(PeerState {
            count: count.clone(),
            recorded: recorded.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    MockPeer {
        url: format!("http://{addr}"),
        count,
        recorded,
    }
}

fn federation_cfg_for_test(peer_urls: &[String], quorum_writes: usize) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let timeout = Duration::from_secs(2);
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(2))
        .build()
        .expect("build test reqwest client");
    let n = 1 + peer_urls.len();
    let policy = ai_memory::replication::QuorumPolicy::new(
        n,
        quorum_writes,
        timeout,
        Duration::from_secs(30),
    )
    .expect("valid quorum policy");
    let peers = peer_urls
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let trimmed = raw.trim_end_matches('/');
            PeerEndpoint {
                id: format!("peer-{i}"),
                sync_push_url: format!("{trimmed}/api/v1/sync/push"),
            }
        })
        .collect();
    FederationConfig {
        policy,
        peers,
        client,
        sender_agent_id: "ai:fold-a2a1-1-test".to_string(),
        // v0.7.0 fold-A2A1.4 backcompat default: this test path doesn't run
        // with api-key auth, so no outbound x-api-key header is needed.
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

async fn build_postgres_app_state(url: &str, federation: Option<FederationConfig>) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let path = std::path::PathBuf::from(":memory:");
    let db: Db = Arc::new(Mutex::new((conn, path, ResolvedTtl::default(), true)));
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    );
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
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

async fn spawn_daemon_with_federation(
    url: &str,
    federation: Option<FederationConfig>,
) -> (
    String,
    Arc<Notify>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    // v0.7.0 fold-A2A1.4 backcompat default — this test does not exercise mTLS
    // enforcement; api-key checks remain off and the inbound bypass is not
    // configured.
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let app_state = build_postgres_app_state(url, federation).await;
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_daemon = shutdown.clone();
    let addr_for_daemon = addr.clone();
    let handle = tokio::spawn(async move {
        ai_memory::daemon_runtime::serve_http_with_shutdown(
            &addr_for_daemon,
            api_key_state,
            app_state,
            shutdown_for_daemon,
        )
        .await
    });
    // #1194: progress-detecting health-check loop with 5 min generous
    // overall timeout. See `tests/common::wait_for_http_ready`.
    wait_for_http_ready(&addr, DAEMON_READY_TIMEOUT)
        .await
        .expect("postgres-backed serve never became ready");
    (format!("http://{addr}"), shutdown, handle)
}

async fn wait_for_counter(counter: &AtomicUsize, min: usize, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if counter.load(Ordering::Relaxed) >= min {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    counter.load(Ordering::Relaxed) >= min
}

/// Seed a source row DIRECTLY through a postgres store handle (no HTTP) so a
/// consolidate-under-replication test can assemble its N sources WITHOUT each
/// HTTP create's own fanout under-replicating on the dead-peer daemon (which
/// would 202 the create and leave the test with no id to consolidate). The
/// row is authored as `agent` in `namespace` so the tenant `ctx` the
/// consolidate handler uses to read sources can see it.
async fn seed_source_row(url: &str, agent: &str, namespace: &str, title: &str) -> String {
    let store = PostgresStore::connect(url)
        .await
        .expect("seed store connect");
    let ctx = CallerContext::for_agent(agent);
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "seeded source row with enough body length to consolidate".to_string(),
        priority: 5,
        confidence: 1.0,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": agent }),
        version: 1,
        ..Memory::default()
    };
    store.store(&ctx, &mem).await.expect("seed source store")
}

// ===================================================================
// S32: notify fanout reaches W-of-N peers on postgres
// ===================================================================

/// A postgres-backed daemon configured with three in-process mock
/// peers and `W=2` quorum must fan a notify-written inbox memory out
/// to peers via the same `broadcast_store_quorum` contract the sqlite
/// path already uses. This pins F-A2A1.1: the postgres `notify`
/// branch in `handlers::hook_subscribers::notify` invokes
/// `fanout_or_503` after `store.notify()` lands.
///
/// Pre-fix: the postgres branch returned `201 CREATED` immediately
/// after `store.notify()` without consulting `app.federation`, so a
/// `notify` on node-A landed in `_inbox/<recipient>` only on node-A.
/// Recipients polling `/inbox` against node-B saw nothing until a
/// (non-existent in our test harness) catchup sync.
///
/// Post-fix: the same notify fans out via quorum_writes, every peer
/// receives the `sync_push` POST, and the test verifies the per-peer
/// counters bumped.
#[tokio::test(flavor = "multi_thread")]
async fn notify_fanout_postgres_reaches_w_of_n_peers() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let peer1 = spawn_inproc_mock_peer().await;
    let peer2 = spawn_inproc_mock_peer().await;
    let peer3 = spawn_inproc_mock_peer().await;
    let peer_urls = vec![peer1.url.clone(), peer2.url.clone(), peer3.url.clone()];
    let cfg = federation_cfg_for_test(&peer_urls, 2);

    let (base, shutdown, handle) = spawn_daemon_with_federation(&url, Some(cfg)).await;
    // v1.0.0 #3140 — bounded: `reqwest::Client::new()` has no request timeout.
    let client = common::bounded_test_client();

    let recipient = format!("ai:bob-{}", uuid::Uuid::new_v4());
    let title = format!("notify-{}", uuid::Uuid::new_v4());
    let body = json!({
        "target_agent_id": recipient,
        "title": title,
        "payload": "hello from alice via postgres",
        "priority": 5,
        "tier": "mid",
    });
    let resp = client
        .post(format!("{base}/api/v1/notify"))
        .header("x-agent-id", "ai:alice-fanout-test")
        .json(&body)
        .send()
        .await
        .expect("notify post");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "notify must succeed: {resp:?}"
    );
    let resp_body: Value = resp.json().await.expect("notify body");
    assert_eq!(resp_body["storage_backend"], "postgres");
    assert!(resp_body["id"].is_string(), "notify must return id");

    // All three peers must observe at least one sync_push POST for
    // the notify-generated inbox memory. Post-quorum detach fanout
    // means stragglers complete too.
    let timeout = FANOUT_OBSERVED_TIMEOUT;
    let p1_ok = wait_for_counter(&peer1.count, 1, timeout).await;
    let p2_ok = wait_for_counter(&peer2.count, 1, timeout).await;
    let p3_ok = wait_for_counter(&peer3.count, 1, timeout).await;
    assert!(
        p1_ok && p2_ok && p3_ok,
        "every peer must observe the notify fanout: p1={} p2={} p3={}",
        peer1.count.load(Ordering::Relaxed),
        peer2.count.load(Ordering::Relaxed),
        peer3.count.load(Ordering::Relaxed),
    );

    // Inspect the wire shape — every peer received an `_inbox/<recipient>`
    // memory whose title matches what we POSTed.
    let recorded = peer1.recorded.lock().await;
    let payload = recorded
        .iter()
        .find(|p| {
            p.get("memories")
                .and_then(|m| m.as_array())
                .is_some_and(|arr| {
                    arr.iter().any(|m| {
                        m.get("title").and_then(|t| t.as_str()) == Some(title.as_str())
                            && m.get("namespace")
                                .and_then(|n| n.as_str())
                                .is_some_and(|ns| ns == format!("_inbox/{recipient}"))
                    })
                })
        })
        .expect("peer-1 must have received the inbox memory in a sync_push body");
    let _ = payload; // silence unused

    shutdown.notify_one();
    let _ = handle.await;
}

// ===================================================================
// S33: subscribe postgres replays history (subscription fan-out)
// ===================================================================

/// Registering a subscription on a postgres-backed daemon must fan
/// the subscription memory out to peers via the same quorum-write
/// contract as the sqlite branch. This is the substrate-side piece
/// that makes "subscribers attached AFTER an event get historical
/// replay per K7 semantics" work on postgres — the subscription
/// memory lands in `_subscriptions/<aid>` on every peer, so the
/// dispatcher on any peer can find it via the shared store.
///
/// Pre-fix: postgres `subscribe` wrote the subscription memory only
/// to the leader's store, so the subscription was invisible to peer
/// dispatchers and historical replay never saw the subscription
/// among its candidate matches.
///
/// Post-fix: the postgres branch in `handlers::hook_subscribers::subscribe`
/// calls `fanout_or_503` with the subscription memory immediately
/// after the `store.store()` call lands.
#[tokio::test(flavor = "multi_thread")]
async fn subscribe_postgres_replays_history() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let peer1 = spawn_inproc_mock_peer().await;
    let peer2 = spawn_inproc_mock_peer().await;
    let peer3 = spawn_inproc_mock_peer().await;
    let peer_urls = vec![peer1.url.clone(), peer2.url.clone(), peer3.url.clone()];
    let cfg = federation_cfg_for_test(&peer_urls, 2);

    let (base, shutdown, handle) = spawn_daemon_with_federation(&url, Some(cfg)).await;
    // v1.0.0 #3140 — bounded: `reqwest::Client::new()` has no request timeout.
    let client = common::bounded_test_client();

    let subscriber_aid = format!("ai:carol-{}", uuid::Uuid::new_v4());
    let target_ns = format!("team-{}", uuid::Uuid::new_v4());
    let body = json!({
        "agent_id": subscriber_aid,
        "namespace": target_ns,
        "secret": "shared-replay-secret",
    });
    let resp = client
        .post(format!("{base}/api/v1/subscriptions"))
        .header("x-agent-id", subscriber_aid.as_str())
        .json(&body)
        .send()
        .await
        .expect("subscribe post");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "subscribe must succeed: {resp:?}"
    );
    let resp_body: Value = resp.json().await.expect("subscribe body");
    assert_eq!(resp_body["storage_backend"], "postgres");
    assert!(resp_body["id"].is_string(), "subscribe must return id");

    // Every peer must observe the subscription memory via sync_push.
    let timeout = FANOUT_OBSERVED_TIMEOUT;
    let p1_ok = wait_for_counter(&peer1.count, 1, timeout).await;
    let p2_ok = wait_for_counter(&peer2.count, 1, timeout).await;
    let p3_ok = wait_for_counter(&peer3.count, 1, timeout).await;
    assert!(
        p1_ok && p2_ok && p3_ok,
        "every peer must observe the subscription fanout: p1={} p2={} p3={}",
        peer1.count.load(Ordering::Relaxed),
        peer2.count.load(Ordering::Relaxed),
        peer3.count.load(Ordering::Relaxed),
    );

    // The fanned-out memory's namespace must be `_subscriptions/<aid>`
    // and its metadata must carry `kind=subscription` so the K7
    // replay query can find it on a freshly-rebooted peer.
    let recorded = peer1.recorded.lock().await;
    let sub_payload = recorded
        .iter()
        .find_map(|p| {
            p.get("memories")
                .and_then(|m| m.as_array())
                .and_then(|arr| {
                    arr.iter().find(|m| {
                        m.get("namespace")
                            .and_then(|n| n.as_str())
                            .is_some_and(|ns| ns == format!("_subscriptions/{subscriber_aid}"))
                            && m.get("metadata")
                                .and_then(|md| md.get("kind"))
                                .and_then(|k| k.as_str())
                                == Some("subscription")
                    })
                })
        })
        .expect("peer-1 must have observed the subscription memory in sync_push");
    let _ = sub_payload;

    // The list_subscriptions endpoint resolves the subscription back
    // through the SAL `list` projection. The post-fanout local row
    // is still present (fanout doesn't move ownership, it mirrors).
    // Per #874 (security-medium, 2026-05-18): the list_subscriptions
    // handler requires X-Agent-Id to match the agent_id= query param,
    // else it returns 403 before reaching the SAL list projection.
    let list_resp = client
        .get(format!(
            "{base}/api/v1/subscriptions?agent_id={subscriber_aid}"
        ))
        .header("x-agent-id", &subscriber_aid)
        .send()
        .await
        .expect("list subs")
        .json::<Value>()
        .await
        .expect("body");
    assert_eq!(list_resp["storage_backend"], "postgres");
    let count = list_resp["count"].as_u64().unwrap_or(0);
    assert!(
        count >= 1,
        "list_subscriptions must surface the just-registered subscription: {list_resp}"
    );

    shutdown.notify_one();
    let _ = handle.await;
}

// ===================================================================
// S58: cross-namespace dispatch on postgres
// ===================================================================

/// Cross-namespace dispatch: a subscription registered against
/// namespace X must remain visible to dispatchers cluster-wide even
/// after a `notify` lands in a *different* namespace `_inbox/Y`. The
/// substrate's cross-namespace contract on postgres is satisfied by
/// fanning the subscription memory under `_subscriptions/<aid>` out
/// to every peer — the dispatcher on any peer can then resolve the
/// subscription against any inbound event regardless of the event's
/// originating namespace.
///
/// This test exercises the full sequence:
///   1. Subscribe carol to namespace `target/observed`.
///   2. Verify the subscription memory fans to all peers.
///   3. Notify carol (lands in `_inbox/carol`, a *different*
///      namespace from `target/observed`).
///   4. Verify the inbox memory ALSO fans to all peers — proves the
///      shared-store cross-namespace plumbing operates end-to-end.
///
/// Pre-fix: postgres `notify` skipped fanout, so a cross-namespace
/// dispatch was a no-op on every peer except the leader.
/// Post-fix: every peer mirrors the inbox memory and the subscription
/// memory, closing the S58 gap.
#[tokio::test(flavor = "multi_thread")]
async fn cross_namespace_dispatch_on_postgres() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let peer1 = spawn_inproc_mock_peer().await;
    let peer2 = spawn_inproc_mock_peer().await;
    let peer3 = spawn_inproc_mock_peer().await;
    let peer_urls = vec![peer1.url.clone(), peer2.url.clone(), peer3.url.clone()];
    let cfg = federation_cfg_for_test(&peer_urls, 2);

    let (base, shutdown, handle) = spawn_daemon_with_federation(&url, Some(cfg)).await;
    // v1.0.0 #3140 — bounded: `reqwest::Client::new()` has no request timeout.
    let client = common::bounded_test_client();

    let carol = format!("ai:carol-{}", uuid::Uuid::new_v4());
    let target_ns = format!("target/observed-{}", uuid::Uuid::new_v4());

    // (1) Subscribe carol to the target namespace.
    let sub_body = json!({
        "agent_id": carol,
        "namespace": target_ns,
        "secret": "shared-xns-secret",
    });
    let sub_resp = client
        .post(format!("{base}/api/v1/subscriptions"))
        .header("x-agent-id", carol.as_str())
        .json(&sub_body)
        .send()
        .await
        .expect("subscribe post");
    assert_eq!(sub_resp.status(), reqwest::StatusCode::CREATED);

    let timeout = FANOUT_OBSERVED_TIMEOUT;
    assert!(
        wait_for_counter(&peer1.count, 1, timeout).await
            && wait_for_counter(&peer2.count, 1, timeout).await
            && wait_for_counter(&peer3.count, 1, timeout).await,
        "subscription fanout must reach every peer"
    );

    let subs_observed_on_p1 = peer1.count.load(Ordering::Relaxed);
    let subs_observed_on_p2 = peer2.count.load(Ordering::Relaxed);
    let subs_observed_on_p3 = peer3.count.load(Ordering::Relaxed);

    // (2) Notify carol — lands in `_inbox/carol`, NOT in
    // `target_ns`. This is the cross-namespace pivot: the
    // subscription namespace differs from the event namespace, but
    // the substrate's shared store must still surface both rows on
    // every peer.
    let notify_body = json!({
        "target_agent_id": carol,
        "title": "cross-namespace event",
        "payload": "event landed in _inbox/<carol>, NOT in target_ns",
        "priority": 7,
        "tier": "mid",
    });
    let notify_resp = client
        .post(format!("{base}/api/v1/notify"))
        .header("x-agent-id", "ai:alice-publisher")
        .json(&notify_body)
        .send()
        .await
        .expect("notify post");
    assert_eq!(notify_resp.status(), reqwest::StatusCode::CREATED);

    // Every peer must observe at least one ADDITIONAL POST beyond
    // the subscription fanout — the notify memory under
    // `_inbox/<carol>`.
    assert!(
        wait_for_counter(&peer1.count, subs_observed_on_p1 + 1, timeout).await,
        "peer-1 must observe the notify fanout in addition to the subscription"
    );
    assert!(
        wait_for_counter(&peer2.count, subs_observed_on_p2 + 1, timeout).await,
        "peer-2 must observe the notify fanout in addition to the subscription"
    );
    assert!(
        wait_for_counter(&peer3.count, subs_observed_on_p3 + 1, timeout).await,
        "peer-3 must observe the notify fanout in addition to the subscription"
    );

    // Wire-shape evidence: peer-1 saw BOTH the subscription row
    // (under `_subscriptions/<carol>`) AND the notify row (under
    // `_inbox/<carol>`). The two namespaces are distinct — this is
    // the cross-namespace property under test.
    let recorded = peer1.recorded.lock().await;
    let saw_subscription = recorded.iter().any(|p| {
        p.get("memories")
            .and_then(|m| m.as_array())
            .is_some_and(|arr| {
                arr.iter().any(|m| {
                    m.get("namespace")
                        .and_then(|n| n.as_str())
                        .is_some_and(|ns| ns == format!("_subscriptions/{carol}"))
                })
            })
    });
    let saw_inbox = recorded.iter().any(|p| {
        p.get("memories")
            .and_then(|m| m.as_array())
            .is_some_and(|arr| {
                arr.iter().any(|m| {
                    m.get("namespace")
                        .and_then(|n| n.as_str())
                        .is_some_and(|ns| ns == format!("_inbox/{carol}"))
                })
            })
    });
    assert!(
        saw_subscription,
        "peer-1 must have observed the subscription memory under `_subscriptions/<carol>`"
    );
    assert!(
        saw_inbox,
        "peer-1 must have observed the notify memory under `_inbox/<carol>`"
    );

    shutdown.notify_one();
    let _ = handle.await;
}

// ===================================================================
// #1480: create pipelines the peer broadcast with the local write
// ===================================================================

/// A postgres-backed `POST /api/v1/memories` (create) on a daemon with
/// three mock peers and `W=2` must:
///   (a) return `201 CREATED` with the new id,
///   (b) durably persist the row locally (GET-by-id round-trips),
///   (c) STILL fan the memory out to every peer.
///
/// This pins the #1480 quorum-write-pipelining restructure of
/// `handlers::create::create_memory_postgres`: the serial
/// `store → audit → dispatch → broadcast` block was replaced by a
/// `tokio::join!(store_fut, broadcast_store_quorum(fed, &mem))` so the
/// local fsync overlaps the peer RTT. The broadcast now fires
/// CONCURRENTLY with the local write rather than after it — this test
/// proves the restructure did not drop the fanout: every peer's
/// `sync_push` counter must still bump, AND the local write must still
/// be durable + retrievable. The id is a caller-generated UUID that
/// `store_with_embedding` RETURNs unchanged, so the pre-durability
/// broadcast body carries the same id the GET resolves.
#[tokio::test(flavor = "multi_thread")]
async fn create_postgres_pipelines_broadcast_with_local_write() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let peer1 = spawn_inproc_mock_peer().await;
    let peer2 = spawn_inproc_mock_peer().await;
    let peer3 = spawn_inproc_mock_peer().await;
    let peer_urls = vec![peer1.url.clone(), peer2.url.clone(), peer3.url.clone()];
    let cfg = federation_cfg_for_test(&peer_urls, 2);

    let (base, shutdown, handle) = spawn_daemon_with_federation(&url, Some(cfg)).await;
    // v1.0.0 #3140 — bounded: `reqwest::Client::new()` has no request timeout.
    let client = common::bounded_test_client();

    let agent = "ai:alice-create-pipeline";
    let title = format!("pipelined-create-{}", uuid::Uuid::new_v4());
    let ns = format!("team-{}", uuid::Uuid::new_v4());
    let body = json!({
        "title": title,
        "content": "body that rides the #1480 pipelined broadcast path",
        "namespace": ns,
        "tier": "mid",
        "priority": 5,
    });
    let resp = client
        .post(format!("{base}/api/v1/memories"))
        .header("x-agent-id", agent)
        .json(&body)
        .send()
        .await
        .expect("create post");
    // (a) 201 CREATED with the new id.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "pipelined create must 201: {resp:?}"
    );
    let resp_body: Value = resp.json().await.expect("create body");
    let new_id = resp_body["id"]
        .as_str()
        .expect("create must return id")
        .to_string();

    // (b) local write durably persisted — GET-by-id round-trips through
    // the postgres SAL `get` path (`{"memory": …, "links": …}`).
    let got: Value = client
        .get(format!("{base}/api/v1/memories/{new_id}"))
        .header("x-agent-id", agent)
        .send()
        .await
        .expect("get memory")
        .json()
        .await
        .expect("get body");
    assert_eq!(
        got["memory"]["id"].as_str(),
        Some(new_id.as_str()),
        "stored memory must be retrievable post-pipeline: {got}"
    );
    assert_eq!(
        got["memory"]["title"].as_str(),
        Some(title.as_str()),
        "retrieved memory title must match the created one: {got}"
    );

    // (c) the pipelined broadcast still fanned out to every peer. Post-
    // quorum straggler detach (the W=2 of N=4 policy) means peer-3
    // completes too even though quorum was met at peer-1+peer-2.
    let timeout = FANOUT_OBSERVED_TIMEOUT;
    let p1_ok = wait_for_counter(&peer1.count, 1, timeout).await;
    let p2_ok = wait_for_counter(&peer2.count, 1, timeout).await;
    let p3_ok = wait_for_counter(&peer3.count, 1, timeout).await;
    assert!(
        p1_ok && p2_ok && p3_ok,
        "pipelined create must still broadcast to every peer: p1={} p2={} p3={}",
        peer1.count.load(Ordering::Relaxed),
        peer2.count.load(Ordering::Relaxed),
        peer3.count.load(Ordering::Relaxed),
    );

    // Wire-shape: the broadcast body carried the just-created memory by
    // the SAME id the GET resolved — proving the pre-durability
    // broadcast and the durable local row reference one identity.
    let recorded = peer1.recorded.lock().await;
    let saw_created = recorded.iter().any(|p| {
        p.get("memories")
            .and_then(|m| m.as_array())
            .is_some_and(|arr| {
                arr.iter().any(|m| {
                    m.get("id").and_then(|i| i.as_str()) == Some(new_id.as_str())
                        && m.get("title").and_then(|t| t.as_str()) == Some(title.as_str())
                })
            })
    });
    assert!(
        saw_created,
        "peer-1 must have received the created memory (id={new_id}) in a sync_push body"
    );

    shutdown.notify_one();
    let _ = handle.await;
}

// ===================================================================
// #2724 (CB-22): bulk_create fans out to peers on postgres
// ===================================================================

/// PARENT: `bulk_create_postgres` ended at the batched `store_batch` with NO
/// `broadcast_store_quorum` / `bulk_catchup_push`, so a postgres daemon
/// configured with `--quorum-peers` silently did NOT replicate rows written
/// through `POST /api/v1/memories/bulk` — while the single-create postgres path
/// (`create_postgres_pipelines_broadcast_with_local_write` above) and the
/// sqlite bulk branch both fanned out. #2724 shares ONE fanout helper across
/// both backends, so a bulk load now reaches every peer.
#[tokio::test(flavor = "multi_thread")]
async fn bulk_create_postgres_fans_out_to_peers_2724() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    common::permissive_attestation_for_tests();

    let peer1 = spawn_inproc_mock_peer().await;
    let peer2 = spawn_inproc_mock_peer().await;
    let peer3 = spawn_inproc_mock_peer().await;
    let peer_urls = vec![peer1.url.clone(), peer2.url.clone(), peer3.url.clone()];
    let cfg = federation_cfg_for_test(&peer_urls, 2);

    let (base, shutdown, handle) = spawn_daemon_with_federation(&url, Some(cfg)).await;
    // v1.0.0 #3140 — bounded: `reqwest::Client::new()` has no request timeout.
    let client = common::bounded_test_client();

    let agent = "ai:alice-bulk-fanout";
    let ns = format!("bulk-2724-{}", uuid::Uuid::new_v4());
    let titles: Vec<String> = (0..3)
        .map(|i| format!("bulk-row-{i}-{}", uuid::Uuid::new_v4()))
        .collect();
    let batch: Vec<Value> = titles
        .iter()
        .map(|t| {
            json!({
                "title": t,
                "content": "bulk row that must fan out post-#2724",
                "namespace": ns,
                "tier": "mid",
                "priority": 5,
            })
        })
        .collect();

    let resp = client
        .post(format!("{base}/api/v1/memories/bulk"))
        .header("x-agent-id", agent)
        .json(&Value::Array(batch))
        .send()
        .await
        .expect("bulk post");
    // A clean batch of 3 distinct rows is a 200 with created == 3.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "bulk must 200: {resp:?}"
    );
    let body: Value = resp.json().await.expect("bulk body");
    assert_eq!(body["created"], 3, "3 distinct rows created: {body}");

    // Every peer must observe the bulk fanout (per-row broadcast + terminal
    // catchup). Straggler detach (W=2 of N=4) completes every peer.
    let timeout = FANOUT_OBSERVED_TIMEOUT;
    assert!(
        wait_for_counter(&peer1.count, 1, timeout).await
            && wait_for_counter(&peer2.count, 1, timeout).await
            && wait_for_counter(&peer3.count, 1, timeout).await,
        "every peer must observe the bulk fanout: p1={} p2={} p3={}",
        peer1.count.load(Ordering::Relaxed),
        peer2.count.load(Ordering::Relaxed),
        peer3.count.load(Ordering::Relaxed),
    );

    // Wire-shape: every one of the three bulk rows reached peer-1 (across the
    // per-row broadcasts and/or the terminal catchup batch).
    let recorded = peer1.recorded.lock().await;
    for t in &titles {
        let seen = recorded.iter().any(|p| {
            p.get("memories")
                .and_then(|m| m.as_array())
                .is_some_and(|arr| {
                    arr.iter()
                        .any(|m| m.get("title").and_then(|x| x.as_str()) == Some(t.as_str()))
                })
        });
        assert!(
            seen,
            "peer-1 must have received bulk row `{t}` in a sync_push body"
        );
    }

    shutdown.notify_one();
    let _ = handle.await;
}

// ===================================================================
// #2860 / #1552 (CB-2860): POST /api/v1/consolidate fans out on postgres
// ===================================================================

/// PARENT (`handlers::power_consolidation::consolidate_memories`, the
/// postgres branch, lines ~466-527): the SAL-ported postgres consolidate
/// arm minted the substrate-derived row and returned WITHOUT broadcasting
/// — a `POST /api/v1/consolidate` against a federated postgres daemon
/// landed the consolidation only locally, so peers never converged the new
/// row or the tombstoned sources.
///
/// Post-#2860 the postgres branch authors the derived row as the daemon's
/// federation identity (`fed.sender_agent_id`, self-relay past strict
/// write-sig), reads it back AS that author, runs the shared
/// `store_finalize_and_disposition` (postgres twin of the sqlite
/// finalize+disposition), and broadcasts it + its source disposition +
/// `derived_from` lineage through `consolidate_fanout`. This test pins the
/// quorum-MET arm: two mock peers ack (`W=2`, `record_local` + two peer
/// acks), so `finalise_quorum` succeeds, the handler returns `201 CREATED`,
/// and every peer's `sync_push` counter bumps for the consolidated row.
#[tokio::test(flavor = "multi_thread")]
async fn consolidate_fanout_postgres_quorum_met_2860() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    common::permissive_attestation_for_tests();

    let peer1 = spawn_inproc_mock_peer().await;
    let peer2 = spawn_inproc_mock_peer().await;
    let peer_urls = vec![peer1.url.clone(), peer2.url.clone()];
    let cfg = federation_cfg_for_test(&peer_urls, 2);

    let (base, shutdown, handle) = spawn_daemon_with_federation(&url, Some(cfg)).await;
    let client = common::bounded_test_client();

    let agent = "ai:alice-consolidate-fanout";
    let ns = format!("consol-2860-{}", uuid::Uuid::new_v4());
    let mut ids = Vec::new();
    for i in 0..2 {
        let body = json!({
            "title": format!("consol-src-{i}-{}", uuid::Uuid::new_v4()),
            "content": format!("source row {i} with enough body length to consolidate"),
            "namespace": ns,
            "tier": "mid",
            "priority": 5,
        });
        let resp = client
            .post(format!("{base}/api/v1/memories"))
            .header("x-agent-id", agent)
            .json(&body)
            .send()
            .await
            .expect("create source post");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::CREATED,
            "source create must 201: {resp:?}"
        );
        let rb: Value = resp.json().await.expect("create body");
        ids.push(
            rb["id"]
                .as_str()
                .expect("create must return id")
                .to_string(),
        );
    }
    // Drain the per-create broadcasts so the counter assertion below is
    // unambiguously attributable to the consolidate fanout.
    let create_timeout = FANOUT_OBSERVED_TIMEOUT;
    assert!(
        wait_for_counter(&peer1.count, 1, create_timeout).await,
        "peer-1 should have observed the source-create fanout first"
    );
    let p1_after_creates = peer1.count.load(Ordering::Relaxed);
    let p2_after_creates = peer2.count.load(Ordering::Relaxed);

    let resp = client
        .post(format!("{base}/api/v1/consolidate"))
        .header("x-agent-id", agent)
        .json(&json!({
            "ids": ids,
            "title": "Consolidated postgres-federated facts",
            "summary": "operator-supplied consolidation summary of sufficient length",
            "namespace": ns,
            "tier": "long",
        }))
        .send()
        .await
        .expect("consolidate post");
    // Quorum met (record_local + two peer acks >= W=2) → 201 CREATED.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "federated postgres consolidate with quorum met must 201: {resp:?}"
    );
    let cbody: Value = resp.json().await.expect("consolidate body");
    assert!(
        cbody["id"].is_string(),
        "consolidate must return the derived row id: {cbody}"
    );
    assert_eq!(
        cbody["consolidated"], 2,
        "two sources consolidated: {cbody}"
    );
    let derived_id = cbody["id"].as_str().unwrap().to_string();

    // The consolidated row (and its source disposition) fanned out: each
    // peer observed at least one MORE sync_push after the create drain.
    let timeout = FANOUT_OBSERVED_TIMEOUT;
    assert!(
        wait_for_counter(&peer1.count, p1_after_creates + 1, timeout).await
            && wait_for_counter(&peer2.count, p2_after_creates + 1, timeout).await,
        "both peers must observe the consolidate fanout: p1={} (was {p1_after_creates}) p2={} (was {p2_after_creates})",
        peer1.count.load(Ordering::Relaxed),
        peer2.count.load(Ordering::Relaxed),
    );

    // Wire-shape: peer-1 received the derived consolidation row by id.
    let recorded = peer1.recorded.lock().await;
    let saw_derived = recorded.iter().any(|p| {
        p.get("memories")
            .and_then(|m| m.as_array())
            .is_some_and(|arr| {
                arr.iter()
                    .any(|m| m.get("id").and_then(|i| i.as_str()) == Some(derived_id.as_str()))
            })
    });
    assert!(
        saw_derived,
        "peer-1 must have received the derived consolidation row (id={derived_id}) in a sync_push body"
    );
    drop(recorded);

    shutdown.notify_one();
    let _ = handle.await;
}

/// PARENT (`consolidate_fanout` -> `finalise_quorum` miss arm, and the
/// postgres branch that returns it): when a federated postgres consolidate
/// CANNOT reach quorum (peer down / partition), the handler must not shape
/// the local-only write as a success. Post-#2861/#2860 it returns the
/// id-bearing `202` `under_replicated_consolidate_response` so the caller
/// can DISCOVER and reconcile the local row, rather than a success-shaped
/// 2xx with nothing to act on.
///
/// One unreachable peer (bound to a free port with no listener) with `W=2`
/// makes quorum unreachable (`record_local` = 1 < 2), so `finalise_quorum`
/// returns the quorum-not-met error and the handler emits the 202.
#[tokio::test(flavor = "multi_thread")]
async fn consolidate_fanout_postgres_under_replicated_is_202_2861() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    common::permissive_attestation_for_tests();

    // A dead peer: a free port with nothing listening → connection refused
    // → AckOutcome::Fail, so W=2 is never reached.
    let dead_url = format!("http://127.0.0.1:{}", free_port());
    let cfg = federation_cfg_for_test(&[dead_url], 2);

    let (base, shutdown, handle) = spawn_daemon_with_federation(&url, Some(cfg)).await;
    let client = common::bounded_test_client();

    let agent = "ai:alice-consolidate-underrep";
    let ns = format!("consol-2861-{}", uuid::Uuid::new_v4());
    // Seed the sources DIRECTLY (not via HTTP): on this dead-peer / W=2 daemon
    // an HTTP create would ITSELF under-replicate (202, no top-level id), so we
    // bypass the create-fanout and drive ONLY the consolidate through the
    // quorum-miss arm under test.
    let mut ids = Vec::new();
    for i in 0..2 {
        let title = format!("underrep-src-{i}-{}", uuid::Uuid::new_v4());
        ids.push(seed_source_row(&url, agent, &ns, &title).await);
    }

    let resp = client
        .post(format!("{base}/api/v1/consolidate"))
        .header("x-agent-id", agent)
        .json(&json!({
            "ids": ids,
            "title": "Under-replicated consolidation",
            "summary": "operator-supplied summary of sufficient length for the row",
            "namespace": ns,
            "tier": "long",
        }))
        .send()
        .await
        .expect("consolidate post");
    // Quorum unreachable → id-bearing 202 ACCEPTED (not a success 2xx).
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::ACCEPTED,
        "under-replicated federated postgres consolidate must 202: {resp:?}"
    );
    let cbody: Value = resp.json().await.expect("consolidate body");
    assert!(
        cbody["id"].is_string(),
        "the 202 must still carry the created row id for reconciliation: {cbody}"
    );

    shutdown.notify_one();
    let _ = handle.await;
}
