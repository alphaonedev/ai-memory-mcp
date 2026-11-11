// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc
)]
//! #8741 fed-delivery, push half (#9087 #9005 #9023 #9057 #9052).
//!
//! Class invariant: every HTTP mutation that commits locally delivers the
//! SAME effect to the federation peers through the one funnel
//! (`handlers::fed_fanout`), on SQLite AND PostgreSQL, and reports the real
//! quorum (`quorum_acks` / `quorum_n` / `quorum_required`). A quorum miss is
//! the exact `202` with `quorum_met: false`, never a silent success.
//! Deletions and erasures travel as `sync_push.deletions` tombstones.
//! Consolidate finalize finds its tombstoned sources and never falls back to
//! fanning out hard deletions.
//!
//! Ordering without sleeps: one recording peer with `W = 2` (`N = 2`), so
//! the quorum needs the peer's ack. The mock peer records the body BEFORE it
//! acks, so the recording is complete when the origin's HTTP response
//! returns.
//!
//! The registry walk (`every_mutating_route_has_a_fanout_row_8741`) parses
//! the router source and fails for any mutating registration without a row,
//! so a new write route cannot ship without deciding its federation effect.

#![cfg(feature = "sal")]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::handlers::routes;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::write_receipt::{QUORUM_ACKS_FIELD, QUORUM_N_FIELD, QUORUM_REQUIRED_FIELD};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

mod common;

/// Origin + one peer.
const QUORUM_N: usize = 2;
/// Both must ack, so the response implies the peer recorded the body.
const QUORUM_W: usize = 2;
/// The admin agent every cell acts as (bulk forget is admin-only).
const ADMIN_AGENT: &str = "ai:fedpush-8741-admin";
/// Peer ack / connect timeout.
const PEER_TIMEOUT: Duration = Duration::from_secs(2);
/// Rows a bulk-forget cell erases (plus one survivor in another namespace).
const FORGET_VICTIMS: usize = 3;
/// Sources one consolidate cell merges.
const CONSOLIDATE_SOURCES: usize = 2;
/// The link relation the link cell creates.
const LINK_RELATION: &str = "related_to";
/// The peer status that makes a cell miss quorum.
const PEER_FAIL_STATUS: StatusCode = StatusCode::SERVICE_UNAVAILABLE;
/// The under-replication status (W3 / G12: local row durable, peers short).
const UNDER_REPLICATED: StatusCode = StatusCode::ACCEPTED;

// ---------------------------------------------------------------------------
// Recording mock peer with a fail switch
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockPeer {
    url: String,
    recorded: Arc<Mutex<Vec<Value>>>,
    fail: Arc<AtomicBool>,
}

async fn spawn_peer() -> MockPeer {
    use axum::{Json as AxumJson, Router, extract::State, routing::post};

    #[derive(Clone)]
    struct PeerState {
        recorded: Arc<Mutex<Vec<Value>>>,
        fail: Arc<AtomicBool>,
    }

    async fn handler(
        State(state): State<PeerState>,
        AxumJson(payload): AxumJson<Value>,
    ) -> (StatusCode, AxumJson<Value>) {
        if state.fail.load(Ordering::Acquire) {
            return (PEER_FAIL_STATUS, AxumJson(json!({"error": "peer down"})));
        }
        state.recorded.lock().await.push(payload);
        (
            StatusCode::OK,
            AxumJson(json!({"applied": 1, "noop": 0, "skipped": 0})),
        )
    }

    let recorded: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let app = Router::new()
        .route(routes::SYNC_PUSH, post(handler))
        .with_state(PeerState {
            recorded: recorded.clone(),
            fail: fail.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock peer");
    let addr = listener.local_addr().expect("peer addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    MockPeer {
        url: format!("http://{addr}"),
        recorded,
        fail,
    }
}

fn federation_cfg(peer: &MockPeer) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let client = reqwest::Client::builder()
        .timeout(PEER_TIMEOUT)
        .connect_timeout(PEER_TIMEOUT)
        .build()
        .expect("peer client");
    let policy = ai_memory::replication::QuorumPolicy::new(
        QUORUM_N,
        QUORUM_W,
        PEER_TIMEOUT,
        Duration::from_secs(30),
    )
    .expect("quorum policy");
    FederationConfig {
        policy,
        peers: vec![PeerEndpoint {
            id: "peer-0".to_string(),
            sync_push_url: format!("{}{}", peer.url, routes::SYNC_PUSH),
        }],
        client,
        sender_agent_id: ADMIN_AGENT.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

// ---------------------------------------------------------------------------
// Origin (in-process router) per backend
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Backend {
    Sqlite,
    #[cfg(feature = "sal-postgres")]
    Postgres,
}

fn app_state(
    db: Db,
    store: Arc<dyn ai_memory::store::MemoryStore>,
    backend: Backend,
    fed: FederationConfig,
) -> AppState {
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(Some(fed)),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: match backend {
            Backend::Sqlite => StorageBackend::Sqlite,
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres => StorageBackend::Postgres,
        },
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
        admin_agent_ids: Arc::new(vec![ADMIN_AGENT.to_string()]),
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

struct Origin {
    router: axum::Router,
    peer: MockPeer,
    ns: String,
    _db_file: Option<tempfile::NamedTempFile>,
}

fn api_key_state() -> ApiKeyState {
    ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    }
}

fn process_setup() {
    // Authenticated-deployment posture so the admin header claim is honoured
    // (same as tests/admin_run_gc_require_admin_1027.rs).
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    common::permissive_attestation_for_tests();
    // #9057 runs in the tombstone disposition (sources retained as
    // Tombstoned, re-broadcast, never hard-deleted at peers).
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
}

/// `None` when the backend is not available in this run (PG URL unset).
async fn origin(backend: Backend) -> Option<Origin> {
    process_setup();
    let peer = spawn_peer().await;
    let fed = federation_cfg(&peer);
    let ns = format!("fedpush-8741-{}", uuid::Uuid::new_v4());
    match backend {
        Backend::Sqlite => {
            let f = tempfile::NamedTempFile::new().expect("tempfile");
            let path = f.path().to_path_buf();
            let conn = ai_memory::db::open(&path).expect("db::open");
            let db: Db = Arc::new(Mutex::new((
                conn,
                path.clone(),
                ResolvedTtl::default(),
                true,
            )));
            let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
                ai_memory::store::sqlite::SqliteStore::open(&path).expect("SqliteStore::open"),
            );
            let router =
                ai_memory::build_router(api_key_state(), app_state(db, store, backend, fed));
            Some(Origin {
                router,
                peer,
                ns,
                _db_file: Some(f),
            })
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres => {
            let url = common::postgres_url()?;
            let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch");
            let db: Db = Arc::new(Mutex::new((
                conn,
                std::path::PathBuf::from(":memory:"),
                ResolvedTtl::default(),
                true,
            )));
            let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
                ai_memory::store::postgres::PostgresStore::connect(&url)
                    .await
                    .expect("PostgresStore::connect"),
            );
            let router =
                ai_memory::build_router(api_key_state(), app_state(db, store, backend, fed));
            Some(Origin {
                router,
                peer,
                ns,
                _db_file: None,
            })
        }
    }
}

impl Origin {
    async fn call(&self, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-agent-id", ADMIN_AGENT)
            .header("content-type", "application/json");
        if body.is_none() {
            req = req.header("content-length", "0");
        }
        let req = req
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .expect("request");
        let resp = self.router.clone().oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    async fn create(&self, ns: &str, title: &str) -> String {
        // Titles are unique per (namespace, title); every cell runs twice.
        let title = format!("{title}-{}", uuid::Uuid::new_v4());
        let (status, body) = self
            .call(
                Method::POST,
                routes::MEMORIES,
                Some(json!({
                    "title": title,
                    "content": format!("{title} body with enough length for every op"),
                    "namespace": ns,
                    "tier": "mid",
                    "priority": 5,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed create: {body}");
        body["id"].as_str().expect("create id").to_string()
    }

    async fn mark(&self) -> usize {
        self.peer.recorded.lock().await.len()
    }

    async fn since(&self, mark: usize) -> Vec<Value> {
        self.peer.recorded.lock().await[mark..].to_vec()
    }
}

fn path_with_id(template: &str, id: &str) -> String {
    template.replace("{id}", id)
}

/// Every string in `bodies[*][field]` (string arrays: deletions / archives /
/// restores).
fn ids_in(bodies: &[Value], field: &str) -> BTreeSet<String> {
    bodies
        .iter()
        .filter_map(|b| b.get(field).and_then(Value::as_array))
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Every `memories[*]` row shipped.
fn memories_in(bodies: &[Value]) -> Vec<Value> {
    bodies
        .iter()
        .filter_map(|b| b.get("memories").and_then(Value::as_array))
        .flatten()
        .cloned()
        .collect()
}

fn assert_quorum_met(label: &str, status: StatusCode, receipt: &Value) {
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{label}: quorum met must be a 2xx success, got {status}: {receipt}"
    );
    assert_eq!(
        receipt[QUORUM_ACKS_FIELD],
        json!(QUORUM_N),
        "{label}: {receipt}"
    );
    assert_eq!(
        receipt[QUORUM_N_FIELD],
        json!(QUORUM_N),
        "{label}: {receipt}"
    );
    assert_eq!(
        receipt[QUORUM_REQUIRED_FIELD],
        json!(QUORUM_W),
        "{label}: {receipt}"
    );
}

fn assert_under_replicated(label: &str, status: StatusCode, receipt: &Value) {
    assert_eq!(status, UNDER_REPLICATED, "{label}: {receipt}");
    assert_eq!(receipt["quorum_met"], json!(false), "{label}: {receipt}");
}

// ---------------------------------------------------------------------------
// The op x backend table
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Op {
    Update,
    Delete,
    Promote,
    Link,
    Archive,
    Restore,
    Forget,
    Consolidate,
}

/// Run one cell. `peer_down` flips the mock peer to 503 right before the op
/// (seeding always runs with the peer up).
async fn run_cell(o: &Origin, op: Op, peer_down: bool) {
    let label = format!("{op:?} peer_down={peer_down}");
    let ns = o.ns.clone();
    let (status, body) = match op {
        Op::Update => {
            let id = o.create(&ns, "upd").await;
            let new_content = format!("updated content {}", uuid::Uuid::new_v4());
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(
                    Method::PUT,
                    &path_with_id(routes::MEMORIES_ID, &id),
                    Some(json!({"content": new_content})),
                )
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                return assert_under_replicated(&label, status, &body);
            }
            let rows = memories_in(&o.since(mark).await);
            assert!(
                rows.iter()
                    .any(|m| m["id"] == json!(id) && m["content"] == json!(new_content)),
                "{label}: peer must receive the updated row {id}: {rows:?}"
            );
            (status, body)
        }
        Op::Delete => {
            let id = o.create(&ns, "del").await;
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(
                    Method::DELETE,
                    &path_with_id(routes::MEMORIES_ID, &id),
                    None,
                )
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                return assert_under_replicated(&label, status, &body);
            }
            let deleted = ids_in(&o.since(mark).await, "deletions");
            assert_eq!(deleted, BTreeSet::from([id]), "{label}");
            (status, body)
        }
        Op::Promote => {
            let id = o.create(&ns, "promo").await;
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(
                    Method::POST,
                    &path_with_id(routes::MEMORIES_ID_PROMOTE, &id),
                    None,
                )
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                return assert_under_replicated(&label, status, &body);
            }
            let rows = memories_in(&o.since(mark).await);
            assert!(
                rows.iter()
                    .any(|m| m["id"] == json!(id) && m["tier"] == json!("long")),
                "{label}: peer must receive the promoted row {id}: {rows:?}"
            );
            (status, body)
        }
        Op::Link => {
            let a = o.create(&ns, "link-a").await;
            let b = o.create(&ns, "link-b").await;
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(
                    Method::POST,
                    routes::LINKS,
                    Some(json!({"source_id": a, "target_id": b, "relation": LINK_RELATION})),
                )
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                return assert_under_replicated(&label, status, &body);
            }
            let bodies = o.since(mark).await;
            let shipped = bodies
                .iter()
                .filter_map(|p| p.get("links").and_then(Value::as_array))
                .flatten()
                .any(|l| {
                    l["source_id"] == json!(a)
                        && l["target_id"] == json!(b)
                        && l["relation"] == json!(LINK_RELATION)
                });
            assert!(shipped, "{label}: peer must receive the link: {bodies:?}");
            (status, body)
        }
        Op::Archive => {
            let id = o.create(&ns, "arch").await;
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(Method::POST, routes::ARCHIVE, Some(json!({"ids": [id]})))
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                return assert_under_replicated(&label, status, &body);
            }
            assert_eq!(
                ids_in(&o.since(mark).await, "archives"),
                BTreeSet::from([id]),
                "{label}"
            );
            (status, body)
        }
        Op::Restore => {
            let id = o.create(&ns, "rest").await;
            let (status, body) = o
                .call(Method::POST, routes::ARCHIVE, Some(json!({"ids": [id]})))
                .await;
            assert!(
                status.is_success(),
                "restore seed archive: {status}: {body}"
            );
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(
                    Method::POST,
                    &path_with_id(routes::ARCHIVE_ID_RESTORE, &id),
                    None,
                )
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                return assert_under_replicated(&label, status, &body);
            }
            assert_eq!(
                ids_in(&o.since(mark).await, "restores"),
                BTreeSet::from([id]),
                "{label}"
            );
            (status, body)
        }
        Op::Forget => {
            // A namespace of its own: the bulk erase must hit exactly these rows.
            let ns = format!("{ns}-forget-{}", uuid::Uuid::new_v4());
            let mut victims = BTreeSet::new();
            for i in 0..FORGET_VICTIMS {
                victims.insert(o.create(&ns, &format!("forget-{i}")).await);
            }
            let other_ns = format!("{ns}-survivor");
            let survivor = o.create(&other_ns, "survivor").await;
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(Method::POST, routes::FORGET, Some(json!({"namespace": ns})))
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                return assert_under_replicated(&label, status, &body);
            }
            assert_eq!(body["deleted"], json!(FORGET_VICTIMS), "{label}: {body}");
            let erased = ids_in(&o.since(mark).await, "deletions");
            assert_eq!(
                erased, victims,
                "{label}: peers must erase exactly the origin's erased set"
            );
            assert!(!erased.contains(&survivor), "{label}: survivor erased");
            (status, body)
        }
        Op::Consolidate => {
            let mut sources = Vec::new();
            for i in 0..CONSOLIDATE_SOURCES {
                sources.push(o.create(&ns, &format!("consol-{i}")).await);
            }
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(
                    Method::POST,
                    routes::CONSOLIDATE,
                    Some(json!({
                        "ids": sources,
                        "title": format!("fedpush 8741 consolidated {}", uuid::Uuid::new_v4()),
                        "summary": "caller supplied consolidation summary of enough length",
                        "namespace": ns,
                        "tier": "long",
                    })),
                )
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                assert_under_replicated(&label, status, &body);
                assert!(
                    body["id"].is_string(),
                    "{label}: 202 names the local row: {body}"
                );
                return;
            }
            let derived = body["id"].as_str().expect("derived id").to_string();
            let bodies = o.since(mark).await;
            let shipped: BTreeSet<String> = memories_in(&bodies)
                .iter()
                .filter_map(|m| m["id"].as_str().map(str::to_string))
                .collect();
            assert!(
                shipped.contains(&derived),
                "{label}: derived row shipped: {bodies:?}"
            );
            for src in &sources {
                assert!(
                    shipped.contains(src),
                    "{label}: tombstoned source {src} re-broadcast: {bodies:?}"
                );
            }
            let deleted = ids_in(&bodies, "deletions");
            assert!(
                deleted.is_empty(),
                "{label}: tombstone disposition must never fan out hard deletions: {deleted:?}"
            );
            (status, body)
        }
    };
    // Peer state first, then the receipt: a red cell names the missing effect.
    assert_quorum_met(&label, status, &body);
}

/// One cell: the op with the peer up (quorum met, peer state asserted),
/// then with the peer down (the exact 202).
async fn run_op(backend: Backend, op: Op) {
    let Some(o) = origin(backend).await else {
        eprintln!("skip {backend:?}: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    run_cell(&o, op, false).await;
    run_cell(&o, op, true).await;
}

/// One named test per (backend, op) so a red names its cell.
macro_rules! op_cells {
    ($($name:ident => $op:expr),+ $(,)?) => {
        mod sqlite_cells {
            use super::*;
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    run_op(Backend::Sqlite, $op).await;
                }
            )+
        }
        #[cfg(feature = "sal-postgres")]
        mod postgres_cells {
            use super::*;
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    run_op(Backend::Postgres, $op).await;
                }
            )+
        }
    };
}

op_cells! {
    update_9087 => Op::Update,
    delete_9005 => Op::Delete,
    promote_9087 => Op::Promote,
    link_create_9087 => Op::Link,
    archive_9052 => Op::Archive,
    restore_9052 => Op::Restore,
    bulk_forget_9023 => Op::Forget,
    consolidate_9057 => Op::Consolidate,
}

// ---------------------------------------------------------------------------
// Registry walk: every mutating route has a federation row
// ---------------------------------------------------------------------------

/// What a mutating route delivers to peers.
#[derive(Debug)]
enum Fed {
    /// Fans out through the funnel (or the write-receipt path), pinned above
    /// or by a named existing test.
    Fanout,
    /// No durable mutation (read, query, verify, compute).
    ReadOnly,
    /// The receive side of federation itself.
    Receive,
    /// A filed fed-delivery finding (issue number).
    Pending(u32),
}

/// `(method, route const, row)`. The key is the route const as written in
/// `src/lib.rs` (two consts can share one handler).
const ROWS: &[(&str, &str, Fed)] = &[
    ("post", "MEMORIES", Fed::Fanout),
    ("post", "ACTIONS_ID_TRANSITION", Fed::Fanout),
    ("post", "SIGNALS", Fed::Fanout),
    ("post", "CHECKPOINTS_ID_RESOLVE", Fed::Fanout),
    ("post", "MEMORIES_BULK", Fed::Fanout),
    ("put", "MEMORIES_ID", Fed::Fanout),
    ("delete", "MEMORIES_ID", Fed::Fanout),
    ("post", "MEMORIES_ID_PROMOTE", Fed::Fanout),
    ("post", "CAPTURE_TURN", Fed::Pending(9153)),
    ("post", "RECALL", Fed::ReadOnly),
    ("post", "FORGET", Fed::Fanout),
    ("post", "CONSOLIDATE", Fed::Fanout),
    ("post", "AUTO_TAG", Fed::Pending(9158)),
    ("post", "EXPAND_QUERY", Fed::ReadOnly),
    ("post", "MEMORY_LOAD_FAMILY", Fed::ReadOnly),
    ("post", "LINKS", Fed::Fanout),
    ("delete", "LINKS", Fed::Pending(9154)),
    ("post", "NAMESPACES", Fed::Pending(9152)),
    ("delete", "NAMESPACES", Fed::Pending(9152)),
    ("post", "NAMESPACES_NS_STANDARD", Fed::Pending(9152)),
    ("delete", "NAMESPACES_NS_STANDARD", Fed::Pending(9152)),
    ("post", "CHECK_DUPLICATE", Fed::ReadOnly),
    ("post", "ENTITIES", Fed::Pending(9153)),
    ("post", "KG_INVALIDATE", Fed::Pending(9154)),
    ("post", "KG_QUERY", Fed::ReadOnly),
    ("post", "KG_FIND_PATHS", Fed::ReadOnly),
    ("post", "FIND_PATHS", Fed::ReadOnly),
    ("post", "LINKS_VERIFY", Fed::ReadOnly),
    ("post", "QUOTA_STATUS", Fed::ReadOnly),
    ("post", "ADMIN_QUARANTINE_ID_RELEASE", Fed::Pending(9154)),
    ("post", "GC", Fed::Pending(9154)),
    ("post", "IMPORT", Fed::Pending(9153)),
    ("post", "ARCHIVE", Fed::Fanout),
    ("delete", "ARCHIVE", Fed::Pending(9154)),
    ("post", "ARCHIVE_ID_RESTORE", Fed::Fanout),
    ("post", "AGENTS", Fed::Pending(9152)),
    ("put", "AGENTS_ID_PUBKEY", Fed::Pending(9158)),
    ("post", "AGENTS_ID_PUBKEY_CHALLENGE", Fed::Pending(9158)),
    ("post", "AGENTS_ID_API_KEY", Fed::Pending(9158)),
    ("post", "AGENTS_ID_API_KEY_REVOKE", Fed::Pending(9158)),
    ("post", "PENDING_ID_APPROVE", Fed::Pending(9152)),
    ("post", "PENDING_ID_REJECT", Fed::Pending(9152)),
    ("post", "APPROVALS_PENDING_ID", Fed::Pending(9152)),
    ("post", "SYNC_PUSH", Fed::Receive),
    ("post", "NOTIFY", Fed::Fanout),
    ("post", "A2A", Fed::Pending(9158)),
    ("post", "SUBSCRIPTIONS", Fed::Fanout),
    ("delete", "SUBSCRIPTIONS", Fed::Pending(9158)),
    ("post", "SESSION_START", Fed::Pending(9158)),
    ("post", "SKILL_REGISTER", Fed::Pending(9158)),
    ("delete", "SKILL_ID", Fed::Pending(9158)),
    ("post", "SKILL_ID_EXPORT", Fed::ReadOnly),
    ("post", "SKILL_ID_PROMOTE", Fed::Pending(9158)),
    ("post", "SKILL_ID_COMPOSE", Fed::Pending(9158)),
    ("post", "SKILL_ID_RETIRE", Fed::Pending(9158)),
    ("post", "SHARE", Fed::Pending(9158)),
    ("post", "MEMORY_SMART_LOAD", Fed::ReadOnly),
    ("post", "MEMORY_REFLECT", Fed::Fanout),
    ("post", "MEMORY_RECALL_OBSERVATIONS", Fed::ReadOnly),
    ("post", "MEMORY_REFLECTION_ORIGIN", Fed::ReadOnly),
    ("post", "MEMORY_DEPENDENTS_OF_INVALIDATED", Fed::ReadOnly),
    ("post", "MEMORY_EXPORT_REFLECTION", Fed::ReadOnly),
    ("post", "MEMORY_ATOMISE", Fed::Pending(9158)),
    ("post", "MEMORY_CALIBRATE_CONFIDENCE", Fed::Pending(9158)),
    ("post", "MEMORY_SWARM_REWIND", Fed::Pending(9154)),
    ("post", "MEMORY_VERIFY", Fed::ReadOnly),
    ("post", "MEMORY_REPLAY", Fed::Pending(9158)),
    ("post", "MEMORY_SUBSCRIPTION_REPLAY", Fed::Pending(9158)),
    ("post", "MEMORY_SUBSCRIPTION_DLQ_LIST", Fed::ReadOnly),
    ("post", "MEMORY_RULE_LIST", Fed::ReadOnly),
    ("post", "MEMORY_CHECK_AGENT_ACTION", Fed::ReadOnly),
];

const MUTATING_METHODS: [&str; 4] = ["post", "put", "delete", "patch"];
const ROUTER_FN: &str = "pub fn build_router_with_timeout(";
const ROUTE_CALL: &str = ".route(";
const ROUTES_PREFIX: &str = "handlers::routes::";

/// Remove `//` line comments (a commented-out registration is not live).
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| l.find("//").map_or(l, |i| &l[..i]))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The argument text of a call whose `(` was just consumed, up to the
/// matching `)`.
fn balanced(s: &str) -> Option<&str> {
    let mut depth = 1_usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[..i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// `(method, route const)` for every mutating registration.
fn mutating_registrations(lib_rs: &str) -> Vec<(String, String)> {
    let start = lib_rs.find(ROUTER_FN).expect("router fn present");
    let body = strip_line_comments(&lib_rs[start..]);
    let end = body.find("\n}\n").expect("router fn end");
    let body = &body[..end];
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find(ROUTE_CALL) {
        let args_start = &rest[at + ROUTE_CALL.len()..];
        let args = balanced(args_start).expect("balanced .route(");
        let path = args
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_start_matches(ROUTES_PREFIX)
            .to_string();
        let bytes = args.as_bytes();
        for method in MUTATING_METHODS {
            let needle = format!("{method}(");
            let mut from = 0;
            while let Some(rel) = args[from..].find(&needle) {
                let pos = from + rel;
                let ident_before =
                    pos > 0 && (bytes[pos - 1].is_ascii_alphanumeric() || bytes[pos - 1] == b'_');
                if !ident_before {
                    out.push((method.to_string(), path.clone()));
                }
                from = pos + needle.len();
            }
        }
        rest = &args_start[args.len()..];
    }
    out
}

#[test]
fn every_mutating_route_has_a_fanout_row_8741() {
    let lib_rs = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("read src/lib.rs");
    let live: BTreeSet<(String, String)> = mutating_registrations(&lib_rs).into_iter().collect();
    assert!(!live.is_empty(), "router scan found no mutating routes");
    let table: BTreeSet<(String, String)> = ROWS
        .iter()
        .map(|(m, p, _)| ((*m).to_string(), (*p).to_string()))
        .collect();
    assert_eq!(table.len(), ROWS.len(), "duplicate rows in ROWS");
    let missing: Vec<_> = live.difference(&table).collect();
    assert!(
        missing.is_empty(),
        "mutating routes with no federation row (add a Fed row: Fanout + a test, \
         ReadOnly, Receive or Pending(issue)): {missing:?}"
    );
    let stale: Vec<_> = table.difference(&live).collect();
    assert!(
        stale.is_empty(),
        "rows for routes that no longer exist: {stale:?}"
    );
    for (_, _, row) in ROWS {
        match row {
            Fed::Pending(issue) => assert!(*issue > 0, "Pending needs an issue"),
            Fed::Fanout | Fed::ReadOnly | Fed::Receive => {}
        }
    }
}

/// The scanner itself: a registration chain, a commented-out route and an
/// identifier that merely ends in a method name.
#[test]
fn registration_scanner_reads_chains_and_skips_comments_8741() {
    let src = "pub fn build_router_with_timeout(\n) {\n    \
        .route(handlers::routes::A, get(h::a).post(h::b).delete(h::c))\n    \
        // .route(handlers::routes::B, post(h::d))\n    \
        .route(handlers::routes::C, get(h::repost(x)))\n}\n";
    let got = mutating_registrations(src);
    assert_eq!(
        got,
        vec![
            ("post".to_string(), "A".to_string()),
            ("delete".to_string(), "A".to_string()),
        ]
    );
}
