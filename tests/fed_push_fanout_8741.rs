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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::push_dlq::{FederationDlqSink, SqliteDlqSink};
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
/// The K7 approval HMAC secret the decision cells sign with.
const APPROVAL_SECRET: &str = "fedpush-8741-approval-secret";
/// The approve-surface body the approval-decide cell sends.
const APPROVE_DECISION_BODY: &str = r#"{"decision":"approve","remember":"once"}"#;
/// The certified-tier marker (#2548, `cert-postgres-age.yml`): with it set a
/// PostgreSQL cell that cannot run is a failure, never a skip.
const CERT_TIER_MARKER: &str = "AI_MEMORY_TEST_AGE_URL";
/// Round 2 LOW-3 — a peer whose `max_page_size` is below the origin's
/// deletion chunk ([`ai_memory::handlers::MAX_BULK_SIZE`]): config enforces
/// no minimum, so a forget of [`FORGET_VICTIMS`] rows exceeds this peer's
/// per-request deletions cap.
const CAPPED_PEER_MAX_PAGE: usize = FORGET_VICTIMS - 1;
/// The mock peer's "no deletions cap" setting.
const UNCAPPED: usize = usize::MAX;
/// The peer id the single-peer federation config names.
const PEER_ID: &str = "peer-0";
/// How many pending DLQ rows a cell reads back (well above any cell's rows).
const DLQ_READ_LIMIT: usize = 64;

// ---------------------------------------------------------------------------
// Recording mock peer with a fail switch
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockPeer {
    url: String,
    recorded: Arc<Mutex<Vec<Value>>>,
    fail: Arc<AtomicBool>,
    /// The receiver's per-request deletions cap ([`UNCAPPED`] = none).
    deletions_cap: Arc<AtomicUsize>,
}

/// The receiver's exact refusal for a push over its deletions cap
/// (`handlers::federation_receive`, the `max_page_size` bound).
fn deletions_cap_refusal(cap: usize) -> String {
    format!("sync_push limited to {cap} deletions per request")
}

async fn spawn_peer() -> MockPeer {
    use axum::{Json as AxumJson, Router, extract::State, routing::post};

    #[derive(Clone)]
    struct PeerState {
        recorded: Arc<Mutex<Vec<Value>>>,
        fail: Arc<AtomicBool>,
        deletions_cap: Arc<AtomicUsize>,
    }

    async fn handler(
        State(state): State<PeerState>,
        AxumJson(payload): AxumJson<Value>,
    ) -> (StatusCode, AxumJson<Value>) {
        if state.fail.load(Ordering::Acquire) {
            return (PEER_FAIL_STATUS, AxumJson(json!({"error": "peer down"})));
        }
        let cap = state.deletions_cap.load(Ordering::Acquire);
        if payload
            .get("deletions")
            .and_then(Value::as_array)
            .is_some_and(|d| d.len() > cap)
        {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(json!({"error": deletions_cap_refusal(cap)})),
            );
        }
        state.recorded.lock().await.push(payload);
        (
            StatusCode::OK,
            AxumJson(json!({"applied": 1, "noop": 0, "skipped": 0})),
        )
    }

    let recorded: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let deletions_cap = Arc::new(AtomicUsize::new(UNCAPPED));
    let app = Router::new()
        .route(routes::SYNC_PUSH, post(handler))
        .with_state(PeerState {
            recorded: recorded.clone(),
            fail: fail.clone(),
            deletions_cap: deletions_cap.clone(),
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
        deletions_cap,
    }
}

fn federation_cfg(
    peer: &MockPeer,
    dlq_sink: Option<Arc<dyn FederationDlqSink>>,
) -> FederationConfig {
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
            id: PEER_ID.to_string(),
            sync_push_url: format!("{}{}", peer.url, routes::SYNC_PUSH),
        }],
        client,
        sender_agent_id: ADMIN_AGENT.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink,
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
    store: Arc<dyn ai_memory::store::MemoryStore>,
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
    // The approve / reject / approval-decide cells sign as the K7 decider.
    ai_memory::config::set_active_hooks_hmac_secret(Some(APPROVAL_SECRET.to_string()));
}

/// `None` when the backend is not available in this run (PG URL unset).
async fn origin(backend: Backend) -> Option<Origin> {
    origin_with(backend, None).await
}

/// [`origin`] with a dead-letter sink wired into the federation config.
async fn origin_with(
    backend: Backend,
    dlq_sink: Option<Arc<dyn FederationDlqSink>>,
) -> Option<Origin> {
    let default_timeout =
        std::time::Duration::from_secs(ai_memory::config::DEFAULT_REQUEST_TIMEOUT_SECS);
    origin_timed(backend, dlq_sink, default_timeout).await
}

/// [`origin_with`] on a router whose request timeout is `request_timeout`
/// (the operator-configurable `build_router_with_timeout` knob).
async fn origin_timed(
    backend: Backend,
    dlq_sink: Option<Arc<dyn FederationDlqSink>>,
    request_timeout: std::time::Duration,
) -> Option<Origin> {
    process_setup();
    let peer = spawn_peer().await;
    let fed = federation_cfg(&peer, dlq_sink);
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
            let router = ai_memory::build_router_with_timeout(
                api_key_state(),
                app_state(db, store.clone(), backend, fed),
                request_timeout,
            );
            Some(Origin {
                router,
                peer,
                ns,
                store,
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
            let router = ai_memory::build_router_with_timeout(
                api_key_state(),
                app_state(db, store.clone(), backend, fed),
                request_timeout,
            );
            Some(Origin {
                router,
                peer,
                ns,
                store,
                _db_file: None,
            })
        }
    }
}

impl Origin {
    async fn call(&self, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call_raw(method, uri, body.map(|b| b.to_string()), &[])
            .await
    }

    /// `call` with the exact body bytes and extra headers (the signed
    /// decision routes sign the bytes they send).
    async fn call_raw(
        &self,
        method: Method,
        uri: &str,
        body: Option<String>,
        extra: &[(&str, String)],
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-agent-id", ADMIN_AGENT)
            .header("content-type", "application/json");
        if body.is_none() {
            req = req.header("content-length", "0");
        }
        for (name, value) in extra {
            req = req.header(*name, value.as_str());
        }
        let req = req
            .body(body.map_or_else(Body::empty, Body::from))
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

    /// Queue an approve-gated pending Store by a distinct requester and
    /// register `ADMIN_AGENT` as the decider (the Human-arm gate: a
    /// registered approver that is not the requester). Returns
    /// `(pending id, queued title)`.
    async fn seed_pending(&self, ns: &str) -> (String, String) {
        let requester = format!("ai:fedpush-8741-req-{}", uuid::Uuid::new_v4().simple());
        let ctx = ai_memory::store::CallerContext::for_agent(requester.clone());
        let now = chrono::Utc::now().to_rfc3339();
        self.store
            .register_agent(
                &ctx,
                &ai_memory::models::AgentRegistration {
                    agent_id: ADMIN_AGENT.to_string(),
                    agent_type: "ai:generic".to_string(),
                    capabilities: Vec::new(),
                    registered_at: now.clone(),
                    last_seen_at: now.clone(),
                },
            )
            .await
            .expect("register the decider agent (the Human-arm gate needs it)");
        let title = format!("pending-8741-{}", uuid::Uuid::new_v4());
        let payload = json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "mid",
            "namespace": ns,
            "title": title,
            "content": format!("{title} queued body with enough length"),
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {"agent_id": requester},
        });
        let pid = self
            .store
            .queue_pending_action(
                &ctx,
                ai_memory::store::GovernedAction::Store,
                ns,
                None,
                &requester,
                &payload,
            )
            .await
            .expect("queue_pending_action");
        (pid, title)
    }

    /// A K7-signed decision POST as `ADMIN_AGENT`.
    async fn signed_decision(&self, uri: &str, pid: &str, body: &str) -> (StatusCode, Value) {
        let ts = chrono::Utc::now().timestamp().to_string();
        let subject = ai_memory::handlers::agent_api_key::approval_subject(pid, ADMIN_AGENT);
        let sig = common::sign_canonical_envelope(APPROVAL_SECRET, &ts, "POST", &subject, body);
        let extra = [
            ("x-ai-memory-timestamp", ts),
            ("x-ai-memory-signature", sig),
        ];
        let body = (!body.is_empty()).then(|| body.to_string());
        self.call_raw(Method::POST, uri, body, &extra).await
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
    RegisterAgent,
    CaptureTurn,
    EntityRegister,
    Import,
    NamespaceStandardSet,
    NamespaceStandardClear,
    Approve,
    Reject,
    ApprovalDecide,
    ForgetEmpty,
}

/// The ids of every `memories[]` row the peer received.
fn memory_ids_in(bodies: &[Value]) -> BTreeSet<String> {
    memories_in(bodies)
        .iter()
        .filter_map(|m| m["id"].as_str().map(str::to_string))
        .collect()
}

/// `(namespace, standard_id)` of every `namespace_meta[]` entry received.
fn ns_meta_in(bodies: &[Value]) -> BTreeSet<(String, String)> {
    bodies
        .iter()
        .filter_map(|p| p.get("namespace_meta").and_then(Value::as_array))
        .flatten()
        .filter_map(|e| {
            Some((
                e["namespace"].as_str()?.to_string(),
                e["standard_id"].as_str()?.to_string(),
            ))
        })
        .collect()
}

fn ns_clears_in(bodies: &[Value]) -> BTreeSet<String> {
    bodies
        .iter()
        .filter_map(|p| p.get("namespace_meta_clears").and_then(Value::as_array))
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// `(id, approved, decider)` of every `pending_decisions[]` entry received.
fn decisions_in(bodies: &[Value]) -> BTreeSet<(String, bool, String)> {
    bodies
        .iter()
        .filter_map(|p| p.get("pending_decisions").and_then(Value::as_array))
        .flatten()
        .filter_map(|d| {
            Some((
                d["id"].as_str()?.to_string(),
                d["approved"].as_bool()?,
                d["decider"].as_str()?.to_string(),
            ))
        })
        .collect()
}

/// T1: approve / reject / approval-decide. Peer up: the peer receives the
/// exact decision and (approve only) the produced row; peer down: the 202.
async fn run_decision(o: &Origin, op: Op, peer_down: bool) -> Option<(StatusCode, Value)> {
    let label = format!("{op:?} peer_down={peer_down}");
    let ns = format!("{}-{}", o.ns, uuid::Uuid::new_v4());
    let (pid, title) = o.seed_pending(&ns).await;
    let mark = o.mark().await;
    o.peer.fail.store(peer_down, Ordering::Release);
    let (status, body) = match op {
        Op::Approve => {
            o.signed_decision(&path_with_id(routes::PENDING_ID_APPROVE, &pid), &pid, "")
                .await
        }
        Op::Reject => {
            o.signed_decision(&path_with_id(routes::PENDING_ID_REJECT, &pid), &pid, "")
                .await
        }
        Op::ApprovalDecide => {
            let uri = routes::APPROVALS_PENDING_ID.replace("{pending_id}", &pid);
            o.signed_decision(&uri, &pid, APPROVE_DECISION_BODY).await
        }
        _ => unreachable!("run_decision handles the decision ops only"),
    };
    o.peer.fail.store(false, Ordering::Release);
    if peer_down {
        assert_under_replicated(&label, status, &body);
        return None;
    }
    let approved = !matches!(op, Op::Reject);
    let bodies = o.since(mark).await;
    assert_eq!(
        decisions_in(&bodies),
        BTreeSet::from([(pid.clone(), approved, ADMIN_AGENT.to_string())]),
        "{label}: peer must receive exactly this decision: {bodies:?}"
    );
    let produced: Vec<Value> = memories_in(&bodies)
        .into_iter()
        .filter(|m| m["title"] == json!(title) && m["namespace"] == json!(ns))
        .collect();
    assert_eq!(
        produced.len(),
        usize::from(approved),
        "{label}: produced rows shipped: {bodies:?}"
    );
    Some((status, body))
}

fn standard_path(ns: &str) -> String {
    routes::NAMESPACES_NS_STANDARD.replace("{ns}", ns)
}

/// #9152 / #9153 cells: one op, then the delivered effect `check`ed
/// against the bodies the peer recorded. Returns `None` for the peer-down
/// pass (the 202 was asserted).
async fn run_extra(o: &Origin, op: Op, peer_down: bool) -> Option<(StatusCode, Value)> {
    let label = format!("{op:?} peer_down={peer_down}");
    let ns = format!("{}-{}", o.ns, uuid::Uuid::new_v4());
    // Seed before the mark: these ops need an existing row.
    let seeded = match op {
        Op::NamespaceStandardSet => Some(o.create(&ns, "std").await),
        Op::NamespaceStandardClear => {
            let id = o.create(&ns, "std-clear").await;
            let (status, body) = o
                .call(Method::POST, &standard_path(&ns), Some(json!({"id": id})))
                .await;
            assert!(status.is_success(), "clear seed set: {status}: {body}");
            Some(id)
        }
        _ => None,
    };
    let (method, uri, req) = match op {
        Op::RegisterAgent => (
            Method::POST,
            routes::AGENTS.to_string(),
            json!({
                "agent_id": format!("ai:fedpush-8741-{}", uuid::Uuid::new_v4().simple()),
                "agent_type": "ai:fedpush",
                "capabilities": ["recall"],
            }),
        ),
        Op::CaptureTurn => (
            Method::POST,
            routes::CAPTURE_TURN.to_string(),
            json!({
                "host_session_id": format!("fedpush-8741-{}", uuid::Uuid::new_v4()),
                "host_turn_index": 1,
                "role": "user",
                "content": "fedpush 8741 captured turn content",
                "namespace": ns,
            }),
        ),
        Op::EntityRegister => (
            Method::POST,
            routes::ENTITIES.to_string(),
            json!({
                "canonical_name": format!("fedpush-entity-{}", uuid::Uuid::new_v4()),
                "namespace": ns,
                "aliases": ["fedpush-alias"],
            }),
        ),
        Op::Import => {
            let now = chrono::Utc::now().to_rfc3339();
            let (a, b) = (
                import_row(&ns, "imp-a", &now),
                import_row(&ns, "imp-b", &now),
            );
            let link = json!({
                "source_id": a["id"], "target_id": b["id"],
                "relation": LINK_RELATION, "created_at": now,
            });
            (
                Method::POST,
                routes::IMPORT.to_string(),
                json!({"memories": [a, b], "links": [link]}),
            )
        }
        Op::NamespaceStandardSet => (
            Method::POST,
            standard_path(&ns),
            json!({"id": seeded.clone().expect("seeded standard")}),
        ),
        Op::NamespaceStandardClear => (Method::DELETE, standard_path(&ns), Value::Null),
        _ => unreachable!("run_extra handles the #9152 / #9153 ops only"),
    };
    let mark = o.mark().await;
    o.peer.fail.store(peer_down, Ordering::Release);
    let (status, body) = o
        .call(method, &uri, (!req.is_null()).then(|| req.clone()))
        .await;
    o.peer.fail.store(false, Ordering::Release);
    if peer_down {
        assert_under_replicated(&label, status, &body);
        return None;
    }
    let bodies = o.since(mark).await;
    match op {
        Op::RegisterAgent => {
            let agent = req["agent_id"].as_str().expect("agent id");
            assert!(
                memories_in(&bodies)
                    .iter()
                    .any(|m| m["namespace"] == json!("_agents")
                        && m["title"].as_str().is_some_and(|t| t.contains(agent))),
                "{label}: peer must receive the _agents row for {agent}: {bodies:?}"
            );
        }
        Op::CaptureTurn | Op::EntityRegister => {
            let id_field = if matches!(op, Op::CaptureTurn) {
                "memory_id"
            } else {
                "entity_id"
            };
            let id = body[id_field].as_str().expect("written id").to_string();
            assert!(
                memory_ids_in(&bodies).contains(&id),
                "{label}: peer must receive row {id}: {bodies:?}"
            );
        }
        Op::Import => {
            let want: BTreeSet<String> = req["memories"]
                .as_array()
                .expect("memories")
                .iter()
                .filter_map(|m| m["id"].as_str().map(str::to_string))
                .collect();
            let got = memory_ids_in(&bodies);
            assert!(
                want.is_subset(&got),
                "{label}: imported rows {want:?} not all shipped: {got:?}"
            );
            let link_shipped = bodies
                .iter()
                .filter_map(|p| p.get("links").and_then(Value::as_array))
                .flatten()
                .any(|l| {
                    l["source_id"] == req["links"][0]["source_id"]
                        && l["target_id"] == req["links"][0]["target_id"]
                        && l["relation"] == json!(LINK_RELATION)
                });
            assert!(
                link_shipped,
                "{label}: imported link not shipped: {bodies:?}"
            );
        }
        Op::NamespaceStandardSet => {
            let sid = seeded.expect("seeded");
            assert!(
                ns_meta_in(&bodies).contains(&(ns.clone(), sid.clone())),
                "{label}: peer must receive the ({ns}, {sid}) binding: {bodies:?}"
            );
            assert!(
                memory_ids_in(&bodies).contains(&sid),
                "{label}: peer must receive the standard row {sid}: {bodies:?}"
            );
        }
        Op::NamespaceStandardClear => {
            assert_eq!(
                ns_clears_in(&bodies),
                BTreeSet::from([ns.clone()]),
                "{label}"
            );
        }
        _ => unreachable!(),
    }
    Some((status, body))
}

/// Run one cell. `peer_down` flips the mock peer to 503 right before the op
/// (seeding always runs with the peer up).
async fn run_cell(o: &Origin, op: Op, peer_down: bool) {
    let label = format!("{op:?} peer_down={peer_down}");
    let ns = o.ns.clone();
    let (status, body) = match op {
        Op::RegisterAgent
        | Op::CaptureTurn
        | Op::EntityRegister
        | Op::Import
        | Op::NamespaceStandardSet
        | Op::NamespaceStandardClear => match run_extra(o, op, peer_down).await {
            Some(done) => done,
            None => return,
        },
        Op::Approve | Op::Reject | Op::ApprovalDecide => {
            match run_decision(o, op, peer_down).await {
                Some(done) => done,
                None => return,
            }
        }
        Op::ForgetEmpty => {
            // F5: nothing matched, nothing to deliver: no fabricated ack
            // count, peer up or down, and the peer receives nothing.
            let ns = format!("{ns}-forget-empty-{}", uuid::Uuid::new_v4());
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(Method::POST, routes::FORGET, Some(json!({"namespace": ns})))
                .await;
            o.peer.fail.store(false, Ordering::Release);
            assert_eq!(status, StatusCode::OK, "{label}: {body}");
            assert_eq!(body["deleted"], json!(0), "{label}: {body}");
            for field in [QUORUM_ACKS_FIELD, QUORUM_N_FIELD, QUORUM_REQUIRED_FIELD] {
                assert!(
                    body.get(field).is_none(),
                    "{label}: {field} stamped: {body}"
                );
            }
            assert!(
                o.since(mark).await.is_empty(),
                "{label}: peer received a body"
            );
            return;
        }
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
            let title = json!(format!(
                "fedpush 8741 consolidated {}",
                uuid::Uuid::new_v4()
            ));
            let mark = o.mark().await;
            o.peer.fail.store(peer_down, Ordering::Release);
            let (status, body) = o
                .call(
                    Method::POST,
                    routes::CONSOLIDATE,
                    Some(json!({
                        "ids": sources,
                        "title": title,
                        "summary": "caller supplied consolidation summary of enough length",
                        "namespace": ns,
                        "tier": "long",
                    })),
                )
                .await;
            o.peer.fail.store(false, Ordering::Release);
            if peer_down {
                assert_under_replicated(&label, status, &body);
                let id = body["id"].as_str().expect("202 names the local row");
                let (got, row) = o
                    .call(Method::GET, &path_with_id(routes::MEMORIES_ID, id), None)
                    .await;
                assert_eq!(
                    got,
                    StatusCode::OK,
                    "{label}: 202 id {id} not persisted: {row}"
                );
                assert_eq!(row["memory"]["title"], title, "{label}: {row}");
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
        return skip_unless_cert(backend);
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
    register_agent_9152 => Op::RegisterAgent,
    namespace_standard_set_9152 => Op::NamespaceStandardSet,
    namespace_standard_clear_9152 => Op::NamespaceStandardClear,
    capture_turn_9153 => Op::CaptureTurn,
    entity_register_9153 => Op::EntityRegister,
    import_9153 => Op::Import,
    pending_approve_8741 => Op::Approve,
    pending_reject_8741 => Op::Reject,
    approval_decide_8741 => Op::ApprovalDecide,
    bulk_forget_empty_8741 => Op::ForgetEmpty,
}

// ---------------------------------------------------------------------------
// Round 2 cells: import bounds, reflect (peer down), capped peer + DLQ
// ---------------------------------------------------------------------------

/// One importable memory row in `ns`.
fn import_row(ns: &str, tag: &str, now: &str) -> Value {
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "tier": "mid",
        "namespace": ns,
        "title": format!("{tag}-{}", uuid::Uuid::new_v4()),
        "content": format!("{tag} imported body with enough length"),
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "import",
        "access_count": 0,
        "created_at": now,
        "updated_at": now,
        "metadata": {},
    })
}

/// `n` importable rows plus a ring of `n` links over them (row i -> row i+1).
fn import_batch(ns: &str, n: usize) -> (Vec<Value>, Vec<Value>) {
    let now = chrono::Utc::now().to_rfc3339();
    let rows: Vec<Value> = (0..n)
        .map(|i| import_row(ns, &format!("bound-{i}"), &now))
        .collect();
    let links = (0..n)
        .map(|i| {
            json!({
                "source_id": rows[i]["id"],
                "target_id": rows[(i + 1) % n]["id"],
                "relation": LINK_RELATION,
                "created_at": now,
            })
        })
        .collect();
    (rows, links)
}

/// Request timeout for the PostgreSQL at-cap import: the PostgreSQL import arm
/// makes one awaited round trip per row and link, so `MAX_BULK_SIZE` of both
/// overruns the default `DEFAULT_REQUEST_TIMEOUT_SECS` (#9209, which exists
/// before this PR). Flip to the default timeout when #9209 lands.
#[cfg(feature = "sal-postgres")]
const PG_IMPORT_AT_CAP_TIMEOUT_SECS: u64 = 300;

/// The router timeout the import-bounds cell runs under: the default on
/// SQLite, [`PG_IMPORT_AT_CAP_TIMEOUT_SECS`] on PostgreSQL (#9209).
fn import_at_cap_timeout(backend: Backend) -> std::time::Duration {
    match backend {
        Backend::Sqlite => {
            std::time::Duration::from_secs(ai_memory::config::DEFAULT_REQUEST_TIMEOUT_SECS)
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres => std::time::Duration::from_secs(PG_IMPORT_AT_CAP_TIMEOUT_SECS),
    }
}

/// Round 2 LOW-1 — the import bounds: one past `MAX_BULK_SIZE` memories or
/// links is the exact 400 and ships nothing; exactly `MAX_BULK_SIZE` of
/// both is accepted, delivered and quorum-met.
async fn run_import_bounds(backend: Backend) {
    let max = ai_memory::handlers::MAX_BULK_SIZE;
    let Some(o) = origin_timed(backend, None, import_at_cap_timeout(backend)).await else {
        return skip_unless_cert(backend);
    };
    let ns = format!("{}-bounds", o.ns);

    let (rows, _) = import_batch(&ns, max + 1);
    let mark = o.mark().await;
    let (status, body) = o
        .call(
            Method::POST,
            routes::IMPORT,
            Some(json!({"memories": rows})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "memories over cap: {body}");
    assert_eq!(
        body,
        json!({"error": format!("import limited to {max} memories")})
    );

    let (_, links) = import_batch(&ns, max + 1);
    let (status, body) = o
        .call(
            Method::POST,
            routes::IMPORT,
            Some(json!({"memories": [], "links": links})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "links over cap: {body}");
    assert_eq!(
        body,
        json!({"error": format!("import limited to {max} links")})
    );
    assert!(
        o.since(mark).await.is_empty(),
        "a refused import ships nothing"
    );

    let (rows, links) = import_batch(&ns, max);
    let want: BTreeSet<String> = rows
        .iter()
        .filter_map(|m| m["id"].as_str().map(str::to_string))
        .collect();
    let (status, body) = o
        .call(
            Method::POST,
            routes::IMPORT,
            Some(json!({"memories": rows, "links": links})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "import at the cap: {body}");
    assert_eq!(body["imported"], json!(max), "import at the cap: {body}");
    let bodies = o.since(mark).await;
    assert_eq!(memory_ids_in(&bodies), want, "every imported row shipped");
    let shipped_links = bodies
        .iter()
        .filter_map(|p| p.get("links").and_then(Value::as_array))
        .flatten()
        .count();
    assert_eq!(shipped_links, max, "every imported link shipped");
    assert_quorum_met("import at the cap", status, &body);
}

/// Round 2 LOW-2 — reflect with the peer down, pinned at its exact current
/// behaviour. Flip when #9182 lands (the reflect route then reports the
/// link fan-out miss through the funnel like every other write).
async fn run_reflect_peer_down(backend: Backend) {
    let Some(o) = origin(backend).await else {
        return skip_unless_cert(backend);
    };
    let ns = format!("{}-reflect", o.ns);
    let mut sources = Vec::new();
    for i in 0..CONSOLIDATE_SOURCES {
        sources.push(o.create(&ns, &format!("reflect-src-{i}")).await);
    }
    let mark = o.mark().await;
    o.peer.fail.store(true, Ordering::Release);
    let (status, body) = o
        .call(
            Method::POST,
            routes::MEMORY_REFLECT,
            Some(json!({
                "source_ids": sources,
                "title": format!("fedpush 8741 reflection {}", uuid::Uuid::new_v4()),
                "content": "fedpush 8741 reflection content of enough length",
                "namespace": ns,
            })),
        )
        .await;
    o.peer.fail.store(false, Ordering::Release);
    pin_reflect_peer_down(status, &body);
    assert!(
        o.since(mark).await.is_empty(),
        "a down peer records nothing: {body}"
    );
}

/// Round 2 LOW-3 — a peer whose `max_page_size` is below the origin's
/// deletion chunk refuses the bulk erase: the origin answers the exact 202
/// and lands one dead-letter row per erased id, with that id's
/// single-deletion body and the peer's exact refusal.
async fn run_capped_peer_forget(backend: Backend) {
    let dlq_dir = tempfile::Builder::new()
        .prefix("fedpush-8741-dlq-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("dlq tempdir");
    let dlq_path = dlq_dir.path().join("dlq.db");
    let dlq_db: Db = Arc::new(Mutex::new((
        ai_memory::db::open(&dlq_path).expect("open dlq db"),
        dlq_path,
        ResolvedTtl::default(),
        true,
    )));
    let sink = Arc::new(SqliteDlqSink::new(dlq_db).await.expect("dlq sink"));
    let Some(o) = origin_with(backend, Some(sink.clone())).await else {
        return skip_unless_cert(backend);
    };
    let ns = format!("{}-capped-{}", o.ns, uuid::Uuid::new_v4());
    let mut victims = BTreeSet::new();
    for i in 0..FORGET_VICTIMS {
        victims.insert(o.create(&ns, &format!("capped-{i}")).await);
    }
    let mark = o.mark().await;
    o.peer
        .deletions_cap
        .store(CAPPED_PEER_MAX_PAGE, Ordering::Release);
    let (status, body) = o
        .call(Method::POST, routes::FORGET, Some(json!({"namespace": ns})))
        .await;
    o.peer.deletions_cap.store(UNCAPPED, Ordering::Release);
    assert_eq!(status, UNDER_REPLICATED, "capped peer forget: {body}");
    assert_eq!(body, partial_ack_receipt(), "capped peer forget");
    assert!(
        ids_in(&o.since(mark).await, "deletions").is_empty(),
        "the capped peer applied nothing"
    );
    let rows = sink
        .take_pending_dlq_rows(DLQ_READ_LIMIT)
        .await
        .expect("dlq rows");
    let landed: BTreeSet<String> = rows.iter().map(|r| r.memory_id.clone()).collect();
    assert_eq!(
        landed, victims,
        "one dead-letter row per erased id: {rows:?}"
    );
    for row in &rows {
        assert_eq!(row.peer_id, PEER_ID, "{row:?}");
        assert_eq!(row.attempt_count, 1, "{row:?}");
        assert_eq!(
            row.payload_json["deletions"],
            json!([row.memory_id]),
            "each row carries its own single-deletion body: {row:?}"
        );
        pin_capped_peer_reason(&row.last_error);
    }
}

/// The exact under-replicated receipt of a one-peer write the peer did not
/// ack: the local commit is the only ack, and a reachable peer that answered
/// without acking is the public `timeout` reason
/// (`federation::quorum::QuorumNotMetPayload::from_err`).
fn partial_ack_receipt() -> Value {
    json!({
        "acks": 1,
        "durability": "local",
        "needed": QUORUM_W,
        "quorum_met": false,
        "reason": "timeout",
    })
}

/// Exact current behaviour of reflect with the peer down: the reflection
/// row's quorum miss reaches the response as the 202 receipt, while the
/// `reflects_on` edge outcomes are logged and dropped (#9182).
/// Flip when #9182 lands: the edges then join the same funnel and this pin
/// is re-cut to the funnel's receipt.
fn pin_reflect_peer_down(status: StatusCode, body: &Value) {
    assert_eq!(status, UNDER_REPLICATED, "reflect, peer down: {body}");
    assert_eq!(*body, partial_ack_receipt(), "reflect, peer down");
}

/// The exact dead-letter reason a capped peer's refusal lands with: the
/// permanent-class tag over the first attempt and its one retry. The peer's
/// refusal text stays out of the row (foreign text never reaches the
/// operator surface); the HTTP status is what the row carries.
const CAPPED_PEER_DLQ_REASON: &str =
    "[ai-memory:class=permanent] first: http 400 Bad Request; retry: http 400 Bad Request";

fn pin_capped_peer_reason(last_error: &str) {
    assert_eq!(last_error, CAPPED_PEER_DLQ_REASON);
}

/// sec-F5 (#2548): under the certified tier a cell that did not run is a
/// failure, never a green skip.
fn skip_unless_cert(backend: Backend) {
    assert!(
        std::env::var_os(CERT_TIER_MARKER).is_none(),
        "{backend:?} cell did not run under the certified tier ({CERT_TIER_MARKER} set, \
         AI_MEMORY_TEST_POSTGRES_URL unset)"
    );
    eprintln!("skip {backend:?}: AI_MEMORY_TEST_POSTGRES_URL not set");
}

/// One named test per (backend, cell).
macro_rules! backend_cells {
    ($($name:ident => $cell:ident),+ $(,)?) => {
        mod sqlite_round2_cells {
            use super::*;
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    $cell(Backend::Sqlite).await;
                }
            )+
        }
        #[cfg(feature = "sal-postgres")]
        mod postgres_round2_cells {
            use super::*;
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    $cell(Backend::Postgres).await;
                }
            )+
        }
    };
}

backend_cells! {
    import_bounds_8741 => run_import_bounds,
    reflect_peer_down_current_9182 => run_reflect_peer_down,
    capped_peer_forget_dlq_8741 => run_capped_peer_forget,
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
    ("post", "CAPTURE_TURN", Fed::Fanout),
    ("post", "RECALL", Fed::ReadOnly),
    ("post", "FORGET", Fed::Fanout),
    ("post", "CONSOLIDATE", Fed::Fanout),
    ("post", "AUTO_TAG", Fed::Pending(9158)),
    ("post", "EXPAND_QUERY", Fed::ReadOnly),
    ("post", "MEMORY_LOAD_FAMILY", Fed::ReadOnly),
    ("post", "LINKS", Fed::Fanout),
    ("delete", "LINKS", Fed::Pending(9154)),
    ("post", "NAMESPACES", Fed::Fanout),
    ("delete", "NAMESPACES", Fed::Fanout),
    ("post", "NAMESPACES_NS_STANDARD", Fed::Fanout),
    ("delete", "NAMESPACES_NS_STANDARD", Fed::Fanout),
    ("post", "CHECK_DUPLICATE", Fed::ReadOnly),
    ("post", "ENTITIES", Fed::Fanout),
    ("post", "KG_INVALIDATE", Fed::Pending(9154)),
    ("post", "KG_QUERY", Fed::ReadOnly),
    ("post", "KG_FIND_PATHS", Fed::ReadOnly),
    ("post", "FIND_PATHS", Fed::ReadOnly),
    ("post", "LINKS_VERIFY", Fed::ReadOnly),
    ("post", "QUOTA_STATUS", Fed::ReadOnly),
    ("post", "ADMIN_QUARANTINE_ID_RELEASE", Fed::Pending(9154)),
    ("post", "GC", Fed::Pending(9154)),
    ("post", "IMPORT", Fed::Fanout),
    ("post", "ARCHIVE", Fed::Fanout),
    ("delete", "ARCHIVE", Fed::Pending(9154)),
    ("post", "ARCHIVE_ID_RESTORE", Fed::Fanout),
    ("post", "AGENTS", Fed::Fanout),
    ("put", "AGENTS_ID_PUBKEY", Fed::Pending(9158)),
    ("post", "AGENTS_ID_PUBKEY_CHALLENGE", Fed::Pending(9158)),
    ("post", "AGENTS_ID_API_KEY", Fed::Pending(9158)),
    ("post", "AGENTS_ID_API_KEY_REVOKE", Fed::Pending(9158)),
    ("post", "PENDING_ID_APPROVE", Fed::Fanout),
    ("post", "PENDING_ID_REJECT", Fed::Fanout),
    ("post", "APPROVALS_PENDING_ID", Fed::Fanout),
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
    // sec-F5: reflect_fanout (route_1111.rs) still swallows push errors.
    ("post", "MEMORY_REFLECT", Fed::Pending(9182)),
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

/// Remove `//` line comments and (nested) `/* */` block comments, so a
/// commented-out registration is not live, while string and char literals
/// pass through verbatim (a `"http://..."` argument is not a comment).
/// Newlines inside block comments are kept so line structure survives.
/// One pass, linear in the input.
fn strip_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match (c, next) {
            ('/', Some('/')) => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            ('/', Some('*')) => {
                let mut depth = 0_usize;
                while i < chars.len() {
                    match (chars[i], chars.get(i + 1).copied()) {
                        ('/', Some('*')) => {
                            depth += 1;
                            i += 2;
                        }
                        ('*', Some('/')) => {
                            depth -= 1;
                            i += 2;
                            if depth == 0 {
                                break;
                            }
                        }
                        ('\n', _) => {
                            out.push('\n');
                            i += 1;
                        }
                        _ => i += 1,
                    }
                }
            }
            ('"', _) => {
                out.push(c);
                i += 1;
                while i < chars.len() {
                    out.push(chars[i]);
                    match chars[i] {
                        '\\' => {
                            if let Some(&esc) = chars.get(i + 1) {
                                out.push(esc);
                            }
                            i += 2;
                        }
                        '"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            ('\'', Some(n)) if n == '\\' || chars.get(i + 2) == Some(&'\'') => {
                // A char literal ('"', '\\', '/'); a lifetime falls through.
                let end = (i + 1..chars.len())
                    .find(|&j| chars[j] == '\'' && (j > i + 2 || n != '\\'))
                    .unwrap_or(chars.len() - 1);
                out.extend(&chars[i..=end]);
                i = end + 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
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
    let body = strip_comments(&lib_rs[start..]);
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

/// T3: a `//` inside a string literal is not a comment (the registration
/// after it stays live) and a `/* */` block (nested, multi-line) is.
#[test]
fn registration_scanner_honours_strings_and_block_comments_8741() {
    let src = "pub fn build_router_with_timeout(\n) {\n    \
        .route(handlers::routes::A, get(h::a)).layer(x(\"http://h/p\")).route(handlers::routes::D, post(h::d))\n    \
        /* .route(handlers::routes::B, post(h::b))\n    /* nested */ .route(handlers::routes::E, put(h::e)) */\n    \
        .route(handlers::routes::C, delete(h::c('/')))\n}\n";
    let got = mutating_registrations(src);
    assert_eq!(
        got,
        vec![
            ("post".to_string(), "D".to_string()),
            ("delete".to_string(), "C".to_string()),
        ]
    );
}

/// T3 bound: the comment stripper is one linear pass (100K+ input).
#[test]
fn comment_stripper_is_linear_on_a_large_input_8741() {
    const REPEAT: usize = 20_000;
    let unit = "x(\"a//b\") /* c */ // d\n";
    let src = unit.repeat(REPEAT);
    assert!(src.len() > 100_000);
    let started = std::time::Instant::now();
    let out = strip_comments(&src);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(out, "x(\"a//b\")  \n".repeat(REPEAT));
}
