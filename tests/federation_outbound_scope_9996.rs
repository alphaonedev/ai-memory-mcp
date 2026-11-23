// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9996 — the sender admits each namespace per peer, deny by default
//! (vote V2-9996, 3-agent vote (71472661)).
//!
//! Every outbound path is driven against real loopback peers that record
//! each request, and every queue assertion reads the real DLQ sink
//! (SQLite here, PostgreSQL in the `sal-postgres` cells):
//!
//! - I1 / C-1: a peer outside the scope of a write gets zero requests and
//!   zero queue rows, on every sibling path (one case each below); an id
//!   whose namespace is unknown sends nothing to a narrowed peer.
//! - I2 / C-2: a permanent (scope) refusal queues nothing; a transient
//!   failure (including a 2xx with an unreadable body) is retried and
//!   bounded by `MAX_REPLAY_ATTEMPTS`, the row is kept.
//! - C-3: a pre-seeded row outside the current scope is never sent and
//!   never deleted: it is quarantined with a typed reason and re-driven
//!   once the scope widens.
//! - C-4: a quorum whose admitted set is below `W` fails with
//!   `QuorumFailureReason::OutboundScope`.
//! - C-8: the config reuses the inbound `allowed_namespaces` shape.

#![cfg(feature = "sal")]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;

use ai_memory::federation::outbound_scope::{
    self, ItemNamespaces, PeerOutboundScope, REASON_NO_OUTBOUND_SCOPE, REASON_NOTHING_IN_SCOPE,
};
use ai_memory::federation::push_dlq::{
    FederationDlqSink, MAX_REPLAY_ATTEMPTS, SqliteDlqSink, out_of_scope_like_prefix,
    redrive_out_of_scope_once, replay_once,
};
use ai_memory::federation::{FederationConfig, PeerEndpoint, sync};
use ai_memory::models::{Memory, MemoryLinkRelation};
use ai_memory::replication::{QuorumError, QuorumFailureReason, QuorumPolicy};

/// #10037 / #10039: the pull path (`GET /sync/since`).
#[path = "federation_outbound_scope_9996_serve/serve.rs"]
mod serve;

// ---------------------------------------------------------------------------
// Recording loopback peer
// ---------------------------------------------------------------------------

/// Response plan: `(status, body)` for the 0-based hit index.
type Plan = dyn Fn(usize) -> (u16, String) + Send + Sync;

#[derive(Clone)]
struct PeerState {
    hits: Arc<AtomicUsize>,
    bodies: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    plan: Arc<Plan>,
}

impl PeerState {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn bodies(&self) -> Vec<serde_json::Value> {
        self.bodies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

async fn peer_handler(State(st): State<PeerState>, body: String) -> impl IntoResponse {
    let n = st.hits.fetch_add(1, Ordering::SeqCst);
    st.bodies
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(serde_json::from_str(&body).unwrap_or(serde_json::Value::Null));
    let (status, body) = (st.plan)(n);
    (
        StatusCode::from_u16(status).expect("valid mock status"),
        body,
    )
}

async fn spawn_peer<F>(plan: F) -> (String, PeerState)
where
    F: Fn(usize) -> (u16, String) + Send + Sync + 'static,
{
    let st = PeerState {
        hits: Arc::new(AtomicUsize::new(0)),
        bodies: Arc::new(std::sync::Mutex::new(Vec::new())),
        plan: Arc::new(plan),
    };
    let app = Router::new()
        .route("/api/v1/sync/push", post(peer_handler))
        .with_state(st.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback peer");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/api/v1/sync/push"), st)
}

fn ok_plan() -> impl Fn(usize) -> (u16, String) + Send + Sync + 'static {
    |_| (200, "{}".to_string())
}

fn err_plan() -> impl Fn(usize) -> (u16, String) + Send + Sync + 'static {
    |_| (500, "{\"error\":\"down\"}".to_string())
}

/// A 2xx whose body is not JSON: no proof of apply (C-2), so transient.
fn unparseable_plan() -> impl Fn(usize) -> (u16, String) + Send + Sync + 'static {
    |_| (200, "not json".to_string())
}

// ---------------------------------------------------------------------------
// Config + fixtures
// ---------------------------------------------------------------------------

const SENDER: &str = "ai:outbound-scope-9996";
/// The namespace every in-scope fixture lives in.
const NS_IN: &str = "team/a/notes";
/// A namespace no narrowed peer below admits.
const NS_OUT: &str = "team/b/private";
/// The narrowed scope of the in-scope peer.
const SCOPE_IN: &[&str] = &["team/a/**", "_epoch"];
/// A scope that admits none of the fixtures.
const SCOPE_OTHER: &[&str] = &["elsewhere/**"];
/// Writes driven by the volume case.
const OUT_OF_SCOPE_WRITES: usize = 1000;
/// Ack deadline for one fan-out.
const ACK_MS: u64 = 2000;

fn scope(patterns: &[&str]) -> PeerOutboundScope {
    PeerOutboundScope::Namespaces(patterns.iter().map(|p| (*p).to_string()).collect())
}

fn peer(id: &str, url: &str, scope: PeerOutboundScope) -> PeerEndpoint {
    PeerEndpoint {
        id: id.to_string(),
        sync_push_url: url.to_string(),
        outbound_scope: scope,
    }
}

fn config(
    peers: Vec<PeerEndpoint>,
    n: usize,
    w: usize,
    sink: Option<Arc<dyn FederationDlqSink>>,
) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    FederationConfig {
        policy: QuorumPolicy::new(n, w, Duration::from_millis(ACK_MS), Duration::from_secs(30))
            .expect("valid quorum policy"),
        peers,
        client,
        sender_agent_id: SENDER.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: sink,
    }
}

fn memory(id: &str, namespace: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: format!("outbound scope fixture {id}"),
        content: "outbound scope fixture body".to_string(),
        source: "test".to_string(),
        priority: 5,
        confidence: 1.0,
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({}),
        version: 1,
        ..Memory::default()
    }
}

fn push_body(mem: &Memory) -> serde_json::Value {
    serde_json::json!({
        "sender_agent_id": SENDER,
        "memories": [mem],
        "dry_run": false,
    })
}

/// A fresh SQLite `Db` with every migration applied, under `.local-runs`.
fn fresh_db() -> (tempfile::TempDir, ai_memory::handlers::Db, PathBuf) {
    let tmp = tempfile::Builder::new()
        .prefix("fed-outbound-9996-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("create local-runs tempdir");
    let db_path = tmp.path().join("dlq.db");
    let conn = ai_memory::storage::open(&db_path).expect("open sqlite");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle = Arc::new(tokio::sync::Mutex::new((conn, db_path.clone(), ttl, true)));
    (tmp, handle, db_path)
}

async fn sqlite_sink() -> (tempfile::TempDir, Arc<dyn FederationDlqSink>, PathBuf) {
    let (tmp, db, path) = fresh_db();
    let sink = SqliteDlqSink::new(db).await.expect("sqlite dlq sink");
    (tmp, Arc::new(sink), path)
}

/// One DLQ row as the table holds it (every row, quarantined or not).
#[derive(Debug)]
struct RawRow {
    memory_id: String,
    peer_id: String,
    attempt_count: i64,
    last_error: String,
    replayed: bool,
}

fn raw_rows(path: &PathBuf) -> Vec<RawRow> {
    // Read-only and without migrations: the sink holds its own connection.
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open sqlite read-only for inspection");
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, peer_id, attempt_count, last_error, replayed_at IS NOT NULL \
             FROM federation_push_dlq ORDER BY id",
        )
        .expect("prepare");
    stmt.query_map([], |r| {
        Ok(RawRow {
            memory_id: r.get(0)?,
            peer_id: r.get(1)?,
            attempt_count: r.get(2)?,
            last_error: r.get(3)?,
            replayed: r.get(4)?,
        })
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

fn quorum_reason(res: Result<usize, QuorumError>) -> QuorumFailureReason {
    match res {
        Err(QuorumError::QuorumNotMet { reason, .. }) => reason,
        other => panic!("expected QuorumNotMet, got {other:?}"),
    }
}

/// The exact `last_error` of a row the sender quarantined for scope.
fn quarantined_reason(refusal_reason: &str) -> String {
    let prefix = out_of_scope_like_prefix();
    format!("{}{refusal_reason}", prefix.trim_end_matches('%'))
}

// ---------------------------------------------------------------------------
// I1 / C-1 / C-4: deny by default, zero bytes, typed quorum shortfall
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unscoped_peer_gets_zero_requests_and_zero_rows_9996() {
    let (_tmp, sink, path) = sqlite_sink().await;
    let (url, st) = spawn_peer(ok_plan()).await;
    let cfg = config(
        vec![peer("peer-deny", &url, PeerOutboundScope::Deny)],
        2,
        2,
        Some(sink),
    );
    let tracker = sync::broadcast_store_quorum(&cfg, &memory("m-deny", NS_IN))
        .await
        .expect("dispatch");
    assert_eq!(
        quorum_reason(tracker.finalise(Instant::now())),
        QuorumFailureReason::OutboundScope
    );
    assert_eq!(st.hits(), 0, "an unscoped peer must receive zero requests");
    assert!(raw_rows(&path).is_empty(), "a scope refusal queues nothing");
}

#[tokio::test]
async fn narrowed_peer_receives_only_its_namespaces_9996() {
    let (url, st) = spawn_peer(ok_plan()).await;
    let cfg = config(vec![peer("peer-in", &url, scope(SCOPE_IN))], 2, 2, None);
    let tracker = sync::broadcast_store_quorum(&cfg, &memory("m-in", NS_IN))
        .await
        .expect("dispatch");
    assert_eq!(tracker.finalise(Instant::now()).expect("quorum met"), 2);
    assert_eq!(st.hits(), 1);
    let body = &st.bodies()[0];
    assert_eq!(body["memories"][0]["id"], "m-in");
    assert!(
        body.get(outbound_scope::OUTBOUND_NAMESPACES_KEY).is_none(),
        "the sender-local annotation never goes on the wire"
    );
}

#[tokio::test]
async fn thousand_out_of_scope_writes_leave_zero_rows_9996() {
    let (_tmp, sink, path) = sqlite_sink().await;
    let (url, st) = spawn_peer(ok_plan()).await;
    // W=1: the local commit meets quorum, so the writes succeed locally
    // while the narrowed peer is never contacted.
    let cfg = config(
        vec![peer("peer-narrow", &url, scope(SCOPE_IN))],
        2,
        1,
        Some(sink),
    );
    for i in 0..OUT_OF_SCOPE_WRITES {
        let tracker = sync::broadcast_store_quorum(&cfg, &memory(&format!("m-out-{i}"), NS_OUT))
            .await
            .expect("dispatch");
        tracker.finalise(Instant::now()).expect("local quorum");
    }
    assert_eq!(st.hits(), 0);
    assert!(raw_rows(&path).is_empty());
    let series = outbound_scope::filtered_series();
    let filtered: u64 = series
        .iter()
        .filter(|s| s.peer_id == "peer-narrow" && s.namespace == NS_OUT)
        .map(|s| s.count)
        .sum();
    assert_eq!(
        filtered,
        u64::try_from(OUT_OF_SCOPE_WRITES).expect("fits"),
        "C-6: every left-out item is counted per peer and namespace"
    );
}

#[tokio::test]
async fn admitted_set_below_w_is_an_outbound_scope_shortfall_9996() {
    let (url_in, st_in) = spawn_peer(ok_plan()).await;
    let (url_out, st_out) = spawn_peer(ok_plan()).await;
    // N=3, W=3: local + one admitted peer is 2 < 3.
    let cfg = config(
        vec![
            peer("peer-in", &url_in, scope(SCOPE_IN)),
            peer("peer-out", &url_out, scope(SCOPE_OTHER)),
        ],
        3,
        3,
        None,
    );
    let tracker = sync::broadcast_store_quorum(&cfg, &memory("m-short", NS_IN))
        .await
        .expect("dispatch");
    match tracker.finalise(Instant::now()) {
        Err(QuorumError::QuorumNotMet {
            got,
            needed,
            reason,
        }) => {
            assert_eq!(needed, 3);
            assert!(got <= 2, "got {got}");
            assert_eq!(reason, QuorumFailureReason::OutboundScope);
        }
        other => panic!("expected an OutboundScope shortfall, got {other:?}"),
    }
    assert_eq!(st_out.hits(), 0);
    assert!(st_in.hits() <= 1);
}

// ---------------------------------------------------------------------------
// I2 / C-2: permanent refusal queues nothing; transient is bounded
// ---------------------------------------------------------------------------

#[tokio::test]
async fn permanent_refusal_queues_nothing_transient_failure_queues_once_9996() {
    let (_tmp, sink, path) = sqlite_sink().await;
    let (url_deny, st_deny) = spawn_peer(err_plan()).await;
    let (url_in, st_in) = spawn_peer(err_plan()).await;
    let cfg = config(
        vec![
            peer("peer-deny", &url_deny, PeerOutboundScope::Deny),
            peer("peer-in", &url_in, scope(SCOPE_IN)),
        ],
        3,
        2,
        Some(sink),
    );
    let tracker = sync::broadcast_store_quorum(&cfg, &memory("m-mixed", NS_IN))
        .await
        .expect("dispatch");
    assert!(tracker.finalise(Instant::now()).is_err());
    assert_eq!(st_deny.hits(), 0);
    assert!(st_in.hits() >= 1);
    let rows = raw_rows(&path);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].memory_id, "m-mixed");
    assert_eq!(rows[0].peer_id, "peer-in");
    assert!(!rows[0].replayed);
}

/// Seed one pending row for `peer_id` carrying `mem`.
async fn seed(sink: &dyn FederationDlqSink, mem: &Memory, peer_id: &str) {
    sink.enqueue_push_failure(
        &mem.id,
        peer_id,
        &push_body(mem),
        "seeded transient failure",
    )
    .await
    .expect("seed DLQ row");
}

async fn transient_ceiling_cell(sink: Arc<dyn FederationDlqSink>, path: Option<&PathBuf>) {
    let id = format!("m-ceiling-{}", uuid::Uuid::new_v4());
    let peer_id = format!("peer-ceiling-{}", uuid::Uuid::new_v4());
    let (url, st) = spawn_peer(unparseable_plan()).await;
    let cfg = config(
        vec![peer(&peer_id, &url, scope(SCOPE_IN))],
        2,
        2,
        Some(sink.clone()),
    );
    seed(&*sink, &memory(&id, NS_IN), &peer_id).await;
    let before = sink.pending_dlq_count().await.expect("count");
    let max = usize::try_from(MAX_REPLAY_ATTEMPTS).expect("fits");
    for _ in 0..max {
        replay_once(&cfg, &*sink).await;
    }
    // The seed counts as attempt 1, so the row reached the ceiling one
    // replay early; every further tick sends nothing.
    let sent = st.hits();
    assert!(sent >= max - 1 && sent <= max, "sent {sent}");
    replay_once(&cfg, &*sink).await;
    assert_eq!(st.hits(), sent, "a row at the ceiling is never re-sent");
    let pending = sink.take_pending_dlq_rows(10_000).await.expect("take");
    assert!(
        pending.iter().all(|r| r.memory_id != id),
        "the row left the replay window"
    );
    assert_eq!(
        sink.pending_dlq_count().await.expect("count"),
        before,
        "the row is kept, never deleted, never counted as delivered"
    );
    if let Some(path) = path {
        let rows = raw_rows(path);
        let row = rows.iter().find(|r| r.memory_id == id).expect("row kept");
        assert!(row.attempt_count >= i64::from(MAX_REPLAY_ATTEMPTS));
        assert!(!row.replayed);
        assert!(
            row.last_error
                .contains(ai_memory::federation::sync::UNPARSEABLE_SUCCESS_BODY_REASON),
            "{}",
            row.last_error
        );
    }
}

#[tokio::test]
async fn unparseable_2xx_is_transient_and_bounded_by_the_ceiling_sqlite_9996() {
    let (_tmp, sink, path) = sqlite_sink().await;
    transient_ceiling_cell(sink, Some(&path)).await;
}

// ---------------------------------------------------------------------------
// C-3: pre-seeded out-of-scope row is quarantined, kept and re-drivable
// ---------------------------------------------------------------------------

async fn pre_seeded_out_of_scope_cell(sink: Arc<dyn FederationDlqSink>, path: Option<&PathBuf>) {
    let id = format!("m-preseed-{}", uuid::Uuid::new_v4());
    let peer_id = format!("peer-preseed-{}", uuid::Uuid::new_v4());
    let (url, st) = spawn_peer(ok_plan()).await;
    // A row queued before the scope narrowed (or by an older binary).
    seed(&*sink, &memory(&id, NS_OUT), &peer_id).await;
    let before = sink.pending_dlq_count().await.expect("count");

    let narrowed = config(
        vec![peer(&peer_id, &url, scope(SCOPE_IN))],
        2,
        2,
        Some(sink.clone()),
    );
    replay_once(&narrowed, &*sink).await;
    replay_once(&narrowed, &*sink).await;
    assert_eq!(st.hits(), 0, "an out-of-scope row is never sent");
    assert!(
        sink.take_pending_dlq_rows(10_000)
            .await
            .expect("take")
            .iter()
            .all(|r| r.memory_id != id),
        "the row is in the terminal state, out of the replay window"
    );
    assert_eq!(sink.pending_dlq_count().await.expect("count"), before);
    if let Some(path) = path {
        let rows = raw_rows(path);
        let row = rows.iter().find(|r| r.memory_id == id).expect("row kept");
        assert_eq!(row.last_error, quarantined_reason(REASON_NOTHING_IN_SCOPE));
        assert!(row.attempt_count >= i64::from(MAX_REPLAY_ATTEMPTS));
        assert!(!row.replayed);
    }

    // A restart with the scope still narrowed re-drives and re-quarantines.
    redrive_out_of_scope_once(&*sink).await;
    let redriven = sink.take_pending_dlq_rows(10_000).await.expect("take");
    let row = redriven
        .iter()
        .find(|r| r.memory_id == id)
        .expect("redrive returns the row to the window");
    assert_eq!(row.attempt_count, 0);
    assert_eq!(row.last_error, quarantined_reason(REASON_NOTHING_IN_SCOPE));
    replay_once(&narrowed, &*sink).await;
    assert_eq!(st.hits(), 0);

    // Widen the scope (a restart with the new env), redrive, replay: the
    // write made under deny is delivered (C-7 at the queue layer).
    let widened = config(
        vec![peer(&peer_id, &url, PeerOutboundScope::all_explicit())],
        2,
        2,
        Some(sink.clone()),
    );
    redrive_out_of_scope_once(&*sink).await;
    replay_once(&widened, &*sink).await;
    assert_eq!(st.hits(), 1, "the widened scope delivers the queued write");
    assert_eq!(st.bodies()[0]["memories"][0]["id"], id.as_str());
    assert_eq!(
        sink.pending_dlq_count().await.expect("count"),
        before - 1,
        "delivered rows leave the queue by replay, never by delete"
    );
    if let Some(path) = path {
        let rows = raw_rows(path);
        let row = rows.iter().find(|r| r.memory_id == id).expect("row kept");
        assert!(row.replayed);
    }
}

#[tokio::test]
async fn pre_seeded_out_of_scope_row_is_quarantined_kept_and_redriven_sqlite_9996() {
    let (_tmp, sink, path) = sqlite_sink().await;
    pre_seeded_out_of_scope_cell(sink, Some(&path)).await;
}

#[tokio::test]
async fn pre_seeded_row_for_unscoped_peer_names_the_no_scope_reason_9996() {
    let (_tmp, sink, path) = sqlite_sink().await;
    let (url, st) = spawn_peer(ok_plan()).await;
    seed(&*sink, &memory("m-noscope", NS_IN), "peer-noscope").await;
    let cfg = config(
        vec![peer("peer-noscope", &url, PeerOutboundScope::Deny)],
        2,
        2,
        Some(sink.clone()),
    );
    replay_once(&cfg, &*sink).await;
    assert_eq!(st.hits(), 0);
    let rows = raw_rows(&path);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].last_error,
        quarantined_reason(REASON_NO_OUTBOUND_SCOPE)
    );
    assert!(!rows[0].replayed);
}

/// I3 — a queued erasure expands only to the peers whose scope admits the
/// erased memory's namespace: the out-of-scope peer gets no queue row and
/// no request, the in-scope peer gets exactly one delete.
#[tokio::test]
async fn erasure_expands_only_to_peers_in_scope_9996() {
    use ai_memory::federation::erasure_outbox;
    let (_tmp, sink, path) = sqlite_sink().await;
    {
        let conn = ai_memory::storage::open(&path).expect("open sqlite");
        erasure_outbox::mark_federation_drainable(&conn, 2).expect("stamp drainable");
        assert!(erasure_outbox::enqueue_erasure(
            &conn,
            "m-erase",
            NS_IN,
            erasure_outbox::surfaces::CLI_DELETE,
        ));
    }
    let (url_in, st_in) = spawn_peer(ok_plan()).await;
    let (url_out, st_out) = spawn_peer(ok_plan()).await;
    let cfg = config(
        vec![
            peer("peer-in", &url_in, scope(SCOPE_IN)),
            peer("peer-out", &url_out, scope(SCOPE_OTHER)),
        ],
        3,
        2,
        Some(sink.clone()),
    );
    replay_once(&cfg, &*sink).await;
    let pending: Vec<String> = raw_rows(&path)
        .into_iter()
        .filter(|r| r.memory_id == "m-erase" && !r.replayed)
        .map(|r| r.peer_id)
        .collect();
    assert_eq!(pending, vec!["peer-in".to_string()]);
    replay_once(&cfg, &*sink).await;
    assert_eq!(st_in.hits(), 1, "the in-scope peer receives the delete");
    assert_eq!(st_out.hits(), 0, "the out-of-scope peer receives nothing");
    assert_eq!(
        st_in.bodies()[0]["deletions"],
        serde_json::json!(["m-erase"])
    );
}

#[test]
fn out_of_scope_like_prefix_is_the_permanent_tagged_cause_9996() {
    let prefix = out_of_scope_like_prefix();
    assert!(prefix.ends_with("outbound_scope: %"), "{prefix}");
    assert_eq!(prefix.matches('%').count(), 1, "{prefix}");
    assert!(
        prefix.starts_with('['),
        "the class tag opens the column: {prefix}"
    );
}

// ---------------------------------------------------------------------------
// C-8: the inbound allowed_namespaces shape round-trips
// ---------------------------------------------------------------------------

#[test]
fn config_reuses_the_inbound_allowed_namespaces_shape_9996() {
    let inbound = ai_memory::federation::peer_attestation::PeerScope {
        allowed_sender_agent_ids: Vec::new(),
        allowed_namespaces: vec!["team/a/**".to_string(), "shared".to_string()],
    };
    let inbound_json = serde_json::to_value(&inbound).expect("serialise inbound");
    let entry = serde_json::json!({
        "allowed_namespaces": inbound_json["allowed_namespaces"].clone(),
    });
    let url = "https://peer-a.example:9077";
    let raw = serde_json::json!({ url: entry }).to_string();
    let map = outbound_scope::parse(&raw).expect("outbound parse");
    assert_eq!(map.len(), 1, "one entry per configured peer");
    let parsed = map.values().next().expect("the one entry");
    assert_eq!(parsed, &scope(&["team/a/**", "shared"]));
    // Same matcher on both sides, for every probe.
    for ns in [
        "team/a/x",
        "team/a/x/y",
        "shared",
        "team/b",
        "sharedx",
        "team",
    ] {
        let inbound_allows = inbound
            .allowed_namespaces
            .iter()
            .any(|p| ai_memory::federation::peer_attestation::namespace_allowed_test_glob(p, ns));
        assert_eq!(parsed.allows(ns), inbound_allows, "namespace {ns}");
    }
    // The inbound-only key is refused, not silently accepted.
    let with_sender = serde_json::json!({
        url: {"allowed_namespaces": ["x"], "allowed_sender_agent_ids": []}
    })
    .to_string();
    assert!(matches!(
        outbound_scope::parse(&with_sender),
        Err(outbound_scope::OutboundScopeConfigError::Malformed(_))
    ));
}

// ---------------------------------------------------------------------------
// I3: one case per sibling outbound path
// ---------------------------------------------------------------------------

/// The in-scope peer acks, the out-of-scope peer must see zero requests.
async fn two_peers() -> (FederationConfig, PeerState, PeerState) {
    let (url_in, st_in) = spawn_peer(ok_plan()).await;
    let (url_out, st_out) = spawn_peer(ok_plan()).await;
    let cfg = config(
        vec![
            peer("peer-in", &url_in, scope(SCOPE_IN)),
            peer("peer-out", &url_out, scope(SCOPE_OTHER)),
        ],
        3,
        2,
        None,
    );
    (cfg, st_in, st_out)
}

/// One sibling case: the in-scope peer meets quorum, the other gets nothing.
macro_rules! sibling_case {
    ($name:ident, $cfg:ident => $call:expr) => {
        #[tokio::test]
        async fn $name() {
            let ($cfg, st_in, st_out) = two_peers().await;
            let tracker = $call.await.expect("dispatch");
            tracker
                .finalise(Instant::now())
                .expect("the in-scope peer meets quorum");
            assert_eq!(st_in.hits(), 1, "the in-scope peer gets the push");
            assert_eq!(st_out.hits(), 0, "the out-of-scope peer gets nothing");
        }
    };
}

/// One unresolved case: an id with no recorded namespace sends nothing.
macro_rules! unresolved_case {
    ($name:ident, $cfg:ident => $call:expr) => {
        #[tokio::test]
        async fn $name() {
            let ($cfg, st_in, st_out) = two_peers().await;
            let tracker = $call.await.expect("dispatch");
            assert_eq!(
                quorum_reason(tracker.finalise(Instant::now())),
                QuorumFailureReason::OutboundScope
            );
            assert_eq!(st_in.hits(), 0, "an unresolved id is not sent");
            assert_eq!(st_out.hits(), 0);
        }
    };
}

fn ns_of(id: &str) -> ItemNamespaces {
    ItemNamespaces::of(id, NS_IN)
}

fn link() -> ai_memory::models::MemoryLink {
    ai_memory::models::MemoryLink {
        source_id: "link-src".to_string(),
        target_id: "link-dst".to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: "2026-11-23T00:00:00+00:00".to_string(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

fn link_namespaces() -> ItemNamespaces {
    let mut m = ItemNamespaces::new();
    m.insert("link-src", NS_IN);
    m.insert("link-dst", NS_IN);
    m
}

fn pending() -> ai_memory::models::PendingAction {
    ai_memory::models::PendingAction {
        id: "pending-1".to_string(),
        action_type: "store".to_string(),
        memory_id: None,
        namespace: NS_IN.to_string(),
        payload: serde_json::json!({}),
        requested_by: SENDER.to_string(),
        requested_at: "2026-11-23T00:00:00+00:00".to_string(),
        status: "pending".to_string(),
        decided_by: None,
        decided_at: None,
        approvals: Vec::new(),
    }
}

fn decision() -> ai_memory::models::PendingDecision {
    ai_memory::models::PendingDecision {
        id: "pending-1".to_string(),
        approved: true,
        decider: SENDER.to_string(),
    }
}

fn transition() -> sync::ActionTransitionOp {
    sync::ActionTransitionOp {
        action_id: "action-1".to_string(),
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

fn checkpoint() -> ai_memory::models::Checkpoint {
    ai_memory::models::Checkpoint {
        id: "checkpoint-1".to_string(),
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

fn signal() -> ai_memory::models::signal::Signal {
    ai_memory::models::signal::Signal {
        id: "signal-1".to_string(),
        namespace: NS_IN.to_string(),
        from_agent: SENDER.to_string(),
        to_agent: None,
        subject: "scope".to_string(),
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

fn meta() -> ai_memory::models::NamespaceMetaEntry {
    ai_memory::models::NamespaceMetaEntry {
        namespace: NS_IN.to_string(),
        standard_id: "std-1".to_string(),
        parent_namespace: None,
        updated_at: "2026-11-23T00:00:00+00:00".to_string(),
    }
}

sibling_case!(sibling_store_9996, cfg => sync::broadcast_store_quorum(&cfg, &memory("s-store", NS_IN)));
sibling_case!(sibling_store_with_embedding_9996, cfg =>
    sync::broadcast_store_quorum_with_embedding(&cfg, &memory("s-emb", NS_IN), None));
sibling_case!(sibling_delete_9996, cfg =>
    sync::broadcast_delete_quorum(&cfg, "s-del", &ns_of("s-del")));
sibling_case!(sibling_delete_batch_9996, cfg =>
sync::broadcast_delete_batch_quorum(&cfg, &["s-b1".to_string(), "s-b2".to_string()], &{
    let mut m = ns_of("s-b1");
    m.insert("s-b2", NS_IN);
    m
}));
sibling_case!(sibling_archive_9996, cfg =>
    sync::broadcast_archive_quorum(&cfg, "s-arc", &ns_of("s-arc")));
sibling_case!(sibling_restore_9996, cfg =>
    sync::broadcast_restore_quorum(&cfg, "s-res", &ns_of("s-res")));
sibling_case!(sibling_link_9996, cfg =>
    sync::broadcast_link_quorum(&cfg, &link(), &link_namespaces()));
sibling_case!(sibling_consolidate_9996, cfg =>
sync::broadcast_consolidate_quorum(
    &cfg,
    &memory("s-cons-new", NS_IN),
    &["s-cons-a".to_string()],
    &[memory("s-cons-a", NS_IN)],
    &[],
));
sibling_case!(sibling_pending_9996, cfg => sync::broadcast_pending_quorum(&cfg, &pending()));
sibling_case!(sibling_pending_decision_9996, cfg =>
    sync::broadcast_pending_decision_quorum(&cfg, &decision(), &ns_of("pending-1")));
sibling_case!(sibling_action_transition_9996, cfg =>
    sync::broadcast_action_transition_quorum(&cfg, &transition(), &ns_of("action-1")));
sibling_case!(sibling_checkpoint_resolution_9996, cfg =>
    sync::broadcast_checkpoint_resolution_quorum(&cfg, &checkpoint()));
sibling_case!(sibling_signal_create_9996, cfg =>
    sync::broadcast_signal_create_quorum(&cfg, &signal()));
sibling_case!(sibling_namespace_meta_9996, cfg =>
    sync::broadcast_namespace_meta_quorum(&cfg, &meta()));
sibling_case!(sibling_namespace_meta_clear_9996, cfg =>
    sync::broadcast_namespace_meta_clear_quorum(&cfg, &[NS_IN.to_string()]));

unresolved_case!(unresolved_delete_9996, cfg =>
    sync::broadcast_delete_quorum(&cfg, "u-del", &ItemNamespaces::new()));
unresolved_case!(unresolved_delete_batch_9996, cfg =>
    sync::broadcast_delete_batch_quorum(&cfg, &["u-b1".to_string()], &ItemNamespaces::new()));
unresolved_case!(unresolved_archive_9996, cfg =>
    sync::broadcast_archive_quorum(&cfg, "u-arc", &ItemNamespaces::new()));
unresolved_case!(unresolved_restore_9996, cfg =>
    sync::broadcast_restore_quorum(&cfg, "u-res", &ItemNamespaces::new()));
unresolved_case!(unresolved_link_9996, cfg =>
    sync::broadcast_link_quorum(&cfg, &link(), &ns_of("link-src")));
unresolved_case!(unresolved_pending_decision_9996, cfg =>
    sync::broadcast_pending_decision_quorum(&cfg, &decision(), &ItemNamespaces::new()));
unresolved_case!(unresolved_action_transition_9996, cfg =>
    sync::broadcast_action_transition_quorum(&cfg, &transition(), &ItemNamespaces::new()));
unresolved_case!(out_of_scope_store_9996, cfg =>
    sync::broadcast_store_quorum(&cfg, &memory("u-store", NS_OUT)));
unresolved_case!(out_of_scope_namespace_meta_clear_9996, cfg =>
    sync::broadcast_namespace_meta_clear_quorum(&cfg, &[NS_OUT.to_string()]));

#[tokio::test]
async fn consolidate_cuts_out_of_scope_sources_for_a_narrowed_peer_9996() {
    let (cfg, st_in, st_out) = two_peers().await;
    let tracker = sync::broadcast_consolidate_quorum(
        &cfg,
        &memory("c-new", NS_IN),
        &["c-in".to_string(), "c-out".to_string()],
        &[memory("c-in", NS_IN), memory("c-out", NS_OUT)],
        &[],
    )
    .await
    .expect("dispatch");
    tracker.finalise(Instant::now()).expect("quorum");
    assert_eq!(st_out.hits(), 0);
    let bodies = st_in.bodies();
    assert_eq!(bodies.len(), 1);
    let text = bodies[0].to_string();
    assert!(text.contains("c-in"), "{text}");
    assert!(
        !text.contains("c-out"),
        "an out-of-scope source leaks: {text}"
    );
}

#[tokio::test]
async fn bulk_catchup_push_sends_only_in_scope_rows_9996() {
    let (cfg, st_in, st_out) = two_peers().await;
    let errors =
        sync::bulk_catchup_push(&cfg, &[memory("k-in", NS_IN), memory("k-out", NS_OUT)]).await;
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(st_out.hits(), 0);
    let bodies = st_in.bodies();
    assert_eq!(bodies.len(), 1);
    let ids: Vec<&str> = bodies[0]["memories"]
        .as_array()
        .expect("memories")
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert_eq!(ids, vec!["k-in"]);
}

// ---------------------------------------------------------------------------
// PostgreSQL cells (same assertions through the trait)
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
async fn pg_sink() -> Option<Arc<dyn FederationDlqSink>> {
    use ai_memory::federation::push_dlq::PostgresDlqSink;
    use ai_memory::store::postgres::PostgresStore;
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("test skipped: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("AI_MEMORY_TEST_POSTGRES_URL is set, so the store must connect");
    Some(Arc::new(PostgresDlqSink::new(Arc::new(store))))
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pre_seeded_out_of_scope_row_is_quarantined_kept_and_redriven_postgres_9996() {
    let Some(sink) = pg_sink().await else { return };
    pre_seeded_out_of_scope_cell(sink, None).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn unparseable_2xx_is_transient_and_bounded_by_the_ceiling_postgres_9996() {
    let Some(sink) = pg_sink().await else { return };
    transient_ceiling_cell(sink, None).await;
}
