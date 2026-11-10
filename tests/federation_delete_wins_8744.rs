// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8744 — delete wins: once a delete of a memory id commits, no store body
//! written before that delete may be applied for the id on any node, on either
//! backend, in any interleaving.
//!
//! - Receiver, unknown id: a federated delete of an id this node does not hold
//!   records a forget-tombstone, so a store body that arrives LATER (a detached
//!   POST overtaken by the delete fan-out, a DLQ replay, a catch-up page) is
//!   refused with `FORGET_TOMBSTONE_DROP_MSG` and the id stays absent.
//! - W1: a DLQ replay batch taken BEFORE the delete committed is re-checked at
//!   send time and never POSTs the store body.
//! - W3: a store body landing in the DLQ after the delete neither writes a row
//!   for the erased id nor overwrites the delete's pending row.
//! - A genuinely new memory (new id) is unaffected.
//! - Stress: concurrent receive and delete of the same ids always end with
//!   every id absent and tombstoned.
//!
//! No sleep is an ordering device: the W1 interleaving is forced by a sink that
//! commits the delete inside `take_pending_dlq_rows`; the stress threads start
//! on a `Barrier`.

#![cfg(feature = "sal")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex as StdMutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use tokio::net::TcpListener;

use ai_memory::federation::push_dlq::{
    FederationDlqSink, FederationPushDlqRow, SentinelExpansion, SqliteDlqSink, replay_once,
};
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::replication::QuorumPolicy;
use ai_memory::storage::{
    FORGET_TOMBSTONE_DROP_MSG, UNHELD_DELETE_TOMBSTONE_NAMESPACE, memory_is_tombstoned,
};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

/// The agent every fixture memory and caller context is stamped with.
const TEST_AGENT: &str = "ai:hc8744-test";
/// The one configured peer of the replay fixture.
const PEER_ID: &str = "peer-0";
/// Ids raced by the stress test (each is stored and deleted concurrently).
const STRESS_IDS: usize = 64;
/// Replay batch size for the W1 test (comfortably above the one row used).
const TAKE_LIMIT: usize = 100;

fn uid(tag: &str) -> String {
    format!("hc8744-{tag}-{}", uuid::Uuid::new_v4())
}

fn memory(id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: "hc8744/delete-wins".to_string(),
        title: format!("delete-wins {id}"),
        content: "#8744 pre-delete store body".to_string(),
        tags: vec!["hc8744".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id": TEST_AGENT}),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

fn store_body(mem: &Memory) -> serde_json::Value {
    serde_json::json!({
        "sender_agent_id": TEST_AGENT,
        "memories": [mem],
        "dry_run": false,
    })
}

fn deletion_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "sender_agent_id": TEST_AGENT,
        "memories": [],
        "deletions": [id],
        "dry_run": false,
    })
}

fn scratch_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("hc8744-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("create .local-runs tempdir")
}

fn fresh_db() -> (tempfile::TempDir, ai_memory::handlers::Db) {
    let tmp = scratch_dir();
    let db_path = tmp.path().join("hc8744.db");
    let conn = ai_memory::storage::open(&db_path).expect("open sqlite");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle = Arc::new(tokio::sync::Mutex::new((conn, db_path, ttl, true)));
    (tmp, handle)
}

/// A `MakeWriter` that appends every rendered tracing line to a shared buffer.
#[derive(Clone, Default)]
struct LogSink(Arc<StdMutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogSink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("sink")).into_owned()
    }
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish()
    }
}

/// Count the refusal lines naming `id`.
fn refusals_for(logs: &str, id: &str) -> usize {
    logs.lines()
        .filter(|l| l.contains(FORGET_TOMBSTONE_DROP_MSG) && l.contains(id))
        .count()
}

fn tombstone_namespace(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT namespace FROM forget_tombstones WHERE memory_id = ?1",
        [id],
        |r| r.get(0),
    )
    .optional()
    .expect("read tombstone")
}

fn live_exists(conn: &rusqlite::Connection, id: &str) -> bool {
    ai_memory::storage::get(conn, id).expect("get").is_some()
}

// ---------------------------------------------------------------------------
// Receiver: the unknown-id delete (W5 on the receiving node)
// ---------------------------------------------------------------------------

/// A federated delete of an id this node never held records a tombstone, and
/// the store body that arrives after it (the overtaken detached POST) is
/// refused with the exact resurrection-guard reason; the id stays absent.
#[test]
fn unheld_federated_delete_refuses_a_later_store_8744() {
    let tmp = scratch_dir();
    let conn = ai_memory::storage::open(&tmp.path().join("r.db")).expect("open");
    let id = uid("unheld");

    let deleted = ai_memory::storage::delete_federated(&conn, &id).expect("delete_federated");
    assert!(!deleted, "nothing was held, so nothing was deleted");
    assert_eq!(
        tombstone_namespace(&conn, &id).as_deref(),
        Some(UNHELD_DELETE_TOMBSTONE_NAMESPACE),
        "the unheld delete must be recorded under the sentinel namespace"
    );

    let logs = LogSink::default();
    let applied = tracing::subscriber::with_default(logs.subscriber(), || {
        ai_memory::storage::insert_if_newer(&conn, &memory(&id))
    })
    .expect("a refused store is an idempotent no-op, not an error");
    assert_eq!(applied, id);
    assert_eq!(
        refusals_for(&logs.text(), &id),
        1,
        "exactly one refusal line with the resurrection-guard reason: {}",
        logs.text()
    );
    assert!(!live_exists(&conn, &id), "the deleted id must stay absent");
}

/// The scoped `deletions[]` lane (`delete_authorized`) records the same
/// tombstone for an unheld id.
#[test]
fn unheld_authorized_delete_records_a_tombstone_8744() {
    let tmp = scratch_dir();
    let conn = ai_memory::storage::open(&tmp.path().join("r.db")).expect("open");
    let id = uid("unheld-auth");
    let allow_all = |_: &str, _: &str| true;
    let deleted =
        ai_memory::storage::delete_authorized(&conn, &id, &allow_all).expect("delete_authorized");
    assert!(!deleted);
    assert!(memory_is_tombstoned(&conn, &id).expect("probe"));
    ai_memory::storage::insert_if_newer(&conn, &memory(&id)).expect("refused no-op");
    assert!(!live_exists(&conn, &id));
}

/// An id held only in `archived_memories` is not erased by a federated delete,
/// so it gets no tombstone (its restore lanes keep today's behaviour).
#[test]
fn archived_only_id_gets_no_tombstone_8744() {
    let tmp = scratch_dir();
    let conn = ai_memory::storage::open(&tmp.path().join("r.db")).expect("open");
    let id = uid("archived");
    ai_memory::storage::insert(&conn, &memory(&id)).expect("insert");
    assert!(ai_memory::storage::archive_memory(&conn, &id, Some("test")).expect("archive"));
    assert!(!live_exists(&conn, &id), "archived rows are not live");

    let deleted = ai_memory::storage::delete_federated(&conn, &id).expect("delete_federated");
    assert!(!deleted);
    assert_eq!(tombstone_namespace(&conn, &id), None);
}

/// A genuinely new memory (a NEW id) after a delete is applied: delete-wins
/// covers only the deleted id.
#[test]
fn new_id_recreate_after_delete_is_applied_8744() {
    let tmp = scratch_dir();
    let conn = ai_memory::storage::open(&tmp.path().join("r.db")).expect("open");
    let old = uid("old");
    ai_memory::storage::delete_federated(&conn, &old).expect("delete_federated");
    let mut fresh = memory(&uid("new"));
    fresh.title = memory(&old).title; // same title slot, new id
    ai_memory::storage::insert_if_newer(&conn, &fresh).expect("insert_if_newer");
    assert!(live_exists(&conn, &fresh.id), "the new id must be applied");
    assert!(!live_exists(&conn, &old));
}

/// The SAL path the `/sync/push` handler uses on sqlite: deletion of an unheld
/// id, then the store body, through `SqliteStore`.
#[tokio::test]
async fn sqlite_store_unheld_deletion_then_store_is_refused_8744() {
    let tmp = scratch_dir();
    let store = SqliteStore::open(tmp.path().join("s.db")).expect("open store");
    let ctx = CallerContext::for_agent(TEST_AGENT);
    let id = uid("sal");
    assert!(!store.apply_remote_deletion(&ctx, &id).await.expect("deletion"));
    let applied = store
        .apply_remote_memory(&ctx, &memory(&id))
        .await
        .expect("refused no-op");
    assert_eq!(applied, id);
    match store.get(&ctx, &id).await {
        Err(StoreError::NotFound { id: missing }) => assert_eq!(missing, id),
        other => panic!("the deleted id must stay absent, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// W3: the DLQ landing after a committed delete
// ---------------------------------------------------------------------------

async fn pending_rows_for(sink: &dyn FederationDlqSink, id: &str) -> Vec<FederationPushDlqRow> {
    sink.take_pending_dlq_rows(TAKE_LIMIT)
        .await
        .expect("take")
        .into_iter()
        .filter(|r| r.memory_id == id)
        .collect()
}

/// After a local delete has queued its deletion row, a late store-failure
/// landing for the same `(memory_id, peer_id)` must not overwrite it.
#[tokio::test]
async fn late_store_landing_keeps_the_pending_deletion_row_8744() {
    let (_tmp, db) = fresh_db();
    let sink = SqliteDlqSink::new(db.clone()).await.expect("sink");
    let mem = memory(&uid("w3"));
    {
        let guard = db.lock().await;
        ai_memory::storage::insert(&guard.0, &mem).expect("insert");
        assert!(ai_memory::storage::delete(&guard.0, &mem.id).expect("delete"));
    }
    sink.enqueue_push_failure(&mem.id, PEER_ID, &deletion_body(&mem.id), "delete down")
        .await
        .expect("enqueue deletion");
    sink.enqueue_push_failure(&mem.id, PEER_ID, &store_body(&mem), "store down")
        .await
        .expect("a skipped store landing is not an error");

    let rows = pending_rows_for(&sink, &mem.id).await;
    assert_eq!(rows.len(), 1, "one pending row per (memory_id, peer_id)");
    assert_eq!(rows[0].payload_json, deletion_body(&mem.id));
    assert_eq!(rows[0].last_error, "delete down");
}

/// A store-failure landing for an id whose delete already committed (and so
/// already purged its rows) writes no row at all.
#[tokio::test]
async fn store_landing_for_an_erased_id_writes_no_row_8744() {
    let (_tmp, db) = fresh_db();
    let sink = SqliteDlqSink::new(db.clone()).await.expect("sink");
    let mem = memory(&uid("w3b"));
    {
        let guard = db.lock().await;
        ai_memory::storage::insert(&guard.0, &mem).expect("insert");
        assert!(ai_memory::storage::delete(&guard.0, &mem.id).expect("delete"));
    }
    sink.enqueue_push_failure(&mem.id, PEER_ID, &store_body(&mem), "store down")
        .await
        .expect("skip is not an error");
    assert!(pending_rows_for(&sink, &mem.id).await.is_empty());
}

// ---------------------------------------------------------------------------
// W1: the replay batch taken before the delete committed
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct PeerState {
    hit_count: Arc<AtomicUsize>,
}

async fn push_handler(
    State(state): State<PeerState>,
    axum::extract::Json(_body): axum::extract::Json<serde_json::Value>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    state.hit_count.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"applied": 1, "noop": 0, "skipped": 0})),
    )
}

async fn spawn_mock_peer(state: PeerState) -> String {
    let app = Router::new()
        .route("/api/v1/sync/push", post(push_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

fn replay_cfg(peer_url: &str, sink: Arc<dyn FederationDlqSink>) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let timeout = Duration::from_secs(5);
    FederationConfig {
        policy: QuorumPolicy::new(2, 2, timeout, Duration::from_secs(30)).expect("policy"),
        peers: vec![PeerEndpoint {
            id: PEER_ID.to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client: reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("client"),
        sender_agent_id: TEST_AGENT.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: Some(sink),
    }
}

/// Forces the W1 interleaving: the local delete of `victim` commits right
/// AFTER the replay batch was taken and BEFORE it is sent.
struct DeleteAfterTake {
    inner: SqliteDlqSink,
    db: ai_memory::handlers::Db,
    victim: String,
}

#[async_trait::async_trait]
impl FederationDlqSink for DeleteAfterTake {
    async fn enqueue_push_failure(
        &self,
        memory_id: &str,
        peer_id: &str,
        payload_json: &serde_json::Value,
        last_error: &str,
    ) -> Result<(), String> {
        self.inner
            .enqueue_push_failure(memory_id, peer_id, payload_json, last_error)
            .await
    }
    async fn take_pending_dlq_rows(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationPushDlqRow>, String> {
        let rows = self.inner.take_pending_dlq_rows(limit).await?;
        let guard = self.db.lock().await;
        ai_memory::storage::delete(&guard.0, &self.victim).map_err(|e| e.to_string())?;
        Ok(rows)
    }
    async fn mark_dlq_row_replayed(&self, id: i64, expected: i32) -> Result<bool, String> {
        self.inner.mark_dlq_row_replayed(id, expected).await
    }
    async fn bump_dlq_attempt(&self, id: i64, last_error: &str) -> Result<(), String> {
        self.inner.bump_dlq_attempt(id, last_error).await
    }
    async fn pending_dlq_count(&self) -> Result<i64, String> {
        self.inner.pending_dlq_count().await
    }
    async fn note_dlq_throttled(&self, id: i64, last_error: &str) -> Result<(), String> {
        self.inner.note_dlq_throttled(id, last_error).await
    }
    async fn reset_throttled_quarantine(&self) -> Result<u64, String> {
        self.inner.reset_throttled_quarantine().await
    }
    async fn expand_erasure_sentinel(
        &self,
        row_id: i64,
        expected_attempt_count: i32,
        memory_id: &str,
        peer_ids: &[String],
        per_peer_payload: &serde_json::Value,
        per_peer_last_error: &str,
    ) -> Result<SentinelExpansion, String> {
        self.inner
            .expand_erasure_sentinel(
                row_id,
                expected_attempt_count,
                memory_id,
                peer_ids,
                per_peer_payload,
                per_peer_last_error,
            )
            .await
    }
    async fn erasure_delete_superseded_by_restore(
        &self,
        memory_id: &str,
        erasure_failed_at: &str,
    ) -> Result<bool, String> {
        self.inner
            .erasure_delete_superseded_by_restore(memory_id, erasure_failed_at)
            .await
    }
    async fn erased_memory_ids(&self, memory_ids: &[String]) -> Result<Vec<String>, String> {
        self.inner.erased_memory_ids(memory_ids).await
    }
}

#[tokio::test]
async fn replay_batch_taken_before_the_delete_is_not_posted_8744() {
    let (_tmp, db) = fresh_db();
    let mem = memory(&uid("w1"));
    {
        let guard = db.lock().await;
        ai_memory::storage::insert(&guard.0, &mem).expect("insert");
    }
    let inner = SqliteDlqSink::new(db.clone()).await.expect("sink");
    inner
        .enqueue_push_failure(&mem.id, PEER_ID, &store_body(&mem), "peer down")
        .await
        .expect("enqueue store row");
    let sink: Arc<dyn FederationDlqSink> = Arc::new(DeleteAfterTake {
        inner,
        db: db.clone(),
        victim: mem.id.clone(),
    });
    let peer = PeerState::default();
    let cfg = replay_cfg(&spawn_mock_peer(peer.clone()).await, sink.clone());

    replay_once(&cfg, sink.as_ref()).await;

    assert_eq!(
        peer.hit_count.load(Ordering::SeqCst),
        0,
        "the pre-delete store body must never reach the peer"
    );
    assert_eq!(sink.pending_dlq_count().await.expect("count"), 0);
    let guard = db.lock().await;
    assert!(!live_exists(&guard.0, &mem.id));
    assert!(memory_is_tombstoned(&guard.0, &mem.id).expect("probe"));
}

// ---------------------------------------------------------------------------
// Stress: concurrent receive and delete of the same ids
// ---------------------------------------------------------------------------

/// Two connections race a receive and a federated delete of every id (opposite
/// orders, started together on a barrier). Whatever the interleaving, every
/// id must end absent and tombstoned.
#[test]
fn concurrent_receive_and_delete_always_end_deleted_8744() {
    let tmp = scratch_dir();
    let path = tmp.path().join("stress.db");
    drop(ai_memory::storage::open(&path).expect("migrate"));
    let ids: Arc<Vec<String>> = Arc::new((0..STRESS_IDS).map(|i| uid(&format!("s{i}"))).collect());
    let start = Arc::new(Barrier::new(2));

    let receiver = {
        let (path, ids, start) = (path.clone(), Arc::clone(&ids), Arc::clone(&start));
        std::thread::spawn(move || {
            let conn = ai_memory::storage::open(&path).expect("open receiver");
            start.wait();
            for id in ids.iter() {
                ai_memory::storage::insert_if_newer(&conn, &memory(id)).expect("receive");
            }
        })
    };
    let deleter = {
        let (path, ids, start) = (path.clone(), Arc::clone(&ids), Arc::clone(&start));
        std::thread::spawn(move || {
            let conn = ai_memory::storage::open(&path).expect("open deleter");
            start.wait();
            for id in ids.iter().rev() {
                ai_memory::storage::delete_federated(&conn, id).expect("delete");
            }
        })
    };
    receiver.join().expect("receiver thread");
    deleter.join().expect("deleter thread");

    let conn = ai_memory::storage::open(&path).expect("open check");
    let resurrected: Vec<&String> = ids.iter().filter(|id| live_exists(&conn, id)).collect();
    assert!(resurrected.is_empty(), "deleted ids came back: {resurrected:?}");
    let untombstoned: Vec<&String> = ids
        .iter()
        .filter(|id| !memory_is_tombstoned(&conn, id).expect("probe"))
        .collect();
    assert!(untombstoned.is_empty(), "deletes left no record: {untombstoned:?}");
}

// ---------------------------------------------------------------------------
// PostgreSQL twins
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::federation::push_dlq::PostgresDlqSink;
    use ai_memory::store::postgres::PostgresStore;

    async fn connect() -> Option<Arc<PostgresStore>> {
        let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
            return None;
        };
        Some(Arc::new(
            PostgresStore::connect(&url).await.expect("connect postgres"),
        ))
    }

    async fn pg_tombstone_namespace(store: &PostgresStore, id: &str) -> Option<String> {
        sqlx::query_scalar("SELECT namespace FROM forget_tombstones WHERE memory_id = $1")
            .bind(id)
            .fetch_optional(store.pool())
            .await
            .expect("read tombstone")
    }

    async fn pg_absent(store: &PostgresStore, ctx: &CallerContext, id: &str) {
        match store.get(ctx, id).await {
            Err(StoreError::NotFound { id: missing }) => assert_eq!(missing, id),
            other => panic!("the deleted id must stay absent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pg_unheld_deletion_then_store_is_refused_8744() {
        let Some(store) = connect().await else { return };
        let ctx = CallerContext::for_agent(TEST_AGENT);
        let id = uid("pg-unheld");
        assert!(!store.apply_remote_deletion(&ctx, &id).await.expect("deletion"));
        assert_eq!(
            pg_tombstone_namespace(&store, &id).await.as_deref(),
            Some(UNHELD_DELETE_TOMBSTONE_NAMESPACE)
        );
        let logs = LogSink::default();
        let applied = {
            let _guard = tracing::subscriber::set_default(logs.subscriber());
            store
                .apply_remote_memory(&ctx, &memory(&id))
                .await
                .expect("refused no-op")
        };
        assert_eq!(applied, id);
        assert_eq!(refusals_for(&logs.text(), &id), 1, "{}", logs.text());
        pg_absent(&store, &ctx, &id).await;
    }

    #[tokio::test]
    async fn pg_new_id_recreate_after_delete_is_applied_8744() {
        let Some(store) = connect().await else { return };
        let ctx = CallerContext::for_agent(TEST_AGENT);
        let old = uid("pg-old");
        store.apply_remote_deletion(&ctx, &old).await.expect("deletion");
        let fresh = memory(&uid("pg-new"));
        store.apply_remote_memory(&ctx, &fresh).await.expect("apply");
        assert_eq!(store.get(&ctx, &fresh.id).await.expect("get").id, fresh.id);
    }

    #[tokio::test]
    async fn pg_late_store_landing_keeps_the_pending_deletion_row_8744() {
        let Some(store) = connect().await else { return };
        let ctx = CallerContext::for_agent(TEST_AGENT);
        let sink = PostgresDlqSink::new(Arc::clone(&store));
        let mem = memory(&uid("pg-w3"));
        store.apply_remote_memory(&ctx, &mem).await.expect("apply");
        store.delete(&ctx, &mem.id).await.expect("delete");
        sink.enqueue_push_failure(&mem.id, PEER_ID, &deletion_body(&mem.id), "delete down")
            .await
            .expect("enqueue deletion");
        sink.enqueue_push_failure(&mem.id, PEER_ID, &store_body(&mem), "store down")
            .await
            .expect("skip is not an error");
        let rows = pending_rows_for(&sink, &mem.id).await;
        assert_eq!(rows.len(), 1, "one pending row per (memory_id, peer_id)");
        assert_eq!(rows[0].payload_json, deletion_body(&mem.id));
        assert_eq!(rows[0].last_error, "delete down");
    }

    #[tokio::test]
    async fn pg_store_landing_for_an_erased_id_writes_no_row_8744() {
        let Some(store) = connect().await else { return };
        let ctx = CallerContext::for_agent(TEST_AGENT);
        let sink = PostgresDlqSink::new(Arc::clone(&store));
        let mem = memory(&uid("pg-w3b"));
        store.apply_remote_memory(&ctx, &mem).await.expect("apply");
        store.delete(&ctx, &mem.id).await.expect("delete");
        sink.enqueue_push_failure(&mem.id, PEER_ID, &store_body(&mem), "store down")
            .await
            .expect("skip is not an error");
        assert!(pending_rows_for(&sink, &mem.id).await.is_empty());
    }

    /// Concurrent receive and federated delete of the same ids on postgres
    /// (two tasks on a multi-thread runtime, started together on a barrier).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pg_concurrent_receive_and_delete_always_end_deleted_8744() {
        let Some(store) = connect().await else { return };
        let ids: Arc<Vec<String>> =
            Arc::new((0..STRESS_IDS).map(|i| uid(&format!("pgs{i}"))).collect());
        let start = Arc::new(tokio::sync::Barrier::new(2));
        let receiver = {
            let (store, ids, start) = (Arc::clone(&store), Arc::clone(&ids), Arc::clone(&start));
            tokio::spawn(async move {
                let ctx = CallerContext::for_agent(TEST_AGENT);
                start.wait().await;
                for id in ids.iter() {
                    store.apply_remote_memory(&ctx, &memory(id)).await.expect("receive");
                }
            })
        };
        let deleter = {
            let (store, ids, start) = (Arc::clone(&store), Arc::clone(&ids), Arc::clone(&start));
            tokio::spawn(async move {
                let ctx = CallerContext::for_agent(TEST_AGENT);
                start.wait().await;
                for id in ids.iter().rev() {
                    store.apply_remote_deletion(&ctx, id).await.expect("delete");
                }
            })
        };
        receiver.await.expect("receiver task");
        deleter.await.expect("deleter task");
        let ctx = CallerContext::for_agent(TEST_AGENT);
        for id in ids.iter() {
            pg_absent(&store, &ctx, id).await;
            assert!(
                pg_tombstone_namespace(&store, id).await.is_some(),
                "delete of {id} left no record"
            );
        }
    }
}
