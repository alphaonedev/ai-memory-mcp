// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#7366](https://github.com/alphaonedev/ai-memory-mcp/issues/7366) —
//! a subscription-LOOKUP error at dispatch must not drop the lifecycle event
//! of a committed row without a durable record.
//!
//! Every later failure inside the dispatcher routes to `subscription_dlq`
//! (#3191 F-5). The pre-admission step — the subscriber lookup itself — only
//! logged a WARN and returned, so a transient backend error (the postgres
//! XX000 bursts of #7130, a locked sqlite file) lost the event with nothing
//! `memory_subscription_dlq_list` could show.
//!
//! Cell A drives the SQLite funnel (`dispatch_event_with_details`) with a real
//! fault: the `subscriptions` table is gone, so `list_by_event` fails on every
//! attempt. Cell B drives the postgres funnel (`dispatch_event_postgres`)
//! through a `MemoryStore` fault double whose `list_by_namespace_prefix`
//! fails like a backend outage. Both assert (1) a durable DLQ record naming
//! the event, the committed row and the namespace, and (2) that the lookup was
//! retried on the `RETRY_BACKOFFS` ladder before the record was written.

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

use std::time::{Duration, Instant};

use ai_memory::subscriptions::{
    RETRY_BACKOFFS, dispatch_event_with_details, list_dlq,
    scan_failure::DISPATCH_SCAN_FAILED_SUB_ID,
};

const EVENT: &str = "memory_store";
const MEMORY_ID: &str = "mem-7366";
const NAMESPACE: &str = "team/ops";
#[cfg(feature = "sal")]
const WRITER: &str = "ai:writer-7366";
const MCP_CLIENT: &str = "writer-7366";

/// The least wall-clock a bounded retry on the ladder can take.
fn ladder_floor() -> Duration {
    RETRY_BACKOFFS.iter().copied().sum()
}

// ---------------------------------------------------------------------------
// CELL A — SQLite: a failing `list_by_event` leaves a durable, replayable row.
// ---------------------------------------------------------------------------

/// Poll the durable DLQ until it holds `want` rows (the sqlite retry runs off
/// the caller's thread, so the record lands after the ladder, not before the
/// dispatch call returns).
fn wait_for_rows(path: &std::path::Path, want: usize) -> Vec<ai_memory::subscriptions::DlqEntry> {
    let deadline = Instant::now() + ladder_floor() + Duration::from_secs(20);
    loop {
        let conn = ai_memory::db::open(path).expect("open for poll");
        let rows = list_dlq(&conn, None).expect("list_dlq");
        if rows.len() >= want || Instant::now() > deadline {
            return rows;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The durable DLQ rows right now (no waiting).
fn durable_rows(path: &std::path::Path) -> Vec<ai_memory::subscriptions::DlqEntry> {
    let conn = ai_memory::db::open(path).expect("open for read");
    list_dlq(&conn, None).expect("list_dlq")
}

fn faulted_db(dir: &tempfile::TempDir) -> (std::path::PathBuf, rusqlite::Connection) {
    let path = dir.path().join("dispatch.db");
    let conn = ai_memory::db::open(&path).expect("open");
    // The injected fault: `list_by_event` prepares a SELECT on `subscriptions`.
    conn.execute_batch("DROP TABLE subscriptions;")
        .expect("drop subscriptions to inject the lookup fault");
    (path, conn)
}

#[test]
fn a_sqlite_lookup_failure_leaves_a_durable_dlq_record_7366() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, conn) = faulted_db(&dir);

    // The MCP caller id the DLQ inspector will resolve for MCP client `writer-7366`.
    let writer = ai_memory::identity::resolve_agent_id(None, Some(MCP_CLIENT))
        .expect("resolve the writer id");
    let started = Instant::now();
    dispatch_event_with_details(
        &conn,
        EVENT,
        MEMORY_ID,
        NAMESPACE,
        Some(&writer),
        &path,
        Some(serde_json::json!({"note": "details-survive"})),
    );
    let returned_after = started.elapsed();
    // #7410: the caller holds the connection lock while it dispatches; the
    // ladder pauses must not run on the caller's thread.
    assert!(
        returned_after < ladder_floor(),
        "dispatch must not sleep the ladder while the caller holds the lock; took {returned_after:?}"
    );

    // #7498: the durable record exists the moment the call returns, BEFORE the
    // detached ladder runs, so a process exit in the ~6 s window loses nothing.
    let at_return = durable_rows(&path);
    assert_eq!(
        at_return.len(),
        1,
        "the record must exist when the dispatch call returns (before the ladder), got {at_return:?}"
    );
    // Let the exhausted ladder finish: it must leave the single record in place.
    std::thread::sleep((ladder_floor() + Duration::from_secs(1)).saturating_sub(started.elapsed()));
    let rows = wait_for_rows(&path, 1);
    let elapsed = started.elapsed();
    assert_eq!(
        rows.len(),
        1,
        "a lookup failure must leave exactly one durable record, got {rows:?}"
    );
    let row = &rows[0];
    assert_eq!(row.event_type, EVENT, "the record names the lost event");
    let payload: serde_json::Value = serde_json::from_str(&row.payload).expect("payload is json");
    assert_eq!(payload["memory_id"], MEMORY_ID);
    assert_eq!(payload["namespace"], NAMESPACE);
    assert_eq!(payload["agent_id"], writer.as_str());
    assert!(
        elapsed >= ladder_floor(),
        "the lookup must be retried on the RETRY_BACKOFFS ladder first; took {elapsed:?}"
    );
    assert!(
        row.subscription_id.starts_with(DISPATCH_SCAN_FAILED_SUB_ID),
        "the record sits under the failed-lookup sentinel: {}",
        row.subscription_id
    );

    // A fresh connection: the DLQ list reads the durable record.
    let conn = ai_memory::db::open(&path).expect("reopen");
    let listed = ai_memory::mcp::handle_subscription_dlq_list(
        &conn,
        &serde_json::json!({}),
        Some(MCP_CLIENT),
    )
    .expect("dlq list for the writer");
    assert_eq!(
        listed["count"], 1,
        "the writer must see the record: {listed}"
    );
    let other = ai_memory::identity::resolve_agent_id(None, Some("someone-else-7366"))
        .expect("resolve another caller");
    assert!(ai_memory::subscriptions::scan_failure::scan_failure_visible_to(row, &writer));
    assert!(
        !ai_memory::subscriptions::scan_failure::scan_failure_visible_to(row, &other),
        "another caller must not see the writer's record"
    );
}

// ---------------------------------------------------------------------------
// CELL E — #7498: a recovery on the LAST retry removes the record.
// ---------------------------------------------------------------------------

#[test]
fn e_sqlite_recovery_on_the_last_retry_removes_the_record_7498() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("recover.db");
    let conn = ai_memory::db::open(&path).expect("open");
    conn.execute_batch("ALTER TABLE subscriptions RENAME TO subscriptions_held;")
        .expect("hide subscriptions to inject the lookup fault");

    let started = Instant::now();
    dispatch_event_with_details(&conn, EVENT, MEMORY_ID, NAMESPACE, None, &path, None);
    let at_return = durable_rows(&path).len();
    assert_eq!(at_return, 1, "the record exists when the call returns");

    // Heal the table just before the LAST retry (the ladder floor is the
    // time of the final attempt).
    let heal_at = ladder_floor().saturating_sub(Duration::from_millis(700));
    std::thread::sleep(heal_at.saturating_sub(started.elapsed()));
    conn.execute_batch("ALTER TABLE subscriptions_held RENAME TO subscriptions;")
        .expect("heal subscriptions");

    let deadline = Instant::now() + ladder_floor() + Duration::from_secs(20);
    let mut left = durable_rows(&path).len();
    while left != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        left = durable_rows(&path).len();
    }
    assert_eq!(
        left, 0,
        "a retry that recovers must delete the durable record it replaces"
    );
}

// ---------------------------------------------------------------------------
// CELL C — #7409: one namespace's flood cannot starve another namespace.
// ---------------------------------------------------------------------------

#[test]
fn c_a_flooded_namespace_does_not_starve_another_namespace_7409() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, conn) = faulted_db(&dir);
    // Fill team/flooded's own bucket to its per-namespace cap.
    conn.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?2) \
         INSERT INTO subscription_dlq \
         (subscription_id, correlation_id, event_type, payload, retry_count, last_error, \
          first_failed_at, last_failed_at) \
         SELECT ?1, 'flood-' || i, 'memory_store', '{}', 0, 'flood', 'now', 'now' FROM n",
        rusqlite::params![
            format!("{DISPATCH_SCAN_FAILED_SUB_ID}:team/flooded"),
            ai_memory::subscriptions::scan_failure::SCAN_FAILURE_MAX_PER_NAMESPACE
        ],
    )
    .expect("fill the bucket to its cap");
    let before = list_dlq(&conn, None).expect("list").len();

    dispatch_event_with_details(&conn, EVENT, MEMORY_ID, "team/other", None, &path, None);

    let rows = wait_for_rows(&path, before + 1);
    assert!(
        rows.iter().any(|r| r.payload.contains("team/other")),
        "another namespace's failure must still be recorded while team/flooded is at its cap"
    );
}

/// Fill `subscription_dlq` with one failed-lookup row in each of `n` distinct
/// namespaces (the cap-defeat vector of #7430: vary the bucket key).
fn fill_distinct_namespaces(conn: &rusqlite::Connection, n: i64) {
    conn.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?2) \
         INSERT INTO subscription_dlq \
         (subscription_id, correlation_id, event_type, payload, retry_count, last_error, \
          first_failed_at, last_failed_at) \
         SELECT ?1 || ':invented-' || i, 'inv-' || i, 'memory_store', '{}', 0, 'x', 'now', 'now' \
         FROM n",
        rusqlite::params![DISPATCH_SCAN_FAILED_SUB_ID, n],
    )
    .expect("fill distinct namespaces");
}

fn failed_lookup_rows(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM subscription_dlq WHERE substr(subscription_id, 1, ?1) = ?2",
        rusqlite::params![
            i64::try_from(DISPATCH_SCAN_FAILED_SUB_ID.len()).expect("len"),
            DISPATCH_SCAN_FAILED_SUB_ID
        ],
        |r| r.get(0),
    )
    .expect("count failed-lookup rows")
}

// ---------------------------------------------------------------------------
// CELL D — #7430: inventing namespaces cannot defeat the retention cap.
// ---------------------------------------------------------------------------

#[test]
fn d_inventing_namespaces_cannot_exceed_the_total_cap_7430() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cap.db");
    let conn = ai_memory::db::open(&path).expect("open");
    let cap = ai_memory::subscriptions::MAX_SUBSCRIPTION_DLQ_ROWS;
    fill_distinct_namespaces(&conn, cap);
    assert_eq!(failed_lookup_rows(&conn), cap);

    ai_memory::subscriptions::scan_failure::record_dispatch_scan_failure(
        &path,
        &ai_memory::subscriptions::scan_failure::ScanFailure {
            event: EVENT,
            memory_id: MEMORY_ID,
            namespace: "team/one-more",
            agent_id: None,
            details: None,
        },
        "sqlite_error",
    );
    assert_eq!(
        failed_lookup_rows(&conn),
        cap,
        "the total of failed-lookup rows must stay bounded however many namespaces are invented"
    );
}

// ---------------------------------------------------------------------------
// CELL H2 — #7503: one writer cannot fill the total cap and starve a victim.
// ---------------------------------------------------------------------------

fn fill_writer_rows(conn: &rusqlite::Connection, n: i64, namespaces: i64, writer: &str) {
    conn.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?2) \
         INSERT INTO subscription_dlq \
         (subscription_id, correlation_id, event_type, payload, retry_count, last_error, \
          first_failed_at, last_failed_at) \
         SELECT ?1 || ':flood-' || (i % ?3), 'fw-' || i, 'memory_store', \
                json_object('agent_id', ?4), 0, 'x', 'now', 'now' \
         FROM n",
        rusqlite::params![DISPATCH_SCAN_FAILED_SUB_ID, n, namespaces, writer],
    )
    .expect("fill one writer");
}

fn writer_rows(conn: &rusqlite::Connection, writer: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM subscription_dlq \
         WHERE substr(subscription_id, 1, ?1) = ?2 AND json_extract(payload, '$.agent_id') = ?3",
        rusqlite::params![
            i64::try_from(DISPATCH_SCAN_FAILED_SUB_ID.len()).expect("len"),
            DISPATCH_SCAN_FAILED_SUB_ID,
            writer
        ],
        |r| r.get(0),
    )
    .expect("count writer rows")
}

fn record_for(path: &std::path::Path, namespace: &str, agent: Option<&str>) {
    ai_memory::subscriptions::scan_failure::record_dispatch_scan_failure(
        path,
        &ai_memory::subscriptions::scan_failure::ScanFailure {
            event: EVENT,
            memory_id: MEMORY_ID,
            namespace,
            agent_id: agent,
            details: None,
        },
        "sqlite_error",
    );
}

#[test]
fn h2_one_writer_cannot_fill_the_total_cap_and_starve_a_victim_7503() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("writer-cap.db");
    let conn = ai_memory::db::open(&path).expect("open");
    let cap = ai_memory::subscriptions::MAX_SUBSCRIPTION_DLQ_ROWS;
    // The r1 probe: a ten-namespace writer floods through the recorder.
    // Pre-seed 9_000 rows directly (the recorder cannot get past its caps
    // faster than one open per call), then drive the recorder to its refusal.
    fill_writer_rows(&conn, 9_000, 10, "ai:flooder");
    let mut calls = 0;
    while writer_rows(&conn, "ai:flooder") < cap && calls < 2_000 {
        let before = writer_rows(&conn, "ai:flooder");
        record_for(
            &path,
            &format!("team/flood-{}", calls % 10),
            Some("ai:flooder"),
        );
        calls += 1;
        if writer_rows(&conn, "ai:flooder") == before {
            break; // refused: the writer is at its cap
        }
    }
    eprintln!(
        "7503 flooder rows={} total={} recorder calls={calls}",
        writer_rows(&conn, "ai:flooder"),
        failed_lookup_rows(&conn)
    );

    record_for(&path, "team/victim", Some("ai:victim"));
    assert_eq!(
        writer_rows(&conn, "ai:victim"),
        1,
        "another tenant's failure must still be recorded while one writer holds the total cap"
    );

    // The flooder, already past its own cap, is refused.
    let before = writer_rows(&conn, "ai:flooder");
    record_for(&path, "team/ns-extra", Some("ai:flooder"));
    assert_eq!(
        writer_rows(&conn, "ai:flooder"),
        before,
        "a writer past its own cap is refused"
    );
}

// ---------------------------------------------------------------------------
// CELL B — postgres funnel: a failing SAL prefix scan leaves a durable row.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal")]
mod postgres_funnel {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ai_memory::handlers::{AppState, StorageBackend, dispatch_event_postgres};
    use ai_memory::models::AgentRegistration;
    use ai_memory::models::Memory;
    use ai_memory::models::MemoryLink;
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{
        CallerContext, Capabilities, Filter, MemoryStore, StoreError, StoreResult, UpdatePatch,
        VerifyReport,
    };
    use tokio::sync::{Mutex, RwLock};

    /// `MemoryStore` fault double: every required method delegates to a real
    /// `SqliteStore`; only `list_by_namespace_prefix` fails, the way a postgres
    /// outage (SQLSTATE XX000) does, and counts how often it was asked.
    struct LookupFaultStore {
        inner: SqliteStore,
        scans: AtomicUsize,
        /// The 1-based scan number from which the lookup succeeds again
        /// (`usize::MAX` = never recovers).
        recover_at: usize,
    }

    #[async_trait::async_trait]
    impl MemoryStore for LookupFaultStore {
        fn capabilities(&self) -> Capabilities {
            self.inner.capabilities()
        }
        async fn store(&self, ctx: &CallerContext, mem: &Memory) -> StoreResult<String> {
            self.inner.store(ctx, mem).await
        }
        async fn get(&self, ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
            self.inner.get(ctx, id).await
        }
        async fn update(
            &self,
            ctx: &CallerContext,
            id: &str,
            patch: UpdatePatch,
        ) -> StoreResult<()> {
            self.inner.update(ctx, id, patch).await
        }
        async fn delete(&self, ctx: &CallerContext, id: &str) -> StoreResult<()> {
            self.inner.delete(ctx, id).await
        }
        async fn list(&self, ctx: &CallerContext, filter: &Filter) -> StoreResult<Vec<Memory>> {
            self.inner.list(ctx, filter).await
        }
        async fn list_by_namespace_prefix(
            &self,
            _ctx: &CallerContext,
            _prefix: &str,
            _limit: usize,
        ) -> StoreResult<Vec<Memory>> {
            let n = self.scans.fetch_add(1, Ordering::SeqCst) + 1;
            if n >= self.recover_at {
                return Ok(Vec::new());
            }
            Err(StoreError::BackendUnavailable {
                backend: "postgres".to_string(),
                sqlstate: Some("XX000".to_string()),
                detail: "injected lookup fault (#7366)".to_string(),
            })
        }
        async fn search(
            &self,
            ctx: &CallerContext,
            query: &str,
            filter: &Filter,
        ) -> StoreResult<Vec<Memory>> {
            self.inner.search(ctx, query, filter).await
        }
        async fn verify(&self, ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
            self.inner.verify(ctx, id).await
        }
        async fn link(&self, ctx: &CallerContext, link: &MemoryLink) -> StoreResult<()> {
            self.inner.link(ctx, link).await
        }
        async fn list_links(&self, namespace: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
            self.inner.list_links(namespace).await
        }
        async fn register_agent(
            &self,
            ctx: &CallerContext,
            agent: &AgentRegistration,
        ) -> StoreResult<()> {
            self.inner.register_agent(ctx, agent).await
        }
    }

    fn make_state(store: Arc<dyn MemoryStore>) -> (AppState, std::path::PathBuf) {
        let scratch = tempfile::tempdir().expect("tempdir");
        let sqlite_path = scratch.path().join("audit.db");
        let conn = ai_memory::db::open(&sqlite_path).expect("open sqlite audit db");
        let db: ai_memory::handlers::Db = Arc::new(Mutex::new((
            conn,
            sqlite_path.clone(),
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
        let state = AppState {
            db,
            embedder: Arc::new(None),
            vector_index: Arc::new(Mutex::new(None)),
            federation: Arc::new(None),
            tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
            scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
            profile: Arc::new(ai_memory::profile::Profile::core()),
            mcp_config: Arc::new(None),
            active_keypair: Arc::new(None),
            family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
            storage_backend: StorageBackend::Postgres,
            store,
            llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
            auto_tag_model: Arc::new(None),
            llm_call_timeout: Duration::from_secs(ai_memory::config::DEFAULT_LLM_CALL_TIMEOUT_SECS),
            replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::new()),
            verify_require_nonce: false,
            federation_nonce_cache: Arc::new(
                ai_memory::identity::replay::FederationNonceCache::new(),
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
        // Keep the scratch files alive for the whole test.
        std::mem::forget(scratch);
        (state, sqlite_path)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn b_postgres_lookup_failure_leaves_a_durable_dlq_record_7366() {
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let inner = SqliteStore::open(store_dir.path().join("store.db")).expect("open store");
        let double = Arc::new(LookupFaultStore {
            inner,
            scans: AtomicUsize::new(0),
            recover_at: usize::MAX,
        });
        let (state, sqlite_path) = make_state(double.clone());

        let started = Instant::now();
        dispatch_event_postgres(
            &state,
            EVENT,
            MEMORY_ID,
            NAMESPACE,
            Some(WRITER),
            Some(serde_json::json!({"note": "details-survive"})),
        )
        .await;
        let returned_after = started.elapsed();
        // #7500: the ladder pauses must not run on the request future.
        assert!(
            returned_after < ladder_floor(),
            "the postgres dispatch must not sleep the ladder on the request future; took {returned_after:?}"
        );
        // #7499: the record exists when the call returns.
        assert_eq!(
            durable_rows(&sqlite_path).len(),
            1,
            "the record must exist when the dispatch call returns"
        );
        // The detached worker finishes the ladder: 1 + RETRY_BACKOFFS.len() scans.
        let deadline = Instant::now() + ladder_floor() + Duration::from_secs(20);
        while double.scans.load(Ordering::SeqCst) < RETRY_BACKOFFS.len() + 1
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let elapsed = started.elapsed();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let conn = ai_memory::db::open(&sqlite_path).expect("reopen audit db");
        let rows = list_dlq(&conn, None).expect("list_dlq");
        assert_eq!(
            rows.len(),
            1,
            "a lookup failure must leave exactly one durable record, got {rows:?}"
        );
        let row = &rows[0];
        assert_eq!(row.event_type, EVENT, "the record names the lost event");
        let payload: serde_json::Value =
            serde_json::from_str(&row.payload).expect("payload is json");
        assert_eq!(payload["memory_id"], MEMORY_ID);
        assert_eq!(payload["namespace"], NAMESPACE);
        assert_eq!(payload["agent_id"], WRITER);
        assert_eq!(
            double.scans.load(Ordering::SeqCst),
            RETRY_BACKOFFS.len() + 1,
            "one initial scan plus one retry per RETRY_BACKOFFS step"
        );
        assert!(
            elapsed >= ladder_floor(),
            "the retries must wait out the ladder; took {elapsed:?}"
        );
    }

    fn faulted(recover_at: usize) -> (Arc<LookupFaultStore>, AppState, std::path::PathBuf) {
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let inner = SqliteStore::open(store_dir.path().join("store.db")).expect("open store");
        std::mem::forget(store_dir);
        let double = Arc::new(LookupFaultStore {
            inner,
            scans: AtomicUsize::new(0),
            recover_at,
        });
        let (state, path) = make_state(double.clone());
        (double, state, path)
    }

    /// #7499: a cancelled request future (client disconnect, handler
    /// timeout) must still leave exactly one durable record.
    #[tokio::test(flavor = "multi_thread")]
    async fn f_postgres_cancelled_request_future_still_leaves_one_record_7499() {
        let (_double, state, path) = faulted(usize::MAX);
        let _ = tokio::time::timeout(
            Duration::from_millis(500),
            dispatch_event_postgres(&state, EVENT, MEMORY_ID, NAMESPACE, Some(WRITER), None),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let rows = durable_rows(&path);
        assert_eq!(
            rows.len(),
            1,
            "a cancelled dispatch future must still leave one durable record, got {rows:?}"
        );
    }

    /// #7498 (postgres funnel): recovery on the LAST retry deletes the record.
    #[tokio::test(flavor = "multi_thread")]
    async fn g_postgres_recovery_on_the_last_retry_removes_the_record_7498() {
        // Scan 1 + one per backoff step; the final scan succeeds.
        let (double, state, path) = faulted(RETRY_BACKOFFS.len() + 1);
        dispatch_event_postgres(&state, EVENT, MEMORY_ID, NAMESPACE, Some(WRITER), None).await;
        assert_eq!(
            durable_rows(&path).len(),
            1,
            "the record exists when the call returns"
        );
        let deadline = Instant::now() + ladder_floor() + Duration::from_secs(20);
        while Instant::now() < deadline
            && (double.scans.load(Ordering::SeqCst) < RETRY_BACKOFFS.len() + 1
                || !durable_rows(&path).is_empty())
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            durable_rows(&path).len(),
            0,
            "a retry that recovers must delete the durable record it replaces"
        );
    }

    /// #7500: three committed rows (a bulk write) must not run the ladder
    /// three times in sequence on the request future.
    #[tokio::test(flavor = "multi_thread")]
    async fn h_postgres_bulk_of_three_returns_well_under_one_ladder_7500() {
        let (_double, state, path) = faulted(usize::MAX);
        let started = Instant::now();
        for i in 0..3 {
            let id = format!("{MEMORY_ID}-{i}");
            dispatch_event_postgres(&state, EVENT, &id, NAMESPACE, Some(WRITER), None).await;
        }
        let took = started.elapsed();
        eprintln!(
            "7500 measured: 3 rows dispatched in {took:?} (ladder floor {:?})",
            ladder_floor()
        );
        assert!(
            took < ladder_floor() / 4,
            "3 postgres dispatches must return well under one ladder; took {took:?}"
        );
        assert_eq!(
            durable_rows(&path).len(),
            3,
            "each failed row has its record"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn d_postgres_inventing_namespaces_cannot_exceed_the_total_cap_7430() {
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let inner = SqliteStore::open(store_dir.path().join("store.db")).expect("open store");
        let double = Arc::new(LookupFaultStore {
            inner,
            scans: AtomicUsize::new(0),
            recover_at: usize::MAX,
        });
        let (state, sqlite_path) = make_state(double);
        let conn = ai_memory::db::open(&sqlite_path).expect("open audit db");
        let cap = ai_memory::subscriptions::MAX_SUBSCRIPTION_DLQ_ROWS;
        fill_distinct_namespaces(&conn, cap);

        dispatch_event_postgres(
            &state,
            EVENT,
            MEMORY_ID,
            "team/one-more",
            Some(WRITER),
            None,
        )
        .await;

        assert_eq!(
            failed_lookup_rows(&conn),
            cap,
            "the postgres funnel must respect the same bounded total"
        );
    }
}
