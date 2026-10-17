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
    DISPATCH_SCAN_FAILED_SUB_ID, RETRY_BACKOFFS, dispatch_event_with_details, list_dlq,
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

#[test]
fn a_sqlite_lookup_failure_leaves_a_durable_dlq_record_7366() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dispatch.db");
    let conn = ai_memory::db::open(&path).expect("open");
    // The injected fault: `list_by_event` prepares a SELECT on `subscriptions`.
    conn.execute_batch("DROP TABLE subscriptions;")
        .expect("drop subscriptions to inject the lookup fault");

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
    let elapsed = started.elapsed();

    let rows = list_dlq(&conn, None).expect("list_dlq");
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
    assert_eq!(row.subscription_id, DISPATCH_SCAN_FAILED_SUB_ID);

    // A fresh connection: the DLQ list reads the durable record.
    let conn = ai_memory::db::open(&path).expect("reopen");
    // Surfaced: the writer sees the record in the DLQ list; another caller
    // does not.
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
    assert!(ai_memory::subscriptions::scan_failure_visible_to(
        row, &writer
    ));
    assert!(
        !ai_memory::subscriptions::scan_failure_visible_to(row, &other),
        "another caller must not see the writer's record"
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
            self.scans.fetch_add(1, Ordering::SeqCst);
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
        let elapsed = started.elapsed();

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
}
