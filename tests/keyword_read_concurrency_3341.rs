// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3341 — keyword-read path must not serialise concurrent HTTP GETs /
//! lists / searches behind a single full-table `list_links(None)` scan
//! (or any other per-request global lock on the postgres handler).
//!
//! Two pins:
//!
//! 1. **GET-by-id uses `get_links_for_anchor`, never `list_links`.** A
//!    probe store panics (fails the test) if the handler still walks the
//!    full edge table.
//! 2. **128-concurrent keyword reads exceed 16-concurrent throughput by
//!    ≥2×** against a lock-free store whose per-call cost is an async
//!    sleep. If the handler still held a mutex across the SAL await, both
//!    concurrencies would collapse to the same ops/s.

#![cfg(feature = "sal")]
#![allow(
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{
    AgentRegistration, ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink, Tier,
};
use ai_memory::store::{
    CallerContext, Capabilities, Filter, MemoryStore, StoreResult, UpdatePatch, VerifyReport,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

const DELAY: Duration = Duration::from_millis(20);
const CALLER: &str = "kw-read-3341";

fn dummy_memory(id: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "kw-read".into(),
        title: id.into(),
        content: "body".into(),
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "user".into(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": CALLER, "scope": "agent"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
        cid: None,
        valid_from: None,
        valid_until: None,
    }
}

/// Lock-free SAL adapter. `get` / `list` / `search` take an async delay
/// (yields the tokio worker) so concurrent handlers can overlap. Counts
/// `list_links` vs `get_links_for_anchor` so a GET-by-id regression that
/// re-introduces the full-table scan fails closed.
struct ProbeStore {
    delay: Duration,
    list_links: AtomicUsize,
    get_links_for_anchor: AtomicUsize,
}

impl ProbeStore {
    fn new(delay: Duration) -> Self {
        Self {
            delay,
            list_links: AtomicUsize::new(0),
            get_links_for_anchor: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl MemoryStore for ProbeStore {
    fn capabilities(&self) -> Capabilities {
        Capabilities::DURABLE
    }
    async fn store(&self, _ctx: &CallerContext, mem: &Memory) -> StoreResult<String> {
        Ok(mem.id.clone())
    }
    async fn get(&self, _ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
        tokio::time::sleep(self.delay).await;
        Ok(dummy_memory(id))
    }
    async fn update(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _patch: UpdatePatch,
    ) -> StoreResult<()> {
        Ok(())
    }
    async fn delete(&self, _ctx: &CallerContext, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    async fn list(&self, _ctx: &CallerContext, _filter: &Filter) -> StoreResult<Vec<Memory>> {
        tokio::time::sleep(self.delay).await;
        Ok(vec![dummy_memory("listed")])
    }
    async fn search(
        &self,
        _ctx: &CallerContext,
        _query: &str,
        _filter: &Filter,
    ) -> StoreResult<Vec<Memory>> {
        tokio::time::sleep(self.delay).await;
        Ok(vec![dummy_memory("searched")])
    }
    async fn verify(&self, _ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
        Ok(VerifyReport {
            memory_id: id.to_string(),
            integrity_ok: true,
            findings: vec![],
            signature_verified: false,
            cid_ok: None,
            cid_mismatch: None,
        })
    }
    async fn link(&self, _ctx: &CallerContext, _link: &MemoryLink) -> StoreResult<()> {
        Ok(())
    }
    async fn list_links(&self, _ns: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
        self.list_links.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
    async fn get_links_for_anchor(&self, _anchor_id: &str) -> StoreResult<Vec<MemoryLink>> {
        self.get_links_for_anchor.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
    async fn register_agent(
        &self,
        _ctx: &CallerContext,
        _agent: &AgentRegistration,
    ) -> StoreResult<()> {
        Ok(())
    }
}

fn build_pg_router(store: Arc<dyn MemoryStore>) -> (axum::Router, NamedTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: Once-gated process-global env write for unsigned test stores.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let db: Db = Arc::new(Mutex::new((conn, db_path, ResolvedTtl::default(), true)));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
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
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), f)
}

async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("X-Agent-Id", CALLER)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_get_memory_uses_get_links_for_anchor_not_list_links() {
    let probe = Arc::new(ProbeStore::new(Duration::ZERO));
    let store: Arc<dyn MemoryStore> = probe.clone();
    let (router, _f) = build_pg_router(store);
    let (status, body) = get_json(&router, "/api/v1/memories/exists-3341").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["memory"]["id"], "exists-3341");
    assert_eq!(
        probe.list_links.load(Ordering::SeqCst),
        0,
        "GET-by-id must not walk list_links(None)"
    );
    assert_eq!(
        probe.get_links_for_anchor.load(Ordering::SeqCst),
        1,
        "GET-by-id must use get_links_for_anchor"
    );
}

async fn hammer(router: &axum::Router, n: usize, path: &str) -> (Duration, usize) {
    let start = Instant::now();
    let mut joins = Vec::with_capacity(n);
    for _ in 0..n {
        let r = router.clone();
        let p = path.to_string();
        joins.push(tokio::spawn(async move {
            let (status, _) = get_json(&r, &p).await;
            status
        }));
    }
    let mut ok = 0usize;
    for j in joins {
        if j.await.expect("join") == StatusCode::OK {
            ok += 1;
        }
    }
    (start.elapsed(), ok)
}

/// 128-concurrent keyword GETs on the postgres handler must deliver at
/// least 2× the ops/s of 16-concurrent GETs. The store itself is
/// lock-free (async sleep); a handler-side mutex across the SAL await
/// would collapse both concurrencies to the same throughput.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn pg_keyword_get_128_concurrent_exceeds_16_concurrent_by_2x() {
    let probe = Arc::new(ProbeStore::new(DELAY));
    let store: Arc<dyn MemoryStore> = probe.clone();
    let (router, _f) = build_pg_router(store);

    // Warm the router / identity path.
    let (warm, _) = get_json(&router, "/api/v1/memories/warm").await;
    assert_eq!(warm, StatusCode::OK);

    let (t16, ok16) = hammer(&router, 16, "/api/v1/memories/n16").await;
    let (t128, ok128) = hammer(&router, 128, "/api/v1/memories/n128").await;
    assert_eq!(ok16, 16, "16-concurrent GETs must all succeed");
    assert_eq!(ok128, 128, "128-concurrent GETs must all succeed");

    let ops16 = 16.0 / t16.as_secs_f64().max(1e-9);
    let ops128 = 128.0 / t128.as_secs_f64().max(1e-9);
    assert!(
        ops128 >= ops16 * 2.0,
        "128-concurrent keyword GET throughput ({ops128:.1} ops/s in {t128:?}) \
         must be ≥2× 16-concurrent ({ops16:.1} ops/s in {t16:?}); \
         list_links={} get_links_for_anchor={}",
        probe.list_links.load(Ordering::SeqCst),
        probe.get_links_for_anchor.load(Ordering::SeqCst)
    );
    assert_eq!(
        probe.list_links.load(Ordering::SeqCst),
        0,
        "no GET may call list_links"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn pg_keyword_list_128_concurrent_exceeds_16_concurrent_by_2x() {
    let probe = Arc::new(ProbeStore::new(DELAY));
    let store: Arc<dyn MemoryStore> = probe;
    let (router, _f) = build_pg_router(store);
    let (warm, _) = get_json(&router, "/api/v1/memories?limit=1").await;
    assert_eq!(warm, StatusCode::OK);

    let (t16, ok16) = hammer(&router, 16, "/api/v1/memories?limit=1").await;
    let (t128, ok128) = hammer(&router, 128, "/api/v1/memories?limit=1").await;
    assert_eq!(ok16, 16);
    assert_eq!(ok128, 128);
    let ops16 = 16.0 / t16.as_secs_f64().max(1e-9);
    let ops128 = 128.0 / t128.as_secs_f64().max(1e-9);
    assert!(
        ops128 >= ops16 * 2.0,
        "128-concurrent list throughput ({ops128:.1} ops/s in {t128:?}) \
         must be ≥2× 16-concurrent ({ops16:.1} ops/s in {t16:?})"
    );
}
