// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3341a — postgres HTTP GET-by-id must use `get_links_for_anchor`
//! (DENIED: full-table `list_links`; ALLOWED: only the anchor's edges).

#![cfg(feature = "sal")]
#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::cast_possible_wrap
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{
    AgentRegistration, ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink,
    MemoryLinkRelation, Tier,
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

const CALLER: &str = "kw-read-3341a";
const ANCHOR: &str = "anchor-3341a";

/// Once-gated env write for unsigned test stores. Lives at module scope
/// so it is not an item-after-statement inside [`build_pg_router`]
/// (`clippy::items_after_statements`, pedantic — CI Lint).
static REQUIRE_ATTESTATION_OFF: std::sync::Once = std::sync::Once::new();

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

fn edge(source: &str, target: &str) -> MemoryLink {
    MemoryLink {
        source_id: source.to_string(),
        target_id: target.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// Counts `list_links` vs `get_links_for_anchor`. `list_links` returns
/// poison edges that must NEVER appear on GET-by-id.
struct ProbeStore {
    list_links: AtomicUsize,
    get_links_for_anchor: AtomicUsize,
}

impl ProbeStore {
    fn new() -> Self {
        Self {
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
        Ok(vec![])
    }
    async fn search(
        &self,
        _ctx: &CallerContext,
        _query: &str,
        _filter: &Filter,
    ) -> StoreResult<Vec<Memory>> {
        Ok(vec![])
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
        Ok(vec![
            edge("unrelated-a", "unrelated-b"),
            edge("unrelated-c", "unrelated-d"),
        ])
    }
    async fn get_links_for_anchor(&self, anchor_id: &str) -> StoreResult<Vec<MemoryLink>> {
        self.get_links_for_anchor.fetch_add(1, Ordering::SeqCst);
        Ok(vec![edge(anchor_id, "only-this-target")])
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
    // SAFETY: Once-gated process-global env write for unsigned test stores.
    REQUIRE_ATTESTATION_OFF
        .call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
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
        llm_call_timeout: std::time::Duration::from_secs(30),
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
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
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

/// DENIED: GET-by-id must not walk `list_links` (full-table scan).
/// ALLOWED: it calls `get_links_for_anchor` once and returns only that
/// anchor's edges (poison edges from `list_links` must not appear).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_get_memory_uses_anchor_links_not_full_table_scan() {
    let probe = Arc::new(ProbeStore::new());
    let store: Arc<dyn MemoryStore> = probe.clone();
    let (router, _f) = build_pg_router(store);
    let (status, body) = get_json(&router, &format!("/api/v1/memories/{ANCHOR}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["memory"]["id"], ANCHOR);
    assert_eq!(
        probe.list_links.load(Ordering::SeqCst),
        0,
        "DENIED: GET-by-id must not walk list_links(None)"
    );
    assert_eq!(
        probe.get_links_for_anchor.load(Ordering::SeqCst),
        1,
        "ALLOWED: GET-by-id must use get_links_for_anchor"
    );
    let links = body["links"].as_array().expect("links array");
    assert_eq!(links.len(), 1, "exactly the anchor's edges: {body}");
    assert_eq!(links[0]["source_id"], ANCHOR);
    assert_eq!(links[0]["target_id"], "only-this-target");
    for l in links {
        assert_ne!(l["source_id"], "unrelated-a");
        assert_ne!(l["source_id"], "unrelated-c");
    }
}
