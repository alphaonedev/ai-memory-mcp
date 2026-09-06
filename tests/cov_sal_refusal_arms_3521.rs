// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3521 — SAL refusal arms: the `/sync/push` receive loop under a
//! BACKEND THAT REFUSES, and the `/links` wire-shape refusals.
//!
//! `sync_push_via_store` is the postgres-side federated receive funnel. Its
//! happy path is well covered by the live-PG suites; what was NOT covered is
//! the behaviour that actually protects the corpus — what the receiver does
//! when the store refuses an apply, and what it TELLS the peer afterwards.
//!
//! The contracts pinned here are claims-truth contracts:
//!
//! * every subcollection whose apply is refused lands in `skipped`, never in
//!   `applied` — a peer must never be told a row landed when it did not, or
//!   it will advance its watermark past data this node does not hold;
//! * a refusing backend DEGRADES the push (nothing applied) instead of
//!   corrupting the accounting or 500-ing the funnel;
//! * an ENGAGED record-stop refuses the whole push up front, before any
//!   write is attempted — the fleet halt switch is a chokepoint, not a
//!   per-operation check that a new funnel could slip past;
//! * a record-stop probe that FAILS refuses too (fail closed): an
//!   unreadable halt switch must never be read as "not stopped".
//!
//! The probe adapter implements only the required `MemoryStore` methods, so
//! every optional apply takes the trait's own `UnsupportedCapability`
//! default — exactly what a partially-implemented adapter would do.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{
    AgentRegistration, ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink,
    MemoryLinkRelation, Tier,
};
use ai_memory::store::{
    CallerContext, Capabilities, Filter, MemoryStore, StoreError, StoreResult, UpdatePatch,
    VerifyReport,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// `/sync/push` reads process-global federation env; serialise the tests
/// that set it (the established convention for the federation suites).
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const PEER: &str = "ai:cov-3521-peer";
const NS: &str = "cov-3521-fed";

/// What the probe's record-stop chokepoint answers.
#[derive(Clone, Copy)]
enum StopProbe {
    /// The default trait arm (`UnsupportedCapability`) — adapter holds no
    /// record-stop registry, so the push proceeds.
    Unsupported,
    /// The halt switch is ENGAGED.
    Engaged,
    /// The halt switch could not be read.
    Unreadable,
}

struct RefusingStore {
    stop: StopProbe,
}

#[async_trait::async_trait]
impl MemoryStore for RefusingStore {
    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }
    async fn store(&self, _ctx: &CallerContext, memory: &Memory) -> StoreResult<String> {
        Ok(memory.id.clone())
    }
    async fn get(&self, _ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
        Err(StoreError::NotFound { id: id.to_string() })
    }
    async fn update(&self, _ctx: &CallerContext, id: &str, _patch: UpdatePatch) -> StoreResult<()> {
        Err(StoreError::NotFound { id: id.to_string() })
    }
    async fn delete(&self, _ctx: &CallerContext, id: &str) -> StoreResult<()> {
        Err(StoreError::NotFound { id: id.to_string() })
    }
    async fn list(&self, _ctx: &CallerContext, _filter: &Filter) -> StoreResult<Vec<Memory>> {
        Ok(Vec::new())
    }
    async fn search(
        &self,
        _ctx: &CallerContext,
        _query: &str,
        _filter: &Filter,
    ) -> StoreResult<Vec<Memory>> {
        Ok(Vec::new())
    }
    async fn verify(&self, _ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
        Ok(VerifyReport {
            memory_id: id.to_string(),
            integrity_ok: true,
            findings: Vec::new(),
            signature_verified: false,
            cid_ok: None,
            cid_mismatch: None,
        })
    }
    async fn link(&self, _ctx: &CallerContext, _link: &MemoryLink) -> StoreResult<()> {
        Ok(())
    }
    async fn list_links(&self, _namespace: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
        Ok(Vec::new())
    }
    async fn register_agent(
        &self,
        _ctx: &CallerContext,
        _agent: &AgentRegistration,
    ) -> StoreResult<()> {
        Ok(())
    }

    async fn record_stop_status(
        &self,
        _ctx: &CallerContext,
    ) -> StoreResult<ai_memory::storage::record_stop::RecordStopStatus> {
        match self.stop {
            StopProbe::Unsupported => Err(StoreError::UnsupportedCapability {
                capability: "RECORD_STOP".to_string(),
            }),
            StopProbe::Engaged => Ok(ai_memory::storage::record_stop::RecordStopStatus {
                stopped: true,
                issued_by: "operator-3521".to_string(),
                scope: "record_plane".to_string(),
            }),
            StopProbe::Unreadable => Err(StoreError::Backend(
                ai_memory::store::BoxBackendError::new("record_stop registry unreadable"),
            )),
        }
    }
}

fn build_sal_router(stop: StopProbe) -> (axum::Router, tempfile::NamedTempFile) {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((conn, db_path, ResolvedTtl::default(), true)));
    let store: Arc<dyn MemoryStore> = Arc::new(RefusingStore { stop });
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

fn memory(id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: format!("cov-3521 {id}"),
        content: "federated row for the refusing-backend probe".to_string(),
        tags: vec!["cov-3521".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": PEER}),
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

/// SAFETY: every caller holds [`FED_ENV_LOCK`] for the duration.
unsafe fn set_permissive_fed_env() {
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
}

/// SAFETY: every caller holds [`FED_ENV_LOCK`] for the duration.
unsafe fn clear_fed_env() {
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_NONCE_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
}

async fn push(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(body).expect("serialise body"),
        ))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .expect("body");
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn full_batch() -> Value {
    let a = memory("cov3521-a");
    let b = memory("cov3521-b");
    json!({
        "sender_agent_id": PEER,
        "sender_clock": {"entries": {}},
        "sender_wall_clock": chrono::Utc::now().to_rfc3339(),
        "memories": [
            serde_json::to_value(&a).expect("memory json"),
            serde_json::to_value(&b).expect("memory json"),
        ],
        "deletions": ["cov3521-gone"],
        "archives": ["cov3521-arch"],
        "restores": ["cov3521-rest"],
        "namespace_meta_clears": [NS],
        "links": [serde_json::to_value(edge(&a.id, &b.id)).expect("link json")],
    })
}

/// A backend that refuses every optional apply must SKIP, never claim
/// `applied`. A peer that read a false `applied` would advance its
/// watermark past rows this node does not hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusing_backend_skips_every_subcollection_and_applies_nothing() {
    let _g = FED_ENV_LOCK.lock().await;
    // SAFETY: FED_ENV_LOCK is held for the whole test.
    unsafe { set_permissive_fed_env() };
    let (router, _f) = build_sal_router(StopProbe::Unsupported);
    let (status, body) = push(&router, &full_batch()).await;
    // SAFETY: same lock scope.
    unsafe { clear_fed_env() };

    assert!(
        status.is_success(),
        "a refusing backend must DEGRADE the push, not fault it; status={status} body={body}"
    );
    let applied = body["applied"].as_u64().unwrap_or_default();
    let skipped = body["skipped"].as_u64().unwrap_or_default();
    assert_eq!(
        applied, 0,
        "nothing may be reported applied when every apply was refused: {body}"
    );
    assert!(
        skipped > 0,
        "the refusals must surface as skipped so the peer does not advance: {body}"
    );
}

/// An ENGAGED record-stop refuses the whole push BEFORE any write is
/// attempted. This is the fleet halt switch: it is a chokepoint on the
/// funnel, not a per-operation check a new subcollection could miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engaged_record_stop_refuses_the_push_before_any_write() {
    let _g = FED_ENV_LOCK.lock().await;
    // SAFETY: FED_ENV_LOCK is held for the whole test.
    unsafe { set_permissive_fed_env() };
    let (router, _f) = build_sal_router(StopProbe::Engaged);
    let (status, body) = push(&router, &full_batch()).await;
    // SAFETY: same lock scope.
    unsafe { clear_fed_env() };

    assert!(
        !status.is_success(),
        "an engaged record-stop must refuse the push; status={status} body={body}"
    );
    assert!(
        body["applied"].as_u64().unwrap_or_default() == 0,
        "a stopped receiver must apply nothing: {body}"
    );
}

/// A record-stop probe that cannot be read is FAIL-CLOSED: an unreadable
/// halt switch must never be treated as "not stopped".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_record_stop_probe_refuses_the_push() {
    let _g = FED_ENV_LOCK.lock().await;
    // SAFETY: FED_ENV_LOCK is held for the whole test.
    unsafe { set_permissive_fed_env() };
    let (router, _f) = build_sal_router(StopProbe::Unreadable);
    let (status, body) = push(&router, &full_batch()).await;
    // SAFETY: same lock scope.
    unsafe { clear_fed_env() };

    assert!(
        !status.is_success(),
        "an unreadable record-stop probe must refuse the push; status={status} body={body}"
    );
    assert!(
        body["applied"].as_u64().unwrap_or_default() == 0,
        "a receiver that cannot read its halt switch must apply nothing: {body}"
    );
}

/// A sender id that is not a valid agent id is refused at the door — the
/// attribution of every row in the batch depends on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_sender_agent_id_is_refused_at_the_door() {
    let _g = FED_ENV_LOCK.lock().await;
    // SAFETY: FED_ENV_LOCK is held for the whole test.
    unsafe { set_permissive_fed_env() };
    let (router, _f) = build_sal_router(StopProbe::Unsupported);
    let (status, body) = push(
        &router,
        &json!({
            "sender_agent_id": "not a valid agent id!!",
            "sender_clock": {"entries": {}},
            "memories": [],
        }),
    )
    .await;
    // SAFETY: same lock scope.
    unsafe { clear_fed_env() };
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an invalid sender id must be refused; body={body}"
    );
}

// ---------------------------------------------------------------------------
// /links wire-shape refusals.
//
// A link is a provenance edge: `create_link` and `delete_link` both mutate
// the graph the lineage / replay / reflection surfaces walk. A body whose
// field TYPES do not match the wire contract must be refused with the parse
// fault named, never coerced into a best-guess edge — a mis-typed endpoint
// silently becoming a different id is exactly the class of corruption the
// durable text can no longer be reconciled against.
// ---------------------------------------------------------------------------

async fn send(router: &axum::Router, method: &str, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("X-Agent-Id", "ai:cov-3521-links")
        .body(Body::from(serde_json::to_vec(body).expect("serialise")))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// `POST /links` with a KNOWN field of the wrong type is a 400 that names
/// the parse fault. (The unknown-field arm is a different, already-pinned
/// refusal; this is the shape arm.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_link_refuses_a_wrongly_typed_endpoint_and_names_the_fault() {
    let (router, _f) = build_sal_router(StopProbe::Unsupported);
    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/links",
        &json!({"source_id": 7, "target_id": "cov3521-b", "relation": "related_to"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a wrongly-typed endpoint must be refused, not coerced; body={body}"
    );
    assert!(
        body["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the refusal must name the parse fault; body={body}"
    );
}

/// `DELETE /links` gets the same treatment: no guessing which edge the
/// caller meant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_link_refuses_a_wrongly_typed_endpoint_and_names_the_fault() {
    let (router, _f) = build_sal_router(StopProbe::Unsupported);
    let (status, body) = send(
        &router,
        "DELETE",
        "/api/v1/links",
        &json!({"source_id": "cov3521-a", "target_id": ["not", "a", "string"]}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a wrongly-typed endpoint must be refused, not coerced; body={body}"
    );
    assert!(
        body["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the refusal must name the parse fault; body={body}"
    );
}
