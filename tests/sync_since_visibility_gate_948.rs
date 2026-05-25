// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on the regression we pin.
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::too_many_lines)]

//! Issue #948 — federation `/sync/since` scope=private visibility
//! gate regression (security-medium, Track A QC sweep 2026-05-20).
//!
//! Pre-#948 `src/handlers/federation_sync_since.rs::sync_since`
//! applied ONLY the per-peer namespace allowlist (#239) before
//! projecting rows to the federation peer. Rows whose namespace
//! matched the allowlist but whose `metadata.scope == "private"`
//! (and whose `metadata.agent_id` belonged to an agent that had NOT
//! consented to share with this peer) were still projected — a
//! federation-mediated cross-tenant disclosure that violated the
//! documented `scope=private` NHI contract.
//!
//! The fix:
//!
//! 1. The handler resolves a `federation_caller` identity from
//!    `X-Peer-Id` (wire-attested peer identity, primary) with
//!    `X-Agent-Id` (the syncing daemon's principal, fallback) and
//!    `""` (default-deny on miss).
//! 2. Every row that survives the namespace allowlist is then
//!    post-filtered through the canonical
//!    `crate::visibility::is_visible_to_caller` helper (landed in
//!    commit `4d30dd638` / #951): a scope=private row is projected
//!    ONLY when `federation_caller` matches either the
//!    `metadata.agent_id` owner OR the `metadata.target_agent_id`
//!    inbox target.
//! 3. The response envelope grows a `excluded_for_scope_private`
//!    counter so operators can tell namespace-filtered rows
//!    (`excluded_for_scope`, #239) apart from scope=private-filtered
//!    rows (`excluded_for_scope_private`, #948).
//!
//! Cases covered:
//!
//! - `peer_cannot_pull_scope_private_row_owned_by_other_agent_948`:
//!   the load-bearing leak — alice owns a `scope=private` row in an
//!   allowlisted namespace; a peer whose X-Peer-Id is NOT alice (and
//!   whose X-Agent-Id fallback is also NOT alice) MUST get zero
//!   rows and `excluded_for_scope_private == 1`.
//! - `owner_peer_can_pull_own_scope_private_row_948`: when the
//!   federation caller's identity (via X-Peer-Id) equals the row
//!   owner, the row is still projected (owner exemption).
//! - `inbox_target_can_pull_scope_private_row_948`: the inbox
//!   carve-out — a sender stamped `target_agent_id` so the recipient
//!   (matched against X-Peer-Id) can still pull the inbox row.
//! - `shared_scope_row_unaffected_948`: a `scope=shared` row in an
//!   allowlisted namespace is projected to every peer regardless of
//!   the scope filter — confirms the post-filter doesn't over-block.

use ai_memory::models::ConfidenceSource;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex so the env-var manipulations don't
/// race on parallel `cargo test`. `tokio::sync::Mutex` (not
/// `std::sync::Mutex`) so the guard can be held across the
/// `oneshot().await` without tripping `clippy::await_holding_lock`.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let path = std::path::PathBuf::from(":memory:");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path,
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"),
        )
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(None),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db)
}

async fn seed_with_metadata(db: &ai_memory::handlers::Db, ns: &str, title: &str, metadata: Value) {
    let lock = db.lock().await;
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: ns.into(),
        title: title.into(),
        content: "x".into(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-948".into(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(&lock.0, &mem).expect("seed insert");
}

fn reset_env() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
}

/// Issue the `/api/v1/sync/since` GET with the given headers and
/// return the (status, parsed-body) pair. Caller chooses which of
/// `X-Peer-Id` / `X-Agent-Id` to send to exercise the federation-
/// caller resolution ladder.
async fn sync_since_with_headers(
    router: axum::Router,
    peer_id: Option<&str>,
    agent_id: Option<&str>,
) -> (StatusCode, Value) {
    let mut req_builder = Request::builder()
        .method("GET")
        .uri("/api/v1/sync/since")
        .header("content-type", "application/json");
    if let Some(p) = peer_id {
        req_builder =
            req_builder.header(ai_memory::federation::peer_attestation::PEER_ID_HEADER, p);
    }
    if let Some(a) = agent_id {
        req_builder = req_builder.header("x-agent-id", a);
    }
    let req = req_builder.body(Body::empty()).unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Set the operator allowlist so `peer-x` is permitted to pull the
/// `shared-948/*` namespace. The visibility gate must enforce the
/// scope=private contract ON TOP OF that namespace permission.
fn install_allowlist_for(peer: &str) {
    let allowlist = format!(
        r#"{{
            "{peer}": {{
                "allowed_namespaces": ["shared-948/*"]
            }}
        }}"#
    );
    unsafe {
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            allowlist,
        );
    }
}

#[tokio::test]
async fn peer_cannot_pull_scope_private_row_owned_by_other_agent_948() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    install_allowlist_for("peer-bob");

    let (router, db) = build_router_with_db();
    // Alice's scope=private row in an allowlisted namespace.
    seed_with_metadata(
        &db,
        "shared-948/alpha",
        "alice-private-948",
        json!({"agent_id": "alice", "scope": "private"}),
    )
    .await;

    // Peer's identity (X-Peer-Id "peer-bob"; X-Agent-Id fallback "bob")
    // is NEITHER the row owner NOR the inbox target. The row MUST be
    // dropped by the visibility post-filter.
    let (status, body) = sync_since_with_headers(router, Some("peer-bob"), Some("bob")).await;

    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);

    assert_eq!(
        status,
        StatusCode::OK,
        "#948: sync_since must always 200; body={body}"
    );
    let mems = body["memories"].as_array().expect("memories array");
    assert!(
        mems.is_empty(),
        "#948 LEAK: peer-bob (not owner, not target) MUST NOT receive \
         alice's scope=private row; got {} row(s); body={body}",
        mems.len()
    );
    assert_eq!(
        body["excluded_for_scope_private"], 1,
        "#948: the dropped scope=private row MUST be reported via \
         excluded_for_scope_private; body={body}"
    );
    assert_eq!(
        body["excluded_for_scope"], 0,
        "#948: namespace filter must NOT have dropped this row \
         (shared-948/alpha matches the allowlist); body={body}"
    );
}

#[tokio::test]
async fn owner_peer_can_pull_own_scope_private_row_948() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    install_allowlist_for("alice");

    let (router, db) = build_router_with_db();
    seed_with_metadata(
        &db,
        "shared-948/beta",
        "alice-private-948",
        json!({"agent_id": "alice", "scope": "private"}),
    )
    .await;

    // Federation caller resolves to "alice" via X-Peer-Id. The owner
    // exemption in `is_visible_to_caller` MUST project the row.
    let (status, body) = sync_since_with_headers(router, Some("alice"), None).await;

    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);

    assert_eq!(status, StatusCode::OK, "#948: status; body={body}");
    let mems = body["memories"].as_array().expect("memories array");
    assert_eq!(
        mems.len(),
        1,
        "#948 owner-exemption: alice MUST be able to pull her own \
         scope=private row over federation; body={body}"
    );
    assert_eq!(
        body["excluded_for_scope_private"], 0,
        "#948: owner-exemption MUST NOT count the row as excluded; \
         body={body}"
    );
}

#[tokio::test]
async fn inbox_target_can_pull_scope_private_row_948() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    install_allowlist_for("alice");

    let (router, db) = build_router_with_db();
    // Carol stamped an inbox-style row addressed to alice. Sender
    // ownership is carol; alice is the target. Alice's federation
    // pull (X-Peer-Id "alice") MUST still receive the row because
    // the inbox carve-out matches her against `target_agent_id`.
    seed_with_metadata(
        &db,
        "shared-948/gamma",
        "carol-to-alice-948",
        json!({
            "agent_id": "carol",
            "scope": "private",
            "target_agent_id": "alice",
        }),
    )
    .await;

    let (status, body) = sync_since_with_headers(router, Some("alice"), None).await;

    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);

    assert_eq!(status, StatusCode::OK, "#948: status; body={body}");
    let mems = body["memories"].as_array().expect("memories array");
    assert_eq!(
        mems.len(),
        1,
        "#948 inbox carve-out: alice as target_agent_id MUST receive \
         the scope=private inbox row; body={body}"
    );
    assert_eq!(
        body["excluded_for_scope_private"], 0,
        "#948 inbox carve-out: row visible to target MUST NOT be \
         counted as excluded; body={body}"
    );
}

#[tokio::test]
async fn shared_scope_row_unaffected_948() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    install_allowlist_for("peer-bob");

    let (router, db) = build_router_with_db();
    // Same setup as the leak case BUT scope=shared. The post-filter
    // MUST NOT touch this row — the predicate's first branch returns
    // true on `scope != "private"`.
    seed_with_metadata(
        &db,
        "shared-948/delta",
        "alice-shared-948",
        json!({"agent_id": "alice", "scope": "shared"}),
    )
    .await;

    let (status, body) = sync_since_with_headers(router, Some("peer-bob"), Some("bob")).await;

    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);

    assert_eq!(status, StatusCode::OK, "#948: status; body={body}");
    let mems = body["memories"].as_array().expect("memories array");
    assert_eq!(
        mems.len(),
        1,
        "#948 false-positive guard: scope=shared row MUST flow through \
         the visibility filter unchanged; body={body}"
    );
    assert_eq!(
        body["excluded_for_scope_private"], 0,
        "#948 false-positive guard: scope=shared row MUST NOT be \
         counted as excluded; body={body}"
    );
}
