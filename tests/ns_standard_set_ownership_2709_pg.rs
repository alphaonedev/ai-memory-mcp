// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2709 (CB-4 / CWE-284, GA blocker) — POSTGRES HTTP `set_namespace_standard`
//! ownership gate must not be bypassed by the visibility fold.
//!
//! ## The exploit this file pins
//!
//! `set_namespace_standard_inner`'s postgres arm gated the bind-ownership
//! check as `if let Ok(resolved_mem) = app.store.get(&ctx, &standard_id)`.
//! `PostgresStore::get` under the tenant-scoped request `ctx`
//! (`bypass_visibility=false`) FOLDS a #910 visibility denial into
//! `Err(NotFound)`, and `is_visible_to_caller` treats a `scope=private` row
//! owned by another agent as invisible. So when `body.id` named another
//! agent's private memory, `get` returned `Err`, the `if let Ok` arm was
//! SKIPPED, NO authorization ran, and `PostgresStore::set_namespace_standard`
//! bound the row via an unfiltered SQL id lookup:
//!
//! ```text
//! POST /api/v1/namespaces/<alice-ns>/standard {"id": "<alice's private id>"}
//!   X-Agent-Id: ai:bob   ->  201, alice's private memory becomes alice-ns's
//!                            governance standard (silent authz bypass).
//! ```
//!
//! The sqlite twin never had this hole: it probes with storage-level
//! `db::get`, which does NOT fold visibility, so the foreign-owned row is
//! resolved and `authorize_namespace_standard_bind` refuses the bind. The fix
//! makes the postgres arm fetch the ownership-probe row under a
//! bypass-visibility (`for_admin(AI_HTTP_INTERNAL)`) ctx — the #2447
//! fold-avoiding precedent — so the real ownership check runs against the
//! REQUEST principal, while the row body is NEVER returned to the caller (the
//! #2537/#2707 read-path withholding is unchanged).
//!
//! Row-state assertions go through a RAW `SELECT` on `namespace_meta` rather
//! than a get-standard round-trip: the bind is what matters, and the raw read
//! is not subject to the withholding/visibility layers.
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip (the house pattern). Deliberately NOT `#[ignore]`: the PR postgres
//! job does not pass `--include-ignored`, so an ignored test silently never
//! runs (the `federation_delete_ns_scope_2488_pg.rs` precedent).

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

const ALICE: &str = "ai:alice-2709";
const BOB: &str = "ai:bob-2709";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

async fn pg_router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store: store.clone(),
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
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
    (ai_memory::build_router(api_key_state, app_state), store)
}

/// Admin ctx — the TEST's own seed write, so it is not visibility-filtered.
fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2709-pg");
    ctx.bypass_visibility = true;
    ctx
}

async fn raw_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("raw pool for namespace_meta assertions")
}

/// The bound standard id for `ns`, read raw from `namespace_meta` (not through
/// the visibility/withholding layers). `None` = no binding row / null pointer.
async fn bound_standard_id(pool: &sqlx::PgPool, ns: &str) -> Option<String> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT standard_id FROM namespace_meta WHERE namespace = $1")
            .bind(ns)
            .fetch_optional(pool)
            .await
            .expect("select namespace_meta standard_id");
    row.and_then(|(sid,)| sid)
}

/// Seed a memory owned by `owner` with an explicit `scope` into `namespace`.
async fn seed_memory(
    store: &Arc<dyn MemoryStore>,
    id: &str,
    namespace: &str,
    owner: &str,
    scope: &str,
) {
    let mem = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: uniq("std-mem-2709"),
        content: "namespace-standard candidate row (2709)".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": owner, "scope": scope}),
        ..Default::default()
    };
    store.store(&admin_ctx(), &mem).await.expect("seed row");
}

/// POST /api/v1/namespaces/{ns}/standard {"id": id?} with `X-Agent-Id: agent`.
async fn post_set_standard(
    router: &axum::Router,
    ns: &str,
    agent: &str,
    id: Option<&str>,
) -> (StatusCode, Value) {
    let body = match id {
        Some(i) => json!({ "id": i }),
        None => json!({}),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/namespaces/{ns}/standard"))
        .header("content-type", "application/json")
        .header("X-Agent-Id", agent)
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

// ---------------------------------------------------------------------
// R-203 #1 — THE #2709 EXPLOIT. bob binds alice's PRIVATE memory as the
// standard of alice's namespace -> must be REFUSED 403, no binding written.
// ---------------------------------------------------------------------

#[tokio::test]
async fn bob_binding_alices_private_memory_refused_2709_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP bob_binding_alices_private_memory_refused_2709_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let alice_ns = uniq("alice-ns-2709");
    let alice_priv_id = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &alice_priv_id, &alice_ns, ALICE, "private").await;

    // EXPLOIT: bob names alice's private memory id. Pre-fix, PostgresStore::get
    // folded the visibility denial into NotFound, the `if let Ok` arm was
    // skipped, and the bind proceeded with NO authorization.
    let (status, report) = post_set_standard(&router, &alice_ns, BOB, Some(&alice_priv_id)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#2709: bob must NOT bind alice's private memory as the namespace \
         standard; got {status}: {report}"
    );

    // And the binding must NOT have been written.
    assert_ne!(
        bound_standard_id(&pool, &alice_ns).await.as_deref(),
        Some(alice_priv_id.as_str()),
        "#2709: alice's private memory must not have become alice-ns's standard"
    );
}

// ---------------------------------------------------------------------
// R-203 #2 — parity control: the OWNER can still bind their own memory.
// ---------------------------------------------------------------------

#[tokio::test]
async fn owner_bind_still_succeeds_2709_pg() {
    let Some(url) = pg_url() else {
        eprintln!("SKIP owner_bind_still_succeeds_2709_pg: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let alice_ns = uniq("alice-own-2709");
    let alice_id = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &alice_id, &alice_ns, ALICE, "private").await;

    // Alice binds her OWN private memory — authorize_namespace_standard_bind
    // returns Ok (owner == caller), so the fix must not over-block this.
    let (status, report) = post_set_standard(&router, &alice_ns, ALICE, Some(&alice_id)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "CONTROL: owner bind must still succeed; got {status}: {report}"
    );
    assert_eq!(
        bound_standard_id(&pool, &alice_ns).await.as_deref(),
        Some(alice_id.as_str()),
        "CONTROL: owner's memory must be bound as the standard; got {report}"
    );
}

// ---------------------------------------------------------------------
// R-203 #3 — parity control: a FIRST-WRITE (auto-seed, no caller id) still
// succeeds. The auto-seeded placeholder is owner-stamped to the caller, so
// the ownership gate re-fetch resolves the caller as owner and passes.
// ---------------------------------------------------------------------

#[tokio::test]
async fn first_write_auto_seed_still_succeeds_2709_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP first_write_auto_seed_still_succeeds_2709_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let fresh_ns = uniq("bob-first-2709");
    // No `id` supplied — the handler auto-seeds a placeholder owned by bob and
    // binds it. The ownership gate must be a no-op for this first write.
    let (status, report) = post_set_standard(&router, &fresh_ns, BOB, None).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "CONTROL: first-write auto-seed must still succeed; got {status}: {report}"
    );
    assert!(
        bound_standard_id(&pool, &fresh_ns).await.is_some(),
        "CONTROL: first-write must bind a placeholder standard; got {report}"
    );
}
