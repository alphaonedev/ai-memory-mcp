// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2542 — POSTGRES twin of the namespace-standard chain-grafting fix
//! (K3 backend parity). Sqlite coverage lives in
//! `tests/ns_standard_parent_graft_2542.rs`.
//!
//! **Route 1 (HTTP pg path).** `set_namespace_standard_inner`'s postgres arm now
//! authorizes the DECLARED `parent` under the same bypass-visibility probe ctx
//! the bound-memory gate uses (so a foreign `scope=private` parent standard is
//! RESOLVED for the ownership check, not folded into `NotFound` → skip — the #2709
//! precedent). A cross-principal parent graft is refused 403; unowned / same-
//! principal parents pass.
//!
//! **Route 2 (governance resolver).** `resolve_governance_policy` walks the
//! entitled-parents-only governance chain (`pg_namespace_chain(.., governance =
//! true)`): each `child → parent` link layers governance ONLY when the parent is
//! UNOWNED or owned by the SAME principal as `child` — the DECLARING namespace,
//! checked PER-HOP (review Finding 1 + the #2479 federation reconciliation). A
//! cross-tenant parent is dropped with a WARN, while a same-owner parent —
//! including a `-`-coincident flat hierarchy AND a federation in-scope parent
//! whose declarer shares its owner — keeps its layer. The trait
//! `build_namespace_chain` stays the full LOOKUP chain on both backends (Finding
//! 4).
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip. Deliberately NOT `#[ignore]` (the PR postgres job does not pass
//! `--include-ignored`; see `ns_standard_set_ownership_2709_pg.rs`).

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines, clippy::doc_markdown)]

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

const ALICE: &str = "ai:alice-2542-pg";
const BOB: &str = "ai:bob-2542-pg";
const ATTACKER: &str = "ai:attacker-2542-pg";
const OP: &str = "ai:operator-2542-pg";
const VICTIM: &str = "ai:victim-2542-pg";

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
    (ai_memory::build_router(api_key_state, app_state), store)
}

/// Admin ctx — the TEST's own seed write, so it is not visibility-filtered.
fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2542-pg");
    ctx.bypass_visibility = true;
    ctx
}

async fn raw_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("raw pool")
}

/// Seed a memory owned by `owner` (scope shared so the bind path can see it).
async fn seed_memory(store: &Arc<dyn MemoryStore>, id: &str, namespace: &str, owner: &str) {
    let mem = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: uniq("std-mem-2542"),
        content: "namespace-standard candidate (2542)".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": owner, "scope": "shared"}),
        ..Default::default()
    };
    store.store(&admin_ctx(), &mem).await.expect("seed row");
}

/// POST /api/v1/namespaces/{ns}/standard with optional `id` + `parent`.
async fn post_set_standard(
    router: &axum::Router,
    ns: &str,
    agent: &str,
    id: Option<&str>,
    parent: Option<&str>,
) -> (StatusCode, Value) {
    let mut body = json!({});
    if let Some(i) = id {
        body["id"] = json!(i);
    }
    if let Some(p) = parent {
        body["parent"] = json!(p);
    }
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

/// Seed a namespace standard directly (raw SQL) with a governance policy and an
/// arbitrary `parent_namespace`, THROUGH THE STORE — so the row lands in the
/// same schema the store reads (post-#3055 the store normalizes its session
/// search_path, so a raw side-pool write can land in a different schema than the
/// store resolves against). `governance` is merged into the standard memory's
/// `metadata.governance`; `owner` into `metadata.agent_id`.
async fn seed_standard_row(
    store: &Arc<dyn MemoryStore>,
    namespace: &str,
    owner: &str,
    governance: Option<Value>,
    parent: Option<&str>,
) {
    let id = uuid::Uuid::new_v4().to_string();
    let mut metadata = json!({ "agent_id": owner, "scope": "shared" });
    if let Some(g) = governance {
        metadata["governance"] = g;
    }
    let mem = ai_memory::models::Memory {
        id: id.clone(),
        namespace: namespace.to_string(),
        title: uniq("std-2542"),
        content: "namespace standard (2542)".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata,
        ..Default::default()
    };
    store
        .store(&admin_ctx(), &mem)
        .await
        .expect("seed standard");
    store
        .set_namespace_standard(&admin_ctx(), namespace, &id, parent)
        .await
        .expect("set namespace standard");
}

async fn cleanup(pool: &sqlx::PgPool, prefix: &str) {
    // `public.`-qualified: the store normalizes its search_path (post-#3055) and
    // #3055 relocates app tables to `public`, so store-seeded rows live there.
    let _ = sqlx::query("DELETE FROM public.namespace_meta WHERE namespace LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM public.memories WHERE namespace LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
}

async fn bound_standard_id(pool: &sqlx::PgPool, ns: &str) -> Option<String> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT standard_id FROM public.namespace_meta WHERE namespace = $1")
            .bind(ns)
            .fetch_optional(pool)
            .await
            .expect("select namespace_meta");
    row.and_then(|(sid,)| sid)
}

// ===========================================================================
// Route 1 — declared-parent entitlement on the pg HTTP bind path.
// ===========================================================================

#[tokio::test]
async fn r1_cross_principal_parent_graft_refused_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP r1_cross_principal_parent_graft_refused_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let victim_ns = uniq("victim-2542");
    let alice_std = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &alice_std, &victim_ns, ALICE).await;
    // Alice binds her own standard at the victim namespace (201).
    let (s, r) = post_set_standard(&router, &victim_ns, ALICE, Some(&alice_std), None).await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "alice binds her victim standard: {r}"
    );

    // Bob owns his OWN bound standard (so the #929 gate passes), then tries to
    // graft his namespace under alice's victim namespace.
    let bob_ns = uniq("bob-ns-2542");
    let bob_std = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &bob_std, &bob_ns, BOB).await;
    let (status, report) =
        post_set_standard(&router, &bob_ns, BOB, Some(&bob_std), Some(&victim_ns)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#2542 Route 1 (pg): cross-principal parent graft MUST be refused; got {status}: {report}"
    );
    let msg = report["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("declared parent namespace standard"),
        "#2542 Route 1 (pg): refusal must name the declared parent; got {report}"
    );
    // The bind must NOT have landed.
    assert_ne!(
        bound_standard_id(&pool, &bob_ns).await.as_deref(),
        Some(bob_std.as_str()),
        "#2542 Route 1 (pg): a refused parent graft must not write the binding"
    );

    cleanup(&pool, &victim_ns).await;
    cleanup(&pool, &bob_ns).await;
}

#[tokio::test]
async fn r1_same_principal_and_unowned_parent_allowed_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP r1_same_principal_and_unowned_parent_allowed_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    // Same-principal: alice owns the parent standard, alice grafts under it.
    let parent_ns = uniq("alice-parent-2542");
    let parent_std = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &parent_std, &parent_ns, ALICE).await;
    let (s, _) = post_set_standard(&router, &parent_ns, ALICE, Some(&parent_std), None).await;
    assert_eq!(s, StatusCode::CREATED);

    let child_ns = uniq("alice-child-2542");
    let child_std = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &child_std, &child_ns, ALICE).await;
    let (status, report) = post_set_standard(
        &router,
        &child_ns,
        ALICE,
        Some(&child_std),
        Some(&parent_ns),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "#2542 Route 1 (pg): same-principal parent graft must be allowed; got {status}: {report}"
    );

    // Unowned: bob grafts under a namespace that has NO standard bound.
    let bob_ns = uniq("bob-unowned-2542");
    let bob_std = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &bob_std, &bob_ns, BOB).await;
    let (status2, report2) = post_set_standard(
        &router,
        &bob_ns,
        BOB,
        Some(&bob_std),
        Some("no-standard-here-2542"),
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::CREATED,
        "#2542 Route 1 (pg): a parent with no standard is unowned and must be allowed; got {status2}: {report2}"
    );

    cleanup(&pool, &parent_ns).await;
    cleanup(&pool, &child_ns).await;
    cleanup(&pool, &bob_ns).await;
}

// ===========================================================================
// Route 2 — CROSS-TENANT parent links excluded from governance on the pg
// resolver (ownership-based, review Finding 1). Same-owner parents (including a
// `-`-coincident flat hierarchy) KEEP their governance layer; cross-tenant
// parents are dropped with a WARN.
// ===========================================================================

#[tokio::test]
async fn r2_cross_tenant_parent_excluded_same_owner_included_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP r2_cross_tenant_parent_excluded_same_owner_included_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(&url).await.expect("connect"));
    let pool = raw_pool(&url).await;

    let suffix = &uuid::Uuid::new_v4().to_string()[..8];
    let approve =
        json!({"write": "approve", "promote": "any", "delete": "owner", "approver": "human"});

    // CROSS-TENANT: `acme-<sfx>` (ATTACKER) carries Approve; the victim's
    // `acme-<sfx>-sub` (ALICE) names it as parent → dropped from governance.
    let acme = format!("acme-{suffix}");
    let acme_sub = format!("acme-{suffix}-sub");
    seed_standard_row(&store, &acme, ATTACKER, Some(approve.clone()), None).await;
    seed_standard_row(&store, &acme_sub, ALICE, None, Some(&acme)).await;

    let resolved = store
        .resolve_governance_policy(&acme_sub)
        .await
        .expect("resolve ok");
    assert!(
        resolved.is_none(),
        "#2542 Route 2 (pg): a CROSS-TENANT parent must not layer governance; got {resolved:?}"
    );

    // REVIEW FINDING 1 (pg): an explicit SAME-OWNER flat `-` hierarchy that
    // COINCIDES with the auto-detect pattern MUST keep its approval gate.
    let corp = format!("acmecorp-{suffix}");
    let corp_frontend = format!("acmecorp-{suffix}-frontend");
    seed_standard_row(&store, &corp, OP, Some(approve.clone()), None).await;
    seed_standard_row(&store, &corp_frontend, OP, None, Some(&corp)).await;

    let inherited = store
        .resolve_governance_policy(&corp_frontend)
        .await
        .expect("resolve ok")
        .expect("#2542 Finding 1 (pg): a same-owner explicit parent MUST layer its governance");
    assert_eq!(
        inherited.core.write,
        ai_memory::models::GovernanceLevel::Approve,
        "#2542 Finding 1 (pg): same-owner parent's Approve write must inherit"
    );
    assert_eq!(
        inherited.core.approver,
        ai_memory::models::ApproverType::Human,
    );

    // Best-effort cleanup through the store's schema (public — the store
    // normalizes its search_path and #3055 relocates app tables to public).
    for ns in [&acme, &acme_sub, &corp, &corp_frontend] {
        let _ = sqlx::query("DELETE FROM public.namespace_meta WHERE namespace = $1")
            .bind(ns)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM public.memories WHERE namespace = $1")
            .bind(ns)
            .execute(&pool)
            .await;
    }
}

/// REGRESSION for the CI-caught #2479 break (pg twin): per-hop entitlement is
/// against the DECLARER of each link, not the leaf — so a same-owner in-scope
/// parent governs an UNOWNED `/`-child.
#[tokio::test]
async fn r2_federation_in_scope_same_owner_parent_applies_through_unowned_leaf_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP r2_federation_in_scope_same_owner_parent_applies_through_unowned_leaf_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(&url).await.expect("connect"));
    let pool = raw_pool(&url).await;

    let suffix = &uuid::Uuid::new_v4().to_string()[..8];
    let victim = format!("victim-{suffix}");
    let alpha = format!("alpha-{suffix}");
    let leaf = format!("{alpha}/sub");
    let permissive = json!({"write": "any", "promote": "any", "delete": "owner"});
    // victim + alpha share an owner (VICTIM); alpha declares `victim` as parent;
    // the leaf `alpha/sub` has no standard of its own.
    seed_standard_row(&store, &victim, VICTIM, Some(permissive), None).await;
    seed_standard_row(&store, &alpha, VICTIM, None, Some(&victim)).await;

    let resolved = store
        .resolve_governance_policy(&leaf)
        .await
        .expect("resolve ok")
        .expect("#2542/#2479 (pg): a same-owner in-scope parent must govern an unowned `/`-child");
    assert_eq!(
        resolved.core.write,
        ai_memory::models::GovernanceLevel::Any,
        "#2542/#2479 (pg): the in-scope parent's write:any must apply through the unowned leaf"
    );

    for ns in [&victim, &alpha] {
        let _ = sqlx::query("DELETE FROM public.namespace_meta WHERE namespace = $1")
            .bind(ns)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM public.memories WHERE namespace = $1")
            .bind(ns)
            .execute(&pool)
            .await;
    }
}
