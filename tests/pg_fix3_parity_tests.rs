// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Fix-round 3 — postgres SAL parity regressions
//! (#1626 / #1628 / #1630 / #1642).
//!
//! Live-postgres gated tests following the skip-if-env-unset pattern of
//! `live_store_with_embedding_persists_full_provenance_1608` and
//! `tests/store_parity_gaps.rs`: every test self-skips with an eprintln
//! when `AI_MEMORY_TEST_POSTGRES_URL` is unset so a plain `cargo test`
//! stays green on nodes without postgres routing, and RUNS the real
//! assertions when the env var points at a live schema.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres --test pg_fix3_parity_tests
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

async fn live_pg() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

/// Memory builder stamped with `metadata.agent_id = owner` so the SAL
/// #1412 caller-owns write gates pass for a `CallerContext::for_agent`
/// built from the same owner.
fn sample_memory(id: &str, namespace: &str, tier: Tier, owner: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier,
        namespace: namespace.to_string(),
        title: format!("title-{id}"),
        content: "fix3 parity test content".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        ..Memory::default()
    }
}

fn parse_ts(s: &str) -> chrono::DateTime<chrono::FixedOffset> {
    chrono::DateTime::parse_from_rfc3339(s).expect("rfc3339 timestamp")
}

/// #1626 — pg promote (trait `update` with `tier: Some(Long)`) must
/// clear `expires_at`, mirroring the sqlite promote handler's explicit
/// `UPDATE memories SET expires_at = NULL`. Pre-fix the trait update's
/// `expires_at = COALESCE($11, expires_at)` left the old mid-tier
/// deadline in place and GC reaped the promoted "long" row.
#[tokio::test]
async fn live_promote_clears_expiry_pg() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let unique = uuid::Uuid::new_v4();
    let owner = format!("ai:fix3-1626-{unique}");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = format!("fix3-1626-{unique}");

    // 1) store mid → tier-default expiry is backfilled (non-NULL).
    let mem = sample_memory(&format!("fix3-1626-a-{unique}"), &ns, Tier::Mid, &owner);
    let id = store.store(&ctx, &mem).await.expect("store mid memory");
    let before = store.get(&ctx, &id).await.expect("get pre-promote");
    assert_eq!(before.tier, Tier::Mid);
    assert!(
        before.expires_at.is_some(),
        "mid-tier store must carry the tier-default expiry backfill (#1466)"
    );

    // 2) promote (the handler's promote patch shape) → expiry cleared.
    let promote_patch = UpdatePatch {
        tier: Some(Tier::Long),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &id, promote_patch)
        .await
        .expect("promote update");
    let after = store.get(&ctx, &id).await.expect("get post-promote");
    assert_eq!(after.tier, Tier::Long, "tier must land long");
    assert!(
        after.expires_at.is_none(),
        "#1626: promoting to long must clear expires_at on postgres \
         (got {:?})",
        after.expires_at
    );

    // 3) rule: an explicitly-supplied patch.expires_at still wins when
    //    the patch tier is NOT long.
    let mem_b = sample_memory(&format!("fix3-1626-b-{unique}"), &ns, Tier::Mid, &owner);
    let id_b = store.store(&ctx, &mem_b).await.expect("store mid memory b");
    let explicit = (chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339();
    let expiry_patch = UpdatePatch {
        expires_at: Some(explicit.clone()),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &id_b, expiry_patch)
        .await
        .expect("explicit expires_at update");
    let got_b = store.get(&ctx, &id_b).await.expect("get b");
    let got_expiry = got_b
        .expires_at
        .as_deref()
        .expect("explicit expires_at must persist when tier is not long");
    assert_eq!(
        parse_ts(got_expiry).timestamp(),
        parse_ts(&explicit).timestamp(),
        "explicit patch.expires_at must win when tier is not long"
    );

    // 4) rule: when the patch tier IS long, the clear wins even when an
    //    explicit expires_at rides the same patch (sqlite upsert
    //    semantics: expiry is only cleared / never set on long).
    let long_with_expiry = UpdatePatch {
        tier: Some(Tier::Long),
        expires_at: Some(explicit),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &id_b, long_with_expiry)
        .await
        .expect("promote-with-expiry update");
    let got_b2 = store.get(&ctx, &id_b).await.expect("get b post-promote");
    assert!(
        got_b2.expires_at.is_none(),
        "#1626: the tier→long clear must win over an explicit \
         patch.expires_at (got {:?})",
        got_b2.expires_at
    );

    // Cleanup (best-effort).
    let _ = store.delete(&ctx, &id).await;
    let _ = store.delete(&ctx, &id_b).await;
}

/// #1628 — `PUT /api/v1/memories/{id}` on a postgres-backed daemon must
/// honor `If-Match`. Pre-fix the handler parsed `if_match_version` and
/// then dropped it on the pg branch (last-write-wins trait `update`);
/// `PostgresStore::update_with_expected_version` had zero production
/// callers. Post-fix: stale If-Match → 409 with the SAME envelope the
/// sqlite branch returns; matching If-Match → 200 + version bump.
#[tokio::test]
async fn live_put_if_match_pg_1628() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let unique = uuid::Uuid::new_v4();
    let owner = format!("ai:fix3-1628-{unique}");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = format!("fix3-1628-{unique}");

    let mem = sample_memory(&format!("fix3-1628-{unique}"), &ns, Tier::Mid, &owner);
    let id = store.store(&ctx, &mem).await.expect("store memory");
    let stored = store.get(&ctx, &id).await.expect("get stored");
    assert_eq!(stored.version, 1, "fresh row must start at version 1");

    let store_arc = std::sync::Arc::new(store);
    let (router, _db_guard) = build_pg_router(std::sync::Arc::clone(&store_arc) as _);

    // 1) Stale If-Match → 409 CONFLICT with the sqlite-shaped envelope.
    let (status, body) = put_memory(
        &router,
        &id,
        &owner,
        Some("999"),
        serde_json::json!({ "content": "updated content via stale if-match attempt" }),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CONFLICT,
        "#1628: stale If-Match must 409 on postgres; got {body}"
    );
    assert_eq!(
        body["status"].as_str(),
        Some("conflict"),
        "envelope: {body}"
    );
    assert_eq!(body["id"].as_str(), Some(id.as_str()), "envelope: {body}");
    assert_eq!(
        body["expected_version"].as_i64(),
        Some(999),
        "envelope: {body}"
    );
    assert_eq!(
        body["current_version"].as_i64(),
        Some(1),
        "envelope: {body}"
    );
    // Byte-equal `error` string vs the sqlite branch (the
    // `crate::storage::VersionConflict` Display impl).
    assert_eq!(
        body["error"].as_str(),
        Some(format!("CONFLICT: memory {id} expected_version=999 but stored version=1").as_str()),
        "envelope: {body}"
    );

    // The stale write must NOT have landed.
    let unchanged = store_arc.get(&ctx, &id).await.expect("get unchanged");
    assert_eq!(unchanged.version, 1, "stale write must not bump version");
    assert_eq!(
        unchanged.content, mem.content,
        "stale write must not mutate content"
    );

    // 2) Matching If-Match → 200 + version bump + mutation lands.
    let (status, body) = put_memory(
        &router,
        &id,
        &owner,
        Some("1"),
        serde_json::json!({ "content": "updated content via matching if-match" }),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "#1628: matching If-Match must 200 on postgres; got {body}"
    );
    assert_eq!(
        body["version"].as_i64(),
        Some(2),
        "#1628: matching If-Match must bump version; got {body}"
    );
    assert_eq!(
        body["content"].as_str(),
        Some("updated content via matching if-match"),
        "matching If-Match must land the mutation; got {body}"
    );

    // Cleanup (best-effort).
    let _ = store_arc.delete(&ctx, &id).await;
}

/// #1630 (#1466 class) — pg consolidate must mint the tier-default
/// expiry. Pre-fix the consolidate INSERT omitted `expires_at`, so a
/// consolidated mid/short row landed NULL (immortal, never GC-reaped)
/// while the sqlite twin (`storage::consolidate`) bound
/// `candidate.effective_expires_at()`.
#[tokio::test]
async fn live_consolidate_backfills_expiry_pg_1630() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let unique = uuid::Uuid::new_v4();
    let owner = format!("ai:fix3-1630-{unique}");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = format!("fix3-1630-{unique}");

    // tier mid → consolidated row must carry the tier-default expiry.
    let a = sample_memory(&format!("fix3-1630-a-{unique}"), &ns, Tier::Mid, &owner);
    let b = sample_memory(&format!("fix3-1630-b-{unique}"), &ns, Tier::Mid, &owner);
    let id_a = store.store(&ctx, &a).await.expect("store a");
    let id_b = store.store(&ctx, &b).await.expect("store b");
    let mid_id = store
        .consolidate(
            &ctx,
            &[id_a, id_b],
            &format!("fix3-1630-mid-{unique}"),
            "consolidated summary (mid)",
            &ns,
            &Tier::Mid,
            "test",
            &owner,
        )
        .await
        .expect("consolidate mid");
    let mid_row = store
        .get(&ctx, &mid_id)
        .await
        .expect("get consolidated mid");
    assert_eq!(mid_row.tier, Tier::Mid);
    assert!(
        mid_row.expires_at.is_some(),
        "#1630: consolidate tier=mid must mint a NOT NULL expires_at \
         (tier-default backfill); got NULL"
    );

    // tier long → no TTL; expires_at stays NULL.
    let c = sample_memory(&format!("fix3-1630-c-{unique}"), &ns, Tier::Mid, &owner);
    let d = sample_memory(&format!("fix3-1630-d-{unique}"), &ns, Tier::Mid, &owner);
    let id_c = store.store(&ctx, &c).await.expect("store c");
    let id_d = store.store(&ctx, &d).await.expect("store d");
    let long_id = store
        .consolidate(
            &ctx,
            &[id_c, id_d],
            &format!("fix3-1630-long-{unique}"),
            "consolidated summary (long)",
            &ns,
            &Tier::Long,
            "test",
            &owner,
        )
        .await
        .expect("consolidate long");
    let long_row = store
        .get(&ctx, &long_id)
        .await
        .expect("get consolidated long");
    assert_eq!(long_row.tier, Tier::Long);
    assert!(
        long_row.expires_at.is_none(),
        "#1630: consolidate tier=long must keep expires_at NULL (no TTL); \
         got {:?}",
        long_row.expires_at
    );

    // Cleanup (best-effort).
    let _ = store.delete(&ctx, &mid_id).await;
    let _ = store.delete(&ctx, &long_id).await;
}

/// #1642 — pg delete must clean `namespace_meta` rows whose
/// `standard_id` points at the deleted memory, mirroring sqlite
/// `storage::delete` (`src/storage/mod.rs:1747-1751`). Pre-fix the
/// namespace kept resolving a standard whose backing memory was gone.
#[tokio::test]
async fn live_delete_cleans_namespace_meta_pg_1642() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let unique = uuid::Uuid::new_v4();
    let owner = format!("ai:fix3-1642-{unique}");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = format!("fix3-1642-{unique}");

    let std_mem = sample_memory(&format!("fix3-1642-{unique}"), &ns, Tier::Long, &owner);
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &ns, &std_id, None)
        .await
        .expect("set namespace standard");
    let got = store
        .get_namespace_standard(&ctx, &ns)
        .await
        .expect("get standard pre-delete");
    assert_eq!(
        got.as_ref().map(|(sid, _)| sid.as_str()),
        Some(std_id.as_str()),
        "standard must resolve before the delete"
    );

    store
        .delete(&ctx, &std_id)
        .await
        .expect("delete standard memory");

    let after = store
        .get_namespace_standard(&ctx, &ns)
        .await
        .expect("get standard post-delete");
    assert!(
        after.is_none(),
        "#1642: deleting the standard memory must remove the \
         namespace_meta row; got {after:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// HTTP harness for the #1628 handler-routing test — a postgres-backed
// router (real `PostgresStore` as the SAL store) so the
// `update_memory` pg branch + If-Match routing is exercised on the
// wire, not just at the store layer. Mirrors the AppState shape of
// `tests/agent_attestation_postgres.rs::build_fake_pg_router` (the
// `db` sqlite tuple is transport plumbing the pg branch never reads).
// ─────────────────────────────────────────────────────────────────────

fn build_pg_router(
    store: std::sync::Arc<dyn MemoryStore>,
) -> (axum::Router, tempfile::NamedTempFile) {
    use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
    use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // The sqlite Db tuple is transport plumbing the pg branch never
    // reads; the NamedTempFile guard is returned so the caller keeps
    // the backing file alive for the router's lifetime.
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
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
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
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
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), f)
}

async fn put_memory(
    router: &axum::Router,
    id: &str,
    agent_id: &str,
    if_match: Option<&str>,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt as _;

    let mut builder = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/memories/{id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id);
    if let Some(v) = if_match {
        builder = builder.header("if-match", v);
    }
    let req = builder
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, parsed)
}
