// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3185 / #3127 — postgres keyword-search SSOT: `Filter.since`/`until`
//! and `source_uri` must NARROW on the production `MemoryStore::search`
//! path (HTTP compose included), never silently drop.
//!
//! Pre-fix `PostgresStore::search` bound neither `created_at` window nor
//! `source_uri`, so `GET /api/v1/search?since=&until=` and
//! `?source_uri=` returned rows OUTSIDE the requested set (wrong
//! results, fail-open widening). The sqlite twin honoured both via
//! `db::search` → `db::search_with_source_uri`.
//!
//! Gated on `sal-postgres` + `AI_MEMORY_TEST_POSTGRES_URL`. `#[ignore]`
//! so a node without live PG stays green; run with `--include-ignored`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines, clippy::doc_markdown)]

use std::sync::Arc;

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn mem_at(
    id: &str,
    ns: &str,
    title: &str,
    content: &str,
    created_at: chrono::DateTime<Utc>,
    owner: &str,
    source_uri: Option<&str>,
) -> Memory {
    let ts = created_at.to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "user".to_string(),
        created_at: ts.clone(),
        updated_at: ts,
        metadata: serde_json::json!({"agent_id": owner, "scope": "collective"}),
        memory_kind: MemoryKind::Observation,
        source_uri: source_uri.map(str::to_string),
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
        ..Memory::default()
    }
}

async fn purge(store: &PostgresStore, ids: &[&str]) {
    for id in ids {
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(id)
            .execute(store.pool())
            .await;
    }
}

fn build_pg_router(store: Arc<dyn MemoryStore>) -> axum::Router {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: ai_memory::handlers::Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let app_state = ai_memory::handlers::AppState {
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
        storage_backend: ai_memory::handlers::StorageBackend::Postgres,
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
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn get_search(router: &axum::Router, query: &str, agent_id: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/search?{query}"))
        .header(ai_memory::HEADER_AGENT_ID, agent_id)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

/// #3185 — trait `search` with `Filter.since`/`until` MUST exclude rows
/// outside the `created_at` window (the pre-fix SQL had no `created_at`
/// bind). Identical id set via the inherent SSOT.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_search_since_until_excludes_rows_outside_window_3185() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "ai:ssot-3185";
    let ctx = CallerContext::for_agent(owner);
    let ns = uid("ns-3185");
    let token = format!("tok3185{}", uuid::Uuid::new_v4().simple());
    let old_id = uid("old");
    let new_id = uid("new");
    let now = Utc::now();
    let old = mem_at(
        &old_id,
        &ns,
        &format!("{token}-old"),
        &format!("{token} old body"),
        now - Duration::days(10),
        owner,
        None,
    );
    let recent = mem_at(
        &new_id,
        &ns,
        &format!("{token}-new"),
        &format!("{token} new body"),
        now - Duration::days(1),
        owner,
        None,
    );
    store.store(&ctx, &old).await.expect("store old");
    store.store(&ctx, &recent).await.expect("store recent");

    let since = now - Duration::days(2);
    let filter = {
        let mut __f = Filter::new();
        __f.namespace = Some(ns.clone());
        __f.since = Some(since);
        __f.limit = 50;
        __f
    };

    let via_trait = MemoryStore::search(&store, &ctx, &token, &filter)
        .await
        .expect("trait search");
    let via_ssot = store
        .search_with_source_uri(&ctx, &token, &filter, None)
        .await
        .expect("ssot search");

    purge(&store, &[&old_id, &new_id]).await;

    let trait_ids: Vec<&str> = via_trait.iter().map(|m| m.id.as_str()).collect();
    let ssot_ids: Vec<&str> = via_ssot.iter().map(|m| m.id.as_str()).collect();
    assert!(
        trait_ids.contains(&new_id.as_str()),
        "in-window row must surface; got {trait_ids:?}"
    );
    assert!(
        !trait_ids.contains(&old_id.as_str()),
        "#3185: trait search MUST exclude created_at < since (T-10d); got {trait_ids:?}"
    );
    assert_eq!(
        trait_ids, ssot_ids,
        "trait search and search_with_source_uri must return the same id set (one SSOT)"
    );
}

/// #3127 — trait `search` with `Filter.source_uri` returns only that URI
/// (and is visibility-gated per #3112: a `scope=private` row owned by
/// another agent does not leak).
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_search_source_uri_and_visibility_3127() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let alice = CallerContext::for_agent("ai:alice-3127");
    let bob = CallerContext::for_agent("ai:bob-3127");
    let ns = uid("ns-3127");
    let token = format!("tok3127{}", uuid::Uuid::new_v4().simple());
    let keep_uri = format!("doc:keep/{}", uuid::Uuid::new_v4().simple());
    let drop_uri = format!("doc:drop/{}", uuid::Uuid::new_v4().simple());
    let keep_id = uid("keep");
    let drop_id = uid("drop");
    let priv_id = uid("priv");
    let now = Utc::now();

    let keep = mem_at(
        &keep_id,
        &ns,
        &format!("{token}-keep"),
        &format!("{token} keep body"),
        now,
        "ai:alice-3127",
        Some(&keep_uri),
    );
    let dropped = mem_at(
        &drop_id,
        &ns,
        &format!("{token}-drop"),
        &format!("{token} drop body"),
        now,
        "ai:alice-3127",
        Some(&drop_uri),
    );
    let mut private = mem_at(
        &priv_id,
        &ns,
        &format!("{token}-priv"),
        &format!("{token} private body"),
        now,
        "ai:alice-3127",
        Some(&keep_uri),
    );
    private.metadata = serde_json::json!({"agent_id": "ai:alice-3127", "scope": "private"});

    store.store(&alice, &keep).await.expect("store keep");
    store.store(&alice, &dropped).await.expect("store drop");
    store.store(&alice, &private).await.expect("store private");

    let filter = {
        let mut __f = Filter::new();
        __f.namespace = Some(ns.clone());
        __f.source_uri = Some(keep_uri.clone());
        __f.limit = 50;
        __f
    };

    let alice_hits = MemoryStore::search(&store, &alice, &token, &filter)
        .await
        .expect("alice search");
    let bob_hits = MemoryStore::search(&store, &bob, &token, &filter)
        .await
        .expect("bob search");

    purge(&store, &[&keep_id, &drop_id, &priv_id]).await;

    let alice_ids: Vec<&str> = alice_hits.iter().map(|m| m.id.as_str()).collect();
    let bob_ids: Vec<&str> = bob_hits.iter().map(|m| m.id.as_str()).collect();

    assert!(
        alice_ids.contains(&keep_id.as_str()),
        "matching source_uri must surface the keep row; got {alice_ids:?}"
    );
    assert!(
        alice_ids.contains(&priv_id.as_str()),
        "owner must see their own private row on the matching URI; got {alice_ids:?}"
    );
    assert!(
        !alice_ids.contains(&drop_id.as_str()),
        "#3127: a different source_uri MUST be excluded; got {alice_ids:?}"
    );
    assert!(
        bob_ids.contains(&keep_id.as_str()),
        "collective keep-row is visible to bob; got {bob_ids:?}"
    );
    assert!(
        !bob_ids.contains(&priv_id.as_str()),
        "#3112/#3127: bob must NOT see alice's scope=private row; got {bob_ids:?}"
    );
}

/// HTTP compose path: `q + source_uri + since` on a live PostgresStore
/// behind `StorageBackend::Postgres`. Pre-fix the postgres early-return
/// dropped both `source_uri` and the created_at window.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_http_compose_q_source_uri_since_3185_3127() {
    let Some(pg) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "ai:http-3185";
    let ctx = CallerContext::for_agent(owner);
    let ns = uid("ns-http");
    let token = format!("tokhttp{}", uuid::Uuid::new_v4().simple());
    let keep_uri = format!("doc:httpkeep/{}", uuid::Uuid::new_v4().simple());
    let other_uri = format!("doc:httpother/{}", uuid::Uuid::new_v4().simple());
    let in_id = uid("in");
    let old_id = uid("old");
    let other_id = uid("other");
    let now = Utc::now();

    let in_window = mem_at(
        &in_id,
        &ns,
        &format!("{token}-in"),
        &format!("{token} in-window keep-uri"),
        now - Duration::days(1),
        owner,
        Some(&keep_uri),
    );
    let too_old = mem_at(
        &old_id,
        &ns,
        &format!("{token}-old"),
        &format!("{token} old keep-uri"),
        now - Duration::days(10),
        owner,
        Some(&keep_uri),
    );
    let other = mem_at(
        &other_id,
        &ns,
        &format!("{token}-other"),
        &format!("{token} in-window other-uri"),
        now - Duration::days(1),
        owner,
        Some(&other_uri),
    );
    pg.store(&ctx, &in_window).await.expect("store in");
    pg.store(&ctx, &too_old).await.expect("store old");
    pg.store(&ctx, &other).await.expect("store other");

    let store: Arc<dyn MemoryStore> = Arc::new(pg);
    let router = build_pg_router(Arc::clone(&store));
    // Use `Z` (not `+00:00`): a `+` in a query string is form-decoded as
    // space, which would make RFC3339 parse fail and silently drop `since`.
    let since = (now - Duration::days(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    // `doc:` scheme colon percent-encoded so Query parsing cannot split
    // the URI; RFC3339 `since` uses `Z` (no `+`) so it is query-safe.
    let qs = format!(
        "q={token}&namespace={ns}&source_uri={}&since={since}",
        keep_uri.replace(':', "%3A"),
    );
    let (status, body) = get_search(&router, &qs, owner).await;

    // Teardown through the concrete adapter.
    if let Some(pg) = store.as_any().downcast_ref::<PostgresStore>() {
        purge(pg, &[&in_id, &old_id, &other_id]).await;
    }

    assert_eq!(status, StatusCode::OK, "{body}");
    let results = body["results"].as_array().expect("results");
    let ids: Vec<&str> = results.iter().filter_map(|r| r["id"].as_str()).collect();
    assert_eq!(
        ids,
        vec![in_id.as_str()],
        "HTTP compose (q + source_uri + since) on pg must return ONLY the in-window \
         matching-URI row; pre-fix since/until and source_uri were dropped; got {ids:?} body={body}"
    );
}
