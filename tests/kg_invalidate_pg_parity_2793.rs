// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
// Test scaffolding: pedantic doc-markdown lints on the narrative header have no
// behavioral impact (mirrors `g4_postgres_link_projects_into_age_graph.rs`).
#![allow(clippy::doc_markdown)]
// The whole parity harness threads the SAL `MemoryStore` trait + `AppState.store`
// field, both of which only exist under `sal`. Default-build (no-`sal`) SQLite
// coverage for the #938 gate this fix rides is already pinned by
// `tests/kg_invalidate_owner_gate_938.rs`.
#![cfg(feature = "sal")]

//! #2793 — `POST /api/v1/kg/invalidate` must reach the real invalidate path
//! on BOTH backends. On Postgres it ALWAYS returned 404.
//!
//! ## The defect this file pins
//!
//! The `#938` caller-vs-source-owner pre-check resolved the source memory with
//! `db::get(&lock.0, ...)` — the SQLite scratch connection, which is EMPTY on a
//! Postgres deployment. So `source_owner` was `None` for every real memory and
//! the handler returned the canonical `{found:false}` 404 BEFORE the
//! `app.store.invalidate_link` Postgres branch could run. The fix branches on
//! `storage_backend` and reads the source via the SAL `app.store.get` on
//! Postgres — the exact class #1134 fixed for the sibling `kg_timeline`
//! handler.
//!
//! ## Parity asserted here
//!
//! - `sqlite_owner_invalidates_own_link_2793` / `pg_...` — the OWNER's POST
//!   returns HTTP 200 `{found:true}` and the link's `valid_until` is stamped.
//!   (Pre-fix: sqlite 200, pg 404 — the divergence.)
//! - `sqlite_non_owner_refused_2793` / `pg_...` — a NON-OWNER is REFUSED and
//!   the link is NOT invalidated (no IDOR opened by the fix). sqlite returns
//!   403 (raw `db::get` sees the row + owner); pg returns 403 or 404 (the SAL
//!   `get` folds a scope=private denial into `NotFound`, #910) — both refuse,
//!   both leave the edge valid.
//!
//! The pg twin soft-skips without `AI_MEMORY_TEST_POSTGRES_URL`. Deliberately
//! NOT `#[ignore]`: the PR-gating `postgres-feature` job runs
//! `cargo test --features sal-postgres` WITHOUT `--include-ignored`, so an
//! `#[ignore]` twin would be invisible to the PR gate — and this bug
//! reproduces on plain pgvector (no AGE needed), so the PR gate CAN catch it.

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::MemoryStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

const REL: &str = "supersedes";

fn owned_memory(id: &str, owner: &str, namespace: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("seed-{owner}-{}", &id[..id.len().min(8)]),
        content: format!("body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-2793".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": owner}),
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
        ..Memory::default()
    }
}

/// Build an `AppState` around a backend-specific `db` + `store` +
/// `storage_backend`. The field set mirrors the g4 / #938 fixtures.
#[allow(clippy::too_many_lines)]
fn app_state(db: Db, store: Arc<dyn MemoryStore>, backend: StorageBackend) -> AppState {
    AppState {
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
        storage_backend: backend,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn router_from(state: AppState) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, state)
}

async fn invalidate_as(
    router: &axum::Router,
    caller: &str,
    source_id: &str,
    target_id: &str,
) -> (StatusCode, Value) {
    let body = json!({"source_id": source_id, "target_id": target_id, "relation": REL});
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/kg/invalidate")
        .header("x-agent-id", caller)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

// ───────────────────────────── SQLite reference ─────────────────────────────

fn sqlite_router(db_path: &std::path::Path) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("SqliteStore"));
    router_from(app_state(db, store, StorageBackend::Sqlite))
}

fn sqlite_link_valid_until(db_path: &std::path::Path, src: &str, tgt: &str) -> Option<String> {
    let conn = ai_memory::db::open(db_path).expect("open");
    conn.query_row(
        "SELECT valid_until FROM memory_links WHERE source_id=?1 AND target_id=?2 AND relation=?3",
        rusqlite::params![src, tgt, REL],
        |r| r.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
}

#[tokio::test]
async fn sqlite_owner_invalidates_own_link_2793() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let conn = ai_memory::db::open(db_path).expect("open");
    let src = uuid::Uuid::new_v4().to_string();
    let tgt = uuid::Uuid::new_v4().to_string();
    ai_memory::db::insert(&conn, &owned_memory(&src, "alice", "kg2793/a")).expect("src");
    ai_memory::db::insert(&conn, &owned_memory(&tgt, "alice", "kg2793/a")).expect("tgt");
    ai_memory::db::create_link(&conn, &src, &tgt, REL).expect("link");
    drop(conn);

    let router = sqlite_router(db_path);
    let (status, body) = invalidate_as(&router, "alice", &src, &tgt).await;
    assert_eq!(status, StatusCode::OK, "owner must get 200; body={body}");
    assert_eq!(body["found"], json!(true));
    assert!(
        sqlite_link_valid_until(db_path, &src, &tgt).is_some(),
        "owner's invalidate must stamp valid_until"
    );
}

#[tokio::test]
async fn sqlite_non_owner_refused_2793() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let conn = ai_memory::db::open(db_path).expect("open");
    let src = uuid::Uuid::new_v4().to_string();
    let tgt = uuid::Uuid::new_v4().to_string();
    ai_memory::db::insert(&conn, &owned_memory(&src, "alice", "kg2793/b")).expect("src");
    ai_memory::db::insert(&conn, &owned_memory(&tgt, "alice", "kg2793/b")).expect("tgt");
    ai_memory::db::create_link(&conn, &src, &tgt, REL).expect("link");
    drop(conn);

    let router = sqlite_router(db_path);
    let (status, _body) = invalidate_as(&router, "bob", &src, &tgt).await;
    assert_ne!(status, StatusCode::OK, "non-owner must NOT succeed");
    assert!(
        sqlite_link_valid_until(db_path, &src, &tgt).is_none(),
        "non-owner's refused POST must leave valid_until NULL"
    );
}

// ─────────────────────────────── Postgres twin ──────────────────────────────

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::models::{MemoryLink, MemoryLinkRelation};
    use ai_memory::store::postgres::PostgresStore;

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    fn uniq(p: &str) -> String {
        format!("{p}-{}", &uuid::Uuid::new_v4().to_string()[..8])
    }

    fn admin_ctx() -> ai_memory::store::CallerContext {
        let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2793-seed");
        ctx.bypass_visibility = true;
        ctx
    }

    async fn pg_router(url: &str) -> axum::Router {
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch");
        let db: Db = Arc::new(Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
        let store: Arc<dyn MemoryStore> =
            Arc::new(PostgresStore::connect(url).await.expect("connect pg"));
        router_from(app_state(db, store, StorageBackend::Postgres))
    }

    fn link(src: &str, tgt: &str) -> MemoryLink {
        let now = chrono::Utc::now().to_rfc3339();
        MemoryLink {
            source_id: src.to_string(),
            target_id: tgt.to_string(),
            relation: MemoryLinkRelation::Supersedes,
            created_at: now.clone(),
            signature: None,
            observed_by: None,
            valid_from: Some(now),
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        }
    }

    /// Read `valid_until` for the (src, tgt, supersedes) edge directly from the
    /// relational `memory_links` table (the durable source of truth).
    async fn link_valid_until(url: &str, src: &str, tgt: &str) -> Option<String> {
        let pool = sqlx::PgPool::connect(url).await.expect("pool");
        // `memory_links.valid_until` is TIMESTAMPTZ on postgres — cast to text
        // so the presence check does not depend on a chrono decode.
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT valid_until::text FROM memory_links \
             WHERE source_id=$1 AND target_id=$2 AND relation=$3",
        )
        .bind(src)
        .bind(tgt)
        .bind(REL)
        .fetch_optional(&pool)
        .await
        .expect("query");
        row.and_then(|r| r.0)
    }

    #[tokio::test]
    async fn pg_owner_invalidates_own_link_2793() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ns = uniq("kg2793a");
        let src = uuid::Uuid::new_v4().to_string();
        let tgt = uuid::Uuid::new_v4().to_string();
        {
            let store = PostgresStore::connect(&url).await.expect("connect");
            let ctx = admin_ctx();
            store
                .store(&ctx, &owned_memory(&src, "alice", &ns))
                .await
                .expect("src");
            store
                .store(&ctx, &owned_memory(&tgt, "alice", &ns))
                .await
                .expect("tgt");
            store.link(&ctx, &link(&src, &tgt)).await.expect("link");
        }

        let router = pg_router(&url).await;
        let (status, body) = invalidate_as(&router, "alice", &src, &tgt).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "#2793: owner MUST get 200 on pg (pre-fix ALWAYS 404); body={body}"
        );
        assert_eq!(body["found"], json!(true));
        assert!(
            link_valid_until(&url, &src, &tgt).await.is_some(),
            "#2793: pg invalidate must actually stamp valid_until on the edge"
        );
    }

    #[tokio::test]
    async fn pg_non_owner_refused_2793() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ns = uniq("kg2793b");
        let src = uuid::Uuid::new_v4().to_string();
        let tgt = uuid::Uuid::new_v4().to_string();
        {
            let store = PostgresStore::connect(&url).await.expect("connect");
            let ctx = admin_ctx();
            store
                .store(&ctx, &owned_memory(&src, "alice", &ns))
                .await
                .expect("src");
            store
                .store(&ctx, &owned_memory(&tgt, "alice", &ns))
                .await
                .expect("tgt");
            store.link(&ctx, &link(&src, &tgt)).await.expect("link");
        }

        let router = pg_router(&url).await;
        let (status, _body) = invalidate_as(&router, "bob", &src, &tgt).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "#2793: non-owner MUST NOT succeed (no IDOR opened by the fix)"
        );
        assert!(
            link_valid_until(&url, &src, &tgt).await.is_none(),
            "#2793: non-owner's refused POST must leave the edge valid"
        );
    }
}
