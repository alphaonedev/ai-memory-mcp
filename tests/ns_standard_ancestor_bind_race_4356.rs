// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the ancestor-owner bind gate is race-safe (#4023/#4447 TOCTOU
//! class): a stranger's FIRST child bind that runs while the ancestor's bind
//! is in flight must not pass on a stale chain read.
//!
//! Deterministic, no timing dependence in the verdict: the test itself holds
//! the in-flight ancestor bind open (an uncommitted `namespace_meta` row for
//! the ancestor, taken under the SAME serialisation every production bind
//! takes: sqlite `BEGIN IMMEDIATE`, postgres the transaction-scoped advisory
//! lock `ns_standard_ancestor::PG_STANDARD_BIND_LOCK_KEY`), launches the
//! stranger's bind on every funnel, then commits. A funnel that checks
//! outside its write transaction (or without the lock) reads the ancestor as
//! absent and binds; a race-safe funnel waits, re-reads, and refuses.
//!
//! Cleanup runs on EVERY exit path (a `Drop` guard; sqlite is a tempdir).

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

mod common;

const ALICE: &str = "ai:alice-4356race";
const BOB: &str = "ai:bob-4356race";
/// How long the in-flight ancestor bind is held open before it commits.
const HOLD: Duration = Duration::from_millis(400);

fn standard(owner: &str, ns: &str, governance: &serde_json::Value) -> Memory {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        title: format!("std {id}"),
        id,
        tier: Tier::Long,
        namespace: ns.to_string(),
        content: "standard".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": owner, "scope": "shared", "governance": governance}),
        ..Memory::default()
    }
}

fn assert_refused_sal(r: Result<(), StoreError>, what: &str) {
    match r {
        Err(StoreError::PermissionDenied { reason, .. }) => assert_eq!(
            reason,
            ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
            "{what}"
        ),
        other => panic!("{what}: the racing stranger bind must be refused, got {other:?}"),
    }
}

/// sqlite: the in-flight ancestor bind holds the single write lock
/// (`BEGIN IMMEDIATE` + the uncommitted row) on its own connection. The MCP
/// wire handler (the funnel the HTTP sqlite arm delegates to) and the SAL
/// adapter race it from their own connections.
// multi_thread: the SAL sqlite adapter blocks its worker in `BEGIN IMMEDIATE`
// (busy wait) while this task sleeps and then commits on another worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_concurrent_first_bind_cannot_pass_on_a_stale_chain_4356() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let path = dir.path().join("memories.db");
    let u = uuid::Uuid::new_v4().simple().to_string();
    let gov = format!("gov4356race{u}");
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.clone()).expect("open SqliteStore"),
    );
    let a = standard(ALICE, &format!("std{u}"), &json!({"write": "owner"}));
    let b = standard(BOB, &format!("std{u}"), &json!({"write": "any"}));
    let a_id = store
        .store(&CallerContext::for_agent(ALICE), &a)
        .await
        .expect("alice std");
    let b_id = store
        .store(&CallerContext::for_agent(BOB), &b)
        .await
        .expect("bob std");

    // The in-flight ancestor bind.
    let holder = ai_memory::db::open(&path).expect("holder conn");
    holder
        .execute_batch("BEGIN IMMEDIATE")
        .expect("hold the write lock");
    holder
        .execute(
            "INSERT INTO namespace_meta (namespace, standard_id, updated_at) \
             VALUES (?1, ?2, '2026-10-01T00:00:00Z')",
            rusqlite::params![gov, a_id],
        )
        .expect("uncommitted ancestor binding");

    // The racing stranger binds: MCP wire handler and SAL adapter.
    let mcp = {
        let (path, leaf, b_id) = (path.clone(), format!("{gov}/mcp"), b_id.clone());
        std::thread::spawn(move || {
            let conn = ai_memory::db::open(&path).expect("mcp conn");
            ai_memory::mcp::handle_namespace_set_standard(
                &conn,
                &json!({"namespace": leaf, "id": b_id, "agent_id": BOB}),
            )
        })
    };
    let sal = {
        let (store, leaf, b_id) = (Arc::clone(&store), format!("{gov}/sal"), b_id.clone());
        tokio::spawn(async move {
            store
                .set_namespace_standard(&CallerContext::for_agent(BOB), &leaf, &b_id, None)
                .await
        })
    };
    tokio::time::sleep(HOLD).await;
    holder.execute_batch("COMMIT").expect("commit the ancestor");

    let mcp_r = mcp.join().expect("mcp thread");
    assert_eq!(
        mcp_r.expect_err("the MCP first bind raced the ancestor and must be refused"),
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD
    );
    assert_refused_sal(sal.await.expect("sal task"), "sqlite SAL");

    // Neither racing bind landed a row.
    let n: i64 = holder
        .query_row(
            "SELECT COUNT(*) FROM namespace_meta WHERE namespace LIKE ?1",
            rusqlite::params![format!("{gov}/%")],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 0, "a refused racing bind must leave no binding");
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
    use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    const API_KEY: &str = "ancestor-race-4356";

    /// Deletes every row this test created, on every exit path (including a
    /// failed assertion): `Drop` cannot await, so it runs the cleanup on a
    /// fresh runtime in its own thread.
    struct Cleanup {
        url: String,
        prefixes: Vec<String>,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let url = self.url.clone();
            let prefixes = self.prefixes.clone();
            let joined = std::thread::spawn(move || {
                let Ok(rt) = tokio::runtime::Runtime::new() else {
                    return;
                };
                rt.block_on(async move {
                    let Ok(pool) = sqlx::PgPool::connect(&url).await else {
                        return;
                    };
                    for p in prefixes {
                        let like = format!("{p}%");
                        let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace LIKE $1")
                            .bind(&like)
                            .execute(&pool)
                            .await;
                        let _ = sqlx::query("DELETE FROM memories WHERE namespace LIKE $1")
                            .bind(&like)
                            .execute(&pool)
                            .await;
                    }
                });
            })
            .join();
            if joined.is_err() {
                eprintln!("#4356 race cleanup thread panicked");
            }
        }
    }

    async fn router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch");
        let db: Db = Arc::new(tokio::sync::Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
        let store: Arc<dyn MemoryStore> = Arc::new(
            ai_memory::store::postgres::PostgresStore::connect(url)
                .await
                .expect("connect postgres adapter"),
        );
        let app = AppState {
            db,
            embedder: Arc::new(None),
            vector_index: Arc::new(tokio::sync::Mutex::new(None)),
            federation: Arc::new(None),
            tier_config: Arc::new(FeatureTier::Keyword.config()),
            scoring: Arc::new(ResolvedScoring::default()),
            profile: Arc::new(ai_memory::profile::Profile::core()),
            mcp_config: Arc::new(None),
            active_keypair: Arc::new(None),
            family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
            storage_backend: StorageBackend::Postgres,
            store: Arc::clone(&store),
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
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
        };
        ai_memory::handlers::admin_role::mark_request_authn_configured(true);
        let r = ai_memory::build_router(
            ApiKeyState {
                key: Some(API_KEY.into()),
                mtls_enforced: false,
                enrolled_agent_keys: Arc::new(
                    ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
                ),
                identity_mode: ai_memory::config::HttpIdentityMode::default(),
                ..Default::default()
            },
            app,
        );
        (r, store)
    }

    /// postgres: the in-flight ancestor bind holds the bind advisory lock and
    /// an uncommitted ancestor row. The SAL adapter and the HTTP route race
    /// it; both must WAIT for the lock (asserted: not finished while held),
    /// then read the committed ancestor and refuse.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn postgres_concurrent_first_bind_cannot_pass_on_a_stale_chain_4356() {
        let Some(url) = common::postgres_url() else {
            return;
        };
        common::permissive_attestation_for_tests();
        let u = uuid::Uuid::new_v4().simple().to_string();
        let gov = format!("gov4356race{u}");
        let std_ns = format!("std4356race{u}");
        let _cleanup = Cleanup {
            url: url.clone(),
            prefixes: vec![gov.clone(), std_ns.clone()],
        };
        let (router, store) = router(&url).await;
        let a = standard(ALICE, &std_ns, &json!({"write": "owner"}));
        let b = standard(BOB, &std_ns, &json!({"write": "any"}));
        let a_id = store
            .store(&CallerContext::for_agent(ALICE), &a)
            .await
            .expect("alice std");
        let b_id = store
            .store(&CallerContext::for_agent(BOB), &b)
            .await
            .expect("bob std");

        let pool = sqlx::PgPool::connect(&url).await.expect("raw pool");
        let mut holder = pool.begin().await.expect("holder tx");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(ai_memory::ns_standard_ancestor::PG_STANDARD_BIND_LOCK_KEY)
            .execute(&mut *holder)
            .await
            .expect("take the bind lock");
        sqlx::query("INSERT INTO namespace_meta (namespace, standard_id) VALUES ($1, $2)")
            .bind(&gov)
            .bind(&a_id)
            .execute(&mut *holder)
            .await
            .expect("uncommitted ancestor binding");

        let sal = {
            let (store, leaf, b_id) = (Arc::clone(&store), format!("{gov}/sal"), b_id.clone());
            tokio::spawn(async move {
                store
                    .set_namespace_standard(&CallerContext::for_agent(BOB), &leaf, &b_id, None)
                    .await
            })
        };
        let http = {
            let (router, leaf, b_id) = (router.clone(), format!("{gov}/http"), b_id.clone());
            tokio::spawn(async move {
                let req = Request::builder()
                    .method("POST")
                    .uri("/api/v1/namespaces")
                    .header("x-api-key", API_KEY)
                    .header("x-agent-id", BOB)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"namespace": leaf, "id": b_id})).expect("body"),
                    ))
                    .expect("request");
                let resp = router.oneshot(req).await.expect("route");
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                    .await
                    .expect("bytes");
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&bytes)
                        .unwrap_or(serde_json::Value::Null),
                )
            })
        };
        tokio::time::sleep(HOLD).await;
        assert!(
            !sal.is_finished(),
            "the SAL bind must wait for the in-flight bind's lock, not read a stale chain"
        );
        assert!(
            !http.is_finished(),
            "the HTTP bind must wait for the in-flight bind's lock, not read a stale chain"
        );
        holder.commit().await.expect("commit the ancestor");

        assert_refused_sal(sal.await.expect("sal task"), "postgres SAL");
        let (status, body) = http.await.expect("http task");
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            body["error"],
            ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
            "{body}"
        );
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM namespace_meta WHERE namespace LIKE $1")
                .bind(format!("{gov}/%"))
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(n, 0, "a refused racing bind must leave no binding");
    }
}
