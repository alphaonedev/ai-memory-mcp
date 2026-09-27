// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4056 — `POST /api/v1/notify` must honour the operator's `[ttl]` tier
//! override on BOTH backends.
//!
//! Pre-fix the Postgres branch called the SAL `notify` with a tier and no
//! TTL, built the row with `expires_at: None`, and the shared insert funnel
//! backfilled the COMPILED tier default. With `short_ttl_secs = 86400` a
//! short-tier notify persisted a 6 h expiry on Postgres and 24 h on SQLite,
//! so unhandled A2A messages vanished from the recipient's inbox early.
//!
//! Every leg drives the REAL router and reads the PERSISTED row. The Postgres
//! leg runs when `AI_MEMORY_TEST_POSTGRES_URL` is set (the CI Postgres job
//! sets it); the SQLite legs run on every `sal` build and pin the positive
//! control. The SAL (`ai_memory::store`) is itself `sal`-gated.
#![cfg(feature = "sal")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl, TtlConfig};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;

const SENDER: &str = "ai:ttl-4056-sender";
const OVERRIDE_SHORT_SECS: i64 = ai_memory::SECS_PER_DAY;

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value, set
    // before any reader in this binary runs.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn ttl(override_short: bool) -> ResolvedTtl {
    if override_short {
        ResolvedTtl::from_config(Some(&TtlConfig {
            short_ttl_secs: Some(OVERRIDE_SHORT_SECS),
            ..TtlConfig::default()
        }))
    } else {
        ResolvedTtl::default()
    }
}

fn router(
    conn: rusqlite::Connection,
    db_path: std::path::PathBuf,
    resolved_ttl: ResolvedTtl,
    backend: StorageBackend,
    store: Arc<dyn MemoryStore>,
) -> axum::Router {
    permissive_attestation_for_tests();
    let db: Db = Arc::new(Mutex::new((conn, db_path, resolved_ttl, true)));
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
        storage_backend: backend,
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
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn sqlite_router(resolved_ttl: ResolvedTtl) -> (axum::Router, Arc<dyn MemoryStore>) {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    // Leak the handle: the router and store outlive this frame, and the OS
    // reclaims the file with the test process.
    std::mem::forget(file);
    let conn = ai_memory::db::open(&path).expect("db::open");
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&path).expect("SqliteStore"));
    (
        router(
            conn,
            path,
            resolved_ttl,
            StorageBackend::Sqlite,
            Arc::clone(&store),
        ),
        store,
    )
}

/// POST one short-tier notify and return the PERSISTED row's
/// `expires_at - created_at`, in seconds.
async fn notify_and_measure(router: &axum::Router, store: &Arc<dyn MemoryStore>) -> i64 {
    let target = format!("ai:ttl-4056-{}", uuid::Uuid::new_v4());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notify")
        .header("content-type", "application/json")
        .header("x-agent-id", SENDER)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "target_agent_id": target,
                "title": "ttl probe",
                "content": "pending A2A message",
                "tier": "short",
            }))
            .expect("json"),
        ))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::CREATED, "notify body={body}");
    let id = body["id"].as_str().expect("receipt carries the row id");

    let ctx = ai_memory::store::CallerContext::for_agent(&target);
    let row = store.get(&ctx, id).await.expect("persisted row");
    let created = chrono::DateTime::parse_from_rfc3339(&row.created_at).expect("created_at");
    let expires = chrono::DateTime::parse_from_rfc3339(
        row.expires_at
            .as_deref()
            .expect("a short-tier notify always expires"),
    )
    .expect("expires_at");
    (expires - created).num_seconds()
}

/// Allow a second of skew between the two stamps; the defect is 64 800 s.
fn assert_offset(label: &str, got: i64, want: i64) {
    assert!(
        (got - want).abs() <= 1,
        "{label}: persisted expiry is created_at + {got}s, want + {want}s"
    );
}

#[tokio::test]
async fn sqlite_notify_honours_the_ttl_override_4056() {
    let (router, store) = sqlite_router(ttl(true));
    assert_offset(
        "sqlite override",
        notify_and_measure(&router, &store).await,
        OVERRIDE_SHORT_SECS,
    );
}

#[tokio::test]
async fn sqlite_notify_without_override_keeps_the_compiled_default_4056() {
    let (router, store) = sqlite_router(ttl(false));
    let compiled = ai_memory::models::Tier::Short
        .default_ttl_secs()
        .expect("short expires");
    assert_offset(
        "sqlite default",
        notify_and_measure(&router, &store).await,
        compiled,
    );
}

/// The SAL request itself: a caller holding the operator's TTL gets it on
/// the row, on the direct trait path too (not only through HTTP).
#[tokio::test]
async fn the_sal_notify_request_carries_the_ttl_on_sqlite_4056() {
    let (_router, store) = sqlite_router(ttl(false));
    let target = format!("ai:ttl-4056-sal-{}", uuid::Uuid::new_v4());
    let ctx = ai_memory::store::CallerContext::for_agent(SENDER);
    let id = store
        .notify_request(
            &ctx,
            ai_memory::store::NotifyRequest {
                target_agent: &target,
                title: "sal",
                payload: "p",
                priority: None,
                tier: None,
                why_trace: None,
                tier_ttl_secs: Some(OVERRIDE_SHORT_SECS),
            },
        )
        .await
        .expect("notify_request");
    let row = store
        .get(&ai_memory::store::CallerContext::for_agent(&target), &id)
        .await
        .expect("row");
    let created = chrono::DateTime::parse_from_rfc3339(&row.created_at).expect("created");
    let expires = chrono::DateTime::parse_from_rfc3339(row.expires_at.as_deref().expect("exp"))
        .expect("expires");
    assert_offset(
        "sal request",
        (expires - created).num_seconds(),
        OVERRIDE_SHORT_SECS,
    );
}

#[cfg(feature = "sal-postgres")]
mod postgres {
    use super::*;

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    async fn pg_router(
        url: &str,
        resolved_ttl: ResolvedTtl,
    ) -> (axum::Router, Arc<dyn MemoryStore>) {
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let store: Arc<dyn MemoryStore> = Arc::new(
            ai_memory::store::postgres::PostgresStore::connect(url)
                .await
                .expect("connect postgres"),
        );
        (
            router(
                conn,
                std::path::PathBuf::from(":memory:"),
                resolved_ttl,
                StorageBackend::Postgres,
                Arc::clone(&store),
            ),
            store,
        )
    }

    /// RED before #4056: 21 600 s (the compiled short default), not 86 400 s.
    #[tokio::test]
    async fn postgres_notify_honours_the_ttl_override_4056() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let (router, store) = pg_router(&url, ttl(true)).await;
        assert_offset(
            "postgres override",
            notify_and_measure(&router, &store).await,
            OVERRIDE_SHORT_SECS,
        );
    }

    /// Control: no override keeps the compiled default on postgres too.
    #[tokio::test]
    async fn postgres_notify_without_override_keeps_the_compiled_default_4056() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let (router, store) = pg_router(&url, ttl(false)).await;
        let compiled = ai_memory::models::Tier::Short
            .default_ttl_secs()
            .expect("short expires");
        assert_offset(
            "postgres default",
            notify_and_measure(&router, &store).await,
            compiled,
        );
    }
}
