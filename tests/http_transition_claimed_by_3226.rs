// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3226 — HTTP `POST /api/v1/actions/{id}/transition` must bind
//! `claimed_by` to the live lease holder (MCP #3009) and reject an
//! unknown `signal_type` (MCP A6-13). Pre-fix HTTP took `claimed_by`
//! verbatim and coerced unknown signal types to `notify`.

#![cfg(feature = "sal")]
#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::similar_names
)]

use std::path::Path;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::Action;
use ai_memory::store::MemoryStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

fn build_sqlite_router(db_path: &Path) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("reopen");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("SqliteStore"));
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
        storage_backend: StorageBackend::Sqlite,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(ai_memory::identity::replay::FederationNonceCache::default()),
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
    ai_memory::build_router(api_key_state, app_state)
}

fn seed_action_with_lease(db_path: &Path, id: &str, holder: &str) {
    let conn = ai_memory::db::open(db_path).expect("seed open");
    let now = chrono::Utc::now().timestamp();
    let action = Action {
        id: id.to_string(),
        namespace: "cov-3226".to_string(),
        kind: "test".to_string(),
        state: ai_memory::models::ActionState::Pending,
        title: "tx".to_string(),
        payload: json!({}),
        priority: 5,
        agent_id: Some("ai:cov".to_string()),
        claimed_by: None,
        vector_clock: json!({}),
        metadata: json!({}),
        created_at: now,
        updated_at: now,
    };
    ai_memory::actions::create(&conn, &action).expect("create action");
    match ai_memory::actions::lease_acquire(&conn, id, holder, now, now + 120)
        .expect("lease_acquire")
    {
        ai_memory::actions::LeaseAcquire::Acquired(_) => {}
        ai_memory::actions::LeaseAcquire::Conflict => panic!("fresh lease must acquire"),
    }
}

async fn post_json(router: axum::Router, uri: &str, body: serde_json::Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:tester")
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    router.oneshot(req).await.expect("oneshot").status()
}

/// HTTP transition with `claimed_by` that is not the live lease holder is 403.
#[tokio::test]
async fn http_transition_claimed_by_not_holder() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("init schema");
    seed_action_with_lease(&db_path, "act-3226", "ai:w1");

    let router = build_sqlite_router(&db_path);
    let status = post_json(
        router,
        "/api/v1/actions/act-3226/transition",
        json!({"to": "claimed", "claimed_by": "ai:w2"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3226: non-holder claimed_by must be 403"
    );

    // Holder succeeds; control-char claimed_by is 400.
    let router = build_sqlite_router(&db_path);
    let ok = post_json(
        router,
        "/api/v1/actions/act-3226/transition",
        json!({"to": "claimed", "claimed_by": "ai:w1"}),
    )
    .await;
    assert_eq!(ok, StatusCode::OK, "#3226: lease holder must transition");

    let router = build_sqlite_router(&db_path);
    let bad = post_json(
        router,
        "/api/v1/actions/act-3226/transition",
        json!({"to": "in_progress", "claimed_by": "bad\nid"}),
    )
    .await;
    assert_eq!(
        bad,
        StatusCode::BAD_REQUEST,
        "#3226: control-char claimed_by must be 400"
    );
}

/// HTTP `POST /signals` rejects an unknown `signal_type` (MCP A6-13 parity).
#[tokio::test]
async fn http_send_signal_rejects_unknown_signal_type() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("init schema");
    let router = build_sqlite_router(&db_path);
    let status = post_json(
        router,
        "/api/v1/signals",
        json!({
            "namespace": "cov-3226",
            "subject": "s",
            "signal_type": "bogus"
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#3226: unknown signal_type must be 400, not coerced to notify"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::CallerContext;
    use ai_memory::store::postgres::PostgresStore;

    fn postgres_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
    }

    async fn build_pg_router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
        ai_memory::handlers::admin_role::mark_request_authn_configured(true);
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
        let pg = PostgresStore::connect(url)
            .await
            .expect("connect postgres");
        let store: Arc<dyn MemoryStore> = Arc::new(pg);
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
            store: Arc::clone(&store),
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

    /// Live-postgres twin of `http_transition_claimed_by_not_holder`.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn http_transition_claimed_by_not_holder() {
        let Some(url) = postgres_url() else {
            panic!("AI_MEMORY_TEST_POSTGRES_URL unset — cannot run live-pg #3226 pin");
        };
        let (router, store) = build_pg_router(&url).await;
        let ctx = CallerContext::for_agent("ai:cov".to_string());
        let now = chrono::Utc::now().timestamp();
        let id = format!("act-3226-{}", uuid::Uuid::new_v4());
        let action = Action {
            id: id.clone(),
            namespace: "cov-3226-pg".to_string(),
            kind: "test".to_string(),
            state: ai_memory::models::ActionState::Pending,
            title: "tx".to_string(),
            payload: json!({}),
            priority: 5,
            agent_id: Some("ai:cov".to_string()),
            claimed_by: None,
            vector_clock: json!({}),
            metadata: json!({}),
            created_at: now,
            updated_at: now,
        };
        store
            .action_create(&ctx, &action)
            .await
            .expect("action_create");
        store
            .lease_acquire(&ctx, &id, "ai:w1", now, now + 120)
            .await
            .expect("lease_acquire");

        let status = post_json(
            router,
            &format!("/api/v1/actions/{id}/transition"),
            json!({"to": "claimed", "claimed_by": "ai:w2"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "#3226 pg: non-holder claimed_by must be 403"
        );
    }
}
