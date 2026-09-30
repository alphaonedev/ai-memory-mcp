// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4091 red-first: HTTP consolidate must never fabricate a summary.
//!
//! For each LLM failure mode (absent / timeout / empty / error) the call must
//! return a typed `503 SUMMARY_UNAVAILABLE`, leave every source untouched
//! (not tombstoned, not deleted, content byte-identical) and create no
//! consolidated row. Covered on both backends and under both source
//! dispositions (tombstone-default and hard-delete).

#![allow(clippy::missing_panics_doc, clippy::too_many_lines, clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{AppState, Db, StorageBackend, consolidate_memories};
use ai_memory::models::{Memory, MemoryKind, Tier};
use axum::{Router, routing::post as axum_post};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

const AGENT: &str = "ai:consolidate-4091";
const CODE: &str = "SUMMARY_UNAVAILABLE";

static FLAG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct FlagGuard {
    _held: tokio::sync::MutexGuard<'static, ()>,
}

impl FlagGuard {
    async fn hold(tombstone_on: bool) -> Self {
        let held = FLAG_LOCK.lock().await;
        ai_memory::config::set_lineage_dag(true);
        ai_memory::config::set_consolidate_tombstone_sources(tombstone_on);
        Self { _held: held }
    }
}

impl Drop for FlagGuard {
    fn drop(&mut self) {
        ai_memory::config::set_lineage_dag(false);
        ai_memory::config::set_consolidate_tombstone_sources(false);
    }
}

fn seed_memory(conn: &rusqlite::Connection, ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": AGENT}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    };
    ai_memory::db::insert(conn, &mem).expect("insert");
    mem
}

fn sqlite_app_state(db: Db, llm_call_timeout: Duration) -> AppState {
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> = {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = ai_memory::store::sqlite::SqliteStore::open(dir.path().join("store.db"))
            .expect("open SqliteStore");
        std::mem::forget(dir);
        Arc::new(s)
    };
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout,
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::new()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::new(),
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
    }
}

fn fresh_sqlite_db() -> (Db, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("t.db")).expect("open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        dir.path().join("t.db"),
        ResolvedTtl::default(),
        true,
    )));
    (db, dir)
}

async fn post_consolidate(
    state: AppState,
    ids: &[String],
    title: &str,
    namespace: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    let app = Router::new()
        .route("/api/v1/consolidate", axum_post(consolidate_memories))
        .with_state(state);
    let body = serde_json::json!({
        "ids": ids,
        "title": title,
        "namespace": namespace,
    });
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/consolidate")
                .method("POST")
                .header("content-type", "application/json")
                .header("x-agent-id", AGENT)
                .body(axum::body::Body::from(
                    serde_json::to_vec(&body).expect("json"),
                ))
                .expect("request"),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
    (status, v)
}

fn assert_sources_intact(conn: &rusqlite::Connection, before: &[Memory]) {
    for m in before {
        let after = ai_memory::db::get(conn, &m.id)
            .expect("get")
            .unwrap_or_else(|| panic!("source {} missing", m.id));
        assert_eq!(after.content, m.content, "source content changed");
        assert_eq!(after.title, m.title, "source title changed");
        assert_eq!(
            after.lifecycle_state,
            ai_memory::models::LifecycleState::Open,
            "source must stay Open, not tombstoned"
        );
    }
}

fn count_in_namespace(conn: &rusqlite::Connection, ns: &str) -> usize {
    ai_memory::db::list(conn, Some(ns), None, 100, 0, None, None, None, None, None, None)
        .expect("list")
        .len()
}

async fn run_llm_absent_case(tombstone_on: bool) {
    let _flags = FlagGuard::hold(tombstone_on).await;
    let (db, _dir) = fresh_sqlite_db();
    let ns = format!("c4091-absent-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let before = {
        let lock = db.lock().await;
        let a = seed_memory(&lock.0, &ns, "alpha title", "alpha meaning one");
        let b = seed_memory(&lock.0, &ns, "beta title", "beta meaning two");
        vec![a, b]
    };
    let ids: Vec<String> = before.iter().map(|m| m.id.clone()).collect();
    let state = sqlite_app_state(db.clone(), Duration::from_secs(30));
    let (status, v) = post_consolidate(state, &ids, "merged", &ns).await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "LLM-absent consolidate must fail closed, got {status} {v}"
    );
    assert_eq!(v["code"].as_str(), Some(CODE), "typed code, got {v}");
    let lock = db.lock().await;
    assert_sources_intact(&lock.0, &before);
    assert_eq!(
        count_in_namespace(&lock.0, &ns),
        2,
        "no consolidated row may be created"
    );
}

#[tokio::test]
async fn sqlite_llm_absent_tombstone_on_4091() {
    run_llm_absent_case(true).await;
}

#[tokio::test]
async fn sqlite_llm_absent_hard_delete_4091() {
    run_llm_absent_case(false).await;
}

fn sqlite_app_state_with_llm(
    db: Db,
    client: ai_memory::llm::OllamaClient,
    llm_call_timeout: Duration,
) -> AppState {
    let mut state = sqlite_app_state(db, llm_call_timeout);
    state.llm.store(Some(client));
    state
}

fn mock_client(base_url: &str) -> ai_memory::llm::OllamaClient {
    ai_memory::llm::OllamaClient::new_with_url_no_health_check(base_url, "test-model")
        .expect("mock llm client")
}

async fn run_wiremock_case(
    tombstone_on: bool,
    mode: &str,
    llm_call_timeout: Duration,
) {
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};
    let _flags = FlagGuard::hold(tombstone_on).await;
    let (db, _dir) = fresh_sqlite_db();
    let ns = format!(
        "c4091-{mode}-{}",
        &uuid::Uuid::new_v4().to_string()[..8]
    );
    let before = {
        let lock = db.lock().await;
        let a = seed_memory(&lock.0, &ns, "alpha title", "alpha meaning one");
        let b = seed_memory(&lock.0, &ns, "beta title", "beta meaning two");
        vec![a, b]
    };
    let ids: Vec<String> = before.iter().map(|m| m.id.clone()).collect();

    let server = MockServer::start().await;
    match mode {
        "empty" => {
            Mock::given(method("POST"))
                .and(path("/api/chat"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"message": {"content": "   "}}),
                ))
                .mount(&server)
                .await;
        }
        "error" => {
            Mock::given(method("POST"))
                .and(path("/api/chat"))
                .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
                .mount(&server)
                .await;
        }
        "timeout" => {
            Mock::given(method("POST"))
                .and(path("/api/chat"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_delay(std::time::Duration::from_secs(2))
                        .set_body_json(serde_json::json!({"message": {"content": "late"}})),
                )
                .mount(&server)
                .await;
        }
        _ => panic!("unknown mode"),
    }
    let client = mock_client(&server.uri());
    let state = sqlite_app_state_with_llm(db.clone(), client, llm_call_timeout);
    let (status, v) = post_consolidate(state, &ids, "merged", &ns).await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "LLM-{mode} consolidate must fail closed, got {status} {v}"
    );
    assert_eq!(v["code"].as_str(), Some(CODE), "typed code, got {v}");
    let lock = db.lock().await;
    assert_sources_intact(&lock.0, &before);
    assert_eq!(
        count_in_namespace(&lock.0, &ns),
        2,
        "no consolidated row may be created"
    );
}

#[tokio::test]
async fn sqlite_llm_empty_tombstone_on_4091() {
    run_wiremock_case(true, "empty", Duration::from_secs(30)).await;
}

#[tokio::test]
async fn sqlite_llm_empty_hard_delete_4091() {
    run_wiremock_case(false, "empty", Duration::from_secs(30)).await;
}

#[tokio::test]
async fn sqlite_llm_error_tombstone_on_4091() {
    run_wiremock_case(true, "error", Duration::from_secs(30)).await;
}

#[tokio::test]
async fn sqlite_llm_error_hard_delete_4091() {
    run_wiremock_case(false, "error", Duration::from_secs(30)).await;
}

#[tokio::test]
async fn sqlite_llm_timeout_tombstone_on_4091() {
    run_wiremock_case(true, "timeout", Duration::from_millis(100)).await;
}

#[tokio::test]
async fn sqlite_llm_timeout_hard_delete_4091() {
    run_wiremock_case(false, "timeout", Duration::from_millis(100)).await;
}

#[cfg(feature = "sal-postgres")]
mod pg_4091 {
    use super::*;

    fn pg_4091_url() -> Option<String> {
        if let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL_4091") {
            if !url.is_empty() {
                return Some(url);
            }
        }
        if let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") {
            if !url.is_empty() {
                // Never run the destructive consolidate test against the shared
                // `ai_memory_test` store; reroute to our own database.
                return Some(url.replace("ai_memory_test", "ai_memory_muse13_4091"));
            }
        }
        let home = std::env::var("HOME").ok()?;
        let raw = std::fs::read_to_string(format!("{home}/.ai-memory-ci-fed-url")).ok()?;
        let raw = raw.trim().to_string();
        if raw.is_empty() {
            return None;
        }
        Some(raw.replace("ai_memory_test", "ai_memory_muse13_4091"))
    }

    async fn pg_app_state(
        store: Arc<dyn ai_memory::store::MemoryStore>,
        llm_call_timeout: Duration,
    ) -> AppState {
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch");
        let db: Db = Arc::new(Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
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
            family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
            storage_backend: StorageBackend::Postgres,
            store,
            llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
            auto_tag_model: Arc::new(None),
            llm_call_timeout,
            replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::new()),
            verify_require_nonce: false,
            federation_nonce_cache: Arc::new(
                ai_memory::identity::replay::FederationNonceCache::new(),
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
        }
    }

    fn pg_memory(ns: &str, title: &str, content: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": AGENT}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: ai_memory::models::LifecycleState::Open,
        }
    }

    async fn run_pg_case(tombstone_on: bool, mode: &str) {
        use ai_memory::store::{CallerContext, Filter, MemoryStore};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};
        let Some(url) = pg_4091_url() else {
            eprintln!("skip pg {mode}: no postgres URL");
            return;
        };
        let _flags = FlagGuard::hold(tombstone_on).await;
        let store: Arc<dyn MemoryStore> =
            Arc::new(ai_memory::store::postgres::PostgresStore::connect(&url).await.expect("pg connect"));
        let ctx = CallerContext::for_agent(AGENT.to_string());
        let ns = format!("pg4091-{mode}-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let a = pg_memory(&ns, "alpha title", "alpha meaning one");
        let b = pg_memory(&ns, "beta title", "beta meaning two");
        store.store(&ctx, &a).await.expect("seed a");
        store.store(&ctx, &b).await.expect("seed b");
        let ids = vec![a.id.clone(), b.id.clone()];

        let mut state = pg_app_state(store.clone(), if mode == "timeout" {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(30)
        })
        .await;
        if mode != "absent" {
            let server = MockServer::start().await;
            match mode {
                "empty" => {
                    Mock::given(method("POST"))
                        .and(path("/api/chat"))
                        .respond_with(ResponseTemplate::new(200).set_body_json(
                            serde_json::json!({"message": {"content": "   "}}),
                        ))
                        .mount(&server)
                        .await;
                }
                "error" => {
                    Mock::given(method("POST"))
                        .and(path("/api/chat"))
                        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
                        .mount(&server)
                        .await;
                }
                "timeout" => {
                    Mock::given(method("POST"))
                        .and(path("/api/chat"))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .set_delay(std::time::Duration::from_secs(2))
                                .set_body_json(serde_json::json!({"message": {"content": "late"}})),
                        )
                        .mount(&server)
                        .await;
                }
                _ => panic!("unknown mode"),
            }
            let client = mock_client(&server.uri());
            state.llm.store(Some(client));
        }
        let (status, v) = post_consolidate(state, &ids, "merged", &ns).await;
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "pg LLM-{mode} must fail closed, got {status} {v}"
        );
        assert_eq!(v["code"].as_str(), Some(CODE), "typed code, got {v}");
        for m in [&a, &b] {
            let after = store.get(&ctx, &m.id).await.expect("source must survive");
            assert_eq!(after.content, m.content, "pg source content changed");
            assert_eq!(
                after.lifecycle_state,
                ai_memory::models::LifecycleState::Open,
                "pg source must stay Open"
            );
        }
        let mut filter = Filter::new();
        filter.namespace = Some(ns.clone());
        filter.limit = 50;
        let rows = store.list(&ctx, &filter).await.expect("pg list");
        assert_eq!(rows.len(), 2, "pg: no consolidated row may be created");
    }

    #[tokio::test]
    async fn pg_llm_absent_tombstone_on_4091() {
        run_pg_case(true, "absent").await;
    }

    #[tokio::test]
    async fn pg_llm_absent_hard_delete_4091() {
        run_pg_case(false, "absent").await;
    }

    #[tokio::test]
    async fn pg_llm_empty_tombstone_on_4091() {
        run_pg_case(true, "empty").await;
    }

    #[tokio::test]
    async fn pg_llm_empty_hard_delete_4091() {
        run_pg_case(false, "empty").await;
    }

    #[tokio::test]
    async fn pg_llm_error_tombstone_on_4091() {
        run_pg_case(true, "error").await;
    }

    #[tokio::test]
    async fn pg_llm_error_hard_delete_4091() {
        run_pg_case(false, "error").await;
    }

    #[tokio::test]
    async fn pg_llm_timeout_tombstone_on_4091() {
        run_pg_case(true, "timeout").await;
    }

    #[tokio::test]
    async fn pg_llm_timeout_hard_delete_4091() {
        run_pg_case(false, "timeout").await;
    }
}
