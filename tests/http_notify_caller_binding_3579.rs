// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3579: an enrolled HTTP caller owns its notification on both backends,
//! regardless of the daemon's ambient identity. MCP keeps its host ladder.

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::{resolve_agent_id, test_agent_id::AgentIdOverride};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

const CALLER: &str = "ai:http-notify-3579";
const AMBIENT: &str = "ai:daemon-notify-3579";

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`, but under `sal` its inner \
                  `Arc<dyn MemoryStore>` is MOVED into the struct literal below; \
                  one signature keeps both feature legs building identically."
    )
)]
fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
    let _ = &store;
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
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store: store.0,
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
    }
}

/// The SAL handle, present only under `feature = "sal"`. Wrapping it in a
/// newtype keeps `app_state_with`'s signature identical across feature legs
/// (the default-feature build has no `MemoryStore` trait at all).
#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

/// Build a sqlite-backed `AppState` over a real on-disk DB. Under `sal` the
/// `SqliteStore` is opened against the SAME file as `app.db`, so both views
/// see the same rows (exactly what `bootstrap_serve` does).
fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    app_state_with(db, StorageBackend::Sqlite, store)
}

/// Build a postgres-backed `AppState`. `app.db` is a throwaway in-memory
/// sqlite — deliberately EMPTY, so any handler that reads it instead of
/// `app.store` returns nothing and the test fails loudly.
#[cfg(feature = "sal-postgres")]
async fn postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    ));
    app_state_with(db, StorageBackend::Postgres, store)
}

fn router(mut app: AppState, token: Option<&str>) -> axum::Router {
    use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
    let enrolled = Arc::new(EnrolledAgentKeys::from_map(
        token
            .map(|t| (api_key_sha256_hex(t), CALLER.to_owned()))
            .into_iter()
            .collect(),
    ));
    app.enrolled_agent_keys = Arc::clone(&enrolled);
    app.http_identity_mode = ai_memory::config::HttpIdentityMode::Enforce;
    ai_memory::build_router(
        ApiKeyState {
            key: token.map(|_| uuid::Uuid::new_v4().to_string()),
            mtls_enforced: false,
            enrolled_agent_keys: enrolled,
            identity_mode: ai_memory::config::HttpIdentityMode::Enforce,
        },
        app,
    )
}

async fn post(
    router: &axum::Router,
    path: &str,
    token: Option<&str>,
    caller: Option<&str>,
    body: &Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header(ai_memory::HEADER_API_KEY, token);
    }
    if let Some(caller) = caller {
        request = request.header(ai_memory::HEADER_AGENT_ID, caller);
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(serde_json::to_vec(body).expect("body")))
                .expect("request"),
        )
        .await
        .expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response");
    (
        status,
        serde_json::from_slice(&bytes).expect("JSON response"),
    )
}

fn body() -> Value {
    json!({"target_agent_id":"ai:recipient-3579","title":uuid::Uuid::new_v4().to_string(),
        "payload":"A real HTTP caller owns this notification.","why_trace":"#3579 caller-binding regression"})
}

async fn stored_row(app: &AppState, id: &str) -> ai_memory::models::Memory {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return app
            .store
            .get(
                &ai_memory::store::CallerContext::for_agent("ai:recipient-3579"),
                id,
            )
            .await
            .expect("read from actual PostgreSQL adapter");
    }
    ai_memory::db::get(&app.db.lock().await.0, id)
        .expect("SQLite read")
        .expect("persisted notify")
}

fn exercise(app: &AppState, rt: &tokio::runtime::Runtime) {
    let token = uuid::Uuid::new_v4().to_string();
    let router = router(app.clone(), Some(&token));
    // No process environment mutation. block_on polls this request on the
    // calling test thread, where the test-only identity seam is scoped.
    for ambient in [None, Some(AMBIENT)] {
        let _identity = ambient.map_or_else(AgentIdOverride::unset, AgentIdOverride::set);
        for header in [None, Some(CALLER)] {
            let body = body();
            let (status, response) = rt.block_on(post(
                &router,
                ai_memory::handlers::routes::NOTIFY,
                Some(&token),
                header,
                &body,
            ));
            assert_eq!(status, StatusCode::CREATED, "{response}");
            assert_eq!(response["from"], CALLER, "ambient={ambient:?}");
            let row = rt.block_on(stored_row(app, response["id"].as_str().expect("notify id")));
            assert_eq!(row.metadata["agent_id"], CALLER, "ambient={ambient:?}");
            assert_eq!(
                row.namespace,
                ai_memory::inbox_namespace("ai:recipient-3579")
            );
            assert_eq!(row.content, body["payload"].as_str().expect("payload"));
        }
        for claim in [AMBIENT, "a2a-hub"] {
            let (status, response) = rt.block_on(post(
                &router,
                ai_memory::handlers::routes::NOTIFY,
                Some(&token),
                Some(claim),
                &body(),
            ));
            assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
            assert_eq!(response["error"], "identity_binding_mismatch");
        }
    }
}

#[test]
fn sqlite_http_notify_retains_key_bound_caller_with_and_without_ambient_3579() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let path = dir.path().join("notify.db");
    let app = sqlite_app_state(&path);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    exercise(&app, &rt);
}

#[test]
fn sqlite_notify_insert_failure_keeps_wire_errors_and_refunds_quota_3579() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let path = dir.path().join("notify.db");
    let app = sqlite_app_state(&path);
    let conn = ai_memory::db::open(&path).expect("fixture database");
    conn.execute_batch(
        "CREATE TRIGGER refuse_notify_3579 BEFORE INSERT ON memories
         BEGIN SELECT RAISE(ABORT, 'notify insert refused 3579'); END;",
    )
    .expect("deterministic downstream insert refusal");
    let _identity = AgentIdOverride::set(CALLER);
    let err = ai_memory::mcp::handle_notify(&conn, &path, &body(), &ResolvedTtl::default(), None)
        .expect_err("insert must fail");
    assert_eq!(err, "notify insert refused 3579");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let token = uuid::Uuid::new_v4().to_string();
    let router = router(app, Some(&token));
    let (status, response) = rt.block_on(post(
        &router,
        ai_memory::handlers::routes::NOTIFY,
        Some(&token),
        Some(CALLER),
        &body(),
    ));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response, json!({"error": "invalid request"}));
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM memories", [], |r| r.get(0))
        .expect("row count");
    assert_eq!(rows, 0);
    let quota = ai_memory::quotas::get_status(
        &conn,
        CALLER,
        &ai_memory::inbox_namespace("ai:recipient-3579"),
    )
    .expect("quota after both failed writes");
    assert_eq!(quota.current_memories_today, 0);
    assert_eq!(quota.current_storage_bytes, 0);
}

#[test]
fn mcp_notify_keeps_host_identity_ladder_and_validation_order_3579() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let path = dir.path().join("notify.db");
    let conn = ai_memory::db::open(&path).expect("fixture database");
    for ambient in [None, Some(AMBIENT)] {
        let _identity = ambient.map_or_else(AgentIdOverride::unset, AgentIdOverride::set);
        let expected = resolve_agent_id(None, Some("client3579")).expect("existing host ladder");
        let response = ai_memory::mcp::handle_notify(
            &conn,
            &path,
            &body(),
            &ResolvedTtl::default(),
            Some("client3579"),
        )
        .expect("MCP notify");
        assert_eq!(response["from"], expected);
        let row = ai_memory::db::get(&conn, response["id"].as_str().expect("id"))
            .expect("read")
            .expect("row");
        assert_eq!(row.metadata["agent_id"], expected);
        if ambient.is_some() {
            assert_eq!(expected, AMBIENT);
        } else {
            assert!(expected.starts_with("ai:client3579@"), "{expected}");
        }
    }
    let _invalid = AgentIdOverride::set("invalid caller with spaces");
    let err =
        ai_memory::mcp::handle_notify(&conn, &path, &json!({}), &ResolvedTtl::default(), None)
            .expect_err("input validation first");
    assert_eq!(err, "target_agent_id is required");
}

#[cfg(feature = "sal-postgres")]
#[test]
fn live_postgres_http_notify_retains_key_bound_caller_with_and_without_ambient_3579() {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("own live PostgreSQL required; never skip");
    // Refuse the LIVE operator database (the certified twin on :5445 on both
    // hosts). CI's ephemeral service database is also named `ai_memory_test`
    // but listens on :5432, so key the guard on name AND port.
    {
        let parsed = reqwest::Url::parse(&url).expect("URL");
        assert!(
            !(parsed.path() == "/ai_memory_test" && parsed.port() == Some(5445)),
            "never the live operator DB on :5445"
        );
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let app = rt.block_on(postgres_app_state(&url));
    exercise(&app, &rt);
    assert_eq!(
        rt.block_on(async {
            app.db
                .lock()
                .await
                .0
                .query_row("SELECT count(*) FROM memories", [], |r| r.get::<_, i64>(0))
                .expect("shadow count")
        }),
        0,
        "PostgreSQL fixture must not write its SQLite shadow"
    );
}
