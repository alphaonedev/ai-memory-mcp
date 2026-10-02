// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4338: every notify funnel refuses an invalid `target_agent_id` with the
//! same typed error and status on both backends, before any quota charge or
//! write, and never echoes the offending value. Funnels: the SAL
//! `MemoryStore::notify` (sqlite and postgres), `POST /api/v1/notify` (sqlite
//! and postgres) and the MCP `memory_notify` handler (sqlite; the postgres
//! daemon has no MCP notify, see #3730). Postgres cells skip only when
//! `AI_MEMORY_TEST_POSTGRES_URL` is unset and FAIL when it is set but
//! unreachable.

#![cfg(feature = "sal")]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

#[cfg(feature = "sal-postgres")]
const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
const GOOD_TARGET: &str = "ai:recipient-4338";

/// The invalid recipients every funnel must refuse identically. Each value is
/// distinctive so an echo in an error body is detectable by substring.
fn invalid_targets() -> Vec<(&'static str, String)> {
    vec![
        ("empty", String::new()),
        ("overlong_129", "a".repeat(129)),
        ("overlong_64k", "z".repeat(64 * 1024)),
        ("bad_charset", "ai:bad\u{1F600}target 4338".to_owned()),
        ("path_traversal", "ai:../../etc/ECHOPROBE4338".to_owned()),
        (
            "reserved",
            ai_memory::identity::sentinels::SYSTEM_PRINCIPAL.to_owned(),
        ),
    ]
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn app_state(db: Db, backend: StorageBackend, store: Arc<dyn MemoryStore>) -> AppState {
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
    }
}

fn sqlite_store(dir: &tempfile::TempDir) -> (Arc<SqliteStore>, std::path::PathBuf) {
    let path = dir.path().join("notify4338.db");
    let store = SqliteStore::open(path.clone()).expect("open SqliteStore");
    (Arc::new(store), path)
}

fn sqlite_app(store: Arc<SqliteStore>, path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    app_state(db, StorageBackend::Sqlite, store)
}

#[cfg(feature = "sal-postgres")]
async fn pg_store() -> Option<Arc<ai_memory::store::postgres::PostgresStore>> {
    let Ok(url) = std::env::var(PG_URL_ENV) else {
        eprintln!("SKIP notify_target_validation_4338 pg: {PG_URL_ENV} unset");
        return None;
    };
    Some(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("AI_MEMORY_TEST_POSTGRES_URL is set but postgres is unreachable"),
    ))
}

#[cfg(feature = "sal-postgres")]
fn pg_app(store: Arc<ai_memory::store::postgres::PostgresStore>) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    app_state(db, StorageBackend::Postgres, store)
}

fn router(mut app: AppState, token: &str, caller: &str) -> axum::Router {
    use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
    let enrolled = Arc::new(EnrolledAgentKeys::from_map(
        [(api_key_sha256_hex(token), caller.to_owned())]
            .into_iter()
            .collect(),
    ));
    app.enrolled_agent_keys = Arc::clone(&enrolled);
    app.http_identity_mode = ai_memory::config::HttpIdentityMode::Enforce;
    ai_memory::build_router(
        ApiKeyState {
            key: Some(uuid::Uuid::new_v4().to_string()),
            mtls_enforced: false,
            enrolled_agent_keys: enrolled,
            identity_mode: ai_memory::config::HttpIdentityMode::Enforce,
            ..Default::default()
        },
        app,
    )
}

async fn http_notify(router: &axum::Router, token: &str, body: &Value) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(ai_memory::handlers::routes::NOTIFY)
        .header("content-type", "application/json")
        .header(ai_memory::HEADER_API_KEY, token)
        .body(Body::from(serde_json::to_vec(body).expect("body")))
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("response");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn notify_body(target: &str) -> Value {
    json!({"target_agent_id": target, "title": "t4338", "payload": "p4338",
        "why_trace": "#4338"})
}

/// A refusal must not echo the target (checked on its distinctive bytes).
fn assert_no_echo(label: &str, target: &str, text: &str) {
    if target.is_empty() {
        return;
    }
    assert!(!text.contains(target), "{label}: refusal echoed the target");
    for probe in ["ECHOPROBE4338", "\u{1F600}", "system"] {
        if target.contains(probe) {
            assert!(!text.contains(probe), "{label}: refusal echoed `{probe}`");
        }
    }
}

async fn assert_nothing_charged(store: &dyn MemoryStore, sender: &str, label: &str) {
    let q = store.quota_status(sender).await.expect("quota status");
    assert_eq!(q.current_memories_today, 0, "{label}: quota was charged");
}

/// Store-level refusal detail for `target`, asserting the typed error.
async fn store_refusal(store: &dyn MemoryStore, label: &str, target: &str) -> String {
    let sender = unique("ai:s4338");
    let ctx = CallerContext::for_agent(&sender);
    let err = store
        .notify(&ctx, target, "t4338", "p4338", None, None, Some("#4338"))
        .await
        .expect_err(label);
    let StoreError::InvalidInput { detail } = err else {
        panic!("{label}: expected InvalidInput, got {err:?}");
    };
    assert_no_echo(label, target, &detail);
    assert_nothing_charged(store, &sender, label).await;
    detail
}

/// HTTP refusal (status, body) for `target` through a fresh sender.
async fn http_refusal(app: &AppState, label: &str, target: &str) -> (StatusCode, String) {
    let sender = unique("ai:h4338");
    let token = uuid::Uuid::new_v4().to_string();
    let router = router(app.clone(), &token, &sender);
    let (status, text) = http_notify(&router, &token, &notify_body(target)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {text}");
    assert_no_echo(label, target, &text);
    assert_nothing_charged(app.store.as_ref(), &sender, label).await;
    (status, text)
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_store_notify_refuses_invalid_target_4338() {
    let dir = tempfile::tempdir().expect("dir");
    let (store, _path) = sqlite_store(&dir);
    for (label, target) in invalid_targets() {
        store_refusal(store.as_ref(), label, &target).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_http_notify_refuses_invalid_target_4338() {
    let dir = tempfile::tempdir().expect("dir");
    let (store, path) = sqlite_store(&dir);
    let app = sqlite_app(store, &path);
    for (label, target) in invalid_targets() {
        http_refusal(&app, label, &target).await;
    }
}

#[test]
fn sqlite_mcp_notify_refuses_invalid_target_without_echo_4338() {
    let conn = rusqlite::Connection::open_in_memory().expect("fixture");
    let path = std::path::Path::new(":memory:");
    let ttl = ResolvedTtl::default();
    for (label, target) in invalid_targets() {
        let params = json!({"target_agent_id": target, "title": "t", "payload": "p"});
        let err = ai_memory::mcp::handle_notify(&conn, path, &params, &ttl, None)
            .expect_err("invalid target refused");
        assert_eq!(err, ai_memory::validate::NOTIFY_TARGET_REFUSAL, "{label}");
        assert_no_echo(label, &target, &err);
    }
}

#[test]
fn validate_notify_target_accepts_the_agent_id_contract_4338() {
    for ok in [
        GOOD_TARGET,
        "a",
        &"a".repeat(128),
        "spiffe://example.org/ns/prod",
    ] {
        assert!(
            ai_memory::validate::validate_notify_target(ok).is_ok(),
            "{ok}"
        );
    }
    for (label, bad) in invalid_targets() {
        let e = ai_memory::validate::validate_notify_target(&bad).expect_err(label);
        assert_eq!(e.to_string(), ai_memory::validate::NOTIFY_TARGET_REFUSAL);
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn pg_store_notify_refuses_invalid_target_4338() {
    let Some(store) = pg_store().await else {
        return;
    };
    for (label, target) in invalid_targets() {
        store_refusal(store.as_ref(), label, &target).await;
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn pg_http_notify_refuses_invalid_target_4338() {
    let Some(store) = pg_store().await else {
        return;
    };
    let app = pg_app(store);
    for (label, target) in invalid_targets() {
        http_refusal(&app, label, &target).await;
    }
}

/// Parity: identical invalid inputs yield the identical typed error text and
/// the identical HTTP status and body on both backends.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_and_pg_refuse_identically_4338() {
    let Some(pg) = pg_store().await else { return };
    let dir = tempfile::tempdir().expect("dir");
    let (sq, path) = sqlite_store(&dir);
    let sq_app = sqlite_app(Arc::clone(&sq), &path);
    let pg_app = pg_app(Arc::clone(&pg));
    for (label, target) in invalid_targets() {
        let a = store_refusal(sq.as_ref(), label, &target).await;
        let b = store_refusal(pg.as_ref(), label, &target).await;
        assert_eq!(a, b, "{label}: store detail differs across backends");
        let (sa, ba) = http_refusal(&sq_app, label, &target).await;
        let (sb, bb) = http_refusal(&pg_app, label, &target).await;
        assert_eq!(sa, sb, "{label}: HTTP status differs");
        assert_eq!(ba, bb, "{label}: HTTP body differs");
    }
}

/// A valid recipient still lands on both backends (the validator is not
/// over-strict) and is charged exactly once.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn valid_target_still_delivers_on_both_backends_4338() {
    let Some(pg) = pg_store().await else { return };
    let dir = tempfile::tempdir().expect("dir");
    let (sq, _path) = sqlite_store(&dir);
    for store in [sq as Arc<dyn MemoryStore>, pg as Arc<dyn MemoryStore>] {
        let sender = unique("ai:ok4338");
        let ctx = CallerContext::for_agent(&sender);
        let target = unique(GOOD_TARGET);
        store
            .notify(&ctx, &target, "t", "p", None, None, Some("#4338"))
            .await
            .expect("valid notify");
        let q = store.quota_status(&sender).await.expect("quota");
        assert_eq!(q.current_memories_today, 1);
    }
}
