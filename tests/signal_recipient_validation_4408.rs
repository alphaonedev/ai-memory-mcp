// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4408: every `signal_send` funnel refuses an invalid `to_agent` with the
//! same typed error and status on both backends, before any sign, quota
//! charge, write or audit record, and never echoes the offending value.
//! Funnels: the SAL `MemoryStore::signal_send` (sqlite and postgres),
//! `POST /api/v1/signals` (sqlite and postgres) and the MCP
//! `memory_signal_send` handler (sqlite; its cells live in the unit module
//! `src/mcp/tools/signal_4408_tests.rs` because the handler is crate-private). Postgres cells skip only when
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
const GOOD_TARGET: &str = "ai:recipient-4408";

/// The invalid recipients every funnel must refuse identically. Each value is
/// distinctive so an echo in an error body is detectable by substring.
fn invalid_targets() -> Vec<(&'static str, String)> {
    vec![
        ("empty", String::new()),
        ("blank", "   ".to_owned()),
        ("overlong_129", "a".repeat(129)),
        ("overlong_64k", "z".repeat(64 * 1024)),
        ("control_chars", "ai:ctl\u{7}\u{1b}ECHOPROBE4408".to_owned()),
        ("nul", "ai:nul\0ECHOPROBE4408".to_owned()),
        ("zero_width", "ai:zw\u{200b}ECHOPROBE4408".to_owned()),
        (
            "reserved",
            ai_memory::identity::sentinels::SYSTEM_PRINCIPAL.to_owned(),
        ),
        ("path_traversal", "ai:../../etc/ECHOPROBE4408".to_owned()),
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
    let path = dir.path().join("signal4408.db");
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
        eprintln!("SKIP signal_recipient_validation_4408 pg: {PG_URL_ENV} unset");
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

const NS: &str = "ns4408";

fn signal_for(ns: &str, from: &str, to: Option<&str>) -> ai_memory::models::Signal {
    ai_memory::models::Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: ns.to_owned(),
        from_agent: from.to_owned(),
        to_agent: to.map(str::to_owned),
        subject: "s4408".to_owned(),
        body: json!({"k": "v4408"}),
        signal_type: ai_memory::models::SignalType::default(),
        in_reply_to: None,
        correlation_id: None,
        reference_ids: json!([]),
        created_at: chrono::Utc::now().timestamp(),
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    }
}

async fn http_signal(router: &axum::Router, token: &str, body: &Value) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(ai_memory::handlers::routes::SIGNALS)
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

fn signal_body(ns: &str, to: &str) -> Value {
    json!({"namespace": ns, "subject": "s4408", "to_agent": to, "body": {"k": "v4408"}})
}

/// A refusal must not echo the recipient (checked on its distinctive bytes).
fn assert_no_echo(label: &str, target: &str, text: &str) {
    if target.is_empty() || target.trim().is_empty() {
        return;
    }
    assert!(!text.contains(target), "{label}: refusal echoed the target");
    for probe in ["ECHOPROBE4408", "\u{200b}", "system"] {
        if target.contains(probe) {
            assert!(!text.contains(probe), "{label}: refusal echoed `{probe}`");
        }
    }
}

/// No row persisted in the namespace through the backend's own read path.
async fn assert_no_row(store: &dyn MemoryStore, ns: &str, label: &str) {
    let ctx = CallerContext::for_agent("ai:reader4408");
    let rows = store
        .signal_inbox(&ctx, ns, None, 100)
        .await
        .expect("signal inbox");
    assert!(rows.is_empty(), "{label}: a signal row was persisted");
}

/// No quota charge and no coordination audit record on the sqlite accounting
/// connection (the quota row always lives on the sqlite `app.db`).
fn assert_no_charge_no_audit(conn: &rusqlite::Connection, sender: &str, ns: &str, label: &str) {
    let q = ai_memory::quotas::get_status(conn, sender, ns).expect("quota status");
    assert_eq!(q.current_storage_bytes, 0, "{label}: quota bytes charged");
    assert_eq!(q.current_memories_today, 0, "{label}: quota charged");
    let audits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [ai_memory::coordination_audit::SIGNAL_SEND],
            |r| r.get(0),
        )
        .expect("audit count");
    assert_eq!(audits, 0, "{label}: a coordination audit row was written");
}

/// Store-level refusal detail for `target`, asserting the typed error.
async fn store_refusal(store: &dyn MemoryStore, label: &str, target: &str) -> String {
    let sender = unique("ai:s4408");
    let ns = unique(NS);
    let ctx = CallerContext::for_agent(&sender);
    let err = store
        .signal_send(&ctx, &signal_for(&ns, &sender, Some(target)), None)
        .await
        .expect_err(label);
    let StoreError::InvalidInput { detail } = err else {
        panic!("{label}: expected InvalidInput, got {err:?}");
    };
    assert_no_echo(label, target, &detail);
    assert_no_row(store, &ns, label).await;
    detail
}

/// HTTP refusal (status, body) for `target` through a fresh sender.
async fn http_refusal(app: &AppState, label: &str, target: &str) -> (StatusCode, String) {
    let sender = unique("ai:h4408");
    let token = uuid::Uuid::new_v4().to_string();
    let router = router(app.clone(), &token, &sender);
    let ns = unique(NS);
    let (status, text) = http_signal(&router, &token, &signal_body(&ns, target)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {text}");
    assert_no_echo(label, target, &text);
    assert_no_row(app.store.as_ref(), &ns, label).await;
    {
        let conn = app.db.lock().await;
        assert_no_charge_no_audit(&conn.0, &sender, &ns, label);
    }
    (status, text)
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_store_signal_send_refuses_invalid_recipient_4408() {
    let dir = tempfile::tempdir().expect("dir");
    let (store, _path) = sqlite_store(&dir);
    for (label, target) in invalid_targets() {
        store_refusal(store.as_ref(), label, &target).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_http_signal_send_refuses_invalid_recipient_4408() {
    let dir = tempfile::tempdir().expect("dir");
    let (store, path) = sqlite_store(&dir);
    let app = sqlite_app(store, &path);
    for (label, target) in invalid_targets() {
        http_refusal(&app, label, &target).await;
    }
}

#[test]
fn validate_signal_recipient_follows_the_agent_id_contract_4408() {
    use ai_memory::validate::validate_signal_recipient as v;
    assert!(v(None).is_ok(), "absent means broadcast");
    for ok in [
        GOOD_TARGET,
        "a",
        &"a".repeat(128),
        "spiffe://example.org/ns/prod",
    ] {
        assert!(v(Some(ok)).is_ok(), "{ok}");
    }
    for (label, bad) in invalid_targets() {
        let e = v(Some(&bad)).expect_err(label);
        assert_eq!(e.to_string(), ai_memory::validate::SIGNAL_RECIPIENT_REFUSAL);
        // The recipient contract is the registration contract.
        assert!(
            ai_memory::validate::validate_agent_id(&bad).is_err(),
            "{label}"
        );
    }
}

/// The recipient is counted in the #1807 storage-only quota bytes (HTTP).
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_http_recipient_is_counted_in_quota_bytes_4408() {
    let dir = tempfile::tempdir().expect("dir");
    let (store, path) = sqlite_store(&dir);
    let app = sqlite_app(store, &path);
    let to = "ai:quota-recipient-4408";
    let ns = unique(NS);
    let mut charged = Vec::new();
    for body in [
        signal_body(&ns, to),
        json!({"namespace": ns, "subject": "s4408", "body": {"k": "v4408"}}),
    ] {
        let sender = unique("ai:q4408");
        let token = uuid::Uuid::new_v4().to_string();
        let router = router(app.clone(), &token, &sender);
        let (status, text) = http_signal(&router, &token, &body).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let conn = app.db.lock().await;
        charged.push(
            ai_memory::quotas::get_status(&conn.0, &sender, &ns)
                .expect("status")
                .current_storage_bytes,
        );
    }
    let delta = i64::try_from(to.len()).expect("len");
    assert_eq!(
        charged[0] - charged[1],
        delta,
        "recipient bytes not counted"
    );
}

/// Absent / null recipient is still a broadcast on the HTTP funnel.
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_http_absent_recipient_is_still_a_broadcast_4408() {
    let dir = tempfile::tempdir().expect("dir");
    let (store, path) = sqlite_store(&dir);
    let app = sqlite_app(store, &path);
    for body in [
        json!({"namespace": NS, "subject": "s", "body": {}}),
        json!({"namespace": NS, "subject": "s", "to_agent": null, "body": {}}),
    ] {
        let sender = unique("ai:b4408");
        let token = uuid::Uuid::new_v4().to_string();
        let router = router(app.clone(), &token, &sender);
        let (status, text) = http_signal(&router, &token, &body).await;
        assert_eq!(status, StatusCode::OK, "{text}");
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn pg_store_signal_send_refuses_invalid_recipient_4408() {
    let Some(store) = pg_store().await else {
        return;
    };
    for (label, target) in invalid_targets() {
        store_refusal(store.as_ref(), label, &target).await;
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn pg_http_signal_send_refuses_invalid_recipient_4408() {
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
async fn sqlite_and_pg_refuse_identically_4408() {
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

/// A valid recipient (and an absent one) still lands on both backends.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn valid_recipient_still_delivers_on_both_backends_4408() {
    let Some(pg) = pg_store().await else { return };
    let dir = tempfile::tempdir().expect("dir");
    let (sq, _path) = sqlite_store(&dir);
    for store in [sq as Arc<dyn MemoryStore>, pg as Arc<dyn MemoryStore>] {
        let sender = unique("ai:ok4408");
        let ctx = CallerContext::for_agent(&sender);
        let target = unique(GOOD_TARGET);
        for to in [Some(target.as_str()), None] {
            store
                .signal_send(&ctx, &signal_for(NS, &sender, to), None)
                .await
                .expect("valid signal");
        }
    }
}
