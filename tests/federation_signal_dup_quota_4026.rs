// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4026 — a DUPLICATE federated signal (legitimate redelivery in a fresh
//! authenticated envelope: lost response, partial-batch retry) must not be
//! charged against the author's cumulative storage-bytes quota.
//!
//! `apply_remote_signal` is idempotent on the signal UUID (a replay no-ops),
//! but pre-fix the postgres receive funnel charged the signal's byte estimate
//! BEFORE calling it and never refunded the no-op, so every redelivery grew a
//! counter that never resets until the author's namespace allowance was
//! exhausted by ONE stored row. The sqlite funnel probes existence before
//! charging. Both backends must now: store one row, charge once, and
//! acknowledge each duplicate as a clean no-op.
//!
//! The postgres cell is gated on `feature = "sal-postgres"` +
//! `AI_MEMORY_TEST_POSTGRES_URL` (skip line otherwise — the house pattern).

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::receive_auth::{
    REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, REQUIRE_SIGNAL_SIG_ENV,
};
use ai_memory::federation::signing::REQUIRE_SIG_ENV;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Signal, SignalType};

const PEER: &str = "ai:peer-4026";
/// Redeliveries of the SAME signal, each in a fresh envelope.
const REDELIVERIES: usize = 5;

static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn set_posture() {
    unsafe {
        std::env::set_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, "0");
        std::env::set_var(REQUIRE_SIG_ENV, "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, "0");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        std::env::remove_var(REQUIRE_SIG_ENV);
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV);
    }
}

fn app_state(
    db: Db,
    backend: StorageBackend,
    store: Arc<dyn ai_memory::store::MemoryStore>,
) -> AppState {
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

fn router_for(state: AppState) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, state)
}

fn sqlite_router() -> (axum::Router, Arc<dyn ai_memory::store::MemoryStore>, Db) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    std::mem::forget(db_tmp);
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    (
        router_for(app_state(db.clone(), StorageBackend::Sqlite, store.clone())),
        store,
        db,
    )
}

#[cfg(feature = "sal-postgres")]
async fn pg_router(url: &str) -> (axum::Router, Arc<dyn ai_memory::store::MemoryStore>, Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres"),
    );
    (
        router_for(app_state(
            db.clone(),
            StorageBackend::Postgres,
            store.clone(),
        )),
        store,
        db,
    )
}

fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-4026");
    ctx.bypass_visibility = true;
    ctx
}

fn make_signal(namespace: &str) -> Signal {
    Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        from_agent: PEER.to_string(),
        to_agent: None,
        subject: "redelivered".to_string(),
        body: json!({"payload": "x".repeat(512)}),
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: json!([]),
        created_at: 1_700_000_000,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    }
}

async fn push(router: &axum::Router, sig: &Signal) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER,
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [sig],
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER,
        )
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn charged_bytes(db: &Db, namespace: &str) -> i64 {
    let lock = db.lock().await;
    ai_memory::quotas::peek_status(&lock.0, PEER, namespace)
        .expect("peek quota")
        .current_storage_bytes
}

async fn run_cell(
    backend: &str,
    router: &axum::Router,
    store: &Arc<dyn ai_memory::store::MemoryStore>,
    db: &Db,
) {
    let ns = format!("ns-4026-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let sig = make_signal(&ns);

    let (status, _) = push(router, &sig).await;
    assert_eq!(status, StatusCode::OK, "{backend}: first delivery");
    let after_first = charged_bytes(db, &ns).await;
    assert!(after_first > 0, "{backend}: the first delivery is charged");
    assert!(
        store
            .signal_get(&admin_ctx(), &sig.id)
            .await
            .expect("signal_get")
            .is_some(),
        "{backend}: the signal is stored"
    );

    for n in 0..REDELIVERIES {
        let (status, body) = push(router, &sig).await;
        assert_eq!(status, StatusCode::OK, "{backend}: redelivery {n}");
        assert_eq!(
            body.get("skipped").and_then(Value::as_u64).unwrap_or(0),
            0,
            "#4026 ({backend}): a duplicate must acknowledge cleanly, not count skipped: {body}"
        );
    }
    let after_dups = charged_bytes(db, &ns).await;
    assert_eq!(
        after_dups, after_first,
        "#4026 ({backend}): {REDELIVERIES} duplicate deliveries of ONE stored signal must \
         not grow the cumulative storage-bytes charge (first={after_first}, now={after_dups})"
    );
}

#[tokio::test]
async fn duplicate_signal_not_charged_sqlite_4026() {
    let _g = FED_ENV_LOCK.lock().await;
    set_posture();
    let (router, store, db) = sqlite_router();
    run_cell("sqlite", &router, &store, &db).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn duplicate_signal_not_charged_pg_4026() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("SKIP duplicate_signal_not_charged_pg_4026: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    set_posture();
    let (router, store, db) = pg_router(&url).await;
    run_cell("postgres", &router, &store, &db).await;
    clear_posture();
}
