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

// ---------------------------------------------------------------------
// CONCURRENT duplicate — the same UUID is stored by another writer AFTER the
// receive's existence probe and BEFORE its write. The probe cannot see it, so
// the charge is taken; the write then fails on the primary key (or finds the
// row), and the charge must be refunded exactly. Deterministic interleave: the
// other writer holds its lock with the duplicate UNCOMMITTED until the receive
// is past its probe, then commits.
// ---------------------------------------------------------------------

fn charged_after_concurrent_duplicate_msg(backend: &str, charged: i64) -> String {
    format!(
        "#4026 ({backend}): a duplicate stored concurrently by another writer must leave \
         this receive's net storage charge at 0 (the write stored nothing); charged={charged}"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_duplicate_signal_refunded_sqlite_4026() {
    let _g = FED_ENV_LOCK.lock().await;
    set_posture();
    let (router, store, db) = sqlite_router();
    let db_path = db.lock().await.1.clone();
    let ns = format!("ns-4026c-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let sig = make_signal(&ns);

    // The other writer: second connection, write lock held, duplicate inserted
    // but NOT committed (invisible to the receive's probe).
    let other = ai_memory::db::open(&db_path).expect("second connection");
    other.execute_batch("BEGIN IMMEDIATE").expect("write lock");
    ai_memory::signals::insert(&other, &sig).expect("duplicate insert");

    let push_router = router.clone();
    let push_sig = sig.clone();
    let task = tokio::spawn(async move { push(&push_router, &push_sig).await });
    // The receive probes (a WAL read of the pre-duplicate snapshot), then its
    // quota charge waits on `busy_timeout` for this connection's lock.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    other.execute_batch("COMMIT").expect("commit duplicate");

    let (status, _) = task.await.expect("push task");
    assert_eq!(status, StatusCode::OK, "sqlite: push status");
    let charged = charged_bytes(&db, &ns).await;
    assert_eq!(
        charged,
        0,
        "{}",
        charged_after_concurrent_duplicate_msg("sqlite", charged)
    );
    assert!(
        store
            .signal_get(&admin_ctx(), &sig.id)
            .await
            .expect("signal_get")
            .is_some(),
        "sqlite: exactly the one stored signal remains"
    );
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_duplicate_signal_refunded_pg_4026() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "SKIP concurrent_duplicate_signal_refunded_pg_4026: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    set_posture();
    let (router, store, db) = pg_router(&url).await;
    let ns = format!("ns-4026c-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let sig = make_signal(&ns);

    // The other writer: blocks every INSERT into `signals` (SELECTs still run),
    // with the duplicate inserted but NOT committed.
    let other = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("second pool");
    let mut tx = other.pool().begin().await.expect("begin");
    sqlx::query("LOCK TABLE signals IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .expect("lock signals");
    sqlx::query(
        "INSERT INTO signals (id, namespace, from_agent, to_agent, subject, body, signal_type, \
         in_reply_to, correlation_id, reference_ids, created_at, expires_at, delivered_at, \
         read_at, acknowledged_at, signature, sender_pubkey) \
         VALUES ($1, $2, $3, NULL, $4, $5, $6, NULL, NULL, $7, $8, NULL, NULL, NULL, NULL, $9, $10)",
    )
    .bind(&sig.id)
    .bind(&sig.namespace)
    .bind(&sig.from_agent)
    .bind(&sig.subject)
    .bind(sig.body.to_string())
    .bind(sig.signal_type.as_str())
    .bind(sig.reference_ids.to_string())
    .bind(sig.created_at)
    .bind(&sig.signature)
    .bind(&sig.sender_pubkey)
    .execute(&mut *tx)
    .await
    .expect("duplicate insert");

    let push_router = router.clone();
    let push_sig = sig.clone();
    let task = tokio::spawn(async move { push(&push_router, &push_sig).await });
    // Wait until the receive's own INSERT is blocked on the table lock — by
    // then its probe and its quota charge have both run.
    let mut blocked = false;
    for _ in 0..200 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND pid <> pg_backend_pid() \
               AND wait_event_type = 'Lock' AND query ILIKE 'insert into signals%'",
        )
        .fetch_one(other.pool())
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            blocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        blocked,
        "the receive's signal INSERT never reached the lock"
    );
    tx.commit().await.expect("commit duplicate");

    let (status, _) = task.await.expect("push task");
    assert_eq!(status, StatusCode::OK, "postgres: push status");
    let charged = charged_bytes(&db, &ns).await;
    assert_eq!(
        charged,
        0,
        "{}",
        charged_after_concurrent_duplicate_msg("postgres", charged)
    );
    assert!(
        store
            .signal_get(&admin_ctx(), &sig.id)
            .await
            .expect("signal_get")
            .is_some(),
        "postgres: exactly the one stored signal remains"
    );
    clear_posture();
}

// ---------------------------------------------------------------------
// RACING duplicates (vote cc79c670 item 2) — N attempts deliver the SAME signal
// at once. Exactly one attempt reports the signal applied; every other attempt
// is a clean no-op or an `Err` that was refunded; the author's net charge equals
// ONE stored signal (the charge a lone sequential delivery takes).
// ---------------------------------------------------------------------

const RACERS: usize = 8;

async fn racing_cell(
    backend: &str,
    router: &axum::Router,
    store: &Arc<dyn ai_memory::store::MemoryStore>,
    db: &Db,
) {
    // Baseline: what ONE lone delivery of an equally sized signal costs.
    let base_ns = format!("ns-4026r0-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let (status, _) = push(router, &make_signal(&base_ns)).await;
    assert_eq!(status, StatusCode::OK, "{backend}: baseline delivery");
    let one_signal = charged_bytes(db, &base_ns).await;
    assert!(one_signal > 0, "{backend}: a stored signal is charged");

    let ns = format!("ns-4026r-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let sig = make_signal(&ns);
    let mut tasks = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let r = router.clone();
        let s = sig.clone();
        tasks.push(tokio::spawn(async move { push(&r, &s).await }));
    }
    let mut applied = 0u64;
    for t in tasks {
        let (status, body) = t.await.expect("racer task");
        assert_eq!(status, StatusCode::OK, "{backend}: racer status");
        applied += body
            .get("signals_applied")
            .and_then(Value::as_u64)
            .unwrap_or(0);
    }
    assert_eq!(
        applied, 1,
        "#4026 ({backend}): exactly one of {RACERS} racing duplicates is applied"
    );
    assert!(
        store
            .signal_get(&admin_ctx(), &sig.id)
            .await
            .expect("signal_get")
            .is_some(),
        "{backend}: the raced signal is stored once"
    );
    let charged = charged_bytes(db, &ns).await;
    assert_eq!(
        charged, one_signal,
        "#4026 ({backend}): {RACERS} racing duplicates must net-charge exactly ONE signal \
         (one={one_signal}, charged={charged})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_duplicate_signals_charge_once_sqlite_4026() {
    let _g = FED_ENV_LOCK.lock().await;
    set_posture();
    let (router, store, db) = sqlite_router();
    racing_cell("sqlite", &router, &store, &db).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_duplicate_signals_charge_once_pg_4026() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "SKIP racing_duplicate_signals_charge_once_pg_4026: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    set_posture();
    let (router, store, db) = pg_router(&url).await;
    racing_cell("postgres", &router, &store, &db).await;
    clear_posture();
}
