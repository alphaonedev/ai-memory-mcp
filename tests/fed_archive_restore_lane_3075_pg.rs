// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3075 lane L-PGP, family F1 — the POSTGRES twin of
//! `tests/fed_archive_restore_lane_3075.rs`.
//!
//! Through v1.0.0 the federated `archives[]` / `restores[]` subcollections were
//! bucketed `unsupported_on_postgres` on a postgres receiver — honest, but the
//! lanes simply did not replicate, so a peer's archive/restore fanout silently
//! stopped at any pg node in the mesh. #3075 routes both through the SAL trait
//! (`apply_remote_archive` / `apply_remote_restore`).
//!
//! Each cell asserts BOTH halves of the gate, on ROW STATE read with raw SQL so
//! no accessor's own error folding can colour the answer:
//!
//! 1. an IN-SCOPE archive APPLIES — the row leaves `memories`, lands in
//!    `archived_memories` stamped `sync_push`, and its in-scope restore brings
//!    it back;
//! 2. an OUT-OF-SCOPE archive is REFUSED (#2447 by-id gate on the STORED
//!    namespace) — the live row survives, and no archive row appears;
//! 3. a FORGET-TOMBSTONED restore is REFUSED (#1848 / G30) — the resurrection
//!    vector stays closed on the backend that just acquired the lane.
//!
//! Asserting only the refusals would also pass on the pre-#3075 funnel that
//! applied nothing at all; asserting only the applies would pass on an ungated
//! funnel. The pair is what pins the gate, and the sqlite twin asserts the
//! identical dispositions so the two receivers cannot drift (#2488).
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip. Deliberately NOT `#[ignore]`: the PR postgres job does not pass
//! `--include-ignored`, so an ignored test silently never runs.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// Serialises every test in this binary — they all mutate process-global
/// federation env vars.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const SYNC_TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";
const PEER_ID: &str = "ai:peer-3075-pg";

struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        clear_posture();
    }
}

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Enrol `PEER_ID` scoped to `<root>/**` ONLY. `AI_MEMORY_FED_SYNC_TRUST_PEER`
/// is actively removed: setting it is what makes federation coverage vacuous.
fn set_scoped_posture(root: &str) {
    // SAFETY: every caller holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{PEER_ID}":{{"allowed_namespaces":["{root}/**"],"allowed_sender_agent_ids":["{PEER_ID}"]}}}}"#
            ),
        );
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn clear_posture() {
    // SAFETY: every caller holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
    }
}

fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-3075-pg");
    ctx.bypass_visibility = true;
    ctx
}

async fn pg_router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
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
        store: store.clone(),
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
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), store)
}

async fn raw_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("raw pool for row-state assertions")
}

async fn live_exists(pool: &sqlx::PgPool, id: &str) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM memories WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("probe live row")
}

async fn archived_reason(pool: &sqlx::PgPool, id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT archive_reason FROM archived_memories WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .expect("probe archive row")
    .flatten()
}

async fn seed_memory(store: &Arc<dyn MemoryStore>, id: &str, namespace: &str) {
    let mem = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: uniq("archive-target"),
        content: "row the federated archive/restore lane acts on".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:victim-3075"}),
        ..Default::default()
    };
    store.store(&admin_ctx(), &mem).await.expect("seed row");
}

async fn push(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER_ID,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

fn archives_push(ids: &[&str]) -> Value {
    json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "archives": ids,
        "dry_run": false,
    })
}

fn restores_push(ids: &[&str]) -> Value {
    json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "restores": ids,
        "dry_run": false,
    })
}

/// The ALLOWED half: an in-scope archive APPLIES on postgres and its restore
/// brings the row back. The `sync_push` reason marker is asserted because it is
/// the shared SSOT both adapters stamp — a backend stamping a different value
/// would make every reason-filtered query and `archive_stats` report disagree
/// across a heterogeneous federation.
#[tokio::test]
async fn federated_archive_then_restore_applies_in_scope_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;

    let root = uniq("pub3075");
    let ns = format!("{root}/ok");
    set_scoped_posture(&root);

    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let id = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &id, &ns).await;
    assert!(live_exists(&pool, &id).await, "precondition: row is live");

    let (status, report) = push(&router, &archives_push(&[&id])).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        !live_exists(&pool, &id).await,
        "#3075: the in-scope archive must move the live row on pg: {report}"
    );
    assert_eq!(
        archived_reason(&pool, &id).await.as_deref(),
        Some(ai_memory::models::field_names::ARCHIVE_REASON_SYNC_PUSH),
        "the federated archive stamps the shared sync_push reason: {report}"
    );
    assert_eq!(report["archived"].as_u64().unwrap_or(0), 1, "{report}");
    assert_eq!(
        report["unsupported_on_postgres"].as_u64().unwrap_or(0),
        0,
        "#3075: archives no longer bucket as unsupported: {report}"
    );

    let (status, report) = push(&router, &restores_push(&[&id])).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        live_exists(&pool, &id).await,
        "#3075: the in-scope restore must bring the row back on pg: {report}"
    );
    assert_eq!(report["restored"].as_u64().unwrap_or(0), 1, "{report}");
    assert_eq!(
        report["unsupported_on_postgres"].as_u64().unwrap_or(0),
        0,
        "{report}"
    );
}

/// The DENIED half: a peer scoped to `<root>/**` must not archive a row in a
/// namespace outside that scope. The subject is the row's STORED namespace
/// resolved by id (#2447), never the wire — `archives[]` carries only an id.
#[tokio::test]
async fn federated_archive_refused_out_of_scope_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;

    let root = uniq("pub3075d");
    let victim_ns = uniq("secure3075d");
    set_scoped_posture(&root);

    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let id = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &id, &victim_ns).await;

    let (status, report) = push(&router, &archives_push(&[&id])).await;
    assert_eq!(status, StatusCode::OK, "the batch survives: {report}");
    assert!(
        live_exists(&pool, &id).await,
        "#2447: an out-of-scope peer must NOT archive a foreign namespace's row: {report}"
    );
    assert!(
        archived_reason(&pool, &id).await.is_none(),
        "and must not have produced an archive row: {report}"
    );
    assert_eq!(report["archived"].as_u64().unwrap_or(0), 0, "{report}");
    assert_eq!(
        report["skipped"].as_u64().unwrap_or(0),
        1,
        "the refusal is sender-visible, never a silent drop: {report}"
    );
}

/// The #1848 / G30 resurrection gate, on the backend that just acquired the
/// lane: a peer must not undo a local forget by pushing a restore. Pinned
/// separately because `PostgresStore::archive_restore` deliberately carries NO
/// tombstone gate (it is the OPERATOR un-forget path, #1771) — the gate lives on
/// `apply_remote_restore`, and a future refactor that merged the two would
/// re-open exactly this vector.
#[tokio::test]
async fn federated_restore_of_tombstoned_id_refused_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;

    let root = uniq("pub3075t");
    let ns = format!("{root}/ok");
    set_scoped_posture(&root);

    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let id = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &id, &ns).await;

    let (status, report) = push(&router, &archives_push(&[&id])).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(!live_exists(&pool, &id).await, "precondition: archived");

    sqlx::query(
        "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at, agent_id, signature) \
         VALUES ($1, $2, $3, $4, NULL)",
    )
    .bind(&id)
    .bind(&ns)
    .bind("2026-09-05T00:00:00Z")
    .bind("ai:victim-3075")
    .execute(&pool)
    .await
    .expect("seed forget tombstone");

    let (status, report) = push(&router, &restores_push(&[&id])).await;
    assert_eq!(status, StatusCode::OK, "the batch survives: {report}");
    assert!(
        !live_exists(&pool, &id).await,
        "#1848/G30: the tombstoned row must NOT be resurrected by a peer: {report}"
    );
    assert_eq!(report["restored"].as_u64().unwrap_or(0), 0, "{report}");
    assert!(
        archived_reason(&pool, &id).await.is_some(),
        "the refusal is a no-op: the archived row is neither restored nor destroyed: {report}"
    );
}
