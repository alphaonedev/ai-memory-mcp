// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4023 — the federation `/sync/push` memories lane authorizes a colliding
//! row's STORED namespace (#2447) on a read that precedes the merge's write
//! transaction. `merge_memory` LWWs `namespace`, so a broader-scoped writer
//! that moves the row between that read and the merge must NOT have the narrow
//! peer's later-timestamped write land on the moved row. The fix re-authorizes
//! the peer's scope against the row the merge actually locks (`FOR UPDATE` on
//! postgres, `BEGIN IMMEDIATE` on sqlite), inside the merge transaction.
//!
//! Choreography (deterministic, no sleeps on postgres):
//!   1. seed a row in the peer's in-scope namespace;
//!   2. a second connection takes the row's write lock;
//!   3. the narrow peer pushes the row's id — its scope pre-read passes (the row
//!      is still in scope) and its merge blocks on the lock;
//!   4. the second connection moves the row into an out-of-scope namespace and
//!      commits;
//!   5. the merge resumes. It must refuse: the moved row's namespace and content
//!      are unchanged.
//!
//! The sqlite cell is the two-connection variant (a second connection holds
//! `BEGIN IMMEDIATE`; the daemon's writes wait on `busy_timeout`). The postgres
//! cell is gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`.

#![cfg(feature = "sal")]
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

static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const ORIGINAL_CONTENT: &str = "broad-writer row content";

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
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

/// Enrol `peer` scoped to `<public_ns_root>/*` ONLY.
fn set_scoped_posture(peer: &str, public_ns_root: &str) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{peer}":{{"allowed_namespaces":["{public_ns_root}/*"],"allowed_sender_agent_ids":["{peer}"]}}}}"#
            ),
        );
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-4023");
    ctx.bypass_visibility = true;
    ctx
}

fn seed_row(id: &str, namespace: &str) -> ai_memory::models::Memory {
    ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: uniq("moved-row"),
        content: ORIGINAL_CONTENT.to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:broad-writer-4023"}),
        ..Default::default()
    }
}

fn push_body(peer: &str, id: &str, namespace: &str) -> Value {
    json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": id,
            "tier": "long",
            "namespace": namespace,
            "title": uniq("narrow-push"),
            "content": "narrow peer overwrite",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "access_count": 0,
            "created_at": "2026-01-01T00:00:00+00:00",
            // Later than the seed AND the move, so it wins every LWW field.
            "updated_at": chrono::Utc::now().to_rfc3339(),
            "metadata": {"agent_id": peer},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": false,
    })
}

async fn push(router: axum::Router, peer: String, body: Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            peer.as_str(),
        )
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 64 * 1024).await;
    status
}

async fn assert_moved_row_untouched(
    backend: &str,
    store: &Arc<dyn MemoryStore>,
    id: &str,
    moved_ns: &str,
) {
    let row = store.get(&admin_ctx(), id).await.expect("row must exist");
    assert_eq!(
        row.namespace, moved_ns,
        "#4023 ({backend}): the narrow peer's merge must not relocate a row a broader \
         writer moved out of its scope (stale pre-read verdict)"
    );
    assert_eq!(
        row.content, ORIGINAL_CONTENT,
        "#4023 ({backend}): the narrow peer's merge must not overwrite the moved row's content"
    );
}

// ---------------------------------------------------------------------
// sqlite — two-connection variant.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_scope_verdict_refused_after_concurrent_move_sqlite_4023() {
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:narrow");
    let public_root = uniq("public");
    let secure_ns = uniq("secure/ops");
    set_scoped_posture(&peer, &public_root);

    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    std::mem::forget(db_tmp);
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let router = router_for(app_state(db, StorageBackend::Sqlite, store.clone()));

    let id = uuid::Uuid::new_v4().to_string();
    let in_scope_ns = format!("{public_root}/shared");
    store
        .store(&admin_ctx(), &seed_row(&id, &in_scope_ns))
        .await
        .expect("seed");

    // Second connection: hold the database write lock.
    let other = ai_memory::db::open(&db_path).expect("second connection");
    other
        .execute_batch("BEGIN IMMEDIATE")
        .expect("second connection write lock");

    let push_task = tokio::spawn(push(
        router.clone(),
        peer.clone(),
        push_body(&peer, &id, &in_scope_ns),
    ));
    // The daemon's scope pre-read is a WAL read and passes; its first write
    // then waits on `busy_timeout` (5 s) for this connection's lock.
    //
    // Why a sleep and why it is safe: sqlite exposes no "a writer is blocked
    // on the lock" observable (the postgres twin polls `pg_stat_activity`), so
    // this waits for the push task to finish its pre-read and reach the
    // blocked `BEGIN IMMEDIATE`. 1500 ms is far below the 5000 ms
    // `busy_timeout`, so the move below always lands while the merge is still
    // waiting and never after it timed out. If a loaded host were slower than
    // 1500 ms the pre-read would see the MOVED row and refuse at the funnel's
    // own pre-check instead: the cell then still passes but no longer reaches
    // the in-transaction re-check. That failure direction is a vacuous pass,
    // not a corruption, and it is bounded by the mutation evidence: with the
    // in-transaction re-check disabled this cell goes red (#4023 review M2/M3).
    // Replacing the sleep with a deterministic sqlite barrier is tracked as
    // the review's N3 follow-up.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    other
        .execute(
            "UPDATE memories SET namespace = ?1 WHERE id = ?2",
            rusqlite::params![secure_ns, id],
        )
        .expect("broader writer moves the row");
    other.execute_batch("COMMIT").expect("commit move");

    let status = push_task.await.expect("push task");
    assert!(
        status.is_success(),
        "sync_push must not hard-error: {status}"
    );
    assert_moved_row_untouched("sqlite", &store, &id, &secure_ns).await;

    // CONTROL: with no concurrent move, the in-scope merge still lands.
    let ctl = uuid::Uuid::new_v4().to_string();
    store
        .store(&admin_ctx(), &seed_row(&ctl, &in_scope_ns))
        .await
        .expect("seed control");
    let status = push(router, peer.clone(), push_body(&peer, &ctl, &in_scope_ns)).await;
    assert!(status.is_success());
    let row = store.get(&admin_ctx(), &ctl).await.expect("control row");
    assert_eq!(
        row.content, "narrow peer overwrite",
        "#4023 (sqlite): an in-scope merge must still apply"
    );
    clear_posture();
}

// ---------------------------------------------------------------------
// postgres — the issue's primary finding.
// ---------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_scope_verdict_refused_after_concurrent_move_pg_4023() {
    use ai_memory::store::postgres::PostgresStore;

    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "SKIP stale_scope_verdict_refused_after_concurrent_move_pg_4023: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:narrow");
    let public_root = uniq("public");
    let secure_ns = uniq("secure/ops");
    set_scoped_posture(&peer, &public_root);

    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    let router = router_for(app_state(db, StorageBackend::Postgres, store.clone()));

    let id = uuid::Uuid::new_v4().to_string();
    let in_scope_ns = format!("{public_root}/shared");
    store
        .store(&admin_ctx(), &seed_row(&id, &in_scope_ns))
        .await
        .expect("seed");

    // Second connection: the broader writer holds the row lock.
    let broad = PostgresStore::connect(&url).await.expect("second pool");
    let mut tx = broad.pool().begin().await.expect("begin");
    sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await
        .expect("lock row");

    let push_task = tokio::spawn(push(
        router.clone(),
        peer.clone(),
        push_body(&peer, &id, &in_scope_ns),
    ));

    // Wait until the receive's merge is BLOCKED on our row lock — by then its
    // scope pre-read (a plain pool read, never blocked by a row lock) is done.
    let mut blocked = false;
    for _ in 0..200 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND pid <> pg_backend_pid() \
               AND wait_event_type = 'Lock' AND query ILIKE '%for update%'",
        )
        .fetch_one(broad.pool())
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            blocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(blocked, "the receive merge never reached the row lock");

    sqlx::query("UPDATE memories SET namespace = $1 WHERE id = $2")
        .bind(&secure_ns)
        .bind(&id)
        .execute(&mut *tx)
        .await
        .expect("broader writer moves the row");
    tx.commit().await.expect("commit move");

    let status = push_task.await.expect("push task");
    assert!(
        status.is_success(),
        "sync_push must not hard-error: {status}"
    );
    assert_moved_row_untouched("postgres", &store, &id, &secure_ns).await;

    // CONTROL: with no concurrent move, the in-scope merge still lands.
    let ctl = uuid::Uuid::new_v4().to_string();
    store
        .store(&admin_ctx(), &seed_row(&ctl, &in_scope_ns))
        .await
        .expect("seed control");
    let status = push(router, peer.clone(), push_body(&peer, &ctl, &in_scope_ns)).await;
    assert!(status.is_success());
    let row = store.get(&admin_ctx(), &ctl).await.expect("control row");
    assert_eq!(
        row.content, "narrow peer overwrite",
        "#4023 (pg): an in-scope merge must still apply"
    );
    clear_posture();
}

// ---------------------------------------------------------------------
// Error parity — the refusal is ONE typed variant on BOTH backends
// (5-agent vote (4d3ea1c5), memory 179cf088).
// ---------------------------------------------------------------------

/// Drive `merge_inbound_authorized` with a refusing authorizer, then an
/// admitting one, on `store`, and assert the refusal is
/// `StoreError::PermissionDenied { action: FEDERATION_MERGE_INBOUND, .. }`
/// (not `Backend`) with the row untouched, and that the admitting authorizer
/// still merges.
async fn assert_typed_refusal(backend: &str, store: &dyn MemoryStore) {
    use ai_memory::store::{FEDERATION_MERGE_INBOUND, StoreError};

    let id = uuid::Uuid::new_v4().to_string();
    let ns = uniq("variant/ns");
    store
        .store(&admin_ctx(), &seed_row(&id, &ns))
        .await
        .expect("seed");
    let mut inbound = seed_row(&id, &ns);
    inbound.content = "narrow peer overwrite".to_string();
    inbound.updated_at = "2026-06-01T00:00:00+00:00".to_string();

    let refused = store
        .merge_inbound_authorized(&admin_ctx(), &inbound, false, &|_stored: &str| false)
        .await;
    match refused {
        Err(StoreError::PermissionDenied { action, target, .. }) => {
            assert_eq!(action, FEDERATION_MERGE_INBOUND, "{backend}: action");
            assert_eq!(target, id, "{backend}: target");
        }
        other => panic!("#4023 ({backend}): expected PermissionDenied, got {other:?}"),
    }
    let row = store.get(&admin_ctx(), &id).await.expect("row");
    assert_eq!(
        row.content, ORIGINAL_CONTENT,
        "{backend}: refusal writes nothing"
    );

    // CONTROL: an admitting authorizer merges.
    store
        .merge_inbound_authorized(&admin_ctx(), &inbound, false, &|_stored: &str| true)
        .await
        .expect("admitted merge");
    let row = store.get(&admin_ctx(), &id).await.expect("row");
    assert_eq!(row.content, "narrow peer overwrite", "{backend}: control");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_refusal_is_permission_denied_variant_sqlite_4023() {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    std::mem::forget(db_tmp);
    drop(ai_memory::db::open(&db_path).expect("db::open"));
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore");
    assert_typed_refusal("sqlite", &store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_refusal_is_permission_denied_variant_pg_4023() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "SKIP merge_refusal_is_permission_denied_variant_pg_4023: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    assert_typed_refusal("postgres", &store).await;
}
