// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4025 — a federated pending-action APPROVAL must be completable.
//!
//! Pre-fix both receive funnels committed `status = 'approved'` BEFORE running
//! the pending action's effect, as a separate step. When the effect failed (or
//! the process stopped in between) the row stayed `approved` with its effect
//! missing, and every redelivery of the same decision was refused as "already
//! decided" — the effect could never be completed. A lost-response redelivery
//! after a SUCCESSFUL execution was likewise counted `skipped`, so the sender
//! never acknowledged.
//!
//! Cells, identical on both backends:
//!   1. FAIL-ONCE: the effect fails (an injected insert fault on the payload's
//!      title); the decision must not become durable — the row stays `pending`
//!      and nothing landed.
//!   2. RETRY: the fault is cleared and the SAME decision is redelivered in a
//!      fresh envelope; exactly one effect lands and the row is `approved`.
//!   3. LOST RESPONSE: the decision is redelivered again; it acknowledges as a
//!      clean no-op (`skipped == 0`) and still exactly one effect exists.
//!
//! The fault is a database trigger scoped to one uuid title, so no other row
//! (or concurrent suite) is affected. Postgres cells are gated on
//! `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;

static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const PEER_ID: &str = "ai:peer-4025";
const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const INJECTED_FAULT: &str = "injected fault 4025";

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

/// Enrol `PEER_ID` scoped to `<root>/*`, authorised to decide as `approver`.
fn set_posture(root: &str, approver: &str) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{PEER_ID}":{{"allowed_namespaces":["{root}/*"],"allowed_sender_agent_ids":["{PEER_ID}","{approver}"]}}}}"#
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
    }
}

fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-4025");
    ctx.bypass_visibility = true;
    ctx
}

async fn register_approver(store: &Arc<dyn MemoryStore>, agent_id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    store
        .register_agent(
            &admin_ctx(),
            &ai_memory::models::AgentRegistration {
                agent_id: agent_id.to_string(),
                agent_type: "nhi".to_string(),
                capabilities: Vec::new(),
                registered_at: now.clone(),
                last_seen_at: now,
            },
        )
        .await
        .expect("register approver");
}

fn pending_entry(pid: &str, namespace: &str, title: &str) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "id": pid,
        "action_type": "store",
        "memory_id": null,
        "namespace": namespace,
        "payload": {
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long",
            "namespace": namespace,
            "title": title,
            "content": "federated governed write (#4025)",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {"agent_id": PEER_ID},
            "reflection_depth": 0,
            "memory_kind": "observation",
        },
        "requested_by": PEER_ID,
        "requested_at": now,
        "status": "pending",
        "decided_by": null,
        "decided_at": null,
        "approvals": []
    })
}

async fn push(router: &axum::Router, pendings: Vec<Value>, decisions: Vec<Value>) -> Value {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "pendings": pendings,
        "pending_decisions": decisions,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER_ID,
        )
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert!(status.is_success(), "push status {status}: {report}");
    report
}

fn counter(report: &Value, key: &str) -> i64 {
    report.get(key).and_then(Value::as_i64).unwrap_or(-1)
}

async fn pending_status(store: &Arc<dyn MemoryStore>, pid: &str) -> String {
    store
        .get_pending(&admin_ctx(), pid)
        .await
        .expect("get_pending")
        .expect("pending row exists")
        .status
}

/// The backend-specific probes the shared cell body needs.
#[allow(async_fn_in_trait)]
trait Fixture {
    async fn arm_fault(&self, title: &str);
    async fn clear_fault(&self);
    async fn count_title(&self, namespace: &str, title: &str) -> i64;
}

async fn run_cell(
    backend: &str,
    router: &axum::Router,
    store: &Arc<dyn MemoryStore>,
    fixture: &impl Fixture,
) {
    let root = uniq("public-4025");
    let ns = format!("{root}/ok");
    let approver = uniq("ai:approver-4025");
    set_posture(&root, &approver);
    register_approver(store, &approver).await;

    let pid = uuid::Uuid::new_v4().to_string();
    let title = uniq("governed-4025");
    let decision = json!({"id": pid, "approved": true, "decider": approver});

    // 1. FAIL-ONCE — the effect fails after a valid approval.
    fixture.arm_fault(&title).await;
    let report = push(
        router,
        vec![pending_entry(&pid, &ns, &title)],
        vec![decision.clone()],
    )
    .await;
    assert_eq!(
        counter(&report, "pendings_applied"),
        1,
        "{backend}: {report}"
    );
    assert_eq!(
        fixture.count_title(&ns, &title).await,
        0,
        "{backend}: the faulted effect must not land"
    );
    assert_eq!(
        pending_status(store, &pid).await,
        "pending",
        "#4025 ({backend}): a failed execution must leave the decision NON-durable \
         (pre-fix it committed `approved` with no effect)"
    );

    // 2. RETRY — fault cleared, same decision, fresh envelope.
    fixture.clear_fault().await;
    let report = push(router, vec![], vec![decision.clone()]).await;
    assert_eq!(
        fixture.count_title(&ns, &title).await,
        1,
        "#4025 ({backend}): the redelivered approval must complete the effect exactly once: {report}"
    );
    assert_eq!(pending_status(store, &pid).await, "approved", "{backend}");
    assert_eq!(
        counter(&report, "pending_decisions_applied"),
        1,
        "{backend}: {report}"
    );
    assert_eq!(counter(&report, "skipped"), 0, "{backend}: {report}");

    // 3. LOST RESPONSE — redelivered after success: clean converged no-op.
    let report = push(router, vec![], vec![decision]).await;
    assert_eq!(
        counter(&report, "skipped"),
        0,
        "#4025 ({backend}): a completed decision must acknowledge as a no-op, not be \
         refused as 'already decided': {report}"
    );
    assert_eq!(counter(&report, "noop"), 1, "{backend}: {report}");
    assert_eq!(
        fixture.count_title(&ns, &title).await,
        1,
        "#4025 ({backend}): the replay must not re-run the effect"
    );
    clear_posture();
}

// ---------------------------------------------------------------------
// sqlite
// ---------------------------------------------------------------------

struct SqliteFixture {
    path: std::path::PathBuf,
}

// The sqlite probes are synchronous; the trait is async for the postgres twin.
#[allow(clippy::unused_async_trait_impl)]
impl Fixture for SqliteFixture {
    async fn arm_fault(&self, title: &str) {
        let conn = rusqlite::Connection::open(&self.path).expect("fixture connection");
        conn.execute_batch(&format!(
            "CREATE TRIGGER fault_4025 BEFORE INSERT ON memories \
             WHEN NEW.title = '{title}' BEGIN SELECT RAISE(ABORT, '{INJECTED_FAULT}'); END;"
        ))
        .expect("arm fault");
    }
    async fn clear_fault(&self) {
        let conn = rusqlite::Connection::open(&self.path).expect("fixture connection");
        conn.execute_batch("DROP TRIGGER fault_4025")
            .expect("clear fault");
    }
    async fn count_title(&self, namespace: &str, title: &str) -> i64 {
        let conn = rusqlite::Connection::open(&self.path).expect("fixture connection");
        conn.query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![namespace, title],
            |r| r.get(0),
        )
        .expect("count")
    }
}

#[tokio::test]
async fn federated_approval_completes_after_failed_execution_sqlite_4025() {
    let _g = FED_ENV_LOCK.lock().await;
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
    run_cell("sqlite", &router, &store, &SqliteFixture { path: db_path }).await;
}

// ---------------------------------------------------------------------
// postgres
// ---------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
struct PgFixture {
    pool: sqlx::PgPool,
    suffix: String,
}

#[cfg(feature = "sal-postgres")]
impl Fixture for PgFixture {
    async fn arm_fault(&self, title: &str) {
        let s = &self.suffix;
        sqlx::query(&format!(
            "CREATE OR REPLACE FUNCTION fault_4025_{s}() RETURNS trigger AS $f$ \
             BEGIN IF NEW.title = '{title}' THEN RAISE EXCEPTION '{INJECTED_FAULT}'; END IF; \
             RETURN NEW; END $f$ LANGUAGE plpgsql"
        ))
        .execute(&self.pool)
        .await
        .expect("fault fn");
        sqlx::query(&format!(
            "CREATE TRIGGER fault_4025_{s} BEFORE INSERT OR UPDATE ON memories \
             FOR EACH ROW EXECUTE FUNCTION fault_4025_{s}()"
        ))
        .execute(&self.pool)
        .await
        .expect("arm fault");
    }
    async fn clear_fault(&self) {
        let s = &self.suffix;
        sqlx::query(&format!(
            "DROP TRIGGER IF EXISTS fault_4025_{s} ON memories"
        ))
        .execute(&self.pool)
        .await
        .expect("clear fault");
        sqlx::query(&format!("DROP FUNCTION IF EXISTS fault_4025_{s}()"))
            .execute(&self.pool)
            .await
            .expect("drop fault fn");
    }
    async fn count_title(&self, namespace: &str, title: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE namespace = $1 AND title = $2")
            .bind(namespace)
            .bind(title)
            .fetch_one(&self.pool)
            .await
            .expect("count")
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn federated_approval_completes_after_failed_execution_pg_4025() {
    use ai_memory::store::postgres::PostgresStore;

    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "SKIP federated_approval_completes_after_failed_execution_pg_4025: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
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
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("fixture pool");
    let fixture = PgFixture {
        pool,
        suffix: uuid::Uuid::new_v4().simple().to_string()[..8].to_string(),
    };
    run_cell("postgres", &router, &store, &fixture).await;
    fixture.clear_fault().await;
}
