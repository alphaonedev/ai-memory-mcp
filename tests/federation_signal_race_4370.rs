// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4370 — a federation-receive RACE LOSER on Postgres must report the same
//! converged outcome sqlite reports for a duplicate.
//!
//! Two deliveries of the SAME signal id can both pass the existence probes and
//! then race to the INSERT; the loser's INSERT fails on the `signals` PRIMARY
//! KEY. Pre-fix the loser surfaced as a hard error: the funnel logged "signal
//! apply failed", counted the signal `skipped` although the row exists (a sender
//! keyed on `skipped` keeps resending), and had charged the author's storage
//! quota for storage it never used. SQLite serialises its racers under the one
//! database lock, so its duplicate is already `noop`. The Postgres loser must be
//! `noop` too, with exactly one stored row and no net quota charge.
//!
//! ## Deterministic race (no timing luck)
//!
//! A second connection opens a transaction and INSERTs the same id UNCOMMITTED.
//! The receive's probes (MVCC snapshot) cannot see it, so the receive proceeds
//! to its own INSERT, which then BLOCKS on the uncommitted unique-index entry.
//! The test waits on `pg_blocking_pids` (the receive's backend is blocked by the
//! holder's backend pid) and only then commits the holder: the receive's INSERT
//! deterministically loses on the primary key. Every wait is a bounded poll on
//! server state, never a sleep-and-hope.
//!
//! ## Hygiene (lessons of the #4010 / #4329 reviews)
//!
//! * its OWN test binary, serialised by one process-wide lock;
//! * every cell body returns `Result`; the cleanup (abort the push task, roll
//!   back the holder, delete this cell's rows by its unique namespace / id,
//!   clear the process env) runs on EVERY exit path, success, assertion or error,
//!   before the verdict is asserted;
//! * the fixture is robust on a churned database: unique ids / namespaces per
//!   run, counts scoped to this cell's own keys, and the blocked-backend probe
//!   scoped to the holder's pid, so leftover rows or concurrent runs on the same
//!   database cannot change the verdict.
//!
//! Postgres cells soft-skip with a named line without `AI_MEMORY_TEST_POSTGRES_URL`
//! (the house pattern); they are never `#[ignore]`.

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown, clippy::too_many_lines)]

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

const PEER: &str = "ai:peer-4370";

/// Serialises every cell in this binary: they mutate process-global env.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// Clears the federation posture env on EVERY exit path (drop), including a
/// panic that unwinds past a cell.
struct Posture;

impl Posture {
    fn set() -> Self {
        // SAFETY: the caller holds FED_ENV_LOCK for the guard's lifetime.
        unsafe {
            std::env::set_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, "0");
            std::env::set_var(REQUIRE_SIG_ENV, "0");
            std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
            std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, "0");
            std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        }
        Self
    }
}

impl Drop for Posture {
    fn drop(&mut self) {
        // SAFETY: the holder owns FED_ENV_LOCK for the guard's lifetime.
        unsafe {
            std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
            std::env::remove_var(REQUIRE_SIG_ENV);
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
            std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV);
        }
    }
}

/// Aborts a spawned task on drop so an early return can never leak it.
#[cfg(feature = "sal-postgres")]
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

#[cfg(feature = "sal-postgres")]
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

macro_rules! ensure {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err(format!($($arg)+));
        }
    };
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

fn sqlite_router() -> Result<(axum::Router, Db, tempfile::TempDir), String> {
    // A TempDir (not a leaked NamedTempFile): the db file AND its -wal / -shm
    // siblings are removed when the guard the caller holds is dropped.
    let dir = tempfile::TempDir::new().map_err(|e| format!("tempdir: {e}"))?;
    let db_path = dir.path().join("race4370.db");
    let _ = ai_memory::db::open(&db_path).map_err(|e| format!("db::open: {e}"))?;
    let conn = ai_memory::db::open(&db_path).map_err(|e| format!("reopen: {e}"))?;
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(&db_path)
            .map_err(|e| format!("open SqliteStore: {e}"))?,
    );
    Ok((
        router_for(app_state(db.clone(), StorageBackend::Sqlite, store)),
        db,
        dir,
    ))
}

#[cfg(feature = "sal-postgres")]
async fn pg_router(
    url: &str,
) -> Result<
    (
        axum::Router,
        Arc<ai_memory::store::postgres::PostgresStore>,
        Db,
    ),
    String,
> {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:"))
        .map_err(|e| format!("scratch sqlite: {e}"))?;
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let pg = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .map_err(|e| format!("connect postgres: {e}"))?,
    );
    let store: Arc<dyn ai_memory::store::MemoryStore> = pg.clone();
    Ok((
        router_for(app_state(db.clone(), StorageBackend::Postgres, store)),
        pg,
        db,
    ))
}

fn make_signal(namespace: &str) -> Signal {
    Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        from_agent: PEER.to_string(),
        to_agent: None,
        subject: "raced".to_string(),
        body: json!({"payload": "x".repeat(256)}),
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

async fn push(router: &axum::Router, sig: &Signal) -> Result<(StatusCode, Value), String> {
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
        .map_err(|e| format!("request: {e}"))?;
    let resp = router
        .clone()
        .oneshot(req)
        .await
        .map_err(|e| format!("oneshot: {e}"))?;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .map_err(|e| format!("body: {e}"))?;
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

/// The counters a sender keys its retry on: `(signals_applied, noop, skipped)`.
fn outcome(body: &Value) -> (u64, u64, u64) {
    let n = |k: &str| body.get(k).and_then(Value::as_u64).unwrap_or(0);
    (n("signals_applied"), n("noop"), n("skipped"))
}

async fn charged_bytes(db: &Db, namespace: &str) -> Result<i64, String> {
    let lock = db.lock().await;
    ai_memory::quotas::peek_status(&lock.0, PEER, namespace)
        .map(|s| s.current_storage_bytes)
        .map_err(|e| format!("peek quota: {e}"))
}

/// The outcome sqlite reports for a duplicate delivery of one stored signal
/// (the reference every Postgres duplicate must equal), plus the first
/// delivery's charge.
async fn sqlite_duplicate_outcome() -> Result<(u64, u64, u64), String> {
    let (router, db, _dir) = sqlite_router()?;
    let ns = format!("ns-4370s-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let sig = make_signal(&ns);
    let (status, first) = push(&router, &sig).await?;
    ensure!(
        status == StatusCode::OK && outcome(&first) == (1, 0, 0),
        "sqlite first delivery must apply: {status} {first}"
    );
    let charged = charged_bytes(&db, &ns).await?;
    ensure!(charged > 0, "sqlite first delivery is charged");
    let (status, dup) = push(&router, &sig).await?;
    ensure!(status == StatusCode::OK, "sqlite duplicate status {status}");
    ensure!(
        charged_bytes(&db, &ns).await? == charged,
        "sqlite duplicate must not grow the charge"
    );
    Ok(outcome(&dup))
}

#[tokio::test]
async fn sqlite_duplicate_signal_is_noop_4370() {
    let _g = FED_ENV_LOCK.lock().await;
    let _p = Posture::set();
    let got = sqlite_duplicate_outcome().await;
    assert_eq!(
        got,
        Ok((0, 1, 0)),
        "#4370: the sqlite reference outcome for a duplicate is applied=0 noop=1 skipped=0"
    );
}

// ---------------------------------------------------------------------
// Postgres: the deterministic race.
// ---------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use sqlx::Row as _;

    pub(super) fn url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    /// Wait (bounded, server-state poll) until some backend is blocked BY the
    /// holder's backend pid. Scoped to the holder's pid, so unrelated activity
    /// on a shared / churned database cannot satisfy it.
    pub(super) async fn wait_blocked_by(
        pool: &sqlx::PgPool,
        holder_pid: i32,
    ) -> Result<(), String> {
        for _ in 0..400 {
            let blocked: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE $1 = ANY(pg_blocking_pids(pid)) AND pid <> $1",
            )
            .bind(holder_pid)
            .fetch_one(pool)
            .await
            .map_err(|e| format!("pg_blocking_pids probe: {e}"))?;
            if blocked > 0 {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        Err("the receive's INSERT never blocked on the holder's uncommitted row".to_string())
    }

    /// Insert `sig` into `signals` on the holder's open transaction.
    pub(super) async fn insert_uncommitted(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        sig: &Signal,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO signals (id, namespace, from_agent, to_agent, subject, body, \
             signal_type, in_reply_to, correlation_id, reference_ids, created_at, expires_at, \
             delivered_at, read_at, acknowledged_at, signature, sender_pubkey) \
             VALUES ($1, $2, $3, NULL, $4, $5, $6, NULL, NULL, $7, $8, NULL, NULL, NULL, NULL, \
             $9, $10)",
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
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .map_err(|e| format!("holder insert: {e}"))
    }

    pub(super) async fn count_signal_rows(pool: &sqlx::PgPool, id: &str) -> Result<i64, String> {
        sqlx::query_scalar("SELECT count(*) FROM signals WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|e| format!("count rows: {e}"))
    }

    /// Delete this cell's rows (by its unique id) — runs on every exit path.
    pub(super) async fn cleanup_signal(pool: &sqlx::PgPool, id: &str) {
        let _ = sqlx::query("DELETE FROM signals WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }

    /// The primary-key constraint name as the LIVE catalog reports it, so a
    /// schema rename fails this cell instead of silently un-classifying the
    /// loser.
    pub(super) async fn signals_pk_name(pool: &sqlx::PgPool) -> Result<String, String> {
        let row = sqlx::query(
            "SELECT conname FROM pg_constraint \
             WHERE conrelid = 'signals'::regclass AND contype = 'p'",
        )
        .fetch_one(pool)
        .await
        .map_err(|e| format!("pk name: {e}"))?;
        row.try_get::<String, _>("conname")
            .map_err(|e| format!("pk name col: {e}"))
    }

    /// Run the race through the HTTP funnel; returns the loser's outcome.
    pub(super) async fn race_through_funnel(url: &str) -> Result<(u64, u64, u64), String> {
        let (router, pg, db) = pg_router(url).await?;
        let ns = format!("ns-4370p-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let sig = make_signal(&ns);
        let result = race_inner(&router, &pg, &db, &sig, &ns).await;
        cleanup_signal(pg.pool(), &sig.id).await;
        result
    }

    async fn race_inner(
        router: &axum::Router,
        pg: &Arc<ai_memory::store::postgres::PostgresStore>,
        db: &Db,
        sig: &Signal,
        ns: &str,
    ) -> Result<(u64, u64, u64), String> {
        ensure!(
            signals_pk_name(pg.pool()).await? == "signals_pkey",
            "the signals primary key is no longer named signals_pkey"
        );
        // Winner: a second connection holds the SAME id, UNCOMMITTED.
        let holder = ai_memory::store::postgres::PostgresStore::connect(&url().ok_or("no pg url")?)
            .await
            .map_err(|e| format!("holder connect: {e}"))?;
        let mut tx = holder
            .pool()
            .begin()
            .await
            .map_err(|e| format!("holder begin: {e}"))?;
        let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("holder pid: {e}"))?;
        insert_uncommitted(&mut tx, sig).await?;

        let push_router = router.clone();
        let push_sig = sig.clone();
        let mut task = AbortOnDrop(tokio::spawn(
            async move { push(&push_router, &push_sig).await },
        ));
        // The receive passed its probes (the holder's row is invisible) and is
        // now parked on the holder's uncommitted unique-index entry.
        wait_blocked_by(pg.pool(), holder_pid).await?;
        tx.commit()
            .await
            .map_err(|e| format!("holder commit: {e}"))?;

        let (status, body) = (&mut task.0)
            .await
            .map_err(|e| format!("push task: {e}"))??;
        ensure!(status == StatusCode::OK, "push status {status}: {body}");
        // The receive reached the INSERT-loses arm; the row exists exactly once.
        ensure!(
            count_signal_rows(pg.pool(), &sig.id).await? == 1,
            "exactly one stored row for the raced id"
        );
        // No net quota charge for the loser (the holder never charged).
        let charged = charged_bytes(db, ns).await?;
        ensure!(
            charged == 0,
            "#4370: the loser must leave no quota charge; charged={charged}"
        );
        Ok(outcome(&body))
    }

    /// A non-racing duplicate delivery of an already-stored signal.
    pub(super) async fn plain_duplicate_outcome(url: &str) -> Result<(u64, u64, u64), String> {
        let (router, pg, db) = pg_router(url).await?;
        let ns = format!("ns-4370d-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let sig = make_signal(&ns);
        let result = async {
            let (status, first) = push(&router, &sig).await?;
            ensure!(
                status == StatusCode::OK && outcome(&first) == (1, 0, 0),
                "pg first delivery must apply: {status} {first}"
            );
            let charged = charged_bytes(&db, &ns).await?;
            let (status, dup) = push(&router, &sig).await?;
            ensure!(status == StatusCode::OK, "pg duplicate status {status}");
            ensure!(
                charged_bytes(&db, &ns).await? == charged,
                "pg non-racing duplicate must not grow the charge"
            );
            Ok(outcome(&dup))
        }
        .await;
        cleanup_signal(pg.pool(), &sig.id).await;
        result
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_racing_duplicate_signal_loser_is_noop_4370() {
    let Some(url) = pg::url() else {
        eprintln!(
            "SKIP pg_racing_duplicate_signal_loser_is_noop_4370: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _p = Posture::set();
    let got = pg::race_through_funnel(&url).await;
    assert_eq!(
        got,
        Ok((0, 1, 0)),
        "#4370: the primary-key loser must report the converged no-op \
         (applied=0 noop=1 skipped=0), not skipped"
    );
}

/// Parity: sqlite duplicate == pg non-racing duplicate == pg racing loser.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_racing_loser_outcome_equals_sqlite_and_nonracing_4370() {
    let Some(url) = pg::url() else {
        eprintln!(
            "SKIP pg_racing_loser_outcome_equals_sqlite_and_nonracing_4370: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _p = Posture::set();
    let sqlite = sqlite_duplicate_outcome().await;
    let non_racing = pg::plain_duplicate_outcome(&url).await;
    let racing = pg::race_through_funnel(&url).await;
    assert!(sqlite.is_ok(), "sqlite reference: {sqlite:?}");
    assert_eq!(
        non_racing, sqlite,
        "#4370 parity: the non-racing pg duplicate must equal sqlite's"
    );
    assert_eq!(
        racing, sqlite,
        "#4370 parity: the pg racing-loser outcome must equal sqlite's duplicate outcome"
    );
}

// ---------------------------------------------------------------------
// Sibling: checkpoints[] on the same federation-receive surface. The lost
// INSERT race was meant to fall back to first-resolution-wins; its unique-
// violation classifier never matched, so the loser was a hard error.
// ---------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
async fn checkpoint_race(url: &str) -> Result<(), String> {
    use ai_memory::checkpoints::InboundResolutionOutcome;
    use ai_memory::models::{Checkpoint, CheckpointState, ConditionType};
    use ai_memory::store::MemoryStore as _;

    let pg = ai_memory::store::postgres::PostgresStore::connect(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let id = uuid::Uuid::new_v4().to_string();
    let incoming = Checkpoint {
        id: id.clone(),
        namespace: format!("ns-4370cp-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        title: "raced resolution (4370)".to_string(),
        condition_type: ConditionType::Approval,
        condition: Value::Null,
        state: CheckpointState::Resolved,
        created_by: PEER.to_string(),
        resolved_by: Some(PEER.to_string()),
        resolution: Some("approved".to_string()),
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: Some(1_700_000_900),
        metadata: Value::Null,
    };
    let mut ctx = ai_memory::store::CallerContext::for_agent(PEER);
    ctx.bypass_visibility = true;

    let holder = ai_memory::store::postgres::PostgresStore::connect(url)
        .await
        .map_err(|e| format!("holder connect: {e}"))?;
    let result = async {
        let mut tx = holder
            .pool()
            .begin()
            .await
            .map_err(|e| format!("holder begin: {e}"))?;
        let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("holder pid: {e}"))?;
        // The winner: the same resolved checkpoint, UNCOMMITTED.
        sqlx::query(
            "INSERT INTO checkpoints (id, namespace, title, condition_type, condition, state, \
             created_by, resolved_by, resolution, created_at, resolved_at, metadata) \
             VALUES ($1, $2, $3, 'approval', 'null', 'resolved', $4, $4, 'approved', $5, $6, 'null')",
        )
        .bind(&incoming.id)
        .bind(&incoming.namespace)
        .bind(&incoming.title)
        .bind(PEER)
        .bind(incoming.created_at)
        .bind(incoming.resolved_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("holder insert: {e}"))?;

        let apply_pg = pg.pool().clone();
        let apply_store = ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .map_err(|e| format!("apply connect: {e}"))?;
        let apply_incoming = incoming.clone();
        let apply_ctx = ctx.clone();
        let mut task = AbortOnDrop(tokio::spawn(async move {
            apply_store
                .apply_remote_checkpoint_resolution(&apply_ctx, &apply_incoming)
                .await
        }));
        pg::wait_blocked_by(&apply_pg, holder_pid).await?;
        tx.commit().await.map_err(|e| format!("holder commit: {e}"))?;
        let loser = (&mut task.0).await
            .map_err(|e| format!("apply task: {e}"))?
            .map_err(|e| format!("#4370: the checkpoint race loser must not be a hard error: {e}"))?;
        // Non-racing: the same incoming applied again, now that the row exists.
        let again = pg
            .apply_remote_checkpoint_resolution(&ctx, &incoming)
            .await
            .map_err(|e| format!("non-racing apply: {e}"))?;
        ensure!(
            loser == again && loser == InboundResolutionOutcome::Noop,
            "#4370: the racing checkpoint loser ({loser:?}) must equal the non-racing outcome ({again:?}) = Noop"
        );
        Ok(())
    }
    .await;
    let _ = sqlx::query("DELETE FROM checkpoints WHERE id = $1")
        .bind(&id)
        .execute(pg.pool())
        .await;
    result
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_racing_checkpoint_resolution_loser_converges_4370() {
    let Some(url) = pg::url() else {
        eprintln!(
            "SKIP pg_racing_checkpoint_resolution_loser_converges_4370: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _p = Posture::set();
    assert_eq!(checkpoint_race(&url).await, Ok(()));
}
