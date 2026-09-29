// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4024 — a federated action transition's operation identity (its signed
//! `nonce`) is recorded ATOMICALLY with the transition it authorizes, on both
//! receive backends (`handlers::federation_receive` for sqlite,
//! `handlers::federation_signing_check::sync_push_via_store` for postgres).
//!
//! Pre-fix both receivers recorded the nonce in the in-memory replay cache
//! BEFORE the compare-and-swap and counted a CAS miss as `noop`:
//!
//! - a transition delivered before its causal predecessor (`StateMismatch`)
//!   was acknowledged as a successful no-op AND burned its nonce, so the
//!   sender's retry was refused as a replay — the op was never applied and
//!   nothing would ever apply it;
//! - a transient CAS error burned the nonce the same way.
//!
//! The replay protection those nonces exist for (#1805, the cyclic-edge
//! replay of an APPLIED transition) must survive the fix: every cell below
//! that retries a never-applied op is paired with one that replays an applied
//! op and requires the refusal, including across a cyclic edge and across a
//! receiver restart (a fresh in-memory cache).
//!
//! Driven through the production `/api/v1/sync/push` route (`build_router`).
//! The postgres cells need `AI_MEMORY_TEST_POSTGRES_URL` and self-skip
//! without it.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::sync::ActionTransitionOp;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::models::{Action, ActionState};

/// Serializes every test that mutates the process-global federation env.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const PEER_HEADER: &str = "x-peer-id";

/// Sets (and on drop restores) the federation env a signed-transition push
/// needs: permissive OUTER envelope signing (the op itself stays signed and
/// verified against the actor's enrolled key), body-agent trust, the key dir
/// holding the actor's key, and a namespace-scope allowlist for the actor.
/// Every holder keeps `FED_ENV_LOCK` for the guard's whole lifetime.
struct FedEnv {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl FedEnv {
    fn new(actor: &str, namespace: &str, key_dir: &std::path::Path) -> Self {
        use ai_memory::federation::peer_attestation::{
            PEER_ATTESTATION_ENV, TRUST_BODY_AGENT_ID_ENV,
        };
        use ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV;
        use ai_memory::federation::signing::REQUIRE_SIG_ENV;
        use ai_memory::identity::keypair::KEY_DIR_ENV;
        let keys = [
            REQUIRE_SIG_ENV,
            TRUST_BODY_AGENT_ID_ENV,
            KEY_DIR_ENV,
            PEER_ATTESTATION_ENV,
            REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        ];
        let saved = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        let allowlist = json!({actor: {
            "allowed_sender_agent_ids": [actor],
            "allowed_namespaces": [namespace],
        }});
        // SAFETY: every caller holds FED_ENV_LOCK; Drop restores the variables
        // before that guard is released.
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "0");
            std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
            std::env::set_var(KEY_DIR_ENV, key_dir);
            std::env::set_var(PEER_ATTESTATION_ENV, allowlist.to_string());
            std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        }
        Self { saved }
    }
}

impl Drop for FedEnv {
    fn drop(&mut self) {
        for (key, previous) in &self.saved {
            // SAFETY: the enclosing test still holds FED_ENV_LOCK.
            unsafe {
                match previous {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// One enrolled actor: its keypair (public half saved into `key_dir`, which
/// the receiver resolves the enrolled key from) plus the env guard.
struct Actor {
    id: String,
    kp: AgentKeypair,
    _key_dir: tempfile::TempDir,
    _env: FedEnv,
}

fn enroll(id: &str, namespace: &str) -> Actor {
    let key_dir = tempfile::tempdir().expect("keydir");
    let kp = ai_memory::identity::keypair::generate(id).expect("keypair");
    ai_memory::identity::keypair::save(&kp, key_dir.path()).expect("save keypair");
    let env = FedEnv::new(id, namespace, key_dir.path());
    Actor {
        id: id.to_string(),
        kp,
        _key_dir: key_dir,
        _env: env,
    }
}

fn uniq(prefix: &str) -> String {
    format!(
        "{prefix}-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

fn pending_action(id: &str, namespace: &str, actor: &str) -> Action {
    Action {
        id: id.to_string(),
        namespace: namespace.to_string(),
        kind: "test".to_string(),
        state: ActionState::Pending,
        title: "tx".to_string(),
        payload: json!({}),
        priority: 5,
        agent_id: Some(actor.to_string()),
        claimed_by: None,
        vector_clock: json!({}),
        metadata: json!({}),
        created_at: 1_700_009_000,
        updated_at: 1_700_009_000,
    }
}

/// A production-shaped signed transition: `claimed_by` is the attesting
/// node (as `coordination::build_signed_transition_op` builds it) and the
/// signature binds action, namespace, edge, nonce and timestamp.
fn signed_op(
    actor: &Actor,
    action_id: &str,
    namespace: &str,
    from: ActionState,
    to: ActionState,
    nonce: &[u8],
    at: i64,
) -> ActionTransitionOp {
    let signable = ai_memory::identity::sign::SignableTransition {
        action_id,
        namespace,
        from_state: from.as_str(),
        to_state: to.as_str(),
        claimed_by: Some(&actor.id),
        nonce,
        created_at: at,
    };
    let signature =
        ai_memory::identity::sign::sign_transition(&actor.kp, &signable).expect("sign transition");
    ActionTransitionOp {
        action_id: action_id.to_string(),
        from_state: from,
        to_state: to,
        claimed_by: Some(actor.id.clone()),
        vector_clock: json!({}),
        updated_at: at,
        signature,
        signer_pubkey: actor.kp.public.to_bytes().to_vec(),
        nonce: nonce.to_vec(),
    }
}

/// POST one op in a FRESH outer envelope (a sender retry / a re-wrapped
/// capture) and return the receiver's report.
async fn push(router: &axum::Router, actor: &str, op: &ActionTransitionOp) -> Value {
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": actor,
        "sender_clock": {"entries": {}},
        "sender_wall_clock": chrono::Utc::now().to_rfc3339(),
        "memories": [],
        "action_transitions": [serde_json::to_value(op).expect("op json")],
    }))
    .expect("body");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(PEER_HEADER, actor)
        .body(Body::from(body))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .expect("body bytes");
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::OK, "push must answer 200; body={v}");
    v
}

fn count(v: &Value, key: &str) -> i64 {
    v[key].as_i64().unwrap_or(-1)
}

/// The report the SENDER reads as "applied": applied=1, nothing skipped.
fn assert_applied(v: &Value, why: &str) {
    assert_eq!(count(v, "action_transitions_applied"), 1, "{why}; body={v}");
    assert_eq!(count(v, "skipped"), 0, "{why}; body={v}");
}

/// The report the sender must NOT read as an ack: nothing applied, and the
/// non-apply is a `skipped` — the `skipped > 0` non-ack trigger of
/// `federation::sync::success_report_non_ack_reason` (#2341), which parks the
/// op for retry — never a `noop`, which the sender reads as a clean ack.
fn assert_not_acked(v: &Value, why: &str) {
    assert_eq!(count(v, "action_transitions_applied"), 0, "{why}; body={v}");
    assert!(count(v, "skipped") >= 1, "{why}: must be skipped; body={v}");
    assert_eq!(count(v, "noop"), 0, "{why}: must not be a noop; body={v}");
}

fn app_state(
    db: Db,
    store: Arc<dyn ai_memory::store::MemoryStore>,
    backend: StorageBackend,
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
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        // A FRESH in-memory cache per router: a second router over the same
        // database is a receiver restart.
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
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn router_for(state: AppState) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, state)
}

// ---------------------------------------------------------------------------
// sqlite receiver (`handlers::federation_receive::sync_push`)
// ---------------------------------------------------------------------------

/// A production router over the sqlite file at `path`. Each call is a fresh
/// receiver process as far as the replay state is concerned.
fn sqlite_router(path: &std::path::Path) -> axum::Router {
    let conn = ai_memory::db::open(path).expect("open sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let store = Arc::new(ai_memory::store::sqlite::SqliteStore::open(path).expect("SqliteStore"));
    router_for(app_state(db, store, StorageBackend::Sqlite))
}

fn sqlite_state(path: &std::path::Path, id: &str) -> ActionState {
    let conn = ai_memory::db::open(path).expect("verify conn");
    ai_memory::actions::get(&conn, id)
        .expect("get")
        .expect("action present")
        .state
}

struct SqliteFixture {
    _db: tempfile::NamedTempFile,
    path: std::path::PathBuf,
    router: axum::Router,
    ns: String,
    action_id: String,
}

fn sqlite_fixture(actor: &str, ns: &str) -> SqliteFixture {
    let db = tempfile::NamedTempFile::new().expect("db tempfile");
    let path = db.path().to_path_buf();
    let action_id = uniq("act-4024");
    {
        let conn = ai_memory::db::open(&path).expect("seed conn");
        ai_memory::actions::create(&conn, &pending_action(&action_id, ns, actor))
            .expect("seed action");
    }
    let router = sqlite_router(&path);
    SqliteFixture {
        _db: db,
        path,
        router,
        ns: ns.to_string(),
        action_id,
    }
}

/// (a)+(b) — a transition that arrives BEFORE its causal predecessor is not
/// acknowledged, does not burn its nonce, and applies when the sender retries
/// it after the predecessor lands.
#[tokio::test]
async fn sqlite_premature_transition_is_not_acked_and_retry_applies_4024() {
    let _g = FED_ENV_LOCK.lock().await;
    let ns = uniq("ns4024a");
    let actor = enroll("ai:fed4024-sqlite-a", &ns);
    let f = sqlite_fixture(&actor.id, &ns);
    let t1 = signed_op(
        &actor,
        &f.action_id,
        &f.ns,
        ActionState::Pending,
        ActionState::Claimed,
        b"4024-sq-a-t1",
        1_700_009_100,
    );
    let t2 = signed_op(
        &actor,
        &f.action_id,
        &f.ns,
        ActionState::Claimed,
        ActionState::InProgress,
        b"4024-sq-a-t2",
        1_700_009_200,
    );

    // T2 first: the action is still `pending`, so the CAS cannot apply.
    let r = push(&f.router, &actor.id, &t2).await;
    assert_not_acked(
        &r,
        "#4024: a causally premature transition must not be acked as a noop",
    );
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::Pending);

    // T1 lands.
    assert_applied(&push(&f.router, &actor.id, &t1).await, "T1 applies");
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::Claimed);

    // The sender's retry of T2 (fresh envelope, same signed op) applies: the
    // premature delivery did NOT consume its operation identity.
    let r = push(&f.router, &actor.id, &t2).await;
    assert_applied(
        &r,
        "#4024: the retry of a never-applied transition must apply",
    );
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::InProgress);

    // (c) — and now that T2 IS applied, a replay of it is refused (#1805).
    let r = push(&f.router, &actor.id, &t2).await;
    assert_not_acked(&r, "#1805: a replay of an applied transition is refused");
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::InProgress);
}

/// (a) — a transient CAS failure does not burn the nonce: the retry applies.
#[tokio::test]
async fn sqlite_transient_cas_error_does_not_burn_nonce_4024() {
    let _g = FED_ENV_LOCK.lock().await;
    let ns = uniq("ns4024b");
    let actor = enroll("ai:fed4024-sqlite-b", &ns);
    let f = sqlite_fixture(&actor.id, &ns);
    let t1 = signed_op(
        &actor,
        &f.action_id,
        &f.ns,
        ActionState::Pending,
        ActionState::Claimed,
        b"4024-sq-b-t1",
        1_700_009_100,
    );

    // Inject ONE substrate failure into the CAS write for this action only.
    let admin = ai_memory::db::open(&f.path).expect("admin conn");
    admin
        .execute_batch(&format!(
            "CREATE TRIGGER t4024_cas_fail BEFORE UPDATE ON actions \
             WHEN NEW.id = '{}' BEGIN SELECT RAISE(ABORT, 'injected transient CAS failure (#4024)'); END;",
            f.action_id
        ))
        .expect("install failing trigger");
    let r = push(&f.router, &actor.id, &t1).await;
    assert_not_acked(&r, "a CAS error is a refusal, not an ack");
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::Pending);

    admin
        .execute_batch("DROP TRIGGER t4024_cas_fail;")
        .expect("drop failing trigger");
    let r = push(&f.router, &actor.id, &t1).await;
    assert_applied(
        &r,
        "#4024: the retry after a transient CAS error must apply",
    );
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::Claimed);
}

/// (c) — #1805 holds across a cyclic edge AND a receiver restart: once T1
/// (`pending → claimed`) applied, a release returns the action to `pending`,
/// and the captured T1 re-wrapped in a fresh envelope is refused — by the
/// same receiver and by a restarted one with an empty in-memory cache.
#[tokio::test]
async fn sqlite_replay_across_cyclic_edge_and_restart_is_refused_4024() {
    let _g = FED_ENV_LOCK.lock().await;
    let ns = uniq("ns4024c");
    let actor = enroll("ai:fed4024-sqlite-c", &ns);
    let f = sqlite_fixture(&actor.id, &ns);
    let t1 = signed_op(
        &actor,
        &f.action_id,
        &f.ns,
        ActionState::Pending,
        ActionState::Claimed,
        b"4024-sq-c-t1",
        1_700_009_100,
    );
    let release = signed_op(
        &actor,
        &f.action_id,
        &f.ns,
        ActionState::Claimed,
        ActionState::Pending,
        b"4024-sq-c-rel",
        1_700_009_200,
    );

    assert_applied(&push(&f.router, &actor.id, &t1).await, "T1 applies");
    assert_applied(
        &push(&f.router, &actor.id, &release).await,
        "release applies",
    );
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::Pending);

    let r = push(&f.router, &actor.id, &t1).await;
    assert_not_acked(
        &r,
        "#1805: cyclic-edge replay of an applied transition is refused",
    );
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::Pending);

    // Receiver restart: a fresh router (fresh in-memory nonce cache) over the
    // same database still refuses — the operation identity is durable.
    let restarted = sqlite_router(&f.path);
    let r = push(&restarted, &actor.id, &t1).await;
    assert_not_acked(
        &r,
        "#4024: replay protection must survive a receiver restart",
    );
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::Pending);
}

/// Atomicity, the other direction: if recording the operation identity fails,
/// the transition must NOT be applied either (no applied-but-unrecorded op,
/// which would reopen #1805). Only meaningful once the identity is durable.
#[tokio::test]
async fn sqlite_identity_record_failure_rolls_back_the_transition_4024() {
    let _g = FED_ENV_LOCK.lock().await;
    let ns = uniq("ns4024d");
    let actor = enroll("ai:fed4024-sqlite-d", &ns);
    let f = sqlite_fixture(&actor.id, &ns);
    let t1 = signed_op(
        &actor,
        &f.action_id,
        &f.ns,
        ActionState::Pending,
        ActionState::Claimed,
        b"4024-sq-d-t1",
        1_700_009_100,
    );

    let admin = ai_memory::db::open(&f.path).expect("admin conn");
    admin
        .execute_batch(&format!(
            "CREATE TRIGGER t4024_nonce_fail BEFORE INSERT ON action_transition_nonces \
             WHEN NEW.action_id = '{}' BEGIN SELECT RAISE(ABORT, 'injected nonce-record failure (#4024)'); END;",
            f.action_id
        ))
        .expect("install failing nonce trigger");
    let r = push(&f.router, &actor.id, &t1).await;
    assert_not_acked(&r, "a failed identity record is a refusal");
    assert_eq!(
        sqlite_state(&f.path, &f.action_id),
        ActionState::Pending,
        "#4024: the CAS must roll back with the failed identity record"
    );

    admin
        .execute_batch("DROP TRIGGER t4024_nonce_fail;")
        .expect("drop failing nonce trigger");
    assert_applied(&push(&f.router, &actor.id, &t1).await, "the retry applies");
    assert_eq!(sqlite_state(&f.path, &f.action_id), ActionState::Claimed);
    let recorded: i64 = admin
        .query_row(
            "SELECT COUNT(*) FROM action_transition_nonces WHERE action_id = ?1",
            [&f.action_id],
            |r| r.get(0),
        )
        .expect("count identity rows");
    assert_eq!(
        recorded, 1,
        "exactly one durable identity row for one applied op"
    );
}

// ---------------------------------------------------------------------------
// postgres receiver (`handlers::federation_signing_check::sync_push_via_store`)
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::MemoryStore as _;
    use ai_memory::store::postgres::PostgresStore;

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    async fn pg_router(url: &str) -> axum::Router {
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
        let store: Arc<dyn ai_memory::store::MemoryStore> =
            Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
        router_for(app_state(db, store, StorageBackend::Postgres))
    }

    struct PgFixture {
        store: PostgresStore,
        ctx: ai_memory::store::CallerContext,
        router: axum::Router,
        url: String,
        ns: String,
        action_id: String,
    }

    async fn pg_fixture(url: &str, actor: &str, ns: &str) -> PgFixture {
        let store = PostgresStore::connect(url).await.expect("seed connect");
        let ctx = ai_memory::store::CallerContext::for_agent(actor.to_string());
        let action_id = uniq("pgact-4024");
        store
            .action_create(&ctx, &pending_action(&action_id, ns, actor))
            .await
            .expect("seed action");
        let router = pg_router(url).await;
        PgFixture {
            store,
            ctx,
            router,
            url: url.to_string(),
            ns: ns.to_string(),
            action_id,
        }
    }

    impl PgFixture {
        async fn state(&self) -> ActionState {
            self.store
                .action_get(&self.ctx, &self.action_id)
                .await
                .expect("get")
                .expect("present")
                .state
        }
    }

    #[tokio::test]
    async fn pg_premature_transition_is_not_acked_and_retry_applies_4024() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(url) = pg_url() else {
            eprintln!(
                "SKIP pg_premature_transition_is_not_acked_and_retry_applies_4024: env unset"
            );
            return;
        };
        let ns = uniq("pgns4024a");
        let actor = enroll(&uniq("ai:fed4024-pg-a"), &ns);
        let f = pg_fixture(&url, &actor.id, &ns).await;
        let t1 = signed_op(
            &actor,
            &f.action_id,
            &f.ns,
            ActionState::Pending,
            ActionState::Claimed,
            b"4024-pg-a-t1",
            1_700_009_100,
        );
        let t2 = signed_op(
            &actor,
            &f.action_id,
            &f.ns,
            ActionState::Claimed,
            ActionState::InProgress,
            b"4024-pg-a-t2",
            1_700_009_200,
        );

        let r = push(&f.router, &actor.id, &t2).await;
        assert_eq!(r["storage_backend"], "postgres", "body={r}");
        assert_not_acked(
            &r,
            "#4024 (pg): a causally premature transition must not be acked as a noop",
        );
        assert_eq!(f.state().await, ActionState::Pending);

        assert_applied(&push(&f.router, &actor.id, &t1).await, "T1 applies (pg)");
        assert_eq!(f.state().await, ActionState::Claimed);

        let r = push(&f.router, &actor.id, &t2).await;
        assert_applied(
            &r,
            "#4024 (pg): the retry of a never-applied transition must apply",
        );
        assert_eq!(f.state().await, ActionState::InProgress);

        let r = push(&f.router, &actor.id, &t2).await;
        assert_not_acked(
            &r,
            "#1805 (pg): a replay of an applied transition is refused",
        );
        assert_eq!(f.state().await, ActionState::InProgress);
    }

    #[tokio::test]
    async fn pg_transient_cas_error_does_not_burn_nonce_4024() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(url) = pg_url() else {
            eprintln!("SKIP pg_transient_cas_error_does_not_burn_nonce_4024: env unset");
            return;
        };
        let ns = uniq("pgns4024b");
        let actor = enroll(&uniq("ai:fed4024-pg-b"), &ns);
        let f = pg_fixture(&url, &actor.id, &ns).await;
        let t1 = signed_op(
            &actor,
            &f.action_id,
            &f.ns,
            ActionState::Pending,
            ActionState::Claimed,
            b"4024-pg-b-t1",
            1_700_009_100,
        );

        // One injected substrate failure on the CAS write, scoped to THIS
        // action so concurrent suites on the shared database are unaffected.
        let tag = f.action_id.replace('-', "_");
        let func = format!("t4024_cas_fail_{tag}");
        sqlx::raw_sql(&format!(
            "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.id = '{id}' THEN RAISE EXCEPTION 'injected transient CAS failure (#4024)'; END IF; RETURN NEW; END $$; \
             CREATE TRIGGER {func} BEFORE UPDATE ON actions FOR EACH ROW EXECUTE FUNCTION {func}();",
            id = f.action_id
        ))
        .execute(f.store.pool())
        .await
        .expect("install failing trigger");
        let r = push(&f.router, &actor.id, &t1).await;
        sqlx::raw_sql(&format!(
            "DROP TRIGGER {func} ON actions; DROP FUNCTION {func}();"
        ))
        .execute(f.store.pool())
        .await
        .expect("drop failing trigger");
        assert_not_acked(&r, "a CAS error is a refusal, not an ack (pg)");
        assert_eq!(f.state().await, ActionState::Pending);

        let r = push(&f.router, &actor.id, &t1).await;
        assert_applied(
            &r,
            "#4024 (pg): the retry after a transient CAS error must apply",
        );
        assert_eq!(f.state().await, ActionState::Claimed);
    }

    #[tokio::test]
    async fn pg_replay_across_cyclic_edge_and_restart_is_refused_4024() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(url) = pg_url() else {
            eprintln!("SKIP pg_replay_across_cyclic_edge_and_restart_is_refused_4024: env unset");
            return;
        };
        let ns = uniq("pgns4024c");
        let actor = enroll(&uniq("ai:fed4024-pg-c"), &ns);
        let f = pg_fixture(&url, &actor.id, &ns).await;
        let t1 = signed_op(
            &actor,
            &f.action_id,
            &f.ns,
            ActionState::Pending,
            ActionState::Claimed,
            b"4024-pg-c-t1",
            1_700_009_100,
        );
        let release = signed_op(
            &actor,
            &f.action_id,
            &f.ns,
            ActionState::Claimed,
            ActionState::Pending,
            b"4024-pg-c-rel",
            1_700_009_200,
        );

        assert_applied(&push(&f.router, &actor.id, &t1).await, "T1 applies (pg)");
        assert_applied(
            &push(&f.router, &actor.id, &release).await,
            "release applies (pg)",
        );
        assert_eq!(f.state().await, ActionState::Pending);

        let r = push(&f.router, &actor.id, &t1).await;
        assert_not_acked(
            &r,
            "#1805 (pg): cyclic-edge replay of an applied transition is refused",
        );
        assert_eq!(f.state().await, ActionState::Pending);

        let restarted = pg_router(&f.url).await;
        let r = push(&restarted, &actor.id, &t1).await;
        assert_not_acked(
            &r,
            "#4024 (pg): replay protection must survive a receiver restart",
        );
        assert_eq!(f.state().await, ActionState::Pending);
    }

    /// Concurrency: N concurrent deliveries of the SAME signed op (each in a
    /// fresh envelope, through independent routers = independent receivers
    /// sharing one database) apply it exactly once; every other delivery is
    /// refused, never double-applied and never acked as a noop.
    #[tokio::test]
    async fn pg_concurrent_duplicate_deliveries_apply_exactly_once_4024() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(url) = pg_url() else {
            eprintln!("SKIP pg_concurrent_duplicate_deliveries_apply_exactly_once_4024: env unset");
            return;
        };
        let ns = uniq("pgns4024e");
        let actor = enroll(&uniq("ai:fed4024-pg-e"), &ns);
        let f = pg_fixture(&url, &actor.id, &ns).await;
        let t1 = signed_op(
            &actor,
            &f.action_id,
            &f.ns,
            ActionState::Pending,
            ActionState::Claimed,
            b"4024-pg-e-t1",
            1_700_009_100,
        );
        let release = signed_op(
            &actor,
            &f.action_id,
            &f.ns,
            ActionState::Claimed,
            ActionState::Pending,
            b"4024-pg-e-rel",
            1_700_009_200,
        );
        assert_applied(&push(&f.router, &actor.id, &t1).await, "T1 applies (pg)");

        // The action is `claimed`; the release is legal. Race 8 deliveries
        // of the release, then 8 replays of T1 (which the release re-enables
        // on the cyclic edge).
        let mut routers = Vec::new();
        for _ in 0..8 {
            routers.push(pg_router(&f.url).await);
        }
        for (op, label) in [(&release, "release"), (&t1, "T1 replay")] {
            let mut tasks = Vec::new();
            for r in &routers {
                let r = r.clone();
                let op = op.clone();
                let id = actor.id.clone();
                tasks.push(tokio::spawn(async move { push(&r, &id, &op).await }));
            }
            let mut applied = 0;
            for t in tasks {
                let v = t.await.expect("join");
                assert_eq!(count(&v, "noop"), 0, "{label}: never a noop; body={v}");
                applied += count(&v, "action_transitions_applied");
            }
            let want = i64::from(label == "release");
            assert_eq!(applied, want, "{label}: applied exactly {want} time(s)");
        }
        assert_eq!(
            f.state().await,
            ActionState::Pending,
            "release applied once; the T1 replays never re-claimed"
        );
    }

    #[tokio::test]
    async fn pg_identity_record_failure_rolls_back_the_transition_4024() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(url) = pg_url() else {
            eprintln!("SKIP pg_identity_record_failure_rolls_back_the_transition_4024: env unset");
            return;
        };
        let ns = uniq("pgns4024d");
        let actor = enroll(&uniq("ai:fed4024-pg-d"), &ns);
        let f = pg_fixture(&url, &actor.id, &ns).await;
        let t1 = signed_op(
            &actor,
            &f.action_id,
            &f.ns,
            ActionState::Pending,
            ActionState::Claimed,
            b"4024-pg-d-t1",
            1_700_009_100,
        );

        let tag = f.action_id.replace('-', "_");
        let func = format!("t4024_nonce_fail_{tag}");
        sqlx::raw_sql(&format!(
            "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.action_id = '{id}' THEN RAISE EXCEPTION 'injected nonce-record failure (#4024)'; END IF; RETURN NEW; END $$; \
             CREATE TRIGGER {func} BEFORE INSERT ON action_transition_nonces FOR EACH ROW EXECUTE FUNCTION {func}();",
            id = f.action_id
        ))
        .execute(f.store.pool())
        .await
        .expect("install failing nonce trigger");
        let r = push(&f.router, &actor.id, &t1).await;
        sqlx::raw_sql(&format!(
            "DROP TRIGGER {func} ON action_transition_nonces; DROP FUNCTION {func}();"
        ))
        .execute(f.store.pool())
        .await
        .expect("drop failing nonce trigger");
        assert_not_acked(&r, "a failed identity record is a refusal (pg)");
        assert_eq!(
            f.state().await,
            ActionState::Pending,
            "#4024 (pg): the CAS must roll back with the failed identity record"
        );

        assert_applied(
            &push(&f.router, &actor.id, &t1).await,
            "the retry applies (pg)",
        );
        assert_eq!(f.state().await, ActionState::Claimed);
        let recorded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM action_transition_nonces WHERE action_id = $1",
        )
        .bind(&f.action_id)
        .fetch_one(f.store.pool())
        .await
        .expect("count identity rows");
        assert_eq!(
            recorded, 1,
            "exactly one durable identity row for one applied op"
        );
    }
}
