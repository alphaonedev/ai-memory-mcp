// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3986 — a LOCAL lease-read ERROR must refuse an inbound federated action
//! transition, never read as "no lease holder".
//!
//! Both `/sync/push` transition funnels read the local lease with
//! `lease_get(..).ok().flatten()`, so a storage error became `None` and
//! `receive_auth::authorize_remote_transition` skipped its lease-holder
//! conflict check — fail OPEN: a validly signed transition by agent B applied
//! over a live lease held by agent A whenever this node could not read that
//! lease.
//!
//! Each cell seeds action `A` with a LIVE lease held by `ai:holder-a-3986` and
//! makes that lease UNREADABLE, then pushes B's signed `pending -> claimed`:
//! * sqlite — the lease row's `expires_at` is corrupted to TEXT, so the row
//!   mapper errors (only that action's read fails); a lease-free action `B` in
//!   the SAME push is the control and still applies;
//! * postgres (ignored tier, `AI_MEMORY_TEST_POSTGRES_URL`) — the `leases`
//!   table is renamed away for the push, then restored for a control push that
//!   applies a lease-free action.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
#[cfg(feature = "sal-postgres")]
use ai_memory::store::CallerContext;
use ai_memory::store::MemoryStore;

static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Zero-config receive posture (the #2863 DO-mesh shape): envelope gates
/// relaxed so the per-write attestation lane is reached; the #1948 route-IN
/// knob OFF so the only lifecycle actor under test is route-OUT. Restored on
/// Drop (also on panic).
struct Posture(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl Posture {
    fn zero_config() -> Self {
        use ai_memory::federation::peer_attestation::{
            PEER_ATTESTATION_ENV, TRUST_BODY_AGENT_ID_ENV,
        };
        use ai_memory::federation::receive_auth::{
            FED_QUARANTINE_UNATTRIBUTED_ENV, REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        };
        use ai_memory::federation::signing::REQUIRE_SIG_ENV;
        let set: [(&'static str, Option<&str>); 8] = [
            (REQUIRE_PUSH_NAMESPACE_SCOPE_ENV, Some("0")),
            (PEER_ATTESTATION_ENV, None),
            (TRUST_BODY_AGENT_ID_ENV, None),
            ("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", Some("0")),
            (REQUIRE_SIG_ENV, Some("0")),
            ("AI_MEMORY_FED_REQUIRE_NONCE", Some("0")),
            ("AI_MEMORY_FED_REQUIRE_WRITE_SIG", None),
            (FED_QUARANTINE_UNATTRIBUTED_ENV, None),
        ];
        let guard = Self(set.iter().map(|(k, _)| (*k, std::env::var_os(k))).collect());
        for (key, value) in set {
            // SAFETY: every caller holds FED_ENV_LOCK; Drop restores before release.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
        guard
    }
}

impl Drop for Posture {
    fn drop(&mut self) {
        for (key, previous) in &self.0 {
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

enum Backend {
    Sqlite,
    #[cfg(feature = "sal-postgres")]
    Postgres(String),
}

/// A production router over the chosen backend, the SAL handle, and the
/// sqlite connection the sqlite funnel writes through.
#[allow(clippy::unused_async)] // the pg arm awaits; the sqlite arm does not
async fn router(backend: &Backend) -> (axum::Router, Arc<dyn MemoryStore>, Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let (store, storage_backend): (Arc<dyn MemoryStore>, StorageBackend) = match backend {
        Backend::Sqlite => {
            let tmp = tempfile::NamedTempFile::new().expect("tempfile");
            let p = tmp.path().to_path_buf();
            std::mem::forget(tmp);
            (
                Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store")),
                StorageBackend::Sqlite,
            )
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(url) => (
            Arc::new(
                ai_memory::store::postgres::PostgresStore::connect(url)
                    .await
                    .expect("connect postgres"),
            ),
            StorageBackend::Postgres,
        ),
    };
    let app_state = AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend,
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
        ..Default::default()
    };
    (ai_memory::build_router(api_key_state, app_state), store, db)
}

#[cfg(feature = "sal-postgres")]
fn pg_store(store: &Arc<dyn MemoryStore>) -> &ai_memory::store::postgres::PostgresStore {
    store
        .as_any()
        .downcast_ref::<ai_memory::store::postgres::PostgresStore>()
        .expect("postgres store")
}

const HOLDER_A: &str = "ai:holder-a-3986";

/// Points the enrolled-key lookup at a hermetic key dir holding `kp`'s public
/// key; restores the previous value on Drop.
struct KeyDir {
    _dir: tempfile::TempDir,
    previous: Option<std::ffi::OsString>,
}

impl KeyDir {
    fn with(kp: &ai_memory::identity::keypair::AgentKeypair) -> Self {
        let dir = tempfile::tempdir().expect("keydir");
        ai_memory::identity::keypair::save(kp, dir.path()).expect("save key");
        let previous = std::env::var_os(ai_memory::identity::keypair::KEY_DIR_ENV);
        // SAFETY: every caller holds FED_ENV_LOCK; Drop restores before release.
        unsafe { std::env::set_var(ai_memory::identity::keypair::KEY_DIR_ENV, dir.path()) };
        Self {
            _dir: dir,
            previous,
        }
    }
}

impl Drop for KeyDir {
    fn drop(&mut self) {
        // SAFETY: the enclosing test still holds FED_ENV_LOCK.
        unsafe {
            match &self.previous {
                Some(v) => std::env::set_var(ai_memory::identity::keypair::KEY_DIR_ENV, v),
                None => std::env::remove_var(ai_memory::identity::keypair::KEY_DIR_ENV),
            }
        }
    }
}

fn action(id: &str, ns: &str, owner: &str) -> ai_memory::models::Action {
    ai_memory::models::Action {
        id: id.to_string(),
        namespace: ns.to_string(),
        kind: "test".to_string(),
        state: ai_memory::models::ActionState::Pending,
        title: "lease 3986".to_string(),
        payload: json!({}),
        priority: 5,
        agent_id: Some(owner.to_string()),
        claimed_by: None,
        vector_clock: json!({}),
        metadata: json!({}),
        created_at: 1_700_009_000,
        updated_at: 1_700_009_000,
    }
}

/// B's signed `pending -> claimed` op on `id`.
fn signed_claim(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    actor: &str,
    id: &str,
    ns: &str,
) -> Value {
    let nonce = uuid::Uuid::new_v4().as_bytes().to_vec();
    let signable = ai_memory::identity::sign::SignableTransition {
        action_id: id,
        namespace: ns,
        from_state: "pending",
        to_state: "claimed",
        claimed_by: Some(actor),
        nonce: &nonce,
        created_at: 1_700_009_100,
    };
    let signature = ai_memory::identity::sign::sign_transition(kp, &signable).expect("sign");
    serde_json::to_value(ai_memory::federation::sync::ActionTransitionOp {
        action_id: id.to_string(),
        from_state: ai_memory::models::ActionState::Pending,
        to_state: ai_memory::models::ActionState::Claimed,
        claimed_by: Some(actor.to_string()),
        vector_clock: json!({}),
        updated_at: 1_700_009_100,
        signature,
        signer_pubkey: kp.public.to_bytes().to_vec(),
        nonce,
    })
    .expect("op json")
}

async fn push(router: &axum::Router, sender: &str, ops: Vec<Value>) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": sender,
        "sender_clock": {"entries": {}},
        "sender_wall_clock": chrono::Utc::now().to_rfc3339(),
        "memories": [],
        "action_transitions": ops,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            sender,
        )
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn applied(report: &Value) -> i64 {
    report["action_transitions_applied"].as_i64().unwrap_or(-1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_unreadable_lease_refuses_transition_3986() {
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = Posture::zero_config();
    let actor = uniq("ai:actor-b-3986");
    let kp = ai_memory::identity::keypair::generate(&actor).expect("kp");
    let _keys = KeyDir::with(&kp);
    let ns = uniq("team/l3986");
    let (a, b) = (uniq("act-a"), uniq("act-b"));
    let backend = Backend::Sqlite;
    let (router, _store, db) = router(&backend).await;
    {
        let lock = db.lock().await;
        ai_memory::actions::create(&lock.0, &action(&a, &ns, &actor)).expect("seed a");
        ai_memory::actions::create(&lock.0, &action(&b, &ns, &actor)).expect("seed b");
        // A LIVE lease held by A whose row the mapper cannot read: the
        // `expires_at` INTEGER column holds TEXT (non-STRICT table).
        lock.0
            .execute(
                "INSERT INTO leases (action_id, holder, acquired_at, expires_at, heartbeat_at) \
                 VALUES (?1, ?2, 0, 'unreadable-3986', 0)",
                rusqlite::params![a, HOLDER_A],
            )
            .expect("seed corrupt lease");
        assert!(
            ai_memory::actions::lease_get(&lock.0, &a).is_err(),
            "precondition: the lease read on A must ERROR"
        );
    }

    let (status, report) = push(
        &router,
        &actor,
        vec![
            signed_claim(&kp, &actor, &a, &ns),
            signed_claim(&kp, &actor, &b, &ns),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(
        applied(&report),
        1,
        "only the lease-free control applies; the unreadable-lease op is refused: {report}"
    );
    let lock = db.lock().await;
    let a_state = ai_memory::actions::get(&lock.0, &a).unwrap().unwrap().state;
    let b_state = ai_memory::actions::get(&lock.0, &b).unwrap().unwrap().state;
    assert_eq!(
        a_state,
        ai_memory::models::ActionState::Pending,
        "#3986: a lease-read error must not read as \"no lease\" — A's lease holder is not B"
    );
    assert_eq!(
        b_state,
        ai_memory::models::ActionState::Claimed,
        "CONTROL: a lease-free action still transitions in the same push"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        Backend, CallerContext, FED_ENV_LOCK, HOLDER_A, KeyDir, Posture, StatusCode, action,
        applied, pg_store, push, router, signed_claim, uniq,
    };

    /// Renames `leases` away so every lease read ERRORS; restores it on Drop
    /// (also on panic) so a failing cell cannot poison the database.
    struct LeasesOffline(sqlx::PgPool);

    impl LeasesOffline {
        async fn take(pool: &sqlx::PgPool) -> Self {
            sqlx::query("ALTER TABLE leases RENAME TO leases_offline_3986")
                .execute(pool)
                .await
                .expect("take leases offline");
            Self(pool.clone())
        }

        async fn restore(self) {
            sqlx::query("ALTER TABLE leases_offline_3986 RENAME TO leases")
                .execute(&self.0)
                .await
                .expect("restore leases");
            std::mem::forget(self);
        }
    }

    impl Drop for LeasesOffline {
        fn drop(&mut self) {
            let pool = self.0.clone();
            // Best effort on the panic path; the happy path uses `restore`.
            let _ = std::thread::spawn(move || {
                tokio::runtime::Runtime::new().map(|rt| {
                    rt.block_on(
                        sqlx::query("ALTER TABLE leases_offline_3986 RENAME TO leases")
                            .execute(&pool),
                    )
                })
            })
            .join();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_unreadable_lease_refuses_transition_3986() {
        let _g = FED_ENV_LOCK.lock().await;
        let _posture = Posture::zero_config();
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .expect("own PG URL required (AI_MEMORY_TEST_POSTGRES_URL); no soft skip");
        let actor = uniq("ai:actor-b-3986");
        let kp = ai_memory::identity::keypair::generate(&actor).expect("kp");
        let _keys = KeyDir::with(&kp);
        let ns = uniq("team/l3986");
        let (a, b) = (uniq("act-a"), uniq("act-b"));
        let backend = Backend::Postgres(url);
        let (router, store, _db) = router(&backend).await;
        let ctx = CallerContext::for_agent(actor.clone());
        store
            .action_create(&ctx, &action(&a, &ns, &actor))
            .await
            .expect("seed a");
        store
            .action_create(&ctx, &action(&b, &ns, &actor))
            .await
            .expect("seed b");
        let pool = pg_store(&store).pool().clone();
        let far_future = chrono::Utc::now().timestamp() + 86_400;
        sqlx::query(
            "INSERT INTO leases (action_id, holder, acquired_at, expires_at, heartbeat_at) \
             VALUES ($1, $2, 0, $3, 0)",
        )
        .bind(&a)
        .bind(HOLDER_A)
        .bind(far_future)
        .execute(&pool)
        .await
        .expect("seed live lease held by A");

        let offline = LeasesOffline::take(&pool).await;
        assert!(
            store.lease_get(&ctx, &a).await.is_err(),
            "precondition: the lease read on A must ERROR"
        );
        let (status, report) =
            push(&router, &actor, vec![signed_claim(&kp, &actor, &a, &ns)]).await;
        offline.restore().await;
        assert_eq!(status, StatusCode::OK, "{report}");
        assert_eq!(
            applied(&report),
            0,
            "#3986: the unreadable-lease op must be refused: {report}"
        );
        assert_eq!(
            store.action_get(&ctx, &a).await.unwrap().unwrap().state,
            ai_memory::models::ActionState::Pending,
            "#3986: a lease-read error must not read as \"no lease\" — A's lease holder is not B"
        );

        // CONTROL: with the lease table readable again, a lease-free action
        // transitions — the refusal above was the lease read, not the push.
        let (status, report) =
            push(&router, &actor, vec![signed_claim(&kp, &actor, &b, &ns)]).await;
        assert_eq!(status, StatusCode::OK, "{report}");
        assert_eq!(applied(&report), 1, "control applies: {report}");
        assert_eq!(
            store.action_get(&ctx, &b).await.unwrap().unwrap().state,
            ai_memory::models::ActionState::Claimed
        );
    }
}
