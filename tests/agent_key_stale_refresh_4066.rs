// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4066 — a registry load whose store read began BEFORE a revoke, a
//! rotation or a newer load must never publish its (stale) result AFTER that
//! newer state was published.
//!
//! The enrolled-key registry is published by whole-map replacement. Before
//! #4066 nothing ordered a load's READ against its PUBLICATION: the
//! background refresh (or a concurrent handler re-read) could capture the key
//! set, lose the race to an admin revoke that reported
//! `"effective": "immediately"`, and then install the captured set —
//! re-arming the revoked credential until the next refresh. The handler's own
//! clone → modify → install transform was likewise a non-atomic
//! read-modify-write against concurrent installers, and two loads were not
//! ordered against each other at all.
//!
//! What this binary pins, without sleeps that decide an outcome:
//!
//! * the REAL refresh funnel (`identity_binding::refresh_agent_keys`, the one
//!   the daemon loop and the admin handlers use) is barriered between its
//!   store read and its publication while the PRODUCTION routes revoke,
//!   rotate, or a newer load publishes; the stale load is released and must
//!   not re-arm anything. Each cell runs on the sqlite adapter and on the
//!   postgres adapter;
//! * a revoked key is refused with the transport's exact 401 body;
//! * a refresh whose read FAILS keeps the revoke's narrowed map (fail-closed:
//!   no revoked key comes back);
//! * two concurrent registry transforms both land (neither undoes the other);
//! * a load overtaken by a mutation, or by a NEWER load, reports
//!   `Superseded` and changes nothing; a bind ticket older than a revoke does
//!   not re-arm.

// Allows sit BEFORE the `#![cfg]` so they still apply on a leg where the cfg
// empties the crate but the `//!` docs above are still linted.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(feature = "sal")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::agent_api_key::mark_credential_transport_confidential;
use ai_memory::handlers::identity_binding::{
    AgentKeyRefresh, EnrolledAgentKeys, api_key_sha256_hex, refresh_agent_keys,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::AgentRegistration;
use ai_memory::store::{CallerContext, MemoryStore};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const SHARED_KEY: &str = "4066-shared-transport-key";
const HMAC_SECRET: &str = "4066-approval-hmac-secret";
/// The transport's refusal body for a key it does not recognise
/// (`transport::record_auth_failure`). A revoked key must get exactly this.
const INVALID_KEY_ERROR: &str = "missing or invalid API key";
/// A route that needs only TRANSPORT authentication.
const PROBE_URI: &str = "/api/v1/capabilities";
/// Response bodies here are small JSON envelopes; the cap only bounds a
/// misbehaving route.
const BODY_LIMIT: usize = 1 << 20;
/// Upper bound on how long a barriered transform waits for its peer to enter.
/// Atomic transforms serialise, so the peer never can; the bound only caps the
/// test's duration and never decides the outcome.
const PEER_ENTRY_WAIT: std::time::Duration = std::time::Duration::from_millis(300);

/// The tests here flip PROCESS-GLOBAL markers (admin authn, credential
/// transport, approval HMAC secret), so they run one at a time. Async-aware
/// because the critical section spans `.await` points (CONCURRENCY-20).
async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
    LOCK.lock().await
}

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_PG_URL").ok())
        .filter(|u| !u.trim().is_empty())
}

/// Per-run identities and tokens. Generated here (never a fixed secret) and
/// unique per run, so a shared postgres cluster cannot leak one run's keys into
/// another's assertions.
struct Cast {
    admin: String,
    second_admin: String,
    other: String,
    admin_token: String,
    second_admin_token: String,
}

impl Cast {
    fn new(backend: &str) -> Self {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        Self {
            admin: format!("ai:k4066-admin-{backend}-{suffix}"),
            second_admin: format!("ai:k4066-admin2-{backend}-{suffix}"),
            other: format!("ai:k4066-other-{backend}-{suffix}"),
            admin_token: format!("k4066-admin-token-{suffix}"),
            second_admin_token: format!("k4066-admin2-token-{suffix}"),
        }
    }

    fn admins(&self) -> [&str; 2] {
        [self.admin.as_str(), self.second_admin.as_str()]
    }

    fn agents(&self) -> [&str; 3] {
        [
            self.admin.as_str(),
            self.second_admin.as_str(),
            self.other.as_str(),
        ]
    }
}

struct Fixture {
    router: axum::Router,
    store: Arc<dyn MemoryStore>,
    registry: Arc<EnrolledAgentKeys>,
    cast: Cast,
    _dir: Option<tempfile::TempDir>,
}

fn app_state(
    db: Db,
    backend: StorageBackend,
    store: Arc<dyn MemoryStore>,
    registry: Arc<EnrolledAgentKeys>,
    admins: &[&str],
) -> AppState {
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::full()),
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
        admin_agent_ids: Arc::new(admins.iter().map(|a| (*a).to_string()).collect()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: registry,
        http_identity_mode: HttpIdentityMode::Advisory,
    }
}

/// Wire the production router so `AppState` and `ApiKeyState` share ONE live
/// registry `Arc`, exactly as `bootstrap_serve` does.
fn router_over(app: AppState, registry: &Arc<EnrolledAgentKeys>) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    mark_credential_transport_confidential(true);
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: Arc::clone(registry),
        identity_mode: HttpIdentityMode::Advisory,
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app)
}

fn daemon_ctx() -> CallerContext {
    CallerContext::for_admin(ai_memory::identity::sentinels::DAEMON_PRINCIPAL)
}

async fn register(store: &Arc<dyn MemoryStore>, agent_id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    store
        .register_agent(
            &daemon_ctx(),
            &AgentRegistration {
                agent_id: agent_id.to_string(),
                agent_type: "human".to_string(),
                capabilities: Vec::new(),
                registered_at: now.clone(),
                last_seen_at: now,
            },
        )
        .await
        .expect("register_agent");
}

/// #8535 — mint and revoke need a KEY-BOUND admin, so both admins enrol their
/// own key in the store before the registry is seeded from it (the boot
/// shape: `from_map` over the store's rows).
async fn seed_admin_keys(store: &Arc<dyn MemoryStore>, cast: &Cast) -> Arc<EnrolledAgentKeys> {
    for (agent, token) in [
        (&cast.admin, &cast.admin_token),
        (&cast.second_admin, &cast.second_admin_token),
    ] {
        let _outcome = store
            .bind_agent_api_key(&daemon_ctx(), agent, &api_key_sha256_hex(token))
            .await
            .expect("seed admin key");
    }
    let seed: HashMap<String, String> = store
        .list_agent_api_keys()
        .await
        .expect("seed registry")
        .into_iter()
        .collect();
    Arc::new(EnrolledAgentKeys::from_map(seed))
}

async fn sqlite_fixture() -> Fixture {
    let cast = Cast::new("sqlite");
    let root = PathBuf::from(".local-runs").join("agent-key-stale-refresh-4066");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix("sqlite")
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let db_path = dir.path().join("m.db");
    {
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        for a in cast.agents() {
            ai_memory::db::register_agent(&conn, a, "human", &[]).expect("register agent");
        }
    }
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let registry = seed_admin_keys(&store, &cast).await;
    let app = app_state(
        db,
        StorageBackend::Sqlite,
        Arc::clone(&store),
        Arc::clone(&registry),
        &cast.admins(),
    );
    Fixture {
        router: router_over(app, &registry),
        store,
        registry,
        cast,
        _dir: Some(dir),
    }
}

#[cfg(feature = "sal-postgres")]
async fn postgres_fixture(url: &str) -> Fixture {
    let cast = Cast::new("pg");
    let pg = ai_memory::store::postgres::PostgresStore::connect(url)
        .await
        .expect("PostgresStore::connect (the certified tier must be exercised, not skipped)");
    let store: Arc<dyn MemoryStore> = Arc::new(pg);
    for a in cast.agents() {
        register(&store, a).await;
    }
    // `app.db` is a deliberately EMPTY scratch sqlite: a handler that read it
    // instead of `app.store` would see no keys and fail the test loudly.
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        scratch,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    // Seeded from the store, so keys other runs left in the cluster are
    // accounted for (the last-key rule counts the WHOLE registry).
    let registry = seed_admin_keys(&store, &cast).await;
    let app = app_state(
        db,
        StorageBackend::Postgres,
        Arc::clone(&store),
        Arc::clone(&registry),
        &cast.admins(),
    );
    Fixture {
        router: router_over(app, &registry),
        store,
        registry,
        cast,
        _dir: None,
    }
}

async fn call(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), BODY_LIMIT).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn post(uri: &str, api_key: &str, caller: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(ai_memory::HEADER_API_KEY, api_key)
        .header(ai_memory::HEADER_AGENT_ID, caller)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("serialise")))
        .expect("build request")
}

/// Mint a server-generated key for `target`, as the key-bound admin `caller`.
async fn mint(router: &axum::Router, api_key: &str, caller: &str, target: &str) -> String {
    let (status, body) = call(
        router,
        post(
            &format!("/api/v1/agents/{target}/api-key"),
            api_key,
            caller,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint for {target}: {body}");
    body["token"].as_str().expect("minted token").to_string()
}

/// Self-revoke through the production route; the answer must be immediate.
async fn self_revoke(router: &axum::Router, api_key: &str, agent: &str) {
    let (status, body) = call(
        router,
        post(
            &format!("/api/v1/agents/{agent}/api-key/revoke"),
            api_key,
            agent,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "self-revoke is immediate: {body}");
    assert_eq!(body["revoked"], true, "{body}");
    assert_eq!(body["effective"], "immediately", "{body}");
}

/// A fresh request that needs only TRANSPORT authentication.
async fn probe(router: &axum::Router, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(PROBE_URI)
        .header(ai_memory::HEADER_API_KEY, token)
        .body(Body::empty())
        .expect("probe");
    let (status, body) = call(router, req).await;
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "probe must not error: {body}"
    );
    (status, body)
}

async fn assert_authenticates(router: &axum::Router, token: &str, what: &str) {
    let (status, body) = probe(router, token).await;
    assert_eq!(status, StatusCode::OK, "{what}: {body}");
}

/// A revoked key is refused with the transport's EXACT refusal, not merely
/// "some failure".
async fn assert_refused(router: &axum::Router, token: &str, what: &str) {
    let (status, body) = probe(router, token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{what}: {body}");
    assert_eq!(body, json!({ "error": INVALID_KEY_ERROR }), "{what}");
}

/// The rows a load would read from `store` right now.
async fn read_rows(store: &Arc<dyn MemoryStore>) -> Result<Vec<(String, String)>, String> {
    store.list_agent_api_keys().await.map_err(|e| e.to_string())
}

/// What a barriered load does once it is released.
#[derive(Clone, Copy)]
enum Release {
    /// Publish the rows it read BEFORE the competing write.
    StaleRows,
    /// Report a read failure.
    ReadError,
}

/// The load's simulated read failure text (the funnel only displays it).
const READ_FAILURE: &str = "4066 simulated store read failure";

/// Start a REAL refresh whose store read happens now and whose publication
/// waits for `release`. Returns once the read has happened.
async fn barriered_load(
    fx: &Fixture,
    release: Release,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<AgentKeyRefresh>,
) {
    let (read_done_tx, read_done_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let registry = Arc::clone(&fx.registry);
    let store = Arc::clone(&fx.store);
    let task = tokio::spawn(async move {
        refresh_agent_keys(&registry, move || async move {
            let rows = read_rows(&store).await;
            read_done_tx.send(()).expect("test still listening");
            release_rx.await.expect("release signal");
            match release {
                Release::StaleRows => rows,
                Release::ReadError => Err(READ_FAILURE.to_string()),
            }
        })
        .await
    });
    read_done_rx.await.expect("the stale load read the store");
    (release_tx, task)
}

/// Convergence: the next ordinary refresh reads the durable truth and agrees
/// with what the competing write published.
async fn assert_converged(fx: &Fixture) {
    let store = Arc::clone(&fx.store);
    let next =
        refresh_agent_keys(&fx.registry, move || async move { read_rows(&store).await }).await;
    assert!(
        matches!(next, AgentKeyRefresh::Unchanged(_)),
        "a fresh read must agree with the published map, got {next:?}"
    );
}

// ---------------------------------------------------------------------------
// Revoke: a stale load released after the revoke cannot re-arm the key.
// ---------------------------------------------------------------------------

async fn stale_refresh_cannot_rearm_a_revoked_key(fx: Fixture) {
    let c = &fx.cast;
    let other_token = mint(&fx.router, &c.admin_token, &c.admin, &c.other).await;
    assert_authenticates(&fx.router, &c.admin_token, "A is enrolled").await;
    assert_authenticates(&fx.router, &other_token, "B is enrolled").await;

    let (release, stale) = barriered_load(&fx, Release::StaleRows).await;

    self_revoke(&fx.router, &c.admin_token, &c.admin).await;
    assert_refused(
        &fx.router,
        &c.admin_token,
        "the revoked key must be dead before the stale load publishes",
    )
    .await;

    release.send(()).expect("stale load still waiting");
    let outcome = stale.await.expect("stale refresh task");
    assert!(
        matches!(outcome, AgentKeyRefresh::Superseded(_)),
        "a load overtaken by a revoke must be discarded, got {outcome:?}"
    );
    assert_refused(
        &fx.router,
        &c.admin_token,
        "a stale refresh published after the revoke must NOT re-arm the revoked key",
    )
    .await;
    assert_authenticates(&fx.router, &other_token, "revoking A must not disturb B").await;

    assert_converged(&fx).await;
    assert_refused(&fx.router, &c.admin_token, "still dead after convergence").await;
    assert!(
        !fx.registry
            .snapshot()
            .contains_key(&api_key_sha256_hex(&c.admin_token)),
        "the revoked digest is absent from the published registry"
    );
}

#[tokio::test]
async fn sqlite_stale_refresh_cannot_rearm_a_revoked_key_4066() {
    let _g = serial().await;
    stale_refresh_cannot_rearm_a_revoked_key(sqlite_fixture().await).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_stale_refresh_cannot_rearm_a_revoked_key_4066() {
    let Some(url) = postgres_url() else {
        eprintln!(
            "skip postgres_stale_refresh_cannot_rearm_a_revoked_key_4066: \
             AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_PG_URL unset"
        );
        return;
    };
    let _g = serial().await;
    stale_refresh_cannot_rearm_a_revoked_key(postgres_fixture(&url).await).await;
}

// ---------------------------------------------------------------------------
// Rotate: revoke + re-mint while a stale load is in flight. The OLD key stays
// dead and the NEW key works once the stale load is released.
// ---------------------------------------------------------------------------

async fn stale_refresh_cannot_undo_a_rotation(fx: Fixture) {
    let c = &fx.cast;
    let other_token = mint(&fx.router, &c.admin_token, &c.admin, &c.other).await;
    let (release, stale) = barriered_load(&fx, Release::StaleRows).await;

    // A rotates: its old key is revoked (immediately, B remains enrolled) and
    // the second admin mints A a new one.
    self_revoke(&fx.router, &c.admin_token, &c.admin).await;
    let rotated = mint(&fx.router, &c.second_admin_token, &c.second_admin, &c.admin).await;
    assert_refused(&fx.router, &c.admin_token, "the old key is dead").await;
    assert_authenticates(&fx.router, &rotated, "the rotated key works").await;

    release.send(()).expect("stale load still waiting");
    let outcome = stale.await.expect("stale refresh task");
    assert!(
        matches!(outcome, AgentKeyRefresh::Superseded(_)),
        "a load overtaken by a rotation must be discarded, got {outcome:?}"
    );
    assert_refused(
        &fx.router,
        &c.admin_token,
        "a stale refresh must not resurrect the rotated-out key",
    )
    .await;
    assert_authenticates(
        &fx.router,
        &rotated,
        "a stale refresh must not drop the rotated-in key",
    )
    .await;
    assert_authenticates(&fx.router, &other_token, "B untouched").await;
    assert_converged(&fx).await;
}

#[tokio::test]
async fn sqlite_stale_refresh_cannot_undo_a_rotation_4066() {
    let _g = serial().await;
    stale_refresh_cannot_undo_a_rotation(sqlite_fixture().await).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_stale_refresh_cannot_undo_a_rotation_4066() {
    let Some(url) = postgres_url() else {
        eprintln!("skip postgres_stale_refresh_cannot_undo_a_rotation_4066: no PG url");
        return;
    };
    let _g = serial().await;
    stale_refresh_cannot_undo_a_rotation(postgres_fixture(&url).await).await;
}

// ---------------------------------------------------------------------------
// Refresh failure: a load whose read fails after a revoke keeps the revoke's
// narrowed map (fail-closed: the revoked key does not come back).
// ---------------------------------------------------------------------------

async fn a_failed_refresh_after_a_revoke_stays_closed(fx: Fixture) {
    let c = &fx.cast;
    let other_token = mint(&fx.router, &c.admin_token, &c.admin, &c.other).await;
    let (release, failing) = barriered_load(&fx, Release::ReadError).await;

    self_revoke(&fx.router, &c.admin_token, &c.admin).await;
    release.send(()).expect("failing load still waiting");
    let outcome = failing.await.expect("failing refresh task");
    let armed = fx.registry.len();
    assert_eq!(
        outcome,
        AgentKeyRefresh::KeptLastKnown(armed),
        "a failed read keeps the published map and reports what is still armed"
    );
    assert_refused(
        &fx.router,
        &c.admin_token,
        "a failed refresh must not re-arm the revoked key",
    )
    .await;
    assert_authenticates(&fx.router, &other_token, "B untouched").await;
}

#[tokio::test]
async fn sqlite_a_failed_refresh_after_a_revoke_stays_closed_4066() {
    let _g = serial().await;
    a_failed_refresh_after_a_revoke_stays_closed(sqlite_fixture().await).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_a_failed_refresh_after_a_revoke_stays_closed_4066() {
    let Some(url) = postgres_url() else {
        eprintln!("skip postgres_a_failed_refresh_after_a_revoke_stays_closed_4066: no PG url");
        return;
    };
    let _g = serial().await;
    a_failed_refresh_after_a_revoke_stays_closed(postgres_fixture(&url).await).await;
}

// ---------------------------------------------------------------------------
// Ordering: two loads over the real store. The OLDER load (it read before an
// out-of-band revoke, e.g. the CLI or a peer writing the store directly) is
// released after a NEWER load already published the revoke; it must not
// install its older set over the newer one.
// ---------------------------------------------------------------------------

async fn an_older_load_cannot_overwrite_a_newer_one(fx: Fixture) {
    let c = &fx.cast;
    let other_token = mint(&fx.router, &c.admin_token, &c.admin, &c.other).await;
    let (release, older) = barriered_load(&fx, Release::StaleRows).await;

    // Out-of-band revoke: the store changes, the registry does not (no
    // handler ran), so only a LOAD can carry it into the registry.
    let removed = fx
        .store
        .revoke_agent_api_key(&daemon_ctx(), &c.other)
        .await
        .expect("out-of-band revoke");
    assert!(removed >= 1, "the binding we minted must be removed");
    assert_authenticates(
        &fx.router,
        &other_token,
        "no load has published the out-of-band revoke yet",
    )
    .await;

    // The interloper: a NEWER load reads after the revoke and publishes it.
    let interloper_fired = Arc::new(AtomicBool::new(false));
    let store = Arc::clone(&fx.store);
    let fired = Arc::clone(&interloper_fired);
    let newer = refresh_agent_keys(&fx.registry, move || async move {
        let rows = read_rows(&store).await;
        fired.store(true, Ordering::SeqCst);
        rows
    })
    .await;
    assert!(
        interloper_fired.load(Ordering::SeqCst),
        "the newer load must actually have run"
    );
    assert!(
        matches!(newer, AgentKeyRefresh::Installed(_)),
        "the newer load publishes the revoke, got {newer:?}"
    );
    assert_refused(&fx.router, &other_token, "the newer load narrowed the map").await;

    release.send(()).expect("older load still waiting");
    let outcome = older.await.expect("older refresh task");
    assert!(
        matches!(outcome, AgentKeyRefresh::Superseded(_)),
        "a load older than a published load must be discarded, got {outcome:?}"
    );
    assert_refused(
        &fx.router,
        &other_token,
        "an older load must not install its older set over the newer one",
    )
    .await;
    assert_authenticates(&fx.router, &c.admin_token, "A untouched").await;
    assert_converged(&fx).await;
}

#[tokio::test]
async fn sqlite_an_older_load_cannot_overwrite_a_newer_one_4066() {
    let _g = serial().await;
    an_older_load_cannot_overwrite_a_newer_one(sqlite_fixture().await).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_an_older_load_cannot_overwrite_a_newer_one_4066() {
    let Some(url) = postgres_url() else {
        eprintln!("skip postgres_an_older_load_cannot_overwrite_a_newer_one_4066: no PG url");
        return;
    };
    let _g = serial().await;
    an_older_load_cannot_overwrite_a_newer_one(postgres_fixture(&url).await).await;
}

/// Keep the helpers referenced on a `sal`-only leg so they cannot rot.
#[test]
fn postgres_url_helper_is_reachable_4066() {
    let _ = postgres_url();
    let _ = register;
}

// ---------------------------------------------------------------------------
// Registry-level pins.
// ---------------------------------------------------------------------------

fn map_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(t, a)| (api_key_sha256_hex(t), (*a).to_string()))
        .collect()
}

fn rows_of(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    map_of(pairs).into_iter().collect()
}

/// Two concurrent transforms, each barriered INSIDE its transform: both
/// removals must land. A non-atomic clone → modify → install lets both copy
/// the same snapshot, and the later install silently restores the key the
/// earlier one removed.
#[test]
fn two_concurrent_transforms_both_land_4066() {
    use std::sync::{Condvar, Mutex};
    let registry = Arc::new(EnrolledAgentKeys::from_map(map_of(&[
        ("tok-a", "agent-a"),
        ("tok-b", "agent-b"),
        ("tok-c", "agent-c"),
    ])));
    // `entered` counts transforms currently executing their body.
    let gate = Arc::new((Mutex::new(0_u32), Condvar::new()));

    let spawn = |agent: &'static str| {
        let registry = Arc::clone(&registry);
        let gate = Arc::clone(&gate);
        std::thread::spawn(move || {
            registry.mutate(|map| {
                let (lock, cvar) = &*gate;
                let mut entered = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *entered += 1;
                cvar.notify_all();
                let _ = cvar
                    .wait_timeout_while(entered, PEER_ENTRY_WAIT, |n| *n < 2)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                map.retain(|_, bound| bound != agent);
            });
        })
    };
    let first = spawn("agent-a");
    let second = spawn("agent-b");
    first.join().expect("first transform");
    second.join().expect("second transform");

    let published = registry.snapshot();
    assert!(
        !published.values().any(|a| a == "agent-a"),
        "A's removal was lost to a concurrent transform: {published:?}"
    );
    assert!(
        !published.values().any(|a| a == "agent-b"),
        "B's removal was lost to a concurrent transform: {published:?}"
    );
    assert!(published.values().any(|a| a == "agent-c"), "C untouched");
}

/// A load whose ticket predates a mutation is discarded; one taken after it
/// publishes normally.
#[tokio::test]
async fn a_load_overtaken_by_a_mutation_is_superseded_4066() {
    let registry =
        EnrolledAgentKeys::from_map(map_of(&[("tok-a", "agent-a"), ("tok-b", "agent-b")]));
    let stale_rows = rows_of(&[("tok-a", "agent-a"), ("tok-b", "agent-b")]);

    let (read_tx, read_rx) = tokio::sync::oneshot::channel::<()>();
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let stale = refresh_agent_keys(&registry, move || async move {
        read_tx.send(()).expect("listening");
        go_rx.await.expect("go");
        Ok::<_, String>(stale_rows)
    });
    let revoke = async {
        read_rx.await.expect("read happened");
        registry.mutate(|m| m.retain(|_, a| a != "agent-a"));
        go_tx.send(()).expect("stale load waiting");
    };
    let (outcome, ()) = tokio::join!(stale, revoke);
    assert_eq!(outcome, AgentKeyRefresh::Superseded(1));
    assert!(
        !registry
            .snapshot()
            .contains_key(&api_key_sha256_hex("tok-a")),
        "the superseded load must not restore the revoked key"
    );

    // A load that starts AFTER the mutation is authoritative again.
    let fresh = refresh_agent_keys(&registry, || async {
        Ok::<_, String>(rows_of(&[("tok-b", "agent-b")]))
    })
    .await;
    assert_eq!(fresh, AgentKeyRefresh::Unchanged(1));
}

/// Two loads, no mutation between them: the load whose ticket is OLDER is
/// released after the newer one published, and must be discarded. Without a
/// load-order guard the older read silently re-arms what the newer one
/// dropped.
#[tokio::test]
async fn an_older_ticket_cannot_overwrite_a_newer_load_4066() {
    let registry =
        EnrolledAgentKeys::from_map(map_of(&[("tok-a", "agent-a"), ("tok-b", "agent-b")]));
    let older_rows = rows_of(&[("tok-a", "agent-a"), ("tok-b", "agent-b")]);
    let newer_rows = rows_of(&[("tok-b", "agent-b")]);

    let (read_tx, read_rx) = tokio::sync::oneshot::channel::<()>();
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let interloper_fired = AtomicBool::new(false);
    let older = refresh_agent_keys(&registry, move || async move {
        read_tx.send(()).expect("listening");
        go_rx.await.expect("go");
        Ok::<_, String>(older_rows)
    });
    let newer = async {
        read_rx.await.expect("the older load read first");
        let outcome = refresh_agent_keys(&registry, || async {
            interloper_fired.store(true, Ordering::SeqCst);
            Ok::<_, String>(newer_rows)
        })
        .await;
        go_tx.send(()).expect("older load waiting");
        outcome
    };
    let (older_outcome, newer_outcome) = tokio::join!(older, newer);
    assert!(
        interloper_fired.load(Ordering::SeqCst),
        "the newer load must actually have run"
    );
    assert_eq!(newer_outcome, AgentKeyRefresh::Installed(1));
    assert_eq!(
        older_outcome,
        AgentKeyRefresh::Superseded(1),
        "the older load must be discarded, not installed over the newer set"
    );
    assert!(
        !registry
            .snapshot()
            .contains_key(&api_key_sha256_hex("tok-a")),
        "the older read must not restore what the newer read dropped"
    );
}

/// A bind's optimistic insert carries a ticket taken BEFORE its durable
/// write. A revoke published in between makes it refuse (`None`): the insert
/// could otherwise re-arm a key the revoke just removed.
#[test]
fn a_bind_ticket_older_than_a_revoke_does_not_rearm_4066() {
    let registry = EnrolledAgentKeys::from_map(map_of(&[("tok-b", "agent-b")]));
    let ticket = registry.begin_load();
    registry.mutate(|m| m.retain(|_, a| a != "agent-a"));
    let applied = registry.mutate_if_current(ticket, |m| {
        m.insert(api_key_sha256_hex("tok-a"), "agent-a".to_string());
    });
    assert_eq!(applied, None, "a stale bind ticket must not apply");
    assert!(
        !registry
            .snapshot()
            .contains_key(&api_key_sha256_hex("tok-a"))
    );

    // A current ticket applies.
    let ticket = registry.begin_load();
    let applied = registry.mutate_if_current(ticket, |m| {
        m.insert(api_key_sha256_hex("tok-a"), "agent-a".to_string());
    });
    assert_eq!(applied, Some(true));
    assert!(
        registry
            .snapshot()
            .contains_key(&api_key_sha256_hex("tok-a"))
    );
}
