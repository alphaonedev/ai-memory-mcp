// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4066 — a registry refresh whose store read began BEFORE a revoke
//! must never publish its (stale) result AFTER the revoke narrowed the live
//! registry.
//!
//! The enrolled-key registry is published by whole-map replacement. Before
//! #4066 nothing ordered a load's READ against its PUBLICATION: the
//! background refresh (or a concurrent handler re-read) could capture the key
//! set, lose the race to an admin revoke that reported
//! `"effective": "immediately"`, and then install the captured set —
//! re-arming the revoked credential until the next refresh. The handler's own
//! clone → modify → install transform was likewise a non-atomic
//! read-modify-write against concurrent installers.
//!
//! What this binary pins, without sleeps:
//!
//! * the REAL refresh funnel (`identity_binding::refresh_agent_keys`, the one
//!   the daemon loop and the admin handlers use) is barriered between its
//!   store read and its publication; admin A's self-revoke completes through
//!   the PRODUCTION route; the stale load is released; A is denied on a fresh
//!   request both before and after the release, and B is untouched. Once on
//!   the sqlite adapter and once on the postgres adapter;
//! * two concurrent registry transforms both land (neither undoes the other);
//! * a load overtaken by a mutation reports `Superseded` and changes nothing.

// Allows sit BEFORE the `#![cfg]` so they still apply on a leg where the cfg
// empties the crate but the `//!` docs above are still linted.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(feature = "sal")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

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

struct Fixture {
    router: axum::Router,
    store: Arc<dyn MemoryStore>,
    registry: Arc<EnrolledAgentKeys>,
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

async fn register(store: &Arc<dyn MemoryStore>, agent_id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    store
        .register_agent(
            &CallerContext::for_admin(ai_memory::identity::sentinels::DAEMON_PRINCIPAL),
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

fn sqlite_fixture(admins: &[&str], agents: &[&str]) -> Fixture {
    let root = PathBuf::from(".local-runs").join("agent-key-stale-refresh-4066");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix("sqlite")
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let db_path = dir.path().join("m.db");
    {
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        for a in agents {
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
    let registry = Arc::new(EnrolledAgentKeys::empty());
    let app = app_state(
        db,
        StorageBackend::Sqlite,
        Arc::clone(&store),
        Arc::clone(&registry),
        admins,
    );
    Fixture {
        router: router_over(app, &registry),
        store,
        registry,
        _dir: Some(dir),
    }
}

#[cfg(feature = "sal-postgres")]
async fn postgres_fixture(url: &str, admins: &[&str], agents: &[&str]) -> Fixture {
    let pg = ai_memory::store::postgres::PostgresStore::connect(url)
        .await
        .expect("PostgresStore::connect (the certified tier must be exercised, not skipped)");
    let store: Arc<dyn MemoryStore> = Arc::new(pg);
    for a in agents {
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
    // Seed from the store so keys other runs left in the shared cluster are
    // accounted for (the last-key rule counts the WHOLE registry).
    let seed: HashMap<String, String> = store
        .list_agent_api_keys()
        .await
        .expect("seed registry")
        .into_iter()
        .collect();
    let registry = Arc::new(EnrolledAgentKeys::from_map(seed));
    let app = app_state(
        db,
        StorageBackend::Postgres,
        Arc::clone(&store),
        Arc::clone(&registry),
        admins,
    );
    Fixture {
        router: router_over(app, &registry),
        store,
        registry,
        _dir: None,
    }
}

async fn call(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn post(uri: &str, caller: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(ai_memory::HEADER_API_KEY, SHARED_KEY)
        .header(ai_memory::HEADER_AGENT_ID, caller)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("serialise")))
        .expect("build request")
}

async fn mint(router: &axum::Router, caller: &str, target: &str) -> String {
    let (status, body) = call(
        router,
        post(
            &format!("/api/v1/agents/{target}/api-key"),
            caller,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint for {target}: {body}");
    body["token"].as_str().expect("minted token").to_string()
}

/// A fresh request that needs only TRANSPORT authentication.
async fn authenticates(router: &axum::Router, token: &str) -> bool {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/capabilities")
        .header(ai_memory::HEADER_API_KEY, token)
        .body(Body::empty())
        .expect("probe");
    let (status, _) = call(router, req).await;
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "probe must not error"
    );
    status != StatusCode::UNAUTHORIZED
}

/// The whole race, backend-agnostic: barrier the REAL refresh between its
/// store read and its publication, revoke through the production route, then
/// release the stale load.
async fn stale_refresh_cannot_rearm_a_revoked_key(fx: Fixture, admin: &str, other: &str) {
    let admin_token = mint(&fx.router, admin, admin).await;
    let other_token = mint(&fx.router, admin, other).await;
    assert!(
        authenticates(&fx.router, &admin_token).await,
        "A is enrolled"
    );
    assert!(
        authenticates(&fx.router, &other_token).await,
        "B is enrolled"
    );

    let (read_done_tx, read_done_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let registry = Arc::clone(&fx.registry);
    let store = Arc::clone(&fx.store);
    let stale = tokio::spawn(async move {
        refresh_agent_keys(&registry, move || async move {
            // The store read happens NOW — A is still enrolled here.
            let rows = store.list_agent_api_keys().await.map_err(|e| e.to_string());
            read_done_tx.send(()).expect("test still listening");
            // ...and the publication waits until the revoke has completed.
            release_rx.await.expect("release signal");
            rows
        })
        .await
    });
    read_done_rx.await.expect("the stale load read the store");

    let (status, body) = call(
        &fx.router,
        post(
            &format!("/api/v1/agents/{admin}/api-key/revoke"),
            admin,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "self-revoke is immediate: {body}");
    assert_eq!(body["revoked"], true);
    assert_eq!(body["effective"], "immediately");
    assert!(
        !authenticates(&fx.router, &admin_token).await,
        "the revoked key must be dead before the stale load publishes"
    );

    release_tx.send(()).expect("stale load still waiting");
    let outcome = stale.await.expect("stale refresh task");
    assert!(
        matches!(outcome, AgentKeyRefresh::Superseded(_)),
        "a load overtaken by a revoke must be discarded, got {outcome:?}"
    );
    assert!(
        !authenticates(&fx.router, &admin_token).await,
        "a stale refresh published after the revoke must NOT re-arm the revoked key"
    );
    assert!(
        authenticates(&fx.router, &other_token).await,
        "revoking A must not disturb B's binding"
    );

    // Convergence: the next ordinary refresh reads the durable truth and
    // agrees with what the revoke published.
    let store = Arc::clone(&fx.store);
    let next = refresh_agent_keys(&fx.registry, move || async move {
        store.list_agent_api_keys().await.map_err(|e| e.to_string())
    })
    .await;
    assert!(
        matches!(next, AgentKeyRefresh::Unchanged(_)),
        "a fresh read must agree with the revoke's map, got {next:?}"
    );
    assert!(!authenticates(&fx.router, &admin_token).await);
    assert!(
        !fx.registry
            .snapshot()
            .contains_key(&api_key_sha256_hex(&admin_token)),
        "the revoked digest is absent from the published registry"
    );
}

#[tokio::test]
async fn sqlite_stale_refresh_cannot_rearm_a_revoked_key_4066() {
    const ADMIN: &str = "ai:k4066-admin-sqlite";
    const OTHER: &str = "ai:k4066-other-sqlite";
    let _g = serial().await;
    let fx = sqlite_fixture(&[ADMIN], &[ADMIN, OTHER]);
    stale_refresh_cannot_rearm_a_revoked_key(fx, ADMIN, OTHER).await;
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
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let admin = format!("ai:k4066-admin-{suffix}");
    let other = format!("ai:k4066-other-{suffix}");
    let _g = serial().await;
    let fx = postgres_fixture(&url, &[admin.as_str()], &[admin.as_str(), other.as_str()]).await;
    stale_refresh_cannot_rearm_a_revoked_key(fx, &admin, &other).await;
}

/// Keep the helper referenced on a `sal`-only leg so it cannot rot.
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
                // Give the OTHER transform every chance to enter with the same
                // snapshot. Atomic transforms serialise, so it cannot; the
                // bounded wait only caps the test's duration and never
                // decides the outcome.
                let _ = cvar
                    .wait_timeout_while(entered, std::time::Duration::from_millis(300), |n| *n < 2)
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
    let stale_rows: Vec<(String, String)> = map_of(&[("tok-a", "agent-a"), ("tok-b", "agent-b")])
        .into_iter()
        .collect();

    let (read_tx, read_rx) = tokio::sync::oneshot::channel::<()>();
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let rows = stale_rows.clone();
    let stale = refresh_agent_keys(&registry, move || async move {
        read_tx.send(()).expect("listening");
        go_rx.await.expect("go");
        Ok::<_, String>(rows)
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
        Ok::<_, String>(map_of(&[("tok-b", "agent-b")]).into_iter().collect())
    })
    .await;
    assert_eq!(fresh, AgentKeyRefresh::Unchanged(1));
}
