// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8574 (umbrella #8493): `AI_MEMORY_ADMIN_HEADER_TRUST=1` no longer
//! re-admits a CLAIMED admin on the four credential routes (pubkey bind,
//! bind challenge, api-key mint, api-key revoke) once at least one per-agent
//! api key is enrolled, in any identity mode. The enrolled registry is the
//! backstop; the claim it backstops must never extend it. The one-boot
//! bootstrap (empty registry) is unchanged.
//!
//! 3-agent vote (6def5ab6), option B.

#![cfg(feature = "sal")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::agent_api_key::mark_credential_transport_confidential;
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::{CallerContext, MemoryStore};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt as _;

const SHARED_KEY: &str = "8574-shared-transport-key";
const ADMIN_TOKEN: &str = "8574-per-agent-admin-token-0123456789abcdef";
const ADMIN: &str = "ai:ops-admin-8574";
const TARGET: &str = "ai:victim-8574";
const DENY_REASON: &str = "header_trust_refused_registry_enrolled";
const MINT_ACTION: &str = "agent_api_key_mint";
const REVOKE_ACTION: &str = "agent_api_key_revoke";

/// The tests mutate PROCESS-GLOBAL state (the admin authn marker, the credential
/// transport marker, the forensic sink and the header-trust env), so they run
/// one at a time; async-aware because the section spans `.await` (CONCURRENCY-20).
async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
    LOCK.lock().await
}

/// Set or clear the operator header-trust opt-in. Every caller holds
/// [`serial`], so no other test in this binary reads the variable meanwhile.
fn set_header_trust(on: bool) {
    // SAFETY: every test in this binary holds `serial()` while it runs.
    unsafe {
        if on {
            std::env::set_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
        } else {
            std::env::remove_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST);
        }
    }
}

fn scratch(tag: &str) -> TempDir {
    let root = PathBuf::from(".local-runs").join("header-trust-credential-routes-8574");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

struct Fixture {
    router: axum::Router,
    store: Arc<dyn MemoryStore>,
    _dir: TempDir,
}

fn build_state(
    registry: &Arc<EnrolledAgentKeys>,
    dir: &TempDir,
    mode: HttpIdentityMode,
) -> (AppState, Arc<dyn MemoryStore>) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    mark_credential_transport_confidential(true);
    let db_path = dir.path().join("m.db");
    {
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        ai_memory::db::register_agent(&conn, TARGET, "ai:test", &[]).expect("register target");
        ai_memory::db::register_agent(&conn, ADMIN, "human", &[]).expect("register admin");
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
    let state = AppState {
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
        storage_backend: StorageBackend::Sqlite,
        store: Arc::clone(&store),
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::clone(registry),
        http_identity_mode: mode,
    };
    (state, store)
}

fn router_for(
    state: AppState,
    registry: &Arc<EnrolledAgentKeys>,
    mode: HttpIdentityMode,
) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: Arc::clone(registry),
        identity_mode: mode,
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, state)
}

/// `enroll_admin` puts ADMIN's own per-agent key in the registry (so presenting
/// `ADMIN_TOKEN` is a key-authenticated admin); `false` leaves the registry
/// empty (the bootstrap shape where the #2044 gate is inert).
fn fixture(tag: &str, mode: HttpIdentityMode, enroll_admin: bool, header_trust: bool) -> Fixture {
    set_header_trust(header_trust);
    let dir = scratch(tag);
    let registry = Arc::new(EnrolledAgentKeys::empty());
    if enroll_admin {
        registry.install(std::collections::HashMap::from([(
            api_key_sha256_hex(ADMIN_TOKEN),
            ADMIN.to_string(),
        )]));
    }
    let (state, store) = build_state(&registry, &dir, mode);
    let router = router_for(state, &registry, mode);
    Fixture {
        router,
        store,
        _dir: dir,
    }
}

fn req(method: &str, uri: &str, api_key: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header(ai_memory::HEADER_API_KEY, api_key)
        .header(ai_memory::HEADER_AGENT_ID, ADMIN)
        .body(Body::from(serde_json::to_vec(body).expect("serialise")))
        .expect("request")
}

async fn call(router: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(request).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn mint(router: &axum::Router, api_key: &str, target: &str) -> (StatusCode, Value) {
    call(
        router,
        req(
            "POST",
            &format!("/api/v1/agents/{target}/api-key"),
            api_key,
            &json!({}),
        ),
    )
    .await
}

fn forensic_text(dir: &TempDir) -> String {
    ai_memory::governance::audit::shutdown();
    let mut text = String::new();
    for entry in std::fs::read_dir(dir.path()).expect("read audit dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            text.push_str(&std::fs::read_to_string(&path).expect("read forensic file"));
        }
    }
    text
}

async fn enrolled_count(store: &Arc<dyn MemoryStore>) -> usize {
    store.list_agent_api_keys().await.expect("list").len()
}

const BIND_ACTION: &str = "bind_agent_pubkey";

async fn seed_admin_key(fx: &Fixture) {
    let _outcome = fx
        .store
        .bind_agent_api_key(
            &CallerContext::for_admin(ai_memory::identity::sentinels::DAEMON_PRINCIPAL),
            ADMIN,
            &api_key_sha256_hex(ADMIN_TOKEN),
        )
        .await
        .expect("seed admin key");
}

async fn pubkey_of(store: &Arc<dyn MemoryStore>) -> Option<String> {
    MemoryStore::agent_pubkey(store.as_ref(), TARGET)
        .await
        .expect("agent_pubkey")
}

/// Drive all four credential routes as the claimed admin (shared key) and
/// assert each is a 403 that changes nothing.
async fn assert_all_four_refused(router: &axum::Router, store: &Arc<dyn MemoryStore>) {
    let keys_before = enrolled_count(store).await;
    assert_four_forbidden(router).await;
    assert_eq!(enrolled_count(store).await, keys_before, "no key change");
    assert_eq!(pubkey_of(store).await, None, "no pubkey bound");
}

/// The four credential routes as the claimed admin: each is a 403, no store read.
async fn assert_four_forbidden(router: &axum::Router) {
    let pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let (s, b) = mint(router, SHARED_KEY, TARGET).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "mint: {b}");
    let (s, b) = call(
        router,
        req(
            "POST",
            &format!("/api/v1/agents/{ADMIN}/api-key/revoke"),
            SHARED_KEY,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "revoke: {b}");
    let (s, b) = call(
        router,
        req(
            "POST",
            &format!("/api/v1/agents/{TARGET}/pubkey/challenge"),
            SHARED_KEY,
            &json!({ "pubkey_b64": pk }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "challenge: {b}");
    let (s, b) = call(
        router,
        req(
            "PUT",
            &format!("/api/v1/agents/{TARGET}/pubkey"),
            SHARED_KEY,
            &json!({ "pubkey_b64": pk, "nonce": "AAAAAAAAAAAAAAAAAAAAAA", "proof_b64": "AAAA" }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "bind: {b}");
}

/// (1) DENIED: opt-in set, advisory, one enrolled key: all four routes refuse a
/// claimed admin, with a deny row carrying the new reason.
#[tokio::test]
async fn header_trust_does_not_admit_claimed_admin_when_keys_enrolled_advisory_8574() {
    let _g = serial().await;
    let fx = fixture("adv", HttpIdentityMode::Advisory, true, true);
    seed_admin_key(&fx).await;
    let audit_dir = scratch("audit-adv");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    assert_all_four_refused(&fx.router, &fx.store).await;
    set_header_trust(false);

    let audit = forensic_text(&audit_dir);
    for action in [MINT_ACTION, REVOKE_ACTION, BIND_ACTION] {
        assert!(audit.contains(action), "deny row for {action}: {audit}");
    }
    assert!(audit.contains(DENY_REASON), "new reason label: {audit}");
}

/// (2) DENIED: the same under `enforce` with one enrolled key.
#[tokio::test]
async fn header_trust_does_not_admit_claimed_admin_when_keys_enrolled_enforce_8574() {
    let _g = serial().await;
    let fx = fixture("enf", HttpIdentityMode::Enforce, true, true);
    seed_admin_key(&fx).await;
    assert_all_four_refused(&fx.router, &fx.store).await;
    set_header_trust(false);
}

/// (3) ALLOWED: the documented bootstrap (empty registry, opt-in set)
/// still mints.
#[tokio::test]
async fn header_trust_bootstrap_with_empty_registry_still_mints_8574() {
    let _g = serial().await;
    let fx = fixture("boot", HttpIdentityMode::Advisory, false, true);
    let (status, body) = mint(&fx.router, SHARED_KEY, ADMIN).await;
    set_header_trust(false);
    assert_eq!(status, StatusCode::OK, "bootstrap mint: {body}");
    assert_eq!(enrolled_count(&fx.store).await, 1);
}

/// (4) ALLOWED: a key-bound admin still mints with the opt-in set.
#[tokio::test]
async fn key_bound_admin_still_mints_with_opt_in_set_8574() {
    let _g = serial().await;
    let fx = fixture("keyed", HttpIdentityMode::Advisory, true, true);
    seed_admin_key(&fx).await;
    let before = enrolled_count(&fx.store).await;
    let (status, body) = mint(&fx.router, ADMIN_TOKEN, TARGET).await;
    set_header_trust(false);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(enrolled_count(&fx.store).await, before + 1);
}

/// (6) DENIED: the in-memory snapshot is empty (failed boot load, stale cache,
/// CLI enrollment on the data tier) while the store holds a key; the opt-in must
/// not admit on the snapshot alone (HIGH-1, authoritative read).
#[tokio::test]
async fn header_trust_refused_when_snapshot_empty_but_store_holds_a_key_8574() {
    let _g = serial().await;
    let fx = fixture("stale", HttpIdentityMode::Advisory, false, true);
    seed_admin_key(&fx).await;
    let audit_dir = scratch("audit-stale");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");
    assert_all_four_refused(&fx.router, &fx.store).await;
    set_header_trust(false);
    let audit = forensic_text(&audit_dir);
    assert!(audit.contains(DENY_REASON), "new reason label: {audit}");
}

/// (7) DENIED: the authoritative read itself fails (unknown registry state):
/// the opt-in arm refuses, never admits (fail closed).
#[tokio::test]
async fn header_trust_refused_when_the_store_read_errors_8574() {
    let _g = serial().await;
    let fx = fixture("rderr", HttpIdentityMode::Advisory, false, true);
    {
        let conn = ai_memory::db::open(&fx._dir.path().join("m.db")).expect("open for fault");
        conn.execute_batch("DROP TABLE agent_api_keys")
            .expect("drop the key table to fault the read");
    }
    let audit_dir = scratch("audit-rderr");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");
    assert_four_forbidden(&fx.router).await;
    set_header_trust(false);
    let audit = forensic_text(&audit_dir);
    assert!(audit.contains(DENY_REASON), "refused label: {audit}");
}

/// (8) DENIED under identity mode `off` (modes are Off/Advisory/Enforce).
#[tokio::test]
async fn header_trust_does_not_admit_claimed_admin_when_keys_enrolled_off_8574() {
    let _g = serial().await;
    let fx = fixture("off", HttpIdentityMode::Off, true, true);
    seed_admin_key(&fx).await;
    assert_all_four_refused(&fx.router, &fx.store).await;
    set_header_trust(false);
}

/// (5) Postgres parity for (1) and (3), own database.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_header_trust_refused_when_keys_enrolled_bootstrap_when_empty_8574() {
    let _g = serial().await;
    set_header_trust(false);
    let dir = scratch("pg");
    let registry = Arc::new(EnrolledAgentKeys::empty());
    registry.install(std::collections::HashMap::from([(
        api_key_sha256_hex(ADMIN_TOKEN),
        ADMIN.to_string(),
    )]));
    let mode = HttpIdentityMode::Advisory;
    let (mut state, _store) = build_state(&registry, &dir, mode);
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let pg = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("own PG database"),
    );
    let store: Arc<dyn MemoryStore> = pg.clone();
    state.store = Arc::clone(&store);
    state.storage_backend = StorageBackend::Postgres;
    let router = router_for(state, &registry, mode);
    let audit_dir = scratch("audit-pg");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    let (status, _) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            ADMIN_TOKEN,
            &json!({ "agent_id": TARGET, "agent_type": "ai:test" }),
        ),
    )
    .await;
    assert!(status.is_success(), "register: {status}");

    set_header_trust(true);
    let before = enrolled_count(&store).await;
    let (status, body) = mint(&router, SHARED_KEY, TARGET).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(enrolled_count(&store).await, before, "no key on postgres");
    let audit = forensic_text(&audit_dir);
    assert!(
        audit.contains(MINT_ACTION) && audit.contains(DENY_REASON),
        "{audit}"
    );

    // Empty registry: the bootstrap still mints.
    registry.install(std::collections::HashMap::new());
    let (status, body) = mint(&router, SHARED_KEY, TARGET).await;
    set_header_trust(false);
    assert_eq!(status, StatusCode::OK, "bootstrap mints on pg: {body}");
    assert_eq!(enrolled_count(&store).await, before + 1);
}

/// Build a router on a fresh PG store whose registry snapshot is EMPTY while
/// `ADMIN` is registered (registered under an enrolled registry first).
#[cfg(feature = "sal-postgres")]
async fn pg_empty_snapshot_router(
    tag: &str,
) -> (
    axum::Router,
    Arc<dyn MemoryStore>,
    Arc<EnrolledAgentKeys>,
    AppState,
    TempDir,
) {
    set_header_trust(false);
    let dir = scratch(tag);
    let registry = Arc::new(EnrolledAgentKeys::empty());
    registry.install(std::collections::HashMap::from([(
        api_key_sha256_hex(ADMIN_TOKEN),
        ADMIN.to_string(),
    )]));
    let mode = HttpIdentityMode::Advisory;
    let (mut state, _store) = build_state(&registry, &dir, mode);
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let pg = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("own PG database"),
    );
    let store: Arc<dyn MemoryStore> = pg.clone();
    state.store = Arc::clone(&store);
    state.storage_backend = StorageBackend::Postgres;
    let router = router_for(state.clone(), &registry, mode);
    let (status, _) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            ADMIN_TOKEN,
            &json!({ "agent_id": TARGET, "agent_type": "ai:test" }),
        ),
    )
    .await;
    assert!(status.is_success(), "register: {status}");
    registry.install(std::collections::HashMap::new());
    (router, store, registry, state, dir)
}

/// (9) Postgres: snapshot empty while the store holds a key: refused.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_header_trust_refused_when_snapshot_empty_but_store_holds_a_key_8574() {
    let _g = serial().await;
    let (router, store, _registry, _state, _dir) = pg_empty_snapshot_router("pgstale").await;
    let _outcome = store
        .bind_agent_api_key(
            &CallerContext::for_admin(ai_memory::identity::sentinels::DAEMON_PRINCIPAL),
            ADMIN,
            &api_key_sha256_hex(ADMIN_TOKEN),
        )
        .await
        .expect("seed admin key on pg");
    set_header_trust(true);
    let before = enrolled_count(&store).await;
    let (status, body) = mint(&router, SHARED_KEY, TARGET).await;
    set_header_trust(false);
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(enrolled_count(&store).await, before, "no key on postgres");
}

/// (10) Postgres: the authoritative read errors (closed pool): refused.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_header_trust_refused_when_the_store_read_errors_8574() {
    let _g = serial().await;
    let (_router, _store, registry, state, _dir) = pg_empty_snapshot_router("pgerr").await;
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let broken = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("second connection to the own database");
    broken.pool().close().await;
    let mut faulted = state;
    faulted.store = Arc::new(broken);
    let router = router_for(faulted, &registry, HttpIdentityMode::Advisory);
    set_header_trust(true);
    assert_four_forbidden(&router).await;
    set_header_trust(false);
}
