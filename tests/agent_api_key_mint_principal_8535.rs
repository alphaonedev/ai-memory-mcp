// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8535 (control finding A2, umbrella #8493) plus #8536 — agent api-key
//! mint and revoke require a VERIFIED principal, never a claimed admin header.
//!
//! The defect: `POST /api/v1/agents/{id}/api-key` (and `.../revoke`) admitted
//! through `require_admin` alone. Under `advisory`, and under `enforce` while
//! the enrolled registry is empty, a caller holding the SHARED transport key and
//! a CLAIMED allowlisted admin `X-Agent-Id` was admitted, and could mint a
//! per-agent key for any registered agent, the admin ids included. A
//! self-minted admin key resolves `KeyAuthenticated`, which defeats the #8494
//! pubkey-bind gate: claimed-header escalation to a key-authenticated
//! principal.
//!
//! Pinned (1, 2 and 5 fail against the pre-#8535 tree):
//!
//! 1. shared key + claimed admin header, advisory: mint refused 403, a durable
//!    deny row, no key row stored;
//! 2. the same under `enforce` with an EMPTY registry (where the #2044 gate is
//!    inert);
//! 3. the operator-opted principal (`AI_MEMORY_ADMIN_HEADER_TRUST`, the env
//!    bootstrap) still mints;
//! 4. an already-enrolled admin key (attested per-agent key) still mints;
//! 5. revoke by the claimed admin is refused the same way;
//! 6. Postgres parity for (1) and (3);
//! 7. #8536: a malformed path id is a 400 that writes NO audit row, on the
//!    pubkey-bind helper too (validate before audit, the #3529 rule).

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

const SHARED_KEY: &str = "8535-shared-transport-key";
const ADMIN_TOKEN: &str = "8535-per-agent-admin-token-0123456789abcdef";
const ADMIN: &str = "ai:ops-admin-8535";
const TARGET: &str = "ai:victim-8535";
const DENY_REASON: &str = "claimed_admin_not_key_authenticated";
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
    let root = PathBuf::from(".local-runs").join("agent-api-key-mint-principal-8535");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

struct Fixture {
    state: AppState,
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
    let router = router_for(state.clone(), &registry, mode);
    Fixture {
        state,
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
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
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

/// Seed the store with ADMIN's own enrolled key so the "no key row stored"
/// assertion counts a known baseline.
async fn seed_admin_key(fx: &Fixture) {
    fx.store
        .bind_agent_api_key(
            &CallerContext::for_admin(ai_memory::identity::sentinels::DAEMON_PRINCIPAL),
            ADMIN,
            &api_key_sha256_hex(ADMIN_TOKEN),
        )
        .await
        .expect("seed admin key");
}

/// (1) DENIED: shared key + claimed admin header, advisory: 403, deny row,
/// nothing stored.
#[tokio::test]
async fn claimed_admin_header_cannot_mint_under_advisory_8535() {
    let _g = serial().await;
    let fx = fixture("adv", HttpIdentityMode::Advisory, true, false);
    seed_admin_key(&fx).await;
    let audit_dir = scratch("audit-adv");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    let before = enrolled_count(&fx.store).await;
    let (status, body) = mint(&fx.router, SHARED_KEY, TARGET).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "claimed admin mint: {body}");
    assert_eq!(enrolled_count(&fx.store).await, before, "no key stored");
    assert!(body.get("token").is_none(), "no token in a refusal: {body}");

    // The attacker also tries to mint a key for the ADMIN id itself.
    let (status, _) = mint(&fx.router, SHARED_KEY, ADMIN).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "self-mint as admin");
    assert_eq!(enrolled_count(&fx.store).await, before, "no admin key");

    let audit = forensic_text(&audit_dir);
    assert!(
        audit.contains(MINT_ACTION) && audit.contains(DENY_REASON),
        "the refusal must land on the durable audit chain: {audit}"
    );
    let _ = &fx.state;
}

/// (2) DENIED: the same under `enforce` with an EMPTY registry.
#[tokio::test]
async fn claimed_admin_header_cannot_mint_under_enforce_empty_registry_8535() {
    let _g = serial().await;
    let fx = fixture("enf", HttpIdentityMode::Enforce, false, false);
    let audit_dir = scratch("audit-enf");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    let (status, body) = mint(&fx.router, SHARED_KEY, TARGET).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(enrolled_count(&fx.store).await, 0, "no key stored");
    assert_eq!(fx.state.enrolled_agent_keys.len(), 0, "registry stays empty");
    let audit = forensic_text(&audit_dir);
    assert!(
        audit.contains(MINT_ACTION) && audit.contains(DENY_REASON),
        "{audit}"
    );
}

/// (3) ALLOWED: the operator-opted env principal (the bootstrap path for the
/// FIRST admin key) still mints.
#[tokio::test]
async fn operator_header_trust_principal_can_mint_the_first_key_8535() {
    let _g = serial().await;
    let fx = fixture("env", HttpIdentityMode::Advisory, false, true);
    let (status, body) = mint(&fx.router, SHARED_KEY, ADMIN).await;
    set_header_trust(false);
    assert_eq!(status, StatusCode::OK, "env bootstrap mint: {body}");
    assert_eq!(enrolled_count(&fx.store).await, 1);
}

/// (4) ALLOWED: an admin presenting its own enrolled per-agent key mints.
#[tokio::test]
async fn attested_per_agent_admin_key_can_mint_8535() {
    let _g = serial().await;
    let fx = fixture("keyed", HttpIdentityMode::Advisory, true, false);
    seed_admin_key(&fx).await;
    let before = enrolled_count(&fx.store).await;
    let (status, body) = mint(&fx.router, ADMIN_TOKEN, TARGET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(enrolled_count(&fx.store).await, before + 1);
}

/// (5) DENIED: revoke by the claimed admin is refused the same way and removes
/// nothing.
#[tokio::test]
async fn claimed_admin_header_cannot_revoke_8535() {
    let _g = serial().await;
    let fx = fixture("rev", HttpIdentityMode::Advisory, true, false);
    seed_admin_key(&fx).await;
    let audit_dir = scratch("audit-rev");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    let before = enrolled_count(&fx.store).await;
    let (status, body) = call(
        &fx.router,
        req(
            "POST",
            &format!("/api/v1/agents/{ADMIN}/api-key/revoke"),
            SHARED_KEY,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(enrolled_count(&fx.store).await, before, "nothing revoked");
    let audit = forensic_text(&audit_dir);
    assert!(
        audit.contains(REVOKE_ACTION) && audit.contains(DENY_REASON),
        "{audit}"
    );
}

/// (7a) #8536 on the mint route: a malformed id is a 400 that writes no audit
/// row (the id never reaches the signed chain).
#[tokio::test]
async fn malformed_id_on_a_claimed_mint_writes_no_audit_row_8536() {
    let _g = serial().await;
    let fx = fixture("ord-mint", HttpIdentityMode::Advisory, true, false);
    let audit_dir = scratch("audit-ord-mint");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    let malformed = "z".repeat(600);
    let (status, body) = mint(&fx.router, SHARED_KEY, &malformed).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let audit = forensic_text(&audit_dir);
    assert!(
        !audit.contains(&malformed),
        "an unvalidated {{id}} must never reach the signed audit chain"
    );
}

/// (7b) #8536 on the #8494 pubkey-bind helper: same ordering.
#[tokio::test]
async fn malformed_id_on_a_claimed_pubkey_bind_writes_no_audit_row_8536() {
    let _g = serial().await;
    let fx = fixture("ord-bind", HttpIdentityMode::Advisory, true, false);
    let audit_dir = scratch("audit-ord-bind");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    let malformed = "y".repeat(600);
    let (status, body) = call(
        &fx.router,
        req(
            "POST",
            &format!("/api/v1/agents/{malformed}/pubkey/challenge"),
            SHARED_KEY,
            &json!({ "pubkey_b64": "AAAA" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let audit = forensic_text(&audit_dir);
    assert!(
        !audit.contains(&malformed),
        "an unvalidated {{id}} must never reach the signed audit chain"
    );
}

/// (6) Postgres parity for (1) and (3), own database.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_claimed_admin_cannot_mint_but_env_principal_can_8535() {
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

    // Register the target through the keyed admin (no claimed-admin path).
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

    let before = enrolled_count(&store).await;
    let (status, body) = mint(&router, SHARED_KEY, TARGET).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(enrolled_count(&store).await, before, "no key on postgres");
    let audit = forensic_text(&audit_dir);
    assert!(
        audit.contains(MINT_ACTION) && audit.contains(DENY_REASON),
        "{audit}"
    );

    set_header_trust(true);
    let (status, body) = mint(&router, SHARED_KEY, TARGET).await;
    set_header_trust(false);
    assert_eq!(status, StatusCode::OK, "env principal mints on pg: {body}");
    assert_eq!(enrolled_count(&store).await, before + 1);
}
