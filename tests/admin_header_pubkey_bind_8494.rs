// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8494 (control finding A, umbrella #8493) — the bootstrap
//! public-key bind must be tied to a VERIFIED principal, never to a claimed
//! admin header.
//!
//! The defect: under the default `advisory` posture a request carrying the
//! shared transport key and a CLAIMED allowlisted admin `X-Agent-Id` was
//! admitted by `require_admin` with a WARN, and could then issue a bind
//! challenge for, and bind, a keypair it controls to any agent. The proof of
//! possession (#3464) proves the caller holds the CANDIDATE key; it does not
//! prove the caller may enrol a key for the TARGET. Binding a key is the root
//! of every later signature check, so the bind and its challenge now require
//! a key-authenticated admin (an enrolled per-agent api-key bound to the
//! admin id), the local operator (CLI / MCP stdio), or the explicit
//! `AI_MEMORY_ADMIN_HEADER_TRUST` opt-in.
//!
//! Pinned, DENIED path first (1 and 4 fail against the pre-#8494 tree):
//!
//! 1. shared key + claimed admin header, no trust opt-in: the challenge and
//!    the bind are both refused (403), a durable audit row names the refusal
//!    and NO key is stored;
//! 2. the local operator path (the CLI funnel) still binds;
//! 3. a key-authenticated admin still binds end to end (challenge + PUT);
//! 4. the same refusal on the Postgres backend (`sal-postgres`, own database).
//!
//! The pure admission predicate is pinned as well, so the opt-in cannot be
//! widened silently.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::{AuthLevel, EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt as _;

const SHARED_KEY: &str = "8494-shared-transport-key";
const ADMIN_TOKEN: &str = "8494-per-agent-admin-token-0123456789abcdef";
const ADMIN: &str = "ai:ops-admin-8494";
const TARGET: &str = "ai:victim-8494";
const REFUSAL_REASON: &str = "claimed_admin_not_key_authenticated";

/// The tests mutate PROCESS-GLOBAL state (the admin-role authn marker and the
/// forensic sink), so they run one at a time; an async-aware mutex because the
/// critical section spans `.await` points (CONCURRENCY-20).
async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
    LOCK.lock().await
}

fn scratch(tag: &str) -> TempDir {
    let root = PathBuf::from(".local-runs").join("admin-header-pubkey-bind-8494");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

struct Fixture {
    state: AppState,
    router: axum::Router,
    db_path: PathBuf,
    _dir: TempDir,
}

fn build_state(registry: &Arc<EnrolledAgentKeys>, dir: &TempDir) -> (AppState, PathBuf) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
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
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::clone(registry),
        http_identity_mode: HttpIdentityMode::Advisory,
    };
    (state, db_path)
}

fn router_for(state: AppState, registry: &Arc<EnrolledAgentKeys>) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: Arc::clone(registry),
        identity_mode: HttpIdentityMode::Advisory,
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, state)
}

/// A daemon whose registry holds ONE enrolled per-agent key, bound to ADMIN.
/// Presenting `SHARED_KEY` yields a claimed admin; presenting `ADMIN_TOKEN`
/// yields a key-authenticated admin.
fn fixture(tag: &str) -> Fixture {
    let dir = scratch(tag);
    let registry = Arc::new(EnrolledAgentKeys::empty());
    registry.install(std::collections::HashMap::from([(
        api_key_sha256_hex(ADMIN_TOKEN),
        ADMIN.to_string(),
    )]));
    let (state, db_path) = build_state(&registry, &dir);
    let router = router_for(state.clone(), &registry);
    Fixture {
        state,
        router,
        db_path,
        _dir: dir,
    }
}

fn keypair() -> ai_memory::identity::keypair::AgentKeypair {
    ai_memory::identity::keypair::generate("attacker-8494").expect("generate keypair")
}

fn req(method: &str, uri: &str, api_key: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header(ai_memory::HEADER_API_KEY, api_key)
        .header(ai_memory::HEADER_AGENT_ID, ADMIN)
        .body(Body::from(serde_json::to_vec(body).expect("serialise")))
        .expect("request")
}

async fn challenge(
    router: &axum::Router,
    api_key: &str,
    pubkey: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/agents/{TARGET}/pubkey/challenge"),
            api_key,
            &serde_json::json!({ "pubkey_b64": pubkey }),
        ))
        .await
        .expect("challenge response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// Run challenge + PUT as `api_key`, answering with `kp`; return the status of
/// the challenge step and, when it was issued, of the bind.
async fn bind_as(
    router: &axum::Router,
    api_key: &str,
    kp: &ai_memory::identity::keypair::AgentKeypair,
) -> (StatusCode, Option<StatusCode>) {
    let pubkey = kp.public_base64();
    let (cstatus, cbody) = challenge(router, api_key, &pubkey).await;
    if cstatus != StatusCode::OK {
        // The attacker does not stop at a refused challenge: a bind with a
        // self-signed proof over a made-up nonce must be refused as well.
        return (cstatus, None);
    }
    let ch = ai_memory::identity::pubkey_bind::BindChallenge {
        nonce_b64: cbody["nonce"].as_str().expect("nonce").to_string(),
        agent_id: TARGET.to_string(),
        pubkey_b64: pubkey.clone(),
        expires_at: cbody["expires_at"]
            .as_str()
            .expect("expires_at")
            .to_string(),
    };
    let proof = ai_memory::identity::pubkey_bind::sign_bind_challenge(
        kp.private.as_ref().expect("generated private key"),
        &ch,
    );
    let resp = router
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/agents/{TARGET}/pubkey"),
            api_key,
            &serde_json::json!({
                "pubkey_b64": pubkey,
                "nonce": ch.nonce_b64,
                "proof_b64": proof,
            }),
        ))
        .await
        .expect("bind response");
    (cstatus, Some(resp.status()))
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

fn stored_key(db_path: &std::path::Path) -> Option<String> {
    let conn = ai_memory::db::open(db_path).expect("inspect db");
    ai_memory::db::agent_pubkey(&conn, TARGET).expect("agent_pubkey")
}

/// (1) DENIED: the shared key plus a claimed admin header can neither take a
/// challenge nor bind; the refusal is on the audit chain; no key is stored.
#[tokio::test]
async fn claimed_admin_header_cannot_bind_a_pubkey_8494() {
    let _g = serial().await;
    let fx = fixture("claimed");
    let audit_dir = scratch("audit-claimed");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    let attacker = keypair();
    let (cstatus, bstatus) = bind_as(&fx.router, SHARED_KEY, &attacker).await;
    assert_eq!(
        cstatus,
        StatusCode::FORBIDDEN,
        "a claimed admin must not even take a bind challenge"
    );
    assert_eq!(bstatus, None, "no challenge, so no bind is reachable");

    // The attacker also tries the bind with a proof it made up itself.
    let pubkey = attacker.public_base64();
    let forged = ai_memory::identity::pubkey_bind::sign_bind_challenge(
        attacker.private.as_ref().expect("private"),
        &ai_memory::identity::pubkey_bind::BindChallenge {
            nonce_b64: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
            agent_id: TARGET.to_string(),
            pubkey_b64: pubkey.clone(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
        },
    );
    let resp = fx
        .router
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/agents/{TARGET}/pubkey"),
            SHARED_KEY,
            &serde_json::json!({
                "pubkey_b64": pubkey,
                "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                "proof_b64": forged,
            }),
        ))
        .await
        .expect("bind response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    assert_eq!(
        stored_key(&fx.db_path),
        None,
        "no key may be stored for the target"
    );
    let audit = forensic_text(&audit_dir);
    assert!(
        audit.contains("bind_agent_pubkey") && audit.contains(REFUSAL_REASON),
        "the refusal must land on the durable audit chain: {audit}"
    );
    let _ = &fx.state;
}

/// (2) ALLOWED: the local operator funnel (CLI `agents bind-pubkey`, MCP stdio)
/// is not an HTTP header claim and still binds.
#[tokio::test]
async fn local_operator_bind_still_succeeds_8494() {
    let _g = serial().await;
    let fx = fixture("local-operator");
    let kp = keypair();
    {
        let conn = ai_memory::db::open(&fx.db_path).expect("open");
        ai_memory::db::bind_agent_pubkey_with_keypair(&conn, TARGET, &kp)
            .expect("the local operator funnel binds");
    }
    assert_eq!(stored_key(&fx.db_path), Some(kp.public_base64()));
}

/// (3) ALLOWED: an admin that presents its own enrolled per-agent key binds
/// end to end over HTTP.
#[tokio::test]
async fn key_authenticated_admin_can_bind_a_pubkey_8494() {
    let _g = serial().await;
    let fx = fixture("keyed");
    let kp = keypair();
    let (cstatus, bstatus) = bind_as(&fx.router, ADMIN_TOKEN, &kp).await;
    assert_eq!(
        cstatus,
        StatusCode::OK,
        "key-authenticated admin: challenge"
    );
    assert_eq!(
        bstatus,
        Some(StatusCode::OK),
        "key-authenticated admin: bind"
    );
    assert_eq!(stored_key(&fx.db_path), Some(kp.public_base64()));
}

/// The admission predicate: key-bound or the explicit operator opt-in only.
#[test]
fn bind_admission_predicate_is_key_bound_or_explicit_opt_in_8494() {
    use ai_memory::handlers::admin_role::pubkey_bind_principal_admitted;
    assert!(!pubkey_bind_principal_admitted(AuthLevel::Claimed, false));
    assert!(pubkey_bind_principal_admitted(AuthLevel::Claimed, true));
    assert!(pubkey_bind_principal_admitted(
        AuthLevel::KeyAuthenticated,
        false
    ));
    assert!(pubkey_bind_principal_admitted(
        AuthLevel::SignatureAttested,
        false
    ));
}

/// (4) Postgres parity for (1): same refusal, nothing stored, own database.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_claimed_admin_header_cannot_bind_a_pubkey_8494() {
    let _g = serial().await;
    let dir = scratch("pg-claimed");
    let registry = Arc::new(EnrolledAgentKeys::empty());
    registry.install(std::collections::HashMap::from([(
        api_key_sha256_hex(ADMIN_TOKEN),
        ADMIN.to_string(),
    )]));
    let (mut state, _db_path) = build_state(&registry, &dir);
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let store = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("own PG database"),
    );
    state.store = store.clone();
    state.storage_backend = ai_memory::handlers::StorageBackend::Postgres;
    let router = router_for(state, &registry);

    let audit_dir = scratch("audit-pg");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    // Register the target through the keyed admin (no claimed-admin path).
    let resp = router
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/agents",
            ADMIN_TOKEN,
            &serde_json::json!({ "agent_id": TARGET, "agent_type": "ai:test" }),
        ))
        .await
        .expect("register");
    assert!(resp.status().is_success(), "register: {}", resp.status());

    let attacker = keypair();
    let (cstatus, _) = bind_as(&router, SHARED_KEY, &attacker).await;
    assert_eq!(cstatus, StatusCode::FORBIDDEN);
    assert_eq!(
        ai_memory::store::MemoryStore::agent_pubkey(store.as_ref(), TARGET)
            .await
            .expect("agent_pubkey"),
        None,
        "no key may be stored on postgres"
    );
    let audit = forensic_text(&audit_dir);
    assert!(
        audit.contains("bind_agent_pubkey") && audit.contains(REFUSAL_REASON),
        "the refusal must land on the durable audit chain: {audit}"
    );

    let kp = keypair();
    let (cstatus, bstatus) = bind_as(&router, ADMIN_TOKEN, &kp).await;
    assert_eq!(cstatus, StatusCode::OK);
    assert_eq!(bstatus, Some(StatusCode::OK), "keyed admin binds on pg");
}
