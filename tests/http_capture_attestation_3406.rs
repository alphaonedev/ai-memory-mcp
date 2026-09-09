// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3406 — real HTTP capture admission, including a live PostgreSQL adapter.
#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

mod common;
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const AGENT: &str = "ai:capture-owner-3406";
const OTHER: &str = "ai:capture-other-3406";

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`, but under `sal` its inner \
                  `Arc<dyn MemoryStore>` is MOVED into the struct literal below; \
                  one signature keeps both feature legs building identically."
    )
)]
fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
    let _ = &store;
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
        #[cfg(feature = "sal")]
        store: store.0,
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

/// The SAL handle, present only under `feature = "sal"`. Wrapping it in a
/// newtype keeps `app_state_with`'s signature identical across feature legs
/// (the default-feature build has no `MemoryStore` trait at all).
#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

/// Build a sqlite-backed `AppState` over a real on-disk DB. Under `sal` the
/// `SqliteStore` is opened against the SAME file as `app.db`, so both views
/// see the same rows (exactly what `bootstrap_serve` does).
fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    app_state_with(db, StorageBackend::Sqlite, store)
}

/// Build a postgres-backed `AppState`. `app.db` is a throwaway in-memory
/// sqlite — deliberately EMPTY, so any handler that reads it instead of
/// `app.store` returns nothing and the test fails loudly.
#[cfg(feature = "sal-postgres")]
async fn postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    ));
    app_state_with(db, StorageBackend::Postgres, store)
}

fn router(app: AppState) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app,
    )
}

async fn post(router: &axum::Router, caller: &str, body: &Value) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/capture_turn")
                .header("content-type", "application/json")
                .header("x-agent-id", caller)
                .body(Body::from(serde_json::to_vec(body).expect("serialize")))
                .expect("request"),
        )
        .await
        .expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("JSON"))
}

fn body(key: Option<&SigningKey>) -> Value {
    let session = uuid::Uuid::new_v4().to_string();
    let content = "A host captured a concrete observation for the attestation regression.";
    let mut body = json!({"host_session_id":session,"host_turn_index":0,"role":"user",
        "content":content,"namespace":"capture-3406",
        "metadata":{"attest_level":"agent_attested"}});
    if let Some(key) = key {
        let canonical = format!("{session}\0{}\0{}\0{content}", 0, "user");
        body["host_signature_b64"] =
            json!(STANDARD.encode(key.sign(canonical.as_bytes()).to_bytes()));
        body["host_pubkey_b64"] = json!(STANDARD.encode(key.verifying_key().to_bytes()));
    }
    body
}

fn exercise(
    app: AppState,
    key: &SigningKey,
    audit_path: &std::path::Path,
    rt: &tokio::runtime::Runtime,
) {
    #[cfg(feature = "sal")]
    let store = Arc::clone(&app.store);
    let router = router(app);
    let other_key = SigningKey::from_bytes(&[43; 32]);
    let allowlist = format!(
        "{},{}",
        STANDARD.encode(key.verifying_key().to_bytes()),
        STANDARD.encode(other_key.verifying_key().to_bytes())
    );
    // Both test entries hold TEST_LOCK; each phase owns
    // common's batch guard, including every request reading its environment.
    for posture in [None, Some("1"), Some("garbage")] {
        let _env = common::MultiEnvVarGuard::apply(&[
            ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", posture),
            ("AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST", Some(&allowlist)),
        ]);
        let (status, denied) = rt.block_on(post(&router, AGENT, &body(None)));
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(denied["code"], "ATTESTATION_FAILED");
        let signed = body(Some(key));
        let (status, allowed) = rt.block_on(post(&router, AGENT, &signed));
        assert_eq!(status, StatusCode::CREATED, "{allowed}");
        assert_eq!(allowed["attest_level"], "signed_by_peer");
        #[cfg(feature = "sal")]
        {
            let persisted = rt
                .block_on(store.get(
                    &ai_memory::store::CallerContext::for_agent(AGENT),
                    allowed["memory_id"].as_str().expect("memory id"),
                ))
                .expect("read persisted capture from the actual adapter");
            assert_eq!(persisted.metadata["attest_level"], "signed_by_peer");
            assert_eq!(persisted.metadata["agent_id"], AGENT);
        }

        let (status, repeated) = rt.block_on(post(&router, AGENT, &signed));
        assert_eq!(status, StatusCode::OK, "{repeated}");
        assert_eq!(repeated["dedup_hit"], true);
        assert_eq!(repeated["memory_id"], allowed["memory_id"]);
        for (caller, rejected_body) in [(OTHER, body(Some(key))), (AGENT, body(Some(&other_key)))] {
            let (status, denied) = rt.block_on(post(&router, caller, &rejected_body));
            assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
            assert_eq!(denied["code"], "ATTESTATION_FAILED");
        }
        let mut tampered = body(Some(key));
        tampered["content"] = json!("changed after signing");
        let (status, denied) = rt.block_on(post(&router, AGENT, &tampered));
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(denied["code"], "ATTESTATION_FAILED");
    }
    for posture in ["0", "false"] {
        let _env = common::MultiEnvVarGuard::apply(&[
            ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", Some(posture)),
            ("AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST", Some(&allowlist)),
        ]);
        ai_memory::audit::init(audit_path, true, false).expect("audit sink");
        let (status, allowed) = rt.block_on(post(&router, AGENT, &body(None)));
        assert_eq!(status, StatusCode::CREATED, "{allowed}");
        assert_eq!(allowed["attest_level"], "self_signed");
        let audit = std::fs::read_to_string(audit_path).expect("audit evidence");
        assert!(audit.contains("unsigned HTTP attestation opt-out"));
        // An explicit opt-out does not admit a signed impersonation.
        let (status, denied) = rt.block_on(post(&router, AGENT, &body(Some(&other_key))));
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(denied["code"], "ATTESTATION_FAILED");
    }
    let _env = common::MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", Some("0")),
        ("AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST", None),
    ]);
    let (status, denied) = rt.block_on(post(&router, AGENT, &body(Some(key))));
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["code"], "ATTESTATION_FAILED");
}

#[test]
fn sqlite_http_capture_posture_binding_and_idempotency_3406() {
    let _serial = TEST_LOCK.lock().expect("test serialization");
    let dir = tempfile::tempdir().expect("fixture directory");
    let path = dir.path().join("capture.db");
    let app = sqlite_app_state(&path);
    let conn = ai_memory::db::open(&path).expect("seed connection");
    let key = SigningKey::from_bytes(&[42; 32]);
    for agent in [AGENT, OTHER] {
        ai_memory::storage::register_agent(&conn, agent, "nhi", &[]).expect("register");
    }
    ai_memory::storage::bind_agent_pubkey_with_signing_key(&conn, AGENT, &key)
        .expect("possession bind");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    exercise(app, &key, &dir.path().join("audit.jsonl"), &rt);
    let spoofed: i64 = conn.query_row("SELECT count(*) FROM memories WHERE namespace = 'capture-3406' AND json_extract(metadata, '$.attest_level') = 'agent_attested'", [], |r| r.get(0)).expect("attestation census");
    assert_eq!(
        spoofed, 0,
        "legacy host envelope must never mint agent_attested"
    );
}

#[cfg(feature = "sal-postgres")]
#[test]
fn live_postgres_http_capture_posture_binding_and_idempotency_3406() {
    use ai_memory::identity::pubkey_bind::{PossessionProof, sign_bind_challenge};
    use ai_memory::store::CallerContext;
    let _serial = TEST_LOCK.lock().expect("test serialization");
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("live pg URL REQUIRED for #3406; no soft skip");
    let dir = tempfile::tempdir().expect("fixture directory");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let app = rt.block_on(postgres_app_state(&url));
    let key = SigningKey::from_bytes(&[42; 32]);
    let public = ai_memory::identity::keypair::encode_public_base64(&key.verifying_key());
    let ctx = CallerContext::for_admin("test:3406");
    rt.block_on(async {
        for agent in [AGENT, OTHER] {
            app.store
                .register_agent(
                    &ctx,
                    &ai_memory::models::AgentRegistration {
                        agent_id: agent.into(),
                        agent_type: "nhi".into(),
                        capabilities: vec![],
                        registered_at: chrono::Utc::now().to_rfc3339(),
                        last_seen_at: chrono::Utc::now().to_rfc3339(),
                    },
                )
                .await
                .expect("register live pg");
        }
        let issued = app
            .store
            .issue_pubkey_bind_challenge(&ctx, AGENT, &public, "test:3406")
            .await
            .expect("challenge");
        let signature = sign_bind_challenge(&key, &issued);
        let taken = app
            .store
            .consume_pubkey_bind_challenge(&ctx, AGENT, &issued.nonce_b64)
            .await
            .expect("consume")
            .expect("unspent");
        let proof = PossessionProof::verify_challenge_response(taken, AGENT, &public, &signature)
            .expect("proof");
        app.store
            .bind_agent_pubkey(&ctx, AGENT, &public, proof)
            .await
            .expect("bound pg key");
    });
    exercise(app, &key, &dir.path().join("audit.jsonl"), &rt);
}
