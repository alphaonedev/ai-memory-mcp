// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1539 — `PUT /api/v1/agents/{id}/pubkey` route integration pin.
//!
//! Pre-#1539 there was NO HTTP/admin surface to bind an agent
//! attestation pubkey: attesting clients under
//! `REQUIRE_AGENT_ATTESTATION=1` needed an out-of-band DB write (the
//! do-1461 provisioning bound via ssh+psql on the region pg node).
//! This pins: admin gating, pubkey validation, the happy-path bind
//! through the SAL trait, and the unregistered-agent error shape.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const ADMIN_CALLER: &str = "ai:ops-admin";
const TARGET_AGENT: &str = "ai:attesting-client";

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1539-bind-pubkey")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn build_app_fixture() -> (AppState, NamedTempFile) {
    // Authenticated-deployment posture so admin header role-claims
    // resolve (#1570) — same as tests/share_http_route_1095.rs.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
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
    let app_state = AppState {
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
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ADMIN_CALLER.to_string()]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (app_state, f)
}

fn router_for_state(app_state: AppState) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn build_router_fixture() -> (axum::Router, NamedTempFile) {
    let (state, f) = build_app_fixture();
    (router_for_state(state), f)
}

async fn register_target_agent(router: &axum::Router) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/agents")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_CALLER)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "agent_id": TARGET_AGENT,
                "agent_type": "ai:test",
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "agent registration must succeed; got {}",
        resp.status()
    );
}

fn valid_keypair() -> ai_memory::identity::keypair::AgentKeypair {
    let dir = fresh_dir();
    // SAFETY-free key-dir override via the documented env knob is not
    // needed — `generate` takes no paths; the keypair lives in memory.
    let _ = dir;
    ai_memory::identity::keypair::generate("test-bind-1539").expect("generate keypair")
}

fn valid_pubkey_b64() -> String {
    valid_keypair().public_base64()
}

fn put_pubkey(agent: &str, caller: &str, pubkey_b64: &str) -> Request<Body> {
    put_pubkey_body(
        agent,
        caller,
        &serde_json::json!({ "pubkey_b64": pubkey_b64 }),
    )
}

fn put_pubkey_body(agent: &str, caller: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/agents/{agent}/pubkey"))
        .header("content-type", "application/json")
        .header("x-agent-id", caller)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// #3464 — run the challenge/response the bind now requires against `router`
/// and return the `PUT` body. The daemon issues a single-use nonce for this
/// (agent, candidate key) pair; the holder of the private half signs the
/// domain-separated transcript.
async fn take_challenge(
    router: &axum::Router,
    agent: &str,
    caller: &str,
    pubkey: &str,
) -> ai_memory::identity::pubkey_bind::BindChallenge {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/agents/{agent}/pubkey/challenge"))
        .header("content-type", "application/json")
        .header("x-agent-id", caller)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "pubkey_b64": pubkey })).unwrap(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the bind challenge must be issued to an admin caller"
    );
    let body = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    ai_memory::identity::pubkey_bind::BindChallenge {
        nonce_b64: v["nonce"].as_str().expect("nonce").to_string(),
        agent_id: agent.to_string(),
        pubkey_b64: pubkey.to_string(),
        expires_at: v["expires_at"].as_str().expect("expires_at").to_string(),
    }
}

/// Answer a fresh challenge with `kp` and build the `PUT` body.
async fn proved_bind_body(
    router: &axum::Router,
    agent: &str,
    caller: &str,
    kp: &ai_memory::identity::keypair::AgentKeypair,
) -> serde_json::Value {
    let pubkey = kp.public_base64();
    let challenge = take_challenge(router, agent, caller, &pubkey).await;
    let proof = ai_memory::identity::pubkey_bind::sign_bind_challenge(
        kp.private.as_ref().expect("generated private key"),
        &challenge,
    );
    serde_json::json!({
        "pubkey_b64": pubkey,
        "nonce": challenge.nonce_b64,
        "proof_b64": proof,
    })
}

/// Happy path: admin binds a valid Ed25519 pubkey to a registered
/// agent → 200 `{bound:true}`.
#[tokio::test]
async fn bind_pubkey_route_happy_path_1539() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let kp = valid_keypair();
    let body = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admin bind of a valid pubkey with a valid possession proof must return 200"
    );
    let body = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["bound"], serde_json::json!(true));
    assert_eq!(v["agent_id"], serde_json::json!(TARGET_AGENT));
}

/// Non-admin caller → 403 (the require_admin gate; generic body, no
/// allowlist probing).
#[tokio::test]
async fn bind_pubkey_route_requires_admin_1539() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let resp = router
        .clone()
        .oneshot(put_pubkey(
            TARGET_AGENT,
            "ai:not-an-admin",
            &valid_pubkey_b64(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "non-admin caller must be refused"
    );
}

/// Garbage pubkey → 400 before any store call.
#[tokio::test]
async fn bind_pubkey_route_rejects_invalid_pubkey_1539() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let resp = router
        .clone()
        .oneshot(put_pubkey(TARGET_AGENT, ADMIN_CALLER, "not-a-key"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "invalid pubkey must be rejected with 400"
    );
}

/// Unregistered agent → the storage layer's typed error surfaces (the
/// bind pre-checks registration), not a silent 200.
#[tokio::test]
async fn bind_pubkey_route_unregistered_agent_errors_1539() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();

    // #3464 — present a VALID possession proof so this test still exercises the
    // registration pre-check rather than stopping at the proof gate.
    let kp = valid_keypair();
    let body = proved_bind_body(&router, "ai:never-registered", ADMIN_CALLER, &kp).await;
    let resp = router
        .clone()
        .oneshot(put_pubkey_body("ai:never-registered", ADMIN_CALLER, &body))
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "binding to an unregistered agent must not succeed; got {}",
        resp.status()
    );
}

/// v1.0.0 #3464 (security-high) — DENIED: an admin who does NOT hold the
/// candidate key cannot bind it.
///
/// The attacker is a legitimate admin. They take the challenge for the
/// victim's key and answer it with a key they DO hold. The signature is
/// perfectly valid — under the wrong key — and must be refused, or the admin
/// role alone would let them mint `agent_attested` writes as the victim.
#[tokio::test]
async fn bind_pubkey_route_refuses_a_proof_from_another_key_3464() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let victim = valid_keypair();
    let attacker = ai_memory::identity::keypair::generate("attacker-3464").expect("keypair");
    // A genuine challenge for the VICTIM's key — the exact transcript the
    // server will verify against...
    let challenge =
        take_challenge(&router, TARGET_AGENT, ADMIN_CALLER, &victim.public_base64()).await;
    // ...answered with the ATTACKER's key. The signature is well-formed and
    // over the RIGHT bytes; only the key is wrong, which is the whole defect.
    let forged = ai_memory::identity::pubkey_bind::sign_bind_challenge(
        attacker.private.as_ref().expect("private"),
        &challenge,
    );
    let body = serde_json::json!({
        "pubkey_b64": victim.public_base64(),
        "nonce": challenge.nonce_b64,
        "proof_b64": forged,
    });
    let resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "#3464 REGRESSED: a bind answered by a key OTHER than the candidate must be \
         refused — admin authority says a caller may enroll a key, never WHICH key"
    );
}

/// The issue's exact attack survives a candidate-only PoP check unless the
/// store also requires the target identity's existing trust anchor. Here the
/// administrator genuinely owns and signs with the candidate key, but may not
/// replace the victim's already-bound key.
#[tokio::test]
async fn admin_owned_candidate_cannot_hijack_bound_agent_over_http_3464() {
    let _dir = fresh_dir();
    let (router, file) = build_router_fixture();
    register_target_agent(&router).await;

    let victim = valid_keypair();
    let bootstrap = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &victim).await;
    let response = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &bootstrap))
        .await
        .expect("bootstrap response");
    assert_eq!(response.status(), StatusCode::OK);

    let attacker = ai_memory::identity::keypair::generate("admin-owned-3464").expect("keypair");
    let hijack = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &attacker).await;
    let response = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &hijack))
        .await
        .expect("hijack response");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "admin role plus possession of the attacker's candidate key must not replace the victim"
    );
    let bytes = axum::body::to_bytes(response.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        body["error"],
        ai_memory::errors::msg::BIND_PROOF_REFUSED,
        "identity-state refusals use the same opaque envelope as stale/invalid proofs"
    );

    let conn = ai_memory::db::open(file.path()).expect("inspect db");
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, TARGET_AGENT).expect("read"),
        Some(victim.public_base64()),
        "the victim key remains live"
    );
    assert_eq!(
        ai_memory::db::agent_pubkey_versions(&conn, TARGET_AGENT)
            .expect("history")
            .len(),
        1,
        "the refused hijack leaves no history mutation"
    );
}

/// v1.0.0 #3464 — DENIED: a bind with no proof at all is refused, and the
/// refusal comes from the proof gate (403), not a body-parse error, so the
/// admin gate and validation still run first.
#[tokio::test]
async fn bind_pubkey_route_refuses_a_bind_with_no_proof_3464() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let resp = router
        .clone()
        .oneshot(put_pubkey(TARGET_AGENT, ADMIN_CALLER, &valid_pubkey_b64()))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a legacy pre-#3464 body carries no possession proof and must fail CLOSED"
    );
}

/// v1.0.0 #3464 — DENIED: a challenge answers exactly once.
#[tokio::test]
async fn bind_pubkey_route_challenge_is_single_use_3464() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let kp = valid_keypair();
    let body = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let first = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &body))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK, "the honest bind succeeds");

    let replay = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &body))
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        StatusCode::FORBIDDEN,
        "a consumed nonce must never admit a second bind"
    );
}

/// v1.0.0 #3464 — DENIED: expiry is enforced by the durable consume, not only
/// by the verifier's wall-clock check, and shares the replay refusal envelope.
#[tokio::test]
async fn bind_pubkey_route_refuses_stale_durable_challenge_3464() {
    let _dir = fresh_dir();
    let (router, file) = build_router_fixture();
    register_target_agent(&router).await;

    let kp = valid_keypair();
    let challenge = take_challenge(&router, TARGET_AGENT, ADMIN_CALLER, &kp.public_base64()).await;
    let proof = ai_memory::identity::pubkey_bind::sign_bind_challenge(
        kp.private.as_ref().expect("private"),
        &challenge,
    );
    let nonce = challenge.nonce_b64.clone();
    let conn = ai_memory::db::open(file.path()).expect("inspect challenge DB");
    let past = ai_memory::validate::canonical_rfc3339(
        &(chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339(),
    );
    conn.execute(
        "UPDATE agent_pubkey_challenges SET expires_at = ?1 WHERE nonce = ?2",
        rusqlite::params![past, nonce],
    )
    .expect("expire durable challenge");
    drop(conn);

    let body = serde_json::json!({
        "pubkey_b64": kp.public_base64(),
        "nonce": nonce,
        "proof_b64": proof,
    });
    let response = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &body))
        .await
        .expect("stale response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(response.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body");
    let response_body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        response_body["error"],
        ai_memory::errors::msg::BIND_PROOF_REFUSED
    );
    let conn = ai_memory::db::open(file.path()).expect("inspect refused bind");
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, TARGET_AGENT).expect("read"),
        None
    );
}

/// v1.0.0 #3464 — DENIED: the challenge endpoint is admin-gated too, so a
/// non-admin cannot even obtain the nonce.
#[tokio::test]
async fn bind_pubkey_challenge_requires_admin_3464() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/agents/{TARGET_AGENT}/pubkey/challenge"))
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:not-an-admin")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "pubkey_b64": valid_pubkey_b64() })).unwrap(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the bind challenge is admin-gated, exactly like the bind it precedes"
    );
}

/// Unsigned malformed timestamps must take the per-row refusal path even
/// when their claimed author has a populated key-history ledger.
async fn unsigned_malformed_import_is_per_row(router: &axum::Router) {
    let stamp = chrono::Utc::now().to_rfc3339();
    let valid = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: format!("valid-import-{}", uuid::Uuid::new_v4()),
        namespace: "import-3464".to_string(),
        content: "A valid neighboring row must survive an unsigned malformed timestamp."
            .to_string(),
        tier: ai_memory::models::Tier::Long,
        created_at: stamp.clone(),
        updated_at: stamp,
        metadata: serde_json::json!({"agent_id": TARGET_AGENT}),
        ..ai_memory::models::Memory::default()
    };
    let mut malformed = valid.clone();
    malformed.id = uuid::Uuid::new_v4().to_string();
    malformed.title = format!("invalid-import-{}", uuid::Uuid::new_v4());
    malformed.created_at = "unsigned-malformed-created-at".to_string();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/import")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_CALLER)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({"memories": [malformed, valid]})).expect("body"),
        ))
        .expect("request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("import response");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "malformed unsigned row must not abort batch"
    );
    let bytes = axum::body::to_bytes(response.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body");
    let result: serde_json::Value = serde_json::from_slice(&bytes).expect("result JSON");
    assert_eq!(
        result["imported"], 1,
        "valid neighbor is imported: {result}"
    );
    assert_eq!(
        result["errors"].as_array().expect("per-row errors").len(),
        1,
        "invalid row is refused: {result}"
    );
}

/// Drive the real admin routes through bootstrap, retry, hijack, cross-agent,
/// stale, replay, and closed-history refusal on the supplied backend.
async fn public_bind_matrix(state: AppState) {
    let router = router_for_state(state.clone());
    register_target_agent(&router).await;
    let owner = valid_keypair();
    let attacker = ai_memory::identity::keypair::generate("ai:matrix-attacker").expect("key");
    let submit = |body: serde_json::Value| {
        let router = router.clone();
        async move {
            router
                .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &body))
                .await
                .expect("HTTP response")
                .status()
        }
    };
    let bootstrap = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &owner).await;
    assert_eq!(submit(bootstrap.clone()).await, StatusCode::OK);
    assert_eq!(submit(bootstrap).await, StatusCode::FORBIDDEN, "replay");
    unsigned_malformed_import_is_per_row(&router).await;
    let retry = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &owner).await;
    assert_eq!(submit(retry).await, StatusCode::OK, "same open key");
    let hijack = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &attacker).await;
    assert_eq!(
        submit(hijack).await,
        StatusCode::FORBIDDEN,
        "admin owns candidate, not target identity"
    );
    let wrong_agent = proved_bind_body(&router, "ai:matrix-other", ADMIN_CALLER, &owner).await;
    assert_eq!(
        submit(wrong_agent).await,
        StatusCode::FORBIDDEN,
        "wrong agent challenge"
    );
    let expired_body = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &owner).await;
    let nonce = expired_body["nonce"].as_str().expect("nonce");
    let past = ai_memory::validate::canonical_rfc3339(
        &(chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339(),
    );
    match state.storage_backend {
        ai_memory::handlers::StorageBackend::Sqlite => {
            let conn = state.db.lock().await;
            conn.0
                .execute(
                    "UPDATE agent_pubkey_challenges SET expires_at = ?1 WHERE nonce = ?2",
                    rusqlite::params![past, nonce],
                )
                .expect("expire own challenge");
        }
        ai_memory::handlers::StorageBackend::Postgres => {
            #[cfg(feature = "sal-postgres")]
            {
                let url =
                    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required");
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&url)
                    .await
                    .expect("own PG database");
                sqlx::query("UPDATE agent_pubkey_challenges SET expires_at = $1 WHERE nonce = $2")
                    .bind(&past)
                    .bind(nonce)
                    .execute(&pool)
                    .await
                    .expect("expire own challenge");
                pool.close().await;
            }
            #[cfg(not(feature = "sal-postgres"))]
            panic!("PostgreSQL fixture requires sal-postgres");
        }
    }
    assert_eq!(
        submit(expired_body).await,
        StatusCode::FORBIDDEN,
        "stale challenge"
    );
    #[cfg(feature = "sal")]
    {
        let ctx = ai_memory::store::CallerContext::for_admin(ADMIN_CALLER);
        assert_eq!(
            state
                .store
                .agent_pubkey(TARGET_AGENT)
                .await
                .expect("current key"),
            Some(owner.public_base64())
        );
        state
            .store
            .revoke_agent_pubkey(&ctx, TARGET_AGENT)
            .await
            .expect("revoke");
    }
    #[cfg(not(feature = "sal"))]
    {
        let conn = state.db.lock().await;
        assert_eq!(
            ai_memory::db::agent_pubkey(&conn.0, TARGET_AGENT).expect("current key"),
            Some(owner.public_base64())
        );
        ai_memory::db::revoke_agent_pubkey(&conn.0, TARGET_AGENT).expect("revoke");
    }
    for candidate in [&owner, &attacker] {
        let reopen = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, candidate).await;
        assert_eq!(
            submit(reopen).await,
            StatusCode::FORBIDDEN,
            "closed history stays closed"
        );
    }
}

#[tokio::test]
async fn sqlite_admin_route_security_matrix_3464() {
    let (state, _file) = build_app_fixture();
    public_bind_matrix(state).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_admin_route_security_matrix_3464() {
    let (mut state, _file) = build_app_fixture();
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    state.store = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("own PG database"),
    );
    state.storage_backend = ai_memory::handlers::StorageBackend::Postgres;
    public_bind_matrix(state).await;
}
