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
/// #8494 — the bootstrap bind needs a KEY-AUTHENTICATED admin, so the admin's
/// enrolled per-agent api key is presented as `X-API-Key` on every admin call.
const ADMIN_TOKEN: &str = "1539-admin-per-agent-token-0123456789abcdef";

/// #8494 — a live registry holding the admin's enrolled per-agent key.
fn admin_enrolled_registry() -> Arc<ai_memory::handlers::identity_binding::EnrolledAgentKeys> {
    let registry = Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty());
    registry.mutate(|m| {
        *m = std::collections::HashMap::from([(
            ai_memory::handlers::identity_binding::api_key_sha256_hex(ADMIN_TOKEN),
            ADMIN_CALLER.to_string(),
        )]);
    });
    registry
}

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
        enrolled_agent_keys: admin_enrolled_registry(),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (app_state, f)
}

fn router_for_state(app_state: AppState) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::clone(&app_state.enrolled_agent_keys),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
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
        .header("x-api-key", ADMIN_TOKEN)
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
        .header("x-api-key", ADMIN_TOKEN)
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
        .header("x-api-key", ADMIN_TOKEN)
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

/// #10109 (A2, SQLite): an idempotent same-key HTTP rebind changes nothing and
/// must execute zero writes — every row's `write_signature`, `updated_at`,
/// `metadata`, and `content` (both the `_agents` registration row and signed
/// user memories) stays byte-identical before and after, and
/// `agent_pubkey_history` keeps one row.
#[tokio::test]
async fn sqlite_same_key_rebind_writes_nothing_10109() {
    type MemoryRowSnap = (String, String, String, String);
    type HistoryRowSnap = (i64, String, String, Option<String>);
    let _dir = fresh_dir();
    let (router, file) = build_router_fixture();
    register_target_agent(&router).await;

    let kp = valid_keypair();
    let first_body = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let first_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &first_body))
        .await
        .expect("first bind response");
    assert_eq!(first_resp.status(), StatusCode::OK);

    // Write a signed regular memory row AND stamp a write_signature on the
    // `_agents` registration row so any `UPDATE memories` is immediately visible
    // via both `updated_at` and `write_signature`.
    let agent_title = ai_memory::models::agent_registration_title(TARGET_AGENT);
    let conn = ai_memory::db::open(file.path()).expect("open db");
    let now = ai_memory::identity::attest::now_attestable_rfc3339();
    let mut signed_mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "rebind-noop-10109".to_string(),
        title: "signed row 10109".to_string(),
        content: "signed body that must remain byte-identical across same-key rebind".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({
            "agent_id": TARGET_AGENT,
            "attest_level": "agent_attested",
        }),
        ..ai_memory::models::Memory::default()
    };
    let sig = ai_memory::identity::attest::sign_memory_write(&kp, &signed_mem, TARGET_AGENT)
        .expect("sign memory");
    ai_memory::identity::attest::persist_write_signature(&mut signed_mem, &sig);
    ai_memory::db::insert(&conn, &signed_mem).expect("insert signed memory");
    // Stamp a write_signature marker on the `_agents` row (preserving the
    // authoritative agent_pubkey / pubkey_bound_at projection).
    conn.execute(
        "UPDATE memories
         SET metadata = json_set(metadata, '$.write_signature', 'sentinel-sig-10109', '$.attest_level', 'agent_attested'),
             content  = json_set(content,  '$.write_signature', 'sentinel-sig-10109', '$.attest_level', 'agent_attested')
         WHERE namespace = ?1 AND title = ?2",
        rusqlite::params![ai_memory::models::AGENTS_NAMESPACE, &agent_title],
    )
    .expect("stamp sentinel signature on _agents row");

    let snapshot = |c: &rusqlite::Connection| -> (Vec<MemoryRowSnap>, Vec<HistoryRowSnap>) {
        let mut stmt = c
            .prepare("SELECT id, updated_at, metadata, content FROM memories ORDER BY id")
            .expect("prepare memories");
        let memories = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("query memories")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect memories");
        let mut hstmt = c
            .prepare(
                "SELECT version, pubkey_b64, bound_at, superseded_at
                 FROM agent_pubkey_history WHERE agent_id = ?1 ORDER BY version",
            )
            .expect("prepare history");
        let history = hstmt
            .query_map([TARGET_AGENT], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .expect("query history")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect history");
        (memories, history)
    };
    let before = snapshot(&conn);
    assert_eq!(before.1.len(), 1, "one history row after first bind");
    drop(conn);

    tokio::time::sleep(std::time::Duration::from_millis(15)).await;

    let rebind_body = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let rebind_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &rebind_body))
        .await
        .expect("rebind response");
    assert_eq!(rebind_resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(rebind_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("rebind body bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("rebind json");
    assert_eq!(
        body,
        serde_json::json!({ "bound": true, "agent_id": TARGET_AGENT }),
        "same-key rebind returns the exact same success payload as first bind"
    );

    let conn = ai_memory::db::open(file.path()).expect("reopen db");
    let after = snapshot(&conn);
    assert_eq!(
        after.0, before.0,
        "same-key HTTP rebind must write nothing to memories (updated_at, write_signature, metadata, content byte-identical)"
    );
    assert_eq!(
        after.1, before.1,
        "same-key HTTP rebind must write nothing to agent_pubkey_history"
    );
}

/// #10109 (A2, PostgreSQL): live PostgreSQL parity for same-key HTTP rebind
/// writing nothing to `memories` or `agent_pubkey_history`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_same_key_rebind_writes_nothing_10109() {
    let (mut state, _file) = build_app_fixture();
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let pg_store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("own PG database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("inspect PG pool");
    state.store = Arc::new(pg_store);
    state.storage_backend = ai_memory::handlers::StorageBackend::Postgres;
    let router = router_for_state(state);

    let agent = format!("ai:pg-rebind-noop-10109-{}", uuid::Uuid::new_v4());
    let reg_req = Request::builder()
        .method("POST")
        .uri("/api/v1/agents")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_CALLER)
        .header("x-api-key", ADMIN_TOKEN)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "agent_id": agent,
                "agent_type": "ai:test",
            }))
            .expect("json"),
        ))
        .expect("reg req");
    let reg_resp = router.clone().oneshot(reg_req).await.expect("reg resp");
    assert_eq!(reg_resp.status(), StatusCode::CREATED);

    let kp = valid_keypair();
    let first_body = proved_bind_body(&router, &agent, ADMIN_CALLER, &kp).await;
    let first_resp = router
        .clone()
        .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &first_body))
        .await
        .expect("first bind");
    assert_eq!(first_resp.status(), StatusCode::OK);

    let agent_title = ai_memory::models::agent_registration_title(&agent);
    // Stamp a write_signature sentinel on the `_agents` row so any UPDATE
    // rewriting metadata/content or moving updated_at is caught immediately.
    sqlx::query(
        "UPDATE memories
         SET metadata = jsonb_set(jsonb_set(metadata, '{write_signature}', '\"sentinel-pg-10109\"'::jsonb, true), '{attest_level}', '\"agent_attested\"'::jsonb, true),
             content  = (jsonb_set(jsonb_set(content::jsonb, '{write_signature}', '\"sentinel-pg-10109\"'::jsonb, true), '{attest_level}', '\"agent_attested\"'::jsonb, true))::text
         WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::models::AGENTS_NAMESPACE)
    .bind(&agent_title)
    .execute(&pool)
    .await
    .expect("stamp sentinel sig on PG _agents row");

    let before_row: (String, serde_json::Value, String) = sqlx::query_as(
        "SELECT updated_at::text, metadata, content FROM memories WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::models::AGENTS_NAMESPACE)
    .bind(&agent_title)
    .fetch_one(&pool)
    .await
    .expect("before _agents row");
    let before_hist: Vec<(i64, String, String, Option<String>)> = sqlx::query_as(
        "SELECT version, pubkey_b64, bound_at::text, superseded_at::text
         FROM agent_pubkey_history WHERE agent_id = $1 ORDER BY version",
    )
    .bind(&agent)
    .fetch_all(&pool)
    .await
    .expect("before history");
    assert_eq!(before_hist.len(), 1, "one history row after first bind");

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let rebind_body = proved_bind_body(&router, &agent, ADMIN_CALLER, &kp).await;
    let rebind_resp = router
        .clone()
        .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &rebind_body))
        .await
        .expect("rebind resp");
    assert_eq!(rebind_resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(rebind_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        body,
        serde_json::json!({ "bound": true, "agent_id": agent })
    );

    let after_row: (String, serde_json::Value, String) = sqlx::query_as(
        "SELECT updated_at::text, metadata, content FROM memories WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::models::AGENTS_NAMESPACE)
    .bind(&agent_title)
    .fetch_one(&pool)
    .await
    .expect("after _agents row");
    let after_hist: Vec<(i64, String, String, Option<String>)> = sqlx::query_as(
        "SELECT version, pubkey_b64, bound_at::text, superseded_at::text
         FROM agent_pubkey_history WHERE agent_id = $1 ORDER BY version",
    )
    .bind(&agent)
    .fetch_all(&pool)
    .await
    .expect("after history");
    assert_eq!(
        after_row, before_row,
        "PostgreSQL same-key HTTP rebind must write nothing (updated_at, write_signature, pubkey_bound_at, content unchanged)"
    );
    assert_eq!(
        after_hist, before_hist,
        "PostgreSQL same-key HTTP rebind must not modify agent_pubkey_history"
    );
}

/// #10109 (operator log): the `existing_identity_requires_lineage` refusal
/// emits one `tracing::warn!` naming `ai-memory identity succeed` and the
/// `agent_id` only (no pubkey, no nonce, no proof), while keeping the HTTP 403
/// wire body equal to `BIND_PROOF_REFUSED`. Runs in an isolated child process
/// so the global tracing callsite cache cannot race sibling tests.
#[test]
fn bind_pubkey_route_existing_identity_refusal_logs_succession_without_secrets_10109() {
    let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "bind_pubkey_route_existing_identity_refusal_log_child_10109",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("spawn log child");
    assert!(
        out.status.success(),
        "log child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
#[ignore = "child helper of bind_pubkey_route_existing_identity_refusal_logs_succession_without_secrets_10109"]
async fn bind_pubkey_route_existing_identity_refusal_log_child_10109() {
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);
    struct GuardWriter(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for GuardWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = GuardWriter;
        fn make_writer(&'a self) -> Self::Writer {
            GuardWriter(Arc::clone(&self.0))
        }
    }

    let buf = SharedBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_target(true)
        .with_writer(buf.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let _dir = fresh_dir();
    let (router, _file) = build_router_fixture();
    register_target_agent(&router).await;

    let victim = valid_keypair();
    let bootstrap = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &victim).await;
    let ok_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &bootstrap))
        .await
        .expect("bootstrap");
    assert_eq!(ok_resp.status(), StatusCode::OK);

    let attacker = ai_memory::identity::keypair::generate("attacker-log-10109").expect("attacker");
    let hijack = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &attacker).await;
    let attacker_pub = attacker.public_base64();
    let hijack_nonce = hijack["nonce"].as_str().expect("nonce").to_string();
    let hijack_proof = hijack["proof_b64"].as_str().expect("proof").to_string();

    let resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &hijack))
        .await
        .expect("hijack");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        body,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED }),
        "HTTP response body must remain exact opaque BIND_PROOF_REFUSED"
    );

    let captured = String::from_utf8(buf.0.lock().expect("lock").clone()).expect("utf8");
    let matching_lines: Vec<&str> = captured
        .lines()
        .filter(|l| l.contains("identity.bind.requires_succession"))
        .collect();
    assert_eq!(
        matching_lines.len(),
        1,
        "expected exactly one warn event on identity.bind.requires_succession; captured:\n{captured}"
    );
    let line = matching_lines[0];
    assert!(
        line.contains("WARN")
            && line.contains("ai-memory identity succeed")
            && line.contains(TARGET_AGENT),
        "operator warn must name ai-memory identity succeed and agent_id: {line}"
    );
    for forbidden in [
        &attacker_pub,
        &victim.public_base64(),
        &hijack_nonce,
        &hijack_proof,
    ] {
        assert!(
            !line.contains(forbidden.as_str()),
            "operator warn must never log key/nonce/proof material ({forbidden:?}): {line}"
        );
    }
}

/// #10197 / #10199 (SQLite): enrolling a self-signed genesis lineage record for
/// an agent whose key is already bound must succeed AND leave `_agents`
/// (`write_signature`, `attest_level`, `updated_at`, `pubkey_bound_at`,
/// `content`), `agent_pubkey_history`, `memory_revisions`, and
/// `row_attestations` completely unchanged (only `agent_lineage` and its
/// witness event advance).
#[tokio::test]
async fn sqlite_genesis_after_bind_preserves_agent_row_10197() {
    let _dir = fresh_dir();
    let (router, file) = build_router_fixture();
    register_target_agent(&router).await;

    let kp = valid_keypair();
    let first_body = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let first_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &first_body))
        .await
        .expect("first bind");
    assert_eq!(first_resp.status(), StatusCode::OK);

    let agent_title = ai_memory::models::agent_registration_title(TARGET_AGENT);
    let conn = ai_memory::db::open(file.path()).expect("open db");
    conn.execute(
        "UPDATE memories
         SET metadata = json_set(metadata, '$.write_signature', 'sentinel-sig-10197', '$.attest_level', 'agent_attested'),
             content  = json_set(content,  '$.write_signature', 'sentinel-sig-10197', '$.attest_level', 'agent_attested')
         WHERE namespace = '_agents' AND title = ?1",
        [&agent_title],
    )
    .expect("stamp sentinel write_signature");

    let snap = |c: &rusqlite::Connection| {
        let agent_row: (String, String, String) = c
            .query_row(
                "SELECT updated_at, metadata, content FROM memories WHERE namespace = '_agents' AND title = ?1",
                [&agent_title],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("agent row");
        let mut hist_stmt = c
            .prepare(
                "SELECT version, pubkey_b64, bind_authority, bound_at, superseded_at
                 FROM agent_pubkey_history WHERE agent_id = ?1 ORDER BY version",
            )
            .expect("prepare history");
        let hist_rows: Vec<(i64, String, String, String, Option<String>)> = hist_stmt
            .query_map([TARGET_AGENT], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .expect("query history")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect history");
        let counts: (i64, i64, i64) = (
            c.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
                .expect("memories count"),
            c.query_row("SELECT COUNT(*) FROM memory_revisions", [], |r| r.get(0))
                .expect("revisions count"),
            c.query_row("SELECT COUNT(*) FROM row_attestations", [], |r| r.get(0))
                .expect("attestations count"),
        );
        (agent_row, hist_rows, counts)
    };
    let witness_rows = |c: &rusqlite::Connection| -> Vec<(String, Vec<u8>)> {
        let mut stmt = c
            .prepare(
                "SELECT event_type, payload_hash FROM signed_events
                 WHERE agent_id = ?1 AND event_type = ?2 ORDER BY id",
            )
            .expect("prepare witness");
        stmt.query_map(
            rusqlite::params![
                TARGET_AGENT,
                ai_memory::signed_events::event_types::IDENTITY_LINEAGE_GENESIS
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("query witness")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect witness")
    };
    let before = snap(&conn);
    let [(v1, _, _, _, sup1)] = before.1.as_slice() else {
        panic!(
            "expected one open history row after initial bind, got {:?}",
            before.1
        );
    };
    assert_eq!(*v1, 1);
    assert!(sup1.is_none(), "initial bind history row must be open");
    assert_eq!(
        witness_rows(&conn),
        Vec::<(String, Vec<u8>)>::new(),
        "#10230: zero genesis witness rows before enroll_lineage"
    );

    std::thread::sleep(std::time::Duration::from_millis(15));

    let recovery_kp =
        ai_memory::identity::keypair::generate("recovery-10197").expect("recovery keypair");
    let record =
        ai_memory::db::enroll_lineage(&conn, TARGET_AGENT, &kp, Some(&recovery_kp.public_base64()))
            .expect("#10197: genesis after same-key bind must succeed on SQLite");
    assert_eq!(record.epoch, 0);

    let after = snap(&conn);
    assert_eq!(
        after.0, before.0,
        "#10197: SQLite same-key genesis must leave _agents row byte-equal (write_signature, attest_level, updated_at, pubkey_bound_at unchanged)"
    );
    assert_eq!(
        after.1, before.1,
        "#10230: SQLite same-key genesis must leave full agent_pubkey_history rows (including superseded_at) byte-equal"
    );
    assert_eq!(
        after.2, before.2,
        "#10197: SQLite same-key genesis must not change row counts in memories, memory_revisions, or row_attestations"
    );
    let expected_witness_hash = record.witness_payload_hash().expect("witness payload hash");
    assert_eq!(
        witness_rows(&conn),
        vec![(
            ai_memory::signed_events::event_types::IDENTITY_LINEAGE_GENESIS.to_string(),
            expected_witness_hash,
        )],
        "#10230: SQLite same-key genesis must append exactly one signed_events witness row (0 -> 1) with matching event_type and payload_hash"
    );
    let lineage_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_lineage WHERE agent_id = ?1",
            [TARGET_AGENT],
            |r| r.get(0),
        )
        .expect("lineage count");
    assert_eq!(lineage_count, 1, "genesis lineage row recorded");
}

/// #10196 / #10198 & #10197 / #10199 (PostgreSQL): recording a self-signed
/// genesis lineage record on an already-bound agent MUST succeed on PostgreSQL
/// (matching SQLite) AND leave `_agents` (`write_signature`, `attest_level`,
/// `updated_at`, `pubkey_bound_at`, `content`), `agent_pubkey_history`,
/// `memory_revisions`, and `row_attestations` byte-identical.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_genesis_after_bind_succeeds_and_preserves_agent_row_10196() {
    use ai_memory::store::{CallerContext, MemoryStore as _};

    let (mut state, _file) = build_app_fixture();
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let pg_store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("own PG database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("inspect PG pool");
    let store_arc = Arc::new(pg_store);
    state.store = Arc::clone(&store_arc) as Arc<dyn ai_memory::store::MemoryStore>;
    state.storage_backend = ai_memory::handlers::StorageBackend::Postgres;
    let router = router_for_state(state);

    let agent = format!("ai:pg-genesis-10196-{}", uuid::Uuid::new_v4());
    let reg_req = Request::builder()
        .method("POST")
        .uri("/api/v1/agents")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_CALLER)
        .header("x-api-key", ADMIN_TOKEN)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "agent_id": agent,
                "agent_type": "ai:test",
            }))
            .expect("json"),
        ))
        .expect("reg req");
    let reg_resp = router.clone().oneshot(reg_req).await.expect("reg resp");
    assert_eq!(reg_resp.status(), StatusCode::CREATED);

    let kp = valid_keypair();
    let first_body = proved_bind_body(&router, &agent, ADMIN_CALLER, &kp).await;
    let first_resp = router
        .clone()
        .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &first_body))
        .await
        .expect("first bind");
    assert_eq!(first_resp.status(), StatusCode::OK);

    let agent_title = ai_memory::models::agent_registration_title(&agent);
    sqlx::query(
        "UPDATE memories
         SET metadata = jsonb_set(jsonb_set(metadata, '{write_signature}', '\"sentinel-pg-10196\"'::jsonb, true), '{attest_level}', '\"agent_attested\"'::jsonb, true),
             content  = (jsonb_set(jsonb_set(content::jsonb, '{write_signature}', '\"sentinel-pg-10196\"'::jsonb, true), '{attest_level}', '\"agent_attested\"'::jsonb, true))::text
         WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::models::AGENTS_NAMESPACE)
    .bind(&agent_title)
    .execute(&pool)
    .await
    .expect("stamp sentinel sig");

    let before_row: (String, serde_json::Value, String) = sqlx::query_as(
        "SELECT updated_at::text, metadata, content FROM memories WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::models::AGENTS_NAMESPACE)
    .bind(&agent_title)
    .fetch_one(&pool)
    .await
    .expect("before _agents row");
    let before_mem_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM memories WHERE title = $1 OR metadata->>'agent_id' = $2",
    )
    .bind(&agent_title)
    .bind(&agent)
    .fetch_one(&pool)
    .await
    .expect("before agent memories count");
    let before_hist: Vec<(i64, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT version, pubkey_b64, bind_authority, bound_at::text, superseded_at::text
         FROM agent_pubkey_history WHERE agent_id = $1 ORDER BY version",
    )
    .bind(&agent)
    .fetch_all(&pool)
    .await
    .expect("before history");
    let before_rev_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM memory_revisions WHERE memory_id IN (
            SELECT id FROM memories WHERE title = $1 OR metadata->>'agent_id' = $2
         )",
    )
    .bind(&agent_title)
    .bind(&agent)
    .fetch_one(&pool)
    .await
    .expect("before revisions");
    let before_attest_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM row_attestations WHERE agent_id = $1")
            .bind(&agent)
            .fetch_one(&pool)
            .await
            .expect("before attestations");
    let before_witnesses: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT event_type, payload_hash FROM signed_events
         WHERE agent_id = $1 AND event_type = $2 ORDER BY id",
    )
    .bind(&agent)
    .bind(ai_memory::signed_events::event_types::IDENTITY_LINEAGE_GENESIS)
    .fetch_all(&pool)
    .await
    .expect("before witnesses");
    assert_eq!(
        before_witnesses,
        Vec::<(String, Vec<u8>)>::new(),
        "#10230: PG zero genesis witness rows before append_lineage_record"
    );

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let genesis = ai_memory::identity::lineage::LineageRecord::genesis(
        &agent,
        &kp.public_base64(),
        None,
        &chrono::Utc::now().to_rfc3339(),
    );
    let sig_input = genesis.signing_input().expect("signing input");
    let sig = ed25519_dalek::Signer::sign(kp.private.as_ref().expect("private key"), &sig_input)
        .to_bytes()
        .to_vec();
    let ctx = CallerContext::for_admin(ADMIN_CALLER);
    store_arc
        .append_lineage_record(&ctx, &agent, &genesis, &sig)
        .await
        .expect("#10196: PostgreSQL genesis after same-key bind must succeed");

    let after_row: (String, serde_json::Value, String) = sqlx::query_as(
        "SELECT updated_at::text, metadata, content FROM memories WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::models::AGENTS_NAMESPACE)
    .bind(&agent_title)
    .fetch_one(&pool)
    .await
    .expect("after _agents row");
    let after_mem_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM memories WHERE title = $1 OR metadata->>'agent_id' = $2",
    )
    .bind(&agent_title)
    .bind(&agent)
    .fetch_one(&pool)
    .await
    .expect("after agent memories count");
    let after_hist: Vec<(i64, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT version, pubkey_b64, bind_authority, bound_at::text, superseded_at::text
         FROM agent_pubkey_history WHERE agent_id = $1 ORDER BY version",
    )
    .bind(&agent)
    .fetch_all(&pool)
    .await
    .expect("after history");
    let after_rev_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM memory_revisions WHERE memory_id IN (
            SELECT id FROM memories WHERE title = $1 OR metadata->>'agent_id' = $2
         )",
    )
    .bind(&agent_title)
    .bind(&agent)
    .fetch_one(&pool)
    .await
    .expect("after revisions");
    let after_attest_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM row_attestations WHERE agent_id = $1")
            .bind(&agent)
            .fetch_one(&pool)
            .await
            .expect("after attestations");
    let after_witnesses: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT event_type, payload_hash FROM signed_events
         WHERE agent_id = $1 AND event_type = $2 ORDER BY id",
    )
    .bind(&agent)
    .bind(ai_memory::signed_events::event_types::IDENTITY_LINEAGE_GENESIS)
    .fetch_all(&pool)
    .await
    .expect("after witnesses");
    let (lineage_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM agent_lineage WHERE agent_id = $1")
            .bind(&agent)
            .fetch_one(&pool)
            .await
            .expect("lineage count");
    assert_eq!(lineage_count, 1, "genesis lineage row recorded on PG");
    assert_eq!(
        after_row, before_row,
        "#10196/#10197: PostgreSQL same-key genesis must leave _agents byte-equal"
    );
    assert_eq!(
        after_mem_count, before_mem_count,
        "#10230: PostgreSQL same-key genesis must leave total memories count unchanged"
    );
    assert_eq!(
        after_hist, before_hist,
        "#10230: PostgreSQL same-key genesis must leave full agent_pubkey_history rows unchanged"
    );
    assert_eq!(
        after_rev_count, before_rev_count,
        "#10196: PostgreSQL same-key genesis must emit zero memory_revisions rows"
    );
    assert_eq!(
        after_attest_count, before_attest_count,
        "#10196: PostgreSQL same-key genesis must write zero row_attestations rows"
    );
    let expected_witness_hash = genesis
        .witness_payload_hash()
        .expect("witness payload hash");
    assert_eq!(
        after_witnesses,
        vec![(
            ai_memory::signed_events::event_types::IDENTITY_LINEAGE_GENESIS.to_string(),
            expected_witness_hash,
        )],
        "#10230: PostgreSQL same-key genesis must append exactly one signed_events witness row (0 -> 1) with matching event_type and payload_hash"
    );
}

/// #10228 / #10109 (SQLite armed twin): arm the SQLite store with real
/// `row_attest::sqlite::arm_with_key` (signed cutovers + signed baseline for
/// `_agents` + live TEMP triggers), then verify admin same-key rebind (200),
/// admin different-key rebind (opaque 403 `BIND_PROOF_REFUSED`), and non-admin
/// bind attempt (403 `"admin role required"`) all leave `_agents`, full
/// `agent_pubkey_history` rows, `memory_revisions`, and full `row_attestations`
/// rows byte-equal and the attestation verifier clean.
#[tokio::test]
async fn sqlite_armed_bind_matrix_admin_and_non_admin_10109() {
    let _dir = fresh_dir();
    let (mut state, file) = build_app_fixture();
    let non_admin_caller = "ai:non-admin-sqlite-10109";
    let non_admin_key_fixture = "fixture-non-admin-sqlite-10109";
    state.enrolled_agent_keys.mutate(|m| {
        m.insert(
            ai_memory::handlers::identity_binding::api_key_sha256_hex(non_admin_key_fixture),
            non_admin_caller.to_string(),
        );
    });
    let bootstrap_router = router_for_state(state);
    register_target_agent(&bootstrap_router).await;

    let kp = valid_keypair();
    let first_body = proved_bind_body(&bootstrap_router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    assert_eq!(
        bootstrap_router
            .clone()
            .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &first_body))
            .await
            .expect("bootstrap bind")
            .status(),
        StatusCode::OK
    );
    drop(bootstrap_router);

    // Arm the SQLite store with the agent's real bound signing key so v103
    // cutovers are signed, the live `_agents` row receives a signed baseline
    // attestation, and the trust anchor seals this DB file.
    let db_path = file.path().to_path_buf();
    let arm_conn = ai_memory::db::open(&db_path).expect("open db to arm");
    ai_memory::storage::row_attest::sqlite::arm_with_key(
        &arm_conn,
        TARGET_AGENT,
        kp.private.as_ref().expect("agent signing key"),
    )
    .expect("#10228: arm SQLite store with bound key");
    drop(arm_conn);

    // Prove the store is genuinely armed: a fresh connection without a session
    // signer installs refusing triggers (`REFUSE_NO_SIGNER`) on attested tables.
    let probe_conn = ai_memory::db::open(&db_path).expect("open armed db probe");
    let trigger_count: i64 = probe_conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_temp_master WHERE type = 'trigger' AND name = 'ra10040_memories_upd'",
            [],
            |r| r.get(0),
        )
        .expect("probe armed trigger");
    assert_eq!(
        trigger_count, 1,
        "#10228: armed SQLite store must install ra10040_memories_upd trigger on reopened handles"
    );
    let agent_title = ai_memory::models::agent_registration_title(TARGET_AGENT);
    let agent_id_row: String = probe_conn
        .query_row(
            "SELECT id FROM memories WHERE namespace = '_agents' AND title = ?1",
            [&agent_title],
            |r| r.get(0),
        )
        .expect("agent row id");
    let raw_write_err = probe_conn
        .execute(
            "UPDATE memories SET updated_at = updated_at, content = content || ' ' WHERE id = ?1",
            [&agent_id_row],
        )
        .expect_err(
            "#10228: armed SQLite handle without session signer must refuse raw memories write",
        );
    assert!(
        raw_write_err
            .to_string()
            .contains(ai_memory::storage::row_attest::sqlite::REFUSE_NO_SIGNER),
        "#10228: expected REFUSE_NO_SIGNER from armed trigger, got: {raw_write_err}"
    );
    drop(probe_conn);

    // Rebuild AppState over the now-armed SQLite store so both SAL and non-SAL
    // handles carry the live armed triggers.
    let (mut armed_state, _unused) = build_app_fixture();
    let armed_conn = ai_memory::db::open(&db_path).expect("open armed db for AppState");
    armed_state.db = Arc::new(tokio::sync::Mutex::new((
        armed_conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    {
        armed_state.store = Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open armed SqliteStore"),
        );
    }
    armed_state.enrolled_agent_keys.mutate(|m| {
        m.insert(
            ai_memory::handlers::identity_binding::api_key_sha256_hex(non_admin_key_fixture),
            non_admin_caller.to_string(),
        );
    });
    let router = router_for_state(armed_state);

    type HistRow = (i64, String, String, String, Option<String>);
    #[derive(Debug, PartialEq, Eq)]
    struct AttestRowSnap {
        id: i64,
        table_name: String,
        row_key: Vec<u8>,
        seq: i64,
        op: String,
        row_digest: Option<Vec<u8>>,
        prior_digest: Vec<u8>,
        agent_id: String,
        key_id: String,
        attested_at: String,
        format_version: i64,
        covered_columns: String,
        store_id: String,
        table_seq: i64,
        table_acc: Vec<u8>,
        signature: Option<Vec<u8>>,
        attestation_digest: Vec<u8>,
    }
    let snap = || -> ((String, String, String), Vec<HistRow>, i64, Vec<AttestRowSnap>) {
        let ro = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("ro snapshot");
        let agent_row: (String, String, String) = ro
            .query_row(
                "SELECT updated_at, metadata, content FROM memories WHERE namespace = '_agents' AND title = ?1",
                [&agent_title],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("agent row");
        let mut hist_stmt = ro
            .prepare(
                "SELECT version, pubkey_b64, bind_authority, bound_at, superseded_at
                 FROM agent_pubkey_history WHERE agent_id = ?1 ORDER BY version",
            )
            .expect("hist stmt");
        let hist: Vec<HistRow> = hist_stmt
            .query_map([TARGET_AGENT], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .expect("hist map")
            .collect::<Result<Vec<_>, _>>()
            .expect("hist collect");
        let rev_count: i64 = ro
            .query_row("SELECT COUNT(*) FROM memory_revisions", [], |r| r.get(0))
            .expect("rev count");
        let mut att_stmt = ro
            .prepare(
                "SELECT id, table_name, row_key, seq, op, row_digest, prior_digest, agent_id,
                        key_id, attested_at, format_version, covered_columns, store_id,
                        table_seq, table_acc, signature, attestation_digest
                 FROM row_attestations ORDER BY id",
            )
            .expect("att stmt");
        let att: Vec<AttestRowSnap> = att_stmt
            .query_map([], |r| {
                Ok(AttestRowSnap {
                    id: r.get(0)?,
                    table_name: r.get(1)?,
                    row_key: r.get(2)?,
                    seq: r.get(3)?,
                    op: r.get(4)?,
                    row_digest: r.get(5)?,
                    prior_digest: r.get(6)?,
                    agent_id: r.get(7)?,
                    key_id: r.get(8)?,
                    attested_at: r.get(9)?,
                    format_version: r.get(10)?,
                    covered_columns: r.get(11)?,
                    store_id: r.get(12)?,
                    table_seq: r.get(13)?,
                    table_acc: r.get(14)?,
                    signature: r.get(15)?,
                    attestation_digest: r.get(16)?,
                })
            })
            .expect("att map")
            .collect::<Result<Vec<_>, _>>()
            .expect("att collect");
        (agent_row, hist, rev_count, att)
    };

    let before = snap();
    assert!(
        before.3.iter().any(|row| row.table_name == "memories"
            && row.op == "baseline"
            && row.signature.is_some()),
        "#10228: armed SQLite store must hold a signed baseline row_attestations entry for memories"
    );

    // 1. Admin same-key rebind -> 200 OK, zero writes (even under armed triggers).
    let same_body = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let same_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &same_body))
        .await
        .expect("sqlite armed same");
    assert_eq!(same_resp.status(), StatusCode::OK);

    // 2. Admin different-key rebind -> opaque 403 BIND_PROOF_REFUSED, zero writes.
    let other_kp =
        ai_memory::identity::keypair::generate("sqlite-armed-other-10109").expect("other kp");
    let diff_body = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &other_kp).await;
    let diff_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &diff_body))
        .await
        .expect("sqlite armed diff");
    assert_eq!(diff_resp.status(), StatusCode::FORBIDDEN);
    let diff_bytes = axum::body::to_bytes(diff_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("diff bytes");
    let diff_json: serde_json::Value = serde_json::from_slice(&diff_bytes).expect("diff json");
    assert_eq!(
        diff_json,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED })
    );

    // 3. Non-admin bind attempt -> 403 exact `"admin role required"`, zero writes.
    let non_admin_req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/agents/{TARGET_AGENT}/pubkey"))
        .header("content-type", "application/json")
        .header("x-agent-id", non_admin_caller)
        .header("x-api-key", non_admin_key_fixture)
        .body(Body::from(serde_json::to_vec(&diff_body).expect("json")))
        .expect("non-admin req");
    let non_admin_resp = router.oneshot(non_admin_req).await.expect("non-admin resp");
    assert_eq!(non_admin_resp.status(), StatusCode::FORBIDDEN);
    let na_bytes = axum::body::to_bytes(non_admin_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("non-admin bytes");
    let na_json: serde_json::Value = serde_json::from_slice(&na_bytes).expect("non-admin json");
    assert_eq!(
        na_json,
        serde_json::json!({ "error": "admin role required" }),
        "#10228: SQLite non-admin bind 403 wire body must match exact admin-role refusal"
    );

    let after = snap();
    assert_eq!(after.0, before.0, "SQLite armed matrix: _agents unchanged");
    assert_eq!(
        after.1, before.1,
        "SQLite armed matrix: full agent_pubkey_history rows unchanged"
    );
    assert_eq!(
        after.2, before.2,
        "SQLite armed matrix: memory_revisions unchanged"
    );
    assert_eq!(
        after.3, before.3,
        "SQLite armed matrix: full row_attestations rows unchanged"
    );
}

/// #10109 r1 item 6 / #10228 (PostgreSQL matrix cells with seeded signed
/// `row_attestations` rows): admin same-key rebind (200, zero writes), admin
/// different-key rebind (opaque 403 `BIND_PROOF_REFUSED`, zero writes), and
/// non-admin bind attempt (exact 403 `"admin role required"`, zero writes) all
/// leave `_agents`, full `agent_pubkey_history` rows, `memory_revisions`, and
/// full `row_attestations` rows byte-equal.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_armed_bind_matrix_admin_and_non_admin_10109() {
    use ai_memory::storage::row_attest::{
        Attestation, FORMAT_VERSION, Op, STORE_ROW_TABLE, ZERO_DIGEST, attestation_digest,
        encode_key, key_id_of, sign,
    };

    let (mut state, _file) = build_app_fixture();
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let pg_store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("own PG database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("inspect PG pool");
    let non_admin_caller = "ai:non-admin-pg-10109";
    let non_admin_key_fixture = "fixture-non-admin-pg-10109";
    state.enrolled_agent_keys.mutate(|m| {
        m.insert(
            ai_memory::handlers::identity_binding::api_key_sha256_hex(non_admin_key_fixture),
            non_admin_caller.to_string(),
        );
    });
    state.store = Arc::new(pg_store);
    state.storage_backend = ai_memory::handlers::StorageBackend::Postgres;
    let router = router_for_state(state);

    let agent = format!("ai:pg-armed-10109-{}", uuid::Uuid::new_v4());
    let reg_req = Request::builder()
        .method("POST")
        .uri("/api/v1/agents")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_CALLER)
        .header("x-api-key", ADMIN_TOKEN)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "agent_id": agent,
                "agent_type": "ai:test",
            }))
            .expect("json"),
        ))
        .expect("reg req");
    assert_eq!(
        router.clone().oneshot(reg_req).await.expect("reg").status(),
        StatusCode::CREATED
    );

    let kp = valid_keypair();
    let first_body = proved_bind_body(&router, &agent, ADMIN_CALLER, &kp).await;
    assert_eq!(
        router
            .clone()
            .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &first_body))
            .await
            .expect("bind")
            .status(),
        StatusCode::OK
    );

    // #10228: actually seed signed `row_attestations` rows (store identity,
    // signed `memories` cutover, and a signed `baseline` attestation for the
    // target agent's `_agents` row) before driving the bind matrix.
    let agent_title = ai_memory::models::agent_registration_title(&agent);
    let (agent_mem_id,): (String,) =
        sqlx::query_as("SELECT id FROM memories WHERE namespace = $1 AND title = $2")
            .bind(ai_memory::models::AGENTS_NAMESPACE)
            .bind(&agent_title)
            .fetch_one(&pool)
            .await
            .expect("agent memory id");
    let store_id = uuid::Uuid::new_v4().to_string();
    let store_id_snap = store_id.clone();
    let now_ts = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string();
    let signer = kp.private.as_ref().expect("agent signing key");
    let key_id = key_id_of(&kp.public);
    let mem_spec = ai_memory::storage::row_attest::spec_for("memories").expect("memories spec");
    let covered = mem_spec.covered();
    let mut store_row = Attestation {
        id: 0,
        table: STORE_ROW_TABLE.to_string(),
        row_key: Vec::new(),
        seq: 0,
        op: Op::Store.as_str().to_string(),
        row_digest: None,
        prior_digest: ZERO_DIGEST.to_vec(),
        agent_id: String::new(),
        key_id: String::new(),
        attested_at: now_ts.clone(),
        format_version: FORMAT_VERSION,
        covered_columns: String::new(),
        store_id: store_id.clone(),
        table_seq: 0,
        table_acc: ZERO_DIGEST.to_vec(),
        signature: None,
        attestation_digest: Vec::new(),
    };
    store_row.attestation_digest = attestation_digest(&store_row);
    let mut cutover_row = Attestation {
        id: 0,
        table: "memories".to_string(),
        row_key: Vec::new(),
        seq: 0,
        op: Op::Cutover.as_str().to_string(),
        row_digest: None,
        prior_digest: ZERO_DIGEST.to_vec(),
        agent_id: agent.clone(),
        key_id: key_id.clone(),
        attested_at: now_ts.clone(),
        format_version: FORMAT_VERSION,
        covered_columns: covered.clone(),
        store_id: store_id.clone(),
        table_seq: 0,
        table_acc: ZERO_DIGEST.to_vec(),
        signature: None,
        attestation_digest: Vec::new(),
    };
    sign(&mut cutover_row, signer);
    let mut baseline_row = Attestation {
        id: 0,
        table: "memories".to_string(),
        row_key: encode_key(
            mem_spec,
            &[ai_memory::storage::row_attest::Cell::Text(
                agent_mem_id.clone(),
            )],
        ),
        seq: 1,
        op: Op::Baseline.as_str().to_string(),
        row_digest: Some(ZERO_DIGEST.to_vec()),
        prior_digest: ZERO_DIGEST.to_vec(),
        agent_id: agent.clone(),
        key_id,
        attested_at: now_ts,
        format_version: FORMAT_VERSION,
        covered_columns: covered,
        store_id,
        table_seq: 1,
        table_acc: ZERO_DIGEST.to_vec(),
        signature: None,
        attestation_digest: Vec::new(),
    };
    sign(&mut baseline_row, signer);
    for a in [&store_row, &cutover_row, &baseline_row] {
        sqlx::query(
            "INSERT INTO row_attestations (
                table_name, row_key, seq, op, row_digest, prior_digest,
                agent_id, key_id, attested_at, format_version, covered_columns,
                store_id, table_seq, table_acc, signature, attestation_digest
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
             ON CONFLICT (table_name, row_key, seq) DO NOTHING",
        )
        .bind(&a.table)
        .bind(&a.row_key)
        .bind(a.seq)
        .bind(&a.op)
        .bind(&a.row_digest)
        .bind(&a.prior_digest)
        .bind(&a.agent_id)
        .bind(&a.key_id)
        .bind(&a.attested_at)
        .bind(a.format_version)
        .bind(&a.covered_columns)
        .bind(&a.store_id)
        .bind(a.table_seq)
        .bind(&a.table_acc)
        .bind(&a.signature)
        .bind(&a.attestation_digest)
        .execute(&pool)
        .await
        .expect("seed signed row_attestations entry on PG");
    }

    type PgHistRow = (i64, String, String, String, Option<String>);
    #[derive(Debug, PartialEq, Eq)]
    struct PgAttestRowSnap {
        id: i64,
        table_name: String,
        row_key: Vec<u8>,
        seq: i64,
        op: String,
        row_digest: Option<Vec<u8>>,
        prior_digest: Vec<u8>,
        agent_id: String,
        key_id: String,
        attested_at: String,
        format_version: i64,
        covered_columns: String,
        store_id: String,
        table_seq: i64,
        table_acc: Vec<u8>,
        signature: Option<Vec<u8>>,
        attestation_digest: Vec<u8>,
    }
    let read_pg_attestations = |rows: Vec<sqlx::postgres::PgRow>| -> Vec<PgAttestRowSnap> {
        use sqlx::Row as _;
        rows.into_iter()
            .map(|r| PgAttestRowSnap {
                id: r.get(0),
                table_name: r.get(1),
                row_key: r.get(2),
                seq: r.get(3),
                op: r.get(4),
                row_digest: r.get(5),
                prior_digest: r.get(6),
                agent_id: r.get(7),
                key_id: r.get(8),
                attested_at: r.get(9),
                format_version: r.get(10),
                covered_columns: r.get(11),
                store_id: r.get(12),
                table_seq: r.get(13),
                table_acc: r.get(14),
                signature: r.get(15),
                attestation_digest: r.get(16),
            })
            .collect()
    };
    let before_row: (String, serde_json::Value, String) = sqlx::query_as(
        "SELECT updated_at::text, metadata, content FROM memories WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::models::AGENTS_NAMESPACE)
    .bind(&agent_title)
    .fetch_one(&pool)
    .await
    .expect("before _agents");
    let before_hist: Vec<PgHistRow> = sqlx::query_as(
        "SELECT version, pubkey_b64, bind_authority, bound_at::text, superseded_at::text
         FROM agent_pubkey_history WHERE agent_id = $1 ORDER BY version",
    )
    .bind(&agent)
    .fetch_all(&pool)
    .await
    .expect("before hist");
    let before_rev: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM memory_revisions WHERE memory_id = $1")
            .bind(&agent_mem_id)
            .fetch_one(&pool)
            .await
            .expect("before rev");
    let before_att = read_pg_attestations(
        sqlx::query(
            "SELECT id, table_name, row_key, seq, op, row_digest, prior_digest, agent_id,
                    key_id, attested_at, format_version, covered_columns, store_id,
                    table_seq, table_acc, signature, attestation_digest
             FROM row_attestations WHERE store_id = $1 OR agent_id = $2 ORDER BY id",
        )
        .bind(&store_id_snap)
        .bind(&agent)
        .fetch_all(&pool)
        .await
        .expect("before att"),
    );
    assert!(
        before_att.iter().any(|r| {
            r.table_name == "memories"
                && r.op == "baseline"
                && r.agent_id == agent
                && r.signature.is_some()
        }),
        "#10228: PG armed matrix must have seeded signed baseline row_attestations entry before matrix calls"
    );

    // 1. Admin same-key rebind -> 200 OK, zero writes.
    let same_body = proved_bind_body(&router, &agent, ADMIN_CALLER, &kp).await;
    let same_resp = router
        .clone()
        .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &same_body))
        .await
        .expect("same");
    assert_eq!(same_resp.status(), StatusCode::OK);

    // 2. Admin different-key rebind -> opaque 403 BIND_PROOF_REFUSED, zero writes.
    let other_kp = ai_memory::identity::keypair::generate("pg-other-10109").expect("other kp");
    let diff_body = proved_bind_body(&router, &agent, ADMIN_CALLER, &other_kp).await;
    let diff_resp = router
        .clone()
        .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &diff_body))
        .await
        .expect("diff");
    assert_eq!(diff_resp.status(), StatusCode::FORBIDDEN);
    let diff_bytes = axum::body::to_bytes(diff_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("bytes");
    let diff_json: serde_json::Value = serde_json::from_slice(&diff_bytes).expect("json");
    assert_eq!(
        diff_json,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED })
    );

    // 3. Non-admin bind attempt -> exact 403 `"admin role required"`, zero writes.
    let non_admin_req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/agents/{agent}/pubkey"))
        .header("content-type", "application/json")
        .header("x-agent-id", non_admin_caller)
        .header("x-api-key", non_admin_key_fixture)
        .body(Body::from(serde_json::to_vec(&diff_body).expect("json")))
        .expect("non-admin req");
    let non_admin_resp = router.oneshot(non_admin_req).await.expect("non-admin resp");
    assert_eq!(non_admin_resp.status(), StatusCode::FORBIDDEN);
    let na_bytes = axum::body::to_bytes(non_admin_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("non-admin bytes");
    let na_json: serde_json::Value = serde_json::from_slice(&na_bytes).expect("non-admin json");
    assert_eq!(
        na_json,
        serde_json::json!({ "error": "admin role required" }),
        "#10228: PG non-admin bind 403 wire body must match exact admin-role refusal"
    );

    let after_row: (String, serde_json::Value, String) = sqlx::query_as(
        "SELECT updated_at::text, metadata, content FROM memories WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::models::AGENTS_NAMESPACE)
    .bind(&agent_title)
    .fetch_one(&pool)
    .await
    .expect("after _agents");
    let after_hist: Vec<PgHistRow> = sqlx::query_as(
        "SELECT version, pubkey_b64, bind_authority, bound_at::text, superseded_at::text
         FROM agent_pubkey_history WHERE agent_id = $1 ORDER BY version",
    )
    .bind(&agent)
    .fetch_all(&pool)
    .await
    .expect("after hist");
    let after_rev: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM memory_revisions WHERE memory_id = $1")
            .bind(&agent_mem_id)
            .fetch_one(&pool)
            .await
            .expect("after rev");
    let after_att = read_pg_attestations(
        sqlx::query(
            "SELECT id, table_name, row_key, seq, op, row_digest, prior_digest, agent_id,
                    key_id, attested_at, format_version, covered_columns, store_id,
                    table_seq, table_acc, signature, attestation_digest
             FROM row_attestations WHERE store_id = $1 OR agent_id = $2 ORDER BY id",
        )
        .bind(&store_id_snap)
        .bind(&agent)
        .fetch_all(&pool)
        .await
        .expect("after att"),
    );
    assert_eq!(after_row, before_row, "PG matrix: _agents unchanged");
    assert_eq!(
        after_hist, before_hist,
        "PG matrix: full agent_pubkey_history rows unchanged"
    );
    assert_eq!(after_rev, before_rev, "PG matrix: revisions unchanged");
    assert_eq!(
        after_att, before_att,
        "PG matrix: full row_attestations rows unchanged"
    );
}

/// #10227: SQLite SAL `append_lineage_record` must preserve the typed
/// `StoreError::PermissionDenied { action: BIND_AGENT_PUBKEY_ACTION, reason }`
/// cause slug (matching PostgreSQL) instead of flattening it to `BackendUnavailable`.
#[cfg(feature = "sal")]
#[tokio::test]
async fn sqlite_sal_lineage_refusal_preserves_typed_cause_10227() {
    use ai_memory::store::{CallerContext, MemoryStore as _, StoreError};

    let _dir = fresh_dir();
    let (router, file) = build_router_fixture();
    register_target_agent(&router).await;

    let kp = valid_keypair();
    let bootstrap = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    assert_eq!(
        router
            .clone()
            .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &bootstrap))
            .await
            .expect("bootstrap")
            .status(),
        StatusCode::OK
    );

    // Close the history head (revoked/superseded state).
    let conn = ai_memory::db::open(file.path()).expect("open db");
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE agent_pubkey_history SET superseded_at = ?1 WHERE agent_id = ?2 AND superseded_at IS NULL",
        rusqlite::params![&now, TARGET_AGENT],
    )
    .expect("close history head");
    drop(conn);

    let store = ai_memory::store::sqlite::SqliteStore::open(file.path()).expect("open store");
    let genesis = ai_memory::identity::lineage::LineageRecord::genesis(
        TARGET_AGENT,
        &kp.public_base64(),
        None,
        &chrono::Utc::now().to_rfc3339(),
    );
    let sig_input = genesis.signing_input().expect("signing input");
    let sig = ed25519_dalek::Signer::sign(kp.private.as_ref().expect("private key"), &sig_input)
        .to_bytes()
        .to_vec();
    let ctx = CallerContext::for_admin(ADMIN_CALLER);
    let err = store
        .append_lineage_record(&ctx, TARGET_AGENT, &genesis, &sig)
        .await
        .expect_err("closed history lineage must refuse");
    match err {
        StoreError::PermissionDenied {
            action,
            target,
            reason,
        } => {
            assert_eq!(action, ai_memory::handlers::BIND_AGENT_PUBKEY_ACTION);
            assert_eq!(target, TARGET_AGENT);
            assert_eq!(
                reason, "closed_identity_requires_recovery",
                "#10227: SQLite SAL lineage refusal must emit exact cause slug"
            );
        }
        other => panic!(
            "#10227: expected StoreError::PermissionDenied with closed_identity_requires_recovery, got {other:?}"
        ),
    }
}

/// #10109 r1 item 5 / #10229 (SQLite): verify exact per-cause operator warn log
/// (`cause="<exact slug>"`, no foreign cause) AND exact forensic audit row
/// `payload["reason"]` across existing-identity, closed-history, and
/// non-canonical stored key refusals while keeping the HTTP 403 wire response
/// identically opaque (`BIND_PROOF_REFUSED`).
#[test]
fn bind_pubkey_route_closed_history_logs_exact_recovery_reason_10109() {
    let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "bind_pubkey_route_closed_history_log_child_10109",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("spawn closed-history log child");
    assert!(
        out.status.success(),
        "closed-history log child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
#[ignore = "child helper of bind_pubkey_route_closed_history_logs_exact_recovery_reason_10109"]
async fn bind_pubkey_route_closed_history_log_child_10109() {
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);
    struct GuardWriter(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for GuardWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = GuardWriter;
        fn make_writer(&'a self) -> Self::Writer {
            GuardWriter(Arc::clone(&self.0))
        }
    }

    let audit_dir = fresh_dir();
    ai_memory::governance::audit::shutdown();
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("init forensic audit");

    let buf = SharedBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_target(true)
        .with_writer(buf.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (router, file) = build_router_fixture();
    register_target_agent(&router).await;

    let kp = valid_keypair();
    let bootstrap = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let ok_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &bootstrap))
        .await
        .expect("bootstrap");
    assert_eq!(ok_resp.status(), StatusCode::OK);

    let all_slugs = [
        "existing_identity_requires_lineage",
        "closed_identity_requires_recovery",
        "non_canonical_stored_key",
        "binding_not_authorized",
        "unclassified_refusal",
    ];
    let assert_exact_log = |expected_slug: &str, expected_msg: &str| {
        let captured = String::from_utf8(buf.0.lock().expect("lock").clone()).expect("utf8");
        buf.0.lock().expect("lock").clear();
        let matching_lines: Vec<&str> = captured
            .lines()
            .filter(|l| l.contains("identity.bind.requires_succession"))
            .collect();
        let [line] = matching_lines.as_slice() else {
            panic!(
                "expected one warn event on identity.bind.requires_succession; captured:\n{captured}"
            );
        };
        let exact_cause = format!("cause=\"{expected_slug}\"");
        assert!(
            line.contains(&exact_cause),
            "#10229: expected exact {exact_cause}, got: {line}"
        );
        assert!(
            line.contains(expected_msg),
            "#10229: expected exact message '{expected_msg}', got: {line}"
        );
        for other in all_slugs.iter().filter(|s| **s != expected_slug) {
            assert!(
                !line.contains(&format!("cause=\"{other}\"")),
                "#10229: log line must not emit foreign cause {other}: {line}"
            );
        }
    };

    // Case 1: existing identity different-key refusal -> existing_identity_requires_lineage.
    let other_kp =
        ai_memory::identity::keypair::generate("sqlite-existing-10229").expect("other kp");
    let diff_attempt = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &other_kp).await;
    let diff_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &diff_attempt))
        .await
        .expect("existing identity bind");
    assert_eq!(diff_resp.status(), StatusCode::FORBIDDEN);
    let diff_bytes = axum::body::to_bytes(diff_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("diff bytes");
    let diff_body: serde_json::Value = serde_json::from_slice(&diff_bytes).expect("diff json");
    assert_eq!(
        diff_body,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED })
    );
    assert_exact_log(
        "existing_identity_requires_lineage",
        "agent already has a bound key",
    );

    // Case 2: closed history head -> closed_identity_requires_recovery.
    let conn = ai_memory::db::open(file.path()).expect("open db");
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE agent_pubkey_history SET superseded_at = ?1 WHERE agent_id = ?2 AND superseded_at IS NULL",
        rusqlite::params![&now, TARGET_AGENT],
    )
    .expect("close history head");
    drop(conn);

    let closed_attempt = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let closed_resp = router
        .clone()
        .oneshot(put_pubkey_body(TARGET_AGENT, ADMIN_CALLER, &closed_attempt))
        .await
        .expect("closed history bind");
    assert_eq!(closed_resp.status(), StatusCode::FORBIDDEN);
    let closed_bytes = axum::body::to_bytes(closed_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("body bytes");
    let closed_body: serde_json::Value = serde_json::from_slice(&closed_bytes).expect("json");
    assert_eq!(
        closed_body,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED }),
        "closed-history refusal wire body must stay opaque BIND_PROOF_REFUSED"
    );
    assert_exact_log(
        "closed_identity_requires_recovery",
        "agent key history is closed or revoked",
    );

    // Case 3: non-canonical stored key -> non_canonical_stored_key.
    // Pick a 32-byte base64url string (passes SQL length/alphabet CHECK) that is
    // not a valid compressed Ed25519 point (`canonical_public_base64` rejects it).
    let non_canonical_point = {
        use base64::Engine as _;
        (0_u8..=255)
            .map(|b| {
                let mut raw = [0_u8; 32];
                raw[0] = b;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
            })
            .find(|cand| ai_memory::identity::keypair::canonical_public_base64(cand).is_err())
            .expect("must find non-curve 32-byte base64url string")
    };
    let conn = ai_memory::db::open(file.path()).expect("open db for corrupt key");
    conn.execute(
        "UPDATE agent_pubkey_history SET pubkey_b64 = ?1, superseded_at = NULL WHERE agent_id = ?2",
        rusqlite::params![&non_canonical_point, TARGET_AGENT],
    )
    .expect("corrupt stored history key");
    drop(conn);

    let noncanon_attempt = proved_bind_body(&router, TARGET_AGENT, ADMIN_CALLER, &kp).await;
    let noncanon_resp = router
        .clone()
        .oneshot(put_pubkey_body(
            TARGET_AGENT,
            ADMIN_CALLER,
            &noncanon_attempt,
        ))
        .await
        .expect("non-canonical bind");
    assert_eq!(noncanon_resp.status(), StatusCode::FORBIDDEN);
    let noncanon_bytes =
        axum::body::to_bytes(noncanon_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
            .await
            .expect("noncanon bytes");
    let noncanon_body: serde_json::Value =
        serde_json::from_slice(&noncanon_bytes).expect("noncanon json");
    assert_eq!(
        noncanon_body,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED })
    );
    assert_exact_log(
        "non_canonical_stored_key",
        "stored agent public key is non-canonical",
    );

    ai_memory::governance::audit::shutdown();
    let audit_text = std::fs::read_dir(audit_dir.path())
        .expect("read audit dir")
        .filter_map(Result::ok)
        .map(|entry| std::fs::read_to_string(entry.path()).expect("read audit file"))
        .collect::<String>();
    let refused_reasons: Vec<String> = audit_text
        .lines()
        .filter_map(|line| {
            serde_json::from_str::<ai_memory::governance::audit::ForensicDecision>(line).ok()
        })
        .filter(|row| {
            row.actor == ADMIN_CALLER
                && row.decision == "refuse"
                && row.kind == ai_memory::handlers::BIND_AGENT_PUBKEY_ACTION
                && row.payload["agent_id"] == TARGET_AGENT
        })
        .filter_map(|row| row.payload["reason"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        refused_reasons,
        vec![
            "existing_identity_requires_lineage".to_string(),
            "closed_identity_requires_recovery".to_string(),
            "non_canonical_stored_key".to_string(),
        ],
        "#10229: SQLite forensic audit sink must record exact per-cause refusal reasons"
    );
}

/// #10229 (PostgreSQL twin): verify exact per-cause operator warn log
/// (`cause="<exact slug>"`, no foreign cause) AND exact forensic audit row
/// `payload["reason"]` on PostgreSQL across existing-identity, closed-history,
/// and non-canonical stored key refusals while keeping the HTTP 403 wire body
/// identically opaque (`BIND_PROOF_REFUSED`).
#[cfg(feature = "sal-postgres")]
#[test]
fn postgres_bind_pubkey_route_refusal_causes_and_audit_10229() {
    let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "postgres_bind_pubkey_route_refusal_causes_and_audit_child_10229",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("spawn PG refusal causes log child");
    assert!(
        out.status.success(),
        "PG refusal causes child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "child helper of postgres_bind_pubkey_route_refusal_causes_and_audit_10229"]
async fn postgres_bind_pubkey_route_refusal_causes_and_audit_child_10229() {
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);
    struct GuardWriter(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for GuardWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = GuardWriter;
        fn make_writer(&'a self) -> Self::Writer {
            GuardWriter(Arc::clone(&self.0))
        }
    }

    let audit_dir = fresh_dir();
    ai_memory::governance::audit::shutdown();
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("init forensic audit");

    let buf = SharedBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_target(true)
        .with_writer(buf.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (mut state, _file) = build_app_fixture();
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PG URL required; no soft skip");
    let pg_store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("own PG database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("inspect PG pool");
    state.store = Arc::new(pg_store);
    state.storage_backend = ai_memory::handlers::StorageBackend::Postgres;
    let router = router_for_state(state);

    let agent = format!("ai:pg-audit-10229-{}", uuid::Uuid::new_v4());
    let reg_req = Request::builder()
        .method("POST")
        .uri("/api/v1/agents")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_CALLER)
        .header("x-api-key", ADMIN_TOKEN)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "agent_id": agent,
                "agent_type": "ai:test",
            }))
            .expect("json"),
        ))
        .expect("reg req");
    assert_eq!(
        router.clone().oneshot(reg_req).await.expect("reg").status(),
        StatusCode::CREATED
    );

    let kp = valid_keypair();
    let bootstrap = proved_bind_body(&router, &agent, ADMIN_CALLER, &kp).await;
    assert_eq!(
        router
            .clone()
            .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &bootstrap))
            .await
            .expect("bootstrap")
            .status(),
        StatusCode::OK
    );

    let all_slugs = [
        "existing_identity_requires_lineage",
        "closed_identity_requires_recovery",
        "non_canonical_stored_key",
        "binding_not_authorized",
        "unclassified_refusal",
    ];
    let assert_exact_log = |expected_slug: &str, expected_msg: &str| {
        let captured = String::from_utf8(buf.0.lock().expect("lock").clone()).expect("utf8");
        buf.0.lock().expect("lock").clear();
        let matching_lines: Vec<&str> = captured
            .lines()
            .filter(|l| l.contains("identity.bind.requires_succession"))
            .collect();
        let [line] = matching_lines.as_slice() else {
            panic!(
                "expected one warn event on identity.bind.requires_succession; captured:\n{captured}"
            );
        };
        let exact_cause = format!("cause=\"{expected_slug}\"");
        assert!(
            line.contains(&exact_cause),
            "#10229 PG: expected exact {exact_cause}, got: {line}"
        );
        assert!(
            line.contains(expected_msg),
            "#10229 PG: expected exact message '{expected_msg}', got: {line}"
        );
        for other in all_slugs.iter().filter(|s| **s != expected_slug) {
            assert!(
                !line.contains(&format!("cause=\"{other}\"")),
                "#10229 PG: log line must not emit foreign cause {other}: {line}"
            );
        }
    };

    // Case 1: existing identity -> existing_identity_requires_lineage.
    let other_kp = ai_memory::identity::keypair::generate("pg-existing-10229").expect("other kp");
    let diff_attempt = proved_bind_body(&router, &agent, ADMIN_CALLER, &other_kp).await;
    let diff_resp = router
        .clone()
        .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &diff_attempt))
        .await
        .expect("pg existing identity bind");
    assert_eq!(diff_resp.status(), StatusCode::FORBIDDEN);
    let diff_bytes = axum::body::to_bytes(diff_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("diff bytes");
    let diff_body: serde_json::Value = serde_json::from_slice(&diff_bytes).expect("diff json");
    assert_eq!(
        diff_body,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED })
    );
    assert_exact_log(
        "existing_identity_requires_lineage",
        "agent already has a bound key",
    );

    // Case 2: closed history -> closed_identity_requires_recovery.
    sqlx::query(
        "UPDATE agent_pubkey_history SET superseded_at = NOW() WHERE agent_id = $1 AND superseded_at IS NULL",
    )
    .bind(&agent)
    .execute(&pool)
    .await
    .expect("close PG history head");

    let closed_attempt = proved_bind_body(&router, &agent, ADMIN_CALLER, &kp).await;
    let closed_resp = router
        .clone()
        .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &closed_attempt))
        .await
        .expect("pg closed history bind");
    assert_eq!(closed_resp.status(), StatusCode::FORBIDDEN);
    let closed_bytes = axum::body::to_bytes(closed_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .expect("closed bytes");
    let closed_body: serde_json::Value = serde_json::from_slice(&closed_bytes).expect("json");
    assert_eq!(
        closed_body,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED })
    );
    assert_exact_log(
        "closed_identity_requires_recovery",
        "agent key history is closed or revoked",
    );

    // Case 3: non-canonical stored key -> non_canonical_stored_key.
    let non_canonical_point = {
        use base64::Engine as _;
        (0_u8..=255)
            .map(|b| {
                let mut raw = [0_u8; 32];
                raw[0] = b;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
            })
            .find(|cand| ai_memory::identity::keypair::canonical_public_base64(cand).is_err())
            .expect("must find non-curve 32-byte base64url string")
    };
    sqlx::query(
        "UPDATE agent_pubkey_history SET pubkey_b64 = $1, superseded_at = NULL WHERE agent_id = $2",
    )
    .bind(&non_canonical_point)
    .bind(&agent)
    .execute(&pool)
    .await
    .expect("corrupt PG history key");

    let noncanon_attempt = proved_bind_body(&router, &agent, ADMIN_CALLER, &kp).await;
    let noncanon_resp = router
        .clone()
        .oneshot(put_pubkey_body(&agent, ADMIN_CALLER, &noncanon_attempt))
        .await
        .expect("pg non-canonical bind");
    assert_eq!(noncanon_resp.status(), StatusCode::FORBIDDEN);
    let noncanon_bytes =
        axum::body::to_bytes(noncanon_resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
            .await
            .expect("noncanon bytes");
    let noncanon_body: serde_json::Value = serde_json::from_slice(&noncanon_bytes).expect("json");
    assert_eq!(
        noncanon_body,
        serde_json::json!({ "error": ai_memory::errors::msg::BIND_PROOF_REFUSED })
    );
    assert_exact_log(
        "non_canonical_stored_key",
        "stored agent public key is non-canonical",
    );

    ai_memory::governance::audit::shutdown();
    let audit_text = std::fs::read_dir(audit_dir.path())
        .expect("read audit dir")
        .filter_map(Result::ok)
        .map(|entry| std::fs::read_to_string(entry.path()).expect("read audit file"))
        .collect::<String>();
    let refused_reasons: Vec<String> = audit_text
        .lines()
        .filter_map(|line| {
            serde_json::from_str::<ai_memory::governance::audit::ForensicDecision>(line).ok()
        })
        .filter(|row| {
            row.actor == ADMIN_CALLER
                && row.decision == "refuse"
                && row.kind == ai_memory::handlers::BIND_AGENT_PUBKEY_ACTION
                && row.payload["agent_id"] == agent
        })
        .filter_map(|row| row.payload["reason"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        refused_reasons,
        vec![
            "existing_identity_requires_lineage".to_string(),
            "closed_identity_requires_recovery".to_string(),
            "non_canonical_stored_key".to_string(),
        ],
        "#10229: PG forensic audit sink must record exact per-cause refusal reasons"
    );
}
