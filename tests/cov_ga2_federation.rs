// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! cov_ga2 — GA-gate coverage backfill for the three sub-90% federation
//! modules under the operator's uniform-90-per-module directive:
//!
//! - `handlers/federation_receive` — drives the production `/sync/push`
//!   route through a real `build_router` so `sync_push` and its closures,
//!   the `attestation_refusal_response` 403 arm, the `#1056` TOFU
//!   allowlist refusal, and `spawn_deferred_embedding_refresh` (no-op
//!   keyword path) execute end-to-end.
//! - `handlers/federation_signing_check` — exercises
//!   `verify_signature_or_reject` (every match arm: no-key permissive,
//!   present-sig-no-key, enrolled-key valid + bad-sig, nonce replay,
//!   peer-enrollment strict refusal), `verify_get_signature_or_reject`
//!   via `/sync/since`, `resolve_peer_verifying_key` /
//!   `cached_trust_bundle` / `require_peer_enrollment_enabled` on those
//!   paths, plus the postgres `sync_push_via_store` arm when
//!   `AI_MEMORY_TEST_POSTGRES_URL` is set.
//! - `federation/sync` — drives `broadcast_{archive,consolidate,delete,
//!   link}_quorum` through both the clean no-peer (`Ok(tracker)`) path
//!   and the one-unreachable-peer path (fanout closure + `Fail` arm +
//!   post-quorum detached drain).
//!
//! The federation env toggles (`AI_MEMORY_FED_REQUIRE_SIG`,
//! `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT`, `AI_MEMORY_KEY_DIR`) are
//! PROCESS-GLOBAL; cargo runs `#[tokio::test]`s in one binary
//! concurrently, so every test that mutates them takes `FED_ENV_LOCK`
//! first (the same serial-guard pattern as `tests/cov3_handlers_postgres`).

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

/// Serializes every test that mutates the process-global federation env
/// vars or `AI_MEMORY_KEY_DIR`. Without this, one test's `remove_var`
/// clobbers another's `set_var` mid-request and the signature/enrollment
/// gate flips, yielding spurious 401/403s.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

// ---------------------------------------------------------------------------
// Router scaffolding (sqlite) — mirrors tests/cov3_handlers_sqlite.rs.
// ---------------------------------------------------------------------------

fn sqlite_router() -> (axum::Router, tempfile::NamedTempFile) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let app_state = AppState {
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
        storage_backend: StorageBackend::Sqlite,
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"),
        ),
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_tmp)
}

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Build a `/sync/push` POST with the given raw body and optional
/// federation headers. `headers` is a slice of `(name, value)`.
fn push_req(body: &[u8], headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

fn get_since_req(query: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/sync/since?{query}"));
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::empty()).unwrap()
}

const SIG_HEADER: &str = "x-memory-sig";
const NONCE_HEADER: &str = "x-memory-nonce";
const PEER_HEADER: &str = "x-peer-id";

/// Generate a fresh peer keypair, persist its public key under a fresh
/// temp `AI_MEMORY_KEY_DIR`, point the env there, and return the dir
/// guard + the signing key so the test can sign bodies that
/// `resolve_peer_verifying_key` will then verify against the enrolled key.
fn enroll_peer(peer_id: &str) -> (tempfile::TempDir, SigningKey) {
    let dir = tempfile::tempdir().expect("keydir");
    let kp = ai_memory::identity::keypair::generate(peer_id).expect("gen keypair");
    ai_memory::identity::keypair::save(&kp, dir.path()).expect("save keypair");
    // SAFETY: caller holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::identity::keypair::KEY_DIR_ENV, dir.path());
    }
    let signing = kp.private.expect("private key present");
    (dir, signing)
}

fn clear_fed_env() {
    // SAFETY: caller holds FED_ENV_LOCK.
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_NONCE_ENV);
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var(ai_memory::identity::keypair::KEY_DIR_ENV);
    }
}

// ---------------------------------------------------------------------------
// handlers/federation_receive — sync_push closures + refusal arms.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_push_require_sig_off_invalid_sender_is_400() {
    let _g = FED_ENV_LOCK.lock().await;
    // REQUIRE_SIG=0 bypasses the signature gate (verify_signature_or_reject
    // returns None at the top); TRUST_BODY so the attestation gate trusts
    // the body sender, letting us reach validate_agent_id in sync_push.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let (r, _t) = sqlite_router();
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": "bad id with spaces",
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let (status, _b) = decode(&r, push_req(&body, &[])).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert_eq!(status, StatusCode::BAD_REQUEST, "invalid sender must 400");
}

#[tokio::test]
async fn sync_push_empty_batch_acks_and_runs_deferred_embed_noop() {
    let _g = FED_ENV_LOCK.lock().await;
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let (r, _t) = sqlite_router();
    // A real memory in the batch exercises the apply loop + the
    // spawn_deferred_embedding_refresh call (no-op: keyword router has no
    // embedder, so the rows-empty / no-embedder early-return fires).
    let now = chrono::Utc::now().to_rfc3339();
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": "ai:cov-ga2-peer",
        "sender_clock": {"entries": {}},
        "sender_wall_clock": now,
        "memories": [{
            "id": "cov-ga2-m1",
            "tier": "mid",
            "namespace": "covga2",
            "title": "ga2 row",
            "content": "deferred embed exercise",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "test",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {"agent_id": "ai:cov-ga2-peer"}
        }]
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert!(
        status.is_success(),
        "embed-path push acks; status={status} body={b}"
    );
    // The row drives the apply loop + the spawn_deferred_embedding_refresh
    // call regardless of whether it applies cleanly or is skipped by
    // validation — both are covered arms. Assert the loop processed it.
    let applied = b["applied"].as_i64().unwrap_or(0);
    let skipped = b["skipped"].as_i64().unwrap_or(0);
    assert_eq!(
        applied + skipped,
        1,
        "the single row hit the apply loop; body={b}"
    );
}

#[tokio::test]
async fn sync_push_sender_mismatch_is_attestation_refusal_403() {
    let _g = FED_ENV_LOCK.lock().await;
    // REQUIRE_SIG=0 to skip the sig gate; NO trust-body bypass, so the
    // #238 attestation runs and a body sender that disagrees with the
    // x-peer-id header trips attestation_refusal_response (403).
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    let (r, _t) = sqlite_router();
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": "ai:claimed-one",
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[(PEER_HEADER, "ai:different-peer")])).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
    }
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "sender/peer mismatch must 403; body={b}"
    );
    assert!(
        b.get("claimed").is_some(),
        "refusal envelope carries claimed/peer_header"
    );
}

#[tokio::test]
async fn sync_push_malformed_body_is_400() {
    let _g = FED_ENV_LOCK.lock().await;
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let (r, _t) = sqlite_router();
    let (status, _b) = decode(&r, push_req(b"{not valid json", &[])).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert_eq!(status, StatusCode::BAD_REQUEST, "malformed body must 400");
}

// ---------------------------------------------------------------------------
// handlers/federation_signing_check — verify_signature_or_reject arms.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_push_unsigned_no_enrolled_key_permissive_allows() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    // REQUIRE_SIG defaults ON (env unset). No sig header, no enrolled key,
    // peer-enrollment NOT strict → the (None, None) permissive arm: allow.
    unsafe {
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let (r, _t) = sqlite_router();
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": "ai:cov-unsigned",
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let (status, _b) = decode(&r, push_req(&body, &[(PEER_HEADER, "ai:cov-unsigned")])).await;
    clear_fed_env();
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert!(
        status.is_success(),
        "unsigned + no enrolled key is permissive; status={status}"
    );
}

#[tokio::test]
async fn sync_push_unsigned_strict_enrollment_refuses_401() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    // (None, None) arm WITH AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 →
    // require_peer_enrollment_enabled() true → peer_not_enrolled 401.
    unsafe {
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "1");
    }
    let (r, _t) = sqlite_router();
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": "ai:cov-strict",
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[(PEER_HEADER, "ai:cov-strict")])).await;
    clear_fed_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "strict enrollment must 401; body={b}"
    );
    assert_eq!(b["error"], "peer_not_enrolled");
}

#[tokio::test]
async fn sync_push_sig_present_no_enrolled_key_refuses_401() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    // REQUIRE_SIG default ON, a sig header present, but NO enrolled key for
    // the peer (KEY_DIR points at an empty dir) → (Some, None) arm:
    // x_memory_sig_no_enrolled_key 401.
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var(ai_memory::identity::keypair::KEY_DIR_ENV, dir.path());
    }
    let (r, _t) = sqlite_router();
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": "ai:cov-sig-nokey",
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let (status, b) = decode(
        &r,
        push_req(
            &body,
            &[
                (PEER_HEADER, "ai:cov-sig-nokey"),
                (SIG_HEADER, "ed25519=AAAA"),
            ],
        ),
    )
    .await;
    clear_fed_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "sig + no key must 401; body={b}"
    );
    assert_eq!(b["error"], "x_memory_sig_no_enrolled_key");
}

#[tokio::test]
async fn sync_push_enrolled_key_valid_sig_passes_verify() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    // Enrolled peer key + a valid body-only signature → (Some, Some) arm
    // verifies, no nonce header (REQUIRE_NONCE off) → permissive accept,
    // then the body deserializes + applies. Exercises
    // resolve_peer_verifying_key's enrolled-key branch + verify_header.
    let peer = "ai:cov-enrolled";
    let (_dir, signing) = enroll_peer(peer);
    // REQUIRE_NONCE defaults ON; a body-only signature carries no nonce
    // header, so disable nonce enforcement for this body-only-verify arm.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_NONCE_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let sig = ai_memory::federation::signing::sign_body_header(&signing, &body);
    let (r, _t) = sqlite_router();
    let (status, b) = decode(
        &r,
        push_req(&body, &[(PEER_HEADER, peer), (SIG_HEADER, &sig)]),
    )
    .await;
    clear_fed_env();
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert!(
        status.is_success(),
        "valid signed push must pass verify; status={status} body={b}"
    );
}

#[tokio::test]
async fn sync_push_enrolled_key_bad_sig_refuses_401() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    // Enrolled peer key, but the signature is over DIFFERENT bytes →
    // verify_header BadSignature → 401.
    let peer = "ai:cov-badsig";
    let (_dir, signing) = enroll_peer(peer);
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    // Sign over tampered bytes so verification fails against `body`.
    let sig = ai_memory::federation::signing::sign_body_header(&signing, b"different bytes");
    let (r, _t) = sqlite_router();
    let (status, b) = decode(
        &r,
        push_req(&body, &[(PEER_HEADER, peer), (SIG_HEADER, &sig)]),
    )
    .await;
    clear_fed_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "bad sig must 401; body={b}"
    );
}

#[tokio::test]
async fn sync_push_nonce_replay_refuses_401() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    // Enrolled key + nonce-bound valid signature: first push is Fresh
    // (accepted), a byte-identical replay re-uses the same (peer, nonce)
    // → ReplayDecision::Replay → 401 x_memory_nonce_replay. The
    // FederationNonceCache lives on AppState, so we must reuse ONE router
    // across both requests.
    let peer = "ai:cov-nonce";
    let (_dir, signing) = enroll_peer(peer);
    unsafe {
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let nonce = "cov-ga2-nonce-001";
    let sig = ai_memory::federation::signing::sign_body_with_nonce_header(&signing, &body, nonce);
    let (r, _t) = sqlite_router();
    let (s1, _b1) = decode(
        &r,
        push_req(
            &body,
            &[
                (PEER_HEADER, peer),
                (SIG_HEADER, &sig),
                (NONCE_HEADER, nonce),
            ],
        ),
    )
    .await;
    let (s2, b2) = decode(
        &r,
        push_req(
            &body,
            &[
                (PEER_HEADER, peer),
                (SIG_HEADER, &sig),
                (NONCE_HEADER, nonce),
            ],
        ),
    )
    .await;
    clear_fed_env();
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert!(
        s1.is_success(),
        "first signed+nonce push is fresh; status={s1}"
    );
    assert_eq!(s2, StatusCode::UNAUTHORIZED, "replay must 401; body={b2}");
    assert_eq!(b2["error"], "x_memory_nonce_replay");
}

// ---------------------------------------------------------------------------
// handlers/federation_signing_check — verify_get_signature_or_reject via
// GET /sync/since.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_since_require_sig_off_permissive_ok() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
    }
    let (r, _t) = sqlite_router();
    let (status, _b) = decode(&r, get_since_req("limit=5", &[])).await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "require_sig=0 since is permissive; status={status}"
    );
}

#[tokio::test]
async fn sync_since_sig_present_no_enrolled_key_refuses_401() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var(ai_memory::identity::keypair::KEY_DIR_ENV, dir.path());
    }
    let (r, _t) = sqlite_router();
    let (status, b) = decode(
        &r,
        get_since_req(
            "limit=5",
            &[
                (PEER_HEADER, "ai:cov-since-nokey"),
                (SIG_HEADER, "ed25519=AAAA"),
            ],
        ),
    )
    .await;
    clear_fed_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "since sig + no key must 401; body={b}"
    );
}

#[tokio::test]
async fn sync_since_enrolled_key_valid_sig_passes() {
    let _g = FED_ENV_LOCK.lock().await;
    clear_fed_env();
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_NONCE_ENV, "0");
    }
    let peer = "ai:cov-since-ok";
    let (_dir, signing) = enroll_peer(peer);
    let path = ai_memory::handlers::routes::SYNC_SINCE;
    let query = "limit=5";
    // canonical_get_bytes is `method || 0x0A || path || 0x0A || query`
    // (federation_signing_check.rs). Reproduce it here — the helper is
    // pub(super) so not reachable from an integration test.
    let mut canonical = Vec::new();
    canonical.extend_from_slice(b"GET");
    canonical.push(b'\n');
    canonical.extend_from_slice(path.as_bytes());
    canonical.push(b'\n');
    canonical.extend_from_slice(query.as_bytes());
    let sig = ai_memory::federation::signing::sign_body_header(&signing, &canonical);
    let (r, _t) = sqlite_router();
    let (status, _b) = decode(
        &r,
        get_since_req(query, &[(PEER_HEADER, peer), (SIG_HEADER, &sig)]),
    )
    .await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "since valid sig must pass; status={status}"
    );
}

// ---------------------------------------------------------------------------
// federation/sync — broadcast_{archive,consolidate,delete,link}_quorum.
// ---------------------------------------------------------------------------

fn ga2_memory(id: &str) -> ai_memory::models::Memory {
    let now = chrono::Utc::now().to_rfc3339();
    ai_memory::models::Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: "covga2".to_string(),
        title: "broadcast row".to_string(),
        content: "quorum fanout test".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:cov-ga2"}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    }
}

fn ga2_link() -> ai_memory::models::MemoryLink {
    ai_memory::models::MemoryLink {
        source_id: "ga2-src".to_string(),
        target_id: "ga2-tgt".to_string(),
        relation: ai_memory::models::MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
    }
}

/// W=1 quorum config with `peers`. W=1 means the local commit alone meets
/// quorum so the broadcast returns `Ok(tracker)` regardless of peer
/// outcomes — letting us exercise the full body cheaply with no live peer.
fn quorum_config(
    peers: Vec<ai_memory::federation::PeerEndpoint>,
) -> ai_memory::federation::FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()
        .unwrap();
    ai_memory::federation::FederationConfig {
        policy: ai_memory::replication::QuorumPolicy::new(
            std::cmp::max(1, peers.len() + 1),
            1,
            Duration::from_millis(400),
            Duration::from_secs(30),
        )
        .unwrap(),
        peers,
        client,
        sender_agent_id: "ai:cov-ga2-sender".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

/// An unreachable peer (closed loopback port) so post_and_classify yields
/// `Fail` after its retry — exercising the fanout `joins.spawn` closure,
/// the `AckOutcome::Fail` match arm, and the post-quorum detached drain.
fn unreachable_peer() -> ai_memory::federation::PeerEndpoint {
    ai_memory::federation::PeerEndpoint {
        id: "peer-ga2-dead".to_string(),
        // 127.0.0.1:1 is reserved + unbound → connection refused fast.
        sync_push_url: "http://127.0.0.1:1/api/v1/sync/push".to_string(),
    }
}

#[tokio::test]
async fn broadcast_archive_quorum_no_peers_ok() {
    let cfg = quorum_config(Vec::new());
    let tracker = ai_memory::federation::sync::broadcast_archive_quorum(&cfg, "arch-1")
        .await
        .expect("archive quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_delete_quorum_no_peers_ok() {
    let cfg = quorum_config(Vec::new());
    let tracker = ai_memory::federation::sync::broadcast_delete_quorum(&cfg, "del-1")
        .await
        .expect("delete quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_link_quorum_no_peers_ok() {
    let cfg = quorum_config(Vec::new());
    let link = ga2_link();
    let tracker = ai_memory::federation::sync::broadcast_link_quorum(&cfg, &link)
        .await
        .expect("link quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_consolidate_quorum_no_peers_ok() {
    let cfg = quorum_config(Vec::new());
    let mem = ga2_memory("consol-new");
    let sources = vec!["src-a".to_string(), "src-b".to_string()];
    let tracker = ai_memory::federation::sync::broadcast_consolidate_quorum(&cfg, &mem, &sources)
        .await
        .expect("consolidate quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_quorum_with_unreachable_peer_exercises_fanout_fail_arm() {
    // W=1 + one unreachable peer: local commit meets quorum, the peer
    // fanout closure runs and yields Fail (connection refused, retried),
    // hitting the AckOutcome::Fail warn arm + the post-quorum detached
    // drain `if !joins.is_empty()`. All four broadcast functions share
    // this loop shape; archive exercises it here.
    let cfg = quorum_config(vec![unreachable_peer()]);
    let tracker = ai_memory::federation::sync::broadcast_archive_quorum(&cfg, "arch-fanout")
        .await
        .expect("archive quorum with dead peer still returns Ok at W=1");
    // Only the local commit ack; no peer ack.
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());

    let cfg2 = quorum_config(vec![unreachable_peer()]);
    let link = ga2_link();
    let t2 = ai_memory::federation::sync::broadcast_link_quorum(&cfg2, &link)
        .await
        .expect("link quorum with dead peer still returns Ok at W=1");
    assert!(t2.finalise(std::time::Instant::now()).is_ok());
}

// ---------------------------------------------------------------------------
// postgres sync_push_via_store — gated on AI_MEMORY_TEST_POSTGRES_URL.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

#[cfg(feature = "sal-postgres")]
async fn pg_router(url: &str) -> axum::Router {
    use tokio::sync::RwLock;
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres"),
    );
    let app_state = AppState {
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
        storage_backend: StorageBackend::Postgres,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["ai:cov-ga2".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_sync_push_via_store_empty_batch_acks() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP pg_sync_push_via_store_empty_batch_acks: AI_MEMORY_TEST_POSTGRES_URL not set"
        );
        return;
    };
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": "ai:cov-ga2-pg",
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert!(
        status.is_success(),
        "pg empty sync_push_via_store acks; status={status} body={b}"
    );
    assert_eq!(b["storage_backend"], "postgres");
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_sync_push_via_store_invalid_sender_rejected() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP pg_sync_push_via_store_invalid_sender_rejected: AI_MEMORY_TEST_POSTGRES_URL not set"
        );
        return;
    };
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": "bad id with spaces",
        "sender_clock": {"entries": {}},
        "memories": []
    }))
    .unwrap();
    let (status, _b) = decode(&r, push_req(&body, &[])).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
        "invalid pg sender rejected; status={status}"
    );
}
