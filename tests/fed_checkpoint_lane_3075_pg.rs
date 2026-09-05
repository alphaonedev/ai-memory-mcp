// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3075 lane L-PGP, family F4 — the POSTGRES half of the federated
//! `checkpoints[]` (commit-checkpoint RESOLUTION) lane proof.
//!
//! ## What changed
//!
//! Through v1.0.0 a postgres receiver bucketed `checkpoints[]` as
//! `unsupported_on_postgres`, so the FED-RQ-01 (#1936) separation-of-duties
//! freeze anchor — and with it the `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG`
//! (#125) binding — simply did not exist on that backend. Honest, but the
//! consequence is that an `EpochAdvance` freeze resolved on one node never
//! reached a pg peer: the two nodes then disagree about whether the epoch is
//! frozen, which is precisely the state the anchor exists to make unambiguous.
//!
//! #3075 routes the lane through the SAL trait
//! (`apply_remote_checkpoint_resolution`) with the sqlite receiver's
//! authorization, unchanged and SHARED — the same
//! `receive_auth::authorize_remote_checkpoint_resolution` verdict against the
//! resolver's locally-ENROLLED key, the same #2708 namespace confinement, the
//! same L5 reserved-anchor refusal, the same first-resolution-wins CRDT rule,
//! and the same rule that the receiver NEVER re-signs.
//!
//! ## Cells (each asserts an APPLIED and a REFUSED disposition on ROW STATE)
//!
//! 1. an enrolled, correctly-signed resolution APPLIES, and the persisted
//!    `signature` / `resolver_pubkey` are the SENDER'S bytes verbatim — the
//!    property that makes the anchor verifiable downstream and the one a
//!    "just call `checkpoint_resolve`" implementation would have destroyed;
//! 2. a FORGED signature is refused under the fail-closed default AND the row
//!    is untouched;
//! 3. an UNENROLLED resolver is refused under the default and ACCEPTED under
//!    the documented `=0` rollout hatch (so the knob is proven load-bearing on
//!    pg, not merely present);
//! 4. a substrate-RESERVED anchor kind is refused (L5) — the pg twin the
//!    `federation_reserved_anchor_l5.rs` parity note previously said did not
//!    exist;
//! 5. FIRST-RESOLUTION-WINS: a second, DIFFERENT resolution of an
//!    already-resolved anchor is a conflict that keeps the local verdict.
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip. Deliberately NOT `#[ignore]`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair as kp_mod;
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// Serialises every test in this binary — they all mutate process-global
/// federation env vars (key dir, enrollment posture, the #125 knob).
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const RESOLVER_ENROLLED: &str = "ai:epoch-operator-3075";
const RESOLVER_GHOST: &str = "ai:ghost-resolver-3075";
const CHECKPOINT_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG";
const PEER_ID: &str = "peer-3075-cp";

struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        // SAFETY: the holder owns FED_ENV_LOCK for the guard's lifetime.
        unsafe {
            std::env::remove_var(CHECKPOINT_SIG_ENV);
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        }
    }
}

/// RAII guard for the per-peer allowlist the #2708 cell installs — an
/// assertion panic must not leak an enrolled scope into the next test in this
/// binary.
struct AllowlistGuard;

impl Drop for AllowlistGuard {
    fn drop(&mut self) {
        // SAFETY: the holder owns FED_ENV_LOCK for the guard's lifetime.
        unsafe {
            std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        }
    }
}

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Shared key dir for the process (leaked so the path stays valid for every
/// request). The enrolled resolver's PUBLIC key is written here once; the
/// funnel's `lookup_peer_public_key` reads `AI_MEMORY_KEY_DIR`.
fn enrolled_key_dir() -> (&'static std::path::Path, kp_mod::AgentKeypair) {
    use std::sync::OnceLock;
    static DIR: OnceLock<(std::path::PathBuf, kp_mod::AgentKeypair)> = OnceLock::new();
    let (p, kp) = DIR.get_or_init(|| {
        let tmp = tempfile::TempDir::new().expect("key tempdir");
        let path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let kp = kp_mod::generate(RESOLVER_ENROLLED).expect("generate resolver");
        let pub_only = kp_mod::AgentKeypair {
            agent_id: RESOLVER_ENROLLED.to_string(),
            public: kp.public,
            private: None,
        };
        kp_mod::save_public_only(&pub_only, &path).expect("enroll resolver pubkey");
        (path, kp)
    });
    (p.as_path(), kp.clone())
}

/// Point the funnel at the enrolled key dir and reach the checkpoint loop (the
/// v0.8 strict peer-enrollment default would 401 the push before it).
fn reset_env(require_checkpoint_sig: Option<&str>) {
    let (dir, _) = enrolled_key_dir();
    // SAFETY: every caller holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(kp_mod::KEY_DIR_ENV, dir);
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        match require_checkpoint_sig {
            Some(v) => std::env::set_var(CHECKPOINT_SIG_ENV, v),
            None => std::env::remove_var(CHECKPOINT_SIG_ENV),
        }
    }
}

async fn pg_router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
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
    };
    (ai_memory::build_router(api_key_state, app_state), store)
}

async fn raw_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("raw pool for row-state assertions")
}

/// PRIMARY assertion surface — raw SQL, so no row mapper's own error folding
/// can colour the answer.
async fn row_state(pool: &sqlx::PgPool, id: &str) -> Option<(String, Option<String>, Vec<u8>)> {
    sqlx::query_as::<_, (String, Option<String>, Option<Vec<u8>>)>(
        "SELECT state, resolution, signature FROM checkpoints WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .expect("read checkpoint row")
    .map(|(state, resolution, sig)| (state, resolution, sig.unwrap_or_default()))
}

/// A resolved checkpoint of `kind` in `namespace`, signed by `signer` and
/// attributed to `resolved_by`.
fn resolved_checkpoint(
    id: &str,
    namespace: &str,
    kind: ai_memory::models::ConditionType,
    resolved_by: &str,
    verdict: &str,
    signer: &kp_mod::AgentKeypair,
) -> ai_memory::models::Checkpoint {
    let mut cp = ai_memory::models::Checkpoint {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: "epoch advance (3075 pg lane)".to_string(),
        condition_type: kind,
        condition: Value::Null,
        state: ai_memory::models::CheckpointState::Resolved,
        created_by: resolved_by.to_string(),
        resolved_by: Some(resolved_by.to_string()),
        resolution: Some(verdict.to_string()),
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: Some(1_700_000_900),
        metadata: Value::Null,
    };
    ai_memory::checkpoints::sign_resolution_into(&mut cp, signer).expect("sign resolution");
    cp
}

async fn push_checkpoint(
    router: &axum::Router,
    cp: &ai_memory::models::Checkpoint,
) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "checkpoints": [serde_json::to_value(cp).expect("serialise checkpoint")],
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER_ID,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

/// Cell 1 — the ALLOWED half, plus the NEVER-RE-SIGN invariant: the persisted
/// attestation must be the SENDER'S bytes, verbatim.
#[tokio::test]
async fn enrolled_signed_resolution_applies_verbatim_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    reset_env(None); // fail-closed default (#125)

    let (_dir, resolver_kp) = enrolled_key_dir();
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let id = uniq("cp3075");
    let cp = resolved_checkpoint(
        &id,
        "_epoch",
        ai_memory::models::ConditionType::EpochAdvance,
        RESOLVER_ENROLLED,
        "approve",
        &resolver_kp,
    );

    let (status, report) = push_checkpoint(&router, &cp).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    let (state, resolution, signature) = row_state(&pool, &id)
        .await
        .unwrap_or_else(|| panic!("#3075: the resolution must land on pg: {report}"));
    assert_eq!(state, "resolved", "{report}");
    assert_eq!(resolution.as_deref(), Some("approve"), "{report}");
    assert_eq!(
        signature, cp.signature,
        "the receiver must persist the SENDER's attestation verbatim and NEVER re-sign: {report}"
    );
    assert_eq!(
        report["checkpoints_applied"].as_u64().unwrap_or(0),
        1,
        "{report}"
    );
    assert_eq!(
        report["unsupported_on_postgres"].as_u64().unwrap_or(0),
        0,
        "#3075: checkpoints no longer bucket as unsupported: {report}"
    );
}

/// Cell 2 — a FORGED signature is refused UNCONDITIONALLY (the #125 knob does
/// not govern it) and the row is untouched.
#[tokio::test]
async fn forged_resolution_signature_refused_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    reset_env(Some("0")); // even the permissive rollout hatch must refuse a forgery

    let (_dir, resolver_kp) = enrolled_key_dir();
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let id = uniq("cp3075f");
    let mut cp = resolved_checkpoint(
        &id,
        "_epoch",
        ai_memory::models::ConditionType::EpochAdvance,
        RESOLVER_ENROLLED,
        "approve",
        &resolver_kp,
    );
    // Tamper the signed verdict AFTER signing: the signature no longer verifies
    // against the resolver's enrolled key.
    cp.resolution = Some("reject".to_string());

    let (status, report) = push_checkpoint(&router, &cp).await;
    assert_eq!(status, StatusCode::OK, "the batch survives: {report}");
    assert!(
        row_state(&pool, &id).await.is_none(),
        "#125: a forged resolution must not land on pg, even under the =0 hatch: {report}"
    );
    assert_eq!(
        report["checkpoints_applied"].as_u64().unwrap_or(0),
        0,
        "{report}"
    );
}

/// Cell 3 — the #125 knob is LOAD-BEARING on pg: an unenrolled resolver is
/// refused under the fail-closed default and accepted under the documented
/// rollout hatch.
#[tokio::test]
async fn unenrolled_resolver_refused_then_hatch_applies_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;

    let ghost = kp_mod::generate(RESOLVER_GHOST).expect("generate ghost resolver");
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    // Strict (default): refused.
    reset_env(None);
    let strict_id = uniq("cp3075u");
    let cp = resolved_checkpoint(
        &strict_id,
        "_epoch",
        ai_memory::models::ConditionType::EpochAdvance,
        RESOLVER_GHOST,
        "approve",
        &ghost,
    );
    let (status, report) = push_checkpoint(&router, &cp).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        row_state(&pool, &strict_id).await.is_none(),
        "#125 fail-closed: an unenrolled resolver must be refused on pg: {report}"
    );

    // Permissive rollout hatch: applied.
    reset_env(Some("0"));
    let hatch_id = uniq("cp3075h");
    let cp = resolved_checkpoint(
        &hatch_id,
        "_epoch",
        ai_memory::models::ConditionType::EpochAdvance,
        RESOLVER_GHOST,
        "approve",
        &ghost,
    );
    let (status, report) = push_checkpoint(&router, &cp).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        row_state(&pool, &hatch_id).await.is_some(),
        "the documented =0 rollout hatch must apply on pg too: {report}"
    );
    assert_eq!(
        report["checkpoints_applied"].as_u64().unwrap_or(0),
        1,
        "{report}"
    );
}

/// Cell 4 — L5: a substrate-RESERVED anchor kind is refused. This is the
/// postgres twin `tests/federation_reserved_anchor_l5.rs` previously recorded
/// as non-existent (because the lane itself did not exist on pg).
#[tokio::test]
async fn reserved_anchor_kind_refused_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    reset_env(None);

    let (_dir, resolver_kp) = enrolled_key_dir();
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let id = uniq("cp3075r");
    // Correctly signed by an ENROLLED resolver — so the ONLY thing standing
    // between this push and a write is the reserved-kind gate.
    let cp = resolved_checkpoint(
        &id,
        "team/ops",
        ai_memory::models::ConditionType::AuditHeadWitness,
        RESOLVER_ENROLLED,
        "approve",
        &resolver_kp,
    );

    let (status, report) = push_checkpoint(&router, &cp).await;
    assert_eq!(status, StatusCode::OK, "the batch survives: {report}");
    assert!(
        row_state(&pool, &id).await.is_none(),
        "L5: a wire-reachable push must not steer the substrate's audit-signal spine: {report}"
    );
    assert_eq!(
        report["checkpoints_applied"].as_u64().unwrap_or(0),
        0,
        "{report}"
    );
}

/// Cell 5 — FIRST-RESOLUTION-WINS: a second, DIFFERENT resolution of an
/// already-resolved anchor is a conflict and the LOCAL verdict is kept.
#[tokio::test]
async fn first_resolution_wins_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    reset_env(None);

    let (_dir, resolver_kp) = enrolled_key_dir();
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let id = uniq("cp3075c");

    let first = resolved_checkpoint(
        &id,
        "_epoch",
        ai_memory::models::ConditionType::EpochAdvance,
        RESOLVER_ENROLLED,
        "approve",
        &resolver_kp,
    );
    let (status, report) = push_checkpoint(&router, &first).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(
        row_state(&pool, &id)
            .await
            .and_then(|(_, r, _)| r)
            .as_deref(),
        Some("approve"),
        "precondition: the first resolution landed: {report}"
    );

    // A byte-identical replay is an idempotent no-op, not a conflict.
    let (_, replay_report) = push_checkpoint(&router, &first).await;
    assert_eq!(
        replay_report["checkpoints_conflicted"]
            .as_u64()
            .unwrap_or(0),
        0,
        "a byte-identical replay is a no-op, never a conflict: {replay_report}"
    );

    // A DIFFERENT verdict for the same anchor loses.
    let second = resolved_checkpoint(
        &id,
        "_epoch",
        ai_memory::models::ConditionType::EpochAdvance,
        RESOLVER_ENROLLED,
        "reject",
        &resolver_kp,
    );
    let (status, report) = push_checkpoint(&router, &second).await;
    assert_eq!(status, StatusCode::OK, "the batch survives: {report}");
    assert_eq!(
        row_state(&pool, &id)
            .await
            .and_then(|(_, r, _)| r)
            .as_deref(),
        Some("approve"),
        "first-resolution-wins: the LOCAL verdict is kept on pg: {report}"
    );
    assert_eq!(
        report["checkpoints_conflicted"].as_u64().unwrap_or(0),
        1,
        "the conflict is sender-visible, never a silent overwrite: {report}"
    );
}

/// Cell 6 — #2708 (CB-3, CWE-284): the namespace confinement, on pg. A peer
/// scoped to `<root>/**` may resolve an anchor in its own scope and must NOT
/// resolve one outside it. Both halves in one cell, correctly signed by an
/// ENROLLED resolver, so the namespace gate is the only variable.
#[tokio::test]
async fn checkpoint_namespace_scope_gated_on_postgres_3075_2708() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    reset_env(None);

    let root = uniq("cpscope");
    let in_scope_ns = format!("{root}/ok");
    let victim_ns = uniq("securecp");
    // SAFETY: this test holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{PEER_ID}":{{"allowed_namespaces":["{root}/**"],"allowed_sender_agent_ids":["{PEER_ID}"]}}}}"#
            ),
        );
    }
    let _allow = AllowlistGuard;

    let (_dir, resolver_kp) = enrolled_key_dir();
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let in_id = uniq("cp3075n");
    let cp = resolved_checkpoint(
        &in_id,
        &in_scope_ns,
        ai_memory::models::ConditionType::Approval,
        RESOLVER_ENROLLED,
        "approve",
        &resolver_kp,
    );
    let (status, report) = push_checkpoint(&router, &cp).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        row_state(&pool, &in_id).await.is_some(),
        "#3075: an in-scope resolution must APPLY on pg: {report}"
    );

    let out_id = uniq("cp3075x");
    let cp = resolved_checkpoint(
        &out_id,
        &victim_ns,
        ai_memory::models::ConditionType::Approval,
        RESOLVER_ENROLLED,
        "approve",
        &resolver_kp,
    );
    let (status, report) = push_checkpoint(&router, &cp).await;
    assert_eq!(status, StatusCode::OK, "the batch survives: {report}");
    assert!(
        row_state(&pool, &out_id).await.is_none(),
        "#2708: a peer scoped to {root}/** must NOT resolve a foreign-namespace anchor: {report}"
    );
    assert_eq!(
        report["checkpoints_applied"].as_u64().unwrap_or(0),
        0,
        "{report}"
    );
}
