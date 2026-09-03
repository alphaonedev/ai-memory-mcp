// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

//! FED-RQ-01 (#1936) — commit-checkpoint RESOLUTIONS federate over `/sync/push`.
//!
//! Drives the FULL HTTP receive funnel (`handlers::sync_push`) with a
//! `checkpoints` subcollection and asserts the authority-lane behaviour the
//! spec pins (epic #1940; format spine votes `4d3ea1c5` + #1947 decision
//! `00d599ec`):
//!
//! - **EpochAdvance round-trip (strict).** A resolver-enrolled, operator-signed
//!   `EpochAdvance` resolution round-trips peer→peer and lands resolved +
//!   attested under the fail-closed default — the §25.2 "epoch closure" leg.
//! - **Strict-gate refusal.** An unenrolled resolver is refused under the
//!   default fail-closed knob (`AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG=1`).
//! - **Escape hatch.** The same unenrolled resolution applies once the operator
//!   opts out (`=0`).
//! - **Forged-signature reject is unconditional** — a signature that does not
//!   verify against the resolver's enrolled key is refused EVEN under permissive.
//! - **Idempotent replay** is a no-op; a **divergent** resolution is a
//!   first-resolution-wins conflict (local kept).
//! - **Outbound inclusion.** `broadcast_checkpoint_resolution_quorum` carries the
//!   resolved checkpoint in the `/sync/push` body it fans out.
//!
//! Env-serialised: the funnel reads `AI_MEMORY_KEY_DIR` (resolver enrollment),
//! the strict/permissive knob, and the peer-enrollment posture from the
//! process-global environment, so every case runs under one async mutex.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::identity::keypair as kp_mod;

/// Process-global async mutex — the funnel reads env vars this test mutates.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const RESOLVER_ENROLLED: &str = "ai:epoch-operator-1936";
const RESOLVER_GHOST: &str = "ai:ghost-resolver-1936";
const CHECKPOINT_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG";

/// Shared key dir for the process (leaked so the path stays valid for every
/// request). The enrolled resolver's PUBLIC key is written here once; the
/// funnel's `lookup_peer_public_key` reads `AI_MEMORY_KEY_DIR`.
fn enrolled_key_dir() -> (&'static std::path::Path, kp_mod::AgentKeypair) {
    use std::sync::OnceLock;
    static DIR: OnceLock<(std::path::PathBuf, kp_mod::AgentKeypair)> = OnceLock::new();
    let (p, kp) = DIR.get_or_init(|| {
        let tmp = tempfile::TempDir::new().expect("key tempdir");
        let path = tmp.path().to_path_buf();
        std::mem::forget(tmp); // leak: keep the dir for the whole test binary
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

/// Point the funnel at the enrolled key dir + reach the checkpoint loop (the
/// v0.8 strict peer-enrollment default would 401 an unenrolled push before the
/// funnel; opt to the permissive posture like `tests/g_issue_238`). Held under
/// `ENV_LOCK` by every caller.
fn reset_env(require_checkpoint_sig: Option<&str>) {
    let (dir, _) = enrolled_key_dir();
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

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"))
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
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
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

/// A resolved `EpochAdvance` checkpoint signed by `signer`, attributed to
/// `resolved_by`. Mirrors `src/cli/epoch_apply.rs`'s triple-anchor build.
fn resolved_epoch_checkpoint(
    id: &str,
    resolved_by: &str,
    verdict: &str,
    signer: &kp_mod::AgentKeypair,
) -> ai_memory::models::Checkpoint {
    let now = 1_700_000_900_i64;
    let mut cp = ai_memory::models::Checkpoint {
        id: id.to_string(),
        namespace: "_epoch".to_string(),
        title: "epoch advance 7".to_string(),
        condition_type: ai_memory::models::ConditionType::EpochAdvance,
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
        resolved_at: Some(now),
        metadata: Value::Null,
    };
    ai_memory::checkpoints::sign_resolution_into(&mut cp, signer).expect("sign resolution");
    cp
}

fn push_body(cp: &ai_memory::models::Checkpoint) -> Value {
    json!({
        "sender_agent_id": "peer-1936",
        "sender_clock": {"entries": {}},
        "memories": [],
        "checkpoints": [serde_json::to_value(cp).expect("serialise checkpoint")],
        "dry_run": false,
    })
}

async fn post_push(router: axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            "peer-1936",
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn count_resolved(db: &ai_memory::handlers::Db, id: &str) -> Option<String> {
    let lock = db.lock().await;
    ai_memory::checkpoints::get(&lock.0, id)
        .unwrap()
        .filter(|c| c.state == ai_memory::models::CheckpointState::Resolved)
        .and_then(|c| c.resolution)
}

// ---------------------------------------------------------------------------
// D — EpochAdvance round-trip under the fail-closed default.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn epoch_advance_resolution_round_trips_strict() {
    let _guard = ENV_LOCK.lock().await;
    reset_env(None); // knob unset → default fail-closed
    let (_dir, resolver_kp) = enrolled_key_dir();
    let (router, db) = build_router_with_db();
    let cp = resolved_epoch_checkpoint("cp-epoch-rt", RESOLVER_ENROLLED, "deadbeef", &resolver_kp);

    let (status, resp) = post_push(router, &push_body(&cp)).await;
    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(resp["checkpoints_applied"], json!(1), "resp={resp}");
    assert_eq!(
        count_resolved(&db, "cp-epoch-rt").await.as_deref(),
        Some("deadbeef")
    );

    // The verify-only consumer (#1878) accepts the round-tripped attestation:
    // the persisted resolution verifies under the enrolled resolver key.
    let lock = db.lock().await;
    let got = ai_memory::checkpoints::get(&lock.0, "cp-epoch-rt")
        .unwrap()
        .expect("present");
    assert!(
        ai_memory::checkpoints::verify(&got),
        "round-tripped EpochAdvance resolution must verify (attestation persisted verbatim)"
    );
}

// ---------------------------------------------------------------------------
// C — strict gate refusal + escape hatch.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn strict_refuses_unenrolled_resolver() {
    let _guard = ENV_LOCK.lock().await;
    reset_env(Some("1")); // explicit fail-closed
    // A resolver with NO enrolled key on the receiver, signed by its own key.
    let ghost_kp = kp_mod::generate(RESOLVER_GHOST).unwrap();
    let (router, db) = build_router_with_db();
    let cp = resolved_epoch_checkpoint("cp-strict-ghost", RESOLVER_GHOST, "ghosted", &ghost_kp);

    let (status, resp) = post_push(router, &push_body(&cp)).await;
    assert_eq!(status, StatusCode::OK, "batch survives: resp={resp}");
    assert_eq!(resp["checkpoints_applied"], json!(0), "resp={resp}");
    assert!(count_resolved(&db, "cp-strict-ghost").await.is_none());
}

#[tokio::test]
async fn escape_hatch_permissive_applies_unenrolled() {
    let _guard = ENV_LOCK.lock().await;
    reset_env(Some("0")); // operator opt-out
    let ghost_kp = kp_mod::generate(RESOLVER_GHOST).unwrap();
    let (router, db) = build_router_with_db();
    let cp = resolved_epoch_checkpoint("cp-permissive", RESOLVER_GHOST, "allowed", &ghost_kp);

    let (status, resp) = post_push(router, &push_body(&cp)).await;
    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(resp["checkpoints_applied"], json!(1), "resp={resp}");
    assert_eq!(
        count_resolved(&db, "cp-permissive").await.as_deref(),
        Some("allowed")
    );
}

// ---------------------------------------------------------------------------
// E — forged signature rejected unconditionally (even permissive).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forged_signature_rejected_even_permissive() {
    let _guard = ENV_LOCK.lock().await;
    reset_env(Some("0")); // permissive — forged still refused
    // Sign with mallory's key but attribute to the ENROLLED resolver: the
    // signature will not verify against the resolver's enrolled key.
    let mallory = kp_mod::generate("ai:mallory-1936").unwrap();
    let (router, db) = build_router_with_db();
    let cp = resolved_epoch_checkpoint("cp-forged", RESOLVER_ENROLLED, "forged", &mallory);

    let (status, resp) = post_push(router, &push_body(&cp)).await;
    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(
        resp["checkpoints_applied"],
        json!(0),
        "forged must not apply: resp={resp}"
    );
    assert!(count_resolved(&db, "cp-forged").await.is_none());
}

// ---------------------------------------------------------------------------
// B — idempotent replay + first-resolution-wins conflict.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn idempotent_replay_is_noop() {
    let _guard = ENV_LOCK.lock().await;
    reset_env(None);
    let (_dir, resolver_kp) = enrolled_key_dir();
    let (router1, db) = build_router_with_db();
    let cp = resolved_epoch_checkpoint("cp-replay", RESOLVER_ENROLLED, "once", &resolver_kp);

    let (_s1, r1) = post_push(router1, &push_body(&cp)).await;
    assert_eq!(r1["checkpoints_applied"], json!(1));

    // Byte-identical replay against the SAME substrate → Noop, no re-apply.
    let router2 = router_sharing_db(&db);
    let (_s2, r2) = post_push(router2, &push_body(&cp)).await;
    assert_eq!(
        r2["checkpoints_applied"],
        json!(0),
        "replay applies nothing: resp={r2}"
    );
    assert_eq!(
        r2["checkpoints_conflicted"],
        json!(0),
        "identical replay is not a conflict: resp={r2}"
    );
    assert_eq!(r2["noop"], json!(1), "resp={r2}");
    assert_eq!(
        count_resolved(&db, "cp-replay").await.as_deref(),
        Some("once")
    );
}

#[tokio::test]
async fn divergent_resolution_conflicts_first_wins() {
    let _guard = ENV_LOCK.lock().await;
    reset_env(None);
    let (_dir, resolver_kp) = enrolled_key_dir();
    let (router, db) = build_router_with_db();

    let first =
        resolved_epoch_checkpoint("cp-conflict", RESOLVER_ENROLLED, "approved", &resolver_kp);
    let (_s1, r1) = post_push(router, &push_body(&first)).await;
    assert_eq!(r1["checkpoints_applied"], json!(1));

    // A DIFFERENT resolution for the same id, posted through a fresh router
    // bound to the SAME db.
    let second =
        resolved_epoch_checkpoint("cp-conflict", RESOLVER_ENROLLED, "rejected", &resolver_kp);
    let router2 = router_sharing_db(&db);
    let (_s2, r2) = post_push(router2, &push_body(&second)).await;
    assert_eq!(r2["checkpoints_applied"], json!(0), "resp={r2}");
    assert_eq!(r2["checkpoints_conflicted"], json!(1), "resp={r2}");
    assert_eq!(
        count_resolved(&db, "cp-conflict").await.as_deref(),
        Some("approved"),
        "first resolution wins"
    );
}

/// Build a second router that shares the given DB handle (so a two-push
/// sequence lands against one substrate).
fn router_sharing_db(db: &ai_memory::handlers::Db) -> axum::Router {
    let store: Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"))
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
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
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(
        ai_memory::handlers::ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: std::sync::Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app_state,
    )
}

// ---------------------------------------------------------------------------
// A — outbound inclusion: the broadcast carries the checkpoint in the body.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn broadcast_includes_checkpoint_in_push_body() {
    use std::sync::Mutex as StdMutex;
    // Capturing mock peer — records the raw request body.
    #[derive(Clone)]
    struct Cap(Arc<StdMutex<Vec<String>>>);
    async fn handler(State(cap): State<Cap>, body: String) -> impl IntoResponse {
        cap.0.lock().unwrap().push(body);
        (StatusCode::OK, "{}")
    }
    let cap = Cap(Arc::new(StdMutex::new(Vec::new())));
    let app = axum::Router::new()
        .route("/api/v1/sync/push", post(handler))
        .with_state(cap.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let cfg = ai_memory::federation::FederationConfig {
        policy: ai_memory::replication::QuorumPolicy::new(
            2,
            1,
            Duration::from_secs(2),
            Duration::from_secs(30),
        )
        .unwrap(),
        peers: vec![ai_memory::federation::PeerEndpoint {
            id: "peer-cap".to_string(),
            sync_push_url: format!("http://{addr}/api/v1/sync/push"),
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap(),
        sender_agent_id: "ai:sender-1936".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    };

    let signer = kp_mod::generate(RESOLVER_ENROLLED).unwrap();
    let cp = resolved_epoch_checkpoint("cp-outbound", RESOLVER_ENROLLED, "shipped", &signer);
    let _ = ai_memory::federation::broadcast_checkpoint_resolution_quorum(&cfg, &cp).await;

    let bodies = cap.0.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1, "peer must receive exactly one push");
    let parsed: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(
        parsed["checkpoints"][0]["id"],
        json!("cp-outbound"),
        "the checkpoint resolution must be included in the /sync/push body: {parsed}"
    );
    assert_eq!(parsed["checkpoints"][0]["resolution"], json!("shipped"));
}
