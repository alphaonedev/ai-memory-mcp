// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! CB-3 / #2708 (CWE-284, security-high) — the federated commit-checkpoint
//! RESOLUTION receive lane (`POST /api/v1/sync/push` `checkpoints[]`) must
//! confine an inbound resolution to the peer's per-peer `allowed_namespaces`
//! scope against the checkpoint's STORED namespace, not the attacker-chosen
//! wire `cp.namespace`.
//!
//! Pre-fix, the Gate-1 choke validated the WIRE `cp.namespace` while
//! `checkpoints::apply_inbound_resolution` CASes on `(id, state)` ONLY —
//! `UPDATE checkpoints SET state=…,resolution=… WHERE id=? AND state='pending'`
//! never compares or writes the namespace. So a peer enrolled + scoped to
//! `public/*` could push a RESOLVED checkpoint whose `id` is a locally-pending
//! `secure/ops` freeze anchor, present `namespace: "public/ok"` on the wire
//! (which `resolution_signable` covers, so a self-signed resolution verifies),
//! and have the CAS resolve the `secure/ops` anchor it has no scope for — the
//! #2447 stored-vs-claimed split applied to the checkpoints authority lane.
//!
//! The fix mirrors the memories lane (`inbound_write_namespace_authorized` with
//! BOTH the claimed AND the STORED namespace): the receive loop resolves the
//! local row's namespace by id (`checkpoints::namespace_by_id`) and refuses when
//! EITHER is out of scope. The two legitimate arms stay intact — a first-landing
//! resolution (no local row) creates under the claimed namespace, and a
//! resolution of a locally-pending anchor is confined to that anchor's STORED
//! namespace.
//!
//! Every test here is R-203-shaped: the exploit FAILS on the parent commit
//! (the CAS resolves the out-of-scope anchor) and PASSES after. The posture
//! guards pin the regressions a naive fix would cause (zero-config unaffected;
//! in-scope resolution still applies; first-resolution-wins idempotency held).
//!
//! Postgres note: the pg funnel buckets `checkpoints[]` as
//! `unsupported_on_postgres` (#1936) — it never applies a federated resolution
//! — so this bypass is sqlite/MCP-native-only and so is the fix + this test.
//!
//! Env-serialised under one async mutex: the funnel reads `AI_MEMORY_KEY_DIR`
//! (resolver enrollment), `AI_MEMORY_FED_PEER_ATTESTATION` (the peer scope), and
//! the sig/enrollment knobs from the process-global environment.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::identity::keypair as kp_mod;
use ai_memory::models::{Checkpoint, CheckpointState, ConditionType};

/// Process-global async mutex — the funnel reads env vars these tests mutate.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// The enrolled resolver AND the pushing peer are the same identity — the peer
/// self-resolves a checkpoint. Its Ed25519 pubkey is enrolled (so the
/// resolution signature verifies under the strict checkpoint-sig default) and
/// its `X-Peer-Id` is scoped to `public/*`.
const PEER_ID: &str = "ai:evil-2708";
const VICTIM_NS: &str = "secure/ops";
const IN_SCOPE_NS: &str = "public/ok";
const CHECKPOINT_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG";

/// `ai:evil-2708` may push as itself, scoped to `public/*` only.
fn scoped_allowlist() -> String {
    format!(
        r#"{{"{PEER_ID}":{{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["{PEER_ID}"]}}}}"#
    )
}

/// Shared key dir for the process (leaked so the path stays valid for every
/// request). The peer/resolver's PUBLIC key is enrolled here once; the funnel's
/// `lookup_peer_public_key` reads `AI_MEMORY_KEY_DIR`.
fn enrolled_key_dir() -> (&'static std::path::Path, kp_mod::AgentKeypair) {
    use std::sync::OnceLock;
    static DIR: OnceLock<(std::path::PathBuf, kp_mod::AgentKeypair)> = OnceLock::new();
    let (p, kp) = DIR.get_or_init(|| {
        let tmp = tempfile::TempDir::new().expect("key tempdir");
        let path = tmp.path().to_path_buf();
        std::mem::forget(tmp); // leak: keep the dir for the whole test binary
        let kp = kp_mod::generate(PEER_ID).expect("generate resolver");
        let pub_only = kp_mod::AgentKeypair {
            agent_id: PEER_ID.to_string(),
            public: kp.public,
            private: None,
        };
        kp_mod::save_public_only(&pub_only, &path).expect("enroll resolver pubkey");
        (path, kp)
    });
    (p.as_path(), kp.clone())
}

/// Point the funnel at the enrolled key dir and the peer's namespace scope.
/// `scoped == false` = the ZERO-CONFIG posture (no peer allowlist at all).
/// Held under `ENV_LOCK` by every caller.
fn reset_env(scoped: bool) {
    let (dir, _) = enrolled_key_dir();
    unsafe {
        std::env::set_var(kp_mod::KEY_DIR_ENV, dir);
        // Reach the checkpoint loop: the v0.8 strict peer-enrollment default and
        // the outer envelope-sig default would refuse the push before the loop.
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_SIG", "0");
        std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        // Keep the INNER checkpoint-resolution sig strict (the default) so a
        // valid enrolled resolution passes the crypto gate and ONLY the
        // namespace gate is left to decide.
        std::env::remove_var(CHECKPOINT_SIG_ENV);
        // Leave AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE unset → default ON.
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        if scoped {
            std::env::set_var(
                ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
                scoped_allowlist(),
            );
        } else {
            std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        }
    }
}

fn clear_env() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_SIG");
        std::env::remove_var(CHECKPOINT_SIG_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
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

/// A locally-PENDING approval checkpoint in `namespace` (carries no
/// attestation — pending checkpoints are unsigned).
fn pending_checkpoint(id: &str, namespace: &str) -> Checkpoint {
    Checkpoint {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: "needs approval".to_string(),
        condition_type: ConditionType::Approval,
        condition: json!({}),
        state: CheckpointState::Pending,
        created_by: "ai:victim-2708".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: None,
        metadata: Value::Null,
    }
}

/// A RESOLVED approval checkpoint attributed to + signed by the enrolled peer,
/// carrying the attacker-chosen wire `namespace`.
fn resolved_checkpoint(id: &str, wire_namespace: &str, verdict: &str) -> Checkpoint {
    let (_dir, signer) = enrolled_key_dir();
    let mut cp = Checkpoint {
        id: id.to_string(),
        namespace: wire_namespace.to_string(),
        title: "needs approval".to_string(),
        condition_type: ConditionType::Approval,
        condition: json!({}),
        state: CheckpointState::Resolved,
        created_by: PEER_ID.to_string(),
        resolved_by: Some(PEER_ID.to_string()),
        resolution: Some(verdict.to_string()),
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: Some(1_700_000_900),
        metadata: Value::Null,
    };
    ai_memory::checkpoints::sign_resolution_into(&mut cp, &signer).expect("sign resolution");
    cp
}

fn push_body(cp: &Checkpoint) -> Value {
    json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "checkpoints": [serde_json::to_value(cp).expect("serialise checkpoint")],
        "dry_run": false,
    })
}

async fn post_push(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
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
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn seed_pending(db: &ai_memory::handlers::Db, cp: &Checkpoint) {
    let lock = db.lock().await;
    ai_memory::checkpoints::insert(&lock.0, cp).expect("seed pending checkpoint");
}

/// `(state, resolution)` of the checkpoint with `id`.
async fn checkpoint_state(
    db: &ai_memory::handlers::Db,
    id: &str,
) -> (CheckpointState, Option<String>) {
    let lock = db.lock().await;
    let cp = ai_memory::checkpoints::get(&lock.0, id)
        .expect("get checkpoint")
        .expect("checkpoint present");
    (cp.state, cp.resolution)
}

// ---------------------------------------------------------------------
// R-203 — the issue's literal failure scenario.
// ---------------------------------------------------------------------

#[tokio::test]
async fn out_of_scope_stored_anchor_cannot_be_resolved_by_wire_namespace_2708() {
    let _g = ENV_LOCK.lock().await;
    reset_env(true);
    let (router, db) = build_router_with_db();

    // A locally-pending freeze anchor in secure/ops (the peer is NOT scoped for
    // it).
    let anchor_id = "cp-secure-anchor-2708";
    seed_pending(&db, &pending_checkpoint(anchor_id, VICTIM_NS)).await;

    // EXPLOIT: the public/*-scoped peer pushes a RESOLVED checkpoint with the
    // secure/ops anchor's id but a `public/ok` WIRE namespace, self-signed and
    // enrolled (so the crypto gate passes). The CAS keys on (id, state) only, so
    // pre-fix it would resolve the secure/ops anchor while the gate saw only the
    // in-scope wire namespace.
    let (status, resp) = post_push(
        &router,
        &push_body(&resolved_checkpoint(
            anchor_id,
            IN_SCOPE_NS,
            "attacker-approved",
        )),
    )
    .await;
    assert!(
        status.is_success(),
        "#2708: sync_push must not hard-error (per-item skip, batch survives); got {status}"
    );
    assert_eq!(
        resp["checkpoints_applied"],
        json!(0),
        "#2708: a peer scoped to public/* must NOT resolve a secure/ops anchor: resp={resp}"
    );

    let (state, resolution) = checkpoint_state(&db, anchor_id).await;
    assert_eq!(
        state,
        CheckpointState::Pending,
        "#2708: the out-of-scope freeze anchor's STORED namespace is the write \
         subject — it must remain unresolved"
    );
    assert_eq!(
        resolution, None,
        "#2708: the attacker's resolution must not be stamped onto the anchor"
    );

    clear_env();
}

// ---------------------------------------------------------------------
// Posture guard — an in-scope resolution still applies (fix confines,
// does not brick the peer).
// ---------------------------------------------------------------------

#[tokio::test]
async fn in_scope_stored_anchor_resolution_applies_2708() {
    let _g = ENV_LOCK.lock().await;
    reset_env(true);
    let (router, db) = build_router_with_db();

    // A locally-pending anchor in the peer's declared scope.
    let anchor_id = "cp-public-anchor-2708";
    seed_pending(&db, &pending_checkpoint(anchor_id, IN_SCOPE_NS)).await;

    let (status, resp) = post_push(
        &router,
        &push_body(&resolved_checkpoint(
            anchor_id,
            IN_SCOPE_NS,
            "legit-approved",
        )),
    )
    .await;
    assert!(status.is_success(), "resp={resp}");
    assert_eq!(
        resp["checkpoints_applied"],
        json!(1),
        "#2708: an in-scope resolution of an in-scope stored anchor must apply: resp={resp}"
    );

    let (state, resolution) = checkpoint_state(&db, anchor_id).await;
    assert_eq!(state, CheckpointState::Resolved);
    assert_eq!(resolution.as_deref(), Some("legit-approved"));

    clear_env();
}

// ---------------------------------------------------------------------
// Posture guard — first-resolution-wins idempotency held under the gate.
// ---------------------------------------------------------------------

#[tokio::test]
async fn first_resolution_wins_idempotency_preserved_under_scope_gate_2708() {
    let _g = ENV_LOCK.lock().await;
    reset_env(true);
    let (router, db) = build_router_with_db();

    let anchor_id = "cp-idem-anchor-2708";
    seed_pending(&db, &pending_checkpoint(anchor_id, IN_SCOPE_NS)).await;

    // First in-scope resolution applies.
    let first = resolved_checkpoint(anchor_id, IN_SCOPE_NS, "approved");
    let (_s1, r1) = post_push(&router, &push_body(&first)).await;
    assert_eq!(r1["checkpoints_applied"], json!(1), "resp={r1}");

    // Byte-identical replay against the SAME substrate → Noop, no re-apply.
    let (_s2, r2) = post_push(&router, &push_body(&first)).await;
    assert_eq!(
        r2["checkpoints_applied"],
        json!(0),
        "#2708: idempotent replay applies nothing: resp={r2}"
    );
    assert_eq!(
        r2["checkpoints_conflicted"],
        json!(0),
        "#2708: identical replay is not a conflict: resp={r2}"
    );

    // A DIFFERENT resolution for the same id → first-resolution-wins conflict.
    let second = resolved_checkpoint(anchor_id, IN_SCOPE_NS, "rejected");
    let (_s3, r3) = post_push(&router, &push_body(&second)).await;
    assert_eq!(r3["checkpoints_applied"], json!(0), "resp={r3}");
    assert_eq!(r3["checkpoints_conflicted"], json!(1), "resp={r3}");

    let (state, resolution) = checkpoint_state(&db, anchor_id).await;
    assert_eq!(state, CheckpointState::Resolved);
    assert_eq!(
        resolution.as_deref(),
        Some("approved"),
        "#2708: first resolution wins under the scope gate"
    );

    clear_env();
}

// ---------------------------------------------------------------------
// Posture guard — zero-config federation is byte-identical to pre-fix.
// ---------------------------------------------------------------------

#[tokio::test]
async fn zero_config_checkpoint_federation_unaffected_2708() {
    let _g = ENV_LOCK.lock().await;
    // No AI_MEMORY_FED_PEER_ATTESTATION at all → the namespace gate short-
    // circuits (`has_allowlist() == false`) and no by-id existence probe runs.
    reset_env(false);
    let (router, db) = build_router_with_db();

    // Even a resolution touching a secure/ops anchor applies — zero-config makes
    // no namespace claim, exactly as before the fix.
    let anchor_id = "cp-zeroconf-anchor-2708";
    seed_pending(&db, &pending_checkpoint(anchor_id, VICTIM_NS)).await;

    let (status, resp) = post_push(
        &router,
        &push_body(&resolved_checkpoint(
            anchor_id,
            VICTIM_NS,
            "zeroconf-approved",
        )),
    )
    .await;
    assert!(status.is_success(), "resp={resp}");
    assert_eq!(
        resp["checkpoints_applied"],
        json!(1),
        "#2708: zero-config checkpoint federation must be byte-identical to pre-fix: resp={resp}"
    );

    let (state, resolution) = checkpoint_state(&db, anchor_id).await;
    assert_eq!(state, CheckpointState::Resolved);
    assert_eq!(resolution.as_deref(), Some("zeroconf-approved"));

    clear_env();
}
