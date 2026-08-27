// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3049 / #3269 / #3278 — federation-RECEIVE secret screen for the
//! coordination plane.
//!
//! A `/sync/push` `signals[]` / `checkpoints[]` / `pendings[]` entry carrying a
//! credential must be REDACTED (never refused — a refusal would diverge
//! replicas, the #1821 lesson) before it is persisted. The gate is
//! `secret_screen::redact_signal_for_storage` / `redact_checkpoint_for_storage`
//! / `redact_pending_action_for_storage` wired in `handlers::federation_receive`
//! AFTER the forged-signature / authorship / namespace-scope /
//! checkpoint-resolution-authz gates so those still see the bytes the peer
//! signed, and BEFORE `signals::insert` / `checkpoints::apply_inbound_resolution`
//! / `db::upsert_pending_action`.
//!
//! #3269 — a hostile peer must NOT be able to bypass the screen by renaming a
//! JSON key to a `#1844` crypto carve-out name (`*_b64` / the exact set): the
//! receive helpers screen with the name carve-out DISABLED, recursing into
//! carved-out subtrees. #3278 — `Signal.reference_ids` and `pendings[].payload`
//! (previously persisted unscreened on this endpoint) are screened too.
//!
//! Dedicated binary: `secret_screen::SCREEN_MODE` is a process-wide
//! `OnceLock` (first writer wins). This file is the only setter in this
//! process.

#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::receive_auth::{REQUIRE_CHECKPOINT_SIG_ENV, REQUIRE_SIGNAL_SIG_ENV};
use ai_memory::federation::signing::REQUIRE_SIG_ENV;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{
    Checkpoint, CheckpointState, ConditionType, PendingAction, Signal, SignalType,
};
use ai_memory::secret_screen::{REDACTION_PLACEHOLDER, SecretScreenMode, set_screen_mode};

/// Canonical AWS access-key fixture the detector is pinned on
/// (`src/secret_screen.rs::detects_aws_access_key`).
const AWS_AKIA_FIXTURE: &str = "AKIAIOSFODNN7EXAMPLE";

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn seed_screen_mode_refuse() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| set_screen_mode(SecretScreenMode::Refuse));
}

fn setup_router() -> (axum::Router, Db) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    std::mem::forget(db_tmp);
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let app_state = AppState {
        db: db.clone(),
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
        #[cfg(feature = "sal")]
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
        ),
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
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

/// Isolate the #3049 screen: disable the orthogonal federation gates so an
/// unsigned inbound coordination row reaches the screen arm. Zero-config
/// (no peer allowlist) so Layer-1 authorship / namespace-scope are no-ops.
fn relax_orthogonal_gates() {
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, "0");
        std::env::set_var(REQUIRE_CHECKPOINT_SIG_ENV, "0");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
}

fn clear_all_env() {
    unsafe {
        std::env::remove_var(REQUIRE_SIG_ENV);
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV);
        std::env::remove_var(REQUIRE_CHECKPOINT_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
}

fn make_signal(from_agent: &str, namespace: &str, subject: &str, body: Value) -> Signal {
    Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        from_agent: from_agent.to_string(),
        to_agent: None,
        subject: subject.to_string(),
        body,
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: json!([]),
        created_at: 1_700_000_000,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    }
}

fn make_checkpoint(id: &str, namespace: &str, title: &str, resolution: &str) -> Checkpoint {
    Checkpoint {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: title.to_string(),
        condition_type: ConditionType::Approval,
        condition: json!({}),
        state: CheckpointState::Resolved,
        created_by: "ai:peer-3049".to_string(),
        resolved_by: Some("ai:peer-3049".to_string()),
        resolution: Some(resolution.to_string()),
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: Some(1_700_000_900),
        metadata: Value::Null,
    }
}

async fn post_sync_push(router: &axum::Router, body: Value, peer_id: &str) -> (StatusCode, Value) {
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            peer_id,
        )
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn i(v: &Value, key: &str) -> i64 {
    v[key].as_i64().unwrap_or(-1)
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_signal_secret_is_redacted_not_skipped_3049() {
    let _g = env_lock();
    seed_screen_mode_refuse();
    clear_all_env();
    relax_orthogonal_gates();
    let (router, db) = setup_router();

    let sig = make_signal(
        "ai:peer-3049",
        "coord/screen",
        &format!("rotate key {AWS_AKIA_FIXTURE}"),
        json!({"note": "clean"}),
    );
    let id = sig.id.clone();
    let body = json!({
        "sender_agent_id": "ai:peer-3049",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [serde_json::to_value(&sig).expect("serialize signal")],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:peer-3049").await;
    let stored = {
        let lock = db.lock().await;
        ai_memory::signals::get(&lock.0, &id)
            .expect("signals::get")
            .expect("signal MUST be persisted, not skipped")
    };
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(
        i(&resp, "signals_applied"),
        1,
        "secret-bearing signal MUST apply (redact, never skip): resp={resp}"
    );
    assert!(
        !stored.subject.contains(AWS_AKIA_FIXTURE),
        "persisted subject still carries the secret: {}",
        stored.subject
    );
    assert!(
        stored.subject.contains(REDACTION_PLACEHOLDER),
        "persisted subject must carry {REDACTION_PLACEHOLDER}: {}",
        stored.subject
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_signal_body_secret_is_redacted_3049() {
    let _g = env_lock();
    seed_screen_mode_refuse();
    clear_all_env();
    relax_orthogonal_gates();
    let (router, db) = setup_router();

    let sig = make_signal(
        "ai:peer-3049",
        "coord/screen",
        "clean subject",
        json!({"token": AWS_AKIA_FIXTURE}),
    );
    let id = sig.id.clone();
    let body = json!({
        "sender_agent_id": "ai:peer-3049",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [serde_json::to_value(&sig).expect("serialize signal")],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:peer-3049").await;
    let stored = {
        let lock = db.lock().await;
        ai_memory::signals::get(&lock.0, &id)
            .expect("signals::get")
            .expect("signal MUST be persisted")
    };
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(i(&resp, "signals_applied"), 1, "resp={resp}");
    let token = stored
        .body
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        !token.contains(AWS_AKIA_FIXTURE),
        "persisted body still carries the secret: {}",
        stored.body
    );
    assert!(
        token.contains(REDACTION_PLACEHOLDER),
        "persisted body token must carry {REDACTION_PLACEHOLDER}: {}",
        stored.body
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_checkpoint_resolution_secret_is_redacted_3049() {
    let _g = env_lock();
    seed_screen_mode_refuse();
    clear_all_env();
    relax_orthogonal_gates();
    let (router, db) = setup_router();

    let id = uuid::Uuid::new_v4().to_string();
    let cp = make_checkpoint(
        &id,
        "coord/screen",
        "needs approval",
        &format!("approved with {AWS_AKIA_FIXTURE}"),
    );
    let body = json!({
        "sender_agent_id": "ai:peer-3049",
        "sender_clock": {"entries": {}},
        "memories": [],
        "checkpoints": [serde_json::to_value(&cp).expect("serialize checkpoint")],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:peer-3049").await;
    let stored = {
        let lock = db.lock().await;
        ai_memory::checkpoints::get(&lock.0, &id)
            .expect("checkpoints::get")
            .expect("checkpoint MUST be persisted, not skipped")
    };
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(
        i(&resp, "checkpoints_applied"),
        1,
        "secret-bearing checkpoint MUST apply (redact, never skip): resp={resp}"
    );
    let resolution = stored.resolution.as_deref().unwrap_or("");
    assert!(
        !resolution.contains(AWS_AKIA_FIXTURE),
        "persisted resolution still carries the secret: {resolution}"
    );
    assert!(
        resolution.contains(REDACTION_PLACEHOLDER),
        "persisted resolution must carry {REDACTION_PLACEHOLDER}: {resolution}"
    );
}

/// #3269 — a hostile peer renames a body key to end in `_b64` (or reuses a
/// carve-out key) and buries a credential in a NESTED OBJECT SUBTREE. Pre-fix
/// the name carve-out inserted the whole subtree verbatim; the receive-mode
/// screen now recurses and redacts it. Exercises the real `/sync/push` path.
#[tokio::test(flavor = "current_thread")]
async fn sync_push_signal_body_b64_carveout_subtree_is_redacted_3269() {
    let _g = env_lock();
    seed_screen_mode_refuse();
    clear_all_env();
    relax_orthogonal_gates();
    let (router, db) = setup_router();

    // `x_b64` matches the `_b64` carve-out suffix; the credential is one level
    // deep so the pre-fix "insert the whole subtree without recursing" bug
    // would land it verbatim.
    let sig = make_signal(
        "ai:peer-3049",
        "coord/screen",
        "clean subject",
        json!({ "x_b64": { "aws": AWS_AKIA_FIXTURE, "note": "buried" } }),
    );
    let id = sig.id.clone();
    let body = json!({
        "sender_agent_id": "ai:peer-3049",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [serde_json::to_value(&sig).expect("serialize signal")],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:peer-3049").await;
    let stored = {
        let lock = db.lock().await;
        ai_memory::signals::get(&lock.0, &id)
            .expect("signals::get")
            .expect("signal MUST be persisted, not skipped")
    };
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(i(&resp, "signals_applied"), 1, "resp={resp}");
    assert!(
        !stored.body.to_string().contains(AWS_AKIA_FIXTURE),
        "carve-out-key subtree credential must NOT survive the receive screen (#3269): {}",
        stored.body
    );
    assert!(
        stored.body.to_string().contains(REDACTION_PLACEHOLDER),
        "the nested credential must be replaced by {REDACTION_PLACEHOLDER}: {}",
        stored.body
    );
}

/// #3278 — a credential in `Signal.reference_ids` (arbitrary peer JSON, NOT a
/// `SignableSignal` field) is redacted on the receive path. Because it is
/// outside the signed surface, the signal still applies.
#[tokio::test(flavor = "current_thread")]
async fn sync_push_signal_reference_ids_secret_is_redacted_3278() {
    let _g = env_lock();
    seed_screen_mode_refuse();
    clear_all_env();
    relax_orthogonal_gates();
    let (router, db) = setup_router();

    let mut sig = make_signal(
        "ai:peer-3049",
        "coord/screen",
        "clean subject",
        json!({ "note": "clean" }),
    );
    sig.reference_ids = json!([format!("see {AWS_AKIA_FIXTURE}")]);
    let id = sig.id.clone();
    let body = json!({
        "sender_agent_id": "ai:peer-3049",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [serde_json::to_value(&sig).expect("serialize signal")],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:peer-3049").await;
    let stored = {
        let lock = db.lock().await;
        ai_memory::signals::get(&lock.0, &id)
            .expect("signals::get")
            .expect("signal MUST be persisted")
    };
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(i(&resp, "signals_applied"), 1, "resp={resp}");
    assert!(
        !stored.reference_ids.to_string().contains(AWS_AKIA_FIXTURE),
        "reference_ids credential must NOT survive (#3278): {}",
        stored.reference_ids
    );
    assert!(
        stored
            .reference_ids
            .to_string()
            .contains(REDACTION_PLACEHOLDER),
        "reference_ids must carry {REDACTION_PLACEHOLDER}: {}",
        stored.reference_ids
    );
}

/// #3278 — a credential in an inbound `pendings[].payload` (arbitrary peer JSON
/// surfaced by the approvals API / K10 SSE) is redacted before upsert.
#[tokio::test(flavor = "current_thread")]
async fn sync_push_pending_payload_secret_is_redacted_3278() {
    let _g = env_lock();
    seed_screen_mode_refuse();
    clear_all_env();
    relax_orthogonal_gates();
    let (router, db) = setup_router();

    let id = uuid::Uuid::new_v4().to_string();
    let pa = PendingAction {
        id: id.clone(),
        action_type: "store".to_string(),
        memory_id: None,
        namespace: "coord/screen".to_string(),
        payload: json!({ "content": format!("rotate {AWS_AKIA_FIXTURE}") }),
        requested_by: "ai:peer-3049".to_string(),
        requested_at: "2026-01-01T00:00:00Z".to_string(),
        status: "pending".to_string(),
        decided_by: None,
        decided_at: None,
        approvals: Vec::new(),
    };
    let body = json!({
        "sender_agent_id": "ai:peer-3049",
        "sender_clock": {"entries": {}},
        "memories": [],
        "pendings": [serde_json::to_value(&pa).expect("serialize pending")],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:peer-3049").await;
    let stored = {
        let lock = db.lock().await;
        ai_memory::db::get_pending_action(&lock.0, &id)
            .expect("get_pending_action")
            .expect("pending MUST be persisted, not skipped")
    };
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(i(&resp, "pendings_applied"), 1, "resp={resp}");
    assert!(
        !stored.payload.to_string().contains(AWS_AKIA_FIXTURE),
        "pending payload credential must NOT survive (#3278): {}",
        stored.payload
    );
    assert!(
        stored.payload.to_string().contains(REDACTION_PLACEHOLDER),
        "pending payload must carry {REDACTION_PLACEHOLDER}: {}",
        stored.payload
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_clean_signal_is_byte_identical_3049() {
    let _g = env_lock();
    seed_screen_mode_refuse();
    clear_all_env();
    relax_orthogonal_gates();
    let (router, db) = setup_router();

    let sig = make_signal(
        "ai:peer-3049",
        "coord/screen",
        "no credentials here",
        json!({"hello": "world"}),
    );
    let id = sig.id.clone();
    let body = json!({
        "sender_agent_id": "ai:peer-3049",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [serde_json::to_value(&sig).expect("serialize signal")],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:peer-3049").await;
    let stored = {
        let lock = db.lock().await;
        ai_memory::signals::get(&lock.0, &id)
            .expect("signals::get")
            .expect("clean signal MUST persist")
    };
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(i(&resp, "signals_applied"), 1, "resp={resp}");
    assert_eq!(stored.subject, "no credentials here");
    assert!(
        !stored.subject.contains(REDACTION_PLACEHOLDER),
        "clean subject must not be redacted"
    );
}
