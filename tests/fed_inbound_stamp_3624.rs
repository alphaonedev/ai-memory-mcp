// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3624 — the federation RECEIVE path attributed an author-less inbound row
//! to the sender for quota AND attestation but never wrote that owner into the
//! PERSISTED `metadata.agent_id`, so the replicated row landed UNSTAMPED
//! (#3124): the stored owner disagreed with the quota/attestation subject, and
//! a later caller-scoped mutation of it was refused as legacy-unowned under
//! `AI_MEMORY_UNSTAMPED_MUTATION=refuse`.
//!
//! Pins on the PERSISTED row (the sink), all through `POST /sync/push`:
//!   1. an author-less inbound row -> stored `metadata.agent_id == sender`;
//!   2. an inbound row WITH `metadata.agent_id` (== sender) keeps it (control);
//!   3. under `refuse`, mutating the replicated row: the SENDER (its resolved
//!      owner) is ADMITTED (the fix stamped it), a DIFFERENT agent is still
//!      REFUSED (the stamp must not fail open). Pre-fix, leg 1 and the sender
//!      leg of 3 are RED (row unstamped).
//!
//! Router shape mirrors the proven-good `tests/g_issue_238_sender_attestation`:
//! an IN-MEMORY (`:memory:`) db held by the router's `db` Arc, a plain
//! current-thread `#[tokio::test]`, and readback THROUGH that same `db` Arc.
//! (An earlier file-backed + `multi_thread` shape hung the receive path.)
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::identity::owner_stamp::{
    ENV_UNSTAMPED_MUTATION, MODE_REFUSE, MutationSite, funnel, metadata_admits_mutation,
};

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const NS: &str = "issue-3624";
const SENDER: &str = "peer-3624";

fn build_router_in_memory() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    // The AppState `store` is required by the struct but unused by the sqlite
    // receive path (which persists to the `db` Connection above) — give it its
    // OWN tempfile so there is no second writer on the receive db.
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let sp = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&sp).expect("open SqliteStore"),
        )
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
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
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

/// One memory; `agent_id = None` is the author-less shape, `Some(a)` seeds
/// `metadata.agent_id`.
fn push_body(id: &str, agent_id: Option<&str>) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    let metadata = match agent_id {
        Some(a) => json!({ "agent_id": a }),
        None => json!({}),
    };
    json!({
        "sender_agent_id": SENDER,
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": id,
            "tier": "long",
            "namespace": NS,
            "title": "replicated write",
            "content": "body for #3624",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": metadata,
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": false,
    })
}

/// Set the receive-path env this suite needs, serialized by the caller's
/// `ENV_LOCK` guard. Uses direct `set_var` (like `g_issue_238`'s `reset_env`)
/// rather than a stack of RAII `EnvVarGuard`s: each `EnvVarGuard` holds the
/// non-reentrant `common::ENV_LOCK` for its whole lifetime, so building a
/// `Vec` of two would self-deadlock on the second `set`. `refuse` selects the
/// `AI_MEMORY_UNSTAMPED_MUTATION` posture (set for leg 3, cleared otherwise so
/// a prior leg-3 run cannot contaminate leg 1/2 under `--test-threads`).
fn set_receive_env(refuse: bool) {
    common::ensure_no_config_env();
    // SAFETY: env mutation is process-global; every caller holds `ENV_LOCK`
    // (the suite's async mutex) across the whole test, serializing these writes
    // against the other legs — the same discipline `g_issue_238::reset_env` uses.
    unsafe {
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            "0",
        );
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        if refuse {
            std::env::set_var(ENV_UNSTAMPED_MUTATION, MODE_REFUSE);
        } else {
            std::env::remove_var(ENV_UNSTAMPED_MUTATION);
        }
    }
}

async fn push(router: axum::Router, body: Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            SENDER,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    // Drain the body (as g_issue_238 does) so nothing is left half-consumed.
    let _ = axum::body::to_bytes(resp.into_body(), 64 * 1024).await;
    status
}

/// Read the PERSISTED metadata back THROUGH the router's own `db` Arc — the
/// `:memory:` connection is the only place the row exists.
async fn stored_metadata(db: &ai_memory::handlers::Db, id: &str) -> Value {
    let lock = db.lock().await;
    ai_memory::db::get(&lock.0, id)
        .unwrap()
        .map_or(Value::Null, |m| m.metadata)
}

fn agent_id_of(meta: &Value) -> Option<String> {
    meta.get("agent_id")
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[tokio::test]
async fn leg1_authorless_inbound_row_is_stamped_with_the_resolved_sender_3624() {
    let _lock = ENV_LOCK.lock().await;
    set_receive_env(false);
    let (router, db) = build_router_in_memory();
    let id = uuid::Uuid::new_v4().to_string();
    let status = push(router, push_body(&id, None)).await;
    assert_eq!(status, StatusCode::OK, "author-less push must land");
    let meta = stored_metadata(&db, &id).await;
    assert_eq!(
        agent_id_of(&meta).as_deref(),
        Some(SENDER),
        "#3624 RED-then-GREEN: the persisted author-less row must carry \
         metadata.agent_id == the resolved sender; metadata={meta}"
    );
}

#[tokio::test]
async fn leg2_inbound_row_with_agent_id_keeps_it_3624() {
    let _lock = ENV_LOCK.lock().await;
    set_receive_env(false);
    let (router, db) = build_router_in_memory();
    let id = uuid::Uuid::new_v4().to_string();
    // agent_id == sender is the #238-attested author (trusted verbatim).
    let status = push(router, push_body(&id, Some(SENDER))).await;
    assert_eq!(status, StatusCode::OK);
    let meta = stored_metadata(&db, &id).await;
    assert_eq!(
        agent_id_of(&meta).as_deref(),
        Some(SENDER),
        "an inbound row WITH metadata.agent_id keeps it (allowed-path control); metadata={meta}"
    );
}

#[tokio::test]
async fn leg3_replicated_row_is_ownable_by_the_sender_but_not_a_stranger_under_refuse_3624() {
    let _lock = ENV_LOCK.lock().await;
    set_receive_env(true);
    let (router, db) = build_router_in_memory();
    let id = uuid::Uuid::new_v4().to_string();
    assert_eq!(push(router, push_body(&id, None)).await, StatusCode::OK);

    // The #3124 mutation gate on the PERSISTED row (`metadata_admits_mutation`
    // is the exact predicate `SqliteStore::update` / `db::update` consult under
    // `AI_MEMORY_UNSTAMPED_MUTATION`). Tested directly on the stored metadata so
    // the pin cannot deadlock on a second async sqlite writer, while pinning the
    // same decision an actual update/delete would reach.
    let meta = stored_metadata(&db, &id).await;
    let site = MutationSite::sqlite(funnel::UPDATE);

    // ABSENCE HALF: under refuse, the SENDER (resolved owner) may mutate the
    // replicated row. RED pre-fix — the row is UNSTAMPED, so refuse refuses the
    // sender as legacy-unowned.
    assert!(
        metadata_admits_mutation(&meta, &id, SENDER, false, site),
        "#3624: the resolved sender owns the replicated row and may mutate it under refuse; metadata={meta}"
    );

    // CONTROL: the stamp must not fail OPEN — a DIFFERENT agent is still refused.
    assert!(
        !metadata_admits_mutation(&meta, &id, "ai:stranger", false, site),
        "a non-owner must still be refused under refuse (the stamp is not open); metadata={meta}"
    );
}
