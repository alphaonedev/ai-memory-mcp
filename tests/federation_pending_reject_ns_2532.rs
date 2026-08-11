// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2532 — federated `pending_decisions[]` REJECT must not veto foreign namespaces.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";
const PEER_ID: &str = "ai:evil-2532";
const VICTIM_NS: &str = "secure/ops";

const SCOPED_ALLOWLIST: &str = r#"{"ai:evil-2532":{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["ai:evil-2532"]}}"#;
const SCOPED_ALLOWLIST_WITH_VICTIM: &str = r#"{"ai:evil-2532":{"allowed_namespaces":["public/*","secure/*"],"allowed_sender_agent_ids":["ai:evil-2532"]}}"#;

struct PostureGuard;
impl Drop for PostureGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
            std::env::remove_var(REQUIRE_ATTEST_ENV);
            std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
            std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
            std::env::remove_var(ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
            std::env::remove_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            );
        }
    }
}

fn set_posture(allowlist: &str) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
        std::env::remove_var(ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            "1",
        );
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            allowlist,
        );
    }
}

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let path = std::path::PathBuf::from(":memory:");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path,
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("store"))
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
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

fn store_payload(namespace: &str) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "tier": "long",
        "namespace": namespace,
        "title": "pending under governance",
        "content": "body",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": now,
        "updated_at": now,
        "metadata": {"agent_id": "ai:victim"},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn seed_local_pending(db: &ai_memory::handlers::Db, namespace: &str) -> String {
    let guard = db.lock().await;
    let payload = store_payload(namespace);
    ai_memory::db::queue_pending_action(
        &guard.0,
        ai_memory::models::GovernedAction::Store,
        namespace,
        None,
        "ai:victim",
        &payload,
    )
    .expect("queue")
}

async fn push_reject(router: &axum::Router, pending_id: &str) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "pending_decisions": [{
            "id": pending_id,
            "approved": false,
            "decider": PEER_ID,
        }],
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
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

async fn pending_status(db: &ai_memory::handlers::Db, id: &str) -> String {
    let guard = db.lock().await;
    guard
        .0
        .query_row(
            "SELECT status FROM pending_actions WHERE id = ?1",
            [id],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default()
}

/// Out-of-scope peer must NOT permanently veto a foreign tenant's pending.
#[tokio::test]
async fn foreign_reject_cannot_veto_out_of_scope_pending_2532() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(SCOPED_ALLOWLIST);
    let (router, db) = build_router_with_db();

    let id = seed_local_pending(&db, VICTIM_NS).await;
    assert_eq!(pending_status(&db, &id).await, "pending");

    let (status, report) = push_reject(&router, &id).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(
        pending_status(&db, &id).await,
        "pending",
        "foreign REJECT must not veto: {report}"
    );
    assert_eq!(
        report["pending_decisions_applied"].as_i64(),
        Some(0),
        "{report}"
    );
    assert!(
        report["skipped"].as_i64().unwrap_or(0) >= 1,
        "refusal must count skipped: {report}"
    );
}

/// In-scope peer can still reject (positive control / convergence).
#[tokio::test]
async fn in_scope_reject_still_applies_2532() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(SCOPED_ALLOWLIST_WITH_VICTIM);
    let (router, db) = build_router_with_db();

    let id = seed_local_pending(&db, VICTIM_NS).await;
    let (status, report) = push_reject(&router, &id).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(
        pending_status(&db, &id).await,
        "rejected",
        "in-scope REJECT must converge: {report}"
    );
    assert_eq!(
        report["pending_decisions_applied"].as_i64(),
        Some(1),
        "{report}"
    );
}
