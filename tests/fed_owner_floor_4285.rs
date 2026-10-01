// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4285 (5-agent vote 4d3ea1c5, memory 1c3e2889) - MEASURED answer to "under
//! an Owner floor (a corrupt/severed governance standard resolves write >=
//! Owner), is federation receive (`/sync/push`) refused for a NON-owner peer?"
//!
//! The receive path authorizes a relayed write by peer attestation + namespace
//! scope (#2447/#2488), NOT by the namespace write-governance level: the only
//! local governance read on the memories lane is the reflection-depth cap. So
//! the Owner floor does NOT refuse a non-owner peer's relayed write, for a
//! corrupt standard exactly as for an intact explicit Owner policy. A corrupt
//! standard therefore never turns a receive into an outage.

#![allow(clippy::too_many_lines, clippy::doc_markdown)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async guard: these tests mutate process-wide federation env
/// vars, and cargo runs `#[tokio::test]`s in a binary concurrently.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const PEER_ID_HEADER: &str = "x-peer-id";
const SENDER: &str = "ai:peer-4285";
const NS: &str = "fed-owner-floor-4285";

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
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store"))
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
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db)
}

fn push_body(id: &str, sender_policy_seq: Option<i64>) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    let mut body = json!({
        "sender_agent_id": SENDER,
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": id,
            "tier": "long",
            "namespace": NS,
            "title": format!("fed4285 {id}"),
            "content": "owner-floor receive cell",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": false,
    });
    if let Some(seq) = sender_policy_seq {
        body["sender_policy_seq"] = json!(seq);
    }
    body
}

async fn count_ns(db: &ai_memory::handlers::Db, ns: &str) -> i64 {
    let lock = db.lock().await;
    lock.0
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            rusqlite::params![ns],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
}

/// Reset the env so each case reaches the FED-RQ-03 gate cleanly: unenrolled
/// peer must pass the signing/enrollment gate, and the #238 sender-attestation
/// must pass (x-peer-id == `sender_agent_id`). Held inside `ENV_LOCK`.
fn reset_env() {
    unsafe {
        // #3582: explicit Standard namespace opt-out lets this downstream
        // control run; the required-scope refusal is pinned in its own suite.
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            "0",
        );
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV);
    }
}

async fn post_push(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(PEER_ID_HEADER, SENDER)
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Bind a standard owned by `ai:owner-4285` to `*` with the given governance blob.
async fn bind_star(db: &ai_memory::handlers::Db, governance: Value) {
    let lock = db.lock().await;
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "std-home-4285".to_string(),
        title: format!("standard-{}", uuid::Uuid::new_v4()),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": "ai:owner-4285", "governance": governance}),
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    let sid = ai_memory::db::insert(&lock.0, &mem).expect("insert standard");
    ai_memory::db::set_namespace_standard(&lock.0, "*", &sid, None).expect("bind *");
}

async fn push_and_count(governance: Value) -> (StatusCode, Value, i64) {
    let guard = ENV_LOCK.lock().await;
    reset_env();
    let (router, db) = build_router_with_db();
    bind_star(&db, governance).await;
    {
        let lock = db.lock().await;
        let p = ai_memory::db::resolve_governance_policy(&lock.0, NS)
            .expect("resolve")
            .expect("governed");
        assert_eq!(p.core.write, ai_memory::models::GovernanceLevel::Owner);
    }
    let (status, body) = post_push(
        &router,
        &push_body("55555555-5555-4555-8555-555555555555", None),
    )
    .await;
    let n = count_ns(&db, NS).await;
    drop(guard);
    (status, body, n)
}

#[tokio::test]
async fn owner_floor_from_corrupt_standard_does_not_refuse_non_owner_peer_receive_4285() {
    let (status, body, n) = push_and_count(json!({"write": "approval-typo-4285"})).await;
    assert_eq!(status, StatusCode::OK, "push must not fail; body={body}");
    assert_eq!(
        n, 1,
        "MEASURED: the Owner floor does not gate federation receive; body={body}"
    );
}

#[tokio::test]
async fn owner_floor_from_intact_owner_policy_behaves_identically_4285() {
    let (status, body, n) = push_and_count(json!({"write": "owner"})).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(
        n, 1,
        "control: an intact explicit Owner policy also admits the relay; body={body}"
    );
}
