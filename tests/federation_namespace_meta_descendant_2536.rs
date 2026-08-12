// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2536 — federated `namespace_meta` must not set hierarchical governance
//! default for out-of-scope descendants via exact/single-level ancestor scope.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";
const PEER_ID: &str = "ai:peer-2536";

/// Exact-scope on the ancestor only — the #2536 exploit posture.
const EXACT_ANCESTOR: &str = r#"{"ai:peer-2536":{"allowed_namespaces":["secure"],"allowed_sender_agent_ids":["ai:peer-2536"]}}"#;

/// Tree-scope covering secure and all descendants — control.
const TREE_ANCESTOR: &str = r#"{"ai:peer-2536":{"allowed_namespaces":["secure/**"],"allowed_sender_agent_ids":["ai:peer-2536"]}}"#;

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

fn set_posture(allowlist: Option<&str>) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
        std::env::remove_var(ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            "1",
        );
        match allowlist {
            Some(body) => std::env::set_var(
                ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
                body,
            ),
            None => {
                std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
            }
        }
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

async fn seed_standard(router: &axum::Router, ns: &str, title: &str) -> String {
    let body = json!({
        "title": title,
        "content": format!("standard body for {title}"),
        "namespace": ns,
        "metadata": {"governance": {"write": "approve", "approver": {"agent": PEER_ID}}}
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "seed standard memory failed: {}",
        resp.status()
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["id"].as_str().unwrap().to_string()
}

async fn push_meta(
    router: &axum::Router,
    namespace: &str,
    standard_id: &str,
) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "namespace_meta": [{
            "namespace": namespace,
            "standard_id": standard_id,
            "parent_namespace": null
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
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    (status, v)
}

async fn stored_standard(db: &ai_memory::handlers::Db, ns: &str) -> Option<String> {
    let lock = db.lock().await;
    ai_memory::db::get_namespace_standard(&lock.0, ns)
        .ok()
        .flatten()
}

async fn resolved_write(
    db: &ai_memory::handlers::Db,
    ns: &str,
) -> Option<ai_memory::models::GovernanceLevel> {
    let lock = db.lock().await;
    ai_memory::db::resolve_governance_policy(&lock.0, ns).map(|p| p.core.write)
}

/// Exact-scope peer sets standard on `secure` → would govern `secure/ops`.
/// Must refuse (#2536).
#[tokio::test]
async fn exact_ancestor_cannot_set_standard_inheriting_to_descendants_2536() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(EXACT_ANCESTOR));
    let (router, db) = build_router_with_db();

    let sid = seed_standard(&router, "secure", "peer standard").await;
    let (status, report) = push_meta(&router, "secure", &sid).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert!(
        stored_standard(&db, "secure").await.is_none(),
        "exact-scope must not bind hierarchical standard: {report}"
    );
    assert_eq!(
        report["namespace_meta_applied"].as_u64(),
        Some(0),
        "{report}"
    );
    assert_eq!(
        report["namespace_meta_refused"].as_u64(),
        Some(1),
        "{report}"
    );
    // Descendant remains ungovered by the peer's would-be policy.
    assert_ne!(
        resolved_write(&db, "secure/ops").await,
        Some(ai_memory::models::GovernanceLevel::Approve),
        "descendant must not inherit peer policy: {report}"
    );
}

/// Tree-scope `secure/**` still binds (positive control).
#[tokio::test]
async fn tree_scope_still_sets_standard_2536() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(TREE_ANCESTOR));
    let (router, db) = build_router_with_db();

    let sid = seed_standard(&router, "secure", "peer standard").await;
    let (status, report) = push_meta(&router, "secure", &sid).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(
        stored_standard(&db, "secure").await.as_deref(),
        Some(sid.as_str()),
        "tree-scope bind must apply: {report}"
    );
    assert_eq!(
        report["namespace_meta_applied"].as_u64(),
        Some(1),
        "{report}"
    );
    assert_eq!(
        report["namespace_meta_refused"].as_u64(),
        Some(0),
        "{report}"
    );
}

#[test]
fn descendant_probe_suffix_is_two_segments_2536() {
    let s = ai_memory::federation::receive_auth::NAMESPACE_META_DESCENDANT_PROBE_SUFFIX;
    assert!(s.starts_with('/'));
    assert_eq!(s.matches('/').count(), 2, "two extra segments: {s}");
}
