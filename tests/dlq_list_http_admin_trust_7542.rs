// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7542 (HIGH, authorization bypass, the #1582 class): the operator view of
//! the failed-lookup DLQ (#7501) must be granted on the HTTP surface only to a
//! TRUSTED admin (`admin_role::is_admin_caller_trusted`), never to a caller
//! that merely types an allowlisted id into the self-asserted `X-Agent-Id`
//! header of a deployment with no request authentication.
//!
//! One test function drives every cell in sequence because the authn marker
//! (`mark_request_authn_configured`) is process-wide.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::subscriptions::scan_failure::{ScanFailure, record_dispatch_scan_failure};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

const API_KEY: &str = "transport-key-7542";
const ADMIN: &str = "ai:root";
const WRITER_A: &str = "ai:writer-a";
const WRITER_B: &str = "ai:writer-b";
const MALLORY: &str = "ai:mallory";
const ROUTE: &str = "/api/v1/memory_subscription_dlq_list";

fn record_for(path: &std::path::Path, namespace: &str, agent: Option<&str>) {
    record_dispatch_scan_failure(
        path,
        &ScanFailure {
            event: "memory_store",
            memory_id: "mem-7542",
            namespace,
            agent_id: agent,
            details: None,
        },
        "sqlite_error",
    );
}

fn build_router(db_path: &std::path::Path, authn: bool) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(authn);
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
    let enrolled = Arc::new(
        ai_memory::handlers::identity_binding::EnrolledAgentKeys::from_map(
            std::collections::HashMap::new(),
        ),
    );
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::full()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: HttpIdentityMode::Advisory,
    };
    let api_key_state = ApiKeyState {
        key: authn.then(|| API_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: HttpIdentityMode::Advisory,
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

/// POST the DLQ list as `agent` (header-bound; `None` = anonymous) and return
/// the sorted writer ids of the rows the caller was shown.
async fn list_as(router: &axum::Router, authn: bool, agent: Option<&str>) -> Vec<String> {
    let mut b = Request::builder()
        .method("POST")
        .uri(ROUTE)
        .header("content-type", "application/json");
    if authn {
        b = b.header("x-api-key", API_KEY);
    }
    if let Some(a) = agent {
        b = b.header("x-agent-id", a);
    }
    let resp = router
        .clone()
        .oneshot(
            b.body(Body::from(serde_json::json!({}).to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "agent {agent:?}");
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let mut writers: Vec<String> = v["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .map(|e| {
            let payload: serde_json::Value =
                serde_json::from_str(e["payload"].as_str().expect("payload str"))
                    .expect("payload json");
            payload["agent_id"]
                .as_str()
                .unwrap_or("(anonymous)")
                .to_string()
        })
        .collect();
    writers.sort();
    writers
}

#[tokio::test]
async fn http_dlq_admin_view_requires_a_trusted_admin_7542() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dlq.db");
    let _ = ai_memory::db::open(&path).expect("db::open");
    record_for(&path, "team/a", Some(WRITER_A));
    record_for(&path, "team/b", Some(WRITER_B));
    record_for(&path, "team/anon", None);

    // Keyless deployment: the header is self-asserted. Forging the admin id
    // must NOT widen the view (the bypass), and a plain caller sees nothing
    // of others.
    let keyless = build_router(&path, false);
    assert_eq!(
        list_as(&keyless, false, Some(ADMIN)).await,
        Vec::<String>::new(),
        "7542: a forged admin X-Agent-Id on a keyless daemon must see no row"
    );
    assert_eq!(
        list_as(&keyless, false, Some(MALLORY)).await,
        Vec::<String>::new(),
        "non-admin non-owner sees none"
    );
    assert_eq!(
        list_as(&keyless, false, None).await,
        Vec::<String>::new(),
        "anonymous sees none"
    );
    // The owner still sees exactly their own row.
    assert_eq!(
        list_as(&keyless, false, Some(WRITER_A)).await,
        vec![WRITER_A.to_string()]
    );

    // Authenticated deployment: a trusted admin sees every row, anonymous
    // ones included; everyone else keeps the owner-scoped view.
    let authed = build_router(&path, true);
    assert_eq!(
        list_as(&authed, true, Some(ADMIN)).await,
        vec![
            "(anonymous)".to_string(),
            WRITER_A.to_string(),
            WRITER_B.to_string()
        ],
        "a trusted admin sees every failed-lookup row"
    );
    assert_eq!(
        list_as(&authed, true, Some(MALLORY)).await,
        Vec::<String>::new(),
        "authenticated non-admin non-owner sees none"
    );
    assert_eq!(
        list_as(&authed, true, None).await,
        Vec::<String>::new(),
        "authenticated anonymous caller sees none"
    );
    assert_eq!(
        list_as(&authed, true, Some(WRITER_B)).await,
        vec![WRITER_B.to_string()],
        "an owner sees only their own row"
    );
    ai_memory::handlers::admin_role::mark_request_authn_configured(false);
}
