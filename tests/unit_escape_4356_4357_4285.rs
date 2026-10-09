// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The assembled #4356 + #4357 + #4285 unit, end to end on both backends: a
//! STRANGER cannot opt a subtree out of the parent's approval-depth gate by
//! binding a child standard that omits the key (#4356 refuses the bind), and a
//! stranger's reflect into the child is PENDING (the parent's threshold 0
//! governs). The bind refusal is what makes the leaf-first-wins "omitted key
//! stops the walk" rule safe.
#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

#[path = "common/sqlite_tempfile.rs"]
mod sqlite_tempfile;

use crate::sqlite_tempfile::SqliteTempFile;
use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use ai_memory::store::{CallerContext, Filter, MemoryStore};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt as _;

/// Cells mutate process env (attestation / `why_trace` postures); one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SHARED_KEY: &str = "issue-4285e-transport-key";
const OWNER: &str = "ai:owner-4285e";
const STRANGER: &str = "ai:stranger-4285e";

fn build_router(
    backend: StorageBackend,
    store: Arc<dyn MemoryStore>,
    sqlite_path: Option<&std::path::Path>,
) -> (axum::Router, SqliteTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = SqliteTempFile::new().expect("tempfile");
    let db_path = sqlite_path.unwrap_or(f.path()).to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let enrolled = Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty());
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
        storage_backend: backend,
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
        admin_agent_ids: Arc::new(vec!["ai:operator".to_string()]),
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
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: HttpIdentityMode::Advisory,
        ..Default::default()
    };
    (ai_memory::build_router(api_key_state, app_state), f)
}

async fn reflect_http_as(router: &axum::Router, agent: &str, body: &Value) -> (StatusCode, Value) {
    // The body `agent_id` must agree with the authenticated header identity.
    let mut body = body.clone();
    body["agent_id"] = json!(agent);
    let body = &body;
    let r = Request::builder()
        .method("POST")
        .uri("/api/v1/memory_reflect")
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", agent)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(body).expect("serialise body"),
        ))
        .expect("build request");
    let resp = router.clone().oneshot(r).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn memory(namespace: &str, title: &str) -> Memory {
    let id = uuid::Uuid::new_v4().to_string();
    Memory {
        // `(title, namespace)` is the upsert key; the id keeps a persistent
        // postgres database from upserting onto a previous run's row.
        title: format!("{title} {id}"),
        id,
        tier: Tier::Long,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        namespace: namespace.into(),
        content: "issue 4285e regression".into(),
        metadata: json!({"agent_id": OWNER}),
        ..Memory::default()
    }
}

async fn reflection_count(store: &Arc<dyn MemoryStore>, ns: &str) -> usize {
    let ctx = CallerContext::for_admin("ai:operator");
    let mut filter = Filter::default();
    filter.namespace = Some(ns.to_string());
    filter.limit = 100;
    store
        .list(&ctx, &filter)
        .await
        .expect("list")
        .into_iter()
        .filter(|m| m.reflection_depth > 0)
        .count()
}

fn gate_body(source_id: &str, ns: &str) -> Value {
    // A unique title: `(title, namespace)` is the upsert key, so a repeated
    // title would upsert onto the previous reflection and self-link it.
    let title = format!("deep reflection {}", uuid::Uuid::new_v4());
    json!({
        "source_ids": [source_id], "title": title, "content": "deep reflection",
        "namespace": ns, "agent_id": OWNER,
    })
}

fn enforce_mode() {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
}

fn sqlite_store(file: &SqliteTempFile) -> Arc<dyn MemoryStore> {
    Arc::new(ai_memory::store::sqlite::SqliteStore::open(file.path()).expect("sqlite"))
}

#[cfg(feature = "sal-postgres")]
async fn pg_store() -> Arc<dyn MemoryStore> {
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("set fresh issue 4357 database URL");
    Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("postgres"),
    )
}

async fn exercise_stranger_cannot_open_subtree_and_reflect_is_pending(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let owner = CallerContext::for_agent(OWNER);
    let stranger = CallerContext::for_agent(STRANGER);
    let parent = format!("pu4285/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(&format!("{parent}/standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 0});
    store.store(&owner, &pstd).await.expect("pstd");
    store
        .set_namespace_standard(&owner, &parent, &pstd.id, None)
        .await
        .expect("owner binds the parent");
    let child = format!("{parent}/child");
    // The stranger's first bind of an omitting child standard must be REFUSED.
    let mut cstd = memory(&format!("{child}/standards"), "stranger standard");
    cstd.metadata["agent_id"] = json!(STRANGER);
    cstd.metadata["governance"] = json!({"write": "any"});
    let _ = store.store(&stranger, &cstd).await;
    let bind = store
        .set_namespace_standard(&stranger, &child, &cstd.id, Some(&parent))
        .await;
    // The refusal KIND, not merely "it refused": the #4356 ancestor-owner
    // gate's closed not-owner refusal (never a storage fault or a missing row).
    match &bind {
        Err(ai_memory::store::StoreError::PermissionDenied { reason, .. }) => assert_eq!(
            reason,
            ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
            "#4356: the stranger's first bind must be the not-owner refusal"
        ),
        other => panic!(
            "#4356: a stranger must not bind the first standard below a governed \
             ancestor (want the not-owner PermissionDenied), got {other:?}"
        ),
    }
    // With no child standard bound, the parent's explicit 0 governs: a stranger's
    // reflect is PENDING (never applied).
    let mut src = memory(&child, "source");
    src.metadata["scope"] = json!("collective");
    store.store(&owner, &src).await.expect("src");
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http_as(&router, STRANGER, &gate_body(&src.id, &child)).await;
    assert!(
        body.get("id").is_none() && body["status"] == "pending",
        "a stranger's reflect must be PENDING: {status} {body}"
    );
    assert_eq!(reflection_count(&store, &child).await, 0);
}

#[tokio::test]
async fn unit_stranger_escape_sqlite() {
    let _serial = SERIAL.lock().await;
    let file = SqliteTempFile::new().expect("sqlite file");
    exercise_stranger_cannot_open_subtree_and_reflect_is_pending(
        sqlite_store(&file),
        StorageBackend::Sqlite,
        Some(file.path()),
    )
    .await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn unit_stranger_escape_postgres() {
    let _serial = SERIAL.lock().await;
    exercise_stranger_cannot_open_subtree_and_reflect_is_pending(
        pg_store().await,
        StorageBackend::Postgres,
        None,
    )
    .await;
}
