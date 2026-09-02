// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1849 (CWE-862, Missing Authorization) — the HTTP admin bulk-forget
//! governance gate.
//!
//! `POST /api/v1/forget` is admin-gated but otherwise destructive across
//! every owner. Before #1849 an admin could erase the rows of a
//! delete-governed namespace (e.g. a `delete:Approve` legal-hold on
//! `compliance/*`) simply by OMITTING the `namespace` and forgetting by
//! pattern/tier — the per-namespace delete-governance gate never ran.
//!
//! The fix resolves the matched namespaces of a `namespace = None` bulk
//! forget (UNCAPPED — never the #1602 preview, which would miss a governed
//! namespace whose rows sort past the cap) and REFUSES the whole forget with
//! `403 FORBIDDEN` if ANY matched namespace carries a non-`Any` `delete`
//! level. `namespace = Some` and forgets that touch only ungoverned
//! namespaces are unchanged.
//!
//! 5-agent vote 4d3ea1c5.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::db;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{
    CorePolicy, GovernanceLevel, GovernancePolicy, Memory, MemoryKind, Tier, default_metadata,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("forget-governance-gate-1849")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Insert a memory carrying an explicit owner `agent_id` so the row matches
/// the bulk-forget pattern.
fn seed_memory(conn: &rusqlite::Connection, ns: &str, title: &str, owner: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

/// Install a namespace standard on `ns` gating `delete` at `delete_level`.
fn install_delete_policy(conn: &rusqlite::Connection, ns: &str, delete_level: GovernanceLevel) {
    let policy = GovernancePolicy {
        core: CorePolicy {
            delete: delete_level,
            ..CorePolicy::default()
        },
        ..Default::default()
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("agent_id".to_string(), json!("ai:operator-admin"));
        obj.insert(
            "governance".to_string(),
            serde_json::to_value(&policy).unwrap(),
        );
    }
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("_standards-{ns}"),
        title: format!("std-{ns}"),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    };
    let sid = db::insert(conn, &standard).expect("insert standard");
    db::set_namespace_standard(conn, ns, &sid, None).expect("set standard");
}

/// Build an HTTP test fixture over the supplied (pre-seeded) DB file, with
/// `ai:operator-admin` on the admin allowlist.
fn build_router(db_path: &Path) -> axum::Router {
    // #1570 — model an AUTHENTICATED deployment so the admin header role-claim
    // resolves (the secure default for a bare X-Agent-Id on an unauthenticated
    // deployment is its own test).
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let conn = db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
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
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["ai:operator-admin".to_string()]),
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
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn forget_as_admin(router: axum::Router, body: serde_json::Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/forget")
        .header("x-agent-id", "ai:operator-admin")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    router.oneshot(req).await.unwrap().status()
}

/// #1849 (case d) — an admin `namespace = None` forget that matches a
/// delete-governed namespace is REFUSED with `403 FORBIDDEN`, and the gated
/// row SURVIVES.
#[tokio::test]
async fn http_admin_namespace_none_forget_refused_on_governed_ns_1849() {
    let _dir = fresh_dir();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();

    let id_held = {
        let conn = db::open(&db_path).expect("db::open seed");
        install_delete_policy(&conn, "compliance-hold-1849", GovernanceLevel::Approve);
        seed_memory(
            &conn,
            "compliance-hold-1849",
            "legalhold secret row",
            "ai:operator-admin",
        )
    };

    let router = build_router(&db_path);
    let status = forget_as_admin(router, json!({ "pattern": "legalhold" })).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#1849: admin namespace=None forget touching a delete-governed ns must be 403"
    );

    // The legal-hold row must be untouched by the refused forget.
    let conn = db::open(&db_path).expect("db::open verify");
    assert!(
        db::get(&conn, &id_held).expect("get held").is_some(),
        "#1849: the legal-hold row must survive the refused bulk forget"
    );
}

/// #1849 control — an admin `namespace = None` forget that touches only
/// UNGOVERNED namespaces is UNCHANGED (no over-refusal): it proceeds (200) and
/// deletes the matched rows.
#[tokio::test]
async fn http_admin_namespace_none_forget_allows_ungoverned_1849() {
    let _dir = fresh_dir();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();

    let id_open = {
        let conn = db::open(&db_path).expect("db::open seed");
        seed_memory(&conn, "open-bulk-1849", "openbulk data row", "ai:someone")
    };

    let router = build_router(&db_path);
    let status = forget_as_admin(router, json!({ "pattern": "openbulk" })).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1849: admin namespace=None forget over an ungoverned ns must be unchanged (200)"
    );

    let conn = db::open(&db_path).expect("db::open verify");
    assert!(
        db::get(&conn, &id_open).expect("get open").is_none(),
        "#1849: the ungoverned row must be deleted (no over-refusal)"
    );
}

/// #1849 control — a `namespace = Some` admin forget against the SAME
/// delete-governed namespace is unchanged by this fix (the namespace-scoped
/// admin path keeps its prior behaviour; only the namespace-OMITTED bypass is
/// closed). It proceeds (200).
#[tokio::test]
async fn http_admin_namespace_some_forget_unchanged_1849() {
    let _dir = fresh_dir();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();

    {
        let conn = db::open(&db_path).expect("db::open seed");
        install_delete_policy(&conn, "compliance-hold-1849", GovernanceLevel::Approve);
        seed_memory(
            &conn,
            "compliance-hold-1849",
            "legalhold scoped row",
            "ai:operator-admin",
        );
    }

    let router = build_router(&db_path);
    let status = forget_as_admin(
        router,
        json!({ "namespace": "compliance-hold-1849", "pattern": "legalhold" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1849: namespace=Some admin forget is unchanged by the namespace-None gate"
    );
}
