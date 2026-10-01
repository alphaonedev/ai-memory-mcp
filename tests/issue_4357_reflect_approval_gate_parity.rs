// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4357 (CWE-862): the L1-8 `require_approval_above_depth` reflection approval
//! gate must hold on EVERY backend. Pre-fix the threshold was read only by the
//! sqlite/MCP `handle_reflect`; `POST /api/v1/memory_reflect` on a postgres
//! daemon applied a reflection above the namespace's threshold immediately
//! instead of parking it for approval, and a queued postgres reflect could not
//! be executed at all (no `reflect` arm in `execute_pending_action`).
//!
//! Funnels: MCP `memory_reflect` (sqlite-only by construction), HTTP on sqlite,
//! HTTP on postgres. The cells run through the same router/handler a client
//! reaches; the parity cell asserts one request yields the same governed
//! outcome on both backends.
#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use ai_memory::store::{CallerContext, Filter, MemoryStore};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tower::ServiceExt as _;

const SHARED_KEY: &str = "issue-4357-transport-key";
const OWNER: &str = "ai:owner-4357";
const APPROVER: &str = "ai:approver-4357";

fn build_router(
    backend: StorageBackend,
    store: Arc<dyn MemoryStore>,
    sqlite_path: Option<&std::path::Path>,
) -> (axum::Router, NamedTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
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

async fn reflect_http(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let r = Request::builder()
        .method("POST")
        .uri("/api/v1/memory_reflect")
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", OWNER)
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
        content: "issue 4357 regression".into(),
        metadata: json!({"agent_id": OWNER}),
        ..Memory::default()
    }
}

/// Bind a standard carrying `governance` to a fresh unique namespace, store a
/// depth-0 source in it, and return `(namespace, source_id)`.
async fn seed_namespace(store: &Arc<dyn MemoryStore>, governance: Value) -> (String, String) {
    let ctx = CallerContext::for_agent(OWNER);
    let ns = format!("p4357/{}", uuid::Uuid::new_v4());
    let source = memory(&ns, "leaf source");
    store.store(&ctx, &source).await.expect("source");
    let mut standard = memory(&format!("{ns}/standards"), "standard");
    standard.metadata["governance"] = governance;
    store.store(&ctx, &standard).await.expect("standard");
    store
        .set_namespace_standard(&ctx, &ns, &standard.id, None)
        .await
        .expect("bind standard");
    (ns, source.id)
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

/// The governed outcome that must be identical on every backend.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    status: String,
    action: String,
    reason: String,
    proposed_depth: u64,
    has_pending_id: bool,
    threshold_leaked: bool,
    reflections_written: usize,
}

fn outcome_of(body: &Value, reflections_written: usize) -> Outcome {
    Outcome {
        status: body["status"].as_str().unwrap_or("<none>").to_string(),
        action: body["action"].as_str().unwrap_or("<none>").to_string(),
        reason: body["reason"].as_str().unwrap_or("<none>").to_string(),
        proposed_depth: body["proposed_depth"].as_u64().unwrap_or(u64::MAX),
        has_pending_id: body["pending_id"].is_string(),
        threshold_leaked: body.to_string().contains("require_approval_above_depth"),
        reflections_written,
    }
}

fn enforce_mode() {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
}

/// HTTP funnel: a depth-1 reflection above `require_approval_above_depth: 0`
/// is parked (never written), the parked row is a replayable `reflect`
/// pending, and approving it lands the reflection.
async fn exercise_http_gate(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) -> Outcome {
    enforce_mode();
    let (ns, source_id) = seed_namespace(
        &store,
        json!({"write": "any", "require_approval_above_depth": 0}),
    )
    .await;
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(&source_id, &ns)).await;
    assert!(
        status.is_success(),
        "#4357: pending is a success status: {status} {body}"
    );
    assert_eq!(
        body["status"], "pending",
        "#4357: a reflection above the approval threshold must be parked, never applied: {status} {body}"
    );
    assert!(
        body.get("id").is_none(),
        "#4357: nothing was applied: {body}"
    );
    let written = reflection_count(&store, &ns).await;
    assert_eq!(
        written, 0,
        "#4357: no reflection row may exist before approval"
    );

    let pending_id = body["pending_id"].as_str().expect("pending_id").to_string();
    let rows = store
        .list_pending_actions(Some("pending"), 1000)
        .await
        .expect("list pending");
    let row = rows
        .iter()
        .find(|p| p.id == pending_id)
        .expect("the parked row exists");
    assert_eq!(row.action_type, "reflect");
    assert_eq!(row.namespace, ns);

    // Approve and execute: the parked reflection must be applyable on this
    // backend (pre-fix postgres had no `reflect` arm in execute_pending_action).
    let approver = CallerContext::for_agent(APPROVER);
    assert!(
        store
            .pending_decide(&approver, &pending_id, true, APPROVER)
            .await
            .expect("approve")
    );
    let applied = store
        .execute_pending_action(&approver, &pending_id)
        .await
        .expect("#4357: an approved reflect pending must execute on every backend");
    assert!(applied.is_some(), "#4357: execute returns the new id");
    assert_eq!(
        reflection_count(&store, &ns).await,
        1,
        "#4357: the approved reflection landed exactly once"
    );
    outcome_of(&body, written)
}

/// At or below the threshold the reflection proceeds (no over-gating).
async fn exercise_http_at_threshold(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (ns, source_id) = seed_namespace(
        &store,
        json!({"write": "any", "require_approval_above_depth": 1}),
    )
    .await;
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(&source_id, &ns)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#4357: depth 1 <= threshold 1: {body}"
    );
    let rid = body["id"]
        .as_str()
        .expect("applied reflection id")
        .to_string();
    assert_eq!(reflection_count(&store, &ns).await, 1);
    // Depth 2 now exceeds the threshold: parked.
    let (status, body) = reflect_http(&router, &gate_body(&rid, &ns)).await;
    assert!(status.is_success(), "{status} {body}");
    assert_eq!(
        body["status"], "pending",
        "#4357: depth 2 > threshold 1: {body}"
    );
    assert_eq!(
        reflection_count(&store, &ns).await,
        1,
        "#4357: depth 2 not written"
    );
}

/// No `require_approval_above_depth` key: no gate (control).
async fn exercise_http_no_gate(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (ns, source_id) = seed_namespace(&store, json!({"write": "any"})).await;
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(&source_id, &ns)).await;
    assert_eq!(status, StatusCode::OK, "#4357 control: {body}");
    assert!(body["id"].is_string(), "{body}");
}

/// Backend-blind resolver: the leaf-first walk (leaf threshold wins, a leaf
/// policy that omits the field ends the walk, an overflowing threshold fails
/// closed to 0) answers identically on every backend.
async fn exercise_resolver(store: Arc<dyn MemoryStore>) {
    let ctx = CallerContext::for_agent(OWNER);
    let parent_ns = format!("p4357r/{}", uuid::Uuid::new_v4());
    let mut parent_std = memory(&format!("{parent_ns}/std"), "parent standard");
    parent_std.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 1});
    store.store(&ctx, &parent_std).await.expect("parent std");
    store
        .set_namespace_standard(&ctx, &parent_ns, &parent_std.id, None)
        .await
        .expect("bind parent");
    assert_eq!(
        store
            .resolve_require_approval_above_depth(&parent_ns)
            .await
            .expect("resolve parent"),
        Some(1)
    );
    for (gov, want) in [
        (
            json!({"write": "any", "require_approval_above_depth": 3}),
            Some(3),
        ),
        // Leaf policy WITHOUT the field: leaf-first-wins, parent must not leak.
        (json!({"write": "any"}), None),
        // 2^32 must not truncate to a disabled gate: fail closed to 0.
        (
            json!({"write": "any", "require_approval_above_depth": 4_294_967_296_u64}),
            Some(0),
        ),
    ] {
        let child_ns = format!("{parent_ns}/child{}", uuid::Uuid::new_v4().simple());
        let mut child_std = memory(&format!("{child_ns}/std"), "child standard");
        child_std.metadata["governance"] = gov.clone();
        store.store(&ctx, &child_std).await.expect("child std");
        store
            .set_namespace_standard(&ctx, &child_ns, &child_std.id, Some(&parent_ns))
            .await
            .expect("bind child");
        assert_eq!(
            store
                .resolve_require_approval_above_depth(&child_ns)
                .await
                .expect("resolve child"),
            want,
            "#4357: governance {gov}"
        );
    }
    // Nothing bound anywhere: no gate.
    assert_eq!(
        store
            .resolve_require_approval_above_depth(&format!("p4357r-none/{}", uuid::Uuid::new_v4()))
            .await
            .expect("resolve unbound"),
        None
    );
}

fn sqlite_store(file: &NamedTempFile) -> Arc<dyn MemoryStore> {
    Arc::new(ai_memory::store::sqlite::SqliteStore::open(file.path()).expect("sqlite"))
}

#[tokio::test]
async fn issue_4357_sqlite_http_reflect_above_threshold_is_parked() {
    let file = NamedTempFile::new().expect("sqlite file");
    let out = exercise_http_gate(
        sqlite_store(&file),
        StorageBackend::Sqlite,
        Some(file.path()),
    )
    .await;
    assert_eq!(out.status, "pending");
}

#[tokio::test]
async fn issue_4357_sqlite_http_threshold_boundary_and_no_gate() {
    let file = NamedTempFile::new().expect("sqlite file");
    exercise_http_at_threshold(
        sqlite_store(&file),
        StorageBackend::Sqlite,
        Some(file.path()),
    )
    .await;
    let file = NamedTempFile::new().expect("sqlite file");
    exercise_http_no_gate(
        sqlite_store(&file),
        StorageBackend::Sqlite,
        Some(file.path()),
    )
    .await;
}

#[tokio::test]
async fn issue_4357_sqlite_resolver_leaf_first_semantics() {
    let file = NamedTempFile::new().expect("sqlite file");
    exercise_resolver(sqlite_store(&file)).await;
}

/// MCP funnel (sqlite by construction: the stdio handler owns a rusqlite
/// connection). Pins the reference behaviour the other backends must match.
fn mcp_pending_outcome() -> (Outcome, Value) {
    enforce_mode();
    let file = NamedTempFile::new().expect("sqlite file");
    let conn = ai_memory::db::open(file.path()).expect("open");
    let ns = format!("p4357m/{}", uuid::Uuid::new_v4());
    let mut source = memory(&ns, "mcp source");
    source.metadata = json!({"agent_id": OWNER});
    let sid = ai_memory::db::insert(&conn, &source).expect("source");
    let mut standard = memory(&format!("{ns}/std"), "mcp standard");
    standard.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 0});
    let std_id = ai_memory::db::insert(&conn, &standard).expect("standard");
    ai_memory::db::set_namespace_standard(&conn, &ns, &std_id, None).expect("bind");
    let params = gate_body(&sid, &ns);
    let out = ai_memory::mcp::handle_reflect(&conn, file.path(), &params, None, None, None, None)
        .expect("mcp reflect");
    let written = ai_memory::db::list(
        &conn,
        Some(&ns),
        None,
        100,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .map_or(usize::MAX, |v| {
        v.into_iter().filter(|m| m.reflection_depth > 0).count()
    });
    (outcome_of(&out, written), out)
}

#[test]
fn issue_4357_mcp_reflect_above_threshold_is_parked() {
    let (out, raw) = mcp_pending_outcome();
    assert_eq!(out.status, "pending", "{raw}");
    assert_eq!(out.reflections_written, 0, "{raw}");
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

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_4357_postgres_http_reflect_above_threshold_is_parked() {
    let out = exercise_http_gate(pg_store().await, StorageBackend::Postgres, None).await;
    assert_eq!(out.status, "pending");
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_4357_postgres_http_threshold_boundary_and_no_gate() {
    exercise_http_at_threshold(pg_store().await, StorageBackend::Postgres, None).await;
    exercise_http_no_gate(pg_store().await, StorageBackend::Postgres, None).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_4357_postgres_resolver_leaf_first_semantics() {
    exercise_resolver(pg_store().await).await;
}

/// Parity: the same request yields the same governed outcome on MCP/sqlite,
/// HTTP/sqlite and HTTP/postgres.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_4357_parity_same_request_same_outcome_on_both_backends() {
    let (mcp, _) = mcp_pending_outcome();
    let file = NamedTempFile::new().expect("sqlite file");
    let sqlite = exercise_http_gate(
        sqlite_store(&file),
        StorageBackend::Sqlite,
        Some(file.path()),
    )
    .await;
    let pg = exercise_http_gate(pg_store().await, StorageBackend::Postgres, None).await;
    assert_eq!(
        sqlite, pg,
        "#4357: sqlite vs postgres HTTP outcome diverged"
    );
    assert_eq!(
        mcp, pg,
        "#4357: MCP(sqlite) vs postgres HTTP outcome diverged"
    );
}
