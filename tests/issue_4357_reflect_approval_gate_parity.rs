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

/// RAII env override: restored on drop, so a panicking cell cannot leak the
/// posture into later cells. Only used while `SERIAL` is held.
struct EnvGuard(&'static str);

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        // SAFETY: every cell holds `SERIAL`, so no other cell reads or writes
        // the process env concurrently.
        unsafe { std::env::set_var(key, value) };
        Self(key)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: as in `set`; the guard is dropped while `SERIAL` is held.
        unsafe { std::env::remove_var(self.0) };
    }
}

const SHARED_KEY: &str = "issue-4357-transport-key";
const OWNER: &str = "ai:owner-4357";
const APPROVER: &str = "ai:approver-4357";

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
        // A well-formed policy that OMITS the field means no gate and the walk
        // STOPS (leaf-first-wins, #2542; GOD final ruling).
        (json!({"write": "any"}), None),
        // An explicit `null` key keeps walking: the parent's value governs.
        (
            json!({"write": "any", "require_approval_above_depth": null}),
            Some(1),
        ),
        // A corrupt level (unparseable policy) never contributes its raw knob.
        (
            json!({"write": "not-a-level", "require_approval_above_depth": 99}),
            Some(1),
        ),
        // A non-integer knob is not honoured as a value; the ancestor governs.
        (
            json!({"write": "any", "require_approval_above_depth": "3"}),
            Some(1),
        ),
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

fn sqlite_store(file: &SqliteTempFile) -> Arc<dyn MemoryStore> {
    Arc::new(ai_memory::store::sqlite::SqliteStore::open(file.path()).expect("sqlite"))
}

#[tokio::test]
async fn issue_4357_sqlite_http_reflect_above_threshold_is_parked() {
    let _serial = SERIAL.lock().await;
    let file = SqliteTempFile::new().expect("sqlite file");
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
    let _serial = SERIAL.lock().await;
    let file = SqliteTempFile::new().expect("sqlite file");
    exercise_http_at_threshold(
        sqlite_store(&file),
        StorageBackend::Sqlite,
        Some(file.path()),
    )
    .await;
    let file = SqliteTempFile::new().expect("sqlite file");
    exercise_http_no_gate(
        sqlite_store(&file),
        StorageBackend::Sqlite,
        Some(file.path()),
    )
    .await;
}

#[tokio::test]
async fn issue_4357_sqlite_resolver_leaf_first_semantics() {
    let _serial = SERIAL.lock().await;
    let file = SqliteTempFile::new().expect("sqlite file");
    exercise_resolver(sqlite_store(&file)).await;
}

/// MCP funnel (sqlite by construction: the stdio handler owns a rusqlite
/// connection). Pins the reference behaviour the other backends must match.
fn mcp_pending_outcome() -> (Outcome, Value) {
    enforce_mode();
    let file = SqliteTempFile::new().expect("sqlite file");
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
    let _serial = SERIAL.blocking_lock();
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
    let _serial = SERIAL.lock().await;
    let out = exercise_http_gate(pg_store().await, StorageBackend::Postgres, None).await;
    assert_eq!(out.status, "pending");
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_4357_postgres_http_threshold_boundary_and_no_gate() {
    let _serial = SERIAL.lock().await;
    exercise_http_at_threshold(pg_store().await, StorageBackend::Postgres, None).await;
    exercise_http_no_gate(pg_store().await, StorageBackend::Postgres, None).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_4357_postgres_resolver_leaf_first_semantics() {
    let _serial = SERIAL.lock().await;
    exercise_resolver(pg_store().await).await;
}

/// Parity: the same request yields the same governed outcome on MCP/sqlite,
/// HTTP/sqlite and HTTP/postgres.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_4357_parity_same_request_same_outcome_on_both_backends() {
    let _serial = SERIAL.lock().await;
    let (mcp, _) = mcp_pending_outcome();
    let file = SqliteTempFile::new().expect("sqlite file");
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

// ---------------------------------------------------------------------------
// Review round 2: resolver inheritance, tenant-scoped replay, provenance,
// attestation ordering.
// ---------------------------------------------------------------------------

const VICTIM: &str = "ai:victim-4357";

async fn reflect_as(router: &axum::Router, agent: &str, body: &Value) -> (StatusCode, Value) {
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

/// Parent standard states threshold 0; the child standard is well-formed but
/// OMITS the field. GOD final ruling (leaf-first-wins, #2542): a well-formed
/// policy that omits the key means NO gate and the walk STOPS, so the resolver
/// answers `None` and a depth-1 reflect into the child is applied (the parent's
/// threshold does not govern it). `declared` binds the parent explicitly,
/// otherwise the chain is the `/` hierarchy. (Inverted from the superseded
/// "omitted continues" rule; safe only once #4356 lands.)
async fn exercise_child_omits_field(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
    declared: bool,
) {
    enforce_mode();
    let ctx = CallerContext::for_agent(OWNER);
    let parent = format!("p4357e/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(&format!("{parent}/standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 0});
    store.store(&ctx, &pstd).await.expect("pstd");
    store
        .set_namespace_standard(&ctx, &parent, &pstd.id, None)
        .await
        .expect("bind parent");
    let child = format!("{parent}/child");
    let mut cstd = memory(&format!("{child}/standards"), "child standard");
    cstd.metadata["governance"] = json!({"write": "any", "promote": "any", "delete": "owner"});
    store.store(&ctx, &cstd).await.expect("cstd");
    let parent_arg = declared.then_some(parent.as_str());
    store
        .set_namespace_standard(&ctx, &child, &cstd.id, parent_arg)
        .await
        .expect("bind child");
    let src = memory(&child, "child source");
    store.store(&ctx, &src).await.expect("src");
    assert_eq!(
        store
            .resolve_require_approval_above_depth(&child)
            .await
            .expect("resolve"),
        None,
        "#4357: a well-formed child that omits the field stops the walk (no gate)"
    );
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(&src.id, &child)).await;
    assert!(
        body.get("id").is_some() && body["status"] != "pending",
        "leaf-first-wins: the omitting child is ungated: {status} {body}"
    );
    assert_eq!(reflection_count(&store, &child).await, 1);
}

/// Rule 5 then rule 3: a CORRUPT leaf under a well-formed parent that OMITS the
/// key. The corrupt level is passed (Severed), the parent stops the walk with no
/// gate, and the passed-corrupt flag turns the result into `Some(0)`.
async fn exercise_corrupt_leaf_under_omitting_parent(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let ctx = CallerContext::for_agent(OWNER);
    let parent = format!("p4357c/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(&format!("{parent}/standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any"});
    store.store(&ctx, &pstd).await.expect("pstd");
    store
        .set_namespace_standard(&ctx, &parent, &pstd.id, None)
        .await
        .expect("bind parent");
    let child = format!("{parent}/child");
    let mut cstd = memory(&format!("{child}/standards"), "child standard");
    cstd.metadata["governance"] = json!({"write": "not-a-level"});
    store.store(&ctx, &cstd).await.expect("cstd");
    store
        .set_namespace_standard(&ctx, &child, &cstd.id, Some(&parent))
        .await
        .expect("bind child");
    let src = memory(&child, "child source");
    store.store(&ctx, &src).await.expect("src");
    assert_eq!(
        store
            .resolve_require_approval_above_depth(&child)
            .await
            .expect("resolve"),
        Some(0),
        "corrupt leaf under an omitting parent fails closed to 0"
    );
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(&src.id, &child)).await;
    assert!(
        body.get("id").is_none() && body["status"] == "pending",
        "{status} {body}"
    );
    assert_eq!(reflection_count(&store, &child).await, 0);
}

/// Parent states threshold 0; the child namespace has NO standard at all.
async fn exercise_child_without_standard(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let ctx = CallerContext::for_agent(OWNER);
    let parent = format!("p4357n/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(&format!("{parent}/standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 0});
    store.store(&ctx, &pstd).await.expect("pstd");
    store
        .set_namespace_standard(&ctx, &parent, &pstd.id, None)
        .await
        .expect("bind parent");
    let child = format!("{parent}/child");
    let src = memory(&child, "child source");
    store.store(&ctx, &src).await.expect("src");
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(&src.id, &child)).await;
    assert!(
        body.get("id").is_none() && body["status"] == "pending",
        "#4357: unbound child must inherit the ancestor threshold: {status} {body}"
    );
}

/// An approved replay must be refused exactly where the direct path is: a
/// hidden private row of another principal holding the same (title,
/// namespace) must survive untouched.
async fn exercise_replay_no_overwrite(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (ns, sid) = seed_namespace(
        &store,
        json!({"write": "any", "require_approval_above_depth": 0}),
    )
    .await;
    let victim = CallerContext::for_agent(VICTIM);
    let title = format!("victim private {}", uuid::Uuid::new_v4());
    let mut vm = memory(&ns, "x");
    vm.title.clone_from(&title);
    vm.content = "VICTIM ORIGINAL CONTENT".into();
    vm.metadata = json!({"agent_id": VICTIM});
    let vid = store.store(&victim, &vm).await.expect("victim store");
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_as(
        &router,
        OWNER,
        &json!({"source_ids": [sid], "title": title, "content": "REPLAY CONTENT",
                "namespace": ns, "agent_id": OWNER}),
    )
    .await;
    assert_eq!(body["status"], "pending", "{status} {body}");
    let pid = body["pending_id"].as_str().expect("pending_id").to_string();
    let approver = CallerContext::for_agent(APPROVER);
    assert!(
        store
            .pending_decide(&approver, &pid, true, APPROVER)
            .await
            .expect("approve")
    );
    let exec = store.execute_pending_action(&approver, &pid).await;
    let admin = CallerContext::for_admin("ai:operator");
    let after = store.get(&admin, &vid).await.expect("victim row");
    assert_eq!(
        after.content, "VICTIM ORIGINAL CONTENT",
        "#4357: the replay overwrote another principal's row (exec={exec:?})"
    );
    assert!(exec.is_err(), "#4357: the replay must be refused: {exec:?}");
}

/// The replayed reflection carries the substrate-stamped provenance of the
/// requester's tenant write: a caller-forged `attest_level` never survives and
/// the row is not stamped substrate-authored.
async fn exercise_replay_provenance(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (ns, sid) = seed_namespace(
        &store,
        json!({"write": "any", "require_approval_above_depth": 0}),
    )
    .await;
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let mut body = gate_body(&sid, &ns);
    body["metadata"] = json!({"attest_level": "agent_attested"});
    let (status, resp) = reflect_http(&router, &body).await;
    assert_eq!(resp["status"], "pending", "{status} {resp}");
    let pid = resp["pending_id"].as_str().expect("pending_id").to_string();
    let queued = store
        .list_pending_actions(Some("pending"), 1000)
        .await
        .expect("list pending")
        .into_iter()
        .find(|p| p.id == pid)
        .expect("queued row");
    assert!(
        queued.payload["metadata"].get("attest_level").is_none(),
        "#4357: a caller attest_level must not ride the queued payload: {}",
        queued.payload
    );
    let approver = CallerContext::for_agent(APPROVER);
    assert!(
        store
            .pending_decide(&approver, &pid, true, APPROVER)
            .await
            .expect("approve")
    );
    let rid = store
        .execute_pending_action(&approver, &pid)
        .await
        .expect("execute")
        .expect("id");
    let admin = CallerContext::for_admin("ai:operator");
    let md = store.get(&admin, &rid).await.expect("reflection").metadata;
    assert_ne!(
        md["attest_level"], "agent_attested",
        "#4357: forged level landed: {md}"
    );
    assert_ne!(
        md["why_trace"], "substrate:system-authored",
        "#4357: tenant reflection stamped substrate-authored: {md}"
    );
    assert_eq!(
        md["agent_id"], OWNER,
        "#4357: authorship stays the requester: {md}"
    );
}

/// With the `why_trace` requirement engaged the direct reflect is refused; the
/// approved replay of the same request must be refused too.
async fn exercise_why_trace_replay(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (ns, sid) = seed_namespace(
        &store,
        json!({"write": "any", "require_approval_above_depth": 0}),
    )
    .await;
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, resp) = reflect_http(&router, &gate_body(&sid, &ns)).await;
    assert_eq!(resp["status"], "pending", "{status} {resp}");
    let pid = resp["pending_id"].as_str().expect("pending_id").to_string();
    let approver = CallerContext::for_agent(APPROVER);
    assert!(
        store
            .pending_decide(&approver, &pid, true, APPROVER)
            .await
            .expect("approve")
    );
    let exec = {
        let _env = EnvGuard::set("AI_MEMORY_REQUIRE_WHY_TRACE", "1");
        store.execute_pending_action(&approver, &pid).await
    };
    assert!(
        !matches!(exec, Ok(Some(_))),
        "#4357: the approved replay bypassed the why_trace gate: {exec:?}"
    );
    assert_eq!(reflection_count(&store, &ns).await, 0);
}

/// Global-strict attestation refuses an unsigned tenant reflect BEFORE it is
/// queued: no pending row, no 2xx.
async fn exercise_strict_attest_before_queue(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (ns, sid) = seed_namespace(
        &store,
        json!({"write": "any", "require_approval_above_depth": 0}),
    )
    .await;
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, resp) = {
        let _env = EnvGuard::set("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "1");
        reflect_http(&router, &gate_body(&sid, &ns)).await
    };
    assert!(
        status.is_client_error() && resp["status"] != "pending",
        "#4357: strict attestation must refuse before queueing: {status} {resp}"
    );
    let queued = store
        .list_pending_actions(Some("pending"), 10_000)
        .await
        .expect("list pending")
        .into_iter()
        .filter(|p| p.namespace == ns)
        .count();
    assert_eq!(
        queued, 0,
        "#4357: nothing may be queued under strict attestation"
    );
}

macro_rules! round2_cells {
    ($($name:ident => $f:ident $(, $arg:expr)?;)*) => {$(
        paste_cell!($name, $f $(, $arg)?);
    )*};
}

macro_rules! paste_cell {
    ($name:ident, $f:ident $(, $arg:expr)?) => {
        mod $name {
            use super::*;

            #[tokio::test]
            async fn issue_4357_sqlite() {
                let _serial = SERIAL.lock().await;
                let file = SqliteTempFile::new().expect("sqlite file");
                $f(sqlite_store(&file), StorageBackend::Sqlite, Some(file.path()) $(, $arg)?).await;
            }

            #[cfg(feature = "sal-postgres")]
            #[tokio::test]
            async fn issue_4357_postgres() {
                let _serial = SERIAL.lock().await;
                $f(pg_store().await, StorageBackend::Postgres, None $(, $arg)?).await;
            }
        }
    };
}

/// A standard whose governance carries the threshold but NO `write` key fails
/// the typed policy parse (`write` is required): a CORRUPT level. It must not
/// turn the gate off. Own namespace, owner caller: pending.
async fn exercise_threshold_only_own_namespace(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (ns, sid) = seed_namespace(&store, json!({"require_approval_above_depth": 0})).await;
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(&sid, &ns)).await;
    assert!(
        body.get("id").is_none() && body["status"] == "pending",
        "#4357: a threshold-only standard must still gate: {status} {body}"
    );
    assert_eq!(reflection_count(&store, &ns).await, 0);
}

/// Same standard, a NON-OWNER tenant reflecting into another owner's
/// namespace: pending, never applied.
async fn exercise_threshold_only_non_owner(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (ns, _owner_source) =
        seed_namespace(&store, json!({"require_approval_above_depth": 0})).await;
    // The tenant's own readable source, stored in the owner's namespace.
    let stranger = CallerContext::for_agent(VICTIM);
    let mut src = memory(&ns, "tenant source");
    src.metadata = json!({"agent_id": VICTIM});
    let sid = store.store(&stranger, &src).await.expect("tenant source");
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let mut body = gate_body(&sid, &ns);
    body["agent_id"] = json!(VICTIM);
    let (status, resp) = reflect_as(&router, VICTIM, &body).await;
    assert!(
        resp.get("id").is_none(),
        "#4357: a non-owner reflect into another owner's namespace was APPLIED: {status} {resp}"
    );
    assert_eq!(reflection_count(&store, &ns).await, 0);
}

/// A corrupt child under an explicit parent 5: the parent decides (the
/// resolver returns 5, never the corrupt level's raw knob, never "no gate").
async fn exercise_corrupt_child_parent_decides(
    store: Arc<dyn MemoryStore>,
    _backend: StorageBackend,
    _sqlite_path: Option<&std::path::Path>,
) {
    let ctx = CallerContext::for_agent(OWNER);
    let parent = format!("p4357c/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(&format!("{parent}/standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 5});
    store.store(&ctx, &pstd).await.expect("pstd");
    store
        .set_namespace_standard(&ctx, &parent, &pstd.id, None)
        .await
        .expect("bind parent");
    let child = format!("{parent}/child");
    let mut cstd = memory(&format!("{child}/standards"), "child standard");
    cstd.metadata["governance"] = json!({"require_approval_above_depth": 99});
    store.store(&ctx, &cstd).await.expect("cstd");
    store
        .set_namespace_standard(&ctx, &child, &cstd.id, None)
        .await
        .expect("bind child");
    assert_eq!(
        store
            .resolve_require_approval_above_depth(&child)
            .await
            .expect("resolve"),
        Some(5),
        "#4357: the explicit ancestor decides over a corrupt level"
    );
}

round2_cells! {
    issue_4357_threshold_only_own_namespace => exercise_threshold_only_own_namespace;
    issue_4357_threshold_only_non_owner_tenant => exercise_threshold_only_non_owner;
    issue_4357_corrupt_child_parent_decides => exercise_corrupt_child_parent_decides;
    issue_4357_child_omits_field_hierarchy => exercise_child_omits_field, false;
    issue_4357_child_omits_field_declared_parent => exercise_child_omits_field, true;
    issue_4357_child_without_standard_inherits => exercise_child_without_standard;
    issue_4357_corrupt_leaf_under_omitting_parent => exercise_corrupt_leaf_under_omitting_parent;
    issue_4357_replay_no_overwrite_hidden_row => exercise_replay_no_overwrite;
    issue_4357_replay_provenance => exercise_replay_provenance;
    issue_4357_why_trace_replay_refused => exercise_why_trace_replay;
    issue_4357_strict_attestation_refuses_before_queue => exercise_strict_attest_before_queue;
}
