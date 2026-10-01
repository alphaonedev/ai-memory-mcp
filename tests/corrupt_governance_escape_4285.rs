// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4285 / #4357 composed rule, end to end: a depth-1 reflect into a child
//! namespace must NOT be applied when the PARENT states
//! `require_approval_above_depth: 0` and the child standard is corrupt, corrupt
//! carrying a larger raw value (99), or (sqlite) its whole `metadata` cell is
//! corrupt. Both backends where the surface exists; the whole-metadata shape
//! cannot exist on postgres (CHECK `memories_metadata_is_object`), asserted
//! below. Helpers are the #4357 test helpers.
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

/// Cells mutate process env (attestation / `why_trace` postures); one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SHARED_KEY: &str = "issue-4285e-transport-key";
const OWNER: &str = "ai:owner-4285e";
const STRANGER: &str = "ai:stranger-4285e";

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
    reflect_http_as(router, OWNER, body).await
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

fn sqlite_store(file: &NamedTempFile) -> Arc<dyn MemoryStore> {
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

/// Parent standard states threshold 0; `child_gov` is the child's standard.
/// Returns (store, child ns, child standard id, child source id).
async fn seed_parent0_child(
    store: &Arc<dyn MemoryStore>,
    child_gov: Value,
) -> (String, String, String) {
    let ctx = CallerContext::for_agent(OWNER);
    let parent = format!("p4285e/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(&format!("{parent}/standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 0});
    store.store(&ctx, &pstd).await.expect("pstd");
    store
        .set_namespace_standard(&ctx, &parent, &pstd.id, None)
        .await
        .expect("bind parent");
    let child = format!("{parent}/child");
    let mut cstd = memory(&format!("{child}/standards"), "child standard");
    cstd.metadata["governance"] = child_gov;
    store.store(&ctx, &cstd).await.expect("cstd");
    store
        .set_namespace_standard(&ctx, &child, &cstd.id, Some(&parent))
        .await
        .expect("bind child");
    let src = memory(&child, "child source");
    store.store(&ctx, &src).await.expect("src");
    (child, cstd.id, src.id)
}

/// The depth-1 reflect must be parked: never applied, nothing written.
async fn assert_not_applied(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
    child: &str,
    src_id: &str,
    what: &str,
) {
    assert_eq!(
        store
            .resolve_require_approval_above_depth(child)
            .await
            .expect("resolve"),
        Some(0),
        "{what}: the parent's explicit threshold must govern"
    );
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(src_id, child)).await;
    assert!(
        body.get("id").is_none() && body["status"] == "pending",
        "#4285: {what} escaped the parent's gate: {status} {body}"
    );
    assert_eq!(reflection_count(&store, child).await, 0, "{what}");
}

async fn exercise_corrupt_child(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (child, _sid, src) = seed_parent0_child(&store, json!({"write": "not-a-level-4285"})).await;
    assert_not_applied(store, backend, sqlite_path, &child, &src, "corrupt child").await;
}

async fn exercise_corrupt_child_99(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let (child, _sid, src) = seed_parent0_child(
        &store,
        json!({"write": "not-a-level-4285", "require_approval_above_depth": 99}),
    )
    .await;
    assert_not_applied(
        store,
        backend,
        sqlite_path,
        &child,
        &src,
        "corrupt child carrying 99",
    )
    .await;
}

/// N1 (#4357 recheck): a standard that is only a threshold knob (no `write`) is
/// a CORRUPT level. With NO ancestor the chain must still fail closed to
/// threshold 0, and the Owner floor applies on top.
async fn exercise_threshold_only_no_ancestor(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let ctx = CallerContext::for_agent(OWNER);
    let ns = format!("p4285n1/{}", uuid::Uuid::new_v4().simple());
    let mut std_mem = memory(&format!("{ns}/standards"), "knob-only standard");
    std_mem.metadata["governance"] = json!({"require_approval_above_depth": 0});
    store.store(&ctx, &std_mem).await.expect("std");
    store
        .set_namespace_standard(&ctx, &ns, &std_mem.id, None)
        .await
        .expect("bind");
    let src = memory(&ns, "source");
    store.store(&ctx, &src).await.expect("src");
    assert_eq!(
        store
            .resolve_require_approval_above_depth(&ns)
            .await
            .expect("resolve"),
        Some(0),
        "N1: a corrupt level with nothing explicit fails closed to 0"
    );
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    // Owner: admitted by the Owner floor, then parked by the Threshold(0) gate.
    let (status, body) = reflect_http(&router, &gate_body(&src.id, &ns)).await;
    assert!(
        body.get("id").is_none() && body["status"] == "pending",
        "N1: threshold-only standard, owner: must be pending: {status} {body}"
    );
    assert_eq!(reflection_count(&store, &ns).await, 0);
    // Non-owner: the Owner floor (and the gate) must keep it from landing.
    let (status, body) = reflect_http_as(&router, STRANGER, &gate_body(&src.id, &ns)).await;
    assert!(
        body.get("id").is_none() && (body["status"] == "pending" || !status.is_success()),
        "N1: threshold-only standard, non-owner: must be pending or refused: {status} {body}"
    );
    assert_eq!(reflection_count(&store, &ns).await, 0);
}

/// Reviewer case C8/C10: under rule 1 a corrupt leaf below an EXPLICIT ancestor
/// threshold of 5 is governed by the 5, so a depth-1 reflect clears the gate.
/// The Owner floor (#4285) is what tightens it: the leaf's owner is not locked
/// out, a non-owner is refused, and the control (the same non-owner against an
/// INTACT permissive leaf, which omits the key and so stops the walk) lands,
/// proving the floor is the cause.
async fn exercise_corrupt_leaf_under_explicit_ancestor_floor(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let ctx = CallerContext::for_agent(OWNER);
    let parent = format!("p4285f/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(&format!("{parent}/standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 5});
    store.store(&ctx, &pstd).await.expect("pstd");
    store
        .set_namespace_standard(&ctx, &parent, &pstd.id, None)
        .await
        .expect("bind parent");
    let mut ids = Vec::new();
    for (leaf, gov) in [
        ("corrupt", json!({"write": "not-a-level-4285"})),
        ("intact", json!({"write": "any"})),
    ] {
        let child = format!("{parent}/{leaf}");
        let mut cstd = memory(&format!("{child}/standards"), "child standard");
        cstd.metadata["governance"] = gov;
        store.store(&ctx, &cstd).await.expect("cstd");
        store
            .set_namespace_standard(&ctx, &child, &cstd.id, Some(&parent))
            .await
            .expect("bind child");
        let mut src = memory(&child, "source");
        src.metadata["scope"] = json!("collective");
        store.store(&ctx, &src).await.expect("src");
        // Corrupt leaf: continues to the explicit ancestor 5 (rule 1). Intact
        // leaf that omits the key: no gate, the walk STOPS (leaf-first-wins).
        let want = if leaf == "corrupt" { Some(5) } else { None };
        assert_eq!(
            store
                .resolve_require_approval_above_depth(&child)
                .await
                .expect("resolve"),
            want,
            "{leaf}"
        );
        ids.push((child, src.id));
    }
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (corrupt_ns, corrupt_src) = &ids[0];
    let (intact_ns, intact_src) = &ids[1];
    // Control: intact permissive leaf, non-owner, depth 1 <= 5: it lands.
    let (status, body) =
        reflect_http_as(&router, STRANGER, &gate_body(intact_src, intact_ns)).await;
    assert!(
        status.is_success() && body.get("id").is_some(),
        "control (intact leaf, non-owner) must land so the floor is the discriminator: {status} {body}"
    );
    // Corrupt leaf, non-owner: Owner floor refuses.
    let (status, body) =
        reflect_http_as(&router, STRANGER, &gate_body(corrupt_src, corrupt_ns)).await;
    assert!(
        body.get("id").is_none() && !status.is_success(),
        "#4285: the Owner floor must refuse a non-owner under a corrupt leaf: {status} {body}"
    );
    assert_eq!(reflection_count(&store, corrupt_ns).await, 0);
    // Corrupt leaf, owner: not locked out; clears the gate (1 <= 5) and lands.
    let (status, body) = reflect_http(&router, &gate_body(corrupt_src, corrupt_ns)).await;
    assert!(
        status.is_success() && body.get("id").is_some(),
        "the owner of a corrupt leaf must not be locked out: {status} {body}"
    );
}

/// Rule 5 then rule 3: a CORRUPT leaf under a well-formed parent that OMITS the
/// key. The corrupt level is passed, the parent stops the walk with no gate, and
/// the passed-corrupt flag makes the result `Some(0)`: the reflect is parked.
async fn exercise_corrupt_leaf_under_omitting_parent(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    enforce_mode();
    let ctx = CallerContext::for_agent(OWNER);
    let parent = format!("p4285o/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(&format!("{parent}/standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any"});
    store.store(&ctx, &pstd).await.expect("pstd");
    store
        .set_namespace_standard(&ctx, &parent, &pstd.id, None)
        .await
        .expect("bind parent");
    let child = format!("{parent}/child");
    let mut cstd = memory(&format!("{child}/standards"), "child standard");
    cstd.metadata["governance"] = json!({"write": "not-a-level-4285"});
    store.store(&ctx, &cstd).await.expect("cstd");
    store
        .set_namespace_standard(&ctx, &child, &cstd.id, Some(&parent))
        .await
        .expect("bind child");
    let src = memory(&child, "source");
    store.store(&ctx, &src).await.expect("src");
    assert_not_applied_zero(store, backend, sqlite_path, &child, &src.id).await;
}

async fn assert_not_applied_zero(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
    child: &str,
    src_id: &str,
) {
    assert_eq!(
        store
            .resolve_require_approval_above_depth(child)
            .await
            .expect("resolve"),
        Some(0)
    );
    let (router, _f) = build_router(backend, Arc::clone(&store), sqlite_path);
    let (status, body) = reflect_http(&router, &gate_body(src_id, child)).await;
    assert!(
        body.get("id").is_none() && body["status"] == "pending",
        "{status} {body}"
    );
    assert_eq!(reflection_count(&store, child).await, 0);
}

macro_rules! escape_cells {
    ($($name:ident => $f:ident;)*) => {$(
        mod $name {
            use super::*;

            #[tokio::test]
            async fn issue_4285_sqlite() {
                let _serial = SERIAL.lock().await;
                let file = NamedTempFile::new().expect("sqlite file");
                $f(sqlite_store(&file), StorageBackend::Sqlite, Some(file.path())).await;
            }

            #[cfg(feature = "sal-postgres")]
            #[tokio::test]
            async fn issue_4285_postgres() {
                let _serial = SERIAL.lock().await;
                $f(pg_store().await, StorageBackend::Postgres, None).await;
            }
        }
    )*};
}

escape_cells! {
    corrupt_child_parent0 => exercise_corrupt_child;
    corrupt_child_carrying_99_parent0 => exercise_corrupt_child_99;
    threshold_only_no_ancestor_n1 => exercise_threshold_only_no_ancestor;
    corrupt_leaf_under_omitting_parent => exercise_corrupt_leaf_under_omitting_parent;
    corrupt_leaf_under_explicit_ancestor_owner_floor => exercise_corrupt_leaf_under_explicit_ancestor_floor;
}

/// sqlite: the child standard's WHOLE `metadata` cell is corrupted after the
/// bind (invalid JSON, array, string). The lenient row mapper reads it as `{}`;
/// the raw-column classifier must treat it as SEVERED so the parent gate holds.
#[tokio::test]
async fn issue_4285_sqlite_whole_metadata_corruption_parent0() {
    let _serial = SERIAL.lock().await;
    for raw in ["{not json", "[1,2]", "\"just a string\""] {
        enforce_mode();
        let file = NamedTempFile::new().expect("sqlite file");
        let store = sqlite_store(&file);
        let (child, sid, src) = seed_parent0_child(&store, json!({"write": "any"})).await;
        let conn = ai_memory::db::open(file.path()).expect("raw conn");
        conn.execute(
            "UPDATE memories SET metadata = ?1 WHERE id = ?2",
            rusqlite::params![raw, sid],
        )
        .expect("corrupt the metadata cell");
        drop(conn);
        assert_not_applied(
            store,
            StorageBackend::Sqlite,
            Some(file.path()),
            &child,
            &src,
            &format!("whole-metadata corruption {raw}"),
        )
        .await;
    }
}

/// postgres: the whole-metadata shape cannot be stored (CHECK constraint), so
/// the escape surface does not exist there. Pinned so the claim stays true.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_4285_postgres_whole_metadata_corruption_is_unrepresentable() {
    let _serial = SERIAL.lock().await;
    let store = pg_store().await;
    let (_child, sid, _src) = seed_parent0_child(&store, json!({"write": "any"})).await;
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("pg url");
    let pool = sqlx::PgPool::connect(&url).await.expect("pool");
    for raw in ["[1,2]", "\"s\"", "7"] {
        let r = sqlx::query("UPDATE memories SET metadata = $1::jsonb WHERE id = $2")
            .bind(raw)
            .bind(&sid)
            .execute(&pool)
            .await;
        assert!(
            r.is_err(),
            "#4285: pg must refuse non-object metadata ({raw}); the CHECK is the guard"
        );
    }
}
