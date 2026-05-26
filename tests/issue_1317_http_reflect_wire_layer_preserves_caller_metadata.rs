// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

//! Wire-layer regression pin for issue #1317 — HTTP-side parallel of
//! PR #1316's MCP `tools/call → handle_reflect` metadata-passthrough
//! test. Extends the substrate-level #1172 coverage (which pins
//! `db::reflect` directly) onto the HTTP surface so the three-surface
//! stable-error-slug + metadata-shape invariants (v1 P18) hold
//! end-to-end across all three surfaces (substrate / MCP / HTTP).
//!
//! ## Defect class
//!
//! The pre-#1172 defect dropped caller-supplied `metadata` keys (most
//! notably `entity_id`) somewhere between the JSON-wire decode and the
//! `ReflectInput.metadata` field carried into `db::reflect`. The MCP
//! wire path is pinned by `tests/issue_1172_reflect_metadata_passthrough.rs::
//! mcp_handle_reflect_preserves_caller_supplied_entity_id`. The HTTP
//! handler [`crate::handlers::route_1111::handle_reflect_http`] is a
//! thin async wrapper around the same `crate::mcp::handle_reflect`
//! substrate primitive — but the JSON body decode + axum extractor
//! chain is its own wire-decode surface and could regress
//! independently of the MCP path. This file pins THAT specific edge:
//! POST `/api/v1/memory_reflect` with `metadata.{entity_id, probe}`
//! must round-trip both keys verbatim into the stored row, must
//! populate the indexed `mentioned_entity_id` column (PERF-8 invariant
//! 2 from #1172), and must not corrupt back-compat for callers that
//! supply only `agent_id`.
//!
//! ## Invariants pinned (per surface)
//!
//! 1. **Entity-binding passthrough.** `POST /api/v1/memory_reflect`
//!    with `metadata: {entity_id: "X", probe: "Y"}` produces a stored
//!    reflection row whose `metadata` JSON column carries BOTH
//!    `entity_id = "X"` AND `probe = "Y"`, alongside the system-spliced
//!    `agent_id` + `reflection_metadata` keys (additive contract from
//!    `src/storage/reflect.rs`).
//! 2. **PERF-8 indexed column.** The same call populates the
//!    `mentioned_entity_id` column with `"X"` via the
//!    `extract_mentioned_entity_id` step-1 path.
//! 3. **Back-compat.** Empty caller metadata (`{}`) still produces the
//!    canonical `{agent_id, reflection_metadata}` shape with no
//!    `entity_id` and a NULL `mentioned_entity_id` (mirrors invariant 4
//!    of `tests/issue_1172_reflect_metadata_passthrough.rs`).
//! 4. **Wire response carries the new id.** The HTTP envelope returns
//!    the same `{id: ...}` shape that the MCP `handle_reflect`
//!    response carries, so callers can chain a row read off the
//!    response id without parsing different envelope shapes per
//!    surface (P18 surface-parity invariant).
//!
//! ## Fixture discipline
//!
//! Each test uses its own namespace + tempfile DB so state isolation
//! holds even when the suite runs in `cargo test --jobs N`. The
//! axum router fixture mirrors the shape `tests/http_routes_1111.rs`
//! uses for the #1111 HTTP-route integration tests — no new helper
//! plumbing introduced.
//!
//! ## Source role-categorical value
//!
//! Per the rationale in `tests/issue_1172_reflect_metadata_passthrough.rs`
//! §"On the choice of `source`": the substrate is heterogeneous-NHI by
//! design (every LLM vendor writes reflections through the same
//! primitive). The fixtures use the vendor-neutral `"api"` source so
//! the regression isn't coupled to any single LLM vendor's identity.

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::db;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use serde_json::{Value, json};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

// ---------------------------------------------------------------------------
// Constants — single source of truth so renaming a fixture is one edit
// and the assertions read against the same names the fixtures produced.
// ---------------------------------------------------------------------------

const FIXTURE_AGENT_ID: &str = "test-agent-1317-http";
/// Vendor-neutral role-categorical source. See file-level docstring.
const FIXTURE_SOURCE: &str = "api";
const FIXTURE_ENTITY_ID: &str = "entity-uuid-1317-http";
const FIXTURE_PROBE_VALUE: &str = "probe-1317-http";

const NS_PASSTHROUGH: &str = "issue-1317-http-pt";
const NS_BACKCOMPAT: &str = "issue-1317-http-bc";

// ---------------------------------------------------------------------------
// Router fixture — mirrors `tests/http_routes_1111.rs::build_router_fixture`.
// Kept here so the test file is self-contained (the existing #1111 fixture
// is private to that integration test binary; cargo's
// one-binary-per-tests-file model means we can't cross-import).
// ---------------------------------------------------------------------------

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1317-http-reflect")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn build_router_fixture() -> (axum::Router, NamedTempFile, PathBuf) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
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
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db_path)
}

/// POST a JSON body to `path` and return the (status, parsed_body) tuple.
async fn post_json(router: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let parsed = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
    (status, parsed)
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Seed one Observation in `db_path/namespace` and return its id. The
/// HTTP `memory_reflect` body's `source_ids` references this row.
fn seed_observation(db_path: &std::path::Path, namespace: &str, title: &str) -> String {
    let conn = db::open(db_path).expect("db::open for seed");
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("issue_1317 fixture observation: {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: FIXTURE_SOURCE.to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": FIXTURE_AGENT_ID}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    db::insert(&conn, &mem).expect("insert observation")
}

/// Probe the sqlite row for the (`metadata` JSON, `mentioned_entity_id`)
/// pair the wire-layer just wrote. Used by every assertion — the
/// HTTP-response envelope only carries the new id; the wire-layer
/// invariant is OBSERVED IN THE DB COLUMN, not in the response body
/// (mirrors the discipline in `tests/issue_1172_reflect_metadata_passthrough.rs`).
fn read_metadata_and_mention(db_path: &std::path::Path, id: &str) -> (Value, Option<String>) {
    let conn = db::open(db_path).expect("db::open for probe");
    conn.query_row(
        "SELECT metadata, mentioned_entity_id FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            let meta_str: String = row.get(0)?;
            let mention: Option<String> = row.get(1)?;
            Ok((
                serde_json::from_str(&meta_str).unwrap_or(Value::Null),
                mention,
            ))
        },
    )
    .expect("read row by id")
}

// ---------------------------------------------------------------------------
// (1) HTTP wire-layer pin — POST /api/v1/memory_reflect preserves
//     caller-supplied metadata.entity_id AND auxiliary keys.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_reflect_preserves_caller_supplied_entity_id_and_probe() {
    let _dir = fresh_dir();
    let (router, f, db_path) = build_router_fixture();
    let src_id = seed_observation(&db_path, NS_PASSTHROUGH, "src-observation-1317-http");

    let body = json!({
        "source_ids": [src_id],
        "title": "reflection-via-http-handler",
        "content": "synthesised reflection content via the HTTP surface",
        "namespace": NS_PASSTHROUGH,
        "agent_id": FIXTURE_AGENT_ID,
        "metadata": {
            "entity_id": FIXTURE_ENTITY_ID,
            "probe": FIXTURE_PROBE_VALUE,
        },
    });

    let (status, resp) = post_json(&router, "/api/v1/memory_reflect", body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1317: HTTP reflect with caller metadata must 200 OK; got {status} {resp}"
    );
    let new_id = resp["id"]
        .as_str()
        .expect("response envelope must carry the new id (P18 surface-parity)")
        .to_string();

    let (meta, mention) = read_metadata_and_mention(&db_path, &new_id);

    // Invariant 1a — caller-supplied entity_id round-trips into stored metadata.
    assert_eq!(
        meta.get("entity_id").and_then(Value::as_str),
        Some(FIXTURE_ENTITY_ID),
        "HTTP wire layer must preserve caller-supplied metadata.entity_id; full metadata = {meta}"
    );

    // Invariant 1b — auxiliary key passthrough. Pre-#1172 the metadata
    // splice DROPPED auxiliary keys alongside entity_id; this asserts
    // the additive contract is honoured for arbitrary caller keys.
    assert_eq!(
        meta.get("probe").and_then(Value::as_str),
        Some(FIXTURE_PROBE_VALUE),
        "HTTP wire layer must preserve auxiliary metadata keys (probe); full metadata = {meta}"
    );

    // System-spliced keys still land alongside caller keys (additive
    // contract from `src/storage/reflect.rs`).
    assert!(
        meta.get("agent_id").is_some(),
        "system-spliced agent_id must coexist with caller keys; full metadata = {meta}"
    );
    assert!(
        meta.get("reflection_metadata").is_some(),
        "system-spliced reflection_metadata must coexist with caller keys; full metadata = {meta}"
    );

    // Invariant 2 — PERF-8 denormalised column populated from caller entity_id.
    assert_eq!(
        mention.as_deref(),
        Some(FIXTURE_ENTITY_ID),
        "HTTP wire layer must populate mentioned_entity_id from caller-supplied metadata.entity_id"
    );

    // Keep the tempfile alive for the test body. Implicit lifetime via
    // `f`'s drop at function-end; bind explicitly so a future
    // 'unused-binding' lint doesn't strip the guard.
    drop(f);
}

// ---------------------------------------------------------------------------
// (2) HTTP back-compat pin — empty caller metadata still produces the
//     canonical {agent_id, reflection_metadata} shape with NULL
//     mentioned_entity_id. Mirrors invariant 4 of #1172 onto the HTTP
//     surface so a future refactor that "fixes" entity_id passthrough
//     by ALWAYS injecting a synthetic entity_id can't slip past.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_reflect_empty_metadata_preserves_canonical_shape() {
    let _dir = fresh_dir();
    let (router, f, db_path) = build_router_fixture();
    let src_id = seed_observation(&db_path, NS_BACKCOMPAT, "src-observation-1317-http-bc");

    let body = json!({
        "source_ids": [src_id],
        "title": "empty-metadata-reflection-1317-http",
        "content": "synthesised reflection content with no caller metadata",
        "namespace": NS_BACKCOMPAT,
        "agent_id": FIXTURE_AGENT_ID,
        "metadata": {},
    });

    let (status, resp) = post_json(&router, "/api/v1/memory_reflect", body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1317: HTTP reflect with empty metadata must 200 OK; got {status} {resp}"
    );
    let new_id = resp["id"].as_str().expect("response id").to_string();

    let (meta, mention) = read_metadata_and_mention(&db_path, &new_id);

    // Canonical shape — system-spliced keys present.
    assert!(
        meta.get("agent_id").is_some(),
        "agent_id must be spliced into stored metadata; full metadata = {meta}"
    );
    assert!(
        meta.get("reflection_metadata").is_some(),
        "reflection_metadata block must be spliced in; full metadata = {meta}"
    );

    // No spurious entity_id when caller didn't supply one.
    assert!(
        meta.get("entity_id").is_none(),
        "no entity_id should appear when caller didn't supply one; full metadata = {meta}"
    );

    // mentioned_entity_id column stays NULL on the back-compat path.
    assert!(
        mention.is_none(),
        "mentioned_entity_id column stays NULL when caller supplied no entity binding; got {mention:?}"
    );

    drop(f);
}
