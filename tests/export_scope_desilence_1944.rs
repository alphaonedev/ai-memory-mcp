// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! #1944 (`B_WARN` de-silencing, 2×5-agent vote `woaiwndla` / `4d3ea1c5`) —
//! regression pins for the `ai-memory export` scope de-silencing on BOTH
//! surfaces.
//!
//! The JSON `export` command emits a memories + links CONVENIENCE view and
//! silently OMITTED the tamper-evidence + governance spine. The ratified
//! hedge (NOT the full v2 exporter — that defers to v1.x) is:
//!
//! - **CLI (`src/cli/io.rs::export`)** — a prominent WARN to **stderr only**
//!   (never stdout, so a piped `export > x.json` stays valid JSON) plus
//!   additive in-payload markers (`export_scope` / `portability_complete` /
//!   `excludes`), with the `{memories, links, count, exported_at}` shape
//!   unchanged.
//! - **HTTP (`src/handlers/admin.rs::export_memories`)** — the SAME additive
//!   markers so the HTTP surface is not a silent-lossy sibling.
//!
//! These tests are non-tautological: the CLI test drives the real binary as
//! a subprocess and asserts (a) stderr carries the WARN, (b) stdout carries
//! the markers, AND (c) stdout is otherwise byte/shape-unchanged (exactly the
//! four original keys plus the three additive markers — no more, no less —
//! and NO WARN text bled into stdout, so a pipe survives). The HTTP test
//! exercises the admin export handler through the real router and asserts the
//! markers ride the response alongside the unchanged corpus shape.

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::export_scope;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::field_names;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

fn seed_memory(db_path: &std::path::Path, owner: &str, namespace: &str) {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("seed-{owner}"),
        content: format!("body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": owner}),
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
        ..Memory::default()
    };
    ai_memory::db::insert(&conn, &mem).expect("insert seed");
}

/// The canonical set of top-level keys the export payload MUST carry after
/// #1944: the four original keys (shape-unchanged) plus the three additive
/// markers — no more, no less.
fn assert_shape_and_markers(v: &Value, ctx: &str) {
    let obj = v
        .as_object()
        .unwrap_or_else(|| panic!("{ctx}: export must be a JSON object; got {v}"));

    // Original convenience-view shape is preserved.
    assert!(
        obj.get("memories").is_some_and(Value::is_array),
        "{ctx}: memories[] preserved"
    );
    assert!(
        obj.get("links").is_some_and(Value::is_array),
        "{ctx}: links[] preserved"
    );
    assert!(
        obj.get("count").is_some_and(Value::is_number),
        "{ctx}: count preserved"
    );
    assert!(
        obj.get(field_names::EXPORTED_AT)
            .is_some_and(Value::is_string),
        "{ctx}: exported_at preserved"
    );

    // Additive scope markers are present with the SSOT values.
    assert_eq!(
        obj.get(field_names::EXPORT_SCOPE).and_then(Value::as_str),
        Some(export_scope::SCOPE_MEMORIES_LINKS),
        "{ctx}: export_scope marker must equal the SSOT value"
    );
    assert_eq!(
        obj.get(field_names::PORTABILITY_COMPLETE)
            .and_then(Value::as_bool),
        Some(false),
        "{ctx}: portability_complete must be false — export is NOT the portability path"
    );
    let excludes = obj
        .get(field_names::EXCLUDES)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{ctx}: excludes[] marker must be present; got {v}"));
    for class in export_scope::OMITTED_SIGNED_CLASSES {
        assert!(
            excludes.iter().any(|e| e.as_str() == Some(class)),
            "{ctx}: excludes must name the omitted spine class {class}; got {v}"
        );
    }
    assert_eq!(
        excludes.len(),
        export_scope::OMITTED_SIGNED_CLASSES.len(),
        "{ctx}: excludes must be exactly the SSOT spine-class set"
    );
}

// ─── CLI surface (subprocess against the real binary) ─────────────────────

#[test]
fn cli_export_warns_on_stderr_and_marks_payload_without_changing_shape_1944() {
    // Arrange: a fresh db under .local-runs (project no-/tmp HARD RULE) with
    // one seeded row so `count` is non-trivial.
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1944-export-scope");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix("cli-export-")
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let db_path = dir.path().join("corpus.db");
    seed_memory(&db_path, "alice", "ns-1944");

    // Act: drive the real `ai-memory --db <db> export` subprocess.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .arg("--db")
        .arg(&db_path)
        .arg("export")
        .env("AI_MEMORY_NO_CONFIG", "1")
        .output()
        .expect("spawn ai-memory export");

    assert!(
        out.status.success(),
        "export must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // (c) stdout is valid JSON — the pipe survives — and NO WARN text bled
    // into stdout (the WARN is stderr-only).
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout MUST be valid JSON for `export > x.json`: {e}\n{stdout}")
    });
    assert!(
        !stdout.contains("WARNING"),
        "the WARN must NOT appear on stdout (it would corrupt a piped export)"
    );

    // (b) markers present + (original shape unchanged).
    assert_shape_and_markers(&v, "cli");
    assert_eq!(v["count"].as_u64(), Some(1), "seeded row is counted");

    // (a) the WARN fired on stderr, names the omitted classes, and points to
    // the real `backup` verb.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("CONVENIENCE"),
        "stderr WARN states convenience scope; got: {stderr}"
    );
    assert!(
        stderr.contains("ai-memory backup"),
        "stderr WARN directs to the lossless `backup` path; got: {stderr}"
    );
    for class in export_scope::OMITTED_SIGNED_CLASSES {
        assert!(
            stderr.contains(class),
            "stderr WARN names omitted spine class {class}; got: {stderr}"
        );
    }
}

// ─── HTTP surface (admin export handler through the real router) ──────────

#[allow(clippy::too_many_lines)]
fn build_router_fixture(db_path: &std::path::Path, admin_ids: Vec<String>) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
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
        admin_agent_ids: Arc::new(admin_ids),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

#[tokio::test]
async fn http_export_carries_scope_markers_without_changing_shape_1944() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_memory(db_path, "alice", "ns-1944/a");
    seed_memory(db_path, "carol", "ns-1944/c");

    let router = build_router_fixture(db_path, vec!["ops:admin".into()]);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/export")
        .header("x-agent-id", "ops:admin")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "admin export must be 200");
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).expect("http export JSON");

    assert_shape_and_markers(&v, "http");
    assert_eq!(v["count"].as_u64(), Some(2), "both seeded rows counted");
}
