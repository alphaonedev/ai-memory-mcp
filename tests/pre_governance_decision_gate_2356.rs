// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2356 (W1A6-03) — END-TO-END proof that `pre_governance_decision` is a
//! REAL dispatchable required event, not enforcement theater.
//!
//! Pre-#2356 `HookEvent::PreGovernanceDecision` was in
//! `ELIGIBLE_REQUIRED_EVENTS` and the boot banner / `doctor --hooks`
//! preflight printed "REQUIRED but NO enabled hook → WILL DENY (enforce)"
//! for it, but the event had ZERO production dispatch sites —
//! `[hooks].required_events = ["pre_governance_decision"]` under
//! `enforce_mode = enforce` never fired and never denied (a fail-open
//! declared control).
//!
//! This test drives the REAL surfaces: an HTTP `POST /api/v1/memories`, an
//! HTTP `DELETE /api/v1/memories/{id}`, an MCP `memory_store` (via
//! `handle_store_for_tests`), and an MCP `memory_check_agent_action`
//! (`handle_check_agent_action`) — once BEFORE the gate is installed (all
//! succeed), then AFTER installing the process gate in `enforce` mode with
//! required `pre_governance_decision` and NO configured hook (all refuse:
//! 503 on HTTP, `Err` on MCP).
//!
//! Isolated in its own integration-test binary because the enforcement gate
//! is a process-global `OnceLock` (first-writer-wins, non-resettable), and
//! a single sequential test avoids intra-file races on the set-once gate.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::hooks::{HookEnforceMode, HookEvent};

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn build_test_router() -> (axum::Router, NamedTempFile) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
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
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
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
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn post_memories(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", "tester-2356")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn delete_memory(router: &axum::Router, id: &str) -> StatusCode {
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/memories/{id}"))
        .header("x-agent-id", "tester-2356")
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

fn mcp_db() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
    permissive_attestation_for_tests();
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("pre-governance-decision-gate-2356");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let db_path = dir.path().join("store.db");
    let conn = ai_memory::storage::open(&db_path).expect("open");
    (dir, db_path, conn)
}

fn mcp_store(
    conn: &rusqlite::Connection,
    db_path: &std::path::Path,
    params: &Value,
) -> Result<Value, String> {
    let ttl = ResolvedTtl::default();
    ai_memory::mcp::tools::handle_store_for_tests(
        conn, db_path, params, None, None, None, &ttl, false, None, None,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn pre_governance_decision_required_with_no_hook_denies_every_surface_2356() {
    let (router, _f) = build_test_router();
    let (_dir, mcp_path, mcp_conn) = mcp_db();

    // ── BEFORE the gate is installed: every surface proceeds ──────────
    let (status, created) = post_memories(
        &router,
        &json!({
            "title": "gate probe 2356",
            "content": "written via the HTTP create path",
            "namespace": "default",
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "with no enforcement gate installed the HTTP write must succeed, got {status}"
    );
    let created_id = created
        .get("id")
        .and_then(Value::as_str)
        .expect("created memory id")
        .to_string();

    let ok = mcp_store(
        &mcp_conn,
        &mcp_path,
        &json!({
            "title": "mcp probe 2356",
            "content": "written via the MCP store path",
            "namespace": "ns-2356",
        }),
    )
    .expect("baseline MCP store must succeed while the gate is uninstalled");
    assert!(ok.get("id").and_then(Value::as_str).is_some());

    let check = ai_memory::mcp::handle_check_agent_action(
        &mcp_conn,
        &json!({"kind": "bash", "command": "echo hello"}),
    )
    .expect("baseline check_agent_action must succeed while the gate is uninstalled");
    assert!(check.get("decision").is_some());

    // ── Install the process gate: enforce mode, `pre_governance_decision`
    // REQUIRED, NO configured hook — the exact posture the boot banner /
    // `doctor --hooks` advertise as "WILL DENY". ──────────────────────
    ai_memory::mcp::install_pre_event_enforce_gate_for_tests(
        Vec::new(),
        HookEnforceMode::Enforce,
        vec![HookEvent::PreGovernanceDecision],
    );

    // HTTP create: the governance decision dispatch is now refused → 503.
    let (after, _) = post_memories(
        &router,
        &json!({
            "title": "gate probe 2356 after",
            "content": "must be refused",
            "namespace": "default",
        }),
    )
    .await;
    assert_eq!(
        after,
        StatusCode::SERVICE_UNAVAILABLE,
        "HTTP POST /api/v1/memories under enforce + required \
         pre_governance_decision + no hook must be DENIED with 503 (#2356)"
    );

    // HTTP delete: same gate, delete-action context.
    let del = delete_memory(&router, &created_id).await;
    assert_eq!(
        del,
        StatusCode::SERVICE_UNAVAILABLE,
        "HTTP DELETE under enforce + required pre_governance_decision + \
         no hook must be DENIED with 503 (#2356)"
    );

    // MCP store: refused with the enforce-gate reason.
    let err = mcp_store(
        &mcp_conn,
        &mcp_path,
        &json!({
            "title": "mcp probe 2356 after",
            "content": "must be refused",
            "namespace": "ns-2356",
        }),
    )
    .expect_err("MCP store must be refused under the installed gate");
    assert!(
        err.contains("hooks.enforce"),
        "refusal names the enforce gate: {err}"
    );

    // MCP check_agent_action: the explicit governance-decision surface.
    let err = ai_memory::mcp::handle_check_agent_action(
        &mcp_conn,
        &json!({"kind": "bash", "command": "echo hello"}),
    )
    .expect_err("check_agent_action must be refused under the installed gate");
    assert!(
        err.contains("hooks.enforce"),
        "refusal names the enforce gate: {err}"
    );
}
