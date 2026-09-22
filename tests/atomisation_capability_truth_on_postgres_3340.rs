// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3340 — the `capabilities.atomisation` claim is HONEST on a postgres-backed
//! daemon, through the real `GET /api/v1/capabilities` wiring (not only the
//! pure overlay the in-module pin proves).
//!
//! `CapabilityAtomisation::current()` hardcodes every engine sub-feature to
//! `"implemented"` because the engine is compiled in; but that engine is typed
//! on a `rusqlite::Connection`, so on postgres every store reports
//! `atomise_outcome=skipped_backend_unsupported` and the HTTP atomise route
//! refuses. The handler overlays the honest posture when
//! `app.storage_backend` is Postgres — this suite drives that branch with a
//! postgres-shaped `AppState` (the shape `bootstrap_serve` builds: scratch
//! sqlite `app.db`, a SAL store handle) and leaves sqlite as the control.
//!
//! Fixture mirrors `tests/skills_fail_closed_on_postgres_3183.rs`; the
//! SqliteStore file lives in a `tempdir` that the test keeps alive (no
//! `NamedTempFile` for a database path, nothing forgotten).

#![allow(clippy::doc_markdown, clippy::too_many_lines)]
#![cfg(feature = "sal")]

use std::sync::Arc;

use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ADMIN: &str = "ai:capabilities-3340";
const ENGINE_FIELDS: [&str; 4] = ["tool", "cli", "auto", "curator"];
const LABEL_FIELDS: [&str; 3] = ["recall_preference", "forensic", "link_relation"];

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before any gated request is issued.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

/// Build an `AppState` for `backend`; the returned `TempDir` owns the
/// SqliteStore file and must outlive the router.
fn app_state(backend: StorageBackend) -> (AppState, tempfile::TempDir) {
    permissive_attestation_for_tests();
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        scratch,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
    let store_path = dir.path().join("store-3340.db");
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(&store_path).expect("open SqliteStore"),
    );
    let app = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (app, dir)
}

async fn capabilities(backend: StorageBackend) -> (StatusCode, Value, tempfile::TempDir) {
    let (app, dir) = app_state(backend);
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/capabilities")
        .header("x-agent-id", ADMIN)
        .body(Body::empty())
        .expect("build request");
    let resp = router.oneshot(req).await.expect("router call");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value, dir)
}

#[tokio::test]
async fn capabilities_atomisation_is_honest_on_postgres_3340() {
    let (status, body, _dir) = capabilities(StorageBackend::Postgres).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let atomisation = body["atomisation"]
        .as_object()
        .unwrap_or_else(|| panic!("#3340: capabilities carries an atomisation object: {body}"));
    assert_eq!(
        atomisation.get("unsupported_on_postgres"),
        Some(&json!(true)),
        "#3340: the postgres daemon discloses that the engine is unsupported: {body}"
    );
    for field in ENGINE_FIELDS {
        assert_eq!(
            atomisation.get(field),
            Some(&json!("unsupported_on_postgres")),
            "#3340: engine field {field} must not read as implemented on postgres: {body}"
        );
    }
    let reason = atomisation["unsupported_reason"]
        .as_str()
        .expect("unsupported_reason is a string");
    assert!(
        reason.contains("#3340") && reason.contains("skipped_backend_unsupported"),
        "the reason names the issue and the failure mode: {reason}"
    );
    for field in LABEL_FIELDS {
        assert!(
            atomisation.contains_key(field),
            "the read/label surface {field} is left in place: {body}"
        );
        assert_ne!(
            atomisation.get(field),
            Some(&json!("unsupported_on_postgres")),
            "the read/label surface {field} is not flipped: {body}"
        );
    }
}

#[tokio::test]
async fn capabilities_atomisation_is_untouched_on_sqlite_3340() {
    let (status, body, _dir) = capabilities(StorageBackend::Sqlite).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let atomisation = body["atomisation"]
        .as_object()
        .unwrap_or_else(|| panic!("capabilities carries an atomisation object: {body}"));
    assert!(
        !atomisation.contains_key("unsupported_on_postgres")
            && !atomisation.contains_key("unsupported_reason"),
        "#3340: sqlite carries no postgres disclosure: {body}"
    );
    for field in ENGINE_FIELDS {
        assert_eq!(
            atomisation.get(field),
            Some(&json!("implemented")),
            "sqlite engine field {field} reads implemented: {body}"
        );
    }
}
