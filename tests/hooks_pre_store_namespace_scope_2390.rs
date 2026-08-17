// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2390 (N9) — the `PreStore` half of the namespace-scope fix, in its OWN test
//! binary.
//!
//! The pre-event enforcement gate is a process-global `OnceLock`
//! (first-writer-wins, non-resettable), so a scoped `PreStore` hook cannot share
//! a binary with tests that seed fixtures through `POST /api/v1/memories` — it
//! would deny their seeding. Hence the split from
//! `hooks_pre_event_namespace_scope_2390.rs`.
//!
//! Signal convention (same as the sibling binary): the hook is
//! `fail_mode = Closed` pointing at a NONEXISTENT command, so `503` == "the
//! scoped hook FIRED" and "not 503" == "it was scoped out".

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::hooks::config::{FailMode, HookConfig, HookMode};
use ai_memory::hooks::{HookEnforceMode, HookEvent};

/// The namespace the scoped hook is bound to — writes here MUST be governed.
const GOVERNED_NS: &str = "prod";
/// A namespace no hook is scoped to — writes here MUST stay ungoverned.
const FREE_NS: &str = "scratch";
/// Command the scoped hook points at. It does not exist, so a hook that FIRES
/// fails to spawn and (being `fail_mode = Closed`) denies the chain.
const NONEXISTENT_HOOK_BIN: &str = "/nonexistent/ai-memory-2390-scoped-hook";

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn scoped_hook(event: HookEvent, namespace: &str) -> HookConfig {
    HookConfig {
        event,
        command: std::path::PathBuf::from(NONEXISTENT_HOOK_BIN),
        priority: 0,
        timeout_ms: 1_000,
        mode: HookMode::Exec,
        enabled: true,
        namespace: namespace.to_string(),
        fail_mode: FailMode::Closed,
    }
}

/// Install the process gate exactly once: ONE `PreStore` hook scoped to
/// [`GOVERNED_NS`], `enforce` mode, EMPTY `required_events` (so the
/// namespace-blind mandatory-PRESENCE gate cannot mask the firing behaviour
/// under test).
fn install_gate_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        ai_memory::mcp::install_pre_event_enforce_gate_for_tests(
            vec![scoped_hook(HookEvent::PreStore, GOVERNED_NS)],
            HookEnforceMode::Enforce,
            Vec::new(),
        );
    });
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
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn post(router: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

/// #2390 — a `PreStore` hook scoped to `prod` MUST fire on a `prod` store and
/// MUST NOT fire on a `scratch` store.
#[tokio::test]
async fn pre_store_scoped_hook_fires_in_namespace_and_not_out_of_namespace_2390() {
    let (router, _f) = build_test_router();
    install_gate_once();

    let (in_scope, body) = post(
        &router,
        "/api/v1/memories",
        &json!({"title": "governed-store", "content": "c", "namespace": GOVERNED_NS}),
    )
    .await;
    assert_eq!(
        in_scope,
        StatusCode::SERVICE_UNAVAILABLE,
        "#2390: a PreStore hook scoped to `{GOVERNED_NS}` MUST fire on a \
         `{GOVERNED_NS}` store; got {in_scope} {body}"
    );

    let (out_of_scope, body) = post(
        &router,
        "/api/v1/memories",
        &json!({"title": "free-store", "content": "c", "namespace": FREE_NS}),
    )
    .await;
    assert_ne!(
        out_of_scope,
        StatusCode::SERVICE_UNAVAILABLE,
        "a `{GOVERNED_NS}`-scoped PreStore hook must NOT fire on a `{FREE_NS}` \
         store; got {out_of_scope} {body}"
    );
}

/// #2390 — the OMITTED-namespace skew the issue named explicitly.
///
/// A caller who omits `namespace` lands in the RESOLVED default namespace, and
/// the gate must scope on THAT, not on "no namespace". Pinned by equivalence: an
/// omitted `namespace` must produce the same gate outcome as passing the default
/// namespace explicitly. Pre-fix the two diverged — the explicit form carried a
/// namespace and the omitted form carried none, which skipped every scoped hook.
#[tokio::test]
async fn pre_store_omitted_namespace_resolves_to_default_and_is_scoped_on_it_2390() {
    let (router, _f) = build_test_router();
    install_gate_once();

    let (omitted, omitted_body) = post(
        &router,
        "/api/v1/memories",
        &json!({"title": "omitted-ns", "content": "c"}),
    )
    .await;
    let (explicit, explicit_body) = post(
        &router,
        "/api/v1/memories",
        &json!({
            "title": "explicit-default-ns",
            "content": "c",
            "namespace": ai_memory::DEFAULT_NAMESPACE,
        }),
    )
    .await;

    assert_eq!(
        omitted.is_success(),
        explicit.is_success(),
        "#2390: omitting `namespace` must resolve through the SAME default \
         ladder as passing `{}` explicitly, so both get the same hook scoping; \
         got omitted={omitted} {omitted_body} vs explicit={explicit} {explicit_body}",
        ai_memory::DEFAULT_NAMESPACE
    );
    // The scoped hook covers `prod`, not the default namespace, so neither form
    // may be denied by it — a default-namespace write is simply not in scope.
    assert_ne!(
        omitted,
        StatusCode::SERVICE_UNAVAILABLE,
        "a `{GOVERNED_NS}`-scoped hook must not fire on a default-namespace \
         store; got {omitted} {omitted_body}"
    );
}
