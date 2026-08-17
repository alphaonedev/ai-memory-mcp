// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2390 (N9) — a namespace-SCOPED pre-event enforcement hook must actually
//! FIRE for an in-scope write and must NOT fire for an out-of-scope one.
//!
//! Pre-fix, `HookChain::fire` resolved the in-flight namespace by reading
//! `payload["namespace"]`, and 11 of the 13 pre-event dispatch sites built a
//! payload with no namespace at all (`{"id": …}` for delete/promote, the raw
//! link body for `PreLink`, the raw MCP arguments elsewhere). Since
//! `HookConfig::matches_namespace(None)` is `false` for a scoped hook, EVERY
//! namespace-scoped hook was skipped on EVERY pre-event — a silently-dead
//! enforcement gate of exactly the class `AI_MEMORY_HOOKS_ENFORCE_MODE` exists
//! to close (#1734 PE-1, wired at #1885 / #1924).
//!
//! # How these tests prove firing without a hook binary
//!
//! Each hook below is `fail_mode = Closed` and points at a NONEXISTENT command.
//! That makes the outcome a clean, binary signal:
//!
//! * hook FIRES  → spawn fails → `FailMode::Closed` → chain `Deny` → HTTP 503
//! * hook SKIPPED → chain returns `Allow` → the handler proceeds (NOT 503)
//!
//! So "503" means "the scoped hook fired" and "not 503" means "it was scoped
//! out", with no script, no daemon, and no dependency on hook stdout.
//!
//! `required_events` is deliberately EMPTY here: the mandatory-PRESENCE gate
//! (`enforce_required_event_presence`) is namespace-blind and would deny on
//! presence grounds alone, masking the firing behaviour under test. Empty
//! required + `Enforce` isolates the FIRE path, which is what #2390 is about.
//!
//! The enforcement gate is a process-global `OnceLock` (first-writer-wins,
//! non-resettable), so all cases share ONE installed gate in this one binary.

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

/// The namespace the scoped hooks are bound to — writes here MUST be governed.
const GOVERNED_NS: &str = "prod";
/// A namespace no hook is scoped to — writes here MUST stay ungoverned.
const FREE_NS: &str = "scratch";
/// Command the scoped hooks point at. It does not exist, so a hook that FIRES
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

/// Install the shared process gate exactly once: hooks for the pre-events under
/// test, ALL scoped to [`GOVERNED_NS`], `enforce` mode, EMPTY `required_events`.
///
/// Deliberately carries NO `PreStore` hook: tests in this binary run in
/// parallel against ONE process-global gate, and a scoped `PreStore` hook would
/// deny another test's in-flight fixture seeding. The `PreStore` case therefore
/// lives in its own binary (`hooks_pre_store_namespace_scope_2390.rs`).
fn install_gate_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        ai_memory::mcp::install_pre_event_enforce_gate_for_tests(
            vec![
                scoped_hook(HookEvent::PreLink, GOVERNED_NS),
                scoped_hook(HookEvent::PreDelete, GOVERNED_NS),
                scoped_hook(HookEvent::PrePromote, GOVERNED_NS),
            ],
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

async fn delete(router: &axum::Router, uri: &str) -> StatusCode {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

/// Seed a memory in `namespace` and return its id. Seeding runs BEFORE the gate
/// is installed so the `pre_store` hook cannot interfere with fixture setup.
async fn seed(router: &axum::Router, namespace: &str, title: &str) -> String {
    let (status, body) = post(
        router,
        "/api/v1/memories",
        &json!({"title": title, "content": "c", "namespace": namespace}),
    )
    .await;
    assert!(
        status.is_success(),
        "seed {title}@{namespace} must be created, got {status} {body}"
    );
    body.get("id")
        .and_then(Value::as_str)
        .unwrap_or(title)
        .to_string()
}

/// #2390 — the headline case. A `PreLink` hook scoped to `prod` MUST fire on a
/// link between two `prod` memories, and MUST NOT fire on a link between two
/// `scratch` memories.
///
/// Pre-fix BOTH links returned non-503: the link payload (the raw caller body)
/// carried no namespace, `matches_namespace(None)` was false, and the scoped
/// hook was skipped unconditionally — namespace-scoped governance was
/// structurally dead on the link lane.
#[tokio::test]
async fn pre_link_scoped_hook_fires_in_namespace_and_not_out_of_namespace_2390() {
    let (router, _f) = build_test_router();
    let prod_a = seed(&router, GOVERNED_NS, "prod-a").await;
    let prod_b = seed(&router, GOVERNED_NS, "prod-b").await;
    let free_a = seed(&router, FREE_NS, "scratch-a").await;
    let free_b = seed(&router, FREE_NS, "scratch-b").await;

    install_gate_once();

    // IN-SCOPE: both endpoints in `prod` → the prod-scoped hook fires → its
    // (nonexistent) command fails to spawn → fail_mode=Closed → 503.
    let (in_scope, body) = post(
        &router,
        "/api/v1/links",
        &json!({"source_id": prod_a, "target_id": prod_b, "relation": "related_to"}),
    )
    .await;
    assert_eq!(
        in_scope,
        StatusCode::SERVICE_UNAVAILABLE,
        "#2390: a PreLink hook scoped to `{GOVERNED_NS}` MUST fire on a link \
         between two `{GOVERNED_NS}` memories (pre-fix it never fired); got \
         {in_scope} {body}"
    );

    // OUT-OF-SCOPE: both endpoints in `scratch` → the prod-scoped hook is
    // correctly skipped → the write proceeds past the gate.
    let (out_of_scope, body) = post(
        &router,
        "/api/v1/links",
        &json!({"source_id": free_a, "target_id": free_b, "relation": "related_to"}),
    )
    .await;
    assert_ne!(
        out_of_scope,
        StatusCode::SERVICE_UNAVAILABLE,
        "a `{GOVERNED_NS}`-scoped hook must NOT fire on a `{FREE_NS}` link — \
         widening every scoped hook to global would be the opposite regression; \
         got {out_of_scope} {body}"
    );
}

/// #2390 — fire-if-ANY across a link's two endpoints. A link whose SOURCE is in
/// the ungoverned namespace but whose TARGET is in the governed one still
/// mutates the governed namespace's graph, so the scoped hook MUST fire.
///
/// Anchoring on the source alone (the pre-existing quota / webhook convention)
/// would let a caller choose which guard hook runs simply by swapping
/// `source_id` and `target_id` — the same bypass class #2390 closes.
#[tokio::test]
async fn pre_link_cross_namespace_fires_hook_scoped_to_either_endpoint_2390() {
    let (router, _f) = build_test_router();
    let prod = seed(&router, GOVERNED_NS, "x-prod").await;
    let free = seed(&router, FREE_NS, "x-scratch").await;

    install_gate_once();

    // source ∈ scratch, target ∈ prod — the endpoint-swap bypass vector.
    let (src_free, body) = post(
        &router,
        "/api/v1/links",
        &json!({"source_id": free, "target_id": prod, "relation": "related_to"}),
    )
    .await;
    assert_eq!(
        src_free,
        StatusCode::SERVICE_UNAVAILABLE,
        "#2390: a link INTO `{GOVERNED_NS}` must fire the `{GOVERNED_NS}`-scoped \
         hook even when the source is in `{FREE_NS}` (else swapping the endpoints \
         picks which guard hook runs); got {src_free} {body}"
    );

    // The mirror direction must fire too.
    let (src_prod, body) = post(
        &router,
        "/api/v1/links",
        &json!({"source_id": prod, "target_id": free, "relation": "related_to"}),
    )
    .await;
    assert_eq!(
        src_prod,
        StatusCode::SERVICE_UNAVAILABLE,
        "a link OUT OF `{GOVERNED_NS}` must fire the scoped hook too; \
         got {src_prod} {body}"
    );
}

/// #2390 — a caller-supplied `"namespace"` key in the request body must NOT be
/// able to decide which hook is in scope.
///
/// `HookChain::fire` used to read `payload["namespace"]`, and the HTTP link
/// handler forwarded the caller's body verbatim as the payload, so adding
/// `"namespace": "scratch"` to a `prod` link would have skipped the prod-scoped
/// guard hook. The gate now matches on the SUBSTRATE-resolved endpoint
/// namespaces and overwrites the payload key.
#[tokio::test]
async fn caller_supplied_namespace_cannot_evade_scoped_pre_link_hook_2390() {
    let (router, _f) = build_test_router();
    let prod_a = seed(&router, GOVERNED_NS, "spoof-a").await;
    let prod_b = seed(&router, GOVERNED_NS, "spoof-b").await;

    install_gate_once();

    let (status, body) = post(
        &router,
        "/api/v1/links",
        &json!({
            "source_id": prod_a,
            "target_id": prod_b,
            "relation": "related_to",
            "namespace": FREE_NS,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "#2390: a caller-asserted `namespace` must NOT scope the hook out — the \
         substrate resolves the endpoints' real namespaces; got {status} {body}"
    );
}

/// #2390 — `PreDelete` / `PrePromote` carried a `{"id": …}` payload with no
/// namespace whatsoever, so a scoped hook could never fire on the destructive
/// lane. The namespace now comes from the TARGET ROW.
#[tokio::test]
async fn pre_delete_and_pre_promote_scoped_hooks_use_the_target_row_namespace_2390() {
    let (router, _f) = build_test_router();
    let prod = seed(&router, GOVERNED_NS, "del-prod").await;
    let free = seed(&router, FREE_NS, "del-scratch").await;
    let prod_promote = seed(&router, GOVERNED_NS, "prom-prod").await;
    let free_promote = seed(&router, FREE_NS, "prom-scratch").await;

    install_gate_once();

    let del_in = delete(&router, &format!("/api/v1/memories/{prod}")).await;
    assert_eq!(
        del_in,
        StatusCode::SERVICE_UNAVAILABLE,
        "#2390: deleting a `{GOVERNED_NS}` row MUST fire the scoped PreDelete \
         hook (pre-fix the payload was `{{\"id\": …}}` with no namespace); got {del_in}"
    );
    let del_out = delete(&router, &format!("/api/v1/memories/{free}")).await;
    assert_ne!(
        del_out,
        StatusCode::SERVICE_UNAVAILABLE,
        "deleting a `{FREE_NS}` row must NOT fire the `{GOVERNED_NS}`-scoped \
         PreDelete hook; got {del_out}"
    );

    let (prom_in, _) = post(
        &router,
        &format!("/api/v1/memories/{prod_promote}/promote"),
        &json!({}),
    )
    .await;
    assert_eq!(
        prom_in,
        StatusCode::SERVICE_UNAVAILABLE,
        "#2390: promoting a `{GOVERNED_NS}` row MUST fire the scoped PrePromote \
         hook; got {prom_in}"
    );
    let (prom_out, _) = post(
        &router,
        &format!("/api/v1/memories/{free_promote}/promote"),
        &json!({}),
    )
    .await;
    assert_ne!(
        prom_out,
        StatusCode::SERVICE_UNAVAILABLE,
        "promoting a `{FREE_NS}` row must NOT fire the `{GOVERNED_NS}`-scoped \
         PrePromote hook; got {prom_out}"
    );
}
