// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3758 — `POST /api/v1/namespaces` (and `/namespaces/{ns}/standard`) may
//! not REPLACE the governance standard another agent currently has bound.
//!
//! Pre-#3758 the SET funnels authorized the memory BEING bound and the
//! declared parent — never the standard CURRENTLY bound — so bob could
//! overwrite alice's policy with a memory of his own (`201 {"set": true}`)
//! while being refused to CLEAR it. The gate is the same predicate CLEAR
//! uses (`visibility::namespace_standard_mutation_admission`), the refusal
//! the same closed shape #3407 established (403 `NOT_OWNER`, `namespace`
//! echoed, the owner never named), on both backends, at the HTTP funnel
//! (before any write) and in the SAL adapter (inside the upsert transaction).
//!
//! Allowed-path controls on the same router: the owner replaces her own
//! standard; an UNBOUND namespace binds for anyone; a SEVERED binding is the
//! repair path and re-points.

#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

mod common;

const ALICE: &str = "ai:alice-3758";
const BOB: &str = "ai:bob-3758";
const API_KEY: &str = "rebind-gate-3758";

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`, but under `sal` its inner \
                  `Arc<dyn MemoryStore>` is MOVED into the struct literal below; \
                  one signature keeps both feature legs building identically."
    )
)]
fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
    let _ = &store;
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store: store.0,
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
        admin_agent_ids: Arc::new(Vec::new()),
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
    }
}

#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    app_state_with(db, StorageBackend::Sqlite, store)
}

#[cfg(feature = "sal-postgres")]
async fn postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    ));
    app_state_with(db, StorageBackend::Postgres, store)
}

fn router(app: AppState) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: Some(API_KEY.into()),
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
            ..Default::default()
        },
        app,
    )
}

async fn call(
    router: &axum::Router,
    method: &str,
    uri: &str,
    caller: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", API_KEY)
        .header("x-agent-id", caller);
    let req = if let Some(b) = body {
        req.header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        req.header("content-length", "0")
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// The ONE closed shape (`handlers::parity::owner_gate_refusal`): 403,
/// `code: NOT_OWNER`, the SSOT `error`, the caller, `namespace` — and nothing
/// that names the owner.
fn assert_rebind_refusal(status: StatusCode, body: &Value, caller: &str, ns: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"],
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
        "{body}"
    );
    assert_eq!(
        body["code"],
        ai_memory::errors::error_codes::NOT_OWNER,
        "{body}"
    );
    assert_eq!(body["caller"], caller, "{body}");
    assert_eq!(body["namespace"], ns, "{body}");
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["caller", "code", "error", "namespace"], "{body}");
    assert!(
        !body.to_string().contains(ALICE),
        "the refusal must never name the owner: {body}"
    );
}

async fn create_memory(router: &axum::Router, caller: &str, ns: &str, title: &str) -> String {
    let (status, mem) = call(
        router,
        "POST",
        "/api/v1/memories",
        caller,
        Some(json!({
            "namespace": ns,
            "title": title,
            "content": format!("{caller}'s standard"),
            "tier": "long",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "metadata": {},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{mem}");
    mem["id"].as_str().expect("memory id").to_owned()
}

async fn bound_standard(router: &axum::Router, ns: &str) -> Value {
    let (status, got) = call(
        router,
        "GET",
        &format!("/api/v1/namespaces?namespace={ns}"),
        ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    got
}

/// Both directions on one router. Returns the refusal body so the postgres
/// twin can be compared byte-for-byte with the sqlite one.
async fn check(app: AppState) -> Value {
    let router = router(app);
    let ns = format!("team-3758-{}", uuid::Uuid::new_v4().simple());
    let alice_std = create_memory(&router, ALICE, &ns, "alice-standard").await;
    let alice_std_2 = create_memory(&router, ALICE, &ns, "alice-standard-2").await;
    let bob_std = create_memory(&router, BOB, &ns, "bob-standard").await;

    // Control: an UNBOUND namespace binds.
    let (status, bound) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        ALICE,
        Some(json!({"namespace": ns, "id": alice_std})),
    )
    .await;
    assert!(
        status.is_success(),
        "alice binds an unbound namespace: {status} {bound}"
    );
    assert!(
        bound_standard(&router, &ns)
            .await
            .to_string()
            .contains(&alice_std)
    );

    // ABSENCE: bob may not REPLACE alice's binding — query form and path form,
    // same body; the binding is untouched.
    let (status, refused) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        BOB,
        Some(json!({"namespace": ns, "id": bob_std})),
    )
    .await;
    assert_rebind_refusal(status, &refused, BOB, &ns);
    let (status, refused_path) = call(
        &router,
        "POST",
        &format!("/api/v1/namespaces/{ns}/standard"),
        BOB,
        Some(json!({"id": bob_std})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_path}");
    assert_eq!(
        refused_path, refused,
        "path and query forms render the same refusal"
    );
    // The S34 nested shape and the id-less placeholder shape are refused
    // BEFORE any write: no placeholder lands in alice's namespace.
    let (status, refused_nested) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        BOB,
        Some(json!({"standard": {"namespace": ns, "governance": {"write": "owner"}}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_nested}");
    assert_eq!(refused_nested, refused);
    let still = bound_standard(&router, &ns).await;
    assert!(
        still.to_string().contains(&alice_std),
        "a refused rebind leaves alice's binding: {still}"
    );
    assert!(
        !still.to_string().contains(&bob_std),
        "bob's memory never became the standard: {still}"
    );

    // PRESENCE: the owner replaces her own standard through the same route.
    let (status, rebound) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        ALICE,
        Some(json!({"namespace": ns, "id": alice_std_2})),
    )
    .await;
    assert!(
        status.is_success(),
        "alice rebinds her own namespace: {status} {rebound}"
    );
    assert!(
        bound_standard(&router, &ns)
            .await
            .to_string()
            .contains(&alice_std_2)
    );

    // Control: an UNBOUND namespace still binds for bob (the gate is about
    // the CURRENT occupant, not about bob).
    let ns_free = format!("{ns}-free");
    let (status, free) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        BOB,
        Some(json!({"namespace": ns_free, "id": bob_std})),
    )
    .await;
    assert!(
        status.is_success(),
        "bob binds an unbound namespace: {status} {free}"
    );

    refused
}

#[tokio::test]
async fn sqlite_rebind_is_gated_on_the_currently_bound_standards_owner_3758() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    check(sqlite_app_state(&dir.path().join("memories.db"))).await;
}

/// The postgres twin; the refusal body is byte-identical to sqlite's for the
/// same caller once the fixture namespace is substituted.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_rebind_is_gated_on_the_currently_bound_standards_owner_3758() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let pg = check(postgres_app_state(&url).await).await;
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let mut sq = check(sqlite_app_state(&dir.path().join("memories.db"))).await;
    sq["namespace"] = pg["namespace"].clone();
    assert_eq!(
        serde_json::to_string(&pg).unwrap(),
        serde_json::to_string(&sq).unwrap(),
        "the rebind refusal must be byte-identical across backends"
    );
}
