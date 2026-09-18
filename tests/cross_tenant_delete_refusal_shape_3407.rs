// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3407 — `DELETE /api/v1/subscriptions` and `DELETE /api/v1/namespaces`
//! refuse a CROSS-TENANT act with ONE closed shape on BOTH backends, and the
//! refusal names nobody.
//!
//! Pre-#3407 the two routes disagreed by backend AND leaked: the sqlite
//! unsubscribe answered `200 {"removed": false}` for another agent's row
//! (indistinguishable from a refusal by status, wrong class for an act that
//! was refused) while postgres answered 403 through the memory owner gate;
//! the namespace-standard clear answered 400 (sqlite) / 403 (postgres) with
//! a body that NAMED THE OWNING AGENT — the identity oracle #3426 closed for
//! memories and left open on the namespace-standard gates (SET and CLEAR).
//!
//! Every refusal cell here sits beside its PRESENCE control on the same
//! router: the owner's own act succeeds through the same route, so a 403
//! cannot pass because the whole route stopped working.

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

const ALICE: &str = "ai:alice-3407";
const BOB: &str = "ai:bob-3407";
const API_KEY: &str = "cross-tenant-3407";

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

/// The ONE closed shape every cross-owner refusal on the HTTP surface takes
/// (`handlers::parity::owner_gate_refusal`): 403, `code: NOT_OWNER`, the
/// per-gate SSOT `error`, the caller, the resource key — and NOTHING that
/// names the owner.
fn assert_closed_refusal(
    status: StatusCode,
    body: &Value,
    error: &str,
    caller: &str,
    resource_key: &str,
    resource: &str,
    owner: &str,
) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], error, "{body}");
    assert_eq!(
        body["code"],
        ai_memory::errors::error_codes::NOT_OWNER,
        "{body}"
    );
    assert_eq!(body["caller"], caller, "{body}");
    assert_eq!(body[resource_key], resource, "{body}");
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        {
            let mut k = vec!["caller", "code", "error", resource_key];
            k.sort_unstable();
            k
        },
        "the closed shape carries exactly these keys: {body}"
    );
    assert!(
        !body.to_string().contains(owner),
        "the refusal must never name the owner {owner}: {body}"
    );
}

/// Both routes, both directions, on one router. Returns the two refusal
/// bodies so a backend twin can be compared byte-for-byte.
async fn check(app: AppState) -> (Value, Value) {
    let router = router(app);

    // ---- subscriptions -----------------------------------------------------
    let (status, created) = call(
        &router,
        "POST",
        "/api/v1/subscriptions",
        ALICE,
        Some(json!({
            "url": "https://example.com/hook-3407",
            "events": "store",
            "secret": "per-sub-secret-3407",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let sub_id = created["id"].as_str().expect("subscription id").to_owned();

    // ABSENCE: bob may not remove alice's subscription — the closed shape,
    // naming nobody, and the row survives.
    let (status, refused_sub) = call(
        &router,
        "DELETE",
        &format!("/api/v1/subscriptions?id={sub_id}"),
        BOB,
        None,
    )
    .await;
    assert_closed_refusal(
        status,
        &refused_sub,
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_SUBSCRIPTION,
        BOB,
        "id",
        &sub_id,
        ALICE,
    );
    let (status, listed) = call(&router, "GET", "/api/v1/subscriptions", ALICE, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert!(
        listed.to_string().contains(&sub_id),
        "a refused cross-tenant delete must leave the row: {listed}"
    );
    // A genuinely ABSENT id keeps the idempotent contract (not a refusal).
    let (status, missing) = call(
        &router,
        "DELETE",
        "/api/v1/subscriptions?id=00000000-0000-4000-8000-00000000d3ad",
        BOB,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{missing}");
    assert_eq!(missing["removed"], false, "{missing}");
    // PRESENCE: the owner removes it through the same route.
    let (status, removed) = call(
        &router,
        "DELETE",
        &format!("/api/v1/subscriptions?id={sub_id}"),
        ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["removed"], true, "{removed}");

    // ---- namespace standard --------------------------------------------------
    let ns = format!("team-3407-{}", uuid::Uuid::new_v4().simple());
    let (status, mem) = call(
        &router,
        "POST",
        "/api/v1/memories",
        ALICE,
        Some(json!({
            "namespace": ns,
            "title": "standard-3407",
            "content": "alice's governance standard",
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
    let std_id = mem["id"].as_str().expect("standard memory id").to_owned();
    let (status, bound) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        ALICE,
        Some(json!({"namespace": ns, "id": std_id})),
    )
    .await;
    assert!(
        status.is_success(),
        "bind alice's standard: {status} {bound}"
    );

    // ABSENCE (both entry forms): bob may not clear alice's standard.
    let (status, refused_ns) = call(
        &router,
        "DELETE",
        &format!("/api/v1/namespaces?namespace={ns}"),
        BOB,
        None,
    )
    .await;
    assert_closed_refusal(
        status,
        &refused_ns,
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
        BOB,
        "namespace",
        &ns,
        ALICE,
    );
    let (status, refused_path) = call(
        &router,
        "DELETE",
        &format!("/api/v1/namespaces/{ns}/standard"),
        BOB,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_path}");
    assert_eq!(
        refused_path, refused_ns,
        "the path form and the query form render the same refusal body"
    );
    // The SET gate on the same family names nobody either: bob may not bind
    // ALICE's memory as a standard (the #929 bound-memory owner gate). (That
    // bob may REBIND alice's namespace to a memory of his own is a separate
    // hole in the SET gate — it authorizes the memory being bound, never the
    // standard currently bound — filed as #3758; not this change's scope.)
    let ns2 = format!("{ns}-set");
    let (status, refused_set) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        BOB,
        Some(json!({"namespace": ns2, "id": std_id})),
    )
    .await;
    assert_closed_refusal(
        status,
        &refused_set,
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
        BOB,
        "namespace",
        &ns2,
        ALICE,
    );
    // The binding is untouched by every refusal above.
    let (status, still) = call(
        &router,
        "GET",
        &format!("/api/v1/namespaces?namespace={ns}"),
        ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{still}");
    assert!(
        still.to_string().contains(&std_id),
        "refused clears/sets must leave alice's standard bound: {still}"
    );
    // PRESENCE: the owner clears it through the same route.
    let (status, cleared) = call(
        &router,
        "DELETE",
        &format!("/api/v1/namespaces?namespace={ns}"),
        ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cleared}");

    // Cross-route: ONE shape — same code, same key set modulo the resource key.
    assert_eq!(refused_sub["code"], refused_ns["code"]);
    (refused_sub, refused_ns)
}

#[tokio::test]
async fn sqlite_cross_tenant_delete_refusals_share_one_shape_3407() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    check(sqlite_app_state(&dir.path().join("memories.db"))).await;
}

/// The postgres twin: the same cells, and the two refusal bodies are
/// BYTE-IDENTICAL to the sqlite ones for the same caller and resource ids
/// (the refusal carries no `storage_backend`; there is nothing to normalise).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_cross_tenant_delete_refusals_share_one_shape_3407() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let (pg_sub, pg_ns) = check(postgres_app_state(&url).await).await;
    // Same shape as sqlite: rebuild the sqlite refusals with the pg ids
    // substituted and compare whole bodies.
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let (sq_sub, sq_ns) = check(sqlite_app_state(&dir.path().join("memories.db"))).await;
    let mut sq_sub = sq_sub;
    sq_sub["id"] = pg_sub["id"].clone();
    let mut sq_ns = sq_ns;
    sq_ns["namespace"] = pg_ns["namespace"].clone();
    assert_eq!(
        serde_json::to_string(&pg_sub).unwrap(),
        serde_json::to_string(&sq_sub).unwrap(),
        "subscription refusal must be byte-identical across backends"
    );
    assert_eq!(
        serde_json::to_string(&pg_ns).unwrap(),
        serde_json::to_string(&sq_ns).unwrap(),
        "namespace-standard refusal must be byte-identical across backends"
    );
}
