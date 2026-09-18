// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3775 — an ANONYMOUS `POST /api/v1/subscriptions` is refused with ONE
//! closed shape on BOTH backends, because create and delete must agree on
//! who the caller is.
//!
//! Pre-#3775 an anonymous POST (no `X-Agent-Id`) stored the per-request
//! `anonymous:req-<uuid8>` principal as the subscription's OWNER, while the
//! anonymous DELETE of that id resolved a FRESH `anonymous:req-*` and — since
//! #3407 — was refused `403 NOT_OWNER`; before #3407 it answered `200
//! removed: false`, which is why `tests/integration.rs::http_smoke_matrix_
//! phases_1_3` passed while never removing anything. Either way the webhook
//! could never be listed or removed through the API (both are caller-scoped),
//! so the asymmetric side is CREATE: it admitted an owner nobody can resolve.
//!
//! The ONE predicate is `identity::is_anonymous_request_id` (behind
//! `Authority::is_anonymous`), consulted at the single resolve site at the
//! top of `subscribe`, BEFORE the sqlite/postgres branch. Every refusal cell
//! sits beside its PRESENCE control on the same router (a named caller
//! creates and removes through the same routes), and the #3407 cross-tenant
//! refusal is re-asserted so the two gates are measured together.

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

const ALICE: &str = "ai:alice-3775";
const BOB: &str = "ai:bob-3775";
const API_KEY: &str = "anonymous-subscribe-3775";

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

/// `caller: None` sends NO `X-Agent-Id` — the anonymous shape under test.
async fn call(
    router: &axum::Router,
    method: &str,
    uri: &str,
    caller: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", API_KEY);
    if let Some(c) = caller {
        req = req.header("x-agent-id", c);
    }
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

fn subscribe_body(tag: &str) -> Value {
    json!({
        "url": format!("https://example.com/hook-3775-{tag}"),
        "events": "store",
        "secret": "per-sub-secret-3775",
    })
}

/// The ONE closed shape of the anonymous-create refusal: 403, the
/// `IDENTITY_REQUIRED` code, the SSOT `error`, and NOTHING else — no
/// principal is named, because none was asserted and none was minted into
/// the body.
fn assert_identity_required(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"],
        ai_memory::errors::msg::SUBSCRIBE_REQUIRES_IDENTITY,
        "{body}"
    );
    assert_eq!(
        body["code"],
        ai_memory::errors::error_codes::IDENTITY_REQUIRED,
        "{body}"
    );
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["code", "error"], "{body}");
    assert!(
        !body.to_string().contains("anonymous:"),
        "the refusal must not echo the minted principal: {body}"
    );
}

/// All cells on one router. Returns the anonymous refusal body and the #3407
/// refusal body so a backend twin can compare them byte-for-byte.
async fn check(app: AppState) -> (Value, Value) {
    let router = router(app);

    // ABSENCE: an anonymous POST is refused, and nothing was created — the
    // anonymous caller's own list is empty AND alice's list stays empty.
    let (status, refused) = call(
        &router,
        "POST",
        "/api/v1/subscriptions",
        None,
        Some(subscribe_body("anon")),
    )
    .await;
    assert_identity_required(status, &refused);
    let (status, listed) = call(&router, "GET", "/api/v1/subscriptions", Some(ALICE), None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert!(
        !listed.to_string().contains("hook-3775-anon"),
        "a refused anonymous subscribe must create no row: {listed}"
    );

    // PRESENCE: the same route, a NAMED caller — create, list, remove.
    let (status, created) = call(
        &router,
        "POST",
        "/api/v1/subscriptions",
        Some(ALICE),
        Some(subscribe_body("alice")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let sub_id = created["id"].as_str().expect("subscription id").to_owned();
    let (status, listed) = call(&router, "GET", "/api/v1/subscriptions", Some(ALICE), None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert!(listed.to_string().contains(&sub_id), "{listed}");

    // #3407 re-asserted on the same router: bob may not remove alice's row,
    // and an ANONYMOUS delete is refused by the same owner gate (the row has
    // an owner; the anonymous principal is not it) — the delete side needs
    // no second anonymous gate.
    let (status, refused_bob) = call(
        &router,
        "DELETE",
        &format!("/api/v1/subscriptions?id={sub_id}"),
        Some(BOB),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_bob}");
    assert_eq!(
        refused_bob["code"],
        ai_memory::errors::error_codes::NOT_OWNER,
        "{refused_bob}"
    );
    assert_eq!(
        refused_bob["error"],
        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_SUBSCRIPTION,
        "{refused_bob}"
    );
    assert!(
        !refused_bob.to_string().contains(ALICE),
        "the #3407 refusal names nobody: {refused_bob}"
    );
    let (status, refused_anon) = call(
        &router,
        "DELETE",
        &format!("/api/v1/subscriptions?id={sub_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_anon}");
    assert_eq!(
        refused_anon["code"],
        ai_memory::errors::error_codes::NOT_OWNER,
        "{refused_anon}"
    );

    // PRESENCE: the creator removes it through the same route.
    let (status, removed) = call(
        &router,
        "DELETE",
        &format!("/api/v1/subscriptions?id={sub_id}"),
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["removed"], true, "{removed}");

    (refused, refused_bob)
}

#[tokio::test]
async fn sqlite_anonymous_subscribe_is_refused_one_shape_3775() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    check(sqlite_app_state(&dir.path().join("memories.db"))).await;
}

/// The postgres twin: the same cells; the anonymous refusal is BYTE-IDENTICAL
/// to sqlite's (the gate runs before the backend branch and carries no id).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_anonymous_subscribe_is_refused_one_shape_3775() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let (pg_anon, pg_bob) = check(postgres_app_state(&url).await).await;
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let (sq_anon, sq_bob) = check(sqlite_app_state(&dir.path().join("memories.db"))).await;
    assert_eq!(
        serde_json::to_string(&pg_anon).unwrap(),
        serde_json::to_string(&sq_anon).unwrap(),
        "the anonymous-subscribe refusal must be byte-identical across backends"
    );
    let mut sq_bob = sq_bob;
    sq_bob["id"] = pg_bob["id"].clone();
    assert_eq!(
        serde_json::to_string(&pg_bob).unwrap(),
        serde_json::to_string(&sq_bob).unwrap(),
        "the #3407 refusal must stay byte-identical across backends"
    );
}

/// The ONE predicate: the string form and the `Authority` form cannot
/// disagree about what "anonymous" means.
#[test]
fn one_anonymous_predicate_3775() {
    let minted = ai_memory::identity::anonymous_request_id();
    assert!(ai_memory::identity::is_anonymous_request_id(&minted));
    assert!(!ai_memory::identity::is_anonymous_request_id(ALICE));
    assert!(!ai_memory::identity::is_anonymous_request_id(
        ai_memory::identity::sentinels::ANONYMOUS_INVALID
    ));
    let allowlist: Vec<String> = Vec::new();
    let inputs = ai_memory::identity::authority::HttpAuthorityInputs {
        header_agent_id: None,
        key_bound_principal: None,
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        enrolled_keys_present: false,
        admin_allowlist: &allowlist,
        header_trusted: true,
    };
    let auth = ai_memory::identity::authority::Authority::resolve_http(inputs)
        .expect("anonymous resolves");
    assert!(auth.is_anonymous());
    assert!(ai_memory::identity::is_anonymous_request_id(
        auth.principal()
    ));
}
