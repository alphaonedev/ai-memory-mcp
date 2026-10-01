// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the FIRST bind of a namespace standard at a `/`-descendant of a
//! GOVERNED ancestor requires the ancestor standard's owner.
//!
//! Pre-#4356 a stranger could bind a memory they own as the standard of
//! `<governed>/<child>` with a permissive policy and thereby opt that subtree
//! out of the ancestor's write / promote / delete / approval gates (CWE-284):
//! the bind gates judged the bound memory, the declared parent and the
//! standard CURRENTLY bound to the target — never the ancestor chain of a
//! target with no binding of its own. 5-agent vote (4d3ea1c5), option A.
//!
//! Cells on BOTH backends and through every surface that reaches the shared
//! verdict: HTTP (query + path + nested S34 form), the MCP wire handler
//! (sqlite) and the SAL trait method (the in-transaction fail-closed floor).
//! Controls: the ancestor owner binds; an UNGOVERNED root is unaffected
//! (allow-on-silence, `tests/ship_gate_governance_inheritance.rs`); the
//! daemon / admin bypass is unaffected.

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

const ALICE: &str = "ai:alice-4356";
const BOB: &str = "ai:bob-4356";
const API_KEY: &str = "ancestor-gate-4356";

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

/// The closed refusal shape (`handlers::parity::owner_gate_refusal`): 403
/// `NOT_OWNER`, the SSOT text, the caller, the namespace — never the owner.
fn assert_refusal(status: StatusCode, body: &Value, caller: &str, ns: &str) {
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
    assert!(
        !body.to_string().contains(ALICE),
        "the refusal must never name the ancestor owner: {body}"
    );
}

async fn create_memory(router: &axum::Router, caller: &str, ns: &str, title: &str) -> String {
    let (status, mem) = call(
        router,
        "POST",
        "/api/v1/memories",
        caller,
        Some(json!({
            "namespace": ns, "title": title,
            "content": format!("{caller}'s standard"),
            "tier": "long", "tags": [], "priority": 5, "confidence": 1.0,
            "source": "api", "metadata": {},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{mem}");
    mem["id"].as_str().expect("memory id").to_owned()
}

async fn bound(router: &axum::Router, ns: &str) -> String {
    let (status, got) = call(
        router,
        "GET",
        &format!("/api/v1/namespaces?namespace={ns}"),
        ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    got.to_string()
}

async fn bind(
    router: &axum::Router,
    caller: &str,
    ns: &str,
    id: &str,
    governance: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = json!({"namespace": ns, "id": id});
    if let Some(g) = governance {
        b["governance"] = g;
    }
    call(router, "POST", "/api/v1/namespaces", caller, Some(b)).await
}

/// Every cell on one backend. Returns the HTTP refusal body (cross-backend
/// byte comparison in the postgres twin).
async fn check(app: AppState) -> Value {
    #[cfg(feature = "sal")]
    let store = Arc::clone(&app.store);
    let db = Arc::clone(&app.db);
    let router = router(app);
    let uniq = uuid::Uuid::new_v4().simple().to_string();
    let gov = format!("gov4356{uniq}");
    let leaf = format!("{gov}/leaf");

    let a_std = create_memory(&router, ALICE, &gov, "alice-ancestor-standard").await;
    let b_std = create_memory(&router, BOB, &leaf, "bob-child-standard").await;
    let a_leaf_std = create_memory(&router, ALICE, &leaf, "alice-child-standard").await;

    // The ancestor: bound by alice with an Owner write floor.
    let (status, got) = bind(
        &router,
        ALICE,
        &gov,
        &a_std,
        Some(json!({"write": "owner"})),
    )
    .await;
    assert!(
        status.is_success(),
        "alice binds the ancestor: {status} {got}"
    );

    // ABSENCE: bob may not open the first child standard — query form.
    let (status, refused) = bind(&router, BOB, &leaf, &b_std, Some(json!({"write": "any"}))).await;
    assert_refusal(status, &refused, BOB, &leaf);
    // path form + nested S34 (id-less placeholder) form: same refusal, BEFORE any write.
    let (status, refused_path) = call(
        &router,
        "POST",
        &format!("/api/v1/namespaces/{}/standard", leaf.replace('/', "%2F")),
        BOB,
        Some(json!({"id": b_std, "governance": {"write": "any"}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_path}");
    assert_eq!(refused_path, refused);
    let (status, refused_nested) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        BOB,
        Some(json!({"standard": {"namespace": leaf, "governance": {"write": "any"}}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_nested}");
    // a deeper descendant with no intermediate standard is gated by the same ancestor
    let deep = format!("{gov}/mid/deep");
    let (status, refused_deep) =
        bind(&router, BOB, &deep, &b_std, Some(json!({"write": "any"}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_deep}");
    // and the opt-out never happened: no binding landed, the ancestor floor still holds.
    assert!(
        !bound(&router, &leaf).await.contains(&b_std),
        "a refused bind must leave the child unbound"
    );
    // MCP wire handler (sqlite connection): refused for bob, allowed for alice.
    {
        let mcp_ns = format!("{gov}/mcpleaf");
        let guard = db.lock().await;
        // postgres' sqlite scratch db has no ancestor, so only assert on the
        // sqlite backend where the ancestor lives in this connection.
        if guard.1 != std::path::Path::new(":memory:") {
            let refused = ai_memory::mcp::handle_namespace_set_standard(
                &guard.0,
                &json!({"namespace": mcp_ns, "id": b_std, "agent_id": BOB}),
            );
            assert_eq!(
                refused.expect_err("bob must be refused on the MCP surface"),
                ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD
            );
            ai_memory::mcp::handle_namespace_set_standard(
                &guard.0,
                &json!({"namespace": mcp_ns, "id": a_leaf_std, "agent_id": ALICE}),
            )
            .expect("the ancestor owner binds on the MCP surface");
            // The operator CLI surface (`ai-memory namespace set-standard`,
            // the trusted daemon principal) is the admin path: unaffected.
            ai_memory::mcp::handle_namespace_set_standard_trusted(
                &guard.0,
                &json!({"namespace": format!("{gov}/cliadm"), "id": b_std}),
                ai_memory::identity::sentinels::DAEMON_PRINCIPAL,
            )
            .expect("the operator / daemon bind is unaffected");
        }
    }

    // SAL trait (the in-transaction floor), same backend.
    #[cfg(feature = "sal")]
    {
        use ai_memory::store::{CallerContext, StoreError};
        let sal_leaf = format!("{gov}/salleaf");
        let err = store
            .set_namespace_standard(&CallerContext::for_agent(BOB), &sal_leaf, &b_std, None)
            .await
            .expect_err("bob's trait-routed first bind must be refused");
        assert!(
            matches!(err, StoreError::PermissionDenied { .. }),
            "{err:?}"
        );
        store
            .set_namespace_standard(
                &CallerContext::for_agent(ALICE),
                &sal_leaf,
                &a_leaf_std,
                None,
            )
            .await
            .expect("the ancestor owner binds through the trait");
        let adm = format!("{gov}/admleaf");
        store
            .set_namespace_standard(
                &CallerContext::for_admin("ai:admin-4356"),
                &adm,
                &b_std,
                None,
            )
            .await
            .expect("an admin/bypass context is unaffected");
    }

    // EXPLICIT PARENT: a flat root that DECLARES the governed `gov` as its
    // (entitled) parent puts its `/`-subtree under `gov`'s owner even though
    // the root's own standard carries no policy (it does not shadow `gov`).
    let ex = format!("expl4356{uniq}");
    let a_ex_std = create_memory(&router, ALICE, &ex, "alice-explicit-root").await;
    let (status, got) = call(
        &router,
        "POST",
        "/api/v1/namespaces",
        ALICE,
        Some(json!({"namespace": ex, "id": a_ex_std, "parent": gov})),
    )
    .await;
    assert!(
        status.is_success(),
        "alice declares gov as ex's parent: {status} {got}"
    );
    let ex_leaf = format!("{ex}/leaf");
    let (status, refused_ex) = bind(
        &router,
        BOB,
        &ex_leaf,
        &b_std,
        Some(json!({"write": "any"})),
    )
    .await;
    assert_refusal(status, &refused_ex, BOB, &ex_leaf);
    let (status, ok) = bind(&router, ALICE, &ex_leaf, &a_leaf_std, None).await;
    assert!(
        status.is_success(),
        "explicit parent: owner binds {status} {ok}"
    );

    // SEVERED ancestor (its standard memory deleted, #2503 sever): nobody but
    // an operator may open a child; same closed shape on both backends.
    let sev = format!("sev4356{uniq}");
    let a_sev_std = create_memory(&router, ALICE, &sev, "alice-severed-standard").await;
    let (status, got) = bind(
        &router,
        ALICE,
        &sev,
        &a_sev_std,
        Some(json!({"write": "owner"})),
    )
    .await;
    assert!(status.is_success(), "{status} {got}");
    let (status, got) = call(
        &router,
        "DELETE",
        &format!("/api/v1/memories/{a_sev_std}"),
        ALICE,
        None,
    )
    .await;
    assert!(
        status.is_success(),
        "delete severs the ancestor: {status} {got}"
    );
    let sev_leaf = format!("{sev}/leaf");
    let (status, refused_sev) = bind(
        &router,
        BOB,
        &sev_leaf,
        &b_std,
        Some(json!({"write": "any"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused_sev}");
    assert_eq!(
        refused_sev["error"],
        ai_memory::ns_standard_ancestor::REASON_ANCESTOR_STANDARD_UNRESOLVABLE,
        "{refused_sev}"
    );
    assert_eq!(
        refused_sev["code"],
        ai_memory::errors::error_codes::NOT_OWNER
    );
    assert!(!refused_sev.to_string().contains(ALICE), "{refused_sev}");

    // PRESENCE: alice (the ancestor's owner) binds the child through HTTP.
    let (status, ok) = bind(
        &router,
        ALICE,
        &leaf,
        &a_leaf_std,
        Some(json!({"write": "any"})),
    )
    .await;
    assert!(
        status.is_success(),
        "the ancestor owner binds the child: {status} {ok}"
    );
    assert!(bound(&router, &leaf).await.contains(&a_leaf_std));

    // CONTROL: an UNGOVERNED root is unaffected for any caller.
    let free = format!("free4356{uniq}/leaf");
    let (status, free_r) = bind(&router, BOB, &free, &b_std, Some(json!({"write": "any"}))).await;
    assert!(
        status.is_success(),
        "an ungoverned subtree stays opt-in for anyone: {status} {free_r}"
    );
    json!({"not_owner": refused, "severed": refused_sev})
}

#[tokio::test]
async fn sqlite_first_child_bind_requires_the_governing_ancestors_owner_4356() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    check(sqlite_app_state(&dir.path().join("memories.db"))).await;
}

/// The postgres twin. A set-but-unreachable URL FAILS (the `expect`s in
/// `postgres_app_state`), never skips; only an UNSET URL skips.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_first_child_bind_requires_the_governing_ancestors_owner_4356() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let pg = check(postgres_app_state(&url).await).await;
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let mut sq = check(sqlite_app_state(&dir.path().join("memories.db"))).await;
    for k in ["not_owner", "severed"] {
        sq[k]["namespace"] = pg[k]["namespace"].clone();
    }
    assert_eq!(
        serde_json::to_string(&pg).unwrap(),
        serde_json::to_string(&sq).unwrap(),
        "the ancestor-gate refusal must be byte-identical across backends"
    );
}
