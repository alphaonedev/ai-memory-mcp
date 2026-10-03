// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4477 — the governance chain is COMPLETE on both backends: a governed
//! ancestor governs every descendant down to `MAX_NAMESPACE_DEPTH`, and a
//! chain that would exceed the bound is REFUSED (fail closed), never truncated.
//!
//! Before the fix postgres kept only the 5 most-specific `/` levels
//! (`GOVERNANCE_INHERITANCE_DEPTH_CAP`), so an ancestor more than 5 levels up
//! governed nothing there, and both backends silently dropped explicit
//! parents beyond their hop budget (pg 5, sqlite 8).
//!
//! Cells, each on sqlite and PG 18.6 over the public HTTP surface, with the
//! cross-backend outcome compared:
//! - a stranger's FIRST bind on a child 6, 7 and 8 levels below a governed
//!   root is refused with the not-owner kind, over HTTP and the SAL trait
//!   (both postgres chain builders: the pool pre-probe and the in-transaction
//!   floor), so it cannot stop the depth walk;
//! - a stranger's depth-1 reflect at depth 6, 7 and 8 under a depth-gated root
//!   is PENDING;
//! - the root's write gate (`owner`) refuses a stranger at depth 7 while the
//!   root's owner is admitted, and its promote / delete gates (`approve`) park
//!   the stranger's promote / delete of its OWN row at depth 7 (ownership
//!   alone would admit it, so only the root's governance can park it);
//! - an explicit-parent chain of 9 entitled hops (one past the bound) above a
//!   governed root refuses a write the same way on both backends (since #4492
//!   such a chain can no longer be BOUND, so its 9th hop is planted as
//!   pre-existing data).

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use ai_memory::store::{CallerContext, MemoryStore};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt as _;

mod common;

const KEY: &str = "issue-4477-key";

/// The two cells share process-global test state (the enforce-mode override,
/// the request-authn flag, the global runtime context); run them one at a
/// time so neither observes the other mid-flight.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const OWNER: &str = "ai:owner-4477";
const STRANGER: &str = "ai:stranger-4477";
const ADMIN: &str = "ai:admin-4477";

fn router(
    backend: StorageBackend,
    store: Arc<dyn MemoryStore>,
    db_path: &std::path::Path,
) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let enrolled = Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty());
    let app = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::full()),
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: HttpIdentityMode::Advisory,
    };
    ai_memory::build_router(
        ApiKeyState {
            key: Some(KEY.to_string()),
            mtls_enforced: false,
            enrolled_agent_keys: enrolled,
            identity_mode: HttpIdentityMode::Advisory,
            ..Default::default()
        },
        app,
    )
}

async fn call(
    router: &axum::Router,
    method: &str,
    uri: &str,
    agent: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", KEY)
        .header("x-agent-id", agent)
        .header("content-type", "application/json");
    let req = req
        .body(match body {
            Some(b) => Body::from(serde_json::to_vec(b).expect("body")),
            None => Body::empty(),
        })
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("bytes");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn memory(owner: &str, namespace: &str, governance: Option<Value>, tier: Tier) -> Memory {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = json!({"agent_id": owner, "scope": "shared"});
    if let Some(g) = governance {
        metadata["governance"] = g;
    }
    Memory {
        title: format!("m4477 {id}"),
        id,
        tier,
        created_at: now.clone(),
        updated_at: now,
        namespace: namespace.into(),
        content: "issue 4477".into(),
        metadata,
        ..Memory::default()
    }
}

/// Bind `governance` as the standard of `ns` (owned by `owner`), by an
/// operator context so the fixture never depends on the gates under test.
async fn govern(
    store: &Arc<dyn MemoryStore>,
    ns: &str,
    owner: &str,
    governance: Option<Value>,
    parent: Option<&str>,
    std_ns: &str,
) {
    let admin = CallerContext::for_admin(ADMIN);
    let s = memory(owner, std_ns, governance, Tier::Long);
    store.store(&admin, &s).await.expect("standard");
    store
        .set_namespace_standard(&admin, ns, &s.id, parent)
        .await
        .expect("bind standard");
}

fn deep(root: &str, depth: usize) -> String {
    let mut ns = root.to_string();
    for i in 1..depth {
        ns = format!("{ns}/l{i}");
    }
    ns
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// (depth, HTTP status, HTTP not-owner, SAL not-owner) of the stranger's
    /// first bind on the deep child.
    binds: Vec<(usize, u16, bool, bool)>,
    /// (depth, reflect applied, reflect pending)
    reflects: Vec<(usize, bool, bool)>,
    stranger_write: u16,
    owner_write_ok: bool,
    stranger_promote: (u16, bool),
    stranger_delete: (u16, bool),
    stranger_row_survives: bool,
    over_depth_write: u16,
    over_depth_owner_write: u16,
}

/// Write a `namespace_meta` link row directly (pre-existing data the bind
/// path would refuse today, #4492). `pg_url` selects postgres.
#[cfg_attr(
    not(feature = "sal-postgres"),
    expect(
        clippy::unused_async,
        reason = "only the postgres arm awaits; one signature for both feature legs"
    )
)]
async fn plant_link(
    pg_url: Option<&str>,
    db_path: &std::path::Path,
    ns: &str,
    standard_id: &str,
    parent: &str,
) {
    #[cfg(feature = "sal-postgres")]
    if let Some(url) = pg_url {
        let pool = sqlx::PgPool::connect(url).await.expect("raw pool");
        sqlx::query(
            "INSERT INTO namespace_meta (namespace, standard_id, parent_namespace) \
             VALUES ($1, $2, $3)",
        )
        .bind(ns)
        .bind(standard_id)
        .bind(parent)
        .execute(&pool)
        .await
        .expect("plant pg link");
        return;
    }
    let _ = pg_url;
    let conn = ai_memory::db::open(db_path).expect("raw sqlite");
    conn.execute(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
         VALUES (?1, ?2, '2026-10-02T00:00:00Z', ?3)",
        rusqlite::params![ns, standard_id, parent],
    )
    .expect("plant sqlite link");
}

async fn run(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    db_path: &std::path::Path,
    pg_url: Option<&str>,
) -> Outcome {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let u = uuid::Uuid::new_v4().simple().to_string();
    let std_ns = format!("std4477{u}");
    let admin = CallerContext::for_admin(ADMIN);

    // A. depth-gated root: reflect at depth 6, 7, 8 is PENDING.
    let rroot = format!("r4477{u}");
    govern(
        &store,
        &rroot,
        OWNER,
        Some(json!({"write": "any", "require_approval_above_depth": 0})),
        None,
        &std_ns,
    )
    .await;
    let mut sources = Vec::new();
    for d in [6usize, 7, 8] {
        let ns = deep(&rroot, d);
        let src = memory(STRANGER, &ns, None, Tier::Long);
        store.store(&admin, &src).await.expect("source");
        sources.push((d, ns, src.id));
    }

    // B. write (`owner`) and promote / delete (`approve`) governed at depth 7.
    let wroot = format!("w4477{u}");
    govern(
        &store,
        &wroot,
        OWNER,
        Some(json!({"write": "owner", "promote": "approve", "delete": "approve"})),
        None,
        &std_ns,
    )
    .await;
    let w7 = deep(&wroot, 7);
    // The stranger's OWN row at depth 7 (seeded by the operator), so ownership
    // alone cannot refuse its promote / delete: only governance can.
    let own = memory(STRANGER, &w7, None, Tier::Mid);
    store.store(&admin, &own).await.expect("stranger row");

    // C. an explicit-parent chain one hop past the bound above a governed root.
    let top = format!("e9x{u}");
    govern(
        &store,
        &top,
        OWNER,
        Some(json!({"write": "owner"})),
        None,
        &std_ns,
    )
    .await;
    let mut above = top.clone();
    for i in (1..9).rev() {
        let ns = format!("e{i}x{u}");
        govern(&store, &ns, OWNER, None, Some(&above), &std_ns).await;
        above = ns;
    }
    // The 9th hop cannot be bound any more (#4492 refuses it at bind time), so
    // it is planted as PRE-EXISTING data (a chain from before #4477), which is
    // exactly what the resolver must still refuse rather than truncate.
    let e0_std = memory(OWNER, &std_ns, None, Tier::Long);
    store.store(&admin, &e0_std).await.expect("e0 standard");
    plant_link(pg_url, db_path, &format!("e0x{u}"), &e0_std.id, &above).await;
    let bottom = format!("e0x{u}/leaf");

    let router = router(backend, Arc::clone(&store), db_path);
    // A2. The stranger's FIRST bind on the deep child (6, 7, 8 levels below
    // the governed root) is REFUSED with the not-owner kind, over HTTP (the
    // pre-write probe: pool chain builder on pg) and over the SAL trait (the
    // in-transaction floor: tx chain builder on pg). Both pg builders were
    // capped at 5; a bind that landed would stop the depth walk and escape.
    let not_owner = ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD;
    let s_std = memory(STRANGER, &std_ns, Some(json!({"write": "any"})), Tier::Long);
    store
        .store(&admin, &s_std)
        .await
        .expect("stranger standard");
    let mut binds = Vec::new();
    for (d, ns, _) in &sources {
        let (bs, bb) = call(
            &router,
            "POST",
            &format!("/api/v1/namespaces/{}/standard", ns.replace('/', "%2F")),
            STRANGER,
            Some(&json!({"id": s_std.id, "governance": {"write": "any"}})),
        )
        .await;
        let sal = store
            .set_namespace_standard(&CallerContext::for_agent(STRANGER), ns, &s_std.id, None)
            .await;
        let sal_not_owner = matches!(
            &sal,
            Err(ai_memory::store::StoreError::PermissionDenied { reason, .. }) if reason == not_owner
        );
        binds.push((*d, bs.as_u16(), bb["error"] == not_owner, sal_not_owner));
    }
    let mut reflects = Vec::new();
    for (d, ns, src) in &sources {
        let (_, b) = call(
            &router,
            "POST",
            "/api/v1/memory_reflect",
            STRANGER,
            Some(&json!({
                "source_ids": [src], "title": format!("r4477 {}", uuid::Uuid::new_v4()),
                "content": "depth-1 reflection", "namespace": ns, "agent_id": STRANGER,
            })),
        )
        .await;
        reflects.push((*d, b.get("id").is_some(), b["status"] == "pending"));
    }
    let write_body = |ns: &str| {
        json!({
            "namespace": ns, "title": format!("w4477 {}", uuid::Uuid::new_v4()),
            "content": "governed write", "tier": "long", "tags": [], "priority": 5,
            "confidence": 1.0, "source": "api", "metadata": {},
        })
    };
    let (sw, _) = call(
        &router,
        "POST",
        "/api/v1/memories",
        STRANGER,
        Some(&write_body(&w7)),
    )
    .await;
    let (ow, ob) = call(
        &router,
        "POST",
        "/api/v1/memories",
        OWNER,
        Some(&write_body(&w7)),
    )
    .await;
    let (sp, spb) = call(
        &router,
        "POST",
        &format!("/api/v1/memories/{}/promote", own.id),
        STRANGER,
        Some(&json!({})),
    )
    .await;
    let (sd, sdb) = call(
        &router,
        "DELETE",
        &format!("/api/v1/memories/{}", own.id),
        STRANGER,
        None,
    )
    .await;
    let survives = store.get(&admin, &own.id).await.is_ok();
    let (ew, _) = call(
        &router,
        "POST",
        "/api/v1/memories",
        STRANGER,
        Some(&write_body(&bottom)),
    )
    .await;
    let (eo, _) = call(
        &router,
        "POST",
        "/api/v1/memories",
        OWNER,
        Some(&write_body(&bottom)),
    )
    .await;
    assert!(
        ow.is_success(),
        "control: the root's owner writes at depth 7: {ow} {ob}"
    );

    Outcome {
        binds,
        reflects,
        stranger_write: sw.as_u16(),
        owner_write_ok: ow.is_success(),
        stranger_promote: (sp.as_u16(), spb["status"] == "pending"),
        stranger_delete: (sd.as_u16(), sdb["status"] == "pending"),
        stranger_row_survives: survives,
        over_depth_write: ew.as_u16(),
        over_depth_owner_write: eo.as_u16(),
    }
}

fn assert_governed(o: &Outcome, tag: &str) {
    for (d, status, http_not_owner, sal_not_owner) in &o.binds {
        assert!(
            *status == 403 && *http_not_owner && *sal_not_owner,
            "{tag}: the stranger's first bind at depth {d} must be the not-owner refusal: {o:?}"
        );
    }
    for (d, applied, pending) in &o.reflects {
        assert!(
            !applied && *pending,
            "{tag}: reflect at depth {d} must be PENDING: {o:?}"
        );
    }
    assert_eq!(o.stranger_write, 403, "{tag}: write at depth 7: {o:?}");
    assert!(o.owner_write_ok, "{tag}: {o:?}");
    assert!(
        o.stranger_promote.1,
        "{tag}: promote at depth 7 must be PENDING: {o:?}"
    );
    assert!(
        o.stranger_delete.1,
        "{tag}: delete at depth 7 must be PENDING: {o:?}"
    );
    assert!(o.stranger_row_survives, "{tag}: {o:?}");
    assert_eq!(
        (o.over_depth_write, o.over_depth_owner_write),
        (500, 500),
        "{tag}: an over-depth chain must refuse (fail closed, the #4043 \
         unreadable-policy class), never resolve truncated: {o:?}"
    );
}

async fn sqlite_outcome() -> Outcome {
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let path = dir.path().join("memories.db");
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.clone()).expect("open SqliteStore"),
    );
    run(store, StorageBackend::Sqlite, &path, None).await
}

#[tokio::test]
async fn sqlite_chain_is_complete_to_max_depth_4477() {
    let _serial = SERIAL.lock().await;
    common::permissive_attestation_for_tests();
    let o = sqlite_outcome().await;
    assert_governed(&o, "sqlite");
}

/// The postgres twin and the cross-backend identity. A set-but-unreachable
/// URL FAILS (never skips); only an UNSET URL skips.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_chain_is_complete_to_max_depth_4477() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    let _serial = SERIAL.lock().await;
    common::permissive_attestation_for_tests();
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres adapter"),
    );
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let pg = run(
        store,
        StorageBackend::Postgres,
        &dir.path().join("scratch.db"),
        Some(url.as_str()),
    )
    .await;
    assert_governed(&pg, "postgres");
    let sq = sqlite_outcome().await;
    assert_eq!(pg, sq, "both backends must produce the identical outcome");
}
