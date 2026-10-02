// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4478 — the federated `namespace_meta[]` apply (`POST /api/v1/sync/push`)
//! runs the #4356 ancestor-owner bind gate on BOTH receive loops (sqlite
//! `federation_receive`, postgres `federation_signing_check`); the postgres
//! admin apply context no longer bypasses it.
//!
//! Scenario (the #4356 security review's federation finding): a parent `P`
//! carries a depth-gated standard owned locally by `STD_OWNER`. A peer whose
//! scope covers `P/x/**` (and a control tree) but NOT `P` pushes the FIRST
//! standard for `P/x` with a permissive policy that omits the depth key.
//!
//! Asserted on each backend, row state first and counters second:
//! - the stranger peer's first bind under `P` is REFUSED and skipped
//!   (`namespace_meta_refused` +1, `P/x` stays unbound) while the in-scope
//!   ungoverned control entry in the SAME batch still applies;
//! - the stranger's depth-1 reflect into `P/x` stays PENDING;
//! - a peer acting for the ancestor owner (allowlisted for `STD_OWNER` in
//!   `allowed_sender_agent_ids`, binding `STD_OWNER`'s standard) is allowed;
//! - with the body-agent-id trust bypass the actor cannot be established and
//!   the first bind is refused (fail closed);
//! - both backends produce the identical outcome.
//!
//! The router is built with `AI_MEMORY_FED_SYNC_TRUST_PEER` actively removed
//! (it would paper over the gates under test, R-203).

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(
    clippy::struct_excessive_bools,
    reason = "a flat outcome record compared across backends"
)]

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

/// Process-global: the cells mutate process-wide env vars.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const PEER: &str = "ai:peer-4478";
const STD_OWNER: &str = "ai:stdowner-4478";
const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";
const SYNC_TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";

/// Restores the env on every exit path, including a failed assertion.
struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        // SAFETY: serialised by ENV_LOCK; test-only env mutation.
        unsafe {
            std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
            std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
            std::env::remove_var(REQUIRE_ATTEST_ENV);
            std::env::remove_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            );
            std::env::remove_var(SYNC_TRUST_PEER_ENV);
            std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
        }
    }
}

/// Enrol `PEER` for `scopes` (tree patterns), allowed to author as `agents`.
fn set_posture(scopes: &[String], agents: &[&str], trust_body_bypass: bool) {
    let allow = json!({PEER: {"allowed_namespaces": scopes, "allowed_sender_agent_ids": agents}});
    // SAFETY: serialised by ENV_LOCK; test-only env mutation.
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            allow.to_string(),
        );
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            "1",
        );
        if trust_body_bypass {
            std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
        } else {
            std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
        }
    }
}

fn router(
    backend: StorageBackend,
    store: Arc<dyn MemoryStore>,
    db_path: &std::path::Path,
) -> axum::Router {
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
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: enrolled,
            identity_mode: HttpIdentityMode::Advisory,
            ..Default::default()
        },
        app,
    )
}

async fn post(
    router: &axum::Router,
    uri: &str,
    agent: Option<&str>,
    peer: bool,
    body: &Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(a) = agent {
        req = req.header("x-agent-id", a);
    }
    if peer {
        req = req.header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER,
        );
    }
    let req = req
        .body(Body::from(serde_json::to_vec(body).expect("body")))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("bytes");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn memory(owner: &str, namespace: &str, governance: Option<Value>) -> Memory {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = json!({"agent_id": owner, "scope": "shared"});
    if let Some(g) = governance {
        metadata["governance"] = g;
    }
    Memory {
        title: format!("m4478 {id}"),
        id,
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        namespace: namespace.into(),
        content: "issue 4478".into(),
        metadata,
        ..Memory::default()
    }
}

fn entry(namespace: &str, standard_id: &str) -> Value {
    json!({
        "namespace": namespace, "standard_id": standard_id, "parent_namespace": null,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    })
}

async fn push(router: &axum::Router, entries: Vec<Value>) -> Value {
    let (status, report) = post(
        router,
        "/api/v1/sync/push",
        None,
        true,
        &json!({
            "sender_agent_id": PEER, "sender_clock": {"entries": {}}, "memories": [],
            "namespace_meta": entries, "namespace_meta_clears": [], "dry_run": false,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "per-entry skip, the batch survives: {report}"
    );
    report
}

fn counter(report: &Value, key: &str) -> u64 {
    report[key]
        .as_u64()
        .unwrap_or_else(|| panic!("counter {key} missing: {report}"))
}

async fn bound(store: &Arc<dyn MemoryStore>, ns: &str) -> Option<String> {
    store
        .get_namespace_standard(&CallerContext::for_admin("ai:admin-4478"), ns)
        .await
        .expect("read binding")
        .map(|(sid, _)| sid)
}

/// One backend's observable outcome (compared across backends).
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    stranger_refused: u64,
    stranger_applied: u64,
    stranger_child_bound: bool,
    control_bound: bool,
    reflect_applied: bool,
    reflect_pending: bool,
    owner_peer_applied: u64,
    owner_child_bound: bool,
    bypass_refused: u64,
    bypass_child_bound: bool,
}

async fn run(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    db_path: &std::path::Path,
) -> Outcome {
    let _guard = PostureGuard;
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let u = uuid::Uuid::new_v4().simple().to_string();
    let parent = format!("p4478/{u}");
    let free = format!("free4478{u}");
    let owner_ctx = CallerContext::for_agent(STD_OWNER);
    let pstd = memory(
        STD_OWNER,
        &format!("std4478{u}"),
        Some(json!({"write": "any", "require_approval_above_depth": 0})),
    );
    store
        .store(&owner_ctx, &pstd)
        .await
        .expect("parent standard");
    store
        .set_namespace_standard(&owner_ctx, &parent, &pstd.id, None)
        .await
        .expect("bind P locally");
    // The peer's own permissive standard (it rode in on `memories` earlier).
    let peer_ctx = CallerContext::for_agent(PEER);
    let s_std = memory(PEER, &format!("std4478{u}"), Some(json!({"write": "any"})));
    store.store(&peer_ctx, &s_std).await.expect("peer standard");
    let f_std = memory(PEER, &format!("std4478{u}"), Some(json!({"write": "any"})));
    store
        .store(&peer_ctx, &f_std)
        .await
        .expect("control standard");
    let child = format!("{parent}/x");
    let src = memory(PEER, &child, None);
    store
        .store(&peer_ctx, &src)
        .await
        .expect("source in the child");
    let router = router(backend, Arc::clone(&store), db_path);

    // 1. Stranger peer: first bind under P refused; the control entry applies.
    set_posture(
        &[format!("{parent}/x/**"), format!("{free}/**")],
        &[PEER],
        false,
    );
    let report = push(
        &router,
        vec![entry(&child, &s_std.id), entry(&free, &f_std.id)],
    )
    .await;
    let stranger_child_bound = bound(&store, &child).await.is_some();
    let control_bound = bound(&store, &free).await.as_deref() == Some(f_std.id.as_str());

    // 2. The stranger's reflect into P/x stays gated by P.
    let (_, rb) = post(
        &router,
        "/api/v1/memory_reflect",
        Some(PEER),
        false,
        &json!({
            "source_ids": [src.id], "title": format!("r4478 {}", uuid::Uuid::new_v4()),
            "content": "depth-1 reflection", "namespace": child, "agent_id": PEER,
        }),
    )
    .await;

    // 3. A peer acting for the ancestor owner: allowed.
    let ok_child = format!("{parent}/ok");
    let o_std = memory(
        STD_OWNER,
        &format!("std4478{u}"),
        Some(json!({"write": "any"})),
    );
    store
        .store(&owner_ctx, &o_std)
        .await
        .expect("owner child standard");
    set_posture(&[format!("{parent}/ok/**")], &[PEER, STD_OWNER], false);
    let owner_report = push(&router, vec![entry(&ok_child, &o_std.id)]).await;
    let owner_child_bound = bound(&store, &ok_child).await.as_deref() == Some(o_std.id.as_str());

    // 4. Trust bypass: the actor cannot be established, fail closed.
    let byp_child = format!("{parent}/byp");
    set_posture(&[format!("{parent}/byp/**")], &[PEER, STD_OWNER], true);
    let bypass_report = push(&router, vec![entry(&byp_child, &o_std.id)]).await;
    let bypass_child_bound = bound(&store, &byp_child).await.is_some();

    Outcome {
        stranger_refused: counter(&report, "namespace_meta_refused"),
        stranger_applied: counter(&report, "namespace_meta_applied"),
        stranger_child_bound,
        control_bound,
        reflect_applied: rb.get("id").is_some(),
        reflect_pending: rb["status"] == "pending",
        owner_peer_applied: counter(&owner_report, "namespace_meta_applied"),
        owner_child_bound,
        bypass_refused: counter(&bypass_report, "namespace_meta_refused"),
        bypass_child_bound,
    }
}

const WANT: Outcome = Outcome {
    stranger_refused: 1,
    stranger_applied: 1,
    stranger_child_bound: false,
    control_bound: true,
    reflect_applied: false,
    reflect_pending: true,
    owner_peer_applied: 1,
    owner_child_bound: true,
    bypass_refused: 1,
    bypass_child_bound: false,
};

async fn sqlite_outcome() -> Outcome {
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let path = dir.path().join("memories.db");
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.clone()).expect("open SqliteStore"),
    );
    run(store, StorageBackend::Sqlite, &path).await
}

#[tokio::test]
async fn sqlite_federated_first_bind_under_governed_ancestor_is_gated_4478() {
    let _env = ENV_LOCK.lock().await;
    common::permissive_attestation_for_tests();
    assert_eq!(sqlite_outcome().await, WANT);
}

/// The postgres twin, and the cross-backend identity of the outcome. A
/// set-but-unreachable URL FAILS (never skips); only an UNSET URL skips.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_federated_first_bind_under_governed_ancestor_is_gated_4478() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    let _env = ENV_LOCK.lock().await;
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
    )
    .await;
    let sq = sqlite_outcome().await;
    assert_eq!(pg, sq, "both backends must produce the identical outcome");
    assert_eq!(pg, WANT);
}
