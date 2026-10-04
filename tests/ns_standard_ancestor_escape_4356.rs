// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the executed approval-gate escape (found by the #4357 security
//! review, both backends, `POST /api/v1/namespaces/{ns}/standard`) is closed.
//!
//! Setup: parent `P` carries a standard with a depth gate
//! (`require_approval_above_depth: 0`), owned by `STD_OWNER`. A DIFFERENT
//! principal then tries to bind the FIRST standard at the `/`-child `P/evil`
//! with a permissive policy that omits the depth key. Under the GOD FINAL
//! walker ruling an omitted key STOPS the walk (leaf-first-wins, #2542), so if
//! that bind landed, the stranger's next depth-1 reflect into `P/evil` would
//! be APPLIED instead of parked.
//!
//! Asserted here, on both backends: the stranger's first bind is REFUSED with
//! the closed 403 `NOT_OWNER` shape (placeholder form and id form), `P/evil`
//! stays unbound, the owner's first bind and an admin bind still succeed. On
//! sqlite, whose reflect path already enforces the depth gate on this carrier,
//! the stranger's reflect into `P/evil` also stays PENDING after the refused
//! bind; the postgres reflect gate is #4357's (PR on f1/4357-v3) and its
//! composition with this fix is verified on the merged tree.

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

const KEY: &str = "issue-4356-escape-key";
const STD_OWNER: &str = "ai:stdowner-4356";
const STRANGER: &str = "ai:stranger-4356";

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

async fn post(router: &axum::Router, agent: &str, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("x-api-key", KEY)
        .header("x-agent-id", agent)
        .header("content-type", "application/json")
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

fn memory(owner: &str, namespace: &str, title: &str) -> Memory {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        title: format!("{title} {id}"),
        id,
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        namespace: namespace.into(),
        content: "issue 4356 escape".into(),
        metadata: json!({"agent_id": owner, "scope": "shared"}),
        ..Memory::default()
    }
}

fn standard_uri(ns: &str) -> String {
    format!("/api/v1/namespaces/{}/standard", ns.replace('/', "%2F"))
}

/// The reflect outcome: `true` when the reflection was APPLIED (written).
async fn reflect_applied(router: &axum::Router, src: &str, ns: &str) -> (bool, Value) {
    let (status, body) = post(
        router,
        STRANGER,
        "/api/v1/memory_reflect",
        &json!({
            "source_ids": [src],
            "title": format!("reflection {}", uuid::Uuid::new_v4()),
            "content": "depth-1 reflection", "namespace": ns, "agent_id": STRANGER,
        }),
    )
    .await;
    let applied = body.get("id").is_some();
    assert!(
        applied || body["status"] == "pending" || !status.is_success(),
        "unexpected reflect outcome {status} {body}"
    );
    (applied, body)
}

async fn escape(store: Arc<dyn MemoryStore>, backend: StorageBackend, db_path: &std::path::Path) {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let sqlite = matches!(backend, StorageBackend::Sqlite);
    let owner = CallerContext::for_agent(STD_OWNER);
    let parent = format!("p4356x/{}", uuid::Uuid::new_v4().simple());
    let mut pstd = memory(STD_OWNER, &format!("{parent}-standards"), "parent standard");
    pstd.metadata["governance"] = json!({"write": "any", "require_approval_above_depth": 0});
    store.store(&owner, &pstd).await.expect("parent standard");
    store
        .set_namespace_standard(&owner, &parent, &pstd.id, None)
        .await
        .expect("bind parent");
    let child = format!("{parent}/evil");
    let stranger = CallerContext::for_agent(STRANGER);
    let src = memory(STRANGER, &child, "stranger source");
    store.store(&stranger, &src).await.expect("source");
    let s_std = memory(
        STRANGER,
        &format!("{parent}-strangerstd"),
        "stranger standard",
    );
    store
        .store(&stranger, &s_std)
        .await
        .expect("stranger standard");
    let router = router(backend, Arc::clone(&store), db_path);

    if sqlite {
        let (applied, body) = reflect_applied(&router, &src.id, &child).await;
        assert!(
            !applied,
            "control: the parent gate holds before the bind: {body}"
        );
    }

    // The escape: the stranger binds the FIRST standard at the `/`-child,
    // placeholder form and id form. Both refused, closed shape, no owner leak.
    for body in [
        json!({"governance": {"write": "any"}}),
        json!({"id": s_std.id, "governance": {"write": "any"}}),
    ] {
        let (status, refused) = post(&router, STRANGER, &standard_uri(&child), &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert_eq!(
            refused["error"],
            ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
            "{refused}"
        );
        assert_eq!(refused["code"], ai_memory::errors::error_codes::NOT_OWNER);
        assert!(
            !refused.to_string().contains(STD_OWNER)
                && !refused.to_string().contains("require_approval_above_depth"),
            "the refusal must not name the owner or echo the policy: {refused}"
        );
    }
    let bound = store
        .get_namespace_standard(&CallerContext::for_admin("ai:admin-4356"), &child)
        .await
        .expect("read child binding");
    assert!(
        bound.is_none(),
        "the refused bind left a binding: {bound:?}"
    );

    // With the bind refused the stranger's reflect into the child is still
    // gated by the parent (sqlite: the carrier's reflect path enforces it).
    if sqlite {
        let (applied, body) = reflect_applied(&router, &src.id, &child).await;
        assert!(!applied, "the parent's depth gate was escaped: {body}");
    }

    // The ancestor's owner may open a child; an admin bind is unaffected.
    let ok_child = format!("{parent}/ok");
    let (status, ok) = post(
        &router,
        STD_OWNER,
        &standard_uri(&ok_child),
        &json!({"governance": {"write": "any"}}),
    )
    .await;
    assert!(status.is_success(), "the owner's first bind: {status} {ok}");
    store
        .set_namespace_standard(
            &CallerContext::for_admin("ai:admin-4356"),
            &format!("{parent}/adm"),
            &s_std.id,
            None,
        )
        .await
        .expect("an admin bind is unaffected");
}

#[tokio::test]
async fn sqlite_stranger_child_bind_escape_is_closed_4356() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let path = dir.path().join("memories.db");
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.clone()).expect("open SqliteStore"),
    );
    escape(store, StorageBackend::Sqlite, &path).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_stranger_child_bind_escape_is_closed_4356() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres adapter"),
    );
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    escape(
        store,
        StorageBackend::Postgres,
        &dir.path().join("scratch.db"),
    )
    .await;
}
