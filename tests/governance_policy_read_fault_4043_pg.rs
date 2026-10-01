// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4043 — POSTGRES side of "an unreadable namespace policy must fail closed".
//!
//! The fault is realistic and row-scoped: the bound namespace standard's
//! `encrypted_envelope` is replaced by bytes that cannot be opened (the shape
//! of a selective key loss or a corrupted ciphertext). Reading the standard
//! then fails closed with an integrity error.
//!
//! - `pg_resolver_propagates_unreadable_standard_4043` pins that the postgres
//!   resolver PROPAGATES the fault (no `None` / "ungoverned" collapse) — the
//!   reason the sqlite defect has no twin in the postgres gate.
//! - `pg_sync_push_refuses_row_when_policy_unreadable_4043` is the postgres
//!   defect this issue's sweep found: federation receive mapped the resolver
//!   error to the compiled default cap (`.ok()`) and applied the row. It must
//!   now refuse that row (reject-before-apply) while a control row into a
//!   readable namespace still lands.
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip (the house pattern). Every namespace / id is uuid-randomised.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{CorePolicy, GovernancePolicy, Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

/// Serialises the tests in this binary (process-global federation env vars).
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

fn admin_ctx() -> CallerContext {
    let mut ctx = CallerContext::for_agent("ai:test-4043-pg");
    ctx.bypass_visibility = true;
    ctx
}

/// A permissive standard (write: Any) that pins a reflection-depth cap, so a
/// READABLE policy never refuses the control write by itself.
fn standard(ns: &str) -> Memory {
    let policy = GovernancePolicy {
        core: CorePolicy {
            max_reflection_depth: Some(1),
            ..CorePolicy::default()
        },
        ..GovernancePolicy::default()
    };
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("_standards-{ns}"),
        title: uniq("standard-4043"),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({
            "agent_id": "ai:owner-4043",
            "governance": serde_json::to_value(policy).unwrap(),
        }),
        version: 1,
        ..Memory::default()
    }
}

/// Bind a fresh standard to `ns` and return its id.
async fn bind_standard(store: &Arc<dyn MemoryStore>, ns: &str) -> String {
    let std_mem = standard(ns);
    let id = store
        .store(&admin_ctx(), &std_mem)
        .await
        .expect("seed standard");
    store
        .set_namespace_standard(&admin_ctx(), ns, &id, None)
        .await
        .expect("bind standard");
    id
}

/// Make the standard row unreadable: an envelope that cannot be opened.
async fn corrupt_standard(pool: &sqlx::PgPool, standard_id: &str) {
    let done =
        sqlx::query("UPDATE memories SET encrypted_envelope = '\\x00ff00ff'::bytea WHERE id = $1")
            .bind(standard_id)
            .execute(pool)
            .await
            .expect("corrupt standard envelope");
    assert_eq!(done.rows_affected(), 1, "the standard row must exist");
}

async fn pg_router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store: store.clone(),
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    (ai_memory::build_router(api_key_state, app_state), store)
}

fn set_posture(peer: &str, ns_root: &str) {
    // SAFETY: serialised by `ENV_LOCK`; no other thread reads these vars.
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{peer}":{{"allowed_namespaces":["{ns_root}/*"],"allowed_sender_agent_ids":["{peer}"]}}}}"#
            ),
        );
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn clear_posture() {
    // SAFETY: serialised by `ENV_LOCK`; no other thread reads these vars.
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn wire_memory(id: &str, namespace: &str, peer: &str) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": namespace,
        "title": uniq("fed-4043"),
        "content": "federated payload",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-07-01T00:00:00+00:00",
        "metadata": {"agent_id": peer},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn push(router: &axum::Router, peer: &str, memories: Vec<Value>) -> StatusCode {
    let body = json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": memories,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            peer,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 64 * 1024).await;
    status
}

async fn stored(store: &Arc<dyn MemoryStore>, id: &str) -> bool {
    store.get(&admin_ctx(), id).await.is_ok()
}

#[tokio::test]
async fn pg_resolver_propagates_unreadable_standard_4043() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP pg_resolver_propagates_unreadable_standard_4043: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = ENV_LOCK.lock().await;
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    let pool = sqlx::PgPool::connect(&url).await.expect("raw pool");
    let ns = uniq("gov4043pg/resolve");
    let sid = bind_standard(&store, &ns).await;

    let readable = store
        .resolve_governance_policy(&ns)
        .await
        .expect("a readable policy resolves");
    assert!(readable.is_some(), "control: the bound policy is found");

    corrupt_standard(&pool, &sid).await;
    let err = store.resolve_governance_policy(&ns).await;
    assert!(
        err.is_err(),
        "#4043 (pg): an unreadable standard must propagate as an error, got {err:?}"
    );
}

#[tokio::test]
async fn pg_sync_push_refuses_row_when_policy_unreadable_4043() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP pg_sync_push_refuses_row_when_policy_unreadable_4043: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = ENV_LOCK.lock().await;
    let peer = uniq("ai:peer4043");
    let root = uniq("gov4043pg");
    set_posture(&peer, &root);
    let (router, store) = pg_router(&url).await;
    let pool = sqlx::PgPool::connect(&url).await.expect("raw pool");

    let readable_ns = format!("{root}/readable");
    let broken_ns = format!("{root}/broken");
    bind_standard(&store, &readable_ns).await;
    let broken_sid = bind_standard(&store, &broken_ns).await;
    corrupt_standard(&pool, &broken_sid).await;

    // CONTROL: a readable policy — the row lands.
    let ok_id = uuid::Uuid::new_v4().to_string();
    let status = push(
        &router,
        &peer,
        vec![wire_memory(&ok_id, &readable_ns, &peer)],
    )
    .await;
    assert!(
        status.is_success(),
        "sync_push must not hard-error, got {status}"
    );
    assert!(
        stored(&store, &ok_id).await,
        "control: a row into a namespace with a READABLE policy must land"
    );

    // #4043: the policy cannot be read — the row must be refused.
    let refused_id = uuid::Uuid::new_v4().to_string();
    let status = push(
        &router,
        &peer,
        vec![wire_memory(&refused_id, &broken_ns, &peer)],
    )
    .await;
    assert!(
        status.is_success(),
        "sync_push must not hard-error, got {status}"
    );
    assert!(
        !stored(&store, &refused_id).await,
        "#4043 (pg): a row into a namespace whose policy cannot be read must NOT be applied"
    );

    clear_posture();
}
