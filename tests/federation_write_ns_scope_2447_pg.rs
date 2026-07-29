// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2447 (CWE-284) — POSTGRES twin of `tests/federation_write_ns_scope_2447.rs`.
//!
//! The sqlite tests prove the gate; these prove the postgres receive twin
//! (`sync_push_via_store`) behaves IDENTICALLY, which is the whole point of
//! putting the verdict in one shared `receive_auth` function. Two additional
//! things are pinned here that have no sqlite analogue:
//!
//! 1. **The #1934 delete gate never landed on this backend at all.**
//!    `PostgresStore::apply_remote_deletion` takes `_ctx` and discards it, and
//!    the `#1934` marker appears nowhere in `federation_signing_check.rs`. The
//!    existing #1934 regression test (`security_authz_isolation_cluster.rs`)
//!    builds a SQLITE router, so a postgres-backed node has been exploitable
//!    for the hard-delete variant this whole time with no test to catch it.
//! 2. **The namespace probe must bypass the #910 visibility filter.**
//!    `PostgresStore::get` folds a visibility denial into `NotFound`, so a
//!    tenant-scoped context would report a hidden foreign row as "no such row"
//!    — fail-OPEN on exactly the `scope=private` rows the gate protects.
//!    `scope_private_victim_row_still_blocks_the_merge_2447_pg` is that pin.
//!
//! Gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`; without
//! the env var every test prints a skip line and returns (the house pattern —
//! see `tests/cov_ga2_pg_federation.rs`). Every namespace / id / peer-id is
//! uuid-randomised so concurrent runs against the shared scratch DB never
//! collide, and no test asserts global-table emptiness.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// Serialises every test in this binary — they all mutate the process-global
/// federation env vars, and cargo runs `#[tokio::test]`s concurrently.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

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
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), store)
}

/// Enrol `peer` scoped to `public-<suffix>/*` ONLY — the issue's scenario.
fn set_scoped_posture(peer: &str, public_ns_root: &str) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{peer}":{{"allowed_namespaces":["{public_ns_root}/*"],"allowed_sender_agent_ids":["{peer}"]}}}}"#
            ),
        );
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

fn wire_memory(id: &str, namespace: &str, peer: &str, title: &str, updated_at: &str) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": namespace,
        "title": title,
        "content": "federated payload",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": updated_at,
        "metadata": {"agent_id": peer},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn push(router: &axum::Router, peer: &str, body: &Value) -> StatusCode {
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

/// Admin ctx — the TEST's own read, so it observes the true stored state
/// regardless of the #910 visibility filter.
fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2447-pg");
    ctx.bypass_visibility = true;
    ctx
}

async fn stored_namespace(store: &Arc<dyn MemoryStore>, id: &str) -> Option<String> {
    store.get(&admin_ctx(), id).await.ok().map(|m| m.namespace)
}

// ---------------------------------------------------------------------
// R-203 (postgres) — the issue's failure scenario on the pg twin.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_write_outside_peer_scope_refused_2447_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP federated_write_outside_peer_scope_refused_2447_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:evil");
    let public_root = uniq("public");
    let victim_ns = uniq("secure/ops");
    set_scoped_posture(&peer, &public_root);
    let (router, store) = pg_router(&url).await;

    // EXPLOIT: push into a namespace outside the peer's declared scope.
    let evil_id = uuid::Uuid::new_v4().to_string();
    let status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [wire_memory(&evil_id, &victim_ns, &peer, "poison", "2026-07-01T00:00:00+00:00")],
            "dry_run": false,
        }),
    )
    .await;
    assert!(status.is_success(), "sync_push must not hard-error");
    assert!(
        stored_namespace(&store, &evil_id).await.is_none(),
        "#2447 (pg): a peer scoped to {public_root}/* must NOT write into {victim_ns}"
    );

    // CONTROL: the same peer, inside scope, still lands.
    let ok_id = uuid::Uuid::new_v4().to_string();
    let ok_ns = format!("{public_root}/ok");
    let ok_status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [wire_memory(&ok_id, &ok_ns, &peer, "legit", "2026-07-01T00:00:00+00:00")],
            "dry_run": false,
        }),
    )
    .await;
    assert!(ok_status.is_success());
    assert_eq!(
        stored_namespace(&store, &ok_id).await.as_deref(),
        Some(ok_ns.as_str()),
        "#2447 (pg): an in-scope write must still be applied"
    );

    clear_posture();
}

// ---------------------------------------------------------------------
// The merge-clobber bypass, and the visibility-filter fail-open it rides.
// ---------------------------------------------------------------------

#[tokio::test]
async fn scope_private_victim_row_still_blocks_the_merge_2447_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP scope_private_victim_row_still_blocks_the_merge_2447_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:evil");
    let public_root = uniq("public");
    let victim_ns = uniq("secure/ops");
    set_scoped_posture(&peer, &public_root);
    let (router, store) = pg_router(&url).await;

    // Seed a victim row the peer has no scope for, marked scope=private and
    // owned by ANOTHER agent. This is the load-bearing shape: a probe built on
    // a tenant-scoped `PostgresStore::get` would see `NotFound` (the #910
    // filter folds a denial into NotFound), conclude "no local row", and let
    // the merge through — fail-OPEN on the most-protected row in the store.
    let victim_id = uuid::Uuid::new_v4().to_string();
    let mut victim = ai_memory::models::Memory::default();
    victim.id.clone_from(&victim_id);
    victim.namespace.clone_from(&victim_ns);
    victim.title = uniq("sensitive");
    victim.content = "secure ops row".to_string();
    victim.created_at = "2026-01-01T00:00:00+00:00".to_string();
    victim.updated_at = "2026-01-02T00:00:00+00:00".to_string();
    victim.metadata = json!({"agent_id": "ai:victim-2447", "scope": "private"});
    store
        .store(&admin_ctx(), &victim)
        .await
        .expect("seed victim row");

    // EXPLOIT: push the VICTIM'S id under an IN-SCOPE namespace with a newer
    // `updated_at`. `merge_memory` LWWs `namespace`, so a claimed-only gate
    // would relocate the private secure row into the attacker's scope.
    let loot_ns = format!("{public_root}/loot");
    let status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [wire_memory(&victim_id, &loot_ns, &peer, "clobbered", "2099-01-01T00:00:00+00:00")],
            "dry_run": false,
        }),
    )
    .await;
    assert!(status.is_success());
    assert_eq!(
        stored_namespace(&store, &victim_id).await.as_deref(),
        Some(victim_ns.as_str()),
        "#2447 (pg): an out-of-scope STORED namespace must block the merge, even when \
         the victim row is scope=private and owned by another agent — the probe must \
         bypass the #910 visibility filter or it fails OPEN on exactly these rows"
    );

    clear_posture();
}

// ---------------------------------------------------------------------
// #1934 postgres parity — the delete gate that never landed on this backend.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_deletion_outside_peer_scope_refused_1934_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP federated_deletion_outside_peer_scope_refused_1934_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:evil");
    let public_root = uniq("public");
    let victim_ns = uniq("secure/ops");
    set_scoped_posture(&peer, &public_root);
    let (router, store) = pg_router(&url).await;

    let victim_id = uuid::Uuid::new_v4().to_string();
    let mut victim = ai_memory::models::Memory::default();
    victim.id.clone_from(&victim_id);
    victim.namespace.clone_from(&victim_ns);
    victim.title = uniq("delete-victim");
    victim.content = "secure ops row".to_string();
    victim.created_at = "2026-01-01T00:00:00+00:00".to_string();
    victim.updated_at = "2026-01-02T00:00:00+00:00".to_string();
    victim.metadata = json!({"agent_id": "ai:victim-2447"});
    store
        .store(&admin_ctx(), &victim)
        .await
        .expect("seed victim row");

    // EXPLOIT: the #1934 hard-delete, on the backend the #1934 fix never
    // reached (`PostgresStore::apply_remote_deletion` discards its `_ctx`).
    let status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [],
            "deletions": [victim_id],
            "dry_run": false,
        }),
    )
    .await;
    assert!(status.is_success());
    assert_eq!(
        stored_namespace(&store, &victim_id).await.as_deref(),
        Some(victim_ns.as_str()),
        "#1934 (pg parity via #2447): a peer scoped to {public_root}/* must NOT \
         hard-delete a row in {victim_ns}"
    );

    clear_posture();
}

// ---------------------------------------------------------------------
// Posture guard — zero-config replication must be unchanged on pg too.
// ---------------------------------------------------------------------

#[tokio::test]
async fn zero_config_federation_write_still_applies_2447_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP zero_config_federation_write_still_applies_2447_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let peer = uniq("ai:zeroconf");
    let ns = uniq("secure/ops");
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
    let (router, store) = pg_router(&url).await;

    let id = uuid::Uuid::new_v4().to_string();
    let status = push(
        &router,
        &peer,
        &json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "memories": [wire_memory(&id, &ns, &peer, "zero-config replication", "2026-07-01T00:00:00+00:00")],
            "dry_run": false,
        }),
    )
    .await;
    assert!(status.is_success());
    assert_eq!(
        stored_namespace(&store, &id).await.as_deref(),
        Some(ns.as_str()),
        "#2447 (pg): zero-config federation must be byte-identical to pre-fix"
    );

    clear_posture();
}
