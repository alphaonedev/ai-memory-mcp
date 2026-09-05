// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2479 (CWE-284) + #3075 — POSTGRES twin of
//! `tests/federation_ns_meta_scope_2479.rs`.
//!
//! ## What changed at #3075
//!
//! Through v1.0.0 the federated GOVERNANCE-STANDARD lanes were STRUCTURALLY
//! UNREACHABLE on a postgres receiver: `sync_push_via_store` bucketed
//! `namespace_meta[]` / `namespace_meta_clears[]` into
//! `unsupported_on_postgres` and never called
//! `MemoryStore::{set,clear}_namespace_standard`. Safe, but a real coverage gap
//! — federated governance-standard rebinding simply did not replicate to a pg
//! peer, so two nodes answered `get_standard` with divergent policy.
//!
//! #3075 lane L-PGP migrates the family: both lanes now APPLY on postgres
//! through the SAL trait, gated by the SAME backend-BLIND verdict the sqlite
//! funnel calls (`receive_auth::inbound_namespace_meta_authorized`). This file
//! is therefore no longer a structural-unreachability control; it is the
//! CROSS-BACKEND AUTHORIZATION proof, and each cell asserts BOTH halves:
//!
//! - an OUT-OF-SCOPE target is REFUSED (row state unchanged, counted in the
//!   additive `namespace_meta_refused`, never a silent drop), and
//! - an IN-SCOPE target is APPLIED (row state written / cleared, counted in
//!   `namespace_meta_applied` / `namespace_meta_cleared`).
//!
//! Asserting only the refusal would pass on the pre-#3075 funnel that applied
//! nothing at all; asserting only the apply would pass on an ungated funnel.
//! The pair is what pins the gate.
//!
//! The claim stays narrow in the other direction too: it is about the
//! FEDERATED subcollections. The same two trait methods are ALSO reachable
//! through the LOCAL surfaces (`handlers::hook_subscribers::
//! {set_namespace_standard, clear_namespace_standard}` and the MCP
//! `memory_namespace_set_standard` / `_clear_standard` tools), which are
//! governed by local authz rather than peer scope and are out of scope here.
//!
//! ## Why the file exists (the #2488 lesson)
//!
//! #2488/#2491 were the same two lines on the two funnels breaking in OPPOSITE
//! directions, undetected, because only one backend was covered. These cells
//! keep the migrated lane honest on the backend nobody was watching: a pg
//! funnel that widened (applied an out-of-scope row) or narrowed (refused an
//! in-scope one) relative to sqlite fails here.
//!
//! The disposition is also asserted to be HONEST: a refusal is visible to the
//! sender as `namespace_meta_refused`, and the migrated lane no longer inflates
//! `unsupported_on_postgres`.
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip. Deliberately NOT `#[ignore]`: the PR postgres job does not pass
//! `--include-ignored`, so an ignored test silently never runs.

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

/// Serialises every test in this binary — they all mutate process-global
/// federation env vars.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const SYNC_TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";
const PEER_ID: &str = "ai:evil-2479-pg";

/// RAII posture guard — an assertion panic must not leak an enrolled allowlist
/// into the next test in this binary.
struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        clear_posture();
    }
}

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
    };
    (ai_memory::build_router(api_key_state, app_state), store)
}

/// Enrol `PEER_ID` scoped to `<root>/**` ONLY — arms Layer 1, mirroring the
/// sqlite twin's `SCOPED_ALLOWLIST_ROOT_AND_PARENT` control posture.
///
/// The `**` (not `*`) is load-bearing for the APPLIED half:
/// `inbound_namespace_meta_authorized` additionally probes a concrete DEEP
/// DESCENDANT of the row's namespace (#2536), so a single-segment `<root>/*`
/// scope legitimately refuses even an in-scope row — the sqlite twin's own
/// in-scope control uses `alpha/**` for exactly this reason. It is still NOT
/// allow-all: `peer_scope_is_allow_all` matches the LITERAL `**` only, so
/// Amendment E's unconditional global-`*` refusal still fires under this
/// posture (asserted below).
///
/// `AI_MEMORY_FED_SYNC_TRUST_PEER` is actively removed: setting it is what makes
/// federation coverage vacuous.
fn set_scoped_posture(root: &str) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{PEER_ID}":{{"allowed_namespaces":["{root}/**"],"allowed_sender_agent_ids":["{PEER_ID}"]}}}}"#
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
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
    }
}

fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2479-pg");
    ctx.bypass_visibility = true;
    ctx
}

async fn raw_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("raw pool for row-state assertions")
}

/// PRIMARY assertion surface — raw SQL against `namespace_meta`, so no trait
/// method's own error folding can colour the answer.
async fn meta_row(pool: &sqlx::PgPool, namespace: &str) -> Option<(String, Option<String>)> {
    sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT standard_id, parent_namespace FROM namespace_meta WHERE namespace = $1",
    )
    .bind(namespace)
    .fetch_optional(pool)
    .await
    .expect("read namespace_meta row")
}

async fn seed_standard_memory(store: &Arc<dyn MemoryStore>, id: &str, namespace: &str) {
    let mem = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: uniq("standard"),
        content: "namespace standard the federated governance lane would bind".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:victim-2479"}),
        ..Default::default()
    };
    store
        .store(&admin_ctx(), &mem)
        .await
        .expect("seed standard");
}

/// The sender-side NON-ACK counter. The crate const is `pub(crate)`, so the
/// literal is spelled once HERE rather than at each assertion site.
fn unsupported(report: &Value) -> u64 {
    report["unsupported_on_postgres"].as_u64().unwrap_or(0)
}

fn meta_entry(namespace: &str, standard_id: &str, parent: Option<&str>) -> Value {
    json!({
        "namespace": namespace,
        "standard_id": standard_id,
        "parent_namespace": parent,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    })
}

async fn push_namespace_meta(
    router: &axum::Router,
    namespace_meta: Vec<Value>,
    clears: Vec<&str>,
) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "namespace_meta": namespace_meta,
        "namespace_meta_clears": clears,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER_ID,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

/// #3075 — the federated `namespace_meta[]` lane APPLIES on postgres for an
/// IN-SCOPE namespace and REFUSES an OUT-OF-SCOPE one, asserted on ROW STATE in
/// both directions with the sender-visible counters secondary.
#[tokio::test]
async fn federated_namespace_meta_lane_scope_gated_on_postgres_2479_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;

    let root = uniq("pub2479");
    let victim_ns = uniq("secure2479");
    let in_scope_ns = format!("{root}/ok");
    set_scoped_posture(&root);

    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let standard_id = uuid::Uuid::new_v4().to_string();
    seed_standard_memory(&store, &standard_id, &in_scope_ns).await;

    assert!(
        meta_row(&pool, &victim_ns).await.is_none(),
        "precondition: no namespace_meta row for the victim namespace"
    );
    assert!(
        meta_row(&pool, &in_scope_ns).await.is_none(),
        "precondition: no namespace_meta row for the in-scope namespace"
    );

    let (status, report) = push_namespace_meta(
        &router,
        vec![
            meta_entry(&victim_ns, &standard_id, None),
            // IN SCOPE — #3075 requires this half to LAND; asserting only the
            // refusal would also pass on the pre-#3075 funnel that applied
            // nothing at all.
            meta_entry(&in_scope_ns, &standard_id, None),
        ],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "batch survives: {report}");

    // PRIMARY — row state, both directions.
    assert!(
        meta_row(&pool, &victim_ns).await.is_none(),
        "the pg funnel must not bind a foreign namespace's standard: {report}"
    );
    assert_eq!(
        meta_row(&pool, &in_scope_ns).await.map(|r| r.0).as_deref(),
        Some(standard_id.as_str()),
        "#3075: the in-scope governance-standard bind must APPLY on pg: {report}"
    );
    // Secondary — sender-visible counters, and the migrated lane no longer
    // inflates the honest non-ack bucket.
    assert_eq!(
        report["namespace_meta_applied"].as_u64().unwrap_or(0),
        1,
        "{report}"
    );
    assert!(
        report["namespace_meta_refused"].as_u64().unwrap_or(0) >= 1,
        "the refusal must be sender-visible, never a silent drop: {report}"
    );
    assert_eq!(
        unsupported(&report),
        0,
        "#3075: namespace_meta no longer buckets as unsupported_on_postgres: {report}"
    );
}

/// The DESTRUCTIVE twin: a federated clear cannot disarm a namespace the peer
/// is NOT scoped for, and DOES converge one it is (#3075).
#[tokio::test]
async fn federated_namespace_meta_clear_scope_gated_on_postgres_2479_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;

    let root = uniq("pub2479c");
    let victim_ns = uniq("secure2479c");
    let in_scope_ns = format!("{root}/ok");
    set_scoped_posture(&root);

    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    // Bind BOTH standards through the LOCAL trait path — the surface that IS
    // reachable on postgres — so the clear has real rows to destroy.
    let victim_standard = uuid::Uuid::new_v4().to_string();
    let in_scope_standard = uuid::Uuid::new_v4().to_string();
    seed_standard_memory(&store, &victim_standard, &victim_ns).await;
    seed_standard_memory(&store, &in_scope_standard, &in_scope_ns).await;
    store
        .set_namespace_standard(&admin_ctx(), &victim_ns, &victim_standard, None)
        .await
        .expect("local bind (victim)");
    store
        .set_namespace_standard(&admin_ctx(), &in_scope_ns, &in_scope_standard, None)
        .await
        .expect("local bind (in scope)");

    let (status, report) =
        push_namespace_meta(&router, vec![], vec![&victim_ns, &in_scope_ns]).await;
    assert_eq!(status, StatusCode::OK, "batch survives: {report}");

    assert_eq!(
        meta_row(&pool, &victim_ns).await.map(|r| r.0).as_deref(),
        Some(victim_standard.as_str()),
        "a federated clear must not disarm a foreign namespace on pg: {report}"
    );
    assert!(
        meta_row(&pool, &in_scope_ns).await.is_none(),
        "#3075: the in-scope clear must converge on pg: {report}"
    );
    assert_eq!(
        report["namespace_meta_cleared"].as_u64().unwrap_or(0),
        1,
        "{report}"
    );
    assert!(
        report["namespace_meta_refused"].as_u64().unwrap_or(0) >= 1,
        "the out-of-scope clear refusal must be sender-visible: {report}"
    );
    assert_eq!(
        unsupported(&report),
        0,
        "#3075: namespace_meta_clears no longer buckets as unsupported: {report}"
    );
}

/// Amendment E's subject, on pg: the GLOBAL `*` standard stays UNREACHABLE from
/// the federated lane even now that the lane applies (#3075). Pinned separately
/// because `*` is the one namespace whose reach is the whole substrate —
/// `build_namespace_chain` prepends it to EVERY namespace's inheritance chain —
/// and the refusal is UNCONDITIONAL (not governed by
/// `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE`) for any peer that did not
/// declare `**`.
#[tokio::test]
async fn federated_global_standard_refused_on_postgres_2479_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = FED_ENV_LOCK.lock().await;
    let _guard = PostureGuard;

    let root = uniq("pub2479g");
    set_scoped_posture(&root);

    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;
    let before = meta_row(
        &pool,
        ai_memory::federation::receive_auth::GLOBAL_STANDARD_NAMESPACE,
    )
    .await;

    let standard_id = uuid::Uuid::new_v4().to_string();
    seed_standard_memory(&store, &standard_id, &format!("{root}/ok")).await;

    let (status, report) = push_namespace_meta(
        &router,
        vec![meta_entry(
            ai_memory::federation::receive_auth::GLOBAL_STANDARD_NAMESPACE,
            &standard_id,
            None,
        )],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let after = meta_row(
        &pool,
        ai_memory::federation::receive_auth::GLOBAL_STANDARD_NAMESPACE,
    )
    .await;
    assert_eq!(
        before, after,
        "the substrate-wide default policy must be untouched by a federated push: {report}"
    );
    assert!(
        report["namespace_meta_refused"].as_u64().unwrap_or(0) >= 1,
        "the Amendment E refusal must be sender-visible: {report}"
    );
    assert_eq!(
        report["namespace_meta_applied"].as_u64().unwrap_or(0),
        0,
        "{report}"
    );
    assert_eq!(unsupported(&report), 0, "{report}");
}
