// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2478 (CWE-284) — POSTGRES twin of
//! `tests/federation_pending_ns_scope_2478.rs`.
//!
//! ## What changed at #3075
//!
//! This file used to record that the federated governance lanes were
//! STRUCTURALLY UNREACHABLE on postgres — `sync_push_via_store` bucketed
//! `pendings[]` / `pending_decisions[]` into `unsupported_on_postgres` and
//! never called `approve_with_approver_type` or `execute_pending_action`, so
//! there was "no pg hole to confine". That was TRUE and is now the description
//! of a CLOSED coverage gap: #3075 lane L-PGP trait-covers both lanes, so a
//! postgres receiver APPLIES federated governance rows and EXECUTES approved
//! ones.
//!
//! The two EXPLOIT cells below are therefore no longer "controls green by
//! construction" — they are the live proof that the #2478 effect-namespace gate
//! runs on postgres. Their security assertions are UNCHANGED (no row lands in
//! the victim namespace; the out-of-scope victim row survives a
//! pending-executed delete); only the disposition counters moved, from
//! `unsupported_on_postgres` to a per-lane refusal.
//!
//! Three cells are ADDED so each direction is pinned:
//!
//! * the APPLIED half — an in-scope pending is upserted and its approval
//!   EXECUTES, landing the payload row (without it, the exploit cells would
//!   also pass on the pre-#3075 funnel that applied nothing at all);
//! * the #2529 refusal — a wire row claiming a TERMINAL status is refused, so a
//!   peer cannot inject a pre-approved row and skip the decision path;
//! * the #2529 clobber refusal — a replay cannot overwrite a locally-DECIDED
//!   row.
//!
//! The claim stays narrow in the other direction: this is about the FEDERATED
//! subcollections. Pending execution is ALSO reachable through the LOCAL
//! approve surfaces (`handlers::approvals`, `handlers::governance`), which are
//! governed by local authz rather than peer scope and are out of scope here.
//!
//! ## Why the file exists (the #2488 lesson)
//!
//! #2488/#2491 were the same two lines on the two funnels breaking in OPPOSITE
//! directions, undetected, because only one backend was covered. The verdict is
//! now SHARED by construction —
//! `federation_receive::pending_namespaces_authorized_resolved` is called by
//! both funnels, which differ only in HOW a stored namespace is read — and
//! these cells keep that honest end-to-end.
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
const PEER_ID: &str = "ai:evil-2478-pg";

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

/// Enrol `PEER_ID` scoped to `<root>/*` ONLY — arms Layer 1, and is the exact
/// posture under which the sqlite twin's exploit cells land.
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
                r#"{{"{PEER_ID}":{{"allowed_namespaces":["{root}/*"],"allowed_sender_agent_ids":["{PEER_ID}"]}}}}"#
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
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2478-pg");
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

/// PRIMARY assertion surface. Raw SQL on purpose: `MemoryStore::get` folds a
/// #910 visibility denial into `NotFound`, so it cannot answer "does this row
/// still exist" honestly.
async fn row_exists(pool: &sqlx::PgPool, id: &str) -> bool {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count row");
    n == 1
}

async fn count_ns(pool: &sqlx::PgPool, namespace: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM memories WHERE namespace = $1")
        .bind(namespace)
        .fetch_one(pool)
        .await
        .expect("count namespace");
    n
}

async fn seed_row(store: &Arc<dyn MemoryStore>, id: &str, namespace: &str, title: &str) {
    let victim = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "row the federated governance lane would target".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:victim-2478"}),
        ..Default::default()
    };
    store
        .store(&admin_ctx(), &victim)
        .await
        .expect("seed victim row");
}

async fn push_governance(
    router: &axum::Router,
    pendings: Vec<Value>,
    decisions: Vec<Value>,
) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "pendings": pendings,
        "pending_decisions": decisions,
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
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

fn counter(report: &Value, key: &str) -> i64 {
    report.get(key).and_then(Value::as_i64).unwrap_or(-1)
}

// ---------------------------------------------------------------------
// EXPLOIT — the EXACT sqlite exploit shape, replayed at a postgres-backed
// receiver: an in-scope declared namespace carrying an out-of-scope payload
// namespace, plus its approval, in one push. Since #3075 this is a LIVE
// exploit cell against a lane that really applies, not a control against a
// lane that applied nothing.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_pending_store_refused_out_of_scope_on_postgres_2478() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let public_root = uniq("public-2478");
    let victim_ns = uniq("secure-2478");
    set_scoped_posture(&public_root);
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let pid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let entry = json!({
        "id": pid,
        "action_type": "store",
        "memory_id": null,
        "namespace": format!("{public_root}/ok"),
        "payload": {
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long",
            "namespace": victim_ns,
            "title": "governed write via federated pending",
            "content": "must never land on a postgres receiver either",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {"agent_id": PEER_ID},
            "reflection_depth": 0,
            "memory_kind": "observation",
        },
        "requested_by": PEER_ID,
        "requested_at": now,
        "status": "pending",
        "decided_by": null,
        "decided_at": null,
        "approvals": []
    });
    let decision = json!({ "id": pid, "approved": true, "decider": "ai:approver" });

    let (status, report) = push_governance(&router, vec![entry], vec![decision]).await;
    assert!(
        status.is_success(),
        "sync_push must not hard-error; got {status} {report}"
    );

    assert_eq!(
        count_ns(&pool, &victim_ns).await,
        0,
        "#2478 pg: the federated governance lanes must not land a row in a \
         namespace outside the peer's scope. Report: {report}"
    );
    assert_eq!(
        counter(&report, "pendings_applied"),
        0,
        "#2478 pg: the out-of-scope injection must be REFUSED, not upserted. \
         Report: {report}"
    );
    assert_eq!(
        counter(&report, "pending_decisions_applied"),
        0,
        "#2478 pg: and its approval must not execute. The counter now EXISTS \
         (#3075 trait-covered the lane) — the assertion is that it stays zero \
         for an out-of-scope effect namespace. Report: {report}"
    );
    assert!(
        counter(&report, "skipped") >= 1,
        "#2478 pg: the refusal must be sender-visible, never a silent drop — \
         the #2491 class. Report: {report}"
    );
    assert_eq!(
        counter(&report, "unsupported_on_postgres"),
        0,
        "#3075: the governance lanes no longer bucket as unsupported; a \
         refusal is now reported per-lane. Report: {report}"
    );
}

// ---------------------------------------------------------------------
// CONTROL — the destructive arm. A `delete`-typed pending naming an
// out-of-scope row by id must not erase it on a postgres receiver.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_pending_delete_cannot_erase_out_of_scope_row_on_postgres_2478() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let public_root = uniq("public-2478d");
    let victim_ns = uniq("secure-2478d");
    set_scoped_posture(&public_root);
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let victim_id = uuid::Uuid::new_v4().to_string();
    seed_row(&store, &victim_id, &victim_ns, &uniq("pg-pending-delete")).await;
    assert!(row_exists(&pool, &victim_id).await, "seed row must exist");

    let pid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let entry = json!({
        "id": pid,
        "action_type": "delete",
        "memory_id": victim_id,
        "namespace": format!("{public_root}/ok"),
        "payload": {},
        "requested_by": PEER_ID,
        "requested_at": now,
        "status": "pending",
        "decided_by": null,
        "decided_at": null,
        "approvals": []
    });
    let decision = json!({ "id": pid, "approved": true, "decider": "ai:approver" });

    let (status, report) = push_governance(&router, vec![entry], vec![decision]).await;
    assert!(status.is_success(), "{report}");

    assert!(
        row_exists(&pool, &victim_id).await,
        "#2478 pg: an out-of-scope row must survive a federated pending-executed \
         deletion on a postgres receiver. Report: {report}"
    );
    assert_eq!(
        counter(&report, "deleted"),
        0,
        "#2478 pg: nothing was destroyed, so the envelope must not claim \
         otherwise. Report: {report}"
    );
}

// ---------------------------------------------------------------------
// #3075 — the APPLIED half. Without it every cell above would also pass
// on the pre-#3075 funnel, which applied nothing at all.
// ---------------------------------------------------------------------

/// Register `agent_id` so the pg Human approve arm's registered-approver check
/// (#1793/#3448) admits it. The gate is deliberately unconditional on the
/// postgres approval surface, so an unregistered decider is refused there even
/// when everything else is in order — which is why this cell registers one
/// rather than reaching for a bypass.
async fn register_approver(store: &Arc<dyn MemoryStore>, agent_id: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    store
        .register_agent(
            &admin_ctx(),
            &ai_memory::models::AgentRegistration {
                agent_id: agent_id.to_string(),
                agent_type: "nhi".to_string(),
                capabilities: Vec::new(),
                registered_at: now.clone(),
                last_seen_at: now,
            },
        )
        .await
        .expect("register approver");
}

/// An IN-SCOPE federated pending is upserted, and its approval EXECUTES on a
/// postgres receiver: the payload row lands. Every gate in the chain runs — the
/// #1920 authorship gate, the #2529 status checks, the #2478 effect-namespace
/// verdict, the hardened `approve_with_approver_type` (self-approval refusal +
/// registered approver) — and the row is the proof they all passed.
#[tokio::test]
async fn federated_pending_applies_and_executes_in_scope_on_postgres_3075() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let public_root = uniq("public-3075");
    let in_scope_ns = format!("{public_root}/ok");
    set_scoped_posture(&public_root);
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let approver = uniq("ai:approver-3075");
    register_approver(&store, &approver).await;

    let pid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let entry = json!({
        "id": pid,
        "action_type": "store",
        "memory_id": null,
        "namespace": in_scope_ns,
        "payload": {
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long",
            "namespace": in_scope_ns,
            "title": uniq("governed write via federated pending"),
            "content": "must LAND on a postgres receiver (#3075)",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {"agent_id": PEER_ID},
            "reflection_depth": 0,
            "memory_kind": "observation",
        },
        "requested_by": PEER_ID,
        "requested_at": now,
        "status": "pending",
        "decided_by": null,
        "decided_at": null,
        "approvals": []
    });
    let decision = json!({ "id": pid, "approved": true, "decider": approver });

    let (status, report) = push_governance(&router, vec![entry], vec![decision]).await;
    assert!(status.is_success(), "{report}");
    assert_eq!(
        counter(&report, "pendings_applied"),
        1,
        "#3075: the in-scope pending must be upserted on pg: {report}"
    );
    assert_eq!(
        counter(&report, "pending_decisions_applied"),
        1,
        "#3075: and its approval must apply: {report}"
    );
    assert_eq!(
        count_ns(&pool, &in_scope_ns).await,
        1,
        "#3075: the approved pending must EXECUTE and land its payload row on a \
         postgres receiver: {report}"
    );
    assert_eq!(counter(&report, "unsupported_on_postgres"), 0, "{report}");
}

/// #2529 — a wire row claiming a TERMINAL status is refused, so a peer cannot
/// inject a pre-approved governance row and skip the decision path entirely.
/// Asserted on the pg funnel because the refusal is the funnel's, not the
/// store's — though the upsert SQL hard-codes `status = 'pending'` as a second,
/// independent layer.
#[tokio::test]
async fn federated_pending_with_terminal_status_refused_on_postgres_2529() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let public_root = uniq("public-2529");
    let in_scope_ns = format!("{public_root}/ok");
    set_scoped_posture(&public_root);
    let (router, _store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let pid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let entry = json!({
        "id": pid,
        "action_type": "store",
        "memory_id": null,
        "namespace": in_scope_ns,
        "payload": {},
        "requested_by": PEER_ID,
        "requested_at": now,
        // The whole point: a peer claiming the row is ALREADY approved.
        "status": "approved",
        "decided_by": PEER_ID,
        "decided_at": now,
        "approvals": []
    });

    let (status, report) = push_governance(&router, vec![entry], vec![]).await;
    assert!(status.is_success(), "the batch survives: {report}");
    assert_eq!(
        counter(&report, "pendings_applied"),
        0,
        "#2529: a pre-decided injection must be refused on pg: {report}"
    );
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pending_actions WHERE id = $1")
        .bind(&pid)
        .fetch_one(&pool)
        .await
        .expect("count pending row");
    assert_eq!(
        n, 0,
        "#2529: and no governance row may exist for it: {report}"
    );
}

/// #2529 — the CLOBBER half: a replay must not overwrite a row this node has
/// already DECIDED. The funnel refuses on the locally-probed status, and the
/// upsert's `ON CONFLICT ... WHERE status = 'pending'` clause refuses again
/// underneath it, so neither layer is load-bearing alone.
#[tokio::test]
async fn federated_pending_cannot_clobber_decided_row_on_postgres_2529() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let public_root = uniq("public-2529c");
    let in_scope_ns = format!("{public_root}/ok");
    set_scoped_posture(&public_root);
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let pid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let entry = json!({
        "id": pid,
        "action_type": "store",
        "memory_id": null,
        "namespace": in_scope_ns,
        "payload": {},
        "requested_by": PEER_ID,
        "requested_at": now,
        "status": "pending",
        "decided_by": null,
        "decided_at": null,
        "approvals": []
    });
    let (status, report) = push_governance(&router, vec![entry.clone()], vec![]).await;
    assert!(status.is_success(), "{report}");
    assert_eq!(counter(&report, "pendings_applied"), 1, "{report}");

    // Decide it LOCALLY (the surface a pg deployment really uses).
    store
        .pending_decide(&admin_ctx(), &pid, false, "ai:local-operator")
        .await
        .expect("local decide");

    // A replay of the same wire row must not resurrect it.
    let (status, report) = push_governance(&router, vec![entry], vec![]).await;
    assert!(status.is_success(), "the batch survives: {report}");
    assert_eq!(
        counter(&report, "pendings_applied"),
        0,
        "#2529: a replay must not clobber a locally-decided row: {report}"
    );
    let (st,): (String,) = sqlx::query_as("SELECT status FROM pending_actions WHERE id = $1")
        .bind(&pid)
        .fetch_one(&pool)
        .await
        .expect("read status");
    assert_eq!(
        st, "rejected",
        "the local decision must survive the replay: {report}"
    );
}
