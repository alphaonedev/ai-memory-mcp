// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! #2478 (CWE-284) — namespace confinement for the federated GOVERNANCE lanes
//! (`/sync/push` `pendings[]` + `pending_decisions[]`) on the sqlite receive
//! funnel (`handlers::federation_receive::sync_push`).
//!
//! ## The hole
//!
//! `pending_decisions[]` reaches `db::approve_with_approver_type` and then
//! `db::execute_pending_action`, whose arms call `insert()` with the PAYLOAD's
//! arbitrary namespace, `delete()` on an attacker-chosen `memory_id` with no
//! namespace check at all, `promote_to_namespace()` into `payload.to_namespace`,
//! and `reflect()` over every `payload.source_ids[i]`. The only gate on the lane
//! was `pending_author_authorized` (#1920), which inspects `requested_by` and
//! the payload's `metadata.agent_id` — never a namespace, and it never resolves
//! `pa.memory_id`. So a correctly-enrolled, correctly-scoped, TOFU-passing peer
//! reached those sinks under DEFAULT config.
//!
//! ## Two traps these cells are shaped to avoid
//!
//! 1. **`pa.namespace` is not the effect.** `execute_pending_action` NEVER READS
//!    it. A gate on the row's own declared namespace passes while
//!    `payload.namespace` lands the write somewhere else entirely — so
//!    `exploit_pendings_plus_decisions_store_lands_foreign_namespace_2478`
//!    deliberately sends an IN-SCOPE `pa.namespace` with an OUT-OF-SCOPE payload
//!    namespace. A `pa.namespace`-only fix leaves that cell RED.
//! 2. **The issue's own acceptance criterion is satisfiable by the wrong fix.**
//!    "A `public/*`-scoped peer cannot land a `secure/ops` row via the
//!    pendings+decisions pair" also passes if you gate ONLY the `pendings[]`
//!    injection — the pending never lands, so the decision has nothing to
//!    execute — while the lane the issue TITLES (`pending_decisions[]` against a
//!    pending row that already exists locally) stays wide open. Hence
//!    `exploit_decisions_only_against_local_pending_2478`, whose push carries NO
//!    `pendings[]` at all.
//!
//! ## Why this file builds its OWN router (R-203, load-bearing)
//!
//! `build_router_fixture` in the shared HTTP-surface suite pre-sets
//! `AI_MEMORY_FED_SYNC_TRUST_PEER=1`, which flips `sync_trust_peer_bypass()` and
//! papers over exactly the refusals under test — that is how
//! `tests/l07_3_chunk_d_http_surface.rs` stayed green over the broken delete
//! lane until #2488. This file builds a router with that var explicitly REMOVED,
//! mirroring `tests/federation_delete_ns_scope_2488.rs`.
//!
//! Primary assertion is always DB ROW STATE, with response counters secondary:
//! `skipped` increments for several unrelated reasons, so `skipped >= 1` alone
//! would not distinguish a scope refusal from a malformed id.
//!
//! Design decided by the 5-agent adversarial vote (`4d3ea1c5`), 5/5
//! ADOPT_WITH_AMENDMENTS.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex — these tests mutate process-wide env vars.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";
const PEER_ID: &str = "ai:evil";
const VICTIM_NS: &str = "secure/ops";
const IN_SCOPE_NS: &str = "public/ok";
/// The registered approver the hardened #1920 Human arm requires. Distinct from
/// `requested_by` so the self-approval reject does not fire.
const APPROVER: &str = "ai:approver";

/// `ai:evil` may act inside `public/*` only.
const SCOPED_ALLOWLIST: &str =
    r#"{"ai:evil":{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// The CONTROL posture: the same peer, scoped to reach the victim namespace too.
const SCOPED_ALLOWLIST_WITH_VICTIM: &str = r#"{"ai:evil":{"allowed_namespaces":["public/*","secure/*"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// Deep-scope posture for the `promote` cell: the peer may act on the leaf but
/// NOT on its ancestor, which is where `promote_to_namespace` clones into.
const SCOPED_ALLOWLIST_DEEP: &str = r#"{"ai:evil":{"allowed_namespaces":["public/deep/x"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// RAII posture guard — `Drop` runs on unwind, so a failing assertion cannot
/// leak an enrolled allowlist into the next test in this binary (#2482 shape).
struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        clear_posture();
    }
}

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let path = std::path::PathBuf::from(":memory:");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path,
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store"))
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

/// Seed the peer-attestation posture. `allowlist == None` = ZERO-CONFIG.
/// `AI_MEMORY_FED_SYNC_TRUST_PEER` is deliberately NEVER set and actively
/// removed — setting it is what makes federation coverage vacuous.
fn set_posture(allowlist: Option<&str>, require_scope: Option<&str>) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        match allowlist {
            Some(json) => std::env::set_var(
                ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
                json,
            ),
            None => {
                std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
            }
        }
        match require_scope {
            Some(v) => std::env::set_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
                v,
            ),
            None => std::env::remove_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            ),
        }
        std::env::remove_var("AI_MEMORY_FED_SYNC_TRUST_PEER");
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
    }
}

/// Register the approver so the hardened #1920 Human arm admits the decision.
/// Without this every cell would pass for the WRONG reason (the approval is
/// refused before the namespace gate is ever consulted).
async fn register_approver(db: &ai_memory::handlers::Db) {
    let guard = db.lock().await;
    ai_memory::db::register_agent(&guard.0, APPROVER, "service", &[]).expect("register approver");
}

/// Create a row through the normal HTTP write path and return its id.
async fn seed_row(router: &axum::Router, namespace: &str, title: &str) -> String {
    let create = json!({
        "title": title,
        "content": "row the federated governance lane will target",
        "tier": "long",
        "namespace": namespace,
        "tags": [],
        "priority": 5,
        "source": "api",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:victim")
        .body(Body::from(create.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_success(), "seed write must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&bytes).unwrap();
    created["id"].as_str().expect("created id").to_string()
}

/// Queue a pending action LOCALLY (not over the wire) so the decisions-only
/// cells act on a row this node minted itself.
async fn seed_local_pending(
    db: &ai_memory::handlers::Db,
    action: ai_memory::models::GovernedAction,
    namespace: &str,
    memory_id: Option<&str>,
    requested_by: &str,
    payload: &Value,
) -> String {
    let guard = db.lock().await;
    ai_memory::db::queue_pending_action(
        &guard.0,
        action,
        namespace,
        memory_id,
        requested_by,
        payload,
    )
    .expect("queue pending action")
}

/// A `Memory`-shaped `store` payload landing in `namespace`.
fn store_payload(namespace: &str) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "tier": "long",
        "namespace": namespace,
        "title": "governed write via federated pending",
        "content": "must never land outside the peer's namespace scope",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": now,
        "updated_at": now,
        // Must equal `requested_by` or `verify_payload_agent_id` refuses the
        // execute for an unrelated reason (S5-H4 approver laundering).
        "metadata": {"agent_id": PEER_ID},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

/// Build one `pendings[]` wire entry.
fn pending_entry(
    id: &str,
    action_type: &str,
    namespace: &str,
    memory_id: Option<&str>,
    payload: &Value,
) -> Value {
    json!({
        "id": id,
        "action_type": action_type,
        "memory_id": memory_id,
        "namespace": namespace,
        "payload": payload,
        "requested_by": PEER_ID,
        "requested_at": chrono::Utc::now().to_rfc3339(),
        "status": "pending",
        "decided_by": null,
        "decided_at": null,
        "approvals": []
    })
}

/// POST a `/sync/push` carrying the given governance subcollections.
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

fn approve(id: &str) -> Value {
    json!({ "id": id, "approved": true, "decider": APPROVER })
}

/// PRIMARY assertion surface: how many live rows in this namespace?
async fn count_ns(db: &ai_memory::handlers::Db, namespace: &str) -> i64 {
    let guard = db.lock().await;
    guard
        .0
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [namespace],
            |r| r.get(0),
        )
        .unwrap()
}

async fn row_exists(db: &ai_memory::handlers::Db, id: &str) -> bool {
    let guard = db.lock().await;
    let n: i64 = guard
        .0
        .query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap();
    n == 1
}

async fn pending_namespace(db: &ai_memory::handlers::Db, id: &str) -> String {
    let guard = db.lock().await;
    guard
        .0
        .query_row(
            "SELECT namespace FROM pending_actions WHERE id = ?1",
            [id],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default()
}

fn counter(report: &Value, key: &str) -> i64 {
    report.get(key).and_then(Value::as_i64).unwrap_or(-1)
}

// ---------------------------------------------------------------------
// R-203 #1 — the headline #2478 exploit: pendings + decisions in ONE push
// lands a row in a namespace the peer is explicitly denied.
//
// The IN-SCOPE `pa.namespace` with an OUT-OF-SCOPE payload namespace is
// deliberate: it is what makes a `pa.namespace`-only "fix" fail this cell.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exploit_pendings_plus_decisions_store_lands_foreign_namespace_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    let pid = uuid::Uuid::new_v4().to_string();
    let entry = pending_entry(
        &pid,
        "store",
        IN_SCOPE_NS, // in scope — the decoy
        None,
        &store_payload(VICTIM_NS), // out of scope — the actual write
    );
    let (status, report) = push_governance(&router, vec![entry], vec![approve(&pid)]).await;
    assert!(
        status.is_success(),
        "sync_push must not hard-error; got {status} {report}"
    );

    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        0,
        "#2478: a peer scoped to public/* must NOT land a row in {VICTIM_NS} by \
         pushing a pending whose declared namespace is in scope while its PAYLOAD \
         namespace is not. `execute_pending_action` never reads `pa.namespace` — it \
         inserts `payload.namespace` — so a gate on the declared field alone is \
         theatre and this assertion is what catches it"
    );
}

// ---------------------------------------------------------------------
// R-203 #2 — the TITLED lane, isolated: a push carrying ONLY
// `pending_decisions[]`, against a pending row this node minted itself.
//
// Gating only the `pendings[]` injection would leave this RED, which is why
// the cell exists (the issue's own acceptance criterion does not cover it).
// ---------------------------------------------------------------------

#[tokio::test]
async fn exploit_decisions_only_against_local_pending_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    let victim_id = seed_row(&router, VICTIM_NS, "decisions-only-delete-target").await;
    // A LOCAL operator queued this deletion; the peer merely approves it.
    let pid = seed_local_pending(
        &db,
        ai_memory::models::GovernedAction::Delete,
        VICTIM_NS,
        Some(&victim_id),
        "ai:local-requester",
        &json!({}),
    )
    .await;

    let (status, report) = push_governance(&router, vec![], vec![approve(&pid)]).await;
    assert!(
        status.is_success(),
        "sync_push must not hard-error; got {status} {report}"
    );

    assert!(
        row_exists(&db, &victim_id).await,
        "#2478: a peer scoped to public/* must NOT be able to execute a \
         {VICTIM_NS} deletion by approving a pending row that already exists \
         locally. This push carries NO pendings[] at all, so a fix that only \
         gates the injection lane leaves the titled hole wide open"
    );
    assert_eq!(
        counter(&report, "deleted"),
        0,
        "#2478: nothing was destroyed, so the envelope must not claim otherwise"
    );
}

// ---------------------------------------------------------------------
// R-203 #3 — the delete arm reaching an out-of-scope row BY ID while the
// pending's declared namespace is in scope.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exploit_delete_arm_by_id_escapes_declared_namespace_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    let victim_id = seed_row(&router, VICTIM_NS, "by-id-delete-target").await;
    let pid = uuid::Uuid::new_v4().to_string();
    let entry = pending_entry(
        &pid,
        "delete",
        IN_SCOPE_NS, // in scope — the decoy
        Some(&victim_id),
        &json!({}),
    );

    let (status, _report) = push_governance(&router, vec![entry], vec![approve(&pid)]).await;
    assert!(status.is_success());

    assert!(
        row_exists(&db, &victim_id).await,
        "#2478: `execute_pending_action`'s delete arm hard-DELETEs `pa.memory_id` \
         with no reference to any namespace, so the target row's STORED namespace \
         must be resolved and refused — an in-scope `pa.namespace` must not launder \
         an out-of-scope target"
    );
}

// ---------------------------------------------------------------------
// R-203 #4 — the promote arm CLONING into an out-of-scope destination.
// `promote_to_namespace` requires an ancestor, so the escape is upward:
// the peer may act on the leaf but not on its parent.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exploit_promote_arm_clones_into_out_of_scope_ancestor_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST_DEEP), None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    let leaf_id = seed_row(&router, "public/deep/x", "promote-source").await;
    let pid = uuid::Uuid::new_v4().to_string();
    let entry = pending_entry(
        &pid,
        "promote",
        "public/deep/x", // in scope
        Some(&leaf_id),
        &json!({ "to_namespace": "public/deep" }), // NOT in scope
    );

    let (status, _report) = push_governance(&router, vec![entry], vec![approve(&pid)]).await;
    assert!(status.is_success());

    assert_eq!(
        count_ns(&db, "public/deep").await,
        0,
        "#2478: the promote arm CLONES the row into `payload.to_namespace`, so the \
         DESTINATION is a write and must be in the peer's scope. The issue text \
         named only 'the target row's stored namespace' for this arm — that is \
         under-specified and this cell is why"
    );
}

// ---------------------------------------------------------------------
// R-203 #5 — the `pendings[]` upsert is ON CONFLICT(id) DO UPDATE over every
// column, so an in-scope claim can RELOCATE and overwrite a foreign
// governance row by id. The stored-namespace check is what closes it.
// ---------------------------------------------------------------------

#[tokio::test]
async fn exploit_pendings_upsert_cannot_clobber_foreign_pending_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    let pid = seed_local_pending(
        &db,
        ai_memory::models::GovernedAction::Store,
        VICTIM_NS,
        None,
        "ai:local-requester",
        &json!({"title": "original", "content": "original"}),
    )
    .await;

    // Same id, in-scope namespace: at parent this overwrites every column.
    let entry = pending_entry(
        &pid,
        "store",
        IN_SCOPE_NS,
        None,
        &store_payload(IN_SCOPE_NS),
    );
    let (status, _report) = push_governance(&router, vec![entry], vec![]).await;
    assert!(status.is_success());

    assert_eq!(
        pending_namespace(&db, &pid).await,
        VICTIM_NS,
        "#2478: `upsert_pending_action` is ON CONFLICT(id) DO UPDATE over every \
         column including `namespace`, so a claimed-only gate would let a public/* \
         peer relocate and overwrite a {VICTIM_NS} governance row by id — the same \
         merge-clobber vector Layer 1's stored-namespace check closes for memories[]"
    );
}

// ---------------------------------------------------------------------
// CONTROL A — the enrolled-SCOPED peer, IN scope, both directions.
// Green at parent AND after the fix: this is the availability guard that
// proves the gate refuses the exploit rather than the lane.
// ---------------------------------------------------------------------

#[tokio::test]
async fn control_enrolled_scoped_peer_in_scope_pair_applies_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST_WITH_VICTIM), None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    // Direction 1 — a STORE into a namespace the peer legitimately holds.
    let pid = uuid::Uuid::new_v4().to_string();
    let entry = pending_entry(&pid, "store", VICTIM_NS, None, &store_payload(VICTIM_NS));
    let (status, report) = push_governance(&router, vec![entry], vec![approve(&pid)]).await;
    assert!(status.is_success(), "{report}");
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        1,
        "#2478 CONTROL: an IN-SCOPE federated pending+decision pair must still \
         apply — the gate must refuse the exploit, not the lane. Report: {report}"
    );

    // Direction 2 — a DELETE of a row in that same in-scope namespace.
    let victim_id = seed_row(&router, VICTIM_NS, "in-scope-delete-target").await;
    let pid2 = uuid::Uuid::new_v4().to_string();
    let entry2 = pending_entry(&pid2, "delete", VICTIM_NS, Some(&victim_id), &json!({}));
    let (status2, report2) = push_governance(&router, vec![entry2], vec![approve(&pid2)]).await;
    assert!(status2.is_success(), "{report2}");
    assert!(
        !row_exists(&db, &victim_id).await,
        "#2478 CONTROL: an IN-SCOPE federated pending-executed deletion must still \
         apply. Report: {report2}"
    );
}

// ---------------------------------------------------------------------
// CONTROL B — ZERO-CONFIG availability guard. With no allowlist the whole
// gate short-circuits and replication is byte-identical to pre-#2478.
// This is the #2491 lesson pinned: a gate that runs unconditionally is a
// silent replication outage.
// ---------------------------------------------------------------------

#[tokio::test]
async fn control_zero_config_pendings_decisions_apply_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(None, None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    let pid = uuid::Uuid::new_v4().to_string();
    let entry = pending_entry(&pid, "store", VICTIM_NS, None, &store_payload(VICTIM_NS));
    let (status, report) = push_governance(&router, vec![entry], vec![approve(&pid)]).await;
    assert!(status.is_success(), "{report}");
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        1,
        "#2478 ZERO-CONFIG: with no AI_MEMORY_FED_PEER_ATTESTATION configured the \
         governance lanes must be byte-identical to pre-#2478. Refusing here would \
         be the #2491 silent-outage class in a new lane. Report: {report}"
    );
    assert_eq!(
        counter(&report, "pending_decisions_applied"),
        1,
        "#2478 ZERO-CONFIG: the decision must be counted as applied"
    );
}

// ---------------------------------------------------------------------
// R-203 #6 — counter honesty. A pending-executed hard DELETE incremented NO
// destructive counter, so the destruction was invisible in the 200.
// ---------------------------------------------------------------------

#[tokio::test]
async fn pending_executed_delete_is_visible_in_the_report_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(None, None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    let victim_id = seed_row(&router, VICTIM_NS, "counter-honesty-target").await;
    let pid = uuid::Uuid::new_v4().to_string();
    let entry = pending_entry(&pid, "delete", VICTIM_NS, Some(&victim_id), &json!({}));
    let (status, report) = push_governance(&router, vec![entry], vec![approve(&pid)]).await;
    assert!(status.is_success(), "{report}");

    assert!(
        !row_exists(&db, &victim_id).await,
        "precondition: the zero-config delete must actually execute. Report: {report}"
    );
    assert_eq!(
        counter(&report, "deleted"),
        1,
        "#2478: a row hard-DELETEd by an approved federated pending action must be \
         counted in the 200 envelope. Reporting 0 while destroying a row is the \
         invisible-delete half of #2478. Report: {report}"
    );
}

// ---------------------------------------------------------------------
// R-203 #7 — a refusal must be VISIBLE. `skipped` is what demotes the
// sender's 2xx to a non-ack (#2341), so a silent 0 would be the #2491 class.
// ---------------------------------------------------------------------

#[tokio::test]
async fn refused_pending_decision_is_reported_as_skipped_2478() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();
    register_approver(&db).await;

    let victim_id = seed_row(&router, VICTIM_NS, "refusal-visibility-target").await;
    let pid = seed_local_pending(
        &db,
        ai_memory::models::GovernedAction::Delete,
        VICTIM_NS,
        Some(&victim_id),
        "ai:local-requester",
        &json!({}),
    )
    .await;

    let (status, report) = push_governance(&router, vec![], vec![approve(&pid)]).await;
    assert!(status.is_success());
    assert_eq!(
        counter(&report, "pending_decisions_applied"),
        0,
        "#2478: a refused decision must not be counted as applied. Report: {report}"
    );
    assert!(
        counter(&report, "skipped") >= 1,
        "#2478: the refusal must be visible to the sender — `skipped > 0` is what \
         demotes the peer's 2xx to a non-ack (#2341). Report: {report}"
    );
}
