// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2710 (CB-5) + #2720 (CB-8/CB-9) — the federated pending-action receive lane
//! must not let a peer stuff the local approval quorum on a fresh insert, forge
//! the signed audit trail with an arbitrary REJECT decider, or overwrite a
//! still-pending row a LOCAL operator authored.
//!
//! - CB-5 / CB-9 F-6: a wire `pendings[]` FRESH insert drops caller-supplied
//!   `approvals[]` / `decided_by` / `decided_at` — approvals converge locally
//!   via `pending_decisions[]`, never verbatim from the wire.
//! - CB-8 F-12: a REJECT rebinds an unauthorized wire `decider` to the attested
//!   peer, so `pending_actions.decided_by` + the signed `pending_action.denied`
//!   audit row record the real actor.
//! - CB-9 F-7: an `ON CONFLICT` body-field UPDATE lands only on a row the
//!   inbound author already owns (`requested_by` bound), so a peer cannot
//!   bait-and-switch a local operator's queued action (`store` -> `delete`).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::models::{Approval, PendingAction};

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const PEER_ID: &str = "ai:peer-2710";
const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";

struct PostureGuard;
impl Drop for PostureGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
            std::env::remove_var(REQUIRE_ATTEST_ENV);
            std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
            std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
            std::env::remove_var(ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
            std::env::remove_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            );
        }
    }
}

fn clear_and_zero_config() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
        std::env::remove_var(ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

/// Enrolled posture: peer may author/decide ONLY as itself, scoped to
/// `public/**` (so it is NOT authorized to decide as any operator id).
fn set_enrolled_self_only() {
    let map = json!({
        PEER_ID: {
            "allowed_sender_agent_ids": [PEER_ID],
            "allowed_namespaces": ["public/**"]
        }
    });
    unsafe {
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            map.to_string(),
        );
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
        std::env::remove_var(ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
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

async fn push(router: &axum::Router, body: Value) -> (StatusCode, Value) {
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

fn push_body(pendings: Vec<Value>, pending_decisions: Vec<Value>) -> Value {
    json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "pendings": Value::Array(pendings),
        "pending_decisions": Value::Array(pending_decisions),
        "dry_run": false,
    })
}

// ---- CB-5 / CB-9 F-6 (fresh-insert quorum stuffing) — pure SQL funnel --------

#[test]
fn upsert_fresh_insert_drops_wire_approvals_2710() {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    // A hostile FRESH pending pre-stuffed with a full approval quorum plus a
    // forged terminal-decider stamp. `status` stays "pending" (the wire loop
    // refuses any other), but every DECISION column is attacker-chosen.
    let pa = PendingAction {
        id: "pa-2710-fresh".into(),
        action_type: "delete".into(),
        memory_id: Some("victim-mem".into()),
        namespace: "secure/ops".into(),
        payload: json!({}),
        requested_by: PEER_ID.into(),
        requested_at: chrono::Utc::now().to_rfc3339(),
        status: "pending".into(),
        decided_by: Some("ai:forged-operator".into()),
        decided_at: Some(chrono::Utc::now().to_rfc3339()),
        approvals: vec![
            Approval {
                agent_id: "ai:stuffed-a".into(),
                approved_at: chrono::Utc::now().to_rfc3339(),
            },
            Approval {
                agent_id: "ai:stuffed-b".into(),
                approved_at: chrono::Utc::now().to_rfc3339(),
            },
        ],
    };
    ai_memory::db::upsert_pending_action(&conn, &pa).unwrap();

    let got = ai_memory::db::get_pending_action(&conn, "pa-2710-fresh")
        .unwrap()
        .expect("row landed");
    assert_eq!(got.status, "pending");
    assert!(
        got.approvals.is_empty(),
        "#2710 CB-5: wire-stuffed approvals[] must be dropped on the fresh insert"
    );
    assert!(
        got.decided_by.is_none(),
        "#2710 CB-9 F-6: wire decided_by must be forced NULL on the fresh insert"
    );
    assert!(
        got.decided_at.is_none(),
        "#2710 CB-9 F-6: wire decided_at must be forced NULL on the fresh insert"
    );
}

#[tokio::test]
async fn federated_fresh_pending_drops_stuffed_approvals_2710() {
    let _lock = ENV_LOCK.lock().await;
    let _g = PostureGuard;
    clear_and_zero_config();
    let (router, db) = build_router_with_db();

    let wire = json!({
        "id": "pa-2710-e2e",
        "action_type": "delete",
        "memory_id": "victim-mem",
        "namespace": "public/ok",
        "payload": {},
        "requested_by": PEER_ID,
        "requested_at": chrono::Utc::now().to_rfc3339(),
        "status": "pending",
        "decided_by": "ai:forged-operator",
        "decided_at": chrono::Utc::now().to_rfc3339(),
        "approvals": [
            {"agent_id": "ai:stuffed-a", "approved_at": chrono::Utc::now().to_rfc3339()},
            {"agent_id": "ai:stuffed-b", "approved_at": chrono::Utc::now().to_rfc3339()}
        ]
    });
    let (st, report) = push(&router, push_body(vec![wire], vec![])).await;
    assert_eq!(st, StatusCode::OK, "{report}");
    assert_eq!(
        report["pendings_applied"].as_u64().unwrap_or(0),
        1,
        "fresh pending must still apply: {report}"
    );

    let guard = db.lock().await;
    let row = ai_memory::db::get_pending_action(&guard.0, "pa-2710-e2e")
        .unwrap()
        .expect("landed");
    assert_eq!(row.status, "pending");
    assert!(
        row.approvals.is_empty(),
        "#2710 CB-5: peer-stuffed approvals[] dropped end-to-end"
    );
    assert!(row.decided_by.is_none(), "#2710 CB-9 F-6: decided_by NULL");
}

// ---- CB-9 F-7 (pending-row bait-and-switch) — pure SQL funnel ----------------

#[test]
fn upsert_conflict_bound_to_original_author_2720_f7() {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    // A LOCAL operator queues a `store` pending.
    ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Store,
        "public/ok",
        None,
        "ai:local-operator",
        &json!({"title": "orig", "content": "orig"}),
    )
    .unwrap();
    let local = ai_memory::db::list_pending_actions(&conn, Some("pending"), 10).unwrap();
    let id = local[0].id.clone();

    // A peer (authorized only to author as itself) tries to take the row over
    // and swap `store` -> `delete` before a human approves it.
    let hijack = PendingAction {
        id: id.clone(),
        action_type: "delete".into(),
        memory_id: Some("victim-mem".into()),
        namespace: "public/ok".into(),
        payload: json!({"title": "evil", "content": "evil"}),
        requested_by: PEER_ID.into(),
        requested_at: chrono::Utc::now().to_rfc3339(),
        status: "pending".into(),
        decided_by: None,
        decided_at: None,
        approvals: vec![],
    };
    ai_memory::db::upsert_pending_action(&conn, &hijack).unwrap();

    let got = ai_memory::db::get_pending_action(&conn, &id)
        .unwrap()
        .expect("row survives");
    assert_eq!(
        got.action_type, "store",
        "#2720 F-7: a peer must not swap a local operator's action_type"
    );
    assert_eq!(
        got.requested_by, "ai:local-operator",
        "#2720 F-7: the original author is preserved"
    );
    assert_eq!(
        got.payload["title"], "orig",
        "#2720 F-7: the payload must not be clobbered by a differently-authored peer"
    );
}

#[test]
fn upsert_conflict_same_author_still_converges_2710() {
    // Regression control: the legitimate re-push of an originator's OWN
    // still-pending row (identical `requested_by`) still converges the body.
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let mut pa = PendingAction {
        id: "pa-2710-conv".into(),
        action_type: "store".into(),
        memory_id: None,
        namespace: "public/ok".into(),
        payload: json!({"title": "v1", "content": "v1"}),
        requested_by: PEER_ID.into(),
        requested_at: chrono::Utc::now().to_rfc3339(),
        status: "pending".into(),
        decided_by: None,
        decided_at: None,
        approvals: vec![],
    };
    ai_memory::db::upsert_pending_action(&conn, &pa).unwrap();
    pa.payload = json!({"title": "v2", "content": "v2"});
    pa.requested_at = chrono::Utc::now().to_rfc3339();
    ai_memory::db::upsert_pending_action(&conn, &pa).unwrap();
    let got = ai_memory::db::get_pending_action(&conn, "pa-2710-conv")
        .unwrap()
        .unwrap();
    assert_eq!(
        got.payload["title"], "v2",
        "same-author re-push must still converge the body"
    );
}

// ---- CB-8 F-12 (forged REJECT decider) — end-to-end via /sync/push -----------

#[tokio::test]
async fn federated_reject_rebinds_forged_decider_2720() {
    let _lock = ENV_LOCK.lock().await;
    let _g = PostureGuard;
    set_enrolled_self_only();
    let (router, db) = build_router_with_db();

    // Seed a local still-pending row (the peer legitimately queued it).
    {
        let guard = db.lock().await;
        let pa = PendingAction {
            id: "pa-2720-rej".into(),
            action_type: "store".into(),
            memory_id: None,
            namespace: "public/ok".into(),
            payload: json!({"title": "t", "content": "c", "namespace": "public/ok"}),
            requested_by: PEER_ID.into(),
            requested_at: chrono::Utc::now().to_rfc3339(),
            status: "pending".into(),
            decided_by: None,
            decided_at: None,
            approvals: vec![],
        };
        ai_memory::db::upsert_pending_action(&guard.0, &pa).unwrap();
    }

    // The peer REJECTs, forging the decider as a real operator id it is NOT
    // authorized to author as.
    let dec = json!({
        "id": "pa-2720-rej",
        "approved": false,
        "decider": "ai:victim-operator"
    });
    let (st, report) = push(&router, push_body(vec![], vec![dec])).await;
    assert_eq!(st, StatusCode::OK, "{report}");

    let guard = db.lock().await;
    let row = ai_memory::db::get_pending_action(&guard.0, "pa-2720-rej")
        .unwrap()
        .expect("row survives");
    assert_eq!(
        row.status, "rejected",
        "the reject still converges: {report}"
    );
    assert_eq!(
        row.decided_by.as_deref(),
        Some(PEER_ID),
        "#2720 F-12: the forged decider must be rebound to the attested peer, \
         not stamped verbatim into the signed audit trail"
    );
    assert_ne!(
        row.decided_by.as_deref(),
        Some("ai:victim-operator"),
        "#2720 F-12: the wire-forged operator id must never be recorded"
    );
}

#[tokio::test]
async fn federated_reject_converges_zero_config_2720() {
    // Control: zero-config (faith-based) reject still converges — no regression
    // to legitimate reject propagation on an unenrolled mesh.
    let _lock = ENV_LOCK.lock().await;
    let _g = PostureGuard;
    clear_and_zero_config();
    let (router, db) = build_router_with_db();

    {
        let guard = db.lock().await;
        let pa = PendingAction {
            id: "pa-2720-zc".into(),
            action_type: "store".into(),
            memory_id: None,
            namespace: "public/ok".into(),
            payload: json!({"title": "t", "content": "c"}),
            requested_by: PEER_ID.into(),
            requested_at: chrono::Utc::now().to_rfc3339(),
            status: "pending".into(),
            decided_by: None,
            decided_at: None,
            approvals: vec![],
        };
        ai_memory::db::upsert_pending_action(&guard.0, &pa).unwrap();
    }

    let dec = json!({"id": "pa-2720-zc", "approved": false, "decider": PEER_ID});
    let (st, report) = push(&router, push_body(vec![], vec![dec])).await;
    assert_eq!(st, StatusCode::OK, "{report}");
    let guard = db.lock().await;
    let row = ai_memory::db::get_pending_action(&guard.0, "pa-2720-zc")
        .unwrap()
        .expect("row survives");
    assert_eq!(
        row.status, "rejected",
        "zero-config reject converges: {report}"
    );
}
