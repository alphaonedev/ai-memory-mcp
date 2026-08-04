// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2529 — federated `pendings[]` must not resurrect a locally-decided pending
//! or land a pre-decided wire row.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const PEER_ID: &str = "ai:peer-2529";
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

async fn push_pendings(router: &axum::Router, pendings: Vec<Value>) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "pendings": pendings,
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

fn pending_wire(id: &str, status: &str, approvals: &Value) -> Value {
    json!({
        "id": id,
        "action_type": "store",
        "memory_id": null,
        "namespace": "public/ok",
        "payload": {
            "title": "t",
            "content": "c",
            "namespace": "public/ok",
            "metadata": {"agent_id": PEER_ID}
        },
        "requested_by": PEER_ID,
        "requested_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "decided_by": if status == "pending" { Value::Null } else { json!("ai:local") },
        "decided_at": if status == "pending" {
            Value::Null
        } else {
            json!(chrono::Utc::now().to_rfc3339())
        },
        "approvals": approvals
    })
}

#[tokio::test]
async fn federated_pending_cannot_resurrect_rejected_row_2529() {
    let _lock = ENV_LOCK.lock().await;
    let _g = PostureGuard;
    clear_and_zero_config();
    let (router, db) = build_router_with_db();

    {
        let guard = db.lock().await;
        let pa = ai_memory::models::PendingAction {
            id: "pa-2529-rej".into(),
            action_type: "store".into(),
            memory_id: None,
            namespace: "public/ok".into(),
            payload: json!({
                "title": "orig",
                "content": "orig",
                "namespace": "public/ok",
                "metadata": {"agent_id": PEER_ID}
            }),
            requested_by: PEER_ID.into(),
            requested_at: chrono::Utc::now().to_rfc3339(),
            status: "pending".into(),
            decided_by: None,
            decided_at: None,
            approvals: vec![],
        };
        ai_memory::db::upsert_pending_action(&guard.0, &pa).unwrap();
        guard
            .0
            .execute(
                "UPDATE pending_actions SET status='rejected', decided_by='ai:local', \
                 decided_at=?1, approvals='[]' WHERE id=?2",
                rusqlite::params![chrono::Utc::now().to_rfc3339(), "pa-2529-rej"],
            )
            .unwrap();
    }

    let (st, report) = push_pendings(
        &router,
        vec![pending_wire(
            "pa-2529-rej",
            "pending",
            &json!([{"agent_id": "ai:attacker", "approved_at": chrono::Utc::now().to_rfc3339()}]),
        )],
    )
    .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "push should 200 with per-item skip: {report}"
    );
    assert_eq!(
        report["pendings_applied"].as_u64().unwrap_or(99),
        0,
        "resurrection must not apply: {report}"
    );
    assert!(
        report["skipped"].as_u64().unwrap_or(0) >= 1,
        "must skip: {report}"
    );

    let guard = db.lock().await;
    let row = ai_memory::db::get_pending_action(&guard.0, "pa-2529-rej")
        .unwrap()
        .expect("row survives");
    assert_eq!(row.status, "rejected", "status must stay decided");
    assert_eq!(row.decided_by.as_deref(), Some("ai:local"));
    assert!(
        row.approvals.is_empty(),
        "approvals must not be wire-clobbered"
    );
}

#[tokio::test]
async fn federated_pending_rejects_wire_non_pending_status_2529() {
    let _lock = ENV_LOCK.lock().await;
    let _g = PostureGuard;
    clear_and_zero_config();
    let (router, db) = build_router_with_db();

    let (st, report) = push_pendings(
        &router,
        vec![pending_wire("pa-2529-pre", "approved", &json!([]))],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(report["pendings_applied"].as_u64().unwrap_or(99), 0);

    let guard = db.lock().await;
    let row = ai_memory::db::get_pending_action(&guard.0, "pa-2529-pre").unwrap();
    assert!(row.is_none(), "pre-approved wire row must not land");
}

#[tokio::test]
async fn control_fresh_pending_still_applies_2529() {
    let _lock = ENV_LOCK.lock().await;
    let _g = PostureGuard;
    clear_and_zero_config();
    let (router, db) = build_router_with_db();

    let (st, report) = push_pendings(
        &router,
        vec![pending_wire("pa-2529-ok", "pending", &json!([]))],
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{report}");
    assert_eq!(
        report["pendings_applied"].as_u64().unwrap_or(0),
        1,
        "fresh pending must still apply: {report}"
    );
    let guard = db.lock().await;
    let row = ai_memory::db::get_pending_action(&guard.0, "pa-2529-ok")
        .unwrap()
        .expect("landed");
    assert_eq!(row.status, "pending");
}

#[test]
fn upsert_sql_does_not_clobber_decided_status_2529() {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let mut pa = ai_memory::models::PendingAction {
        id: "pa-sql-2529".into(),
        action_type: "store".into(),
        memory_id: None,
        namespace: "public/ok".into(),
        payload: json!({"title": "a", "content": "b"}),
        requested_by: "ai:x".into(),
        requested_at: chrono::Utc::now().to_rfc3339(),
        status: "pending".into(),
        decided_by: None,
        decided_at: None,
        approvals: vec![],
    };
    ai_memory::db::upsert_pending_action(&conn, &pa).unwrap();
    conn.execute(
        "UPDATE pending_actions SET status='rejected', decided_by='ai:local' WHERE id=?1",
        ["pa-sql-2529"],
    )
    .unwrap();
    pa.status = "pending".into();
    pa.decided_by = None;
    pa.payload = json!({"title": "evil", "content": "evil"});
    ai_memory::db::upsert_pending_action(&conn, &pa).unwrap();
    let got = ai_memory::db::get_pending_action(&conn, "pa-sql-2529")
        .unwrap()
        .unwrap();
    assert_eq!(got.status, "rejected");
    assert_eq!(got.decided_by.as_deref(), Some("ai:local"));
    assert_eq!(
        got.payload["title"], "a",
        "payload must not update on decided"
    );
}
