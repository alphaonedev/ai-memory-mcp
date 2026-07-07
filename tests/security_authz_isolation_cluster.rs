// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! Adversarial end-to-end regressions for the v0.9.0 authz / tenant-
//! isolation security cluster (#1918):
//!
//! - **#1919** — `POST /api/v1/memories/bulk` must enforce the SAME
//!   required-agent-attestation gate (#1751) that single-create enforces:
//!   an unsigned batch under the required default is refused (403
//!   ATTESTATION_FAILED) and NOTHING lands.
//! - **#1922** — `GET /api/v1/search` must not let a caller-supplied
//!   `as_agent` drive team/unit/org visibility: an `as_agent` that
//!   disagrees with the authenticated caller is refused (403).
//! - **#1934** — federated `deletions[]` must be confined to the peer's
//!   per-peer `allowed_namespaces` scope: a peer scoped to `public/*`
//!   cannot hard-delete a `secure/ops` row.
//! - **#1920** — a hostile peer must not be able to forge a governance
//!   approval over `/sync/push`: a `pending_decisions[]` entry with an
//!   unregistered / self-asserted `decider` no longer approves+executes
//!   the pending action.
//!
//! Each test asserts the fix-forward behaviour (the exploit is BLOCKED).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex — several tests mutate process-wide env
/// vars (attestation-required, peer allowlist), so they must not race.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";

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
        std::sync::Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"),
        )
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
        llm: std::sync::Arc::new(None),
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
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db)
}

async fn post_json(
    router: &axum::Router,
    uri: &str,
    agent: Option<&str>,
    body: &Value,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(a) = agent {
        b = b.header(ai_memory::HEADER_AGENT_ID, a);
    }
    let req = b.body(Body::from(body.to_string())).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get(router: &axum::Router, uri: &str, agent: Option<&str>) -> (StatusCode, Value) {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(a) = agent {
        b = b.header(ai_memory::HEADER_AGENT_ID, a);
    }
    let req = b.body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn count_ns(db: &ai_memory::handlers::Db, ns: &str) -> i64 {
    let lock = db.lock().await;
    lock.0
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            rusqlite::params![ns],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
}

// ---------------------------------------------------------------------
// #1919 — bulk_create must enforce the required-attestation gate.
// ---------------------------------------------------------------------

#[tokio::test]
async fn bulk_create_unsigned_rejected_under_required_attestation_1919() {
    let _g = ENV_LOCK.lock().await;
    // Exploit precondition: required-attestation is on (the v0.9 default).
    unsafe { std::env::set_var(REQUIRE_ATTEST_ENV, "1") };
    let (router, db) = build_router_with_db();

    // Attacker POSTs an UNSIGNED batch with a self-asserted victim id.
    let body = json!([
        {
            "title": "forged-1",
            "content": "unsigned bulk row forging victim identity",
            "tier": "long",
            "namespace": "victim-ns-1919",
            "tags": [],
            "priority": 5,
            "source": "api"
        }
    ]);
    let (status, resp) =
        post_json(&router, "/api/v1/memories/bulk", Some("ai:curator"), &body).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#1919: unsigned bulk under required-attestation MUST 403; got {status}: {resp}"
    );
    assert_eq!(
        resp["code"], "ATTESTATION_FAILED",
        "#1919: refusal must carry the ATTESTATION_FAILED code; body={resp}"
    );
    // Fail-closed: NOTHING landed.
    assert_eq!(
        count_ns(&db, "victim-ns-1919").await,
        0,
        "#1919: no unsigned bulk row may persist when the batch is refused"
    );
    unsafe { std::env::remove_var(REQUIRE_ATTEST_ENV) };
}

#[tokio::test]
async fn bulk_create_unsigned_allowed_when_attestation_opted_out_1919() {
    let _g = ENV_LOCK.lock().await;
    // Legitimate behaviour preserved: with the explicit opt-out, unsigned
    // bulk still works (we must not break the permissive deployment).
    unsafe { std::env::set_var(REQUIRE_ATTEST_ENV, "0") };
    let (router, db) = build_router_with_db();

    let body = json!([
        {
            "title": "legit-1",
            "content": "unsigned bulk row, permissive deployment",
            "tier": "long",
            "namespace": "legit-ns-1919",
            "tags": [],
            "priority": 5,
            "source": "api"
        }
    ]);
    let (status, resp) =
        post_json(&router, "/api/v1/memories/bulk", Some("ai:writer"), &body).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "#1919: with attestation opted out, unsigned bulk must still succeed; got {status}: {resp}"
    );
    assert_eq!(
        count_ns(&db, "legit-ns-1919").await,
        1,
        "#1919: the legitimate permissive bulk row must land"
    );
    unsafe { std::env::remove_var(REQUIRE_ATTEST_ENV) };
}

// ---------------------------------------------------------------------
// #1922 — search must not honour a caller-supplied as_agent that
// disagrees with the authenticated caller.
// ---------------------------------------------------------------------

#[tokio::test]
async fn search_rejects_spoofed_as_agent_1922() {
    let _g = ENV_LOCK.lock().await;
    unsafe { std::env::remove_var(REQUIRE_ATTEST_ENV) };
    let (router, _db) = build_router_with_db();

    // EXPLOIT: attacker (own id "ai:attacker") drives team/unit/org
    // visibility off a victim's namespace via ?as_agent=.
    let (status, resp) = get(
        &router,
        "/api/v1/search?q=secret&as_agent=victimorg/victimunit/victimteam/x",
        Some("ai:attacker"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#1922: a caller-supplied as_agent that disagrees with the authenticated caller MUST 403; \
         got {status}: {resp}"
    );

    // Same, but with NO X-Agent-Id at all (the second, unauthenticated
    // channel the issue calls out): still refused.
    let (status_anon, _) = get(
        &router,
        "/api/v1/search?q=secret&as_agent=victimorg/victimunit/victimteam/x",
        None,
    )
    .await;
    assert_eq!(
        status_anon,
        StatusCode::FORBIDDEN,
        "#1922: anonymous caller supplying an attacker-chosen as_agent MUST 403 too"
    );

    // Control: a search WITHOUT as_agent is accepted (visibility binds to
    // the authenticated caller) — we did not break the legit path.
    let (status_ok, _) = get(&router, "/api/v1/search?q=secret", Some("ai:attacker")).await;
    assert_eq!(
        status_ok,
        StatusCode::OK,
        "#1922: a normal search with no as_agent must still succeed"
    );
}

// ---------------------------------------------------------------------
// #1934 — federated deletions confined to the peer's namespace scope.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_deletion_outside_peer_scope_refused_1934() {
    let _g = ENV_LOCK.lock().await;
    // Enrol a peer "ai:evil" scoped ONLY to public/*.
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            r#"{"ai:evil":{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["ai:evil"]}}"#,
        );
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
    }
    let (router, db) = build_router_with_db();

    // Seed a victim row in secure/ops via the normal create path.
    let create = json!({
        "title": "sensitive",
        "content": "secure ops row the peer has no scope for",
        "tier": "long",
        "namespace": "secure/ops",
        "tags": [],
        "priority": 5,
        "source": "api"
    });
    let (cstatus, cresp) = post_json(&router, "/api/v1/memories", Some("ai:victim"), &create).await;
    assert!(
        cstatus == StatusCode::OK || cstatus == StatusCode::CREATED,
        "seed create failed: {cstatus}: {cresp}"
    );
    let victim_id = cresp["id"].as_str().expect("created id").to_string();
    assert_eq!(count_ns(&db, "secure/ops").await, 1);

    // EXPLOIT: peer scoped to public/* pushes a deletion of the secure/ops id.
    let push = json!({
        "sender_agent_id": "ai:evil",
        "sender_clock": {"entries": {}},
        "memories": [],
        "deletions": [victim_id],
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            "ai:evil",
        )
        .body(Body::from(push.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let pstatus = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 64 * 1024).await;

    // The push is accepted (batch semantics) but the out-of-scope delete
    // is refused — the victim row SURVIVES.
    assert!(
        pstatus.is_success() || pstatus == StatusCode::OK,
        "#1934: sync_push should not hard-error; got {pstatus}"
    );
    assert_eq!(
        count_ns(&db, "secure/ops").await,
        1,
        "#1934: a peer scoped to public/* must NOT delete a secure/ops row"
    );

    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var(REQUIRE_ATTEST_ENV);
    }
}

// ---------------------------------------------------------------------
// #1920 — a hostile peer cannot forge a governance approval + execute.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_forged_approval_does_not_execute_1920() {
    let _g = ENV_LOCK.lock().await;
    // Zero-config federation posture (no allowlist) so the request passes
    // the TOFU / signature gates; the APPROVAL gate must still fire.
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
    }
    let (router, db) = build_router_with_db();

    // EXPLOIT: one push injects a Human-gated pending `store` AND a forged
    // approval for it with an attacker-chosen, unregistered decider.
    let pid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let payload = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "tier": "long",
        "namespace": "secure/gov1920",
        "title": "governed write",
        "content": "should never land via a forged federation approval",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": now,
        "updated_at": now,
        "metadata": {"agent_id": "victim"},
        "reflection_depth": 0,
        "memory_kind": "observation",
    });
    let push = json!({
        "sender_agent_id": "ai:hostile",
        "sender_clock": {"entries": {}},
        "memories": [],
        "pendings": [{
            "id": pid,
            "action_type": "store",
            "memory_id": null,
            "namespace": "secure/gov1920",
            "payload": payload,
            "requested_by": "victim",
            "requested_at": now,
            "status": "pending",
            "decided_by": null,
            "decided_at": null,
            "approvals": []
        }],
        "pending_decisions": [{
            "id": pid,
            "approved": true,
            "decider": "anyone"
        }],
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            "ai:hostile",
        )
        .body(Body::from(push.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let pstatus = resp.status();
    let _ = axum::body::to_bytes(resp.into_body(), 64 * 1024).await;
    assert!(
        pstatus.is_success(),
        "#1920: sync_push should not hard-error; got {pstatus}"
    );

    // The forged approval is refused by the hardened gate, so the pending
    // action's `store` side effect NEVER executed: no row in secure/gov1920.
    assert_eq!(
        count_ns(&db, "secure/gov1920").await,
        0,
        "#1920: a forged federation approval must NOT approve+execute a Human-gated pending action"
    );
    // And the pending row is still awaiting a legitimate human decision.
    let still_pending = {
        let lock = db.lock().await;
        lock.0
            .query_row(
                "SELECT status FROM pending_actions WHERE id = ?1",
                rusqlite::params![pid],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_default()
    };
    assert_eq!(
        still_pending, "pending",
        "#1920: the pending action must remain 'pending' after a forged approval"
    );

    unsafe {
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var(REQUIRE_ATTEST_ENV);
    }
}
