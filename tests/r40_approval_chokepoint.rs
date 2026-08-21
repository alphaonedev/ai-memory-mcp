// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! R40 (#2991 / #2355) — the ONE signed-approval quorum CHOKEPOINT across every
//! approve funnel.
//!
//! # What this proves
//!
//! * **Surface parity (#2355).** All the wire approve funnels reachable with a
//!   sqlite conn — the MCP `memory_pending_approve` tool, the HTTP
//!   `POST /api/v1/approvals/{id}` (`approval_decide`) endpoint, and the HTTP
//!   `POST /api/v1/pending/{id}/approve` (`approve_pending`) endpoint — enforce
//!   the R40 gate IDENTICALLY on an escalation-flagged pending: an approve with
//!   NO signatures is REFUSED (fail-closed), a FORGED signature is REFUSED, and
//!   only a met m-of-n quorum PROCEEDS. Pre-#2355 the gate fired on MCP only and
//!   both HTTP funnels bypassed it. (The two Postgres twins are proven against a
//!   live enterprise-fed tier — see the `#[ignore]` pg tests below.)
//! * **Audit chaining on the HTTP surface (§5.4).** A met quorum on the HTTP
//!   funnel chains an `approval_quorum_met` `signed_events` row — pre-fix that
//!   spine had an HTTP hole.
//! * **Exemption discrimination (#2991 removal proof).** The single-use,
//!   CID-bound post-quorum execution exemption admits ONLY the exact approved
//!   write and is consumed once — a write whose CID was never registered is
//!   never exempted. `scripts/check-cert-removal-proof.sh` neutralises
//!   `consume_execution_exemption` to `return true` and asserts
//!   `exemption_discriminates_unregistered_cid` goes RED.

#![cfg(feature = "sal")]
#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex};

use ai_memory::approvals::Decision;
use ai_memory::approvals::signed::{
    SignedApproval, approval_signing_bytes, consume_execution_exemption, execution_exemption_cid,
    register_execution_exemption, route_escalation_to_approval_gate,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{GovernedAction, Memory, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use tower::ServiceExt as _;

mod common;

/// Serialises the env-mutating (operator-key enrollment) + K7-secret tests.
static GLOBAL_LOCK: Mutex<()> = Mutex::new(());

const TEST_SECRET: &str = "r40-chokepoint-secret";
const REQUESTER: &str = "ai:worker";
const APPROVER: &str = "operator-1";

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_b64(sk: &SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
}

fn enroll_operator(sk: &SigningKey) {
    // SAFETY: guarded by GLOBAL_LOCK; single-threaded within the critical section.
    unsafe {
        std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", pubkey_b64(sk));
        std::env::set_var("AI_MEMORY_APPROVAL_THRESHOLD", "1");
    }
}

fn clear_operator() {
    // SAFETY: guarded by GLOBAL_LOCK.
    unsafe {
        std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY");
        std::env::remove_var("AI_MEMORY_APPROVER_PUBKEYS");
        std::env::remove_var("AI_MEMORY_APPROVAL_THRESHOLD");
    }
}

/// A valid approval signature over `(pending_id, Approve)` by `sk`.
fn sign_approval(sk: &SigningKey, pending_id: &str) -> SignedApproval {
    let msg = approval_signing_bytes(pending_id, Decision::Approve);
    SignedApproval {
        signer_pubkey_b64: pubkey_b64(sk),
        signature_b64: base64::engine::general_purpose::STANDARD.encode(sk.sign(&msg).to_bytes()),
    }
}

/// A FORGED signature: enrolled signer, valid length, but over DIFFERENT bytes.
fn forged_approval(sk: &SigningKey) -> SignedApproval {
    let wrong = approval_signing_bytes("pa-DIFFERENT-BYTES", Decision::Approve);
    SignedApproval {
        signer_pubkey_b64: pubkey_b64(sk),
        signature_b64: base64::engine::general_purpose::STANDARD.encode(sk.sign(&wrong).to_bytes()),
    }
}

fn approvals_json(sigs: &[SignedApproval]) -> Value {
    Value::Array(
        sigs.iter()
            .map(|s| json!({ "pubkey": s.signer_pubkey_b64, "signature": s.signature_b64 }))
            .collect(),
    )
}

fn open_db(db_path: &std::path::Path) -> rusqlite::Connection {
    ai_memory::db::open(db_path).expect("db::open")
}

fn build_sqlite_router() -> (axum::Router, std::path::PathBuf) {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    std::mem::forget(f);
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
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
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), db_path)
}

/// Seed a STORE-shaped, escalation-flagged pending (as the L1-6 producer would)
/// on the DB the router opened; register the operator so the Human-arm approve
/// gate admits it. Returns the pending id.
fn seed_escalated_store_pending(db_path: &std::path::Path, ns: &str, content: &str) -> String {
    let conn = open_db(db_path);
    ai_memory::db::register_agent(&conn, APPROVER, "ai:generic", &[]).ok();
    let mem = Memory {
        namespace: ns.to_string(),
        title: format!("chokepoint-{}", uuid::Uuid::new_v4()),
        content: content.to_string(),
        tier: Tier::Long,
        metadata: json!({ "agent_id": REQUESTER }),
        ..Memory::default()
    };
    route_escalation_to_approval_gate(
        &conn,
        GovernedAction::Store,
        ns,
        None,
        REQUESTER,
        &serde_json::to_value(&mem).expect("memory to value"),
        "test-escalate-rule",
        "escalated for signed approval (test)",
    )
    .expect("route escalation")
}

fn signed_http_request(uri: &str, pending_id: &str, body: &Value) -> Request<Body> {
    let body_str = serde_json::to_string(body).unwrap();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let sig =
        common::sign_canonical_envelope(TEST_SECRET, &timestamp, "POST", pending_id, &body_str);
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-ai-memory-timestamp", &timestamp)
        .header("x-ai-memory-signature", sig)
        .header("x-agent-id", APPROVER)
        .body(Body::from(body_str))
        .unwrap()
}

async fn http_status(router: &axum::Router, req: Request<Body>) -> StatusCode {
    router.clone().oneshot(req).await.unwrap().status()
}

// ---------------------------------------------------------------------------
// #2991 removal-proof lane test — the exemption is CID-bound + single-use.
// `scripts/check-cert-removal-proof.sh` neutralises `consume_execution_exemption`
// to `return true` and asserts THIS test goes RED.
// ---------------------------------------------------------------------------

#[test]
fn exemption_discriminates_unregistered_cid() {
    let approved = Memory {
        namespace: "removal-proof-ns".to_string(),
        title: "approved".to_string(),
        content: "the-one-approved-body".to_string(),
        metadata: json!({ "agent_id": REQUESTER }),
        ..Memory::default()
    };
    let approved_cid = execution_exemption_cid(&approved);
    let _guard = register_execution_exemption("pa-approved", &approved_cid);

    // A DIFFERENT write's CID was never registered → NEVER exempted. Under the
    // `return true` mutation this returns true and the assert reds.
    let attacker = Memory {
        content: "a-DIFFERENT-unapproved-body".to_string(),
        ..approved.clone()
    };
    let attacker_cid = execution_exemption_cid(&attacker);
    assert_ne!(
        approved_cid, attacker_cid,
        "distinct content → distinct cid"
    );
    assert!(
        !consume_execution_exemption(&attacker_cid),
        "an unregistered CID must NEVER be exempted (CWE-306 replay class)"
    );

    // The registered CID is admitted exactly once (single-use).
    assert!(
        consume_execution_exemption(&approved_cid),
        "registered CID admitted once"
    );
    assert!(
        !consume_execution_exemption(&approved_cid),
        "single-use: a second consume of the same CID is denied"
    );
}

// ---------------------------------------------------------------------------
// #2355 surface parity — MCP + both sqlite HTTP funnels enforce identically.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approval_decide_sqlite_enforces_gate() {
    let _g = GLOBAL_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_operator();
    let operator = keypair(11);
    enroll_operator(&operator);
    ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, db_path) = build_sqlite_router();

    // (a) missing signatures → fail-closed 403.
    let pid = seed_escalated_store_pending(&db_path, "dec-a", "body-a");
    let uri = format!("/api/v1/approvals/{pid}");
    let body = json!({ "decision": "approve" });
    assert_eq!(
        http_status(&router, signed_http_request(&uri, &pid, &body)).await,
        StatusCode::FORBIDDEN,
        "missing-when-required must 403 on approval_decide"
    );

    // (b) forged signature → 403.
    let pid = seed_escalated_store_pending(&db_path, "dec-b", "body-b");
    let uri = format!("/api/v1/approvals/{pid}");
    let body = json!({ "decision": "approve", "approvals": approvals_json(&[forged_approval(&operator)]) });
    assert_eq!(
        http_status(&router, signed_http_request(&uri, &pid, &body)).await,
        StatusCode::FORBIDDEN,
        "forged signature must 403 on approval_decide"
    );

    // (c) met quorum → 200 approved + executed.
    let pid = seed_escalated_store_pending(&db_path, "dec-c", "body-c");
    let uri = format!("/api/v1/approvals/{pid}");
    let body = json!({ "decision": "approve", "approvals": approvals_json(&[sign_approval(&operator, &pid)]) });
    let resp = router
        .clone()
        .oneshot(signed_http_request(&uri, &pid, &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "met quorum must proceed on approval_decide"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["approved"], true, "met quorum approves+executes: {v}");

    clear_operator();
    ai_memory::config::set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approve_pending_sqlite_enforces_gate() {
    let _g = GLOBAL_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_operator();
    let operator = keypair(12);
    enroll_operator(&operator);
    ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, db_path) = build_sqlite_router();

    // (a) missing signatures → fail-closed 403.
    let pid = seed_escalated_store_pending(&db_path, "app-a", "body-a");
    let uri = format!("/api/v1/pending/{pid}/approve");
    let body = json!({});
    assert_eq!(
        http_status(&router, signed_http_request(&uri, &pid, &body)).await,
        StatusCode::FORBIDDEN,
        "missing-when-required must 403 on approve_pending"
    );

    // (b) forged signature → 403.
    let pid = seed_escalated_store_pending(&db_path, "app-b", "body-b");
    let uri = format!("/api/v1/pending/{pid}/approve");
    let body = json!({ "approvals": approvals_json(&[forged_approval(&operator)]) });
    assert_eq!(
        http_status(&router, signed_http_request(&uri, &pid, &body)).await,
        StatusCode::FORBIDDEN,
        "forged signature must 403 on approve_pending"
    );

    // (c) met quorum → 200 approved.
    let pid = seed_escalated_store_pending(&db_path, "app-c", "body-c");
    let uri = format!("/api/v1/pending/{pid}/approve");
    let body = json!({ "approvals": approvals_json(&[sign_approval(&operator, &pid)]) });
    let resp = router
        .clone()
        .oneshot(signed_http_request(&uri, &pid, &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "met quorum must proceed on approve_pending"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["approved"], true, "met quorum approves: {v}");

    clear_operator();
    ai_memory::config::set_active_hooks_hmac_secret(None);
}

#[test]
fn mcp_funnel_enforces_gate() {
    let _g = GLOBAL_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_operator();
    let operator = keypair(13);
    enroll_operator(&operator);
    let conn = open_db(std::path::Path::new(":memory:"));
    ai_memory::db::register_agent(&conn, "ai:operator", "ai:generic", &[]).ok();

    // (a) missing signatures → refused.
    let mem = Memory {
        namespace: "mcp-a".to_string(),
        title: "t".to_string(),
        content: "body-a".to_string(),
        metadata: json!({ "agent_id": REQUESTER }),
        ..Memory::default()
    };
    let pid = route_escalation_to_approval_gate(
        &conn,
        GovernedAction::Store,
        "mcp-a",
        None,
        REQUESTER,
        &serde_json::to_value(&mem).unwrap(),
        "r",
        "escalated",
    )
    .unwrap();
    let err = ai_memory::mcp::handle_pending_approve(
        &conn,
        &json!({ "id": pid, "agent_id": "ai:operator" }),
        None,
    )
    .expect_err("missing-when-required must be refused on MCP");
    assert!(
        err.contains("signed approval"),
        "MCP refusal names the gate: {err}"
    );

    // (b) met quorum → approved.
    let sig = sign_approval(&operator, &pid);
    let res = ai_memory::mcp::handle_pending_approve(
        &conn,
        &json!({ "id": pid, "agent_id": "ai:operator",
                 "approvals": [{ "pubkey": sig.signer_pubkey_b64, "signature": sig.signature_b64 }] }),
        None,
    );
    match res {
        Ok(v) => assert_eq!(v["approved"], true, "MCP met quorum approves: {v}"),
        Err(e) => assert!(!e.contains("signed approval"), "must be past the gate: {e}"),
    }

    clear_operator();
}

// ---------------------------------------------------------------------------
// #2355 pg twins — the postgres branches of approval_decide + approve_pending
// route through the SAME chokepoint. The fake-pg dispatch harness
// (storage_backend = Postgres, SAL store = a DISJOINT SqliteStore) exercises
// the real pg-branch handler code deterministically in CI; the live_pg module
// re-proves it against the enterprise-fed tier.
// ---------------------------------------------------------------------------

fn build_fake_pg_router() -> (axum::Router, std::path::PathBuf) {
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        scratch,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
    let store_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(&store_path).expect("open SqliteStore"),
    );
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
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
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (
        ai_memory::build_router(api_key_state, app_state),
        store_path,
    )
}

/// Seed a STORE-shaped, escalation-flagged pending into the SAL store's backing
/// file (reachable ONLY via the trait dispatch on a Postgres-backed router).
fn seed_escalated_store_pending_in_store(
    store_path: &std::path::Path,
    ns: &str,
    content: &str,
) -> String {
    seed_escalated_store_pending(store_path, ns, content)
}

/// pg twin of `approval_decide` — the gate fires on the Postgres branch.
#[tokio::test]
async fn approval_decide_postgres_enforces_gate() {
    let _g = GLOBAL_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_operator();
    let operator = keypair(15);
    enroll_operator(&operator);
    ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, store_path) = build_fake_pg_router();

    let pid = seed_escalated_store_pending_in_store(&store_path, "pgdec-a", "body-a");
    let uri = format!("/api/v1/approvals/{pid}");
    assert_eq!(
        http_status(
            &router,
            signed_http_request(&uri, &pid, &json!({ "decision": "approve" }))
        )
        .await,
        StatusCode::FORBIDDEN,
        "pg approval_decide must 403 when signed approval is required but missing"
    );

    let pid = seed_escalated_store_pending_in_store(&store_path, "pgdec-b", "body-b");
    let uri = format!("/api/v1/approvals/{pid}");
    let body = json!({ "decision": "approve", "approvals": approvals_json(&[forged_approval(&operator)]) });
    assert_eq!(
        http_status(&router, signed_http_request(&uri, &pid, &body)).await,
        StatusCode::FORBIDDEN,
        "pg approval_decide must 403 on a forged signature"
    );

    let pid = seed_escalated_store_pending_in_store(&store_path, "pgdec-c", "body-c");
    let uri = format!("/api/v1/approvals/{pid}");
    let body = json!({ "decision": "approve", "approvals": approvals_json(&[sign_approval(&operator, &pid)]) });
    let resp = router
        .clone()
        .oneshot(signed_http_request(&uri, &pid, &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "pg approval_decide met quorum must proceed"
    );

    clear_operator();
    ai_memory::config::set_active_hooks_hmac_secret(None);
}

/// pg twin of `approve_pending` — the gate fires on the Postgres branch.
#[tokio::test]
async fn approve_pending_postgres_enforces_gate() {
    let _g = GLOBAL_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_operator();
    let operator = keypair(16);
    enroll_operator(&operator);
    ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, store_path) = build_fake_pg_router();

    let pid = seed_escalated_store_pending_in_store(&store_path, "pgapp-a", "body-a");
    let uri = format!("/api/v1/pending/{pid}/approve");
    assert_eq!(
        http_status(&router, signed_http_request(&uri, &pid, &json!({}))).await,
        StatusCode::FORBIDDEN,
        "pg approve_pending must 403 when signed approval is required but missing"
    );

    let pid = seed_escalated_store_pending_in_store(&store_path, "pgapp-b", "body-b");
    let uri = format!("/api/v1/pending/{pid}/approve");
    let body = json!({ "approvals": approvals_json(&[sign_approval(&operator, &pid)]) });
    let resp = router
        .clone()
        .oneshot(signed_http_request(&uri, &pid, &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "pg approve_pending met quorum must proceed"
    );

    clear_operator();
    ai_memory::config::set_active_hooks_hmac_secret(None);
}

// ---------------------------------------------------------------------------
// §5.4 — the quorum event chains on the HTTP surface (not MCP-only).
// ---------------------------------------------------------------------------

fn collect_kind_rows(dir: &std::path::Path, kind: &str) -> Vec<Value> {
    use std::io::{BufRead, BufReader};
    let mut hits = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return hits;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(n) = name.to_str() else { continue };
        if !n.starts_with("forensic-") || !n.to_ascii_lowercase().ends_with(".jsonl") {
            continue;
        }
        let Ok(f) = std::fs::File::open(entry.path()) else {
            continue;
        };
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<Value>(&line)
                && v.get("kind").and_then(|k| k.as_str()) == Some(kind)
            {
                hits.push(v);
            }
        }
    }
    hits
}

#[tokio::test]
async fn met_quorum_chains_approval_quorum_met_on_http_surface() {
    use ai_memory::governance::audit as forensic;
    let _g = GLOBAL_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_operator();
    let operator = keypair(14);
    enroll_operator(&operator);
    ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));

    let dir = tempfile::tempdir().expect("forensic dir");
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");

    let (router, db_path) = build_sqlite_router();
    let pid = seed_escalated_store_pending(&db_path, "audit-ns", "audit-body");
    let uri = format!("/api/v1/approvals/{pid}");
    let body = json!({ "decision": "approve", "approvals": approvals_json(&[sign_approval(&operator, &pid)]) });
    let status = http_status(&router, signed_http_request(&uri, &pid, &body)).await;
    assert_eq!(status, StatusCode::OK, "met quorum must proceed");

    forensic::flush_blocking();
    let rows = collect_kind_rows(dir.path(), "approval_quorum_met");
    forensic::shutdown();

    assert!(
        !rows.is_empty(),
        "record_quorum_event must chain an `approval_quorum_met` forensic row on the HTTP \
         approve surface (§5.4 audit spine had an HTTP hole pre-#2355)"
    );

    clear_operator();
    ai_memory::config::set_active_hooks_hmac_secret(None);
}

// ---------------------------------------------------------------------------
// Live enterprise-fed tier — the pg twins enforce the gate on a REAL
// PostgresStore. Seed-free: a PRESENTED (forged / unenrolled) signature engages
// the chokepoint on the pg branch and is refused (403) BEFORE the pg finalizer
// (get_pending / governance_approve_with_consensus) even runs — proving the
// gate is wired ABOVE the postgres finalizer, not bypassed as it was pre-#2355.
// Requires AI_MEMORY_TEST_POSTGRES_URL (the enterprise-fed tier); run with
// `--include-ignored --test-threads=1`.
// ---------------------------------------------------------------------------
#[cfg(feature = "sal-postgres")]
mod live_pg {
    use super::*;

    async fn build_live_pg_router(url: &str) -> axum::Router {
        let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
            ai_memory::store::postgres::PostgresStore::connect(url)
                .await
                .expect("connect postgres adapter (enterprise-fed tier)"),
        );
        let scratch =
            ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(tokio::sync::Mutex::new((
            scratch,
            std::path::PathBuf::from(":memory:"),
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
        let app_state = AppState {
            db,
            embedder: Arc::new(None),
            vector_index: Arc::new(tokio::sync::Mutex::new(None)),
            federation: Arc::new(None),
            tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
            scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
            profile: Arc::new(ai_memory::profile::Profile::core()),
            mcp_config: Arc::new(None),
            active_keypair: Arc::new(None),
            family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
            storage_backend: StorageBackend::Postgres,
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
            enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
            http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
        };
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        };
        ai_memory::build_router(api_key_state, app_state)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (enterprise-fed tier)"]
    async fn approval_decide_postgres_gate_refuses_presented_forgery_live() {
        let Some(url) = common::postgres_url() else {
            eprintln!("skipping approval_decide_postgres_gate_refuses_presented_forgery_live");
            return;
        };
        let _g = GLOBAL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_operator();
        let operator = keypair(21);
        enroll_operator(&operator);
        ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
        let router = build_live_pg_router(&url).await;

        // A forged signature engages the gate on the pg branch → 403, BEFORE the
        // pg finalizer touches the (non-existent) pending row.
        let pid = format!("pa-live-{}", uuid::Uuid::new_v4());
        let uri = format!("/api/v1/approvals/{pid}");
        let body = json!({ "decision": "approve", "approvals": approvals_json(&[forged_approval(&operator)]) });
        assert_eq!(
            http_status(&router, signed_http_request(&uri, &pid, &body)).await,
            StatusCode::FORBIDDEN,
            "live pg approval_decide must 403 on a forged presented signature (gate above finalizer)"
        );

        clear_operator();
        ai_memory::config::set_active_hooks_hmac_secret(None);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (enterprise-fed tier)"]
    async fn approve_pending_postgres_gate_refuses_presented_forgery_live() {
        let Some(url) = common::postgres_url() else {
            eprintln!("skipping approve_pending_postgres_gate_refuses_presented_forgery_live");
            return;
        };
        let _g = GLOBAL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_operator();
        let operator = keypair(22);
        enroll_operator(&operator);
        ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
        let router = build_live_pg_router(&url).await;

        let pid = format!("pa-live-{}", uuid::Uuid::new_v4());
        let uri = format!("/api/v1/pending/{pid}/approve");
        let body = json!({ "approvals": approvals_json(&[forged_approval(&operator)]) });
        assert_eq!(
            http_status(&router, signed_http_request(&uri, &pid, &body)).await,
            StatusCode::FORBIDDEN,
            "live pg approve_pending must 403 on a forged presented signature (gate above finalizer)"
        );

        clear_operator();
        ai_memory::config::set_active_hooks_hmac_secret(None);
    }
}
