// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #2634 / cert-blocker CB-24 — the governance-audit-verdict class.
//!
//! The tamper-evident governance audit chain recorded `decision="allow"`
//! BEFORE the gate that can refuse a governed action ran, so a REFUSED
//! action was chained as ALLOWED (or, for `clear_namespace_standard`,
//! not chained at all). No surface could record a DENY. These tests pin
//! the fix: each surface now records the TRUE verdict —
//!
//! * `namespace_set_standard`  — refused bind → `refuse`, allowed → `allow`.
//! * `namespace_clear_standard` — refused clear → `refuse` (previously NO
//!   row at all), allowed → `allow`.
//! * `pending_approve` (MCP)    — refused approval → `refuse`, allowed →
//!   `allow`.
//! * `approve_pending` (HTTP, `src/handlers/governance.rs`) — self-approval
//!   refusal (#2643) → `refuse`.
//! * `approval_decide` (HTTP K10, `src/handlers/approvals.rs`) —
//!   self-approval refusal → `refuse`.
//!
//! The forensic sink is process-global; each `tests/*.rs` is its own
//! process, so a file-local mutex serialises the in-file tests and unique
//! namespaces / ids isolate the rows we assert on.

// `await_holding_lock` mirrors the sibling `admin_audit_chain_913.rs`
// suite: the std::sync::Mutex protects the process-global forensic SINK
// from cross-test races and is never awaited on.
#![allow(clippy::missing_panics_doc, clippy::await_holding_lock)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::governance::audit as forensic;
use serde_json::json;

fn forensic_lock() -> &'static Mutex<()> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn fresh_dir() -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2634-audit-verdict");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// The v1.0.0 store-path attestation default is REQUIRED on the HTTP-direct
/// surface; the MCP/CLI store fixtures here are unsigned. Pin the permissive
/// opt-out for this process (the required default is pinned elsewhere).
fn permissive_attestation() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write set before any store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

/// Collect the `decision` tokens of every forensic row of `kind` whose
/// `payload[id_field] == id_val` — scopes the assertion to this test's rows.
fn decisions_for(dir: &std::path::Path, kind: &str, id_field: &str, id_val: &str) -> Vec<String> {
    use std::io::{BufRead, BufReader};
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
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
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if v.get("kind").and_then(|k| k.as_str()) != Some(kind) {
                continue;
            }
            if v.get("payload")
                .and_then(|p| p.get(id_field))
                .and_then(|x| x.as_str())
                != Some(id_val)
            {
                continue;
            }
            if let Some(d) = v.get("decision").and_then(|d| d.as_str()) {
                out.push(d.to_string());
            }
        }
    }
    out
}

fn open_db() -> (rusqlite::Connection, tempfile::NamedTempFile) {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    (conn, f)
}

/// Seed a memory owned by `owner` (stamped into `metadata.agent_id`) via the
/// MCP store path. Returns its id.
fn seed_memory(
    conn: &rusqlite::Connection,
    db_path: &std::path::Path,
    namespace: &str,
    title: &str,
    owner: &str,
) -> String {
    permissive_attestation();
    let ttl = ResolvedTtl::default();
    let v = ai_memory::mcp::tools::handle_store_for_tests(
        conn,
        db_path,
        &json!({
            "tier": "long",
            "namespace": namespace,
            "title": title,
            "content": "2634 anchor",
            "priority": 5,
            "agent_id": owner,
        }),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        None,
    )
    .expect("seed memory store");
    v["id"].as_str().expect("seed id").to_string()
}

// -----------------------------------------------------------------------
// namespace_set_standard — the gate ran AFTER the "allow" record (pre-fix).
// -----------------------------------------------------------------------

#[test]
fn set_standard_refused_bind_records_refuse_not_allow() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");

    let (conn, f) = open_db();
    // A standard memory OWNED BY BOB — alice may not bind it.
    let std_id = seed_memory(
        &conn,
        f.path(),
        "ns-2634-set-refuse",
        "bob's standard",
        "owner-bob",
    );

    let res = ai_memory::mcp::handle_namespace_set_standard(
        &conn,
        &json!({
            "namespace": "ns-2634-set-refuse",
            "id": std_id,
            "agent_id": "caller-alice",
        }),
    );
    assert!(res.is_err(), "non-owner bind must be refused; got {res:?}");

    forensic::shutdown();
    let decisions = decisions_for(
        dir.path(),
        "namespace_set_standard",
        "namespace",
        "ns-2634-set-refuse",
    );
    assert!(
        decisions.contains(&"refuse".to_string()),
        "#2634: a refused set_standard must chain `refuse`; got {decisions:?}"
    );
    assert!(
        !decisions.contains(&"allow".to_string()),
        "#2634 regression: a refused set_standard must NOT chain `allow`; got {decisions:?}"
    );
}

#[test]
fn set_standard_allowed_bind_records_allow() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");

    let (conn, f) = open_db();
    let std_id = seed_memory(
        &conn,
        f.path(),
        "ns-2634-set-allow",
        "alice's standard",
        "caller-alice",
    );

    let res = ai_memory::mcp::handle_namespace_set_standard(
        &conn,
        &json!({
            "namespace": "ns-2634-set-allow",
            "id": std_id,
            "agent_id": "caller-alice",
        }),
    );
    assert!(res.is_ok(), "owner bind must be allowed; got {res:?}");

    forensic::shutdown();
    let decisions = decisions_for(
        dir.path(),
        "namespace_set_standard",
        "namespace",
        "ns-2634-set-allow",
    );
    assert_eq!(
        decisions,
        vec!["allow".to_string()],
        "#2634: an allowed set_standard must chain exactly one `allow`; got {decisions:?}"
    );
}

// -----------------------------------------------------------------------
// namespace_clear_standard — the gate ran BEFORE the record (pre-fix), so a
// refused clear left NO forensic row at all (opposite ordering, same class).
// -----------------------------------------------------------------------

#[test]
fn clear_standard_refused_now_records_refuse() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");

    let (conn, f) = open_db();
    // Bob binds a bob-owned standard → creates the namespace_meta row.
    let std_id = seed_memory(
        &conn,
        f.path(),
        "ns-2634-clear-refuse",
        "bob's standard",
        "owner-bob",
    );
    ai_memory::mcp::handle_namespace_set_standard(
        &conn,
        &json!({ "namespace": "ns-2634-clear-refuse", "id": std_id, "agent_id": "owner-bob" }),
    )
    .expect("bob binds his standard");

    // Alice (non-owner) tries to clear it → refused.
    let res = ai_memory::mcp::handle_namespace_clear_standard(
        &conn,
        &json!({ "namespace": "ns-2634-clear-refuse", "agent_id": "caller-alice" }),
    );
    assert!(res.is_err(), "non-owner clear must be refused; got {res:?}");

    forensic::shutdown();
    let decisions = decisions_for(
        dir.path(),
        "namespace_clear_standard",
        "namespace",
        "ns-2634-clear-refuse",
    );
    assert!(
        decisions.contains(&"refuse".to_string()),
        "#2634: a refused clear_standard must now chain a `refuse` row (pre-fix it chained \
         NOTHING); got {decisions:?}"
    );
    assert!(
        !decisions.contains(&"allow".to_string()),
        "#2634: a refused clear_standard must NOT chain `allow`; got {decisions:?}"
    );
}

#[test]
fn clear_standard_allowed_records_allow() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");

    let (conn, f) = open_db();
    let std_id = seed_memory(
        &conn,
        f.path(),
        "ns-2634-clear-allow",
        "bob's standard",
        "owner-bob",
    );
    ai_memory::mcp::handle_namespace_set_standard(
        &conn,
        &json!({ "namespace": "ns-2634-clear-allow", "id": std_id, "agent_id": "owner-bob" }),
    )
    .expect("bob binds his standard");

    // Owner clears it → allowed.
    let res = ai_memory::mcp::handle_namespace_clear_standard(
        &conn,
        &json!({ "namespace": "ns-2634-clear-allow", "agent_id": "owner-bob" }),
    );
    assert!(res.is_ok(), "owner clear must be allowed; got {res:?}");

    forensic::shutdown();
    let decisions = decisions_for(
        dir.path(),
        "namespace_clear_standard",
        "namespace",
        "ns-2634-clear-allow",
    );
    assert!(
        decisions.contains(&"allow".to_string()),
        "#2634: an allowed clear_standard must chain `allow`; got {decisions:?}"
    );
    assert!(
        !decisions.contains(&"refuse".to_string()),
        "#2634: an allowed clear_standard must NOT chain `refuse`; got {decisions:?}"
    );
}

// -----------------------------------------------------------------------
// pending_approve (MCP) — the "allow" record fired before the approve gate.
// -----------------------------------------------------------------------

#[test]
fn mcp_pending_approve_refused_records_refuse_not_allow() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");

    let (conn, _f) = open_db();
    let pending_id = ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Promote,
        "ns-2634-pa-refuse",
        Some("11111111-2222-3333-4444-555555555555"),
        "ai:requester",
        &json!({ "target_tier": "long" }),
    )
    .expect("queue pending");
    // Decide it first so a subsequent approve hits the `Rejected` (already
    // decided) gate — a deterministic governed refusal.
    ai_memory::db::decide_pending_action(&conn, &pending_id, false, "ai:decider")
        .expect("pre-decide");

    let res = ai_memory::mcp::handle_pending_approve(
        &conn,
        &json!({ "id": pending_id, "agent_id": "ai:approver" }),
        None,
    );
    assert!(
        res.is_err(),
        "approving an already-decided action must be refused; got {res:?}"
    );

    forensic::shutdown();
    let decisions = decisions_for(dir.path(), "pending_approve", "pending_id", &pending_id);
    assert!(
        decisions.contains(&"refuse".to_string()),
        "#2634: a refused pending_approve must chain `refuse`; got {decisions:?}"
    );
    assert!(
        !decisions.contains(&"allow".to_string()),
        "#2634 regression: a refused pending_approve must NOT chain `allow`; got {decisions:?}"
    );
}

#[test]
fn mcp_pending_approve_allowed_records_allow() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");

    let (conn, _f) = open_db();
    let pending_id = ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Promote,
        "ns-2634-pa-allow",
        Some("22222222-3333-4444-5555-666666666666"),
        "ai:requester",
        &json!({ "target_tier": "long" }),
    )
    .expect("queue pending");

    // LocalOperator surface, no AI_MEMORY_AGENT_ID → approver accepted. The
    // downstream execute of a Promote against an absent row may error, but the
    // "allow" verdict is recorded BEFORE that (the #913 intent guarantee).
    let _ = ai_memory::mcp::handle_pending_approve(
        &conn,
        &json!({ "id": pending_id, "agent_id": "ai:approver" }),
        None,
    );

    forensic::shutdown();
    let decisions = decisions_for(dir.path(), "pending_approve", "pending_id", &pending_id);
    assert!(
        decisions.contains(&"allow".to_string()),
        "#2634: an allowed pending_approve must chain `allow`; got {decisions:?}"
    );
    assert!(
        !decisions.contains(&"refuse".to_string()),
        "#2634: an allowed pending_approve must NOT chain `refuse`; got {decisions:?}"
    );
}

// -----------------------------------------------------------------------
// HTTP surfaces — self-approval refusal (#2643) must chain `refuse`.
// -----------------------------------------------------------------------

const HMAC_SECRET_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Reproduce `verify_approval_hmac`'s canonical: key = `SHA-256(secret)`,
/// signature = `hex(HMAC-SHA256(key, "<ts>.POST.<pending_id>.<body>"))`.
fn approval_signature(secret: &str, canonical: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    let key = {
        let mut h = Sha256::new();
        h.update(secret.as_bytes());
        h.finalize()
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("hmac key");
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn build_router() -> (axum::Router, tempfile::NamedTempFile, PathBuf) {
    permissive_attestation();
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = ai_memory::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
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
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db_path)
}

/// Queue a pending action owned by `requester` into the router's db file.
fn queue_pending(db_path: &std::path::Path, namespace: &str, requester: &str) -> String {
    let conn = ai_memory::db::open(db_path).expect("open for queue");
    ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Promote,
        namespace,
        Some("33333333-4444-5555-6666-777777777777"),
        requester,
        &json!({ "target_tier": "long" }),
    )
    .expect("queue pending")
}

#[tokio::test]
async fn http_approve_pending_self_approval_records_refuse() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));

    let (router, _f, db_path) = build_router();
    // requester == approver → self-approval refusal (#2643) on the HTTP surface.
    let pending_id = queue_pending(&db_path, "ns-2634-http-gov", "operator-alice");

    let ts = chrono::Utc::now().timestamp().to_string();
    // governance.rs approve_pending: empty body, canonical binds an empty body.
    let canonical = format!("{ts}.POST.{pending_id}.");
    let sig = approval_signature(HMAC_SECRET_HEX, &canonical);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/pending/{pending_id}/approve"))
        .header("x-agent-id", "operator-alice")
        .header("x-ai-memory-signature", format!("sha256={sig}"))
        .header("x-ai-memory-timestamp", ts)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::FORBIDDEN,
        "self-approval must be 403-refused"
    );

    forensic::shutdown();
    ai_memory::config::set_active_hooks_hmac_secret(None);
    let decisions = decisions_for(dir.path(), "pending_approve", "pending_id", &pending_id);
    assert!(
        decisions.contains(&"refuse".to_string()),
        "#2634: an HTTP self-approval refusal (approve_pending) must chain `refuse`; got {decisions:?}"
    );
    assert!(
        !decisions.contains(&"allow".to_string()),
        "#2634 regression: it must NOT chain `allow`; got {decisions:?}"
    );
}

#[tokio::test]
async fn http_approval_decide_self_approval_records_refuse() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("init forensic sink");
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));

    let (router, _f, db_path) = build_router();
    let pending_id = queue_pending(&db_path, "ns-2634-http-k10", "operator-alice");

    let body = json!({ "decision": "approve" });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let body_str = String::from_utf8(body_bytes.clone()).unwrap();
    let ts = chrono::Utc::now().timestamp().to_string();
    let canonical = format!("{ts}.POST.{pending_id}.{body_str}");
    let sig = approval_signature(HMAC_SECRET_HEX, &canonical);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", "operator-alice")
        .header("x-ai-memory-signature", format!("sha256={sig}"))
        .header("x-ai-memory-timestamp", ts)
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::FORBIDDEN,
        "self-approval must be 403-refused"
    );

    forensic::shutdown();
    ai_memory::config::set_active_hooks_hmac_secret(None);
    let decisions = decisions_for(
        dir.path(),
        "approval_decide_approve",
        "pending_id",
        &pending_id,
    );
    assert!(
        decisions.contains(&"refuse".to_string()),
        "#2634: an HTTP self-approval refusal (approval_decide) must chain `refuse`; got {decisions:?}"
    );
    assert!(
        !decisions.contains(&"allow".to_string()),
        "#2634 regression: it must NOT chain `allow`; got {decisions:?}"
    );
}
