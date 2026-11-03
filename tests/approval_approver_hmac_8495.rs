// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8495 (umbrella #8493, control finding C) — the K10 approval decide
//! signature must commit to WHO is deciding, not only to which row.
//!
//! Pre-fix the decide HMAC covered `<ts>.<METHOD>.<pending_id>.<body>`. The
//! approver came from the `X-Agent-Id` header beside it, outside the signed
//! bytes, so a signed decide could be re-attributed to another approver and
//! one holder of the server-wide secret could cast votes under N names.
//!
//! The fix is the signed-subject layout v2,
//! `<ts>.<METHOD>.<pending_id>@<approver>.<body>`, copied from the api-key
//! approval route (`handlers::agent_api_key::approval_subject`). A v1 signature
//! that still verifies is reported as `legacy_unbound_approver` and refused;
//! it is never counted as a bound approver.
//!
//! Pins, on the sqlite branch AND on the postgres branch of the handler (the
//! fake-pg harness of `tests/k10_approval_postgres_dispatch_1618.rs`, plus a
//! live `PostgresStore` module under `sal-postgres`):
//!   1. a signature minted for approver X does not verify when the request
//!      names approver Y (tampered approver field);
//!   2. a decide as X records X as the decider, and the same signed bytes
//!      presented as Y are refused;
//!   3. a v1 (approver-unbound) signature is refused as
//!      `legacy_unbound_approver`, not accepted;
//!   4. under the `enforce` identity posture, one shared credential cannot
//!      fill a 2-of-N consensus quorum by naming two approvers, while two
//!      key-attested approvers can.
//!
//! The governance twin `POST /api/v1/pending/{id}/approve|reject` shares the
//! verifier and is pinned for (2) and (3).

#![cfg(feature = "sal")]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ai_memory::config::{HttpIdentityMode, set_active_hooks_hmac_secret};
use ai_memory::handlers::agent_api_key::approval_subject;
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tower::ServiceExt as _;

mod common;

/// The HMAC secret is process-global state; every test in this binary
/// takes this lock (same idiom as `tests/k10_approval_http.rs`).
static LOCK_8495: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SECRET: &str = "approval-approver-hmac-8495-secret";
const SHARED_KEY: &str = "shared-transport-key-8495";
const ALICE_KEY: &str = "alice-per-agent-key-8495";
const BOB_KEY: &str = "bob-per-agent-key-8495";
const REQUESTER: &str = "requester-8495";
const APPROVER_X: &str = "approver-x-8495";
const APPROVER_Y: &str = "approver-y-8495";
const LEGACY_UNBOUND_APPROVER: &str = "legacy_unbound_approver";

#[derive(Clone, Copy, Debug)]
enum Backend {
    /// `storage_backend = Sqlite`: the handler's rusqlite branch.
    Sqlite,
    /// `storage_backend = Postgres` over a `SqliteStore`: the handler's
    /// SAL-trait (postgres) branch, as in the #1618 dispatch test.
    FakePostgres,
}

#[derive(Clone, Copy, Debug)]
enum Posture {
    /// v1.0.0 default: advisory, zero enrolled per-agent keys.
    Default,
    /// `enforce` with alice and bob enrolled; transport needs `SHARED_KEY`
    /// or a per-agent key.
    EnforceWithKeys,
}

struct Harness {
    router: axum::Router,
    db_path: PathBuf,
    _file: NamedTempFile,
}

fn build(backend: Backend, posture: Posture) -> Harness {
    let file = NamedTempFile::new().expect("tempfile");
    let db_path = file.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let (enrolled, mode, key) = match posture {
        Posture::Default => (
            Arc::new(EnrolledAgentKeys::empty()),
            HttpIdentityMode::default(),
            None,
        ),
        Posture::EnforceWithKeys => {
            let mut map = HashMap::new();
            map.insert(api_key_sha256_hex(ALICE_KEY), "alice".to_string());
            map.insert(api_key_sha256_hex(BOB_KEY), "bob".to_string());
            (
                Arc::new(EnrolledAgentKeys::from_map(map)),
                HttpIdentityMode::Enforce,
                Some(SHARED_KEY.to_string()),
            )
        }
    };
    let storage_backend = match backend {
        Backend::Sqlite => StorageBackend::Sqlite,
        Backend::FakePostgres => StorageBackend::Postgres,
    };
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
        storage_backend,
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
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: mode,
    };
    let api_key_state = ApiKeyState {
        key,
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: mode,
        ..Default::default()
    };
    Harness {
        router: ai_memory::build_router(api_key_state, app_state),
        db_path,
        _file: file,
    }
}

/// Seed a memory plus a delete-shaped pending row targeting it, and
/// register the approvers the tests decide as.
fn seed_delete_pending(db_path: &Path, namespace: &str) -> String {
    let conn = ai_memory::db::open(db_path).expect("open seed conn");
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: format!("t-8495-{}", uuid::Uuid::new_v4()),
        content: "seeded by the #8495 approver-binding test".into(),
        priority: 5,
        confidence: 1.0,
        source: "test".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({}),
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    let mem_id = ai_memory::db::insert(&conn, &mem).expect("insert memory");
    for agent in [APPROVER_X, APPROVER_Y, "alice", "bob"] {
        ai_memory::db::register_agent(&conn, agent, "ai:generic", &[]).ok();
    }
    ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Delete,
        namespace,
        Some(&mem_id),
        REQUESTER,
        &json!({"reason": "8495"}),
    )
    .expect("queue_pending_action")
}

/// Seed a store-shaped pending row in a namespace whose standard requires a
/// 2-of-N consensus.
fn seed_consensus_pending(db_path: &Path, namespace: &str) -> String {
    let conn = ai_memory::db::open(db_path).expect("open seed conn");
    let standard = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: format!("{namespace}-standard"),
        content: "policy".into(),
        priority: 5,
        confidence: 1.0,
        source: "test".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({"governance": {
            "write": "approve", "promote": "any", "delete": "owner",
            "approver": {"consensus": 2}
        }}),
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    let standard_id = ai_memory::db::insert(&conn, &standard).expect("insert standard");
    ai_memory::db::set_namespace_standard(&conn, namespace, &standard_id, None)
        .expect("set_namespace_standard");
    for agent in ["alice", "bob"] {
        ai_memory::db::register_agent(&conn, agent, "ai:generic", &[]).ok();
    }
    let target = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: format!("{namespace}-target-{}", uuid::Uuid::new_v4()),
        content: "deleted once two approvers agree".into(),
        metadata: json!({}),
        ..standard
    };
    let target_id = ai_memory::db::insert(&conn, &target).expect("insert target");
    ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Delete,
        namespace,
        Some(&target_id),
        REQUESTER,
        &json!({"reason": "quorum-8495"}),
    )
    .expect("queue_pending_action")
}

fn pending_row(db_path: &Path, pending_id: &str) -> ai_memory::models::PendingAction {
    let conn = ai_memory::db::open(db_path).expect("reopen");
    ai_memory::db::get_pending_action(&conn, pending_id)
        .expect("get_pending_action")
        .expect("pending row exists")
}

/// v2 envelope: the approver is inside the signed subject.
fn sign_v2(ts: &str, path_id: &str, approver: &str, body: &str) -> String {
    common::sign_canonical_envelope(
        SECRET,
        ts,
        "POST",
        &approval_subject(path_id, approver),
        body,
    )
}

/// v1 envelope: the pre-#8495 layout, approver outside the signed bytes.
fn sign_v1(ts: &str, path_id: &str, body: &str) -> String {
    common::sign_canonical_envelope(SECRET, ts, "POST", path_id, body)
}

fn now_ts() -> String {
    chrono::Utc::now().timestamp().to_string()
}

fn request(
    uri: &str,
    ts: &str,
    sig: &str,
    agent: &str,
    api_key: Option<&str>,
    body: &str,
) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-ai-memory-timestamp", ts)
        .header("x-ai-memory-signature", sig)
        .header("x-agent-id", agent);
    if let Some(k) = api_key {
        b = b.header("x-api-key", k);
    }
    b.body(Body::from(body.to_string())).expect("request")
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn approve_body() -> String {
    json!({"decision": "approve", "remember": "once"}).to_string()
}

fn decide_uri(pending_id: &str) -> String {
    format!("/api/v1/approvals/{pending_id}")
}

// ---------------------------------------------------------------------------
// (1) tampered approver field
// ---------------------------------------------------------------------------

async fn tampered_approver_fails_verification(backend: Backend) {
    let h = build(backend, Posture::Default);
    let pid = seed_delete_pending(&h.db_path, "ns-8495-tamper");
    let body = approve_body();
    let ts = now_ts();
    let sig_for_x = sign_v2(&ts, &pid, APPROVER_X, &body);

    // The signature names X; the request names Y. Refused, row untouched.
    let (status, v) = send(
        &h.router,
        request(&decide_uri(&pid), &ts, &sig_for_x, APPROVER_Y, None, &body),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{backend:?}: an approver swapped after signing must not verify; body={v}"
    );
    assert_eq!(pending_row(&h.db_path, &pid).status, "pending");

    // Positive control: the same signature with the approver it names
    // verifies and decides.
    let (status, v) = send(
        &h.router,
        request(&decide_uri(&pid), &ts, &sig_for_x, APPROVER_X, None, &body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{backend:?}: body={v}");
    assert_eq!(v["approved"], json!(true), "{backend:?}: body={v}");
}

#[tokio::test]
async fn tampered_approver_fails_verification_sqlite_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    tampered_approver_fails_verification(Backend::Sqlite).await;
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn tampered_approver_fails_verification_postgres_branch_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    tampered_approver_fails_verification(Backend::FakePostgres).await;
    set_active_hooks_hmac_secret(None);
}

// ---------------------------------------------------------------------------
// (2) decide as X binds X; the same bytes as Y are refused
// ---------------------------------------------------------------------------

async fn decide_binds_the_signing_approver(backend: Backend, deny: bool) {
    let h = build(backend, Posture::Default);
    let pid = seed_delete_pending(&h.db_path, "ns-8495-bind");
    let body = if deny {
        json!({"decision": "deny", "remember": "once"}).to_string()
    } else {
        approve_body()
    };
    let ts = now_ts();
    let sig = sign_v2(&ts, &pid, APPROVER_X, &body);

    // Presented as Y FIRST, so the refusal cannot be the replay cache.
    let (status, v) = send(
        &h.router,
        request(&decide_uri(&pid), &ts, &sig, APPROVER_Y, None, &body),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{backend:?} deny={deny}: X's signature presented as Y must be refused; body={v}"
    );

    let (status, v) = send(
        &h.router,
        request(&decide_uri(&pid), &ts, &sig, APPROVER_X, None, &body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{backend:?} deny={deny}: body={v}");
    assert_eq!(v["decided_by"], json!(APPROVER_X), "{backend:?}: body={v}");
    let row = pending_row(&h.db_path, &pid);
    assert_eq!(
        row.decided_by.as_deref(),
        Some(APPROVER_X),
        "{backend:?} deny={deny}: the stored decision must name the signing approver"
    );
    assert_eq!(row.status, if deny { "rejected" } else { "approved" });
}

#[tokio::test]
async fn decide_binds_the_signing_approver_sqlite_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    decide_binds_the_signing_approver(Backend::Sqlite, false).await;
    decide_binds_the_signing_approver(Backend::Sqlite, true).await;
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn decide_binds_the_signing_approver_postgres_branch_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    decide_binds_the_signing_approver(Backend::FakePostgres, false).await;
    decide_binds_the_signing_approver(Backend::FakePostgres, true).await;
    set_active_hooks_hmac_secret(None);
}

// ---------------------------------------------------------------------------
// (3) a v1 signature is legacy_unbound_approver, never a bound approval
// ---------------------------------------------------------------------------

async fn legacy_v1_signature_is_reported_unbound(backend: Backend) {
    let h = build(backend, Posture::Default);
    let pid = seed_delete_pending(&h.db_path, "ns-8495-legacy");
    let body = approve_body();
    let ts = now_ts();
    let (status, v) = send(
        &h.router,
        request(
            &decide_uri(&pid),
            &ts,
            &sign_v1(&ts, &pid, &body),
            APPROVER_X,
            None,
            &body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{backend:?}: body={v}");
    assert_eq!(
        v["error"],
        json!(LEGACY_UNBOUND_APPROVER),
        "{backend:?}: a v1 signature must be reported as unbound; body={v}"
    );
    assert_eq!(
        v["signature_layout_version"],
        json!(2),
        "{backend:?}: body={v}"
    );
    let row = pending_row(&h.db_path, &pid);
    assert_eq!(row.status, "pending", "{backend:?}: nothing decided");
    assert!(
        row.decided_by.is_none(),
        "{backend:?}: no approver recorded"
    );
}

#[tokio::test]
async fn legacy_v1_signature_is_reported_unbound_sqlite_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    legacy_v1_signature_is_reported_unbound(Backend::Sqlite).await;
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn legacy_v1_signature_is_reported_unbound_postgres_branch_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    legacy_v1_signature_is_reported_unbound(Backend::FakePostgres).await;
    set_active_hooks_hmac_secret(None);
}

// ---------------------------------------------------------------------------
// (4) one shared credential cannot fill a 2-of-N quorum under enforce
// ---------------------------------------------------------------------------

async fn one_credential_cannot_fill_a_quorum(backend: Backend) {
    let h = build(backend, Posture::EnforceWithKeys);
    let pid = seed_consensus_pending(&h.db_path, "ns-8495-quorum");
    let body = approve_body();

    // One secret, one shared transport key, two approver names — each
    // signature correctly binds the name it presents.
    let refused_secs = chrono::Utc::now().timestamp();
    for name in ["alice", "bob"] {
        let ts = refused_secs.to_string();
        let (status, v) = send(
            &h.router,
            request(
                &decide_uri(&pid),
                &ts,
                &sign_v2(&ts, &pid, name, &body),
                name,
                Some(SHARED_KEY),
                &body,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{backend:?}: a shared-key vote as {name} must be refused under enforce; body={v}"
        );
    }
    let row = pending_row(&h.db_path, &pid);
    assert_eq!(row.status, "pending", "{backend:?}: quorum must not be met");
    assert!(
        row.approvals.is_empty(),
        "{backend:?}: no vote may be recorded"
    );

    // Positive control: two key-attested approvers do meet the quorum.
    // The refused alice vote above passed the signature check, so its
    // nonce is spent; sign one second before it so this is a fresh signature
    // inside the replay window rather than a replay of that one.
    let ts = (refused_secs - 1).to_string();
    let (status, v) = send(
        &h.router,
        request(
            &decide_uri(&pid),
            &ts,
            &sign_v2(&ts, &pid, "alice", &body),
            "alice",
            Some(ALICE_KEY),
            &body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{backend:?}: body={v}");
    assert_eq!(v["votes"], json!(1), "{backend:?}: body={v}");
    assert_eq!(v["quorum"], json!(2), "{backend:?}: body={v}");
    let ts = (refused_secs - 1).to_string();
    let (status, v) = send(
        &h.router,
        request(
            &decide_uri(&pid),
            &ts,
            &sign_v2(&ts, &pid, "bob", &body),
            "bob",
            Some(BOB_KEY),
            &body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{backend:?}: body={v}");
    assert_eq!(v["approved"], json!(true), "{backend:?}: body={v}");
}

#[tokio::test]
async fn one_credential_cannot_fill_a_quorum_sqlite_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    one_credential_cannot_fill_a_quorum(Backend::Sqlite).await;
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn one_credential_cannot_fill_a_quorum_postgres_branch_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    one_credential_cannot_fill_a_quorum(Backend::FakePostgres).await;
    set_active_hooks_hmac_secret(None);
}

// ---------------------------------------------------------------------------
// Governance twin: POST /api/v1/pending/{id}/approve|reject
// ---------------------------------------------------------------------------

#[tokio::test]
async fn governance_pending_routes_bind_the_approver_8495() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    for backend in [Backend::Sqlite, Backend::FakePostgres] {
        for verb in ["approve", "reject"] {
            let h = build(backend, Posture::Default);
            let pid = seed_delete_pending(&h.db_path, "ns-8495-gov");
            let uri = format!("/api/v1/pending/{pid}/{verb}");
            let body = String::new();

            // (3) a v1 signature is legacy_unbound_approver.
            let ts = now_ts();
            let (status, v) = send(
                &h.router,
                request(
                    &uri,
                    &ts,
                    &sign_v1(&ts, &pid, &body),
                    APPROVER_X,
                    None,
                    &body,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{backend:?} {verb}: {v}");
            assert_eq!(
                v["error"],
                json!(LEGACY_UNBOUND_APPROVER),
                "{backend:?} {verb}: {v}"
            );

            // (2) X's signature presented as Y is refused; as X it decides.
            let ts = now_ts();
            let sig = sign_v2(&ts, &pid, APPROVER_X, &body);
            let (status, v) =
                send(&h.router, request(&uri, &ts, &sig, APPROVER_Y, None, &body)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{backend:?} {verb}: {v}");
            let (status, v) =
                send(&h.router, request(&uri, &ts, &sig, APPROVER_X, None, &body)).await;
            assert_eq!(status, StatusCode::OK, "{backend:?} {verb}: {v}");
            let row = pending_row(&h.db_path, &pid);
            assert_eq!(
                row.decided_by.as_deref(),
                Some(APPROVER_X),
                "{backend:?} {verb}"
            );
        }
    }
    set_active_hooks_hmac_secret(None);
}

// ---------------------------------------------------------------------------
// (5) #8546 — the layout 2 subject is injective: the approver cannot be
//     shifted into the body
// ---------------------------------------------------------------------------

/// The approver the shift case signs for: `APPROVER_X` plus a `.`-suffix,
/// legal inside an agent id (`validate_agent_id` admits `.`). The suffix is
/// digits so the shifted body still parses as JSON (`1.5`) and so reaches
/// the HMAC check on every decide route instead of a body-shape 400.
const SHIFTED_SIGNER: &str = "approver-x-8495.1";
/// The body the shift case signs.
const SHIFTED_SIGNED_BODY: &str = "5";
/// The body the shift case presents: the approver's `.1` suffix moved into it.
const SHIFTED_PRESENTED_BODY: &str = "1.5";

/// The three decide routes that verify through `verify_approver_bound_hmac`.
fn decide_routes(pid: &str) -> [(&'static str, String); 3] {
    [
        ("approval_decide", decide_uri(pid)),
        ("approve_pending", format!("/api/v1/pending/{pid}/approve")),
        ("reject_pending", format!("/api/v1/pending/{pid}/reject")),
    ]
}

/// A signature minted for `x.1` over body `5` must not verify as approver `x`
/// with body `1.5`: before #8546 both requests hashed the same bytes.
async fn shifted_approver_is_refused(backend: Backend) {
    for (endpoint, _) in decide_routes("") {
        let h = build(backend, Posture::Default);
        let pid = seed_delete_pending(&h.db_path, "ns-8546-shift");
        let uri = decide_routes(&pid)
            .into_iter()
            .find(|(e, _)| *e == endpoint)
            .map(|(_, u)| u)
            .expect("route");
        let ts = now_ts();
        let sig = sign_v2(&ts, &pid, SHIFTED_SIGNER, SHIFTED_SIGNED_BODY);
        let (status, v) = send(
            &h.router,
            request(&uri, &ts, &sig, APPROVER_X, None, SHIFTED_PRESENTED_BODY),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{backend:?} {endpoint}: a signature for {SHIFTED_SIGNER} must not verify as \
             {APPROVER_X}; body={v}"
        );
        let row = pending_row(&h.db_path, &pid);
        assert_eq!(row.status, "pending", "{backend:?} {endpoint}");
        assert_eq!(row.decided_by, None, "{backend:?} {endpoint}");
    }
}

#[tokio::test]
async fn shifted_approver_is_refused_sqlite_8546() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    shifted_approver_is_refused(Backend::Sqlite).await;
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn shifted_approver_is_refused_postgres_branch_8546() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    shifted_approver_is_refused(Backend::FakePostgres).await;
    set_active_hooks_hmac_secret(None);
}

/// The signed subject is length-prefixed, so it is the same bytes for the
/// signer and the verifier and different bytes for every other split.
#[test]
fn approval_subject_is_length_prefixed_8546() {
    assert_eq!(
        approval_subject("p-1", "x.1"),
        "3:p-1@3:x.1",
        "pending id and approver are each prefixed with their byte length"
    );
    assert_ne!(
        format!(
            "{}.{SHIFTED_SIGNED_BODY}",
            approval_subject("p", SHIFTED_SIGNER)
        ),
        format!(
            "{}.{SHIFTED_PRESENTED_BODY}",
            approval_subject("p", APPROVER_X)
        ),
    );
}

/// The governance verbs refuse a non-empty body that is not JSON with 400
/// BEFORE the HMAC is verified, so a captured signature is never spent on a
/// malformed body and a shifted body is never read as "no approvals".
async fn non_json_governance_body_is_refused(backend: Backend) {
    for verb in ["approve", "reject"] {
        let h = build(backend, Posture::Default);
        let pid = seed_delete_pending(&h.db_path, "ns-8546-body");
        let uri = format!("/api/v1/pending/{pid}/{verb}");
        let body = "ops.";
        let ts = now_ts();
        let sig = sign_v2(&ts, &pid, APPROVER_X, body);
        let (status, v) = send(&h.router, request(&uri, &ts, &sig, APPROVER_X, None, body)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{backend:?} {verb}: a non-JSON body must be refused; body={v}"
        );
        assert_eq!(
            pending_row(&h.db_path, &pid).status,
            "pending",
            "{backend:?} {verb}"
        );
        // The refusal did not spend the nonce: the signature over the empty
        // body made in the same second still decides.
        let sig = sign_v2(&ts, &pid, APPROVER_X, "");
        let (status, v) = send(&h.router, request(&uri, &ts, &sig, APPROVER_X, None, "")).await;
        assert_eq!(status, StatusCode::OK, "{backend:?} {verb}: body={v}");
    }
}

#[tokio::test]
async fn non_json_governance_body_is_refused_sqlite_8546() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    non_json_governance_body_is_refused(Backend::Sqlite).await;
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn non_json_governance_body_is_refused_postgres_branch_8546() {
    let _g = LOCK_8495.lock().await;
    set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    non_json_governance_body_is_refused(Backend::FakePostgres).await;
    set_active_hooks_hmac_secret(None);
}

// ---------------------------------------------------------------------------
// (4) postgres parity on a live PostgresStore (skip when no URL is set)
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod live_pg {
    use super::*;
    use ai_memory::store::{CallerContext, MemoryStore};

    fn live_router(store: Arc<dyn MemoryStore>) -> axum::Router {
        let scratch = ai_memory::db::open(Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(tokio::sync::Mutex::new((
            scratch,
            PathBuf::from(":memory:"),
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
            enrolled_agent_keys: Arc::new(EnrolledAgentKeys::empty()),
            http_identity_mode: HttpIdentityMode::default(),
        };
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(EnrolledAgentKeys::empty()),
            identity_mode: HttpIdentityMode::default(),
            ..Default::default()
        };
        ai_memory::build_router(api_key_state, app_state)
    }

    async fn seed_live(store: &Arc<dyn MemoryStore>) -> String {
        let ctx = CallerContext::for_agent(REQUESTER.to_string());
        let ns = format!("ns-8495-live-{}", uuid::Uuid::new_v4().simple());
        let mem = ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: ai_memory::models::Tier::Long,
            namespace: ns.clone(),
            title: format!("t-8495-live-{}", uuid::Uuid::new_v4()),
            content: "seeded by the #8495 live postgres test".into(),
            priority: 5,
            confidence: 1.0,
            source: "test".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata: json!({}),
            version: 1,
            ..ai_memory::models::Memory::default()
        };
        let mem_id = store.store(&ctx, &mem).await.expect("store memory");
        let now = chrono::Utc::now().to_rfc3339();
        for agent in [APPROVER_X, APPROVER_Y] {
            store
                .register_agent(
                    &ctx,
                    &ai_memory::models::AgentRegistration {
                        agent_id: agent.to_string(),
                        agent_type: "ai:generic".to_string(),
                        capabilities: Vec::new(),
                        registered_at: now.clone(),
                        last_seen_at: now.clone(),
                    },
                )
                .await
                .ok();
        }
        store
            .queue_pending_action(
                &ctx,
                ai_memory::store::GovernedAction::Delete,
                &ns,
                Some(&mem_id),
                REQUESTER,
                &json!({"reason": "8495-live"}),
            )
            .await
            .expect("queue_pending_action")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn live_postgres_binds_the_approver_8495() {
        let Some(url) = common::postgres_url() else {
            eprintln!("skipping live_postgres_binds_the_approver_8495: no postgres url");
            return;
        };
        let _g = LOCK_8495.lock().await;
        set_active_hooks_hmac_secret(Some(SECRET.to_string()));
        let store: Arc<dyn MemoryStore> = Arc::new(
            ai_memory::store::postgres::PostgresStore::connect(&url)
                .await
                .expect("connect postgres adapter"),
        );
        let router = live_router(store.clone());
        let body = approve_body();

        // (3) v1 → legacy_unbound_approver.
        let pid = seed_live(&store).await;
        let ts = now_ts();
        let (status, v) = send(
            &router,
            request(
                &decide_uri(&pid),
                &ts,
                &sign_v1(&ts, &pid, &body),
                APPROVER_X,
                None,
                &body,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "live pg: {v}");
        assert_eq!(v["error"], json!(LEGACY_UNBOUND_APPROVER), "live pg: {v}");

        // (1) + (2) X's signature as Y refused; as X binds X.
        let ts = now_ts();
        let sig = sign_v2(&ts, &pid, APPROVER_X, &body);
        let (status, v) = send(
            &router,
            request(&decide_uri(&pid), &ts, &sig, APPROVER_Y, None, &body),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "live pg: {v}");
        let (status, v) = send(
            &router,
            request(&decide_uri(&pid), &ts, &sig, APPROVER_X, None, &body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "live pg: {v}");
        assert_eq!(v["decided_by"], json!(APPROVER_X), "live pg: {v}");
        let ctx = CallerContext::for_agent(APPROVER_X.to_string());
        let row = store
            .get_pending(&ctx, &pid)
            .await
            .expect("get_pending")
            .expect("row");
        assert_eq!(row.decided_by.as_deref(), Some(APPROVER_X), "live pg");
        set_active_hooks_hmac_secret(None);
    }
}
