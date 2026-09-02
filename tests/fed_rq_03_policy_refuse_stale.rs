// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! FED-RQ-03 (#1947, 5-agent vote `wd8wtmg0n`) — cross-node governance
//! `policy_version` REFUSE-STALE gate on the federation receive path.
//!
//! Invariants pinned here (both backends — sqlite always; postgres via the
//! `#[ignore]` parity test run with `--include-ignored` +
//! `AI_MEMORY_TEST_POSTGRES_URL`):
//!
//!   1. A push advertising a STALE `sender_policy_seq` (strictly behind the
//!      receiver's committed governance policy) is REFUSED — `409 CONFLICT`
//!      with the typed `stale_policy_version` tag — and the memory does NOT
//!      land (reject-before-apply; no `MemoryStore` verbatim-apply).
//!   2. A FRESH (equal / ahead) `sender_policy_seq` is ACCEPTED (control) and
//!      the memory lands.
//!   3. An ABSENT `sender_policy_seq` is ACCEPTED (rollout fail-OPEN —
//!      staleness undeterminable, a non-advertising peer is never refused).
//!   4. `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0` accepts even a DETECTED-stale
//!      push (the heterogeneous-policy rollout opt-out).
//!
//! The gate runs BEFORE the postgres dispatch and before any apply loop, so
//! the pg parity test proves the refusal fires without ever touching the
//! `PostgresStore` — the "no pg verbatim-apply" property.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async guard: these tests mutate process-wide federation env
/// vars, and cargo runs `#[tokio::test]`s in a binary concurrently.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const PEER_ID_HEADER: &str = "x-peer-id";
const SENDER: &str = "ai:fedrq03-peer";
const NS: &str = "fedrq03";

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
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db)
}

/// Advance the local committed governance policy `n` times so
/// `current_policy_version().seq == n`. Uses the signed append path (the same
/// surface `epoch-apply` binds against).
async fn advance_policy(db: &ai_memory::handlers::Db, n: usize) {
    let kp = ai_memory::identity::keypair::generate("operator").expect("gen operator key");
    let signing = kp.private.as_ref().expect("operator private key");
    let lock = db.lock().await;
    for _ in 0..n {
        ai_memory::governance::policy_version::append_policy_advance_no_tx(
            &lock.0, signing, "operator",
        )
        .expect("append policy advance");
    }
    let pv =
        ai_memory::governance::policy_version::current_policy_version(&lock.0).expect("read pv");
    assert_eq!(
        pv.seq,
        i64::try_from(n).expect("advance count fits i64"),
        "local policy seq must reflect the advances"
    );
}

/// A `/sync/push` body with a single self-authored memory, optionally carrying
/// a `sender_policy_seq` (None = absent / not advertised).
fn push_body(id: &str, sender_policy_seq: Option<i64>) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    let mut body = json!({
        "sender_agent_id": SENDER,
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": id,
            "tier": "long",
            "namespace": NS,
            "title": format!("fedrq03 {id}"),
            "content": "policy-gate regression body",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": false,
    });
    if let Some(seq) = sender_policy_seq {
        body["sender_policy_seq"] = json!(seq);
    }
    body
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

/// Reset the env so each case reaches the FED-RQ-03 gate cleanly: unenrolled
/// peer must pass the signing/enrollment gate, and the #238 sender-attestation
/// must pass (x-peer-id == `sender_agent_id`). Held inside `ENV_LOCK`.
fn reset_env() {
    unsafe {
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV);
    }
}

async fn post_push(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(PEER_ID_HEADER, SENDER)
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn stale_policy_version_is_refused_before_apply() {
    let guard = ENV_LOCK.lock().await;
    reset_env();
    let (router, db) = build_router_with_db();
    advance_policy(&db, 5).await; // local committed policy seq = 5

    // Sender advertises seq 3 — strictly behind → DETECTED-stale → refuse.
    let (status, body) = post_push(
        &router,
        &push_body("11111111-1111-4111-8111-111111111111", Some(3)),
    )
    .await;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a stale policy_version push must be refused 409; body={body}"
    );
    assert_eq!(
        body["error"],
        ai_memory::federation::receive_auth::STALE_POLICY_ERROR_TAG,
        "typed stale-policy error tag"
    );
    assert_eq!(body["sender_policy_seq"], 3);
    assert_eq!(body["local_policy_seq"], 5);
    assert_eq!(
        count_ns(&db, NS).await,
        0,
        "no memory may land on a stale-policy refusal (reject-before-apply)"
    );
}

/// Break the local governance policy read so `current_policy_version`
/// returns `Err` on every attempt.
///
/// `policy_advance_count` short-circuits to `Ok(0)` when `signed_events` is
/// ABSENT, so dropping the table would exercise the (legitimate) `seq=0`
/// sentinel, not the fault path. Renaming the column the count query filters
/// on keeps the table present and makes the SELECT itself fail — the shape a
/// transient `SQLITE_BUSY` / corrupted-read fault takes at this call site.
async fn break_policy_read(db: &ai_memory::handlers::Db) {
    let lock = db.lock().await;
    lock.0
        .execute_batch("ALTER TABLE signed_events RENAME COLUMN event_type TO event_type_broken;")
        .expect("break the policy-version read");
    assert!(
        ai_memory::governance::policy_version::current_policy_version(&lock.0).is_err(),
        "the fault must actually make the policy read fail — otherwise this test is vacuous"
    );
}

/// REGRESSION (fail-open fix) — a local governance policy-read fault must
/// REFUSE the push, not accept it.
///
/// Pre-fix `refuse_if_stale_policy` swallowed the `Err` and returned `None`
/// (accept), so a peer could ride out FED-RQ-03 by inducing a transient
/// governance-read fault it can generate itself with parallel pushes, and
/// apply under a stale policy. `503` (not `409`) because the condition is
/// transient and the peer SHOULD retry.
#[tokio::test]
async fn policy_read_fault_refuses_503_and_does_not_apply() {
    let guard = ENV_LOCK.lock().await;
    reset_env();
    let (router, db) = build_router_with_db();
    advance_policy(&db, 5).await;
    break_policy_read(&db).await;

    // A push that would otherwise be ACCEPTED (fresh seq) — proving the
    // refusal comes from the read fault, not from staleness.
    let (status, body) = post_push(
        &router,
        &push_body("44444444-4444-4444-8444-444444444444", Some(5)),
    )
    .await;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a policy-read fault must FAIL CLOSED with a retryable 503; body={body}"
    );
    assert_eq!(
        body["error"], "policy_read_unavailable",
        "typed policy-read-fault tag (distinct from the stale tag); body={body}"
    );
    assert!(
        body.get("detail").is_none(),
        "Fable HIGH (#3133): raw rusqlite/IO error must not ride the peer wire; body={body}"
    );
    let note = body["note"].as_str().unwrap_or("");
    assert!(
        note.contains("retryable"),
        "note must say it is retryable: {note}"
    );
    assert!(
        note.contains(ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV),
        "note must name the documented opt-out: {note}"
    );
    assert_eq!(
        count_ns(&db, NS).await,
        0,
        "no memory may land when staleness is undeterminable (reject-before-apply)"
    );
}

/// The documented rollout opt-out is UNCHANGED by the fail-closed fix: with
/// the gate disabled, a policy-read fault still ACCEPTS exactly as before.
#[tokio::test]
async fn policy_read_fault_still_accepts_when_gate_disabled() {
    let guard = ENV_LOCK.lock().await;
    reset_env();
    unsafe {
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
            "0",
        );
    }
    let (router, db) = build_router_with_db();
    advance_policy(&db, 5).await;
    break_policy_read(&db).await;

    let (status, body) = post_push(
        &router,
        &push_body("55555555-5555-4555-8555-555555555555", Some(3)),
    )
    .await;
    unsafe {
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV);
    }
    drop(guard);

    assert_ne!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0 keeps the legacy accept-on-fault; body={body}"
    );
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "the gate is disabled, so nothing may be refused as stale either; body={body}"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "non-vacuous: the push must actually be ACCEPTED under the opt-out; body={body}"
    );
}

#[tokio::test]
async fn fresh_policy_version_is_accepted() {
    let guard = ENV_LOCK.lock().await;
    reset_env();
    let (router, db) = build_router_with_db();
    advance_policy(&db, 5).await;

    // Equal seq (control): not stale → accept + memory lands.
    let (status, body) = post_push(
        &router,
        &push_body("22222222-2222-4222-8222-222222222222", Some(5)),
    )
    .await;
    // Ahead seq: also not stale.
    let (status_ahead, _) = post_push(
        &router,
        &push_body("33333333-3333-4333-8333-333333333333", Some(9)),
    )
    .await;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::OK,
        "equal policy_version accepts; body={body}"
    );
    assert_eq!(status_ahead, StatusCode::OK, "ahead policy_version accepts");
    assert_eq!(
        count_ns(&db, NS).await,
        2,
        "both fresh pushes must land their memory"
    );
}

#[tokio::test]
async fn absent_policy_version_is_accepted_failopen() {
    let guard = ENV_LOCK.lock().await;
    reset_env();
    let (router, db) = build_router_with_db();
    advance_policy(&db, 5).await;

    // No sender_policy_seq advertised → fail-OPEN (rollout safety).
    let (status, body) = post_push(
        &router,
        &push_body("44444444-4444-4444-8444-444444444444", None),
    )
    .await;
    drop(guard);

    assert_eq!(
        status,
        StatusCode::OK,
        "an absent policy_version is never hard-refused (fail-open); body={body}"
    );
    assert_eq!(count_ns(&db, NS).await, 1, "the non-advertising push lands");
}

#[tokio::test]
async fn opt_out_accepts_even_stale() {
    let guard = ENV_LOCK.lock().await;
    reset_env();
    // Operator opt-out for a deliberate heterogeneous-policy rollout window.
    unsafe {
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
            "0",
        );
    }
    let (router, db) = build_router_with_db();
    advance_policy(&db, 5).await;

    let (status, body) = post_push(
        &router,
        &push_body("55555555-5555-4555-8555-555555555555", Some(1)),
    )
    .await;
    unsafe {
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV);
    }
    drop(guard);

    assert_eq!(
        status,
        StatusCode::OK,
        "AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0 accepts even a stale push; body={body}"
    );
    assert_eq!(count_ns(&db, NS).await, 1, "stale push lands under opt-out");
}

// ---------------------------------------------------------------------------
// Postgres parity — the gate is backend-identical. It reads the local policy
// from the sqlite governance connection (`app.db`) and refuses BEFORE the
// postgres dispatch, so a stale push 409s on a pg-backed receiver without ever
// touching the `PostgresStore` (the "no pg verbatim-apply" property). Self-
// skips without `AI_MEMORY_TEST_POSTGRES_URL`; run with `--include-ignored`.
// ---------------------------------------------------------------------------
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live PG); run with --include-ignored"]
async fn stale_policy_version_refused_on_postgres_backend() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };

    let guard = ENV_LOCK.lock().await;
    reset_env();

    // Scratch sqlite carries the governance policy surface even on a pg node
    // (sqlite is the sole rules store on every backend — amendment 7).
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    advance_policy(&db, 4).await;

    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = std::sync::Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
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
        storage_backend: ai_memory::handlers::StorageBackend::Postgres,
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
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(
        ai_memory::handlers::ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: std::sync::Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app_state,
    );

    // Stale (seq 1 < local 4) → refuse before the pg dispatch.
    let (stale_status, stale_body) = post_push(
        &router,
        &push_body(&uuid::Uuid::new_v4().to_string(), Some(1)),
    )
    .await;
    // Fresh (seq 4 == local) → accepted → dispatched to the pg store.
    let (fresh_status, _) = post_push(
        &router,
        &push_body(&uuid::Uuid::new_v4().to_string(), Some(4)),
    )
    .await;
    drop(guard);

    assert_eq!(
        stale_status,
        StatusCode::CONFLICT,
        "pg-backed receiver refuses a stale push identically; body={stale_body}"
    );
    assert_eq!(
        stale_body["error"],
        ai_memory::federation::receive_auth::STALE_POLICY_ERROR_TAG
    );
    assert_eq!(
        fresh_status,
        StatusCode::OK,
        "a fresh push is accepted + dispatched to the pg store"
    );
}
