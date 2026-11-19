// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #9596 — the durable per-peer sync clock that `GET /sync/since`
//! records must be keyed on the AUTHENTICATED peer, never on request
//! fields.
//!
//! The handler records a `sync_state(agent_id, peer_id)` watermark as a
//! side effect of a pull. Pre-fix both columns came from the request
//! (`X-Agent-Id` and `?peer=`), so one caller could write or advance the
//! clock row of another principal, including the server's own
//! `(local_id, peer)` cursor rows that the catch-up loop reads.
//!
//! Class invariant pinned here, for every combination in the tables:
//!   1. a request authenticated as peer P whose clock fields name anyone
//!      other than P is refused with the exact `sync_since_peer_mismatch`
//!      tag and writes NO `sync_state` row;
//!   2. a request with no authenticated peer writes NO `sync_state` row
//!      (the pull itself is served as before);
//!   3. a request authenticated as P that names only P records `(P, P)`.
//!
//! The fixture is the real production router (`ai_memory::build_router`)
//! with an enrolled Ed25519 peer key, signing the canonical GET bytes the
//! receiver verifies (same shape as `federation_sync_since_sig_1031`).
//! `sync_state` is a sqlite-only table (the postgres branch of the handler
//! never writes a clock), so only the sqlite cell applies.

#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tempfile::TempDir;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::peer_attestation::{PEER_ATTESTATION_ENV, PEER_ID_HEADER};
use ai_memory::federation::signing::{
    NONCE_HEADER, REQUIRE_NONCE_ENV, REQUIRE_SIG_ENV, SIGNATURE_HEADER, sign_body_with_nonce_header,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair as kp_mod;

/// The enrolled, signing peer.
const ALICE: &str = "ai:peer-alice";
/// A second principal the authenticated peer must not be able to key.
const VICTIM: &str = "ai:peer-victim";
/// Stands in for the server's own agent id: a `(SERVER, x)` row is the
/// shape of the catch-up cursor the daemon reads back.
const SERVER: &str = "ai:server-self";
const SYNC_SINCE_PATH: &str = "/api/v1/sync/since";
const MISMATCH_TAG: &str = "sync_since_peer_mismatch";
const KEY_DIR_ENV: &str = "AI_MEMORY_KEY_DIR";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";
/// Both peers may pull `public/*`, so the scope gate never short-circuits
/// before the clock write.
const ALLOWLIST: &str = r#"{"ai:peer-alice":{"allowed_namespaces":["public/*"]},"ai:peer-victim":{"allowed_namespaces":["public/*"]}}"#;
const SEED_NS: &str = "public/sync";
const SEED_UPDATED_AT: &str = "2026-01-02T03:04:05+00:00";
const BODY_CAP: usize = 4 * 1024 * 1024;
/// Owner-only mode the key store requires of its directory.
#[cfg(unix)]
const KEY_DIR_MODE: u32 = 0o700;

struct Fixture {
    router: axum::Router,
    alice: kp_mod::AgentKeypair,
    db_path: PathBuf,
    _db_tmp: tempfile::NamedTempFile,
    _key_tmp: TempDir,
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Posture for one test. Every var the handler reads is set or removed
/// explicitly, so no test inherits another's state.
fn set_posture(require_sig: bool) {
    // SAFETY: env mutation; every caller holds `env_lock()` for the whole
    // test, so no other test in this binary observes the intermediate state.
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, if require_sig { "1" } else { "0" });
        std::env::set_var(REQUIRE_NONCE_ENV, "1");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(TRUST_PEER_ENV);
        std::env::set_var(PEER_ATTESTATION_ENV, ALLOWLIST);
    }
}

fn clear_posture() {
    // SAFETY: as in `set_posture`.
    unsafe {
        for var in [
            REQUIRE_SIG_ENV,
            REQUIRE_NONCE_ENV,
            REQUIRE_ENROLLMENT_ENV,
            TRUST_PEER_ENV,
            PEER_ATTESTATION_ENV,
            KEY_DIR_ENV,
        ] {
            std::env::remove_var(var);
        }
    }
}

fn setup() -> Fixture {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let seed_conn = ai_memory::db::open(&db_path).expect("db::open");
    // One row in an allowed namespace so the pull has a watermark to record.
    seed_conn
        .execute(
            "INSERT INTO memories \
                 (id, tier, namespace, title, content, tags, priority, confidence, source, \
                  metadata, access_count, created_at, updated_at) \
             VALUES ('seed-9596', 'long', ?1, 'seed', 'body', '[]', 5, 1.0, 'api', \
                     json('{\"scope\":\"collective\"}'), 0, ?2, ?2)",
            rusqlite::params![SEED_NS, SEED_UPDATED_AT],
        )
        .expect("seed row");
    drop(seed_conn);
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));

    let key_tmp = TempDir::new().expect("key tempdir");
    // The key store refuses a group- or world-writable directory (#3198);
    // pin owner-only so the fixture does not depend on the caller's umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            key_tmp.path(),
            std::fs::Permissions::from_mode(KEY_DIR_MODE),
        )
        .expect("chmod key dir");
    }
    // SAFETY: env mutation under `env_lock()` (see `set_posture`).
    unsafe {
        std::env::set_var(KEY_DIR_ENV, key_tmp.path());
    }
    let alice = kp_mod::generate(ALICE).expect("generate alice keypair");
    let alice_pub_only = kp_mod::AgentKeypair {
        agent_id: alice.agent_id.clone(),
        public: alice.public,
        private: None,
    };
    kp_mod::save_public_only(&alice_pub_only, key_tmp.path()).expect("enrol alice pubkey");

    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
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
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
        ),
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
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    Fixture {
        router: ai_memory::build_router(api_key_state, app_state),
        alice,
        db_path,
        _db_tmp: db_tmp,
        _key_tmp: key_tmp,
    }
}

/// Canonical bytes the receiver verifies (`method \n path \n query`).
fn canonical_get(query: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"GET\n");
    v.extend_from_slice(SYNC_SINCE_PATH.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(query.as_bytes());
    v
}

/// The query string for one pull: `?peer=` only when `peer` is `Some`.
fn query_for(peer: Option<&str>) -> String {
    match peer {
        Some(p) => format!("limit=10&peer={p}"),
        None => "limit=10".to_string(),
    }
}

/// One pull. `sign_as_alice` signs the exact query with alice's key and a
/// fresh nonce; otherwise no signature headers are sent.
async fn pull(
    host: &Fixture,
    query: &str,
    peer_id_header: Option<&str>,
    agent_id_header: Option<&str>,
    sign_as_alice: bool,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("{SYNC_SINCE_PATH}?{query}"));
    if let Some(p) = peer_id_header {
        builder = builder.header(PEER_ID_HEADER, p);
    }
    if let Some(a) = agent_id_header {
        builder = builder.header(ai_memory::HEADER_AGENT_ID, a);
    }
    if sign_as_alice {
        let priv_key = host.alice.private.as_ref().expect("alice has private key");
        let nonce = uuid::Uuid::new_v4().to_string();
        let sig = sign_body_with_nonce_header(priv_key, &canonical_get(query), &nonce);
        builder = builder
            .header(SIGNATURE_HEADER, sig)
            .header(NONCE_HEADER, nonce);
    }
    let resp = host
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("router answers");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), BODY_CAP)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Every `(agent_id, peer_id)` row in `sync_state`, sorted.
fn clock_rows(host: &Fixture) -> Vec<(String, String)> {
    let conn = ai_memory::db::open(&host.db_path).expect("reopen for read");
    let mut stmt = conn
        .prepare("SELECT agent_id, peer_id FROM sync_state ORDER BY agent_id, peer_id")
        .expect("prepare");
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

/// Signed alice, clock fields naming someone else. `(?peer=, X-Agent-Id)`.
const MISMATCH_CASES: &[(Option<&str>, Option<&str>)] = &[
    // names another peer as the clock's peer
    (Some(VICTIM), None),
    // names another peer AND the server's own id as the clock owner: the
    // shape that would advance the server's own catch-up cursor
    (Some(VICTIM), Some(SERVER)),
    // its own peer id, but the server's id as the clock owner
    (Some(ALICE), Some(SERVER)),
    // its own peer id, another peer as the clock owner
    (Some(ALICE), Some(VICTIM)),
];

#[tokio::test(flavor = "current_thread")]
async fn authenticated_peer_naming_another_principal_is_refused_and_writes_no_clock_9596() {
    let _g = env_lock();
    for &(peer_param, agent_header) in MISMATCH_CASES {
        set_posture(true);
        let host = setup();
        let query = query_for(peer_param);
        let (status, body) = pull(&host, &query, Some(ALICE), agent_header, true).await;
        let rows = clock_rows(&host);
        clear_posture();
        assert_eq!(
            rows,
            Vec::<(String, String)>::new(),
            "#9596: a pull authenticated as {ALICE} naming peer={peer_param:?} \
             agent={agent_header:?} must write no clock row; body={body}"
        );
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "#9596: mismatch peer={peer_param:?} agent={agent_header:?} must be refused; body={body}"
        );
        assert_eq!(
            body["error"].as_str(),
            Some(MISMATCH_TAG),
            "#9596: refusal must carry the exact tag; body={body}"
        );
        assert_eq!(
            body["authenticated_peer"].as_str(),
            Some(ALICE),
            "#9596: refusal names the authenticated peer; body={body}"
        );
    }
}

/// No authenticated peer: `(X-Peer-Id, ?peer=, X-Agent-Id)` combinations a
/// caller can send without proving any identity (`REQUIRE_SIG=0`).
const UNAUTHENTICATED_CASES: &[(Option<&str>, Option<&str>, Option<&str>)] = &[
    (Some(VICTIM), Some(VICTIM), Some(SERVER)),
    (Some(ALICE), Some(ALICE), Some(ALICE)),
    (Some(VICTIM), Some(VICTIM), Some(VICTIM)),
];

#[tokio::test(flavor = "current_thread")]
async fn unauthenticated_pull_writes_no_clock_9596() {
    let _g = env_lock();
    for &(peer_header, peer_param, agent_header) in UNAUTHENTICATED_CASES {
        set_posture(false);
        let host = setup();
        let query = query_for(peer_param);
        let (status, body) = pull(&host, &query, peer_header, agent_header, false).await;
        let rows = clock_rows(&host);
        clear_posture();
        assert_eq!(
            rows,
            Vec::<(String, String)>::new(),
            "#9596: an unauthenticated pull (x-peer-id={peer_header:?} peer={peer_param:?} \
             agent={agent_header:?}) must write no clock row; body={body}"
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "#9596: the unauthenticated pull itself is still served; body={body}"
        );
        assert_eq!(
            body["count"].as_u64(),
            Some(1),
            "#9596: the seeded row is still projected; body={body}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn unsigned_pull_from_enrolled_peer_is_refused_and_writes_no_clock_9596() {
    let _g = env_lock();
    set_posture(true);
    let host = setup();
    let query = query_for(Some(ALICE));
    let (status, body) = pull(&host, &query, Some(ALICE), Some(ALICE), false).await;
    let rows = clock_rows(&host);
    clear_posture();
    assert_eq!(rows, Vec::<(String, String)>::new(), "body={body}");
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(
        body["error"].as_str(),
        Some("x_memory_sig_missing"),
        "body={body}"
    );
}

/// The authenticated peer naming only itself: with and without the
/// optional `X-Agent-Id` header (both production pullers send it equal to
/// `X-Peer-Id`).
const OWN_CLOCK_AGENT_HEADERS: &[Option<&str>] = &[Some(ALICE), None];

#[tokio::test(flavor = "current_thread")]
async fn authenticated_peer_records_only_its_own_clock_9596() {
    let _g = env_lock();
    for &agent_header in OWN_CLOCK_AGENT_HEADERS {
        set_posture(true);
        let host = setup();
        let query = query_for(Some(ALICE));
        let (status, body) = pull(&host, &query, Some(ALICE), agent_header, true).await;
        let rows = clock_rows(&host);
        let watermarks = {
            let conn = ai_memory::db::open(&host.db_path).expect("reopen for read");
            ai_memory::db::sync_state_load(&conn, ALICE).expect("load clock")
        };
        clear_posture();
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert_eq!(
            rows,
            vec![(ALICE.to_string(), ALICE.to_string())],
            "#9596: the clock is keyed (authenticated peer, authenticated peer); \
             agent={agent_header:?} body={body}"
        );
        assert!(
            watermarks.entries.contains_key(ALICE),
            "#9596: the recorded watermark is readable under the authenticated peer; \
             agent={agent_header:?}"
        );
    }
}

/// A pull that asks for no clock (no `?peer=`) writes none, authenticated
/// or not, exactly as before the fix.
#[tokio::test(flavor = "current_thread")]
async fn pull_without_peer_param_writes_no_clock_9596() {
    let _g = env_lock();
    set_posture(true);
    let host = setup();
    let query = query_for(None);
    let (status, body) = pull(&host, &query, Some(ALICE), Some(ALICE), true).await;
    let rows = clock_rows(&host);
    clear_posture();
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(rows, Vec::<(String, String)>::new(), "body={body}");
}
