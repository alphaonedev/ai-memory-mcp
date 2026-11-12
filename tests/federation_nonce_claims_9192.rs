// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9192 (PR #9187 review r1, classes C2 + C3; 3-agent vote 71472661) - an
//! accepted signed federation nonce is NEVER replayable, and a nonce store
//! that cannot answer refuses with 503 `nonce_store_unavailable`.
//!
//! Ruling R: the nonce carries no time, so the replay window is the key
//! lifetime. The invariant must hold for every cache bound, every restart and
//! every number of peers, on `/sync/push` and the signed `GET /sync/since`
//! alike, on sqlite AND PostgreSQL.
//!
//! Two layers of cells:
//! - HTTP cells drive the production router (`build_router`) in-process. The
//!   sqlite twin runs over a real file under `.local-runs/`; the `_pg` twin
//!   runs over its own scratch database (`common::pg_barrier::ScratchDb`,
//!   dropped on exit, never `ai_memory_test`). A restart is a second router
//!   over the same store.
//! - Store cells (`--features sal`) drive `FederationNonceCache::check_store`
//!   over the SAL store of each backend: every cache bound, more keys than the
//!   cache keeps, racing claimants, an outage, a commit-time failure, a
//!   cancelled claim and 100 000 claims with the measured bytes per row.

#![allow(clippy::too_many_lines)]
// The env_lock guard is held across .await on a current_thread runtime so no
// other test observes the intermediate `AI_MEMORY_FED_REQUIRE_*` state.
#![allow(clippy::await_holding_lock)]

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::signing::{
    NONCE_HEADER, REQUIRE_NONCE_ENV, REQUIRE_SIG_ENV, SIGNATURE_HEADER, canonical_get_bytes,
    sign_body_with_nonce_header,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair as kp_mod;
use ai_memory::identity::replay::FEDERATION_NONCE_CAPACITY_PER_PEER;

/// Seed of every push nonce these cells mint (deterministic, #9192 item 9).
const PUSH_SEED: &str = "nonce-9192-push";
/// Seed of every signed-GET nonce these cells mint.
const GET_SEED: &str = "nonce-9192-get";
/// Seed of the nonces the store-outage cells mint.
const OUTAGE_SEED: &str = "nonce-9192-outage";
/// The enrolled sender every cell signs as.
const ALICE: &str = "ai:peer-alice-9192";
/// A second enrolment of ALICE's key (the "removed and re-added" peer).
const ALICE_READDED: &str = "ai:peer-alice-readded-9192";
/// A nonce far larger than any bound the receiver may accept (#9192 item 6).
const OVERSIZE_NONCE_LEN: usize = 4096;
/// The push route.
const PUSH_PATH: &str = "/api/v1/sync/push";
/// The signed catch-up route.
const SINCE_PATH: &str = "/api/v1/sync/since";
/// The query every signed GET carries.
const SINCE_QUERY: &str = "limit=1";
/// The stable 401 replay tag.
const REPLAY_TAG: &str = "x_memory_nonce_replay";
/// The stable 401 oversize tag.
const OVERSIZE_TAG: &str = "x_memory_nonce_oversize";
/// The stable 503 store-outage error.
const STORE_UNAVAILABLE: &str = "nonce_store_unavailable";
/// The claims table the receiver writes (C1, schema v103).
const CLAIMS_TABLE: &str = "federation_nonce_claims";
/// Response bodies are tiny; this bounds the read.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Forged pushes the rejection cell sends.
const FORGED_PUSHES: u64 = 8;
/// The receiver's sqlite file inside a cell's scratch directory.
const DB_FILE: &str = "ai-memory.db";
/// The live-PostgreSQL admin URL (lane-minted database; never printed).
#[cfg(feature = "sal-postgres")]
const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
/// Prefix of every scratch database these cells create (swept by `ScratchDb`).
#[cfg(feature = "sal-postgres")]
const PG_SCRATCH_PREFIX: &str = "ai_memory_nonce9192";

/// Deterministic nonce `i` of `seed` (#9192 item 9).
fn test_nonce(seed: &str, i: u64) -> String {
    format!("{seed}-{i:016x}")
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Arm signature and nonce enforcement (the caller holds [`env_lock`]).
fn require_sig_and_nonce() {
    // SAFETY: env mutation under env_lock on a current_thread runtime.
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "1");
        std::env::set_var(REQUIRE_NONCE_ENV, "1");
    }
}

/// A scratch directory under `<repo>/.local-runs/` (never a tmpfs).
fn scratch(prefix: &str) -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("scratch root");
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(&root)
        .expect("scratch dir")
}

/// The live-PostgreSQL admin URL, or `None` (the `_pg` cells then skip).
#[cfg(feature = "sal-postgres")]
fn pg_admin_url() -> Option<String> {
    let url = std::env::var(PG_URL_ENV).ok().filter(|u| !u.is_empty());
    if url.is_none() {
        eprintln!("skip: {PG_URL_ENV} not set");
    }
    url
}

/// Which store a receiver runs over.
enum Backend {
    /// A sqlite file (`<dir>/ai-memory.db`).
    Sqlite(PathBuf),
    /// A PostgreSQL scratch database (its URL).
    #[cfg(feature = "sal-postgres")]
    Postgres(String),
}

/// How a cell reads (and breaks) the claims table behind a receiver.
enum Rows {
    Sqlite(PathBuf),
    #[cfg(feature = "sal-postgres")]
    Postgres(sqlx::PgPool),
}

// Without `sal-postgres` only the sqlite arms (no await) are compiled, hence
// the `unused_async` allowances below.
impl Rows {
    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn count(&self) -> i64 {
        let sql = format!("SELECT COUNT(*) FROM {CLAIMS_TABLE}");
        match self {
            Self::Sqlite(path) => rusqlite::Connection::open(path)
                .expect("raw sqlite")
                .query_row(&sql, [], |r| r.get(0))
                .expect("count claims"),
            #[cfg(feature = "sal-postgres")]
            Self::Postgres(pool) => sqlx::query_scalar(&sql)
                .fetch_one(pool)
                .await
                .expect("count claims"),
        }
    }

    /// Make every claim fail: the claims table is gone.
    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn break_store(&self) {
        let sql = format!("DROP TABLE {CLAIMS_TABLE}");
        match self {
            Self::Sqlite(path) => rusqlite::Connection::open(path)
                .expect("raw sqlite")
                .execute_batch(&sql)
                .expect("break the claims store"),
            #[cfg(feature = "sal-postgres")]
            Self::Postgres(pool) => {
                sqlx::raw_sql(&sql)
                    .execute(pool)
                    .await
                    .expect("break the claims store");
            }
        }
    }
}

struct Host {
    router: axum::Router,
    rows: Rows,
}

/// The sender's keypair, enrolled (public half only) in `dir/keys`.
fn enrol_alice(dir: &Path) -> kp_mod::AgentKeypair {
    let key_dir = dir.join("keys");
    std::fs::create_dir_all(&key_dir).expect("key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod key dir");
    }
    // SAFETY: env mutation under env_lock (see require_sig_and_nonce).
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", &key_dir);
    }
    let alice = kp_mod::generate(ALICE).expect("generate alice keypair");
    let public_only = kp_mod::AgentKeypair {
        agent_id: alice.agent_id.clone(),
        public: alice.public,
        private: None,
    };
    kp_mod::save_public_only(&public_only, &key_dir).expect("enrol alice");
    alice
}

/// Enrol `alice`'s public key under a second id (a removed-and-re-added peer).
fn reenrol_as(dir: &Path, alice: &kp_mod::AgentKeypair, agent_id: &str) {
    let public_only = kp_mod::AgentKeypair {
        agent_id: agent_id.to_string(),
        public: alice.public,
        private: None,
    };
    kp_mod::save_public_only(&public_only, &dir.join("keys")).expect("re-enrol alice");
}

/// A receiver over `backend` (a second call is a daemon restart: a fresh
/// process cache over the same store).
#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn host_on(backend: &Backend) -> Host {
    let (db_path, storage_backend, rows) = match backend {
        Backend::Sqlite(dir) => {
            let path = dir.join(DB_FILE);
            (path.clone(), StorageBackend::Sqlite, Rows::Sqlite(path))
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(_) => (
            PathBuf::from(":memory:"),
            StorageBackend::Postgres,
            // Replaced below once the store is connected.
            Rows::Sqlite(PathBuf::from(":memory:")),
        ),
    };
    #[cfg(feature = "sal")]
    let (store, rows): (Arc<dyn ai_memory::store::MemoryStore>, Rows) = match backend {
        Backend::Sqlite(_) => (
            Arc::new(
                ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
            ),
            rows,
        ),
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(url) => {
            let pg = ai_memory::store::postgres::PostgresStore::connect(url)
                .await
                .expect("connect postgres");
            let pool = pg.pool().clone();
            (Arc::new(pg), Rows::Postgres(pool))
        }
    };
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
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
        storage_backend,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(ai_memory::identity::replay::FederationNonceCache::new()),
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
    Host {
        router: ai_memory::build_router(api_key_state, app_state),
        rows,
    }
}

fn push_body(sender: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "sender_agent_id": sender,
        "sender_clock": {"entries": {}},
        "memories": [],
        "dry_run": false,
    }))
    .expect("push body")
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A signed push from `sender` with `nonce`; `forge` corrupts the signature.
async fn push(
    host: &Host,
    alice: &kp_mod::AgentKeypair,
    sender: &str,
    nonce: &str,
    forge: bool,
) -> (StatusCode, Value) {
    let body = push_body(sender);
    let key = alice.private.as_ref().expect("alice private key");
    let signed_over = if forge {
        b"forged".to_vec()
    } else {
        body.clone()
    };
    let sig = sign_body_with_nonce_header(key, &signed_over, nonce);
    let req = Request::builder()
        .method("POST")
        .uri(PUSH_PATH)
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            sender,
        )
        .header(SIGNATURE_HEADER, sig)
        .header(NONCE_HEADER, nonce)
        .body(Body::from(body))
        .expect("push request");
    send(&host.router, req).await
}

/// A signed `GET /sync/since` from `sender` with `nonce`.
async fn get_since(
    host: &Host,
    alice: &kp_mod::AgentKeypair,
    sender: &str,
    nonce: &str,
) -> (StatusCode, Value) {
    let key = alice.private.as_ref().expect("alice private key");
    let canonical = canonical_get_bytes("GET", SINCE_PATH, SINCE_QUERY);
    let sig = sign_body_with_nonce_header(key, &canonical, nonce);
    let req = Request::builder()
        .method("GET")
        .uri(format!("{SINCE_PATH}?{SINCE_QUERY}"))
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            sender,
        )
        .header(SIGNATURE_HEADER, sig)
        .header(NONCE_HEADER, nonce)
        .body(Body::empty())
        .expect("get request");
    send(&host.router, req).await
}

fn assert_replay(got: &(StatusCode, Value), what: &str) {
    assert_eq!(got.0, StatusCode::UNAUTHORIZED, "{what}: {}", got.1);
    assert_eq!(got.1["error"], REPLAY_TAG, "{what}: {}", got.1);
}

fn assert_accepted(got: &(StatusCode, Value), what: &str) {
    assert_eq!(got.0, StatusCode::OK, "{what}: {}", got.1);
}

/// (a)+(h) - the default cache bound plus one more accepted nonce, then the
/// FIRST push nonce and the first GET nonce (accepted before the flood) must
/// both still be refused; push and GET share one namespace both ways.
async fn cell_cap_plus_one_shared_namespace(dir: &Path, backend: &Backend) {
    let alice = enrol_alice(dir);
    let host = host_on(backend).await;
    assert_accepted(
        &get_since(&host, &alice, ALICE, &test_nonce(GET_SEED, 0)).await,
        "first GET nonce",
    );
    let flood = u64::try_from(FEDERATION_NONCE_CAPACITY_PER_PEER).expect("cap fits u64") + 1;
    for i in 0..flood {
        let got = push(&host, &alice, ALICE, &test_nonce(PUSH_SEED, i), false).await;
        assert_accepted(&got, &format!("fresh push nonce {i}"));
    }
    assert_replay(
        &push(&host, &alice, ALICE, &test_nonce(PUSH_SEED, 0), false).await,
        "push nonce 0 after cap+1 pushes",
    );
    assert_replay(
        &get_since(&host, &alice, ALICE, &test_nonce(GET_SEED, 0)).await,
        "GET nonce 0 after cap+1 pushes",
    );
    // Shared namespace, both directions.
    assert_replay(
        &get_since(&host, &alice, ALICE, &test_nonce(PUSH_SEED, 1)).await,
        "a push nonce replayed as a GET",
    );
    let get_first = test_nonce(GET_SEED, 1);
    assert_accepted(
        &get_since(&host, &alice, ALICE, &get_first).await,
        "fresh GET nonce",
    );
    assert_replay(
        &push(&host, &alice, ALICE, &get_first, false).await,
        "a GET nonce replayed as a push",
    );
    assert_eq!(
        host.rows.count().await,
        i64::try_from(flood).expect("flood fits i64") + 2,
        "one claim row per accepted nonce, none pruned"
    );
}

/// (a) restart - an accepted nonce is refused by a restarted receiver.
async fn cell_restart(dir: &Path, backend: &Backend) {
    let alice = enrol_alice(dir);
    let push_nonce = test_nonce(PUSH_SEED, 0);
    let get_nonce = test_nonce(GET_SEED, 0);
    {
        let host = host_on(backend).await;
        assert_accepted(
            &push(&host, &alice, ALICE, &push_nonce, false).await,
            "push before restart",
        );
        assert_accepted(
            &get_since(&host, &alice, ALICE, &get_nonce).await,
            "GET before restart",
        );
    }
    let restarted = host_on(backend).await;
    assert_replay(
        &push(&restarted, &alice, ALICE, &push_nonce, false).await,
        "push after restart",
    );
    assert_replay(
        &get_since(&restarted, &alice, ALICE, &get_nonce).await,
        "GET after restart",
    );
    assert_eq!(
        restarted.rows.count().await,
        2,
        "one row per accepted nonce"
    );
}

/// (g) - the peer is removed and re-added (here: its key re-enrolled under a
/// new id): a nonce accepted under the old enrolment is still refused.
async fn cell_peer_readd(dir: &Path, backend: &Backend) {
    let alice = enrol_alice(dir);
    let host = host_on(backend).await;
    let nonce = test_nonce(PUSH_SEED, 7);
    assert_accepted(
        &push(&host, &alice, ALICE, &nonce, false).await,
        "first push",
    );
    std::fs::remove_file(dir.join("keys").join(format!("{ALICE}.pub")))
        .expect("remove the old enrolment");
    reenrol_as(dir, &alice, ALICE_READDED);
    assert_replay(
        &push(&host, &alice, ALICE_READDED, &nonce, false).await,
        "same key, re-added peer id",
    );
    let restarted = host_on(backend).await;
    assert_replay(
        &push(&restarted, &alice, ALICE_READDED, &nonce, false).await,
        "same key, re-added peer id, after a restart",
    );
}

/// (i) - a bad signature and an oversize nonce add no claim row and evict
/// nothing (the earlier accepted nonce is still refused afterwards).
async fn cell_rejects_add_no_rows(dir: &Path, backend: &Backend) {
    let alice = enrol_alice(dir);
    let host = host_on(backend).await;
    let accepted = test_nonce(PUSH_SEED, 0);
    assert_accepted(
        &push(&host, &alice, ALICE, &accepted, false).await,
        "first push",
    );
    let before = host.rows.count().await;
    for i in 1..=FORGED_PUSHES {
        let got = push(&host, &alice, ALICE, &test_nonce(PUSH_SEED, i), true).await;
        assert_eq!(
            got.0,
            StatusCode::UNAUTHORIZED,
            "forged push {i}: {}",
            got.1
        );
        assert_ne!(got.1["error"], REPLAY_TAG, "forged push {i}: {}", got.1);
    }
    let oversize = "n".repeat(OVERSIZE_NONCE_LEN);
    let got = push(&host, &alice, ALICE, &oversize, false).await;
    assert_eq!(got.0, StatusCode::UNAUTHORIZED, "oversize push: {}", got.1);
    assert_eq!(got.1["error"], OVERSIZE_TAG, "oversize push: {}", got.1);
    let got = get_since(&host, &alice, ALICE, &oversize).await;
    assert_eq!(got.0, StatusCode::UNAUTHORIZED, "oversize GET: {}", got.1);
    assert_eq!(got.1["error"], OVERSIZE_TAG, "oversize GET: {}", got.1);
    assert_eq!(
        host.rows.count().await,
        before,
        "rejected requests must not claim"
    );
    assert_replay(
        &push(&host, &alice, ALICE, &accepted, false).await,
        "the accepted nonce after the rejected flood",
    );
    // A forged nonce was never claimed: signed properly, it is fresh.
    assert_accepted(
        &push(&host, &alice, ALICE, &test_nonce(PUSH_SEED, 1), false).await,
        "a nonce first seen on a forged request",
    );
}

/// (e) - the claims store cannot answer: push and GET refuse with 503
/// `nonce_store_unavailable` (retryable), for a new nonce AND for one the
/// receiver already accepted (and cached), and nothing is admitted.
async fn cell_store_outage(dir: &Path, backend: &Backend) {
    let alice = enrol_alice(dir);
    let host = host_on(backend).await;
    let seen = test_nonce(OUTAGE_SEED, 0);
    assert_accepted(
        &push(&host, &alice, ALICE, &seen, false).await,
        "push before the outage",
    );
    host.rows.break_store().await;
    for (nonce, what) in [
        (seen.clone(), "cached nonce"),
        (test_nonce(OUTAGE_SEED, 1), "new nonce"),
    ] {
        for (got, route) in [
            (push(&host, &alice, ALICE, &nonce, false).await, "push"),
            (get_since(&host, &alice, ALICE, &nonce).await, "GET"),
        ] {
            assert_eq!(
                got.0,
                StatusCode::SERVICE_UNAVAILABLE,
                "{route} {what} during outage: {}",
                got.1
            );
            assert_eq!(
                got.1["error"], STORE_UNAVAILABLE,
                "{route} {what}: {}",
                got.1
            );
        }
    }
}

/// One sqlite HTTP cell and its `_pg` twin over a fresh scratch database.
macro_rules! http_twin {
    ($cell:ident, $sqlite:ident, $pg:ident, $prefix:literal) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $sqlite() {
            let _g = env_lock();
            require_sig_and_nonce();
            let dir = scratch($prefix);
            $cell(dir.path(), &Backend::Sqlite(dir.path().to_path_buf())).await;
        }

        #[cfg(feature = "sal-postgres")]
        #[tokio::test(flavor = "current_thread")]
        async fn $pg() {
            let Some(admin) = pg_admin_url() else {
                return;
            };
            let _g = env_lock();
            require_sig_and_nonce();
            let dir = scratch($prefix);
            let db = pg_barrier::ScratchDb::create(&admin, PG_SCRATCH_PREFIX)
                .await
                .expect("create scratch database");
            $cell(dir.path(), &Backend::Postgres(db.url())).await;
        }
    };
}

http_twin!(
    cell_cap_plus_one_shared_namespace,
    nonce_survives_cap_plus_one_and_is_shared_by_push_and_get_9192,
    nonce_survives_cap_plus_one_and_is_shared_by_push_and_get_pg_9192,
    "nonce-9192-cap-"
);
http_twin!(
    cell_restart,
    nonce_is_refused_after_restart_9192,
    nonce_is_refused_after_restart_pg_9192,
    "nonce-9192-restart-"
);
http_twin!(
    cell_peer_readd,
    nonce_is_refused_after_peer_readd_with_same_key_9192,
    nonce_is_refused_after_peer_readd_with_same_key_pg_9192,
    "nonce-9192-readd-"
);
http_twin!(
    cell_rejects_add_no_rows,
    bad_signature_and_oversize_nonce_add_no_rows_9192,
    bad_signature_and_oversize_nonce_add_no_rows_pg_9192,
    "nonce-9192-reject-"
);
http_twin!(
    cell_store_outage,
    store_outage_refuses_with_503_9192,
    store_outage_refuses_with_503_pg_9192,
    "nonce-9192-outage-"
);

/// Store cells: `FederationNonceCache::check_store` over each backend's SAL
/// store (the path the PostgreSQL receiver takes).
#[cfg(feature = "sal")]
mod store_cells {
    use super::{Backend, DB_FILE, Rows, scratch, test_nonce};
    use ai_memory::identity::replay::{
        FEDERATION_NONCE_CAPACITY_PER_PEER, FEDERATION_NONCE_MAX_PEERS, FederationNonceCache,
        NonceClaimKey, ReplayDecision,
    };
    use ai_memory::store::MemoryStore;
    use std::sync::Arc;
    use std::time::Duration;

    /// Seed of every store-cell nonce (#9192 item 9).
    const STORE_SEED: &str = "nonce-9192-store";
    /// The cache bounds every invariant cell runs over (#9192 test a).
    const CAPS: [usize; 4] = [0, 1, 3, FEDERATION_NONCE_CAPACITY_PER_PEER];
    /// Keys beyond the cache's slot bound (#9192 test a).
    const EXTRA_KEYS: usize = 2;
    /// The peer id the store cells claim as.
    const PEER: &str = "ai:peer-9192-store";
    /// Racing claimants of one nonce (#9192 test d).
    const RACERS: usize = 8;
    /// How long the cancellation cell lets a blocked claim run before it drops
    /// the future (#9192 test f).
    const CANCEL_AFTER: Duration = Duration::from_millis(300);
    /// How long the sqlite cancellation cell waits for the blocker to take the
    /// store's connection before it starts the claim it cancels.
    const BLOCKER_SETTLE: Duration = Duration::from_millis(200);
    /// The 100K-claim cell's size (#9192 test k). The sqlite twin is the
    /// `identity::replay` unit cell (the sqlite daemon claims through
    /// `check_with_conn`, not through the SAL store).
    #[cfg(feature = "sal-postgres")]
    const BULK_CLAIMS: u64 = 100_000;
    /// Wall-clock ceiling of the 100K cell: every claim is its own committed
    /// transaction, so this bounds linear cost; a quadratic regression would
    /// be orders of magnitude over it.
    #[cfg(feature = "sal-postgres")]
    const BULK_CEILING: Duration = Duration::from_secs(600);
    /// Growth ratchet: bytes per claim row, PRIMARY KEY index included.
    #[cfg(feature = "sal-postgres")]
    const BYTES_PER_ROW_CEILING: u64 = 256;

    /// The `i`-th of many distinct verifying keys.
    fn nth_key(i: u64) -> [u8; 32] {
        let mut k = [0xC3_u8; 32];
        k[..8].copy_from_slice(&i.to_be_bytes());
        k
    }

    fn key(verifying_key: u64, seed: &str, i: u64) -> NonceClaimKey {
        NonceClaimKey::for_verifying_key(&nth_key(verifying_key), PEER, &test_nonce(seed, i))
            .expect("claim key")
    }

    fn as_u64(n: usize) -> u64 {
        u64::try_from(n).expect("usize fits u64")
    }

    /// A fresh SAL handle on `backend` (a second call is a second daemon).
    #[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
    async fn open_store(backend: &Backend) -> (Arc<dyn MemoryStore>, Rows) {
        match backend {
            Backend::Sqlite(dir) => {
                let path = dir.join(DB_FILE);
                let store =
                    ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore");
                (Arc::new(store), Rows::Sqlite(path))
            }
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres(url) => {
                let pg = ai_memory::store::postgres::PostgresStore::connect(url)
                    .await
                    .expect("connect postgres");
                let pool = pg.pool().clone();
                (Arc::new(pg), Rows::Postgres(pool))
            }
        }
    }

    /// (a) + (b) + (c) — for every cache bound (0 included): cap+1 accepted
    /// nonces on key 0 and one nonce on each of more keys than the cache keeps;
    /// every one is then a replay through the same cache, through a restarted
    /// cache, and through a second handle on the store.
    async fn cell_every_cap(backend: &Backend) {
        for cap in CAPS {
            let seed = format!("{STORE_SEED}-cap{cap}");
            let (store, rows) = open_store(backend).await;
            let before = rows.count().await;
            let cache = FederationNonceCache::with_capacity(cap);
            assert_eq!(cache.capacity(), cap);
            let flood = as_u64(cap) + 1;
            let keys = as_u64(FEDERATION_NONCE_MAX_PEERS + EXTRA_KEYS);
            let mut claimed = Vec::new();
            for i in 0..flood {
                claimed.push(key(0, &seed, i));
            }
            for k in 1..=keys {
                claimed.push(key(k, &seed, 0));
            }
            for k in &claimed {
                assert_eq!(
                    cache.check_store(store.as_ref(), k).await,
                    ReplayDecision::Fresh,
                    "cap {cap}: first claim"
                );
            }
            assert!(cache.len_for_key(claimed[0].key_fp()) <= cap, "cap {cap}");
            assert!(
                cache.peer_count() <= FEDERATION_NONCE_MAX_PEERS,
                "cap {cap}"
            );
            if cap == 0 {
                assert_eq!(cache.peer_count(), 0, "cap 0 caches nothing");
            }
            for k in &claimed {
                assert_eq!(
                    cache.check_store(store.as_ref(), k).await,
                    ReplayDecision::Replay,
                    "cap {cap}: same cache"
                );
            }
            let restarted = FederationNonceCache::with_capacity(cap);
            let (second, _) = open_store(backend).await;
            for k in &claimed {
                assert_eq!(
                    restarted.check_store(second.as_ref(), k).await,
                    ReplayDecision::Replay,
                    "cap {cap}: restarted cache on a second handle"
                );
            }
            let added = rows.count().await - before;
            assert_eq!(
                added,
                i64::try_from(claimed.len()).expect("fits i64"),
                "cap {cap}: one row per claim, none pruned"
            );
        }
    }

    /// (d) — RACERS claimants of one nonce at once: exactly one Fresh, at cap
    /// 0 and at the default bound, with one shared cache and with one cache
    /// (and one store handle) per racer.
    async fn cell_race(backend: &Backend) {
        for cap in [0, FEDERATION_NONCE_CAPACITY_PER_PEER] {
            for shared in [true, false] {
                let target = key(1, &format!("{STORE_SEED}-race-{cap}-{shared}"), 0);
                let shared_cache = Arc::new(FederationNonceCache::with_capacity(cap));
                let (shared_store, _) = open_store(backend).await;
                let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
                let mut tasks = Vec::new();
                for _ in 0..RACERS {
                    let (cache, store) = if shared {
                        (Arc::clone(&shared_cache), Arc::clone(&shared_store))
                    } else {
                        (
                            Arc::new(FederationNonceCache::with_capacity(cap)),
                            open_store(backend).await.0,
                        )
                    };
                    let barrier = Arc::clone(&barrier);
                    let target = target.clone();
                    tasks.push(tokio::spawn(async move {
                        barrier.wait().await;
                        cache.check_store(store.as_ref(), &target).await
                    }));
                }
                let mut decisions = Vec::new();
                for t in tasks {
                    decisions.push(t.await.expect("racer"));
                }
                let fresh = decisions
                    .iter()
                    .filter(|d| **d == ReplayDecision::Fresh)
                    .count();
                let replay = decisions
                    .iter()
                    .filter(|d| **d == ReplayDecision::Replay)
                    .count();
                assert_eq!(
                    (fresh, replay),
                    (1, RACERS - 1),
                    "cap {cap} shared {shared}: {decisions:?}"
                );
            }
        }
    }

    /// (e) — the store twin of `issue_9140_store_claim_error`: the claims
    /// table is gone; a cached AND a new nonce are `Unavailable` (never Replay,
    /// never Fresh), the new one leaves no cache entry, the counter moves once
    /// per refusal.
    async fn cell_outage(backend: &Backend) {
        let (store, rows) = open_store(backend).await;
        let cache = FederationNonceCache::new();
        let cached = key(1, STORE_SEED, 1);
        assert_eq!(
            cache.check_store(store.as_ref(), &cached).await,
            ReplayDecision::Fresh
        );
        rows.break_store().await;
        let fresh = key(1, STORE_SEED, 2);
        let before = ai_memory::metrics::federation_nonce_store_unavailable_count();
        assert_eq!(
            cache.check_store(store.as_ref(), &cached).await,
            ReplayDecision::Unavailable,
            "cached nonce during the outage"
        );
        assert_eq!(
            cache.check_store(store.as_ref(), &fresh).await,
            ReplayDecision::Unavailable,
            "new nonce during the outage"
        );
        assert!(
            !cache.is_cached(&fresh),
            "an unanswered claim caches nothing"
        );
        assert!(
            ai_memory::metrics::federation_nonce_store_unavailable_count() - before >= 2,
            "the unavailable counter moves on each refusal"
        );
    }

    /// (f) — a claim whose future is dropped while the store is blocked leaves
    /// no cache entry, and the nonce is claimable once the store frees up.
    async fn cell_cancelled_claim_sqlite(dir: &std::path::Path) {
        let backend = Backend::Sqlite(dir.to_path_buf());
        let (store, _) = open_store(&backend).await;
        let blocker = rusqlite::Connection::open(dir.join(DB_FILE)).expect("raw sqlite");
        blocker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold the write lock");
        // The holder takes the store's connection and waits on the write lock.
        let holder_store = Arc::clone(&store);
        let holder = tokio::spawn(async move {
            FederationNonceCache::new()
                .check_store(holder_store.as_ref(), &key(2, STORE_SEED, 0))
                .await
        });
        tokio::time::sleep(BLOCKER_SETTLE).await;
        let cache = FederationNonceCache::new();
        let target = key(2, STORE_SEED, 1);
        let cancelled =
            tokio::time::timeout(CANCEL_AFTER, cache.check_store(store.as_ref(), &target)).await;
        assert!(
            cancelled.is_err(),
            "the claim was still waiting: {cancelled:?}"
        );
        assert!(!cache.is_cached(&target), "a dropped claim caches nothing");
        blocker.execute_batch("COMMIT").expect("release");
        assert_eq!(holder.await.expect("holder"), ReplayDecision::Fresh);
        assert_eq!(
            cache.check_store(store.as_ref(), &target).await,
            ReplayDecision::Fresh,
            "the cancelled nonce was never admitted"
        );
    }

    /// (k) — 100 000 distinct claims on one key stay linear and bounded: every
    /// one is fresh, one row each, the cache holds at most its bound, under a
    /// fixed wall-clock ceiling; returns the measured bytes per row.
    #[cfg(feature = "sal-postgres")]
    async fn cell_bulk(backend: &Backend) -> u64 {
        let (store, rows) = open_store(backend).await;
        let cache = FederationNonceCache::new();
        let started = std::time::Instant::now();
        for i in 0..BULK_CLAIMS {
            assert_eq!(
                cache
                    .check_store(store.as_ref(), &key(3, STORE_SEED, i))
                    .await,
                ReplayDecision::Fresh,
                "bulk claim {i}"
            );
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < BULK_CEILING,
            "{BULK_CLAIMS} claims took {elapsed:?}"
        );
        assert_eq!(
            rows.count().await,
            i64::try_from(BULK_CLAIMS).expect("fits i64")
        );
        assert_eq!(
            cache.len_for_key(key(3, STORE_SEED, 0).key_fp()),
            FEDERATION_NONCE_CAPACITY_PER_PEER
        );
        assert_eq!(
            cache
                .check_store(store.as_ref(), &key(3, STORE_SEED, 0))
                .await,
            ReplayDecision::Replay
        );
        let Rows::Postgres(pool) = &rows else {
            unreachable!("the bulk cell runs on postgres")
        };
        let bytes = table_bytes(pool).await;
        let per_row = bytes / BULK_CLAIMS;
        eprintln!(
            "#9192 growth: {BULK_CLAIMS} claims in {elapsed:?}, {bytes} bytes, {per_row} bytes/row"
        );
        assert!(
            per_row <= BYTES_PER_ROW_CEILING,
            "{per_row} bytes per claim row exceeds {BYTES_PER_ROW_CEILING}"
        );
        per_row
    }

    /// Bytes the claims table occupies: heap, PRIMARY KEY index and TOAST.
    #[cfg(feature = "sal-postgres")]
    async fn table_bytes(pool: &sqlx::PgPool) -> u64 {
        let bytes: i64 = sqlx::query_scalar("SELECT pg_total_relation_size($1::regclass)")
            .bind(super::CLAIMS_TABLE)
            .fetch_one(pool)
            .await
            .expect("pg_total_relation_size");
        u64::try_from(bytes).expect("non-negative size")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_cap_restart_handle_and_peer_count_refuses_9192() {
        let dir = scratch("nonce-9192-store-cap-");
        cell_every_cap(&Backend::Sqlite(dir.path().to_path_buf())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_identical_claims_admit_exactly_one_9192() {
        let dir = scratch("nonce-9192-store-race-");
        cell_race(&Backend::Sqlite(dir.path().to_path_buf())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn store_outage_is_unavailable_for_cached_and_new_9192() {
        let dir = scratch("nonce-9192-store-outage-");
        cell_outage(&Backend::Sqlite(dir.path().to_path_buf())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelled_claim_leaves_no_cache_entry_9192() {
        let dir = scratch("nonce-9192-store-cancel-");
        cell_cancelled_claim_sqlite(dir.path()).await;
    }

    #[cfg(feature = "sal-postgres")]
    mod pg {
        use super::super::{CLAIMS_TABLE, Rows};
        use super::super::{PG_SCRATCH_PREFIX, pg_admin_url, pg_barrier};
        use super::{
            Backend, CANCEL_AFTER, FederationNonceCache, ReplayDecision, STORE_SEED, cell_bulk,
            cell_every_cap, cell_outage, cell_race, key, open_store,
        };

        /// A deferred check that raises at COMMIT for every claim row.
        const FAIL_FN_DDL: &str = "CREATE FUNCTION public.nonce_9192_fail() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN \
             RAISE EXCEPTION 'issue 9192 forced claim commit failure'; END $$";
        /// The constraint trigger fires at COMMIT (after the INSERT returned).
        const FAIL_TRIGGER_DDL: &str = "CREATE CONSTRAINT TRIGGER nonce_9192_fail_at_commit \
             AFTER INSERT ON federation_nonce_claims DEFERRABLE INITIALLY DEFERRED \
             FOR EACH ROW EXECUTE FUNCTION public.nonce_9192_fail()";
        const DISARM_DDL: &str =
            "DROP TRIGGER nonce_9192_fail_at_commit ON federation_nonce_claims";

        async fn scratch_db() -> Option<pg_barrier::ScratchDb> {
            let admin = pg_admin_url()?;
            Some(
                pg_barrier::ScratchDb::create(&admin, PG_SCRATCH_PREFIX)
                    .await
                    .expect("create scratch database"),
            )
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn every_cap_restart_handle_and_peer_count_refuses_pg_9192() {
            let Some(db) = scratch_db().await else { return };
            cell_every_cap(&Backend::Postgres(db.url())).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn concurrent_identical_claims_admit_exactly_one_pg_9192() {
            let Some(db) = scratch_db().await else { return };
            cell_race(&Backend::Postgres(db.url())).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn store_outage_is_unavailable_for_cached_and_new_pg_9192() {
            let Some(db) = scratch_db().await else { return };
            cell_outage(&Backend::Postgres(db.url())).await;
        }

        /// (e) commit-error cell — the claim's COMMIT fails: `Unavailable`, no
        /// row, no cache entry; after recovery the nonce is claimable.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn claim_commit_error_is_unavailable_and_writes_nothing_pg_9192() {
            let Some(db) = scratch_db().await else { return };
            let backend = Backend::Postgres(db.url());
            let (store, rows) = open_store(&backend).await;
            let Rows::Postgres(pool) = &rows else {
                unreachable!("a postgres backend")
            };
            for ddl in [FAIL_FN_DDL, FAIL_TRIGGER_DDL] {
                sqlx::raw_sql(ddl)
                    .execute(pool)
                    .await
                    .expect("arm the commit failure");
            }
            let cache = FederationNonceCache::new();
            let k = key(4, STORE_SEED, 0);
            assert_eq!(
                cache.check_store(store.as_ref(), &k).await,
                ReplayDecision::Unavailable
            );
            assert!(!cache.is_cached(&k));
            assert_eq!(rows.count().await, 0, "the failed commit wrote nothing");
            sqlx::raw_sql(DISARM_DDL)
                .execute(pool)
                .await
                .expect("disarm");
            assert_eq!(
                cache.check_store(store.as_ref(), &k).await,
                ReplayDecision::Fresh,
                "after recovery the never-admitted nonce is claimable"
            );
        }

        /// (f) — a claim blocked on a conflicting uncommitted claim is dropped:
        /// no cache entry; once the other transaction rolls back, the nonce is
        /// claimable exactly once.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn cancelled_claim_leaves_no_cache_entry_pg_9192() {
            let Some(db) = scratch_db().await else { return };
            let backend = Backend::Postgres(db.url());
            let (store, rows) = open_store(&backend).await;
            let Rows::Postgres(pool) = &rows else {
                unreachable!("a postgres backend")
            };
            let target = key(5, STORE_SEED, 0);
            let mut blocker = pool.begin().await.expect("blocker tx");
            sqlx::query(&format!(
                "INSERT INTO {CLAIMS_TABLE} (key_fp, nonce_fp) VALUES ($1, $2)"
            ))
            .bind(target.key_fp().as_slice())
            .bind(target.nonce_fp().as_slice())
            .execute(&mut *blocker)
            .await
            .expect("uncommitted conflicting claim");
            let cache = FederationNonceCache::new();
            let cancelled =
                tokio::time::timeout(CANCEL_AFTER, cache.check_store(store.as_ref(), &target))
                    .await;
            assert!(
                cancelled.is_err(),
                "the claim was still waiting: {cancelled:?}"
            );
            assert!(!cache.is_cached(&target), "a dropped claim caches nothing");
            blocker.rollback().await.expect("roll the blocker back");
            assert_eq!(
                cache.check_store(store.as_ref(), &target).await,
                ReplayDecision::Fresh,
                "the cancelled claim admitted nothing"
            );
            assert_eq!(
                cache.check_store(store.as_ref(), &target).await,
                ReplayDecision::Replay
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn hundred_thousand_claims_stay_bounded_pg_9192() {
            let Some(db) = scratch_db().await else { return };
            cell_bulk(&Backend::Postgres(db.url())).await;
        }
    }
}
