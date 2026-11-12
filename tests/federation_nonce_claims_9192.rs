// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9192 (PR #9187 review r1, classes C2 + C3; 3-agent vote 71472661) - an
//! accepted signed federation nonce is NEVER replayable, and a nonce store
//! that cannot answer refuses with 503 `nonce_store_unavailable`.
//!
//! Ruling R: the nonce carries no time, so the replay window is the key
//! lifetime. The invariant must hold for every cache bound, every restart and
//! every number of peers, on `/sync/push` and the signed `GET /sync/since`
//! alike. These cells drive the production router (`build_router`) in-process
//! over a real sqlite file under `.local-runs/`, so a restart is a second
//! router over the same file.

#![allow(clippy::too_many_lines)]
// The env_lock guard is held across .await on a current_thread runtime so no
// other test observes the intermediate `AI_MEMORY_FED_REQUIRE_*` state.
#![allow(clippy::await_holding_lock)]

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

struct Host {
    router: axum::Router,
    db_path: PathBuf,
}

/// The sender's keypair, enrolled (public half only) in `dir/keys` under
/// both [`ALICE`] and, when `readd` is set, [`ALICE_READDED`].
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

/// A receiver over `dir/ai-memory.db` (a second call is a daemon restart).
fn host_on(dir: &Path) -> Host {
    let db_path = dir.join("ai-memory.db");
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
    Host {
        router: ai_memory::build_router(api_key_state, app_state),
        db_path,
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

fn claim_rows(db_path: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("raw sqlite");
    conn.query_row(&format!("SELECT COUNT(*) FROM {CLAIMS_TABLE}"), [], |r| {
        r.get(0)
    })
    .expect("count claims")
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
#[tokio::test(flavor = "current_thread")]
async fn nonce_survives_cap_plus_one_and_is_shared_by_push_and_get_9192() {
    let _g = env_lock();
    require_sig_and_nonce();
    let dir = scratch("nonce-9192-cap-");
    let alice = enrol_alice(dir.path());
    let host = host_on(dir.path());
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
        claim_rows(&host.db_path),
        i64::try_from(flood).expect("flood fits i64") + 2,
        "one claim row per accepted nonce, none pruned"
    );
}

/// (a) restart - an accepted nonce is refused by a restarted receiver.
#[tokio::test(flavor = "current_thread")]
async fn nonce_is_refused_after_restart_9192() {
    let _g = env_lock();
    require_sig_and_nonce();
    let dir = scratch("nonce-9192-restart-");
    let alice = enrol_alice(dir.path());
    let push_nonce = test_nonce(PUSH_SEED, 0);
    let get_nonce = test_nonce(GET_SEED, 0);
    {
        let host = host_on(dir.path());
        assert_accepted(
            &push(&host, &alice, ALICE, &push_nonce, false).await,
            "push before restart",
        );
        assert_accepted(
            &get_since(&host, &alice, ALICE, &get_nonce).await,
            "GET before restart",
        );
    }
    let restarted = host_on(dir.path());
    assert_replay(
        &push(&restarted, &alice, ALICE, &push_nonce, false).await,
        "push after restart",
    );
    assert_replay(
        &get_since(&restarted, &alice, ALICE, &get_nonce).await,
        "GET after restart",
    );
}

/// (g) - the peer is removed and re-added (here: its key re-enrolled under a
/// new id): a nonce accepted under the old enrolment is still refused.
#[tokio::test(flavor = "current_thread")]
async fn nonce_is_refused_after_peer_readd_with_same_key_9192() {
    let _g = env_lock();
    require_sig_and_nonce();
    let dir = scratch("nonce-9192-readd-");
    let alice = enrol_alice(dir.path());
    let host = host_on(dir.path());
    let nonce = test_nonce(PUSH_SEED, 7);
    assert_accepted(
        &push(&host, &alice, ALICE, &nonce, false).await,
        "first push",
    );
    std::fs::remove_file(dir.path().join("keys").join(format!("{ALICE}.pub")))
        .expect("remove the old enrolment");
    reenrol_as(dir.path(), &alice, ALICE_READDED);
    assert_replay(
        &push(&host, &alice, ALICE_READDED, &nonce, false).await,
        "same key, re-added peer id",
    );
}

/// (i) - a bad signature and an oversize nonce add no claim row and evict
/// nothing (the earlier accepted nonce is still refused afterwards).
#[tokio::test(flavor = "current_thread")]
async fn bad_signature_and_oversize_nonce_add_no_rows_9192() {
    let _g = env_lock();
    require_sig_and_nonce();
    let dir = scratch("nonce-9192-reject-");
    let alice = enrol_alice(dir.path());
    let host = host_on(dir.path());
    let accepted = test_nonce(PUSH_SEED, 0);
    assert_accepted(
        &push(&host, &alice, ALICE, &accepted, false).await,
        "first push",
    );
    let before = claim_rows(&host.db_path);
    for i in 1..=8 {
        let got = push(&host, &alice, ALICE, &test_nonce(PUSH_SEED, i), true).await;
        assert_eq!(
            got.0,
            StatusCode::UNAUTHORIZED,
            "forged push {i}: {}",
            got.1
        );
    }
    let oversize = "n".repeat(OVERSIZE_NONCE_LEN);
    let got = push(&host, &alice, ALICE, &oversize, false).await;
    assert_eq!(got.0, StatusCode::UNAUTHORIZED, "oversize push: {}", got.1);
    assert_eq!(got.1["error"], OVERSIZE_TAG, "oversize push: {}", got.1);
    let got = get_since(&host, &alice, ALICE, &oversize).await;
    assert_eq!(got.0, StatusCode::UNAUTHORIZED, "oversize GET: {}", got.1);
    assert_eq!(got.1["error"], OVERSIZE_TAG, "oversize GET: {}", got.1);
    assert_eq!(
        claim_rows(&host.db_path),
        before,
        "rejected requests must not claim"
    );
    assert_replay(
        &push(&host, &alice, ALICE, &accepted, false).await,
        "the accepted nonce after the rejected flood",
    );
}

/// (e) - the claims store cannot answer: push and GET refuse with 503
/// `nonce_store_unavailable` (retryable), for a new nonce AND for one the
/// receiver already accepted, and nothing is admitted.
#[tokio::test(flavor = "current_thread")]
async fn store_outage_refuses_with_503_9192() {
    let _g = env_lock();
    require_sig_and_nonce();
    let dir = scratch("nonce-9192-outage-");
    let alice = enrol_alice(dir.path());
    let host = host_on(dir.path());
    let seen = test_nonce(OUTAGE_SEED, 0);
    assert_accepted(
        &push(&host, &alice, ALICE, &seen, false).await,
        "push before the outage",
    );
    {
        let conn = rusqlite::Connection::open(&host.db_path).expect("raw sqlite");
        conn.execute_batch(&format!("DROP TABLE {CLAIMS_TABLE}"))
            .expect("break the claims store");
    }
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
