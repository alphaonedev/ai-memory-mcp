// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9766 (refs #9367, #9341) - behavioural cells for the `/api/v1/sync/*`
//! exemption from the authority chokepoint, against a receiver in Enforce
//! mode with per-agent keys enrolled and no shared key.
//!
//! ## What the exemption is
//! `authority_layer` (`src/handlers/authority.rs`) resolves the caller
//! identity of every non-exempt route. A present `X-Agent-Id` that fails
//! `validate::validate_agent_id` (a reserved internal name such as `system`
//! is one) is refused 400 `VALIDATION_FAILED`. `AUTHORITY_EXEMPT_PREFIXES`
//! holds `/api/v1/sync/`: peer sync authenticates through the cert-peer
//! binding and the `X-Memory-Sig` body signature instead, so the layer must
//! not run on those routes. The gate in `identity_binding` that answers 403
//! `attested_identity_required` is never reached by a sync handler.
//!
//! ## Why a rewriting recorder
//! The real outbound clients always send a valid `X-Agent-Id` (their own
//! id), so a receiver without the exemption would still answer them. To make
//! the exemption observable, the receiver router is wrapped in one outermost
//! test middleware that (a) replaces `X-Agent-Id` with the reserved value
//! [`RESERVED_AGENT_ID`] on `/api/v1/sync/*` requests only and (b) records
//! the exact status and body the production router answered. The production
//! router (`build_router`) and the production clients are otherwise
//! untouched. With the exemption removed the layer refuses the rewritten
//! header 400 with the layer's body and every sync cell goes red (`/sync/since`
//! answers 200 only when exempt; `/sync/push` validates the header itself, so
//! its handler-shaped 400 body, without `code`, is what proves the layer was
//! skipped); the control cell proves the same header IS refused by the layer
//! on a non-exempt route, so the sync cells cannot pass vacuously.
//!
//! ## Backend
//! The authority layer runs before any handler and never touches the store,
//! so the property under test is the same on sqlite and postgres; the cells
//! use the sqlite default. A postgres cell would exercise the sync handlers,
//! not the exemption.

#![allow(clippy::await_holding_lock)]
#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::Value;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::signing::{REQUIRE_NONCE_ENV, REQUIRE_SIG_ENV};
use ai_memory::federation::{FederationConfig, PeerEndpoint, sync};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair as kp_mod;
use ai_memory::models::{Memory, Tier};
use ai_memory::replication::QuorumPolicy;

/// The receiver's key directory env var (read by the signature gate).
const KEY_DIR_ENV: &str = "AI_MEMORY_KEY_DIR";
/// A name `validate_agent_id` refuses as reserved for internal use.
const RESERVED_AGENT_ID: &str = "system";
/// Exact refusal text `validate_agent_id` produces for [`RESERVED_AGENT_ID`].
const RESERVED_REFUSAL: &str =
    "agent_id 'system' is reserved for internal use and cannot be supplied by wire callers";
/// Prefix the authority layer puts on its refusal (`HeaderIdentityInvalid`).
const LAYER_REFUSAL_PREFIX: &str = "invalid agent_id: ";
/// Prefix `sync_push` puts on its own, handler-level refusal of the same value.
const HANDLER_REFUSAL_PREFIX: &str = "invalid x-agent-id: ";
/// Exempt route family under test.
const SYNC_PATH_PREFIX: &str = "/api/v1/sync/";
/// Non-exempt control route.
const CONTROL_PATH: &str = "/api/v1/memories";
/// The sender (and enrolled peer) id of the cells.
const PEER_ID: &str = "ai:node-9766";
/// Body cap for the recorder.
const BODY_CAP: usize = 4 * 1024 * 1024;
/// The enrolled per-agent api key (never sent by the sync clients).
const ENROLLED_TOKEN: &str = "enrolled-9766-token";
const ENROLLED_AGENT: &str = "enrolled-agent-9766";

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One request the receiver answered: path, exact status, parsed body.
#[derive(Clone, Debug)]
struct Row {
    path: String,
    status: StatusCode,
    body: Value,
}

type Rows = Arc<StdMutex<Vec<Row>>>;

fn rows_for(rows: &Rows, path: &str) -> Vec<Row> {
    rows.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|r| r.path == path)
        .cloned()
        .collect()
}

async fn rewrite_and_record(
    State(rows): State<Rows>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    if path.starts_with(SYNC_PATH_PREFIX) {
        req.headers_mut().insert(
            ai_memory::HEADER_AGENT_ID,
            HeaderValue::from_static(RESERVED_AGENT_ID),
        );
    }
    let resp = next.run(req).await;
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, BODY_CAP)
        .await
        .unwrap_or_default();
    rows.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Row {
            path,
            status: parts.status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        });
    Response::from_parts(parts, Body::from(bytes))
}

fn enrolled_keys() -> Arc<EnrolledAgentKeys> {
    let mut m = HashMap::new();
    m.insert(
        api_key_sha256_hex(ENROLLED_TOKEN),
        ENROLLED_AGENT.to_string(),
    );
    Arc::new(EnrolledAgentKeys::from_map(m))
}

struct Receiver {
    url: String,
    rows: Rows,
    _db: tempfile::NamedTempFile,
    _keys: TempDir,
}

/// Scratch root under the repository's gitignored run directory (no tmpfs).
fn scratch_root() -> std::path::PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-9766-sync-exempt");
    std::fs::create_dir_all(&root).expect("create scratch root");
    root
}

/// Key directory owner-only (0700): the key loader refuses a group- or
/// world-writable directory (#3198).
fn private_key_dir() -> TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir_in(scratch_root()).expect("receiver key dir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 key dir");
    dir
}

fn scratch_db() -> tempfile::NamedTempFile {
    tempfile::NamedTempFile::new_in(scratch_root()).expect("scratch db file")
}

/// Production router in Enforce mode: per-agent keys enrolled, NO shared key,
/// the sender's public key enrolled on disk, wrapped in the recorder.
async fn spawn_receiver(sender_pub: &kp_mod::AgentKeypair) -> Receiver {
    let db_tmp = scratch_db();
    let db_path = db_tmp.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));

    let key_dir = private_key_dir();
    // SAFETY: env mutation; the caller holds `env_lock` for the whole test.
    unsafe {
        std::env::set_var(KEY_DIR_ENV, key_dir.path());
        std::env::set_var(REQUIRE_SIG_ENV, "1");
        std::env::set_var(REQUIRE_NONCE_ENV, "0");
    }
    let pub_only = kp_mod::AgentKeypair {
        agent_id: sender_pub.agent_id.clone(),
        public: sender_pub.public,
        private: None,
    };
    kp_mod::save_public_only(&pub_only, key_dir.path()).expect("enrol sender pubkey on receiver");

    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: enrolled_keys(),
        identity_mode: HttpIdentityMode::Enforce,
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
        llm_call_timeout: Duration::from_secs(30),
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
        enrolled_agent_keys: enrolled_keys(),
        http_identity_mode: HttpIdentityMode::Enforce,
    };
    let rows: Rows = Arc::new(StdMutex::new(Vec::new()));
    let router: Router = ai_memory::build_router(api_key_state, app_state).layer(
        axum::middleware::from_fn_with_state(rows.clone(), rewrite_and_record),
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind receiver");
    let addr = listener.local_addr().expect("receiver addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    Receiver {
        url: format!("http://{addr}"),
        rows,
        _db: db_tmp,
        _keys: key_dir,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client")
}

fn clear_env() {
    // SAFETY: env mutation; the caller holds `env_lock`.
    unsafe {
        std::env::remove_var(KEY_DIR_ENV);
        std::env::remove_var(REQUIRE_SIG_ENV);
        std::env::remove_var(REQUIRE_NONCE_ENV);
    }
}

fn memory(id: &str, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        title: format!("title-{id}"),
        content: format!("content-{id}"),
        namespace: ns.to_string(),
        tier: Tier::Mid,
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    }
}

/// Control: the reserved `X-Agent-Id` IS refused on a non-exempt route of the
/// very same receiver (exact status, code and message), so the sync cells
/// below cannot pass because the header is harmless.
#[tokio::test(flavor = "current_thread")]
async fn control_reserved_agent_id_is_refused_on_non_exempt_route_9766() {
    let _g = env_lock();
    let sender = kp_mod::generate(PEER_ID).expect("generate sender keypair");
    let rx = spawn_receiver(&sender).await;

    let resp = client()
        .get(format!("{}{CONTROL_PATH}", rx.url))
        .header(ai_memory::HEADER_AGENT_ID, RESERVED_AGENT_ID)
        .send()
        .await
        .expect("control request");
    let status = resp.status();
    let body: Value = resp.json().await.expect("control body json");
    clear_env();

    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "control body={body}"
    );
    assert_eq!(
        body["code"].as_str(),
        Some(ai_memory::errors::error_codes::VALIDATION_FAILED),
        "control body={body}"
    );
    let want = format!("{LAYER_REFUSAL_PREFIX}{RESERVED_REFUSAL}");
    assert_eq!(
        body["error"].as_str(),
        Some(want.as_str()),
        "control body={body}"
    );
}

/// `/sync/push` validates `X-Agent-Id` itself, so with the rewritten reserved
/// value it answers 400 from the HANDLER. The layer's refusal differs in
/// shape (it carries `code: VALIDATION_FAILED` and the `invalid agent_id:`
/// prefix), so the handler's exact body proves the request got past the
/// chokepoint. Every recorded push must be that answer.
fn assert_push_reached_handler(push: &[Row]) {
    assert!(
        !push.is_empty(),
        "no /sync/push request reached the receiver"
    );
    let want = format!("{HANDLER_REFUSAL_PREFIX}{RESERVED_REFUSAL}");
    for row in push {
        assert_eq!(
            row.status,
            StatusCode::BAD_REQUEST,
            "push body={}",
            row.body
        );
        assert_eq!(
            row.body["error"].as_str(),
            Some(want.as_str()),
            "push body={}",
            row.body
        );
        assert!(
            row.body.get("code").is_none(),
            "a layer refusal carries `code`, the handler's does not; push body={}",
            row.body
        );
    }
}

/// Cell 1 - federation receive family: the catch-up puller
/// (`catchup_once_for_tests`, `/sync/since`) and the store fan-out pusher
/// (`broadcast_store_quorum`, `/sync/push`) reach the Enforce receiver and
/// get the exact success status and body shape; no 400 `VALIDATION_FAILED`,
/// no 403 `attested_identity_required`.
#[tokio::test(flavor = "current_thread")]
async fn federation_receive_family_sync_routes_are_exempt_9766() {
    let _g = env_lock();
    let _ = ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_a| Ok(())));
    let sender = kp_mod::generate(PEER_ID).expect("generate sender keypair");
    let rx = spawn_receiver(&sender).await;

    let cfg = FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30))
            .expect("quorum policy"),
        peers: vec![PeerEndpoint {
            id: "peer-9766".to_string(),
            sync_push_url: format!("{}{}", rx.url, ai_memory::handlers::routes::SYNC_PUSH),
        }],
        client: client(),
        sender_agent_id: PEER_ID.to_string(),
        api_key: None,
        signing_key: Some(Arc::new(
            sender.private.clone().expect("sender private key"),
        )),
        dlq_sink: None,
    };

    ai_memory::federation::receive::catchup_once_for_tests(&cfg).await;
    let tracker = sync::broadcast_store_quorum(&cfg, &memory("fed-9766-a", "ns-9766-fed"))
        .await
        .expect("store quorum tracker");
    let finalised = tracker.finalise(std::time::Instant::now());
    clear_env();

    let since = rows_for(&rx.rows, ai_memory::handlers::routes::SYNC_SINCE);
    assert_eq!(
        since.len(),
        1,
        "exactly one /sync/since request; rows={since:?}"
    );
    assert_eq!(
        since[0].status,
        StatusCode::OK,
        "since body={}",
        since[0].body
    );
    assert_eq!(since[0].body["count"], 0, "since body={}", since[0].body);
    assert_eq!(
        since[0].body["memories"],
        Value::Array(Vec::new()),
        "since body={}",
        since[0].body
    );

    let push = rows_for(&rx.rows, ai_memory::handlers::routes::SYNC_PUSH);
    assert_push_reached_handler(&push);
    // Quorum outcome is not under test (the local write alone acks W=1).
    let _ = finalised;
}

/// Cell 2 - daemon runtime family: `sync_cycle_once` (pull `/sync/since`
/// then push `/sync/push`, both signed with the daemon key) against the same
/// Enforce receiver; exact status and body per route.
#[tokio::test(flavor = "current_thread")]
async fn daemon_runtime_family_sync_routes_are_exempt_9766() {
    let _g = env_lock();
    let sender = kp_mod::generate(PEER_ID).expect("generate sender keypair");
    let rx = spawn_receiver(&sender).await;

    // The daemon signs with the key under `AI_MEMORY_KEY_DIR`; the receiver
    // verifies against the public half enrolled in the same directory.
    let key_dir = std::env::var(KEY_DIR_ENV).expect("key dir set by spawn_receiver");
    kp_mod::save(&sender, std::path::Path::new(&key_dir)).expect("enrol daemon signing key");

    let src_tmp = scratch_db();
    let conn = ai_memory::db::open(src_tmp.path()).expect("sender db::open");
    ai_memory::db::insert(&conn, &memory("dr-9766-a", "ns-9766-dr")).expect("seed outgoing row");
    drop(conn);

    let res = ai_memory::daemon_runtime::sync_cycle_once(
        &client(),
        src_tmp.path(),
        PEER_ID,
        &rx.url,
        None,
        100,
    )
    .await;
    clear_env();

    let since = rows_for(&rx.rows, ai_memory::handlers::routes::SYNC_SINCE);
    assert_eq!(
        since.len(),
        1,
        "exactly one /sync/since request; rows={since:?}"
    );
    assert_eq!(
        since[0].status,
        StatusCode::OK,
        "since body={}",
        since[0].body
    );
    assert_eq!(since[0].body["count"], 0, "since body={}", since[0].body);

    let push = rows_for(&rx.rows, ai_memory::handlers::routes::SYNC_PUSH);
    assert_push_reached_handler(&push);
    let _ = res;
}
