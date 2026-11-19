// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9367 V-4 — the forwarder against a REAL daemon (the production router,
//! the production `api_key_auth` layer, a real store) on SQLite and on
//! PostgreSQL (3-agent vote 71472661).
//!
//! Per backend, three daemons:
//! - no api key configured, variable UNSET: the forward is the request of
//!   today and the row is written;
//! - the per-agent key bound to the explicit agent id, `enforce` mode: the
//!   keyed forward is accepted and the row is written;
//! - the per-agent key bound to ANOTHER agent id, `enforce` mode: every site
//!   is a named error naming the variable and the configured agent id (never
//!   the key), zero rows are written and nothing is retried without the key.
//!
//! The PostgreSQL cell runs under `sal-postgres` against the database named
//! by `AI_MEMORY_TEST_POSTGRES_URL` (a minted ci-v2-pg database) and reports
//! a skip when the variable is unset, as every postgres cell of this crate.
//!
//! No cell writes the process environment (#3475, gate arm (d)): each cell
//! re-runs itself in children started from a CLEAN environment that holds
//! exactly the variables the phase needs (`test_support::spawn_test_child`,
//! the #3152 precedent). The daemon cell runs its unset phase in one child and
//! its two keyed phases in a second child whose start state names the key
//! file; the parent only spawns and checks.

use super::*;
use crate::identity::test_agent_id::AgentIdOverride;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// The env var the forwarder reads.
const KEY_FILE_ENV: &str = "AI_MEMORY_AGENT_API_KEY_FILE";
/// The explicit process identity every cell runs as.
const AGENT: &str = "ai:alice";
/// The agent id the mismatching key is bound to.
const OTHER_AGENT: &str = "ai:bob";
/// How long a cell waits for its daemon to bind.
const DAEMON_BIND_WAIT: Duration = Duration::from_secs(60);

/// A synthetic key: random hex, never a literal in the source.
fn synthetic_key() -> String {
    format!(
        "amk_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Scratch dir under the clone (never /tmp).
fn scratch(cell: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("9367")
        .join(format!("{cell}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// In a keyed child: write `<key>\n` mode 0600 at the path its start
/// environment names in [`KEY_FILE_ENV`]; return that path.
fn child_key_file(key: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = std::path::PathBuf::from(
        std::env::var_os(KEY_FILE_ENV).expect("the parent names the key file"),
    );
    std::fs::write(&path, format!("{key}\n")).expect("write token file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    path
}

/// This module's path inside the lib test binary.
const MODULE: &str = "mcp::store::transport::forward_key_daemon_9367_tests";
/// Marks the clean child a cell spawns for itself; never set in a parent.
const CHILD_ROLE_ENV: &str = "AI_MEMORY_TEST_FORWARD_KEY_DAEMON_CHILD_9367";
/// The key file name inside a cell's scratch dir.
const TOKEN_NAME: &str = "agent.token";
/// The permissive attestation posture the daemon cell starts its children in.
const ATTESTATION_OFF: &str = "0";

/// `true` in the child a cell spawned for itself.
fn is_child() -> bool {
    std::env::var_os(CHILD_ROLE_ENV).is_some()
}

/// Run `test` of this module again in a child whose environment is CLEAN
/// plus exactly `env` and the role marker; the child must pass and must have
/// run that one test (a filter that matches nothing also exits 0).
fn run_in_child(test: &str, env: &[(&str, &str)]) {
    let mut vars = vec![(CHILD_ROLE_ENV, "1")];
    vars.extend_from_slice(env);
    let out = crate::test_support::spawn_test_child(&format!("{MODULE}::{test}"), &vars);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{test} child failed:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed") && !stdout.contains("0 passed"),
        "{test} child ran no test:\n{stdout}"
    );
}

/// Run `test` in a clean child whose environment names
/// `<scratch(cell)>/agent.token` in [`KEY_FILE_ENV`] plus `extra`, then drop
/// the scratch dir.
fn run_keyed_child(test: &str, cell: &str, extra: &[(&str, &str)]) {
    let dir = scratch(cell);
    let path = dir.join(TOKEN_NAME);
    let path = path.to_str().expect("utf-8 scratch path");
    let mut env = vec![(KEY_FILE_ENV, path)];
    env.extend_from_slice(extra);
    run_in_child(test, &env);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Parent role of the daemon cell: phase 1 in a clean child with the key
/// variable unset, phases 2-3 in a clean child that names a key path; both
/// start with the permissive attestation posture plus `extra`.
fn daemon_children(test: &str, extra: &[(&str, &str)]) {
    let mut env = vec![(
        crate::identity::attest::ENV_REQUIRE_AGENT_ATTESTATION,
        ATTESTATION_OFF,
    )];
    env.extend_from_slice(extra);
    run_in_child(test, &env);
    run_keyed_child(test, "daemon", &env);
}

/// The daemon's auth layer: no key at all, or a shared transport key plus
/// one per-agent key bound to `bound_to` in `enforce` mode.
fn auth(binding: Option<(&str, &str)>) -> crate::handlers::ApiKeyState {
    let Some((key, bound_to)) = binding else {
        return crate::handlers::ApiKeyState::default();
    };
    let map = std::collections::HashMap::from([(
        crate::handlers::identity_binding::api_key_sha256_hex(key),
        bound_to.to_string(),
    )]);
    crate::handlers::ApiKeyState {
        key: Some(synthetic_key()),
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            crate::handlers::identity_binding::EnrolledAgentKeys::from_map(map),
        ),
        identity_mode: crate::config::HttpIdentityMode::Enforce,
        ..Default::default()
    }
}

#[cfg(feature = "sal")]
type SalStore = Arc<dyn crate::store::MemoryStore>;
#[cfg(not(feature = "sal"))]
type SalStore = ();

fn app_state(
    db: crate::handlers::Db,
    backend: crate::handlers::StorageBackend,
    store: SalStore,
) -> crate::handlers::AppState {
    let _ = &store;
    crate::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(crate::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(crate::config::ResolvedScoring::default()),
        profile: Arc::new(crate::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(crate::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(crate::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(crate::identity::replay::FederationNonceCache::default()),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(crate::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(crate::reload::Swappable::new(
            crate::config::ResolvedModels::default(),
        )),
        runtime: crate::runtime_context::RuntimeContext::global_arc(),
        max_page_size: crate::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(crate::handlers::identity_binding::EnrolledAgentKeys::empty()),
        http_identity_mode: crate::config::HttpIdentityMode::default(),
    }
}

/// Where a daemon keeps its rows.
#[derive(Clone)]
enum Backend {
    Sqlite(std::path::PathBuf),
    #[cfg(feature = "sal-postgres")]
    Postgres(String),
}

async fn state_for(backend: &Backend) -> crate::handlers::AppState {
    match backend {
        Backend::Sqlite(path) => {
            let conn = crate::db::open(path).expect("open sqlite db");
            let db: crate::handlers::Db = Arc::new(tokio::sync::Mutex::new((
                conn,
                path.clone(),
                crate::config::ResolvedTtl::default(),
                true,
            )));
            #[cfg(feature = "sal")]
            let store: SalStore = Arc::new(
                crate::store::sqlite::SqliteStore::open(path.clone()).expect("open SqliteStore"),
            );
            #[cfg(not(feature = "sal"))]
            let store: SalStore = ();
            app_state(db, crate::handlers::StorageBackend::Sqlite, store)
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(url) => {
            let conn = crate::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
            let db: crate::handlers::Db = Arc::new(tokio::sync::Mutex::new((
                conn,
                std::path::PathBuf::from(":memory:"),
                crate::config::ResolvedTtl::default(),
                true,
            )));
            let store: SalStore = Arc::new(
                crate::store::postgres::PostgresStore::connect(url)
                    .await
                    .expect("connect postgres adapter"),
            );
            app_state(db, crate::handlers::StorageBackend::Postgres, store)
        }
    }
}

/// Serve the production router over loopback on its own runtime thread and
/// return its base URL. The thread lives until the child process exits.
fn spawn_daemon(backend: Backend, auth: crate::handlers::ApiKeyState) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("daemon runtime");
        rt.block_on(async move {
            let app = state_for(&backend).await;
            crate::handlers::admin_role::mark_request_authn_configured(true);
            let router = crate::build_router(auth, app);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let port = listener.local_addr().expect("addr").port();
            tx.send(format!("http://127.0.0.1:{port}"))
                .expect("send url");
            let _ = axum::serve(listener, router).await;
        });
    });
    rx.recv_timeout(DAEMON_BIND_WAIT).expect("daemon bound")
}

/// The number of memory rows the backend holds.
fn rows(backend: &Backend) -> usize {
    match backend {
        Backend::Sqlite(path) => {
            let conn = crate::db::open(path).expect("open sqlite db");
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
                .expect("count");
            usize::try_from(n).expect("non-negative count")
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(url) => {
            let rt = tokio::runtime::Runtime::new().expect("count runtime");
            rt.block_on(async {
                let store = crate::store::postgres::PostgresStore::connect(url)
                    .await
                    .expect("connect postgres adapter");
                crate::store::MemoryStore::stats(&store)
                    .await
                    .expect("stats")
                    .total
            })
        }
    }
}

fn store_params(tag: &str) -> Value {
    json!({
        "title": format!("forward-key-9367-{tag}-{}", uuid::Uuid::new_v4().simple()),
        "content": "c",
        "namespace": "forward-key-9367",
    })
}

/// The V-4 cell body, shared by both backends. `fresh` makes a new backend
/// (its own sqlite file, or the one minted postgres database).
fn daemon_cell(fresh: &dyn Fn(&str) -> Backend) {
    let _id = AgentIdOverride::set(AGENT);
    // The forwarded store is an unsigned HTTP-direct write; the daemon's
    // compiled default requires attestation on that surface (#1985), so the
    // cells model the permissive posture, as the HTTP receipt cells do
    // (tests/write_receipts_http_3555.rs). The key path is what is tested.
    // The posture is the child's start state (`daemon_children`).
    assert_eq!(
        std::env::var(crate::identity::attest::ENV_REQUIRE_AGENT_ATTESTATION).as_deref(),
        Ok(ATTESTATION_OFF),
        "the child starts in the permissive posture"
    );

    if std::env::var_os(KEY_FILE_ENV).is_none() {
        // 1. Variable UNSET, daemon without an api key: today's forward.
        let backend = fresh("unset");
        let url = spawn_daemon(backend.clone(), auth(None));
        let before = rows(&backend);
        forward_store_to_http(&url, &store_params("unset"), Some("ai:test"))
            .unwrap_or_else(|e| panic!("unset variable must forward as today: {e}"));
        assert_eq!(rows(&backend), before + 1, "unset: the row is written");
        return;
    }

    // 2. Key bound to the explicit agent id: accepted, row written.
    let key = synthetic_key();
    child_key_file(&key);
    let backend = fresh("bound");
    let url = spawn_daemon(backend.clone(), auth(Some((&key, AGENT))));
    let before = rows(&backend);
    forward_store_to_http(&url, &store_params("bound"), Some("ai:test"))
        .unwrap_or_else(|e| panic!("a key bound to {AGENT} must be accepted: {e}"));
    assert_eq!(rows(&backend), before + 1, "bound: the row is written");

    // 3. Key bound to ANOTHER agent id: named error per site, zero rows.
    let backend = fresh("other");
    let url = spawn_daemon(backend.clone(), auth(Some((&key, OTHER_AGENT))));
    let before = rows(&backend);
    let sites = vec![
        (
            "store",
            forward_store_to_http(&url, &store_params("other"), Some("ai:test")),
        ),
        (
            "transition",
            forward_action_transition_to_http(
                &url,
                &json!({"id": "act-9367", "to": "claimed"}),
                Some("ai:test"),
            ),
        ),
        (
            "signal",
            forward_signal_send_to_http(
                &url,
                &json!({"namespace": "forward-key-9367", "subject": "s"}),
                Some("ai:test"),
            ),
        ),
    ];
    for (site, result) in sites {
        let err = result.expect_err(&format!("{site}: a key bound to another agent must error"));
        assert!(
            err.ends_with(&format!(
                "returned 403 Forbidden; the daemon refused the key in {KEY_FILE_ENV} for agent '{AGENT}'"
            )),
            "{site}: {err}"
        );
        assert!(!err.contains(&key), "{site}: key bytes in the error");
    }
    assert_eq!(rows(&backend), before, "a refused key writes zero rows");
}

#[test]
fn sqlite_daemon_keyed_forward_9367() {
    const TEST: &str = "sqlite_daemon_keyed_forward_9367";
    let _lock = crate::identity::agent_id_env_test_lock();
    if !is_child() {
        daemon_children(TEST, &[]);
        return;
    }
    let dbs = scratch("sqlite-dbs");
    daemon_cell(&|tag| Backend::Sqlite(dbs.join(format!("{tag}.db"))));
    let _ = std::fs::remove_dir_all(&dbs);
}

/// One keyed `POST` over a raw loopback socket: the status line and the body.
fn raw_post(base: &str, path: &str, key: &str, body: &Value) -> (String, String) {
    use std::io::{Read as _, Write as _};
    let addr = base.trim_start_matches("http://");
    let payload = body.to_string();
    let mut sock = std::net::TcpStream::connect(addr).expect("connect daemon");
    write!(
        sock,
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\n{}: {key}\r\n{}: {AGENT}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        crate::HEADER_API_KEY,
        crate::HEADER_AGENT_ID,
        payload.len()
    )
    .expect("write request");
    let mut reply = String::new();
    sock.read_to_string(&mut reply).expect("read reply");
    let (head, rest) = reply.split_once("\r\n\r\n").expect("header end");
    let status = head.lines().next().unwrap_or_default().to_string();
    (status, rest.to_string())
}

/// Evidence pin (to-file candidate, behaviour unchanged): a keyed forwarded
/// store to a daemon with the DEFAULT attestation settings is refused by the
/// HTTP-direct attestation gate (src/handlers/create.rs, #1985), not by the
/// key: 403 with the daemon's `ATTESTATION_FAILED` body, zero rows, and the
/// forwarder names the daemon's code, never "refused the key".
#[test]
fn default_attestation_daemon_refuses_keyed_forward_9367() {
    const TEST: &str = "default_attestation_daemon_refuses_keyed_forward_9367";
    let _lock = crate::identity::agent_id_env_test_lock();
    if !is_child() {
        // The child's clean environment holds no attestation setting: the
        // daemon runs on its compiled default.
        run_keyed_child(TEST, "default-attest", &[]);
        return;
    }
    let _id = AgentIdOverride::set(AGENT);
    assert!(
        std::env::var_os(crate::identity::attest::ENV_REQUIRE_AGENT_ATTESTATION).is_none(),
        "the child starts on the compiled attestation default"
    );
    let key = synthetic_key();
    let path = child_key_file(&key);
    let dir = path.parent().expect("key file dir");
    let backend = Backend::Sqlite(dir.join("default.db"));
    let url = spawn_daemon(backend.clone(), auth(Some((&key, AGENT))));
    let before = rows(&backend);

    // The daemon's exact reply to the request the forwarder sends, over a raw
    // socket (no second HTTP client under src/mcp, K-6).
    let (status_line, body) = raw_post(&url, "/api/v1/memories", &key, &store_params("raw"));
    assert_eq!(status_line, "HTTP/1.1 403 Forbidden");
    let body: Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(
        body,
        json!({
            "code": crate::errors::error_codes::ATTESTATION_FAILED,
            "error": crate::handlers::errors::ATTESTATION_FAILED_MSG,
        })
    );

    let err = forward_store_to_http(&url, &store_params("fwd"), Some("ai:test"))
        .expect_err("a default daemon refuses the unsigned forwarded store");
    assert!(
        err.ends_with(&format!(
            "returned 403 Forbidden; daemon code {}",
            crate::errors::error_codes::ATTESTATION_FAILED
        )),
        "{err}"
    );
    assert!(!err.contains(&key), "key bytes in the error");
    assert_eq!(rows(&backend), before, "the refused store writes zero rows");
}

#[cfg(feature = "sal-postgres")]
#[test]
fn postgres_daemon_keyed_forward_9367() {
    const TEST: &str = "postgres_daemon_keyed_forward_9367";
    // The minted PostgreSQL database (never printed). Named inside the cell so
    // the CI partition selects this one test, not the module, for the PG leg.
    const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
    let _lock = crate::identity::agent_id_env_test_lock();
    let Some(url) = std::env::var(PG_URL_ENV).ok().filter(|u| !u.is_empty()) else {
        assert!(!is_child(), "the parent passes the database to its child");
        eprintln!("{TEST}: {PG_URL_ENV} unset; skipped");
        return;
    };
    if !is_child() {
        // The clean child gets the minted database by name, never on stdout.
        daemon_children(TEST, &[(PG_URL_ENV, url.as_str())]);
        return;
    }
    daemon_cell(&|_| Backend::Postgres(url.clone()));
}
