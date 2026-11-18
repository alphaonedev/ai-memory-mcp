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

fn key_file(dir: &std::path::Path, key: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("agent.token");
    std::fs::write(&path, format!("{key}\n")).expect("write token file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    path
}

fn set_env(name: &str, value: &std::ffi::OsStr) {
    // SAFETY: the cell runs alone in its own re-exec'd child process.
    unsafe { std::env::set_var(name, value) };
}

fn unset_env(name: &str) {
    // SAFETY: as `set_env`.
    unsafe { std::env::remove_var(name) };
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

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is `()` without `sal`; one signature for both feature legs"
    )
)]
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
    let dir = scratch("daemon");
    // The forwarded store is an unsigned HTTP-direct write; the daemon's
    // compiled default requires attestation on that surface (#1985), so the
    // cells model the permissive posture, as the HTTP receipt cells do
    // (tests/write_receipts_http_3555.rs). The key path is what is tested.
    set_env(
        crate::identity::attest::ENV_REQUIRE_AGENT_ATTESTATION,
        std::ffi::OsStr::new("0"),
    );

    // 1. Variable UNSET, daemon without an api key: today's forward.
    unset_env(KEY_FILE_ENV);
    let backend = fresh("unset");
    let url = spawn_daemon(backend.clone(), auth(None));
    let before = rows(&backend);
    forward_store_to_http(&url, &store_params("unset"), Some("ai:test"))
        .unwrap_or_else(|e| panic!("unset variable must forward as today: {e}"));
    assert_eq!(rows(&backend), before + 1, "unset: the row is written");

    // 2. Key bound to the explicit agent id: accepted, row written.
    let key = synthetic_key();
    set_env(KEY_FILE_ENV, key_file(&dir, &key).as_os_str());
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
    let sites: Vec<(&str, Result<Value, String>)> = vec![
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sqlite_daemon_keyed_forward_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::transport::forward_key_daemon_9367_tests::sqlite_daemon_keyed_forward_9367",
    ) {
        return;
    }
    let dbs = scratch("sqlite-dbs");
    daemon_cell(&|tag| Backend::Sqlite(dbs.join(format!("{tag}.db"))));
    let _ = std::fs::remove_dir_all(&dbs);
}

#[cfg(feature = "sal-postgres")]
#[test]
fn postgres_daemon_keyed_forward_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::transport::forward_key_daemon_9367_tests::postgres_daemon_keyed_forward_9367",
    ) {
        return;
    }
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|u| !u.is_empty())
    else {
        eprintln!("postgres_daemon_keyed_forward_9367: AI_MEMORY_TEST_POSTGRES_URL unset; skipped");
        return;
    };
    daemon_cell(&|_| Backend::Postgres(url.clone()));
}
