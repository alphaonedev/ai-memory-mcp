// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3064 lane L-PGP — postgres tool-parity regression suite.
//!
//! Issue #3064 ("MCP tools unreachable on postgres deployments") tracked a
//! set of `/api/v1` paths that a postgres-backed daemon refused with the
//! fail-closed `501 NOT IMPLEMENTED` envelope, because their handlers took
//! `app.db.lock()` (the empty scratch sqlite) with no SAL branch. This suite
//! is the proof-of-dispatch half of the control described in the module doc
//! of `tests/pg_supported_route_inventory_gate_2799.rs`: the inventory gate
//! makes the allow-list REVIEWABLE, and each test here makes one opened
//! entry BEHAVIOURALLY TRUE.
//!
//! Every family is asserted on BOTH backends through the SAME in-process
//! HTTP daemon so a wire-shape divergence cannot hide:
//!
//! * **sqlite** — always runs (default features included), over a temp DB
//!   under `.local-runs/` (project no-`/tmp` HARD RULE);
//! * **postgres** — gated on `feature = "sal-postgres"` + a live
//!   `AI_MEMORY_TEST_POSTGRES_URL`, and skipped cleanly (with a `skipping`
//!   line) when either is absent — the established pattern from
//!   `tests/serve_postgres_extended.rs`.
//!
//! Each family asserts three things:
//!
//! 1. the route returns the REAL result on postgres (a 200, never the 501
//!    envelope), proving the request reached a SAL-dispatching handler;
//! 2. the JSON envelope has the SAME SHAPE as the sqlite answer (wire-shape
//!    parity — the key set, not the row contents, which are per-backend);
//! 3. the DENIED path refuses identically on both backends (owner-isolation
//!    / cross-tenant), so opening the route did not open a leak.

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify, RwLock};

mod common;
use common::{DAEMON_READY_TIMEOUT, free_port, pg_test_client, postgres_url, wait_for_http_ready};

/// Admin allow-list principal used by every fixture in this file.
const OWNER_AGENT: &str = "ai:pgparity-3064";
/// A second, unrelated principal — the DENIED half of every family.
const OTHER_AGENT: &str = "ai:pgparity-3064-intruder";

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("pg-parity-3064");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Shared `AppState` skeleton. `db` is ALWAYS a real sqlite handle (the
/// daemon opens one even on postgres — see `src/daemon_runtime.rs`), and the
/// `store` + `storage_backend` pair is what selects the backend a
/// SAL-dispatching handler actually reads.
fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
    // #1570 — model an AUTHENTICATED deployment (api_key configured at boot)
    // so the admin-gated routes admit the fixture's header role-claims.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let _ = &store;
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store: store.0,
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
        admin_agent_ids: Arc::new(vec![OWNER_AGENT.to_string(), OTHER_AGENT.to_string()]),
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
    }
}

/// The SAL handle, present only under `feature = "sal"`. Wrapping it in a
/// newtype keeps `app_state_with`'s signature identical across feature legs
/// (the default-feature build has no `MemoryStore` trait at all).
#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

/// Build a sqlite-backed `AppState` over a real on-disk DB. Under `sal` the
/// `SqliteStore` is opened against the SAME file as `app.db`, so both views
/// see the same rows (exactly what `bootstrap_serve` does).
fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    app_state_with(db, StorageBackend::Sqlite, store)
}

/// Build a postgres-backed `AppState`. `app.db` is a throwaway in-memory
/// sqlite — deliberately EMPTY, so any handler that reads it instead of
/// `app.store` returns nothing and the test fails loudly.
#[cfg(feature = "sal-postgres")]
async fn postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    ));
    app_state_with(db, StorageBackend::Postgres, store)
}

/// Spawn the in-process daemon for an already-built `AppState`.
async fn spawn(
    app_state: AppState,
) -> (
    String,
    Arc<Notify>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_daemon = shutdown.clone();
    let addr_for_daemon = addr.clone();
    let handle = tokio::spawn(async move {
        ai_memory::daemon_runtime::serve_http_with_shutdown(
            &addr_for_daemon,
            api_key_state,
            app_state,
            shutdown_for_daemon,
        )
        .await
    });
    wait_for_http_ready(&addr, DAEMON_READY_TIMEOUT)
        .await
        .expect("daemon ready");
    (format!("http://{addr}"), shutdown, handle)
}

/// Sorted top-level key set of a JSON object — the wire-SHAPE fingerprint
/// the parity assertions compare across backends.
fn key_shape(v: &Value) -> Vec<String> {
    let mut keys: Vec<String> = v
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

async fn store_memory(
    client: &reqwest::Client,
    base: &str,
    namespace: &str,
    title: &str,
    content: &str,
) -> String {
    let resp = client
        .post(format!("{base}/api/v1/memories"))
        .json(&json!({
            "tier": "long",
            "namespace": namespace,
            "title": title,
            "content": content,
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "system",
        }))
        .send()
        .await
        .expect("store POST");
    assert!(
        resp.status().is_success(),
        "store must succeed: status={}",
        resp.status()
    );
    let v: Value = resp.json().await.expect("store body");
    v["id"].as_str().expect("stored id").to_string()
}

async fn link(client: &reqwest::Client, base: &str, source: &str, target: &str) {
    let resp = client
        .post(format!("{base}/api/v1/links"))
        .json(&json!({
            "source_id": source,
            "target_id": target,
            "relation": "related_to",
        }))
        .send()
        .await
        .expect("link POST");
    assert!(resp.status().is_success(), "link must succeed");
}

// ─────────────────────────────────────────────────────────────────────
// F1 — the bare `/api/v1/find_paths` alias
// ─────────────────────────────────────────────────────────────────────

/// Drive both the bare alias and its canonical twin over one daemon and
/// return `(alias_status, alias_body, kg_status, kg_body, denied_status)`.
async fn f1_exercise(base: &str) -> (u16, Value, u16, Value, u16) {
    let client = pg_test_client(OWNER_AGENT);
    let ns = format!("f1-find-paths-{}", uuid::Uuid::new_v4());
    let a = store_memory(&client, base, &ns, "A", "node A").await;
    let b = store_memory(&client, base, &ns, "B", "node B").await;
    let c = store_memory(&client, base, &ns, "C", "node C").await;
    link(&client, base, &a, &b).await;
    link(&client, base, &b, &c).await;

    let body = json!({"source_id": a, "target_id": c, "max_depth": 5});
    let alias = client
        .post(format!("{base}/api/v1/find_paths"))
        .json(&body)
        .send()
        .await
        .expect("alias POST");
    let alias_status = alias.status().as_u16();
    let alias_body: Value = alias.json().await.expect("alias body");

    let kg = client
        .post(format!("{base}/api/v1/kg/find_paths"))
        .json(&body)
        .send()
        .await
        .expect("kg POST");
    let kg_status = kg.status().as_u16();
    let kg_body: Value = kg.json().await.expect("kg body");

    // DENIED half — a control-character id is refused by `validate_id`
    // BEFORE any storage access, on the alias exactly as on the twin.
    let denied = client
        .post(format!("{base}/api/v1/find_paths"))
        .json(&json!({"source_id": "bad\u{0}id", "target_id": "worse\u{0}id"}))
        .send()
        .await
        .expect("denied POST");
    let denied_status = denied.status().as_u16();

    (alias_status, alias_body, kg_status, kg_body, denied_status)
}

/// The alias must behave EXACTLY like `/api/v1/kg/find_paths` — same 200,
/// same envelope, same refusal — because `src/lib.rs` wires both paths to
/// the same handler. Before #3064 family F1 the alias was absent from
/// `postgres_endpoint_supported`, so a postgres daemon answered 501 for a
/// route whose twin it already served.
///
/// `sal`-gated on BOTH backends: `handlers::kg_find_paths` is compiled out
/// without the feature and answers `find_paths requires --features sal`, so
/// there is no default-feature behaviour to pin for this family (the other
/// families in this file DO run on the default-feature leg).
#[cfg(feature = "sal")]
#[tokio::test(flavor = "multi_thread")]
async fn f1_find_paths_alias_matches_kg_find_paths_sqlite() {
    let dir = fresh_dir("f1-sqlite");
    let state = sqlite_app_state(&dir.path().join("f1.db"));
    let (base, shutdown, handle) = spawn(state).await;

    let (alias_status, alias_body, kg_status, kg_body, denied_status) = f1_exercise(&base).await;
    assert_eq!(alias_status, 200, "alias body={alias_body}");
    assert_eq!(kg_status, 200);
    assert_eq!(
        key_shape(&alias_body),
        key_shape(&kg_body),
        "alias and canonical envelopes must have the same shape"
    );
    assert!(
        !alias_body["paths"]
            .as_array()
            .expect("paths array")
            .is_empty(),
        "the A->B->C chain must yield at least one path: {alias_body}"
    );
    assert_eq!(denied_status, 400, "invalid ids must be refused");

    shutdown.notify_one();
    let _ = handle.await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn f1_find_paths_alias_matches_kg_find_paths_postgres() {
    let Some(url) = postgres_url() else {
        eprintln!("skipping f1_find_paths_alias_matches_kg_find_paths_postgres");
        return;
    };
    let state = postgres_app_state(&url).await;
    let (base, shutdown, handle) = spawn(state).await;

    let (alias_status, alias_body, kg_status, kg_body, denied_status) = f1_exercise(&base).await;
    assert_ne!(
        alias_status, 501,
        "the bare find_paths alias must no longer be fail-closed on postgres: {alias_body}"
    );
    assert_eq!(alias_status, 200, "alias body={alias_body}");
    assert_eq!(kg_status, 200);
    assert_eq!(
        key_shape(&alias_body),
        key_shape(&kg_body),
        "alias and canonical envelopes must have the same shape on postgres"
    );
    assert!(
        !alias_body["paths"]
            .as_array()
            .expect("paths array")
            .is_empty(),
        "the A->B->C chain must yield at least one path on postgres: {alias_body}"
    );
    assert_eq!(
        denied_status, 400,
        "invalid ids must be refused on postgres"
    );

    shutdown.notify_one();
    let _ = handle.await;
}

// Keep the postgres-only helper referenced on non-pg legs so the sqlite
// build does not warn about an unused import.
#[cfg(not(feature = "sal-postgres"))]
#[allow(dead_code)]
fn _postgres_url_referenced() -> Option<String> {
    postgres_url()
}
