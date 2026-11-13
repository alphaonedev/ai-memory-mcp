// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! #9082 - `/sync/since` filtered by the row's OWN `updated_at`, a value the
//! writer chose. A row that reached the serving node with an `updated_at`
//! below a puller's cursor (a relayed row, a backward clock step on the
//! origin) was never served to that puller again.
//!
//! The fix (5-agent vote 4d3ea1c5, memory c472a44b) is a change sequence the
//! SERVING node assigns in commit order (`memories.sync_seq`). A puller that
//! sends `after_seq` walks `sync_seq > after_seq` and sees every row whatever
//! its timestamps; `next_seq` is the highest sequence EXAMINED before the
//! visibility filters; an empty page echoes `after_seq`; a request above the
//! head (a restored node) walks from 0; `seq_epoch` names the database so a
//! puller can tell a restored or re-initialised peer from a live one.
//!
//! Red at the cherry-picked #8815 tip: the response has no `next_seq` and the
//! late, relayed row is never served. Every assertion names the exact value.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::federation::{FederationConfig, PeerEndpoint, PullOutcome, RefusalReason};
use ai_memory::replication::QuorumPolicy;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_SIG";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";

/// Wire names (`models::field_names`); the wire contract is the literal.
const AFTER_SEQ: &str = "after_seq";
const NEXT_SEQ: &str = "next_seq";
const SEQ_EPOCH: &str = "seq_epoch";

const NAMESPACE: &str = "fed-9082";
/// The three nodes of the relay: A (origin), B (relay), C (edge).
const NODE_A: &str = "node-a-9082";
const NODE_B: &str = "node-b-9082";
const NODE_C: &str = "node-c-9082";
/// Every node may pull and serve the corpus namespace for every other node.
const SCOPE_JSON: &str = r#"{
  "node-a-9082":{"allowed_namespaces":["fed-9082"]},
  "node-b-9082":{"allowed_namespaces":["fed-9082"]},
  "node-c-9082":{"allowed_namespaces":["fed-9082"]}
}"#;

/// The page size of the serving walk tests.
const PAGE: usize = 4;
/// Windows each generative case spans (the invariant asks for 2x the window).
const WINDOWS: usize = 2;

/// The timestamp classes the walk must be blind to.
const TS_MIN: &str = "0001-01-01T00:00:00+00:00";
const TS_BELOW: &str = "2026-01-01T00:00:00+00:00";
const TS_EQUAL: &str = "2026-06-01T00:00:00+00:00";
const TS_ABOVE: &str = "2026-07-01T00:00:00+00:00";
const TS_FAR_FUTURE: &str = "9999-12-31T23:59:59+00:00";
const TS_CLASSES: [&str; 5] = [TS_FAR_FUTURE, TS_MIN, TS_EQUAL, TS_BELOW, TS_ABOVE];
/// The relayed row's stamp: older than everything the edge already has.
const TS_RELAYED: &str = "2020-01-01T00:00:00+00:00";
/// One tag over `validate_tags`' cap of 50: the store keeps the row (no
/// CHECK on the tag count) and the puller refuses it as invalid.
const INVALID_TAG_COUNT: usize = 51;

/// Throughput row: rows seeded on the large table and the named ceilings.
const LARGE_TABLE_ROWS: usize = 20_000;
const LARGE_TABLE_PAGE: usize = 500;
const LARGE_TABLE_SEED_CEILING: Duration = Duration::from_secs(60);
const LARGE_TABLE_WALK_CEILING: Duration = Duration::from_secs(60);

/// Where a hidden or refused row sits in the first window.
#[derive(Clone, Copy, Debug)]
enum Position {
    First,
    Middle,
    Last,
}

const POSITIONS: [Position; 3] = [Position::First, Position::Middle, Position::Last];

impl Position {
    fn index(self) -> usize {
        match self {
            Self::First => 0,
            Self::Middle => PAGE / 2,
            Self::Last => PAGE - 1,
        }
    }
}

// ---------------------------------------------------------------------------
// posture and fixtures
// ---------------------------------------------------------------------------

fn set_posture() {
    // SAFETY: every env mutation in this binary runs under `ENV_LOCK`, and no
    // other thread reads the environment while the guard is held (precedent
    // tests/federation_sync_since_watermark_2441.rs `set_posture`).
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(TRUST_PEER_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            SCOPE_JSON,
        );
    }
}

fn clear_posture() {
    // SAFETY: as `set_posture`.
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_SIG_ENV);
        std::env::remove_var(TRUST_PEER_ENV);
    }
}

/// Test scratch lives under the worktree's `.local-runs/`, never a tmpfs.
fn scratch_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/test-9082");
    std::fs::create_dir_all(&root).expect("create scratch root");
    root
}

/// One node: its sqlite file (the daemon db), its router and, on the
/// postgres cell, the store and the scratch database it lives in.
struct Node {
    db: ai_memory::handlers::Db,
    db_path: PathBuf,
    router: axum::Router,
    #[cfg(feature = "sal-postgres")]
    pg: Option<(sqlx::PgPool, common::pg_barrier::ScratchDb)>,
    _dir: tempfile::TempDir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Sqlite,
    #[cfg(feature = "sal-postgres")]
    Postgres,
}

fn open_db(path: &Path) -> ai_memory::handlers::Db {
    let conn = ai_memory::db::open(path).expect("open node db");
    Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )))
}

fn app_state(
    db: &ai_memory::handlers::Db,
    #[cfg(feature = "sal")] store: Arc<dyn ai_memory::store::MemoryStore>,
    backend: ai_memory::handlers::StorageBackend,
) -> ai_memory::handlers::AppState {
    ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store,
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
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn api_key_state() -> ai_memory::handlers::ApiKeyState {
    ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    }
}

/// A sqlite node. With `sal` the store is a `SqliteStore` on the SAME file so
/// the router and the catch-up loop see one database.
fn sqlite_node(name: &str) -> Node {
    let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir");
    let db_path = dir.path().join(format!("{name}.db"));
    let db = open_db(&db_path);
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open sqlite store"));
    let state = app_state(
        &db,
        #[cfg(feature = "sal")]
        store,
        ai_memory::handlers::StorageBackend::Sqlite,
    );
    Node {
        router: ai_memory::build_router(api_key_state(), state),
        db,
        db_path,
        #[cfg(feature = "sal-postgres")]
        pg: None,
        _dir: dir,
    }
}

#[cfg(feature = "sal-postgres")]
async fn postgres_node(name: &str) -> Option<Node> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (postgres cell)");
        return None;
    };
    let scratch = common::pg_barrier::ScratchDb::create(&url, "hcfedpull_9082")
        .await
        .expect("create scratch database");
    let store = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("connect scratch database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&scratch.url())
        .await
        .expect("raw pool");
    let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir");
    let db_path = dir.path().join(format!("{name}.db"));
    let db = open_db(&db_path);
    let state = app_state(
        &db,
        Arc::new(store),
        ai_memory::handlers::StorageBackend::Postgres,
    );
    Some(Node {
        router: ai_memory::build_router(api_key_state(), state),
        db,
        db_path,
        pg: Some((pool, scratch)),
        _dir: dir,
    })
}

#[cfg_attr(
    not(feature = "sal-postgres"),
    expect(
        clippy::unused_async,
        reason = "only the sal-postgres cell awaits; one async signature serves both builds"
    )
)]
async fn node(backend: Backend, name: &str) -> Option<Node> {
    match backend {
        Backend::Sqlite => Some(sqlite_node(name)),
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres => postgres_node(name).await,
    }
}

/// Insert one row the way a relay or a direct write lands it: straight into
/// the node's database, so no write-path posture is in play.
async fn seed(node: &Node, id: &str, updated_at: &str, priority: i64) {
    seed_tagged(node, id, updated_at, priority, "[]").await;
}

/// [`seed`] with an explicit `tags` JSON array.
async fn seed_tagged(node: &Node, id: &str, updated_at: &str, priority: i64, tags: &str) {
    #[cfg(feature = "sal-postgres")]
    if let Some((pool, _)) = node.pg.as_ref() {
        sqlx::query(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
             confidence, source, metadata, access_count, created_at, updated_at) \
             VALUES ($1, 'long', $2, $3, 'sync_seq corpus row (#9082)', $7::jsonb, $4, 1.0, \
             'api', '{\"agent_id\":\"ai:puller\",\"scope\":\"collective\"}'::jsonb, 0, \
             $5::timestamptz, $6::timestamptz)",
        )
        .bind(id)
        .bind(NAMESPACE)
        .bind(format!("row {id}"))
        .bind(i32::try_from(priority).expect("priority fits"))
        .bind(TS_MIN)
        .bind(updated_at)
        .bind(tags)
        .execute(pool)
        .await
        .expect("seed pg row");
        return;
    }
    let guard = node.db.lock().await;
    guard
        .0
        .execute(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
             confidence, source, metadata, access_count, created_at, updated_at) \
             VALUES (?1, 'long', ?2, ?3, 'sync_seq corpus row (#9082)', ?7, ?4, 1.0, 'api', \
             '{\"agent_id\":\"ai:puller\",\"scope\":\"collective\"}', 0, ?5, ?6)",
            rusqlite::params![
                id,
                NAMESPACE,
                format!("row {id}"),
                priority,
                TS_MIN,
                updated_at,
                tags
            ],
        )
        .expect("seed row");
}

/// Run one raw statement on the node's backend (sqlite `?n`, postgres `$n`
/// spelled by the caller per backend).
async fn exec(node: &Node, sqlite_sql: &str, pg_sql: &str, id: &str) {
    #[cfg(feature = "sal-postgres")]
    if let Some((pool, _)) = node.pg.as_ref() {
        sqlx::query(pg_sql)
            .bind(id)
            .execute(pool)
            .await
            .expect("exec pg");
        return;
    }
    let _ = pg_sql;
    let guard = node.db.lock().await;
    guard
        .0
        .execute(sqlite_sql, rusqlite::params![id])
        .expect("exec sqlite");
}

async fn seq_of(node: &Node, id: &str) -> i64 {
    #[cfg(feature = "sal-postgres")]
    if let Some((pool, _)) = node.pg.as_ref() {
        let v: i64 = sqlx::query_scalar("SELECT sync_seq FROM memories WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("seq of");
        return v;
    }
    let guard = node.db.lock().await;
    guard
        .0
        .query_row("SELECT sync_seq FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .expect("seq of")
}

async fn hide(node: &Node, id: &str) {
    exec(
        node,
        "UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = ?1",
        "UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = $1",
        id,
    )
    .await;
}

/// One `/sync/since` request as `NODE_C`. `after_seq` is sent raw so the
/// negative case reaches the handler.
async fn get(router: &axum::Router, after_seq: Option<&str>, limit: usize) -> (StatusCode, Value) {
    let uri = match after_seq {
        Some(a) => format!("/api/v1/sync/since?limit={limit}&peer={NODE_C}&{AFTER_SEQ}={a}"),
        None => format!("/api/v1/sync/since?limit={limit}&peer={NODE_C}"),
    };
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            NODE_C,
        )
        .body(Body::empty())
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).expect("json envelope"),
    )
}

async fn pull_seq(router: &axum::Router, after_seq: i64, limit: usize) -> Value {
    let (status, v) = get(router, Some(&after_seq.to_string()), limit).await;
    assert_eq!(status, StatusCode::OK, "seq pull must answer 200: {v}");
    v
}

fn ids(v: &Value) -> Vec<String> {
    v["memories"]
        .as_array()
        .expect("memories array")
        .iter()
        .map(|m| m["id"].as_str().expect("id").to_string())
        .collect()
}

fn next_seq(v: &Value) -> i64 {
    v[NEXT_SEQ]
        .as_i64()
        .unwrap_or_else(|| panic!("#9082: a seq response must carry {NEXT_SEQ}; got {v}"))
}

fn epoch(v: &Value) -> String {
    v[SEQ_EPOCH]
        .as_str()
        .unwrap_or_else(|| panic!("#9082: a seq response must carry {SEQ_EPOCH}; got {v}"))
        .to_string()
}

/// Walk the node from `start` until an empty page. Returns the ids in serve
/// order and the `next_seq` of every window (the empty echo included).
async fn walk(router: &axum::Router, start: i64, limit: usize) -> (Vec<String>, Vec<i64>) {
    let mut served = Vec::new();
    let mut cursors = Vec::new();
    let mut after = start;
    // A bound on the walk: every row moves the cursor by at least one.
    for _ in 0..=LARGE_TABLE_ROWS {
        let v = pull_seq(router, after, limit).await;
        let page = ids(&v);
        let next = next_seq(&v);
        cursors.push(next);
        if page.is_empty() && next == after {
            return (served, cursors);
        }
        assert!(
            next > after,
            "#9082: next_seq must move past {after}; got {next}"
        );
        served.extend(page);
        after = next;
    }
    panic!("#9082: the walk did not converge");
}

// ---------------------------------------------------------------------------
// serving side
// ---------------------------------------------------------------------------

/// The generative table: timestamps (min, below, equal, above, far future,
/// mixed over 2x the window) x hidden-row position (first, middle, last of
/// window one). Every visible row is served exactly once in seq order, the
/// hidden row never, and each window's `next_seq` is the seq of the last row
/// it EXAMINED (the hidden one included).
async fn generative_walk(backend: Backend) {
    for position in POSITIONS {
        let Some(n) = node(backend, &format!("gen-{position:?}")).await else {
            return;
        };
        let total = PAGE * WINDOWS;
        let mut order = Vec::new();
        for i in 0..total {
            let id = format!("gen-{position:?}-{i:02}");
            // Mixed windows: consecutive rows jump between the classes, so no
            // timestamp order matches the insert (commit) order.
            seed(&n, &id, TS_CLASSES[(i * 3) % TS_CLASSES.len()], 5).await;
            order.push(id);
        }
        let hidden = order[position.index()].clone();
        hide(&n, &hidden).await;
        // The hide is a real change of a replicated column: it re-numbers the
        // row to the head, so it now sits LAST in the walk.
        let mut seq_order = Vec::new();
        for id in &order {
            seq_order.push((seq_of(&n, id).await, id.clone()));
        }
        seq_order.sort();
        let (served, cursors) = walk(&n.router, 0, PAGE).await;
        let expected: Vec<String> = seq_order
            .iter()
            .filter(|(_, id)| *id != hidden)
            .map(|(_, id)| id.clone())
            .collect();
        assert_eq!(
            served, expected,
            "{backend:?}/{position:?}: exact serve order"
        );
        let expected_cursors: Vec<i64> = seq_order
            .chunks(PAGE)
            .map(|c| c.last().expect("chunk").0)
            .chain(std::iter::once(seq_order.last().expect("rows").0))
            .collect();
        assert_eq!(
            cursors, expected_cursors,
            "{backend:?}/{position:?}: window cursors"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_seq_walk_serves_every_row_whatever_its_timestamp_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    generative_walk(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_seq_walk_serves_every_row_whatever_its_timestamp_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    generative_walk(Backend::Postgres).await;
    clear_posture();
}

/// THE defect: a row that lands after the puller's cursor passed its
/// timestamp. The seq walk serves it; the legacy since path still does not
/// (risk: old pullers keep the hole), quoted so the gap stays visible.
async fn late_row_below_cursor(backend: Backend) {
    let Some(n) = node(backend, "late").await else {
        return;
    };
    seed(&n, "late-1", TS_EQUAL, 5).await;
    seed(&n, "late-2", TS_ABOVE, 5).await;
    let (served, cursors) = walk(&n.router, 0, PAGE).await;
    assert_eq!(served, ["late-1", "late-2"], "{backend:?}: first walk");
    let cursor = *cursors.last().expect("cursor");
    let (_, legacy) = get(&n.router, None, PAGE).await;
    let legacy_since = legacy["next_since"].as_str().map(str::to_string);

    seed(&n, "late-relayed", TS_RELAYED, 5).await;
    let v = pull_seq(&n.router, cursor, PAGE).await;
    assert_eq!(
        ids(&v),
        ["late-relayed"],
        "{backend:?}: the late row is served"
    );
    assert_eq!(next_seq(&v), cursor + 1, "{backend:?}: next_seq is its seq");

    let since = legacy_since.expect("legacy next_since");
    let uri = format!(
        "/api/v1/sync/since?limit={PAGE}&peer={NODE_C}&since={}",
        since.replace('+', "%2B").replace(':', "%3A")
    );
    let req = Request::builder()
        .uri(uri)
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            NODE_C,
        )
        .body(Body::empty())
        .expect("request");
    let resp = n.router.clone().oneshot(req).await.expect("oneshot");
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    let old: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        ids(&old),
        Vec::<String>::new(),
        "{backend:?}: the since path keeps the hole for old pullers (documented risk)"
    );
    assert!(
        old.get(NEXT_SEQ).is_none(),
        "the since path carries no next_seq: {old}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_late_row_below_cursor_is_served_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    late_row_below_cursor(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_late_row_below_cursor_is_served_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    late_row_below_cursor(Backend::Postgres).await;
    clear_posture();
}

/// A bump happens only on an INSERT or a real change of a replicated column.
async fn bump_rules(backend: Backend) {
    let Some(n) = node(backend, "bump").await else {
        return;
    };
    seed(&n, "bump-1", TS_EQUAL, 5).await;
    seed(&n, "bump-2", TS_EQUAL, 5).await;
    let s1 = seq_of(&n, "bump-1").await;
    let s2 = seq_of(&n, "bump-2").await;
    assert_eq!(
        (s1, s2),
        (1, 2),
        "{backend:?}: inserts number from 1 in commit order"
    );

    // Unreplicated column: no bump.
    exec(
        &n,
        "UPDATE memories SET access_count = access_count + 1 WHERE id = ?1",
        "UPDATE memories SET access_count = access_count + 1 WHERE id = $1",
        "bump-1",
    )
    .await;
    assert_eq!(
        seq_of(&n, "bump-1").await,
        s1,
        "{backend:?}: access_count is a touch"
    );
    // Replicated column set to its own value: no bump.
    exec(
        &n,
        "UPDATE memories SET title = title WHERE id = ?1",
        "UPDATE memories SET title = title WHERE id = $1",
        "bump-1",
    )
    .await;
    assert_eq!(
        seq_of(&n, "bump-1").await,
        s1,
        "{backend:?}: a no-op write is no change"
    );
    // A caller cannot pin the seq: a direct write of the column is not a
    // replicated change and a relayed insert is renumbered (risk: a raw
    // `SET sync_seq` is unguarded; nothing in the product issues one).
    // Real change: bump to the head.
    exec(
        &n,
        "UPDATE memories SET title = 'changed 9082' WHERE id = ?1",
        "UPDATE memories SET title = 'changed 9082' WHERE id = $1",
        "bump-1",
    )
    .await;
    assert_eq!(
        seq_of(&n, "bump-1").await,
        3,
        "{backend:?}: a real change takes head+1"
    );
    let v = pull_seq(&n.router, s2, PAGE).await;
    assert_eq!(
        ids(&v),
        ["bump-1"],
        "{backend:?}: the changed row is re-served"
    );
    assert_eq!(next_seq(&v), 3, "{backend:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_seq_bumps_only_on_insert_or_real_change_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    bump_rules(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_seq_bumps_only_on_insert_or_real_change_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    bump_rules(Backend::Postgres).await;
    clear_posture();
}

/// Empty-page echo, the reset above the head, the stable epoch and the 400 on
/// a negative `after_seq`.
async fn edges(backend: Backend) {
    let Some(n) = node(backend, "edges").await else {
        return;
    };
    let empty = pull_seq(&n.router, 0, PAGE).await;
    assert_eq!(
        (ids(&empty).len(), next_seq(&empty)),
        (0, 0),
        "{backend:?}: empty db"
    );
    let e0 = epoch(&empty);
    assert!(!e0.is_empty(), "{backend:?}: the epoch is never empty");
    seed(&n, "edge-1", TS_EQUAL, 5).await;
    seed(&n, "edge-2", TS_ABOVE, 5).await;

    let echo = pull_seq(&n.router, 2, PAGE).await;
    assert_eq!(
        ids(&echo),
        Vec::<String>::new(),
        "{backend:?}: nothing past the head"
    );
    assert_eq!(
        next_seq(&echo),
        2,
        "{backend:?}: an empty page echoes after_seq"
    );
    assert_eq!(epoch(&echo), e0, "{backend:?}: the epoch is stable");

    // A puller whose cursor is above the head (this node was restored or
    // re-initialised under it) is walked from 0, never left stranded.
    let reset = pull_seq(&n.router, 1_000, PAGE).await;
    assert_eq!(
        ids(&reset),
        ["edge-1", "edge-2"],
        "{backend:?}: above head walks from 0"
    );
    assert_eq!(next_seq(&reset), 2, "{backend:?}");

    let (status, body) = get(&n.router, Some("-1"), PAGE).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{backend:?}: negative after_seq: {body}"
    );
    let (status, body) = get(&n.router, Some("not-a-number"), PAGE).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{backend:?}: non-integer: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_seq_edges_echo_reset_epoch_and_refusal_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    edges(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_seq_edges_echo_reset_epoch_and_refusal_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    edges(Backend::Postgres).await;
    clear_posture();
}

/// The epoch is regenerated on restore, so a puller's stored cursor against
/// the old database is treated as foreign.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_regenerates_the_seq_epoch_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let n = sqlite_node("restore");
    seed(&n, "restore-1", TS_EQUAL, 5).await;
    let before = epoch(&pull_seq(&n.router, 0, PAGE).await);
    let snapshot = n.db_path.with_file_name("restore-snapshot.db");
    {
        let guard = n.db.lock().await;
        guard
            .0
            .execute("VACUUM INTO ?1", [snapshot.to_string_lossy().as_ref()])
            .expect("snapshot");
    }
    let target = n.db_path.with_file_name("restore-target.db");
    std::fs::copy(&snapshot, &target).expect("copy snapshot");
    // #9176 F6: a file copied back WITHOUT `ai-memory restore` carries the
    // source file's identity, so its first open re-mints the epoch too.
    let copied_epoch = {
        let copied = ai_memory::db::open(&target).expect("open copy");
        let head = ai_memory::storage::sync_seq::seq_head(&copied).expect("head");
        assert_ne!(
            head.epoch, before,
            "a copied database file gets a new epoch at its first open (#9176 F6)"
        );
        assert_eq!(head.head, 1, "the copy keeps its head");
        head.epoch
    };
    {
        let again = ai_memory::db::open(&target).expect("reopen copy");
        let head = ai_memory::storage::sync_seq::seq_head(&again).expect("head");
        assert_eq!(
            head.epoch, copied_epoch,
            "the copy is re-minted once, not per open"
        );
    }
    // `restore` arms the reset before it publishes; the next open consumes it.
    ai_memory::storage::sync_seq::arm_epoch_reset(&target).expect("arm");
    let marker = ai_memory::storage::sync_seq::epoch_reset_marker_path(&target);
    assert!(marker.exists(), "the sidecar is armed");
    let fresh = {
        let restored = ai_memory::db::open(&target).expect("open restored");
        let head = ai_memory::storage::sync_seq::seq_head(&restored).expect("head");
        assert_ne!(head.epoch, before, "a restored database gets a new epoch");
        assert_ne!(head.epoch, copied_epoch, "the armed reset mints again");
        assert_eq!(head.head, 1, "the head survives, the epoch does not");
        head.epoch
    };
    assert!(!marker.exists(), "the sidecar is consumed by the open");
    let reopened = ai_memory::db::open(&target).expect("reopen");
    let head = ai_memory::storage::sync_seq::seq_head(&reopened).expect("head");
    assert_eq!(
        head.epoch, fresh,
        "the reset happens once, not on every open"
    );
    clear_posture();
}

/// Every `(id, sync_seq)` pair and the counter `(head, epoch)`.
type SeqSnapshot = (Vec<(String, i64)>, (i64, String));

async fn seq_snapshot(node: &Node) -> SeqSnapshot {
    #[cfg(feature = "sal-postgres")]
    if let Some((pool, _)) = node.pg.as_ref() {
        let rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT id, sync_seq FROM memories ORDER BY id")
                .fetch_all(pool)
                .await
                .expect("pg seq rows");
        let counter: (i64, String) =
            sqlx::query_as("SELECT head, epoch FROM sync_seq_counter WHERE id = 1")
                .fetch_one(pool)
                .await
                .expect("pg counter");
        return (rows, counter);
    }
    let guard = node.db.lock().await;
    let mut stmt = guard
        .0
        .prepare("SELECT id, sync_seq FROM memories ORDER BY id")
        .expect("prepare seq rows");
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("seq rows")
        .collect::<Result<Vec<(String, i64)>, _>>()
        .expect("collect seq rows");
    let counter = guard
        .0
        .query_row(
            "SELECT head, epoch FROM sync_seq_counter WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("counter");
    (rows, counter)
}

/// Rewind the stamp below v102 (one transaction, the #3528 shape) and run the
/// ladder again through the backend's own open path.
async fn rerun_v102(node: &Node) {
    const STAMP_BELOW_V102: i32 = 101;
    #[cfg(feature = "sal-postgres")]
    if let Some((pool, scratch)) = node.pg.as_ref() {
        let mut tx = pool.begin().await.expect("begin stamp rewind");
        sqlx::query("DELETE FROM schema_version")
            .execute(&mut *tx)
            .await
            .expect("clear stamp");
        sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
            .bind(STAMP_BELOW_V102)
            .execute(&mut *tx)
            .await
            .expect("seed v101 stamp");
        tx.commit().await.expect("commit stamp rewind");
        let _store = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
            .await
            .expect("re-run the ladder");
        return;
    }
    {
        let guard = node.db.lock().await;
        guard
            .0
            .execute_batch(&format!(
                "BEGIN; DELETE FROM schema_version; \
                 INSERT INTO schema_version (version) VALUES ({STAMP_BELOW_V102}); COMMIT;"
            ))
            .expect("rewind stamp");
    }
    let _conn = ai_memory::db::open(&node.db_path).expect("re-run the ladder");
}

/// F1 (#9176 r1): a second run of the v102 migration (stamp rewind, a
/// re-applied ladder) never renumbers an assigned `sync_seq` and never moves
/// the counter: a row a puller has not pulled yet must never drop below that
/// puller's cursor under the same epoch.
async fn v102_rerun_keeps_seq(backend: Backend) {
    let Some(n) = node(backend, "rerun").await else {
        return;
    };
    // Insert order differs from (updated_at, id) order, so a re-run of the
    // backfill would renumber every row.
    for (i, ts) in TS_CLASSES.iter().enumerate() {
        seed(&n, &format!("rerun-{i}"), ts, 5).await;
    }
    exec(
        &n,
        "UPDATE memories SET title = 'bumped' WHERE id = ?1",
        "UPDATE memories SET title = 'bumped' WHERE id = $1",
        "rerun-0",
    )
    .await;
    let before = seq_snapshot(&n).await;
    assert_eq!(
        before.1.0,
        i64::try_from(TS_CLASSES.len() + 1).expect("rows"),
        "{backend:?}: five inserts and one bump"
    );
    rerun_v102(&n).await;
    let after = seq_snapshot(&n).await;
    assert_eq!(
        after, before,
        "{backend:?}: a v102 re-run keeps every sync_seq, the head and the epoch"
    );
    // The triggers are live after the re-run: the next write takes head + 1.
    seed(&n, "rerun-after", TS_EQUAL, 5).await;
    assert_eq!(
        seq_of(&n, "rerun-after").await,
        before.1.0 + 1,
        "{backend:?}: the counter continues"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_v102_rerun_keeps_every_sync_seq_and_the_counter_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    v102_rerun_keeps_seq(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_v102_rerun_keeps_every_sync_seq_and_the_counter_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    v102_rerun_keeps_seq(Backend::Postgres).await;
    clear_posture();
}

/// Drop the triggers a column drop needs out of the way (the F2 helpers).
async fn drop_seq_triggers(node: &Node) {
    #[cfg(feature = "sal-postgres")]
    if let Some((pool, _)) = node.pg.as_ref() {
        sqlx::raw_sql(ai_memory::storage::sync_seq::SQL_DROP_SYNC_SEQ_TRIGGERS_PG)
            .execute(pool)
            .await
            .expect("drop pg triggers");
        return;
    }
    let guard = node.db.lock().await;
    guard
        .0
        .execute_batch(ai_memory::storage::sync_seq::SQL_DROP_SYNC_SEQ_TRIGGERS)
        .expect("drop sqlite triggers");
}

/// #9176 r1: a row written while the triggers are dropped (a ladder re-run
/// that drops a bump column) is numbered above the head by the v102 re-run
/// and served, never left at a placeholder (postgres) or the default 0
/// (sqlite) that no walk reaches. Assigned values are kept.
async fn v102_rerun_numbers_rows_written_without_triggers(backend: Backend) {
    const ASSIGNED_ROWS: usize = 3;
    let Some(n) = node(backend, "heal").await else {
        return;
    };
    for i in 0..ASSIGNED_ROWS {
        seed(&n, &format!("heal-{i}"), TS_EQUAL, 5).await;
    }
    let before = seq_snapshot(&n).await;
    drop_seq_triggers(&n).await;
    seed(&n, "heal-orphan", TS_EQUAL, 5).await;
    assert!(
        seq_of(&n, "heal-orphan").await <= 0,
        "{backend:?}: without the triggers the row is unnumbered"
    );
    rerun_v102(&n).await;
    let head = i64::try_from(ASSIGNED_ROWS).expect("rows");
    assert_eq!(
        seq_of(&n, "heal-orphan").await,
        head + 1,
        "{backend:?}: the re-run numbers the row above the head"
    );
    let after = seq_snapshot(&n).await;
    assert_eq!(after.1.0, head + 1, "{backend:?}: the head moves past it");
    assert_eq!(after.1.1, before.1.1, "{backend:?}: the epoch is kept");
    for row in &before.0 {
        assert!(
            after.0.contains(row),
            "{backend:?}: assigned value kept: {row:?}"
        );
    }
    let page = pull_seq(&n.router, head, PAGE).await;
    assert_eq!(
        ids(&page),
        vec!["heal-orphan".to_string()],
        "{backend:?}: the walk serves the row: {page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_v102_rerun_numbers_rows_written_without_triggers_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    v102_rerun_numbers_rows_written_without_triggers(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_v102_rerun_numbers_rows_written_without_triggers_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    v102_rerun_numbers_rows_written_without_triggers(Backend::Postgres).await;
    clear_posture();
}

/// Throughput: the trigger and the walk on a large table stay inside named
/// ceilings, and the walk serves every row exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_seq_walk_large_table_inside_ceiling_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let n = sqlite_node("large");
    let started = Instant::now();
    {
        let mut guard = n.db.lock().await;
        let tx = guard.0.transaction().expect("tx");
        for i in 0..LARGE_TABLE_ROWS {
            tx.execute(
                "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
                 confidence, source, metadata, access_count, created_at, updated_at) \
                 VALUES (?1, 'long', ?2, ?1, 'x', '[]', 5, 1.0, 'api', \
                 '{\"agent_id\":\"ai:puller\",\"scope\":\"collective\"}', 0, ?3, ?3)",
                rusqlite::params![
                    format!("large-{i:05}"),
                    NAMESPACE,
                    TS_CLASSES[i % TS_CLASSES.len()]
                ],
            )
            .expect("insert");
        }
        tx.commit().expect("commit");
    }
    let seeded = started.elapsed();
    assert!(
        seeded < LARGE_TABLE_SEED_CEILING,
        "{LARGE_TABLE_ROWS} inserts took {seeded:?} (ceiling {LARGE_TABLE_SEED_CEILING:?})"
    );
    let started = Instant::now();
    let (served, _) = walk(&n.router, 0, LARGE_TABLE_PAGE).await;
    let walked = started.elapsed();
    assert_eq!(served.len(), LARGE_TABLE_ROWS, "every row served");
    assert_eq!(
        served.iter().collect::<BTreeSet<_>>().len(),
        LARGE_TABLE_ROWS,
        "each exactly once"
    );
    assert!(
        walked < LARGE_TABLE_WALK_CEILING,
        "walk took {walked:?} (ceiling {LARGE_TABLE_WALK_CEILING:?})"
    );
    eprintln!("throughput-9082: seed {seeded:?} walk {walked:?} rows {LARGE_TABLE_ROWS}");
    clear_posture();
}

// ---------------------------------------------------------------------------
// postgres concurrency: commit order and the counter lock
// ---------------------------------------------------------------------------

/// Wait until `pid` is blocked on a lock (deterministic, no sleep ordering).
#[cfg(feature = "sal-postgres")]
async fn wait_until_lock_waiting(pool: &sqlx::PgPool, pid: i32) {
    for _ in 0..2_000 {
        let waiting: Option<String> =
            sqlx::query_scalar("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1")
                .bind(pid)
                .fetch_optional(pool)
                .await
                .expect("pg_stat_activity")
                .flatten();
        if waiting.as_deref() == Some("Lock") {
            return;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("pid {pid} never waited on a lock");
}

/// Two writers: the second cannot take a seq until the first commits, so a
/// reader never sees seq N+1 while N is in flight (seq order = commit order).
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_concurrent_writers_commit_in_seq_order_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let Some(n) = postgres_node("concurrent").await else {
        clear_posture();
        return;
    };
    let (pool, _) = n.pg.as_ref().expect("pg");
    let mut first = pool.begin().await.expect("tx1");
    sqlx::query("UPDATE sync_seq_counter SET head = head WHERE id = 1")
        .execute(&mut *first)
        .await
        .expect("noop");
    let insert = "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
                  confidence, source, metadata, access_count, created_at, updated_at) \
                  VALUES ($1, 'long', $2, $1, 'x', '[]'::jsonb, 5, 1.0, 'api', \
                  '{\"agent_id\":\"ai:puller\",\"scope\":\"collective\"}'::jsonb, 0, \
                  now(), now())";
    sqlx::query(insert)
        .bind("cc-first")
        .bind(NAMESPACE)
        .execute(&mut *first)
        .await
        .expect("first insert");
    let second_pool = pool.clone();
    let second = tokio::spawn(async move {
        let mut tx = second_pool.begin().await.expect("tx2");
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("pid");
        let pid_tx = pid;
        let fut = async move {
            sqlx::query(insert)
                .bind("cc-second")
                .bind(NAMESPACE)
                .execute(&mut *tx)
                .await
                .expect("second insert");
            tx.commit().await.expect("commit second");
        };
        (pid_tx, fut)
    });
    let (pid, fut) = second.await.expect("join");
    let handle = tokio::spawn(fut);
    wait_until_lock_waiting(pool, pid).await;
    // The reader sees nothing: seq 1 is in flight and seq 2 cannot exist yet.
    let mid = pull_seq(&n.router, 0, PAGE).await;
    assert_eq!(
        ids(&mid),
        Vec::<String>::new(),
        "no row is visible mid-flight"
    );
    first.commit().await.expect("commit first");
    handle.await.expect("second writer");
    let v = pull_seq(&n.router, 0, PAGE).await;
    assert_eq!(
        ids(&v),
        ["cc-first", "cc-second"],
        "seq order = commit order"
    );
    assert_eq!(next_seq(&v), 2);
    clear_posture();
}

/// F5 (#9176 r1): the counter is taken only at COMMIT (a deferred constraint
/// trigger), after every row lock the transaction needs is already held, so
/// it can never be one edge of a lock cycle. The shape is the production one:
/// writer `two` locks its rows up front (the `lock_order_4209` funnel: SELECT
/// ... FOR UPDATE, then UPDATE) while writer `one` has already changed a row
/// and then needs a row `two` holds. Before the fix `two` waited for the
/// counter `one` held and `one` waited for `two`'s row: SQLSTATE 40P01 on one
/// side, a failed write that no caller retries. Now both commit, in commit
/// order, and the counter matches the committed rows.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_multi_row_writers_never_deadlock_on_the_counter_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let Some(n) = postgres_node("deadlock").await else {
        clear_posture();
        return;
    };
    for id in ["dl-a", "dl-b", "dl-c"] {
        seed(&n, id, TS_EQUAL, 5).await;
    }
    let seeded_head = seq_snapshot(&n).await.1.0;
    let (pool, _) = n.pg.as_ref().expect("pg");
    let mut one = pool.begin().await.expect("tx one");
    let mut two = pool.begin().await.expect("tx two");
    // one: a replicated change on dl-a (the old design took the counter here).
    sqlx::query("UPDATE memories SET title = 'one' WHERE id = 'dl-a'")
        .execute(&mut *one)
        .await
        .expect("one changes dl-a");
    // two: locks dl-b up front, then changes dl-c.
    sqlx::query("SELECT 1 FROM memories WHERE id = 'dl-b' FOR UPDATE")
        .execute(&mut *two)
        .await
        .expect("two locks dl-b");
    let two_task = tokio::spawn(async move {
        sqlx::query("UPDATE memories SET title = 'two' WHERE id = 'dl-c'")
            .execute(&mut *two)
            .await?;
        sqlx::query("UPDATE memories SET title = 'two-b' WHERE id = 'dl-b'")
            .execute(&mut *two)
            .await?;
        two.commit().await
    });
    let one_task = tokio::spawn(async move {
        // one: needs dl-b, which two holds until it commits.
        sqlx::query("UPDATE memories SET title = 'one-b' WHERE id = 'dl-b'")
            .execute(&mut *one)
            .await?;
        one.commit().await
    });
    let code = |r: &Result<(), sqlx::Error>| -> Option<String> {
        match r {
            Err(sqlx::Error::Database(db)) => db.code().map(|c| c.to_string()),
            Err(other) => Some(other.to_string()),
            Ok(()) => None,
        }
    };
    let two_result = two_task.await.expect("join two");
    let one_result = one_task.await.expect("join one");
    assert_eq!(
        [code(&two_result), code(&one_result)],
        [None, None],
        "both writers commit: no 40P01 deadlock victim"
    );
    let snap = seq_snapshot(&n).await;
    let seq = |id: &str| {
        snap.0
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, s)| *s)
            .expect("row present")
    };
    // two commits first and numbers dl-c (+1) and dl-b (+2); one's commit
    // then numbers dl-a (+3) and re-numbers dl-b (+4), the last writer.
    assert_eq!(
        [seq("dl-c"), seq("dl-a"), seq("dl-b")],
        [seeded_head + 1, seeded_head + 3, seeded_head + 4],
        "seq order is commit order, the last writer of dl-b holds the highest seq"
    );
    assert_eq!(
        snap.1.0,
        seeded_head + 4,
        "the counter matches the committed rows"
    );
    clear_posture();
}

/// Insert a corpus row inside an open transaction (the [`seed`] shape).
#[cfg(feature = "sal-postgres")]
async fn insert_in_tx(tx: &mut sqlx::PgConnection, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
         confidence, source, metadata, access_count, created_at, updated_at) \
         VALUES ($1, 'long', $2, $3, 'sync_seq corpus row (#9082)', '[]'::jsonb, 5, 1.0, \
         'api', '{\"agent_id\":\"ai:puller\",\"scope\":\"collective\"}'::jsonb, 0, \
         $4::timestamptz, $5::timestamptz)",
    )
    .bind(id)
    .bind(NAMESPACE)
    .bind(format!("row {id}"))
    .bind(TS_MIN)
    .bind(TS_EQUAL)
    .execute(tx)
    .await
    .map(|_| ())
}

/// F5 (#9176 r1), the INSERT sibling of the test above: a new row takes only
/// a placeholder at insert time (the after-insert assignment is deferred to
/// COMMIT), so a multi-row writer that inserts and then needs a row another
/// writer holds is never one edge of a cycle through the counter. Before the
/// fix `one`'s insert held the counter, `two`'s insert waited for it while
/// `two` held the row `one` needed next: 40P01 on one side.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_multi_row_inserters_never_deadlock_on_the_counter_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let Some(n) = postgres_node("deadlock_ins").await else {
        clear_posture();
        return;
    };
    seed(&n, "di-b", TS_EQUAL, 5).await;
    let seeded_head = seq_snapshot(&n).await.1.0;
    let (pool, _) = n.pg.as_ref().expect("pg");
    let mut one = pool.begin().await.expect("tx one");
    let mut two = pool.begin().await.expect("tx two");
    // one: inserts a row (the old design took the counter here).
    insert_in_tx(&mut one, "di-one").await.expect("one inserts");
    // two: locks di-b up front.
    sqlx::query("SELECT 1 FROM memories WHERE id = 'di-b' FOR UPDATE")
        .execute(&mut *two)
        .await
        .expect("two locks di-b");
    let two_task = tokio::spawn(async move {
        insert_in_tx(&mut two, "di-two").await?;
        two.commit().await
    });
    let one_task = tokio::spawn(async move {
        // one: needs di-b, which two holds until it commits.
        sqlx::query("UPDATE memories SET title = 'one-b' WHERE id = 'di-b'")
            .execute(&mut *one)
            .await?;
        one.commit().await
    });
    let code = |r: &Result<(), sqlx::Error>| -> Option<String> {
        match r {
            Err(sqlx::Error::Database(db)) => db.code().map(|c| c.to_string()),
            Err(other) => Some(other.to_string()),
            Ok(()) => None,
        }
    };
    let two_result = two_task.await.expect("join two");
    let one_result = one_task.await.expect("join one");
    assert_eq!(
        [code(&two_result), code(&one_result)],
        [None, None],
        "both inserters commit: no 40P01 deadlock victim"
    );
    let snap = seq_snapshot(&n).await;
    let seq = |id: &str| {
        snap.0
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, s)| *s)
            .expect("row present")
    };
    // two commits first and numbers di-two (+1); one's commit then numbers
    // di-one (+2) and re-numbers di-b (+3), in that trigger order.
    assert_eq!(
        seq("di-two"),
        seeded_head + 1,
        "the first committer takes the next value"
    );
    assert!(
        seq("di-one") > seeded_head + 1 && seq("di-b") > seeded_head + 1,
        "the later committer's rows sit above it: {snap:?}"
    );
    assert_eq!(
        snap.1.0,
        seeded_head + 3,
        "the counter matches the committed rows"
    );
    clear_posture();
}

// ---------------------------------------------------------------------------
// puller side: the relay, refused rows, a restored peer
// ---------------------------------------------------------------------------

async fn serve(node: &Node) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let router = node.router.clone();
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

fn fed_config(local_id: &str, peer_id: &str, peer_url: &str) -> FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30))
            .expect("policy"),
        peers: vec![PeerEndpoint {
            id: peer_id.to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: local_id.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

async fn pass(cfg: &FederationConfig, puller: &Node) -> PullOutcome {
    let mut outcomes = ai_memory::federation::catchup_pass_for_tests(cfg, &puller.db).await;
    assert_eq!(outcomes.len(), 1, "one peer, one outcome");
    outcomes.remove(0).1
}

async fn stored(node: &Node) -> BTreeSet<String> {
    let guard = node.db.lock().await;
    let mut stmt = guard
        .0
        .prepare("SELECT id FROM memories WHERE namespace = ?1")
        .expect("prepare");
    stmt.query_map([NAMESPACE], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

fn pull_cursor(
    node: &Node,
    local: &str,
    peer: &str,
) -> ai_memory::storage::sync_seq::PullSeqCursor {
    let conn = rusqlite::Connection::open(&node.db_path).expect("open");
    ai_memory::storage::sync_seq::sync_pull_seq_get(&conn, local, peer).expect("cursor")
}

/// The two-hop relay. A writes r1; B pulls A; C pulls B. A then receives a
/// row stamped older than everything (a relay or a backward clock step). B
/// pulls it by seq, B's own trigger numbers it, and C pulls it from B.
async fn relay(origin_backend: Backend) {
    let Some(a) = node(origin_backend, "relay-a").await else {
        return;
    };
    let b = sqlite_node("relay-b");
    let c = sqlite_node("relay-c");
    let a_url = serve(&a).await;
    let b_url = serve(&b).await;
    let b_from_a = fed_config(NODE_B, NODE_A, &a_url);
    let c_from_b = fed_config(NODE_C, NODE_B, &b_url);

    seed(&a, "relay-r1", TS_ABOVE, 5).await;
    let ab = pass(&b_from_a, &b).await;
    assert_eq!(
        (ab.applied, ab.refused.len()),
        (1, 0),
        "{origin_backend:?}: B <- A r1"
    );
    let bc = pass(&c_from_b, &c).await;
    assert_eq!(
        (bc.applied, bc.refused.len()),
        (1, 0),
        "{origin_backend:?}: C <- B r1"
    );

    seed(&a, "relay-r0", TS_RELAYED, 5).await;
    let ab = pass(&b_from_a, &b).await;
    assert_eq!(
        ab.applied, 1,
        "{origin_backend:?}: B pulls the old-stamped row by seq"
    );
    let bc = pass(&c_from_b, &c).await;
    assert_eq!(
        bc.applied, 1,
        "{origin_backend:?}: C pulls the relayed row from B"
    );
    let want: BTreeSet<String> = ["relay-r0", "relay-r1"].map(String::from).into();
    assert_eq!(
        stored(&c).await,
        want,
        "{origin_backend:?}: the edge holds every row"
    );

    let cb = pull_cursor(&c, NODE_C, NODE_B);
    let b_head = {
        let guard = b.db.lock().await;
        ai_memory::storage::sync_seq::seq_head(&guard.0).expect("b head")
    };
    assert_eq!(cb.last_seq, Some(b_head.head), "C's seq cursor is B's head");
    assert_eq!(
        cb.seq_epoch,
        Some(b_head.epoch),
        "C's cursor carries B's epoch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_two_hop_relay_reaches_the_edge_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    relay(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_origin_two_hop_relay_reaches_the_edge_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    relay(Backend::Postgres).await;
    clear_posture();
}

/// Refused-row position table on the seq path: an invalid row at the first,
/// middle or last place of a window is recorded with its exact reason and
/// passed; every valid row lands and the cursor reaches the head.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seq_puller_records_and_passes_a_refused_row_at_every_position_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    for position in POSITIONS {
        let b = sqlite_node(&format!("refuse-b-{position:?}"));
        let c = sqlite_node(&format!("refuse-c-{position:?}"));
        let b_url = serve(&b).await;
        let cfg = fed_config(NODE_C, NODE_B, &b_url);
        let mut valid = BTreeSet::new();
        let mut refused_id = String::new();
        for i in 0..PAGE {
            let id = format!("refuse-{position:?}-{i}");
            if i == position.index() {
                let tags = serde_json::to_string(
                    &(0..INVALID_TAG_COUNT)
                        .map(|t| format!("t{t}"))
                        .collect::<Vec<_>>(),
                )
                .expect("tags json");
                seed_tagged(&b, &id, TS_CLASSES[i % TS_CLASSES.len()], 5, &tags).await;
                refused_id = id;
            } else {
                seed(&b, &id, TS_CLASSES[i % TS_CLASSES.len()], 5).await;
                valid.insert(id);
            }
        }
        let out = pass(&cfg, &c).await;
        assert_eq!(out.applied, PAGE - 1, "{position:?}: every valid row lands");
        assert_eq!(
            out.refused.len(),
            1,
            "{position:?}: one refusal: {:?}",
            out.refused
        );
        assert_eq!(out.refused[0].memory_id, refused_id, "{position:?}");
        assert_eq!(
            out.refused[0].reason,
            RefusalReason::InvalidMemory,
            "{position:?}"
        );
        assert_eq!(stored(&c).await, valid, "{position:?}: exact set stored");
        let cursor = pull_cursor(&c, NODE_C, NODE_B);
        assert_eq!(
            cursor.last_seq,
            Some(i64::try_from(PAGE).expect("page")),
            "{position:?}: the refused row is passed, the cursor reaches the head"
        );
    }
    clear_posture();
}

/// A peer restored from a backup under the puller's cursor (new epoch, head
/// below the stored `last_seq`): the puller walks it from 0 and lands the rows
/// written after the restore point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seq_puller_rewalks_a_restored_peer_with_a_stale_high_cursor_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let b = sqlite_node("restored-b");
    let c = sqlite_node("restored-c");
    let b_url = serve(&b).await;
    let cfg = fed_config(NODE_C, NODE_B, &b_url);
    for i in 0..3 {
        seed(&b, &format!("pre-{i}"), TS_EQUAL, 5).await;
    }
    let out = pass(&cfg, &c).await;
    assert_eq!(out.applied, 3, "first walk");
    // Simulate the restore: B's rows after the snapshot are gone, its counter
    // is back at the snapshot head and the restore gave it a new epoch.
    {
        let guard = b.db.lock().await;
        guard
            .0
            .execute_batch(
                "DELETE FROM memories; UPDATE sync_seq_counter SET head = 0 WHERE id = 1;",
            )
            .expect("simulate restore");
        ai_memory::storage::sync_seq::regenerate_seq_epoch(&guard.0).expect("regen");
    }
    seed(&b, "post-restore", TS_RELAYED, 5).await;
    let out = pass(&cfg, &c).await;
    assert_eq!(out.applied, 1, "the row written after the restore lands");
    assert!(
        stored(&c).await.contains("post-restore"),
        "post-restore row stored"
    );
    let cursor = pull_cursor(&c, NODE_C, NODE_B);
    let head = {
        let guard = b.db.lock().await;
        ai_memory::storage::sync_seq::seq_head(&guard.0).expect("head")
    };
    assert_eq!(
        cursor.last_seq,
        Some(head.head),
        "cursor re-based on the restored head"
    );
    assert_eq!(
        cursor.seq_epoch,
        Some(head.epoch),
        "cursor adopts the new epoch"
    );
    clear_posture();
}

/// A peer restored under the puller's cursor whose head has since passed the
/// stored `last_seq` (new epoch, head above the cursor): the server cannot see
/// the stale cursor, so only the puller's epoch check walks it from 0. Without
/// it the rows numbered at or below the old cursor are skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seq_puller_rewalks_a_restored_peer_whose_head_passed_the_cursor_9082() {
    const PRE_RESTORE_ROWS: usize = 3;
    const POST_RESTORE_ROWS: usize = PRE_RESTORE_ROWS + 2;
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let b = sqlite_node("passed-b");
    let c = sqlite_node("passed-c");
    let b_url = serve(&b).await;
    let cfg = fed_config(NODE_C, NODE_B, &b_url);
    for i in 0..PRE_RESTORE_ROWS {
        seed(&b, &format!("pre-{i}"), TS_EQUAL, 5).await;
    }
    assert_eq!(pass(&cfg, &c).await.applied, PRE_RESTORE_ROWS, "first walk");
    {
        let guard = b.db.lock().await;
        guard
            .0
            .execute_batch(
                "DELETE FROM memories; UPDATE sync_seq_counter SET head = 0 WHERE id = 1;",
            )
            .expect("simulate restore");
        ai_memory::storage::sync_seq::regenerate_seq_epoch(&guard.0).expect("regen");
    }
    let mut post = BTreeSet::new();
    for i in 0..POST_RESTORE_ROWS {
        let id = format!("post-{i}");
        seed(&b, &id, TS_RELAYED, 5).await;
        post.insert(id);
    }
    // decision: assert a two-window convergence over one window, because
    // `resolve_seq` answers 0 on an epoch mismatch and each catch-up pass
    // walks one window per peer: the first window lands the rows above the
    // old cursor and re-arms the walk at 0 under the new epoch, the second
    // walks the new numbering from the start.
    let first = pass(&cfg, &c).await;
    assert_eq!(
        first.applied,
        POST_RESTORE_ROWS - PRE_RESTORE_ROWS,
        "the first window lands the rows numbered above the old cursor"
    );
    let rearmed = pull_cursor(&c, NODE_C, NODE_B);
    assert_eq!(
        rearmed.last_seq,
        Some(0),
        "an epoch mismatch re-arms the walk at 0"
    );
    let head_epoch = {
        let guard = b.db.lock().await;
        ai_memory::storage::sync_seq::seq_head(&guard.0)
            .expect("head")
            .epoch
    };
    assert_eq!(
        rearmed.seq_epoch,
        Some(head_epoch),
        "the re-armed cursor carries the new epoch"
    );
    let _second = pass(&cfg, &c).await;
    let got = stored(&c).await;
    assert!(post.is_subset(&got), "post-restore rows stored: {got:?}");
    let cursor = pull_cursor(&c, NODE_C, NODE_B);
    assert_eq!(
        cursor.last_seq,
        Some(i64::try_from(POST_RESTORE_ROWS).expect("rows")),
        "cursor at the restored head"
    );
    clear_posture();
}

// ---------------------------------------------------------------------------
// #9176 round 1
// ---------------------------------------------------------------------------

/// F6 (PostgreSQL): a database that comes back from a restore carries another
/// instance's `node_identity` and a lower head. The next connect re-mints the
/// epoch, so a puller whose cursor the restored head has already passed walks
/// it from 0 and lands every row written after the restore, including those
/// numbered at or below its old cursor.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_restored_peer_is_rewalked_after_its_head_passes_the_cursor_9176() {
    const PRE_RESTORE_ROWS: usize = 3;
    const POST_RESTORE_ROWS: usize = PRE_RESTORE_ROWS + 2;
    const FOREIGN_IDENTITY: &str = "restored-from-another-cluster:00000001:1";
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let Some(b) = postgres_node("pg-restored-b").await else {
        clear_posture();
        return;
    };
    let (pool, scratch) = b.pg.as_ref().expect("pg node");
    let bound: Option<String> =
        sqlx::query_scalar("SELECT node_identity FROM sync_seq_counter WHERE id = 1")
            .fetch_one(pool)
            .await
            .expect("identity");
    let live_identity = bound.expect("connect binds the node identity (#9176 F6)");
    let c = sqlite_node("pg-restored-c");
    let b_url = serve(&b).await;
    let cfg = fed_config(NODE_C, NODE_B, &b_url);
    for i in 0..PRE_RESTORE_ROWS {
        seed(&b, &format!("pre-{i}"), TS_EQUAL, 5).await;
    }
    assert_eq!(pass(&cfg, &c).await.applied, PRE_RESTORE_ROWS, "first walk");
    let before = epoch(&pull_seq(&b.router, 0, PAGE).await);
    // The restore: the rows after the snapshot are gone, the counter is back
    // at the snapshot head and the identity is the source instance's.
    sqlx::raw_sql(&format!(
        "DELETE FROM memories; UPDATE sync_seq_counter SET head = 0, \
         node_identity = '{FOREIGN_IDENTITY}' WHERE id = 1;"
    ))
    .execute(pool)
    .await
    .expect("simulate restore");
    let _reopened = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("reconnect the restored database");
    let (identity, head): (Option<String>, i64) =
        sqlx::query_as("SELECT node_identity, head FROM sync_seq_counter WHERE id = 1")
            .fetch_one(pool)
            .await
            .expect("counter");
    assert_eq!(
        identity.as_deref(),
        Some(live_identity.as_str()),
        "re-bound"
    );
    assert_eq!(head, 0, "the restored head is kept");
    let after = epoch(&pull_seq(&b.router, 0, PAGE).await);
    assert_ne!(
        after, before,
        "a restored database gets a new epoch (#9176 F6)"
    );
    let mut post = BTreeSet::new();
    for i in 0..POST_RESTORE_ROWS {
        let id = format!("post-{i}");
        seed(&b, &id, TS_RELAYED, 5).await;
        post.insert(id);
    }
    // Two windows, as on SQLite: the first lands the rows above the old
    // cursor and re-arms the walk at 0 under the new epoch.
    let first = pass(&cfg, &c).await;
    assert_eq!(
        first.applied,
        POST_RESTORE_ROWS - PRE_RESTORE_ROWS,
        "the first window lands the rows numbered above the old cursor"
    );
    assert_eq!(
        pull_cursor(&c, NODE_C, NODE_B).last_seq,
        Some(0),
        "an epoch mismatch re-arms the walk at 0"
    );
    let _second = pass(&cfg, &c).await;
    assert!(
        post.is_subset(&stored(&c).await),
        "every row written after the restore lands, including those numbered at or below the old cursor"
    );
    let cursor = pull_cursor(&c, NODE_C, NODE_B);
    assert_eq!(
        cursor.seq_epoch.as_deref(),
        Some(after.as_str()),
        "new epoch adopted"
    );
    // A plain reconnect of the same instance keeps the epoch.
    let _again = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("reconnect");
    assert_eq!(epoch(&pull_seq(&b.router, 0, PAGE).await), after, "stable");
    clear_posture();
}

/// S4: `limit=0` makes the same progress on both backends: a page of one row.
async fn limit_zero_parity(backend: Backend) {
    let Some(n) = node(backend, "limit-zero").await else {
        return;
    };
    seed(&n, "lz-1", TS_EQUAL, 5).await;
    seed(&n, "lz-2", TS_ABOVE, 5).await;
    let v = pull_seq(&n.router, 0, 0).await;
    assert_eq!(ids(&v), ["lz-1"], "{backend:?}: limit=0 serves one row");
    assert_eq!(next_seq(&v), 1, "{backend:?}: limit=0 advances by one");
    assert_eq!(
        v["limit"], 1,
        "{backend:?}: the echoed limit is the clamped one"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_seq_limit_zero_advances_one_row_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    limit_zero_parity(Backend::Sqlite).await;
    clear_posture();
}

/// #9176 F3: the seq clamp does not reach the since path, where `limit=0`
/// answers 0 rows on both backends (the sqlite behaviour before #9082; the
/// postgres path floored the limit at 1 in the SAL adapter and served a row).
async fn since_limit_zero_serves_nothing(backend: Backend) {
    let Some(n) = node(backend, "since-limit-zero").await else {
        return;
    };
    seed(&n, "slz-1", TS_EQUAL, 5).await;
    seed(&n, "slz-2", TS_ABOVE, 5).await;
    let (status, v) = get(&n.router, None, 0).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{backend:?}: since pull answers 200: {v}"
    );
    assert_eq!(
        ids(&v),
        Vec::<String>::new(),
        "{backend:?}: since-path limit=0 serves 0 rows"
    );
    assert_eq!(v["count"], 0, "{backend:?}: since-path count is 0");
    assert_eq!(
        v["limit"], 0,
        "{backend:?}: since-path limit is not clamped"
    );
    let (status, all) = get(&n.router, None, PAGE).await;
    assert_eq!(status, StatusCode::OK, "{backend:?}: control pull: {all}");
    assert_eq!(
        ids(&all).len(),
        2,
        "{backend:?}: control: both seeded rows are served at a real limit"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_since_limit_zero_serves_no_rows_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    since_limit_zero_serves_nothing(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_since_limit_zero_serves_no_rows_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    since_limit_zero_serves_nothing(Backend::Postgres).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_seq_limit_zero_advances_one_row_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    limit_zero_parity(Backend::Postgres).await;
    clear_posture();
}

/// S5: a row this node cannot decrypt is passed by `next_seq` and recorded in
/// the page's `undecryptable` list with its seq and id (the handler WARNs it).
async fn undecryptable_is_recorded(backend: Backend) {
    let Some(n) = node(backend, "undecryptable").await else {
        return;
    };
    for id in ["ud-1", "ud-2", "ud-3"] {
        seed(&n, id, TS_EQUAL, 5).await;
    }
    // Poison ud-2: a non-NULL envelope that opens under no key. The write
    // bumps its seq to 4.
    exec(
        &n,
        "UPDATE memories SET content = '', encrypted_envelope = randomblob(48) WHERE id = ?1",
        "UPDATE memories SET content = '', encrypted_envelope = decode(repeat('ff', 48), 'hex') \
         WHERE id = $1",
        "ud-2",
    )
    .await;
    assert_eq!(
        seq_of(&n, "ud-2").await,
        4,
        "{backend:?}: the poison write bumps"
    );
    let v = pull_seq(&n.router, 0, PAGE).await;
    assert_eq!(
        ids(&v),
        ["ud-1", "ud-3"],
        "{backend:?}: the row is not served"
    );
    assert_eq!(next_seq(&v), 4, "{backend:?}: next_seq passes it");
    let page = page_after_seq(&n, 0, PAGE).await;
    assert_eq!(
        page.undecryptable,
        vec![(4, "ud-2".to_string())],
        "{backend:?}: recorded with its seq and id"
    );
    assert_eq!(page.next_seq, 4, "{backend:?}");
}

async fn page_after_seq(
    node: &Node,
    after: i64,
    limit: usize,
) -> ai_memory::storage::sync_seq::SeqPage {
    #[cfg(feature = "sal-postgres")]
    if let Some((_, scratch)) = node.pg.as_ref() {
        use ai_memory::store::MemoryStore as _;
        let store = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
            .await
            .expect("connect");
        return store
            .list_memories_after_seq(after, limit)
            .await
            .expect("pg page");
    }
    let guard = node.db.lock().await;
    ai_memory::storage::sync_seq::memories_after_seq(&guard.0, after, limit).expect("page")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_seq_walk_records_an_undecryptable_row_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    undecryptable_is_recorded(Backend::Sqlite).await;
    clear_posture();
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_seq_walk_records_an_undecryptable_row_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    undecryptable_is_recorded(Backend::Postgres).await;
    clear_posture();
}

/// F8: the seq path records no serving-side `sync_state` row for the puller;
/// the since path on the same node does (the probe sees real writes).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seq_pull_records_no_serving_sync_state_9176() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let n = sqlite_node("no-observe");
    seed(&n, "obs-1", TS_EQUAL, 5).await;
    let rows = |n: &Node| {
        let conn = rusqlite::Connection::open(&n.db_path).expect("open");
        conn.query_row(
            "SELECT COUNT(*) FROM sync_state WHERE peer_id = ?1",
            [NODE_C],
            |r| r.get::<_, i64>(0),
        )
        .expect("count")
    };
    let _ = pull_seq(&n.router, 0, PAGE).await;
    assert_eq!(
        rows(&n),
        0,
        "the seq path records no sync_state row (#9176 F8)"
    );
    let (status, body) = get(&n.router, None, PAGE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(rows(&n), 1, "the since path records one (control)");
    clear_posture();
}

/// F2/S2 SSOT: both migrations' `memories_sync_seq_au` column lists (the
/// `UPDATE OF` list and the `WHEN` chain) are exactly `SYNC_SEQ_BUMP_COLUMNS`,
/// and any later migration that drops or renames one of those columns drops
/// the trigger first.
#[test]
fn sync_seq_trigger_columns_match_the_ssot_9176() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ssot: Vec<&str> = ai_memory::storage::sync_seq::SYNC_SEQ_BUMP_COLUMNS.to_vec();
    for rel in [
        "migrations/sqlite/0086_v102_sync_seq.sql",
        "migrations/postgres/0059_v102_sync_seq.sql",
    ] {
        let sql = std::fs::read_to_string(root.join(rel)).expect("read migration");
        let start = sql.find("AFTER UPDATE OF").expect("au trigger") + "AFTER UPDATE OF".len();
        let end = start + sql[start..].find("ON memories").expect("ON memories");
        let listed: Vec<&str> = sql[start..end].split(',').map(str::trim).collect();
        assert_eq!(listed, ssot, "{rel}: UPDATE OF list");
        let when = &sql[end..end + sql[end..].find(';').expect("trigger end")];
        let mut seen: Vec<&str> = Vec::new();
        for part in when.split("OLD.").skip(1) {
            let col = part
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .expect("column");
            if !seen.contains(&col) {
                seen.push(col);
            }
        }
        assert_eq!(seen, ssot, "{rel}: WHEN chain");
    }
    for (dir, after) in [("migrations/sqlite", 86_u32), ("migrations/postgres", 59)] {
        for entry in std::fs::read_dir(root.join(dir)).expect("read dir") {
            let path = entry.expect("entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            let Some(num) = name.split('_').next().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if num <= after {
                continue;
            }
            let sql = std::fs::read_to_string(&path)
                .expect("read")
                .to_ascii_lowercase();
            let touches = ssot.iter().any(|c| {
                sql.contains(&format!("drop column {c}"))
                    || sql.contains(&format!("drop column if exists {c}"))
                    || sql.contains(&format!("rename column {c}"))
            });
            if touches {
                assert!(
                    sql.contains("drop trigger if exists memories_sync_seq_au"),
                    "{name}: drops or renames a sync_seq column without rebuilding memories_sync_seq_au"
                );
            }
        }
    }
}
