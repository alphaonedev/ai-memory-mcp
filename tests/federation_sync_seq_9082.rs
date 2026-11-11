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
    // A copy that was not published by a restore keeps the epoch.
    {
        let copied = ai_memory::db::open(&target).expect("open copy");
        let head = ai_memory::storage::sync_seq::seq_head(&copied).expect("head");
        assert_eq!(head.epoch, before, "an unarmed open never resets the epoch");
    }
    // `restore` arms the reset before it publishes; the next open consumes it.
    ai_memory::storage::sync_seq::arm_epoch_reset(&target).expect("arm");
    let marker = ai_memory::storage::sync_seq::epoch_reset_marker_path(&target);
    assert!(marker.exists(), "the sidecar is armed");
    let fresh = {
        let restored = ai_memory::db::open(&target).expect("open restored");
        let head = ai_memory::storage::sync_seq::seq_head(&restored).expect("head");
        assert_ne!(head.epoch, before, "a restored database gets a new epoch");
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

/// The counter lock can deadlock against a writer that takes another lock
/// first. Postgres detects it and aborts exactly one side with SQLSTATE
/// 40P01 (the code the `tx_retry` funnel retries); the other commits, and the
/// counter matches the committed rows. Never a hang.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_counter_deadlock_aborts_one_side_with_40p01_9082() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let Some(n) = postgres_node("deadlock").await else {
        clear_posture();
        return;
    };
    seed(&n, "dl-a", TS_EQUAL, 5).await;
    seed(&n, "dl-b", TS_EQUAL, 5).await;
    let (pool, _) = n.pg.as_ref().expect("pg");
    let mut one = pool.begin().await.expect("tx one");
    let mut two = pool.begin().await.expect("tx two");
    // one: changes dl-a (takes the counter lock).
    sqlx::query("UPDATE memories SET title = 'one' WHERE id = 'dl-a'")
        .execute(&mut *one)
        .await
        .expect("one changes dl-a");
    // two: locks dl-b without a replicated change (no counter yet).
    sqlx::query("SELECT 1 FROM memories WHERE id = 'dl-b' FOR UPDATE")
        .execute(&mut *two)
        .await
        .expect("two locks dl-b");
    let two_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *two)
        .await
        .expect("pid");
    let two_task = tokio::spawn(async move {
        // two: now needs the counter (held by one).
        let r = sqlx::query("UPDATE memories SET title = 'two' WHERE id = 'dl-a'")
            .execute(&mut *two)
            .await;
        (r.map(|_| ()), two)
    });
    wait_until_lock_waiting(pool, two_pid).await;
    // one: needs dl-b (held by two) -> the cycle.
    let one_result = sqlx::query("UPDATE memories SET title = 'one-b' WHERE id = 'dl-b'")
        .execute(&mut *one)
        .await
        .map(|_| ());
    let (two_result, two) = two_task.await.expect("join two");
    let code = |r: &Result<(), sqlx::Error>| -> Option<String> {
        match r {
            Err(sqlx::Error::Database(db)) => db.code().map(|c| c.to_string()),
            _ => None,
        }
    };
    let codes = [code(&one_result), code(&two_result)];
    assert_eq!(
        codes
            .iter()
            .filter(|c| c.as_deref() == Some("40P01"))
            .count(),
        1,
        "exactly one side is the deadlock victim with SQLSTATE 40P01: {codes:?}"
    );
    if one_result.is_ok() {
        one.commit().await.expect("commit one");
        drop(two);
    } else {
        drop(one);
        // two holds the counter now; its update of dl-a went through.
        two.commit().await.expect("commit two");
    }
    let head: i64 = sqlx::query_scalar("SELECT head FROM sync_seq_counter WHERE id = 1")
        .fetch_one(pool)
        .await
        .expect("head");
    let max: i64 = sqlx::query_scalar("SELECT MAX(sync_seq) FROM memories")
        .fetch_one(pool)
        .await
        .expect("max");
    assert_eq!(
        head, max,
        "the counter matches the committed rows after the abort"
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
