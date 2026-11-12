// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9147 / #9149 / #9150 (umbrella #8741) — the receiver lifecycle state is a
//! MERGE BARRIER for every federation write funnel, on SQLite AND PostgreSQL.
//!
//! Class invariant: once a row sits at a terminal or hidden receiver state
//! (archived, quarantined, contaminated, federated-deleted), no inbound
//! funnel (`apply_remote_memory`, `merge_inbound`, `restores[]`, the
//! archive-restore verb) may make that row's content live / open again, and
//! no inbound push may change the bytes behind a hold.
//!
//! The cells are table-driven over {state} x {funnel} x {push shape} and run
//! the SAME driver against both adapters through the `MemoryStore` trait; row
//! state is read with raw SQL so no accessor's visibility folding can colour
//! the answer. Every assertion is an exact value (row counts, content bytes,
//! lifecycle string, the restore verdict), never a bare `is_err`.
//!
//! PostgreSQL cells soft-skip when `AI_MEMORY_TEST_POSTGRES_URL` is unset
//! (deliberately not `#[ignore]`: the PR postgres job never passes
//! `--include-ignored`).

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::store::{CallerContext, MemoryStore};

/// Content of the row as the receiver first applied it (what a reviewer sees).
const ORIGINAL_CONTENT: &str = "barrier-9147 original reviewed bytes";
/// Content a later (or replayed / delayed) peer push carries.
const PUSHED_CONTENT: &str = "barrier-9147 swapped bytes behind the barrier";
/// Lifecycle a released row carries.
const OPEN_STATE: &str = "open";
/// Node-local hold states under test (`NODE_LOCAL_LIFECYCLE_STATES`).
const HELD_STATES: [&str; 2] = ["quarantined", "contaminated"];
/// Seconds the "newer" push is stamped after the original.
const NEWER_OFFSET_SECS: i64 = 30;
/// Seconds the "older" push is stamped before the original.
const OLDER_OFFSET_SECS: i64 = -30;
/// Base instant every row is stamped from (well in the past, so the
/// `now + skew` clamp never rewrites a pushed `updated_at`).
const BASE_INSTANT: &str = "2026-01-01T00:00:00+00:00";

/// Which inbound funnel a cell drives.
#[derive(Debug, Clone, Copy)]
enum Funnel {
    /// `/sync/push` `memories[]` insert-if-newer lane.
    ApplyRemoteMemory,
    /// The same-id field-merge lane (`merge_inbound`).
    MergeInbound,
}

const FUNNELS: [Funnel; 2] = [Funnel::ApplyRemoteMemory, Funnel::MergeInbound];

/// Push shapes: a byte-identical replay, a newer edit, an older (delayed) one.
#[derive(Debug, Clone, Copy)]
enum Push {
    Replay,
    Newer,
    Older,
}

const PUSHES: [Push; 3] = [Push::Replay, Push::Newer, Push::Older];

/// How the receiver moved the row out of `memories` before the origin's delete.
#[derive(Debug, Clone, Copy)]
enum ArchiveSource {
    /// An archive (owner archive / `archives[]`), no tombstone.
    Archive,
    /// An operator `forget` with archive: tombstone AND archive copy.
    Forget,
}

const ARCHIVE_SOURCES: [ArchiveSource; 2] = [ArchiveSource::Archive, ArchiveSource::Forget];

/// Which restore funnel tries to bring the row back.
#[derive(Debug, Clone, Copy)]
enum Restore {
    /// The operator / owner archive-restore verb (HTTP, MCP and CLI all reach
    /// this funnel; the operator lane is owner-blind).
    ArchiveRestore,
    /// The federated `restores[]` lane.
    RemoteRestore,
}

const RESTORES: [Restore; 2] = [Restore::ArchiveRestore, Restore::RemoteRestore];

fn ts(offset_secs: i64) -> String {
    let base = chrono::DateTime::parse_from_rfc3339(BASE_INSTANT).expect("base instant parses");
    (base + chrono::Duration::seconds(offset_secs)).to_rfc3339()
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn operator_ctx() -> CallerContext {
    let mut ctx = CallerContext::for_agent("ai:test-merge-barrier-9147");
    ctx.bypass_visibility = true;
    ctx
}

fn mk_row(id: &str, namespace: &str, title: &str, content: &str, updated_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["barrier-9147".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "federation".to_string(),
        created_at: ts(0),
        updated_at: updated_at.to_string(),
        metadata: serde_json::json!({"agent_id": "ai:peer-9147"}),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

fn pushed(seed: &Memory, push: Push) -> Memory {
    match push {
        Push::Replay => seed.clone(),
        Push::Newer => {
            let mut m = seed.clone();
            m.content = PUSHED_CONTENT.to_string();
            m.updated_at = ts(NEWER_OFFSET_SECS);
            m
        }
        Push::Older => {
            let mut m = seed.clone();
            m.content = PUSHED_CONTENT.to_string();
            m.updated_at = ts(OLDER_OFFSET_SECS);
            m
        }
    }
}

/// Raw-SQL view of one adapter's tables (no accessor visibility folding).
enum RawView {
    Sqlite(std::path::PathBuf),
    #[cfg(feature = "sal-postgres")]
    Postgres(sqlx::PgPool),
}

/// Row state the invariant is asserted on.
#[derive(Debug, PartialEq, Eq)]
struct RowState {
    live: i64,
    archived: i64,
    tombstones: i64,
    /// `(content, lifecycle_state)` of the live row, when there is one.
    live_row: Option<(String, String)>,
}

// Without `sal-postgres` the only variant is sqlite (sync rusqlite), so the
// shared async signature has nothing to await in that build.
#[cfg_attr(
    not(feature = "sal-postgres"),
    allow(clippy::unused_async, clippy::unused_async_trait_impl)
)]
impl RawView {
    async fn row_state(&self, id: &str) -> RowState {
        match self {
            Self::Sqlite(path) => {
                let conn = rusqlite::Connection::open(path).expect("raw sqlite open");
                let count = |sql: &str| -> i64 {
                    conn.query_row(sql, [id], |r| r.get(0))
                        .expect("raw sqlite count")
                };
                let live_row = conn
                    .query_row(
                        "SELECT content, lifecycle_state FROM memories WHERE id = ?1",
                        [id],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                    .ok();
                RowState {
                    live: count("SELECT COUNT(*) FROM memories WHERE id = ?1"),
                    archived: count("SELECT COUNT(*) FROM archived_memories WHERE id = ?1"),
                    tombstones: count(
                        "SELECT COUNT(*) FROM forget_tombstones WHERE memory_id = ?1",
                    ),
                    live_row,
                }
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres(pool) => {
                let count = |sql: &'static str| {
                    let pool = pool.clone();
                    let id = id.to_string();
                    async move {
                        sqlx::query_scalar::<_, i64>(sql)
                            .bind(id)
                            .fetch_one(&pool)
                            .await
                            .expect("raw pg count")
                    }
                };
                let live_row: Option<(String, String)> =
                    sqlx::query_as("SELECT content, lifecycle_state FROM memories WHERE id = $1")
                        .bind(id)
                        .fetch_optional(pool)
                        .await
                        .expect("raw pg live row");
                RowState {
                    live: count("SELECT COUNT(*) FROM memories WHERE id = $1").await,
                    archived: count("SELECT COUNT(*) FROM archived_memories WHERE id = $1").await,
                    tombstones: count(
                        "SELECT COUNT(*) FROM forget_tombstones WHERE memory_id = $1",
                    )
                    .await,
                    live_row,
                }
            }
        }
    }

    /// Put the live row into a node-local hold, as the receive-side
    /// quarantine / contamination stamp does (no `updated_at` bump).
    async fn hold(&self, id: &str, state: &str) {
        match self {
            Self::Sqlite(path) => {
                let conn = rusqlite::Connection::open(path).expect("raw sqlite open");
                let changed = conn
                    .execute(
                        "UPDATE memories SET lifecycle_state = ?1 WHERE id = ?2",
                        [state, id],
                    )
                    .expect("raw sqlite hold");
                assert_eq!(changed, 1, "hold must hit exactly the seeded row");
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres(pool) => {
                let done = sqlx::query("UPDATE memories SET lifecycle_state = $1 WHERE id = $2")
                    .bind(state)
                    .bind(id)
                    .execute(pool)
                    .await
                    .expect("raw pg hold");
                assert_eq!(
                    done.rows_affected(),
                    1,
                    "hold must hit exactly the seeded row"
                );
            }
        }
    }
}

async fn push_via(store: &Arc<dyn MemoryStore>, funnel: Funnel, row: &Memory) -> String {
    let ctx = operator_ctx();
    match funnel {
        Funnel::ApplyRemoteMemory => store.apply_remote_memory(&ctx, row).await,
        Funnel::MergeInbound => store.merge_inbound(&ctx, row, false).await,
    }
    .unwrap_or_else(|e| panic!("{funnel:?} push must not error: {e}"))
}

async fn seed(store: &Arc<dyn MemoryStore>, view: &RawView, row: &Memory) {
    let applied = push_via(store, Funnel::ApplyRemoteMemory, row).await;
    assert_eq!(applied, row.id);
    let st = view.row_state(&row.id).await;
    assert_eq!(
        st.live_row,
        Some((ORIGINAL_CONTENT.to_string(), OPEN_STATE.to_string())),
        "seed must land live and open"
    );
}

/// #9149 — an archived id (no live row) is a merge barrier: no push shape on
/// any funnel re-inserts it.
async fn archive_barrier_cells(store: Arc<dyn MemoryStore>, view: RawView, backend: &str) {
    let ctx = operator_ctx();
    for funnel in FUNNELS {
        for push in PUSHES {
            let ns = uniq("barrier-9149");
            let id = uuid::Uuid::new_v4().to_string();
            let row = mk_row(&id, &ns, &uniq("t"), ORIGINAL_CONTENT, &ts(0));
            seed(&store, &view, &row).await;
            let archived = store
                .apply_remote_archive(&ctx, &id)
                .await
                .expect("archive applies");
            assert!(archived, "{backend}: archive must move the seeded row");
            let returned = push_via(&store, funnel, &pushed(&row, push)).await;
            assert_eq!(
                returned, id,
                "{backend} {funnel:?} {push:?}: no-op returns the id"
            );
            assert_eq!(
                view.row_state(&id).await,
                RowState {
                    live: 0,
                    archived: 1,
                    tombstones: 0,
                    live_row: None
                },
                "{backend} {funnel:?} {push:?}: archived id re-inserted live (#9149)"
            );
        }
    }
}

/// #9150 — a node-local hold is a merge barrier: no push shape on any funnel
/// changes the bytes behind the hold or lifts it, whether it names the held
/// row by id or claims its `(title, namespace)` slot under another id.
async fn hold_barrier_cells(store: Arc<dyn MemoryStore>, view: RawView, backend: &str) {
    for held in HELD_STATES {
        for funnel in FUNNELS {
            for push in PUSHES {
                for same_id in [true, false] {
                    let ns = uniq("barrier-9150");
                    let id = uuid::Uuid::new_v4().to_string();
                    let row = mk_row(&id, &ns, &uniq("t"), ORIGINAL_CONTENT, &ts(0));
                    seed(&store, &view, &row).await;
                    view.hold(&id, held).await;
                    let mut inbound = pushed(&row, push);
                    if !same_id {
                        inbound.id = uuid::Uuid::new_v4().to_string();
                    }
                    push_via(&store, funnel, &inbound).await;
                    let st = view.row_state(&id).await;
                    assert_eq!(
                        st.live_row,
                        Some((ORIGINAL_CONTENT.to_string(), held.to_string())),
                        "{backend} {held} {funnel:?} {push:?} same_id={same_id}: \
                         bytes behind the hold changed (#9150)"
                    );
                    if !same_id {
                        assert_eq!(
                            view.row_state(&inbound.id).await.live,
                            0,
                            "{backend} {held} {funnel:?} {push:?}: a slot-claiming push \
                             must not land beside the held row"
                        );
                    }
                }
            }
        }
    }
}

/// #9147 — an origin delete of an id the receiver had archived (or forgotten)
/// leaves nothing any restore funnel can bring back, and tombstones the id.
async fn deletion_barrier_cells(store: Arc<dyn MemoryStore>, view: RawView, backend: &str) {
    let ctx = operator_ctx();
    for source in ARCHIVE_SOURCES {
        for restore in RESTORES {
            let ns = uniq("barrier-9147");
            let id = uuid::Uuid::new_v4().to_string();
            let row = mk_row(&id, &ns, &uniq("t"), ORIGINAL_CONTENT, &ts(0));
            seed(&store, &view, &row).await;
            match source {
                ArchiveSource::Archive => {
                    let moved = store
                        .apply_remote_archive(&ctx, &id)
                        .await
                        .expect("archive applies");
                    assert!(moved, "{backend}: archive must move the seeded row");
                }
                ArchiveSource::Forget => {
                    let forgotten = store
                        .forget(&ctx, Some(&ns), None, None, true)
                        .await
                        .expect("forget applies");
                    assert_eq!(forgotten, 1, "{backend}: forget must take the seeded row");
                }
            }
            store
                .apply_remote_deletion(&ctx, &id)
                .await
                .expect("origin deletion applies");
            let restored = match restore {
                Restore::ArchiveRestore => store.archive_restore(&ctx, &id).await,
                Restore::RemoteRestore => store.apply_remote_restore(&ctx, &id).await,
            }
            .unwrap_or_else(|e| panic!("{backend} {source:?} {restore:?}: restore errored: {e}"));
            assert!(
                !restored,
                "{backend} {source:?} {restore:?}: a federated-deleted row was restored (#9147)"
            );
            assert_eq!(
                view.row_state(&id).await,
                RowState {
                    live: 0,
                    archived: 0,
                    tombstones: 1,
                    live_row: None
                },
                "{backend} {source:?} {restore:?}: deletion left a restorable copy or no tombstone"
            );
        }
    }
}

/// #9147 C5 — the barrier tags a count cell drops on, one seeded target each
/// (`ReceiverMergeBarrier::as_str` words, which are also the metric labels).
const DROP_TAGS: [&str; 4] = ["tombstoned", "archived", "quarantined", "contaminated"];
/// #9147 C5 — fresh rows each count cell pushes beside the barrier targets.
const FRESH_ROWS: usize = 3;

/// #9147 C5 — the merge-barrier drop counter is process-global; every cell
/// that pushes into a barrier holds this so a count cell's exact metric delta
/// cannot absorb a concurrent cell's drops.
static DROP_METRIC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Move a seeded live row behind the barrier named by `tag`.
async fn put_behind_barrier(store: &Arc<dyn MemoryStore>, view: &RawView, id: &str, tag: &str) {
    let ctx = operator_ctx();
    match tag {
        "tombstoned" => {
            let deleted = store
                .apply_remote_deletion(&ctx, id)
                .await
                .expect("origin deletion applies");
            assert!(deleted, "deletion must take the seeded row");
            assert_eq!(
                view.row_state(id).await.tombstones,
                1,
                "deletion tombstones"
            );
        }
        "archived" => {
            let moved = store
                .apply_remote_archive(&ctx, id)
                .await
                .expect("archive applies");
            assert!(moved, "archive must move the seeded row");
        }
        held => view.hold(id, held).await,
    }
}

/// #9147 C5 — the `/sync/push` response field that counts barrier drops.
const DROPPED_FIELD: &str = "merge_barrier_dropped";
/// The `/sync/push` response field that counts applied rows.
const APPLIED_FIELD: &str = "applied";
/// The `/sync/push` route.
const PUSH_PATH: &str = "/api/v1/sync/push";
/// A `validate_memory`-accepted source for the rows the `/sync/push` cell sends.
const PUSH_SOURCE: &str = "api";
/// The peer every push cell speaks as (also each row's `metadata.agent_id`).
const PEER: &str = "ai:peer-9147";
/// Response body cap for the router cells.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// #9147 C5 — the federation receive env one push cell runs under
/// (unsigned push accepted, body sender trusted, `PEER` scoped to one
/// namespace); restores every variable on drop. Held only under
/// [`DROP_METRIC_LOCK`], which serializes every cell in this binary that
/// reaches a receive funnel.
struct PushEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl PushEnv {
    fn new(namespace: &str) -> Self {
        use ai_memory::federation::peer_attestation::{
            PEER_ATTESTATION_ENV, TRUST_BODY_AGENT_ID_ENV,
        };
        use ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV;
        use ai_memory::federation::signing::REQUIRE_SIG_ENV;
        let keys = [
            REQUIRE_SIG_ENV,
            TRUST_BODY_AGENT_ID_ENV,
            PEER_ATTESTATION_ENV,
            REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        ];
        let saved = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        let allowlist = serde_json::json!({PEER: {
            "allowed_sender_agent_ids": [PEER],
            "allowed_namespaces": [namespace],
        }});
        // SAFETY: every caller holds DROP_METRIC_LOCK; Drop restores the
        // variables before that guard is released.
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "0");
            std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
            std::env::set_var(PEER_ATTESTATION_ENV, allowlist.to_string());
            std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        }
        Self(saved)
    }
}

impl Drop for PushEnv {
    fn drop(&mut self) {
        for (key, previous) in &self.0 {
            // SAFETY: the enclosing cell still holds DROP_METRIC_LOCK.
            unsafe {
                match previous {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// The production router over `store` (and, for sqlite, the same file as the
/// handler's `Db` connection).
fn push_router(
    store: Arc<dyn MemoryStore>,
    db_path: &std::path::Path,
    backend: ai_memory::handlers::StorageBackend,
) -> axum::Router {
    use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
    use ai_memory::handlers::{ApiKeyState, AppState, Db};
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
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
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
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
    ai_memory::build_router(api_key_state, app_state)
}

/// One unsigned `/sync/push` of `rows` from [`PEER`].
async fn sync_push(
    router: &axum::Router,
    rows: &[Memory],
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt as _;
    let body = serde_json::to_vec(&serde_json::json!({
        "sender_agent_id": PEER,
        "sender_clock": {"entries": {}},
        "memories": rows,
    }))
    .expect("push body");
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(PUSH_PATH)
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER,
        )
        .body(axum::body::Body::from(body))
        .expect("push request");
    let resp = router.clone().oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("push response body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// #9147 C5 (cF10, cF11) — the `/sync/push` tally: one batch of
/// `DROP_TAGS.len()` barrier targets and `FRESH_ROWS` fresh rows answers
/// EXACTLY `applied = FRESH_ROWS` and `merge_barrier_dropped =
/// DROP_TAGS.len()`.
async fn push_tally_cell(
    store: Arc<dyn MemoryStore>,
    view: RawView,
    router: &axum::Router,
    backend: &str,
) {
    let ns = uniq("barrier-c5-push");
    let _env = PushEnv::new(&ns);
    let mut batch = Vec::new();
    for tag in DROP_TAGS {
        let id = uuid::Uuid::new_v4().to_string();
        let row = mk_row(&id, &ns, &uniq("t"), ORIGINAL_CONTENT, &ts(0));
        seed(&store, &view, &row).await;
        put_behind_barrier(&store, &view, &id, tag).await;
        batch.push(pushed(&row, Push::Newer));
    }
    let fresh: Vec<Memory> = (0..FRESH_ROWS)
        .map(|_| {
            let id = uuid::Uuid::new_v4().to_string();
            mk_row(&id, &ns, &uniq("t"), PUSHED_CONTENT, &ts(0))
        })
        .collect();
    batch.extend(fresh.iter().cloned());
    // `validate_memory` admits only the wire source vocabulary; the
    // funnel-level seeds keep `federation`, the pushed copies speak `api`.
    for row in &mut batch {
        row.source = PUSH_SOURCE.to_string();
    }
    let (status, body) = sync_push(router, &batch).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "{backend}: push acks: {body}"
    );
    assert_eq!(
        (body[APPLIED_FIELD].as_u64(), body[DROPPED_FIELD].as_u64()),
        (
            u64::try_from(FRESH_ROWS).ok(),
            u64::try_from(DROP_TAGS.len()).ok()
        ),
        "{backend}: (applied, merge_barrier_dropped) of the push: {body}"
    );
    for row in &fresh {
        assert_eq!(
            view.row_state(&row.id).await.live,
            1,
            "{backend}: an applied fresh row is live"
        );
    }
}

fn sqlite_store() -> (tempfile::TempDir, Arc<dyn MemoryStore>, RawView) {
    let scratch = std::env::current_dir().expect("cwd").join(".local-runs");
    std::fs::create_dir_all(&scratch).expect("scratch root");
    let dir = tempfile::Builder::new()
        .prefix("merge-barrier-9147-")
        .tempdir_in(&scratch)
        .expect("scratch dir");
    let path = dir.path().join("ai-memory.db");
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore"));
    (dir, store, RawView::Sqlite(path))
}

#[tokio::test]
async fn sqlite_archive_is_a_merge_barrier_9149() {
    let _metric = DROP_METRIC_LOCK.lock().await;
    let (_dir, store, view) = sqlite_store();
    archive_barrier_cells(store, view, "sqlite").await;
}

#[tokio::test]
async fn sqlite_hold_is_a_merge_barrier_9150() {
    let _metric = DROP_METRIC_LOCK.lock().await;
    let (_dir, store, view) = sqlite_store();
    hold_barrier_cells(store, view, "sqlite").await;
}

#[tokio::test]
async fn sqlite_sync_push_counts_barrier_drops_apart_9147() {
    let _metric = DROP_METRIC_LOCK.lock().await;
    let (_dir, store, view) = sqlite_store();
    // Irrefutable without `sal-postgres` (sqlite is then the only variant).
    #[cfg_attr(not(feature = "sal-postgres"), allow(irrefutable_let_patterns))]
    let RawView::Sqlite(path) = &view else {
        panic!("sqlite_store yields a sqlite view");
    };
    let router = push_router(
        Arc::clone(&store),
        path,
        ai_memory::handlers::StorageBackend::Sqlite,
    );
    push_tally_cell(store, view, &router, "sqlite").await;
}

#[tokio::test]
async fn sqlite_federated_deletion_is_a_restore_barrier_9147() {
    let (_dir, store, view) = sqlite_store();
    deletion_barrier_cells(store, view, "sqlite").await;
}

/// Nonces each #9140 cell records (several, so one lucky ordering cannot pass).
const NONCE_CELLS: usize = 16;
/// Distinct peers (verifying keys) the #9140 cells rotate over.
const NONCE_PEERS: usize = 3;
/// Seed of the #9140 cell nonces (#9192 item 9: deterministic, never random).
const NONCE_SEED_9140: &str = "nonce-9140";

/// Deterministic nonce `i` of `seed` (#9192 item 9).
fn test_nonce(seed: &str, i: u64) -> String {
    format!("{seed}-{i:016x}")
}

/// The claim key of cell `cell`: peer `cell % NONCE_PEERS`, its own key bytes.
fn cell_key(backend: &str, cell: usize) -> ai_memory::identity::replay::NonceClaimKey {
    let peer = cell % NONCE_PEERS;
    let key_bytes = [u8::try_from(peer).expect("peer index fits u8"); 32];
    let seed = format!("{NONCE_SEED_9140}-{backend}");
    ai_memory::identity::replay::NonceClaimKey::for_verifying_key(
        &key_bytes,
        &format!("ai:peer-9140-{peer}"),
        &test_nonce(&seed, u64::try_from(cell).expect("cell index fits u64")),
    )
    .expect("cell nonce is in bounds")
}

/// #9140 / #9192 — the federation nonce claim is a STORE-scoped replay
/// barrier: two daemons over the same sqlite file (two connections, two
/// caches) must not both accept the same `(key, nonce)`, and a third daemon
/// started later (a restart) must refuse it too. Table-driven over which
/// daemon records first.
#[test]
fn sqlite_nonce_replay_is_store_scoped_9140() {
    use ai_memory::identity::replay::{FederationNonceCache, ReplayDecision};
    let scratch = std::env::current_dir().expect("cwd").join(".local-runs");
    std::fs::create_dir_all(&scratch).expect("scratch root");
    let dir = tempfile::Builder::new()
        .prefix("nonce-9140-")
        .tempdir_in(&scratch)
        .expect("scratch dir");
    let path = dir.path().join("ai-memory.db");
    let conn_a = ai_memory::db::open(&path).expect("daemon a connection");
    let conn_b = ai_memory::db::open(&path).expect("daemon b connection");
    let (daemon_a, daemon_b) = (FederationNonceCache::new(), FederationNonceCache::new());
    for cell in 0..NONCE_CELLS {
        let key = cell_key("sqlite-conn", cell);
        let ((first, first_conn), (second, second_conn)) = if cell % 2 == 0 {
            ((&daemon_a, &conn_a), (&daemon_b, &conn_b))
        } else {
            ((&daemon_b, &conn_b), (&daemon_a, &conn_a))
        };
        assert_eq!(
            first.check_with_conn(first_conn, &key),
            ReplayDecision::Fresh,
            "cell {cell}: first sight of a nonce is fresh"
        );
        assert_eq!(
            second.check_with_conn(second_conn, &key),
            ReplayDecision::Replay,
            "cell {cell}: a second daemon on the same store accepted a captured push (#9140)"
        );
        assert_eq!(
            first.check_with_conn(first_conn, &key),
            ReplayDecision::Replay,
            "cell {cell}: the recording daemon must still see its own replay"
        );
    }
    let restarted = FederationNonceCache::new();
    let conn_c = ai_memory::db::open(&path).expect("restarted daemon connection");
    for cell in 0..NONCE_CELLS {
        assert_eq!(
            restarted.check_with_conn(&conn_c, &cell_key("sqlite-conn", cell)),
            ReplayDecision::Replay,
            "cell {cell}: a restarted daemon admitted an accepted nonce (#9192)"
        );
    }
}

/// #9140 / #9192 — the shared-claim half of the cells: two caches that claim
/// through the SAL store (two daemons over one store, each with its own
/// memory), then a fresh cache over the first store (a restart).
async fn shared_nonce_cells(store_a: &dyn MemoryStore, store_b: &dyn MemoryStore, backend: &str) {
    use ai_memory::identity::replay::{FederationNonceCache, ReplayDecision};
    let (daemon_a, daemon_b) = (FederationNonceCache::new(), FederationNonceCache::new());
    let seed = format!("{backend}-{}", uuid::Uuid::new_v4().simple());
    for cell in 0..NONCE_CELLS {
        let key = cell_key(&seed, cell);
        let ((first, first_store), (second, second_store)) = if cell % 2 == 0 {
            ((&daemon_a, store_a), (&daemon_b, store_b))
        } else {
            ((&daemon_b, store_b), (&daemon_a, store_a))
        };
        assert_eq!(
            first.check_store(first_store, &key).await,
            ReplayDecision::Fresh,
            "{backend} cell {cell}: first sight of a nonce is fresh"
        );
        assert_eq!(
            second.check_store(second_store, &key).await,
            ReplayDecision::Replay,
            "{backend} cell {cell}: a sibling daemon accepted a captured push (#9140)"
        );
        assert_eq!(
            first.check_store(first_store, &key).await,
            ReplayDecision::Replay,
            "{backend} cell {cell}: the recording daemon must still see its own replay"
        );
    }
    let restarted = FederationNonceCache::new();
    for cell in 0..NONCE_CELLS {
        assert_eq!(
            restarted.check_store(store_a, &cell_key(&seed, cell)).await,
            ReplayDecision::Replay,
            "{backend} cell {cell}: a restarted daemon admitted an accepted nonce (#9192)"
        );
    }
}

/// #9140 — the SAL claim on the sqlite adapter (two caches over one store).
#[tokio::test]
async fn sqlite_store_claimed_nonce_replay_is_store_scoped_9140() {
    let (_dir, store_a, view) = sqlite_store();
    // Irrefutable without `sal-postgres` (sqlite is then the only variant).
    #[cfg_attr(not(feature = "sal-postgres"), allow(irrefutable_let_patterns))]
    let RawView::Sqlite(path) = &view else {
        panic!("sqlite_store yields a sqlite view");
    };
    // A second adapter on the same file: a sibling daemon of the same store.
    let store_b: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(path).expect("open sibling store"));
    shared_nonce_cells(store_a.as_ref(), store_b.as_ref(), "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
async fn pg_store() -> Option<(Arc<dyn MemoryStore>, RawView)> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("raw pg pool");
    Some((Arc::new(store), RawView::Postgres(pool)))
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_archive_is_a_merge_barrier_9149() {
    let _metric = DROP_METRIC_LOCK.lock().await;
    let Some((store, view)) = pg_store().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    archive_barrier_cells(store, view, "postgres").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_hold_is_a_merge_barrier_9150() {
    let _metric = DROP_METRIC_LOCK.lock().await;
    let Some((store, view)) = pg_store().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    hold_barrier_cells(store, view, "postgres").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_sync_push_counts_barrier_drops_apart_9147() {
    let _metric = DROP_METRIC_LOCK.lock().await;
    let Some((store, view)) = pg_store().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    // The postgres receive lane never opens the handler's sqlite `Db`.
    let router = push_router(
        Arc::clone(&store),
        std::path::Path::new(":memory:"),
        ai_memory::handlers::StorageBackend::Postgres,
    );
    push_tally_cell(store, view, &router, "postgres").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_federated_deletion_is_a_restore_barrier_9147() {
    let Some((store, view)) = pg_store().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    deletion_barrier_cells(store, view, "postgres").await;
}

/// #9140 — two PostgreSQL daemons over one database (two connections, two
/// caches) must not both accept the same `(peer, nonce)`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_nonce_replay_is_store_scoped_9140() {
    let Some((store_a, _view_a)) = pg_store().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let Some((store_b, _view_b)) = pg_store().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    shared_nonce_cells(store_a.as_ref(), store_b.as_ref(), "postgres").await;
}
