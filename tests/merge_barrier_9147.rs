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
    let (_dir, store, view) = sqlite_store();
    archive_barrier_cells(store, view, "sqlite").await;
}

#[tokio::test]
async fn sqlite_hold_is_a_merge_barrier_9150() {
    let (_dir, store, view) = sqlite_store();
    hold_barrier_cells(store, view, "sqlite").await;
}

#[tokio::test]
async fn sqlite_federated_deletion_is_a_restore_barrier_9147() {
    let (_dir, store, view) = sqlite_store();
    deletion_barrier_cells(store, view, "sqlite").await;
}

/// Nonces each #9140 cell records (several, so one lucky ordering cannot pass).
const NONCE_CELLS: usize = 16;

/// #9140 — the federation nonce cache is a STORE-scoped replay barrier: two
/// daemons over the same store (two `FederationNonceCache` instances on one
/// sqlite path, each with its own in-memory map) must not both accept the
/// same `(peer, nonce)`. Table-driven over which instance records first.
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
    let daemon_a = FederationNonceCache::new_with_db_persistence(&path).expect("daemon a cache");
    let daemon_b = FederationNonceCache::new_with_db_persistence(&path).expect("daemon b cache");
    for cell in 0..NONCE_CELLS {
        let peer = format!("ai:peer-9140-{}", cell % 3);
        let nonce = uuid::Uuid::new_v4().to_string();
        let (first, second) = if cell % 2 == 0 {
            (&daemon_a, &daemon_b)
        } else {
            (&daemon_b, &daemon_a)
        };
        assert_eq!(
            first.record_and_check(&peer, &nonce),
            ReplayDecision::Fresh,
            "cell {cell}: first sight of a nonce is fresh"
        );
        assert_eq!(
            second.record_and_check(&peer, &nonce),
            ReplayDecision::Replay,
            "cell {cell}: a second daemon on the same store accepted a captured push (#9140)"
        );
        assert_eq!(
            first.record_and_check(&peer, &nonce),
            ReplayDecision::Replay,
            "cell {cell}: the recording daemon must still see its own replay"
        );
    }
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
    let Some((store, view)) = pg_store().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    archive_barrier_cells(store, view, "postgres").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_hold_is_a_merge_barrier_9150() {
    let Some((store, view)) = pg_store().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    hold_barrier_cells(store, view, "postgres").await;
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
