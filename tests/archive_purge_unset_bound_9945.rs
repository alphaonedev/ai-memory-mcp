// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9945 (GA standard 1, no data destruction) — an unset, zero or negative
//! archive retention bound deletes NOTHING, on both backends.
//!
//! ## The defect these tests pin closed
//!
//! The `PostgreSQL` maintenance loop called
//! `store.archive_purge(&admin, archive_max_days)` every tick. With
//! `archive_max_days` unset that is `archive_purge(&admin, None)`, and the
//! adapter ran an unpredicated `DELETE FROM archived_memories`: every
//! archived row was destroyed on every GC tick of a daemon whose operator
//! never asked for a retention bound. A bound of `0` reached the same
//! delete-everything predicate (`archived_at < now`).
//!
//! ## What is asserted (one cell per backend)
//!
//! For each degenerate bound (unset, zero, negative, past the cap) a fresh
//! store is seeded with rows archived 10 days ago and one archived now. The
//! bound resolves the way the maintenance loop resolves it
//! (`RetentionDays::from_config`), the retention entry point
//! (`retention_purge`) runs with it, and the test asserts the exact purged
//! count (zero) and that every seeded id is still archived. A bounded case
//! (5 days) asserts that exactly the two 10-day-old ids are deleted and the
//! fresh one is kept; the explicit `archive_purge_all` deletes every row. The
//! `PostgreSQL` cell runs on its own scratch database (`common/pg_barrier.rs`),
//! because the admin purge is store-wide.
//!
//! ## One maintenance tick (#10009)
//!
//! Each maintenance loop body is one tick (`daemon_runtime::pg_maintenance_tick`,
//! `daemon_runtime::sqlite_gc_tick`), and the tick cells drive it directly over
//! four archived rows: two archived 36 hours ago, one 12 hours ago and one now.
//! A tick with no bound purges nothing; a tick with a 1-day bound purges
//! exactly the two 36-hour rows and keeps the other two. A tick that calls the
//! purge-all primitive, or a bound off by one day either way, turns them red.
#![cfg(feature = "sal")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};
use ai_memory::validate::{RetentionDays, RetentionDaysError};

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// Owner of every seeded row.
const OWNER: &str = "ai:archive-purge-9945";
/// The daemon principal the maintenance loop purges as.
const ADMIN: &str = "ai:daemon-9945";
/// Namespace of every seeded row.
const NAMESPACE: &str = "archive-purge-9945";
/// Age, in days, of the rows a 5-day bound must delete.
const OLD_AGE_DAYS: i64 = 10;
/// The explicit positive bound of the bounded case.
const BOUND_DAYS: i64 = 5;
/// Rows archived `OLD_AGE_DAYS` ago per case.
const OLD_ROWS: usize = 2;
/// One day past the retention cap (`MAX_DURATION_DAYS` = 36500).
const OVER_CAP_DAYS: i64 = 36_501;
/// The degenerate bounds: unset, zero, negative, past the cap. None of them
/// is a bound.
const UNBOUNDED: [Option<i64>; 4] = [None, Some(0), Some(-1), Some(OVER_CAP_DAYS)];
/// Age, in hours, of the tick rows a 1-day bound must delete.
const TICK_OLD_HOURS: i32 = 36;
/// Age, in hours, of the tick row inside the 1-day bound.
const TICK_NEAR_HOURS: i32 = 12;
/// The tick's bound, in days: between `TICK_NEAR_HOURS` and `TICK_OLD_HOURS`.
const TICK_BOUND_DAYS: i64 = 1;
/// Tick rows archived `TICK_OLD_HOURS` ago.
const TICK_OLD_ROWS: usize = 2;
/// Every tick row: the old ones, the near one and the fresh one.
const TICK_ALL_ROWS: usize = TICK_OLD_ROWS + 2;
/// Lock wait of the probe connection, in seconds.
const PROBE_BUSY_SECS: u64 = 10;
/// Scratch database prefix of the `PostgreSQL` cell.
#[cfg(feature = "sal-postgres")]
const SCRATCH_PREFIX: &str = "ai_memory_t9945_";

/// Seeded ids: `old` archived `OLD_AGE_DAYS` ago, `fresh` archived now.
struct Seeded {
    old: Vec<String>,
    fresh: String,
}

impl Seeded {
    fn all(&self) -> Vec<String> {
        let mut ids = self.old.clone();
        ids.push(self.fresh.clone());
        ids
    }
}

fn memory(label: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NAMESPACE.to_string(),
        title: format!("archive-9945-{label}"),
        content: format!("archived body {label}"),
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": OWNER }),
        ..Memory::default()
    }
}

/// Store `OLD_ROWS + 1` memories and archive them all.
async fn seed(store: &dyn MemoryStore) -> Seeded {
    let owner = CallerContext::for_agent(OWNER);
    let admin = CallerContext::for_admin(ADMIN);
    let mut ids = Vec::with_capacity(OLD_ROWS + 1);
    for n in 0..=OLD_ROWS {
        let id = store
            .store(&owner, &memory(&n.to_string()))
            .await
            .expect("seed memory");
        ids.push(id);
    }
    let moved = store
        .archive_by_ids(&admin, &ids, Some("test-9945"))
        .await
        .expect("archive seeded rows");
    assert_eq!(moved, OLD_ROWS + 1, "every seeded row is archived");
    let fresh = ids.pop().expect("one fresh row");
    Seeded { old: ids, fresh }
}

/// A plain second connection to the store's file. `db::open` replays the
/// schema bootstrap and migration ladder beside the store's live
/// connection; the probe needs only reads and one `UPDATE`.
fn raw_sqlite(path: &std::path::Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("open sqlite");
    conn.busy_timeout(std::time::Duration::from_secs(PROBE_BUSY_SECS))
        .expect("busy timeout");
    conn
}

/// `archived_at` back-dating and probing, per backend.
enum Probe<'a> {
    Sqlite(&'a std::path::Path),
    #[cfg(feature = "sal-postgres")]
    Pg(&'a sqlx::PgPool),
}

impl Probe<'_> {
    // The Pg arm is the only `.await`; a `sal`-only build has just the
    // sqlite arm.
    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn backdate(&self, id: &str, days: i64) {
        match self {
            Self::Sqlite(path) => {
                let at = (chrono::Utc::now() - chrono::TimeDelta::days(days)).to_rfc3339();
                let conn = raw_sqlite(path);
                let n = conn
                    .execute(
                        "UPDATE archived_memories SET archived_at = ?1 WHERE id = ?2",
                        rusqlite::params![at, id],
                    )
                    .expect("backdate sqlite");
                assert_eq!(n, 1, "backdate {id}");
            }
            #[cfg(feature = "sal-postgres")]
            Self::Pg(pool) => {
                let res = sqlx::query(
                    "UPDATE archived_memories \
                     SET archived_at = now() - make_interval(days => $2::int) WHERE id = $1",
                )
                .bind(id)
                .bind(i32::try_from(days).expect("small test age"))
                .execute(*pool)
                .await
                .expect("backdate pg");
                assert_eq!(res.rows_affected(), 1, "backdate {id}");
            }
        }
    }

    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn backdate_hours(&self, id: &str, hours: i32) {
        match self {
            Self::Sqlite(path) => {
                let at =
                    (chrono::Utc::now() - chrono::TimeDelta::hours(i64::from(hours))).to_rfc3339();
                let conn = raw_sqlite(path);
                let n = conn
                    .execute(
                        "UPDATE archived_memories SET archived_at = ?1 WHERE id = ?2",
                        rusqlite::params![at, id],
                    )
                    .expect("backdate sqlite");
                assert_eq!(n, 1, "backdate {id}");
            }
            #[cfg(feature = "sal-postgres")]
            Self::Pg(pool) => {
                let res = sqlx::query(
                    "UPDATE archived_memories \
                     SET archived_at = now() - make_interval(hours => $2::int) WHERE id = $1",
                )
                .bind(id)
                .bind(hours)
                .execute(*pool)
                .await
                .expect("backdate pg");
                assert_eq!(res.rows_affected(), 1, "backdate {id}");
            }
        }
    }

    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn count(&self) -> i64 {
        match self {
            Self::Sqlite(path) => raw_sqlite(path)
                .query_row("SELECT count(*) FROM archived_memories", [], |r| r.get(0))
                .expect("count sqlite"),
            #[cfg(feature = "sal-postgres")]
            Self::Pg(pool) => sqlx::query_scalar("SELECT count(*) FROM archived_memories")
                .fetch_one(*pool)
                .await
                .expect("count pg"),
        }
    }

    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn archived(&self, id: &str) -> bool {
        match self {
            Self::Sqlite(path) => {
                let conn = raw_sqlite(path);
                conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM archived_memories WHERE id = ?1)",
                    rusqlite::params![id],
                    |r| r.get(0),
                )
                .expect("probe sqlite")
            }
            #[cfg(feature = "sal-postgres")]
            Self::Pg(pool) => {
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM archived_memories WHERE id = $1)")
                    .bind(id)
                    .fetch_one(*pool)
                    .await
                    .expect("probe pg")
            }
        }
    }
}

async fn seed_and_age(store: &dyn MemoryStore, probe: &Probe<'_>) -> Seeded {
    let seeded = seed(store).await;
    for id in &seeded.old {
        probe.backdate(id, OLD_AGE_DAYS).await;
    }
    seeded
}

/// Tick rows: `old` archived `TICK_OLD_HOURS` ago, `near` archived
/// `TICK_NEAR_HOURS` ago, `fresh` archived now.
struct TickSeeded {
    old: Vec<String>,
    near: String,
    fresh: String,
}

/// Store and archive `TICK_ALL_ROWS` memories, then age them.
async fn seed_tick(store: &dyn MemoryStore, probe: &Probe<'_>) -> TickSeeded {
    let owner = CallerContext::for_agent(OWNER);
    let mut ids = Vec::with_capacity(TICK_ALL_ROWS);
    for n in 0..TICK_ALL_ROWS {
        let id = store
            .store(&owner, &memory(&format!("tick-{n}")))
            .await
            .expect("seed memory");
        ids.push(id);
    }
    let moved = store
        .archive_by_ids(&CallerContext::for_admin(ADMIN), &ids, Some("test-10009"))
        .await
        .expect("archive seeded rows");
    assert_eq!(moved, TICK_ALL_ROWS, "every tick row is archived");
    let fresh = ids.pop().expect("fresh row");
    let near = ids.pop().expect("near row");
    probe.backdate_hours(&near, TICK_NEAR_HOURS).await;
    for id in &ids {
        probe.backdate_hours(id, TICK_OLD_HOURS).await;
    }
    TickSeeded {
        old: ids,
        near,
        fresh,
    }
}

/// After a tick with no bound: the count is unchanged and every row is kept.
async fn assert_tick_kept_every_row(backend: &str, probe: &Probe<'_>, seeded: &TickSeeded) {
    assert_eq!(
        probe.count().await,
        i64::try_from(TICK_ALL_ROWS).expect("small count"),
        "{backend}: a tick with no bound changed the archive count"
    );
    for id in seeded.old.iter().chain([&seeded.near, &seeded.fresh]) {
        assert!(
            probe.archived(id).await,
            "{backend}: a tick with no bound deleted archived row {id}"
        );
    }
}

/// After a tick with the 1-day bound: exactly the old rows are gone.
async fn assert_tick_purged_exactly_old(backend: &str, probe: &Probe<'_>, seeded: &TickSeeded) {
    assert_eq!(
        probe.count().await,
        i64::try_from(TICK_ALL_ROWS - TICK_OLD_ROWS).expect("small count"),
        "{backend}: a 1-day tick purge count"
    );
    for id in &seeded.old {
        assert!(
            !probe.archived(id).await,
            "{backend}: a 1-day tick kept the {TICK_OLD_HOURS}h row {id}"
        );
    }
    for id in [&seeded.near, &seeded.fresh] {
        assert!(
            probe.archived(id).await,
            "{backend}: a 1-day tick deleted the row {id} inside the bound"
        );
    }
}

/// The degenerate-bound cell: the retention purge reports exactly zero and
/// every id survives, for the daemon principal and for an agent.
async fn assert_unbounded_deletes_nothing(
    backend: &str,
    store: &dyn MemoryStore,
    probe: &Probe<'_>,
    bound: Option<i64>,
) {
    let seeded = seed_and_age(store, probe).await;
    let retention = RetentionDays::from_config(bound);
    assert_eq!(retention, None, "{backend}: {bound:?} is not a bound");
    for ctx in [
        CallerContext::for_admin(ADMIN),
        CallerContext::for_agent(OWNER),
    ] {
        let purged = store
            .retention_purge(&ctx, retention)
            .await
            .expect("an absent bound is not an error");
        assert_eq!(purged, 0, "{backend}: bound {bound:?} purged {purged} rows");
        for id in seeded.all() {
            assert!(
                probe.archived(&id).await,
                "{backend}: bound {bound:?} deleted archived row {id}"
            );
        }
    }
}

/// The bounded cell: exactly the rows older than the bound are deleted.
async fn assert_bounded_deletes_exactly_old(
    backend: &str,
    store: &dyn MemoryStore,
    probe: &Probe<'_>,
) {
    let seeded = seed_and_age(store, probe).await;
    let days = RetentionDays::new(BOUND_DAYS).expect("5 is a bound");
    let purged = store
        .retention_purge(&CallerContext::for_admin(ADMIN), Some(days))
        .await
        .expect("bounded purge");
    assert_eq!(purged, OLD_ROWS, "{backend}: bounded purge count");
    for id in &seeded.old {
        assert!(!probe.archived(id).await, "{backend}: old row {id} kept");
    }
    assert!(
        probe.archived(&seeded.fresh).await,
        "{backend}: fresh row {} deleted",
        seeded.fresh
    );
}

/// The explicit, named purge-all deletes every archived row, fresh or old.
async fn assert_purge_all_deletes_every_row(
    backend: &str,
    store: &dyn MemoryStore,
    probe: &Probe<'_>,
) {
    let seeded = seed_and_age(store, probe).await;
    let purged = store
        .archive_purge_all(&CallerContext::for_admin(ADMIN))
        .await
        .expect("explicit purge-all");
    assert_eq!(purged, OLD_ROWS + 1, "{backend}: purge-all count");
    for id in seeded.all() {
        assert!(!probe.archived(&id).await, "{backend}: purge-all kept {id}");
    }
}

/// Every degenerate bound is refused by the validated constructor with its
/// exact reason, so no caller can build a `RetentionDays` from it.
#[test]
fn degenerate_bound_has_no_constructor_9945() {
    let table: [(i64, RetentionDaysError, &str); 4] = [
        (
            0,
            RetentionDaysError::NotPositive(0),
            "older_than_days must be at least 1 day (got 0)",
        ),
        (
            -1,
            RetentionDaysError::NotPositive(-1),
            "older_than_days must be at least 1 day (got -1)",
        ),
        (
            i64::MIN,
            RetentionDaysError::NotPositive(i64::MIN),
            "older_than_days must be at least 1 day (got -9223372036854775808)",
        ),
        (
            OVER_CAP_DAYS,
            RetentionDaysError::TooLarge(OVER_CAP_DAYS),
            "older_than_days must not exceed 36500 days (got 36501)",
        ),
    ];
    for (days, variant, text) in table {
        let err = RetentionDays::new(days).expect_err("degenerate bound refused");
        assert_eq!(err, variant, "{days}");
        assert_eq!(err.to_string(), text, "{days}");
    }
}

fn scratch_dir() -> tempfile::TempDir {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

#[tokio::test]
async fn sqlite_unset_zero_negative_bound_deletes_nothing_9945() {
    key_dir_sandbox::pin();
    for bound in UNBOUNDED {
        let dir = scratch_dir();
        let path = dir.path().join("archive-9945.db");
        let store = SqliteStore::open(&path).expect("open sqlite store");
        assert_unbounded_deletes_nothing("sqlite", &store, &Probe::Sqlite(&path), bound).await;
    }
}

#[tokio::test]
async fn sqlite_bounded_purge_deletes_exactly_older_rows_9945() {
    key_dir_sandbox::pin();
    let dir = scratch_dir();
    let path = dir.path().join("archive-9945.db");
    let store = SqliteStore::open(&path).expect("open sqlite store");
    assert_bounded_deletes_exactly_old("sqlite", &store, &Probe::Sqlite(&path)).await;
}

/// The `SQLite` maintenance loop's purge (`auto_purge_archive`) with every
/// degenerate bound deletes nothing.
#[tokio::test]
async fn sqlite_maintenance_purge_unset_bound_deletes_nothing_9945() {
    key_dir_sandbox::pin();
    for bound in UNBOUNDED {
        let dir = scratch_dir();
        let path = dir.path().join("archive-9945.db");
        let store = SqliteStore::open(&path).expect("open sqlite store");
        let probe = Probe::Sqlite(&path);
        let seeded = seed_and_age(&store, &probe).await;
        let conn = raw_sqlite(&path);
        let retention = RetentionDays::from_config(bound);
        let purged = ai_memory::db::auto_purge_archive(&conn, retention).expect("auto purge");
        assert_eq!(purged, 0, "sqlite maintenance: bound {bound:?}");
        for id in seeded.all() {
            assert!(probe.archived(&id).await, "sqlite maintenance deleted {id}");
        }
    }
}

#[tokio::test]
async fn sqlite_explicit_purge_all_deletes_every_row_9945() {
    key_dir_sandbox::pin();
    let dir = scratch_dir();
    let path = dir.path().join("archive-9945.db");
    let store = SqliteStore::open(&path).expect("open sqlite store");
    assert_purge_all_deletes_every_row("sqlite", &store, &Probe::Sqlite(&path)).await;
}

/// #10009 sibling: one `SQLite` gc tick (fold, gc, archive purge) with no
/// bound purges nothing, and with a 1-day bound purges exactly the older rows.
#[tokio::test]
async fn sqlite_gc_tick_none_keeps_all_and_one_day_purges_exactly_older_10009() {
    key_dir_sandbox::pin();
    let dir = scratch_dir();
    let path = dir.path().join("archive-10009.db");
    let store = SqliteStore::open(&path).expect("open sqlite store");
    let probe = Probe::Sqlite(&path);
    let seeded = seed_tick(&store, &probe).await;
    let conn = raw_sqlite(&path);
    let ttl = ai_memory::config::ResolvedTtl::default();
    ai_memory::daemon_runtime::sqlite_gc_tick(&conn, &ttl, false, None);
    assert_tick_kept_every_row("sqlite", &probe, &seeded).await;
    let bound = RetentionDays::new(TICK_BOUND_DAYS).expect("1 is a bound");
    ai_memory::daemon_runtime::sqlite_gc_tick(&conn, &ttl, false, Some(bound));
    assert_tick_purged_exactly_old("sqlite", &probe, &seeded).await;
}

#[cfg(feature = "sal-postgres")]
async fn pg_store() -> Option<(
    pg_barrier::ScratchDb,
    ai_memory::store::postgres::PostgresStore,
)> {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
        .await
        .expect("create scratch database");
    let store = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("connect scratch database");
    Some((scratch, store))
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_unset_zero_negative_bound_deletes_nothing_9945() {
    key_dir_sandbox::pin();
    for bound in UNBOUNDED {
        let Some((_scratch, store)) = pg_store().await else {
            return;
        };
        assert_unbounded_deletes_nothing("postgres", &store, &Probe::Pg(store.pool()), bound).await;
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_bounded_purge_deletes_exactly_older_rows_9945() {
    key_dir_sandbox::pin();
    let Some((_scratch, store)) = pg_store().await else {
        return;
    };
    assert_bounded_deletes_exactly_old("postgres", &store, &Probe::Pg(store.pool())).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_explicit_purge_all_deletes_every_row_9945() {
    key_dir_sandbox::pin();
    let Some((_scratch, store)) = pg_store().await else {
        return;
    };
    assert_purge_all_deletes_every_row("postgres", &store, &Probe::Pg(store.pool())).await;
}

/// The `AppState` the `PostgreSQL` maintenance tick runs against: the pg
/// store, the postgres backend tag and a scratch sqlite audit `db`.
#[cfg(feature = "sal-postgres")]
fn pg_app_state(
    db_path: &std::path::Path,
    store: std::sync::Arc<dyn MemoryStore>,
) -> ai_memory::handlers::AppState {
    use std::sync::Arc;
    let conn = ai_memory::db::open(db_path).expect("open scratch sqlite");
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    ai_memory::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Postgres,
        store,
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
    }
}

/// #10009: one pass of the `PostgreSQL` maintenance loop
/// (`pg_maintenance_tick`) with no bound purges 0 rows, and with a 1-day
/// bound purges exactly the rows older than one day and no other.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_maintenance_tick_none_keeps_all_and_one_day_purges_exactly_older_10009() {
    key_dir_sandbox::pin();
    let Some((_scratch, store)) = pg_store().await else {
        return;
    };
    let pool = store.pool().clone();
    let probe = Probe::Pg(&pool);
    let seeded = seed_tick(&store, &probe).await;
    let dir = scratch_dir();
    let app = pg_app_state(
        &dir.path().join("audit-10009.db"),
        std::sync::Arc::new(store),
    );
    let admin = CallerContext::for_admin(ADMIN);
    ai_memory::daemon_runtime::pg_maintenance_tick(&app, &admin, false, None).await;
    assert_tick_kept_every_row("postgres", &probe, &seeded).await;
    let bound = RetentionDays::new(TICK_BOUND_DAYS).expect("1 is a bound");
    ai_memory::daemon_runtime::pg_maintenance_tick(&app, &admin, false, Some(bound)).await;
    assert_tick_purged_exactly_old("postgres", &probe, &seeded).await;
}
