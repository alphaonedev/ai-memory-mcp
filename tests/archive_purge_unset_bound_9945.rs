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
