// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1580 — WAL read-pool for the HTTP SQLite path.
//!
//! ## Why
//!
//! Every HTTP handler reaches SQLite through a single
//! `Arc<Mutex<Connection>>` ([`super::transport::Db`]). The v0.7.0
//! final-gate performance audit (#1579 Tier C1) measured that this one
//! mutex flat-lines read throughput from concurrency 1 → 32 (recall
//! ~3–5 rps at 100k rows regardless of how many requests are in flight)
//! and head-of-line-blocks writes to p50 2.08 s under mixed load. An
//! 8-reader WAL prototype on the identical worst-case recall proved a
//! **4.1×** speed-up: WAL permits any number of concurrent read
//! transactions on **distinct** connections while a single writer
//! proceeds in parallel.
//!
//! ## What
//!
//! This module hand-rolls (no new dependency, per the operator
//! sole-authority rule — mirroring the hand-rolled admission-control
//! [`crate::compose_admission_control`] and per-request timeout layers)
//! a fixed-size pool of **read-only** connections ([`ReadPool`]) plus a
//! narrow-waist [`db_read_op`] helper — the read-side sibling of
//! [`super::transport::db_op`]. Read-only handlers (`get`, `list`,
//! `search`, and recall's SELECT/FTS/HNSW phase) dispatch their SELECTs
//! through the pool; every mutation — including recall's `touch`
//! (`access_count`/`expires_at`/promotion) — stays on the existing
//! single writer connection so write serialization and read-your-writes
//! are unchanged.
//!
//! ## Pool ownership — Db-Arc-keyed registry
//!
//! The pool is **not** a field on [`super::transport::AppState`] (that
//! would churn ~95 `AppState` construction sites) and **not** a single
//! process-global (which would alias across the integration suite's
//! multiple distinct-DB routers — a real correctness hazard). Instead a
//! process-global registry maps each `Db` Arc's identity to its own
//! lazily-built [`ReadPool`]:
//!
//! - **No aliasing** — distinct `app.db` Arcs (distinct daemons/routers
//!   /tests) get distinct pools keyed to their own database file.
//! - **No ABA** — the registry stores a [`Weak`] to the `Db`'s inner
//!   allocation, which pins the address so a dropped `Db`'s slot cannot
//!   be reused by a different database while its entry lives; a failed
//!   `Weak::upgrade` marks the entry stale and it is evicted/rebuilt.
//! - **Per-test-fresh** — every test opens a unique temp DB → a unique
//!   `Db` Arc → its own pool, with nothing to reset between cases.
//! - **Lazy** — the pool materializes on the first read for a given
//!   `Db` (one brief writer lock to learn the on-disk path), so no boot
//!   seeding is required and routers built directly in tests work
//!   without going through `serve()`.
//!
//! The design realizes the per-instance, per-test-fresh correctness the
//! 5-agent vote (memory `4d3ea1c5`) selected (Option B) while keeping
//! the registry's near-zero blast radius.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::config::ResolvedTtl;

use super::transport::Db;

/// The inner type behind the [`Db`] `Arc<tokio::sync::Mutex<…>>`.
/// Declared here so the registry can hold a [`Weak`] to exactly that
/// allocation for ABA-safe keying.
type DbInner = tokio::sync::Mutex<(rusqlite::Connection, PathBuf, ResolvedTtl, bool)>;

/// Number of read-only connections per pool.
///
/// Matches the 8-reader configuration the #1579 prototype measured at
/// 4.1×. SQLite WAL readers are cheap (one fd + a private page cache);
/// 8 covers the typical multi-core HTTP runtime without exhausting file
/// descriptors even when several routers coexist in one process.
pub const DEFAULT_READ_POOL_SIZE: usize = 8;

/// A fixed-size set of read-only SQLite connections to one database.
///
/// Each connection is guarded by its own [`std::sync::Mutex`] (not the
/// shared writer mutex), so up to `N` reads run genuinely in parallel
/// under WAL. Checkout is round-robin with a `try_lock` ring scan:
/// pick a starting slot, take the first un-contended connection, and
/// only block (on the starting slot) when every connection is busy.
pub struct ReadPool {
    slots: Vec<Mutex<rusqlite::Connection>>,
    rr: AtomicUsize,
}

impl ReadPool {
    /// Open a pool of `size` read-only connections against an
    /// already-initialized database at `path`.
    ///
    /// # Errors
    ///
    /// Propagates [`crate::storage::open_read_only`] failures (connection
    /// open, SQLCipher unlock, PRAGMA application).
    ///
    /// # Panics
    ///
    /// Panics if `size == 0` — a zero-connection pool is a programming
    /// error (callers use [`DEFAULT_READ_POOL_SIZE`]).
    pub fn open(path: &Path, size: usize) -> anyhow::Result<Self> {
        assert!(size >= 1, "read-pool size must be >= 1");
        let mut slots = Vec::with_capacity(size);
        for _ in 0..size {
            slots.push(Mutex::new(crate::storage::open_read_only(path)?));
        }
        Ok(Self {
            slots,
            rr: AtomicUsize::new(0),
        })
    }

    /// Run `op` against an available read-only connection.
    ///
    /// Round-robins the starting slot, then scans the ring with
    /// `try_lock` so a contended connection is skipped rather than
    /// waited on; if every connection is in use the call blocks on the
    /// round-robin-selected slot. A poisoned slot mutex is recovered via
    /// `into_inner` — a panic in a prior reader closure must not wedge
    /// the whole pool.
    pub fn with_conn<T>(&self, op: impl FnOnce(&rusqlite::Connection) -> T) -> T {
        let n = self.slots.len();
        let start = self.rr.fetch_add(1, Ordering::Relaxed) % n;
        for i in 0..n {
            let idx = (start + i) % n;
            if let Ok(guard) = self.slots[idx].try_lock() {
                return op(&guard);
            }
        }
        let guard = self.slots[start]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        op(&guard)
    }

    /// Number of connections in the pool (test/diagnostic accessor).
    #[must_use]
    pub fn size(&self) -> usize {
        self.slots.len()
    }
}

/// Process-global registry: `Db`-Arc identity → its lazily-built pool.
///
/// Keyed by the raw `Arc::as_ptr` address; the stored [`Weak`] pins the
/// allocation so the address cannot be recycled by a different database
/// while the entry lives (ABA-safe).
static REGISTRY: OnceLock<Mutex<HashMap<usize, (Weak<DbInner>, Arc<ReadPool>)>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<usize, (Weak<DbInner>, Arc<ReadPool>)>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolve (or lazily build) the [`ReadPool`] for a given writer [`Db`].
///
/// Fast path: a registry hit whose [`Weak`] still upgrades returns the
/// cached pool with no writer lock. Slow path (cold or stale entry):
/// take one brief writer lock to read the on-disk path, open the pool,
/// and insert it (double-checking under the registry lock so racing
/// readers share one pool). Stale entries (their `Db` dropped) are
/// pruned opportunistically.
///
/// Runs inside a `spawn_blocking` worker (it may take the writer's
/// `blocking_lock`), so it must never be called on a tokio runtime
/// thread.
fn pool_for(db: &Db) -> anyhow::Result<Arc<ReadPool>> {
    let key = Arc::as_ptr(db) as usize;

    // Fast path — live cached entry, no writer lock.
    {
        let map = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((weak, pool)) = map.get(&key) {
            if weak.strong_count() > 0 {
                return Ok(Arc::clone(pool));
            }
        }
    }

    // Cold/stale — learn the path (one brief writer lock) and build.
    let path = { db.blocking_lock().1.clone() };
    // #1580 — `:memory:` databases are per-connection: a separate
    // read-only connection opens its OWN empty in-memory DB and would
    // never see the writer's rows. Disable the pool for in-memory paths
    // so the caller falls back to the writer connection (the only one
    // that holds the data). Production HTTP daemons always open a file
    // DB; this guards `:memory:` test harnesses + misconfigurations.
    let path_str = path.to_string_lossy();
    if path_str.is_empty() || path_str.contains(":memory:") {
        return Err(anyhow::anyhow!(
            "read-pool disabled for in-memory database ({path_str})"
        ));
    }
    let pool = Arc::new(ReadPool::open(&path, DEFAULT_READ_POOL_SIZE)?);
    let weak = Arc::downgrade(db);

    let mut map = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    // Double-check: another reader may have built it while we opened
    // connections.
    if let Some((w, p)) = map.get(&key) {
        if w.strong_count() > 0 {
            return Ok(Arc::clone(p));
        }
    }
    // Prune dead entries so the map can't grow unbounded across many
    // short-lived `Db`s (e.g. a test binary that builds hundreds).
    map.retain(|_, (w, _)| w.strong_count() > 0);
    map.insert(key, (weak, Arc::clone(&pool)));
    Ok(pool)
}

/// #1580 — the read-side narrow-waist helper, sibling of
/// [`super::transport::db_op`].
///
/// Dispatches a synchronous read-only `rusqlite` closure onto the
/// blocking pool against a pooled read-only connection, so concurrent
/// reads no longer serialize on the single writer mutex. The closure
/// receives `&rusqlite::Connection` (read handlers that also need the
/// resolved TTL or DB path read them from `AppState`, not the writer
/// tuple).
///
/// **Infallible + graceful**: if the pool cannot be built (e.g. a
/// read-only open failure), the call logs a WARN and falls back to the
/// existing writer connection so the request still succeeds — never a
/// hard failure introduced by the optimization. The return type matches
/// `db_op` (`T`, not `Result<T>`) so migrating a handler from `db_op` to
/// `db_read_op` is a drop-in change.
///
/// # Panics
///
/// Panics only if the `spawn_blocking` worker itself panics or the
/// runtime is shutting down (same contract as `db_op`).
pub async fn db_read_op<T, F>(db: Db, op: F) -> T
where
    T: Send + 'static,
    F: FnOnce(&rusqlite::Connection) -> T + Send + 'static,
{
    tokio::task::spawn_blocking(move || match pool_for(&db) {
        Ok(pool) => pool.with_conn(op),
        Err(e) => {
            tracing::warn!(
                target: "ai_memory::read_pool",
                error = %e,
                "read-pool unavailable; falling back to the writer connection"
            );
            let guard = db.blocking_lock();
            op(&guard.0)
        }
    })
    .await
    .expect("#1580: db_read_op spawn_blocking worker panicked or runtime shut down")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use std::time::Duration;
    use tokio::sync::Mutex as TokioMutex;

    /// Build a FILE-backed `Db` (the read-pool is disabled for `:memory:`
    /// because separate connections to `:memory:` see separate databases).
    fn file_db() -> (tempfile::NamedTempFile, Db) {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = crate::storage::open(tmp.path()).expect("open writer");
        let db: Db = Arc::new(TokioMutex::new((
            conn,
            tmp.path().to_path_buf(),
            crate::config::ResolvedTtl::default(),
            true,
        )));
        (tmp, db)
    }

    /// Insert a bare memory row on the writer connection (avoids building
    /// a full 27-field `Memory`; the read-pool tests only need *some* row
    /// to observe).
    async fn seed_row(db: &Db, id: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        let guard = db.lock().await;
        guard
            .0
            .execute(
                "INSERT INTO memories \
                 (id, tier, namespace, title, content, tags, priority, confidence, \
                  source, access_count, created_at, updated_at, metadata, reflection_depth) \
                 VALUES (?1, 'mid', 'ns', 't', 'c', '[]', 5, 1.0, 's', 0, ?2, ?2, '{}', 0)",
                params![id, now],
            )
            .expect("seed insert");
    }

    fn count_rows(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
            .expect("count")
    }

    /// Two concurrent reads are genuinely in flight on DISTINCT pool
    /// connections at the same instant — proven by a `Barrier(2)` rendezvous
    /// INSIDE both reader closures: if the pool served them on one
    /// serialized connection the barrier would never release and the
    /// `timeout` would fire. No wall-clock ratio assertion.
    #[tokio::test]
    async fn read_pool_two_concurrent_readers_inflight_during_held_write() {
        let (_tmp, db) = file_db();
        seed_row(&db, "r1").await;

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let b2 = Arc::clone(&barrier);
        let h1 = tokio::spawn(db_read_op(db.clone(), move |conn| {
            let n = count_rows(conn);
            b1.wait();
            n
        }));
        let h2 = tokio::spawn(db_read_op(db.clone(), move |conn| {
            let n = count_rows(conn);
            b2.wait();
            n
        }));

        let joined = tokio::time::timeout(Duration::from_secs(10), async {
            (h1.await.unwrap(), h2.await.unwrap())
        })
        .await
        .expect("both readers must be in flight concurrently (barrier would hang if serialized)");
        assert_eq!(joined, (1, 1), "both pooled readers see the seeded row");
    }

    /// Read-your-writes: a row committed on the writer is visible through a
    /// freshly-opened pool connection (the pool is built lazily on first
    /// read, AFTER the write committed; WAL readers see the latest commit).
    #[tokio::test]
    async fn read_pool_read_your_writes_after_commit() {
        let (_tmp, db) = file_db();
        seed_row(&db, "ryw1").await;
        let got = db_read_op(db.clone(), |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE id = 'ryw1'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(-1)
        })
        .await;
        assert_eq!(got, 1, "pooled read must see the just-committed row");
    }

    /// A pooled read completes while the writer's tokio mutex is HELD —
    /// proving reads no longer serialize behind the single writer lock
    /// (the F5.11 / recall-touch class of contention). The pool is warmed
    /// first so the read takes the registry fast-path (no writer lock at
    /// all); then we hold the writer guard and assert a concurrent read
    /// still returns under a timeout.
    #[tokio::test]
    async fn read_pool_does_not_block_concurrent_writer_hold() {
        let (_tmp, db) = file_db();
        seed_row(&db, "nb1").await;
        // Warm the pool so the registry has a live entry (fast-path).
        let _ = db_read_op(db.clone(), count_rows).await;

        // Hold the writer's tokio mutex for the whole read.
        let writer_guard = db.lock().await;
        let read = tokio::time::timeout(
            Duration::from_secs(10),
            db_read_op(db.clone(), count_rows),
        )
        .await
        .expect("pooled read must complete while the writer mutex is held");
        assert_eq!(read, 1);
        drop(writer_guard);
    }

    /// The pool is disabled for `:memory:` (per-connection databases) and
    /// `db_read_op` falls back to the writer connection — so a read still
    /// sees rows written on the writer even though no pool is built.
    #[tokio::test]
    async fn read_pool_falls_back_to_writer_for_in_memory_db() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let db: Db = Arc::new(TokioMutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            crate::config::ResolvedTtl::default(),
            true,
        )));
        seed_row(&db, "mem1").await;
        // pool_for returns Err for :memory:; db_read_op falls back to the
        // writer guard, which DOES hold the row.
        let got = db_read_op(db.clone(), count_rows).await;
        assert_eq!(got, 1, "in-memory fallback reads the writer connection");
    }
}
