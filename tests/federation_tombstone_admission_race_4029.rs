// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4029 (SEC, data-integrity / erasure) — a federation ADMISSION must never
//! resurrect an id that a CONCURRENT erasure tombstoned.
//!
//! ## The defect this pins closed
//!
//! The G30 resurrection guard (#1821 / #2314) probed `forget_tombstones`
//! OUTSIDE the transaction that then inserted the inbound row (sqlite: its own
//! autocommit statement; postgres: the pool). A forget / hard delete that
//! committed on ANOTHER connection between that negative probe and the insert
//! left BOTH a live row and its tombstone — erased content was back.
//!
//! ## How the interleaving is forced
//!
//! The `test-support` admission seam (`storage::admission_hook`) blocks the
//! admission right after its NEGATIVE tombstone probe. While it is parked an
//! erasure runs on an INDEPENDENT connection (sqlite: a second `Connection`
//! on the same file — never two tasks sharing one mutex; postgres: the pool),
//! then the admission is released. Final state is read on a third
//! connection: the live row must be ABSENT and the tombstone PRESENT.
//!
//! Pre-fix the parked admission held no lock, the erasure committed at once,
//! and the resumed insert re-created the row (RED). Post-fix the admission
//! holds the write lock / admission advisory lock across probe + insert, so
//! the erasure waits, then erases the admitted row (GREEN).
//!
//! The postgres twins are `#[ignore]` + `sal-postgres` and read
//! `AI_MEMORY_TEST_POSTGRES_URL`.

#![allow(clippy::too_many_lines)]

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage::admission_hook::test_seam;

/// Every test in this binary installs the ONE process-wide admission hook and
/// may flip the process-wide append-only flag: serialize them. An async-aware
/// mutex (the postgres cells hold it across `.await`, CONCURRENCY-20); the
/// synchronous sqlite cells take it with `blocking_lock`.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// How long a parked admission waits for its release before giving up (a
/// hung test must fail, never hang CI).
const PARK_LIMIT: Duration = Duration::from_secs(20);
/// How long the test gives the erasure to finish while the admission is
/// parked. Pre-fix it finishes at once; post-fix it is BLOCKED (the lock is
/// held), so this simply elapses.
const ERASURE_WINDOW: Duration = Duration::from_millis(700);

fn memory(id: &str, ns: &str, title: &str, updated_at: &str, content: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: "2026-09-01T00:00:00Z".to_string(),
        updated_at: updated_at.to_string(),
        metadata: serde_json::json!({"agent_id": "ai:race-4029"}),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// A parking hook for exactly `id`: announces the park on `parked`, then
/// waits for `release`.
struct Park {
    parked: Receiver<()>,
    release: Sender<()>,
}

fn install_park(id: &str) -> Park {
    let (parked_tx, parked_rx) = channel::<()>();
    let (release_tx, release_rx) = channel::<()>();
    let target = id.to_string();
    let parked_tx = Mutex::new(parked_tx);
    let release_rx = Mutex::new(release_rx);
    test_seam::set(Arc::new(move |admitted: &str| {
        if admitted != target {
            return;
        }
        let _ = parked_tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(());
        let _ = release_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv_timeout(PARK_LIMIT);
    }));
    Park {
        parked: parked_rx,
        release: release_tx,
    }
}

// ---------------------------------------------------------------- sqlite --

mod sqlite {
    use super::*;
    use ai_memory::db;
    use rusqlite::Connection;
    use std::path::{Path, PathBuf};

    #[derive(Clone, Copy, Debug)]
    pub(super) enum Admission {
        InsertIfNewer,
        MergeInbound,
    }

    #[derive(Clone, Copy, Debug)]
    pub(super) enum Erasure {
        HardDelete,
        Forget,
    }

    fn scratch() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("fit-4029-")
            .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
            .expect("tempdir under .local-runs");
        let path = dir.path().join("race.db");
        drop(db::open(&path).expect("create + migrate"));
        (dir, path)
    }

    fn live_rows(path: &Path, id: &str) -> i64 {
        let c = Connection::open(path).expect("reader");
        c.query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .expect("count")
    }

    fn tombstoned(path: &Path, id: &str) -> bool {
        let c = db::open(path).expect("reader");
        db::memory_is_tombstoned(&c, id).expect("probe")
    }

    fn erase(path: &Path, id: &str, ns: &str, how: Erasure) {
        let c = db::open(path).expect("erasure connection");
        match how {
            Erasure::HardDelete => {
                assert!(db::delete(&c, id).expect("delete"), "row existed");
            }
            Erasure::Forget => {
                let n = db::forget(&c, Some(ns), None, None, false).expect("forget");
                assert_eq!(n, 1, "forget reaped the row");
            }
        }
    }

    pub(super) fn race(admission: Admission, erasure: Erasure, append_only: bool) {
        let _serial = SERIAL.blocking_lock();
        ai_memory::config::set_append_only(append_only);
        let (_dir, path) = scratch();
        let id = format!("race-4029-{}", uuid::Uuid::new_v4());
        let ns = format!("fit4029/{admission:?}-{erasure:?}-{append_only}").to_lowercase();
        let title = "the erased memory";

        // A live local row the erasure will target.
        {
            let c = db::open(&path).expect("seed");
            db::insert_if_newer(
                &c,
                &memory(&id, &ns, title, "2026-09-01T00:00:00Z", "local text"),
            )
            .expect("seed row");
        }
        assert_eq!(live_rows(&path, &id), 1);

        // A stale peer still holds the row (newer clock, so it would win LWW).
        let park = install_park(&id);
        let push_path = path.clone();
        let push_id = id.clone();
        let push_ns = ns.clone();
        let admission_thread = std::thread::spawn(move || {
            let c = db::open(&push_path).expect("admission connection");
            let inbound = memory(
                &push_id,
                &push_ns,
                title,
                "2026-09-02T00:00:00Z",
                "a stale peer's copy of the erased text",
            );
            match admission {
                Admission::InsertIfNewer => db::insert_if_newer(&c, &inbound).map(|_| ()),
                Admission::MergeInbound => db::merge_inbound(&c, &inbound, false).map(|_| ()),
            }
        });

        park.parked
            .recv_timeout(PARK_LIMIT)
            .expect("the admission reached its tombstone probe");

        // The erasure, on an INDEPENDENT connection, while the admission is
        // parked after its negative probe.
        let (done_tx, done_rx) = channel::<()>();
        let erase_path = path.clone();
        let erase_id = id.clone();
        let erase_ns = ns.clone();
        let erasure_thread = std::thread::spawn(move || {
            erase(&erase_path, &erase_id, &erase_ns, erasure);
            let _ = done_tx.send(());
        });
        let erased_while_parked = done_rx.recv_timeout(ERASURE_WINDOW).is_ok();
        let _ = park.release.send(());

        let admitted = admission_thread.join().expect("admission thread");
        erasure_thread.join().expect("erasure thread");
        test_seam::clear();
        ai_memory::config::set_append_only(false);
        admitted.expect("the admission itself succeeds (or is dropped)");

        assert!(
            tombstoned(&path, &id),
            "{admission:?}/{erasure:?}/append_only={append_only}: the erasure's tombstone must remain"
        );
        assert_eq!(
            live_rows(&path, &id),
            0,
            "#4029 {admission:?}/{erasure:?}/append_only={append_only}: a federation admission \
             racing an erasure resurrected the erased row (erasure committed while the \
             admission was parked: {erased_while_parked})"
        );
    }

    /// The inverse order: the erasure commits FIRST, then the stale peer
    /// pushes — the probe sees the tombstone and drops the write.
    pub(super) fn inverse(admission: Admission, erasure: Erasure) {
        let _serial = SERIAL.blocking_lock();
        let (_dir, path) = scratch();
        let id = format!("race-4029-inv-{}", uuid::Uuid::new_v4());
        let ns = format!("fit4029/inv-{admission:?}-{erasure:?}").to_lowercase();
        {
            let c = db::open(&path).expect("seed");
            db::insert_if_newer(&c, &memory(&id, &ns, "t", "2026-09-01T00:00:00Z", "x"))
                .expect("seed");
        }
        erase(&path, &id, &ns, erasure);
        let c = db::open(&path).expect("push connection");
        let inbound = memory(&id, &ns, "t", "2026-09-02T00:00:00Z", "stale copy");
        match admission {
            Admission::InsertIfNewer => {
                db::insert_if_newer(&c, &inbound).expect("dropped, not failed");
            }
            Admission::MergeInbound => {
                db::merge_inbound(&c, &inbound, false).expect("dropped, not failed");
            }
        }
        assert!(tombstoned(&path, &id));
        assert_eq!(live_rows(&path, &id), 0, "tombstone-wins");
    }
}

#[test]
fn sqlite_insert_if_newer_vs_hard_delete_4029() {
    sqlite::race(
        sqlite::Admission::InsertIfNewer,
        sqlite::Erasure::HardDelete,
        false,
    );
}

#[test]
fn sqlite_insert_if_newer_vs_forget_4029() {
    sqlite::race(
        sqlite::Admission::InsertIfNewer,
        sqlite::Erasure::Forget,
        false,
    );
}

#[test]
fn sqlite_merge_inbound_vs_hard_delete_4029() {
    sqlite::race(
        sqlite::Admission::MergeInbound,
        sqlite::Erasure::HardDelete,
        false,
    );
}

#[test]
fn sqlite_merge_inbound_vs_forget_4029() {
    sqlite::race(
        sqlite::Admission::MergeInbound,
        sqlite::Erasure::Forget,
        false,
    );
}

#[test]
fn sqlite_race_with_append_only_on_4029() {
    sqlite::race(
        sqlite::Admission::InsertIfNewer,
        sqlite::Erasure::HardDelete,
        true,
    );
    sqlite::race(
        sqlite::Admission::MergeInbound,
        sqlite::Erasure::Forget,
        true,
    );
}

#[test]
fn sqlite_inverse_order_tombstone_wins_4029() {
    for admission in [
        sqlite::Admission::InsertIfNewer,
        sqlite::Admission::MergeInbound,
    ] {
        for erasure in [sqlite::Erasure::HardDelete, sqlite::Erasure::Forget] {
            sqlite::inverse(admission, erasure);
        }
    }
}

/// The federated `restores[]` apply. A live row and an ARCHIVED snapshot of
/// the same id coexist after a same-id federation merge (the #1773
/// `federation_merge` snapshot). A forget then deletes the live row and
/// tombstones the id — and a restore that decided "not tombstoned" BEFORE the
/// forget committed must not bring the snapshot back after it.
#[test]
fn sqlite_federated_restore_vs_forget_4029() {
    use ai_memory::db;
    let _serial = SERIAL.blocking_lock();
    let dir = tempfile::Builder::new()
        .prefix("fit-4029-restore-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("tempdir");
    let path = dir.path().join("restore.db");
    drop(db::open(&path).expect("create + migrate"));
    let id = format!("race-4029-restore-{}", uuid::Uuid::new_v4());
    let ns = "fit4029/restore";
    {
        let c = db::open(&path).expect("seed");
        db::insert_if_newer(&c, &memory(&id, ns, "r", "2026-09-01T00:00:00Z", "v1")).expect("seed");
        // Same-id merge: archives the pre-merge row, keeps the live one.
        db::merge_inbound(
            &c,
            &memory(&id, ns, "r", "2026-09-02T00:00:00Z", "v2"),
            false,
        )
        .expect("merge");
        let archived: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
                [&id],
                |r| r.get(0),
            )
            .expect("archived count");
        assert_eq!(archived, 1, "the federation_merge snapshot exists");
    }
    let park = install_park(&id);
    let restore_path = path.clone();
    let restore_id = id.clone();
    let restore = std::thread::spawn(move || {
        let c = db::open(&restore_path).expect("restore connection");
        db::restore_archived_unless_tombstoned(&c, &restore_id)
    });
    park.parked
        .recv_timeout(PARK_LIMIT)
        .expect("restore parked");
    let (done_tx, done_rx) = channel::<()>();
    let forget_path = path.clone();
    let forgetter = std::thread::spawn(move || {
        let c = db::open(&forget_path).expect("forget connection");
        let n = db::forget(&c, Some(ns), None, None, false).expect("forget");
        let _ = done_tx.send(());
        n
    });
    let forgot_while_parked = done_rx.recv_timeout(ERASURE_WINDOW).is_ok();
    let _ = park.release.send(());
    // Post-fix the restore still sees the live row (collision) or the
    // tombstone; either is a refusal. Pre-fix it restores the snapshot.
    let restored = restore.join().expect("restore thread");
    assert_eq!(
        forgetter.join().expect("forget thread"),
        1,
        "forget reaped the live row"
    );
    test_seam::clear();
    let c = db::open(&path).expect("reader");
    let live: i64 = c
        .query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [&id], |r| {
            r.get(0)
        })
        .expect("count");
    assert!(
        db::memory_is_tombstoned(&c, &id).expect("probe"),
        "tombstone remains"
    );
    assert_eq!(
        live, 0,
        "#4029: a federated restore racing a forget resurrected the erased row \
         (restore result {restored:?}; forget committed while parked: {forgot_while_parked})"
    );
}

// -------------------------------------------------------------- postgres --

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    pub(super) fn url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    #[derive(Clone, Copy, Debug)]
    pub(super) enum Admission {
        ApplyRemote,
        MergeInbound,
    }

    #[derive(Clone, Copy, Debug)]
    pub(super) enum Erasure {
        HardDelete,
        Forget,
    }

    fn admin() -> CallerContext {
        let mut ctx = CallerContext::for_agent("ai:race-4029");
        ctx.bypass_visibility = true;
        ctx
    }

    async fn live_rows(store: &PostgresStore, id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .expect("count")
    }

    async fn tombstoned(store: &PostgresStore, id: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM forget_tombstones WHERE memory_id = $1)")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .expect("probe")
    }

    pub(super) async fn race(admission: Admission, erasure: Erasure) {
        let Some(url) = url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let _serial = SERIAL.lock().await;
        let store = Arc::new(PostgresStore::connect(&url).await.expect("connect"));
        let ctx = admin();
        let id = uuid::Uuid::new_v4().to_string();
        let ns = format!("fit4029-pg/{admission:?}-{erasure:?}-{}", &id[..8]).to_lowercase();
        store
            .apply_remote_memory(
                &ctx,
                &memory(
                    &id,
                    &ns,
                    "the erased memory",
                    "2026-09-01T00:00:00Z",
                    "local",
                ),
            )
            .await
            .expect("seed");
        assert_eq!(live_rows(&store, &id).await, 1);

        let park = install_park(&id);
        let push_store = Arc::clone(&store);
        let push_ctx = ctx.clone();
        let inbound = memory(
            &id,
            &ns,
            "the erased memory",
            "2026-09-02T00:00:00Z",
            "a stale peer's copy of the erased text",
        );
        let admission_task = tokio::spawn(async move {
            match admission {
                Admission::ApplyRemote => push_store.apply_remote_memory(&push_ctx, &inbound).await,
                Admission::MergeInbound => {
                    push_store.merge_inbound(&push_ctx, &inbound, false).await
                }
            }
        });
        // The hook parks a runtime worker thread (it blocks by design); wait
        // for it from a blocking thread so the async workers stay free.
        let parked = tokio::task::spawn_blocking(move || {
            let ok = park.parked.recv_timeout(PARK_LIMIT).is_ok();
            (ok, park.release)
        });
        let (ok, release) = parked.await.expect("join park waiter");
        assert!(ok, "the admission reached its tombstone probe");

        let erase_store = Arc::clone(&store);
        let erase_ctx = ctx.clone();
        let erase_id = id.clone();
        let erase_ns = ns.clone();
        let erasure_task = tokio::spawn(async move {
            match erasure {
                Erasure::HardDelete => erase_store.delete(&erase_ctx, &erase_id).await,
                Erasure::Forget => erase_store
                    .forget(&erase_ctx, Some(&erase_ns), None, None, false)
                    .await
                    .map(|_| ()),
            }
        });
        tokio::time::sleep(ERASURE_WINDOW).await;
        let erased_while_parked = erasure_task.is_finished();
        let _ = release.send(());

        // A genuine same-id race may resolve as a postgres deadlock (40P01)
        // that aborts ONE side whole — fail closed. Either outcome is fine;
        // what is asserted is the final state.
        let admitted = admission_task.await.expect("admission task");
        let erased = erasure_task.await.expect("erasure task");
        test_seam::clear();
        if let Err(e) = &erased {
            // The erasure lost a deadlock: re-run it (the production funnels
            // retry through tx_retry; a retry here keeps the assertion about
            // the admission, not about scheduling).
            eprintln!("erasure aborted ({e}); re-running");
            match erasure {
                Erasure::HardDelete => store.delete(&ctx, &id).await.expect("re-delete"),
                Erasure::Forget => {
                    store
                        .forget(&ctx, Some(&ns), None, None, false)
                        .await
                        .expect("re-forget");
                }
            }
        }
        eprintln!("admission result: {admitted:?}");

        assert!(
            tombstoned(&store, &id).await,
            "{admission:?}/{erasure:?}: the tombstone must remain"
        );
        assert_eq!(
            live_rows(&store, &id).await,
            0,
            "#4029 pg {admission:?}/{erasure:?}: a federation admission racing an erasure \
             resurrected the erased row (erasure finished while parked: {erased_while_parked})"
        );
    }
}

/// Postgres twin of `sqlite_federated_restore_vs_forget_4029`: a live row
/// and an archived copy of the same id coexist; a federated restore parked
/// after its negative probe must not resurrect the row a concurrent forget
/// erased.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_federated_restore_vs_forget_4029() {
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};
    let Some(url) = pg::url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let _serial = SERIAL.lock().await;
    let store = Arc::new(PostgresStore::connect(&url).await.expect("connect"));
    let mut ctx = CallerContext::for_agent("ai:race-4029");
    ctx.bypass_visibility = true;
    let id = uuid::Uuid::new_v4().to_string();
    let ns = format!("fit4029-pg/restore-{}", &id[..8]);
    store
        .apply_remote_memory(&ctx, &memory(&id, &ns, "r", "2026-09-01T00:00:00Z", "v1"))
        .await
        .expect("seed");
    assert_eq!(
        store
            .archive_by_ids(&ctx, std::slice::from_ref(&id), Some("test"))
            .await
            .expect("archive"),
        1
    );
    store
        .apply_remote_memory(&ctx, &memory(&id, &ns, "r", "2026-09-02T00:00:00Z", "v2"))
        .await
        .expect("live again beside its archived copy");

    let park = install_park(&id);
    let restore_store = Arc::clone(&store);
    let restore_ctx = ctx.clone();
    let restore_id = id.clone();
    let restore_task = tokio::spawn(async move {
        restore_store
            .apply_remote_restore(&restore_ctx, &restore_id)
            .await
    });
    let parked = tokio::task::spawn_blocking(move || {
        let ok = park.parked.recv_timeout(PARK_LIMIT).is_ok();
        (ok, park.release)
    });
    let (ok, release) = parked.await.expect("join park waiter");
    assert!(ok, "the restore reached its tombstone probe");
    let forget_store = Arc::clone(&store);
    let forget_ctx = ctx.clone();
    let forget_ns = ns.clone();
    let forget_task = tokio::spawn(async move {
        forget_store
            .forget(&forget_ctx, Some(&forget_ns), None, None, false)
            .await
    });
    tokio::time::sleep(ERASURE_WINDOW).await;
    let forgot_while_parked = forget_task.is_finished();
    let _ = release.send(());
    let restored = restore_task.await.expect("restore task");
    let forgot = forget_task.await.expect("forget task");
    test_seam::clear();
    if forgot.is_err() {
        store
            .forget(&ctx, Some(&ns), None, None, false)
            .await
            .expect("re-forget");
    }
    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE id = $1")
        .bind(&id)
        .fetch_one(store.pool())
        .await
        .expect("count");
    let tomb: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM forget_tombstones WHERE memory_id = $1)")
            .bind(&id)
            .fetch_one(store.pool())
            .await
            .expect("probe");
    assert!(tomb, "the tombstone remains");
    assert_eq!(
        live, 0,
        "#4029 pg: a federated restore racing a forget resurrected the erased row \
         (restore {restored:?}; forget finished while parked: {forgot_while_parked})"
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_apply_remote_memory_vs_hard_delete_4029() {
    pg::race(pg::Admission::ApplyRemote, pg::Erasure::HardDelete).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_apply_remote_memory_vs_forget_4029() {
    pg::race(pg::Admission::ApplyRemote, pg::Erasure::Forget).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_merge_inbound_vs_hard_delete_4029() {
    pg::race(pg::Admission::MergeInbound, pg::Erasure::HardDelete).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
async fn pg_merge_inbound_vs_forget_4029() {
    pg::race(pg::Admission::MergeInbound, pg::Erasure::Forget).await;
}
