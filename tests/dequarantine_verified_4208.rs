// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4208 F2/F3 — pins for `MemoryStore::dequarantine_verified`: the trait
//! default is fail-closed, and `SqliteStore` releases a quarantine only when
//! the stored row is the attested, verified unit (content / title / namespace /
//! kind / author) — never for an unattested incoming row, never on a mismatch.

#![cfg(feature = "sal")]

use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::{CallerContext, MemoryStore, sqlite::SqliteStore};
use serde_json::json;

const ID: &str = "m-4208-unit";

fn mem(content: &str, attest: Option<&str>) -> Memory {
    mem_with_id(ID, content, attest)
}

fn mem_with_id(id: &str, content: &str, attest: Option<&str>) -> Memory {
    let mut meta = json!({"agent_id": "ai:author-4208"});
    if let Some(a) = attest {
        meta["attest_level"] = json!(a);
    }
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "ns-4208".into(),
        title: "title-4208".into(),
        content: content.into(),
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "user".into(),
        access_count: 0,
        created_at: "2026-06-16T00:00:00+00:00".into(),
        updated_at: "2026-06-16T00:00:00+00:00".into(),
        last_accessed_at: None,
        expires_at: None,
        metadata: meta,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
        cid: None,
        valid_from: None,
        valid_until: None,
    }
}

struct Fx {
    store: SqliteStore,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn seeded_quarantined(local_content: &str) -> Fx {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("t.db");
    let store = SqliteStore::open(&path).expect("open");
    store
        .store(
            &CallerContext::for_agent("ai:author-4208"),
            &mem(local_content, Some("agent_attested")),
        )
        .await
        .expect("seed");
    let c = rusqlite::Connection::open(&path).expect("raw");
    let n = c
        .execute(
            "UPDATE memories SET lifecycle_state='quarantined' WHERE id=?1",
            [ID],
        )
        .expect("quarantine");
    assert_eq!(n, 1);
    Fx {
        store,
        path,
        _dir: dir,
    }
}

fn state(fx: &Fx) -> String {
    rusqlite::Connection::open(&fx.path)
        .expect("raw")
        .query_row(
            "SELECT lifecycle_state FROM memories WHERE id=?1",
            [ID],
            |r| r.get(0),
        )
        .expect("state")
}

#[tokio::test]
async fn sqlite_releases_when_stored_row_is_the_attested_unit_4208() {
    let fx = seeded_quarantined("signed text").await;
    let v = mem("signed text", Some("agent_attested"));
    assert!(fx.store.dequarantine_verified(ID, &v).await.expect("call"));
    assert_eq!(state(&fx), "open");
}

#[tokio::test]
async fn sqlite_keeps_quarantine_when_stored_content_differs_4208() {
    let fx = seeded_quarantined("local never-attested text").await;
    let v = mem("signed text", Some("agent_attested"));
    assert!(!fx.store.dequarantine_verified(ID, &v).await.expect("call"));
    assert_eq!(state(&fx), "quarantined");
}

/// F3: identical stored content, but the incoming row is not attested.
#[tokio::test]
async fn sqlite_keeps_quarantine_when_incoming_not_attested_4208() {
    for attest in [None, Some("claimed"), Some("unsigned")] {
        let fx = seeded_quarantined("signed text").await;
        let v = mem("signed text", attest);
        assert!(!fx.store.dequarantine_verified(ID, &v).await.expect("call"));
        assert_eq!(state(&fx), "quarantined", "attest={attest:?}");
    }
}

#[tokio::test]
async fn sqlite_absent_or_open_row_releases_nothing_4208() {
    let fx = seeded_quarantined("signed text").await;
    let v = mem("signed text", Some("agent_attested"));
    let mut other = v.clone();
    other.id = "absent".into();
    assert!(
        !fx.store
            .dequarantine_verified("absent", &other)
            .await
            .expect("absent")
    );
    assert!(fx.store.dequarantine_verified(ID, &v).await.expect("first"));
    assert!(
        !fx.store
            .dequarantine_verified(ID, &v)
            .await
            .expect("already open")
    );
}

/// #4314 — the primitive must JOIN a caller-held transaction instead of
/// nesting its own `BEGIN IMMEDIATE`. Pre-fix the nested BEGIN errored
/// ("cannot start a transaction within a transaction"), so an attested row
/// that should be released stayed quarantined. Commit of the outer
/// transaction must land the release.
#[tokio::test]
async fn sqlite_releases_inside_caller_transaction_4314() {
    let fx = seeded_quarantined("signed text").await;
    let v = mem("signed text", Some("agent_attested"));
    let c = rusqlite::Connection::open(&fx.path).expect("raw");
    c.execute_batch("BEGIN IMMEDIATE").expect("outer begin");
    let released = ai_memory::storage::dequarantine_if_verified_unit(&c, ID, &v)
        .expect("must join the caller's transaction, not nest a BEGIN");
    assert!(
        released,
        "attested unit must be released inside the outer txn"
    );
    assert!(
        !c.is_autocommit(),
        "the caller's transaction must stay open"
    );
    c.execute_batch("COMMIT").expect("outer commit");
    assert_eq!(state(&fx), "open");
}

/// #4314 — joining means the CALLER decides: an outer ROLLBACK undoes the
/// release (it was not committed on its own), so the row stays quarantined.
#[tokio::test]
async fn sqlite_outer_rollback_undoes_joined_release_4314() {
    let fx = seeded_quarantined("signed text").await;
    let v = mem("signed text", Some("agent_attested"));
    let c = rusqlite::Connection::open(&fx.path).expect("raw");
    c.execute_batch("BEGIN IMMEDIATE").expect("outer begin");
    let released = ai_memory::storage::dequarantine_if_verified_unit(&c, ID, &v)
        .expect("must join the caller's transaction, not nest a BEGIN");
    assert!(released);
    c.execute_batch("ROLLBACK").expect("outer rollback");
    assert_eq!(state(&fx), "quarantined");
}

/// #4314 — a mismatch inside a caller transaction releases nothing and
/// leaves the caller's transaction open and usable.
#[tokio::test]
async fn sqlite_mismatch_inside_caller_transaction_keeps_quarantine_4314() {
    let fx = seeded_quarantined("local never-attested text").await;
    let v = mem("signed text", Some("agent_attested"));
    let c = rusqlite::Connection::open(&fx.path).expect("raw");
    c.execute_batch("BEGIN IMMEDIATE").expect("outer begin");
    let released = ai_memory::storage::dequarantine_if_verified_unit(&c, ID, &v)
        .expect("must join the caller's transaction, not nest a BEGIN");
    assert!(!released);
    assert!(
        !c.is_autocommit(),
        "the caller's transaction must stay open"
    );
    c.execute_batch("COMMIT").expect("outer commit");
    assert_eq!(state(&fx), "quarantined");
}

thread_local! {
    /// The concurrent writer the busy handler drives (same thread as the call
    /// under test, so a plain `Connection` is fine).
    static CONCURRENT_WRITER: std::cell::RefCell<Option<rusqlite::Connection>> =
        const { std::cell::RefCell::new(None) };
}
static HANDLER_FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Busy handler for the connection under test: the first time it is asked to
/// wait, the concurrent writer swaps the stored content and commits, releasing
/// the write lock, then asks for a retry.
fn swap_content_then_retry(_attempt: i32) -> bool {
    if HANDLER_FIRED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return false;
    }
    CONCURRENT_WRITER.with(|w| {
        let w = w.borrow();
        let Some(b) = w.as_ref() else { return false };
        b.execute(
            "UPDATE memories SET content='swapped by concurrent writer' WHERE id=?1",
            [ID],
        )
        .is_ok()
            && b.execute_batch("COMMIT").is_ok()
    })
}

/// #6162 F7 — the check and the release are ONE write transaction on
/// SQLite: a second connection holding the write lock makes the call wait
/// BEFORE it reads, and it then sees the content that writer committed.
///
/// Connection B holds `BEGIN IMMEDIATE`. The connection under test (A) is
/// asked to release a row whose stored content matches the verified unit.
/// A's busy handler lets B swap the stored content and commit, then retries.
/// With the transaction (BEGIN IMMEDIATE first) A's read happens after the
/// swap, the content no longer matches, and the row stays quarantined. With
/// no transaction (mutant T3) A reads the matching content first, only the
/// UPDATE waits on the lock, and the release lands on content that was
/// swapped under it (time-of-check to time-of-use). Deterministic: the swap
/// is driven from inside the busy handler, no timing involved.
#[tokio::test]
async fn sqlite_release_is_one_write_transaction_two_connections_6162() {
    HANDLER_FIRED.store(false, std::sync::atomic::Ordering::SeqCst);
    let fx = seeded_quarantined("signed text").await;
    let v = mem("signed text", Some("agent_attested"));

    let b = rusqlite::Connection::open(&fx.path).expect("writer b");
    b.execute_batch("BEGIN IMMEDIATE")
        .expect("b holds the write lock");
    CONCURRENT_WRITER.with(|w| *w.borrow_mut() = Some(b));

    let a = rusqlite::Connection::open(&fx.path).expect("connection under test");
    a.busy_handler(Some(swap_content_then_retry))
        .expect("busy handler");
    let released = ai_memory::storage::dequarantine_if_verified_unit(&a, ID, &v);
    CONCURRENT_WRITER.with(|w| *w.borrow_mut() = None);

    assert!(
        HANDLER_FIRED.load(std::sync::atomic::Ordering::SeqCst),
        "the call never waited on the held write lock; the interleaving did not happen"
    );
    assert!(
        !released.expect("call must complete after the retry"),
        "release must not land on content swapped by a concurrent writer"
    );
    assert_eq!(state(&fx), "quarantined");
}

/// #6162 round 3: the store upserts on `(title, namespace)`, so two cells that
/// share a fixture title and namespace merge into one row when they run in
/// parallel against one database. Every fixture identity must therefore be
/// unique per id (per cell).
#[test]
fn fixture_identity_is_unique_per_cell_6162() {
    let a = mem_with_id("m-4208-cell-a", "signed text", Some("agent_attested"));
    let b = mem_with_id("m-4208-cell-b", "signed text", Some("agent_attested"));
    assert_ne!(a.title, b.title, "cells must not share a title slot");
    assert_ne!(a.namespace, b.namespace, "cells must not share a namespace");
}

#[cfg(feature = "sal-postgres")]
mod pg {
    //! #6162 F6 — direct Postgres release-path cells for the unattested,
    //! absent-row and already-open cases (the SQLite twins are above). Each
    //! uses a fresh id and removes its row. Live-Postgres tier: run with
    //! `AI_MEMORY_TEST_POSTGRES_URL` set and `--ignored`.
    use super::{ID, mem_with_id};
    use ai_memory::store::{CallerContext, MemoryStore, postgres::PostgresStore};

    async fn connect() -> PostgresStore {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .expect("own PG URL required (AI_MEMORY_TEST_POSTGRES_URL); no soft skip");
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres")
    }

    fn fresh_id(tag: &str) -> String {
        format!("{ID}-pg-{tag}-{}", uuid::Uuid::new_v4())
    }

    /// Store an attested row and force it into `quarantined`.
    async fn seed(store: &PostgresStore, id: &str, quarantine: bool) {
        store
            .store(
                &CallerContext::for_agent("ai:author-4208"),
                &mem_with_id(id, "signed text", Some("agent_attested")),
            )
            .await
            .expect("seed");
        if quarantine {
            let n = sqlx::query("UPDATE memories SET lifecycle_state='quarantined' WHERE id=$1")
                .bind(id)
                .execute(store.pool())
                .await
                .expect("quarantine")
                .rows_affected();
            assert_eq!(n, 1);
        }
    }

    async fn state_and_version(store: &PostgresStore, id: &str) -> (String, i64) {
        let row: (String, i64) =
            sqlx::query_as("SELECT lifecycle_state, version FROM memories WHERE id=$1")
                .bind(id)
                .fetch_one(store.pool())
                .await
                .expect("row");
        row
    }

    async fn cleanup(store: &PostgresStore, id: &str) {
        let _ = sqlx::query("DELETE FROM memories WHERE id=$1")
            .bind(id)
            .execute(store.pool())
            .await;
    }

    /// Positive control: the verified unit is released (and the version bumps).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_releases_when_stored_row_is_the_attested_unit_6162() {
        let store = connect().await;
        let id = fresh_id("ok");
        seed(&store, &id, true).await;
        let (_, v0) = state_and_version(&store, &id).await;
        let v = mem_with_id(&id, "signed text", Some("agent_attested"));
        assert!(store.dequarantine_verified(&id, &v).await.expect("call"));
        let (st, v1) = state_and_version(&store, &id).await;
        cleanup(&store, &id).await;
        assert_eq!(st, "open");
        assert_eq!(v1, v0 + 1);
    }

    /// Mutant pairing: drop `persisted_is_verified_unit` in the pg release path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_keeps_quarantine_when_incoming_not_attested_6162() {
        let store = connect().await;
        for attest in [None, Some("claimed"), Some("unsigned")] {
            let id = fresh_id("unattested");
            seed(&store, &id, true).await;
            let v = mem_with_id(&id, "signed text", attest);
            let released = store.dequarantine_verified(&id, &v).await.expect("call");
            let (st, _) = state_and_version(&store, &id).await;
            cleanup(&store, &id).await;
            assert!(!released, "attest={attest:?}");
            assert_eq!(st, "quarantined", "attest={attest:?}");
        }
    }

    /// Mutant pairing: the absent-row arm returns `Ok(true)`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_absent_row_releases_nothing_6162() {
        let store = connect().await;
        let id = fresh_id("absent");
        let v = mem_with_id(&id, "signed text", Some("agent_attested"));
        assert!(!store.dequarantine_verified(&id, &v).await.expect("call"));
    }

    /// Mutant pairing: drop the `lifecycle_state != Quarantined` early return
    /// AND the `AND lifecycle_state = $3` UPDATE guard (the two are a double
    /// defense; removing only one is behaviourally equivalent, which is why
    /// the cell also pins the untouched version).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_already_open_row_releases_nothing_and_is_untouched_6162() {
        let store = connect().await;
        let id = fresh_id("open");
        seed(&store, &id, false).await;
        let (_, v0) = state_and_version(&store, &id).await;
        let v = mem_with_id(&id, "signed text", Some("agent_attested"));
        let released = store.dequarantine_verified(&id, &v).await.expect("call");
        let (st, v1) = state_and_version(&store, &id).await;
        cleanup(&store, &id).await;
        assert!(!released);
        assert_eq!(st, "open");
        assert_eq!(v1, v0, "an already-open row must not be rewritten");
    }

    /// #6162 round 3: four cells seed concurrently against one database. Each
    /// seed must land its own row (no merge into a shared `(title, namespace)`
    /// slot), which is what makes the cells above parallel-safe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_concurrent_fixtures_do_not_collide_6162() {
        let store = connect().await;
        let ids: Vec<String> = ["a", "b", "c", "d"].iter().map(|t| fresh_id(t)).collect();
        tokio::join!(
            seed(&store, &ids[0], false),
            seed(&store, &ids[1], false),
            seed(&store, &ids[2], false),
            seed(&store, &ids[3], false),
        );
        let landed: i64 = sqlx::query_scalar("SELECT count(*) FROM memories WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_one(store.pool())
            .await
            .expect("count");
        for id in &ids {
            cleanup(&store, id).await;
        }
        assert_eq!(
            landed,
            i64::try_from(ids.len()).expect("len"),
            "every concurrent seed must land its own row"
        );
    }
}
