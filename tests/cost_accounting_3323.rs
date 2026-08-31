// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3323 — end-to-end coverage for per-lineage + per-namespace
//! token/cost accounting against a fully-bootstrapped SQLite database.
//!
//! The module-level unit tests in `src/cost/mod.rs` cover the counter
//! table + cost model in isolation; this file drives the REAL write
//! funnel (`db::insert` -> `insert_inner` hook), the lineage-DAG rollup
//! (which walks `memory_links`), and counter accuracy under concurrent
//! writers. The SQLite<->Postgres parity assertion is gated on
//! `AI_MEMORY_TEST_POSTGRES_URL` and skips cleanly when unset.

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::path::Path;

use ai_memory::cost::{self, DEFAULT_ROLLUP_DEPTH};
use ai_memory::db;
use ai_memory::models::{Memory, MemoryLinkRelation, Tier};

fn mem(id: &str, ns: &str, content: &str) -> Memory {
    Memory {
        id: id.to_string(),
        namespace: ns.to_string(),
        title: id.to_string(),
        content: content.to_string(),
        tier: Tier::Long,
        created_at: "2026-02-01T00:00:00+00:00".to_string(),
        ..Memory::default()
    }
}

fn tokens_of(m: &Memory) -> i64 {
    i64::try_from(ai_memory::storage::count_memory_tokens(m)).unwrap_or(i64::MAX)
}

#[test]
fn write_funnel_meters_namespace_and_lineage_node() {
    let conn = db::open(Path::new(":memory:")).expect("open");
    let m = mem(
        "m1",
        "team/a",
        "a reasonably sized memory content body for tokenizing",
    );
    let want = tokens_of(&m);
    db::insert(&conn, &m).expect("insert");

    // Namespace counter reflects the authored tokens.
    let ns = cost::namespace_rollup(&conn, "team/a")
        .expect("ns rollup")
        .expect("namespace metered");
    assert_eq!(ns.tokens_written, want);
    assert_eq!(ns.write_events, 1);
    assert!(
        ns.micro_usd() > 0,
        "a nonzero write must carry a nonzero cost"
    );

    // The lineage rollup of the self-rooted node equals its own tokens.
    let lin = cost::lineage_rollup(&conn, "m1", DEFAULT_ROLLUP_DEPTH).expect("lineage rollup");
    assert_eq!(lin.tokens_written, want);
    assert_eq!(lin.scope_key, "m1");
}

#[test]
fn lineage_root_rollup_sums_the_whole_cascade() {
    let conn = db::open(Path::new(":memory:")).expect("open");
    // One root, three atoms split from it (each derives_from the root).
    let root = mem(
        "root",
        "team/a",
        "the large original parent memory that got split",
    );
    db::insert(&conn, &root).expect("insert root");
    let mut want = tokens_of(&root);
    for i in 0..3 {
        let atom = mem(
            &format!("atom-{i}"),
            "team/a",
            "a derived atom of some length here",
        );
        want += tokens_of(&atom);
        db::insert(&conn, &atom).expect("insert atom");
        // Edge: atom (source, newer) --derives_from--> root (target, older).
        db::create_link(
            &conn,
            &format!("atom-{i}"),
            "root",
            MemoryLinkRelation::DerivesFrom.as_str(),
        )
        .expect("derives_from edge");
    }

    // The per-lineage-ROOT figure is the summed spend of the root + its
    // three descendants — the "$50k cascade" as one number.
    let rollup = cost::lineage_rollup(&conn, "root", DEFAULT_ROLLUP_DEPTH).expect("rollup");
    assert_eq!(
        rollup.tokens_written, want,
        "root rollup must sum root + all atoms"
    );
    assert_eq!(rollup.write_events, 4);
    assert!(rollup.micro_usd() > 0);

    // A single atom in isolation only carries its own tokens.
    let one = cost::lineage_rollup(&conn, "atom-0", DEFAULT_ROLLUP_DEPTH).expect("rollup");
    assert!(one.tokens_written < rollup.tokens_written);
}

#[test]
fn namespace_rollups_rank_by_spend() {
    let conn = db::open(Path::new(":memory:")).expect("open");
    db::insert(&conn, &mem("s", "cheap", "tiny")).expect("insert");
    for i in 0..25 {
        db::insert(
            &conn,
            &mem(
                &format!("b{i}"),
                "spendy",
                "a much longer body of content that costs more tokens each",
            ),
        )
        .expect("insert");
    }
    let rollups = cost::all_namespace_rollups(&conn).expect("all ns rollups");
    assert_eq!(rollups.len(), 2);
    assert_eq!(
        rollups[0].scope_key, "spendy",
        "most-expensive namespace first"
    );
    assert!(rollups[0].tokens_written > rollups[1].tokens_written);
}

#[test]
fn recall_metering_aggregates_and_accrues() {
    let conn = db::open(Path::new(":memory:")).expect("open");
    let a = mem("a", "team/a", "alpha recalled content");
    let b = mem("b", "team/a", "bravo recalled content longer");
    let want = tokens_of(&a) + tokens_of(&b);
    // Drive the recall meter directly (the SAL recall funnels call exactly
    // this on their writable connection).
    cost::record_recall_sqlite(&conn, &[(a, 0.9), (b, 0.8)]);

    let ns = cost::namespace_rollup(&conn, "team/a")
        .expect("ns rollup")
        .expect("metered");
    assert_eq!(ns.recall_events, 2);
    assert_eq!(ns.tokens_recalled, want);
    assert_eq!(
        ns.tokens_written, 0,
        "recall must not inflate the write counter"
    );
}

/// Counters must stay EXACT under concurrent writers. SQLite serializes
/// writers, and each write's counter upsert rides the same connection's
/// autocommit tx as the insert, so N concurrent inserts of the same memory
/// yield a counter of exactly N — never a lost update.
#[test]
fn counters_are_exact_under_concurrent_writes() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 50;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cost_concurrency.db");
    // Bootstrap once so every worker opens an already-migrated file.
    {
        let conn = db::open(&path).expect("bootstrap");
        drop(conn);
    }

    let sample = mem(
        "shared",
        "team/hot",
        "a shared memory re-stored under contention",
    );
    let per_write = tokens_of(&sample);

    std::thread::scope(|s| {
        for t in 0..THREADS {
            let path = path.clone();
            s.spawn(move || {
                let conn = db::open(&path).expect("worker open");
                for i in 0..PER_THREAD {
                    // Distinct ids so every insert is a genuine new row (a
                    // (title,namespace) merge would still meter, but distinct
                    // rows make the arithmetic unambiguous).
                    let m = mem(
                        &format!("w{t}-{i}"),
                        "team/hot",
                        "a shared memory re-stored under contention",
                    );
                    db::insert(&conn, &m).expect("worker insert");
                }
            });
        }
    });

    let conn = db::open(&path).expect("reopen");
    let ns = cost::namespace_rollup(&conn, "team/hot")
        .expect("ns rollup")
        .expect("metered");
    let expected_events = i64::try_from(THREADS * PER_THREAD).unwrap();
    assert_eq!(ns.write_events, expected_events, "no lost counter updates");
    assert_eq!(
        ns.tokens_written,
        per_write.saturating_mul(expected_events),
        "aggregated token count is exact under contention"
    );
}

/// Recall counters must also stay EXACT under concurrent recallers. Each
/// worker records the same served set repeatedly on its own connection to
/// the shared file; the aggregate `recall_events` must equal exactly the
/// total number of served rows (no lost update).
#[test]
fn recall_counters_are_exact_under_concurrent_recalls() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 40;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cost_recall_concurrency.db");
    {
        let conn = db::open(&path).expect("bootstrap");
        drop(conn);
    }
    let a = mem("ra", "team/recall", "alpha served content");
    let b = mem("rb", "team/recall", "bravo served content longer body");
    let per_recall_tokens = tokens_of(&a) + tokens_of(&b);

    std::thread::scope(|s| {
        for _ in 0..THREADS {
            let path = path.clone();
            let a = a.clone();
            let b = b.clone();
            s.spawn(move || {
                let conn = db::open(&path).expect("worker open");
                for _ in 0..PER_THREAD {
                    cost::record_recall_sqlite(&conn, &[(a.clone(), 0.9), (b.clone(), 0.8)]);
                }
            });
        }
    });

    let conn = db::open(&path).expect("reopen");
    let ns = cost::namespace_rollup(&conn, "team/recall")
        .expect("ns rollup")
        .expect("metered");
    let served_rows = i64::try_from(THREADS * PER_THREAD * 2).unwrap();
    assert_eq!(
        ns.recall_events, served_rows,
        "no lost recall counter updates"
    );
    let recalls = i64::try_from(THREADS * PER_THREAD).unwrap();
    assert_eq!(
        ns.tokens_recalled,
        per_recall_tokens.saturating_mul(recalls),
        "aggregated recalled-token count is exact under contention"
    );
}

/// SQLite<->Postgres parity: the same store + recall sequence must produce
/// identical counters on both backends. Skips when no test cluster is set.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sqlite_postgres_counter_parity() {
    use ai_memory::store::postgres::PostgresStore;

    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let pool = store.pool();

    // Clean slate for a deterministic assertion.
    sqlx::query(
        "DELETE FROM token_cost_counters WHERE scope_key LIKE 'parity/%' OR scope_key LIKE 'p-%'",
    )
    .execute(pool)
    .await
    .expect("clean counters");

    let a = mem("p-a", "parity/ns", "alpha parity content body");
    let b = mem("p-b", "parity/ns", "bravo parity content body longer");
    let sqlite_conn = db::open(Path::new(":memory:")).expect("open sqlite");
    db::insert(&sqlite_conn, &a).expect("sqlite insert a");
    db::insert(&sqlite_conn, &b).expect("sqlite insert b");
    let sqlite_ns = cost::namespace_rollup(&sqlite_conn, "parity/ns")
        .expect("sqlite rollup")
        .expect("metered");

    ai_memory::cost::postgres::record_write_pg(pool, &a, "p-a").await;
    ai_memory::cost::postgres::record_write_pg(pool, &b, "p-b").await;
    let pg_ns = ai_memory::cost::postgres::namespace_rollup_pg(pool, "parity/ns")
        .await
        .expect("pg rollup")
        .expect("metered");

    assert_eq!(
        sqlite_ns.tokens_written, pg_ns.tokens_written,
        "namespace write tokens must match across backends"
    );
    assert_eq!(sqlite_ns.write_events, pg_ns.write_events);
    assert_eq!(
        sqlite_ns.usd_string(),
        pg_ns.usd_string(),
        "the dollar figure must be backend-agnostic"
    );
}
