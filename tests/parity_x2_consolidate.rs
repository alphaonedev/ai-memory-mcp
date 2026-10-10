// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7030 campaign X, cells X2a (sqlite) / X2b (postgres):
//! `consolidate_with_expected_versions` failure semantics. Source `k` of the
//! input is missing; the call must fail without touching state on both
//! backends, and a healthy retry (lineage tombstoning ON) must leave the same
//! durable state.
//!
//! Ignore-gated cross-backend assertions:
//! * `x2_parity_error_variant` - sqlite flattens a missing source to
//!   `Backend`, postgres returns `NotFound` (#7091).
//! * `x2_parity_tombstone_audit` - the sqlite tombstone audit event is
//!   dropped under a nested `BEGIN IMMEDIATE` (#7092).
//!
//! Postgres cells skip with a reason when `AI_MEMORY_TEST_POSTGRES_URL` is unset.

#![cfg(feature = "sal")]

mod common;
#[path = "common/parity_fault.rs"]
mod parity_fault;
#[path = "common/parity_oracle.rs"]
mod parity_oracle;

use ai_memory::models::Tier;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use parity_fault::{CALLER, PoisonKind, poison_row, row_id};
use parity_oracle::{RawDb, StateDigest, state_digest};

const N: usize = 3;
const K: usize = 1;
const PREFIX: &str = "x2";
const NS: &str = "parity/x2";

/// Serialises the runs: the lineage flags are process-global atomics.
static FLAGS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Run {
    seeded: StateDigest,
    fault_err: Option<StoreError>,
    after_fault: StateDigest,
    retry: Result<String, StoreError>,
    after_retry: StateDigest,
}

/// Tables a consolidation can touch; wiped before a postgres run (see `pg_run`).
const RESET_SQL: &str = "TRUNCATE memories, memory_links, archived_memories, \
    forget_tombstones, signed_events, memory_revisions, agent_quotas, actions, leases CASCADE";

async fn run_x2(store: &dyn MemoryStore, raw: &RawDb, reset: bool) -> Run {
    let _guard = FLAGS.lock().await;
    if reset {
        parity_oracle::exec(raw, RESET_SQL).await;
    }
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);

    let poison = poison_row(K, PoisonKind::MissingSource);
    let caller = CallerContext::for_agent(CALLER);
    let sources: Vec<_> = (0..N)
        .map(|i| {
            parity_fault::memory(
                &row_id(PREFIX, i),
                &format!("{PREFIX}-title-{i:02}"),
                NS,
                CALLER,
            )
        })
        .collect();
    store
        .store_batch(&caller, &sources)
        .await
        .expect("seed sources");
    let ids: Vec<String> = sources.iter().map(|m| m.id.clone()).collect();
    let versions = vec![1_i64; N];
    let seeded = state_digest(raw).await;

    let consolidate = |ids: Vec<String>, versions: Vec<i64>| {
        let caller = caller.clone();
        async move {
            store
                .consolidate_with_expected_versions(
                    &caller,
                    &ids,
                    "x2 merged",
                    "x2 summary",
                    NS,
                    &Tier::Long,
                    "parity",
                    CALLER,
                    Some(&versions),
                )
                .await
        }
    };

    let (bad_ids, bad_versions) = poison.consolidate_inputs(&ids, &versions);
    let fault_err = consolidate(bad_ids, bad_versions).await.err();
    let after_fault = state_digest(raw).await;
    let retry = consolidate(ids, versions).await;
    let after_retry = state_digest(raw).await;

    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
    Run {
        seeded,
        fault_err,
        after_fault,
        retry,
        after_retry,
    }
}

/// Replace the (random) consolidated id so digests compare across backends.
#[cfg(feature = "sal-postgres")]
fn mask(d: &StateDigest, id: &str) -> StateDigest {
    let mut out = d.clone();
    for rows in out.0.values_mut() {
        for row in rows {
            for cell in row {
                if cell == id {
                    *cell = "<consolidated>".to_string();
                }
            }
        }
    }
    for rows in out.0.values_mut() {
        rows.sort();
    }
    out
}

fn assert_atomic(run: &Run, backend: &str) {
    assert!(
        run.fault_err.is_some(),
        "{backend}: consolidating a missing source {K} must fail"
    );
    assert_eq!(
        run.after_fault.without(&["signed_events"]),
        run.seeded.without(&["signed_events"]),
        "{backend}: a failed consolidation must leave NO durable change"
    );
    let id = run
        .retry
        .as_ref()
        .expect("healthy consolidation must commit");
    assert!(
        run.after_retry
            .section("memories")
            .iter()
            .any(|r| &r[0] == id),
        "{backend}: the consolidated memory must exist"
    );
}

async fn sqlite_run() -> Run {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x2.db");
    let store = SqliteStore::open(&path).expect("open sqlite");
    run_x2(&store, &RawDb::Sqlite(path), false).await
}

/// F3: a panic in a cell must restore both process-global flags.
#[tokio::test]
async fn x2_flags_reset_after_panic() {
    let failed = tokio::spawn(async {
        let dir = tempfile::tempdir().expect("panic control tempdir");
        let store = SqliteStore::open(dir.path().join("flags.db")).expect("flags sqlite");
        // The first digest fails after the run has enabled both flags.
        let raw = RawDb::Sqlite(dir.path().join("absent.db"));
        run_x2(&store, &raw, false).await;
    })
    .await;
    assert!(
        failed.expect_err("oracle open must panic").is_panic(),
        "F3 panic control"
    );
    let _guard = FLAGS.lock().await;
    let lineage = ai_memory::config::lineage_dag_enabled();
    // Inspect the sub-flag while its master is on, then reset even on red.
    ai_memory::config::set_lineage_dag(true);
    let tombstones = ai_memory::config::consolidate_tombstone_sources_enabled();
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
    assert_eq!(
        (lineage, tombstones),
        (false, false),
        "F3: flags reset on unwind"
    );
}

/// F1: a run owns its database and must not erase the provisioning lane.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn x2_postgres_preserves_lane_sentinel() {
    const SENTINEL: &str = "x2-lane-sentinel";
    let Some(url) = common::pg_isolate::isolated_url() else {
        eprintln!("skip: x2_postgres_preserves_lane_sentinel: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    common::lane_db::assert_lane_database(&url);
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("lane sentinel");
    let caller = CallerContext::for_agent(CALLER);
    store
        .store(
            &caller,
            &parity_fault::memory(SENTINEL, SENTINEL, NS, CALLER),
        )
        .await
        .expect("seed lane sentinel");
    let run = pg_run().await.expect("postgres configured");
    assert_atomic(&run, "postgres sentinel run");
    let retained = store.get(&caller, SENTINEL).await;
    store.pool().close().await;
    assert_eq!(
        retained
            .expect("F1: lane sentinel survives a sibling run")
            .id,
        SENTINEL
    );
}

/// Postgres runs in the database's `public` schema, not a per-test schema:
/// the lineage leaf path issues `SET LOCAL search_path = ag_catalog, "$user",
/// public` (AGE), which drops a test schema from the path. The campaign tables
/// are therefore wiped per run, so the URL must be a dedicated lane database.
#[cfg(feature = "sal-postgres")]
async fn pg_run() -> Option<Run> {
    use ai_memory::store::postgres::PostgresStore;
    let Some(url) = common::pg_isolate::isolated_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (X2b needs a live postgres)");
        return None;
    };
    common::lane_db::assert_lane_database(&url);
    let store = PostgresStore::connect(&url).await.expect("connect pg");
    let raw = RawDb::Pg(store.pool().clone());
    Some(run_x2(&store, &raw, true).await)
}

/// X2a: sqlite consolidation is atomic and retry-clean.
#[tokio::test]
async fn x2a_sqlite_consolidate_atomic() {
    assert_atomic(&sqlite_run().await, "sqlite");
}

/// F5: an audit-only partial commit must fail the atomicity assertion.
#[tokio::test]
async fn x2_atomicity_rejects_audit_only_change() {
    let mut run = sqlite_run().await;
    run.after_fault.0.insert(
        "signed_events".to_string(),
        vec![vec!["memory_link.created".to_string(), "1".to_string()]],
    );
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_atomic(&run, "F5 audit-only mutation");
    }));
    assert!(
        caught.is_err(),
        "F5: signed_events must participate in atomicity"
    );
}

/// X2b: postgres consolidation is atomic and retry-clean.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn x2b_postgres_consolidate_atomic() {
    if let Some(run) = pg_run().await {
        assert_atomic(&run, "postgres");
    }
}

/// Cross-backend: same durable state after the fault and after the retry,
/// excluding the audit sections the two gated cells own.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn x2_parity() {
    let Some(pg) = pg_run().await else { return };
    let sq = sqlite_run().await;
    let skip = ["signed_events", "quota"];
    assert_eq!(
        sq.after_fault.without(&skip),
        pg.after_fault.without(&skip),
        "X2 state after the faulted consolidation"
    );
    let (sid, pid) = (
        sq.retry.as_ref().expect("sqlite retry"),
        pg.retry.as_ref().expect("pg retry"),
    );
    assert_eq!(
        mask(&sq.after_retry, sid).without(&skip),
        mask(&pg.after_retry, pid).without(&skip),
        "X2 state after the healthy consolidation"
    );
}

/// Cross-backend error variant for the missing source (#7091).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "X2 divergence tracked in issue #7091 — un-ignore when fixed"]
async fn x2_parity_error_variant() {
    let Some(pg) = pg_run().await else { return };
    let sq = sqlite_run().await;
    assert_eq!(
        parity_oracle::err_variant(sq.fault_err.as_ref().expect("sqlite err")).0,
        parity_oracle::err_variant(pg.fault_err.as_ref().expect("pg err")).0,
        "X2 error variant for a missing consolidation source (sqlite vs postgres)"
    );
}

/// The tombstone-path consolidation links every source to the new memory; each
/// link must leave a `memory_link.created` audit row on BOTH backends, the same
/// number on each (#7092: sqlite warn-drops it, postgres never writes it).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "X2 divergence tracked in issue #7092 — un-ignore when fixed"]
async fn x2_parity_tombstone_audit() {
    let Some(pg) = pg_run().await else { return };
    let sq = sqlite_run().await;
    let audited = |d: &StateDigest| -> usize {
        d.section("signed_events")
            .iter()
            .filter(|r| r[0] == "memory_link.created")
            .map(|r| r[1].parse::<usize>().expect("count"))
            .sum()
    };
    let links = |d: &StateDigest| d.section("links").len();
    for (name, run) in [("sqlite", &sq), ("postgres", &pg)] {
        assert_eq!(
            audited(&run.after_retry),
            links(&run.after_retry),
            "X2 {name}: one memory_link.created audit row per derived_from link"
        );
    }
    assert_eq!(
        sq.after_retry.section("signed_events"),
        pg.after_retry.section("signed_events"),
        "X2 signed_events (event_type, count) after a tombstoning consolidation"
    );
}
