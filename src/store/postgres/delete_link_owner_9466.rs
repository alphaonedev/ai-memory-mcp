// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9466 — postgres half of the `delete_link` owner-read cells, over the
//! table shared with sqlite (`crate::store::delete_link_owner_9466`). Gated
//! on `AI_MEMORY_TEST_POSTGRES_URL`; run through the CI v2 per-binary
//! isolation wrapper so each run gets its own minted database.

use super::PostgresStore;
use crate::store::delete_link_owner_9466::{
    ALICE, BOB, CASES, Caller, ENDPOINT_METADATA_SET, Endpoint, MALLORY, READ_FAULT_TABLE,
    SEED_OWNER, SET_ENDPOINT_METADATA, arm_read_fault, edge, judge, seed_memory,
};
use crate::store::{
    CallerContext, DELETE_LINK_SOURCE_LOOKUP, DELETE_LINK_TARGET_LOOKUP, MemoryStore, StoreError,
};

/// `undefined_table` — the SQLSTATE a read of [`READ_FAULT_TABLE`] fails with.
const PG_SQLSTATE_UNDEFINED_TABLE: &str = "42P01";

/// The env var that names the scratch database (the CI v2 wrapper mints it).
const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";

/// The store of the scratch database, or `None` (with the house SKIP line,
/// `src/store/update_atomicity_3152_tests.rs` `pg_url`) when it is unset.
async fn pg_store_9466(test: &str) -> Option<PostgresStore> {
    let Ok(url) = std::env::var(PG_URL_ENV) else {
        eprintln!("SKIP {test}: {PG_URL_ENV} unset");
        return None;
    };
    Some(PostgresStore::connect(&url).await.expect("connect"))
}

async fn set_metadata(store: &PostgresStore, id: &str, state: Endpoint) {
    let metadata = state.metadata_text().expect("present endpoint");
    let updated = sqlx::query("UPDATE memories SET metadata = $1::jsonb WHERE id = $2")
        .bind(metadata)
        .bind(id)
        .execute(&store.pool)
        .await
        .expect(SET_ENDPOINT_METADATA)
        .rows_affected();
    assert_eq!(updated, 1, "{ENDPOINT_METADATA_SET}");
}

/// Seed both endpoints and the edge between them. With both rows present the
/// edge is linked while the seed owner still owns both; with an endpoint
/// absent (a fresh id with no row) it is an ORPHAN edge, inserted with the
/// foreign keys off (`session_replication_role = replica` on one pooled
/// connection, reset before the connection returns): both `memory_links`
/// keys are `ON DELETE CASCADE`, so it cannot arise with the keys on.
async fn seed_pair(store: &PostgresStore, source: Endpoint, target: Endpoint) -> (String, String) {
    let seed = CallerContext::for_agent(SEED_OWNER);
    let mut ids = Vec::with_capacity(2);
    for (state, title) in [(source, "source"), (target, "target")] {
        let id = if state.metadata_text().is_some() {
            store
                .store(&seed, &seed_memory(title))
                .await
                .expect("seed endpoint")
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        ids.push(id);
    }
    let target_id = ids.pop().expect("target id");
    let source_id = ids.pop().expect("source id");
    let both = source.metadata_text().is_some() && target.metadata_text().is_some();
    if both {
        store
            .link(&seed, &edge(&source_id, &target_id))
            .await
            .expect("seed edge");
    } else {
        let mut conn = store.pool.acquire().await.expect("acquire");
        sqlx::query("SET session_replication_role = replica")
            .execute(&mut *conn)
            .await
            .expect("foreign keys off");
        let inserted = sqlx::query(
            "INSERT INTO memory_links (source_id, target_id, relation) \
             VALUES ($1, $2, 'related_to')",
        )
        .bind(&source_id)
        .bind(&target_id)
        .execute(&mut *conn)
        .await;
        sqlx::query("RESET session_replication_role")
            .execute(&mut *conn)
            .await
            .expect("foreign keys on");
        assert_eq!(
            inserted.expect("seed orphan edge").rows_affected(),
            1,
            "orphan edge must be seeded"
        );
    }
    for (id, state) in [(&source_id, source), (&target_id, target)] {
        if state.metadata_text().is_some() {
            set_metadata(store, id, state).await;
        }
    }
    (source_id, target_id)
}

async fn edge_count(store: &PostgresStore, source_id: &str, target_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM memory_links WHERE source_id = $1 AND target_id = $2")
        .bind(source_id)
        .bind(target_id)
        .fetch_one(&store.pool)
        .await
        .expect("count edges")
}

/// Every row of the shared table a `jsonb` column can hold: the answer, the
/// exact refusal text, and the edge still present after every refusal.
#[tokio::test]
async fn delete_link_owner_table_pg_9466() {
    let Some(store) = pg_store_9466("delete_link_owner_table_pg_9466").await else {
        return;
    };
    let mut failures = Vec::new();
    let mut ran = 0_usize;
    for case in CASES {
        if case.source.sqlite_only() || case.target.sqlite_only() {
            continue;
        }
        ran += 1;
        let (source_id, target_id) = seed_pair(&store, case.source, case.target).await;
        let got = store
            .delete_link(&case.caller.ctx(), &source_id, &target_id)
            .await;
        let left = edge_count(&store, &source_id, &target_id).await;
        if let Err(reason) = judge(case, &got, left) {
            failures.push(reason);
        }
    }
    assert!(ran > 0, "the shared table must have postgres rows");
    assert!(
        failures.is_empty(),
        "postgres delete_link owner table: {} of {ran} case(s) wrong:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A failed owner read is the store error, verbatim (with its SQLSTATE), and
/// removes nothing — for a caller a defaulted owner would admit.
#[tokio::test]
async fn delete_link_owner_read_error_pg_9466() {
    let Some(store) = pg_store_9466("delete_link_owner_read_error_pg_9466").await else {
        return;
    };
    let callers = [
        (Endpoint::Stamped(ALICE), Caller::Agent(ALICE)),
        (Endpoint::Unstamped, Caller::Agent(MALLORY)),
    ];
    for (state, caller) in callers {
        for (fault_source, what) in [
            (true, DELETE_LINK_SOURCE_LOOKUP),
            (false, DELETE_LINK_TARGET_LOOKUP),
        ] {
            let (source_id, target_id) = seed_pair(&store, state, state).await;
            arm_read_fault(if fault_source { &source_id } else { &target_id });
            let got = store
                .delete_link(&caller.ctx(), &source_id, &target_id)
                .await;
            let expected = format!(
                "backend unavailable: postgres: {what}: error returned from database: \
                 relation \"{READ_FAULT_TABLE}\" does not exist"
            );
            match &got {
                Err(e @ StoreError::BackendUnavailable { sqlstate, .. }) => {
                    assert_eq!(
                        e.to_string(),
                        expected,
                        "{state:?} / {caller:?}: a failed {what} must be the store error"
                    );
                    assert_eq!(
                        sqlstate.as_deref(),
                        Some(PG_SQLSTATE_UNDEFINED_TABLE),
                        "{state:?} / {caller:?}: the SQLSTATE must survive"
                    );
                }
                other => panic!(
                    "{state:?} / {caller:?}: a failed {what} must be BackendUnavailable \
                     `{expected}`, got {other:?}"
                ),
            }
            assert_eq!(
                edge_count(&store, &source_id, &target_id).await,
                1,
                "{state:?} / {caller:?}: a failed {what} must remove nothing"
            );
        }
    }
}

/// Bound on waiting for `delete_link` to queue behind the other session's
/// row lock; it queues within milliseconds when the owner read locks.
const LOCK_WAIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// How often the waiter re-checks `pg_blocking_pids`.
const LOCK_WAIT_POLL: std::time::Duration = std::time::Duration::from_millis(20);
/// Bound on `delete_link` finishing once the other session commits.
const DELETE_AFTER_COMMIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// `true` once some session is blocked behind backend `pid`, `false` when
/// [`LOCK_WAIT_DEADLINE`] passes first.
async fn someone_waits_on(store: &PostgresStore, pid: i32) -> bool {
    let deadline = tokio::time::Instant::now() + LOCK_WAIT_DEADLINE;
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
             WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid)))",
        )
        .bind(pid)
        .fetch_one(&store.pool)
        .await
        .expect("read pg_blocking_pids");
        if waiting {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(LOCK_WAIT_POLL).await;
    }
}

/// #9466 (E-6) — the owner reads of `PostgresStore::delete_link` are
/// `FOR SHARE` inside the DELETE's transaction. Class: a read that feeds an
/// owner decision and the write it guards are one atomic unit. A second
/// session holds an uncommitted owner change on one endpoint; `delete_link`
/// must queue behind it (observed through `pg_blocking_pids`), then decide
/// on the committed new owner: the former owner is refused and the edge is
/// kept.
#[tokio::test]
async fn delete_link_owner_read_waits_for_owner_change_pg_9466() {
    let Some(store) = pg_store_9466("delete_link_owner_read_waits_for_owner_change_pg_9466").await
    else {
        return;
    };
    // (re-stamped endpoint, the caller who owns it before the change)
    for (restamp_source, caller) in [(true, ALICE), (false, BOB)] {
        let (source_id, target_id) =
            seed_pair(&store, Endpoint::Stamped(ALICE), Endpoint::Stamped(BOB)).await;
        let endpoint_id = if restamp_source {
            &source_id
        } else {
            &target_id
        };
        let mut other = store.pool.begin().await.expect("second session");
        let other_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *other)
            .await
            .expect("second session pid");
        let changed = sqlx::query(
            "UPDATE memories SET metadata = jsonb_set(metadata, '{agent_id}', to_jsonb($1::text)) \
             WHERE id = $2",
        )
        .bind(MALLORY)
        .bind(endpoint_id)
        .execute(&mut *other)
        .await
        .expect("second session owner change")
        .rows_affected();
        assert_eq!(changed, 1, "the second session holds the owner change");

        let ctx = CallerContext::for_agent(caller);
        let delete = store.delete_link(&ctx, &source_id, &target_id);
        let observe = async {
            let queued = someone_waits_on(&store, other_pid).await;
            other.commit().await.expect("second session commit");
            queued
        };
        let (got, queued) = tokio::join!(
            async {
                tokio::time::timeout(DELETE_AFTER_COMMIT_DEADLINE + LOCK_WAIT_DEADLINE, delete)
                    .await
                    .map(|r| r.map_err(|e| e.to_string()))
            },
            observe
        );
        assert!(
            queued,
            "restamp source={restamp_source}: delete_link must queue behind the uncommitted \
             owner change, not decide on the old owner (delete: {got:?})"
        );
        assert_eq!(
            got,
            Ok(Ok(false)),
            "restamp source={restamp_source}: the former owner is refused after the change"
        );
        assert_eq!(
            edge_count(&store, &source_id, &target_id).await,
            1,
            "restamp source={restamp_source}: the edge is kept"
        );
    }
}
