// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9466 — postgres half of the `delete_link` owner-read cells, over the
//! table shared with sqlite (`crate::store::delete_link_owner_9466`). Gated
//! on `AI_MEMORY_TEST_POSTGRES_URL`; run through the CI v2 per-binary
//! isolation wrapper so each run gets its own minted database.

use super::PostgresStore;
use crate::store::delete_link_owner_9466::{
    ALICE, CASES, Caller, Endpoint, MALLORY, READ_FAULT_TABLE, SEED_OWNER, arm_read_fault, edge,
    judge, seed_memory,
};
use crate::store::{
    CallerContext, DELETE_LINK_SOURCE_LOOKUP, DELETE_LINK_TARGET_LOOKUP, MemoryStore, StoreError,
};

/// `undefined_table` — the SQLSTATE a read of [`READ_FAULT_TABLE`] fails with.
const PG_SQLSTATE_UNDEFINED_TABLE: &str = "42P01";

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(PostgresStore::connect(&url).await.expect("connect"))
}

async fn set_metadata(store: &PostgresStore, id: &str, state: Endpoint) {
    let metadata = state.metadata_text().expect("present endpoint");
    let updated = sqlx::query("UPDATE memories SET metadata = $1::jsonb WHERE id = $2")
        .bind(metadata)
        .bind(id)
        .execute(&store.pool)
        .await
        .expect("set endpoint metadata")
        .rows_affected();
    assert_eq!(updated, 1, "endpoint metadata must be set");
}

/// Seed both endpoints and, when both exist, the edge between them (linked
/// while the seed owner still owns both rows). An absent endpoint is a fresh
/// id with no row.
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
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
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
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
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
