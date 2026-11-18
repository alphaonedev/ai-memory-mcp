// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9466 — sqlite half of the `delete_link` owner-read cells. The case table
//! is shared with postgres (`crate::store::delete_link_owner_9466`); a gate
//! that holds on one backend only turns the other backend's cell red.

use super::SqliteStore;
use crate::store::delete_link_owner_9466::{
    ALICE, CASES, Caller, Endpoint, MALLORY, READ_FAULT_TABLE, SEED_OWNER, arm_read_fault, edge,
    judge, seed_memory,
};
use crate::store::{
    CallerContext, DELETE_LINK_SOURCE_LOOKUP, DELETE_LINK_TARGET_LOOKUP, MemoryStore, StoreResult,
};

fn open_store() -> SqliteStore {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    // The store owns the file from here; the guard must not delete it first.
    std::mem::forget(file);
    SqliteStore::open(&path).expect("open SqliteStore")
}

/// One endpoint row in `state`, or a fresh id with no row for `Absent`.
async fn seed_endpoint(store: &SqliteStore, state: Endpoint, title: &str) -> String {
    let Some(metadata) = state.metadata_text() else {
        return uuid::Uuid::new_v4().to_string();
    };
    let seed = CallerContext::for_agent(SEED_OWNER);
    let id = store
        .store(&seed, &seed_memory(title))
        .await
        .expect("seed endpoint");
    let conn = store.state.lock().await;
    let updated = conn
        .execute(
            "UPDATE memories SET metadata = ?1 WHERE id = ?2",
            rusqlite::params![metadata, id],
        )
        .expect("set endpoint metadata");
    assert_eq!(updated, 1, "endpoint metadata must be set");
    id
}

/// Seed both endpoints and the edge between them. With both rows present the
/// edge is linked while the seed owner still owns both; with an endpoint
/// absent it is an ORPHAN edge, inserted with the foreign keys off (both
/// `memory_links` keys are `ON DELETE CASCADE`, so it cannot arise with the
/// keys on — it is the shape the gate must still refuse when it exists).
async fn seed_pair(store: &SqliteStore, source: Endpoint, target: Endpoint) -> (String, String) {
    let seed = CallerContext::for_agent(SEED_OWNER);
    let both = source.metadata_text().is_some() && target.metadata_text().is_some();
    if !both {
        let source_id = seed_endpoint(store, source, "source").await;
        let target_id = seed_endpoint(store, target, "target").await;
        let conn = store.state.lock().await;
        conn.execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("foreign keys off");
        let inserted = conn
            .execute(
                "INSERT INTO memory_links (source_id, target_id, relation, created_at) \
                 VALUES (?1, ?2, 'related_to', ?3)",
                rusqlite::params![source_id, target_id, chrono::Utc::now().to_rfc3339()],
            )
            .expect("seed orphan edge");
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("foreign keys on");
        assert_eq!(inserted, 1, "orphan edge must be seeded");
        return (source_id, target_id);
    }
    let source_id = store
        .store(&seed, &seed_memory("source"))
        .await
        .expect("seed source");
    let target_id = store
        .store(&seed, &seed_memory("target"))
        .await
        .expect("seed target");
    store
        .link(&seed, &edge(&source_id, &target_id))
        .await
        .expect("seed edge");
    let conn = store.state.lock().await;
    for (id, state) in [(&source_id, source), (&target_id, target)] {
        let metadata = state.metadata_text().expect("present endpoint");
        let updated = conn
            .execute(
                "UPDATE memories SET metadata = ?1 WHERE id = ?2",
                rusqlite::params![metadata, id],
            )
            .expect("set endpoint metadata");
        assert_eq!(updated, 1, "endpoint metadata must be set");
    }
    (source_id, target_id)
}

async fn edge_count(store: &SqliteStore, source_id: &str, target_id: &str) -> i64 {
    let conn = store.state.lock().await;
    conn.query_row(
        "SELECT COUNT(*) FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
        rusqlite::params![source_id, target_id],
        |row| row.get(0),
    )
    .expect("count edges")
}

/// Every row of the shared table: the answer, the exact refusal text, and
/// the edge still present after every refusal.
#[tokio::test]
async fn delete_link_owner_table_sqlite_9466() {
    let store = open_store();
    let mut failures = Vec::new();
    for case in CASES {
        let (source_id, target_id) = seed_pair(&store, case.source, case.target).await;
        let got = store
            .delete_link(&case.caller.ctx(), &source_id, &target_id)
            .await;
        let left = edge_count(&store, &source_id, &target_id).await;
        if let Err(reason) = judge(case, &got, left) {
            failures.push(reason);
        }
    }
    assert!(
        failures.is_empty(),
        "sqlite delete_link owner table: {} of {} case(s) wrong:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n")
    );
}

/// The exact sqlite `Display` of a failed owner read.
fn read_error_text(what: &str) -> String {
    format!("underlying backend error: {what}: no such table: {READ_FAULT_TABLE}")
}

/// A failed owner read is the store error, verbatim, and removes nothing —
/// for a caller a defaulted owner would admit (the owner of both endpoints,
/// and a stranger on two unstamped rows, which a `""` fold admits as legacy).
#[tokio::test]
async fn delete_link_owner_read_error_sqlite_9466() {
    let store = open_store();
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
            let got: StoreResult<bool> = store
                .delete_link(&caller.ctx(), &source_id, &target_id)
                .await;
            let got = got.map_err(|e| e.to_string());
            assert_eq!(
                got,
                Err(read_error_text(what)),
                "{state:?} / {caller:?}: a failed {what} must be the store error"
            );
            assert_eq!(
                edge_count(&store, &source_id, &target_id).await,
                1,
                "{state:?} / {caller:?}: a failed {what} must remove nothing"
            );
        }
    }
}
