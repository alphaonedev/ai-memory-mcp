// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9466 — sqlite half of the `delete_link` owner-read cells. The case table
//! is shared with postgres (`crate::store::delete_link_owner_9466`); a gate
//! that holds on one backend only turns the other backend's cell red.

use super::{OWNER_GATE_TEST_HOOK, SqliteStore};
use crate::store::delete_link_owner_9466::{
    ALICE, BOB, CASES, Caller, ENDPOINT_METADATA_SET, Endpoint, MALLORY, READ_FAULT_TABLE,
    SEED_OWNER, SET_ENDPOINT_METADATA, arm_read_fault, edge, judge, seed_memory,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long the second connection waits for the write lock before SQLite
/// names the refusal; short, so a held lock fails the attempt fast.
const SECOND_WRITER_BUSY_TIMEOUT: Duration = Duration::from_millis(100);
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
    set_metadata(&conn, &id, &metadata);
    id
}

/// Overwrite one endpoint row's metadata with its case state.
fn set_metadata(conn: &rusqlite::Connection, id: &str, metadata: &str) {
    // The sanctioned metadata overwrite (#8341 pin): no raw `memories` write here.
    crate::storage::set_row_metadata(conn, id, metadata).expect(SET_ENDPOINT_METADATA);
    let kept: String = conn
        .query_row(
            "SELECT metadata FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .expect("read back endpoint metadata");
    assert_eq!(kept, metadata, "{ENDPOINT_METADATA_SET}");
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
        set_metadata(&conn, id, &metadata);
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
        if let Err(mismatch) = judge(case, &got, left) {
            failures.push(mismatch.to_string());
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

/// What a second connection's owner re-stamp of one endpoint returned: the
/// rows it changed, or the SQLite error code that refused it.
type SecondWriter = Arc<Mutex<Option<Result<(), Option<rusqlite::ErrorCode>>>>>;

/// Arm the gate-to-write interleave point of `delete_link` (keyed by the
/// source id): once the owner decision is taken, a SECOND connection on the
/// same file tries to hand `endpoint_id` to [`MALLORY`].
fn arm_second_writer(path: std::path::PathBuf, source_id: &str, endpoint_id: &str) -> SecondWriter {
    let outcome: SecondWriter = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&outcome);
    let endpoint = endpoint_id.to_string();
    let hook: Box<dyn FnOnce() + Send> = Box::new(move || {
        let other = rusqlite::Connection::open(&path).expect("second connection");
        other
            .busy_timeout(SECOND_WRITER_BUSY_TIMEOUT)
            .expect("second connection busy timeout");
        // The seeded endpoint metadata is exactly the owner stamp, so the
        // sanctioned overwrite with MALLORY's stamp is the owner re-stamp.
        let restamp = Endpoint::Stamped(MALLORY)
            .metadata_text()
            .expect("a stamped endpoint has metadata");
        let got = crate::storage::set_row_metadata(&other, &endpoint, &restamp).map_err(|e| {
            e.downcast_ref::<rusqlite::Error>()
                .and_then(rusqlite::Error::sqlite_error_code)
        });
        *slot.lock().expect("second writer slot") = Some(got);
    });
    OWNER_GATE_TEST_HOOK
        .lock()
        .expect("owner gate hook")
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(source_id.to_string(), hook);
    outcome
}

fn stored_owner(path: &std::path::Path, id: &str) -> String {
    rusqlite::Connection::open(path)
        .expect("reader")
        .query_row(
            "SELECT json_extract(metadata, '$.agent_id') FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .expect("endpoint owner")
}

/// #9466 (D-6) — the owner reads of `SqliteStore::delete_link` and the
/// DELETE they authorise are ONE `BEGIN IMMEDIATE` transaction. Class: a
/// read that feeds an owner decision and the write it guards are one atomic
/// unit. A second connection that tries to change an endpoint's owner after
/// the decision fails by name (`DatabaseBusy`), the owner's delete lands,
/// and the endpoint keeps the owner the decision read.
#[tokio::test]
async fn delete_link_owner_read_and_delete_one_txn_sqlite_9466() {
    let store = open_store();
    // (re-stamped endpoint, the caller who owns it at decision time)
    for (restamp_source, caller) in [(true, ALICE), (false, BOB)] {
        let (source_id, target_id) =
            seed_pair(&store, Endpoint::Stamped(ALICE), Endpoint::Stamped(BOB)).await;
        let endpoint_id = if restamp_source {
            &source_id
        } else {
            &target_id
        };
        let second = arm_second_writer(store.path.clone(), &source_id, endpoint_id);
        let got = store
            .delete_link(&CallerContext::for_agent(caller), &source_id, &target_id)
            .await
            .map_err(|e| e.to_string());
        let second = second.lock().expect("second writer slot").take();
        assert_eq!(
            second,
            Some(Err(Some(rusqlite::ErrorCode::DatabaseBusy))),
            "restamp source={restamp_source}: an owner change between the decision and the \
             DELETE must be refused by the held write lock (delete: {got:?})"
        );
        assert_eq!(
            got,
            Ok(true),
            "restamp source={restamp_source}: the owner's delete"
        );
        assert_eq!(edge_count(&store, &source_id, &target_id).await, 0);
        assert_eq!(
            stored_owner(&store.path, endpoint_id),
            if restamp_source { ALICE } else { BOB },
            "restamp source={restamp_source}: the endpoint keeps the owner the decision read"
        );
    }
}
