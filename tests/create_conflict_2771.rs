// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2771 — the default `on_conflict=error` create disposition must be
//! ATOMICALLY fail-closed: a second create racing into the same
//! `(title, namespace)` key is REFUSED (typed conflict), never allowed to
//! silently overwrite the first writer's durable `content`.
//!
//! Pre-#2771 the `error` path was probe-then-upsert (`find_by_title_namespace`
//! → `Ok(None)` → `INSERT … ON CONFLICT DO UPDATE SET content=excluded`), so a
//! writer that slipped in between the probe and the write had its content
//! clobbered with no 409 and no snapshot — a North-Star data-loss defect.
//!
//! sqlite is covered directly at the `db::insert_no_overwrite` chokepoint
//! (single-process + a genuine two-connection race); postgres is covered via
//! the SAL `store_with_embedding_no_overwrite` trait method under a real
//! two-task race (gated on `AI_MEMORY_TEST_POSTGRES_URL`).

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};

fn mem(id: &str, ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["conflict-2771".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-2771".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:tester" }),
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
    }
}

// ───────────────────────────────────────────────────────────────────
// sqlite — single-connection deterministic (the core fix contract)
// ───────────────────────────────────────────────────────────────────

/// The winner's content survives; the loser is REFUSED with the typed
/// `ConflictError` carrying the winner's id, and exactly one row exists.
#[test]
fn create_error_mode_refuses_and_preserves_content_sqlite_2771() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m.db");
    let conn = ai_memory::db::open(&path).expect("open");

    let winner = mem(
        "id-winner",
        "team/ops",
        "shared-title",
        "WINNER durable content",
    );
    let winner_id = ai_memory::db::insert_no_overwrite(&conn, &winner).expect("first create ok");
    assert_eq!(winner_id, "id-winner");

    // Second create — same (title, namespace), DIFFERENT id + content.
    let loser = mem(
        "id-loser",
        "team/ops",
        "shared-title",
        "LOSER content MUST NOT land",
    );
    let err = ai_memory::db::insert_no_overwrite(&conn, &loser)
        .expect_err("second create MUST be refused, never overwrite");
    let conflict = err
        .downcast_ref::<ai_memory::storage::ConflictError>()
        .expect("typed ConflictError");
    assert_eq!(conflict.existing_id, "id-winner");
    assert_eq!(conflict.title, "shared-title");
    assert_eq!(conflict.namespace, "team/ops");

    // Durable content is untouched — the winner's, NOT the loser's.
    let row = ai_memory::db::get(&conn, "id-winner")
        .expect("get")
        .expect("row present");
    assert_eq!(row.content, "WINNER durable content");
    // The loser row was never created.
    assert!(
        ai_memory::db::get(&conn, "id-loser")
            .expect("get")
            .is_none(),
        "loser id must not exist"
    );
}

/// Control: the LEGACY `db::insert` (the `merge`/upsert path the non-error
/// dispositions keep) DOES overwrite — proving the regression above is
/// load-bearing and that the fix changed only the `error` disposition.
#[test]
fn legacy_merge_insert_still_upserts_content_sqlite_2771() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m.db");
    let conn = ai_memory::db::open(&path).expect("open");

    let first = mem("id-1", "team/ops", "shared-title", "first content");
    ai_memory::db::insert(&conn, &first).expect("first insert");
    let second = mem(
        "id-2",
        "team/ops",
        "shared-title",
        "second content wins on merge",
    );
    // merge/upsert keeps the SURVIVING row's id but takes the incoming content.
    ai_memory::db::insert(&conn, &second).expect("merge upsert");
    let row = ai_memory::db::get(&conn, "id-1")
        .expect("get")
        .expect("surviving row");
    assert_eq!(
        row.content, "second content wins on merge",
        "merge disposition upserts content (unchanged by #2771)"
    );
}

// ───────────────────────────────────────────────────────────────────
// sqlite — genuine two-connection race (multi-process-shaped)
// ───────────────────────────────────────────────────────────────────

/// Two connections to the SAME file DB race the same `(title, namespace)`
/// create. The `(title, namespace)` UNIQUE index guarantees exactly one
/// winner; the loser gets the typed `ConflictError` (never a silent
/// overwrite, never two rows). WAL + a generous busy-timeout keep the loser
/// off the `SQLITE_BUSY` lock-contention path so the conflict is decided by
/// the index, not by lock timing.
#[test]
fn concurrent_two_connection_create_exactly_one_winner_sqlite_2771() {
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m.db");
    // Materialise the schema once on a throwaway connection so both racers
    // open an already-migrated file (avoids a migration/DDL race that is not
    // what this test is about).
    drop(ai_memory::db::open(&path).expect("seed schema"));

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for tag in ["A", "B"] {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let conn = ai_memory::db::open(&path).expect("open");
            conn.busy_timeout(Duration::from_secs(10))
                .expect("busy_timeout");
            let m = mem(
                &format!("id-{tag}"),
                "race/ns",
                "raced-title",
                &format!("content-from-{tag}"),
            );
            barrier.wait();
            ai_memory::db::insert_no_overwrite(&conn, &m)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();

    let winners: Vec<&String> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(winners.len(), 1, "exactly one create must win the race");
    for r in &results {
        if let Err(e) = r {
            e.downcast_ref::<ai_memory::storage::ConflictError>()
                .expect("loser must get the typed ConflictError, not a lock/other error");
        }
    }

    // Exactly one row, and its content matches the winner (never overwritten).
    let conn = ai_memory::db::open(&path).expect("reopen");
    let winner_id = winners[0].clone();
    let row = ai_memory::db::get(&conn, &winner_id)
        .expect("get")
        .expect("winner row present");
    let expected = format!("content-from-{}", winner_id.trim_start_matches("id-"));
    assert_eq!(row.content, expected, "winner content must be durable");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = ?1 AND namespace = ?2",
            rusqlite::params!["raced-title", "race/ns"],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(count, 1, "the race must leave exactly one row");
}

// ───────────────────────────────────────────────────────────────────
// postgres — SAL trait, real two-task race (gated on live pg)
// ───────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::mem;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, StoreError};
    use std::sync::Arc;

    async fn connect() -> Option<Arc<PostgresStore>> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        Some(Arc::new(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        ))
    }

    fn uid(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4())
    }

    /// Two concurrent `store_with_embedding_no_overwrite` calls on the same
    /// `(title, namespace)` on separate pooled connections: exactly one wins
    /// (Ok), the other gets `StoreError::Conflict`, and the durable content is
    /// the winner's — never the loser's silent overwrite.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_no_overwrite_exactly_one_winner_pg_2771() {
        let Some(store) = connect().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ns = uid("race-ns");
        let title = "pg-raced-title".to_string();

        let a = {
            let (store, ns, title) = (Arc::clone(&store), ns.clone(), title.clone());
            tokio::spawn(async move {
                let ctx = CallerContext::for_agent("ai:racer-a");
                let m = mem(&uid("a"), &ns, &title, "content-A");
                store
                    .store_with_embedding_no_overwrite(&ctx, &m, None, None)
                    .await
                    .map(|id| (id, "content-A".to_string()))
            })
        };
        let b = {
            let (store, ns, title) = (Arc::clone(&store), ns.clone(), title.clone());
            tokio::spawn(async move {
                let ctx = CallerContext::for_agent("ai:racer-b");
                let m = mem(&uid("b"), &ns, &title, "content-B");
                store
                    .store_with_embedding_no_overwrite(&ctx, &m, None, None)
                    .await
                    .map(|id| (id, "content-B".to_string()))
            })
        };
        let ra = a.await.expect("join a");
        let rb = b.await.expect("join b");

        let oks: Vec<&(String, String)> = [&ra, &rb]
            .into_iter()
            .filter_map(|r| r.as_ref().ok())
            .collect();
        assert_eq!(oks.len(), 1, "exactly one create must win the pg race");
        for r in [&ra, &rb] {
            if let Err(e) = r {
                assert!(
                    matches!(e, StoreError::Conflict { .. }),
                    "loser must get StoreError::Conflict, got {e:?}"
                );
            }
        }

        let (winner_id, winner_content) = oks[0].clone();
        // #2771 — the winning row is scope=private, owned by the racer's
        // authoritative `metadata.agent_id`, so a THIRD-PARTY reader is
        // correctly DENIED by `is_visible_to_caller` (NotFound) — the
        // visibility control working, not data loss. This assertion is a
        // DURABILITY check (did the winner's content physically persist,
        // unoverwritten?), so it reads with a visibility-BYPASS admin ctx
        // (`for_admin` sets `bypass_visibility`) to observe the row regardless
        // of ownership. It is NOT a visibility test.
        let ctx = CallerContext::for_admin("ai:reader");
        let row = store.get(&ctx, &winner_id).await.expect("get winner");
        assert_eq!(
            row.content, winner_content,
            "the durable pg content must be the winner's, never overwritten"
        );
    }
}
