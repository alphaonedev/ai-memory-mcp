// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4216 (data-integrity) — RED cells: a federation merge that REPLACES a
//! row's content keeps `version = MAX(local, remote)`, so an optimistic
//! writer that read the row BEFORE the merge still holds a "current" version
//! and its `If-Match` write silently overwrites the merged content (a lost
//! update, no conflict signalled).
//!
//! Scenario (both backends): nodes A and B both hold M at `version = 2`; a
//! user on each edits it, so each reaches `version = 3` with different text.
//! B's row (newer `updated_at`) is merged into A: A's content becomes B's
//! text while A's version stays `MAX(3, 3) = 3`. A client on A that read M at
//! version 3 before the merge now writes with `If-Match: 3`.
//!
//! * `*_stale_if_match_after_a_content_merge_is_refused_4216` — RED on the
//!   carrier: the stale write succeeds and B's merged edit is lost. The
//!   expected outcome (a `VersionConflict`) is the one every option in
//!   `4216-OPTIONS-claude-l2b.md` must deliver.
//! * `*_idempotent_redelivery_does_not_bump_4216` — GUARD (green on the
//!   carrier): re-delivering the same row must not move `version`, or every
//!   replay would raise spurious conflicts. A fix must keep it green.
//!
//! Ruling: 5-agent vote 4d3ea1c5 (memory ea23f404), verdict A as amended by
//! f2r (the change predicate EXCLUDES `crdt_field_clocks` and
//! `version_vector`). #4218 (an inbound version bound) rides the same cells.
//!
//! The #4045 consolidation-CAS cell follows the #4045 landing: that CAS reads
//! `memories.version`, which these cells prove now moves on a merge.

#![cfg(feature = "sal")]

use ai_memory::models::Memory;
use serde_json::json;

const AGENT: &str = "ai:alice-4216";

/// A full replicated row for `id` at `version` with `content`, stamped
/// `updated_at` (RFC3339).
fn row(id: &str, version: i64, content: &str, updated_at: &str) -> Memory {
    serde_json::from_value(json!({
        "id": id,
        "tier": "long",
        "namespace": "fit-4216",
        "title": format!("lost update probe {id}"),
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "nhi",
        "access_count": 0,
        "created_at": "2026-09-20T00:00:00Z",
        "updated_at": updated_at,
        "version": version,
        "metadata": {"agent_id": AGENT}
    }))
    .expect("memory")
}

/// `row` with an explicit priority and metadata (`agent_id` is always kept).
fn row_with(
    id: &str,
    version: i64,
    content: &str,
    updated_at: &str,
    priority: i64,
    extra_metadata: &serde_json::Value,
) -> Memory {
    let mut m = row(id, version, content, updated_at);
    m.priority = i32::try_from(priority).expect("priority");
    if let (Some(dst), Some(src)) = (m.metadata.as_object_mut(), extra_metadata.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    m
}

/// A long-ago `updated_at`: the row LOSES every last-write-wins comparison.
const STALE: &str = "2026-09-01T00:00:00Z";

/// The #4218 bounds, restated from the ruling so a silent change is caught.
const JUMP: i64 = 1 << 32;

/// A timestamp safely after every local write in the test (inside the
/// receive-side freshness clamp), so the remote row wins LWW.
fn soon() -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(2)).to_rfc3339()
}

mod sqlite {
    use super::{JUMP, STALE, row, row_with, soon};
    use ai_memory::db;
    use serde_json::json;

    fn open() -> (tempfile::TempDir, rusqlite::Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = db::open(&dir.path().join("m.db")).expect("open");
        (dir, conn)
    }

    /// A local content edit through the If-Match funnel.
    fn edit(
        conn: &rusqlite::Connection,
        id: &str,
        content: &str,
        expected: i64,
    ) -> anyhow::Result<(bool, bool)> {
        db::update_with_expected_version(
            conn,
            id,
            None,
            Some(content),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(expected),
            None,
        )
    }

    /// Node A's row at version 3 (insert = 1, then two local edits).
    fn node_a_at_v3(conn: &rusqlite::Connection) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let base = row(&id, 1, "v1", &chrono::Utc::now().to_rfc3339());
        db::insert(conn, &base).expect("insert");
        edit(conn, &id, "v2 shared", 1).expect("edit to v2");
        edit(conn, &id, "A's concurrent edit", 2).expect("edit to v3");
        let v = db::get_any(conn, &id).expect("read").expect("row").version;
        assert_eq!(v, 3, "precondition: node A holds M at version 3");
        id
    }

    #[test]
    fn sqlite_stale_if_match_after_a_content_merge_is_refused_4216() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        // The client on A reads M at version 3 (before the merge).
        let observed = db::get_any(&conn, &id).expect("read").expect("row").version;
        // B's concurrent edit (also version 3, newer updated_at) merges in.
        let remote = row(&id, 3, "B's concurrent edit", &soon());
        db::merge_inbound(&conn, &remote, false).expect("merge");
        let merged = db::get_any(&conn, &id).expect("read").expect("row");
        assert_eq!(
            merged.content, "B's concurrent edit",
            "precondition: LWW replaced A's content with B's"
        );
        // The stale If-Match write must be refused, not land over B's edit.
        let stale = edit(&conn, &id, "stale overwrite", observed);
        let after = db::get_any(&conn, &id).expect("read").expect("row");
        assert!(
            stale.is_err(),
            "#4216: If-Match {observed} passed after a merge replaced the content \
             (merged version {}); B's edit was overwritten: {:?}",
            merged.version,
            after.content
        );
        assert_eq!(after.content, "B's concurrent edit", "#4216: lost update");
    }

    #[test]
    fn sqlite_idempotent_redelivery_does_not_bump_4216() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        let remote = row(&id, 3, "B's concurrent edit", &soon());
        db::merge_inbound(&conn, &remote, false).expect("merge");
        let once = db::get_any(&conn, &id).expect("read").expect("row").version;
        db::merge_inbound(&conn, &remote, false).expect("re-delivery");
        let twice = db::get_any(&conn, &id).expect("read").expect("row").version;
        assert_eq!(once, twice, "a replay of the same row moved the version");
    }

    fn version_of(conn: &rusqlite::Connection, id: &str) -> i64 {
        db::get_any(conn, id).expect("read").expect("row").version
    }

    #[test]
    fn sqlite_insert_if_newer_stale_if_match_is_refused_4216() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        let observed = version_of(&conn, &id);
        db::insert_if_newer(&conn, &row(&id, 3, "B's concurrent edit", &soon())).expect("merge");
        assert_eq!(
            db::get_any(&conn, &id).expect("read").expect("row").content,
            "B's concurrent edit",
            "precondition: newer-wins replaced the content"
        );
        assert!(
            edit(&conn, &id, "stale overwrite", observed).is_err(),
            "#4216: If-Match {observed} passed after insert_if_newer replaced the content"
        );
    }

    #[test]
    fn sqlite_insert_if_newer_replay_does_not_bump_4216() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        let remote = row(&id, 3, "B's concurrent edit", &soon());
        db::insert_if_newer(&conn, &remote).expect("merge");
        let once = version_of(&conn, &id);
        assert_eq!(once, 4, "GREATEST(3, 3) + 1 for the content change");
        db::insert_if_newer(&conn, &remote).expect("replay");
        assert_eq!(version_of(&conn, &id), once, "a replay moved the version");
    }

    #[test]
    fn sqlite_losing_push_changing_nothing_does_not_bump_4216() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        let before = version_of(&conn, &id);
        // Older updated_at, same priority/tier/confidence: nothing changes.
        db::insert_if_newer(&conn, &row(&id, 3, "a stale peer's text", STALE)).expect("push");
        assert_eq!(version_of(&conn, &id), before);
        db::merge_inbound(&conn, &row(&id, 3, "a stale peer's text", STALE), false).expect("merge");
        assert_eq!(version_of(&conn, &id), before);
    }

    #[test]
    fn sqlite_losing_push_that_raises_priority_bumps_4216() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        let before = version_of(&conn, &id);
        // Loses LWW but the MAX arm raises priority: USER data changed.
        db::insert_if_newer(
            &conn,
            &row_with(&id, 3, "a stale peer's text", STALE, 9, &json!({})),
        )
        .expect("push");
        let after = db::get_any(&conn, &id).expect("read").expect("row");
        assert_eq!(
            after.priority, 9,
            "precondition: the MAX arm raised priority"
        );
        assert_eq!(after.version, before + 1, "#4216: a data change must bump");
        assert!(edit(&conn, &id, "stale", before).is_err());
    }

    #[test]
    fn sqlite_merge_inbound_losing_push_that_raises_priority_bumps_4216() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        let before = version_of(&conn, &id);
        db::merge_inbound(
            &conn,
            &row_with(&id, 3, "a stale peer's text", STALE, 9, &json!({})),
            false,
        )
        .expect("merge");
        assert_eq!(version_of(&conn, &id), before + 1);
    }

    #[test]
    fn sqlite_bookkeeping_only_difference_does_not_bump_4216() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        let before = version_of(&conn, &id);
        // Differs ONLY in merge bookkeeping and recall bookkeeping.
        let mut remote = row_with(
            &id,
            3,
            "A's concurrent edit",
            STALE,
            5,
            &json!({
                "crdt_field_clocks": {"row": 7, "leaves": {"/content": [5, "x"]}},
                "version_vector": {"entries": {"node-b": "2026-09-22T00:00:00Z"}},
            }),
        );
        remote.access_count = 40;
        db::merge_inbound(&conn, &remote, false).expect("merge");
        assert_eq!(
            version_of(&conn, &id),
            before,
            "crdt_field_clocks / version_vector / access_count are not user data"
        );
    }

    #[test]
    fn sqlite_an_i64_max_push_is_clamped_not_pinned_4218() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        db::merge_inbound(
            &conn,
            &row(&id, i64::MAX, "B's concurrent edit", &soon()),
            false,
        )
        .expect("merge");
        let v = version_of(&conn, &id);
        assert!(v <= 3 + JUMP + 1, "#4218: the peer pinned version at {v}");
        // The row stays editable.
        edit(&conn, &id, "local edit after the push", v).expect("local edit");
        let id2 = node_a_at_v3(&conn);
        db::insert_if_newer(&conn, &row(&id2, i64::MAX, "B's concurrent edit", &soon()))
            .expect("push");
        assert!(version_of(&conn, &id2) <= 3 + JUMP + 1);
    }

    #[test]
    fn sqlite_a_legitimate_push_inside_the_bound_applies_4218() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        db::merge_inbound(&conn, &row(&id, 40, "B's concurrent edit", &soon()), false)
            .expect("merge");
        assert_eq!(version_of(&conn, &id), 41, "GREATEST(3, 40) + 1");
    }

    #[test]
    fn sqlite_the_receive_validation_refuses_the_i64_max_pin_4218() {
        let err = ai_memory::validate::validate_memory(&row("m", i64::MAX, "c", STALE))
            .expect_err("i64::MAX must be refused");
        assert!(err.to_string().contains("replicated version"), "{err}");
        assert!(ai_memory::validate::validate_memory(&row("m", 7, "c", STALE)).is_ok());
    }

    #[test]
    fn sqlite_a_local_update_at_the_version_ceiling_saturates_4218() {
        let (_dir, conn) = open();
        let id = node_a_at_v3(&conn);
        // A row poisoned before the bound existed.
        conn.execute(
            "UPDATE memories SET version = ?1 WHERE id = ?2",
            rusqlite::params![i64::MAX, id],
        )
        .expect("poison");
        edit(&conn, &id, "local edit", i64::MAX).expect("edit at the ceiling");
        let (v, ty): (i64, String) = conn
            .query_row(
                "SELECT version, typeof(version) FROM memories WHERE id = ?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("row");
        assert_eq!(ty, "integer", "#4218: the counter overflowed into a REAL");
        assert_eq!(v, i64::MAX);
    }
}

#[cfg(feature = "sal-postgres")]
mod pg {
    //! Live-postgres twins (`--ignored`, `AI_MEMORY_TEST_POSTGRES_URL` REQUIRED:
    //! an unset URL fails the cell, it never passes vacuously).
    use super::{AGENT, JUMP, STALE, row, row_with, soon};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};
    use serde_json::json;

    async fn connect() -> PostgresStore {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .expect("AI_MEMORY_TEST_POSTGRES_URL is required for the live-postgres cells");
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres")
    }

    fn ctx() -> CallerContext {
        CallerContext::for_agent(AGENT)
    }

    async fn edit(
        store: &PostgresStore,
        id: &str,
        content: &str,
        expected: i64,
    ) -> ai_memory::store::StoreResult<i64> {
        let patch = UpdatePatch {
            content: Some(content.to_string()),
            ..UpdatePatch::default()
        };
        store
            .update_with_expected_version(&ctx(), id, patch, Some(expected))
            .await
    }

    async fn version_of(store: &PostgresStore, id: &str) -> i64 {
        store.get(&ctx(), id).await.expect("read").version
    }

    /// Node A's row at version 3 (store = 1, then two local edits).
    async fn node_a_at_v3(store: &PostgresStore) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let base = row(&id, 1, "v1", &chrono::Utc::now().to_rfc3339());
        store.store(&ctx(), &base).await.expect("store");
        let v1 = version_of(store, &id).await;
        edit(store, &id, "v2 shared", v1).await.expect("edit to v2");
        edit(store, &id, "A's concurrent edit", v1 + 1)
            .await
            .expect("edit to v3");
        assert_eq!(version_of(store, &id).await, v1 + 2);
        id
    }

    /// The two pg apply funnels, so each cell runs on both.
    #[derive(Clone, Copy, Debug)]
    enum Funnel {
        ApplyRemote,
        MergeInbound,
    }

    async fn apply(store: &PostgresStore, f: Funnel, m: &Memory) {
        match f {
            Funnel::ApplyRemote => store.apply_remote_memory(&ctx(), m).await.map(|_| ()),
            Funnel::MergeInbound => store.merge_inbound(&ctx(), m, false).await.map(|_| ()),
        }
        .expect("apply");
    }

    use ai_memory::models::Memory;

    const FUNNELS: [Funnel; 2] = [Funnel::ApplyRemote, Funnel::MergeInbound];

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_stale_if_match_after_a_content_merge_is_refused_4216() {
        let store = connect().await;
        for f in FUNNELS {
            let id = node_a_at_v3(&store).await;
            let observed = version_of(&store, &id).await;
            apply(
                &store,
                f,
                &row(&id, observed, "B's concurrent edit", &soon()),
            )
            .await;
            let merged = store.get(&ctx(), &id).await.expect("read");
            assert_eq!(
                merged.content, "B's concurrent edit",
                "{f:?} precondition: LWW replaced A's content with B's"
            );
            let stale = edit(&store, &id, "stale overwrite", observed).await;
            let after = store.get(&ctx(), &id).await.expect("read");
            assert!(
                stale.is_err(),
                "#4216 {f:?}: If-Match {observed} passed after a merge replaced the content \
                 (merged version {}); B's edit was overwritten: {:?}",
                merged.version,
                after.content
            );
            assert_eq!(after.content, "B's concurrent edit", "#4216: lost update");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_idempotent_redelivery_does_not_bump_4216() {
        let store = connect().await;
        for f in FUNNELS {
            let id = node_a_at_v3(&store).await;
            let v = version_of(&store, &id).await;
            let remote = row(&id, v, "B's concurrent edit", &soon());
            apply(&store, f, &remote).await;
            let once = version_of(&store, &id).await;
            assert_eq!(once, v + 1, "{f:?}: GREATEST + 1 for the content change");
            apply(&store, f, &remote).await;
            assert_eq!(
                version_of(&store, &id).await,
                once,
                "{f:?}: a replay of the same row moved the version"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_losing_push_bumps_only_when_user_data_changes_4216() {
        let store = connect().await;
        for f in FUNNELS {
            let id = node_a_at_v3(&store).await;
            let before = version_of(&store, &id).await;
            apply(&store, f, &row(&id, before, "a stale peer's text", STALE)).await;
            assert_eq!(
                version_of(&store, &id).await,
                before,
                "{f:?}: a losing push that changed nothing must not bump"
            );
            apply(
                &store,
                f,
                &row_with(&id, before, "a stale peer's text", STALE, 9, &json!({})),
            )
            .await;
            let after = store.get(&ctx(), &id).await.expect("read");
            assert_eq!(after.priority, 9, "{f:?}: the MAX arm raised priority");
            assert_eq!(after.version, before + 1, "{f:?}: a data change must bump");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_bookkeeping_only_difference_does_not_bump_4216() {
        let store = connect().await;
        for f in FUNNELS {
            let id = node_a_at_v3(&store).await;
            let before = version_of(&store, &id).await;
            let mut remote = row_with(
                &id,
                before,
                "A's concurrent edit",
                STALE,
                5,
                &json!({
                    "crdt_field_clocks": {"row": 7, "leaves": {"/content": [5, "x"]}},
                    "version_vector": {"entries": {"node-b": "2026-09-22T00:00:00Z"}},
                }),
            );
            remote.access_count = 40;
            apply(&store, f, &remote).await;
            assert_eq!(
                version_of(&store, &id).await,
                before,
                "{f:?}: crdt_field_clocks / version_vector / access_count are not user data"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_an_i64_max_push_is_clamped_not_pinned_4218() {
        let store = connect().await;
        for f in FUNNELS {
            let id = node_a_at_v3(&store).await;
            let before = version_of(&store, &id).await;
            apply(
                &store,
                f,
                &row(&id, i64::MAX, "B's concurrent edit", &soon()),
            )
            .await;
            let v = version_of(&store, &id).await;
            assert!(
                v <= before + JUMP + 1,
                "#4218 {f:?}: the peer pinned version at {v}"
            );
            edit(&store, &id, "local edit after the push", v)
                .await
                .expect("the row stays editable");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_a_legitimate_push_inside_the_bound_applies_4218() {
        let store = connect().await;
        for f in FUNNELS {
            let id = node_a_at_v3(&store).await;
            let before = version_of(&store, &id).await;
            apply(
                &store,
                f,
                &row(&id, before + 37, "B's concurrent edit", &soon()),
            )
            .await;
            assert_eq!(
                version_of(&store, &id).await,
                before + 38,
                "{f:?}: GREATEST + 1"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_a_local_update_at_the_version_ceiling_fails_cleanly_4218() {
        let store = connect().await;
        let id = node_a_at_v3(&store).await;
        // A row poisoned before the bound existed (bigint already at the edge).
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("url");
        let pool = sqlx::PgPool::connect(&url).await.expect("pool");
        sqlx::query("UPDATE memories SET version = $1 WHERE id = $2")
            .bind(i64::MAX)
            .bind(&id)
            .execute(&pool)
            .await
            .expect("poison");
        let res = edit(&store, &id, "local edit", i64::MAX).await;
        assert!(res.is_err(), "the overflowing +1 must fail, not wrap");
        let after = store.get(&ctx(), &id).await.expect("read");
        assert_eq!(after.version, i64::MAX, "the failed update changed nothing");
        assert_eq!(after.content, "A's concurrent edit");
    }
}
