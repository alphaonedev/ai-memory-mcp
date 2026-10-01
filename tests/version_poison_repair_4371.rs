// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4371 (data-integrity, ga-blocker) — rows whose `memories.version` a peer
//! pinned at or near `i64::MAX` BEFORE the #4218 inbound bound.
//!
//! Before: sqlite saturates the local `+ 1`, so the row edits but its
//! `If-Match` token is frozen (a lost update goes unfenced); postgres refuses
//! every edit (the row is un-editable); a JSON client cannot even represent
//! the value (> 2^53). After: the v101 ladder step clamps every counter above
//! `MAX_REPLICATED_VERSION` (2^40) in `memories` AND `archived_memories`
//! (text, `updated_at` and every other column untouched) and a sqlite edit at
//! the `i64::MAX` ceiling is refused like postgres.
//!
//! Each cell seeds the poison with raw SQL (the inbound bound now refuses it
//! on every write funnel), rewinds the schema stamp to v100 and reopens so the
//! ladder runs, exactly as an upgrade of a legacy database does.

#![cfg(feature = "sal")]

use ai_memory::models::Memory;
use ai_memory::models::replicated_version::MAX_REPLICATED_VERSION;
use serde_json::json;

const AGENT: &str = "ai:alice-4371";
const CEILING: i64 = MAX_REPLICATED_VERSION;

fn row(id: &str, title: &str, version: i64, content: &str, updated_at: &str) -> Memory {
    serde_json::from_value(json!({
        "id": id,
        "tier": "long",
        "namespace": "fit-4371",
        "title": title,
        "content": content,
        "tags": ["poison"],
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

fn soon() -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(2)).to_rfc3339()
}

mod sqlite {
    use super::{CEILING, row, soon};
    use ai_memory::db;
    use rusqlite::{Connection, params};

    fn edit(
        conn: &Connection,
        id: &str,
        content: &str,
        expected: Option<i64>,
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
            expected,
            None,
        )
    }

    fn version_of(conn: &Connection, id: &str) -> i64 {
        db::get_any(conn, id).expect("read").expect("row").version
    }

    /// Rewind the schema stamp so the next open runs the ladder from v100.
    fn rewind_to_v100(conn: &Connection) {
        conn.execute("DELETE FROM schema_version", [])
            .expect("clear");
        conn.execute("INSERT INTO schema_version (version) VALUES (100)", [])
            .expect("stamp v100");
    }

    fn seed(conn: &Connection, title: &str, version: i64) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        db::insert(
            conn,
            &row(
                &id,
                title,
                1,
                "original text",
                &chrono::Utc::now().to_rfc3339(),
            ),
        )
        .expect("insert");
        conn.execute(
            "UPDATE memories SET version = ?1 WHERE id = ?2",
            params![version, id],
        )
        .expect("poison");
        id
    }

    fn open_poisoned(versions: &[i64]) -> (tempfile::TempDir, std::path::PathBuf, Vec<String>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("m.db");
        let conn = db::open(&path).expect("open");
        let ids: Vec<String> = versions
            .iter()
            .enumerate()
            .map(|(i, v)| seed(&conn, &format!("poison row {i}"), *v))
            .collect();
        rewind_to_v100(&conn);
        drop(conn);
        (dir, path, ids)
    }

    #[test]
    fn sqlite_v101_repair_clamps_poisoned_rows_and_loses_nothing_4371() {
        let versions = [i64::MAX, i64::MAX - 1, CEILING + 1, CEILING, 5];
        let (_dir, path, ids) = open_poisoned(&versions);
        let before = Connection::open(&path).expect("raw");
        let snap = |id: &str| -> (String, String, String, String) {
            before
                .query_row(
                    "SELECT title, content, tags, updated_at FROM memories WHERE id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .expect("snap")
        };
        let text_before: Vec<_> = ids.iter().map(|i| snap(i)).collect();
        drop(before);

        let conn = db::open(&path).expect("reopen runs the v101 ladder step");
        let want = [CEILING, CEILING, CEILING, CEILING, 5];
        for ((id, want), (i, text)) in ids.iter().zip(want).zip(text_before.iter().enumerate()) {
            assert_eq!(
                version_of(&conn, id),
                want,
                "#4371: row {i} (seeded {}) not repaired",
                versions[i]
            );
            let (t, c, g, u) = conn
                .query_row(
                    "SELECT title, content, tags, updated_at FROM memories WHERE id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .expect("after");
            assert_eq!(
                &(t, c, g, u),
                text,
                "#4371: repair rewrote more than the counter"
            );
        }
        let stamp: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .expect("stamp");
        assert_eq!(stamp, 101, "the ladder reaches the v101 tip");

        // Idempotent: reopen again, nothing moves.
        drop(conn);
        let conn = db::open(&path).expect("second open");
        for (id, want) in ids.iter().zip(want) {
            assert_eq!(
                version_of(&conn, id),
                want,
                "#4371: second open moved a counter"
            );
        }
    }

    #[test]
    fn sqlite_v101_repair_rewrites_a_real_typed_poisoned_counter_4371() {
        let (_dir, path, ids) = open_poisoned(&[7]);
        let raw = Connection::open(&path).expect("raw");
        // The pre-#4218 sqlite overflow turned the column into a REAL.
        raw.execute(
            "UPDATE memories SET version = 9.3e18 WHERE id = ?1",
            params![ids[0]],
        )
        .expect("real");
        let ty: String = raw
            .query_row(
                "SELECT typeof(version) FROM memories WHERE id = ?1",
                params![ids[0]],
                |r| r.get(0),
            )
            .expect("typeof");
        assert_eq!(ty, "real", "precondition: the poisoned counter is a REAL");
        drop(raw);
        let conn = db::open(&path).expect("reopen");
        assert_eq!(
            version_of(&conn, &ids[0]),
            CEILING,
            "#4371: REAL not repaired"
        );
    }

    #[test]
    fn sqlite_repaired_row_is_editable_with_a_moving_if_match_token_4371() {
        let (_dir, path, ids) = open_poisoned(&[i64::MAX]);
        let conn = db::open(&path).expect("reopen");
        let id = &ids[0];
        let t0 = version_of(&conn, id);
        assert_eq!(t0, CEILING, "#4371: poisoned row not repaired");
        edit(&conn, id, "edit one", Some(t0)).expect("edit at the repaired token");
        let t1 = version_of(&conn, id);
        assert_eq!(t1, t0 + 1, "#4371: the token must move");
        // The old token no longer passes: the lost update is fenced.
        let stale = edit(&conn, id, "stale overwrite", Some(t0));
        assert!(
            stale.is_err(),
            "#4371: a stale If-Match passed (frozen token)"
        );
        let now = db::get_any(&conn, id).expect("read").expect("row");
        assert_eq!(now.content, "edit one", "#4371: lost update");
        edit(&conn, id, "edit two", Some(t1)).expect("second edit");
        assert_eq!(version_of(&conn, id), t1 + 1);
    }

    #[test]
    fn sqlite_merge_onto_a_repaired_row_moves_the_token_4371() {
        let (_dir, path, ids) = open_poisoned(&[i64::MAX]);
        let conn = db::open(&path).expect("reopen");
        let id = &ids[0];
        let observed = version_of(&conn, id);
        let title: String = conn
            .query_row(
                "SELECT title FROM memories WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .expect("title");
        db::insert_if_newer(&conn, &row(id, &title, 3, "peer edit", &soon())).expect("merge");
        let merged = db::get_any(&conn, id).expect("read").expect("row");
        assert_eq!(merged.content, "peer edit", "precondition: LWW applied");
        assert!(
            merged.version > observed,
            "#4371: a content merge left the token at {} (observed {observed}); a stale \
             If-Match would pass",
            merged.version
        );
        assert!(edit(&conn, id, "stale overwrite", Some(observed)).is_err());
    }

    #[test]
    fn sqlite_restore_of_a_poisoned_archived_row_is_bounded_4371() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("m.db");
        let conn = db::open(&path).expect("open");
        let id = seed(&conn, "archived poison", 3);
        assert!(db::archive_memory(&conn, &id, Some("test")).expect("archive"));
        conn.execute(
            "UPDATE archived_memories SET version = ?1 WHERE id = ?2",
            params![i64::MAX, id],
        )
        .expect("poison archived");
        rewind_to_v100(&conn);
        drop(conn);
        let conn = db::open(&path).expect("reopen");
        let archived: i64 = conn
            .query_row(
                "SELECT version FROM archived_memories WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .expect("archived version");
        assert_eq!(archived, CEILING, "#4371: archived counter not repaired");
        assert!(db::restore_archived(&conn, &id).expect("restore"));
        let live = version_of(&conn, &id);
        assert_eq!(
            live, CEILING,
            "#4371: restore carried a poisoned counter back"
        );
        edit(&conn, &id, "post-restore edit", Some(live)).expect("restored row is editable");
    }

    /// Sibling counter (`access_count`, peer-pushable, merged as a max): a
    /// value pinned at `i64::MAX` must not break the recall touch. Control on
    /// sqlite (the `MIN(.., 1000000)` clamp already holds); red on postgres.
    #[test]
    fn sqlite_touch_with_access_count_pinned_at_i64_max_is_bounded_4371() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = db::open(&dir.path().join("m.db")).expect("open");
        let id = seed(&conn, "access pinned", 1);
        conn.execute(
            "UPDATE memories SET access_count = ?1 WHERE id = ?2",
            params![i64::MAX, id],
        )
        .expect("pin");
        db::touch(&conn, &id, 3600, 86400).expect("touch must not fail");
        let n: i64 = conn
            .query_row(
                "SELECT access_count FROM memories WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(n, 1_000_000, "#4371: access_count not bounded");
    }

    #[test]
    fn sqlite_update_at_the_i64_max_ceiling_is_refused_not_frozen_4371() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = db::open(&dir.path().join("m.db")).expect("open");
        let id = seed(&conn, "ceiling row", i64::MAX - 1);
        // One below the ceiling still moves (to the ceiling).
        edit(&conn, &id, "last edit", Some(i64::MAX - 1)).expect("edit below ceiling");
        assert_eq!(version_of(&conn, &id), i64::MAX);
        let archived_before: i64 = conn
            .query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
            .expect("count");
        // At the ceiling the edit is REFUSED (postgres parity); nothing changes.
        for expected in [None, Some(i64::MAX)] {
            let err = edit(&conn, &id, "never lands", expected)
                .expect_err("#4371: an edit at i64::MAX succeeded with a frozen token");
            assert!(
                err.to_string().contains("version counter exhausted"),
                "#4371: wrong refusal: {err}"
            );
            let row = db::get_any(&conn, &id).expect("read").expect("row");
            assert_eq!((row.content.as_str(), row.version), ("last edit", i64::MAX));
        }
        let archived_after: i64 = conn
            .query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
            .expect("count");
        assert_eq!(
            archived_before, archived_after,
            "#4371: a refused edit left a partial archive row"
        );
        // A stale token at the ceiling is still a version conflict, not exhaustion.
        let err = edit(&conn, &id, "stale", Some(3)).expect_err("stale token");
        assert!(
            err.downcast_ref::<ai_memory::db::VersionConflict>()
                .is_some(),
            "#4371: a stale token must stay a VersionConflict, got {err}"
        );
    }
}

#[cfg(feature = "sal-postgres")]
mod pg {
    //! Live-postgres twins (`--ignored`, `AI_MEMORY_TEST_POSTGRES_URL` REQUIRED:
    //! an unset URL fails the cell, it never passes vacuously).
    use super::{AGENT, CEILING, row, soon};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

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

    /// Store a row, poison its counter (live and archived twin) with raw SQL,
    /// then rewind the schema stamp so the next connect runs the v101 step.
    async fn poison(version: i64) -> (String, String) {
        let store = connect().await;
        let id = uuid::Uuid::new_v4().to_string();
        let title = format!("poison {id}");
        store
            .store(
                &ctx(),
                &row(
                    &id,
                    &title,
                    1,
                    "original text",
                    &chrono::Utc::now().to_rfc3339(),
                ),
            )
            .await
            .expect("store");
        sqlx::query("UPDATE memories SET version = $1 WHERE id = $2")
            .bind(version)
            .bind(&id)
            .execute(store.pool())
            .await
            .expect("poison");
        (id, title)
    }

    async fn rewind_to_v100(store: &PostgresStore) {
        sqlx::query("DELETE FROM schema_version WHERE version > 100")
            .execute(store.pool())
            .await
            .expect("rewind");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_v101_repair_clamps_poisoned_rows_and_loses_nothing_4371() {
        let mut seeded = Vec::new();
        for v in [i64::MAX, i64::MAX - 1, CEILING + 1, CEILING, 5] {
            seeded.push((v, poison(v).await));
        }
        let store = connect().await;
        let before: Vec<(String, String)> = {
            let mut out = Vec::new();
            for (_, (id, _)) in &seeded {
                let m = store.get(&ctx(), id).await.expect("read");
                out.push((m.content.clone(), m.updated_at.clone()));
            }
            out
        };
        // An archived twin carrying the poison too.
        let (aid, _) = &seeded[0].1;
        sqlx::query(
            "INSERT INTO archived_memories (id, tier, namespace, title, content, tags, priority, \
             confidence, source, access_count, created_at, updated_at, archived_at, version) \
             SELECT id || '-arch', tier, namespace, title || '-arch', content, tags, priority, \
             confidence, source, access_count, created_at, updated_at, NOW(), $2 \
             FROM memories WHERE id = $1",
        )
        .bind(aid)
        .bind(i64::MAX)
        .execute(store.pool())
        .await
        .expect("seed archived poison");
        rewind_to_v100(&store).await;
        drop(store);

        let store = connect().await; // reconnect runs the v101 ladder step
        for ((v, (id, _)), (content, updated_at)) in seeded.iter().zip(&before) {
            let want = if *v > CEILING { CEILING } else { *v };
            assert_eq!(version_of(&store, id).await, want, "#4371: seeded {v}");
            let m = store.get(&ctx(), id).await.expect("read");
            assert_eq!(&m.content, content, "#4371: repair rewrote content");
            assert_eq!(&m.updated_at, updated_at, "#4371: repair moved updated_at");
        }
        let archived: i64 =
            sqlx::query_scalar("SELECT version FROM archived_memories WHERE id = $1")
                .bind(format!("{aid}-arch"))
                .fetch_one(store.pool())
                .await
                .expect("archived version");
        assert_eq!(archived, CEILING, "#4371: archived counter not repaired");
        let stamp: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
            .fetch_one(store.pool())
            .await
            .expect("stamp");
        assert_eq!(stamp, 101);

        // Idempotent: another connect changes nothing.
        drop(store);
        let store = connect().await;
        let (id0, _) = &seeded[0].1;
        assert_eq!(version_of(&store, id0).await, CEILING);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_repaired_row_is_editable_with_a_moving_if_match_token_4371() {
        let (id, _) = poison(i64::MAX).await;
        let store = connect().await;
        // Before the repair the row is un-editable (checked add refuses).
        rewind_to_v100(&store).await;
        drop(store);
        let store = connect().await;
        let t0 = version_of(&store, &id).await;
        assert_eq!(t0, CEILING, "#4371: poisoned row not repaired");
        let t1 = edit(&store, &id, "edit one", t0)
            .await
            .expect("#4371: repaired row must be editable");
        assert_eq!(t1, t0 + 1, "#4371: the token must move");
        assert!(
            edit(&store, &id, "stale overwrite", t0).await.is_err(),
            "#4371: a stale If-Match passed"
        );
        assert_eq!(
            store.get(&ctx(), &id).await.expect("read").content,
            "edit one"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_merge_onto_a_repaired_row_moves_the_token_4371() {
        let (id, title) = poison(i64::MAX).await;
        let store = connect().await;
        rewind_to_v100(&store).await;
        drop(store);
        let store = connect().await;
        let observed = version_of(&store, &id).await;
        store
            .apply_remote_memory(&ctx(), &row(&id, &title, 3, "peer edit", &soon()))
            .await
            .expect("apply");
        let merged = store.get(&ctx(), &id).await.expect("read");
        assert_eq!(merged.content, "peer edit", "precondition: LWW applied");
        assert!(
            merged.version > observed,
            "#4371: merge left the token at {} (observed {observed})",
            merged.version
        );
        assert!(
            edit(&store, &id, "stale overwrite", observed)
                .await
                .is_err()
        );
    }

    /// Sibling counter: `access_count` pinned at `i64::MAX` (a replicated value
    /// the shared validation only requires to be non-negative) overflowed the
    /// postgres recall touch (`access_count + 1`), failing the statement on
    /// every recall of the row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_touch_and_fold_with_access_count_pinned_at_i64_max_are_bounded_4371() {
        let (id, _) = poison(5).await;
        let store = connect().await;
        sqlx::query("UPDATE memories SET access_count = $1 WHERE id = $2")
            .bind(i64::MAX)
            .bind(&id)
            .execute(store.pool())
            .await
            .expect("pin");
        store
            .touch_after_recall(std::slice::from_ref(&id))
            .await
            .expect("#4371: the recall touch must not overflow");
        let n: i64 = sqlx::query_scalar("SELECT access_count FROM memories WHERE id = $1")
            .bind(&id)
            .fetch_one(store.pool())
            .await
            .expect("count");
        assert_eq!(n, 1_000_000, "#4371: access_count not bounded");

        sqlx::query("UPDATE memories SET access_count = $1 WHERE id = $2")
            .bind(i64::MAX)
            .bind(&id)
            .execute(store.pool())
            .await
            .expect("re-pin");
        store
            .record_recall_observation(
                "rid-4371",
                &[(id.clone(), "hybrid".into(), 1, 0.5)],
                None,
                None,
            )
            .await
            .expect("observe");
        store
            .fold_recall_accesses()
            .await
            .expect("#4371: the access fold must not overflow");
        let n: i64 = sqlx::query_scalar("SELECT access_count FROM memories WHERE id = $1")
            .bind(&id)
            .fetch_one(store.pool())
            .await
            .expect("count");
        assert_eq!(n, 1_000_000, "#4371: folded access_count not bounded");
    }
}
