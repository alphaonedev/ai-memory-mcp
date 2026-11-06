// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4206 — the federation title-slot newer-wins merge must leave the
//! overwritten local text recoverable.
//!
//! An inbound row whose id is ABSENT locally falls through to the
//! `(title, namespace)` newer-wins upsert (sqlite `insert_if_newer`, postgres
//! `apply_remote_memory`). When it wins the LWW tiebreak it rewrites the local
//! row's text in place. #1773 / #3961 snapshot the pre-merge row on the
//! same-id lane; this pins the SAME `federation_merge` archive snapshot on the
//! title-slot lane, on both backends, with the #4035 rule: only when the text
//! actually changes (a replay must not replace the last recoverable preimage).
//!
//! Cells (each backend):
//! * a newer inbound with new text → the local row's pre-merge text is in
//!   `archived_memories` under `federation_merge`, keyed by the LOCAL id;
//! * a losing (older) inbound → no archive, local text unchanged;
//! * a newer inbound carrying the SAME text as the live row (a replay) → the
//!   earlier snapshot is not replaced.

use ai_memory::models::{Memory, Tier};
use serde_json::json;

const AGENT: &str = "ai:owner-4206";
const OLD_TS: &str = "2026-01-01T00:00:00+00:00";
const MID_TS: &str = "2026-02-01T00:00:00+00:00";
const NEW_TS: &str = "2026-03-01T00:00:00+00:00";

fn mem(ns: &str, title: &str, content: &str, updated_at: &str) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: title.to_string(),
        content: content.to_string(),
        namespace: ns.to_string(),
        tier: Tier::Long,
        metadata: json!({"agent_id": AGENT, "scope": "collective"}),
        created_at: OLD_TS.to_string(),
        updated_at: updated_at.to_string(),
        ..Memory::default()
    }
}

mod sqlite_side {
    use super::{MID_TS, NEW_TS, OLD_TS, mem};
    use ai_memory::models::field_names::ARCHIVE_REASON_FEDERATION_MERGE;
    use rusqlite::OptionalExtension as _;

    fn open() -> (tempfile::TempDir, rusqlite::Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = ai_memory::db::open(&dir.path().join("m4206.db")).expect("open");
        (dir, conn)
    }

    fn archived(conn: &rusqlite::Connection, id: &str) -> Option<(String, String)> {
        conn.query_row(
            "SELECT content, archive_reason FROM archived_memories WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .expect("archive probe")
    }

    fn live_content(conn: &rusqlite::Connection, id: &str) -> String {
        conn.query_row("SELECT content FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .expect("live row")
    }

    #[test]
    fn title_slot_merge_snapshots_the_overwritten_local_text_4206() {
        let (_dir, conn) = open();
        let local = mem("fed4206", "shared title", "LOCAL-A", OLD_TS);
        let local_id = ai_memory::db::insert(&conn, &local).expect("seed local");

        let inbound = mem("fed4206", "shared title", "REMOTE-B", NEW_TS);
        let applied = ai_memory::db::insert_if_newer(&conn, &inbound).expect("merge");
        assert_eq!(
            applied, local_id,
            "the inbound folds into the local title slot"
        );
        assert_eq!(live_content(&conn, &local_id), "REMOTE-B", "remote won");

        let snap = archived(&conn, &local_id);
        assert_eq!(
            snap,
            Some((
                "LOCAL-A".to_string(),
                ARCHIVE_REASON_FEDERATION_MERGE.to_string()
            )),
            "#4206: the overwritten local text must be recoverable from the archive"
        );
    }

    #[test]
    fn losing_inbound_writes_no_archive_4206() {
        let (_dir, conn) = open();
        let local = mem("fed4206", "t-lose", "LOCAL-A", NEW_TS);
        let local_id = ai_memory::db::insert(&conn, &local).expect("seed local");
        let stale = mem("fed4206", "t-lose", "STALE-B", OLD_TS);
        ai_memory::db::insert_if_newer(&conn, &stale).expect("merge");
        assert_eq!(live_content(&conn, &local_id), "LOCAL-A", "local kept");
        assert_eq!(
            archived(&conn, &local_id),
            None,
            "a losing inbound archives nothing"
        );
    }

    #[test]
    fn identical_replay_keeps_the_prior_snapshot_4206() {
        let (_dir, conn) = open();
        let local = mem("fed4206", "t-replay", "LOCAL-A", OLD_TS);
        let local_id = ai_memory::db::insert(&conn, &local).expect("seed local");
        let first = mem("fed4206", "t-replay", "REMOTE-B", MID_TS);
        ai_memory::db::insert_if_newer(&conn, &first).expect("merge 1");
        // A newer replay of the SAME text (different peer id, newer timestamp)
        // wins the tiebreak but changes nothing: the A snapshot must survive.
        let replay = mem("fed4206", "t-replay", "REMOTE-B", NEW_TS);
        ai_memory::db::insert_if_newer(&conn, &replay).expect("merge 2");
        assert_eq!(live_content(&conn, &local_id), "REMOTE-B");
        assert_eq!(
            archived(&conn, &local_id).map(|(c, _)| c).as_deref(),
            Some("LOCAL-A"),
            "a no-change replay must not replace the last recoverable preimage"
        );
    }
}

#[cfg(feature = "sal-postgres")]
mod postgres_side {
    use super::{MID_TS, NEW_TS, OLD_TS, mem};
    use ai_memory::models::field_names::ARCHIVE_REASON_FEDERATION_MERGE;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        // A configured-but-unreachable server must FAIL the cell, not skip it:
        // a silent `None` here made these cells vacuously green (#4206).
        Some(
            PostgresStore::connect(&url)
                .await
                .expect("AI_MEMORY_TEST_POSTGRES_URL is set but the connect failed"),
        )
    }

    async fn archived(pg: &PostgresStore, id: &str) -> Option<(String, String)> {
        sqlx::query_as::<_, (String, String)>(
            "SELECT content, archive_reason FROM archived_memories WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pg.pool())
        .await
        .expect("archive probe")
    }

    async fn live_content(pg: &PostgresStore, id: &str) -> String {
        sqlx::query_scalar::<_, String>("SELECT content FROM memories WHERE id = $1")
            .bind(id)
            .fetch_one(pg.pool())
            .await
            .expect("live row")
    }

    async fn cleanup(pg: &PostgresStore, ns: &str) {
        for sql in [
            "DELETE FROM archived_memories WHERE namespace = $1",
            "DELETE FROM memories WHERE namespace = $1",
        ] {
            let _ = sqlx::query(sql).bind(ns).execute(pg.pool()).await;
        }
    }

    fn ns() -> String {
        format!("pg4206-{}", uuid::Uuid::new_v4().simple())
    }

    #[tokio::test]
    async fn pg_title_slot_merge_snapshots_the_overwritten_local_text_4206() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = CallerContext::for_admin("pg-4206");
        let ns = ns();
        let local_id = MemoryStore::apply_remote_memory(
            &pg,
            &ctx,
            &mem(&ns, "shared title", "LOCAL-A", OLD_TS),
        )
        .await
        .expect("seed local");
        let applied = MemoryStore::apply_remote_memory(
            &pg,
            &ctx,
            &mem(&ns, "shared title", "REMOTE-B", NEW_TS),
        )
        .await
        .expect("merge");
        assert_eq!(
            applied, local_id,
            "the inbound folds into the local title slot"
        );
        assert_eq!(live_content(&pg, &local_id).await, "REMOTE-B", "remote won");
        let snap = archived(&pg, &local_id).await;
        cleanup(&pg, &ns).await;
        assert_eq!(
            snap,
            Some((
                "LOCAL-A".to_string(),
                ARCHIVE_REASON_FEDERATION_MERGE.to_string()
            )),
            "#4206: the overwritten local text must be recoverable from the archive"
        );
    }

    #[tokio::test]
    async fn pg_losing_inbound_and_identical_replay_4206() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = CallerContext::for_admin("pg-4206");
        let ns = ns();
        // Losing inbound: nothing archived, local kept.
        let keep =
            MemoryStore::apply_remote_memory(&pg, &ctx, &mem(&ns, "t-lose", "LOCAL-A", NEW_TS))
                .await
                .expect("seed");
        MemoryStore::apply_remote_memory(&pg, &ctx, &mem(&ns, "t-lose", "STALE-B", OLD_TS))
            .await
            .expect("stale");
        let lose_content = live_content(&pg, &keep).await;
        let lose_archive = archived(&pg, &keep).await;
        // Replay: the first win snapshots A; a newer same-text replay keeps it.
        let rid =
            MemoryStore::apply_remote_memory(&pg, &ctx, &mem(&ns, "t-replay", "LOCAL-A", OLD_TS))
                .await
                .expect("seed");
        MemoryStore::apply_remote_memory(&pg, &ctx, &mem(&ns, "t-replay", "REMOTE-B", MID_TS))
            .await
            .expect("merge 1");
        MemoryStore::apply_remote_memory(&pg, &ctx, &mem(&ns, "t-replay", "REMOTE-B", NEW_TS))
            .await
            .expect("merge 2");
        let replay_archive = archived(&pg, &rid).await.map(|(c, _)| c);
        cleanup(&pg, &ns).await;
        assert_eq!(lose_content, "LOCAL-A", "local kept");
        assert_eq!(lose_archive, None, "a losing inbound archives nothing");
        assert_eq!(
            replay_archive.as_deref(),
            Some("LOCAL-A"),
            "a no-change replay must not replace the last recoverable preimage"
        );
    }
}
