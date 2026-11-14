// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8888 / #8932 — `migrate` carries every row class and never folds into
//! another owner's row.
//!
//! Class invariant: `memories_read == memories_written + cross_owner_kept`
//! holds only when every source row reached the destination or is counted as
//! refused. That covers archived rows (the `archived_memories` table) and
//! expired rows GC has not swept yet, both of which the live-row `list` walk
//! never returned. A destination row of another owner holding the same
//! `(title, namespace)` slot is kept byte-for-byte and the refusal is counted.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};
use rusqlite::{Connection, params};

const NS: &str = "migrate8888";
const SOURCE_AGENT: &str = "alice";
const FOREIGN_AGENT: &str = "bob";
const SEED_ADMIN: &str = "ai:seed-8888";
const ARCHIVE_REASON: &str = "issue-8888 archived fixture";
const PAST_EXPIRY: &str = "2020-01-01T00:00:00Z";
const LIVE_ID: &str = "m-live";
const ARCHIVED_ID: &str = "m-archived";
const EXPIRED_ID: &str = "m-expired";
const SHARED_TITLE: &str = "shared slot title";
const FOREIGN_CONTENT: &str = "bob's private destination text";
const INCOMING_CONTENT: &str = "alice's incoming source text";
const PAGE: usize = 100;

fn mem(id: &str, title: &str, content: &str, owner: &str) -> Memory {
    mem_in(NS, id, title, content, owner)
}

fn mem_in(ns: &str, id: &str, title: &str, content: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "system".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": owner, "scope": "private" }),
        version: 1,
        ..Memory::default()
    }
}

/// Scratch dir under `.local-runs/` (project no-`/tmp` HARD RULE).
fn scratch(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-8888-migrate-classes");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn count(path: &std::path::Path, sql: &str) -> i64 {
    let conn = Connection::open(path).expect("raw open");
    conn.query_row(sql, [], |r| r.get(0)).expect("count query")
}

fn report_usize(report: &serde_json::Value, key: &str) -> u64 {
    report
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("migrate report carries no `{key}` counter: {report}"))
}

/// #8888 — an archived row and an expired-but-unswept row both arrive, with
/// their archive and expiry columns preserved, and the report counts them
/// against an independent per-table source count.
#[tokio::test]
async fn issue_8888_migrate_carries_archived_and_expired_unswept_rows() {
    let dir = scratch("classes");
    let src_path = dir.path().join("src.db");
    let dst_path = dir.path().join("dst.db");
    let src = SqliteStore::open(src_path.to_str().unwrap()).expect("open src");
    let dst = SqliteStore::open(dst_path.to_str().unwrap()).expect("open dst");
    let ctx = CallerContext::for_admin(SEED_ADMIN);

    for (id, title) in [
        (LIVE_ID, "live row"),
        (ARCHIVED_ID, "archived row"),
        (EXPIRED_ID, "expired row"),
    ] {
        src.store(&ctx, &mem(id, title, "durable text", SOURCE_AGENT))
            .await
            .expect("seed source row");
    }
    let archived = src
        .archive_by_ids(&ctx, &[ARCHIVED_ID.to_string()], Some(ARCHIVE_REASON))
        .await
        .expect("archive fixture row");
    assert_eq!(archived, 1, "fixture archives exactly one row");
    {
        let conn = Connection::open(&src_path).expect("raw open src");
        let n = conn
            .execute(
                // A Long row never carries an expiry (the store clears
                // it), so the expired-unswept fixture is a Mid row.
                "UPDATE memories SET expires_at = ?1, tier = ?2 WHERE id = ?3",
                params![PAST_EXPIRY, Tier::Mid.as_str(), EXPIRED_ID],
            )
            .expect("expire the fixture row");
        assert_eq!(n, 1, "fixture expires exactly one row");
    }
    let src_memories = count(&src_path, "SELECT COUNT(*) FROM memories");
    let src_archived = count(&src_path, "SELECT COUNT(*) FROM archived_memories");
    assert_eq!((src_memories, src_archived), (2, 1), "fixture shape");
    let src_archive_row = src
        .list_archived(None, PAGE, 0)
        .await
        .expect("source archive listing")
        .into_iter()
        .find(|row| row["id"] == ARCHIVED_ID)
        .expect("source archive row");

    let report = ai_memory::migrate::migrate(&src, &dst, PAGE, None, false).await;
    let value = serde_json::to_value(&report).expect("report serializes");

    assert!(
        report.errors.is_empty(),
        "clean migrate: {:?}",
        report.errors
    );
    assert_eq!(report.memories_read, 2, "live + expired-unswept rows read");
    assert_eq!(
        report.memories_written, 2,
        "live + expired-unswept rows written"
    );
    assert_eq!(
        report_usize(&value, "archived_read"),
        1,
        "archived rows read"
    );
    assert_eq!(
        report_usize(&value, "archived_written"),
        1,
        "archived rows written"
    );
    assert_eq!(
        count(&dst_path, "SELECT COUNT(*) FROM memories"),
        src_memories,
        "memories table per-table count matches the source"
    );
    assert_eq!(
        count(&dst_path, "SELECT COUNT(*) FROM archived_memories"),
        src_archived,
        "archived_memories table per-table count matches the source"
    );

    let dst_conn = Connection::open(&dst_path).expect("raw open dst");
    let expires: Option<String> = dst_conn
        .query_row(
            "SELECT expires_at FROM memories WHERE id = ?1",
            params![EXPIRED_ID],
            |r| r.get(0),
        )
        .expect("expired row arrived");
    // The store canonicalises RFC 3339 precision, so compare instants.
    let instant = |s: &str| chrono::DateTime::parse_from_rfc3339(s).expect("rfc3339 expiry");
    assert_eq!(
        expires.as_deref().map(instant),
        Some(instant(PAST_EXPIRY)),
        "expiry preserved"
    );
    let dst_archive_row = dst
        .list_archived(None, PAGE, 0)
        .await
        .expect("destination archive listing")
        .into_iter()
        .find(|row| row["id"] == ARCHIVED_ID)
        .expect("archived row arrived");
    for key in [
        "archived_at",
        "archive_reason",
        "title",
        "content",
        "namespace",
    ] {
        assert_eq!(
            dst_archive_row[key], src_archive_row[key],
            "archived row column `{key}` preserved"
        );
    }
    assert_eq!(dst_archive_row["archive_reason"], ARCHIVE_REASON);

    // Idempotent re-run: nothing new is written and nothing is lost.
    let rerun = ai_memory::migrate::migrate(&src, &dst, PAGE, None, false).await;
    assert!(rerun.errors.is_empty(), "clean re-run: {:?}", rerun.errors);
    assert_eq!(
        count(&dst_path, "SELECT COUNT(*) FROM archived_memories"),
        src_archived,
        "re-run does not duplicate the archived row"
    );
}

/// #8932 — the destination already holds bob's private row in the same
/// `(title, namespace)` slot. Migrating alice's row must keep bob's row
/// byte-for-byte and count the refusal; it must never fold into it.
#[tokio::test]
async fn issue_8932_migrate_keeps_foreign_owner_slot_holder() {
    let dir = scratch("foreign");
    let src_path = dir.path().join("src.db");
    let dst_path = dir.path().join("dst.db");
    let src = SqliteStore::open(src_path.to_str().unwrap()).expect("open src");
    let dst = SqliteStore::open(dst_path.to_str().unwrap()).expect("open dst");
    let ctx = CallerContext::for_admin(SEED_ADMIN);

    src.store(
        &ctx,
        &mem("m-alice", SHARED_TITLE, INCOMING_CONTENT, SOURCE_AGENT),
    )
    .await
    .expect("seed source");
    dst.store(
        &ctx,
        &mem("m-bob", SHARED_TITLE, FOREIGN_CONTENT, FOREIGN_AGENT),
    )
    .await
    .expect("seed destination");

    let report = ai_memory::migrate::migrate(&src, &dst, PAGE, None, false).await;
    let value = serde_json::to_value(&report).expect("report serializes");

    assert_eq!(report.memories_read, 1);
    assert_eq!(report.memories_written, 0, "nothing folded into bob's row");
    assert_eq!(
        report_usize(&value, "cross_owner_kept"),
        1,
        "refusal counted"
    );
    assert!(
        report.errors.is_empty(),
        "a counted refusal is not an error"
    );

    let conn = Connection::open(&dst_path).expect("raw open dst");
    let (content, meta): (String, String) = conn
        .query_row(
            "SELECT content, metadata FROM memories WHERE id = 'm-bob'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("bob's row still present");
    assert_eq!(content, FOREIGN_CONTENT, "bob's content kept");
    let meta: serde_json::Value = serde_json::from_str(&meta).expect("metadata json");
    assert_eq!(meta["agent_id"], FOREIGN_AGENT, "bob's ownership kept");
    assert_eq!(
        count(&dst_path, "SELECT COUNT(*) FROM memories"),
        1,
        "no second row minted either"
    );
}

/// Postgres cells. Each self-skips when `AI_MEMORY_TEST_POSTGRES_URL` is
/// unset; CI v2 runs them against a per-binary clone. Ids and the namespace
/// carry a per-run suffix so a shared database never collides, and every
/// migrate call is scoped to that namespace.
#[cfg(feature = "sal-postgres")]
mod postgres_cells {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    fn run_suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    /// #8888 on both backends: sqlite -> postgres carries the expired-unswept
    /// and archived rows, then postgres -> sqlite carries them back, so the
    /// postgres `list_expired_unswept`, archive read and archived insert all
    /// run. The expiry and archive columns survive both hops.
    #[tokio::test]
    async fn issue_8888_migrate_carries_archived_and_expired_rows_through_postgres() {
        let Some(url) = pg_url() else {
            eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let suffix = run_suffix();
        let ns = format!("{NS}-pg-{suffix}");
        let live_id = format!("{LIVE_ID}-{suffix}");
        let archived_id = format!("{ARCHIVED_ID}-{suffix}");
        let expired_id = format!("{EXPIRED_ID}-{suffix}");
        let dir = scratch("pg-classes");
        let src_path = dir.path().join("src.db");
        let back_path = dir.path().join("back.db");
        let src = SqliteStore::open(src_path.to_str().unwrap()).expect("open src");
        let back = SqliteStore::open(back_path.to_str().unwrap()).expect("open back");
        let pg = PostgresStore::connect(&url)
            .await
            .expect("connect postgres");
        let ctx = CallerContext::for_admin(SEED_ADMIN);

        for (id, title) in [
            (&live_id, "live row"),
            (&archived_id, "archived row"),
            (&expired_id, "expired row"),
        ] {
            src.store(&ctx, &mem_in(&ns, id, title, "durable text", SOURCE_AGENT))
                .await
                .expect("seed source row");
        }
        let archived = src
            .archive_by_ids(
                &ctx,
                std::slice::from_ref(&archived_id),
                Some(ARCHIVE_REASON),
            )
            .await
            .expect("archive fixture row");
        assert_eq!(archived, 1, "fixture archives exactly one row");
        {
            let conn = Connection::open(&src_path).expect("raw open src");
            let n = conn
                .execute(
                    "UPDATE memories SET expires_at = ?1, tier = ?2 WHERE id = ?3",
                    params![PAST_EXPIRY, Tier::Mid.as_str(), expired_id],
                )
                .expect("expire the fixture row");
            assert_eq!(n, 1, "fixture expires exactly one row");
        }

        for (hop, report) in [
            (
                "sqlite -> postgres",
                ai_memory::migrate::migrate(&src, &pg, PAGE, Some(ns.clone()), false).await,
            ),
            (
                "postgres -> sqlite",
                ai_memory::migrate::migrate(&pg, &back, PAGE, Some(ns.clone()), false).await,
            ),
        ] {
            let value = serde_json::to_value(&report).expect("report serializes");
            assert!(report.errors.is_empty(), "{hop}: {:?}", report.errors);
            assert_eq!(
                report.memories_read, 2,
                "{hop}: live + expired-unswept read"
            );
            assert_eq!(
                report.memories_written, 2,
                "{hop}: live + expired-unswept written"
            );
            assert_eq!(
                report_usize(&value, "archived_read"),
                1,
                "{hop}: archived read"
            );
            assert_eq!(
                report_usize(&value, "archived_written"),
                1,
                "{hop}: archived written"
            );
        }

        let conn = Connection::open(&back_path).expect("raw open back");
        let expires: Option<String> = conn
            .query_row(
                "SELECT expires_at FROM memories WHERE id = ?1",
                params![expired_id],
                |r| r.get(0),
            )
            .expect("expired row made the round trip");
        let instant = |s: &str| chrono::DateTime::parse_from_rfc3339(s).expect("rfc3339 expiry");
        assert_eq!(
            expires.as_deref().map(instant),
            Some(instant(PAST_EXPIRY)),
            "expiry preserved through postgres"
        );
        let row = back
            .list_archived(Some(&ns), PAGE, 0)
            .await
            .expect("archive listing")
            .into_iter()
            .find(|row| row["id"] == archived_id.as_str())
            .expect("archived row made the round trip");
        assert_eq!(row["archive_reason"], ARCHIVE_REASON);
    }

    /// #8932 on postgres: bob's private destination row in the same
    /// `(title, namespace)` slot is kept and the refusal is counted.
    #[tokio::test]
    async fn issue_8932_migrate_keeps_foreign_owner_slot_holder_on_postgres() {
        let Some(url) = pg_url() else {
            eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let suffix = run_suffix();
        let ns = format!("{NS}-pg-foreign-{suffix}");
        let bob_id = format!("m-bob-{suffix}");
        let dir = scratch("pg-foreign");
        let src_path = dir.path().join("src.db");
        let src = SqliteStore::open(src_path.to_str().unwrap()).expect("open src");
        let pg = PostgresStore::connect(&url)
            .await
            .expect("connect postgres");
        let ctx = CallerContext::for_admin(SEED_ADMIN);

        src.store(
            &ctx,
            &mem_in(
                &ns,
                &format!("m-alice-{suffix}"),
                SHARED_TITLE,
                INCOMING_CONTENT,
                SOURCE_AGENT,
            ),
        )
        .await
        .expect("seed source");
        pg.store(
            &ctx,
            &mem_in(&ns, &bob_id, SHARED_TITLE, FOREIGN_CONTENT, FOREIGN_AGENT),
        )
        .await
        .expect("seed postgres destination");

        let report = ai_memory::migrate::migrate(&src, &pg, PAGE, Some(ns.clone()), false).await;
        let value = serde_json::to_value(&report).expect("report serializes");
        assert_eq!(report.memories_read, 1);
        assert_eq!(report.memories_written, 0, "nothing folded into bob's row");
        assert_eq!(
            report_usize(&value, "cross_owner_kept"),
            1,
            "refusal counted"
        );
        assert!(
            report.errors.is_empty(),
            "a counted refusal is not an error"
        );

        let kept = pg
            .get(&ctx, &bob_id)
            .await
            .expect("bob's row still present");
        assert_eq!(kept.content, FOREIGN_CONTENT, "bob's content kept");
        assert_eq!(
            kept.metadata["agent_id"], FOREIGN_AGENT,
            "bob's ownership kept"
        );
        // `Filter` is #[non_exhaustive]: build it by field assignment.
        let mut filter = ai_memory::store::Filter::default();
        filter.namespace = Some(ns.clone());
        filter.limit = PAGE;
        let rows = pg.list(&ctx, &filter).await.expect("namespace listing");
        assert_eq!(rows.len(), 1, "no second row minted either");
    }
}
