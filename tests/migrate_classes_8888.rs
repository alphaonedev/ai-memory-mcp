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
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
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
                "UPDATE memories SET expires_at = ?1 WHERE id = ?2",
                params![PAST_EXPIRY, EXPIRED_ID],
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

    assert!(report.errors.is_empty(), "clean migrate: {:?}", report.errors);
    assert_eq!(report.memories_read, 2, "live + expired-unswept rows read");
    assert_eq!(report.memories_written, 2, "live + expired-unswept rows written");
    assert_eq!(report_usize(&value, "archived_read"), 1, "archived rows read");
    assert_eq!(report_usize(&value, "archived_written"), 1, "archived rows written");
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
    assert_eq!(expires.as_deref(), Some(PAST_EXPIRY), "expiry preserved");
    let dst_archive_row = dst
        .list_archived(None, PAGE, 0)
        .await
        .expect("destination archive listing")
        .into_iter()
        .find(|row| row["id"] == ARCHIVED_ID)
        .expect("archived row arrived");
    for key in ["archived_at", "archive_reason", "title", "content", "namespace"] {
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
    dst.store(&ctx, &mem("m-bob", SHARED_TITLE, FOREIGN_CONTENT, FOREIGN_AGENT))
        .await
        .expect("seed destination");

    let report = ai_memory::migrate::migrate(&src, &dst, PAGE, None, false).await;
    let value = serde_json::to_value(&report).expect("report serializes");

    assert_eq!(report.memories_read, 1);
    assert_eq!(report.memories_written, 0, "nothing folded into bob's row");
    assert_eq!(report_usize(&value, "cross_owner_kept"), 1, "refusal counted");
    assert!(report.errors.is_empty(), "a counted refusal is not an error");

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
