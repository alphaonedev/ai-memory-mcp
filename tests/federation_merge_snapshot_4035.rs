// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

//! #4035 — the SQLite same-`id` federation merge keeps ONE pre-merge recovery
//! snapshot per row (`archived_memories`, `archive_reason = federation_merge`,
//! `INSERT OR REPLACE` keyed by id). Pre-fix `overwrite_full_row_by_id`
//! archived the CURRENT live row on EVERY merge, with no check that the merge
//! changes anything: apply A→B (archive = A), redeliver B (the product does
//! this itself — `bulk_catchup_push` resends every committed row with a fresh
//! nonce) and the archive became a copy of B. The only recovery copy of A was
//! gone, and a LOSING older row (LWW discards it) destroyed it just the same.
//!
//! The contract pinned here: the snapshot is replaced ONLY when the merge
//! changes the row's logical text (title / plaintext content). A no-change
//! replay and a losing inbound leave the earlier snapshot in place; a
//! genuinely newer text rolls it forward. Every cell reads the archive row
//! back through plain SQL so the assertion is on the stored bytes.

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::storage;

mod common;
use common::fresh_db_tempfile_conn as fresh_db;

const NS: &str = "merge-snapshot-4035";
const ID: &str = "merge-snapshot-4035-row";

const T0: &str = "2026-06-16T00:00:00+00:00";
const T1: &str = "2026-06-16T01:00:00+00:00";
const T2: &str = "2026-06-16T02:00:00+00:00";
const T_OLDER: &str = "2026-06-15T00:00:00+00:00";

fn row(content: &str, updated_at: &str) -> Memory {
    Memory {
        id: ID.to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: "merge-snapshot-4035".to_string(),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: T0.to_string(),
        updated_at: updated_at.to_string(),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:origin-4035" }),
        version: 1,
        ..Memory::default()
    }
}

/// `(content, archive_reason)` of the row's recovery snapshot, if any.
fn snapshot(conn: &rusqlite::Connection) -> Option<(String, String)> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT content, archive_reason FROM archived_memories WHERE id = ?1",
        [ID],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .optional()
    .expect("read the archive slot")
}

fn live_content(conn: &rusqlite::Connection) -> String {
    conn.query_row("SELECT content FROM memories WHERE id = ?1", [ID], |r| {
        r.get::<_, String>(0)
    })
    .expect("live row present")
}

/// A→B then: replay B, a losing older row, then a genuinely newer C.
#[test]
fn replay_and_losing_merge_keep_the_pre_merge_snapshot_4035() {
    let (_tmp, conn) = fresh_db();
    storage::insert(&conn, &row("originalalpha", T0)).expect("seed A");

    // A → B (newer): the snapshot is A — the pre-#4035 contract, unchanged.
    storage::merge_inbound(&conn, &row("newerbeta", T1), false).expect("merge B");
    assert_eq!(live_content(&conn), "newerbeta");
    let (archived, reason) = snapshot(&conn).expect("A→B leaves a recovery snapshot");
    assert_eq!(reason, "federation_merge");
    assert_eq!(archived, "originalalpha", "the snapshot is the text B replaced");

    // Redeliver B byte-for-byte: nothing changes, so the snapshot must stay A.
    storage::merge_inbound(&conn, &row("newerbeta", T1), false).expect("replay B");
    assert_eq!(live_content(&conn), "newerbeta");
    assert_eq!(
        snapshot(&conn).map(|(c, _)| c).as_deref(),
        Some("originalalpha"),
        "#4035: a no-change replay must not overwrite the only recovery copy of A"
    );

    // A LOSING older row: LWW keeps B live, so the snapshot must still be A.
    storage::merge_inbound(&conn, &row("olderloser", T_OLDER), false).expect("merge loser");
    assert_eq!(live_content(&conn), "newerbeta", "LWW discards the older row");
    assert_eq!(
        snapshot(&conn).map(|(c, _)| c).as_deref(),
        Some("originalalpha"),
        "#4035: a losing inbound changes nothing and must not touch the snapshot"
    );

    // A genuinely newer C: the snapshot rolls forward to B.
    storage::merge_inbound(&conn, &row("newestgamma", T2), false).expect("merge C");
    assert_eq!(live_content(&conn), "newestgamma");
    assert_eq!(
        snapshot(&conn).map(|(c, _)| c).as_deref(),
        Some("newerbeta"),
        "a merge that changes the text replaces the snapshot with the text it replaced"
    );
}

/// A merge that changes only a non-text CRDT field (tags union) converges
/// that field and leaves the text snapshot alone.
#[test]
fn non_text_field_merge_converges_without_replacing_the_snapshot_4035() {
    let (_tmp, conn) = fresh_db();
    storage::insert(&conn, &row("originalalpha", T0)).expect("seed A");
    storage::merge_inbound(&conn, &row("newerbeta", T1), false).expect("merge B");

    let mut tagged = row("newerbeta", T2);
    tagged.tags = vec!["from-peer".to_string()];
    storage::merge_inbound(&conn, &tagged, false).expect("merge tags");

    let tags: String = conn
        .query_row("SELECT tags FROM memories WHERE id = ?1", [ID], |r| r.get(0))
        .expect("tags column");
    assert!(
        tags.contains("from-peer"),
        "the non-text field still converges (tags union): {tags}"
    );
    assert_eq!(
        snapshot(&conn).map(|(c, _)| c).as_deref(),
        Some("originalalpha"),
        "#4035: a merge that does not change title/content keeps the earlier snapshot"
    );
}
