// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4365 (WP-ERASURE #6048) — erasure completeness: a HARD forget
//! (`archive = false`), a hard delete-by-id, and a hard gc eviction must
//! not leave a same-id `archived_memories` snapshot (`in_place_edit`,
//! `federation_merge`) of the erased row's EARLIER text behind.
//!
//! Pre-fix every hard-erase funnel removed only the live `memories` row:
//! the #1725 pre-edit snapshot stayed at rest under the same id (with its
//! `cid_genesis` pre-image), and `archive restore <id>` brought the earlier
//! text back as a live row even though a signed FORGET tombstone had been
//! written for that id.
//!
//! The control cell pins the inverse: a SOFT forget (`archive = true`) is
//! a recoverable MOVE, so its `forget` archive row stays and restores.

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::path::PathBuf;

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use rusqlite::Connection;

const OLD_TEXT: &str = "#4365 EARLIER text that must not survive a hard erase";
const NEW_TEXT: &str = "#4365 live text at erase time";

fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("hard-erase-archive-snapshots-4365");
    std::fs::create_dir_all(&root).ok();
    root
}

fn fresh_db(tag: &str) -> Connection {
    let dir = tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(scratch_root())
        .expect("tempdir under .local-runs");
    let path = dir.path().join("db.sqlite");
    let conn = db::open(&path).expect("init db");
    std::mem::forget(dir); // keep the file alive for the test's connection
    conn
}

fn mem(id: &str, ns: &str, expires_at: Option<&str>) -> Memory {
    let now = "2026-07-20T00:00:00Z".to_string();
    Memory {
        id: id.into(),
        tier: Tier::Short,
        namespace: ns.into(),
        title: format!("title {id}"),
        content: OLD_TEXT.into(),
        priority: 5,
        confidence: 1.0,
        source: "system".into(),
        created_at: now.clone(),
        updated_at: now,
        expires_at: expires_at.map(str::to_string),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:4365" }),
        ..Memory::default()
    }
}

/// Insert the row and edit it in place so the #1725 `in_place_edit`
/// snapshot of `OLD_TEXT` lands in `archived_memories` under the SAME id
/// while the live row now holds `NEW_TEXT`.
fn seed_with_snapshot(conn: &Connection, id: &str, ns: &str, expires_at: Option<&str>) {
    db::insert(conn, &mem(id, ns, expires_at)).expect("insert");
    let (changed, _) = db::update(
        conn,
        id,
        None,
        Some(NEW_TEXT),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("in-place edit");
    assert!(changed, "fixture: the in-place edit landed");
    assert_eq!(
        archived_snapshot(conn, id),
        Some((OLD_TEXT.to_string(), "in_place_edit".to_string())),
        "fixture: the pre-edit snapshot is in archived_memories"
    );
}

/// `(content, archive_reason)` of the same-id archive row, if any.
fn archived_snapshot(conn: &Connection, id: &str) -> Option<(String, String)> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT content, archive_reason FROM archived_memories WHERE id = ?1",
        [id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .optional()
    .expect("probe archive")
}

fn live_content(conn: &Connection, id: &str) -> Option<String> {
    use rusqlite::OptionalExtension;
    conn.query_row("SELECT content FROM memories WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .optional()
    .expect("probe live")
}

/// Cell 1 — hard delete-by-id (`db::delete`, the `--hard` CLI path and the
/// trait `delete`): no same-id snapshot survives, restore has nothing.
#[test]
fn hard_delete_erases_the_same_id_archive_snapshot_4365() {
    let conn = fresh_db("hard-delete-");
    let id = "4365-hard-delete";
    seed_with_snapshot(&conn, id, "ns-4365-delete", None);

    assert!(db::delete(&conn, id).expect("hard delete"));
    assert!(
        db::memory_is_tombstoned(&conn, id).expect("probe"),
        "forget tombstone written"
    );
    assert_eq!(live_content(&conn, id), None, "live row erased");
    assert_eq!(
        archived_snapshot(&conn, id),
        None,
        "#4365: a hard delete must not leave the earlier text at rest under the same id"
    );
    assert!(
        !db::restore_archived(&conn, id).expect("restore"),
        "#4365: nothing to restore after a hard delete"
    );
    assert_eq!(live_content(&conn, id), None, "restore resurrected nothing");
}

/// Cell 2 — hard bulk forget (`archive = false`): same contract for every
/// victim of the forget set.
#[test]
fn hard_forget_erases_the_same_id_archive_snapshots_4365() {
    let conn = fresh_db("hard-forget-");
    let ns = "ns-4365-forget";
    seed_with_snapshot(&conn, "4365-fgt-a", ns, None);
    seed_with_snapshot(&conn, "4365-fgt-b", ns, None);

    let forgot = db::forget(&conn, Some(ns), None, None, false).expect("hard forget");
    assert_eq!(forgot, 2);
    for id in ["4365-fgt-a", "4365-fgt-b"] {
        assert!(db::memory_is_tombstoned(&conn, id).expect("probe"));
        assert_eq!(
            archived_snapshot(&conn, id),
            None,
            "#4365: hard forget must erase the same-id snapshot of {id}"
        );
        assert!(
            !db::restore_archived(&conn, id).expect("restore"),
            "#4365: restore after a hard forget returns false for {id}"
        );
        assert_eq!(live_content(&conn, id), None);
    }
}

/// Cell 2b — the owner-scoped hard forget funnel (`forget_for_caller`).
#[test]
fn hard_forget_for_caller_erases_the_same_id_archive_snapshot_4365() {
    let conn = fresh_db("hard-forget-caller-");
    let ns = "ns-4365-forget-caller";
    let id = "4365-fgt-caller";
    seed_with_snapshot(&conn, id, ns, None);

    let forgot =
        db::forget_for_caller(&conn, Some(ns), None, None, false, "ai:4365").expect("hard forget");
    assert_eq!(forgot, 1);
    assert_eq!(
        archived_snapshot(&conn, id),
        None,
        "#4365: the owner-scoped hard forget must erase the same-id snapshot"
    );
    assert!(!db::restore_archived(&conn, id).expect("restore"));
}

/// Cell 3 — hard TTL eviction (`gc(archive = false)`): the same erasure
/// primitive, the same contract.
#[test]
fn hard_gc_eviction_erases_the_same_id_archive_snapshot_4365() {
    let conn = fresh_db("hard-gc-");
    let id = "4365-gc";
    // Already expired at seed time, so the sweep reaps it.
    seed_with_snapshot(&conn, id, "ns-4365-gc", Some("2020-01-01T00:00:00Z"));

    let reaped = db::gc(&conn, false).expect("hard gc");
    assert!(reaped >= 1, "the expired row was reaped: {reaped}");
    assert_eq!(live_content(&conn, id), None, "live row evicted");
    assert_eq!(
        archived_snapshot(&conn, id),
        None,
        "#4365: a hard gc eviction must erase the same-id snapshot"
    );
    assert!(!db::restore_archived(&conn, id).expect("restore"));
}

/// Control — a SOFT forget (`archive = true`) is a recoverable MOVE: the
/// `forget` archive row (the text live at forget time) stays and restores.
#[test]
fn soft_forget_keeps_its_recoverable_archive_row_4365() {
    let conn = fresh_db("soft-forget-");
    let ns = "ns-4365-soft";
    let id = "4365-soft";
    seed_with_snapshot(&conn, id, ns, None);

    assert_eq!(
        db::forget(&conn, Some(ns), None, None, true).expect("soft forget"),
        1
    );
    assert_eq!(
        archived_snapshot(&conn, id),
        Some((NEW_TEXT.to_string(), "forget".to_string())),
        "control: the soft forget's own archive row (live text at forget time) stays"
    );
    assert!(
        db::restore_archived(&conn, id).expect("restore"),
        "control: the operator un-forget still round-trips (#1771 / #1848 option B)"
    );
    assert_eq!(live_content(&conn, id).as_deref(), Some(NEW_TEXT));
}
