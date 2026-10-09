// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4366 (WP-ERASURE #6048) — the archive read surfaces must apply the
//! fail-CLOSED lifecycle allow-list (`crate::models::lifecycle_visible_clause`
//! / `LifecycleState::is_recall_visible`) exactly as every live read / egress
//! lane does (#1948): a `quarantined` row copied into `archived_memories`
//! (a merge snapshot, a gc / forget archive, an operator archive) must stay
//! as invisible — and as un-restorable — as the live row it came from.
//!
//! Pre-fix `list_archived_scoped` / `list_archived` / `archive_stats_scoped`
//! / `archive_stats` checked only owner + namespace visibility, so content
//! the node deliberately black-holed became listable, and `restore_archived`
//! would put it back live.

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::path::PathBuf;

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use rusqlite::Connection;

const NS: &str = "ns-archive-lifecycle-4366";
const HIDDEN_TEXT: &str = "#4366 quarantined text that must stay hidden in the archive";
const OPEN_TEXT: &str = "#4366 ordinary text that stays listable and restorable";

fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("archive-lifecycle-visibility-4366");
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

fn mem(id: &str, content: &str) -> Memory {
    let now = "2026-07-20T00:00:00Z".to_string();
    Memory {
        id: id.into(),
        tier: Tier::Mid,
        namespace: NS.into(),
        title: format!("title {id}"),
        content: content.into(),
        priority: 5,
        confidence: 1.0,
        source: "system".into(),
        created_at: now.clone(),
        updated_at: now,
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:4366" }),
        ..Memory::default()
    }
}

/// Seed one quarantined row and one open row, archive BOTH (an operator
/// archive is the simplest copy path; the merge snapshot and the gc/forget
/// archive carry `lifecycle_state` through the same INSERT-SELECT column).
fn seed_archived_pair(conn: &Connection) -> (&'static str, &'static str) {
    let hidden = "4366-quarantined";
    let open = "4366-open";
    db::insert(conn, &mem(hidden, HIDDEN_TEXT)).expect("insert hidden");
    db::insert(conn, &mem(open, OPEN_TEXT)).expect("insert open");
    // Quarantine is system-only (#1948): set it the way the route-in does.
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = ?1",
        [hidden],
    )
    .expect("quarantine the row");
    assert!(db::archive_memory(conn, hidden, Some("explicit")).expect("archive hidden"));
    assert!(db::archive_memory(conn, open, Some("explicit")).expect("archive open"));
    let archived_state: String = conn
        .query_row(
            "SELECT lifecycle_state FROM archived_memories WHERE id = ?1",
            [hidden],
            |r| r.get(0),
        )
        .expect("archived lifecycle");
    assert_eq!(
        archived_state, "quarantined",
        "fixture: the archive row carries the state"
    );
    (hidden, open)
}

fn listed_ids(rows: &[serde_json::Value]) -> Vec<String> {
    let mut ids: Vec<String> = rows
        .iter()
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect();
    ids.sort();
    ids
}

/// Cell 1 — the caller-scoped AND the unscoped listing both hide the
/// quarantined archive row and keep the open one.
#[test]
fn archive_list_hides_a_quarantined_row_4366() {
    let conn = fresh_db("archive-list-");
    let (hidden, open) = seed_archived_pair(&conn);

    let scoped = db::list_archived_scoped(&conn, Some(NS), None, 50, 0).expect("scoped list");
    assert_eq!(
        listed_ids(&scoped),
        vec![open.to_string()],
        "#4366: the scoped archive listing must hide the quarantined row {hidden}; got {scoped:?}"
    );
    let text_leaked = scoped.iter().any(|r| {
        r["content"]
            .as_str()
            .is_some_and(|c| c.contains(HIDDEN_TEXT))
    });
    assert!(
        !text_leaked,
        "#4366: the quarantined text must not be listable"
    );

    let unscoped = db::list_archived(&conn, Some(NS), 50, 0).expect("unscoped list");
    assert_eq!(
        listed_ids(&unscoped),
        vec![open.to_string()],
        "#4366: the unscoped archive listing must hide the quarantined row too; got {unscoped:?}"
    );
}

/// Cell 2 — both stats aggregates count only the visible archive row.
#[test]
fn archive_stats_exclude_a_quarantined_row_4366() {
    let conn = fresh_db("archive-stats-");
    let (_hidden, _open) = seed_archived_pair(&conn);

    let scoped = db::archive_stats_scoped(&conn, None).expect("scoped stats");
    assert_eq!(
        scoped["archived_total"],
        serde_json::json!(1),
        "#4366: scoped stats count only the visible row: {scoped}"
    );
    let unscoped = db::archive_stats(&conn).expect("unscoped stats");
    assert_eq!(
        unscoped["archived_total"],
        serde_json::json!(1),
        "#4366: unscoped stats count only the visible row: {unscoped}"
    );
}

/// Cell 3 — restore refuses the quarantined archive row (`Ok(false)`, the
/// unnamed not-found shape every hidden-row read lane uses) and leaves it
/// archived; the open row still restores (control).
#[test]
fn archive_restore_refuses_a_quarantined_row_and_restores_the_open_one_4366() {
    let conn = fresh_db("archive-restore-");
    let (hidden, open) = seed_archived_pair(&conn);

    assert!(
        !db::restore_archived(&conn, hidden).expect("restore hidden"),
        "#4366: restoring a quarantined archive row must be refused"
    );
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            [hidden],
            |r| r.get(0),
        )
        .expect("probe live");
    assert_eq!(
        live, 0,
        "#4366: the quarantined row must not come back live"
    );
    let still_archived: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            [hidden],
            |r| r.get(0),
        )
        .expect("probe archive");
    assert_eq!(
        still_archived, 1,
        "the refused row stays archived (hidden, not destroyed)"
    );

    // The owner-scoped restore funnel refuses too.
    assert!(
        !db::restore_archived_for_caller(&conn, hidden, "ai:4366")
            .expect("restore hidden as owner"),
        "#4366: the owner-scoped restore must refuse the quarantined row as well"
    );

    // Control: an ordinary archived row restores.
    assert!(db::restore_archived(&conn, open).expect("restore open"));
    let restored: String = conn
        .query_row("SELECT content FROM memories WHERE id = ?1", [open], |r| {
            r.get(0)
        })
        .expect("restored content");
    assert_eq!(restored, OPEN_TEXT);
}
