// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7559 — `create_link_signed_with_window` inside a caller-owned transaction
//! must never leave a link committed without its `memory_link.created` audit
//! row, even when the caller swallows the error (the synthesis supersede
//! callers log and continue). The edge INSERT and the audit append share a
//! SAVEPOINT: an audit failure rolls both back before the error is returned.

use ai_memory::db;
use ai_memory::models::{Memory, MemoryLinkRelation, Tier, default_metadata};
use rusqlite::Connection;

const NS: &str = "link-audit-savepoint-7559";

fn open_db() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn seed(conn: &Connection, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    metadata["agent_id"] = serde_json::Value::String("ai:7559".into());
    db::insert(
        conn,
        &Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: NS.to_string(),
            title: title.to_string(),
            content: format!("durable text for {title}"),
            created_at: now.clone(),
            updated_at: now,
            metadata,
            ..Memory::default()
        },
    )
    .expect("seed")
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).expect("count")
}

const LINKS: &str = "SELECT COUNT(*) FROM memory_links";
const AUDITS: &str = "SELECT COUNT(*) FROM signed_events WHERE event_type = 'memory_link.created'";

#[test]
fn swallowed_audit_failure_in_a_transaction_commits_neither_row_7559() {
    let conn = open_db();
    let a = seed(&conn, "a 7559");
    let b = seed(&conn, "b 7559");
    conn.execute_batch(
        "CREATE TRIGGER x7559_audit_fault BEFORE INSERT ON signed_events \
         WHEN NEW.event_type = 'memory_link.created' \
         BEGIN SELECT RAISE(ABORT, 'x7559 injected audit fault'); END;",
    )
    .expect("install fault");
    conn.execute_batch("BEGIN IMMEDIATE").expect("begin");
    // The synthesis callers log this error and keep going; so does this cell.
    let outcome =
        db::create_link_signed(&conn, &a, &b, MemoryLinkRelation::Supersedes.as_str(), None);
    assert!(
        outcome.is_err(),
        "the audit failure must surface: {outcome:?}"
    );
    conn.execute_batch("COMMIT").expect("commit after swallow");
    assert_eq!(
        count(&conn, LINKS),
        0,
        "#7559: a link must not commit without its audit row"
    );
    assert_eq!(count(&conn, AUDITS), 0);
}

#[test]
fn transactional_link_still_commits_with_its_audit_row_7559() {
    let conn = open_db();
    let a = seed(&conn, "a ok 7559");
    let b = seed(&conn, "b ok 7559");
    conn.execute_batch("BEGIN IMMEDIATE").expect("begin");
    db::create_link_signed(&conn, &a, &b, MemoryLinkRelation::Supersedes.as_str(), None)
        .expect("healthy link in a transaction");
    conn.execute_batch("COMMIT").expect("commit");
    assert_eq!(count(&conn, LINKS), 1);
    assert_eq!(count(&conn, AUDITS), 1);
    // The no-op replay appends nothing and leaves the savepoint stack clean.
    conn.execute_batch("BEGIN IMMEDIATE").expect("begin 2");
    db::create_link_signed(&conn, &a, &b, MemoryLinkRelation::Supersedes.as_str(), None)
        .expect("replay");
    conn.execute_batch("COMMIT").expect("commit 2");
    assert_eq!(count(&conn, LINKS), 1);
    assert_eq!(count(&conn, AUDITS), 1);
}
