// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use ai_memory::background::fts_integrity::{IntegrityStatus, Outcome, run_once};
use ai_memory::models::{Memory, Tier};
use ai_memory::storage as db;
use std::cell::RefCell;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

fn memory() -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: "snapshot regression".into(),
        content: "originalalpha".into(),
        namespace: format!("regression-{}", uuid::Uuid::new_v4()),
        tier: Tier::Long,
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        ..Memory::default()
    }
}

fn patch(
    conn: &rusqlite::Connection,
    id: &str,
    content: Option<&str>,
    version: Option<i64>,
) -> anyhow::Result<(bool, bool)> {
    db::update_with_expected_version(
        conn,
        id,
        None,
        content,
        None,
        None,
        None,
        Some(8),
        None,
        None,
        None,
        None,
        version,
        None,
    )
}

type Rendezvous = (Sender<()>, Receiver<()>);
thread_local! {
    static BEFORE_LOCK: RefCell<Option<Rendezvous>> = const { RefCell::new(None) };
}

// SQLite invokes trace before executing BEGIN. On the carrier this is AFTER
// the patch's read; after the fix it is BEFORE the read. Let an independent
// writer commit here, with bounded rendezvous and no production test hook.
fn before_begin(sql: &str) {
    if sql.starts_with("BEGIN IMMEDIATE") {
        BEFORE_LOCK.with(|slot| {
            if let Some((start, done)) = slot.borrow_mut().take() {
                start.send(()).unwrap();
                done.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        });
    }
}

#[test]
fn update_preserves_concurrent_content_and_actual_preimage_4034() {
    for _ in 0..20 {
        for mode in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("store.db");
            let mut conn = db::open(&path).unwrap();
            let other = db::open(&path).unwrap();
            let mem = memory();
            db::insert(&conn, &mem).unwrap();
            let version = db::get(&conn, &mem.id).unwrap().unwrap().version;
            let id = mem.id.clone();
            let (start_tx, start_rx) = channel();
            let (done_tx, done_rx) = channel();
            let writer = std::thread::spawn(move || {
                start_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                patch(&other, &id, Some("concurrentbeta"), None).unwrap();
                done_tx.send(()).unwrap();
            });
            BEFORE_LOCK.with(|slot| *slot.borrow_mut() = Some((start_tx, done_rx)));
            conn.trace(Some(before_begin));
            let result = patch(
                &conn,
                &mem.id,
                (mode == 2).then_some("finalgamma"),
                (mode == 1).then_some(version),
            );
            conn.trace(None);
            writer.join().unwrap();
            let live = db::get(&conn, &mem.id).unwrap().unwrap();
            if mode == 1 {
                assert!(
                    result
                        .unwrap_err()
                        .downcast_ref::<db::VersionConflict>()
                        .is_some()
                );
            } else {
                assert!(result.unwrap().0);
            }
            assert_eq!(
                live.content,
                if mode == 2 {
                    "finalgamma"
                } else {
                    "concurrentbeta"
                },
                "#4034: omitted content must resolve under the write lock"
            );
            let archive: String = conn
                .query_row(
                    "SELECT content FROM archived_memories WHERE id=?1",
                    [&mem.id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                archive,
                if mode == 2 {
                    "concurrentbeta"
                } else {
                    "originalalpha"
                }
            );
        }
    }
}

#[test]
fn supersede_preserves_concurrent_content_and_rejects_stale_version_4034() {
    for _ in 0..20 {
        for versioned in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("supersede.db");
            let mut conn = db::open(&path).unwrap();
            let other = db::open(&path).unwrap();
            let mem = memory();
            db::insert(&conn, &mem).unwrap();
            let version = db::get(&conn, &mem.id).unwrap().unwrap().version;
            let id = mem.id.clone();
            let (start_tx, start_rx) = channel();
            let (done_tx, done_rx) = channel();
            let writer = std::thread::spawn(move || {
                start_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                patch(&other, &id, Some("concurrentbeta"), None).unwrap();
                done_tx.send(()).unwrap();
            });
            BEFORE_LOCK.with(|slot| *slot.borrow_mut() = Some((start_tx, done_rx)));
            conn.trace(Some(before_begin));
            let result = db::update_with_archive_on_supersede(
                &conn,
                &mem.id,
                None,
                None,
                None,
                None,
                None,
                Some(8),
                None,
                None,
                None,
                None,
                versioned.then_some(version),
                ai_memory::models::EditSource::Llm,
            );
            conn.trace(None);
            writer.join().unwrap();
            if versioned {
                assert!(
                    result
                        .unwrap_err()
                        .downcast_ref::<db::VersionConflict>()
                        .is_some(),
                    "#4034: supersede must check the locked version"
                );
                assert_eq!(
                    db::get(&conn, &mem.id).unwrap().unwrap().content,
                    "concurrentbeta"
                );
            } else {
                let result = result.unwrap();
                assert_eq!(
                    db::get(&conn, &result.new_id).unwrap().unwrap().content,
                    "concurrentbeta",
                    "#4034: supersede must inherit the locked content"
                );
                let prior: String = conn
                    .query_row(
                        "SELECT content FROM archived_memories WHERE id=?1",
                        [&mem.id],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(prior, "concurrentbeta");
            }
        }
    }
}

#[test]
fn caller_owned_update_transaction_rolls_back_4034() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let mem = memory();
    db::insert(&conn, &mem).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    patch(&conn, &mem.id, Some("changed"), None).unwrap();
    assert!(!conn.is_autocommit());
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        db::get(&conn, &mem.id).unwrap().unwrap().content,
        mem.content
    );
    let count: i64 = conn
        .query_row("SELECT count(*) FROM archived_memories", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn unchanged_merge_does_not_create_recovery_snapshot_4035() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let a = memory();
    db::insert(&conn, &a).unwrap();
    db::merge_inbound(&conn, &a, false).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM archived_memories WHERE id=?1",
            [&a.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "unchanged content needs no recovery snapshot");
}

#[test]
fn merge_replay_preserves_recovery_snapshot_4035() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let a = memory();
    db::insert(&conn, &a).unwrap();
    let archive = || {
        conn.query_row(
            "SELECT content FROM archived_memories WHERE id=?1",
            [&a.id],
            |r| r.get::<_, String>(0),
        )
        .unwrap()
    };
    let mut b = a.clone();
    b.content = "newerbeta".into();
    b.updated_at = "2026-01-02T00:00:00+00:00".into();
    db::merge_inbound(&conn, &b, false).unwrap();
    assert_eq!(archive(), a.content);
    db::merge_inbound(&conn, &b, false).unwrap();
    assert_eq!(
        archive(),
        a.content,
        "#4035: replay must preserve prior content"
    );
    let mut older = a.clone();
    older.priority = 9;
    db::merge_inbound(&conn, &older, false).unwrap();
    assert_eq!(archive(), a.content);
    assert_eq!(db::get(&conn, &a.id).unwrap().unwrap().priority, 9);
    let mut c = b.clone();
    c.content = "latestgamma".into();
    c.updated_at = "2026-01-03T00:00:00+00:00".into();
    db::merge_inbound(&conn, &c, false).unwrap();
    assert_eq!(archive(), b.content);
    let mut title_only = c.clone();
    title_only.title = "renamed".into();
    title_only.updated_at = "2026-01-04T00:00:00+00:00".into();
    db::merge_inbound(&conn, &title_only, false).unwrap();
    assert_eq!(archive(), c.content);
}

#[test]
fn deep_fts_check_detects_equal_count_stale_postings_4036() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let mem = memory();
    db::insert(&conn, &mem).unwrap();
    let status = IntegrityStatus::new(3600);
    assert_eq!(run_once(&conn, &status, 1), Outcome::Verified);
    let trigger: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='memories_au'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute_batch("DROP TRIGGER memories_au").unwrap();
    conn.execute(
        "UPDATE memories SET content='replacementbeta' WHERE id=?1",
        [&mem.id],
    )
    .unwrap();
    conn.execute_batch(&trigger).unwrap();
    let matches = |token| {
        conn.query_row(
            "SELECT count(*) FROM memories_fts WHERE memories_fts MATCH ?1",
            [token],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    };
    assert_eq!(matches("originalalpha"), 1);
    assert_eq!(matches("replacementbeta"), 0);
    let counts: (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM memories), (SELECT count(*) FROM memories_fts)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1));
    assert!(db::fts_probe(&conn).is_ok());
    assert!(
        db::fts_integrity_check(&conn).is_err(),
        "#4036: deep check must compare external content"
    );
    assert_eq!(run_once(&conn, &status, 2), Outcome::Corrupt);
    conn.execute_batch("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')")
        .unwrap();
    assert_eq!(run_once(&conn, &status, 3), Outcome::Verified);
    assert_eq!(matches("originalalpha"), 0);
    assert_eq!(matches("replacementbeta"), 1);
    conn.execute_batch("DROP TABLE memories_fts").unwrap();
    assert_eq!(run_once(&conn, &status, 4), Outcome::Unavailable);
}
