// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! #8890 / #4034 — lost-update class on the SQLite write funnels.
//!
//! * #8890: `promote_to_namespace` writes the clone and its `derived_from`
//!   edge as ONE logical write. An injected failure on the second statement
//!   must leave NO clone behind.
//! * #4034: `update` and the supersede path read the row they patch. That
//!   read must happen under the write lock, so a writer that commits between
//!   the read and the write is never overwritten by the stale snapshot.
//!
//! The interleave is deterministic: a second connection holds
//! `BEGIN IMMEDIATE`; the writer under test runs on a thread whose busy
//! handler raises a flag the moment it waits for that lock; only then does
//! the second connection commit its own change and release the lock.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ai_memory::models::{ConfidenceSource, EditSource};
use ai_memory::{db, models};

const NS: &str = "lu8890/team";
const PARENT_NS: &str = "lu8890";
const TITLE_BEFORE: &str = "title-before";
const TITLE_CONCURRENT: &str = "title-concurrent";
const CONTENT_PATCH: &str = "content-from-the-patch";
const LOCK_WAIT_CEILING: Duration = Duration::from_secs(10);
const BUSY_BACKOFF: Duration = Duration::from_millis(5);

fn mem(title: &str) -> models::Memory {
    let now = chrono::Utc::now().to_rfc3339();
    models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: models::Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: "original-content".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({}),
        memory_kind: models::MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..models::Memory::default()
    }
}

#[test]
fn promote_8890_failed_link_leaves_no_clone() {
    let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
    let conn = db::open(&dir.path().join("p.db")).expect("open");
    let source = mem("promote-src");
    db::insert(&conn, &source).expect("seed");
    conn.execute_batch(
        "CREATE TEMP TRIGGER inject_8890 BEFORE INSERT ON main.memory_links \
         BEGIN SELECT RAISE(ABORT, 'injected-8890'); END;",
    )
    .expect("inject second-statement failure");
    let err = db::promote_to_namespace(&conn, &source.id, PARENT_NS, None)
        .expect_err("the link insert is refused, so the promote must fail");
    assert!(
        format!("{err:#}").contains("injected-8890"),
        "unexpected error: {err:#}"
    );
    let clones: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [PARENT_NS],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        clones, 0,
        "#8890: a half-written promote left an orphan clone"
    );
    assert!(conn.is_autocommit(), "promote left a transaction open");
    // The funnel still works once the fault is gone.
    conn.execute_batch("DROP TRIGGER temp.inject_8890")
        .expect("drop trigger");
    let id = db::promote_to_namespace(&conn, &source.id, PARENT_NS, None).expect("promote");
    let links: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
            [&id, &source.id],
            |r| r.get(0),
        )
        .expect("count links");
    assert_eq!(links, 1);
}

/// Run `write` on its own connection while `blocker` holds the write lock;
/// once `write` is waiting for that lock, commit `UPDATE memories SET title`
/// on the blocker and let `write` finish. Returns `write`'s result.
fn interleave<T: Send + 'static>(
    path: &Path,
    id: &str,
    flag: &'static AtomicBool,
    busy: fn(i32) -> bool,
    write: impl FnOnce(&rusqlite::Connection) -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<T> {
    let blocker = db::open(path).expect("open blocker");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("take write lock");
    let writer_path = path.to_path_buf();
    let handle = std::thread::spawn(move || {
        let conn = db::open(&writer_path).expect("open writer");
        conn.busy_handler(Some(busy)).expect("busy handler");
        write(&conn)
    });
    let started = Instant::now();
    while !flag.load(Ordering::Acquire) {
        assert!(
            started.elapsed() < LOCK_WAIT_CEILING,
            "the writer never waited for the write lock"
        );
        std::thread::sleep(BUSY_BACKOFF);
    }
    blocker
        .execute(
            "UPDATE memories SET title = ?1, version = version + 1 WHERE id = ?2",
            rusqlite::params![TITLE_CONCURRENT, id],
        )
        .expect("concurrent title write");
    blocker
        .execute_batch("COMMIT")
        .expect("commit concurrent write");
    handle.join().expect("writer thread")
}

static UPDATE_WAITING: AtomicBool = AtomicBool::new(false);
fn update_busy(_: i32) -> bool {
    UPDATE_WAITING.store(true, Ordering::Release);
    std::thread::sleep(BUSY_BACKOFF);
    true
}

#[test]
fn update_4034_concurrent_commit_is_not_overwritten_by_stale_read() {
    let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
    let path = dir.path().join("u.db");
    let seeded = mem(TITLE_BEFORE);
    db::insert(&db::open(&path).expect("open"), &seeded).expect("seed");
    let id = seeded.id.clone();
    let (found, _) = interleave(
        &path,
        &seeded.id,
        &UPDATE_WAITING,
        update_busy,
        move |conn| {
            db::update(
                conn,
                &id,
                None,
                Some(CONTENT_PATCH),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        },
    )
    .expect("update");
    assert!(found);
    let row = db::get(&db::open(&path).expect("open"), &seeded.id)
        .expect("get")
        .expect("row");
    assert_eq!(row.content, CONTENT_PATCH);
    assert_eq!(
        row.title, TITLE_CONCURRENT,
        "#4034: the stale pre-read reverted a committed concurrent title"
    );
}

static SUPERSEDE_WAITING: AtomicBool = AtomicBool::new(false);
fn supersede_busy(_: i32) -> bool {
    SUPERSEDE_WAITING.store(true, Ordering::Release);
    std::thread::sleep(BUSY_BACKOFF);
    true
}

#[test]
fn supersede_4034_concurrent_commit_is_not_overwritten_by_stale_read() {
    let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
    let path = dir.path().join("s.db");
    let seeded = mem(TITLE_BEFORE);
    db::insert(&db::open(&path).expect("open"), &seeded).expect("seed");
    let id = seeded.id.clone();
    let result = interleave(
        &path,
        &seeded.id,
        &SUPERSEDE_WAITING,
        supersede_busy,
        move |conn| {
            db::update_with_archive_on_supersede(
                conn,
                &id,
                None,
                Some(CONTENT_PATCH),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                EditSource::Llm,
            )
        },
    )
    .expect("supersede");
    let conn = db::open(&path).expect("open");
    let row = db::get(&conn, &result.new_id)
        .expect("get")
        .expect("new row");
    assert_eq!(row.content, CONTENT_PATCH);
    assert_eq!(
        row.title, TITLE_CONCURRENT,
        "#4034: the superseding row was composed from a stale pre-read"
    );
    assert!(
        db::get(&conn, &seeded.id).expect("get").is_none(),
        "old row archived"
    );
}
