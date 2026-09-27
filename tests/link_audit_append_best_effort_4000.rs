// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown)]
//! #4000 — SQLite link creation is audited BEST-EFFORT.
//!
//! `docs/security/audit-trail-coverage.md` used to say every successful
//! memory write, `link` included, is chain-logged in `signed_events` with
//! "none" as the success-leg gap. `create_link_signed_with_window` appends
//! `memory_link.created` AFTER the link INSERT and, on an append failure,
//! logs a WARN and still returns `Ok` with the link kept. This pins that
//! behaviour — the link row exists, no `memory_link.created` event exists,
//! and the WARN is emitted — so the corrected coverage matrix ("SQLite link
//! creation can succeed without an audit row when its best-effort append
//! fails") stays true, and a future change to fail-closed shows up here as a
//! deliberate test edit rather than silent drift from the docs.

use std::sync::{Arc, Mutex};

use ai_memory::db;
use ai_memory::models;
use tempfile::TempDir;

#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn seed(conn: &rusqlite::Connection, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: models::Tier::Mid,
        namespace: "fit-4000".to_string(),
        title: title.to_string(),
        content: "x".to_string(),
        source: "import".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: models::default_metadata(),
        priority: 5,
        confidence: 1.0,
        version: 1,
        ..models::Memory::default()
    };
    db::insert(conn, &mem).expect("db::insert")
}

fn count(conn: &rusqlite::Connection, sql: &str, params: impl rusqlite::Params) -> i64 {
    conn.query_row(sql, params, |r| r.get(0)).expect("count")
}

#[test]
fn link_is_kept_and_reported_when_its_audit_append_fails_4000() {
    let tmp = TempDir::new().expect("tempdir");
    let conn = db::open(&tmp.path().join("ai-memory.db")).expect("db::open");
    let src = seed(&conn, "src");
    let dst = seed(&conn, "dst");

    // Force every `signed_events` append to fail, the way a transient
    // substrate error would, without touching the link table.
    conn.execute_batch(
        "CREATE TRIGGER fit_4000_fail_audit BEFORE INSERT ON signed_events \
         BEGIN SELECT RAISE(ABORT, 'fit-4000 forced audit failure'); END;",
    )
    .expect("install failing trigger");

    let sink = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let attest = tracing::subscriber::with_default(subscriber, || {
        db::create_link_signed(&conn, &src, &dst, "related_to", None)
    })
    .expect("link creation succeeds even though its audit append failed");
    assert_eq!(attest, "unsigned");

    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
            [&src, &dst],
        ),
        1,
        "the link row is kept"
    );
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'memory_link.created'",
            [],
        ),
        0,
        "no memory_link.created audit row was written"
    );
    let logs = String::from_utf8_lossy(&sink.0.lock().expect("sink")).into_owned();
    assert!(
        logs.contains("failed to append memory_link.created audit row"),
        "the failed append must be surfaced as a WARN; logs:\n{logs}"
    );

    // Control: with the trigger gone the same path DOES audit, so the zero
    // above is the forced failure, not a path that never audits.
    conn.execute_batch("DROP TRIGGER fit_4000_fail_audit;")
        .expect("drop trigger");
    let third = seed(&conn, "third");
    db::create_link_signed(&conn, &src, &third, "related_to", None).expect("second link");
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'memory_link.created'",
            [],
        ),
        1,
        "a healthy append writes exactly one memory_link.created row"
    );
}
