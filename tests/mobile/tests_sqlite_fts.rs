// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7.0 Posture-1a (issue #1068 Layer 3) — SQLite + FTS5 tests on
// the iOS / Android device-shipped sqlite binary.
//
// ai-memory always builds with `sqlite-bundled` (rusqlite/bundled),
// so the bundled SQLite C blob is what actually runs on mobile too.
// However, behavioral quirks still surface on mobile because:
//
//   - The mobile OS may impose stricter per-process file-descriptor
//     limits than the host (iOS ~256, Android ~1024 vs. linux ~65k).
//   - FTS5 tokenizer ICU support varies — iOS sqlite ships with ICU,
//     bundled sqlite does NOT, so unicode tokenization is byte-only
//     on bundled builds.
//   - Mobile sqlite's `PRAGMA journal_mode=WAL` interacts with the
//     OS's fsync(2) behavior differently under iOS background
//     suspension.
//
// Tests here use bundled sqlite directly (rusqlite::Connection).

use rusqlite::Connection;

use super::harness::{cleanup, sandbox_db_path};

#[test]
fn sqlite_fts5_basic_index_query() {
    let p = sandbox_db_path("fts5_basic");
    {
        let conn = Connection::open(&p).expect("open sqlite under sandbox");
        conn.execute_batch(
            "CREATE VIRTUAL TABLE memories USING fts5(title, content, tokenize='unicode61');
             INSERT INTO memories(title, content) VALUES ('mobile ci', 'iPhone Android cross compile');
             INSERT INTO memories(title, content) VALUES ('other', 'unrelated body');",
        )
        .expect("create + insert into fts5 table");

        let mut stmt = conn
            .prepare("SELECT title FROM memories WHERE memories MATCH 'iPhone'")
            .expect("prepare fts query");
        let row: String = stmt
            .query_row([], |r| r.get(0))
            .expect("expected one row matching 'iPhone'");
        assert_eq!(row, "mobile ci");
    }
    cleanup(&p);
}

#[test]
fn sqlite_wal_mode_round_trip() {
    let p = sandbox_db_path("sqlite_wal");
    {
        let conn = Connection::open(&p).expect("open sqlite");
        let mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .expect("PRAGMA journal_mode=WAL succeeds");
        // Under iOS sandbox, WAL mode may downgrade to MEMORY if the
        // sandbox doesn't permit the auxiliary -wal file in the same
        // directory. We accept either WAL or MEMORY — but NOT delete
        // (which would mean WAL wasn't engaged at all).
        assert!(
            mode == "wal" || mode == "memory",
            "expected WAL or MEMORY journal_mode, got {mode}"
        );
        conn.execute_batch(
            "CREATE TABLE m(id INTEGER PRIMARY KEY, body TEXT);
             INSERT INTO m(body) VALUES ('one'), ('two');",
        )
        .unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM m", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
    cleanup(&p);
}

// TODO #1068 Layer 3 follow-up: extend to
//   - PRAGMA synchronous=NORMAL behavior under iOS suspension
//   - FTS5 'porter unicode61' tokenizer chain
//   - Foreign key cascade on Android scoped-storage
//   - Concurrent reader + writer under mobile fd limit
//   - Sqlite version-string drift check (bundled vs. device sqlite
//     when the consuming app links against libsqlite3.dylib instead)
