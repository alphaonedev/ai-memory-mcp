// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4007 — an invalid `--tier` on `store` / `update` is refused BEFORE the
//! database is opened, so a refused command deletes nothing.
//!
//! `docs/CLI_REFERENCE.md` ("`--tier` fails closed", #3130) promised exactly
//! that, but `store` ran `db::open` and then `db::gc_if_needed` — which
//! archives (or, with `archive_on_gc=false`, erases) every expired row and
//! commits — and only THEN parsed the tier; `update` also opened (and so
//! created / migrated) the database first. The fix moves the parse above the
//! open on both verbs, making the documented guarantee true rather than
//! weakening the sentence. Both halves are pinned here through the real
//! binary: a refused `store` leaves an expired row in place, and neither verb
//! creates a database file it was pointed at.

use assert_cmd::Command;
use tempfile::TempDir;

fn ai_memory(db: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().unwrap()]);
    cmd
}

fn memory_rows(db: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count memories")
}

#[test]
fn refused_store_tier_does_not_gc_an_expired_row_4007() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("mem.db");
    ai_memory(&db)
        .args(["store", "-T", "expired-row", "-c", "body that has expired"])
        .assert()
        .success();
    {
        let conn = rusqlite::Connection::open(&db).expect("open db");
        let n = conn
            .execute(
                "UPDATE memories SET expires_at = '2000-01-01T00:00:00+00:00'",
                [],
            )
            .expect("expire the row");
        assert_eq!(n, 1, "fixture: exactly one row to expire");
    }
    assert_eq!(memory_rows(&db), 1);

    let out = ai_memory(&db)
        .args(["store", "-T", "new", "-c", "new body", "--tier", "Long"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        stderr.contains("invalid tier"),
        "the refusal must name the tier: {stderr}"
    );
    assert_eq!(
        memory_rows(&db),
        1,
        "a refused store must not run GC first — the expired row was removed \
         before the tier error (#4007)"
    );
}

#[test]
fn refused_tier_does_not_create_the_database_4007() {
    for verb in [
        vec!["store", "-T", "t", "-c", "c", "--tier", "Long"],
        vec![
            "update",
            "00000000-0000-4000-8000-000000000000",
            "--tier",
            "Long",
        ],
    ] {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("absent.db");
        ai_memory(&db).args(&verb).assert().failure();
        assert!(
            !db.exists(),
            "`{}` with an invalid tier opened (and so created) the database \
             before refusing (#4007)",
            verb[0]
        );
    }
}
