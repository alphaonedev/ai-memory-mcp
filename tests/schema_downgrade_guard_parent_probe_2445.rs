// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #2445 — the R-203 fail-at-parent probe for the schema DOWNGRADE guard.
//!
//! Deliberately written against the PRE-#2445 public API ONLY (`db::open`,
//! `current_schema_version`, raw `rusqlite`) so it COMPILES AND RUNS at the
//! parent commit. At the parent it FAILS — `db::open` returns `Ok` against a
//! database stamped five versions ahead of this binary's ladder, and the write
//! that follows lands in a schema this binary does not understand. After the
//! fix it passes.
//!
//! It is kept permanently, not discarded after the demonstration: it is the
//! only assertion in the suite that exercises the guard purely as a black box,
//! so it stays honest even if the internal `schema_guard` surface is later
//! restructured.

use rusqlite::params;

/// Stamp the recorded schema version through a RAW connection — no bootstrap,
/// no ladder, no guard — so the fixture is unaffected by the behaviour under
/// test on either side of the fix.
fn stamp_raw(path: &std::path::Path, version: i64) {
    let conn = rusqlite::Connection::open(path).expect("raw open");
    conn.execute("DELETE FROM schema_version", []).unwrap();
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        params![version],
    )
    .unwrap();
}

#[test]
fn an_older_binary_must_refuse_to_open_a_newer_database_2445() {
    // SAFETY: `AI_MEMORY_ALLOW_SCHEMA_AHEAD` is the post-fix hatch; the parent
    // commit does not read it. Clearing it keeps the probe meaningful on both
    // sides without referencing any post-fix symbol.
    unsafe { std::env::remove_var("AI_MEMORY_ALLOW_SCHEMA_AHEAD") };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ai-memory.db");
    drop(ai_memory::db::open(&path).expect("fresh open"));

    let tip = ai_memory::storage::migrations::current_schema_version();
    let ahead = tip + 5;
    stamp_raw(&path, ahead);

    // PRE-#2445: this returns `Ok` and the caller proceeds to write a database
    // whose schema it does not understand — the silent-corruption class.
    let result = ai_memory::db::open(&path);
    assert!(
        result.is_err(),
        "an older binary (ladder tip v{tip}) must REFUSE a database stamped \
         v{ahead}; opening it and writing is silent corruption of the durable \
         tier (#2445)"
    );
    let msg = format!("{:#}", result.unwrap_err());
    assert!(
        msg.contains(&format!("v{ahead}")) && msg.contains(&format!("v{tip}")),
        "the refusal must name BOTH the observed and the supported version so \
         an operator knows which binary to install: {msg}"
    );

    // The refusal must not have ratcheted the stamp — the newer database is
    // left exactly as found for the correct binary to pick up.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let observed: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(observed, ahead, "a refused open must leave the stamp alone");
}
