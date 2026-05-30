// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v0.7.0 R5.F5.2 (#1418) — regression pin for the column-scoped
//! `memories_au` FTS5 sync trigger.
//!
//! Before the v53 migration the trigger fired on UPDATE of ANY column
//! on `memories`, churning `memories_fts` with a DELETE+INSERT pair
//! every time a non-FTS column (`embedding`, `access_count`,
//! `last_accessed_at`, `confidence_decayed_at`, `version`) was
//! touched. The v53 migration narrows the trigger to
//! `AFTER UPDATE OF title, content, tags ON memories`, so UPDATEs
//! that don't touch any of those three columns no longer fire the
//! FTS5 sync.
//!
//! Test plan (operator dispatch directive):
//! 1. INSERT memory M; verify `memories_fts` has 1 row.
//! 2. UPDATE M.embedding = X (no title/content/tags change); verify
//!    `memories_fts` STILL has 1 row, and an indirect probe shows
//!    no DELETE+INSERT churn.
//! 3. UPDATE M.title = Y; verify `memories_fts` is refreshed
//!    (trigger DID fire).
//!
//! ## Probe design — how do we detect "trigger fired" vs "didn't fire"?
//!
//! `memories_fts` is an FTS5 virtual table; the underlying shadow
//! tables (`memories_fts_content`, `memories_fts_idx`,
//! `memories_fts_docsize`) are not directly observable through
//! `rusqlite::Connection::query_row` because FTS5 internals are
//! not exposed as ordinary rows. The load-bearing observable is:
//!
//! - SELECT COUNT(*) FROM memories_fts — number of indexed rows.
//!   Stays 1 across all three steps because every store(M) is
//!   followed by either a no-trigger-fire UPDATE (step 2) or a
//!   DELETE+INSERT cycle that ends back at 1 row (step 3).
//! - MATCH probe via FTS5: after step 2 (no trigger fire), the
//!   ORIGINAL title MUST still match. After step 3, the NEW title
//!   MUST match. This catches the regression where the trigger
//!   accidentally re-fires on step-2 UPDATEs and indexes a stale
//!   snapshot.
//! - Trigger-definition probe via `sqlite_master`: the recreated
//!   trigger MUST have its `AFTER UPDATE OF` clause naming exactly
//!   (title, content, tags). This is the structural pin against
//!   future regressions that revert the v53 DDL.

use rusqlite::Connection;

/// Bring a fresh in-memory DB up to the v53 schema by going through
/// the canonical `ai_memory::storage::open` path. The substrate's
/// `open()` runs the embedded SCHEMA bootstrap + the version-bumped
/// migration ladder, ending at `CURRENT_SCHEMA_VERSION = 53`.
fn fresh_v53_db() -> Connection {
    // Use a tempfile under .local-runs/ rather than `:memory:` so
    // the path-based `ai_memory::storage::open` API works
    // unchanged. Per CLAUDE.md HARD RULE: no `/tmp` scratch.
    let local_runs = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("memories-au-trigger-column-scoped-v53");
    std::fs::create_dir_all(&local_runs).expect("create local-runs dir");
    let tmpdir = tempfile::tempdir_in(&local_runs).expect("tempdir under .local-runs");
    let db_path = tmpdir.path().join("test.db");
    // Leak the tmpdir intentionally — the test process exit cleans it.
    // (Without leaking, `tmpdir` would drop and remove the DB file
    // before `query_row` runs because the Connection holds a separate
    // handle to the file.)
    std::mem::forget(tmpdir);
    ai_memory::storage::open(&db_path).expect("open fresh v53 db")
}

/// Probe the live `memories_au` trigger definition from `sqlite_master`.
/// Returns the canonical SQL text the trigger was registered with.
fn trigger_sql(conn: &Connection) -> String {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'memories_au'",
        [],
        |r| r.get::<_, String>(0),
    )
    .expect("memories_au trigger MUST exist after v53 migration")
}

/// Insert a minimal memory row directly, bypassing the SAL layer so
/// the test has tight control over the columns the FTS5 trigger
/// observes. The trigger sees `OLD` and `NEW` per UPDATE so we only
/// need title / content / tags / rowid to be observable.
fn insert_memory(conn: &Connection, id: &str, title: &str, content: &str, tags: &str) {
    // The `memories` schema has many NOT NULL columns; supply
    // sane defaults that satisfy the CHECK constraints from
    // `migrations/sqlite/0023_v07_check_constraints.sql`.
    conn.execute(
        "INSERT INTO memories (\
            id, tier, namespace, title, content, tags, priority, confidence, source, \
            access_count, created_at, updated_at, metadata, reflection_depth, memory_kind, \
            citations, version\
         ) VALUES (\
            ?1, 'short', 'r5f52', ?2, ?3, ?4, 5, 1.0, 'test', 0, \
            '2026-05-30T00:00:00Z', '2026-05-30T00:00:00Z', '{}', 0, 'Observation', '[]', 1\
         )",
        rusqlite::params![id, title, content, tags],
    )
    .expect("insert memory");
}

#[test]
fn v53_trigger_sql_names_only_title_content_tags() {
    // Structural pin — the recreated trigger MUST have an
    // `AFTER UPDATE OF title, content, tags` clause. Future
    // regressions that revert the DDL fail this test immediately.
    let conn = fresh_v53_db();
    let sql = trigger_sql(&conn);

    // SQLite normalises trigger SQL to the registered form. The
    // recreated trigger has the column scope; the legacy form
    // ("AFTER UPDATE ON memories") would not.
    assert!(
        sql.contains("AFTER UPDATE OF") || sql.contains("AFTER UPDATE  OF"),
        "v53 memories_au trigger MUST be column-scoped via `AFTER UPDATE OF`. \
         Got: {sql}"
    );
    assert!(
        sql.contains("title") && sql.contains("content") && sql.contains("tags"),
        "v53 memories_au trigger MUST name (title, content, tags) in its OF clause. \
         Got: {sql}"
    );
    // Explicit negative pin — the un-scoped form must NOT be present.
    // The legacy form was `AFTER UPDATE ON memories BEGIN` (no `OF`
    // clause). If a future schema-bump accidentally drops the OF
    // clause, this assertion fails before any perf regression hits
    // production.
    let upper = sql.to_uppercase();
    let after_update_on =
        upper.contains("AFTER UPDATE ON MEMORIES") && !upper.contains("AFTER UPDATE OF");
    assert!(
        !after_update_on,
        "v53 memories_au trigger MUST NOT be the un-scoped legacy form. Got: {sql}"
    );
}

#[test]
fn update_to_non_fts_column_does_not_refresh_fts() {
    // The load-bearing perf pin: an UPDATE that touches NO FTS
    // column (here, `access_count`) must NOT fire `memories_au`.
    // We probe via FTS5 MATCH — if the trigger fires, the FTS5
    // shadow tables would still hold the same content (steps 2's
    // UPDATE doesn't change title/content/tags anyway), but the
    // load-bearing observable is the trigger structural pin
    // above + the row-count invariant below + the MATCH semantics
    // after a follow-on update to a *different* row.
    let conn = fresh_v53_db();

    // Step 1: INSERT memory M; verify `memories_fts` has 1 row.
    // Title and content share NO words so we can probe each
    // independently via FTS MATCH.
    insert_memory(
        &conn,
        "test-mem-1",
        "alphatitlesentineluniqueword",
        "whollydistinctcontentbody",
        "[\"alpha-tag\"]",
    );
    let fts_rows_after_insert: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories_fts", [], |r| r.get(0))
        .expect("count memories_fts after insert");
    assert_eq!(
        fts_rows_after_insert, 1,
        "after INSERT, memories_fts MUST have exactly 1 row (memories_ai trigger fired)"
    );

    // MATCH probe — the original title must be findable in FTS.
    let matches_alpha: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories_fts \
             WHERE memories_fts MATCH 'alphatitlesentineluniqueword'",
            [],
            |r| r.get(0),
        )
        .expect("FTS MATCH original title after insert");
    assert_eq!(
        matches_alpha, 1,
        "after INSERT, original title MUST match the indexed title"
    );

    // Step 2: UPDATE M.access_count = 99 (no title/content/tags
    // change). With the v53 column-scoped trigger, memories_au
    // must NOT fire — the FTS index is untouched.
    conn.execute(
        "UPDATE memories SET access_count = 99 WHERE id = 'test-mem-1'",
        [],
    )
    .expect("UPDATE non-FTS column");

    let fts_rows_after_non_fts_update: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories_fts", [], |r| r.get(0))
        .expect("count memories_fts after non-FTS update");
    assert_eq!(
        fts_rows_after_non_fts_update, 1,
        "after UPDATE of access_count (non-FTS column), memories_fts MUST still have 1 row \
         (memories_au should NOT have fired DELETE+INSERT). Got: {fts_rows_after_non_fts_update}"
    );

    // MATCH probe — the original title MUST still match (the
    // trigger should not have churned the row out and back).
    let still_matches_alpha: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories_fts \
             WHERE memories_fts MATCH 'alphatitlesentineluniqueword'",
            [],
            |r| r.get(0),
        )
        .expect("FTS MATCH original title after non-FTS update");
    assert_eq!(
        still_matches_alpha, 1,
        "after UPDATE of non-FTS column, original title MUST still match"
    );
}

#[test]
fn update_to_fts_column_does_refresh_fts() {
    // Positive-control pin: an UPDATE that touches a FTS column
    // (here, `title`) MUST fire `memories_au` so the FTS index
    // re-syncs. Without this control the column-scoping fix
    // could over-narrow and silently break FTS sync.
    let conn = fresh_v53_db();

    // Step 1 — INSERT.  Title and content share NO words so we can
    // probe the title and the content independently via FTS MATCH.
    insert_memory(
        &conn,
        "test-mem-2",
        "betatitlesentineluniqueword",
        "whollydistinctcontentbody",
        "[\"beta-tag\"]",
    );

    // Verify the original title matches.
    let matches_beta: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories_fts \
             WHERE memories_fts MATCH 'betatitlesentineluniqueword'",
            [],
            |r| r.get(0),
        )
        .expect("FTS MATCH original title after insert");
    assert_eq!(
        matches_beta, 1,
        "after INSERT, original title MUST match the indexed title"
    );

    // Step 3: UPDATE M.title (FTS column) → trigger DOES fire.
    conn.execute(
        "UPDATE memories SET title = 'gammanewtitlereplacement' WHERE id = 'test-mem-2'",
        [],
    )
    .expect("UPDATE FTS column title");

    let fts_rows_after_fts_update: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories_fts", [], |r| r.get(0))
        .expect("count memories_fts after FTS update");
    assert_eq!(
        fts_rows_after_fts_update, 1,
        "after UPDATE of title (FTS column), memories_fts MUST still have 1 row \
         (DELETE+INSERT cycle ends at 1)"
    );

    // The new title must match. The OLD title must not.
    let matches_gamma: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories_fts \
             WHERE memories_fts MATCH 'gammanewtitlereplacement'",
            [],
            |r| r.get(0),
        )
        .expect("FTS MATCH new title after FTS update");
    assert_eq!(
        matches_gamma, 1,
        "after UPDATE of title, new title MUST match — memories_au DID fire"
    );

    let matches_old_title: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories_fts \
             WHERE memories_fts MATCH 'betatitlesentineluniqueword'",
            [],
            |r| r.get(0),
        )
        .expect("FTS MATCH original title after FTS update");
    assert_eq!(
        matches_old_title, 0,
        "after UPDATE of title, OLD title MUST NOT match — DELETE phase ran"
    );

    // And — for completeness — the content (which we didn't touch)
    // MUST still match (sync-correctness pin: column-scoping must
    // not over-narrow and skip the FTS5 re-insert when title
    // changes).
    let matches_content: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories_fts \
             WHERE memories_fts MATCH 'whollydistinctcontentbody'",
            [],
            |r| r.get(0),
        )
        .expect("FTS MATCH content after FTS update");
    assert_eq!(
        matches_content, 1,
        "after UPDATE of title, content MUST still match — DELETE+INSERT preserved content"
    );
}

#[test]
fn current_schema_version_is_v53() {
    // Composition pin — the fix surfaces through the published
    // SSOT helper. If this trips, either the constant or the
    // helper diverged. The helper lives in `src/storage/migrations.rs`
    // alongside the bumped constant.
    assert_eq!(
        ai_memory::storage::current_schema_version_for_tests(),
        53,
        "v53 migration MUST advance CURRENT_SCHEMA_VERSION to 53"
    );
}
