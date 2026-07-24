// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! v0.7.0 issue #894 — Postgres+AGE schema-parity gap closeout: cross-
//! backend regression harness.
//!
//! The seven provenance / observation closeouts that landed against the
//! sqlite path (Gaps 1, 2, 3, 5, 6, 7 — Gap 4 was the docs-only #887) all
//! need a postgres mirror so Track C/D federation testing has a
//! byte-identical SAL surface to drive when network routing to the
//! 192.168.1.50 PG host is restored.
//!
//! This harness encodes one `verify_<gap>()` async fn per gap and runs
//! each verification against BOTH adapters:
//!
//! * Sqlite — always available; the sqlite-side `storage::` free
//!   functions are the reference implementation and every assertion
//!   below is sqlite-validated.
//! * Postgres — gated on `AI_MEMORY_TEST_POSTGRES_URL`. When unset
//!   (the current state on this development node — network routing to
//!   192.168.1.50 is the documented blocker per issue #79), the
//!   postgres half is skipped via `#[ignore]` so `cargo test` stays
//!   green. The harness still COMPILES against the sal-postgres path
//!   so a future runner that flips the env var picks up zero-friction
//!   coverage.
//!
//! ## Why a single harness?
//!
//! Per CLAUDE.md prime directive (pm-v3, memory cd8ede94): every gap
//! gets fixed end-to-end with retest evidence. Per-gap unit tests
//! already live with each helper (`tests/optimistic_concurrency.rs`,
//! `tests/source_uri_column.rs`, `src/observations/gc.rs`'s in-module
//! suite, etc.). This harness exists specifically to pin the
//! ADAPTER-PARITY invariant: every sqlite assertion in the list below
//! MUST also hold on the postgres adapter, or Track C/D federation
//! drifts into a "works on sqlite, fails on postgres" hazard.
//!
//! ## Scope of each `verify_<gap>` function
//!
//! Each verifier exercises the minimum AC envelope for its gap:
//!   * Gap 1 (#884) — optimistic concurrency: two concurrent updates
//!     against the same memory must produce exactly one winner; the
//!     loser receives a typed `VersionConflict` envelope.
//!   * Gap 2 (#885) — first-class `source_uri` column: a memory stored
//!     with `source_uri = X` is retrievable via the reciprocal
//!     `list_by_source_uri(X)` lookup with index-only fetch.
//!   * Gap 3 (#886) — recall-observations ledger: writes land
//!     idempotently under `(recall_id, memory_id)`; the TTL prune
//!     deletes only rows older than the cutoff.
//!   * Gap 5 (#888) — `update_with_archive_on_supersede`: returns
//!     `(archived_id, new_id)`; the OLD row lands in
//!     `archived_memories.archive_reason='superseded'`; the NEW row
//!     carries `metadata.superseded_id` pointing back to the OLD id.
//!   * Gap 6 (#889) — `search_with_source_uri`: a query restricted by
//!     `source_uri` returns only memories from that URI even when the
//!     FTS query would otherwise match cross-document rows.
//!   * Gap 7 (#860) — `get_links` surfaces `valid_from`, `valid_until`,
//!     `observed_by`, `attest_level` on every link row, not just the
//!     four-column projection the pre-fix code emitted.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use ai_memory::observations;
use rusqlite::Connection;
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────
// Sqlite fixture: in-memory DB seeded through the canonical `db::open`
// path so the migration ladder fires (the verifications below
// reference v45/v46/v47 columns that the ladder ALTERs in).
// ─────────────────────────────────────────────────────────────────────

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

fn seed_memory(conn: &Connection, id: &str, ns: &str, title: &str, content: &str) -> String {
    let mem = Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed memory");
    id.to_string()
}

// ─────────────────────────────────────────────────────────────────────
// Sqlite-side verifiers — each `verify_<gap>_sqlite` exercises the
// reference implementation. The same shape is mirrored on the postgres
// side under `verify_<gap>_postgres` when `AI_MEMORY_TEST_POSTGRES_URL`
// is set.
// ─────────────────────────────────────────────────────────────────────

/// Gap 1 (#884) — optimistic concurrency. Sqlite reference.
fn verify_gap_1_version_sqlite() {
    let conn = fresh_sqlite();
    let id = seed_memory(&conn, "g1-v", "test", "v1", "original content");

    // Read current version (should be 1).
    let v1: i64 = conn
        .query_row(
            "SELECT version FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("read initial version");
    assert_eq!(v1, 1, "fresh row starts at version=1");

    // First update with expected_version=1 succeeds and bumps to 2.
    db::update_with_expected_version(
        &conn,
        &id,
        Some("v2"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(1),
        None, // #1834 valid_until
    )
    .expect("first update succeeds");
    let v2: i64 = conn
        .query_row(
            "SELECT version FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("read bumped version");
    assert_eq!(v2, 2, "successful update bumps version");

    // Second update with stale expected_version=1 fails with
    // VersionConflict.
    let res = db::update_with_expected_version(
        &conn,
        &id,
        Some("v3"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(1),
        None, // #1834 valid_until
    );
    let err = res.expect_err("stale expected_version must fail");
    let conflict = err
        .downcast_ref::<db::VersionConflict>()
        .expect("error must be VersionConflict");
    assert_eq!(conflict.expected, 1);
    assert_eq!(conflict.current, 2);
}

/// Gap 2 (#885) — first-class `source_uri` column + partial index.
/// Sqlite reference.
fn verify_gap_2_source_uri_sqlite() {
    let conn = fresh_sqlite();
    // Seed a memory with source_uri populated via the column.
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, source_uri, created_at, updated_at)
         VALUES ('g2-a', 'long', 'test', 'g2 title a', 'content', 'uri:fixture/a', ?1, ?1)",
        rusqlite::params![&now],
    )
    .expect("seed source_uri row");
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, source_uri, created_at, updated_at)
         VALUES ('g2-b', 'long', 'test', 'g2 title b', 'content', 'uri:fixture/a', ?1, ?1)",
        rusqlite::params![&now],
    )
    .expect("seed second source_uri row");
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, source_uri, created_at, updated_at)
         VALUES ('g2-c', 'long', 'test', 'g2 title c', 'content', 'uri:fixture/b', ?1, ?1)",
        rusqlite::params![&now],
    )
    .expect("seed third source_uri row");

    let hits = db::list_by_source_uri(&conn, "uri:fixture/a", Some("test"), None, None, None)
        .expect("list_by_source_uri");
    assert_eq!(hits.len(), 2, "two memories under uri:fixture/a");
    for m in &hits {
        assert_eq!(m.source_uri.as_deref(), Some("uri:fixture/a"));
    }
}

/// Gap 3 (#886) — recall_observations ledger + TTL prune. Sqlite
/// reference.
fn verify_gap_3_recall_observations_sqlite() {
    let conn = fresh_sqlite();
    seed_memory(&conn, "g3-m1", "test", "g3 t1", "g3 content");
    seed_memory(&conn, "g3-m2", "test", "g3 t2", "g3 content");

    // Write two observations under the same recall_id.
    let written = observations::record_recall(
        &conn,
        "g3-r1",
        &[
            observations::Candidate {
                memory_id: "g3-m1",
                retriever: "hybrid",
                rank: 1,
                score: 0.91,
            },
            observations::Candidate {
                memory_id: "g3-m2",
                retriever: "hybrid",
                rank: 2,
                score: 0.84,
            },
        ],
    )
    .expect("record_recall");
    assert_eq!(written, 2);

    // Replay-safety: a second insert under the same (recall_id, memory_id)
    // is INSERT OR IGNORE, no error, zero rows added.
    let again = observations::record_recall(
        &conn,
        "g3-r1",
        &[observations::Candidate {
            memory_id: "g3-m1",
            retriever: "hybrid",
            rank: 1,
            score: 0.91,
        }],
    )
    .expect("idempotent re-write");
    assert_eq!(again, 0);

    // Backdate one row and run the prune.
    conn.execute(
        "UPDATE recall_observations SET observed_at = '2020-01-01T00:00:00Z' WHERE memory_id = 'g3-m1'",
        [],
    )
    .expect("backdate row");
    let pruned = observations::gc::prune_before(&conn, "2024-01-01T00:00:00Z").expect("prune");
    assert_eq!(pruned, 1, "only the backdated row gets pruned");
}

/// Gap 5 (#888) — `update_with_archive_on_supersede`. Sqlite reference.
fn verify_gap_5_edit_source_sqlite() {
    let conn = fresh_sqlite();
    let id = seed_memory(&conn, "g5-a", "test", "g5 original", "old content");

    let result = db::update_with_archive_on_supersede(
        &conn,
        &id,
        None,
        Some("new content"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        ai_memory::models::EditSource::Llm,
    )
    .expect("supersede");
    assert_eq!(result.archived_id, id, "archived_id is the OLD id");
    assert_ne!(result.new_id, id, "new_id is freshly minted");

    // OLD row must be in archived_memories with reason='superseded'.
    let archive_reason: String = conn
        .query_row(
            "SELECT archive_reason FROM archived_memories WHERE id = ?1",
            rusqlite::params![&result.archived_id],
            |r| r.get(0),
        )
        .expect("archived row exists");
    assert_eq!(archive_reason, "superseded");

    // OLD row must NOT be in live `memories` anymore.
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            rusqlite::params![&result.archived_id],
            |r| r.get(0),
        )
        .expect("count live");
    assert_eq!(live, 0, "OLD row evicted from live memories");

    // NEW row must carry metadata.superseded_id pointing at OLD id.
    let new_meta_json: String = conn
        .query_row(
            "SELECT metadata FROM memories WHERE id = ?1",
            rusqlite::params![&result.new_id],
            |r| r.get(0),
        )
        .expect("new row metadata");
    let new_meta: serde_json::Value = serde_json::from_str(&new_meta_json).expect("parse metadata");
    assert_eq!(
        new_meta["superseded_id"].as_str(),
        Some(result.archived_id.as_str())
    );
    assert_eq!(new_meta["edit_source"].as_str(), Some("llm"));
}

/// #1725 (P0.2) — lossless DEFAULT update path. Sqlite reference: a
/// content edit snapshots the prior content into `archived_memories`
/// (SAME memory_id, `archive_reason='in_place_edit'`, no fork) BEFORE
/// the in-place UPDATE; repeated edits keep the MOST-RECENT pre-edit
/// snapshot (single-snapshot retention); a non-content edit
/// (priority / metadata only) archives nothing. The postgres twin is
/// `pg_parity_gap_1725_in_place_archive` below — a 2-edit divergence
/// (sqlite `INSERT OR REPLACE` keeps v2; a postgres `ON CONFLICT DO
/// NOTHING` would wrongly keep v1) is exactly what this pins.
fn verify_gap_1725_in_place_archive_sqlite() {
    let conn = fresh_sqlite();
    let id = seed_memory(&conn, "g1725-a", "test", "g1725 title", "content-v1");

    // Edit 1: content v1 → v2. Archives v1 under 'in_place_edit'.
    let (ok, changed) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some("content-v2"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_until
    )
    .expect("edit 1");
    assert!(ok && changed, "edit 1 applied with content_changed=true");

    let (a_content, a_reason): (String, String) = conn
        .query_row(
            "SELECT content, archive_reason FROM archived_memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("archive row exists after edit 1");
    assert_eq!(a_content, "content-v1", "archive holds the prior content");
    assert_eq!(a_reason, "in_place_edit");

    // memory_id UNCHANGED + the live row carries the NEW content.
    let live_content: String = conn
        .query_row(
            "SELECT content FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("live row after edit 1");
    assert_eq!(
        live_content, "content-v2",
        "live row has new content under the SAME id"
    );

    // Edit 2: content v2 → v3. The archive must REPLACE to the
    // MOST-RECENT pre-edit snapshot (v2), still ONE row, still SAME id.
    db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some("content-v3"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_until
    )
    .expect("edit 2");
    let archive_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("count archive after edit 2");
    assert_eq!(archive_count, 1, "single-snapshot retention (most-recent)");
    let a2_content: String = conn
        .query_row(
            "SELECT content FROM archived_memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("archive content after edit 2");
    assert_eq!(
        a2_content, "content-v2",
        "keeps the immediately-prior snapshot (v2), not the original (v1)"
    );

    // Non-content edit (priority only) archives NOTHING.
    let nid = seed_memory(
        &conn,
        "g1725-b",
        "test",
        "g1725 prio-only",
        "stable content",
    );
    db::update_with_expected_version(
        &conn,
        &nid,
        None,
        None,
        None,
        None,
        None,
        Some(9),
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_until
    )
    .expect("priority-only edit");
    let nonc_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            rusqlite::params![&nid],
            |r| r.get(0),
        )
        .expect("count archive for non-content edit");
    assert_eq!(
        nonc_count, 0,
        "a metadata/priority-only edit archives nothing"
    );
}

/// #2221 (data-integrity archive-parity) — SUPERSEDE-re-archive
/// last-wins parity. Sqlite reference: superseding a memory whose OLD
/// id ALREADY has an `archived_memories` row (an `in_place_edit`
/// snapshot from a prior content edit — SAME id, live row still
/// present) must SUCCEED and OVERWRITE that snapshot with the
/// `archive_reason='superseded'` copy of the OLD live payload. Sqlite's
/// supersede funnels through `archive_memory_no_tx`'s `INSERT OR
/// REPLACE` (last-wins), so it always succeeded. The postgres twin
/// `pg_parity_gap_2221_supersede_rearchive_lastwins` FAILS on the
/// pre-#2221 `ON CONFLICT (id) DO NOTHING` + 0-rows-affected `NotFound`
/// path (a mistyped `NotFound` for a memory that EXISTS); #2221 aligns
/// the pg site to the shared `SQL_ARCHIVE_ON_CONFLICT_LAST_WINS` clause.
fn verify_gap_2221_supersede_rearchive_lastwins_sqlite() {
    let conn = fresh_sqlite();
    let id = seed_memory(&conn, "g2221-a", "test", "g2221 title", "content-v1");

    // Precondition: an in-place content edit snapshots the prior content
    // (v1) into `archived_memories` under archive_reason='in_place_edit',
    // SAME id, live row kept (now content-v2). This is the archive row
    // the subsequent supersede's INSERT must overwrite, not choke on.
    let (ok, changed) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some("content-v2"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_until
    )
    .expect("in-place edit");
    assert!(ok && changed, "in-place edit applied");
    let pre_reason: String = conn
        .query_row(
            "SELECT archive_reason FROM archived_memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("in_place_edit snapshot exists");
    assert_eq!(pre_reason, "in_place_edit", "precondition snapshot present");

    // Supersede X. The archive step re-archives the OLD live row
    // (content-v2) under archive_reason='superseded' — hitting the
    // pre-existing archived_memories row for this id.
    let result = db::update_with_archive_on_supersede(
        &conn,
        &id,
        None,
        Some("content-v3"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        ai_memory::models::EditSource::Llm,
    )
    .expect("supersede must succeed even with a pre-existing archive row");
    assert_eq!(result.archived_id, id, "archived_id is the OLD id");
    assert_ne!(result.new_id, id, "new_id is freshly minted");

    // The archive row for the OLD id is now LAST-WINS: reason flipped to
    // 'superseded' and content is the OLD live payload (content-v2),
    // overwriting the earlier in_place_edit snapshot — NOT first-wins.
    let (a_reason, a_content): (String, String) = conn
        .query_row(
            "SELECT archive_reason, content FROM archived_memories WHERE id = ?1",
            rusqlite::params![&result.archived_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("archived row exists after supersede");
    assert_eq!(a_reason, "superseded", "reason overwritten last-wins");
    assert_eq!(
        a_content, "content-v2",
        "archived payload is the OLD live row (last-wins), not the stale snapshot"
    );

    // OLD row evicted from live; the NEW row carries content-v3.
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            rusqlite::params![&result.archived_id],
            |r| r.get(0),
        )
        .expect("count live old");
    assert_eq!(live, 0, "OLD row evicted from live memories");
    let new_content: String = conn
        .query_row(
            "SELECT content FROM memories WHERE id = ?1",
            rusqlite::params![&result.new_id],
            |r| r.get(0),
        )
        .expect("new row content");
    assert_eq!(
        new_content, "content-v3",
        "new row carries the patched content"
    );
}

/// Gap 6 (#889) — `search_with_source_uri` post-filters by URI. Sqlite
/// reference.
fn verify_gap_6_search_source_uri_sqlite() {
    let conn = fresh_sqlite();
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, source_uri, created_at, updated_at)
         VALUES ('g6-a', 'long', 'test', 'foo bar', 'matching keyword payload',
                 'uri:doc/a', ?1, ?1)",
        rusqlite::params![&now],
    )
    .expect("seed g6 a");
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, source_uri, created_at, updated_at)
         VALUES ('g6-b', 'long', 'test', 'foo baz', 'matching keyword payload',
                 'uri:doc/b', ?1, ?1)",
        rusqlite::params![&now],
    )
    .expect("seed g6 b");
    // Rebuild FTS so the new rows are searchable.
    conn.execute(
        "INSERT INTO memories_fts(memories_fts) VALUES('rebuild')",
        [],
    )
    .expect("rebuild fts");

    // Without the source_uri filter we get both matches.
    let all = db::search_with_source_uri(
        &conn, "matching", None, None, 10, None, None, None, None, None, None, false, None, None,
    )
    .expect("search all");
    assert!(all.len() >= 2, "FTS returns at least the two seeded rows");

    // With source_uri filter we get only the one row from uri:doc/a.
    let scoped = db::search_with_source_uri(
        &conn,
        "matching",
        None,
        None,
        10,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some("uri:doc/a"),
        None, // #1720 caller
    )
    .expect("search scoped");
    assert_eq!(scoped.len(), 1, "source_uri filter narrows to one match");
    assert_eq!(scoped[0].id, "g6-a");
}

/// Gap 7 (#860) — `get_links` surfaces temporal-validity + attestation
/// columns. Sqlite reference.
fn verify_gap_7_get_links_columns_sqlite() {
    let conn = fresh_sqlite();
    seed_memory(&conn, "g7-src", "test", "g7 source", "content");
    seed_memory(&conn, "g7-dst", "test", "g7 target", "content");

    // Seed with attest_level='unsigned' so the H3 atomicity trigger
    // (requires 64-byte signature for self_signed / peer_attested) is
    // satisfied. The Gap-7 assertion is that get_links surfaces the
    // column AT ALL — any non-NULL value proves the column is on the
    // wire. tests/signed_link_roundtrip.rs covers the signed path.
    conn.execute(
        "INSERT INTO memory_links \
            (source_id, target_id, relation, created_at, valid_from, valid_until, observed_by, attest_level) \
         VALUES (?1, ?2, 'related_to', ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            "g7-src",
            "g7-dst",
            "2025-05-01T00:00:00Z",
            "2025-05-01T00:00:00Z",
            "2026-05-01T00:00:00Z",
            "agent:g7-witness",
            "unsigned",
        ],
    )
    .expect("seed link with full row shape");

    let links = db::get_links(&conn, "g7-src").expect("get_links");
    assert_eq!(links.len(), 1);
    let l = &links[0];
    assert_eq!(l.source_id, "g7-src");
    assert_eq!(l.target_id, "g7-dst");
    assert_eq!(l.valid_from.as_deref(), Some("2025-05-01T00:00:00Z"));
    assert_eq!(l.valid_until.as_deref(), Some("2026-05-01T00:00:00Z"));
    assert_eq!(l.observed_by.as_deref(), Some("agent:g7-witness"));
    assert_eq!(l.attest_level.as_deref(), Some("unsigned"));
}

// ─────────────────────────────────────────────────────────────────────
// Sqlite-side gate — runs unconditionally on every `cargo test`. Pins
// the reference implementation so a regression on the sqlite path is
// caught BEFORE we even start the postgres-side comparison.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn sqlite_parity_gap_1_version() {
    verify_gap_1_version_sqlite();
}

#[test]
fn sqlite_parity_gap_2_source_uri_column() {
    verify_gap_2_source_uri_sqlite();
}

#[test]
fn sqlite_parity_gap_3_recall_observations() {
    verify_gap_3_recall_observations_sqlite();
}

#[test]
fn sqlite_parity_gap_5_edit_source() {
    verify_gap_5_edit_source_sqlite();
}

#[test]
fn sqlite_parity_gap_6_search_source_uri() {
    verify_gap_6_search_source_uri_sqlite();
}

#[test]
fn sqlite_parity_gap_7_get_links_columns() {
    verify_gap_7_get_links_columns_sqlite();
}

#[test]
fn sqlite_parity_gap_1725_in_place_archive() {
    verify_gap_1725_in_place_archive_sqlite();
}

#[test]
fn sqlite_parity_gap_2221_supersede_rearchive_lastwins() {
    verify_gap_2221_supersede_rearchive_lastwins_sqlite();
}

/// #1725 regression — `update_with_expected_version` must work when the
/// CALLER already holds a transaction. The synthesis merge path
/// (`src/mcp/tools/store/synthesis.rs`) wraps candidate updates +
/// provenance rows in one `BEGIN IMMEDIATE`; the #1725 archive-before-
/// update wrap must NOT open a nested `BEGIN` (sqlite errors "cannot
/// start a transaction within a transaction"). `is_autocommit()` gates
/// the inner tx so the archive + UPDATE run inside the caller's tx.
/// #228 / #1728 Commit A-carry — the archive → restore SQL copy paths
/// carry the `encrypted_envelope` BLOB column, so archiving an encrypted
/// memory preserves the ciphertext and restoring round-trips it. Without
/// the carry the archive INSERT-SELECT would drop the column (DEFAULT
/// NULL) and the ciphertext would be unrecoverable once Commit B wires
/// encryption. Exercises archive_memory (→ archive_memory_no_tx) +
/// restore_archived. (pg twin lives in the postgres_side mod once the pg
/// carry lands.)
#[test]
fn sqlite_archive_restore_carries_encrypted_envelope_1728() {
    let conn = fresh_sqlite();
    let id = seed_memory(&conn, "g1728-env", "test", "enc title", "placeholder");
    let envelope: Vec<u8> = vec![2, 7, 7, 7, 42, 99, 1, 0, 255, 16];
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        rusqlite::params![&envelope, &id],
    )
    .expect("set envelope on live row");

    let archived = db::archive_memory(&conn, &id, Some("manual")).expect("archive");
    assert!(archived);
    let arch_env: Vec<u8> = conn
        .query_row(
            "SELECT encrypted_envelope FROM archived_memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("archived row carries envelope");
    assert_eq!(
        arch_env, envelope,
        "archive carries the ciphertext envelope"
    );

    let restored = db::restore_archived(&conn, &id).expect("restore");
    assert!(restored);
    let live_env: Vec<u8> = conn
        .query_row(
            "SELECT encrypted_envelope FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("restored row carries envelope");
    assert_eq!(
        live_env, envelope,
        "restore round-trips the ciphertext envelope"
    );
}

#[test]
fn sqlite_update_inside_caller_transaction_does_not_nest_1725() {
    let conn = fresh_sqlite();
    let id = seed_memory(&conn, "g1725-tx", "test", "tx title", "content-v1");

    conn.execute_batch("BEGIN IMMEDIATE")
        .expect("open the caller's outer transaction");
    let (ok, changed) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some("content-v2"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_until
    )
    .expect("in-place update inside an open tx must NOT nest-error");
    assert!(ok && changed, "update applied with content_changed");
    conn.execute_batch("COMMIT")
        .expect("commit the caller's tx");

    // The live row carries the new content and the in_place_edit snapshot
    // of the prior content was archived inside (and committed with) the
    // caller's transaction.
    let live: String = conn
        .query_row(
            "SELECT content FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("live row");
    assert_eq!(live, "content-v2");
    let archived: String = conn
        .query_row(
            "SELECT content FROM archived_memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("in_place_edit archive committed with the caller tx");
    assert_eq!(archived, "content-v1");
}

// ─────────────────────────────────────────────────────────────────────
// v0.7.0 #1117 — sqlite-side parity pin for the SAL trait `update`
// version bump (#1024). Postgres parity pin lives in `postgres_side`
// below as `trait_update_bumps_version_1024`; this is the sqlite
// reference companion. Gated on the `sal` feature because the SAL
// trait (`MemoryStore`, `SqliteStore`) lives behind it.
// ─────────────────────────────────────────────────────────────────────

/// v0.7.0 #1024 + #1117 — sqlite `MemoryStore::update` MUST bump
/// `memories.version` on every call. The sqlite adapter delegates to
/// `crate::storage::update` which has carried the version bump since
/// schema v45 (#884 Gap-1), but there was no `_1024`-tagged regression
/// test pinning the SAL-trait-surface behavior. A future refactor of
/// the sqlite adapter that bypasses the version bump (e.g. an `UPDATE`
/// helper that forgets `version = version + 1`) would silently break
/// optimistic-concurrency parity with postgres.
///
/// The test mirrors the postgres `trait_update_bumps_version_1024`
/// shape so a single grep on `_1024` surfaces both halves of the
/// parity contract.
#[cfg(feature = "sal")]
#[tokio::test]
async fn sqlite_trait_update_bumps_version_1024() {
    use ai_memory::store::MemoryStore;
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = ai_memory::store::sqlite::SqliteStore::open(tmp.path().join("trait-update.db"))
        .expect("open SqliteStore");
    // `for_admin` sets `bypass_visibility=true` so the seeded row is
    // readable back through `store.get` regardless of the metadata
    // agent_id visibility-gate match.
    let ctx = ai_memory::store::CallerContext::for_admin("parity-test-1117");
    let mem = Memory {
        id: "sqlite-1024-version".to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "parity-test".to_string(),
        title: "title-trait-update-1024".to_string(),
        content: "parity test content".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "parity-test-1117"}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    store.store(&ctx, &mem).await.expect("seed");
    let after_seed = store.get(&ctx, &mem.id).await.expect("get after seed");
    assert_eq!(
        after_seed.version, 1,
        "#1024 sqlite: fresh upsert MUST land at version=1"
    );

    let patch1 = ai_memory::store::UpdatePatch {
        content: Some("first update".to_string()),
        ..ai_memory::store::UpdatePatch::default()
    };
    store
        .update(&ctx, &mem.id, patch1)
        .await
        .expect("trait update #1");
    let after_1 = store.get(&ctx, &mem.id).await.expect("get #1");
    assert_eq!(
        after_1.version, 2,
        "#1024 sqlite: first trait update MUST bump version 1 → 2; got {}",
        after_1.version
    );

    let patch2 = ai_memory::store::UpdatePatch {
        content: Some("second update".to_string()),
        ..ai_memory::store::UpdatePatch::default()
    };
    store
        .update(&ctx, &mem.id, patch2)
        .await
        .expect("trait update #2");
    let after_2 = store.get(&ctx, &mem.id).await.expect("get #2");
    assert_eq!(
        after_2.version, 3,
        "#1024 sqlite: second trait update MUST bump version 2 → 3; got {}",
        after_2.version
    );
}

/// FBL-12 residual (#2378) — sqlite reference companion to
/// `postgres_side::pg_charge_update_growth_over_cap_returns_quota_exceeded_2378`
/// (which is `#[ignore]`-gated on a live PG host, so it never actuates in
/// CI). This half runs unconditionally and pins the sqlite trait impl's
/// three cheap arms so the two backends demonstrably agree on the
/// no-charge cases:
///
/// - an EMPTY owner charges nothing and returns `Ok(0)` — an update on a
///   row with no resolvable owner has nobody to bill, and inventing a
///   charge against `""` would corrupt an unrelated counter;
/// - a shrink / no-op (`new_bytes <= old_bytes`) charges nothing — a
///   caller cannot bank storage credit by shrinking a row;
/// - a positive growth charges exactly `new_bytes - old_bytes`.
#[cfg(feature = "sal")]
#[tokio::test]
async fn sqlite_charge_update_growth_no_charge_arms_2378() {
    use ai_memory::store::MemoryStore;
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = ai_memory::store::sqlite::SqliteStore::open(tmp.path().join("grow-2378.db"))
        .expect("open SqliteStore");
    let ctx = ai_memory::store::CallerContext::for_admin("parity-test-2378");
    let ns = "parity-test";

    // Empty owner → Ok(0), and no quota row is conjured for `""`.
    let anon = store
        .charge_update_growth(&ctx, "", ns, 0, 4096)
        .await
        .expect("empty owner is a no-op, not an error");
    assert_eq!(anon, 0, "an ownerless update must charge nobody");

    // Shrink / no-op → Ok(0).
    let shrink = store
        .charge_update_growth(&ctx, "sqlite-grow-2378", ns, 500, 100)
        .await
        .expect("shrink is a no-op");
    assert_eq!(shrink, 0, "shrink/no-op must charge zero");
    let equal = store
        .charge_update_growth(&ctx, "sqlite-grow-2378", ns, 250, 250)
        .await
        .expect("equal bytes is a no-op");
    assert_eq!(equal, 0, "an unchanged byte count must charge zero");

    // Positive growth charges exactly the delta, and the counter agrees.
    let delta = store
        .charge_update_growth(&ctx, "sqlite-grow-2378", ns, 100, 250)
        .await
        .expect("within-cap growth charges");
    assert_eq!(delta, 150, "growth charges exactly new_bytes - old_bytes");
    let rows = store
        .quota_status_list_ns(ns)
        .await
        .expect("quota_status_list_ns");
    let row = rows
        .iter()
        .find(|r| r.agent_id == "sqlite-grow-2378")
        .expect("charged agent has a quota row");
    assert_eq!(
        row.current_storage_bytes, 150,
        "only the positive delta landed on the counter"
    );
    assert!(
        !rows.iter().any(|r| r.agent_id.is_empty()),
        "the empty-owner no-op must not create a quota row"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Postgres-side gate — compiles under `sal-postgres`; skipped on
// `cargo test` by `#[ignore]` so this development node (which cannot
// reach the 192.168.1.50 PG host per the documented Track-C/D
// network blocker, issue #79) stays green. When the network gap is
// closed, an operator runs `cargo test --features sal-postgres
// --ignored -- store_parity_gaps` with `AI_MEMORY_TEST_POSTGRES_URL`
// pointing at the live host to actuate the parity assertions.
//
// Every postgres-side test self-skips with a tracing::info call when
// the env var is unset, so an accidental `--ignored` run from a node
// without PG routing still succeeds quietly rather than erroring.
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
mod postgres_side {
    use super::{
        verify_gap_1_version_sqlite, verify_gap_2_source_uri_sqlite,
        verify_gap_3_recall_observations_sqlite, verify_gap_5_edit_source_sqlite,
        verify_gap_6_search_source_uri_sqlite, verify_gap_7_get_links_columns_sqlite,
        verify_gap_1725_in_place_archive_sqlite,
        verify_gap_2221_supersede_rearchive_lastwins_sqlite,
    };
    use ai_memory::models::Memory;
    use ai_memory::store::postgres::PostgresStore;

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "skipping postgres parity verify: PostgresStore::connect failed: {e}\n\
                     (test-infra blocker per issue #79 — 192.168.50.100 ↔ 192.168.1.50 routing)"
                );
                None
            }
        }
    }

    /// Gap 1 (#884) — postgres twin of `verify_gap_1_version_sqlite`.
    /// Exercises `PostgresStore::update_with_expected_version`'s
    /// optimistic-concurrency gate end-to-end.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_gap_1_version() {
        let Some(pg) = live_pg().await else {
            return;
        };
        // Sqlite reference still runs to pin the contract shape.
        verify_gap_1_version_sqlite();

        // Postgres-side: seed a row, drive the version gate.
        let ctx = ai_memory::store::CallerContext::for_agent("parity-test");
        let mem = sample_memory("pg-g1");
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &mem).await;

        let patch = ai_memory::store::UpdatePatch {
            title: Some("v2".to_string()),
            ..ai_memory::store::UpdatePatch::default()
        };
        // #1628 — the inherent helper now takes a CallerContext and
        // applies the caller-owns gate. The fixture row carries no
        // `metadata.agent_id` stamp, so exercise the version gate via
        // the admin/bypass context (the owner gate + handler routing
        // are pinned by `tests/pg_fix3_parity_tests.rs`).
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test");
        let new_v = pg
            .update_with_expected_version(&admin_ctx, &mem.id, patch.clone(), Some(1))
            .await
            .expect("first update succeeds");
        assert_eq!(new_v, 2);

        // Stale expected_version must fail with the typed envelope.
        let err = pg
            .update_with_expected_version(&admin_ctx, &mem.id, patch, Some(1))
            .await
            .expect_err("stale expected_version must conflict");
        let msg = format!("{err}");
        assert!(
            msg.contains("VersionConflict"),
            "expected VersionConflict, got: {msg}"
        );
    }

    /// FBL-12 residual (#2378) — postgres `charge_update_growth`: a
    /// content-growth charge that would breach `max_storage_bytes` is
    /// refused with the typed `QuotaExceeded` (→ HTTP 429) via the single
    /// TOCTOU-free conditional UPDATE, while a within-cap growth charges
    /// the delta and a shrink / no-op charges nothing. This is the pg twin
    /// of the sqlite `crate::quotas::charge_update_growth` contract that
    /// the HTTP `PUT /memories/{id}` postgres branch now consults.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_charge_update_growth_over_cap_returns_quota_exceeded_2378() {
        use ai_memory::store::{MemoryStore, StoreError};
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = ai_memory::store::CallerContext::for_agent("parity-test-2378");
        let ns = "q2378";

        // A shrink / no-op charges nothing.
        let owner_noop = "pg-grow-noop-2378";
        let z = MemoryStore::charge_update_growth(&pg, &ctx, owner_noop, ns, 500, 100)
            .await
            .expect("shrink is a no-op");
        assert_eq!(z, 0, "shrink/no-op must charge zero");

        // A within-cap growth charges the delta and returns it.
        let owner_ok = "pg-grow-ok-2378";
        let d = MemoryStore::charge_update_growth(&pg, &ctx, owner_ok, ns, 0, 128)
            .await
            .expect("within-cap growth charges");
        assert_eq!(d, 128, "within-cap growth returns the charged delta");
        // Compensating refund keeps the shared pg row from accumulating
        // across repeated --ignored runs.
        pg.refund_update_growth(owner_ok, ns, 128).await;

        // A growth larger than the 100 MiB default cap is refused,
        // regardless of any residual from prior runs (current + 200 MiB
        // always exceeds a 100 MiB ceiling).
        let owner_cap = "pg-grow-cap-2378";
        let over = 200 * 1024 * 1024;
        let err = MemoryStore::charge_update_growth(&pg, &ctx, owner_cap, ns, 0, over)
            .await
            .expect_err("growth past cap must be refused");
        match err {
            StoreError::QuotaExceeded { limit, .. } => {
                assert_eq!(
                    limit,
                    ai_memory::quotas::QuotaLimit::StorageBytes.as_str(),
                    "limit names storage_bytes"
                );
            }
            other => panic!("expected QuotaExceeded, got: {other}"),
        }
    }

    /// #1725 (P0.2) — postgres twin of
    /// `verify_gap_1725_in_place_archive_sqlite`. Drives the lossless
    /// in-place update path through `PostgresStore` and asserts the
    /// prior content lands in `archived_memories` with
    /// `archive_reason='in_place_edit'`, the SAME memory_id, single-
    /// snapshot (most-recent) retention across two edits, and no archive
    /// on a non-content edit. Catches the `ON CONFLICT DO NOTHING`
    /// (keep-oldest) parity divergence the sqlite `INSERT OR REPLACE`
    /// reference does not have.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_gap_1725_in_place_archive() {
        let Some(pg) = live_pg().await else {
            return;
        };
        // Sqlite reference still runs to pin the contract shape.
        verify_gap_1725_in_place_archive_sqlite();

        // The fixture carries no metadata.agent_id, so drive the
        // caller-owns gate via the admin/bypass context (same idiom as
        // `pg_parity_gap_1_version`).
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test");
        let mut mem = sample_memory("pg-g1725");
        mem.content = "content-v1".to_string();
        let _ = ai_memory::store::MemoryStore::store(&pg, &admin_ctx, &mem).await;

        // Edit 1: content v1 → v2. Archives v1 under 'in_place_edit'.
        let p1 = ai_memory::store::UpdatePatch {
            content: Some("content-v2".to_string()),
            ..ai_memory::store::UpdatePatch::default()
        };
        pg.update_with_expected_version(&admin_ctx, &mem.id, p1, None)
            .await
            .expect("edit 1");
        let (a_content, a_reason): (String, String) =
            sqlx::query_as("SELECT content, archive_reason FROM archived_memories WHERE id = $1")
                .bind(&mem.id)
                .fetch_one(pg.pool())
                .await
                .expect("archive row after edit 1");
        assert_eq!(a_content, "content-v1", "archive holds the prior content");
        assert_eq!(a_reason, "in_place_edit");

        // memory_id UNCHANGED + live row carries the NEW content.
        let live: String = sqlx::query_scalar("SELECT content FROM memories WHERE id = $1")
            .bind(&mem.id)
            .fetch_one(pg.pool())
            .await
            .expect("live row after edit 1");
        assert_eq!(live, "content-v2", "live row has new content, same id");

        // Edit 2: content v2 → v3. Most-recent snapshot (v2), ONE row.
        let p2 = ai_memory::store::UpdatePatch {
            content: Some("content-v3".to_string()),
            ..ai_memory::store::UpdatePatch::default()
        };
        pg.update_with_expected_version(&admin_ctx, &mem.id, p2, None)
            .await
            .expect("edit 2");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories WHERE id = $1")
            .bind(&mem.id)
            .fetch_one(pg.pool())
            .await
            .expect("count archive after edit 2");
        assert_eq!(count, 1, "single-snapshot retention (most-recent)");
        let a2: String = sqlx::query_scalar("SELECT content FROM archived_memories WHERE id = $1")
            .bind(&mem.id)
            .fetch_one(pg.pool())
            .await
            .expect("archive content after edit 2");
        assert_eq!(
            a2, "content-v2",
            "keeps immediately-prior snapshot (v2), not original (v1)"
        );

        // Non-content edit (priority only) archives NOTHING.
        let mut mem2 = sample_memory("pg-g1725-b");
        mem2.content = "stable content".to_string();
        let _ = ai_memory::store::MemoryStore::store(&pg, &admin_ctx, &mem2).await;
        let p3 = ai_memory::store::UpdatePatch {
            priority: Some(9),
            ..ai_memory::store::UpdatePatch::default()
        };
        pg.update_with_expected_version(&admin_ctx, &mem2.id, p3, None)
            .await
            .expect("priority-only edit");
        let nonc: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories WHERE id = $1")
            .bind(&mem2.id)
            .fetch_one(pg.pool())
            .await
            .expect("count archive non-content");
        assert_eq!(nonc, 0, "metadata/priority-only edit archives nothing");
    }

    /// #2221 (data-integrity archive-parity) — postgres twin of
    /// `verify_gap_2221_supersede_rearchive_lastwins_sqlite`. Superseding
    /// a memory whose OLD id already carries an `archived_memories` row
    /// (an `in_place_edit` snapshot; live row still present) must SUCCEED
    /// and OVERWRITE that snapshot last-wins. Pre-#2221 the pg supersede
    /// Step-1 archive INSERT used `ON CONFLICT (id) DO NOTHING` + a
    /// 0-rows-affected `NotFound`, so this exact case ROLLED BACK with a
    /// mistyped `NotFound` for a memory that EXISTS — while the sqlite
    /// reference (INSERT OR REPLACE) succeeded. This twin FAILS on the
    /// old pg behavior and passes once the site adopts the shared
    /// `SQL_ARCHIVE_ON_CONFLICT_LAST_WINS` clause.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_gap_2221_supersede_rearchive_lastwins() {
        let Some(pg) = live_pg().await else {
            return;
        };
        // Sqlite reference pins the last-wins contract shape.
        verify_gap_2221_supersede_rearchive_lastwins_sqlite();

        let ctx = ai_memory::store::CallerContext::for_agent("parity-test");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let mut mem = sample_memory(&format!("pg-g2221-{run}"));
        mem.content = "content-v1".to_string();
        mem.metadata = serde_json::json!({ "agent_id": "parity-test" });
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &mem).await;

        // Precondition: an in-place content edit snapshots content-v1 into
        // archived_memories under archive_reason='in_place_edit' (SAME id,
        // live row kept at content-v2) — the row the supersede must
        // overwrite last-wins rather than choke on.
        let p1 = ai_memory::store::UpdatePatch {
            content: Some("content-v2".to_string()),
            ..ai_memory::store::UpdatePatch::default()
        };
        pg.update_with_expected_version(&ctx, &mem.id, p1, None)
            .await
            .expect("in-place edit");
        let pre_reason: String =
            sqlx::query_scalar("SELECT archive_reason FROM archived_memories WHERE id = $1")
                .bind(&mem.id)
                .fetch_one(pg.pool())
                .await
                .expect("in_place_edit snapshot exists");
        assert_eq!(pre_reason, "in_place_edit", "precondition snapshot present");

        // Supersede X. Pre-#2221 this returned Err(NotFound) because the
        // ON CONFLICT (id) DO NOTHING left rows_affected == 0 against the
        // pre-existing archive row; post-#2221 the last-wins DO UPDATE
        // succeeds — byte-parity with the sqlite INSERT OR REPLACE.
        let patch = ai_memory::store::UpdatePatch {
            content: Some("content-v3".to_string()),
            ..ai_memory::store::UpdatePatch::default()
        };
        let (archived_id, new_id) = pg
            .update_with_archive_on_supersede(
                &mem.id,
                patch,
                None,
                ai_memory::models::EditSource::Llm,
            )
            .await
            .expect("supersede must succeed even with a pre-existing archive row");
        assert_eq!(archived_id, mem.id, "archived_id is the OLD id");
        assert_ne!(new_id, mem.id, "new_id is freshly minted");

        // Last-wins: the archive row for the OLD id now carries reason
        // 'superseded' and the OLD LIVE payload (content-v2), overwriting
        // the stale in_place_edit snapshot — byte-identical to sqlite.
        let (a_reason, a_content): (String, String) =
            sqlx::query_as("SELECT archive_reason, content FROM archived_memories WHERE id = $1")
                .bind(&mem.id)
                .fetch_one(pg.pool())
                .await
                .expect("archive row after supersede");
        assert_eq!(a_reason, "superseded", "reason overwritten last-wins");
        assert_eq!(
            a_content, "content-v2",
            "archived payload is the OLD live row (last-wins), not the stale snapshot"
        );

        // OLD row evicted from live; the NEW row carries content-v3.
        let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE id = $1")
            .bind(&mem.id)
            .fetch_one(pg.pool())
            .await
            .expect("count live old");
        assert_eq!(live, 0, "OLD row evicted from live memories");
        let new_content: String = sqlx::query_scalar("SELECT content FROM memories WHERE id = $1")
            .bind(&new_id)
            .fetch_one(pg.pool())
            .await
            .expect("new row content");
        assert_eq!(
            new_content, "content-v3",
            "new row carries the patched content"
        );
    }

    /// #228 / #1728 Commit A-carry — postgres twin of
    /// `sqlite_archive_restore_carries_encrypted_envelope_1728`. The pg
    /// archive → restore SQL copy paths must carry the
    /// `encrypted_envelope` BYTEA column, so archiving an encrypted
    /// memory preserves the ciphertext and restoring round-trips it.
    /// Drives `archive_by_ids` (archive INSERT-SELECT carry) +
    /// `archive_restore` (restore INSERT-SELECT carry) through
    /// `PostgresStore` against a known envelope written via raw sqlx.
    /// Without the carry the INSERT-SELECT would drop the column
    /// (DEFAULT NULL) and the ciphertext would be unrecoverable.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_archive_restore_carries_encrypted_envelope_1728() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        // Sqlite reference pins the contract shape.
        super::sqlite_archive_restore_carries_encrypted_envelope_1728();

        // The fixture carries no metadata.agent_id, so drive the
        // archive/restore paths via the admin/bypass context.
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-1728");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let mem = sample_memory(&format!("pg-1728-env-{run}"));
        let _ = MemoryStore::store(&pg, &admin_ctx, &mem).await;

        // Stamp a known ciphertext envelope onto the live row.
        let envelope: Vec<u8> = vec![2, 7, 7, 7, 42, 99, 1, 0, 255, 16];
        sqlx::query("UPDATE memories SET encrypted_envelope = $1 WHERE id = $2")
            .bind(&envelope)
            .bind(&mem.id)
            .execute(pg.pool())
            .await
            .expect("set envelope on live row");

        // Archive: the INSERT-SELECT must carry the envelope into
        // archived_memories.
        let moved = pg
            .archive_by_ids(&admin_ctx, std::slice::from_ref(&mem.id), Some("manual"))
            .await
            .expect("archive_by_ids");
        assert_eq!(moved, 1, "one row archived");
        let arch_env: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_envelope FROM archived_memories WHERE id = $1")
                .bind(&mem.id)
                .fetch_one(pg.pool())
                .await
                .expect("archived row carries envelope");
        assert_eq!(
            arch_env, envelope,
            "archive carries the ciphertext envelope"
        );

        // Restore: the INSERT-SELECT must round-trip the envelope back
        // onto the live memories row.
        let restored = pg
            .archive_restore(&admin_ctx, &mem.id)
            .await
            .expect("archive_restore");
        assert!(restored, "restore reports success");
        let live_env: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_envelope FROM memories WHERE id = $1")
                .bind(&mem.id)
                .fetch_one(pg.pool())
                .await
                .expect("restored row carries envelope");
        assert_eq!(
            live_env, envelope,
            "restore round-trips the ciphertext envelope"
        );
    }

    /// #228 Commit B — postgres twin of the sqlite ON-path test
    /// (`commit_b_on_path_seals_content_and_get_decrypts`). With the
    /// `AI_MEMORY_ENCRYPT_AT_REST` gate on, `PostgresStore::store` seals
    /// content into `encrypted_envelope` (BYTEA), the `content` column
    /// holds the empty placeholder, and `MemoryStore::get` transparently
    /// decrypts. agent_id on the row matches the seal recipient.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_commit_b_on_path_seals_and_get_decrypts_228() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: pg tests are #[ignore] and run serially under --ignored.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        let agent = "pg-commit-b-on-agent";
        let run = uuid::Uuid::new_v4().simple().to_string();
        let plaintext = "pg sensitive content — #228 Commit B ON";
        let mut mem = sample_memory(&format!("pg-commitb-on-{run}"));
        mem.content = plaintext.to_string();
        mem.metadata = serde_json::json!({ "agent_id": agent });
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-228");
        let id = MemoryStore::store(&pg, &admin_ctx, &mem)
            .await
            .expect("store under encryption");

        // Raw row: content placeholder empty, envelope non-NULL.
        let (raw_content, envelope): (String, Option<Vec<u8>>) =
            sqlx::query_as("SELECT content, encrypted_envelope FROM memories WHERE id = $1")
                .bind(&id)
                .fetch_one(pg.pool())
                .await
                .expect("raw read");
        assert_eq!(
            raw_content, "",
            "content column holds the empty placeholder"
        );
        assert!(envelope.is_some(), "encrypted_envelope must be non-NULL");

        // get transparently decrypts.
        let fetched = MemoryStore::get(&pg, &admin_ctx, &id).await.expect("get");
        assert_eq!(
            fetched.content, plaintext,
            "#228 Commit B (pg): get must recover the plaintext"
        );

        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
    }

    /// #2288 — at-rest encryption parity for the BULK funnel. Under the
    /// `AI_MEMORY_ENCRYPT_AT_REST` gate, `PostgresStore::store_batch` MUST
    /// seal each row exactly as `store()` does: `content` holds the empty
    /// placeholder, `encrypted_envelope` (BYTEA) carries the ciphertext,
    /// and `MemoryStore::get` transparently decrypts. Pre-#2288 the bulk
    /// funnel bound plaintext into `content` and NEVER populated the
    /// envelope, so `POST /api/v1/memories/bulk` persisted PLAINTEXT while
    /// the operator believed at-rest encryption was on — a silent bypass.
    ///
    /// Teardown runs BEFORE the assertions (the shared `ai_memory_test`
    /// DB has no per-test isolation — #2287), so a failed assertion never
    /// leaks the seeded row.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_store_batch_seals_content_2288() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: pg tests are #[ignore] and run serially under --ignored.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        let agent = "pg-2288-batch-agent";
        let run = uuid::Uuid::new_v4().simple().to_string();
        let plaintext = "pg batch sensitive content — #2288 seal parity";
        let mut mem = sample_memory(&format!("pg-2288-batch-{run}"));
        mem.content = plaintext.to_string();
        mem.metadata = serde_json::json!({ "agent_id": agent });
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2288");

        let ids = MemoryStore::store_batch(&pg, &admin_ctx, std::slice::from_ref(&mem))
            .await
            .expect("store_batch under encryption");
        assert_eq!(ids.len(), 1, "one id returned");
        let id = ids[0].clone();

        // Raw row: content placeholder empty, envelope non-NULL.
        let (raw_content, envelope): (String, Option<Vec<u8>>) =
            sqlx::query_as("SELECT content, encrypted_envelope FROM memories WHERE id = $1")
                .bind(&id)
                .fetch_one(pg.pool())
                .await
                .expect("raw read");
        // get transparently decrypts.
        let fetched = MemoryStore::get(&pg, &admin_ctx, &id).await.expect("get");

        // Teardown FIRST so an assertion failure below never leaks the row.
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await;
        // SAFETY: restore the env before asserting.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }

        assert_eq!(
            raw_content, "",
            "#2288: store_batch content column must hold the empty placeholder, not plaintext"
        );
        assert!(
            !raw_content.contains("sensitive"),
            "#2288: the plaintext must never reach the content column"
        );
        assert!(
            envelope.is_some(),
            "#2288: store_batch must populate encrypted_envelope under the at-rest gate"
        );
        assert_eq!(
            fetched.content, plaintext,
            "#2288: get must transparently recover the sealed plaintext"
        );
    }

    // ================================================================
    // #2292 — at-rest content-seal parity for the remaining postgres
    // content-write funnels (siblings of #2288's `store_batch`). Each
    // funnel minted / rewrote a `memories` row via a bespoke INSERT/UPDATE
    // that bound plaintext into `content` and omitted `encrypted_envelope`,
    // so an `AI_MEMORY_ENCRYPT_AT_REST` deployment leaked plaintext while
    // `store()` sealed. All now route through `seal_content_for_insert`.
    //
    // Test design: every funnel has an ON-gate SEAL assertion (the
    // security-critical one — content column holds NO plaintext + envelope
    // present + `get` decrypts). The OFF-gate byte-identical assertion is
    // pinned on the two representative conflict shapes (unconditional:
    // `store_with_embedding`; newer-wins: `apply_remote_memory`); the
    // OFF branch is the shared `seal_content_for_insert` `None` arm
    // (verbatim content + NULL envelope) exercised identically by every
    // funnel, so those two pins cover the off-path for all eight.
    // #[ignore]-gated live-pg per convention; teardown-before-assert (#2287).
    // ================================================================

    /// #2292 — read the RAW `content` + `encrypted_envelope` for `id`, run
    /// `get` (which transparently decrypts while the gate is still ON), then
    /// DELETE the row (teardown BEFORE the caller asserts — shared DB, #2287).
    /// Returns `(raw_content, envelope, decrypted_content)`.
    async fn seal_probe_2292(
        pg: &PostgresStore,
        id: &str,
        ctx: &ai_memory::store::CallerContext,
    ) -> (String, Option<Vec<u8>>, String) {
        use ai_memory::store::MemoryStore;
        let (raw_content, envelope): (String, Option<Vec<u8>>) =
            sqlx::query_as("SELECT content, encrypted_envelope FROM memories WHERE id = $1")
                .bind(id)
                .fetch_one(pg.pool())
                .await
                .expect("raw read");
        let decrypted = MemoryStore::get(pg, ctx, id)
            .await
            .map(|m| m.content)
            .unwrap_or_default();
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(id)
            .execute(pg.pool())
            .await;
        (raw_content, envelope, decrypted)
    }

    fn assert_sealed_2292(raw: &str, env: Option<&Vec<u8>>, decrypted: &str, plaintext: &str) {
        assert_eq!(
            raw, "",
            "#2292: content column must hold the empty placeholder, not plaintext"
        );
        assert!(
            !raw.contains("SENSITIVE"),
            "#2292: the plaintext must never reach the content column"
        );
        assert!(
            env.is_some(),
            "#2292: encrypted_envelope must be populated under the at-rest gate"
        );
        assert_eq!(
            decrypted, plaintext,
            "#2292: get must transparently recover the sealed plaintext"
        );
    }

    /// #2292 — `store_with_embedding` (PRIMARY embedded-write hot path).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_store_with_embedding_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();

        // ── ON: content is sealed. ──────────────────────────────────
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: pg tests are #[ignore] and run serially under --ignored.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };
        let plaintext = "pg SENSITIVE 2292 store_with_embedding";
        let mut mem = sample_memory(&format!("pg-2292-swe-on-{run}"));
        mem.content = plaintext.to_string();
        mem.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let id = MemoryStore::store_with_embedding(&pg, &admin_ctx, &mem, None, None)
            .await
            .expect("store_with_embedding under encryption");
        let (raw, env, dec) = seal_probe_2292(&pg, &id, &admin_ctx).await;
        // SAFETY: restore env before asserting.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
        assert_sealed_2292(&raw, env.as_ref(), &dec, plaintext);

        // ── OFF: byte-identical — plaintext stored, envelope NULL. ───
        let prev_off = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: as above.
        unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };
        let off_plain = "pg plaintext-when-off 2292 swe";
        let mut mem_off = sample_memory(&format!("pg-2292-swe-off-{run}"));
        mem_off.content = off_plain.to_string();
        mem_off.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let off_id = MemoryStore::store_with_embedding(&pg, &admin_ctx, &mem_off, None, None)
            .await
            .expect("store_with_embedding, gate off");
        let (raw_off, env_off, dec_off) = seal_probe_2292(&pg, &off_id, &admin_ctx).await;
        // SAFETY: restore.
        unsafe {
            if let Some(v) = prev_off {
                std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v);
            }
        }
        assert_eq!(
            raw_off, off_plain,
            "#2292: gate OFF stores plaintext verbatim (byte-identical)"
        );
        assert!(
            env_off.is_none(),
            "#2292: gate OFF leaves encrypted_envelope NULL"
        );
        assert_eq!(dec_off, off_plain, "#2292: gate OFF get returns plaintext");
    }

    /// #2292 — `apply_remote_memory` (federation inbound; NEWER-WINS
    /// content arm, so the envelope arm must move in lockstep). Fresh-insert
    /// path (unique title) exercises the seal on the INSERT; the ON-conflict
    /// lockstep CASE is asserted structurally by the SQL text.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_apply_remote_memory_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();

        // ── ON. ─────────────────────────────────────────────────────
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };
        let plaintext = "pg SENSITIVE 2292 apply_remote";
        let mut mem = sample_memory(&format!("pg-2292-remote-on-{run}"));
        mem.content = plaintext.to_string();
        mem.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let id = MemoryStore::apply_remote_memory(&pg, &admin_ctx, &mem)
            .await
            .expect("apply_remote_memory under encryption");
        let (raw, env, dec) = seal_probe_2292(&pg, &id, &admin_ctx).await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
        assert_sealed_2292(&raw, env.as_ref(), &dec, plaintext);

        // ── OFF: byte-identical. ────────────────────────────────────
        let prev_off = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: as above.
        unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };
        let off_plain = "pg plaintext-when-off 2292 remote";
        let mut mem_off = sample_memory(&format!("pg-2292-remote-off-{run}"));
        mem_off.content = off_plain.to_string();
        mem_off.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let off_id = MemoryStore::apply_remote_memory(&pg, &admin_ctx, &mem_off)
            .await
            .expect("apply_remote_memory, gate off");
        let (raw_off, env_off, _dec) = seal_probe_2292(&pg, &off_id, &admin_ctx).await;
        // SAFETY: restore.
        unsafe {
            if let Some(v) = prev_off {
                std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v);
            }
        }
        assert_eq!(
            raw_off, off_plain,
            "#2292: apply_remote gate OFF stores plaintext verbatim"
        );
        assert!(
            env_off.is_none(),
            "#2292: apply_remote gate OFF leaves encrypted_envelope NULL"
        );
    }

    /// #2303 — pin the federation-send-decrypts invariant on postgres.
    /// `list_memories_updated_since` backs the `GET /api/v1/sync/since`
    /// federation peer-pull surface. At-rest encryption seals a row's
    /// plaintext into `encrypted_envelope`, leaving `content=""` as a
    /// storage sentinel; the #2292 `apply_remote_memory` receive-side
    /// sealing is safe ONLY because this SEND path decrypts before
    /// shipping. If it ever shipped the raw sealed row instead, a
    /// receiving peer would re-seal that EMPTY string under its own
    /// key — content='' + a fresh envelope, unrecoverable silent
    /// content loss with no error anywhere. This asserts the send-path
    /// read returns decrypted plaintext, not the placeholder, so a
    /// future regression that skips the decrypt fails this test.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_list_memories_updated_since_decrypts_for_send_2303() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2303");
        let run = uuid::Uuid::new_v4().simple().to_string();

        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        // Capture a tight since-bound BEFORE the insert so the send-path
        // read below scopes to just this row on a shared live DB.
        let since_ts = chrono::Utc::now().to_rfc3339();
        let plaintext = "pg SENSITIVE 2303 fed-send";
        let mut mem = sample_memory(&format!("pg-2303-fed-send-{run}"));
        mem.content = plaintext.to_string();
        mem.metadata = serde_json::json!({ "agent_id": "pg-2303-agent" });
        let id = MemoryStore::store_with_embedding(&pg, &admin_ctx, &mem, None, None)
            .await
            .expect("store under encryption");

        // Sanity: the on-disk row IS sealed before the send-path read.
        let (raw, env): (String, Option<Vec<u8>>) =
            sqlx::query_as("SELECT content, encrypted_envelope FROM memories WHERE id = $1")
                .bind(&id)
                .fetch_one(pg.pool())
                .await
                .expect("raw read");
        assert_eq!(
            raw, "",
            "#2303: sanity — at-rest row must hold the sealed placeholder"
        );
        assert!(
            env.is_some(),
            "#2303: sanity — at-rest row must carry a non-NULL envelope"
        );

        // The federation SEND path itself.
        let sent = MemoryStore::list_memories_updated_since(&pg, Some(&since_ts), 5000)
            .await
            .expect("list_memories_updated_since");
        let wire = sent.iter().find(|m| m.id == id).map(|m| m.content.clone());

        // Teardown before asserting (shared DB, #2287 convention).
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }

        let wire_content = wire.expect("#2303: row must be present in the send-path result");
        assert_eq!(
            wire_content, plaintext,
            "#2303: federation send path must ship DECRYPTED plaintext, not the sealed placeholder"
        );
        assert_ne!(
            wire_content, "",
            "#2303: federation send path must never ship the empty sealed placeholder"
        );
    }

    /// #2292 — `capture_turn_idempotent` (L4 turn capture).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_capture_turn_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        let plaintext = "pg SENSITIVE 2292 capture_turn";
        let mut mem = sample_memory(&format!("pg-2292-capture-{run}"));
        mem.content = plaintext.to_string();
        mem.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let ev = ai_memory::signed_events::SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "pg-2292-agent".to_string(),
            event_type: "l4.capture".to_string(),
            payload_hash: vec![0u8; 32],
            signature: None,
            attest_level: "claimed".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        };
        let write = ai_memory::models::CaptureTurnWrite {
            memory: mem.clone(),
            sha256: uuid::Uuid::new_v4().as_bytes().to_vec(),
            host_kind: "claude-code".to_string(),
            host_session_id: format!("sess-{run}"),
            host_turn_index: 0,
            recovered_at_ms: 0,
            signed_event: ev,
        };
        let res = MemoryStore::capture_turn_idempotent(&pg, &admin_ctx, &write)
            .await
            .expect("capture_turn under encryption");
        let (raw, env, dec) = seal_probe_2292(&pg, &res.memory_id, &admin_ctx).await;
        // Best-effort dedup-row cleanup so re-runs stay isolated.
        let _ = sqlx::query("DELETE FROM transcript_line_dedup WHERE host_session_id = $1")
            .bind(format!("sess-{run}"))
            .execute(pg.pool())
            .await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
        assert_sealed_2292(&raw, env.as_ref(), &dec, plaintext);
    }

    /// #2292 — `recover_turn_idempotent` (L2 transcript recovery).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_recover_turn_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        let plaintext = "pg SENSITIVE 2292 recover_turn";
        let mut mem = sample_memory(&format!("pg-2292-recover-{run}"));
        mem.content = plaintext.to_string();
        mem.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let norm = uuid::Uuid::new_v4().as_bytes().to_vec();
        let write = ai_memory::models::RecoverTurnWrite {
            memory: mem.clone(),
            normalized_sha256: norm.clone(),
            raw_sha256: uuid::Uuid::new_v4().as_bytes().to_vec(),
            host_kind: "claude-code".to_string(),
            transcript_path: format!("/x/{run}"),
            host_session_id: None,
            host_turn_index: None,
            recovered_at_ms: 0,
        };
        let res = MemoryStore::recover_turn_idempotent(&pg, &admin_ctx, &write)
            .await
            .expect("recover_turn under encryption");
        let (raw, env, dec) = seal_probe_2292(&pg, &res.memory_id, &admin_ctx).await;
        let _ = sqlx::query("DELETE FROM transcript_line_dedup WHERE sha256 = $1")
            .bind(norm)
            .execute(pg.pool())
            .await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
        assert_sealed_2292(&raw, env.as_ref(), &dec, plaintext);
    }

    /// #2292 — `reflect_with_hooks` (reflection synthesis; the derived
    /// `content` is `input.content`).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_reflect_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let ns = format!("parity-test/2292-reflect-{run}");
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        // Seed one source memory to reflect on.
        let mut src = sample_memory(&format!("pg-2292-reflect-src-{run}"));
        src.namespace.clone_from(&ns);
        src.content = "source body".to_string();
        src.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let src_id = MemoryStore::store(&pg, &admin_ctx, &src)
            .await
            .expect("store reflect source");

        let plaintext = "pg SENSITIVE 2292 reflection body";
        let input = ai_memory::db::ReflectInput {
            source_ids: vec![src_id.clone()],
            title: format!("pg-2292-reflection-{run}"),
            content: plaintext.to_string(),
            namespace: Some(ns.clone()),
            tier: ai_memory::models::Tier::Mid,
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "nhi".to_string(),
            agent_id: "pg-2292-agent".to_string(),
            metadata: serde_json::json!({}),
        };
        let outcome = pg
            .reflect(&admin_ctx, &input)
            .await
            .expect("reflect under encryption");
        let (raw, env, dec) = seal_probe_2292(&pg, &outcome.id, &admin_ctx).await;
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(&src_id)
            .execute(pg.pool())
            .await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
        assert_sealed_2292(&raw, env.as_ref(), &dec, plaintext);
    }

    /// #2292 — `consolidate` (the consolidated `summary` is the sealed
    /// content).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_consolidate_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let ns = format!("parity-test/2292-consol-{run}");
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        let mut src = sample_memory(&format!("pg-2292-consol-src-{run}"));
        src.namespace.clone_from(&ns);
        src.content = "source body".to_string();
        src.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let src_id = MemoryStore::store(&pg, &admin_ctx, &src)
            .await
            .expect("store consolidate source");

        let plaintext = "pg SENSITIVE 2292 consolidated summary";
        let id = MemoryStore::consolidate(
            &pg,
            &admin_ctx,
            std::slice::from_ref(&src_id),
            &format!("pg-2292-consolidated-{run}"),
            plaintext,
            &ns,
            &ai_memory::models::Tier::Long,
            "test",
            "pg-2292-agent",
        )
        .await
        .expect("consolidate under encryption");
        let (raw, env, dec) = seal_probe_2292(&pg, &id, &admin_ctx).await;
        // Source rows are deleted by consolidate; best-effort sweep anyway.
        let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
            .bind(&ns)
            .execute(pg.pool())
            .await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
        assert_sealed_2292(&raw, env.as_ref(), &dec, plaintext);
    }

    /// #2292 — `update_with_archive_on_supersede` (the append-and-archive
    /// twin mints a NEW version row carrying the patched content).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_supersede_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        let mut orig = sample_memory(&format!("pg-2292-supersede-{run}"));
        orig.content = "original body".to_string();
        orig.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let old_id = MemoryStore::store(&pg, &admin_ctx, &orig)
            .await
            .expect("store supersede original");

        let plaintext = "pg SENSITIVE 2292 superseding body";
        let patch = ai_memory::store::UpdatePatch {
            content: Some(plaintext.to_string()),
            ..Default::default()
        };
        let (_old, new_id) = pg
            .update_with_archive_on_supersede(
                &old_id,
                patch,
                None,
                ai_memory::models::EditSource::Llm,
            )
            .await
            .expect("supersede under encryption");
        let (raw, env, dec) = seal_probe_2292(&pg, &new_id, &admin_ctx).await;
        let _ = sqlx::query("DELETE FROM archived_memories WHERE id = $1")
            .bind(&old_id)
            .execute(pg.pool())
            .await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
        assert_sealed_2292(&raw, env.as_ref(), &dec, plaintext);
    }

    /// #2292 — `merge_inbound` (same-id federation merge; the full-row UPDATE
    /// that the issue audit MISSED). Under an enabled gate a merge onto an
    /// EXISTING sealed row must re-seal the merged content, never overwrite
    /// it with plaintext + leave a stale envelope.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_merge_inbound_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        // Seed the existing row (sealed under the gate).
        let mut orig = sample_memory(&format!("pg-2292-merge-{run}"));
        orig.content = "original body".to_string();
        orig.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let id = MemoryStore::store(&pg, &admin_ctx, &orig)
            .await
            .expect("store merge original");

        // Inbound: SAME id, strictly-newer updated_at, new sensitive content
        // → merge_inbound resolves the by-id UPDATE path.
        let plaintext = "pg SENSITIVE 2292 merged inbound body";
        let mut inbound = orig.clone();
        inbound.id = id.clone();
        inbound.content = plaintext.to_string();
        inbound.updated_at = (chrono::Utc::now() + chrono::Duration::seconds(30)).to_rfc3339();
        let merged_id = MemoryStore::merge_inbound(&pg, &admin_ctx, &inbound)
            .await
            .expect("merge_inbound under encryption");
        assert_eq!(merged_id, id, "merge resolves the same-id UPDATE path");
        let (raw, env, dec) = seal_probe_2292(&pg, &id, &admin_ctx).await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
        assert_sealed_2292(&raw, env.as_ref(), &dec, plaintext);
    }

    /// #2292 — the 9th funnel: the DEFAULT (non-If-Match) trait `update()`.
    /// Pre-#2292 its live UPDATE bound `patch.content` PLAINTEXT via
    /// `content = COALESCE($3, content)` with NO `encrypted_envelope`, so a
    /// content patch under an enabled gate wrote V2 plaintext while the stale
    /// envelope kept cipher(V1) — `get()` (decrypts on envelope-PRESENCE)
    /// returned the OLD V1, silently LOSING the V2 update (worse than a leak).
    /// This asserts (a) a content patch seals V2 + `get()` returns the NEW V2,
    /// and (b) a follow-up METADATA-ONLY patch leaves the sealed envelope
    /// intact (the `$3 IS NULL` CASE guard — the same guard the If-Match twin
    /// now uses). Teardown-before-assert (#2287).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_update_seals_content_2292() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2292");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serial #[ignore] pg tests.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };

        // Seed the row with V1 (sealed under the gate).
        let mut orig = sample_memory(&format!("pg-2292-update-{run}"));
        orig.content = "original V1 body".to_string();
        orig.metadata = serde_json::json!({ "agent_id": "pg-2292-agent" });
        let id = MemoryStore::store(&pg, &admin_ctx, &orig)
            .await
            .expect("store V1");

        // Content patch V2 via the DEFAULT (non-If-Match) trait update.
        let v2 = "pg SENSITIVE 2292 update V2 body";
        let patch = ai_memory::store::UpdatePatch {
            content: Some(v2.to_string()),
            ..Default::default()
        };
        MemoryStore::update(&pg, &admin_ctx, &id, patch)
            .await
            .expect("update V2 under encryption");
        let (raw_c, env_c): (String, Option<Vec<u8>>) =
            sqlx::query_as("SELECT content, encrypted_envelope FROM memories WHERE id = $1")
                .bind(&id)
                .fetch_one(pg.pool())
                .await
                .expect("raw after content patch");
        let got_v2 = MemoryStore::get(&pg, &admin_ctx, &id)
            .await
            .map(|m| m.content)
            .unwrap_or_default();

        // Metadata-only patch (no content) — the sealed envelope must survive.
        let meta_patch = ai_memory::store::UpdatePatch {
            priority: Some(7),
            ..Default::default()
        };
        MemoryStore::update(&pg, &admin_ctx, &id, meta_patch)
            .await
            .expect("metadata-only update");
        let (raw_m, env_m): (String, Option<Vec<u8>>) =
            sqlx::query_as("SELECT content, encrypted_envelope FROM memories WHERE id = $1")
                .bind(&id)
                .fetch_one(pg.pool())
                .await
                .expect("raw after metadata patch");
        let got_after_meta = MemoryStore::get(&pg, &admin_ctx, &id)
            .await
            .map(|m| m.content)
            .unwrap_or_default();

        // Teardown BEFORE asserts (shared DB, #2287).
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await;
        let _ = sqlx::query("DELETE FROM archived_memories WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await;
        // SAFETY: restore.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }

        // (a) content patch sealed + NO silent data loss.
        assert_eq!(
            raw_c, "",
            "#2292: update content column must hold the placeholder, not plaintext V2"
        );
        assert!(
            !raw_c.contains("SENSITIVE"),
            "#2292: the V2 plaintext must never reach the content column"
        );
        assert!(
            env_c.is_some(),
            "#2292: update must populate encrypted_envelope for a content patch"
        );
        assert_eq!(
            got_v2, v2,
            "#2292: get must return the NEW V2 (no silent data loss back to stale V1)"
        );
        // (b) metadata-only patch preserved the sealed envelope.
        assert_eq!(
            raw_m, "",
            "#2292: metadata-only patch keeps the content placeholder"
        );
        assert!(
            env_m.is_some(),
            "#2292: metadata-only patch must NOT null the sealed envelope (CASE guard)"
        );
        assert_eq!(
            got_after_meta, v2,
            "#2292: metadata-only patch must preserve V2 (envelope untouched)"
        );
    }

    /// #2289 — `PostgresStore::store_batch` MUST persist the caller-supplied
    /// `kind_provenance` (#1945), mirroring `store()` and the sqlite
    /// trait-default loop. Pre-#2289 the bulk INSERT never listed the
    /// column, so a batch-stored memory silently dropped its epistemic-typing
    /// provenance on postgres. Teardown-before-assert (shared DB, #2287).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_store_batch_persists_kind_provenance_2289() {
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let mut mem = sample_memory(&format!("pg-2289-kp-{run}"));
        // `kind_provenance` rides `metadata` (extract_kind_provenance).
        mem.metadata = serde_json::json!({ "kind_provenance": "regex" });
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-2289");

        let ids = MemoryStore::store_batch(&pg, &admin_ctx, std::slice::from_ref(&mem))
            .await
            .expect("store_batch");
        let id = ids[0].clone();

        let kp: Option<String> =
            sqlx::query_scalar("SELECT kind_provenance FROM memories WHERE id = $1")
                .bind(&id)
                .fetch_one(pg.pool())
                .await
                .expect("read kind_provenance");

        // Teardown FIRST.
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await;

        assert_eq!(
            kp.as_deref(),
            Some("regex"),
            "#2289: store_batch must persist caller-supplied kind_provenance"
        );
    }

    /// #228 Commit B — postgres twin of the sqlite fail-closed test. A
    /// row with a non-NULL envelope whose recipient key cannot decrypt
    /// (sealed to agent A but the row names agent B) must FAIL the read
    /// (mapped to a StoreError), never leak the empty placeholder.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_commit_b_missing_key_fails_closed_on_read_228() {
        use ai_memory::encryption::{encrypt, get_or_create_keypair};
        use ai_memory::store::MemoryStore;
        let Some(pg) = live_pg().await else {
            return;
        };
        let seal_agent = "pg-commit-b-seal";
        let wrong_agent = "pg-commit-b-wrong";
        let kp = get_or_create_keypair(seal_agent).expect("keypair");
        let env_bytes = encrypt("pg secret for seal_agent", &kp.public)
            .expect("encrypt")
            .to_bytes();

        let run = uuid::Uuid::new_v4().simple().to_string();
        let mut mem = sample_memory(&format!("pg-commitb-fc-{run}"));
        mem.content = String::new();
        mem.metadata = serde_json::json!({ "agent_id": wrong_agent });
        let admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-228");
        let id = MemoryStore::store(&pg, &admin_ctx, &mem)
            .await
            .expect("store");

        // Stamp an envelope sealed to a DIFFERENT agent than the row names.
        sqlx::query("UPDATE memories SET encrypted_envelope = $1 WHERE id = $2")
            .bind(&env_bytes)
            .bind(&id)
            .execute(pg.pool())
            .await
            .expect("stamp mismatched envelope");

        let result = MemoryStore::get(&pg, &admin_ctx, &id).await;
        assert!(
            result.is_err(),
            "fail-closed (pg): an undecryptable envelope must error the read"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("decrypt failed"),
            "fail-closed (pg) error must name the decrypt failure; got: {msg}"
        );
    }

    /// Gap 2 (#885) — postgres twin of `verify_gap_2_source_uri_sqlite`.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_gap_2_source_uri_column() {
        let Some(pg) = live_pg().await else {
            return;
        };
        verify_gap_2_source_uri_sqlite();
        let ctx = ai_memory::store::CallerContext::for_agent("parity-test");
        let mut m1 = sample_memory("pg-g2-a");
        m1.source_uri = Some("uri:pg-fixture/a".to_string());
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &m1).await;
        let mut m2 = sample_memory("pg-g2-b");
        m2.source_uri = Some("uri:pg-fixture/a".to_string());
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &m2).await;

        let hits = pg
            .list_by_source_uri("uri:pg-fixture/a", None, None)
            .await
            .expect("list_by_source_uri");
        assert!(
            hits.len() >= 2,
            "two seeded memories should match uri:pg-fixture/a"
        );
        for m in &hits {
            assert_eq!(m.source_uri.as_deref(), Some("uri:pg-fixture/a"));
        }
    }

    /// Gap 3 (#886) — postgres twin of
    /// `verify_gap_3_recall_observations_sqlite`. Exercises
    /// `PostgresStore::recall_observation_insert` + `_gc`.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_gap_3_recall_observations() {
        let Some(pg) = live_pg().await else {
            return;
        };
        verify_gap_3_recall_observations_sqlite();
        let ctx = ai_memory::store::CallerContext::for_agent("parity-test");
        let m1 = sample_memory("pg-g3-1");
        let m2 = sample_memory("pg-g3-2");
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &m1).await;
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &m2).await;

        let written = pg
            .recall_observation_insert(
                "pg-g3-r1",
                &[
                    (m1.id.clone(), "hybrid".to_string(), 1, 0.9),
                    (m2.id.clone(), "hybrid".to_string(), 2, 0.8),
                ],
                None,
                None,
            )
            .await
            .expect("insert observations");
        assert_eq!(written, 2);

        // Idempotency: ON CONFLICT DO NOTHING.
        let again = pg
            .recall_observation_insert(
                "pg-g3-r1",
                &[(m1.id.clone(), "hybrid".to_string(), 1, 0.9)],
                None,
                None,
            )
            .await
            .expect("idempotent replay");
        assert_eq!(again, 0);

        // TTL prune — 365 days keeps everything fresh.
        let pruned = pg
            .recall_observation_gc(365)
            .await
            .expect("recall_observation_gc");
        assert_eq!(pruned, 0, "nothing older than 365d in a freshly-seeded DB");
    }

    /// Gap 5 (#888) — postgres twin of
    /// `verify_gap_5_edit_source_sqlite`.
    ///
    /// #1627 — extended to pin the FULL-column carry on the supersede
    /// INSERT: pre-#1627 the NEW row persisted only 15 of the table's
    /// columns, silently resetting `memory_kind`, `reflection_depth`,
    /// `citations`, `confidence_source`, `entity_id`, and `expires_at`
    /// to their SQL DEFAULTs (the sqlite twin routes through
    /// `storage::insert` and carries everything).
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_gap_5_edit_source() {
        let Some(pg) = live_pg().await else {
            return;
        };
        verify_gap_5_edit_source_sqlite();
        let ctx = ai_memory::store::CallerContext::for_agent("parity-test");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let mut mem = sample_memory(&format!("pg-g5-{run}"));
        // #1627 — seed the provenance columns the supersede must carry.
        mem.tier = ai_memory::models::Tier::Mid;
        mem.expires_at = Some((chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339());
        mem.metadata = serde_json::json!({ "agent_id": "parity-test" });
        mem.memory_kind = ai_memory::models::MemoryKind::Reflection;
        mem.reflection_depth = 2;
        mem.citations = vec![ai_memory::models::Citation {
            uri: "https://example.com/g5-evidence".to_string(),
            accessed_at: chrono::Utc::now().to_rfc3339(),
            hash: None,
            span: None,
        }];
        mem.confidence_source = ai_memory::models::ConfidenceSource::AutoDerived;
        mem.entity_id = Some("ent-g5".to_string());
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &mem).await;

        let patch = ai_memory::store::UpdatePatch {
            content: Some("new content".to_string()),
            ..ai_memory::store::UpdatePatch::default()
        };
        let (archived_id, new_id) = pg
            .update_with_archive_on_supersede(
                &mem.id,
                patch,
                None,
                ai_memory::models::EditSource::Llm,
            )
            .await
            .expect("supersede");
        assert_eq!(archived_id, mem.id);
        assert_ne!(new_id, mem.id);

        // #1627 — the NEW row must carry the full provenance shape.
        let new_row = ai_memory::store::MemoryStore::get(&pg, &ctx, &new_id)
            .await
            .expect("get superseding row");
        assert_eq!(new_row.content, "new content");
        assert_eq!(
            new_row.memory_kind,
            ai_memory::models::MemoryKind::Reflection,
            "#1627: memory_kind must survive the supersede"
        );
        assert_eq!(
            new_row.reflection_depth, 2,
            "#1627: reflection_depth must survive the supersede"
        );
        assert_eq!(
            new_row.citations.first().map(|c| c.uri.as_str()),
            Some("https://example.com/g5-evidence"),
            "#1627: citations must survive the supersede"
        );
        assert_eq!(
            new_row.confidence_source,
            ai_memory::models::ConfidenceSource::AutoDerived,
            "#1627: confidence_source must survive the supersede"
        );
        assert_eq!(
            new_row.entity_id.as_deref(),
            Some("ent-g5"),
            "#1627: entity_id must survive the supersede"
        );
        assert!(
            new_row.expires_at.is_some(),
            "#1627: expires_at must carry per the sqlite new_expires logic"
        );
    }

    /// Gap 6 (#889) — postgres twin of
    /// `verify_gap_6_search_source_uri_sqlite`.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_gap_6_search_source_uri() {
        let Some(pg) = live_pg().await else {
            return;
        };
        verify_gap_6_search_source_uri_sqlite();
        let ctx = ai_memory::store::CallerContext::for_agent("parity-test");
        let mut m1 = sample_memory("pg-g6-a");
        m1.title = "foo bar".to_string();
        m1.content = "matching keyword payload".to_string();
        m1.source_uri = Some("uri:pg-doc/a".to_string());
        let mut m2 = sample_memory("pg-g6-b");
        m2.title = "foo baz".to_string();
        m2.content = "matching keyword payload".to_string();
        m2.source_uri = Some("uri:pg-doc/b".to_string());
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &m1).await;
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &m2).await;

        let filter = ai_memory::store::Filter {
            limit: 10,
            ..ai_memory::store::Filter::default()
        };
        let scoped = pg
            .search_with_source_uri("matching", &filter, Some("uri:pg-doc/a"))
            .await
            .expect("search_with_source_uri");
        for m in &scoped {
            assert_eq!(m.source_uri.as_deref(), Some("uri:pg-doc/a"));
        }
    }

    /// Gap 7 (#860) — postgres twin of
    /// `verify_gap_7_get_links_columns_sqlite`.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_gap_7_get_links_columns() {
        let Some(pg) = live_pg().await else {
            return;
        };
        verify_gap_7_get_links_columns_sqlite();
        // Postgres get_links shape only — seed + project is covered by
        // the `link` + `get_links` SAL pair; the rich seed lives in
        // tests/sal_postgres.rs.
        let _links = pg
            .get_links("pg-g7-nonexistent")
            .await
            .expect("get_links accepts unknown id");
    }

    fn sample_memory(id: &str) -> Memory {
        Memory {
            id: id.to_string(),
            tier: ai_memory::models::Tier::Long,
            namespace: "parity-test".to_string(),
            title: format!("title-{id}"),
            content: "parity test content".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            reflection_depth: 0,
            memory_kind: ai_memory::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            ..Memory::default()
        }
    }

    // -----------------------------------------------------------------
    // v0.7.0 #1069 — promised regression tests for #1024 + #1026
    // -----------------------------------------------------------------

    /// v0.7.0 #1024 + #1069 — postgres `MemoryStore::update` MUST
    /// bump `memories.version` on every call. Pre-#1024 the
    /// `UPDATE memories SET …` clause omitted `version = version + 1`
    /// so a postgres-backed daemon answering `PUT /api/v1/memories/:id`
    /// (without `If-Match`) left `version` at 1 forever — breaking
    /// optimistic concurrency. The #1024 close comment promised this
    /// regression test but never created it; #1069's QC pass surfaced
    /// the documentation drift.
    ///
    /// The fix at `src/store/postgres.rs:7022-7069` added the
    /// missing `, version = version + 1` to the SET clause. This
    /// test drives two sequential `update` calls through the SAL
    /// trait surface and asserts the row's `version` advances
    /// 1 → 2 → 3.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn trait_update_bumps_version_1024() {
        let Some(pg) = live_pg().await else {
            return;
        };
        // #1138: the SAL get path applies is_visible_to_caller (#910);
        // a private-scope row with no owner is invisible to every
        // caller. The test's purpose is verifying the trait `update`
        // bumps version, not visibility, so use for_admin (which sets
        // bypass_visibility = true).
        let ctx = ai_memory::store::CallerContext::for_admin("parity-test-1024");
        let mem = sample_memory("pg-1024-version");
        ai_memory::store::MemoryStore::store(&pg, &ctx, &mem)
            .await
            .expect("store seed");
        let after_seed = ai_memory::store::MemoryStore::get(&pg, &ctx, &mem.id)
            .await
            .expect("get after seed");
        assert_eq!(
            after_seed.version, 1,
            "#1024: fresh upsert MUST land at version=1"
        );

        let patch1 = ai_memory::store::UpdatePatch {
            content: Some("first update".to_string()),
            ..ai_memory::store::UpdatePatch::default()
        };
        ai_memory::store::MemoryStore::update(&pg, &ctx, &mem.id, patch1)
            .await
            .expect("trait update #1");
        let after_1 = ai_memory::store::MemoryStore::get(&pg, &ctx, &mem.id)
            .await
            .expect("get");
        assert_eq!(
            after_1.version, 2,
            "#1024: first trait update MUST bump version 1 → 2; got {}",
            after_1.version
        );

        let patch2 = ai_memory::store::UpdatePatch {
            content: Some("second update".to_string()),
            ..ai_memory::store::UpdatePatch::default()
        };
        ai_memory::store::MemoryStore::update(&pg, &ctx, &mem.id, patch2)
            .await
            .expect("trait update #2");
        let after_2 = ai_memory::store::MemoryStore::get(&pg, &ctx, &mem.id)
            .await
            .expect("get");
        assert_eq!(
            after_2.version, 3,
            "#1024: second trait update MUST bump version 2 → 3; got {}",
            after_2.version
        );
    }

    /// v0.7.0 #1030 + #1110 — postgres `list_memories` MUST honor
    /// `Filter.agent_id`. The #1030 close-comment cited a full lib
    /// run but no specific regression test name; the `_1110` follow-
    /// up files the sqlite-parity pin for the postgres-side branch.
    ///
    /// Pre-#1030 the postgres WHERE clause omitted the
    /// `metadata->>'agent_id' = $7` filter binding so a postgres
    /// daemon answering `GET /api/v1/memories?agent_id=ai:alice`
    /// returned cross-agent rows. The fix added the binding; this
    /// test pins the SAL trait `list` surface so a future postgres
    /// refactor that drops the binding (e.g. moving `agent_id` out
    /// of `metadata` into a dedicated column without updating the
    /// WHERE clause) fails the regression.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn postgres_list_filters_by_agent_id_1030() {
        let Some(pg) = live_pg().await else {
            return;
        };
        // #1138: bypass_visibility (via for_admin) so the test observes
        // both alice + bob rows. The test's purpose is verifying that
        // the postgres WHERE clause binds the agent_id filter, NOT the
        // visibility gate.
        let ctx = ai_memory::store::CallerContext::for_admin("parity-test-1110");
        let mut m1 = sample_memory("pg-1030-alice");
        m1.metadata = serde_json::json!({"agent_id": "ai:alice"});
        let mut m2 = sample_memory("pg-1030-bob");
        m2.metadata = serde_json::json!({"agent_id": "ai:bob"});
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &m1).await;
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &m2).await;

        let filter = ai_memory::store::Filter {
            agent_id: Some("ai:alice".into()),
            limit: 100,
            ..ai_memory::store::Filter::default()
        };
        let hits = ai_memory::store::MemoryStore::list(&pg, &ctx, &filter)
            .await
            .expect("list with agent_id filter");
        assert!(
            hits.iter().any(|m| m.id == "pg-1030-alice"),
            "#1030: alice row must be present in agent_id=ai:alice filter result"
        );
        assert!(
            hits.iter().all(|m| m.id != "pg-1030-bob"),
            "#1030: bob row must NOT appear under agent_id=ai:alice filter; \
             postgres WHERE clause must bind the agent_id parameter"
        );
    }

    /// v0.7.0 #1026 + #1069 — postgres `run_gc(archive=true)` MUST
    /// wrap the archive-INSERT + live-DELETE in a single
    /// transaction. Pre-#1026 each statement auto-committed on the
    /// pool — a crash, `statement_timeout`, or pool-checkout
    /// failure between them could leave rows in BOTH `memories` and
    /// `archived_memories` (or rows archive-copied with stale data
    /// on later re-run since `ON CONFLICT DO UPDATE` clobbers
    /// `archived_at` + `archive_reason`).
    ///
    /// Full crash-injection (drop the pg connection mid-tx) requires
    /// harness-level pid-kill which is out of scope for a unit
    /// test. The production transaction wrapper at
    /// `src/store/postgres.rs:8607-8848` IS the load-bearing piece;
    /// this test pins the happy path + the committed-state
    /// consistency: every expired memory ends up EITHER in
    /// `archived_memories` (post-archive + delete) OR still in
    /// `memories` (gc skipped), never in both. A future regression
    /// that removes the `tx = self.pool.begin().await?` +
    /// `tx.commit()` shape would either fail the delete-side
    /// assertion below OR break the archive-restoration test suite
    /// — the contract stays pinned end-to-end.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn run_gc_is_transactional_1026() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = ai_memory::store::CallerContext::for_agent("parity-test-1026");
        // Seed an expired short-tier memory by setting expires_at
        // in the past.
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let mut mem = sample_memory("pg-1026-expired");
        mem.tier = ai_memory::models::Tier::Short;
        mem.expires_at = Some(past.clone());
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &mem).await;

        let archived = ai_memory::store::MemoryStore::run_gc(&pg, true)
            .await
            .expect("run_gc");
        assert!(
            archived >= 1,
            "#1026: run_gc(archive=true) MUST archive at least the one expired \
             fixture; got {archived}"
        );

        // After GC commits, the expired memory MUST NOT exist in
        // the live `memories` table. `MemoryStore::get` returns
        // `Err(StoreError::NotFound { .. })` for missing rows.
        let live = ai_memory::store::MemoryStore::get(&pg, &ctx, &mem.id).await;
        assert!(
            live.is_err(),
            "#1026: expired memory MUST be deleted from live `memories` \
             after run_gc commits — get() must return Err(NotFound); got {live:?}"
        );
    }

    /// #1776 — `forget(archive=true)` must archive AND delete the matched set in
    /// ONE transaction (the postgres twin of the sqlite
    /// `forget_archive_and_delete_are_atomic_1776` test, mirroring
    /// `run_gc_is_transactional_1026`). Pre-fix the archive INSERT and the DELETE
    /// ran on SEPARATE pooled connections in autocommit, so a concurrent write
    /// or crash between them could delete a row the archive-SELECT never
    /// captured = irrecoverable loss. After forget commits, the row MUST be gone
    /// from live `memories` AND restorable from the archive (proving it was
    /// archived, not lost). A regression that removed the
    /// `tx = self.pool.begin()` + `tx.commit()` shape would break this.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn forget_is_transactional_1776() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = ai_memory::store::CallerContext::for_agent("parity-test-1776");
        let mut mem = sample_memory("pg-1776-forget");
        mem.namespace = "parity-forget-1776".to_string();
        let _ = ai_memory::store::MemoryStore::store(&pg, &ctx, &mem).await;

        let deleted = ai_memory::store::MemoryStore::forget(
            &pg,
            &ctx,
            Some("parity-forget-1776"),
            None,
            None,
            true,
        )
        .await
        .expect("forget");
        assert!(
            deleted >= 1,
            "#1776: forget(archive=true) MUST delete the fixture; got {deleted}"
        );

        // Deleted from live `memories`.
        let live = ai_memory::store::MemoryStore::get(&pg, &ctx, &mem.id).await;
        assert!(
            live.is_err(),
            "#1776: forgotten memory MUST be deleted from live `memories`; got {live:?}"
        );

        // Archived (recoverable), not lost: restore-by-id succeeds iff the
        // archive INSERT committed in the same tx as the delete.
        let restored = ai_memory::store::MemoryStore::archive_restore(&pg, &ctx, &mem.id).await;
        assert!(
            matches!(restored, Ok(true)),
            "#1776: forgotten memory MUST be archived (restorable), proving the \
             archive committed with the delete; got {restored:?}"
        );
    }

    // -----------------------------------------------------------------
    // v0.8.0 #1709/#1720 Workstream-A (unit A7) — postgres twin of the
    // sqlite cross-tenant `scope=private` leak regression
    // (`tests/visibility_private_leak_1720.rs`) + the bypass-correctness
    // contract (`tests/sqlite_admin_bypass_visibility_a7_1720.rs`).
    //
    // The postgres recall/search/recall_hybrid read paths are ALREADY
    // owner-keyed at HEAD with the `target_agent_id` carve-out and a
    // NULL-caller trust-all bypass (src/store/postgres.rs ~10577 / 10771
    // / 11627):
    //
    //   $N::text IS NULL
    //   OR COALESCE(metadata->>'scope','private') <> 'private'
    //   OR metadata->>'agent_id' = $N
    //   OR metadata->>'target_agent_id' = $N
    //
    // with `caller = if ctx.bypass_visibility { None } else { Some(..) }`.
    // So pg has NO leak — A7 is parity verification, not a pg fix. This
    // test pins the adapter-agnostic contract on the POSTGRES side:
    //
    //   * non-admin (no bypass) + as_agent=NS  → MUST NOT see alice's
    //     private row (owner-keyed; the closed leak),
    //   * owner alice                          → MUST see her own row,
    //   * target_agent_id carve-out (inbox)    → recipient sees it,
    //   * admin bypass (as_agent=Some)         → trust-all, sees private
    //     (the same contract A7 just restored on sqlite).
    //
    // Gated on `AI_MEMORY_TEST_POSTGRES_URL` via `live_pg()` (skip-with-
    // eprintln when unset, like every sibling pg-parity test) so it
    // compiles + documents the contract here and runs in CI-with-pg.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_parity_private_leak_and_bypass_a7_1720() {
        const NS: &str = "fortitude/X";
        const ALICE: &str = "ai:alice";
        const BOB: &str = "ai:bob";
        const NEEDLE: &str = "needle-a7";

        let Some(pg) = live_pg().await else {
            return;
        };

        // Seed alice's scope=private row + a target_agent_id inbox row
        // (carve-out: alice owns it, bob is the recipient). Use a bypass
        // ctx to seed so the SAL store path applies no visibility filter
        // to the writes; the rows carry explicit owner/scope metadata.
        let seed_ctx = ai_memory::store::CallerContext::for_admin("parity-test-a7");
        let mut priv_mem = sample_memory("pg-a7-alice-priv");
        priv_mem.namespace = NS.to_string();
        priv_mem.content = format!("{NEEDLE} alice private");
        priv_mem.metadata = serde_json::json!({"agent_id": ALICE, "scope": "private"});
        let mut inbox_mem = sample_memory("pg-a7-inbox");
        inbox_mem.namespace = NS.to_string();
        inbox_mem.content = format!("{NEEDLE} alice inbox for bob");
        inbox_mem.metadata =
            serde_json::json!({"agent_id": ALICE, "scope": "private", "target_agent_id": BOB});
        let _ = ai_memory::store::MemoryStore::store(&pg, &seed_ctx, &priv_mem).await;
        let _ = ai_memory::store::MemoryStore::store(&pg, &seed_ctx, &inbox_mem).await;

        let filter = ai_memory::store::Filter {
            namespace: Some(NS.to_string()),
            limit: 100,
            ..ai_memory::store::Filter::default()
        };

        let has = |rows: &[Memory], id: &str| rows.iter().any(|m| m.id == id);
        let has_scored = |rows: &[(Memory, f64)], id: &str| rows.iter().any(|(m, _)| m.id == id);

        // --- bob (non-admin, no bypass) impersonating the namespace ---
        let mut bob_ctx = ai_memory::store::CallerContext::for_agent(BOB);
        bob_ctx.as_agent = Some(NS.to_string());
        assert!(!bob_ctx.bypass_visibility, "non-admin ctx never bypasses");

        let bob_search = ai_memory::store::MemoryStore::search(&pg, &bob_ctx, NEEDLE, &filter)
            .await
            .expect("bob search");
        assert!(
            !has(&bob_search, "pg-a7-alice-priv"),
            "#1720 pg LEAK: bob (non-admin) MUST NOT see alice's private row via search; got={:?}",
            bob_search.iter().map(|m| &m.id).collect::<Vec<_>>()
        );
        // Inbox carve-out: bob IS the target_agent_id, so bob DOES see it.
        assert!(
            has(&bob_search, "pg-a7-inbox"),
            "#1720 pg: target_agent_id carve-out MUST let bob read alice's inbox row via search"
        );

        let bob_recall =
            ai_memory::store::MemoryStore::recall_hybrid(&pg, &bob_ctx, NEEDLE, None, &filter)
                .await
                .expect("bob recall_hybrid");
        assert!(
            !has_scored(&bob_recall, "pg-a7-alice-priv"),
            "#1720 pg LEAK: bob MUST NOT see alice's private row via recall_hybrid; got={:?}",
            bob_recall.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
        );
        assert!(
            has_scored(&bob_recall, "pg-a7-inbox"),
            "#1720 pg: target_agent_id carve-out MUST let bob read alice's inbox via recall_hybrid"
        );

        // --- alice (owner) sees her own private row ---
        let mut alice_ctx = ai_memory::store::CallerContext::for_agent(ALICE);
        alice_ctx.as_agent = Some(NS.to_string());
        let alice_search = ai_memory::store::MemoryStore::search(&pg, &alice_ctx, NEEDLE, &filter)
            .await
            .expect("alice search");
        assert!(
            has(&alice_search, "pg-a7-alice-priv"),
            "#1720 pg: owner alice MUST see her own private row via search"
        );

        // --- admin bypass = trust-all, sees private REGARDLESS of as_agent
        //     (the same contract A7 restored on sqlite). Pin BOTH as_agent
        //     shapes so the postgres NULL-caller trust-all is unambiguous.
        for with_as_agent in [false, true] {
            let mut admin_ctx = ai_memory::store::CallerContext::for_admin("parity-test-a7-admin");
            assert!(admin_ctx.bypass_visibility, "for_admin sets bypass");
            if with_as_agent {
                admin_ctx.as_agent = Some(NS.to_string());
            }
            let admin_search =
                ai_memory::store::MemoryStore::search(&pg, &admin_ctx, NEEDLE, &filter)
                    .await
                    .expect("admin search");
            assert!(
                has(&admin_search, "pg-a7-alice-priv"),
                "#1720 A7 pg: admin bypass (as_agent={with_as_agent}) MUST trust-all and see \
                 alice's private row via search — parity with sqlite + the pg NULL-caller bypass"
            );
            let admin_recall = ai_memory::store::MemoryStore::recall_hybrid(
                &pg, &admin_ctx, NEEDLE, None, &filter,
            )
            .await
            .expect("admin recall_hybrid");
            assert!(
                has_scored(&admin_recall, "pg-a7-alice-priv"),
                "#1720 A7 pg: admin bypass (as_agent={with_as_agent}) MUST trust-all and see \
                 alice's private row via recall_hybrid"
            );
        }
    }
}
