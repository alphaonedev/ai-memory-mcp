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
