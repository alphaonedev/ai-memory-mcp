// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

//! v1.0.0 #1834 (pre-ship 3x7 battery, HIGH) — VALID-time rendering
//! canonicalization regression suite.
//!
//! Every #1834 predicate compares the RFC3339 TEXT `valid_from` /
//! `valid_until` columns LEXICOGRAPHICALLY against the caller's `valid_at`
//! (sqlite list/recall/hybrid/semantic SQL, the HNSW Rust re-filter, the
//! postgres `::text` binds). RFC3339 admits many renderings of the SAME
//! instant (`Z` vs `+00:00`, non-UTC offsets, variable fractional digits)
//! that order WRONGLY as bytes:
//!
//! * `'2026-06-01T00:00:00Z' > '2026-06-01T00:00:00+00:00'` (`'Z'` 0x5A >
//!   `'+'` 0x2B) — a `Z`-rendered `valid_until` at the boundary instant was
//!   wrongly INCLUDED against a `+00:00`-rendered `valid_at`
//!   (end-exclusivity violated), and a `Z`-rendered `valid_from` at the
//!   boundary was wrongly EXCLUDED (start-inclusivity violated).
//! * a `+05:00`-offset bound mis-ordered by HOURS.
//!
//! The fix canonicalizes to ONE fixed UTC rendering
//! (`validate::canonicalize_valid_time`, `YYYY-MM-DDTHH:MM:SS.ffffffZ`) at
//! every trust boundary (write funnels + `valid_at` query binds) and heals
//! pre-fix rows via the schema-v86 normalization arm. Each test here FAILS
//! on the pre-fix build. Postgres twins live in
//! `tests/claim_bitemporal_1834_pg.rs::pg_mixed_renderings_compare_as_instants_1834`.

use ai_memory::config::ResolvedScoring;
use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::storage;
use ai_memory::validate::canonicalize_valid_time;
use std::sync::{Mutex, OnceLock};

mod common;
use common::fresh_db_tempfile_conn as fresh_db;

fn test_serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

const NS: &str = "validtime-canon-1834";
const TERM: &str = "canonvalidclaim";

/// The boundary instant in its `Z` rendering…
const BOUND_Z: &str = "2026-06-01T00:00:00Z";
/// …and the SAME instant in its `+00:00` rendering.
const BOUND_OFFSET_UTC: &str = "2026-06-01T00:00:00+00:00";
/// …and the SAME instant rendered at a non-UTC offset (+05:00).
const BOUND_OFFSET_KABUL: &str = "2026-06-01T05:00:00+05:00";
/// The canonical fixed-UTC rendering of that instant.
const BOUND_CANON: &str = "2026-06-01T00:00:00.000000Z";

fn mem(title: &str, valid_from: Option<&str>, valid_until: Option<&str>) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("{TERM} claim body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: now.clone(),
        updated_at: now,
        memory_kind: MemoryKind::Claim,
        valid_from: valid_from.map(str::to_string),
        valid_until: valid_until.map(str::to_string),
        version: 1,
        ..Memory::default()
    }
}

fn titles_keyword(conn: &rusqlite::Connection, valid_at: Option<&str>) -> Vec<String> {
    let (rows, _) = db::recall(
        conn,
        TERM,
        Some(NS),
        50,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        false,
        None,
        None,
        valid_at,
    )
    .expect("keyword recall");
    let mut t: Vec<String> = rows.into_iter().map(|(m, _)| m.title).collect();
    t.sort();
    t
}

fn titles_hybrid(conn: &rusqlite::Connection, valid_at: Option<&str>) -> Vec<String> {
    let scoring = ResolvedScoring::default();
    let (rows, _) = db::recall_hybrid(
        conn,
        TERM,
        &[0.0_f32; 8],
        Some(NS),
        50,
        None,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        &scoring,
        false,
        None,
        None,
        None,
        valid_at,
    )
    .expect("hybrid recall");
    let mut t: Vec<String> = rows.into_iter().map(|(m, _)| m.title).collect();
    t.sort();
    t
}

fn titles_list(conn: &rusqlite::Connection, valid_at: Option<&str>) -> Vec<String> {
    let rows = db::list(
        conn,
        Some(NS),
        None,
        50,
        0,
        None,
        None,
        None,
        None,
        None,
        valid_at,
    )
    .expect("list");
    let mut t: Vec<String> = rows.into_iter().map(|m| m.title).collect();
    t.sort();
    t
}

/// The canonical form itself: fixed-width UTC micros with a `Z` suffix, and
/// every rendering of one instant maps to the SAME bytes (idempotent).
#[test]
fn canonical_rendering_is_fixed_utc_micros() {
    for rendering in [BOUND_Z, BOUND_OFFSET_UTC, BOUND_OFFSET_KABUL, BOUND_CANON] {
        assert_eq!(
            canonicalize_valid_time(rendering).as_deref(),
            Some(BOUND_CANON),
            "every rendering of the instant must canonicalize to the same bytes"
        );
    }
    // Sub-second digits are fixed-width (padded/truncated to micros).
    assert_eq!(
        canonicalize_valid_time("2026-06-01T00:00:00.5Z").as_deref(),
        Some("2026-06-01T00:00:00.500000Z"),
    );
    // Unparseable input is refused (callers keep the original bytes).
    assert_eq!(canonicalize_valid_time("not-a-timestamp"), None);
}

/// Pre-fix failure #1: an equal-instant `Z` vs `+00:00` pair at the
/// `valid_until` boundary. The claim `[JAN, BOUND)` stored with `Z`
/// renderings queried at the boundary instant rendered `+00:00` must be
/// EXCLUDED (end-exclusive) on keyword recall, hybrid recall, and list —
/// pre-fix the byte comparison `'...Z' > '...+00:00'` wrongly INCLUDED it.
/// Symmetrically, the open claim `[BOUND, ∞)` must be INCLUDED
/// (start-inclusive) — pre-fix `'...Z' <= '...+00:00'` was false, wrongly
/// EXCLUDING it.
#[test]
fn equal_instant_z_vs_offset_holds_half_open_contract_on_all_paths() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    storage::insert(
        &conn,
        &mem("bounded", Some("2026-01-01T00:00:00Z"), Some(BOUND_Z)),
    )
    .expect("insert bounded");
    storage::insert(&conn, &mem("open", Some(BOUND_Z), None)).expect("insert open");

    for query_rendering in [BOUND_OFFSET_UTC, BOUND_Z, BOUND_OFFSET_KABUL, BOUND_CANON] {
        for titles in [
            titles_keyword(&conn, Some(query_rendering)),
            titles_hybrid(&conn, Some(query_rendering)),
            titles_list(&conn, Some(query_rendering)),
        ] {
            assert_eq!(
                titles,
                vec!["open".to_string()],
                "at the boundary instant (rendered {query_rendering}) the bounded \
                 claim must be excluded (end-exclusive) and the open claim \
                 included (start-inclusive), regardless of rendering"
            );
        }
    }
}

/// Pre-fix failure #2: a non-UTC-offset stored bound mis-filters by hours.
/// `[2026-06-01T05:00:00+05:00, ∞)` == `[2026-06-01T00:00:00Z, ∞)`; an
/// as-of 30 minutes after the start is INSIDE the window — pre-fix the byte
/// comparison `'...05:00:00+05:00' <= '...00:30:00Z'` was false, wrongly
/// excluding it. An as-of one second before the start stays excluded.
#[test]
fn nonutc_offset_bounds_filter_by_instant_not_bytes() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    storage::insert(&conn, &mem("offsetclaim", Some(BOUND_OFFSET_KABUL), None))
        .expect("insert offset claim");

    for titles_fn in [titles_keyword, titles_hybrid, titles_list] {
        assert_eq!(
            titles_fn(&conn, Some("2026-06-01T00:30:00Z")),
            vec!["offsetclaim".to_string()],
            "an instant inside the offset-rendered window must match"
        );
        assert!(
            titles_fn(&conn, Some("2026-05-31T23:59:59Z")).is_empty(),
            "an instant before the offset-rendered window must not match"
        );
    }

    // The stored bytes are canonical.
    let rows = db::list(
        &conn,
        Some(NS),
        None,
        50,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("list all");
    assert_eq!(
        rows[0].valid_from.as_deref(),
        Some(BOUND_CANON),
        "the insert funnel must persist the canonical fixed-UTC rendering"
    );
}

/// Pre-fix failure #3: the HNSW Rust re-filter (`semantic_phase`'s
/// candidate loop) compared raw bytes with `>` / `<=`. Drive it in
/// isolation via `recall_hybrid_precomputed_hnsw` with a NON-FTS-matching
/// context (empty FTS pool) and fabricated ANN hits, so every surviving row
/// came through the Rust re-filter.
#[test]
fn hnsw_rust_refilter_applies_canonical_half_open_contract() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    let bounded_id = storage::insert(
        &conn,
        &mem("hnswbounded", Some("2026-01-01T00:00:00Z"), Some(BOUND_Z)),
    )
    .expect("insert bounded");
    let open_id =
        storage::insert(&conn, &mem("hnswopen", Some(BOUND_Z), None)).expect("insert open");
    // The HNSW branch re-verifies every hit against the ROW-SIDE stored
    // vector (#1692/#2167) — a row with no embedding is excluded as
    // unverifiable — so store matching vectors for both candidates.
    let qvec = [1.0_f32, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    storage::set_embedding(&conn, &bounded_id, &qvec, "test#none").expect("embed bounded");
    storage::set_embedding(&conn, &open_id, &qvec, "test#none").expect("embed open");
    let hits = vec![
        ai_memory::hnsw::VectorHit {
            id: bounded_id,
            distance: 0.05,
        },
        ai_memory::hnsw::VectorHit {
            id: open_id,
            distance: 0.05,
        },
    ];

    let scoring = ResolvedScoring::default();
    let titles_via_hits = |valid_at: Option<&str>| -> Vec<String> {
        let (rows, _) = db::recall_hybrid_precomputed_hnsw(
            &conn,
            // Deliberately does NOT match the stored content, so the FTS
            // pool is empty and ONLY the HNSW branch supplies candidates.
            "zzunmatchedcontextzz",
            &[1.0_f32, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            Some(NS),
            50,
            None,
            None,
            None,
            &hits,
            ai_memory::SECS_PER_HOUR,
            ai_memory::SECS_PER_DAY,
            None,
            None,
            &scoring,
            false,
            None,
            None,
            None,
            valid_at,
        )
        .expect("hybrid precomputed-hnsw recall");
        let mut t: Vec<String> = rows.into_iter().map(|(m, _)| m.title).collect();
        t.sort();
        t
    };

    // Both rows are ANN candidates with no valid_at filter.
    assert_eq!(
        titles_via_hits(None),
        vec!["hnswbounded".to_string(), "hnswopen".to_string()],
        "sanity: both fabricated hits survive with no valid-time filter"
    );
    // At the boundary instant rendered `+00:00`: bounded OUT (end-exclusive
    // against its Z-rendered close), open IN (start-inclusive).
    assert_eq!(
        titles_via_hits(Some(BOUND_OFFSET_UTC)),
        vec!["hnswopen".to_string()],
        "the HNSW Rust re-filter must apply the half-open contract by INSTANT \
         (pre-fix the raw-byte compare wrongly included the Z-rendered close)"
    );
    // At a +05:00 rendering of the same instant: identical result.
    assert_eq!(
        titles_via_hits(Some(BOUND_OFFSET_KABUL)),
        vec!["hnswopen".to_string()],
        "a non-UTC offset rendering of the same instant must filter identically"
    );
}

/// Pre-fix data written by an older binary carries mixed renderings ON
/// DISK. The schema-v86 in-code arm must normalize `memories` +
/// `archived_memories` rows to the canonical rendering (instant-preserving,
/// unparseable values kept byte-identical), after which the predicates
/// filter correctly with plain byte comparison.
#[test]
fn v86_migration_normalizes_legacy_mixed_renderings() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (tmp, conn) = fresh_db();
    let id = storage::insert(&conn, &mem("legacyrow", Some(BOUND_Z), None)).expect("insert");

    // Simulate a pre-fix on-disk state: raw mixed renderings + version 85.
    conn.execute(
        "UPDATE memories SET valid_from = ?1, valid_until = ?2 WHERE id = ?3",
        rusqlite::params!["2026-01-01T05:00:00+05:00", BOUND_Z, id],
    )
    .expect("plant legacy renderings");
    conn.execute("DELETE FROM schema_version", [])
        .expect("clear version");
    conn.execute("INSERT INTO schema_version (version) VALUES (85)", [])
        .expect("stamp v85");
    drop(conn);

    // Re-open: the migration ladder runs the v86 normalization arm.
    let conn = ai_memory::db::open(tmp.path()).expect("re-open runs v86");
    let row = storage::get(&conn, &id).expect("get").expect("present");
    assert_eq!(
        row.valid_from.as_deref(),
        Some("2026-01-01T00:00:00.000000Z"),
        "v86 must normalize a +05:00-rendered valid_from to canonical UTC \
         (instant-preserving: 05:00+05:00 == 00:00Z)"
    );
    assert_eq!(
        row.valid_until.as_deref(),
        Some(BOUND_CANON),
        "v86 must normalize a Z-rendered valid_until to the canonical micros form"
    );

    // And the healed row now filters correctly at the boundary.
    assert!(
        titles_keyword(&conn, Some(BOUND_OFFSET_UTC)).is_empty(),
        "post-migration, the boundary instant excludes the healed row \
         (end-exclusive) regardless of the query rendering"
    );
    assert_eq!(
        titles_keyword(&conn, Some("2026-03-01T00:00:00+00:00")),
        vec!["legacyrow".to_string()],
        "post-migration, an instant inside the healed window matches"
    );

    // Idempotence: a second pass over an already-canonical DB is a no-op.
    conn.execute("DELETE FROM schema_version", [])
        .expect("clear version again");
    conn.execute("INSERT INTO schema_version (version) VALUES (85)", [])
        .expect("stamp v85 again");
    drop(conn);
    let conn = ai_memory::db::open(tmp.path()).expect("re-open again");
    let row2 = storage::get(&conn, &id).expect("get").expect("present");
    assert_eq!(row2.valid_from, row.valid_from);
    assert_eq!(row2.valid_until, row.valid_until);
}

/// #2281 — the schema-v86 in-code arm must ALSO normalize mixed
/// renderings on `archived_memories`, not just `memories`. The v85
/// archive-parity migration carries `valid_from`/`valid_until` into the
/// archive on the round-trip; a pre-v86 binary therefore left mixed
/// renderings on archived rows exactly as it did on live rows, and the
/// #1834 predicates compare those TEXT columns lexicographically. This
/// pins the archive arm at `src/storage/migrations.rs` (the
/// `has_archive_table` branch of the v86 normalization): plant a mixed
/// rendering on an ARCHIVED row at schema 85, re-open, and assert the
/// archived row's valid_from/valid_until heal to the canonical fixed-UTC
/// form.
#[test]
fn v86_migration_normalizes_archived_memories_rows_2281() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (tmp, conn) = fresh_db();
    let id = storage::insert(&conn, &mem("archivedrow", Some(BOUND_Z), None)).expect("insert");
    // Move the row into `archived_memories` (v85 archive-parity carries the
    // #1834 valid-time columns across the round-trip).
    assert!(
        storage::archive_memory(&conn, &id, Some("valid-time-2281")).expect("archive"),
        "the row must archive into archived_memories"
    );

    // Simulate a pre-fix on-disk state on the ARCHIVED row: raw mixed
    // renderings + version 85.
    conn.execute(
        "UPDATE archived_memories SET valid_from = ?1, valid_until = ?2 WHERE id = ?3",
        rusqlite::params!["2026-01-01T05:00:00+05:00", "2026-06-01T00:00:00Z", id],
    )
    .expect("plant legacy renderings on archived row");
    conn.execute("DELETE FROM schema_version", [])
        .expect("clear version");
    conn.execute("INSERT INTO schema_version (version) VALUES (85)", [])
        .expect("stamp v85");
    drop(conn);

    // Re-open: the migration ladder runs the v86 normalization arm, which
    // must reach `archived_memories`.
    let conn = ai_memory::db::open(tmp.path()).expect("re-open runs v86");
    let (arch_from, arch_until): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT valid_from, valid_until FROM archived_memories WHERE id = ?1",
            rusqlite::params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("archived row present");
    assert_eq!(
        arch_from.as_deref(),
        Some("2026-01-01T00:00:00.000000Z"),
        "v86 must normalize a +05:00-rendered archived valid_from to canonical UTC \
         (instant-preserving: 05:00+05:00 == 00:00Z)"
    );
    assert_eq!(
        arch_until.as_deref(),
        Some(BOUND_CANON),
        "v86 must normalize a Z-rendered archived valid_until to the canonical micros form"
    );
}

/// The `valid_until` update patch canonicalizes the close instant at the
/// funnel, so a `+05:00`-rendered close persists as fixed UTC and the
/// closed window filters by instant.
#[test]
fn update_patch_canonicalizes_close_rendering() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_tmp, conn) = fresh_db();
    let id = storage::insert(&conn, &mem("closable", Some("2026-01-01T00:00:00Z"), None))
        .expect("insert");

    let (found, _) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(BOUND_OFFSET_KABUL),
    )
    .expect("close via update");
    assert!(found);

    let row = storage::get(&conn, &id).expect("get").expect("present");
    assert_eq!(
        row.valid_until.as_deref(),
        Some(BOUND_CANON),
        "the update funnel must persist the canonical rendering of the close"
    );
    // End-exclusive at the close instant in ANY rendering.
    assert!(titles_keyword(&conn, Some(BOUND_Z)).is_empty());
    assert!(titles_keyword(&conn, Some(BOUND_OFFSET_UTC)).is_empty());
    // Still valid strictly before the close.
    assert_eq!(
        titles_keyword(&conn, Some("2026-05-31T23:59:59Z")),
        vec!["closable".to_string()]
    );
}
