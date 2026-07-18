// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2035 — v85 archive→restore lossless round-trip pin for the
//! #1834 claim-bitemporal VALID-time.
//!
//! The v79/#1834 columns `memories.valid_from` / `memories.valid_until`
//! (RFC3339 TEXT; the half-open `[valid_from, valid_until)` interval a
//! claim is asserted to hold) were never mirrored onto
//! `archived_memories`, so a memory archived (GC eviction, explicit
//! `forget`, or the in_place_edit supersede snapshot) and later restored
//! came back with both columns NULL — silently DROPPING the claim's
//! validity interval. This is the exact loss class #1025 (schema v49)
//! closed for the other 14 v0.7.0 columns; schema v85 adds the two
//! columns to `archived_memories` on both backends and threads them
//! through the archive INSERT...SELECT and restore INSERT...SELECT sites.
//!
//! The `Memory` struct does NOT carry `valid_from`/`valid_until` (they
//! are column-only, threaded via the #1834 dedicated claim-write path),
//! so this test writes them via a direct UPDATE and asserts the
//! round-trip at the SQL column level on BOTH legs (archive then
//! restore). The sqlite test runs unconditionally; the postgres twin is
//! `#[ignore]`-gated on `AI_MEMORY_TEST_POSTGRES_URL` (issue #79).

#![allow(
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::similar_names
)]

use ai_memory::db;
use ai_memory::models::Tier;
use rusqlite::{Connection, params};

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

const VF: &str = "2026-01-01T00:00:00+00:00";
const VU: &str = "2026-12-31T23:59:59+00:00";

#[test]
fn sqlite_archive_restore_roundtrips_valid_time_2035() {
    let conn = fresh_sqlite();
    let mut mem = ai_memory::models::Memory {
        id: "vt-2035-sqlite".to_string(),
        namespace: "ns2035".to_string(),
        title: "valid-time-roundtrip".to_string(),
        content: "claim body".to_string(),
        tier: Tier::Long,
        ..ai_memory::models::Memory::default()
    };
    mem.created_at = "2026-05-21T12:00:00Z".to_string();
    mem.updated_at = "2026-05-21T12:00:00Z".to_string();
    db::insert(&conn, &mem).expect("seed memory");

    // Land the #1834 claim-validity interval (the shape the dedicated
    // claim-write path writes).
    conn.execute(
        "UPDATE memories SET valid_from = ?1, valid_until = ?2 WHERE id = ?3",
        params![VF, VU, &mem.id],
    )
    .expect("set valid-time");

    // Archive — memories → archived_memories.
    assert!(
        db::archive_memory(&conn, &mem.id, Some("rt-test")).expect("archive"),
        "archive_memory must report success"
    );

    // Leg 1 — the archive copy must carry the interval.
    let (a_vf, a_vu): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT valid_from, valid_until FROM archived_memories WHERE id = ?1",
            params![&mem.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read archived valid-time");
    assert_eq!(
        a_vf.as_deref(),
        Some(VF),
        "#2035: archive must carry valid_from"
    );
    assert_eq!(
        a_vu.as_deref(),
        Some(VU),
        "#2035: archive must carry valid_until"
    );

    // Leg 2 — restore, then the live row must carry the interval back.
    assert!(
        db::restore_archived(&conn, &mem.id).expect("restore"),
        "restore_archived must report success"
    );
    let (r_vf, r_vu): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT valid_from, valid_until FROM memories WHERE id = ?1",
            params![&mem.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read restored valid-time");
    assert_eq!(
        r_vf.as_deref(),
        Some(VF),
        "#2035: restore must round-trip valid_from losslessly"
    );
    assert_eq!(
        r_vu.as_deref(),
        Some(VU),
        "#2035: restore must round-trip valid_until losslessly"
    );
}

/// Postgres twin — skipped by default per the Track C/D
/// `AI_MEMORY_TEST_POSTGRES_URL` convention (issue #79). Seeds + sets the
/// interval + archives + restores through the SAL surface, then reads the
/// two columns back with a raw sqlx query against the store pool.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn postgres_archive_restore_roundtrips_valid_time_2035() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — postgres half skipped");
        return;
    };
    let pg = match ai_memory::store::postgres::PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("PostgresStore::connect failed: {e}");
            return;
        }
    };
    let id = "vt-2035-pg";
    let ctx = ai_memory::store::CallerContext::for_admin("rt-2035-pg");
    let mem = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: "ns2035".to_string(),
        title: "valid-time-roundtrip".to_string(),
        content: "claim body".to_string(),
        tier: Tier::Long,
        created_at: "2026-05-21T12:00:00Z".to_string(),
        updated_at: "2026-05-21T12:00:00Z".to_string(),
        ..ai_memory::models::Memory::default()
    };
    ai_memory::store::MemoryStore::store(&pg, &ctx, &mem)
        .await
        .expect("seed");

    // Land the #1834 claim-validity interval directly (column-only field).
    sqlx::query("UPDATE memories SET valid_from = $1, valid_until = $2 WHERE id = $3")
        .bind(VF)
        .bind(VU)
        .bind(id)
        .execute(pg.pool())
        .await
        .expect("set valid-time");

    // Archive → restore through the SAL surface.
    ai_memory::store::MemoryStore::archive_by_ids(
        &pg,
        &ctx,
        std::slice::from_ref(&mem.id),
        Some("rt-test"),
    )
    .await
    .expect("archive_by_ids");

    // Leg 1 — the archive copy carries the interval.
    let (a_vf, a_vu): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT valid_from, valid_until FROM archived_memories WHERE id = $1")
            .bind(id)
            .fetch_one(pg.pool())
            .await
            .expect("read archived valid-time");
    assert_eq!(
        a_vf.as_deref(),
        Some(VF),
        "#2035 pg: archive must carry valid_from"
    );
    assert_eq!(
        a_vu.as_deref(),
        Some(VU),
        "#2035 pg: archive must carry valid_until"
    );

    ai_memory::store::MemoryStore::archive_restore(&pg, &ctx, &mem.id)
        .await
        .expect("restore");

    // Leg 2 — the restored live row carries the interval back.
    let (r_vf, r_vu): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT valid_from, valid_until FROM memories WHERE id = $1")
            .bind(id)
            .fetch_one(pg.pool())
            .await
            .expect("read restored valid-time");
    assert_eq!(
        r_vf.as_deref(),
        Some(VF),
        "#2035 pg: restore must round-trip valid_from losslessly"
    );
    assert_eq!(
        r_vu.as_deref(),
        Some(VU),
        "#2035 pg: restore must round-trip valid_until losslessly"
    );
}
