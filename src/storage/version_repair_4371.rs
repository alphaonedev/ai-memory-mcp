// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4371 — the one-time (schema v101) repair of `memories.version` counters a
//! federation peer pinned above the replicated ceiling BEFORE the #4218 bound
//! existed.
//!
//! A row at or near `i64::MAX` is an optimistic-concurrency dead end: on
//! sqlite the saturating `+ 1` leaves the counter where it is, so the
//! `If-Match` token never moves and no longer fences a lost update; on
//! postgres the checked `+ 1` refuses every edit, so the row is un-editable;
//! and a JSON client cannot represent the value exactly (above 2^53). The
//! repair clamps every counter above
//! [`crate::models::replicated_version::MAX_REPLICATED_VERSION`] back to that
//! ceiling, in `memories` and in `archived_memories` (a restore carries the
//! archived counter back to a live row). Only the counter is written: text,
//! `updated_at` (the last-writer-wins key), embeddings and every other column
//! are untouched, so no data is lost and no row looks newer to a peer.
//!
//! Idempotent (a second run matches no row), and run by the ladder inside the
//! migration transaction behind the pre-migration snapshot. A NULL archived
//! version (legacy rows) compares false and is left alone.

use anyhow::Result;
use rusqlite::{Connection, params};

use crate::models::replicated_version::MAX_REPLICATED_VERSION;

/// Rows repaired by one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VersionRepair {
    /// Live `memories` rows clamped.
    pub(crate) memories: usize,
    /// `archived_memories` rows clamped.
    pub(crate) archived: usize,
}

/// Clamp every live and archived version above the replicated ceiling.
///
/// A REAL-typed value (the pre-#4218 sqlite overflow turned the column into a
/// REAL) compares greater than the integer ceiling and is rewritten as an
/// INTEGER by the same statement. A table that does not exist (a test fixture
/// that stamped a schema without applying it) is skipped, never an error.
///
/// # Errors
///
/// Any SQLite failure (the caller's transaction rolls the whole step back).
pub(crate) fn repair_poisoned_versions(conn: &Connection) -> Result<VersionRepair> {
    let memories = clamp_table(conn, "memories")?;
    let archived = clamp_table(conn, "archived_memories")?;
    if memories > 0 || archived > 0 {
        tracing::warn!(
            memories,
            archived,
            ceiling = MAX_REPLICATED_VERSION,
            "#4371: clamped memories.version counters pinned above the replicated \
             ceiling before the #4218 bound; the rows stay readable and editable"
        );
    }
    Ok(VersionRepair { memories, archived })
}

fn clamp_table(conn: &Connection, table: &'static str) -> Result<usize> {
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![table],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(0);
    }
    let n = conn.execute(
        &format!("UPDATE {table} SET version = ?1 WHERE version > ?1"),
        params![MAX_REPLICATED_VERSION],
    )?;
    Ok(n)
}

/// A memory whose version counter sits at `i64::MAX` and cannot move (#4371).
/// A local edit is refused with this typed error, never applied with a frozen
/// token (the postgres checked add refuses the same row). The row is not
/// modified; the v101 repair (or a re-sync of a bounded version) moves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionCounterExhausted {
    /// The memory whose counter is exhausted.
    pub id: String,
}

impl std::fmt::Display for VersionCounterExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "version counter exhausted for memory {} (#4371)",
            self.id
        )
    }
}

impl std::error::Error for VersionCounterExhausted {}

/// After a zero-row `UPDATE ... WHERE version < i64::MAX`: is the row there,
/// at the ceiling, and did the caller's `expected_version` (when given) match
/// it? Then the refusal is the exhausted counter, not a version conflict.
///
/// # Errors
///
/// Any SQLite failure reading the row.
pub(crate) fn exhausted_counter(
    conn: &Connection,
    id: &str,
    expected_version: Option<i64>,
) -> Result<Option<VersionCounterExhausted>> {
    let current = super::get_any(conn, id)?.map(|m| m.version);
    Ok(match current {
        Some(v) if v == i64::MAX && expected_version.is_none_or(|e| e == v) => {
            Some(VersionCounterExhausted { id: id.to_string() })
        }
        _ => None,
    })
}
