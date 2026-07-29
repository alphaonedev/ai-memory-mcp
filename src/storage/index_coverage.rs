// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Recall-completeness index-coverage reconciliation (#1964).
//!
//! Recall answers a query from two indexes layered over the `memories`
//! table: the FTS5 keyword index (`memories_fts`) and the semantic ANN
//! index (built from the rows carrying a stored `embedding`). A record can
//! sit in `memories` yet be **absent from an index** — never embedded
//! (keyword-tier / oversize), evicted from the in-memory ANN cap (#1005
//! M8), or dropped from the FTS index by a trigger desync or index tamper.
//! When that happens semantic (or keyword) recall silently skips the row:
//! it is censored from the result set without any signed byte changing.
//!
//! This module reconciles what the indexes cover against the `memories`
//! table so recall can report that coverage **honestly** — "N of M rows
//! are vector-indexed; semantic recall may miss the un-indexed M−N" —
//! rather than presenting a partial result as complete. It computes over
//! the existing tables (no schema change): a `COUNT` per index vs the live
//! `memories` count.
//!
//! # What each figure means
//!
//! - **ANN coverage** ([`IndexCoverage::ann_coverage_fraction`]) — the
//!   fraction of rows with a stored embedding. Below 100 % is *expected*
//!   and legitimate: keyword-tier and oversize rows are never embedded, so
//!   they are keyword-recallable only. The figure is surfaced so the
//!   incompleteness of *semantic* recall over a partially-embedded corpus
//!   is **visible**, not silent.
//! - **FTS coverage** ([`IndexCoverage::fts_coverage_fraction`]) — the
//!   fraction of rows present in the FTS5 index (counted via the
//!   `memories_fts_docsize` shadow table, one row per indexed document,
//!   kept in lockstep with `memories` by the INSERT/DELETE/UPDATE
//!   triggers). This SHOULD be exactly 100 %: every row is FTS-indexed by
//!   trigger. A shortfall is a genuine desync / tamper signal — rows that
//!   have gone missing from keyword recall.

use anyhow::Result;
use rusqlite::Connection;

/// FTS5 shadow table carrying one row per indexed document. Reading it is a
/// plain table read (no FTS5 MATCH), so it works without the query planner
/// touching the virtual table. Present because `memories_fts` is created
/// with column-size tracking on (the default), which SQLite needs for
/// `bm25()` ranking.
const SQL_FTS_DOC_COUNT: &str = "SELECT COUNT(*) FROM memories_fts_docsize";

/// Live row count of the `memories` table.
///
/// `pub(crate)` since #2444 so the `backup` / `restore` corpus probe reuses
/// this ONE named statement instead of re-scattering the literal (pm-v3.1
/// no-hardcoded-literal rule / `scripts/check-hardcoded-literals.sh`).
pub(crate) const SQL_TOTAL_MEMORIES: &str = "SELECT COUNT(*) FROM memories";

/// A reconciliation snapshot of recall-index coverage against the
/// `memories` table, for one database (see the [module docs](self)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexCoverage {
    /// Live rows in `memories` — the denominator for both coverage figures.
    pub total_rows: i64,
    /// Rows carrying a stored `embedding` (ANN-recallable).
    pub ann_indexed_rows: i64,
    /// Rows present in the FTS5 index (`memories_fts_docsize` count), or
    /// `None` when that shadow table can't be read (a non-standard FTS
    /// build); the caller renders `None` as "not observable" rather than
    /// as a zero-coverage alarm.
    pub fts_indexed_rows: Option<i64>,
}

impl IndexCoverage {
    /// Fraction of `total_rows` that are ANN-recallable (`0.0..=1.0`). An
    /// empty corpus is vacuously fully covered (`1.0`).
    #[must_use]
    pub fn ann_coverage_fraction(&self) -> f64 {
        fraction(self.ann_indexed_rows, self.total_rows)
    }

    /// Fraction of `total_rows` present in the FTS index (`0.0..=1.0`), or
    /// `None` when the FTS document count is unobservable. An empty corpus
    /// is vacuously fully covered (`1.0`).
    #[must_use]
    pub fn fts_coverage_fraction(&self) -> Option<f64> {
        self.fts_indexed_rows.map(|n| fraction(n, self.total_rows))
    }

    /// Rows in `memories` with NO stored embedding — the population that
    /// semantic recall cannot reach (keyword-recallable only). Never
    /// negative.
    #[must_use]
    pub fn ann_unindexed_rows(&self) -> i64 {
        (self.total_rows - self.ann_indexed_rows).max(0)
    }

    /// Rows in `memories` absent from the FTS index — the keyword-recall
    /// censorship signal — or `None` when the FTS count is unobservable.
    #[must_use]
    pub fn fts_unindexed_rows(&self) -> Option<i64> {
        self.fts_indexed_rows.map(|n| (self.total_rows - n).max(0))
    }

    /// Whether every live row is present in the FTS index (the expected,
    /// in-sync state). `None` FTS count is treated as "cannot confirm a
    /// desync" → `true` (no false alarm).
    #[must_use]
    pub fn fts_fully_covered(&self) -> bool {
        self.fts_indexed_rows.is_none_or(|n| n >= self.total_rows)
    }
}

/// Whole-corpus fraction with an empty-corpus guard: an empty (or
/// negative-guarded) denominator is vacuously fully covered.
fn fraction(numerator: i64, denominator: i64) -> f64 {
    if denominator <= 0 {
        return 1.0;
    }
    numerator as f64 / denominator as f64
}

/// Reconcile recall-index coverage against the `memories` table (#1964).
///
/// Computes the live row count, the ANN-indexed (embedded) row count, and
/// — best-effort — the FTS-indexed document count. The FTS figure is
/// `None` when the `memories_fts_docsize` shadow table cannot be read
/// (e.g. a legacy DB predating FTS5, or a build without column-size
/// tracking); the ANN + total figures are always computed.
///
/// # Errors
/// Returns an error only when the base `memories` count or the embedded
/// count query fails (a corrupt / unopenable DB). An unreadable FTS shadow
/// table is degraded to `None`, not an error.
pub fn recall_index_coverage(conn: &Connection) -> Result<IndexCoverage> {
    let total_rows: i64 = conn.query_row(SQL_TOTAL_MEMORIES, [], |r| r.get(0))?;
    let ann_indexed_rows: i64 =
        conn.query_row(crate::SQL_COUNT_EMBEDDED_MEMORIES, [], |r| r.get(0))?;
    // Best-effort: a missing / non-standard FTS shadow table degrades to
    // "not observable" rather than failing the whole reconciliation.
    let fts_indexed_rows: Option<i64> = conn.query_row(SQL_FTS_DOC_COUNT, [], |r| r.get(0)).ok();

    Ok(IndexCoverage {
        total_rows,
        ann_indexed_rows,
        fts_indexed_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure fraction / accessor math (no DB) ─────────────────────────

    #[test]
    fn empty_corpus_is_vacuously_fully_covered() {
        let cov = IndexCoverage {
            total_rows: 0,
            ann_indexed_rows: 0,
            fts_indexed_rows: Some(0),
        };
        assert!((cov.ann_coverage_fraction() - 1.0).abs() < f64::EPSILON);
        assert_eq!(cov.fts_coverage_fraction(), Some(1.0));
        assert_eq!(cov.ann_unindexed_rows(), 0);
        assert!(cov.fts_fully_covered());
    }

    #[test]
    fn fully_indexed_reports_100_percent() {
        let cov = IndexCoverage {
            total_rows: 10,
            ann_indexed_rows: 10,
            fts_indexed_rows: Some(10),
        };
        assert!((cov.ann_coverage_fraction() - 1.0).abs() < f64::EPSILON);
        assert_eq!(cov.fts_coverage_fraction(), Some(1.0));
        assert_eq!(cov.ann_unindexed_rows(), 0);
        assert_eq!(cov.fts_unindexed_rows(), Some(0));
        assert!(cov.fts_fully_covered());
    }

    #[test]
    fn partial_ann_coverage_is_honest() {
        // 3 of 10 rows embedded — semantic recall misses the other 7.
        let cov = IndexCoverage {
            total_rows: 10,
            ann_indexed_rows: 3,
            fts_indexed_rows: Some(10),
        };
        assert!((cov.ann_coverage_fraction() - 0.3).abs() < 1e-9);
        assert_eq!(cov.ann_unindexed_rows(), 7);
        // FTS is still fully covered (a partial ANN is normal, not a desync).
        assert!(cov.fts_fully_covered());
    }

    #[test]
    fn fts_shortfall_flags_desync() {
        // 8 of 10 rows in the FTS index → 2 rows censored from keyword recall.
        let cov = IndexCoverage {
            total_rows: 10,
            ann_indexed_rows: 10,
            fts_indexed_rows: Some(8),
        };
        assert_eq!(cov.fts_unindexed_rows(), Some(2));
        assert!(!cov.fts_fully_covered());
        assert!((cov.fts_coverage_fraction().unwrap() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn unobservable_fts_never_false_alarms() {
        let cov = IndexCoverage {
            total_rows: 10,
            ann_indexed_rows: 10,
            fts_indexed_rows: None,
        };
        assert_eq!(cov.fts_coverage_fraction(), None);
        assert_eq!(cov.fts_unindexed_rows(), None);
        assert!(cov.fts_fully_covered());
    }
}
