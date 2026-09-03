// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Form 5 — calibration sweep.
//!
//! Reads `confidence_shadow_observations` since N days back and emits
//! per-(namespace, source) baselines: the median derived confidence the
//! [`crate::confidence::derive`] engine produced over the observed
//! window. Driven by the `ai-memory calibrate confidence --from-shadow`
//! CLI subcommand and the `memory_calibrate_confidence` MCP tool.
//!
//! Audit-honest contract: the sweep is **read-only** by default. The
//! computed baselines are surfaced as a report; persistence into a
//! calibration store is an opt-in follow-up that operators run only
//! after reviewing the output (so a poorly-sampled window can't
//! silently re-pin a namespace's confidence ceiling).
//!
//! # Streaming aggregation (Cluster G, PERF-12)
//!
//! Pre-Cluster-G, this module materialised the entire window into a
//! `Vec<(ShadowObservation, String)>` (via INNER JOIN against
//! `memories` to pull the source role), then grouped + sorted in Rust.
//! A long-running shadow-mode deployment with millions of observations
//! exhausted memory on the calibration call.
//!
//! Post-Cluster-G, the sweep streams in two passes:
//!
//! 1. **Group counts + mean** (single SQL aggregation):
//!    ```sql
//!    SELECT namespace, source, COUNT(*), AVG(derived_confidence)
//!    FROM confidence_shadow_observations
//!    WHERE observed_at >= ?1
//!    GROUP BY namespace, source
//!    ```
//!
//! 2. **Per-group median + bucket histogram** (cursor-based scan):
//!    ```sql
//!    SELECT derived_confidence FROM confidence_shadow_observations
//!    WHERE observed_at >= ?1 AND namespace = ?2 AND source = ?3
//!    ORDER BY derived_confidence ASC
//!    ```
//!    The compound `(namespace, source, observed_at)` index added in
//!    schema v40 keeps the WHERE-predicate scan tight. Pass 1 already
//!    knows each group's `count`, so Pass 2 walks the ASC cursor once
//!    per group tracking only a running row index plus the (at most
//!    two) captured central value(s) at `mid = count / 2` — no
//!    per-group `Vec<f64>` materialisation at all, matching the
//!    module's streaming contract exactly rather than merely moving
//!    the allocation from all-observations to one-group (#1905). The
//!    median is the mean of the two central values for an even count
//!    (`(values[mid-1] + values[mid]) / 2`) and the single central
//!    value for an odd count, matching pre-Cluster-G semantics (#1915);
//!    buckets fold into 10 stack-allocated counters via the same
//!    single pass.
//!
//! The denormalised `source` column (also schema v40) removed the
//! grouping join with `memories` — orphan observation rows whose
//! source memory has been CASCADE-deleted continue to surface in the
//! report under their stamped `source` value, which is the audit-
//! honest behaviour (the calibration sample was real; the source
//! memory's later deletion doesn't unmake the observation). Pass 1
//! does carry a read-only **`LEFT JOIN memories`** for the v1.0.0 §11.5
//! (#1707) consume-vs-access divergence evidence (`access_count`); it is
//! a LEFT join with `COALESCE(access_count, 0)`, so orphan rows still
//! surface (as access 0) and the orphan-tolerant contract above holds.

use anyhow::Result;
use chrono::Utc;
use rusqlite::{Connection, params};
use serde::Serialize;

/// Default sweep window. The Form 5 brief calls for 30 days; tunable
/// per call via the CLI `--days N` flag and the MCP `days` parameter.
pub const DEFAULT_WINDOW_DAYS: i64 = 30;

/// `tracing` target for this module's shadow-mode calibration logs. One
/// named const referenced at every emit site (pm-v3.1 no-scattered-literal).
const LOG_TARGET: &str = "confidence.calibrate";

/// One per-(namespace, source) row in the calibration report.
///
/// `source` is the `memories.source` role label (`user`, `claude`,
/// `api`, …) denormalised onto each shadow observation via the
/// v40-schema column. `count` is the number of observations that
/// contributed; `median` and the bucket distribution let an operator
/// spot a skewed sample.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PerSourceBaseline {
    pub namespace: String,
    pub source: String,
    pub count: u64,
    /// Median derived confidence across the window. Robust to outliers
    /// vs. the mean.
    pub median: f64,
    /// Mean derived confidence — emitted alongside the median so a
    /// caller can spot a skew-vs-tail distinction at a glance.
    pub mean: f64,
    /// Bucketed distribution of derived values. 10 buckets covering
    /// `[0.0, 0.1)` … `[0.9, 1.0]` so a downstream UI can plot a
    /// histogram without re-reading the observation table.
    pub buckets: [u64; 10],
    /// v0.9.0 §11.5 (#1706) — `COUNT(recall_outcome = 'consumed') /
    /// COUNT(recall_outcome IS NOT NULL)` for this `(namespace, source)`
    /// group. **SHADOW MODE — logged only, never consulted by
    /// [`crate::storage::recall`].** `None` when no shadow row in the
    /// window has a correlated `recall_observations` ledger entry yet
    /// (either the ledger is absent/empty, or the offline sweep hasn't
    /// run — see [`crate::confidence::shadow::backfill_recall_outcomes`]).
    /// This is the future #1707/#C live-wire decision's evidence base,
    /// not a ranking input.
    pub consumption_utility: Option<f64>,
    /// v1.0.0 §11.5 (#1707) — the shadow-divergence evidence the #1707
    /// conditional gate requires ("execute the live recall-utility term
    /// ONLY IF consume-rate diverges meaningfully from the existing
    /// `access_count` usage proxy, else close won't-do"). **SHADOW MODE —
    /// logged only, never consulted by [`crate::storage::recall`].**
    /// `None` when the window has no judged (ledger-correlated) row.
    pub consume_access_divergence: Option<ConsumeAccessDivergence>,
}

/// v1.0.0 §11.5 (#1707) — measured evidence for whether the recall-usage
/// consume signal carries information the recall blend's existing
/// `MIN(access_count, 50) * 0.1` usage proxy does not.
///
/// The #1707 gate ships the live recall-utility term ONLY IF this shows a
/// meaningful divergence; otherwise the signal is redundant and #1707 is
/// closed won't-do. The two `mean_access_*` fields are the collinearity
/// tell: when `consumed` rows carry a systematically higher `access_count`
/// than `unconsumed` rows (`mean_access_consumed` >> `mean_access_unconsumed`),
/// the consume signal tracks the access proxy and adds no new ranking
/// information. Paired with a low `consumed_count / (consumed + unconsumed)`
/// (sparsity), that is the "does-not-diverge → close won't-do" branch.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ConsumeAccessDivergence {
    /// Rows this window whose correlated ledger entry marked the memory
    /// consumed (`recall_outcome = 'consumed'`).
    pub consumed_count: u64,
    /// Rows judged-but-not-consumed (`recall_outcome = 'unconsumed'`).
    pub unconsumed_count: u64,
    /// Mean `memories.access_count` across the consumed rows; `None` when
    /// `consumed_count == 0`.
    pub mean_access_consumed: Option<f64>,
    /// Mean `memories.access_count` across the unconsumed rows; `None` when
    /// `unconsumed_count == 0`.
    pub mean_access_unconsumed: Option<f64>,
}

/// Top-level calibration report emitted by the sweep.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CalibrationReport {
    pub window_days: i64,
    pub total_observations: u64,
    pub baselines: Vec<PerSourceBaseline>,
}

/// Compute the calibration report by scanning shadow observations from
/// the last `days` days.
///
/// `now` is parameterised so tests can pin a deterministic clock. The
/// production CLI/MCP wrappers pass `Utc::now()`.
///
/// # Errors
///
/// Returns an error when `days` is outside `0..=36500`, checked timestamp
/// subtraction fails, or an underlying SQLite operation fails.
#[allow(clippy::cast_precision_loss)]
pub fn calibrate_from_shadow(
    conn: &Connection,
    days: i64,
    now: chrono::DateTime<Utc>,
) -> Result<CalibrationReport> {
    // #3384 — caller-controlled windows must never reach chrono's panicking
    // `Duration::days` / `DateTime - Duration` operators. Keep the bound and
    // checked arithmetic in the substrate function so both CLI and MCP callers
    // inherit the same fail-closed behavior.
    let since_dt = crate::validate::checked_days_ago(now, "days", days, 0)?;
    let since = since_dt.to_rfc3339();

    // v0.9.0 §11.5 (#1706) — offline sweep step, ridden on this existing
    // cadence (no new hot-path code, no new schema): backfill
    // `recall_outcome` for any shadow row a `recall_observations` ledger
    // entry has since appeared for. SHADOW MODE — the backfilled column
    // only feeds `consumption_utility` below; it is never read by
    // `crate::storage::recall`. Skip-with-WARN (item 4) is handled
    // inside `backfill_recall_outcomes` itself, so this call never fails
    // the report just because the ledger is absent.
    let backfilled = crate::confidence::shadow::backfill_recall_outcomes(conn)?;
    if backfilled > 0 {
        tracing::info!(
            target: LOG_TARGET,
            backfilled,
            "shadow sweep: backfilled recall_outcome from the recall_observations ledger"
        );
    }

    // Pass 1: per-group count + mean + consumption tallies, computed
    // entirely in SQL. The denormalised `source` column (schema v40)
    // lets us avoid the INNER JOIN against `memories` that
    // pre-Cluster-G code carried.
    // v1.0.0 §11.5 (#1707) — the same offline pass also LEFT JOINs
    // `memories` to sum `access_count` across the consumed vs unconsumed
    // rows, so the report carries the consume-vs-access divergence evidence
    // the #1707 gate requires. Still SHADOW MODE (log/report only); the JOIN
    // is read-only and `crate::storage::recall` is untouched.
    let mut stmt = conn.prepare(
        "SELECT o.namespace, o.source, COUNT(*), AVG(o.derived_confidence),
                SUM(CASE WHEN o.recall_outcome = 'consumed' THEN 1 ELSE 0 END),
                SUM(CASE WHEN o.recall_outcome IS NOT NULL THEN 1 ELSE 0 END),
                SUM(CASE WHEN o.recall_outcome = 'consumed'
                         THEN COALESCE(m.access_count, 0) ELSE 0 END),
                SUM(CASE WHEN o.recall_outcome = 'unconsumed'
                         THEN COALESCE(m.access_count, 0) ELSE 0 END)
         FROM confidence_shadow_observations o
         LEFT JOIN memories m ON m.id = o.memory_id
         WHERE o.observed_at >= ?1
         GROUP BY o.namespace, o.source
         ORDER BY o.namespace, o.source",
    )?;
    let groups: Vec<(String, String, i64, f64, i64, i64, i64, i64)> = stmt
        .query_map(params![since.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, f64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    let total_observations: u64 = groups.iter().map(|(_, _, c, ..)| *c as u64).sum();

    // Pass 2: per-group cursor scan for median + bucket histogram.
    // The compound (namespace, source, observed_at) index from
    // schema v40 makes the WHERE filter cheap; the per-group result
    // set is bounded by the group size (typically thousands, not
    // millions) so the streaming Vec<f64> stays small.
    let mut median_stmt = conn.prepare(
        "SELECT derived_confidence
         FROM confidence_shadow_observations
         WHERE observed_at >= ?1 AND namespace = ?2 AND source = ?3
         ORDER BY derived_confidence ASC",
    )?;

    let mut baselines: Vec<PerSourceBaseline> = Vec::with_capacity(groups.len());
    for (
        namespace,
        source,
        count_i64,
        mean,
        consumed_i64,
        judged_i64,
        access_consumed_i64,
        access_unconsumed_i64,
    ) in groups
    {
        if count_i64 <= 0 {
            continue;
        }
        let count = count_i64 as u64;
        let mut rows =
            median_stmt.query(params![since.as_str(), namespace.as_str(), source.as_str()])?;
        let mut buckets = [0_u64; 10];
        // #1905 — the median needs only the value(s) at the central
        // index/indices; `count` is already known from Pass 1, so we
        // track a running row index over the ASC cursor and capture
        // just those scalars instead of materialising the whole group
        // into a `Vec<f64>`. This keeps Pass 2 O(1) memory per group
        // (independent of group size) rather than reintroducing the
        // exact unbounded-Vec allocation the streaming redesign was
        // written to eliminate.
        let mid = (count as usize) / 2;
        let even_count = count % 2 == 0;
        let mut lower_mid_value: Option<f64> = None;
        let mut mid_value: Option<f64> = None;
        let mut row_idx: usize = 0;
        while let Some(row) = rows.next()? {
            let v: f64 = row.get(0)?;
            let bucket_idx = ((v.clamp(0.0, 1.0) * 10.0) as usize).min(9);
            buckets[bucket_idx] += 1;
            if row_idx == mid {
                mid_value = Some(v);
            } else if even_count && row_idx + 1 == mid {
                lower_mid_value = Some(v);
            }
            row_idx += 1;
        }
        // Rows arrived ORDER BY ASC — the captured scalar(s) at `mid`
        // (and `mid - 1` for an even count) are the median inputs.
        let median = match (even_count, lower_mid_value, mid_value) {
            (true, Some(lower), Some(upper)) => (lower + upper) / 2.0,
            (false, _, Some(single)) => single,
            _ => 0.0,
        };

        // v0.9.0 §11.5 (#1706) — consumption_utility = consumed / judged,
        // over the rows this window's backfill could actually correlate
        // against the ledger. `None` (not zero) when `judged_i64 == 0` —
        // an honest "no evidence yet" rather than a misleading 0.0 that
        // would read as "never consumed".
        let consumption_utility = if judged_i64 > 0 {
            Some(consumed_i64 as f64 / judged_i64 as f64)
        } else {
            None
        };
        if let Some(cu) = consumption_utility {
            // SHADOW MODE — logged only; `crate::storage::recall` never
            // reads this. Evidence for the future #1707/#C live-wire
            // decision, not a ranking input.
            tracing::info!(
                target: LOG_TARGET,
                namespace = %namespace,
                source = %source,
                consumption_utility = cu,
                judged = judged_i64,
                "shadow consumption utility (SHADOW MODE — not consulted by recall())"
            );
        }

        // v1.0.0 §11.5 (#1707) — the consume-vs-access divergence evidence.
        // `unconsumed = judged - consumed` (the SQL split is exhaustive over
        // `recall_outcome IS NOT NULL`). Means are `None` when their bucket
        // is empty (honest "no evidence", never a misleading 0.0).
        let consume_access_divergence = if judged_i64 > 0 {
            let consumed_count = consumed_i64.max(0) as u64;
            let unconsumed_count = (judged_i64 - consumed_i64).max(0) as u64;
            let mean_access_consumed =
                (consumed_count > 0).then(|| access_consumed_i64 as f64 / consumed_count as f64);
            let mean_access_unconsumed = (unconsumed_count > 0)
                .then(|| access_unconsumed_i64 as f64 / unconsumed_count as f64);
            // Log the divergence tell: sparsity + the collinearity ratio.
            // A low consumed share AND consumed-rows-carry-higher-access is
            // the "does-not-diverge → close won't-do" signal the gate names.
            tracing::info!(
                target: LOG_TARGET,
                namespace = %namespace,
                source = %source,
                consumed = consumed_count,
                unconsumed = unconsumed_count,
                mean_access_consumed = mean_access_consumed.unwrap_or(f64::NAN),
                mean_access_unconsumed = mean_access_unconsumed.unwrap_or(f64::NAN),
                "shadow consume-vs-access divergence (SHADOW MODE — #1707 gate evidence, not consulted by recall())"
            );
            Some(ConsumeAccessDivergence {
                consumed_count,
                unconsumed_count,
                mean_access_consumed,
                mean_access_unconsumed,
            })
        } else {
            None
        };

        baselines.push(PerSourceBaseline {
            namespace,
            source,
            count,
            median,
            mean,
            buckets,
            consumption_utility,
            consume_access_divergence,
        });
    }
    drop(median_stmt);

    Ok(CalibrationReport {
        window_days: days,
        total_observations,
        baselines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::shadow::observe;
    use crate::models::ConfidenceSignals;
    use crate::storage::open as open_storage;

    fn open_tmp() -> (Connection, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("test.db");
        let _ = open_storage(&path).expect("open storage");
        let conn = Connection::open(&path).expect("open conn");
        (conn, dir)
    }

    fn seed_mem(conn: &Connection, id: &str, ns: &str, source: &str) {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, source, created_at, updated_at)
             VALUES (?1, 'mid', ?2, ?1, 'c', ?3, '2026-05-15T00:00:00Z', '2026-05-15T00:00:00Z')",
            params![id, ns, source],
        )
        .expect("seed mem");
    }

    fn signals() -> ConfidenceSignals {
        ConfidenceSignals::default()
    }

    #[test]
    fn calibrate_emits_per_source_baselines() {
        let (conn, _dir) = open_tmp();
        seed_mem(&conn, "m1", "ns", "user");
        seed_mem(&conn, "m2", "ns", "user");
        seed_mem(&conn, "m3", "ns", "claude");
        observe(&conn, "m1", "ns", "user", 0.9, 0.5, &signals(), None).unwrap();
        observe(&conn, "m2", "ns", "user", 0.9, 0.7, &signals(), None).unwrap();
        observe(&conn, "m3", "ns", "claude", 0.9, 0.3, &signals(), None).unwrap();

        let report = calibrate_from_shadow(&conn, 30, Utc::now()).expect("calibrate");
        assert_eq!(report.total_observations, 3);
        assert_eq!(report.baselines.len(), 2);
        let user = report
            .baselines
            .iter()
            .find(|b| b.source == "user")
            .expect("user baseline");
        assert_eq!(user.count, 2);
        assert!(
            (user.median - 0.6).abs() < 1e-6,
            "median got {}",
            user.median
        );
        let claude = report
            .baselines
            .iter()
            .find(|b| b.source == "claude")
            .expect("claude baseline");
        assert!((claude.median - 0.3).abs() < 1e-6);
    }

    #[test]
    fn calibrate_median_correct_for_larger_even_and_odd_groups() {
        // #1905 — regression test for the O(1)-memory running-index
        // median that replaced the removed per-group `Vec<f64>`. Uses
        // groups large enough that an off-by-one in the running index
        // (`row_idx == mid` / `row_idx + 1 == mid`) would misalign the
        // captured central value(s) and silently corrupt the median.
        let (conn, _dir) = open_tmp();
        seed_mem(&conn, "m-odd", "ns-big", "odd-src");
        seed_mem(&conn, "m-even", "ns-big", "even-src");

        // Odd group: 101 values, 0.00..=1.00 step 0.01. True median
        // (middle of 101 sorted values, index 50) is 0.50.
        for i in 0..101 {
            let v = f64::from(i) / 100.0;
            observe(
                &conn,
                "m-odd",
                "ns-big",
                "odd-src",
                0.9,
                v,
                &signals(),
                None,
            )
            .unwrap();
        }
        // Even group: 100 values, 0.00..=0.99 step 0.01. True median is
        // the mean of index 49 (0.49) and index 50 (0.50) -> 0.495.
        for i in 0..100 {
            let v = f64::from(i) / 100.0;
            observe(
                &conn,
                "m-even",
                "ns-big",
                "even-src",
                0.9,
                v,
                &signals(),
                None,
            )
            .unwrap();
        }

        let report = calibrate_from_shadow(&conn, 30, Utc::now()).expect("calibrate");
        let odd = report
            .baselines
            .iter()
            .find(|b| b.source == "odd-src")
            .expect("odd baseline");
        assert_eq!(odd.count, 101);
        assert!(
            (odd.median - 0.50).abs() < 1e-9,
            "odd-group median got {}",
            odd.median
        );

        let even = report
            .baselines
            .iter()
            .find(|b| b.source == "even-src")
            .expect("even baseline");
        assert_eq!(even.count, 100);
        assert!(
            (even.median - 0.495).abs() < 1e-9,
            "even-group median got {}",
            even.median
        );
    }

    #[test]
    fn calibrate_buckets_cover_full_range() {
        let (conn, _dir) = open_tmp();
        seed_mem(&conn, "m1", "ns", "user");
        for v in &[0.05, 0.25, 0.45, 0.55, 0.95] {
            observe(&conn, "m1", "ns", "user", 0.9, *v, &signals(), None).unwrap();
        }
        let report = calibrate_from_shadow(&conn, 30, Utc::now()).expect("calibrate");
        let b = &report.baselines[0];
        // One value in each of buckets 0, 2, 4, 5, 9
        assert_eq!(b.buckets[0], 1);
        assert_eq!(b.buckets[2], 1);
        assert_eq!(b.buckets[4], 1);
        assert_eq!(b.buckets[5], 1);
        assert_eq!(b.buckets[9], 1);
        assert_eq!(b.count, 5);
    }

    #[test]
    fn calibrate_filters_by_window() {
        let (conn, _dir) = open_tmp();
        seed_mem(&conn, "m1", "ns", "user");
        // Insert one row with a very old observed_at by direct INSERT.
        conn.execute(
            "INSERT INTO confidence_shadow_observations
                (memory_id, namespace, source, caller_confidence, derived_confidence,
                 signals, recall_outcome, observed_at)
             VALUES ('m1', 'ns', 'user', 0.9, 0.5, '{}', NULL, '2020-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        observe(&conn, "m1", "ns", "user", 0.9, 0.7, &signals(), None).unwrap();
        let report = calibrate_from_shadow(&conn, 1, Utc::now()).expect("calibrate");
        // Old row outside the 1-day window drops out.
        assert_eq!(report.total_observations, 1);
        let b = &report.baselines[0];
        assert!((b.median - 0.7).abs() < 1e-6);
    }

    #[test]
    fn calibrate_empty_table_returns_empty_report() {
        let (conn, _dir) = open_tmp();
        let report = calibrate_from_shadow(&conn, 30, Utc::now()).expect("calibrate");
        assert_eq!(report.total_observations, 0);
        assert!(report.baselines.is_empty());
    }

    /// v0.9.0 §11.5 (#1706) — no `recall_observations` ledger entry for
    /// any shadow row in the window ⇒ `consumption_utility` stays
    /// `None` (an honest "no evidence yet", never a misleading `0.0`).
    #[test]
    fn consumption_utility_is_none_without_ledger_evidence() {
        let (conn, _dir) = open_tmp();
        seed_mem(&conn, "m1", "ns", "user");
        observe(&conn, "m1", "ns", "user", 0.9, 0.5, &signals(), None).unwrap();

        let report = calibrate_from_shadow(&conn, 30, Utc::now()).expect("calibrate");
        let b = &report.baselines[0];
        assert_eq!(
            b.consumption_utility, None,
            "no ledger row correlated ⇒ None, not 0.0"
        );
    }

    /// v0.9.0 §11.5 (#1706) — `calibrate_from_shadow` rides the offline
    /// sweep: it backfills `recall_outcome` from the
    /// `recall_observations` ledger BEFORE aggregating, so
    /// `consumption_utility` reflects consumption that happened after
    /// the shadow row was first observed.
    #[test]
    fn calibrate_from_shadow_backfills_and_computes_consumption_utility() {
        let (conn, _dir) = open_tmp();
        seed_mem(&conn, "m1", "ns", "user");
        seed_mem(&conn, "m2", "ns", "user");
        seed_mem(&conn, "consumer", "ns", "user");
        observe(&conn, "m1", "ns", "user", 0.9, 0.5, &signals(), None).unwrap();
        observe(&conn, "m2", "ns", "user", 0.9, 0.6, &signals(), None).unwrap();

        crate::observations::record_recall(
            &conn,
            "r1",
            &[
                crate::observations::Candidate {
                    memory_id: "m1",
                    retriever: "hybrid",
                    rank: 1,
                    score: 0.9,
                },
                crate::observations::Candidate {
                    memory_id: "m2",
                    retriever: "hybrid",
                    rank: 2,
                    score: 0.8,
                },
            ],
        )
        .unwrap();
        // Only m1 gets cited downstream — m2 was recalled but unused.
        crate::observations::mark_consumed(&conn, "r1", &["m1"], "consumer").unwrap();

        let report = calibrate_from_shadow(&conn, 30, Utc::now()).expect("calibrate");
        let b = &report.baselines[0];
        assert_eq!(b.source, "user");
        // 1 of 2 judged rows consumed ⇒ 0.5.
        assert!(
            (b.consumption_utility.expect("must have evidence") - 0.5).abs() < 1e-9,
            "got {:?}",
            b.consumption_utility
        );

        // The backfill is durable in the substrate, not just report-local:
        // a fresh read of the shadow table shows the stamped outcomes.
        let rows = crate::confidence::shadow::observations_since(&conn, Some("ns"), None)
            .expect("read back");
        let m1_outcome = rows
            .iter()
            .find(|r| r.memory_id == "m1")
            .and_then(|r| r.recall_outcome.clone());
        let m2_outcome = rows
            .iter()
            .find(|r| r.memory_id == "m2")
            .and_then(|r| r.recall_outcome.clone());
        assert_eq!(m1_outcome.as_deref(), Some("consumed"));
        assert_eq!(m2_outcome.as_deref(), Some("unconsumed"));
    }
}
