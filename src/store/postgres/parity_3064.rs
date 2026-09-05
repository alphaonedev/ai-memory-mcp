// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3064 lane L-PGP — postgres SAL implementations for the MCP tools whose
//! HTTP mirrors were fail-closed `501` on a postgres-backed daemon.
//!
//! These live in their own module rather than in `src/store/postgres.rs`
//! because that file sits at its `qual_10_module_size_ceiling` budget; the
//! lane brief mandates a submodule over a private ceiling bump. The wiring
//! mirrors `postgres/pubkey_history.rs`: an `impl PostgresStore` block whose
//! methods the trait arms in `postgres.rs` forward to.
//!
//! Every query here is a READ except the ONE `recall_outcome` backfill, which
//! is record-stop gated and SKIPPED (never forced, never refused) when the
//! record plane is stopped — see `backfill_recall_outcomes_pg`.

use chrono::{DateTime, Utc};

use super::{PostgresStore, StoreError, StoreResult, to_store_err};
use crate::confidence::calibrate::{CalibrationReport, ConsumeAccessDivergence, PerSourceBaseline};

/// `tracing` target for this module's calibration logs — the SAME target the
/// sqlite sweep uses, so an operator filters one name across both backends.
const LOG_TARGET: &str = "confidence.calibrate";

/// Bucket count of the derived-confidence histogram. Mirrors the sqlite
/// `PerSourceBaseline::buckets` array width; declared once so the SQL width
/// and the Rust array width cannot drift apart silently.
const BUCKET_COUNT: usize = 10;

/// One Pass-1 aggregate row: the per-(namespace, source) group tallies.
struct GroupRow {
    namespace: String,
    source: String,
    count: i64,
    mean: f64,
    consumed: i64,
    judged: i64,
    access_consumed: i64,
    access_unconsumed: i64,
}

impl PostgresStore {
    /// #3064 family F3 — the postgres twin of
    /// `crate::confidence::calibrate::calibrate_from_shadow`.
    ///
    /// Same three stages, same order, same wire shape:
    ///
    /// 1. bounded-window refusal + `since` cutoff via the SHARED
    ///    `validate::checked_days_ago`, so an out-of-range `days` is refused
    ///    with the identical message on both backends and the window boundary
    ///    is computed once, not twice;
    /// 2. the `recall_outcome` backfill (the one write — see
    ///    [`Self::backfill_recall_outcomes_pg`]);
    /// 3. Pass 1's single `GROUP BY` aggregation, then Pass 2's per-group
    ///    ordered scan for the median + histogram.
    ///
    /// Pass 2 is deliberately NOT collapsed into a window function: the
    /// sqlite sweep's median is defined as the mean of the two central values
    /// for an even count and the single central value for an odd one (#1915),
    /// and reproducing that contract explicitly is what keeps the two
    /// backends' numbers equal rather than merely similar.
    ///
    /// # Errors
    ///
    /// Propagates the bounded-window refusal from `checked_days_ago` and any
    /// postgres error.
    pub(super) async fn calibrate_confidence_report_pg(
        &self,
        days: i64,
        now: DateTime<Utc>,
    ) -> StoreResult<CalibrationReport> {
        // #3384 — caller-controlled windows must never reach chrono's
        // panicking `Duration::days`. The SHARED validator is the SSOT for
        // both the bound and the message.
        let since_dt = crate::validate::checked_days_ago(now, "days", days, 0).map_err(|e| {
            StoreError::InvalidInput {
                detail: e.to_string(),
            }
        })?;
        let since = since_dt.to_rfc3339();

        self.backfill_recall_outcomes_pg().await?;

        let groups = self.calibrate_pass1_pg(&since).await?;
        let total_observations: u64 = groups
            .iter()
            .map(|g| u64::try_from(g.count).unwrap_or(0))
            .sum();

        let mut baselines: Vec<PerSourceBaseline> = Vec::with_capacity(groups.len());
        for group in groups {
            if group.count <= 0 {
                continue;
            }
            let count = u64::try_from(group.count).unwrap_or(0);
            let (median, buckets) = self
                .calibrate_pass2_pg(&since, &group.namespace, &group.source, count)
                .await?;

            // v0.9.0 §11.5 (#1706) — consumption_utility = consumed / judged.
            // `None` (not zero) when nothing in the window correlated against
            // the ledger — an honest "no evidence yet" rather than a 0.0 that
            // would read as "never consumed".
            let consumption_utility = if group.judged > 0 {
                Some(ratio(group.consumed, group.judged))
            } else {
                None
            };
            if let Some(cu) = consumption_utility {
                tracing::info!(
                    target: LOG_TARGET,
                    namespace = %group.namespace,
                    source = %group.source,
                    consumption_utility = cu,
                    judged = group.judged,
                    "shadow consumption utility (SHADOW MODE — not consulted by recall())"
                );
            }

            // v1.0.0 §11.5 (#1707) — the consume-vs-access divergence
            // evidence. `unconsumed = judged - consumed` (the SQL split is
            // exhaustive over `recall_outcome IS NOT NULL`). Means are `None`
            // when their bucket is empty — never a misleading 0.0.
            let consume_access_divergence = if group.judged > 0 {
                let consumed_count = u64::try_from(group.consumed.max(0)).unwrap_or(0);
                let unconsumed_count =
                    u64::try_from((group.judged - group.consumed).max(0)).unwrap_or(0);
                Some(ConsumeAccessDivergence {
                    consumed_count,
                    unconsumed_count,
                    mean_access_consumed: (consumed_count > 0)
                        .then(|| ratio(group.access_consumed, group.consumed.max(1))),
                    mean_access_unconsumed: (unconsumed_count > 0).then(|| {
                        ratio(
                            group.access_unconsumed,
                            (group.judged - group.consumed).max(1),
                        )
                    }),
                })
            } else {
                None
            };

            baselines.push(PerSourceBaseline {
                namespace: group.namespace,
                source: group.source,
                count,
                median,
                mean: group.mean,
                buckets,
                consumption_utility,
                consume_access_divergence,
            });
        }

        Ok(CalibrationReport {
            window_days: days,
            total_observations,
            baselines,
        })
    }

    /// Pass 1 — per-group count / mean / consumption tallies, computed
    /// entirely in SQL, mirroring the sqlite aggregation column for column.
    ///
    /// The `LEFT JOIN memories` is read-only and carries the #1707
    /// `access_count` evidence; being a LEFT join with `COALESCE(..., 0)`,
    /// orphan observation rows whose source memory was CASCADE-deleted still
    /// surface (as access 0), which is the audit-honest contract the sqlite
    /// module documents.
    async fn calibrate_pass1_pg(&self, since: &str) -> StoreResult<Vec<GroupRow>> {
        let rows: Vec<(String, String, i64, Option<f64>, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT o.namespace,
                    o.source,
                    COUNT(*)::BIGINT,
                    AVG(o.derived_confidence),
                    SUM(CASE WHEN o.recall_outcome = 'consumed' THEN 1 ELSE 0 END)::BIGINT,
                    SUM(CASE WHEN o.recall_outcome IS NOT NULL THEN 1 ELSE 0 END)::BIGINT,
                    SUM(CASE WHEN o.recall_outcome = 'consumed'
                             THEN COALESCE(m.access_count, 0) ELSE 0 END)::BIGINT,
                    SUM(CASE WHEN o.recall_outcome = 'unconsumed'
                             THEN COALESCE(m.access_count, 0) ELSE 0 END)::BIGINT
             FROM confidence_shadow_observations o
             LEFT JOIN memories m ON m.id = o.memory_id
             WHERE o.observed_at >= $1
             GROUP BY o.namespace, o.source
             ORDER BY o.namespace, o.source",
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| to_store_err("calibrate pass 1 aggregate", e))?;

        Ok(rows
            .into_iter()
            .map(
                |(namespace, source, count, mean, consumed, judged, access_c, access_u)| GroupRow {
                    namespace,
                    source,
                    count,
                    // AVG over a non-empty group is never NULL, but a NULL
                    // would otherwise panic an `unwrap`; 0.0 is the same value
                    // an empty group would report and the group is skipped
                    // upstream when `count <= 0`.
                    mean: mean.unwrap_or(0.0),
                    consumed,
                    judged,
                    access_consumed: access_c,
                    access_unconsumed: access_u,
                },
            )
            .collect())
    }

    /// Pass 2 — the per-group ordered scan that yields the median plus the
    /// 10-bucket histogram.
    ///
    /// The whole group is fetched (bounded by the group size, exactly as the
    /// sqlite cursor is) and walked once: the histogram needs every value, and
    /// the median needs only the value(s) at the central index, so the walk
    /// captures those scalars rather than sorting a second time — the values
    /// arrive `ORDER BY derived_confidence ASC` from the server.
    async fn calibrate_pass2_pg(
        &self,
        since: &str,
        namespace: &str,
        source: &str,
        count: u64,
    ) -> StoreResult<(f64, [u64; BUCKET_COUNT])> {
        let values: Vec<(f64,)> = sqlx::query_as(
            "SELECT derived_confidence
             FROM confidence_shadow_observations
             WHERE observed_at >= $1 AND namespace = $2 AND source = $3
             ORDER BY derived_confidence ASC",
        )
        .bind(since)
        .bind(namespace)
        .bind(source)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| to_store_err("calibrate pass 2 median scan", e))?;

        let mut buckets = [0_u64; BUCKET_COUNT];
        let mid = usize::try_from(count / 2).unwrap_or(usize::MAX);
        let even_count = count % 2 == 0;
        let mut lower_mid_value: Option<f64> = None;
        let mut mid_value: Option<f64> = None;
        for (row_idx, (value,)) in values.into_iter().enumerate() {
            buckets[bucket_index(value)] += 1;
            if row_idx == mid {
                mid_value = Some(value);
            } else if even_count && row_idx + 1 == mid {
                lower_mid_value = Some(value);
            }
        }
        // Rows arrived ORDER BY ASC — the captured scalar(s) at `mid` (and
        // `mid - 1` for an even count) are the median inputs. `0.0` is the
        // sqlite twin's value for the degenerate empty case.
        let median = match (even_count, lower_mid_value, mid_value) {
            (true, Some(lower), Some(upper)) => f64::midpoint(lower, upper),
            (false, _, Some(single)) => single,
            _ => 0.0,
        };
        Ok((median, buckets))
    }

    /// The ONE write in the calibration sweep: backfill `recall_outcome` for
    /// any shadow row a `recall_observations` ledger entry has since appeared
    /// for. SHADOW MODE — the backfilled column only feeds the report's
    /// optional `consumption_utility` / divergence fields and is never read by
    /// `crate::storage::recall`.
    ///
    /// Two ways this DEGRADES rather than failing the whole report, mirroring
    /// the sqlite twin's skip-with-WARN contract:
    ///
    /// * the ledger relation is absent — nothing to correlate against;
    /// * the record plane is STOPPED — the substrate is refusing writes, and a
    ///   read-only operator report must not be the one caller that forces one.
    ///   The postgres adapter is therefore STRICTER than sqlite under a
    ///   stopped plane (sqlite's `backfill_recall_outcomes` is ungated), which
    ///   is the fail-closed direction: the baselines are unaffected and only
    ///   the optional evidence fields degrade to `None`.
    ///
    /// Every other error propagates.
    async fn backfill_recall_outcomes_pg(&self) -> StoreResult<()> {
        if let Err(e) = self.gate_record_stop().await {
            tracing::warn!(
                target: LOG_TARGET,
                error = %e,
                "record plane stopped — skipping the shadow recall_outcome backfill; \
                 calibration baselines are unaffected and the consumption-utility \
                 evidence degrades to `null` for un-backfilled rows"
            );
            return Ok(());
        }
        let ledger_present: Option<(Option<String>,)> =
            sqlx::query_as("SELECT to_regclass('recall_observations')::TEXT")
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| to_store_err("probe recall_observations relation", e))?;
        if !matches!(ledger_present, Some((Some(_),))) {
            tracing::warn!(
                target: "confidence.shadow",
                "recall_observations ledger absent, skipping consumption utility backfill"
            );
            return Ok(());
        }
        let updated = sqlx::query(
            "UPDATE confidence_shadow_observations o
                SET recall_outcome = CASE
                        WHEN EXISTS (
                            SELECT 1 FROM recall_observations ro
                             WHERE ro.memory_id = o.memory_id
                               AND ro.consumed = TRUE
                        ) THEN 'consumed'
                        ELSE 'unconsumed'
                    END
              WHERE o.recall_outcome IS NULL
                AND EXISTS (
                    SELECT 1 FROM recall_observations ro
                     WHERE ro.memory_id = o.memory_id
                )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| to_store_err("backfill shadow recall_outcome", e))?
        .rows_affected();
        if updated > 0 {
            tracing::info!(
                target: LOG_TARGET,
                backfilled = updated,
                "shadow sweep: backfilled recall_outcome from the recall_observations ledger"
            );
        }
        Ok(())
    }
}

/// `numerator / denominator` as an `f64`, total over a zero denominator.
///
/// A zero denominator returns `0.0` rather than `NaN`/`inf`, so a degenerate
/// group can never serialize a non-finite number into the report (PERF-25:
/// never let a `NaN` reach an ordering or a wire field).
fn ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    i64_to_f64(numerator) / i64_to_f64(denominator)
}

/// `i64 -> f64` for the report's row COUNTS and summed `access_count` values.
///
/// This is a WIDENING conversion, not a narrowing one (PERF-07 governs
/// narrowing integer casts): it is EXACT for every magnitude below `2^53`,
/// which every realistic corpus row count and access-count sum is, and it
/// saturates rather than wrapping past that. The sqlite SSOT
/// `crate::confidence::calibrate::calibrate_from_shadow` carries the
/// IDENTICAL `cast_precision_loss` allow over the IDENTICAL arithmetic —
/// keeping the same form here is what makes the two backends' means and
/// ratios provably equal rather than merely close.
#[allow(clippy::cast_precision_loss)]
fn i64_to_f64(value: i64) -> f64 {
    value as f64
}

/// Histogram bucket for a derived-confidence value: ten half-open buckets
/// `[0.0, 0.1) .. [0.9, 1.0]`, with the `1.0` edge folded into the last one.
///
/// Computes the SAME `clamp(0.0, 1.0) * 10.0` product and the SAME truncation
/// the sqlite sweep does, so the two histograms agree bucket for bucket, but
/// resolves the integral result through a total lookup instead of a lossy
/// `f64 as usize` narrowing cast (PERF-07 / PERF-09).
fn bucket_index(value: f64) -> usize {
    let truncated = (value.clamp(0.0, 1.0) * 10.0).trunc();
    (0..BUCKET_COUNT)
        .find(|i| u32::try_from(*i).map(f64::from).unwrap_or(f64::NAN) == truncated)
        .unwrap_or(BUCKET_COUNT - 1)
}

#[cfg(test)]
mod tests {
    use super::{bucket_index, i64_to_f64, ratio};

    #[test]
    fn bucket_index_matches_the_sqlite_contract() {
        assert_eq!(bucket_index(0.0), 0);
        assert_eq!(bucket_index(0.09), 0);
        assert_eq!(bucket_index(0.1), 1);
        assert_eq!(bucket_index(0.55), 5);
        assert_eq!(bucket_index(0.9), 9);
        // The `1.0` edge lands in the LAST bucket, never out of bounds.
        assert_eq!(bucket_index(1.0), 9);
        // Out-of-range values clamp rather than panicking or wrapping.
        assert_eq!(bucket_index(-3.0), 0);
        assert_eq!(bucket_index(7.5), 9);
    }

    #[test]
    fn ratio_is_total_and_never_divides_by_zero() {
        assert!((ratio(1, 2) - 0.5).abs() < f64::EPSILON);
        assert!((ratio(0, 5) - 0.0).abs() < f64::EPSILON);
        // A zero denominator returns 0.0 instead of producing NaN/inf, so a
        // degenerate group can never poison the serialized report.
        assert!((ratio(7, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn i64_to_f64_is_exact_past_the_i32_range() {
        assert!((i64_to_f64(0) - 0.0).abs() < f64::EPSILON);
        assert!((i64_to_f64(-5) - -5.0).abs() < f64::EPSILON);
        assert!((i64_to_f64(1_000_000) - 1_000_000.0).abs() < f64::EPSILON);
        // Exact well past the i32 range — the values this feeds (row counts,
        // summed access_count) never approach the 2^53 exactness bound.
        assert!((i64_to_f64(5_000_000_000) - 5_000_000_000.0).abs() < f64::EPSILON);
    }
}
