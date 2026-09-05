// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3345 — curator self-report retention: the daily rollup and the
//! historical-backlog collapse.
//!
//! ## The defect
//!
//! Every curator sweep wrote its cycle report to `_curator/reports` as a
//! `Tier::Mid`, never-expiring, first-class memory. On the certified f1 tier
//! (`curator --daemon --interval-secs 300`) that is 287 rows/day: **24,930
//! rows, 24,801 of them carrying a paid embedding, against 512 real
//! memories** — 97% of the store was the curator talking about itself.
//!
//! ## The posture this module implements
//!
//! A self-report is bookkeeping ABOUT the store, not knowledge IN it. So:
//!
//! 1. the per-sweep row is `Tier::Short` with an explicit
//!    [`CURATOR_REPORT_TTL_HOURS`] expiry (in
//!    [`crate::autonomy::persist_self_report`]);
//! 2. **before** any of a day's rows can reach that TTL, every cycle folds the
//!    day into ONE summary row in [`CURATOR_REPORTS_DAILY_NAMESPACE`], so the
//!    day's aggregate outlives its per-sweep detail — bounded retention with
//!    no information loss, which is the whole point of rolling up rather than
//!    simply deleting;
//! 3. the pre-existing backlog is collapsed by
//!    [`prune_reports`], which is a **dry run by default**, rolls each affected
//!    day up before touching anything, and then re-targets those rows onto the
//!    #3345 retention (`Tier::Short`, `created_at + CURATOR_REPORT_TTL_HOURS`,
//!    earliest-wins). It never deletes: reaping stays with the audited GC path,
//!    which archives what it reaps when `archive_on_gc` is on.
//!
//! Nothing here is destructive and every step is idempotent, chunked and
//! resumable — re-running the prune on a collapsed store stamps zero rows.
//!
//! The no-embedding half of #3345 is NOT here: it lives in the visibility
//! SSOT ([`crate::visibility::SQL_AND_NOT_SUBSTRATE`]) because it has to hold
//! for every substrate namespace, not just this one.

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde_json::{Map, Value};

use crate::autonomy::{
    CURATOR_REPORT_ROLLUP_TTL_DAYS, CURATOR_REPORT_TTL_HOURS, CURATOR_REPORTS_DAILY_NAMESPACE,
    CURATOR_REPORTS_NAMESPACE, CURATOR_SOURCE_LABEL,
};
use crate::models::{ConfidenceSource, Memory, Tier};

/// Upper bound on per-sweep rows folded into ONE day's summary in a single
/// pass. A 60-second sweep interval — four times faster than the fastest
/// interval observed in the fleet — produces 1,440 rows/day, so this leaves
/// headroom while keeping the fold's working set provably bounded on a store
/// whose backlog is pathological.
pub const ROLLUP_MAX_ROWS_PER_DAY: usize = 4_096;

/// Rows the backlog collapse stamps per transaction. Chunked so a prune over a
/// 25k-row backlog holds a short write lock repeatedly rather than one long
/// one, and so an interrupted run resumes exactly where it stopped.
pub const PRUNE_CHUNK_ROWS: usize = 2_000;

/// Upper bound on distinct days the backlog collapse rolls up in one
/// invocation. ~3 months of daily buckets; a deeper backlog simply needs the
/// command run again (it is idempotent and resumable by construction).
pub const PRUNE_MAX_DAYS: usize = 128;

/// Defensive ceiling on chunk iterations in one prune call, so a backend that
/// somehow reports progress without making any cannot spin. Shared with the
/// postgres arm so both backends bound the collapse identically.
pub const PRUNE_MAX_CHUNKS: usize = 10_000;

/// The wire/JSON key carrying the rolled-up UTC date (`YYYY-MM-DD`).
pub const ROLLUP_KEY_DATE: &str = "rollup_date";
/// The wire/JSON key carrying the number of cycles folded into a summary.
pub const ROLLUP_KEY_CYCLES: &str = "cycles";

/// Outcome of a [`prune_reports`] pass. Every field is a count so the caller
/// can print an operator-legible ledger in either mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct PruneReport {
    /// Per-sweep report rows carrying NO expiry (the unbounded backlog) at the
    /// start of the pass.
    pub backlog: usize,
    /// Distinct UTC days folded into a daily summary. Zero on a dry run.
    pub days_rolled_up: usize,
    /// Rows whose expiry this pass stamped. Zero on a dry run.
    pub stamped: usize,
    /// `true` when nothing was written (the default mode).
    pub dry_run: bool,
}

/// Fold a day's per-sweep report bodies into ONE summary object.
///
/// Pure and backend-free, so the sqlite daemon path and the backlog collapse
/// share the identical aggregation.
///
/// The fold is deliberately GENERIC over the report's keys — every numeric key
/// is summed, every boolean key is OR-ed, and `cycle_ts` is tracked as a
/// first/last window. A counter added to the self-report body therefore
/// appears in the rollup with no change here, which is what stops the summary
/// from silently going stale against the thing it summarises.
#[must_use]
pub fn fold_reports(date: &str, bodies: &[Value]) -> Value {
    let mut totals: Map<String, Value> = Map::new();
    let mut flags: Map<String, Value> = Map::new();
    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;
    let mut max_duration_ms: i64 = 0;

    for body in bodies {
        let Some(obj) = body.as_object() else {
            continue;
        };
        for (key, value) in obj {
            match value {
                Value::Bool(b) => {
                    let prior = flags.get(key).and_then(Value::as_bool).unwrap_or(false);
                    flags.insert(key.clone(), Value::Bool(prior || *b));
                }
                Value::Number(n) => {
                    // Reports carry integral counters; a non-integral value is
                    // folded through `as_f64`'s truncation rather than dropped,
                    // so an unexpected shape degrades the precision of ONE
                    // summed field instead of losing the field.
                    #[allow(clippy::cast_possible_truncation)]
                    let delta = n
                        .as_i64()
                        .unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64);
                    if key == KEY_CYCLE_DURATION_MS {
                        max_duration_ms = max_duration_ms.max(delta);
                    }
                    let prior = totals.get(key).and_then(Value::as_i64).unwrap_or(0);
                    totals.insert(key.clone(), Value::from(prior.saturating_add(delta)));
                }
                Value::String(s) if key == KEY_CYCLE_TS => {
                    if first_ts.as_ref().is_none_or(|f| s < f) {
                        first_ts = Some(s.clone());
                    }
                    if last_ts.as_ref().is_none_or(|l| s > l) {
                        last_ts = Some(s.clone());
                    }
                }
                _ => {}
            }
        }
    }

    serde_json::json!({
        ROLLUP_KEY_DATE: date,
        ROLLUP_KEY_CYCLES: bodies.len(),
        "first_cycle_ts": first_ts,
        "last_cycle_ts": last_ts,
        "cycle_duration_ms_max": max_duration_ms,
        "totals": Value::Object(totals),
        "flags": Value::Object(flags),
    })
}

/// Report-body key carrying the cycle's wall-clock timestamp.
const KEY_CYCLE_TS: &str = "cycle_ts";
/// Report-body key carrying the cycle's duration.
const KEY_CYCLE_DURATION_MS: &str = "cycle_duration_ms";

/// Build the daily-summary [`Memory`] for `date`.
///
/// The `(title, namespace)` pair is stable per date and `db::insert` upserts on
/// exactly that key, so re-folding a day REPLACES its summary rather than
/// appending a second one — the property that makes both the per-cycle rollup
/// and the backlog collapse idempotent.
#[must_use]
pub fn daily_rollup_memory(date: &str, bodies: &[Value], now: DateTime<Utc>) -> Memory {
    let ts = now.to_rfc3339();
    let body = fold_reports(date, bodies);
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: CURATOR_REPORTS_DAILY_NAMESPACE.to_string(),
        title: format!("curator daily @ {date}"),
        content: serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()),
        tags: vec!["_curator".to_string(), "_report".to_string()],
        priority: 2,
        confidence: 1.0,
        source: CURATOR_SOURCE_LABEL.to_string(),
        created_at: ts.clone(),
        updated_at: ts,
        expires_at: Some(
            (now + chrono::Duration::days(CURATOR_REPORT_ROLLUP_TTL_DAYS)).to_rfc3339(),
        ),
        // #2110 — substrate-authored write through a direct `db::insert`.
        metadata: serde_json::json!({
            "agent_id": crate::identity::sentinels::AI_CURATOR,
            "why_trace": crate::storage::WHY_TRACE_SUBSTRATE_SYSTEM,
        }),
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// The UTC date (`YYYY-MM-DD`) prefix of an RFC3339 timestamp.
///
/// Report rows are written by the substrate with `Utc::now().to_rfc3339()`, so
/// the first ten bytes ARE the UTC date; the SQL side groups on the same
/// `substr(created_at, 1, 10)` so the Rust and SQL views of "which day is this
/// row in" cannot disagree.
#[must_use]
pub fn utc_date_prefix(rfc3339: &str) -> &str {
    rfc3339.get(..DATE_PREFIX_LEN).unwrap_or(rfc3339)
}

/// Length of a `YYYY-MM-DD` date prefix.
const DATE_PREFIX_LEN: usize = 10;

/// Read the live per-sweep report bodies for one UTC day, bounded by
/// [`ROLLUP_MAX_ROWS_PER_DAY`].
///
/// # Errors
///
/// Propagates the underlying SQLite error.
pub fn report_bodies_for_day(conn: &Connection, date: &str) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare_cached(
        "SELECT content FROM memories \
         WHERE namespace = ?1 AND substr(created_at, 1, 10) = ?2 \
         ORDER BY created_at ASC LIMIT ?3",
    )?;
    let rows = stmt.query_map(
        params![
            CURATOR_REPORTS_NAMESPACE,
            date,
            i64::try_from(ROLLUP_MAX_ROWS_PER_DAY).unwrap_or(i64::MAX)
        ],
        |row| row.get::<_, String>(0),
    )?;
    let mut out = Vec::new();
    for row in rows {
        // A body that will not parse is skipped, not fatal: one malformed
        // report must never stop the day from being summarised.
        if let Ok(value) = serde_json::from_str::<Value>(&row?) {
            out.push(value);
        }
    }
    Ok(out)
}

/// Fold one UTC day into its daily summary row. Returns the number of
/// per-sweep rows folded (0 = nothing to summarise, nothing written).
///
/// # Errors
///
/// Propagates SQLite read/write errors.
pub fn roll_up_day(conn: &Connection, date: &str, now: DateTime<Utc>) -> Result<usize> {
    let bodies = report_bodies_for_day(conn, date)?;
    if bodies.is_empty() {
        return Ok(0);
    }
    let mem = daily_rollup_memory(date, &bodies, now);
    // The upsert key is `(title, namespace)`, so the returned id is the
    // EXISTING summary row's when this day has already been folded — which is
    // exactly what makes a re-fold replace rather than append.
    let _rolled_up_id = crate::db::insert(conn, &mem)?;
    Ok(bodies.len())
}

/// Fold TODAY's cycles into today's summary. Called once per curator cycle.
///
/// Recomputing the whole day (rather than incrementing yesterday's summary) is
/// what makes this safe to run on every cycle: it is idempotent, it self-heals
/// a cycle that failed to fold, and because a day is always folded while ALL of
/// its rows are still live (they live [`CURATOR_REPORT_TTL_HOURS`]), the last
/// fold of a day is complete and stays frozen once the date rolls over.
///
/// # Errors
///
/// Propagates SQLite read/write errors.
pub fn roll_up_today(conn: &Connection) -> Result<usize> {
    let now = Utc::now();
    let today = now.format("%Y-%m-%d").to_string();
    roll_up_day(conn, &today, now)
}

/// What makes a per-sweep report row "backlog": it is NOT yet under the #3345
/// retention.
///
/// **The marker is the TIER, and that is a measured decision, not a
/// convenience.** The obvious predicate — `expires_at IS NULL` — finds nothing
/// on a real store: `db::insert` backfills the tier default through
/// [`crate::models::Memory::effective_expires_at`] (#1466), so the pre-#3345
/// writer's `Tier::Mid` rows were stamped `created_at + 7 days` on the way in.
/// The 24,930 rows on the certified f1 tier were therefore not
/// missing-an-expiry, they were **expired-and-never-reaped** (the missing
/// reaper), and a NULL-expiry prune would have reported "nothing to do" while
/// the whole backlog sat there.
///
/// The fixed writer stamps `Tier::Short`; every legacy row is `Tier::Mid` (or
/// an older tier). So the tier IS the exact, cheap, backend-portable marker —
/// no date arithmetic in SQL, no RFC3339-vs-`datetime()` format drift, and the
/// collapse is idempotent because it rewrites the tier as it goes.
fn backlog_marker_tier() -> &'static str {
    Tier::Short.as_str()
}

/// Count per-sweep report rows not yet under the #3345 retention.
///
/// # Errors
///
/// Propagates the underlying SQLite error.
pub fn backlog_count(conn: &Connection) -> Result<usize> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND tier <> ?2",
        params![CURATOR_REPORTS_NAMESPACE, backlog_marker_tier()],
        |r| r.get(0),
    )?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// Distinct UTC days present in the backlog, oldest first, bounded by
/// [`PRUNE_MAX_DAYS`].
///
/// # Errors
///
/// Propagates the underlying SQLite error.
pub fn backlog_days(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT substr(created_at, 1, 10) AS d FROM memories \
         WHERE namespace = ?1 AND tier <> ?2 ORDER BY d ASC LIMIT ?3",
    )?;
    let rows = stmt.query_map(
        params![
            CURATOR_REPORTS_NAMESPACE,
            backlog_marker_tier(),
            i64::try_from(PRUNE_MAX_DAYS).unwrap_or(i64::MAX)
        ],
        |row| row.get::<_, String>(0),
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Stamp the retention the rows of ONE already-folded day should have had.
/// Returns the number of rows stamped (0 = that day is drained).
///
/// Scoped to a single day ON PURPOSE. `backlog_days` is capped at
/// [`PRUNE_MAX_DAYS`], so an unscoped stamp would set an expiry on rows whose
/// day had not been summarised yet — the one way this collapse could lose
/// information. Pairing "fold day D" with "stamp only day D" makes that
/// structurally impossible: a row's retention is stamped only after its day's
/// aggregate is durable.
///
/// The retention is derived PER ROW from its own `created_at`, never a blanket
/// `now`: a report written five minutes ago keeps its full
/// [`CURATOR_REPORT_TTL_HOURS`] window, while a report from June is already
/// past its window and becomes GC-eligible on the next tick. The write only
/// ever moves an expiry EARLIER — a row whose expiry is already inside the
/// window keeps its own, so the collapse can shorten over-long substrate
/// retention (which is its entire purpose) but can never extend the life of a
/// row the store was already going to reap.
///
/// # Errors
///
/// Propagates SQLite read/write errors.
pub fn stamp_backlog_chunk(conn: &Connection, date: &str, chunk: usize) -> Result<usize> {
    // B7 (LESSON-5) — a store under a record-stop accepts NO writes, and this
    // is a write path that does not funnel through `db::insert`. Gate it here
    // rather than allowlist it: a frozen store must refuse the collapse, not
    // quietly re-target retention behind the freeze.
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let mut stmt = conn.prepare_cached(
        "SELECT id, created_at, expires_at FROM memories \
         WHERE namespace = ?1 AND tier <> ?2 AND substr(created_at, 1, 10) = ?3 \
         ORDER BY id LIMIT ?4",
    )?;
    let rows = stmt
        .query_map(
            params![
                CURATOR_REPORTS_NAMESPACE,
                backlog_marker_tier(),
                date,
                i64::try_from(chunk).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.is_empty() {
        return Ok(0);
    }
    let mut stamped = 0usize;
    for (id, created_at, current) in rows {
        let target = backlog_expiry_for(&created_at);
        // Earliest-wins: never lengthen.
        let expiry = match current {
            Some(existing) if existing < target => existing,
            _ => target,
        };
        stamped += conn.execute(
            "UPDATE memories SET tier = ?1, expires_at = ?2 \
             WHERE id = ?3 AND namespace = ?4 AND tier <> ?1",
            params![backlog_marker_tier(), expiry, id, CURATOR_REPORTS_NAMESPACE],
        )?;
    }
    Ok(stamped)
}

/// The expiry a backlog row should have carried: its own `created_at` plus
/// [`CURATOR_REPORT_TTL_HOURS`], rendered in the SAME canonical form the write
/// funnels stamp so string-ordered `expires_at` comparisons stay correct. An
/// unparseable `created_at` falls back to `now` + the window — never to a NULL
/// or a malformed value.
fn backlog_expiry_for(created_at: &str) -> String {
    let base = DateTime::parse_from_rfc3339(created_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let stamp = (base + chrono::Duration::hours(CURATOR_REPORT_TTL_HOURS)).to_rfc3339();
    crate::validate::canonical_valid_time_opt(Some(&stamp)).unwrap_or(stamp)
}

/// Collapse the historical `_curator/reports` backlog.
///
/// `apply == false` (the default the CLI exposes) writes NOTHING and returns
/// the counts a real run would act on. `apply == true` walks the backlog DAY BY
/// DAY: fold the day into its summary, then — and only then — re-target that
/// day's rows onto the #3345 retention in [`PRUNE_CHUNK_ROWS`] chunks.
/// Deletion is never performed here: the rows become ordinary expired rows that
/// the audited GC path reaps (and archives, under `archive_on_gc`), so the
/// collapse is reversible up to the archive's own retention.
///
/// Shortening over-long retention on substrate bookkeeping IS the operation —
/// see [`backlog_marker_tier`] for why the legacy rows carry a 7-day tier
/// default rather than no expiry at all. It only ever moves an expiry earlier,
/// never later, and it touches no namespace but `_curator/reports`.
///
/// A backlog deeper than [`PRUNE_MAX_DAYS`] is collapsed by running the command
/// again — each invocation is bounded, and no row is ever stamped ahead of its
/// day's summary.
///
/// # Errors
///
/// Propagates SQLite read/write errors. A failure part-way through leaves a
/// partially-collapsed store, which the next invocation completes: every step
/// is idempotent and predicated on its own remaining work.
pub fn prune_reports(conn: &Connection, apply: bool) -> Result<PruneReport> {
    let backlog = backlog_count(conn)?;
    let mut report = PruneReport {
        backlog,
        dry_run: !apply,
        ..PruneReport::default()
    };
    if !apply || backlog == 0 {
        return Ok(report);
    }
    let now = Utc::now();
    let mut chunk_budget = PRUNE_MAX_CHUNKS;
    for day in backlog_days(conn)? {
        // Fold FIRST. A day whose fold found nothing is left entirely alone —
        // its rows keep their NULL expiry rather than being stamped with no
        // summary standing behind them.
        if roll_up_day(conn, &day, now)? == 0 {
            continue;
        }
        report.days_rolled_up += 1;
        while chunk_budget > 0 {
            chunk_budget -= 1;
            let stamped = stamp_backlog_chunk(conn, &day, PRUNE_CHUNK_ROWS)?;
            if stamped == 0 {
                break;
            }
            report.stamped += stamped;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(ts: &str, tagged: i64, degraded: bool) -> Value {
        serde_json::json!({
            "cycle_ts": ts,
            "cycle_duration_ms": 10,
            "auto_tagged": tagged,
            "rollback_log_degraded": degraded,
        })
    }

    #[test]
    fn fold_sums_numbers_ors_flags_and_windows_timestamps() {
        let bodies = vec![
            body("2026-09-01T00:05:00+00:00", 3, false),
            body("2026-09-01T23:55:00+00:00", 4, true),
        ];
        let folded = fold_reports("2026-09-01", &bodies);
        assert_eq!(
            folded[ROLLUP_KEY_CYCLES], 2,
            "one summary must count every folded cycle"
        );
        assert_eq!(
            folded["totals"]["auto_tagged"], 7,
            "numeric counters are summed across the day"
        );
        assert_eq!(
            folded["flags"]["rollback_log_degraded"], true,
            "a degraded cycle must never be OR-ed away by a healthy one"
        );
        assert_eq!(folded["first_cycle_ts"], "2026-09-01T00:05:00+00:00");
        assert_eq!(folded["last_cycle_ts"], "2026-09-01T23:55:00+00:00");
    }

    #[test]
    fn fold_of_no_bodies_is_an_empty_day() {
        let folded = fold_reports("2026-09-02", &[]);
        assert_eq!(folded[ROLLUP_KEY_CYCLES], 0);
        assert_eq!(folded[ROLLUP_KEY_DATE], "2026-09-02");
    }

    #[test]
    fn backlog_expiry_is_created_at_plus_the_retention_window() {
        let got = backlog_expiry_for("2026-06-06T00:00:00+00:00");
        let parsed = DateTime::parse_from_rfc3339(&got).expect("canonical RFC3339");
        let base = DateTime::parse_from_rfc3339("2026-06-06T00:00:00+00:00").unwrap();
        assert_eq!(
            (parsed - base).num_hours(),
            CURATOR_REPORT_TTL_HOURS,
            "a backlog row must get the window it should have had, not `now`"
        );
    }

    #[test]
    fn utc_date_prefix_takes_the_calendar_day() {
        assert_eq!(utc_date_prefix("2026-09-01T12:00:00+00:00"), "2026-09-01");
        assert_eq!(utc_date_prefix("2026"), "2026");
    }
}
