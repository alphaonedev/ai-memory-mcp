// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3323 — per-lineage + per-namespace token/cost accounting.
//!
//! This module gives a runaway atomisation/reflection cascade a DOLLAR
//! FIGURE instead of a discovery — the "$50k on the screen". It is
//! deliberately SELF-CONTAINED and ADVISORY: it never sits on the
//! integrity-critical path, holds no durable memory truth, and every
//! increment is best-effort so a metering failure can never fail or roll
//! back a memory write or recall (North Star: degrade, never corrupt).
//!
//! ## Model
//!
//! One counter relation, [`TABLE`], keyed by `(scope_kind, scope_key)`:
//!
//! * [`SCOPE_NAMESPACE`] — `scope_key` is the namespace. The direct
//!   "how much has this namespace cost" figure.
//! * [`SCOPE_LINEAGE`] — `scope_key` is a MEMORY ID, i.e. one node in the
//!   `derives_from` lineage DAG. Each node accrues its OWN tokens at O(1)
//!   on the write path (deliberately NO DAG walk on the hot write path —
//!   the #3196 "writes must not stall" property). The per-lineage-ROOT
//!   figure is a REPORT-time rollup: [`lineage_rollup`] sums a root plus
//!   the descendants reachable through the provenance subset
//!   (`storage::lineage_descendants`).
//!
//! The tokens->cost conversion ([`micro_usd_for_tokens`]) is applied ONLY
//! at rollup time, so the durable rows hold exact integer token counts
//! (never a float — a float aggregate/key would corrupt ordering,
//! PERF-25) and re-pricing the fleet needs no row rewrite.
//!
//! ## Coverage boundary (honest)
//!
//! WRITE metering is universal for the SQLite/default path: it rides
//! `storage::insert_inner`, the single LOCAL-authorship write chokepoint
//! (federation/import admission is excluded — those tokens were spent on
//! the authoring node), plus `PostgresStore::store`. RECALL metering
//! rides the SAL store funnels (`SqliteStore::recall_hybrid` /
//! `PostgresStore::recall_hybrid`) where a WRITABLE connection exists;
//! the read-only HTTP recall fast-path defers, consistent with recall
//! staying pure (#1953). A build/config that never routes through those
//! funnels simply reports fewer numbers — never wrong ones.

use rusqlite::{Connection, params, params_from_iter};

use crate::models::Memory;

/// The counter relation name (SSOT for the table, shared by the DDL doc
/// twins and every statement in this module).
pub const TABLE: &str = "token_cost_counters";

/// `scope_kind` value: `scope_key` is a namespace.
pub const SCOPE_NAMESPACE: &str = "namespace";
/// `scope_kind` value: `scope_key` is a memory id — a node in the
/// `derives_from` lineage DAG.
pub const SCOPE_LINEAGE: &str = "lineage";

/// Embedded SQLite DDL doc twin, applied by the additive v93 migration arm.
pub const MIGRATION_V93_SQLITE: &str =
    include_str!("../../migrations/sqlite/0077_v93_token_cost_counters.sql");

/// Default blended advisory price: micro-USD ($1e-6) per 1,000 tokens.
/// `10_000` micro-USD / 1K tokens = $0.01 / 1K tokens = $10 / 1M tokens —
/// a deliberately round, blended input+output figure. This is an ESTIMATE
/// for fleet cost-attribution, not a billing oracle; override per
/// deployment with [`RATE_ENV`].
pub const DEFAULT_MICRO_USD_PER_1K_TOKENS: u64 = 10_000;

/// Environment override for [`DEFAULT_MICRO_USD_PER_1K_TOKENS`]. Parsed as
/// a `u64`; an absent or unparseable value falls back to the default
/// (fail-safe — an advisory price must never hard-error).
pub const RATE_ENV: &str = "AI_MEMORY_COST_MICRO_USD_PER_1K_TOKENS";

/// The active micro-USD-per-1K-tokens rate: [`RATE_ENV`] if it parses,
/// else [`DEFAULT_MICRO_USD_PER_1K_TOKENS`]. Read at rollup time only
/// (never on the write/recall hot path), so this is not a hot-path cost.
#[must_use]
pub fn micro_usd_per_1k_tokens() -> u64 {
    std::env::var(RATE_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MICRO_USD_PER_1K_TOKENS)
}

/// Convert a token count to micro-USD using the active rate. Saturating
/// throughout (a trillion-agent fleet must never wrap a cost into a small
/// number — PERF-01/03): a negative input clamps to 0, the multiply
/// saturates at `u64::MAX`.
#[must_use]
pub fn micro_usd_for_tokens(tokens: i64) -> u64 {
    let t = u64::try_from(tokens.max(0)).unwrap_or(0);
    t.saturating_mul(micro_usd_per_1k_tokens()) / 1_000
}

/// Render micro-USD as a plain `"$D.CC"` string (integer math only — no
/// float ever touches a currency value). `50_000_000_000` micro-USD →
/// `"$50000.00"`.
#[must_use]
pub fn format_usd(micro_usd: u64) -> String {
    let dollars = micro_usd / 1_000_000;
    let cents = (micro_usd % 1_000_000) / 10_000;
    format!("${dollars}.{cents:02}")
}

/// Default lineage-DAG walk depth for [`lineage_rollup`]. Matches the
/// server-side lineage traversal ceiling (`storage::lineage_*`).
pub const DEFAULT_ROLLUP_DEPTH: usize = 5;

/// The SQLite integer ceiling, used to CLAMP an increment so a counter can
/// only ever SATURATE, never wrap (SQLite silently promotes an overflowing
/// `INTEGER + INTEGER` to a float — a corruption this table must not risk).
const I64_CEILING: i64 = i64::MAX;

/// A rolled-up counter row plus its derived cost. Exact integer token
/// counts; cost is computed on demand from [`micro_usd_for_tokens`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostRollup {
    /// [`SCOPE_NAMESPACE`] or [`SCOPE_LINEAGE`].
    pub scope_kind: String,
    /// The namespace, or the lineage root memory id.
    pub scope_key: String,
    /// Cumulative cl100k_base tokens authored under this scope.
    pub tokens_written: i64,
    /// Cumulative cl100k_base tokens served (recalled) under this scope.
    pub tokens_recalled: i64,
    /// Number of write events attributed to this scope.
    pub write_events: i64,
    /// Number of recall hits attributed to this scope.
    pub recall_events: i64,
}

impl CostRollup {
    /// Written + recalled tokens, saturating.
    #[must_use]
    pub fn tokens_total(&self) -> i64 {
        self.tokens_written.saturating_add(self.tokens_recalled)
    }

    /// Total cost in micro-USD (written + recalled tokens).
    #[must_use]
    pub fn micro_usd(&self) -> u64 {
        micro_usd_for_tokens(self.tokens_total())
    }

    /// Total cost rendered as `"$D.CC"`.
    #[must_use]
    pub fn usd_string(&self) -> String {
        format_usd(self.micro_usd())
    }
}

// ---------------------------------------------------------------------------
// SQLite increment funnels (best-effort — never fail the caller's write).
// ---------------------------------------------------------------------------

/// Upsert one scope's WRITE delta. `MIN(... , I64_CEILING)` makes the
/// counter saturate rather than overflow into a float.
const WRITE_UPSERT_SQL: &str = "INSERT INTO token_cost_counters \
    (scope_kind, scope_key, tokens_written, write_events, tokens_recalled, recall_events, updated_at) \
    VALUES (?1, ?2, ?3, ?4, 0, 0, ?5) \
    ON CONFLICT(scope_kind, scope_key) DO UPDATE SET \
        tokens_written = MIN(tokens_written + excluded.tokens_written, 9223372036854775807), \
        write_events   = MIN(write_events + excluded.write_events, 9223372036854775807), \
        updated_at     = excluded.updated_at";

/// Upsert one scope's RECALL delta.
const RECALL_UPSERT_SQL: &str = "INSERT INTO token_cost_counters \
    (scope_kind, scope_key, tokens_written, write_events, tokens_recalled, recall_events, updated_at) \
    VALUES (?1, ?2, 0, 0, ?3, ?4, ?5) \
    ON CONFLICT(scope_kind, scope_key) DO UPDATE SET \
        tokens_recalled = MIN(tokens_recalled + excluded.tokens_recalled, 9223372036854775807), \
        recall_events   = MIN(recall_events + excluded.recall_events, 9223372036854775807), \
        updated_at      = excluded.updated_at";

/// Best-effort: attribute a single LOCAL-authorship write to its namespace
/// and its own lineage node. A failure (e.g. a partial-schema fixture with
/// no counter table) is logged at debug and swallowed — advisory metering
/// must never fail a durable write (North Star). Runs on the caller's
/// write connection, so it commits atomically with the insert's tx.
pub fn record_write_sqlite(conn: &Connection, mem: &Memory, memory_id: &str) {
    if let Err(e) = try_record_write(conn, mem, memory_id) {
        tracing::debug!(target: "cost", "token/cost write metering skipped (non-fatal): {e}");
    }
}

fn try_record_write(conn: &Connection, mem: &Memory, memory_id: &str) -> rusqlite::Result<()> {
    let tokens = clamp_tokens(crate::storage::count_memory_tokens(mem));
    let now = now_rfc3339();
    let mut stmt = conn.prepare_cached(WRITE_UPSERT_SQL)?;
    stmt.execute(params![SCOPE_NAMESPACE, mem.namespace, tokens, 1_i64, now])?;
    stmt.execute(params![SCOPE_LINEAGE, memory_id, tokens, 1_i64, now])?;
    Ok(())
}

/// Best-effort: attribute a served recall set to each result's namespace
/// and lineage node. Deltas are AGGREGATED per scope in-process so a
/// 50-result recall spanning one namespace pays one namespace upsert, not
/// fifty. A failure is logged at debug and swallowed.
pub fn record_recall_sqlite(conn: &Connection, results: &[(Memory, f64)]) {
    if results.is_empty() {
        return;
    }
    if let Err(e) = try_record_recall(conn, results) {
        tracing::debug!(target: "cost", "token/cost recall metering skipped (non-fatal): {e}");
    }
}

fn try_record_recall(conn: &Connection, results: &[(Memory, f64)]) -> rusqlite::Result<()> {
    // (scope_kind, scope_key) -> (tokens, events)
    let mut agg: std::collections::BTreeMap<(&str, &str), (i64, i64)> =
        std::collections::BTreeMap::new();
    for (mem, _score) in results {
        let tokens = clamp_tokens(crate::storage::count_memory_tokens(mem));
        accumulate(&mut agg, SCOPE_NAMESPACE, &mem.namespace, tokens);
        accumulate(&mut agg, SCOPE_LINEAGE, &mem.id, tokens);
    }
    let now = now_rfc3339();
    let mut stmt = conn.prepare_cached(RECALL_UPSERT_SQL)?;
    for ((kind, key), (tokens, events)) in agg {
        stmt.execute(params![kind, key, tokens, events, now])?;
    }
    Ok(())
}

fn accumulate<'a>(
    agg: &mut std::collections::BTreeMap<(&'a str, &'a str), (i64, i64)>,
    kind: &'a str,
    key: &'a str,
    tokens: i64,
) {
    let entry = agg.entry((kind, key)).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(tokens);
    entry.1 = entry.1.saturating_add(1);
}

// ---------------------------------------------------------------------------
// SQLite rollup queries (report path — cost model applied here).
// ---------------------------------------------------------------------------

/// The per-namespace rollup for one namespace, or `None` if the namespace
/// has never been metered.
///
/// # Errors
///
/// Propagates any `rusqlite` error (e.g. the counter table is absent).
pub fn namespace_rollup(
    conn: &Connection,
    namespace: &str,
) -> rusqlite::Result<Option<CostRollup>> {
    conn.query_row(
        "SELECT scope_key, tokens_written, tokens_recalled, write_events, recall_events \
         FROM token_cost_counters WHERE scope_kind = ?1 AND scope_key = ?2",
        params![SCOPE_NAMESPACE, namespace],
        |row| {
            Ok(CostRollup {
                scope_kind: SCOPE_NAMESPACE.to_string(),
                scope_key: row.get(0)?,
                tokens_written: row.get(1)?,
                tokens_recalled: row.get(2)?,
                write_events: row.get(3)?,
                recall_events: row.get(4)?,
            })
        },
    )
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        other => Err(other),
    })
}

/// Every per-namespace rollup, most-expensive first. The fleet-wide "where
/// is the money going" report.
///
/// # Errors
///
/// Propagates any `rusqlite` error.
pub fn all_namespace_rollups(conn: &Connection) -> rusqlite::Result<Vec<CostRollup>> {
    let mut stmt = conn.prepare(
        "SELECT scope_key, tokens_written, tokens_recalled, write_events, recall_events \
         FROM token_cost_counters WHERE scope_kind = ?1 \
         ORDER BY (tokens_written + tokens_recalled) DESC, scope_key ASC",
    )?;
    let rows = stmt.query_map(params![SCOPE_NAMESPACE], |row| {
        Ok(CostRollup {
            scope_kind: SCOPE_NAMESPACE.to_string(),
            scope_key: row.get(0)?,
            tokens_written: row.get(1)?,
            tokens_recalled: row.get(2)?,
            write_events: row.get(3)?,
            recall_events: row.get(4)?,
        })
    })?;
    rows.collect()
}

/// The per-lineage-ROOT rollup: the summed token/cost of `root_id` plus
/// every memory reachable from it through the `derives_from` provenance
/// DAG (up to `max_depth` hops). This is where a runaway cascade shows its
/// dollar figure — the root and all its spawned atoms/reflections summed
/// into one number.
///
/// The returned [`CostRollup`] always carries `scope_kind =`
/// [`SCOPE_LINEAGE`] and `scope_key = root_id`, even when no node under the
/// root has been metered (all-zero rollup).
///
/// # Errors
///
/// Propagates lineage-traversal errors from `storage::lineage_descendants`
/// and any `rusqlite` error from the counter read.
pub fn lineage_rollup(
    conn: &Connection,
    root_id: &str,
    max_depth: usize,
) -> anyhow::Result<CostRollup> {
    // Distinct node set: the root plus its provenance descendants. A DAG
    // can reach a node by multiple paths, so dedupe to never double-count.
    let mut ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    ids.insert(root_id.to_string());
    for node in crate::storage::lineage_descendants(conn, root_id, max_depth)? {
        ids.insert(node.id);
    }

    let mut rollup = CostRollup {
        scope_kind: SCOPE_LINEAGE.to_string(),
        scope_key: root_id.to_string(),
        tokens_written: 0,
        tokens_recalled: 0,
        write_events: 0,
        recall_events: 0,
    };

    // One `IN (?, ?, ...)` aggregate over the node set. `SUM` is NULL over
    // an empty match, so `COALESCE` to 0.
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT COALESCE(SUM(tokens_written), 0), COALESCE(SUM(tokens_recalled), 0), \
                COALESCE(SUM(write_events), 0), COALESCE(SUM(recall_events), 0) \
         FROM token_cost_counters \
         WHERE scope_kind = '{SCOPE_LINEAGE}' AND scope_key IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let (w, r, we, re): (i64, i64, i64, i64) = stmt
        .query_row(params_from_iter(ids.iter()), |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
    rollup.tokens_written = w;
    rollup.tokens_recalled = r;
    rollup.write_events = we;
    rollup.recall_events = re;
    Ok(rollup)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Clamp a `usize` token count into the non-negative `i64` domain the
/// counter columns hold (saturating — a value past `i64::MAX` is
/// astronomically impossible for one memory, but never wrap).
fn clamp_tokens(tokens: usize) -> i64 {
    i64::try_from(tokens).unwrap_or(I64_CEILING)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(feature = "sal-postgres")]
pub mod postgres;

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests exercise the counter table + cost model in isolation
    // (only `token_cost_counters` created). The lineage-DAG rollup, which
    // walks `memory_links`, is covered end-to-end in
    // tests/cost_accounting_3323.rs against a fully bootstrapped database.
    fn open() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(MIGRATION_V93_SQLITE)
            .expect("create counter table");
        conn
    }

    fn mem(id: &str, ns: &str, content: &str) -> Memory {
        Memory {
            id: id.to_string(),
            namespace: ns.to_string(),
            content: content.to_string(),
            ..Memory::default()
        }
    }

    // Direct read of a single lineage-NODE counter row (no DAG walk), so
    // the unit tests can assert the node accrual without `memory_links`.
    fn node_written(conn: &Connection, id: &str) -> i64 {
        conn.query_row(
            "SELECT tokens_written FROM token_cost_counters \
             WHERE scope_kind = ?1 AND scope_key = ?2",
            params![SCOPE_LINEAGE, id],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    #[test]
    fn cost_model_is_integer_exact() {
        // Default rate: $10 / 1M tokens => 1M tokens == $10.00.
        assert_eq!(micro_usd_for_tokens(1_000_000), 10_000_000);
        assert_eq!(format_usd(10_000_000), "$10.00");
        // The headline "$50k" figure round-trips.
        assert_eq!(format_usd(50_000_000_000), "$50000.00");
        // Negative clamps to zero, never panics or wraps.
        assert_eq!(micro_usd_for_tokens(-5), 0);
    }

    #[test]
    fn cost_model_saturates_never_wraps() {
        // A pathological token count must saturate, not wrap to a small
        // (wrong) number.
        assert_eq!(micro_usd_for_tokens(i64::MAX), u64::MAX / 1_000);
    }

    #[test]
    fn write_increments_namespace_and_lineage_node() {
        let conn = open();
        let m = mem("id-1", "team-a", "hello world this is content");
        let tokens = clamp_tokens(crate::storage::count_memory_tokens(&m));
        assert!(tokens > 0);
        record_write_sqlite(&conn, &m, "id-1");

        let ns = namespace_rollup(&conn, "team-a").unwrap().unwrap();
        assert_eq!(ns.tokens_written, tokens);
        assert_eq!(ns.write_events, 1);
        assert_eq!(ns.tokens_recalled, 0);

        // The lineage node accrues its own tokens (self-rooted at write).
        assert_eq!(node_written(&conn, "id-1"), tokens);
    }

    #[test]
    fn repeated_writes_accumulate_exactly() {
        let conn = open();
        let m = mem("id-1", "team-a", "content body here");
        let tokens = clamp_tokens(crate::storage::count_memory_tokens(&m));
        for _ in 0..100 {
            record_write_sqlite(&conn, &m, "id-1");
        }
        let ns = namespace_rollup(&conn, "team-a").unwrap().unwrap();
        assert_eq!(ns.write_events, 100);
        assert_eq!(ns.tokens_written, tokens.saturating_mul(100));
    }

    #[test]
    fn recall_aggregates_per_scope() {
        let conn = open();
        let a = mem("a", "team-a", "alpha content");
        let b = mem("b", "team-a", "bravo content longer text");
        let ta = clamp_tokens(crate::storage::count_memory_tokens(&a));
        let tb = clamp_tokens(crate::storage::count_memory_tokens(&b));
        record_recall_sqlite(&conn, &[(a, 0.9), (b, 0.8)]);

        let ns = namespace_rollup(&conn, "team-a").unwrap().unwrap();
        // Two results, one namespace: one aggregated row, two events.
        assert_eq!(ns.recall_events, 2);
        assert_eq!(ns.tokens_recalled, ta.saturating_add(tb));
        assert_eq!(ns.tokens_written, 0);
    }

    #[test]
    fn all_namespace_rollups_orders_by_spend() {
        let conn = open();
        record_write_sqlite(&conn, &mem("s", "small", "hi"), "s");
        for _ in 0..50 {
            record_write_sqlite(&conn, &mem("b", "big", "a much longer content body"), "b");
        }
        let rollups = all_namespace_rollups(&conn).unwrap();
        assert_eq!(rollups.len(), 2);
        // Most-expensive namespace first.
        assert_eq!(rollups[0].scope_key, "big");
        assert!(rollups[0].tokens_written > rollups[1].tokens_written);
    }

    #[test]
    fn negative_counter_is_rejected_by_check() {
        // The CHECK constraints keep an out-of-band writer from planting a
        // negative counter (advisory data-integrity floor).
        let conn = open();
        let bad = conn.execute(
            "INSERT INTO token_cost_counters \
             (scope_kind, scope_key, tokens_written, updated_at) VALUES (?1, ?2, -1, 'now')",
            params![SCOPE_NAMESPACE, "x"],
        );
        assert!(
            bad.is_err(),
            "negative tokens_written must violate the CHECK"
        );
        // And an unknown scope kind is rejected too.
        let bad_kind = conn.execute(
            "INSERT INTO token_cost_counters \
             (scope_kind, scope_key, updated_at) VALUES ('bogus', 'x', 'now')",
            [],
        );
        assert!(
            bad_kind.is_err(),
            "unknown scope_kind must violate the CHECK"
        );
    }

    #[test]
    fn best_effort_never_panics_without_table() {
        // A connection with NO counter table must silently no-op, never
        // panic — advisory metering can never break a write.
        let conn = Connection::open_in_memory().unwrap();
        let m = mem("id-1", "team-a", "content");
        record_write_sqlite(&conn, &m, "id-1");
        record_recall_sqlite(&conn, &[(m, 0.5)]);
    }
}
