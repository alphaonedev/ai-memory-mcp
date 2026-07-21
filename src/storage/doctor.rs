// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Doctor / observability probes over the sqlite substrate: governance-rule
//! and subscription counts, pending-action timeout sweep, capability-expansion
//! ledger, and the `ai-memory doctor` reflection/sync/dim probes.
//!
//! Extracted verbatim from `storage/mod.rs` (#1802 R-05, S1); behavior-identical.
//! Every public item is re-exported at `crate::storage::*` (and therefore
//! `crate::db::*`) via the itemized shim in `storage/mod.rs`, so no caller
//! path changes.

use anyhow::Result;
use chrono::Utc;
use rusqlite::{Connection, params};

use std::collections::HashMap;

use crate::models::GovernancePolicy;

/// Check if a memory ID is a namespace standard (used by consolidate to warn).
pub fn is_namespace_standard(conn: &Connection, id: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM namespace_meta WHERE standard_id = ?1",
        params![id],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0)
        > 0
}

/// v0.6.3 (capabilities schema v2): count namespace standards whose
/// `metadata.governance` is non-null. A "rule" here means a namespace
/// has an explicit governance policy attached to its standard memory.
/// The count is a transparent passthrough — the full permission system
/// arrives in v0.7 (arch-enhancement-spec §3).
pub fn count_active_governance_rules(conn: &Connection) -> Result<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories m
             INNER JOIN namespace_meta nm ON nm.standard_id = m.id
             WHERE json_extract(m.metadata, '$.governance') IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(usize::try_from(count.max(0)).unwrap_or(0))
}

/// v0.7.0 K5 — enumerate every namespace whose standard memory carries an
/// explicit `metadata.governance` policy and return `(namespace, policy)`
/// pairs sorted lexicographically by namespace.
///
/// Companion to [`count_active_governance_rules`] (which returns just the
/// count). Powers the `permissions.rule_summary` field surfaced by
/// capabilities v3 — the K5 increment closes the v0.6.3.1 honesty
/// disclosure that the field was previously dropped from the wire because
/// no per-rule serializer existed.
///
/// Rows whose `metadata.governance` payload fails to round-trip through
/// `GovernancePolicy::from_metadata` are silently skipped — the
/// capabilities surface is best-effort and a malformed policy must not
/// take down the entire response. The wider gate
/// (`enforce_governance` → `read_namespace_policy`) already swallows the
/// same parse failures, so the surfaces stay consistent.
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures (e.g. table missing); the
/// row-level parse failures noted above are handled internally.
pub fn list_active_governance_policies(
    conn: &Connection,
) -> Result<Vec<(String, GovernancePolicy)>> {
    // Pull the raw `(namespace, metadata)` tuples for every namespace
    // whose standard memory has a non-null `metadata.governance`. We
    // ORDER BY at the SQL layer so the lex sort comes free and the
    // caller doesn't have to re-sort.
    let mut stmt = conn.prepare(
        "SELECT nm.namespace, m.metadata
         FROM namespace_meta nm
         INNER JOIN memories m ON m.id = nm.standard_id
         WHERE json_extract(m.metadata, '$.governance') IS NOT NULL
         ORDER BY nm.namespace ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let ns: String = r.get(0)?;
        let meta_str: String = r.get(1)?;
        Ok((ns, meta_str))
    })?;

    let mut out = Vec::new();
    for row in rows.flatten() {
        let (ns, meta_str) = row;
        // Parse the metadata blob; skip rows that don't deserialize.
        let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_str) else {
            continue;
        };
        // `from_metadata` returns `None` when the field is missing/null
        // (the SQL filter already excludes that path) and
        // `Some(Err(_))` on a malformed policy payload — skip both.
        match GovernancePolicy::from_metadata(&meta) {
            Some(Ok(policy)) => out.push((ns, policy)),
            _ => continue,
        }
    }
    Ok(out)
}

/// v0.6.3 (capabilities schema v2): count rows in the `subscriptions`
/// table. Used by `handle_capabilities` as a proxy for "registered
/// hooks" — the hook pipeline itself is v0.7 Bucket 0 work.
pub fn count_subscriptions(conn: &Connection) -> Result<usize> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM subscriptions", [], |r| r.get(0))
        .unwrap_or(0);
    Ok(usize::try_from(count.max(0)).unwrap_or(0))
}

/// v0.6.3 (capabilities schema v2): count `pending_actions` rows whose
/// `status` matches the predicate. Used by `handle_capabilities` to
/// surface live approval queue depth.
pub fn count_pending_actions_by_status(conn: &Connection, status: &str) -> Result<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_actions WHERE status = ?1",
            params![status],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(usize::try_from(count.max(0)).unwrap_or(0))
}

/// v0.7.0 K2 — pending_actions timeout sweeper.
///
/// Scans `pending_actions` for `status='pending'` rows whose age exceeds
/// the per-row `default_timeout_seconds` (or `global_default_secs` when
/// the per-row column is NULL). Transitions matching rows to
/// `status='expired'` and stamps `expired_at = now`.
///
/// Returns the list of `(id, namespace)` tuples that were just expired
/// so the caller can fan out approval-decision events. Empty queue is a
/// silent no-op.
///
/// Closes the v0.6.3.1 honest-Capabilities-v2 disclosure that
/// `default_timeout_seconds` was previously advertised but unused (the
/// v2 honesty patch had dropped it from the wire shape; K2 ships the
/// backing sweeper so the field is meaningful again).
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures (e.g. table missing).
pub fn sweep_pending_action_timeouts(
    conn: &Connection,
    global_default_secs: i64,
) -> Result<Vec<(String, String)>> {
    // Step 1 — find candidates. We compute age in SQL via julianday()
    // arithmetic so the sweep is index-friendly and avoids parsing
    // every `requested_at` row in Rust. The composite index
    // `idx_pending_status_requested` (added in migration v21) keeps
    // the planner from full-scanning the table.
    //
    // The `default_timeout_seconds` column is nullable; rows with NULL
    // fall back to `global_default_secs`. A non-positive global default
    // disables the sweeper entirely (operator escape hatch).
    if global_default_secs <= 0 {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, namespace FROM pending_actions
         WHERE status = 'pending'
           AND (julianday('now') - julianday(requested_at)) * 86400.0
               > COALESCE(default_timeout_seconds, ?1)",
    )?;
    let rows: Vec<(String, String)> = stmt
        .query_map(params![global_default_secs], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2 — flip status='expired' + stamp expired_at. We update
    // row-by-row inside a single transaction so a failure mid-batch
    // rolls back cleanly. The WHERE clause re-checks status='pending'
    // so a concurrent decide_pending_action wins (its decision is
    // not overwritten).
    let now = Utc::now().to_rfc3339();
    let tx_savepoint = conn.unchecked_transaction()?;
    {
        let mut update = tx_savepoint.prepare(
            "UPDATE pending_actions
             SET status = 'expired', expired_at = ?1
             WHERE id = ?2 AND status = 'pending'",
        )?;
        for (id, _) in &rows {
            update.execute(params![now, id])?;
        }
    }
    tx_savepoint.commit()?;
    // v0.7.0 S5-M2 — emit a `pending_action.timed_out` audit row per
    // expired pending row so the audit chain captures the timeout
    // transition alongside approve / deny. Best-effort: a missing
    // pending row or audit failure is logged at WARN; the sweep
    // itself has already committed.
    for (id, _) in &rows {
        if let Ok(Some(pa)) = super::get_pending_action(conn, id) {
            super::emit_pending_action_event(conn, &pa, "pending_action.timed_out", None);
        }
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// `ai-memory doctor` (P7 / R7) — query helpers.
// ---------------------------------------------------------------------------
//
// These read-only helpers back the `ai-memory doctor` CLI subcommand. Each
// query is a single indexed `COUNT(*)` (or close to it) so the reporter can
// run an entire health pass without holding the DB lock long enough to
// block live writers.
//
// Surfaces consumed:
// - `count_dim_violations` reads the post-P2 `embedding_dim` column when
//   present and gracefully reports `Ok(None)` on pre-P2 schemas (the column
//   doesn't exist yet on `release/v0.6.3`).
// - `count_index_evictions` reads the post-P3 `index_evictions_total` global
//   counter when wired (there is no schema-level surface today; it returns
//   `Ok(None)` so the doctor can render a "not yet observed" line).
// - `count_oldest_pending_action_age_secs` is portable today and reports the
//   age of the oldest `pending` row in seconds.
// - `count_governance_chain_depth` walks `parent_namespace` for each
//   namespace_meta row to estimate the inheritance depth distribution
//   the P4 enforcer will eventually consume.

/// Count rows whose `embedding_dim` (post-P2) does not match the modal
/// dim within their namespace. On pre-P2 schemas the `embedding_dim`
/// column doesn't exist; the function returns `Ok(None)` so the doctor
/// can render "not yet observed (pre-P2 schema)".
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures — a missing column is
/// reported as `Ok(None)`, not an error.
pub fn doctor_dim_violations(conn: &Connection) -> Result<Option<usize>> {
    let has_dim = conn
        .prepare("SELECT embedding_dim FROM memories LIMIT 0")
        .is_ok();
    if !has_dim {
        return Ok(None);
    }
    // For each namespace, find the modal dim (most-frequent non-null value)
    // and count rows whose dim differs from it. Rows with NULL dim but a
    // non-empty embedding count as violations too — they are mid-migration.
    let n: i64 = conn
        .query_row(
            "WITH per_ns_modes AS (
                 SELECT namespace, embedding_dim, COUNT(*) AS c
                 FROM memories
                 WHERE embedding IS NOT NULL AND embedding_dim IS NOT NULL
                 GROUP BY namespace, embedding_dim
             ),
             ranked AS (
                 SELECT namespace, embedding_dim,
                        ROW_NUMBER() OVER (PARTITION BY namespace ORDER BY c DESC) AS rn
                 FROM per_ns_modes
             ),
             modes AS (
                 SELECT namespace, embedding_dim AS modal_dim
                 FROM ranked WHERE rn = 1
             )
             SELECT COUNT(*)
             FROM memories m
             LEFT JOIN modes mo ON mo.namespace = m.namespace
             WHERE m.embedding IS NOT NULL
               AND (m.embedding_dim IS NULL
                    OR (mo.modal_dim IS NOT NULL AND m.embedding_dim != mo.modal_dim))",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(Some(usize::try_from(n.max(0)).unwrap_or(0)))
}

/// Age in seconds of the oldest `pending` row in `pending_actions`, or
/// `None` if the queue is empty (or the column is unparseable). The
/// doctor uses this to flag a backlog older than 24h as critical.
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures (e.g. missing table).
pub fn doctor_oldest_pending_age_secs(conn: &Connection) -> Result<Option<i64>> {
    let row: Option<String> = conn
        .query_row(
            "SELECT requested_at FROM pending_actions WHERE status = 'pending'
             ORDER BY requested_at ASC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok();
    let Some(ts) = row else {
        return Ok(None);
    };
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&ts) else {
        return Ok(None);
    };
    // M11 (v0.7.0 round-2) — clamp negative ages to 0. `requested_at`
    // is stamped by the writer's clock; on a host with skewed time
    // (NTP slewing back, intentional misconfiguration, or VM time
    // travel) `now - parsed` can land negative and downstream
    // consumers (the doctor surface treats this as "age in seconds")
    // would surface a nonsensical figure. The WARN gives operators
    // the signal so they can investigate the clock drift instead of
    // chasing a phantom backlog.
    let raw_age = (Utc::now() - parsed.with_timezone(&Utc)).num_seconds();
    let age = if raw_age < 0 {
        tracing::warn!(
            requested_at = %ts,
            raw_age_seconds = raw_age,
            "pending_actions row has future timestamp; clamping age to 0"
        );
        0
    } else {
        raw_age
    };
    Ok(Some(age))
}

/// Count of namespaces that have a standard registered with a non-null
/// `metadata.governance` block, and the count without (just a standard
/// memory but no policy attached).
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures.
pub fn doctor_governance_coverage(conn: &Connection) -> Result<(usize, usize)> {
    let with_policy: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories m
             INNER JOIN namespace_meta nm ON nm.standard_id = m.id
             WHERE json_extract(m.metadata, '$.governance') IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let total_meta: i64 = conn
        .query_row("SELECT COUNT(*) FROM namespace_meta", [], |r| r.get(0))
        .unwrap_or(0);
    let with = usize::try_from(with_policy.max(0)).unwrap_or(0);
    let total = usize::try_from(total_meta.max(0)).unwrap_or(0);
    Ok((with, total.saturating_sub(with)))
}

/// Distribution of the `parent_namespace` chain depth across
/// `namespace_meta` rows. Returns a Vec where index `i` is the count of
/// namespaces with chain depth `i` (depth 0 = no parent).
///
/// Walks each row's `parent_namespace` chain up to a hard cap of 16 to
/// avoid runaway loops on malformed data. Rows whose chain exceeds the
/// cap are bucketed at the cap.
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures.
pub fn doctor_governance_depth_distribution(conn: &Connection) -> Result<Vec<usize>> {
    const MAX_DEPTH: usize = 16;
    let mut stmt = conn.prepare("SELECT namespace, parent_namespace FROM namespace_meta")?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
    })?;
    let parent_map: HashMap<String, Option<String>> = rows
        .filter_map(rusqlite::Result::ok)
        .collect::<HashMap<_, _>>();
    let mut hist = vec![0_usize; MAX_DEPTH + 1];
    for ns in parent_map.keys() {
        let mut depth = 0_usize;
        let mut cur = parent_map.get(ns).cloned().flatten();
        while let Some(p) = cur {
            depth += 1;
            if depth >= MAX_DEPTH {
                break;
            }
            cur = parent_map.get(&p).cloned().flatten();
        }
        let bucket = depth.min(MAX_DEPTH);
        hist[bucket] += 1;
    }
    Ok(hist)
}

/// Sum of `subscriptions.dispatch_count` and `subscriptions.failure_count`
/// across all rows. Returns `(dispatched, failed)`. Used by the doctor to
/// estimate webhook delivery success rate.
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures.
pub fn doctor_webhook_delivery_totals(conn: &Connection) -> Result<(u64, u64)> {
    let dispatched: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(dispatch_count), 0) FROM subscriptions",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let failed: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(failure_count), 0) FROM subscriptions",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok((
        u64::try_from(dispatched.max(0)).unwrap_or(0),
        u64::try_from(failed.max(0)).unwrap_or(0),
    ))
}

/// Maximum sync-clock skew in seconds across the `sync_state` table —
/// the largest gap between `last_pulled_at` (when this peer last heard
/// from a peer) and `last_seen_at` (the peer's own `updated_at` advance).
/// Returns `Ok(None)` when `sync_state` is empty or the columns are
/// missing on a pre-T3 schema.
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures.
// ---------------------------------------------------------------------
// v0.6.4-009 — capability-expansion audit log
// ---------------------------------------------------------------------

/// Single audit_log row (capability-expansion shape — extensible).
#[derive(Debug, Clone)]
pub struct CapabilityExpansionRow {
    pub id: String,
    pub agent_id: Option<String>,
    pub event_type: String,
    pub requested_family: Option<String>,
    pub granted: bool,
    pub attestation_tier: Option<String>,
    pub timestamp: String,
}

/// Record a capability-expansion attempt. Used by
/// `handle_capabilities_family` after the allowlist decision is made.
/// Records BOTH grant and deny outcomes so operators can see attempted
/// access patterns even when the gate refused.
///
/// `granted=true` means the agent received the schemas; `granted=false`
/// means the agent was denied or the family was unknown.
///
/// Best-effort: a failed insert (e.g., disk full) is logged via tracing
/// but does not propagate the error to the caller — the audit trail
/// must never block the actual call.
pub fn record_capability_expansion(
    conn: &Connection,
    agent_id: Option<&str>,
    family: &str,
    granted: bool,
    attestation_tier: Option<&str>,
) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let result = conn.execute(
        "INSERT INTO audit_log (id, agent_id, event_type, requested_family, \
         granted, attestation_tier, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            id,
            agent_id,
            "capability_expansion",
            family,
            i32::from(granted),
            attestation_tier,
            now,
        ],
    );
    if let Err(e) = result {
        tracing::warn!(
            "audit_log insert failed (capability_expansion / agent={:?} / family={}): {e}",
            agent_id,
            family,
        );
    }
}

/// List recent capability-expansion rows, newest first. `limit` clamps
/// the row count.
pub fn list_capability_expansions(
    conn: &Connection,
    limit: usize,
    agent_filter: Option<&str>,
) -> Result<Vec<CapabilityExpansionRow>> {
    let n = (limit.min(10_000)) as i64;
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<CapabilityExpansionRow> {
        Ok(CapabilityExpansionRow {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            event_type: r.get(2)?,
            requested_family: r.get(3)?,
            granted: r.get::<_, i64>(4)? != 0,
            attestation_tier: r.get(5)?,
            timestamp: r.get(6)?,
        })
    };
    if let Some(a) = agent_filter {
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, event_type, requested_family, granted, \
             attestation_tier, timestamp FROM audit_log \
             WHERE event_type = 'capability_expansion' AND agent_id = ?1 \
             ORDER BY timestamp DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![a, n], map_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, event_type, requested_family, granted, \
             attestation_tier, timestamp FROM audit_log \
             WHERE event_type = 'capability_expansion' \
             ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![n], map_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

pub fn doctor_max_sync_skew_secs(conn: &Connection) -> Result<Option<i64>> {
    let mut stmt = match conn.prepare(
        "SELECT last_seen_at, last_pulled_at FROM sync_state WHERE last_pulled_at IS NOT NULL",
    ) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut max_skew: Option<i64> = None;
    for row in rows {
        let Ok((seen, pulled)) = row else { continue };
        let Ok(s) = chrono::DateTime::parse_from_rfc3339(&seen) else {
            continue;
        };
        let Ok(p) = chrono::DateTime::parse_from_rfc3339(&pulled) else {
            continue;
        };
        let skew = (s.with_timezone(&Utc) - p.with_timezone(&Utc))
            .num_seconds()
            .abs();
        max_skew = Some(max_skew.map_or(skew, |m| m.max(skew)));
    }
    Ok(max_skew)
}

// ---------------------------------------------------------------------------
// L1-4 — Reflection-depth telemetry for `ai-memory doctor`.
// ---------------------------------------------------------------------------

/// One namespace's reflection-depth distribution row returned by
/// [`doctor_reflection_depth_distribution`].
///
/// The four depth buckets mirror the default `max_reflection_depth=3`
/// cap: depth 0 (direct memories), depth 1, depth 2, depth 3+. Depth
/// 3+ is collapsed into a single counter because depths beyond the cap
/// are impossible to store under standard policy; the bucket exists so
/// future schemas with raised caps still produce a non-zero column.
pub struct ReflectionDepthRow {
    pub namespace: String,
    pub depth0: i64,
    pub depth1: i64,
    pub depth2: i64,
    pub depth3_plus: i64,
    pub avg_depth: f64,
    pub max_depth: i64,
    pub total: i64,
}

/// Depth distribution across all namespaces that hold at least one
/// memory with `reflection_depth > 0`, plus the `_global_` aggregate.
///
/// Uses a single GROUP BY pass so the query is a single indexed scan
/// over `memories.reflection_depth`. A fresh DB (all rows at depth 0)
/// returns an empty `Vec` — the caller (doctor) renders that as
/// "no reflections observed".
///
/// # Errors
///
/// Returns `Err` only on hard SQLite failures (e.g. the `memories`
/// table does not exist yet — pre-migration schemas).
pub fn doctor_reflection_depth_distribution(conn: &Connection) -> Result<Vec<ReflectionDepthRow>> {
    // Aggregate per namespace, only namespaces that contain at least
    // one reflected memory (depth > 0). The doctor renders a global
    // summary from the returned rows; the SQL avoids a second pass by
    // letting the caller roll up the namespace rows.
    let mut stmt = conn.prepare(
        "SELECT
             namespace,
             SUM(CASE WHEN reflection_depth = 0 THEN 1 ELSE 0 END),
             SUM(CASE WHEN reflection_depth = 1 THEN 1 ELSE 0 END),
             SUM(CASE WHEN reflection_depth = 2 THEN 1 ELSE 0 END),
             SUM(CASE WHEN reflection_depth >= 3 THEN 1 ELSE 0 END),
             AVG(CAST(reflection_depth AS REAL)),
             MAX(reflection_depth),
             COUNT(*)
         FROM memories
         GROUP BY namespace
         HAVING MAX(reflection_depth) > 0
         ORDER BY namespace",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ReflectionDepthRow {
            namespace: r.get(0)?,
            depth0: r.get(1)?,
            depth1: r.get(2)?,
            depth2: r.get(3)?,
            depth3_plus: r.get(4)?,
            avg_depth: r.get(5)?,
            max_depth: r.get(6)?,
            total: r.get(7)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Count of `reflection.depth_exceeded` audit events in `signed_events`
/// within a given look-back window.
///
/// `since_rfc3339` is an RFC 3339 timestamp; only events with
/// `timestamp >= since_rfc3339` are counted. Pass the epoch
/// (`"1970-01-01T00:00:00Z"`) to count all-time.
///
/// Returns `0` when the `signed_events` table does not exist (pre-H5
/// schemas) rather than propagating the error, matching the pattern
/// in other doctor helpers.
///
/// # Errors
///
/// Returns `Err` only on hard query failures (table exists but query
/// is malformed — should not happen in practice).
pub fn doctor_reflection_depth_exceeded_count(
    conn: &Connection,
    since_rfc3339: &str,
) -> Result<i64> {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events
             WHERE event_type = 'reflection.depth_exceeded'
               AND timestamp >= ?1",
            params![since_rfc3339],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(n)
}

/// Reflection totals per namespace: memories created in the last 24h,
/// 7d, and all-time that have `reflection_depth > 0`.
///
/// Returns one tuple `(ns, last_24h, last_7d, all_time)` per
/// namespace that has at least one reflected memory. Namespaces with
/// no reflections are omitted; the caller renders "no reflections" for
/// the global summary.
///
/// # Errors
///
/// Returns `Err` on hard SQLite failures.
pub fn doctor_reflection_totals_by_namespace(
    conn: &Connection,
) -> Result<Vec<(String, i64, i64, i64)>> {
    let now = Utc::now();
    let last_day_cutoff = (now - chrono::Duration::hours(24)).to_rfc3339();
    let cutoff_7d = (now - chrono::Duration::days(7)).to_rfc3339();

    let mut stmt = conn.prepare(
        "SELECT
             namespace,
             SUM(CASE WHEN created_at >= ?1 THEN 1 ELSE 0 END),
             SUM(CASE WHEN created_at >= ?2 THEN 1 ELSE 0 END),
             COUNT(*)
         FROM memories
         WHERE reflection_depth > 0
         GROUP BY namespace
         ORDER BY namespace",
    )?;
    let rows = stmt.query_map(params![last_day_cutoff, cutoff_7d], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}
