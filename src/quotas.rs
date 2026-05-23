// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Track K, Task K8 — per-agent + per-namespace rate limits +
//! storage caps.
//!
//! Each `(agent_id, namespace)` tuple gets a single row in the
//! `agent_quotas` table tracking three rolling-window counters
//! (memories written today, storage bytes consumed lifetime, links
//! written today) against three limits (`max_memories_per_day`,
//! `max_storage_bytes`, `max_links_per_day`). The `store_memory` +
//! `memory_link` write paths consult [`check_and_record`] before
//! committing; on exceeded limit the call returns a [`QuotaError`]
//! naming the limit that was hit, which the MCP layer maps to a
//! `QUOTA_EXCEEDED` diagnostic.
//!
//! Daily counters reset at UTC midnight via [`reset_daily`], driven by
//! the K8 sweep loop wired into `daemon_runtime::bootstrap_serve` —
//! same lifecycle shape as the K2 pending-actions sweeper and the I3
//! transcript-lifecycle sweeper.
//!
//! ## Per-namespace dimension (v0.7.0 #1156, schema v50)
//!
//! Pre-v50 the substrate keyed quota accounting on `agent_id` alone:
//! an agent that wrote generously in a personal scratch namespace
//! starved their writes against a shared namespace because the same
//! daily cap applied to both. v50 extends the PK to
//! `(agent_id, namespace)` so per-namespace allotments hold even when
//! a single agent operates across many namespaces. Operators carving
//! tight blast-radius limits on a single shared namespace no longer
//! need to lower the agent's overall cap.
//!
//! The sentinel namespace string `_global` (underscore prefix puts it
//! outside the validated namespace charset, so no caller-supplied
//! namespace can collide) carries forward every pre-v50 row's
//! accounting verbatim. Callers that do not have a per-namespace
//! context to pass (boundary layers, the daily-reset sweep, the
//! legacy aggregate view) use `_global` to land on the
//! historically-shaped row.
//!
//! ## NSA CSI MCP mapping
//!
//! This module backs **NSA recommendation (c)** "Implement strict
//! input validation and authorization checks" and **NSA concern (h)**
//! "Denial of service" by giving operators per-namespace blast-radius
//! controls on a compromised or misbehaving agent. Defense-in-depth
//! on top of the seven-layer DoS substrate documented in
//! `docs/compliance/nsa-csi-mcp-security-mapping.md`.
//!
//! Compiled defaults: 1000 memories/day, 100 MiB storage cap, 5000
//! links/day. Defaults are deliberately generous so the K8 substrate is
//! invisible to small-scale operations; tuning down is per-deployment.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

/// Sentinel namespace string used by the v50 backwards-compat path
/// and by every call site that lacks a per-namespace context.
///
/// The leading underscore visibly separates the sentinel from
/// user-supplied namespaces by convention; while
/// [`crate::validate::validate_namespace`] does not strictly reject
/// `_`-prefixed identifiers, the substrate convention is that
/// operators don't use them for user data.
///
/// Pre-v50 rows backfill to this namespace during the v50 schema
/// migration; the MCP tool / HTTP route boundary defaults to this
/// string when the caller omits the optional `namespace` argument.
pub const GLOBAL_NAMESPACE: &str = "_global";

/// Default daily memory store ceiling per (agent, namespace). Generous;
/// tune down per-deployment by overwriting the row's
/// `max_memories_per_day` after it auto-inserts on first use.
pub const DEFAULT_MAX_MEMORIES_PER_DAY: i64 = 1000;

/// Default lifetime storage cap per (agent, namespace) (100 MiB).
/// Counts the (title + content + metadata) byte length of every memory
/// the agent writes; not reset by the daily sweep.
pub const DEFAULT_MAX_STORAGE_BYTES: i64 = 100 * 1024 * 1024;

/// Default daily link creation ceiling per (agent, namespace). Same
/// shape as the memory ceiling; reset to 0 at UTC midnight.
pub const DEFAULT_MAX_LINKS_PER_DAY: i64 = 5000;

/// Which write operation to charge against the agent's quota.
///
/// Variants:
/// - [`QuotaOp::Memory`] — one memory store. Charges 1 against
///   `current_memories_today` and `bytes` against `current_storage_bytes`.
/// - [`QuotaOp::Link`] — one link create. Charges 1 against
///   `current_links_today`. Storage is unaffected (links are a single
///   row keyed on a 3-tuple, not user-supplied bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaOp {
    /// Storing one memory of `bytes` payload size. The byte count is
    /// the sum of (title + content + metadata) lengths — same shape the
    /// `current_storage_bytes` counter accumulates.
    Memory { bytes: i64 },
    /// Creating one link. Single-row insert; no storage delta.
    Link,
}

/// Which limit was hit. The MCP error string surfaces this name so a
/// caller can switch on it without parsing the human-readable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaLimit {
    /// `current_memories_today >= max_memories_per_day` after the
    /// pending op would post.
    MemoriesPerDay,
    /// `current_storage_bytes + op.bytes > max_storage_bytes`.
    StorageBytes,
    /// `current_links_today >= max_links_per_day` after the pending op
    /// would post.
    LinksPerDay,
}

impl QuotaLimit {
    /// Canonical lower-snake-case name for diagnostic strings + the
    /// MCP wire format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoriesPerDay => "memories_per_day",
            Self::StorageBytes => "storage_bytes",
            Self::LinksPerDay => "links_per_day",
        }
    }
}

/// Failure returned by [`check_quota`] when a write would push the
/// agent's counters past one of the three limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaError {
    /// Agent whose quota was exceeded.
    pub agent_id: String,
    /// Namespace whose quota was exceeded (v50; #1156). Pre-v50
    /// surfaces always reported `_global` here for byte-for-byte
    /// compatibility with the legacy single-PK accounting.
    pub namespace: String,
    /// Which limit was hit.
    pub limit: QuotaLimit,
    /// The current value of the counter the limit applies to.
    pub current: i64,
    /// The configured ceiling.
    pub max: i64,
}

impl std::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QUOTA_EXCEEDED: agent {} namespace {} hit {} (current={}, max={})",
            self.agent_id,
            self.namespace,
            self.limit.as_str(),
            self.current,
            self.max,
        )
    }
}

impl std::error::Error for QuotaError {}

/// Snapshot of one `(agent_id, namespace)` quota row, returned by
/// [`get_status`] and surfaced over the MCP `memory_quota_status`
/// tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaStatus {
    pub agent_id: String,
    /// Per-namespace dimension (v50, #1156). `_global` for callers
    /// that did not pass a namespace; otherwise the caller-supplied
    /// namespace string. The aggregate-view path
    /// ([`get_aggregate_status`]) reports `_global` here too because
    /// the rollup is keyed by `agent_id` alone.
    #[serde(default = "default_namespace")]
    pub namespace: String,
    pub max_memories_per_day: i64,
    pub max_storage_bytes: i64,
    pub max_links_per_day: i64,
    pub current_memories_today: i64,
    pub current_storage_bytes: i64,
    pub current_links_today: i64,
    pub day_started_at: String,
    pub created_at: String,
    pub updated_at: String,
}

fn default_namespace() -> String {
    GLOBAL_NAMESPACE.to_string()
}

/// Auto-insert a default quota row for an `(agent_id, namespace)`
/// tuple that doesn't have one yet, then return the row. Idempotent —
/// concurrent calls converge on a single row because
/// `(agent_id, namespace)` is the PRIMARY KEY.
fn ensure_row(conn: &Connection, agent_id: &str, namespace: &str) -> Result<QuotaStatus> {
    if let Some(row) = load_row(conn, agent_id, namespace)? {
        return Ok(row);
    }
    let now = chrono::Utc::now().to_rfc3339();
    let day = day_bucket(&now);
    conn.execute(
        "INSERT OR IGNORE INTO agent_quotas
         (agent_id, namespace,
          max_memories_per_day, max_storage_bytes, max_links_per_day,
          current_memories_today, current_storage_bytes, current_links_today,
          day_started_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 0, ?6, ?7, ?7)",
        params![
            agent_id,
            namespace,
            DEFAULT_MAX_MEMORIES_PER_DAY,
            DEFAULT_MAX_STORAGE_BYTES,
            DEFAULT_MAX_LINKS_PER_DAY,
            day,
            now,
        ],
    )
    .context("failed to insert default quota row")?;
    load_row(conn, agent_id, namespace)?
        .context("quota row missing immediately after insert (concurrent delete?)")
}

/// Load a quota row by `(agent_id, namespace)`, returning `None` if
/// the row does not exist. Pure read — does not insert defaults.
fn load_row(conn: &Connection, agent_id: &str, namespace: &str) -> Result<Option<QuotaStatus>> {
    conn.query_row(
        "SELECT agent_id, namespace,
                max_memories_per_day, max_storage_bytes, max_links_per_day,
                current_memories_today, current_storage_bytes, current_links_today,
                day_started_at, created_at, updated_at
         FROM agent_quotas
         WHERE agent_id = ?1 AND namespace = ?2",
        params![agent_id, namespace],
        |r| {
            Ok(QuotaStatus {
                agent_id: r.get(0)?,
                namespace: r.get(1)?,
                max_memories_per_day: r.get(2)?,
                max_storage_bytes: r.get(3)?,
                max_links_per_day: r.get(4)?,
                current_memories_today: r.get(5)?,
                current_storage_bytes: r.get(6)?,
                current_links_today: r.get(7)?,
                day_started_at: r.get(8)?,
                created_at: r.get(9)?,
                updated_at: r.get(10)?,
            })
        },
    )
    .optional()
    .context("failed to load agent quota row")
}

/// Return the YYYY-MM-DD bucket for an RFC3339 UTC timestamp. Used to
/// compare `day_started_at` against "today" without crossing into a
/// chrono date type — the SQL column is RFC3339 string-typed.
fn day_bucket(rfc3339: &str) -> String {
    rfc3339.get(..10).unwrap_or(rfc3339).to_string()
}

/// v0.7 K8 — pre-write quota check.
///
/// Auto-inserts the default row on first call for an `(agent_id,
/// namespace)` tuple. If the row's `day_started_at` rolled over since
/// the last write, the counters are zeroed inline (the sweeper is the
/// bulk path; this path keeps the per-write quota honest even if the
/// sweeper hasn't fired yet).
///
/// On a clean check, returns `Ok(())`. On a quota breach, returns
/// `Err(QuotaError)` naming the limit that was hit and the
/// counter/ceiling values at the moment of the check.
///
/// ## v0.7.0 #1156 — per-namespace dimension
///
/// `namespace` keys the per-namespace accounting row. Callers that
/// lack a per-namespace context (boundary layers, daily reset)
/// pass [`GLOBAL_NAMESPACE`].
///
/// # Errors
///
/// - [`QuotaError`] when one of the three limits would be exceeded by
///   the pending op.
/// - Wrapped SQL errors when the substrate read fails.
pub fn check_quota(
    conn: &Connection,
    agent_id: &str,
    namespace: &str,
    op: QuotaOp,
) -> std::result::Result<(), QuotaCheckError> {
    let row = ensure_row(conn, agent_id, namespace).map_err(QuotaCheckError::Sql)?;

    // Inline daily-bucket roll: if the stored bucket isn't today, treat
    // the daily counters as 0 for this check. The sweeper performs the
    // matching SQL UPDATE so a downstream `get_status` reports zeros
    // even if no further writes happen until midnight.
    let today = day_bucket(&chrono::Utc::now().to_rfc3339());
    let stored_day = day_bucket(&row.day_started_at);
    let (memories_today, links_today) = if stored_day == today {
        (row.current_memories_today, row.current_links_today)
    } else {
        (0, 0)
    };

    match op {
        QuotaOp::Memory { bytes } => {
            if memories_today + 1 > row.max_memories_per_day {
                return Err(QuotaCheckError::Quota(QuotaError {
                    agent_id: agent_id.to_string(),
                    namespace: namespace.to_string(),
                    limit: QuotaLimit::MemoriesPerDay,
                    current: memories_today,
                    max: row.max_memories_per_day,
                }));
            }
            if row.current_storage_bytes + bytes > row.max_storage_bytes {
                return Err(QuotaCheckError::Quota(QuotaError {
                    agent_id: agent_id.to_string(),
                    namespace: namespace.to_string(),
                    limit: QuotaLimit::StorageBytes,
                    current: row.current_storage_bytes,
                    max: row.max_storage_bytes,
                }));
            }
        }
        QuotaOp::Link => {
            if links_today + 1 > row.max_links_per_day {
                return Err(QuotaCheckError::Quota(QuotaError {
                    agent_id: agent_id.to_string(),
                    namespace: namespace.to_string(),
                    limit: QuotaLimit::LinksPerDay,
                    current: links_today,
                    max: row.max_links_per_day,
                }));
            }
        }
    }

    Ok(())
}

/// Wire-shape error for [`check_quota`] — separates the "the agent
/// hit the limit" case from "the substrate read failed" so callers can
/// surface the former as a `QUOTA_EXCEEDED` diagnostic and the latter
/// as a 500-class internal error.
#[derive(Debug)]
pub enum QuotaCheckError {
    /// The pending op would exceed one of the three limits.
    Quota(QuotaError),
    /// The substrate read failed (DB error, missing migration, etc.).
    Sql(anyhow::Error),
}

impl std::fmt::Display for QuotaCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quota(q) => std::fmt::Display::fmt(q, f),
            Self::Sql(e) => write!(f, "quota check substrate error: {e}"),
        }
    }
}

impl std::error::Error for QuotaCheckError {}

/// v0.7 K8 / H12 (#628 blocker) — atomic check + record. Combines the
/// quota check with the counter increment under a single
/// `BEGIN IMMEDIATE` SQLite transaction so concurrent writers cannot
/// each pass the check and then both increment the counter past the
/// cap. `BEGIN IMMEDIATE` acquires a `RESERVED` lock on the database
/// at the start of the transaction; SQLite serialises every other
/// would-be writer behind the lock until COMMIT/ROLLBACK, which is
/// the SQLite analogue of `SELECT ... FOR UPDATE` against the
/// `(agent_id, namespace)` `agent_quotas` row.
///
/// On a clean check + increment, returns `Ok(())`. On a quota breach,
/// returns `Err(QuotaError)` naming the limit that was hit and the
/// counter / ceiling values at the moment of the check; the
/// transaction is rolled back so no counter mutation persists.
///
/// ## v0.7.0 #1156 — per-namespace dimension
///
/// `namespace` keys the per-namespace accounting row. The K8 write
/// paths (`store_memory`, `memory_link`) supply the target memory's
/// namespace so per-namespace allotments hold even when one agent
/// writes across many namespaces.
///
/// # Errors
///
/// - [`QuotaCheckError::Quota`] when one of the three limits would be
///   exceeded by the pending op.
/// - [`QuotaCheckError::Sql`] when the substrate read or write fails.
pub fn check_and_record(
    conn: &Connection,
    agent_id: &str,
    namespace: &str,
    op: QuotaOp,
) -> std::result::Result<(), QuotaCheckError> {
    // Make sure the row exists OUTSIDE the immediate transaction;
    // `INSERT OR IGNORE` itself is atomic and contention-free.
    let _ = ensure_row(conn, agent_id, namespace).map_err(QuotaCheckError::Sql)?;

    // BEGIN IMMEDIATE — acquires a RESERVED lock immediately. This is
    // the SQLite shape of "SELECT ... FOR UPDATE": no other connection
    // can begin a write transaction until we COMMIT or ROLLBACK. The
    // window between SELECT and UPDATE inside the transaction is
    // therefore safe from another writer's UPDATE racing past us.
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| QuotaCheckError::Sql(anyhow::anyhow!("BEGIN IMMEDIATE failed: {e}")))?;

    let result: std::result::Result<(), QuotaCheckError> = (|| {
        let row = load_row(conn, agent_id, namespace)
            .map_err(QuotaCheckError::Sql)?
            .ok_or_else(|| {
                QuotaCheckError::Sql(anyhow::anyhow!(
                    "quota row vanished mid-transaction for agent {agent_id} namespace {namespace}"
                ))
            })?;

        // Inline daily-bucket roll: if the stored bucket isn't today,
        // the daily counters are treated as zero for the check AND
        // the UPDATE below resets them.
        let now = chrono::Utc::now().to_rfc3339();
        let today = day_bucket(&now);
        let stored_day = day_bucket(&row.day_started_at);
        let day_rolled = stored_day != today;
        let (memories_today, links_today) = if day_rolled {
            (0, 0)
        } else {
            (row.current_memories_today, row.current_links_today)
        };

        match op {
            QuotaOp::Memory { bytes } => {
                if memories_today + 1 > row.max_memories_per_day {
                    return Err(QuotaCheckError::Quota(QuotaError {
                        agent_id: agent_id.to_string(),
                        namespace: namespace.to_string(),
                        limit: QuotaLimit::MemoriesPerDay,
                        current: memories_today,
                        max: row.max_memories_per_day,
                    }));
                }
                if row.current_storage_bytes + bytes > row.max_storage_bytes {
                    return Err(QuotaCheckError::Quota(QuotaError {
                        agent_id: agent_id.to_string(),
                        namespace: namespace.to_string(),
                        limit: QuotaLimit::StorageBytes,
                        current: row.current_storage_bytes,
                        max: row.max_storage_bytes,
                    }));
                }
                if day_rolled {
                    conn.execute(
                        "UPDATE agent_quotas SET
                           current_memories_today = 1,
                           current_links_today = 0,
                           current_storage_bytes = current_storage_bytes + ?1,
                           day_started_at = ?2,
                           updated_at = ?2
                         WHERE agent_id = ?3 AND namespace = ?4",
                        params![bytes, now, agent_id, namespace],
                    )
                    .map_err(|e| QuotaCheckError::Sql(anyhow::anyhow!("update failed: {e}")))?;
                } else {
                    conn.execute(
                        "UPDATE agent_quotas SET
                           current_memories_today = current_memories_today + 1,
                           current_storage_bytes = current_storage_bytes + ?1,
                           updated_at = ?2
                         WHERE agent_id = ?3 AND namespace = ?4",
                        params![bytes, now, agent_id, namespace],
                    )
                    .map_err(|e| QuotaCheckError::Sql(anyhow::anyhow!("update failed: {e}")))?;
                }
            }
            QuotaOp::Link => {
                if links_today + 1 > row.max_links_per_day {
                    return Err(QuotaCheckError::Quota(QuotaError {
                        agent_id: agent_id.to_string(),
                        namespace: namespace.to_string(),
                        limit: QuotaLimit::LinksPerDay,
                        current: links_today,
                        max: row.max_links_per_day,
                    }));
                }
                if day_rolled {
                    conn.execute(
                        "UPDATE agent_quotas SET
                           current_memories_today = 0,
                           current_links_today = 1,
                           day_started_at = ?1,
                           updated_at = ?1
                         WHERE agent_id = ?2 AND namespace = ?3",
                        params![now, agent_id, namespace],
                    )
                    .map_err(|e| QuotaCheckError::Sql(anyhow::anyhow!("update failed: {e}")))?;
                } else {
                    conn.execute(
                        "UPDATE agent_quotas SET
                           current_links_today = current_links_today + 1,
                           updated_at = ?1
                         WHERE agent_id = ?2 AND namespace = ?3",
                        params![now, agent_id, namespace],
                    )
                    .map_err(|e| QuotaCheckError::Sql(anyhow::anyhow!("update failed: {e}")))?;
                }
            }
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")
                .map_err(|e| QuotaCheckError::Sql(anyhow::anyhow!("quota commit failed: {e}")))?;
            Ok(())
        }
        Err(e) => {
            // Rollback is best-effort — even if it fails, the
            // transaction is implicitly aborted on connection drop.
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// v0.7 K8 / H12 — refund a previously-recorded op. Used by callers
/// that have already incremented the counters via
/// [`check_and_record`] but whose downstream insert failed AFTER the
/// quota commit. Decrements the same counters [`check_and_record`]
/// incremented; storage bytes is decremented for `QuotaOp::Memory`.
///
/// Counters never go below zero (saturating) so a buggy double-refund
/// cannot poison the substrate.
///
/// ## v0.7.0 #1156 — per-namespace dimension
///
/// Pass the same `(agent_id, namespace)` pair the matching
/// [`check_and_record`] call used so the refund lands on the same
/// accounting row.
///
/// # Errors
///
/// Wrapped SQL errors on update failure.
pub fn refund_op(conn: &Connection, agent_id: &str, namespace: &str, op: QuotaOp) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    match op {
        QuotaOp::Memory { bytes } => {
            conn.execute(
                "UPDATE agent_quotas SET
                   current_memories_today = MAX(current_memories_today - 1, 0),
                   current_storage_bytes = MAX(current_storage_bytes - ?1, 0),
                   updated_at = ?2
                 WHERE agent_id = ?3 AND namespace = ?4",
                params![bytes, now, agent_id, namespace],
            )?;
        }
        QuotaOp::Link => {
            conn.execute(
                "UPDATE agent_quotas SET
                   current_links_today = MAX(current_links_today - 1, 0),
                   updated_at = ?1
                 WHERE agent_id = ?2 AND namespace = ?3",
                params![now, agent_id, namespace],
            )?;
        }
    }
    Ok(())
}

/// v0.7 K8 — record a successful write against the
/// `(agent_id, namespace)` quota counters. Called AFTER the underlying
/// insert succeeds so a failed store does not consume quota.
///
/// **DEPRECATED for new code paths**: prefer [`check_and_record`]
/// which combines the check + record into a single atomic transaction
/// (closes H12 TOCTOU). `record_op` remains for callers (and tests)
/// that bypass the check phase entirely.
///
/// If the stored `day_started_at` rolled over since the row was last
/// touched, the daily counters are reset before the new op posts —
/// matching the inline-roll semantics in [`check_quota`] so the two
/// stay coherent without an intervening sweep.
///
/// # Errors
///
/// Wrapped SQL errors on update failure.
pub fn record_op(conn: &Connection, agent_id: &str, namespace: &str, op: QuotaOp) -> Result<()> {
    // ensure_row is idempotent so callers that skip check_quota (none
    // today, but defensive) still produce a coherent counter.
    let row = ensure_row(conn, agent_id, namespace)?;
    let now = chrono::Utc::now().to_rfc3339();
    let today = day_bucket(&now);
    let stored_day = day_bucket(&row.day_started_at);
    let day_rolled = stored_day != today;

    match op {
        QuotaOp::Memory { bytes } => {
            if day_rolled {
                conn.execute(
                    "UPDATE agent_quotas SET
                       current_memories_today = 1,
                       current_links_today = 0,
                       current_storage_bytes = current_storage_bytes + ?1,
                       day_started_at = ?2,
                       updated_at = ?2
                     WHERE agent_id = ?3 AND namespace = ?4",
                    params![bytes, now, agent_id, namespace],
                )?;
            } else {
                conn.execute(
                    "UPDATE agent_quotas SET
                       current_memories_today = current_memories_today + 1,
                       current_storage_bytes = current_storage_bytes + ?1,
                       updated_at = ?2
                     WHERE agent_id = ?3 AND namespace = ?4",
                    params![bytes, now, agent_id, namespace],
                )?;
            }
        }
        QuotaOp::Link => {
            if day_rolled {
                conn.execute(
                    "UPDATE agent_quotas SET
                       current_memories_today = 0,
                       current_links_today = 1,
                       day_started_at = ?1,
                       updated_at = ?1
                     WHERE agent_id = ?2 AND namespace = ?3",
                    params![now, agent_id, namespace],
                )?;
            } else {
                conn.execute(
                    "UPDATE agent_quotas SET
                       current_links_today = current_links_today + 1,
                       updated_at = ?1
                     WHERE agent_id = ?2 AND namespace = ?3",
                    params![now, agent_id, namespace],
                )?;
            }
        }
    }
    Ok(())
}

/// v0.7 K8 — daily counter reset. Zeros `current_memories_today` +
/// `current_links_today` for every `(agent_id, namespace)` row whose
/// `day_started_at` is not the current UTC date. Driven by the K8
/// sweep loop on a 60-second cadence; the inline-roll branch in
/// [`check_quota`] / [`record_op`] is the per-write fallback so the
/// substrate stays honest even if the sweeper is delayed.
///
/// Operates across every namespace in one statement — no per-namespace
/// loop is needed because the WHERE clause hits every stale row by
/// definition.
///
/// Returns the number of rows that were reset (0 when no agent has
/// crossed midnight since the previous sweep).
///
/// # Errors
///
/// Wrapped SQL errors on update failure.
pub fn reset_daily(conn: &Connection) -> Result<usize> {
    let now = chrono::Utc::now().to_rfc3339();
    let today = day_bucket(&now);
    let affected = conn.execute(
        "UPDATE agent_quotas SET
           current_memories_today = 0,
           current_links_today = 0,
           day_started_at = ?1,
           updated_at = ?1
         WHERE substr(day_started_at, 1, 10) <> ?2",
        params![now, today],
    )?;
    Ok(affected)
}

/// v0.7 K8 — read the current quota row for an
/// `(agent_id, namespace)` tuple, auto-inserting a default row if
/// none exists. Backs the namespace-scoped form of the
/// `memory_quota_status` MCP tool.
///
/// ## v0.7.0 #1156 — per-namespace dimension
///
/// Callers that lack a per-namespace context (boundary layer with no
/// `namespace` arg supplied, legacy tests) pass [`GLOBAL_NAMESPACE`]
/// to land on the historically-shaped row.
///
/// # Errors
///
/// Wrapped SQL errors on read failure.
pub fn get_status(conn: &Connection, agent_id: &str, namespace: &str) -> Result<QuotaStatus> {
    ensure_row(conn, agent_id, namespace)
}

/// v0.7 K8 / #1156 — read the aggregate quota row for an agent,
/// summing every per-namespace row. Returns a synthesised
/// [`QuotaStatus`] with `namespace = "_global"` and the *summed*
/// daily counters + summed lifetime storage bytes; the ceiling
/// columns report the maximum observed across every namespace row
/// (so the surfaced numbers don't lie about the per-namespace caps).
///
/// When the agent has no rows at all, falls back to
/// [`ensure_row`] against [`GLOBAL_NAMESPACE`] — the same shape
/// pre-v50 callers expected (auto-inserts a default `_global` row).
///
/// Backs the namespace-omitted form of `memory_quota_status` so the
/// pre-#1156 tool shape continues to make sense even after the
/// per-namespace dimension lands.
///
/// # Errors
///
/// Wrapped SQL errors on read failure.
pub fn get_aggregate_status(conn: &Connection, agent_id: &str) -> Result<QuotaStatus> {
    let mut stmt = conn
        .prepare(
            "SELECT
                COALESCE(MAX(max_memories_per_day), 0),
                COALESCE(MAX(max_storage_bytes), 0),
                COALESCE(MAX(max_links_per_day), 0),
                COALESCE(SUM(current_memories_today), 0),
                COALESCE(SUM(current_storage_bytes), 0),
                COALESCE(SUM(current_links_today), 0),
                COALESCE(MIN(day_started_at), ''),
                COALESCE(MIN(created_at), ''),
                COALESCE(MAX(updated_at), '')
             FROM agent_quotas WHERE agent_id = ?1",
        )
        .context("failed to prepare aggregate quota query")?;
    let row: Option<(i64, i64, i64, i64, i64, i64, String, String, String)> = stmt
        .query_row(params![agent_id], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
            ))
        })
        .optional()
        .context("failed to read aggregate quota row")?;
    drop(stmt);
    if let Some((mm, ms, ml, cm, cs, cl, day, created, updated)) = row {
        if !created.is_empty() {
            return Ok(QuotaStatus {
                agent_id: agent_id.to_string(),
                namespace: GLOBAL_NAMESPACE.to_string(),
                max_memories_per_day: mm,
                max_storage_bytes: ms,
                max_links_per_day: ml,
                current_memories_today: cm,
                current_storage_bytes: cs,
                current_links_today: cl,
                day_started_at: day,
                created_at: created,
                updated_at: updated,
            });
        }
    }
    // No rows at all: fall back to ensure_row at the global sentinel.
    ensure_row(conn, agent_id, GLOBAL_NAMESPACE)
}

/// v0.7 K8 — read every quota row in the substrate. Backs the
/// `memory_quota_status` MCP tool when the operator omits the
/// `agent_id` parameter (operator-facing surface).
///
/// ## v0.7.0 #1156 — per-namespace dimension
///
/// When `namespace_filter` is `Some(ns)`, only rows in that namespace
/// are returned (drives the `?namespace=` HTTP query param + the
/// MCP tool's optional `namespace` arg). When `None`, every row in
/// the substrate is returned, ordered by `(agent_id ASC, namespace ASC)`
/// for stable output across calls.
///
/// # Errors
///
/// Wrapped SQL errors on read failure.
pub fn list_status(conn: &Connection, namespace_filter: Option<&str>) -> Result<Vec<QuotaStatus>> {
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<QuotaStatus> {
        Ok(QuotaStatus {
            agent_id: r.get(0)?,
            namespace: r.get(1)?,
            max_memories_per_day: r.get(2)?,
            max_storage_bytes: r.get(3)?,
            max_links_per_day: r.get(4)?,
            current_memories_today: r.get(5)?,
            current_storage_bytes: r.get(6)?,
            current_links_today: r.get(7)?,
            day_started_at: r.get(8)?,
            created_at: r.get(9)?,
            updated_at: r.get(10)?,
        })
    };
    let mut out = Vec::new();
    if let Some(ns) = namespace_filter {
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, namespace,
                        max_memories_per_day, max_storage_bytes, max_links_per_day,
                        current_memories_today, current_storage_bytes, current_links_today,
                        day_started_at, created_at, updated_at
                 FROM agent_quotas
                 WHERE namespace = ?1
                 ORDER BY agent_id ASC, namespace ASC",
            )
            .context("failed to prepare per-namespace quota list query")?;
        let rows = stmt
            .query_map(params![ns], map_row)
            .context("failed to query per-namespace quota rows")?;
        for row in rows {
            out.push(row.context("failed to materialize quota row")?);
        }
    } else {
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, namespace,
                        max_memories_per_day, max_storage_bytes, max_links_per_day,
                        current_memories_today, current_storage_bytes, current_links_today,
                        day_started_at, created_at, updated_at
                 FROM agent_quotas
                 ORDER BY agent_id ASC, namespace ASC",
            )
            .context("failed to prepare quota list query")?;
        let rows = stmt
            .query_map([], map_row)
            .context("failed to query quota rows")?;
        for row in rows {
            out.push(row.context("failed to materialize quota row")?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory");
        // Apply the K8 substrate via the production migration ladder:
        // v28 creates the legacy single-PK table; v50 migrates it to
        // the compound `(agent_id, namespace)` PK shape #1156 ships.
        // Hand-apply both so unit tests see the v50 shape.
        conn.execute_batch(include_str!(
            "../migrations/sqlite/0022_v07_agent_quotas.sql"
        ))
        .expect("apply v28 K8 migration");
        conn.execute_batch(include_str!(
            "../migrations/sqlite/0042_v50_per_namespace_quota.sql"
        ))
        .expect("apply v50 per-namespace migration");
        conn
    }

    #[test]
    fn check_quota_under_limit_returns_ok() {
        let conn = fresh_db();
        assert!(
            check_quota(
                &conn,
                "agent-a",
                GLOBAL_NAMESPACE,
                QuotaOp::Memory { bytes: 100 }
            )
            .is_ok()
        );
    }

    #[test]
    fn check_quota_at_memory_limit_returns_quota_exceeded() {
        let conn = fresh_db();
        // First call inserts the default row.
        check_quota(
            &conn,
            "agent-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_quotas SET max_memories_per_day = 1
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-a", GLOBAL_NAMESPACE],
        )
        .unwrap();
        record_op(
            &conn,
            "agent-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        let err = check_quota(
            &conn,
            "agent-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap_err();
        match err {
            QuotaCheckError::Quota(q) => {
                assert_eq!(q.limit, QuotaLimit::MemoriesPerDay);
                assert_eq!(q.max, 1);
                assert_eq!(q.namespace, GLOBAL_NAMESPACE);
            }
            QuotaCheckError::Sql(e) => panic!("expected QuotaError, got SQL: {e}"),
        }
    }

    #[test]
    fn check_quota_storage_bytes_limit_fires() {
        let conn = fresh_db();
        check_quota(
            &conn,
            "agent-b",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_quotas SET max_storage_bytes = 100
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-b", GLOBAL_NAMESPACE],
        )
        .unwrap();
        let err = check_quota(
            &conn,
            "agent-b",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 200 },
        )
        .unwrap_err();
        match err {
            QuotaCheckError::Quota(q) => assert_eq!(q.limit, QuotaLimit::StorageBytes),
            QuotaCheckError::Sql(e) => panic!("expected QuotaError, got SQL: {e}"),
        }
    }

    #[test]
    fn check_quota_links_per_day_limit_fires() {
        let conn = fresh_db();
        check_quota(&conn, "agent-c", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        conn.execute(
            "UPDATE agent_quotas SET max_links_per_day = 1, current_links_today = 1
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-c", GLOBAL_NAMESPACE],
        )
        .unwrap();
        let err = check_quota(&conn, "agent-c", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap_err();
        match err {
            QuotaCheckError::Quota(q) => assert_eq!(q.limit, QuotaLimit::LinksPerDay),
            QuotaCheckError::Sql(e) => panic!("expected QuotaError, got SQL: {e}"),
        }
    }

    #[test]
    fn record_op_increments_counters() {
        let conn = fresh_db();
        record_op(
            &conn,
            "agent-d",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 42 },
        )
        .unwrap();
        let s = get_status(&conn, "agent-d", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_memories_today, 1);
        assert_eq!(s.current_storage_bytes, 42);
        record_op(&conn, "agent-d", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        let s2 = get_status(&conn, "agent-d", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s2.current_links_today, 1);
    }

    #[test]
    fn reset_daily_zeros_stale_rows_only() {
        let conn = fresh_db();
        record_op(
            &conn,
            "agent-e",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 10 },
        )
        .unwrap();
        record_op(&conn, "agent-f", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        // Roll agent-e's day_started_at back to yesterday.
        conn.execute(
            "UPDATE agent_quotas SET day_started_at = '2020-01-01T00:00:00+00:00'
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-e", GLOBAL_NAMESPACE],
        )
        .unwrap();
        let n = reset_daily(&conn).unwrap();
        assert_eq!(n, 1, "exactly one stale row should be reset");
        let s_e = get_status(&conn, "agent-e", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s_e.current_memories_today, 0);
        let s_f = get_status(&conn, "agent-f", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(
            s_f.current_links_today, 1,
            "fresh row must not be touched by the daily reset"
        );
        // Storage is lifetime, never reset.
        assert_eq!(s_e.current_storage_bytes, 10);
    }

    #[test]
    fn list_status_returns_all_rows_sorted() {
        let conn = fresh_db();
        record_op(
            &conn,
            "z-agent",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        record_op(
            &conn,
            "a-agent",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        record_op(
            &conn,
            "m-agent",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        let rows = list_status(&conn, None).unwrap();
        let ids: Vec<&str> = rows.iter().map(|r| r.agent_id.as_str()).collect();
        assert_eq!(ids, vec!["a-agent", "m-agent", "z-agent"]);
    }

    #[test]
    fn get_status_auto_inserts_default_row() {
        let conn = fresh_db();
        let s = get_status(&conn, "fresh-agent", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.max_memories_per_day, DEFAULT_MAX_MEMORIES_PER_DAY);
        assert_eq!(s.max_storage_bytes, DEFAULT_MAX_STORAGE_BYTES);
        assert_eq!(s.max_links_per_day, DEFAULT_MAX_LINKS_PER_DAY);
        assert_eq!(s.current_memories_today, 0);
        assert_eq!(s.namespace, GLOBAL_NAMESPACE);
    }

    #[test]
    fn quota_limit_as_str_returns_expected_canonical_form() {
        assert_eq!(QuotaLimit::MemoriesPerDay.as_str(), "memories_per_day");
        assert_eq!(QuotaLimit::StorageBytes.as_str(), "storage_bytes");
        assert_eq!(QuotaLimit::LinksPerDay.as_str(), "links_per_day");
    }

    #[test]
    fn quota_error_display_format_contract() {
        let err = QuotaError {
            agent_id: "alice".to_string(),
            namespace: "team/policies".to_string(),
            limit: QuotaLimit::StorageBytes,
            current: 1024,
            max: 2048,
        };
        let s = format!("{err}");
        assert!(s.contains("QUOTA_EXCEEDED"));
        assert!(s.contains("alice"));
        assert!(s.contains("team/policies"));
        assert!(s.contains("storage_bytes"));
        assert!(s.contains("current=1024"));
        assert!(s.contains("max=2048"));
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn quota_check_error_display_quota_variant_delegates_to_inner() {
        let err = QuotaCheckError::Quota(QuotaError {
            agent_id: "bob".to_string(),
            namespace: GLOBAL_NAMESPACE.to_string(),
            limit: QuotaLimit::MemoriesPerDay,
            current: 99,
            max: 100,
        });
        let s = format!("{err}");
        assert!(s.contains("QUOTA_EXCEEDED"));
        assert!(s.contains("memories_per_day"));
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn quota_check_error_display_sql_variant_wraps_substrate_error() {
        let err = QuotaCheckError::Sql(anyhow::anyhow!("boom"));
        let s = format!("{err}");
        assert!(s.contains("quota check substrate error"));
        assert!(s.contains("boom"));
    }

    #[test]
    fn check_and_record_under_limit_increments_counters() {
        let conn = fresh_db();
        check_and_record(
            &conn,
            "agent-cr-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 50 },
        )
        .unwrap();
        let s = get_status(&conn, "agent-cr-a", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_memories_today, 1);
        assert_eq!(s.current_storage_bytes, 50);
        check_and_record(&conn, "agent-cr-a", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        let s2 = get_status(&conn, "agent-cr-a", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s2.current_links_today, 1);
    }

    #[test]
    fn check_and_record_at_memories_limit_returns_quota_error_and_rolls_back() {
        let conn = fresh_db();
        check_and_record(
            &conn,
            "agent-cr-b",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        // Tighten the cap so the next write would exceed.
        conn.execute(
            "UPDATE agent_quotas SET max_memories_per_day = 1
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-cr-b", GLOBAL_NAMESPACE],
        )
        .unwrap();
        let err = check_and_record(
            &conn,
            "agent-cr-b",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap_err();
        match err {
            QuotaCheckError::Quota(q) => {
                assert_eq!(q.limit, QuotaLimit::MemoriesPerDay);
            }
            QuotaCheckError::Sql(e) => panic!("expected Quota, got SQL: {e}"),
        }
        // Counter NOT incremented (rollback).
        let s = get_status(&conn, "agent-cr-b", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_memories_today, 1);
    }

    #[test]
    fn check_and_record_storage_limit_returns_quota_error() {
        let conn = fresh_db();
        check_and_record(
            &conn,
            "agent-cr-c",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_quotas SET max_storage_bytes = 100
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-cr-c", GLOBAL_NAMESPACE],
        )
        .unwrap();
        let err = check_and_record(
            &conn,
            "agent-cr-c",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1000 },
        )
        .expect_err("storage cap should fire");
        match err {
            QuotaCheckError::Quota(q) => assert_eq!(q.limit, QuotaLimit::StorageBytes),
            QuotaCheckError::Sql(e) => panic!("expected quota, got SQL: {e}"),
        }
    }

    #[test]
    fn check_and_record_links_limit_returns_quota_error() {
        let conn = fresh_db();
        check_and_record(&conn, "agent-cr-d", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        conn.execute(
            "UPDATE agent_quotas SET max_links_per_day = 1
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-cr-d", GLOBAL_NAMESPACE],
        )
        .unwrap();
        let err = check_and_record(&conn, "agent-cr-d", GLOBAL_NAMESPACE, QuotaOp::Link)
            .expect_err("links cap should fire");
        match err {
            QuotaCheckError::Quota(q) => assert_eq!(q.limit, QuotaLimit::LinksPerDay),
            QuotaCheckError::Sql(e) => panic!("expected quota, got SQL: {e}"),
        }
    }

    #[test]
    fn check_and_record_day_roll_branch_for_memory_zeros_daily_counters() {
        let conn = fresh_db();
        check_and_record(
            &conn,
            "agent-cr-e",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 10 },
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_quotas SET day_started_at = '2020-01-01T00:00:00+00:00',
                current_memories_today = 999, current_links_today = 7
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-cr-e", GLOBAL_NAMESPACE],
        )
        .unwrap();
        check_and_record(
            &conn,
            "agent-cr-e",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 5 },
        )
        .unwrap();
        let s = get_status(&conn, "agent-cr-e", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_memories_today, 1);
        assert_eq!(s.current_links_today, 0);
        assert_eq!(s.current_storage_bytes, 15);
    }

    #[test]
    fn check_and_record_day_roll_branch_for_link_resets_daily_counters() {
        let conn = fresh_db();
        check_and_record(&conn, "agent-cr-f", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        conn.execute(
            "UPDATE agent_quotas SET day_started_at = '2020-01-01T00:00:00+00:00',
                current_memories_today = 50, current_links_today = 8
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-cr-f", GLOBAL_NAMESPACE],
        )
        .unwrap();
        check_and_record(&conn, "agent-cr-f", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        let s = get_status(&conn, "agent-cr-f", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_memories_today, 0);
        assert_eq!(s.current_links_today, 1);
    }

    #[test]
    fn refund_op_memory_decrements_counters_saturating_to_zero() {
        let conn = fresh_db();
        check_and_record(
            &conn,
            "agent-rf-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 200 },
        )
        .unwrap();
        refund_op(
            &conn,
            "agent-rf-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 200 },
        )
        .unwrap();
        let s = get_status(&conn, "agent-rf-a", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_memories_today, 0);
        assert_eq!(s.current_storage_bytes, 0);
        refund_op(
            &conn,
            "agent-rf-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 200 },
        )
        .unwrap();
        let s2 = get_status(&conn, "agent-rf-a", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s2.current_memories_today, 0);
        assert_eq!(s2.current_storage_bytes, 0);
    }

    #[test]
    fn refund_op_link_decrements_counter_saturating_to_zero() {
        let conn = fresh_db();
        check_and_record(&conn, "agent-rf-b", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        refund_op(&conn, "agent-rf-b", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        let s = get_status(&conn, "agent-rf-b", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_links_today, 0);
        refund_op(&conn, "agent-rf-b", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        let s2 = get_status(&conn, "agent-rf-b", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s2.current_links_today, 0);
    }

    #[test]
    fn record_op_day_roll_branch_for_memory() {
        let conn = fresh_db();
        record_op(
            &conn,
            "agent-ro-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 100 },
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_quotas SET day_started_at = '2020-01-01T00:00:00+00:00',
                current_memories_today = 50, current_links_today = 4
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-ro-a", GLOBAL_NAMESPACE],
        )
        .unwrap();
        record_op(
            &conn,
            "agent-ro-a",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 5 },
        )
        .unwrap();
        let s = get_status(&conn, "agent-ro-a", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_memories_today, 1);
        assert_eq!(s.current_links_today, 0);
        assert_eq!(s.current_storage_bytes, 105);
    }

    #[test]
    fn record_op_day_roll_branch_for_link() {
        let conn = fresh_db();
        record_op(&conn, "agent-ro-b", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        conn.execute(
            "UPDATE agent_quotas SET day_started_at = '2020-01-01T00:00:00+00:00',
                current_memories_today = 7, current_links_today = 9
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-ro-b", GLOBAL_NAMESPACE],
        )
        .unwrap();
        record_op(&conn, "agent-ro-b", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        let s = get_status(&conn, "agent-ro-b", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.current_memories_today, 0);
        assert_eq!(s.current_links_today, 1);
    }

    #[test]
    fn quota_status_serde_roundtrip_carries_namespace() {
        let conn = fresh_db();
        let s = get_status(&conn, "ser-agent", "team/policies").unwrap();
        let json = serde_json::to_string(&s).unwrap();
        let parsed: QuotaStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_id, "ser-agent");
        assert_eq!(parsed.namespace, "team/policies");
        assert_eq!(parsed.max_memories_per_day, DEFAULT_MAX_MEMORIES_PER_DAY);
    }

    #[test]
    fn check_quota_day_roll_branch_treats_daily_as_zero() {
        let conn = fresh_db();
        check_quota(
            &conn,
            "agent-cq-roll",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_quotas SET day_started_at = '2020-01-01T00:00:00+00:00',
                current_memories_today = 99999, current_links_today = 99999
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-cq-roll", GLOBAL_NAMESPACE],
        )
        .unwrap();
        assert!(
            check_quota(
                &conn,
                "agent-cq-roll",
                GLOBAL_NAMESPACE,
                QuotaOp::Memory { bytes: 1 }
            )
            .is_ok()
        );
        assert!(check_quota(&conn, "agent-cq-roll", GLOBAL_NAMESPACE, QuotaOp::Link).is_ok());
    }

    // ─────────────────────────────────────────────────────────────────
    // v0.7.0 #1156 — per-namespace dimension regression tests
    // ─────────────────────────────────────────────────────────────────

    /// #1156 — quota counters MUST stay isolated across namespaces.
    /// An agent that hits their memories/day cap in namespace A still
    /// has full headroom in namespace B.
    #[test]
    fn per_namespace_isolation_memories() {
        let conn = fresh_db();
        // Auto-insert default rows in two namespaces.
        check_and_record(
            &conn,
            "agent-ns",
            "alice/scratch",
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        check_and_record(
            &conn,
            "agent-ns",
            "team/policies",
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        // Tighten ONLY the alice/scratch row.
        conn.execute(
            "UPDATE agent_quotas SET max_memories_per_day = 1
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-ns", "alice/scratch"],
        )
        .unwrap();
        // Second write to alice/scratch trips the cap.
        let err = check_and_record(
            &conn,
            "agent-ns",
            "alice/scratch",
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap_err();
        match err {
            QuotaCheckError::Quota(q) => {
                assert_eq!(q.namespace, "alice/scratch");
                assert_eq!(q.limit, QuotaLimit::MemoriesPerDay);
            }
            QuotaCheckError::Sql(e) => panic!("expected Quota, got SQL: {e}"),
        }
        // But team/policies still has headroom: writes succeed.
        check_and_record(
            &conn,
            "agent-ns",
            "team/policies",
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
    }

    /// #1156 — storage cap is per-namespace too. Bytes recorded in
    /// namespace A do not consume the cap of namespace B.
    #[test]
    fn per_namespace_isolation_storage_bytes() {
        let conn = fresh_db();
        check_and_record(
            &conn,
            "agent-ns2",
            "alice/scratch",
            QuotaOp::Memory { bytes: 50 },
        )
        .unwrap();
        // Tighten alice/scratch storage cap to 100 bytes.
        conn.execute(
            "UPDATE agent_quotas SET max_storage_bytes = 100
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-ns2", "alice/scratch"],
        )
        .unwrap();
        // A 60-byte write in alice/scratch trips storage cap.
        let err = check_and_record(
            &conn,
            "agent-ns2",
            "alice/scratch",
            QuotaOp::Memory { bytes: 60 },
        )
        .unwrap_err();
        assert!(matches!(err, QuotaCheckError::Quota(q) if q.limit == QuotaLimit::StorageBytes));
        // Same 60-byte write in shared/team-a goes through (independent
        // accounting row, 100 MiB default cap).
        check_and_record(
            &conn,
            "agent-ns2",
            "shared/team-a",
            QuotaOp::Memory { bytes: 60 },
        )
        .unwrap();
    }

    /// #1156 — per-namespace links/day isolation.
    #[test]
    fn per_namespace_isolation_links() {
        let conn = fresh_db();
        check_and_record(&conn, "agent-ns3", "alice/scratch", QuotaOp::Link).unwrap();
        conn.execute(
            "UPDATE agent_quotas SET max_links_per_day = 1
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["agent-ns3", "alice/scratch"],
        )
        .unwrap();
        let err = check_and_record(&conn, "agent-ns3", "alice/scratch", QuotaOp::Link)
            .expect_err("links cap on alice/scratch should fire");
        assert!(matches!(err, QuotaCheckError::Quota(q) if q.limit == QuotaLimit::LinksPerDay));
        // Different namespace still has headroom.
        check_and_record(&conn, "agent-ns3", "team/policies", QuotaOp::Link).unwrap();
    }

    /// #1156 — `get_aggregate_status` sums counters across every
    /// namespace row for an agent.
    #[test]
    fn aggregate_status_sums_across_namespaces() {
        let conn = fresh_db();
        record_op(
            &conn,
            "agent-agg",
            "alice/scratch",
            QuotaOp::Memory { bytes: 100 },
        )
        .unwrap();
        record_op(
            &conn,
            "agent-agg",
            "team/policies",
            QuotaOp::Memory { bytes: 200 },
        )
        .unwrap();
        record_op(&conn, "agent-agg", "alice/scratch", QuotaOp::Link).unwrap();
        record_op(&conn, "agent-agg", "team/policies", QuotaOp::Link).unwrap();
        record_op(&conn, "agent-agg", "team/policies", QuotaOp::Link).unwrap();

        let agg = get_aggregate_status(&conn, "agent-agg").unwrap();
        assert_eq!(agg.agent_id, "agent-agg");
        assert_eq!(agg.namespace, GLOBAL_NAMESPACE);
        // Two memory ops in two namespaces.
        assert_eq!(agg.current_memories_today, 2);
        // 100 + 200 bytes.
        assert_eq!(agg.current_storage_bytes, 300);
        // 1 + 2 links.
        assert_eq!(agg.current_links_today, 3);
    }

    /// #1156 — `list_status(None)` returns every row across every
    /// namespace, sorted by (agent_id ASC, namespace ASC).
    #[test]
    fn list_status_returns_per_namespace_rows_sorted() {
        let conn = fresh_db();
        record_op(&conn, "agent-ls", "z-ns", QuotaOp::Memory { bytes: 1 }).unwrap();
        record_op(&conn, "agent-ls", "a-ns", QuotaOp::Memory { bytes: 1 }).unwrap();
        let rows = list_status(&conn, None).unwrap();
        // Should have 2 rows, both for agent-ls.
        let agent_ls_rows: Vec<&QuotaStatus> =
            rows.iter().filter(|r| r.agent_id == "agent-ls").collect();
        assert_eq!(agent_ls_rows.len(), 2);
        // Namespaces are sorted ascending: a-ns before z-ns.
        assert_eq!(agent_ls_rows[0].namespace, "a-ns");
        assert_eq!(agent_ls_rows[1].namespace, "z-ns");
    }

    /// #1156 — `list_status(Some(ns))` filters down to one namespace.
    #[test]
    fn list_status_namespace_filter() {
        let conn = fresh_db();
        record_op(
            &conn,
            "agent-lf",
            "team/policies",
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        record_op(
            &conn,
            "agent-lf",
            "alice/scratch",
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        record_op(
            &conn,
            "other-agent",
            "team/policies",
            QuotaOp::Memory { bytes: 1 },
        )
        .unwrap();
        let rows = list_status(&conn, Some("team/policies")).unwrap();
        for r in &rows {
            assert_eq!(r.namespace, "team/policies");
        }
        // Two agents wrote in team/policies — both must appear.
        let agent_ids: std::collections::HashSet<&str> =
            rows.iter().map(|r| r.agent_id.as_str()).collect();
        assert!(agent_ids.contains("agent-lf"));
        assert!(agent_ids.contains("other-agent"));
    }

    /// #1156 — sentinel namespace `_global` is the backwards-compat
    /// landing zone. Pre-v50 callers (who pass `_global`) see the
    /// historically-shaped accounting row.
    #[test]
    fn global_sentinel_is_backwards_compat_landing_zone() {
        let conn = fresh_db();
        record_op(
            &conn,
            "agent-bc",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 42 },
        )
        .unwrap();
        let s = get_status(&conn, "agent-bc", GLOBAL_NAMESPACE).unwrap();
        assert_eq!(s.namespace, GLOBAL_NAMESPACE);
        assert_eq!(s.current_memories_today, 1);
        assert_eq!(s.current_storage_bytes, 42);
    }
}
