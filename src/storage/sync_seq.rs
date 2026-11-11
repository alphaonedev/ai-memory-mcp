// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v102 (#9082) - the serving-assigned change sequence (SQLite SSOT; the
//! postgres twin lives in `store::postgres`).
//!
//! `/sync/since` used to filter by the row's OWN `updated_at`, a value the
//! WRITER chose. A row that reached this node with an `updated_at` below a
//! puller's cursor (a relayed row, a backward clock step on the origin) was
//! never served to that puller again. `memories.sync_seq` is assigned by THIS
//! node's triggers, in commit order, on every insert and on every real change
//! of a replicated column, so a puller that walks `sync_seq > after_seq` in
//! ascending order sees every row this node holds, whatever its timestamps.
//!
//! The value is never taken from push, import or restore input: `Memory`
//! carries no `sync_seq` field and the AFTER INSERT trigger re-numbers every
//! inserted row from the one-row `sync_seq_counter`.
//!
//! Shape ratified by the 5-agent vote (4d3ea1c5), memory c472a44b.

use anyhow::{Context as _, Result, anyhow};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::models::Memory;

/// Error text when the one-row `sync_seq_counter` is absent (both backends).
pub const SYNC_SEQ_COUNTER_MISSING: &str = "sync_seq_counter row 1 is missing (v102)";

/// Error text for a negative `after_seq` reaching a store (both backends).
#[must_use]
pub fn negative_after_seq_detail(after_seq: i64) -> String {
    format!("after_seq must be >= 0, got {after_seq}")
}

const MIGRATION_V102_SQLITE: &str = include_str!("../../migrations/sqlite/0086_v102_sync_seq.sql");

/// Splits the v102 file into its run-once head and its idempotent tail.
const MIGRATION_V102_ONCE_MARKER: &str = "-- @@v102-once@@";

/// Apply the v102 migration (doc twin: `migrations/sqlite/0086_v102_sync_seq.sql`).
///
/// Re-runnable: the column add and the backfill (the part of the file above
/// [`MIGRATION_V102_ONCE_MARKER`]) run only while `memories.sync_seq` is
/// absent, so a ladder re-run never adds the column twice nor re-numbers live
/// rows; the rest of the file is idempotent on its own.
pub(super) fn migrate_v102(conn: &Connection) -> Result<()> {
    let (once, always) = MIGRATION_V102_SQLITE
        .split_once(MIGRATION_V102_ONCE_MARKER)
        .ok_or_else(|| {
            anyhow!("v102 migration file lost its {MIGRATION_V102_ONCE_MARKER} marker")
        })?;
    let has_column: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM pragma_table_info('memories') WHERE name = 'sync_seq')",
            [],
            |row| row.get(0),
        )
        .context("probe memories.sync_seq")?;
    if !has_column {
        conn.execute_batch(once)
            .context("apply v102 sync_seq column and backfill")?;
    }
    conn.execute_batch(always)
        .context("apply v102 sync_seq counter, index and triggers")?;
    conn.execute(super::migrations::SQL_CLEAR_SCHEMA_VERSION, [])?;
    conn.execute("INSERT INTO schema_version (version) VALUES (102)", [])?;
    Ok(())
}

/// The serving node's counter head and the opaque epoch it was taken under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqHead {
    /// Highest sequence value this node has handed out.
    pub head: i64,
    /// Opaque per-database id, regenerated on restore.
    pub epoch: String,
}

/// One page of the sequence walk.
#[derive(Debug, Clone)]
pub struct SeqPage {
    /// The visible, decryptable rows of the page, in `sync_seq` order.
    pub memories: Vec<Memory>,
    /// Rows the `LIMIT` returned before the visibility and decrypt filters.
    pub raw_count: usize,
    /// The highest `sync_seq` EXAMINED (visible or not); `effective_after`
    /// when the page is empty. Never the counter head.
    pub next_seq: i64,
    /// The `after_seq` the walk actually used: the requested value, or 0 when
    /// the request was above the head (a restored or re-initialised node).
    pub effective_after: i64,
    /// Counter head and epoch read with the page.
    pub head: SeqHead,
}

/// Read the counter head and epoch.
///
/// # Errors
/// Fails closed when the counter row is missing (a v102 database always has it).
pub fn seq_head(conn: &Connection) -> Result<SeqHead> {
    conn.query_row(
        "SELECT head, epoch FROM sync_seq_counter WHERE id = 1",
        [],
        |row| {
            Ok(SeqHead {
                head: row.get(0)?,
                epoch: row.get(1)?,
            })
        },
    )
    .optional()?
    .ok_or_else(|| anyhow!(SYNC_SEQ_COUNTER_MISSING))
}

/// Walk `memories` by `sync_seq > after_seq`, ascending, at most `limit` rows.
///
/// Lifecycle-hidden rows (tombstoned, quarantined) and rows this node cannot
/// decrypt are examined and counted in `next_seq` but not returned, so the
/// walk never re-scans them. A request above the head walks from 0.
///
/// # Errors
/// Returns an error on a SQL failure or a negative `after_seq` (the handler
/// refuses that with a 400 before it gets here).
pub fn memories_after_seq(conn: &Connection, after_seq: i64, limit: usize) -> Result<SeqPage> {
    if after_seq < 0 {
        return Err(anyhow!(negative_after_seq_detail(after_seq)));
    }
    let head = seq_head(conn)?;
    let effective_after = if after_seq > head.head { 0 } else { after_seq };
    let limit_i = i64::try_from(limit).unwrap_or(i64::MAX);
    let cols = super::memory_row_columns("");
    let vis = crate::models::lifecycle_visible_clause("");
    let vis_expr = vis.strip_prefix("AND ").unwrap_or(&vis);
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols}, sync_seq AS sync_seq_examined, \
                CASE WHEN {vis_expr} THEN 1 ELSE 0 END AS sync_seq_visible \
           FROM memories WHERE sync_seq > ?1 ORDER BY sync_seq ASC LIMIT ?2"
    ))?;
    let rows = stmt
        .query_map(params![effective_after, limit_i], |row| {
            let seq: i64 = row.get("sync_seq_examined")?;
            let visible: i64 = row.get("sync_seq_visible")?;
            if visible == 0 {
                return Ok((seq, None));
            }
            Ok((seq, super::row_to_memory_scan(row)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let raw_count = rows.len();
    let next_seq = rows.last().map_or(effective_after, |(seq, _)| *seq);
    let memories = rows.into_iter().filter_map(|(_, mem)| mem).collect();
    Ok(SeqPage {
        memories,
        raw_count,
        next_seq,
        effective_after,
        head,
    })
}

/// Give the database a fresh epoch, so every puller's stored `last_seq`
/// against this node is treated as foreign and the walk restarts at 0.
/// Called after a restore publishes a snapshot over the live database.
///
/// # Errors
/// Fails closed when the counter row is missing.
pub fn regenerate_seq_epoch(conn: &Connection) -> Result<String> {
    let epoch: Option<String> = conn
        .query_row(
            "UPDATE sync_seq_counter SET epoch = lower(hex(randomblob(16))) WHERE id = 1 \
             RETURNING epoch",
            [],
            |row| row.get(0),
        )
        .optional()?;
    epoch.ok_or_else(|| anyhow!(SYNC_SEQ_COUNTER_MISSING))
}

/// Suffix of the sidecar a restore leaves beside the database it publishes.
/// The next read-write open regenerates the epoch and removes it.
pub const SEQ_EPOCH_RESET_SUFFIX: &str = ".seq-epoch-reset";

/// The epoch-reset sidecar path for `db`.
#[must_use]
pub fn epoch_reset_marker_path(db: &std::path::Path) -> std::path::PathBuf {
    let mut name = db
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(SEQ_EPOCH_RESET_SUFFIX);
    db.with_file_name(name)
}

/// Arm the epoch reset for `db`: write the sidecar and make it durable.
///
/// decision: a sidecar consumed at the next open over rewriting the restored
/// file because #3131 pins the published database byte-identical to the
/// snapshot. The sidecar is armed BEFORE the publish, so a crash in between
/// costs at most one spurious reset (every puller re-walks from 0), never a
/// restored database that keeps the old epoch.
///
/// # Errors
/// The sidecar cannot be created or fsynced.
pub fn arm_epoch_reset(db: &std::path::Path) -> std::io::Result<()> {
    let marker = epoch_reset_marker_path(db);
    let file = std::fs::File::create(&marker)?;
    file.sync_all()?;
    if let Some(dir) = marker.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Consume an armed epoch reset on a read-write open of `db`.
///
/// A database that predates v102 has no counter: the migration that just ran
/// minted a fresh epoch, so the sidecar is only removed. The sidecar is
/// removed only after the new epoch is committed.
///
/// # Errors
/// The epoch cannot be regenerated or the sidecar cannot be removed; the open
/// fails closed rather than serve a restored database under its old epoch.
pub fn consume_epoch_reset(conn: &Connection, db: &std::path::Path) -> Result<()> {
    let marker = epoch_reset_marker_path(db);
    match marker.try_exists() {
        Ok(false) => return Ok(()),
        Ok(true) => {}
        Err(e) => {
            return Err(anyhow!(
                "cannot tell whether {} exists ({e}) - refusing to serve a possibly \
                 restored database under its old sync_seq epoch (#9082)",
                marker.display()
            ));
        }
    }
    let has_counter: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' \
           AND name = 'sync_seq_counter')",
        [],
        |row| row.get(0),
    )?;
    if has_counter {
        let epoch = regenerate_seq_epoch(conn)?;
        tracing::warn!(
            target: "federation",
            epoch = %epoch,
            "restored database: sync_seq epoch regenerated, pullers re-walk from 0 (#9082)"
        );
    }
    std::fs::remove_file(&marker)
        .with_context(|| format!("removing the epoch-reset sidecar {}", marker.display()))?;
    Ok(())
}

/// The puller's stored sequence cursor against one peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullSeqCursor {
    /// Highest `next_seq` applied; `None` walks from 0. Never seeded from the
    /// timestamp cursor.
    pub last_seq: Option<i64>,
    /// The peer's epoch `last_seq` was taken under.
    pub seq_epoch: Option<String>,
}

impl PullSeqCursor {
    /// The `after_seq` to send for this cursor (0 when none is stored).
    #[must_use]
    pub fn after_seq(&self) -> i64 {
        self.last_seq.unwrap_or(0)
    }
}

/// Load the puller's sequence cursor for `(agent_id, peer_id)`.
///
/// # Errors
/// Returns an error on a SQL failure.
pub fn sync_pull_seq_get(
    conn: &Connection,
    agent_id: &str,
    peer_id: &str,
) -> Result<PullSeqCursor> {
    let found = conn
        .query_row(
            "SELECT last_seq, seq_epoch FROM sync_pull_seq WHERE agent_id = ?1 AND peer_id = ?2",
            params![agent_id, peer_id],
            |row| {
                Ok(PullSeqCursor {
                    last_seq: row.get(0)?,
                    seq_epoch: row.get(1)?,
                })
            },
        )
        .optional()?;
    Ok(found.unwrap_or_default())
}

/// Store the puller's sequence cursor. NOT monotonic: a peer reset (new epoch,
/// or a head below the old cursor) legitimately lowers it.
///
/// # Errors
/// Returns an error on a negative `last_seq` or a SQL failure.
pub fn sync_pull_seq_set(
    conn: &Connection,
    agent_id: &str,
    peer_id: &str,
    last_seq: i64,
    seq_epoch: &str,
) -> Result<()> {
    if last_seq < 0 {
        return Err(anyhow!("last_seq must be >= 0, got {last_seq}"));
    }
    conn.execute(
        "INSERT INTO sync_pull_seq (agent_id, peer_id, last_seq, seq_epoch, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(agent_id, peer_id) DO UPDATE SET \
            last_seq = excluded.last_seq, seq_epoch = excluded.seq_epoch, \
            updated_at = excluded.updated_at",
        params![
            agent_id,
            peer_id,
            last_seq,
            seq_epoch,
            Utc::now().to_rfc3339()
        ],
    )?;
    Ok(())
}
