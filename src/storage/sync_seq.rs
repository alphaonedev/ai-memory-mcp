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
use crate::models::field_names as field;

/// Error text when the one-row `sync_seq_counter` is absent (both backends).
pub const SYNC_SEQ_COUNTER_MISSING: &str = "sync_seq_counter row 1 is missing (v102)";

/// Error text for a negative `after_seq` reaching a store (both backends).
#[must_use]
pub fn negative_after_seq_detail(after_seq: i64) -> String {
    format!("after_seq must be >= 0, got {after_seq}")
}

const MIGRATION_V102_SQLITE: &str = include_str!("../../migrations/sqlite/0086_v102_sync_seq.sql");

/// Splits the v102 file into its run-once head and its idempotent tail (both
/// backends: `migrations/sqlite/0086_v102_sync_seq.sql` and
/// `migrations/postgres/0059_v102_sync_seq.sql`).
pub const MIGRATION_V102_ONCE_MARKER: &str = "-- @@v102-once@@";

/// The replicated `memories` columns whose real change bumps `sync_seq`, in
/// trigger order. SSOT for the column lists of `memories_sync_seq_au` in both
/// migration files (pinned by `tests/federation_sync_seq_9082.rs`).
///
/// The trigger names every column, so `ALTER TABLE memories DROP COLUMN` (or
/// `RENAME COLUMN`) of any of them fails while the trigger exists (sqlite:
/// "error in trigger memories_sync_seq_au after drop column"). A migration or
/// fixture that drops or renames one runs [`SQL_DROP_SYNC_SEQ_TRIGGERS`] first
/// and recreates the triggers after (the v102 tail is idempotent and recreates
/// them) (#9176 F2).
pub const SYNC_SEQ_BUMP_COLUMNS: [&str; 25] = [
    "tier",
    field::NAMESPACE,
    "title",
    "content",
    "tags",
    "priority",
    field::CONFIDENCE,
    "source",
    field::CREATED_AT,
    field::UPDATED_AT,
    "metadata",
    field::REFLECTION_DEPTH,
    field::MEMORY_KIND,
    field::ENTITY_ID,
    field::PERSONA_VERSION,
    "citations",
    field::SOURCE_URI,
    field::SOURCE_SPAN,
    field::CONFIDENCE_SOURCE,
    field::CONFIDENCE_SIGNALS,
    "version",
    field::LIFECYCLE_STATE,
    field::VALID_FROM,
    field::VALID_UNTIL,
    field::ENCRYPTED_ENVELOPE,
];

/// Names of the two triggers that assign `sync_seq` (same names on both
/// backends; on postgres they are deferred constraint triggers).
pub const SYNC_SEQ_TRIGGERS: [&str; 2] = ["memories_sync_seq_ai", "memories_sync_seq_au"];

/// Drops the sqlite `sync_seq` assignment triggers. See
/// [`SYNC_SEQ_BUMP_COLUMNS`]; the postgres spelling is
/// [`SQL_DROP_SYNC_SEQ_TRIGGERS_PG`].
pub const SQL_DROP_SYNC_SEQ_TRIGGERS: &str = "DROP TRIGGER IF EXISTS memories_sync_seq_ai; \
     DROP TRIGGER IF EXISTS memories_sync_seq_au;";

/// Drops the postgres `sync_seq` triggers whose definition names a bump
/// column (postgres refuses `DROP COLUMN` of a column a trigger depends on).
/// The v102 tail recreates them on the next migrate.
pub const SQL_DROP_SYNC_SEQ_TRIGGERS_PG: &str = "DROP TRIGGER IF EXISTS memories_sync_seq_ai ON memories; \
     DROP TRIGGER IF EXISTS memories_sync_seq_au ON memories;";

/// Most rows one sequence page returns (both backends; the postgres store
/// clamps to the same value, `STORE_LIST_MAX_LIMIT_SAL`).
pub const SEQ_PAGE_LIMIT_MAX: usize = 10_000;

/// Clamp a requested page size to `1..=SEQ_PAGE_LIMIT_MAX`, so `limit=0`
/// still makes progress on both backends (#9176 S4).
#[must_use]
pub fn clamp_seq_limit(limit: usize) -> usize {
    limit.clamp(1, SEQ_PAGE_LIMIT_MAX)
}

/// Why a row the walk examined was not served although it is visible.
pub const SEQ_ROW_UNDECRYPTABLE: &str = "undecryptable";

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
    // A counter created before `node_identity` existed gains the column here
    // (sqlite has no ADD COLUMN IF NOT EXISTS).
    let has_identity: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM pragma_table_info('sync_seq_counter') \
               WHERE name = 'node_identity')",
            [],
            |row| row.get(0),
        )
        .context("probe sync_seq_counter.node_identity")?;
    if !has_identity {
        conn.execute_batch("ALTER TABLE sync_seq_counter ADD COLUMN node_identity TEXT")
            .context("add sync_seq_counter.node_identity")?;
    }
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
    /// Visible rows this node could not decrypt, as `(sync_seq, id)`. They are
    /// passed (the walk must not stall on them) and the handler logs each one
    /// with [`SEQ_ROW_UNDECRYPTABLE`]; a later replicated change (a key
    /// rotation rewrites `encrypted_envelope`, a bump column) re-offers the
    /// row under a new seq (#9176 S5).
    pub undecryptable: Vec<(i64, String)>,
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
    let limit_i = i64::try_from(clamp_seq_limit(limit)).unwrap_or(i64::MAX);
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
            let id: String = row.get("id")?;
            Ok((seq, Some(super::row_to_memory_scan(row)?.ok_or(id))))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let raw_count = rows.len();
    let next_seq = rows.last().map_or(effective_after, |(seq, _)| *seq);
    let mut memories = Vec::with_capacity(raw_count);
    let mut undecryptable = Vec::new();
    for (seq, served) in rows {
        match served {
            Some(Ok(mem)) => memories.push(mem),
            Some(Err(id)) => undecryptable.push((seq, id)),
            None => {}
        }
    }
    Ok(SeqPage {
        memories,
        undecryptable,
        raw_count,
        next_seq,
        effective_after,
        head,
    })
}

/// Give the database a fresh epoch, so every puller's stored `last_seq`
/// against this node is treated as foreign and the walk restarts at 0.
///
/// The runtime entry: it is record-stop gated (#9176 B7). The open-time
/// re-mint after a restore runs inside [`bind_node_identity`], reached only
/// from [`bind_at_open`].
///
/// # Errors
/// [`crate::storage::StorageError::RecordStopped`] (or the other
/// [`crate::storage::record_stop::gate_storage_conn`] refusals) while the
/// record plane is stopped; fails closed when the counter row is missing.
pub fn regenerate_seq_epoch(conn: &Connection) -> Result<String> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
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

/// The open-time sync_seq bind of a read-write open of `db` (#9082, #9176).
///
/// One entry for the open funnel: it consumes an armed epoch reset (a
/// restore published this file) and binds the epoch to the file's identity
/// (a copy carries another file's). Both writes run in [`bind_node_identity`],
/// the one record-stop-exempt writer, so an open completes under record-stop;
/// the sidecar is removed only after the new epoch is committed. A database
/// that predates v102 has no counter: the migration that just ran minted a
/// fresh epoch, so the sidecar is only removed.
///
/// # Errors
/// The sidecar's existence cannot be read, the counter cannot be read or
/// updated, or the sidecar cannot be removed; the open fails closed rather
/// than serve a restored or copied database under its old epoch.
pub(super) fn bind_at_open(conn: &Connection, db: &std::path::Path) -> Result<()> {
    let marker = epoch_reset_marker_path(db);
    let restored = match marker.try_exists() {
        Ok(found) => found,
        Err(e) => {
            return Err(anyhow!(
                "cannot tell whether {} exists ({e}) - refusing to serve a possibly \
                 restored database under its old sync_seq epoch (#9082)",
                marker.display()
            ));
        }
    };
    let bind = if restored {
        Rebind::Restored
    } else {
        Rebind::OnIdentityChange
    };
    bind_node_identity(conn, sqlite_node_identity(db).as_deref(), bind)?;
    if restored {
        std::fs::remove_file(&marker)
            .with_context(|| format!("removing the epoch-reset sidecar {}", marker.display()))?;
    }
    Ok(())
}

/// Why [`bind_node_identity`] may re-mint the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rebind {
    /// Only when the stored identity differs (a copy of another database).
    OnIdentityChange,
    /// Always: a restore published a snapshot over this file (#9082).
    Restored,
}

/// The restore-sensitive identity of the database file at `db`: its inode on
/// unix (a copy, a `mv` of a copy or a restore onto another host gets a new
/// one). `None` where the platform has no inode or the file cannot be
/// stat'ed; the bind is then skipped.
#[must_use]
pub fn sqlite_node_identity(db: &std::path::Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(db)
            .ok()
            .map(|m| format!("ino:{}", m.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = db;
        None
    }
}

/// #9176 F6: bind the seq epoch to `identity` on a read-write open. A first
/// bind (NULL) records it; a different stored value means this file is a
/// copy of another database, so the epoch is re-minted and every puller
/// walks it again from 0. [`Rebind::Restored`] re-mints whatever is stored.
/// Returns the new epoch when one was minted.
///
/// Open-time only and record-stop exempt (B7 allowlist row, the #3172
/// open-time precedent): private, reached only from [`bind_at_open`].
///
/// # Errors
/// The counter cannot be read or updated, or a restore finds no counter
/// row; the open fails closed rather than serve a copied or restored
/// database under its old epoch.
fn bind_node_identity(
    conn: &Connection,
    identity: Option<&str>,
    bind: Rebind,
) -> Result<Option<String>> {
    let has_counter: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' \
           AND name = 'sync_seq_counter')",
        [],
        |row| row.get(0),
    )?;
    if !has_counter {
        return Ok(None);
    }
    if bind == Rebind::Restored {
        let epoch: Option<String> = conn
            .query_row(
                "UPDATE sync_seq_counter SET epoch = lower(hex(randomblob(16))), \
                   node_identity = COALESCE(?1, node_identity) \
                 WHERE id = 1 RETURNING epoch",
                [identity],
                |row| row.get(0),
            )
            .optional()?;
        let epoch = epoch.ok_or_else(|| anyhow!(SYNC_SEQ_COUNTER_MISSING))?;
        tracing::warn!(
            target: crate::federation::peer::FED_LOG_TARGET,
            epoch = %epoch,
            "restored database: sync_seq epoch regenerated, pullers re-walk from 0 (#9082)"
        );
        return Ok(Some(epoch));
    }
    let Some(identity) = identity else {
        return Ok(None);
    };
    let stored: Option<Option<String>> = conn
        .query_row(
            "SELECT node_identity FROM sync_seq_counter WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match stored {
        None => Ok(None),
        Some(Some(prev)) if prev == identity => Ok(None),
        Some(None) => {
            conn.execute(
                "UPDATE sync_seq_counter SET node_identity = ?1 \
                 WHERE id = 1 AND node_identity IS NULL",
                [identity],
            )?;
            Ok(None)
        }
        Some(Some(_)) => {
            // The guard on the old value makes a concurrent second opener of
            // the same copy a no-op instead of a second re-mint.
            let epoch: Option<String> = conn
                .query_row(
                    "UPDATE sync_seq_counter SET node_identity = ?1, \
                       epoch = lower(hex(randomblob(16))) \
                     WHERE id = 1 AND node_identity IS NOT ?1 RETURNING epoch",
                    [identity],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(epoch) = epoch else {
                return Ok(None);
            };
            tracing::warn!(
                target: crate::federation::peer::FED_LOG_TARGET,
                epoch = %epoch,
                "database file changed identity since the last open (a copy): \
                 sync_seq epoch regenerated, pullers re-walk from 0 (#9176)"
            );
            Ok(Some(epoch))
        }
    }
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
/// or a head below the old cursor) legitimately lowers it. Record-stop gated
/// (#9176 B7): a stopped record plane moves no cursor.
///
/// # Errors
/// [`crate::storage::StorageError::RecordStopped`] (or the other
/// [`crate::storage::record_stop::gate_storage_conn`] refusals) while the
/// record plane is stopped; a negative `last_seq` or a SQL failure.
pub fn sync_pull_seq_set(
    conn: &Connection,
    agent_id: &str,
    peer_id: &str,
    last_seq: i64,
    seq_epoch: &str,
) -> Result<()> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
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
