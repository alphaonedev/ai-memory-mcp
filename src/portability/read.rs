// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2006 — the net-new full read-all surface the integrity exporter needs.
//!
//! The v1 export core (`storage::export_all` / `export_links`) covers memories
//! + links; the signed-class read-alls that already exist are reused directly
//! (`signed_events::list_signed_events`, `storage::model_attest::list`,
//! `governance::rules_store::list`, `storage::list_agents`,
//! `storage::read_lineage`). This module fills the THREE gaps:
//!
//! - `forget_tombstones` — the table had no row struct AND no read-all (only a
//!   `memory_is_tombstoned` existence probe), so both are net-new here.
//! - `memory_revisions` — [`crate::revisions::RevisionLeaf`] exists but has no
//!   read-all, and it deliberately omits the storage-filled `prev_hash` +
//!   `sequence` columns; L2 re-verify (the revision-chain recompute) needs
//!   BOTH, so [`RevisionRow`] carries the leaf alongside them.
//! - `agent_lineage` — [`crate::storage::read_lineage`] is per-agent; the
//!   exporter needs every agent, so [`read_all_agent_lineage`] sweeps
//!   `SELECT DISTINCT agent_id` and flattens.
//!
//! These are storage reads only (no encoding); the hex DTOs in the emit path
//! consume them.

use anyhow::{Result, anyhow};
use rusqlite::Connection;

use crate::identity::lineage::LineageRecord;
use crate::revisions::{RecordKind, RevisionLeaf};

/// One `forget_tombstones` row — the signed erasure receipt (spec §V2-2.3):
/// identity + time + signature, NEVER a content fingerprint (a fingerprint
/// would re-leak the erased row). The `signature` is `None` on a daemon with
/// no audit key installed (same posture as `signed_events` / revisions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgetTombstone {
    /// The erased memory's uuid.
    pub memory_id: String,
    /// The erased row's namespace.
    pub namespace: String,
    /// RFC3339 instant the forget was recorded.
    pub forgotten_at: String,
    /// The agent that caused the erasure, or `None`.
    pub agent_id: Option<String>,
    /// Ed25519 signature over
    /// [`crate::storage::forget_tombstone_signable_bytes`], or `None`.
    pub signature: Option<Vec<u8>>,
}

/// A `memory_revisions` row for export: the [`RevisionLeaf`] plus the two
/// storage-filled chain columns it omits (`prev_hash`, `sequence`) that the
/// L2 revision-chain re-verify needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRow {
    /// The identity-only revision leaf.
    pub leaf: RevisionLeaf,
    /// v72 — SHA-256 over the canonical bytes of the prior leaf (or the
    /// zero hash for the first).
    pub prev_hash: Vec<u8>,
    /// v72 — monotonic chain rank (the ordering authority for export).
    pub sequence: i64,
}

/// One exported `agent_lineage` record: the signed key-succession
/// [`LineageRecord`] plus its detached Ed25519 signature (spec §V2-2.4).
#[derive(Debug, Clone)]
pub struct LineageExport {
    /// The identity this record belongs to (also `record.agent_id`).
    pub agent_id: String,
    /// The signed succession/custody/revocation record.
    pub record: LineageRecord,
    /// Ed25519 signature over the record's canonical bytes.
    pub signature: Vec<u8>,
}

/// Read EVERY `forget_tombstones` row, ordered deterministically
/// (`forgotten_at`, then `memory_id`) so the export is byte-stable.
///
/// # Errors
/// The underlying `rusqlite` query fails.
pub fn read_all_forget_tombstones(conn: &Connection) -> Result<Vec<ForgetTombstone>> {
    let mut stmt = conn.prepare(
        "SELECT memory_id, namespace, forgotten_at, agent_id, signature \
         FROM forget_tombstones \
         ORDER BY forgotten_at ASC, memory_id ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ForgetTombstone {
            memory_id: r.get(0)?,
            namespace: r.get(1)?,
            forgotten_at: r.get(2)?,
            agent_id: r.get(3)?,
            signature: r.get(4)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Read EVERY `memory_revisions` row, ordered by `sequence` ASC (spec
/// §V2-2.2 — a streaming importer chains without buffering).
///
/// # Errors
/// The query fails, or a row carries a `kind` outside the closed
/// [`RecordKind`] vocabulary (a corrupt DB — the table's CHECK constraint
/// should make this unreachable).
pub fn read_all_memory_revisions(conn: &Connection) -> Result<Vec<RevisionRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, memory_id, kind, prior_version, namespace, agent_id, \
                created_at, signature, prev_hash, sequence \
         FROM memory_revisions \
         ORDER BY sequence ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,          // id
            r.get::<_, String>(1)?,          // memory_id
            r.get::<_, String>(2)?,          // kind
            r.get::<_, Option<i64>>(3)?,     // prior_version
            r.get::<_, String>(4)?,          // namespace
            r.get::<_, Option<String>>(5)?,  // agent_id
            r.get::<_, String>(6)?,          // created_at
            r.get::<_, Option<Vec<u8>>>(7)?, // signature
            r.get::<_, Vec<u8>>(8)?,         // prev_hash
            r.get::<_, i64>(9)?,             // sequence
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            memory_id,
            kind,
            prior_version,
            namespace,
            agent_id,
            created_at,
            signature,
            prev_hash,
            sequence,
        ) = row?;
        let kind = RecordKind::from_str_opt(&kind)
            .ok_or_else(|| anyhow!("memory_revisions row {id} has unknown kind {kind:?}"))?;
        out.push(RevisionRow {
            leaf: RevisionLeaf {
                id,
                memory_id,
                kind,
                prior_version,
                namespace,
                agent_id,
                created_at,
                signature,
            },
            prev_hash,
            sequence,
        });
    }
    Ok(out)
}

/// Sweep EVERY agent's lineage: `SELECT DISTINCT agent_id FROM agent_lineage`,
/// then reuse [`crate::storage::read_lineage`] per agent and flatten. Records
/// are ordered by `(agent_id, epoch)` so the export is byte-stable and a
/// verifier sees each chain in ascending-epoch order.
///
/// Returns an empty vec when the `agent_lineage` table is absent (pre-v76) —
/// mirroring [`crate::storage::read_lineage`]'s own table-absent tolerance.
///
/// # Errors
/// A per-agent [`crate::storage::read_lineage`] read fails.
pub fn read_all_agent_lineage(conn: &Connection) -> Result<Vec<LineageExport>> {
    let table_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = 'agent_lineage')",
        [],
        |r| r.get(0),
    )?;
    if !table_exists {
        return Ok(Vec::new());
    }
    let agent_ids = {
        let mut stmt =
            conn.prepare("SELECT DISTINCT agent_id FROM agent_lineage ORDER BY agent_id ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for id in rows {
            ids.push(id?);
        }
        ids
    };
    let mut out = Vec::new();
    for agent_id in agent_ids {
        // `read_lineage` returns records in ascending-epoch order.
        for (record, signature) in crate::storage::read_lineage(conn, &agent_id)? {
            out.push(LineageExport {
                agent_id: agent_id.clone(),
                record,
                signature,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_db() -> Connection {
        let dir = tempfile::Builder::new()
            .prefix("issue-2006-read-")
            .tempdir_in({
                let root = std::env::current_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
                    .join(".local-runs")
                    .join("issue-2006-read");
                std::fs::create_dir_all(&root).ok();
                root
            })
            .expect("tempdir under .local-runs");
        let path = dir.path().join("read.db");
        drop(crate::db::open(&path).expect("init db"));
        // Keep the tempdir alive for the connection's lifetime by leaking it —
        // the .local-runs root is the project scratch space.
        std::mem::forget(dir);
        crate::db::open(&path).expect("open db")
    }

    #[test]
    fn read_alls_on_a_fresh_db_are_empty_not_error() {
        // A migrated-but-empty DB: the three read-alls must return empty vecs
        // (the tables exist post-migration; lineage tolerates absence too),
        // never error — the exporter emits empty arrays for empty classes.
        let conn = empty_db();
        assert!(
            read_all_forget_tombstones(&conn)
                .expect("tombstones")
                .is_empty()
        );
        assert!(
            read_all_memory_revisions(&conn)
                .expect("revisions")
                .is_empty()
        );
        assert!(read_all_agent_lineage(&conn).expect("lineage").is_empty());
    }
}
