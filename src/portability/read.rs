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
use crate::models::{Memory, Tier, field_names};
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

// ── archived_memories (#2571, spec §6.4) ────────────────────────────────────

/// One `archived_memories` row for export (issue #2571) — the v1 spec §6.4
/// class ("same column set as `memories[]`, plus `archived_at` /
/// `archive_reason` / `original_tier` / `original_expires_at` /
/// `embedding` / `embedding_dim`") extended with the v49/#1025
/// atomisation/entity columns and the v84/v87 `embedding_space` /
/// `kind_provenance` additions. The live-shaped columns cross through
/// [`crate::storage::row_to_memory`] — the SAME mapper `export_all` uses for
/// `memories[]` — so content is DECRYPTED at read time exactly like a live
/// export (the envelope never carries ciphertext) and `cid` is always
/// `None`: `archived_memories` never gained the v74 cid columns (content-
/// addressing is a `memories`-only concept).
#[derive(Debug, Clone)]
pub struct ArchivedMemoryRow {
    /// The live-Memory-shaped columns (decrypted content, typed enums).
    pub memory: Memory,
    pub archived_at: String,
    pub archive_reason: String,
    pub original_tier: Option<Tier>,
    pub original_expires_at: Option<String>,
    pub embedding: Option<Vec<u8>>,
    pub embedding_dim: Option<i32>,
    pub embedding_space: Option<String>,
    pub atomised_into: Option<i64>,
    pub atom_of: Option<String>,
    pub mentioned_entity_id: Option<String>,
    pub kind_provenance: Option<String>,
}

/// Read EVERY `archived_memories` row, ordered deterministically
/// (`archived_at`, then `id`) so the export is byte-stable.
///
/// # Errors
/// The underlying `rusqlite` query fails, or a row's at-rest envelope cannot
/// be decrypted (fail-closed — `row_to_memory` uses the SAME
/// completeness-critical policy `export_all` applies to `memories[]`; an
/// export must never silently omit an archived row).
pub fn read_all_archived_memories(conn: &Connection) -> Result<Vec<ArchivedMemoryRow>> {
    let mut stmt =
        conn.prepare("SELECT * FROM archived_memories ORDER BY archived_at ASC, id ASC")?;
    let rows = stmt.query_map([], |row| {
        let memory = crate::storage::row_to_memory(row)?;
        let original_tier = row
            .get::<_, Option<String>>("original_tier")
            .unwrap_or(None)
            .and_then(|s| Tier::from_str(&s));
        Ok(ArchivedMemoryRow {
            memory,
            archived_at: row.get(field_names::ARCHIVED_AT)?,
            archive_reason: row
                .get(field_names::ARCHIVE_REASON)
                .unwrap_or_else(|_| "ttl_expired".to_string()),
            original_tier,
            original_expires_at: row
                .get::<_, Option<String>>("original_expires_at")
                .unwrap_or(None),
            embedding: row.get::<_, Option<Vec<u8>>>("embedding").unwrap_or(None),
            embedding_dim: row
                .get::<_, Option<i32>>(field_names::EMBEDDING_DIM)
                .unwrap_or(None),
            embedding_space: row
                .get::<_, Option<String>>("embedding_space")
                .unwrap_or(None),
            atomised_into: row
                .get::<_, Option<i64>>(field_names::ATOMISED_INTO)
                .unwrap_or(None),
            atom_of: row
                .get::<_, Option<String>>(field_names::ATOM_OF)
                .unwrap_or(None),
            mentioned_entity_id: row
                .get::<_, Option<String>>(field_names::MENTIONED_ENTITY_ID)
                .unwrap_or(None),
            kind_provenance: row
                .get::<_, Option<String>>("kind_provenance")
                .unwrap_or(None),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// ── namespace_meta (#2571, spec §6.1) ───────────────────────────────────────

/// One `namespace_meta` row for export (issue #2571, spec §6.1): the
/// namespace's governance binding (`standard_id` — which memory carries its
/// `CorePolicy` standard) and its explicit hierarchical parent
/// (`parent_namespace`, the chain `build_namespace_chain` walks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceMetaRow {
    pub namespace: String,
    pub standard_id: Option<String>,
    pub parent_namespace: Option<String>,
    pub updated_at: String,
}

/// Read EVERY `namespace_meta` row, ordered by `namespace` ASC so the export
/// is byte-stable.
///
/// # Errors
/// The underlying `rusqlite` query fails.
pub fn read_all_namespace_meta(conn: &Connection) -> Result<Vec<NamespaceMetaRow>> {
    // The table name is derived from the SAME class-name SSOT the export
    // conformance marker uses (`export_scope::OMITTED_CLASS_NAMESPACE_META`)
    // rather than a fresh `"namespace_meta"` literal (pm-v3.1 hardcoded-
    // literal gate; Fable review F1, 2026-08-11).
    let sql = format!(
        "SELECT namespace, standard_id, parent_namespace, updated_at \
         FROM {} ORDER BY namespace ASC",
        crate::export_scope::OMITTED_CLASS_NAMESPACE_META
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| {
        Ok(NamespaceMetaRow {
            namespace: r.get(0)?,
            standard_id: r.get(1)?,
            parent_namespace: r.get(2)?,
            updated_at: r.get(3)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// ── archived_memory_links (#2571, schema v70 / #1771) ───────────────────────

/// One `archived_memory_links` row for export (issue #2571) — the v70
/// (#1771) archive-link snapshot: a memory's links preserved at the moment
/// it was archived, so `restore_archived` can re-attach them. Deliberately
/// carries no FK (mirrors the table itself, `src/storage/migrations.rs` v70
/// arm), so a snapshot referencing an id absent at import time is a
/// harmless inert row, never an FK-abort risk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedMemoryLinkRow {
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
    pub created_at: String,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub observed_by: Option<String>,
    pub signature: Option<Vec<u8>>,
    pub attest_level: Option<String>,
    pub archived_at: String,
}

/// Read EVERY `archived_memory_links` row, ordered deterministically so the
/// export is byte-stable.
///
/// # Errors
/// The underlying `rusqlite` query fails.
pub fn read_all_archived_memory_links(conn: &Connection) -> Result<Vec<ArchivedMemoryLinkRow>> {
    let mut stmt = conn.prepare(
        "SELECT source_id, target_id, relation, created_at, valid_from, valid_until, \
                observed_by, signature, attest_level, archived_at \
         FROM archived_memory_links \
         ORDER BY archived_at ASC, source_id ASC, target_id ASC, relation ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ArchivedMemoryLinkRow {
            source_id: r.get(0)?,
            target_id: r.get(1)?,
            relation: r.get(2)?,
            created_at: r.get(3)?,
            valid_from: r.get(4)?,
            valid_until: r.get(5)?,
            observed_by: r.get(6)?,
            signature: r.get(7)?,
            attest_level: r.get(8)?,
            archived_at: r.get(9)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
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
        // A migrated-but-empty DB: the read-alls must return empty vecs (the
        // tables exist post-migration; lineage tolerates absence too), never
        // error — the exporter emits empty arrays for empty classes.
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
        // #2571 — archived_memories / namespace_meta / archived_memory_links.
        assert!(
            read_all_archived_memories(&conn)
                .expect("archived memories")
                .is_empty()
        );
        assert!(
            read_all_namespace_meta(&conn)
                .expect("namespace meta")
                .is_empty()
        );
        assert!(
            read_all_archived_memory_links(&conn)
                .expect("archived memory links")
                .is_empty()
        );
    }

    /// #2571 — an archived row's live-shaped columns round-trip through
    /// `row_to_memory` exactly like a `memories[]` export: decrypted content,
    /// typed enums, `cid` always `None` (the table never gained the v74 cid
    /// columns).
    #[test]
    fn read_all_archived_memories_round_trips_the_archive_shape() {
        let conn = empty_db();
        crate::storage::insert(
            &conn,
            &Memory {
                id: "m1".into(),
                title: "t".into(),
                content: "c".into(),
                namespace: "ns".into(),
                ..Default::default()
            },
        )
        .expect("seed live row");
        crate::storage::archive_memory_no_tx(&conn, "m1", Some("manual")).expect("archive");

        let rows = read_all_archived_memories(&conn).expect("read archived");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.memory.id, "m1");
        assert_eq!(row.memory.title, "t");
        assert_eq!(row.memory.content, "c");
        assert_eq!(
            row.memory.cid, None,
            "archived_memories carries no cid column"
        );
        assert_eq!(row.archive_reason, "manual");
        assert!(!row.archived_at.is_empty());
    }

    /// #2571 — namespace_meta and archived_memory_links read-alls surface a
    /// seeded row with every column intact.
    #[test]
    fn read_all_namespace_meta_and_archived_links_surface_seeded_rows() {
        let conn = empty_db();
        crate::storage::insert(
            &conn,
            &Memory {
                id: "std-mem-1".into(),
                title: "standard".into(),
                content: "policy".into(),
                namespace: "team/eng".into(),
                ..Default::default()
            },
        )
        .expect("seed standard-carrying memory");
        crate::storage::set_namespace_standard(&conn, "team/eng", "std-mem-1", None)
            .expect("seed namespace_meta");
        let ns_rows = read_all_namespace_meta(&conn).expect("read namespace_meta");
        assert_eq!(ns_rows.len(), 1);
        assert_eq!(ns_rows[0].namespace, "team/eng");
        assert_eq!(ns_rows[0].standard_id.as_deref(), Some("std-mem-1"));

        conn.execute(
            "INSERT INTO archived_memory_links \
                (source_id, target_id, relation, created_at, archived_at) \
             VALUES ('a', 'b', 'related_to', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')",
            [],
        )
        .expect("seed archived_memory_links");
        let link_rows = read_all_archived_memory_links(&conn).expect("read archived links");
        assert_eq!(link_rows.len(), 1);
        assert_eq!(link_rows[0].source_id, "a");
        assert_eq!(link_rows[0].target_id, "b");
        assert_eq!(link_rows[0].relation, "related_to");
    }
}
