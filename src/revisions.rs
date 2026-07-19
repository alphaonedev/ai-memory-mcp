// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G6 (#1823) — the append-only spine's signed revision ledger.
//!
//! Every supersede / tombstone / forget / archive / expire / evict /
//! consolidate transition appends ONE signed, identity-only leaf to the
//! `memory_revisions` table via [`append_revision_leaf`] (sqlite) or
//! `pg_append_revision_leaf_in_tx` (postgres). The leaf carries the
//! memory's IDENTITY (`memory_id`, `kind`, `prior_version`, `namespace`,
//! `agent_id`, `created_at`) and NEVER its content — a content
//! fingerprint would re-leak an erased row, the same posture as
//! [`crate::storage::forget_tombstone_signable_bytes`].
//!
//! Each leaf carries a `prev_hash` + `sequence` pair mirroring
//! [`crate::signed_events`], so the ledger is a verifiable hash chain an
//! auditor can replay from the stored columns alone.
//!
//! STEP 1 (foundation): this module exposes the [`RecordKind`] vocabulary
//! and the leaf-append primitive. The mutation sites are NOT yet routed
//! through it — that is step 2+.

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::signed_events::ZERO_HASH;

/// Field separator for [`canonical_revision_chain_bytes`]. ASCII 0x1F
/// ("Unit Separator") — present in neither RFC3339 timestamps, UUID-ish
/// ids, nor namespace strings, so it cannot collide with field content.
const FIELD_SEP: u8 = 0x1F;

/// The seven append-only revision kinds. Mirrors the `kind` CHECK
/// constraint on `memory_revisions` (sqlite migration v72 / postgres
/// `0031_v07_memory_revisions.sql`) — the on-wire string and this enum
/// are a single source of truth and MUST stay in lockstep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// A new version superseded the prior one (the prior row is archived).
    Supersede,
    /// The memory was tombstoned (logical delete, identity retained).
    Tombstone,
    /// The memory was forgotten (erasure — content gone, identity kept).
    Forget,
    /// The memory was archived (moved to cold storage).
    Archive,
    /// The memory expired (TTL reached).
    Expire,
    /// The memory was evicted (capacity / quota pressure).
    Evict,
    /// The memory was consolidated into / merged with another.
    Consolidate,
}

impl RecordKind {
    /// All seven kinds, in declaration order. The CHECK constraint on
    /// `memory_revisions.kind` is pinned to exactly these strings.
    pub const ALL: [RecordKind; 7] = [
        RecordKind::Supersede,
        RecordKind::Tombstone,
        RecordKind::Forget,
        RecordKind::Archive,
        RecordKind::Expire,
        RecordKind::Evict,
        RecordKind::Consolidate,
    ];

    /// The canonical on-wire / on-disk string (the `kind` column value).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordKind::Supersede => "SUPERSEDE",
            RecordKind::Tombstone => "TOMBSTONE",
            RecordKind::Forget => "FORGET",
            RecordKind::Archive => "ARCHIVE",
            RecordKind::Expire => "EXPIRE",
            RecordKind::Evict => "EVICT",
            RecordKind::Consolidate => "CONSOLIDATE",
        }
    }

    /// Parse a `kind` column value back into the enum. Returns `None` for
    /// any string outside the CHECK-constrained vocabulary.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "SUPERSEDE" => Some(RecordKind::Supersede),
            "TOMBSTONE" => Some(RecordKind::Tombstone),
            "FORGET" => Some(RecordKind::Forget),
            "ARCHIVE" => Some(RecordKind::Archive),
            "EXPIRE" => Some(RecordKind::Expire),
            "EVICT" => Some(RecordKind::Evict),
            "CONSOLIDATE" => Some(RecordKind::Consolidate),
            _ => None,
        }
    }
}

/// An identity-only revision leaf. The `prev_hash` + `sequence` chain
/// columns are NOT carried here — they are computed by the append
/// primitive at insert time (callers MUST NOT pre-populate them), exactly
/// as [`crate::signed_events::SignedEvent`] does for the audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionLeaf {
    /// Stable id for this revision leaf (the primary key).
    pub id: String,
    /// The memory this transition concerns.
    pub memory_id: String,
    /// Which append-only transition this leaf records.
    pub kind: RecordKind,
    /// The `version` of the memory immediately before this transition, or
    /// `None` when not applicable / unknown.
    pub prior_version: Option<i64>,
    /// The memory's namespace.
    pub namespace: String,
    /// The agent that caused the transition, or `None` for an
    /// unidentified caller.
    pub agent_id: Option<String>,
    /// RFC3339 instant the transition occurred.
    pub created_at: String,
    /// Ed25519 signature over [`Self::signable_bytes`], or `None` when the
    /// daemon has no audit key installed (same posture as
    /// `signed_events` / `forget_tombstones`).
    pub signature: Option<Vec<u8>>,
}

impl RevisionLeaf {
    /// Build an UNSIGNED leaf. Call [`Self::signed`] to attach the
    /// Ed25519 signature with the daemon audit key.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        memory_id: impl Into<String>,
        kind: RecordKind,
        prior_version: Option<i64>,
        namespace: impl Into<String>,
        agent_id: Option<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            memory_id: memory_id.into(),
            kind,
            prior_version,
            namespace: namespace.into(),
            agent_id,
            created_at: created_at.into(),
            signature: None,
        }
    }

    /// The canonical IDENTITY-ONLY signable bytes for this leaf. NEVER
    /// includes content (a content fingerprint would re-leak an erased
    /// row). See [`revision_leaf_signable_bytes`].
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        revision_leaf_signable_bytes(
            &self.memory_id,
            self.kind,
            self.prior_version,
            &self.namespace,
            self.agent_id.as_deref(),
            &self.created_at,
        )
    }

    /// Attach the Ed25519 signature using the same daemon audit key the
    /// `signed_events` + `forget_tombstones` paths use
    /// ([`crate::governance::audit::try_sign_audit_payload`]). When the
    /// daemon has no audit key the leaf stays unsigned (`signature =
    /// None`), exactly as the audit chain does.
    #[must_use]
    pub fn signed(mut self) -> Self {
        let bytes = self.signable_bytes();
        self.signature =
            crate::governance::audit::try_sign_audit_payload(&bytes).map(|(sig, _)| sig);
        self
    }
}

/// The canonical IDENTITY-ONLY signable bytes for a revision leaf —
/// mirrors [`crate::storage::forget_tombstone_signable_bytes`]: a
/// versioned domain-separation prefix followed by the delimiter-joined
/// identity fields. Deterministic, so a receiver can recompute + verify
/// the Ed25519 signature against the signer's enrolled key. NEVER carries
/// content.
#[must_use]
pub fn revision_leaf_signable_bytes(
    memory_id: &str,
    kind: RecordKind,
    prior_version: Option<i64>,
    namespace: &str,
    agent_id: Option<&str>,
    created_at: &str,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"memory-revision-v1\x00";
    let prior = prior_version.map(|v| v.to_string()).unwrap_or_default();
    let agent = agent_id.unwrap_or("");
    let mut bytes = Vec::with_capacity(
        DOMAIN.len()
            + memory_id.len()
            + kind.as_str().len()
            + prior.len()
            + namespace.len()
            + agent.len()
            + created_at.len()
            + 5,
    );
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(memory_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(kind.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(prior.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(agent.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(created_at.as_bytes());
    bytes
}

/// Canonical chain-bytes encoding of a stored leaf at a given `sequence`,
/// over which the NEXT row's `prev_hash` is computed. Mirrors
/// [`crate::signed_events::canonical_chain_bytes`] — byte-stable so an
/// auditor can replay the chain from the stored columns alone.
#[must_use]
pub fn canonical_revision_chain_bytes(leaf: &RevisionLeaf, sequence: i64) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(
        leaf.id.len()
            + leaf.memory_id.len()
            + leaf.kind.as_str().len()
            + leaf.namespace.len()
            + leaf.agent_id.as_deref().map_or(0, str::len)
            + leaf.created_at.len()
            + leaf.signature.as_ref().map_or(0, Vec::len)
            + 16
            + 8, // eight separators + headroom
    );
    out.extend_from_slice(leaf.id.as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(leaf.memory_id.as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(leaf.kind.as_str().as_bytes());
    out.push(FIELD_SEP);
    if let Some(v) = leaf.prior_version {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.push(FIELD_SEP);
    out.extend_from_slice(leaf.namespace.as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(leaf.agent_id.as_deref().unwrap_or("").as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(leaf.created_at.as_bytes());
    out.push(FIELD_SEP);
    if let Some(sig) = leaf.signature.as_ref() {
        out.extend_from_slice(sig);
    }
    out.push(FIELD_SEP);
    out.extend_from_slice(&sequence.to_be_bytes());
    out
}

/// Read the `memory_revisions` chain head — `(max_sequence,
/// prev_canonical_hash)`. Returns `(0, ZERO_HASH)` on an empty table.
/// Mirrors [`crate::signed_events`]' `read_chain_head`.
///
/// v0.9.0 G5b (#1822) — `pub` so the audit-head witness emitter
/// ([`crate::governance::audit`]) can bind the `memory_revisions` head into
/// the dual-chain [`crate::models::ConditionType::AuditHeadWitness`] anchor
/// alongside the `signed_events` head.
pub fn read_revision_chain_head(conn: &Connection) -> Result<(i64, [u8; 32])> {
    let head: Option<(
        String,
        String,
        String,
        Option<i64>,
        String,
        Option<String>,
        String,
        Option<Vec<u8>>,
        i64,
    )> = conn
        .query_row(
            "SELECT id, memory_id, kind, prior_version, namespace, agent_id, created_at, \
                    signature, sequence \
             FROM memory_revisions \
             ORDER BY sequence DESC \
             LIMIT 1",
            [],
            |r| {
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
            },
        )
        .optional()
        .context("read memory_revisions chain head")?;

    match head {
        None => Ok((0, ZERO_HASH)),
        Some((
            id,
            memory_id,
            kind_s,
            prior_version,
            namespace,
            agent_id,
            created_at,
            signature,
            sequence,
        )) => {
            let kind = RecordKind::from_str_opt(&kind_s).ok_or_else(|| {
                anyhow!("memory_revisions chain head has unknown kind {kind_s:?}")
            })?;
            let leaf = RevisionLeaf {
                id,
                memory_id,
                kind,
                prior_version,
                namespace,
                agent_id,
                created_at,
                signature,
            };
            let canon = canonical_revision_chain_bytes(&leaf, sequence);
            let mut hasher = Sha256::new();
            hasher.update(&canon);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&hasher.finalize());
            Ok((sequence, digest))
        }
    }
}

/// v1.0.0 #2202 (CWE-354) — recompute
/// `SHA-256(canonical_revision_chain_bytes(row, sequence))` as lowercase hex for
/// the SURVIVING `memory_revisions` row at `sequence`, or `None` when no row
/// survives there (or its `kind` is unknown → the head-hash lane withholds
/// `Unknown`). The `memory_revisions` twin of
/// [`crate::signed_events`]'s `recompute_signed_row_hash_at`: the #1873 witness
/// head-hash lane compares the witnessed revision head hash against THIS
/// recompute AT the anchored sequence. `canonical_revision_chain_bytes` excludes
/// `prev_hash` and rows are append-immutable, so the anchored row's hash is
/// stable under later appends and comparing whenever `anchored_seq <= db_head`
/// can never false-positive on a clean chain.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn recompute_revision_row_hash_at(conn: &Connection, sequence: i64) -> Result<Option<String>> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        String,
        Option<i64>,
        String,
        Option<String>,
        String,
        Option<Vec<u8>>,
    )> = conn
        .query_row(
            "SELECT id, memory_id, kind, prior_version, namespace, agent_id, created_at, \
                    signature \
             FROM memory_revisions \
             WHERE sequence = ?1 \
             LIMIT 1",
            [sequence],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )
        .optional()
        .context("recompute memory_revisions row at sequence")?;
    let Some((id, memory_id, kind_s, prior_version, namespace, agent_id, created_at, signature)) =
        row
    else {
        return Ok(None);
    };
    let Some(kind) = RecordKind::from_str_opt(&kind_s) else {
        return Ok(None);
    };
    let leaf = RevisionLeaf {
        id,
        memory_id,
        kind,
        prior_version,
        namespace,
        agent_id,
        created_at,
        signature,
    };
    let canon = canonical_revision_chain_bytes(&leaf, sequence);
    let mut hasher = Sha256::new();
    hasher.update(&canon);
    Ok(Some(crate::signed_events::hex_lower(
        hasher.finalize().as_slice(),
    )))
}

/// Append ONE signed identity-only leaf to `memory_revisions`, computing
/// the `prev_hash` + `sequence` chain columns at insert time. The caller
/// owns the transaction (this is the `_no_tx` / in-tx shape, mirroring
/// [`crate::signed_events::append_signed_event_no_tx`]) so the leaf can be
/// appended in the SAME transaction as the data mutation it records — the
/// chain never lags the data and a rollback discards both.
///
/// # Errors
///
/// Propagates the chain-head read error or the INSERT error. Callers MUST
/// roll back their own transaction on error.
pub fn append_revision_leaf(conn: &Connection, leaf: &RevisionLeaf) -> Result<()> {
    let (max_seq, prev_hash) =
        read_revision_chain_head(conn).context("append revision leaf: read head")?;
    let next_seq = max_seq + 1;
    conn.execute(
        "INSERT INTO memory_revisions \
            (id, memory_id, kind, prior_version, namespace, agent_id, created_at, \
             signature, prev_hash, sequence) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            leaf.id,
            leaf.memory_id,
            leaf.kind.as_str(),
            leaf.prior_version,
            leaf.namespace,
            leaf.agent_id,
            leaf.created_at,
            leaf.signature,
            prev_hash.to_vec(),
            next_seq,
        ],
    )
    .context("append revision leaf: insert")?;
    Ok(())
}

/// v0.9.0 G6 (#1823) STEP 2 — the gated sqlite convenience used by every
/// sanctioned mutation primitive. When the append-only spine is OFF (the
/// default) this is a NO-OP, so the legacy mutation path stays
/// BYTE-IDENTICAL. When ON it mints a fresh leaf id, signs the
/// identity-only bytes with the daemon audit key (unsigned when no key is
/// installed, same posture as `signed_events`), and appends ONE leaf in
/// the caller's transaction via [`append_revision_leaf`].
///
/// Callers hold the surrounding transaction and MUST emit the leaf in the
/// SAME tx as the mutation it records — BEFORE a destructive delete
/// (capture-then-compact) or alongside an in-place content UPDATE (COW
/// supersede) — so the chain never lags the data and a rollback discards
/// both. Content is NEVER carried (an erased row must not be re-leaked).
///
/// # Errors
///
/// Propagates the chain-head read / INSERT error from
/// [`append_revision_leaf`]. The caller MUST roll back its own transaction.
pub fn emit_revision_leaf_if_enabled(
    conn: &Connection,
    memory_id: &str,
    kind: RecordKind,
    prior_version: Option<i64>,
    namespace: &str,
    agent_id: Option<&str>,
    created_at: &str,
) -> Result<()> {
    if !crate::config::append_only_enabled() {
        return Ok(());
    }
    let leaf = RevisionLeaf::new(
        uuid::Uuid::new_v4().to_string(),
        memory_id,
        kind,
        prior_version,
        namespace,
        agent_id.map(str::to_string),
        created_at,
    )
    .signed();
    append_revision_leaf(conn, &leaf)
}

/// v0.9.0 G13-mem (#1859, COND 1) — the SINGLE predicate that decides
/// whether `consolidate` appends its per-source `CONSOLIDATE` leaf, shared
/// verbatim by BOTH backends (`db::consolidate` here and
/// `PostgresStore::consolidate` via `pg_emit_consolidate_leaf_if_enabled`).
///
/// A leaf is emitted when EITHER spine is on:
///   * `append_only` (#1823 G6) — the capture-then-compact discipline that
///     already emitted the Postgres CONSOLIDATE leaf pre-#1859, OR
///   * `consolidate_tombstone_sources` (#1859 G13) — the lineage-DAG
///     tombstone path, whose acceptance invariant ("a CONSOLIDATE leaf is
///     appended") must hold even when the append-only spine is off. This
///     is the DELIBERATE decoupling COND 1 requires: the gated
///     [`emit_revision_leaf_if_enabled`] helper hard-returns unless
///     `append_only_enabled()`, so routing the lineage emission through it
///     would silently no-op.
///
/// Keying every consolidate emission to this ONE predicate — and calling
/// [`emit_consolidate_leaf`] exactly once per source — is what guarantees
/// EXACTLY ONE leaf per source under every flag combination (never zero
/// when either spine is on, never two when both are).
#[must_use]
pub fn consolidate_leaf_enabled() -> bool {
    crate::config::append_only_enabled() || crate::config::consolidate_tombstone_sources_enabled()
}

/// v0.9.0 G13-mem (#1859, COND 1) — append EXACTLY ONE signed
/// `CONSOLIDATE` leaf for one merged-away source, in the caller's open
/// transaction. The sqlite half of the single emission site; callers gate
/// on [`consolidate_leaf_enabled`] and call this at most once per source.
///
/// # Errors
///
/// Propagates the chain-head read / INSERT error from
/// [`append_revision_leaf`]. The caller MUST roll back its own transaction.
pub fn emit_consolidate_leaf(
    conn: &Connection,
    memory_id: &str,
    prior_version: Option<i64>,
    namespace: &str,
    agent_id: Option<&str>,
    created_at: &str,
) -> Result<()> {
    let leaf = RevisionLeaf::new(
        uuid::Uuid::new_v4().to_string(),
        memory_id,
        RecordKind::Consolidate,
        prior_version,
        namespace,
        agent_id.map(str::to_string),
        created_at,
    )
    .signed();
    append_revision_leaf(conn, &leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_kind_roundtrips_all_seven() {
        for k in RecordKind::ALL {
            assert_eq!(RecordKind::from_str_opt(k.as_str()), Some(k));
        }
        assert_eq!(RecordKind::ALL.len(), 7);
        assert!(RecordKind::from_str_opt("NOPE").is_none());
    }

    #[test]
    fn signable_bytes_are_identity_only_and_domain_prefixed() {
        let b = revision_leaf_signable_bytes(
            "mem-1",
            RecordKind::Supersede,
            Some(3),
            "global",
            Some("ai:alice"),
            "2026-06-30T00:00:00Z",
        );
        assert!(b.starts_with(b"memory-revision-v1\x00"));
        // Identity fields present; no content anywhere in scope.
        let s = String::from_utf8_lossy(&b);
        assert!(s.contains("mem-1"));
        assert!(s.contains("SUPERSEDE"));
        assert!(s.contains("global"));
        assert!(s.contains("ai:alice"));
    }

    #[test]
    fn append_revision_leaf_chains_prev_hash_and_sequence() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE memory_revisions (\
                 id TEXT PRIMARY KEY, memory_id TEXT NOT NULL, kind TEXT NOT NULL, \
                 prior_version INTEGER, namespace TEXT NOT NULL, agent_id TEXT, \
                 created_at TEXT NOT NULL, signature BLOB, prev_hash BLOB NOT NULL, \
                 sequence INTEGER NOT NULL);",
        )
        .unwrap();

        let leaf1 = RevisionLeaf::new(
            "rev-1",
            "mem-1",
            RecordKind::Supersede,
            Some(1),
            "global",
            Some("ai:alice".to_string()),
            "2026-06-30T00:00:00Z",
        );
        append_revision_leaf(&conn, &leaf1).unwrap();
        let leaf2 = RevisionLeaf::new(
            "rev-2",
            "mem-1",
            RecordKind::Tombstone,
            Some(2),
            "global",
            Some("ai:alice".to_string()),
            "2026-06-30T00:00:01Z",
        );
        append_revision_leaf(&conn, &leaf2).unwrap();

        let (seq1, ph1): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT sequence, prev_hash FROM memory_revisions WHERE id = 'rev-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let (seq2, ph2): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT sequence, prev_hash FROM memory_revisions WHERE id = 'rev-2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        // First row anchors to the all-zero head.
        assert_eq!(ph1, ZERO_HASH.to_vec());
        // Second row's prev_hash is the SHA-256 over leaf1's canonical
        // chain bytes at sequence 1 — non-zero, and recomputable.
        let mut hasher = Sha256::new();
        hasher.update(canonical_revision_chain_bytes(&leaf1, 1));
        assert_eq!(ph2, hasher.finalize().as_slice());
    }
}
