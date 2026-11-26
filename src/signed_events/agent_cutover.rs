// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 (signed writes) — the agent-attribution cutover marker that schema
//! step v103 appends (`3-agent vote (71472661)` V1-AGENT-SIG-SCHEMA decision A,
//! conditions S-1 and S-3; V1V2-AGENT-ROW-VERIFY condition B-5).
//!
//! The marker is ONE `signed_events` row of type [`AGENT_CUTOVER_EVENT_TYPE`],
//! appended at the chain head by the v103 migration step, in the same
//! transaction as the version stamp, and only when the chain is non-empty. Its
//! `payload_hash` commits to:
//!
//! - its own chain position (`sequence`);
//! - the canonical chain hash of the row before it (the preceding head);
//! - the count of agent-labelled rows (`self_signed`, `signed_by_peer`,
//!   `peer_attested`) below it: the legacy rows written before the cutover.
//!
//! The marker carries NO signature: migrations run without the daemon key.
//! Its authority is the recompute. Every committed value is a deterministic
//! function of the chain prefix, so the walk re-derives the hash from the rows
//! below the marker and accepts it only on an exact match. A changed count, a
//! changed preceding row, a second marker or a marker with any other agent,
//! attestation, signature or cause fails closed
//! ([`crate::signed_events::SignatureFailure::CutoverMarkerInvalid`]).
//!
//! The resolver is pure: each backend reads the marker rows (at most two), the
//! row before the first one and the per-`attest_level` counts below it, then
//! hands them to [`resolve`], so both backends judge identical inputs (K3).

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::{
    AgentAttestation, RowSignatureVerdict, SignatureFailure, SignedEvent, SignerIdentity,
    canonical_chain_bytes,
};

/// #10108 — the `event_type` of the single cutover marker row. Append refuses
/// it on both backends; only the v103 migration step writes it.
pub const AGENT_CUTOVER_EVENT_TYPE: &str = "signed_events.agent_cutover";

/// #10108 — the reserved `agent_id` of the marker row.
pub const AGENT_CUTOVER_AGENT_ID: &str = "ai-memory:migration-v103";

/// #10108 — the domain and version tag of the marker's `payload_hash`
/// pre-image. A new definition gets a new tag, never a reuse of this one.
const AGENT_CUTOVER_PREIMAGE_DOMAIN: &[u8] = b"ai-memory/signed-events/agent-cutover-v1\0";

/// #10108 — the most marker-type rows a resolver reads. Two is enough to tell
/// "exactly one" from "more than one".
pub const AGENT_CUTOVER_ROW_LIMIT: i64 = 2;

/// #10108 — `true` iff `attest_level` names an agent-signed row
/// ([`SignerIdentity::Agent`]), the rows the marker counts.
#[must_use]
pub fn is_agent_labelled(attest_level: &str) -> bool {
    match SignerIdentity::of(attest_level) {
        SignerIdentity::Agent(
            AgentAttestation::SelfSigned
            | AgentAttestation::SignedByPeer
            | AgentAttestation::PeerAttested,
        ) => true,
        SignerIdentity::Daemon
        | SignerIdentity::Recorder
        | SignerIdentity::LineageWitness
        | SignerIdentity::Unsigned
        | SignerIdentity::Unrecognised => false,
    }
}

/// #10108 — the count of agent-labelled rows in per-`attest_level` group
/// counts. A negative group count (a corrupt read) or an overflow is `None`,
/// which the resolver treats as an invalid marker (fail closed).
#[must_use]
pub fn legacy_agent_row_count<'a>(groups: impl IntoIterator<Item = (&'a str, i64)>) -> Option<u64> {
    let mut total: u64 = 0;
    for (attest_level, count) in groups {
        let count = u64::try_from(count).ok()?;
        if is_agent_labelled(attest_level) {
            total = total.checked_add(count)?;
        }
    }
    Some(total)
}

/// #10108 — the marker's `payload_hash`: SHA-256 over the versioned domain
/// tag, the big-endian sequence, the length-prefixed preceding head hash and
/// the big-endian legacy agent-row count.
///
/// A non-positive `sequence` is `None` (a marker always sits above a row).
#[must_use]
pub fn agent_cutover_payload_hash(
    sequence: i64,
    prev_head_hash: &[u8],
    legacy_agent_rows: u64,
) -> Option<Vec<u8>> {
    let seq = u64::try_from(sequence).ok().filter(|s| *s > 0)?;
    let prev_len = u64::try_from(prev_head_hash.len()).ok()?;
    let mut h = Sha256::new();
    h.update(AGENT_CUTOVER_PREIMAGE_DOMAIN);
    h.update(seq.to_be_bytes());
    h.update(prev_len.to_be_bytes());
    h.update(prev_head_hash);
    h.update(legacy_agent_rows.to_be_bytes());
    Some(h.finalize().to_vec())
}

/// #10108 — the marker row the v103 step appends above `head`, the current
/// last row of the chain. `id` and `timestamp` are the caller's (each backend
/// formats its own timestamp); every committed field is derived here.
///
/// `None` when `head` cannot carry a row above it (sequence overflow).
#[must_use]
pub fn build_marker(
    head: &SignedEvent,
    legacy_agent_rows: u64,
    id: String,
    timestamp: String,
) -> Option<SignedEvent> {
    let sequence = head.sequence.checked_add(1)?;
    let prev_hash = Sha256::digest(canonical_chain_bytes(head)).to_vec();
    let payload_hash = agent_cutover_payload_hash(sequence, &prev_hash, legacy_agent_rows)?;
    Some(SignedEvent {
        id,
        agent_id: AGENT_CUTOVER_AGENT_ID.to_string(),
        event_type: AGENT_CUTOVER_EVENT_TYPE.to_string(),
        payload_hash,
        signature: None,
        attest_level: crate::models::AttestLevel::Unsigned.as_str().to_string(),
        timestamp,
        prev_hash,
        sequence,
        cause_hash: None,
    })
}

/// #10108 — the resolved cutover of one database. Matched exhaustively by
/// [`AgentCutover::verdict_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCutover {
    /// No marker row: the database has not crossed v103 with a non-empty
    /// chain. Every row is judged as before the cutover.
    Absent,
    /// Exactly one marker row, and its recompute matched.
    Valid {
        /// The marker's chain position.
        sequence: i64,
        /// The legacy agent-labelled rows below it.
        legacy_agent_rows: u64,
    },
    /// A marker-type row exists but the database holds more than one, or the
    /// recompute did not match. Every marker-type row then fails.
    Invalid,
}

impl AgentCutover {
    /// #10108 — the verdict for `event` when it is a marker-type row, else
    /// `None` (the caller classifies it as before). Runs before
    /// [`crate::signed_events::classify_row_signature`] on both walks, so an
    /// unsigned marker is never read as a by-design unsigned row.
    #[must_use]
    pub fn verdict_for(self, event: &SignedEvent) -> Option<RowSignatureVerdict> {
        if event.event_type != AGENT_CUTOVER_EVENT_TYPE {
            return None;
        }
        Some(match self {
            Self::Valid { sequence, .. } if sequence == event.sequence => {
                RowSignatureVerdict::Verified
            }
            Self::Valid { .. } | Self::Absent | Self::Invalid => {
                RowSignatureVerdict::Failed(SignatureFailure::CutoverMarkerInvalid)
            }
        })
    }

    /// The marker's sequence when it validated.
    #[must_use]
    pub fn sequence(self) -> Option<i64> {
        match self {
            Self::Valid { sequence, .. } => Some(sequence),
            Self::Absent | Self::Invalid => None,
        }
    }
}

/// #10108 — judge the marker. `markers` are the marker-type rows in ascending
/// sequence (at most [`AGENT_CUTOVER_ROW_LIMIT`]); `prev` is the row directly
/// below the first marker (highest sequence under it); `legacy_agent_rows` is
/// the agent-labelled row count below it (`None` on a corrupt count).
#[must_use]
pub fn resolve(
    markers: &[SignedEvent],
    prev: Option<&SignedEvent>,
    legacy_agent_rows: Option<u64>,
) -> AgentCutover {
    let marker = match markers {
        [] => return AgentCutover::Absent,
        [one] => one,
        _ => return AgentCutover::Invalid,
    };
    let (Some(prev), Some(count)) = (prev, legacy_agent_rows) else {
        return AgentCutover::Invalid;
    };
    let well_formed = marker.agent_id == AGENT_CUTOVER_AGENT_ID
        && marker.attest_level == crate::models::AttestLevel::Unsigned.as_str()
        && marker.signature.is_none()
        && marker.cause_hash.is_none()
        && prev.sequence.checked_add(1) == Some(marker.sequence);
    if !well_formed {
        return AgentCutover::Invalid;
    }
    let prev_hash = Sha256::digest(canonical_chain_bytes(prev)).to_vec();
    if marker.prev_hash != prev_hash {
        return AgentCutover::Invalid;
    }
    match agent_cutover_payload_hash(marker.sequence, &prev_hash, count) {
        Some(expected) if expected == marker.payload_hash => AgentCutover::Valid {
            sequence: marker.sequence,
            legacy_agent_rows: count,
        },
        Some(_) | None => AgentCutover::Invalid,
    }
}

/// #10108 — resolve the sqlite cutover over the WHOLE table, whatever window
/// the caller walks.
///
/// # Errors
/// Propagates a `rusqlite` read error.
pub fn resolve_sqlite_agent_cutover(conn: &Connection) -> Result<AgentCutover> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {} FROM signed_events WHERE event_type = ?1 \
             ORDER BY COALESCE(sequence, 0) ASC LIMIT ?2",
            super::SIGNED_EVENT_ROW_COLUMNS
        ))
        .context("agent cutover: prepare")?;
    let markers: Vec<SignedEvent> = stmt
        .query_map(
            params![AGENT_CUTOVER_EVENT_TYPE, AGENT_CUTOVER_ROW_LIMIT],
            super::read_signed_event_row,
        )
        .context("agent cutover: query")?
        .collect::<rusqlite::Result<_>>()
        .context("agent cutover: collect")?;
    let Some(first) = markers.first() else {
        return Ok(AgentCutover::Absent);
    };
    let below = first.sequence;
    let prev = sqlite_row_below(conn, below)?;
    let count = sqlite_legacy_agent_rows(conn, below)?;
    Ok(resolve(&markers, prev.as_ref(), count))
}

/// The row with the highest sequence below `below`.
fn sqlite_row_below(conn: &Connection, below: i64) -> Result<Option<SignedEvent>> {
    conn.query_row(
        &format!(
            "SELECT {} FROM signed_events WHERE COALESCE(sequence, 0) < ?1 \
             ORDER BY COALESCE(sequence, 0) DESC LIMIT 1",
            super::SIGNED_EVENT_ROW_COLUMNS
        ),
        params![below],
        super::read_signed_event_row,
    )
    .optional()
    .context("agent cutover: row below")
}

/// The agent-labelled row count below `below` (`None` on a corrupt count).
fn sqlite_legacy_agent_rows(conn: &Connection, below: i64) -> Result<Option<u64>> {
    let mut stmt = conn
        .prepare(
            "SELECT attest_level, COUNT(*) FROM signed_events \
             WHERE COALESCE(sequence, 0) < ?1 GROUP BY attest_level",
        )
        .context("agent cutover: count prepare")?;
    let groups: Vec<(String, i64)> = stmt
        .query_map(params![below], |r| Ok((r.get(0)?, r.get(1)?)))
        .context("agent cutover: count query")?
        .collect::<rusqlite::Result<_>>()
        .context("agent cutover: count collect")?;
    Ok(legacy_agent_row_count(
        groups.iter().map(|(a, n)| (a.as_str(), *n)),
    ))
}

/// #10108 (S-3) — append the marker at the sqlite chain head. Runs inside the
/// caller's migrate transaction, before the v103 stamp, so the marker and the
/// stamp commit or roll back together. Writes nothing when the chain is empty
/// or a marker-type row already exists (a restored database carries its own).
/// Returns the marker's sequence when one was written.
///
/// # Errors
/// Propagates a read or insert error, and refuses a chain whose head hash does
/// not match its head row (a partially migrated chain).
pub fn write_sqlite_agent_cutover(conn: &Connection) -> Result<Option<i64>> {
    let existing: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM signed_events WHERE event_type = ?1)",
            params![AGENT_CUTOVER_EVENT_TYPE],
            |r| r.get(0),
        )
        .context("agent cutover: existing marker")?;
    if existing {
        return Ok(None);
    }
    let (head_seq, head_hash) = super::read_chain_head(conn).context("agent cutover: head")?;
    let above = head_seq.saturating_add(1);
    let Some(head) = sqlite_row_below(conn, above)? else {
        return Ok(None);
    };
    let Some(count) = sqlite_legacy_agent_rows(conn, above)? else {
        anyhow::bail!("agent cutover: corrupt attest_level counts below sequence {above}");
    };
    let Some(marker) = build_marker(
        &head,
        count,
        uuid::Uuid::new_v4().to_string(),
        chrono::Utc::now().to_rfc3339(),
    ) else {
        anyhow::bail!("agent cutover: no sequence above head {head_seq}");
    };
    if head.sequence != head_seq || marker.prev_hash != head_hash {
        anyhow::bail!("agent cutover: chain head {head_seq} does not match its row");
    }
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, NULL)",
        params![
            marker.id,
            marker.agent_id,
            marker.event_type,
            marker.payload_hash,
            marker.attest_level,
            marker.timestamp,
            marker.prev_hash,
            marker.sequence,
        ],
    )
    .context("agent cutover: insert marker")?;
    Ok(Some(marker.sequence))
}
