// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8968 / #8932 — the ONE owner guard every merge-style import write runs
//! before it may replace or fold into an existing destination row.
//!
//! Class invariant: a row of another owner is never replaced or merged by an
//! import or a migrate. The upsert-merge write paths (`--on-conflict merge` on
//! the CLI, the Portability-v2 importer under `ConflictMode::Merge`, and the
//! HTTP `POST /api/v1/import` sqlite route) all reach `storage::insert`, whose
//! `ON CONFLICT` upsert folds the incoming row into whatever row holds the
//! `(title, namespace)` slot or the incoming id. Before this guard, that holder
//! could be another agent's `scope=private` row.
//!
//! Disposition (copied from the #3151 archived-lane posture): the incoming row
//! is counted, a per-row WARN is emitted, and the destination row is kept
//! byte-for-byte. The guard never names the holder's id in the error text, so
//! a probe cannot learn another owner's private id through it.
//!
//! decision: an owner-less holder (no `metadata.agent_id`) counts as not
//! another owner, over refusing it, because owner-less rows are the
//! single-tenant posture `find_by_title_namespace(.., None)` already trusts.
//! A holder whose metadata does not parse is treated as another owner's row
//! (fail closed).

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::models::Memory;

/// Display text of [`ForeignOwnerKept`]. Pinned by the #8968 tests.
pub const FOREIGN_OWNER_KEPT_MSG: &str =
    "skipped: the destination row holding this slot belongs to another owner; destination row kept";

/// The metadata key that carries a row's owning agent.
const OWNER_METADATA_KEY: &str = "agent_id";

/// The sqlite id probe of [`foreign_holder`].
const SQLITE_HOLDER_BY_ID: &str = "SELECT metadata FROM memories WHERE id = ?1";

/// The Postgres id probe of `PostgresStore::foreign_slot_holder`, kept next to
/// its sqlite twin so both backends probe the same row.
pub const PG_HOLDER_BY_ID: &str = "SELECT metadata FROM memories WHERE id = $1";

/// Typed refusal: the incoming row would have replaced or merged into a row
/// of another owner. Callers downcast to count it (never as a hard failure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignOwnerKept {
    /// The id of the INCOMING row that was not written.
    pub incoming_id: String,
}

impl std::fmt::Display for ForeignOwnerKept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {FOREIGN_OWNER_KEPT_MSG}", self.incoming_id)
    }
}

impl std::error::Error for ForeignOwnerKept {}

/// Whether a holder whose decoded metadata is `meta` belongs to an owner
/// other than `incoming`. `None` is metadata that did not decode, which is
/// treated as another owner's row (fail closed). A holder with no recorded
/// owner is not foreign. Shared by the sqlite guard and the Postgres
/// `foreign_slot_holder` so both backends decide identically.
#[must_use]
pub fn holder_is_foreign(meta: Option<&serde_json::Value>, incoming: Option<&str>) -> bool {
    let Some(meta) = meta else {
        return true;
    };
    match meta.get(OWNER_METADATA_KEY) {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(holder)) => incoming != Some(holder.as_str()),
        // An owner field of any other JSON type names no comparable owner:
        // fail closed.
        Some(_) => true,
    }
}

/// The owner the incoming row claims (after any restamp the caller applied).
#[must_use]
pub fn incoming_owner(mem: &Memory) -> Option<&str> {
    mem.metadata
        .get(OWNER_METADATA_KEY)
        .and_then(serde_json::Value::as_str)
}

fn is_foreign(raw_meta: &str, incoming: Option<&str>) -> bool {
    let decoded = serde_json::from_str::<serde_json::Value>(raw_meta).ok();
    holder_is_foreign(decoded.as_ref(), incoming)
}

/// The id of the destination row an upsert of `mem` would replace or fold
/// into, when that row belongs to another owner. Probes BOTH conflict keys the
/// upsert writes on: the incoming id, and the `(title, namespace)` slot holder
/// (the v100 partial-unique-index occupant, so a tombstone holds no slot).
///
/// # Errors
///
/// Returns the underlying SQLite error.
pub fn foreign_holder(conn: &Connection, mem: &Memory) -> Result<Option<String>> {
    let incoming = incoming_owner(mem);
    let by_id: Option<String> = conn
        .query_row(SQLITE_HOLDER_BY_ID, params![mem.id], |r| r.get(0))
        .optional()
        .with_context(|| format!("owner guard: id probe for memory {}", mem.id))?;
    if let Some(raw) = by_id
        && is_foreign(&raw, incoming)
    {
        return Ok(Some(mem.id.clone()));
    }
    let slot: Option<(String, String)> = conn
        .query_row(
            &format!(
                "SELECT id, metadata FROM memories WHERE title = ?1 AND namespace = ?2 AND {} \
                 LIMIT 1",
                crate::models::TITLE_SLOT_INDEX_PREDICATE
            ),
            params![mem.title, mem.namespace],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .with_context(|| format!("owner guard: title-slot probe for memory {}", mem.id))?;
    Ok(slot.and_then(|(id, raw)| is_foreign(&raw, incoming).then_some(id)))
}

/// `storage::insert` (the upsert-merge write) behind the owner guard: a row
/// of another owner is never replaced or merged; the call returns a typed
/// [`ForeignOwnerKept`] instead and writes nothing.
///
/// # Errors
///
/// [`ForeignOwnerKept`] when the conflict holder is another owner's row; the
/// underlying storage error otherwise.
pub fn insert_merge_owner_guarded(conn: &Connection, mem: &Memory) -> Result<String> {
    if foreign_holder(conn, mem)?.is_some() {
        tracing::warn!(
            target: "ai_memory::portability::owner_guard",
            memory_id = %mem.id,
            "merge import kept the destination row: the slot belongs to another owner (#8968)"
        );
        return Err(ForeignOwnerKept {
            incoming_id: mem.id.clone(),
        }
        .into());
    }
    crate::storage::insert(conn, mem)
}

/// Whether `err` is the typed owner-guard refusal.
#[must_use]
pub fn is_foreign_owner_kept(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ForeignOwnerKept>().is_some()
}
