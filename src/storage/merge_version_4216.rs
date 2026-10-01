// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4216 / #4218 — sqlite side of the federation merge-version rule (see
//! [`crate::models::replicated_version`] for the ruling and the ONE shared
//! change predicate). Used by `insert_if_newer`, whose newer-wins SQL upsert
//! keeps `version = MAX(local, remote)` while it replaces content.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

use crate::models::Memory;
use crate::models::replicated_version::user_data_changed;

/// The local `(title, namespace)` slot row an inbound newer-wins upsert may
/// merge into, read under the merge's write lock (ERRORS-19: a decode failure
/// is kept as `None`, which the rule treats as CHANGED, the safe direction).
pub(super) struct SlotPreimage {
    id: String,
    pub(super) version: i64,
    memory: Option<Memory>,
}

/// Read a row for the change comparison. A read or decode failure is logged
/// with the row id (ERRORS-19) and kept as `None`, which the rule treats as
/// CHANGED (the safe direction).
fn read_for_compare(conn: &Connection, id: &str) -> Option<Memory> {
    match super::get_any(conn, id) {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(
                memory_id = %id,
                error = %e,
                "#4216: could not read a row to compare a federation merge; treating it as changed"
            );
            None
        }
    }
}

/// Read the slot row, if any, before the upsert.
pub(super) fn read_slot_preimage(
    conn: &Connection,
    title: &str,
    namespace: &str,
) -> Result<Option<SlotPreimage>> {
    let found: Option<(String, i64)> = conn
        .query_row(
            &format!(
                "SELECT id, version FROM memories WHERE title = ?1 AND namespace = ?2 AND {}",
                crate::models::TITLE_SLOT_INDEX_PREDICATE
            ),
            params![title, namespace],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(found.map(|(id, version)| SlotPreimage {
        memory: read_for_compare(conn, &id),
        id,
        version,
    }))
}

/// After the upsert: when the merge changed the slot row's user data, move
/// its `version` to `GREATEST(local, remote) + 1` (the upsert already left
/// the GREATEST). A fresh insert, a replay and a losing push that changed
/// nothing leave the version alone.
pub(super) fn bump_if_user_data_changed(
    conn: &Connection,
    pre: Option<&SlotPreimage>,
    merged_id: &str,
) -> Result<()> {
    let Some(pre) = pre else { return Ok(()) };
    let post = read_for_compare(conn, merged_id);
    let changed = match (pre.memory.as_ref(), post.as_ref()) {
        (Some(before), Some(after)) => user_data_changed(before, after),
        // An unreadable side cannot prove "unchanged": fail toward the bump.
        _ => true,
    };
    if !changed {
        return Ok(());
    }
    // The upsert already left GREATEST(local, remote); one past it, saturating
    // (the same fragment every sqlite `version + 1` site uses, #4218).
    conn.execute(
        "UPDATE memories SET version = MIN(version, 9223372036854775806) + 1 WHERE id = ?1",
        params![merged_id],
    )?;
    debug_assert_eq!(pre.id, merged_id, "title-slot merge hits the slot row");
    Ok(())
}
