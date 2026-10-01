// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4216 / #4218 — postgres side of the federation merge-version rule (see
//! [`crate::models::replicated_version`] for the ruling and the ONE shared
//! change predicate). Used by `apply_remote_memory`, whose newer-wins SQL
//! upsert keeps `version = GREATEST(local, remote)` while it replaces content.

use sqlx::Row;

use super::{PostgresStore, SQL_SELECT_MEMORY_ROW_BY_ID, to_store_err};
use crate::models::Memory;
use crate::models::replicated_version::{bumped_version, user_data_changed};
use crate::store::StoreResult;

/// The live `(title, namespace)` slot row an inbound upsert may merge into,
/// locked `FOR UPDATE` in the caller's tx. A decode failure is kept as `None`,
/// which the rule treats as CHANGED (the safe direction).
pub(super) struct SlotPreimage {
    pub(super) version: i64,
    memory: Option<Memory>,
}

/// Lock and read the slot row, if any, before the upsert.
pub(super) async fn read_slot_preimage(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    title: &str,
    namespace: &str,
) -> StoreResult<Option<SlotPreimage>> {
    let slot = sqlx::query(&format!(
        "SELECT id, version FROM memories WHERE namespace = $1 AND title = $2 AND {} FOR UPDATE",
        crate::models::TITLE_SLOT_INDEX_PREDICATE
    ))
    .bind(namespace)
    .bind(title)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| to_store_err("apply_remote_memory slot pre-image", e))?;
    let Some(slot) = slot else { return Ok(None) };
    let id: String = slot
        .try_get("id")
        .map_err(|e| to_store_err("apply_remote_memory slot id", e))?;
    let version: i64 = slot
        .try_get("version")
        .map_err(|e| to_store_err("apply_remote_memory slot version", e))?;
    Ok(Some(SlotPreimage {
        version,
        memory: read_memory(tx, &id).await?,
    }))
}

/// Read one row for the change comparison. A SQL error is PROPAGATED (a
/// swallowed one would abort the tx and surface later as 25P02, hiding the root
/// cause); only a mapper / decrypt failure is logged with the row id and kept as
/// `None`, which the rule treats as CHANGED (the safe direction).
async fn read_memory(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
) -> StoreResult<Option<Memory>> {
    let row = sqlx::query(&SQL_SELECT_MEMORY_ROW_BY_ID)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| to_store_err("apply_remote_memory compare read", e))?;
    let Some(row) = row else { return Ok(None) };
    match PostgresStore::row_to_memory(&row) {
        Ok(memory) => Ok(Some(memory)),
        Err(e) => {
            tracing::warn!(
                memory_id = %id,
                error = %e,
                "#4216: could not decode a row to compare a federation merge; treating it as changed"
            );
            Ok(None)
        }
    }
}

/// After the upsert: when the merge changed the slot row's user data, move its
/// `version` to `GREATEST(local, remote) + 1` (the upsert already left the
/// GREATEST). A fresh insert, a replay and a losing push that changed nothing
/// leave the version alone.
pub(super) async fn bump_if_user_data_changed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pre: Option<&SlotPreimage>,
    merged_id: &str,
) -> StoreResult<()> {
    let Some(pre) = pre else { return Ok(()) };
    let post = read_memory(tx, merged_id).await?;
    let changed = match (pre.memory.as_ref(), post.as_ref()) {
        (Some(before), Some(after)) => user_data_changed(before, after),
        // An unreadable side cannot prove "unchanged": fail toward the bump.
        _ => true,
    };
    if !changed {
        return Ok(());
    }
    let merged_version: i64 = sqlx::query_scalar("SELECT version FROM memories WHERE id = $1")
        .bind(merged_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| to_store_err("apply_remote_memory merged version", e))?;
    sqlx::query("UPDATE memories SET version = $1 WHERE id = $2")
        .bind(bumped_version(merged_version))
        .bind(merged_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("apply_remote_memory version bump", e))?;
    Ok(())
}
