// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4371 — postgres twin of `storage::version_repair_4371`: the one-time
//! (schema v101) clamp of `memories.version` / `archived_memories.version`
//! counters a peer pinned above
//! [`crate::models::replicated_version::MAX_REPLICATED_VERSION`] before the
//! #4218 bound. Such a row is un-editable (the checked `+ 1` refuses the
//! `bigint` edge); the clamp makes it editable again with a moving `If-Match`
//! token. Only the counter is written. Idempotent: a second run matches no row.

use super::to_store_err;
use crate::models::replicated_version::MAX_REPLICATED_VERSION;
use crate::store::StoreResult;

/// Clamp every live and archived version above the replicated ceiling inside
/// the caller's migration transaction. Returns `(memories, archived)` rows.
pub(super) async fn repair_poisoned_versions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> StoreResult<(u64, u64)> {
    let memories = sqlx::query("UPDATE memories SET version = $1 WHERE version > $1")
        .bind(MAX_REPLICATED_VERSION)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("clamp poisoned memories.version (v101)", e))?
        .rows_affected();
    let archived = sqlx::query("UPDATE archived_memories SET version = $1 WHERE version > $1")
        .bind(MAX_REPLICATED_VERSION)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("clamp poisoned archived_memories.version (v101)", e))?
        .rows_affected();
    Ok((memories, archived))
}
