// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9147 / #9149 / #9150 — the postgres twin of the sqlite receiver
//! lifecycle MERGE BARRIER (`crate::storage::receiver_merge_barrier`), in its
//! own child module (`postgres.rs` is at its `qual_10` budget).
//!
//! The probe runs INSIDE the funnel's transaction, after the funnel's
//! title-slot advisory lock and `FOR UPDATE` row lock, so the verdict and the
//! write it gates are one atomic unit. The barrier states and their order
//! (tombstoned, then archived-without-live, then held) are identical to the
//! sqlite probe so the two backends cannot drift.

use super::*;
use crate::storage::ReceiverMergeBarrier;

/// `true` when the id is archived on this node and has no live row (#9149).
const SQL_ARCHIVED_WITHOUT_LIVE: &str = "SELECT EXISTS(SELECT 1 FROM archived_memories WHERE id = $1) \
     AND NOT EXISTS(SELECT 1 FROM memories WHERE id = $1)";

/// The lifecycle state of the live row by id (#9150).
const SQL_LIFECYCLE_BY_ID: &str = "SELECT lifecycle_state FROM memories WHERE id = $1";

/// Probe the receiver merge barrier for an inbound row inside `tx`.
/// `title_slot` is the `(title, namespace)` an upsert would land on (`None`
/// for a same-id overwrite).
///
/// # Errors
///
/// The probe's sqlx error; the caller rolls back (a probe that cannot decide
/// never lets the write through).
pub(super) async fn pg_receiver_merge_barrier(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    memory_id: &str,
    title_slot: Option<(&str, &str)>,
) -> Result<Option<ReceiverMergeBarrier>, sqlx::Error> {
    let tombstoned: bool = sqlx::query_scalar(federation_3075::SQL_FORGET_TOMBSTONE_EXISTS)
        .bind(memory_id)
        .fetch_one(&mut **tx)
        .await?;
    if tombstoned {
        return Ok(Some(ReceiverMergeBarrier::Tombstoned));
    }
    let archived: bool = sqlx::query_scalar(SQL_ARCHIVED_WITHOUT_LIVE)
        .bind(memory_id)
        .fetch_one(&mut **tx)
        .await?;
    if archived {
        return Ok(Some(ReceiverMergeBarrier::Archived));
    }
    let mut states: Vec<String> = sqlx::query_scalar(SQL_LIFECYCLE_BY_ID)
        .bind(memory_id)
        .fetch_all(&mut **tx)
        .await?;
    if let Some((title, namespace)) = title_slot {
        let sql = format!(
            "SELECT lifecycle_state FROM memories \
             WHERE title = $1 AND namespace = $2 AND {}",
            crate::models::TITLE_SLOT_INDEX_PREDICATE
        );
        let slot: Vec<String> = sqlx::query_scalar(&sql)
            .bind(title)
            .bind(namespace)
            .fetch_all(&mut **tx)
            .await?;
        states.extend(slot);
    }
    Ok(states
        .iter()
        .filter_map(|s| crate::models::LifecycleState::from_str(s))
        .find(|s| crate::models::crdt_merge::is_node_local_lifecycle(*s))
        .map(ReceiverMergeBarrier::Held))
}

/// #9147 — the archived half of a federated deletion, inside the deletion's
/// transaction: purge every `archived_memories` copy of `id` so no restore
/// path can republish the deleted content, and — when no live row reached
/// [`pg_hard_delete_in_tx`]'s tombstone (`live_deleted == false`) — write the
/// signed forget tombstone here, bound to the archived namespace, so LWW
/// cannot re-admit the id. Returns the number of archived rows purged.
///
/// # Errors
///
/// The sqlx error of any statement; the caller rolls the deletion back.
pub(super) async fn pg_purge_archived_copy_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    archived_namespace: Option<&str>,
    live_deleted: bool,
) -> Result<u64, sqlx::Error> {
    let Some(namespace) = archived_namespace else {
        return Ok(0);
    };
    if !live_deleted {
        let now_str = chrono::Utc::now().to_rfc3339();
        let signable = crate::storage::forget_tombstone_signable_bytes(id, namespace, &now_str);
        let signature: Option<Vec<u8>> =
            crate::governance::audit::try_sign_audit_payload(&signable).map(|(s, _)| s);
        sqlx::query(SQL_INSERT_FORGET_TOMBSTONE)
            .bind(id)
            .bind(namespace)
            .bind(&now_str)
            .bind(None::<String>)
            .bind(&signature)
            .execute(&mut **tx)
            .await?;
    }
    Ok(sqlx::query(SQL_DELETE_ARCHIVED_MEMORY_BY_ID)
        .bind(id)
        .execute(&mut **tx)
        .await?
        .rows_affected())
}
