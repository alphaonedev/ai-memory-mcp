// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4208 — the evidence-bound route-OUT dequarantine-on-attest (postgres twin
//! of [`crate::storage::dequarantine_if_verified_unit`]).
//!
//! The row is read `FOR UPDATE` and released on the SAME transaction, and only
//! when the stored row shows the content of the unit this node verified
//! ([`crate::models::persisted_is_verified_unit`]). A verified unit that lost
//! the newer-wins merge leaves never-attested content on the row, so the
//! quarantine stays (fail closed); a concurrent writer cannot swap the content
//! between the check and the release.

use super::{PostgresStore, SQL_SELECT_MEMORY_ROW_BY_ID_FOR_UPDATE, to_store_err};
use crate::models::{LifecycleState, Memory};
use crate::store::StoreResult;

impl PostgresStore {
    /// See the module doc. Returns `true` when a quarantine was cleared.
    ///
    /// # Errors
    /// A record-stop refusal, a read / decrypt failure (fail closed: the row
    /// stays quarantined) or the UPDATE error.
    pub(super) async fn dequarantine_verified_in_tx(
        &self,
        id: &str,
        verified_inbound: &Memory,
    ) -> StoreResult<bool> {
        self.gate_record_stop().await?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("dequarantine_verified begin tx", e))?;
        let row = sqlx::query(&SQL_SELECT_MEMORY_ROW_BY_ID_FOR_UPDATE)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| to_store_err("dequarantine_verified read row", e))?;
        let Some(row) = row else {
            return Ok(false);
        };
        let persisted = Self::row_to_memory(&row)?;
        if persisted.lifecycle_state != LifecycleState::Quarantined
            || !crate::models::persisted_is_verified_unit(&persisted, verified_inbound)
        {
            return Ok(false);
        }
        let released = sqlx::query(
            "UPDATE memories SET lifecycle_state = $1, updated_at = NOW(), version = version + 1 \
             WHERE id = $2 AND lifecycle_state = $3",
        )
        .bind(LifecycleState::Open.as_str())
        .bind(id)
        .bind(LifecycleState::Quarantined.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("dequarantine_verified", e))?
        .rows_affected()
            > 0;
        tx.commit()
            .await
            .map_err(|e| to_store_err("dequarantine_verified commit", e))?;
        Ok(released)
    }
}
