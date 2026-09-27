// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Forced final certification of the active PostgreSQL audit chain (#4070).
use super::{PgSignedEventWalkRow, PostgresStore, pg_build_audit_head_witness_in_tx};
use crate::signed_events::{SignedEvent, canonical_chain_bytes, hex_lower};
use sha2::{Digest, Sha256};

impl PostgresStore {
    /// Persist a final dual-head witness, bypassing the append-time throttle.
    ///
    /// Call only after local writers have quiesced. A repeatable-read snapshot
    /// binds both heads and genesis consistently even if another node writes.
    /// The database checkpoint commits before its off-table anchor is fsynced;
    /// any failure is propagated and must make shutdown uncertified.
    ///
    /// # Errors
    /// Returns database, enrolled-custody, signing, or durable-anchor errors.
    pub async fn force_shutdown_witness(&self) -> anyhow::Result<()> {
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        let head: Option<PgSignedEventWalkRow> = sqlx::query_as(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, prev_hash, sequence, cause_hash FROM signed_events WHERE sequence IS NOT NULL ORDER BY sequence DESC LIMIT 1"
        ).fetch_optional(&mut *tx).await?;
        let Some((
            id,
            agent_id,
            event_type,
            payload_hash,
            signature,
            attest_level,
            timestamp,
            prev_hash,
            sequence,
            cause_hash,
        )) = head
        else {
            return Ok(());
        };
        let event = SignedEvent {
            id,
            agent_id,
            event_type,
            payload_hash,
            signature,
            attest_level,
            timestamp: timestamp.to_rfc3339(),
            prev_hash,
            sequence,
            cause_hash,
        };
        let hash = hex_lower(Sha256::digest(canonical_chain_bytes(&event)).as_slice());
        let checkpoint = pg_build_audit_head_witness_in_tx(&mut tx, sequence, &hash, true).await?;
        tx.commit().await?;
        if let Some(checkpoint) = checkpoint {
            crate::governance::audit::append_head_anchor_durable(&checkpoint)?;
        }
        Ok(())
    }
}
