// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Transactional schema-v97 key-history mutations.

use super::{PostgresStore, StoreError, StoreResult, to_store_err};

impl PostgresStore {
    /// Outer bind/lineage admission already refreshed the durable stop state.
    /// Recheck its shared flag without checking out another connection while
    /// `tx` holds the pool's last available connection.
    fn gate_record_stop_in_transaction(&self) -> StoreResult<()> {
        crate::store::record_stop::gate_flag(&self.record_stop)
    }

    /// Append the next key version in `tx`. Same-open-key is idempotent; every
    /// distinct transition closes the open row and appends a dense version.
    pub(super) async fn append_pubkey_version_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        agent_id: &str,
        pubkey_b64: &str,
        flat_pubkey_b64: Option<&str>,
        proof: &crate::identity::pubkey_bind::PossessionProof,
        now: &str,
    ) -> StoreResult<()> {
        self.gate_record_stop_in_transaction()?;
        let latest: Option<(i64, String, String, Option<String>)> = sqlx::query_as(
            "SELECT version, pubkey_b64, bound_at, superseded_at FROM agent_pubkey_history
             WHERE agent_id = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(agent_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| to_store_err("read latest agent pubkey version", e))?;
        proof
            .authorize_storage_state(
                agent_id,
                pubkey_b64,
                flat_pubkey_b64,
                latest
                    .as_ref()
                    .map(|(_, key, _, superseded)| (key.as_str(), superseded.is_none())),
            )
            .map_err(|_| StoreError::PermissionDenied {
                action: crate::handlers::BIND_AGENT_PUBKEY_ACTION.to_string(),
                target: agent_id.to_string(),
                reason: crate::errors::msg::BIND_PROOF_REFUSED.to_string(),
            })?;
        let prior: Vec<(String,)> =
            sqlx::query_as("SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = $1")
                .bind(agent_id)
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| to_store_err("read agent pubkey history for reuse check", e))?;
        let reused = crate::identity::keypair::canonical_history_contains(
            pubkey_b64,
            prior.iter().map(|row| row.0.as_str()),
        )
        .map_err(|e| StoreError::IntegrityFailed {
            detail: e.to_string(),
        })?;
        if reused {
            if latest
                .as_ref()
                .is_some_and(|(_, live, _, end)| end.is_none() && live == pubkey_b64)
            {
                return Ok(());
            }
            return Err(StoreError::InvalidInput {
                detail: "refusing to reactivate a superseded or revoked agent pubkey".to_string(),
            });
        }
        if let Some((_, _, bound_at, superseded_at)) = latest.as_ref() {
            crate::storage::validate_agent_pubkey_transition_time(
                bound_at,
                superseded_at.as_deref(),
                now,
            )
            .map_err(|error| StoreError::InvalidInput {
                detail: format!("refusing non-monotonic pubkey history transition: {error}"),
            })?;
        }
        if latest
            .as_ref()
            .is_some_and(|(_, _, _, superseded)| superseded.is_none())
        {
            sqlx::query(
                "UPDATE agent_pubkey_history SET superseded_at = $2
                 WHERE agent_id = $1 AND superseded_at IS NULL",
            )
            .bind(agent_id)
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(|e| to_store_err("supersede agent pubkey version", e))?;
        }
        let (next,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM agent_pubkey_history WHERE agent_id = $1",
        )
        .bind(agent_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| to_store_err("next agent pubkey version", e))?;
        sqlx::query(
            "INSERT INTO agent_pubkey_history
                (agent_id, version, pubkey_b64, bind_authority, proof_nonce, bound_at, superseded_at)
             VALUES ($1, $2, $3, $4, $5, $6, NULL)",
        )
        .bind(agent_id)
        .bind(next)
        .bind(pubkey_b64)
        .bind(proof.authority().as_str())
        .bind(proof.nonce_b64())
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("append agent pubkey version", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::PostgresStore;
    use crate::store::{CallerContext, MemoryStore as _, PoolConfig};

    #[tokio::test]
    async fn history_write_gate_does_not_reacquire_exhausted_pool_3464() {
        let url =
            std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("own PostgreSQL test URL required");
        let store = PostgresStore::connect(&url).await.expect("store");
        let agent = format!("ai:pool-gate-{}", uuid::Uuid::new_v4());
        let ctx = CallerContext::for_admin(&agent);
        let registered_at = chrono::Utc::now().to_rfc3339();
        store
            .register_agent(
                &ctx,
                &crate::models::AgentRegistration {
                    agent_id: agent.clone(),
                    agent_type: "ai:generic".to_string(),
                    capabilities: Vec::new(),
                    registered_at: registered_at.clone(),
                    last_seen_at: registered_at,
                },
            )
            .await
            .expect("register");
        let key = crate::identity::keypair::generate(&agent).expect("key");
        let proof = crate::store::prove_possession_via_store(
            &store,
            &ctx,
            &agent,
            key.private.as_ref().expect("private"),
        )
        .await
        .expect("possession");
        // Exhaust a supported pool after initialization. Schema initialization
        // itself needs more than one connection; that is outside this test.
        let mut occupied = Vec::new();
        for _ in 1..PoolConfig::default().max_connections {
            occupied.push(store.pool.acquire().await.expect("occupy spare connection"));
        }
        let mut tx = store.pool.begin().await.expect("occupy final connection");
        // Reproduce a TTL expiring while the outer operation waited for its
        // transaction. A second pool checkout would wait until acquire timeout.
        tokio::time::sleep(std::time::Duration::from_millis(
            super::super::RECORD_STOP_REFRESH_TTL_MS,
        ))
        .await;
        assert!(
            super::super::record_stop_refresh_now_ms() >= super::super::RECORD_STOP_REFRESH_TTL_MS
        );
        store
            .record_stop_refreshed_ms
            .store(0, std::sync::atomic::Ordering::Release);
        let stamp = chrono::Utc::now().to_rfc3339();
        let public = key.public_base64();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            store.append_pubkey_version_tx(&mut tx, &agent, &public, None, &proof, &stamp),
        )
        .await
        .expect("history write must not check out another pool connection")
        .expect("history append");
        store
            .record_stop
            .engage(&agent, crate::store::record_stop::SCOPE_RECORD_PLANE);
        let refused = store
            .append_pubkey_version_tx(&mut tx, &agent, &public, Some(&public), &proof, &stamp)
            .await;
        assert!(
            matches!(refused, Err(crate::store::StoreError::Stopped { .. })),
            "cached stop must still block the write"
        );
        tx.rollback()
            .await
            .expect("rollback isolated history probe");
    }
}
