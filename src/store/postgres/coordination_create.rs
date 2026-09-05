// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Atomic direct-action and routine write funnels (#3359).

use super::{PostgresStore, StoreError, StoreResult, Utc, quota_defaults, to_store_err};
use crate::models::{Action, EdgeType, RoutineState};
use sqlx::{Postgres, Transaction};

impl PostgresStore {
    pub(super) async fn create_guarded_action_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        action: Action,
    ) -> StoreResult<String> {
        self.gate_record_stop().await?;
        let (action, bytes) = crate::coordination_guard::prepare_action(action)
            .map_err(|detail| StoreError::IntegrityFailed { detail })?;
        self.charge_storage_growth_in_transaction(
            tx,
            action.agent_id.as_deref().unwrap_or_default(),
            &action.namespace,
            0,
            bytes,
        )
        .await?;
        // #1709 Pillar 1 — JSON columns stored as TEXT (parity with sqlite).
        sqlx::query(
            "INSERT INTO actions \
                (id, namespace, kind, state, title, payload, priority, agent_id, \
                 claimed_by, vector_clock, metadata, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(&action.id)
        .bind(&action.namespace)
        .bind(&action.kind)
        .bind(action.state.as_str())
        .bind(&action.title)
        .bind(action.payload.to_string())
        .bind(action.priority)
        .bind(&action.agent_id)
        .bind(&action.claimed_by)
        .bind(action.vector_clock.to_string())
        .bind(action.metadata.to_string())
        .bind(action.created_at)
        .bind(action.updated_at)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("action_create", e))?;
        Ok(action.id)
    }

    pub(super) async fn charge_storage_growth_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &str,
        ns: &str,
        old_bytes: i64,
        new_bytes: i64,
    ) -> StoreResult<i64> {
        self.gate_record_stop().await?;
        let delta = new_bytes.saturating_sub(old_bytes);
        if delta <= 0 || owner.is_empty() {
            return Ok(0);
        }
        let now = Utc::now();
        // Ensure the quota row exists (contention-free; INSERT always
        // reports success or a benign conflict). Storage bytes are
        // cumulative (never daily-reset), so day-roll logic is irrelevant
        // to a storage-only charge.
        sqlx::query(
            "INSERT INTO agent_quotas (
                 agent_id, namespace,
                 max_memories_per_day, max_storage_bytes, max_links_per_day,
                 current_memories_today, current_storage_bytes, current_links_today,
                 day_started_at, created_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, 0, 0, 0, $6, $6, $6)
             ON CONFLICT (agent_id, namespace) DO NOTHING",
        )
        .bind(owner)
        .bind(ns)
        .bind(quota_defaults().max_memories_per_day)
        .bind(quota_defaults().max_storage_bytes)
        .bind(quota_defaults().max_links_per_day)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("ensure agent_quotas row (charge_update_growth)", e))?;

        // ONE conditional UPDATE — the ceiling re-check and the increment
        // are a single atomic statement, so no concurrent growth can push
        // `current_storage_bytes` past `max_storage_bytes`. rows_affected
        // == 0 ⇒ the guard refused (the row exists — we just ensured it).
        let res = sqlx::query(
            "UPDATE agent_quotas
                SET current_storage_bytes = current_storage_bytes + $1,
                    updated_at = $2
              WHERE agent_id = $3 AND namespace = $4
                AND current_storage_bytes + $1 <= max_storage_bytes",
        )
        .bind(delta)
        .bind(now)
        .bind(owner)
        .bind(ns)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("charge_update_growth storage increment", e))?;

        if res.rows_affected() == 0 {
            // Re-read the row so the typed error names accurate current/max.
            let row: Option<(i64, i64)> = sqlx::query_as(
                "SELECT current_storage_bytes, max_storage_bytes \
                 FROM agent_quotas WHERE agent_id = $1 AND namespace = $2",
            )
            .bind(owner)
            .bind(ns)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| to_store_err("re-read agent_quotas after growth refusal", e))?;
            let (current, max) = row.unwrap_or((0, quota_defaults().max_storage_bytes));
            return Err(StoreError::QuotaExceeded {
                agent_id: owner.to_string(),
                namespace: ns.to_string(),
                limit: crate::quotas::QuotaLimit::StorageBytes.as_str().to_string(),
                current,
                max,
            });
        }
        Ok(delta)
    }

    pub(super) async fn add_action_edge_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        from_action: &str,
        to_action: &str,
        edge_type: EdgeType,
        now: i64,
    ) -> StoreResult<()> {
        self.gate_record_stop().await?;
        if from_action == to_action {
            return Err(StoreError::IntegrityFailed {
                detail: format!("refused self-edge on action {from_action}"),
            });
        }
        if edge_type != crate::models::EdgeType::Sibling {
            // Does `to_action` already reach `from_action` via non-sibling arcs?
            // If so, `from_action -> to_action` would close a cycle.
            let cycle: Option<i32> = sqlx::query_scalar(
                "WITH RECURSIVE reach(node) AS ( \
                     SELECT $1::text \
                     UNION \
                     SELECT e.to_action FROM action_edges e JOIN reach r ON e.from_action = r.node \
                     WHERE e.edge_type <> $3) \
                 SELECT 1 FROM reach WHERE node = $2 LIMIT 1",
            )
            .bind(to_action)
            .bind(from_action)
            .bind(crate::models::EdgeType::Sibling.as_str())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| to_store_err("action_add_edge cycle-check", e))?;
            if cycle.is_some() {
                // Byte-equal wire error with the sqlite twin. The tx is dropped
                // (ROLLBACK) on this early return, releasing the advisory lock.
                return Err(StoreError::IntegrityFailed {
                    detail: format!(
                        "refused edge {from_action} -> {to_action}: would close an ordering cycle"
                    ),
                });
            }
        }
        sqlx::query(
            "INSERT INTO action_edges (from_action, to_action, edge_type, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (from_action, to_action, edge_type) DO NOTHING",
        )
        .bind(from_action)
        .bind(to_action)
        .bind(edge_type.as_str())
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("action_add_edge", e))?;
        Ok(())
    }

    pub(super) async fn materialize_routine(
        &self,
        routine_id: &str,
        arguments: &serde_json::Value,
    ) -> StoreResult<Vec<String>> {
        self.gate_record_stop().await?;
        crate::coordination_guard::require_payload_size("arguments", arguments)
            .map_err(|detail| StoreError::IntegrityFailed { detail })?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("routine materialize begin", e))?;
        let row = sqlx::query(super::PG_ROUTINE_SELECT_BY_ID)
            .bind(routine_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| to_store_err("routine materialize load", e))?;
        let routine = super::pg_row_to_routine(&row)?;
        if routine.state != RoutineState::Frozen {
            return Err(StoreError::IntegrityFailed {
                detail: crate::routines::ROUTINE_NOT_FROZEN.to_string(),
            });
        }
        let now = Utc::now().timestamp();
        let plan = crate::routines::materialization::plan(&routine, arguments, now)
            .map_err(|detail| StoreError::IntegrityFailed { detail })?;
        super::pg_advisory_lock_action_edges(&mut tx)
            .await
            .map_err(|e| to_store_err("routine edges lock", e))?;
        let mut ids = Vec::with_capacity(plan.actions.len());
        for action in plan.actions {
            ids.push(
                self.create_guarded_action_in_transaction(&mut tx, action)
                    .await?,
            );
        }
        for (from, to, edge_type) in plan.edges {
            self.add_action_edge_in_transaction(&mut tx, &from, &to, edge_type, now)
                .await?;
        }
        tx.commit()
            .await
            .map_err(|e| to_store_err("routine materialize commit", e))?;
        Ok(ids)
    }
}
