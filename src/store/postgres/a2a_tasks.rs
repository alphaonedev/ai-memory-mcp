// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444 - postgres twin of [`crate::storage::a2a_tasks`]: durable Task rows
//! for the Agent2Agent (A2A 1.0) standard binding.
//!
//! Own module for the same `qual_10_module_size_ceiling` budget reason as
//! `api_key_bind_3535`. Every statement is scoped by the AUTHENTICATED
//! `agent_id`, and the transition is a single compare-and-set `UPDATE`
//! (`state = ANY($from)`) whose affected-row count names the one winner. The
//! history is content-free (ids only); the `a2a_task_memories` link table
//! cascades from `memories`, so every memory delete path removes the link in
//! the same statement (see the sqlite twin for the contract).

use std::collections::HashSet;

use crate::storage::a2a_tasks::{
    A2A_TERMINAL_STATES_SQL, A2A_TERMINAL_TASK_RETENTION, A2aHistoryEntry, A2aTaskFilter,
    A2aTaskPage, A2aTaskRow, A2aTaskUpdate, COLUMN_ARTIFACTS_JSON, COLUMN_HISTORY_JSON,
    COLUMN_METADATA_JSON, abandoned_cutoff, filter_linked_history, parse_json_column,
};
use crate::store::StoreError;

use super::{PostgresStore, StoreResult, to_store_err};

type TaskTuple = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

const PG_SELECT_COLUMNS: &str = "id, context_id, agent_id, state, status_timestamp, \
     history_json, artifacts_json, metadata_json, created_at, updated_at";

fn corrupt(e: &anyhow::Error) -> StoreError {
    StoreError::InvalidInput {
        detail: e.to_string(),
    }
}

/// Decode a fetched row. A corrupt JSON column is an error, never a default.
pub(crate) fn tuple_to_task(t: TaskTuple) -> StoreResult<A2aTaskRow> {
    Ok(A2aTaskRow {
        id: t.0,
        context_id: t.1,
        agent_id: t.2,
        state: t.3,
        status_timestamp: t.4,
        history: parse_json_column(&t.5, COLUMN_HISTORY_JSON).map_err(|e| corrupt(&e))?,
        artifacts: parse_json_column(&t.6, COLUMN_ARTIFACTS_JSON).map_err(|e| corrupt(&e))?,
        metadata: parse_json_column(&t.7, COLUMN_METADATA_JSON).map_err(|e| corrupt(&e))?,
        created_at: t.8,
        updated_at: t.9,
    })
}

impl PostgresStore {
    /// The inbox memory ids still linked to `task_id`.
    async fn a2a_linked_memories(&self, task_id: &str) -> StoreResult<HashSet<String>> {
        const CTX: &str = "a2a_task_memories";
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT memory_id FROM a2a_task_memories WHERE task_id = $1")
                .bind(task_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| to_store_err(CTX, e))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Decode a row and keep only the history entries whose memory is linked.
    async fn a2a_finish_row(&self, t: TaskTuple) -> StoreResult<A2aTaskRow> {
        let mut task = tuple_to_task(t)?;
        let linked = self.a2a_linked_memories(&task.id).await?;
        task.history = filter_linked_history(&task.history, &linked);
        Ok(task)
    }

    /// Insert a new Task row, then in the SAME transaction fail-and-retire the
    /// caller's abandoned active tasks and prune its oldest terminal tasks. The
    /// record-stop gate is taken in the function that owns the `INSERT` (B7
    /// structural scan) and by the trait arm (B7' parity scan).
    ///
    /// # Errors
    ///
    /// Surfaces the record-stop refusal and any query failure.
    pub(super) async fn a2a_task_insert_pg(&self, task: &A2aTaskRow) -> StoreResult<()> {
        const CTX: &str = "a2a_task_insert";
        self.gate_record_stop().await?;
        let mut tx = self.pool.begin().await.map_err(|e| to_store_err(CTX, e))?;
        sqlx::query(
            "INSERT INTO a2a_tasks (id, context_id, agent_id, state, status_timestamp, \
             history_json, artifacts_json, metadata_json, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&task.id)
        .bind(&task.context_id)
        .bind(&task.agent_id)
        .bind(&task.state)
        .bind(&task.status_timestamp)
        .bind(task.history.to_string())
        .bind(task.artifacts.to_string())
        .bind(task.metadata.to_string())
        .bind(&task.created_at)
        .bind(&task.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err(CTX, e))?;
        // Active tasks nobody can finish any more are retired (FAILED), so the
        // non-terminal row count stays bounded.
        let cutoff = abandoned_cutoff(chrono::Utc::now());
        sqlx::query(
            "UPDATE a2a_tasks SET state = 'TASK_STATE_FAILED', status_timestamp = $2, \
             updated_at = $2 WHERE agent_id = $1 \
             AND state IN ('TASK_STATE_SUBMITTED', 'TASK_STATE_WORKING') AND updated_at < $2",
        )
        .bind(&task.agent_id)
        .bind(&cutoff)
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err(CTX, e))?;
        // Retention bound (A2A conformance 401): keep the newest finished tasks.
        let keep = i64::try_from(A2A_TERMINAL_TASK_RETENTION).unwrap_or(i64::MAX);
        let prune = format!(
            "DELETE FROM a2a_tasks WHERE agent_id = $1 AND state IN ({A2A_TERMINAL_STATES_SQL}) \
             AND id NOT IN (SELECT id FROM a2a_tasks WHERE agent_id = $1 \
             AND state IN ({A2A_TERMINAL_STATES_SQL}) ORDER BY updated_at DESC, id DESC LIMIT $2)"
        );
        sqlx::query(&prune)
            .bind(&task.agent_id)
            .bind(keep)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        tx.commit().await.map_err(|e| to_store_err(CTX, e))?;
        Ok(())
    }

    /// Fetch one task owned by `agent_id`.
    ///
    /// # Errors
    ///
    /// Surfaces query failures and corrupt JSON columns.
    pub(super) async fn a2a_task_get_pg(
        &self,
        agent_id: &str,
        id: &str,
    ) -> StoreResult<Option<A2aTaskRow>> {
        const CTX: &str = "a2a_task_get";
        let sql =
            format!("SELECT {PG_SELECT_COLUMNS} FROM a2a_tasks WHERE id = $1 AND agent_id = $2");
        let row: Option<TaskTuple> = sqlx::query_as(&sql)
            .bind(id)
            .bind(agent_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        match row {
            Some(t) => Ok(Some(self.a2a_finish_row(t).await?)),
            None => Ok(None),
        }
    }

    /// List the caller's tasks, newest update first.
    ///
    /// # Errors
    ///
    /// Surfaces query failures and corrupt JSON columns.
    pub(super) async fn a2a_task_list_pg(
        &self,
        agent_id: &str,
        filter: &A2aTaskFilter,
    ) -> StoreResult<A2aTaskPage> {
        const CTX: &str = "a2a_task_list";
        const WHERE: &str = "agent_id = $1 \
             AND ($2::text IS NULL OR context_id = $2) \
             AND ($3::text IS NULL OR state = $3) \
             AND ($4::text IS NULL OR status_timestamp > $4)";
        let total: (i64,) =
            sqlx::query_as(&format!("SELECT COUNT(*) FROM a2a_tasks WHERE {WHERE}"))
                .bind(agent_id)
                .bind(filter.context_id.as_deref())
                .bind(filter.state.as_deref())
                .bind(filter.status_timestamp_after.as_deref())
                .fetch_one(&self.pool)
                .await
                .map_err(|e| to_store_err(CTX, e))?;
        let sql = format!(
            "SELECT {PG_SELECT_COLUMNS} FROM a2a_tasks WHERE {WHERE} \
             ORDER BY updated_at DESC, id ASC LIMIT $5 OFFSET $6"
        );
        let fetched: Vec<TaskTuple> = sqlx::query_as(&sql)
            .bind(agent_id)
            .bind(filter.context_id.as_deref())
            .bind(filter.state.as_deref())
            .bind(filter.status_timestamp_after.as_deref())
            .bind(i64::try_from(filter.limit).unwrap_or(i64::MAX))
            .bind(i64::try_from(filter.offset).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        let mut rows = Vec::with_capacity(fetched.len());
        for t in fetched {
            rows.push(self.a2a_finish_row(t).await?);
        }
        Ok(A2aTaskPage {
            rows,
            total: usize::try_from(total.0).unwrap_or(0),
        })
    }

    /// Every task row of every agent (content-free), oldest first, for export.
    ///
    /// # Errors
    ///
    /// Surfaces query failures and corrupt JSON columns.
    pub(super) async fn a2a_task_export_pg(&self) -> StoreResult<Vec<A2aTaskRow>> {
        const CTX: &str = "a2a_task_export";
        let sql =
            format!("SELECT {PG_SELECT_COLUMNS} FROM a2a_tasks ORDER BY created_at ASC, id ASC");
        let fetched: Vec<TaskTuple> = sqlx::query_as(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        let mut rows = Vec::with_capacity(fetched.len());
        for t in fetched {
            rows.push(self.a2a_finish_row(t).await?);
        }
        Ok(rows)
    }

    /// Atomic compare-and-set transition; `true` for the single winner. The
    /// history entry and artifact are appended inside the statement and the
    /// entry's inbox memory is linked in the same transaction.
    ///
    /// # Errors
    ///
    /// Surfaces the record-stop refusal, an oversized history entry and any
    /// query failure.
    pub(super) async fn a2a_task_transition_pg(
        &self,
        agent_id: &str,
        id: &str,
        from_states: &[&str],
        to_state: &str,
        update: &A2aTaskUpdate,
    ) -> StoreResult<bool> {
        const CTX: &str = "a2a_task_transition";
        self.gate_record_stop().await?;
        if from_states.is_empty() {
            return Ok(false);
        }
        let history = update
            .history_append
            .as_ref()
            .map(A2aHistoryEntry::to_bounded_json)
            .transpose()
            .map_err(|e| corrupt(&e))?;
        let artifact = update.artifact_append.as_ref().map(ToString::to_string);
        let from: Vec<String> = from_states.iter().map(|s| (*s).to_string()).collect();
        let mut tx = self.pool.begin().await.map_err(|e| to_store_err(CTX, e))?;
        let result = sqlx::query(
            "UPDATE a2a_tasks SET state = $1, status_timestamp = $2, updated_at = $2, \
             history_json = CASE WHEN $3::text IS NULL THEN history_json \
                 ELSE (history_json::jsonb || jsonb_build_array($3::text::jsonb))::text END, \
             artifacts_json = CASE WHEN $4::text IS NULL THEN artifacts_json \
                 ELSE (artifacts_json::jsonb || jsonb_build_array($4::text::jsonb))::text END \
             WHERE id = $5 AND agent_id = $6 AND state = ANY($7)",
        )
        .bind(to_state)
        .bind(&update.status_timestamp)
        .bind(history.as_deref())
        .bind(artifact.as_deref())
        .bind(id)
        .bind(agent_id)
        .bind(&from)
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err(CTX, e))?;
        let won = result.rows_affected() == 1;
        if won {
            if let Some(entry) = &update.history_append {
                // Linked only when the memory still exists (see the sqlite twin).
                sqlx::query(
                    "INSERT INTO a2a_task_memories (task_id, memory_id) \
                     SELECT $1, id FROM memories WHERE id = $2 ON CONFLICT DO NOTHING",
                )
                .bind(id)
                .bind(&entry.memory_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| to_store_err(CTX, e))?;
            }
        }
        tx.commit().await.map_err(|e| to_store_err(CTX, e))?;
        Ok(won)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(history: &str, artifacts: &str, metadata: &str) -> TaskTuple {
        (
            "t1".into(),
            "c".into(),
            "a".into(),
            "TASK_STATE_WORKING".into(),
            "ts".into(),
            history.into(),
            artifacts.into(),
            metadata.into(),
            "ts".into(),
            "ts".into(),
        )
    }

    #[test]
    fn corrupt_json_column_is_an_error_not_a_default() {
        // #8444 r2 code LOW-3 (postgres decode path).
        assert!(tuple_to_task(tuple("[]", "[]", "{}")).is_ok());
        assert!(tuple_to_task(tuple("not json", "[]", "{}")).is_err());
        assert!(tuple_to_task(tuple("[]", "{", "{}")).is_err());
        assert!(tuple_to_task(tuple("[]", "[]", "")).is_err());
    }
}
