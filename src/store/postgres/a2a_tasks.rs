// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444 - postgres twin of [`crate::storage::a2a_tasks`]: durable Task rows
//! for the Agent2Agent (A2A 1.0) standard binding.
//!
//! Own module for the same `qual_10_module_size_ceiling` budget reason as
//! `api_key_bind_3535`. Every statement is scoped by the AUTHENTICATED
//! `agent_id`, and the transition is a single compare-and-set `UPDATE`
//! (`state = ANY($from)`) whose affected-row count names the one winner.

use crate::storage::a2a_tasks::{
    A2A_TERMINAL_STATES_SQL, A2A_TERMINAL_TASK_RETENTION, A2aTaskFilter, A2aTaskPage, A2aTaskRow,
    A2aTaskUpdate,
};
use serde_json::Value;

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

fn json_or_default(raw: &str, default: Value) -> Value {
    serde_json::from_str(raw).unwrap_or(default)
}

fn tuple_to_task(t: TaskTuple) -> A2aTaskRow {
    A2aTaskRow {
        id: t.0,
        context_id: t.1,
        agent_id: t.2,
        state: t.3,
        status_timestamp: t.4,
        history: json_or_default(&t.5, Value::Array(Vec::new())),
        artifacts: json_or_default(&t.6, Value::Array(Vec::new())),
        metadata: json_or_default(&t.7, Value::Object(serde_json::Map::new())),
        created_at: t.8,
        updated_at: t.9,
    }
}

impl PostgresStore {
    /// Insert a new Task row. The record-stop gate is taken in the function
    /// that owns the `INSERT` (B7 structural scan) and by the trait arm (B7'
    /// parity scan).
    ///
    /// # Errors
    ///
    /// Surfaces the record-stop refusal and any query failure.
    pub(super) async fn a2a_task_insert_pg(&self, task: &A2aTaskRow) -> StoreResult<()> {
        const CTX: &str = "a2a_task_insert";
        self.gate_record_stop().await?;
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
        .execute(&self.pool)
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
            .execute(&self.pool)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        Ok(())
    }

    /// Fetch one task owned by `agent_id`.
    ///
    /// # Errors
    ///
    /// Surfaces query failures.
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
        Ok(row.map(tuple_to_task))
    }

    /// List the caller's tasks, newest update first.
    ///
    /// # Errors
    ///
    /// Surfaces query failures.
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
        let rows: Vec<TaskTuple> = sqlx::query_as(&sql)
            .bind(agent_id)
            .bind(filter.context_id.as_deref())
            .bind(filter.state.as_deref())
            .bind(filter.status_timestamp_after.as_deref())
            .bind(i64::try_from(filter.limit).unwrap_or(i64::MAX))
            .bind(i64::try_from(filter.offset).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| to_store_err(CTX, e))?;
        Ok(A2aTaskPage {
            rows: rows.into_iter().map(tuple_to_task).collect(),
            total: usize::try_from(total.0).unwrap_or(0),
        })
    }

    /// Atomic compare-and-set transition; `true` for the single winner.
    ///
    /// # Errors
    ///
    /// Surfaces the record-stop refusal and any query failure.
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
        let from: Vec<String> = from_states.iter().map(|s| (*s).to_string()).collect();
        let result = sqlx::query(
            "UPDATE a2a_tasks SET state = $1, status_timestamp = $2, updated_at = $2, \
             history_json = COALESCE($3, history_json), \
             artifacts_json = COALESCE($4, artifacts_json) \
             WHERE id = $5 AND agent_id = $6 AND state = ANY($7)",
        )
        .bind(to_state)
        .bind(&update.status_timestamp)
        .bind(update.history.as_ref().map(ToString::to_string))
        .bind(update.artifacts.as_ref().map(ToString::to_string))
        .bind(id)
        .bind(agent_id)
        .bind(&from)
        .execute(&self.pool)
        .await
        .map_err(|e| to_store_err(CTX, e))?;
        Ok(result.rows_affected() == 1)
    }
}
