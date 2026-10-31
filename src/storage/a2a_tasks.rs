// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444 - durable Task rows for the Google Agent2Agent (A2A 1.0) standard
//! binding (SQLite SSOT; the postgres twin is `store::postgres::a2a_tasks`).
//!
//! Every function takes the `agent_id` of the AUTHENTICATED caller and scopes
//! the statement by it, so a caller can never read, list or move another
//! caller's task: an unknown id and another caller's id are indistinguishable
//! (`None` / `false`). State changes are compare-and-set `UPDATE`s guarded by
//! the set of states the transition may start from; the winner is the one
//! statement that reports exactly one affected row, so a concurrent
//! `CancelTask` and completion leave exactly one terminal state.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One persisted A2A Task. `state` is the A2A TaskState wire string
/// (`TASK_STATE_*`); the JSON columns hold the Task's `history`, `artifacts`
/// and `metadata` verbatim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskRow {
    pub id: String,
    pub context_id: String,
    pub agent_id: String,
    pub state: String,
    pub status_timestamp: String,
    pub history: Value,
    pub artifacts: Value,
    pub metadata: Value,
    pub created_at: String,
    pub updated_at: String,
}

/// `ListTasks` filter. `limit` is already clamped by the caller (1..=100).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct A2aTaskFilter {
    pub context_id: Option<String>,
    pub state: Option<String>,
    /// RFC 3339 lower bound (exclusive) on `status_timestamp`.
    pub status_timestamp_after: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

/// One page of `ListTasks` plus the total number of matching rows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct A2aTaskPage {
    pub rows: Vec<A2aTaskRow>,
    pub total: usize,
}

/// The columns a state transition rewrites together with the state.
#[derive(Debug, Clone, PartialEq)]
pub struct A2aTaskUpdate {
    pub status_timestamp: String,
    /// `Some` replaces `history_json`.
    pub history: Option<Value>,
    /// `Some` replaces `artifacts_json`.
    pub artifacts: Option<Value>,
}

/// Most finished (terminal) tasks kept per authenticated agent. When an insert
/// pushes an agent past this bound its oldest finished tasks are deleted, so
/// the task table cannot grow without limit (A2A conformance 401). Active
/// (non-terminal) tasks are never pruned.
pub const A2A_TERMINAL_TASK_RETENTION: usize = 1000;

/// SQL list of the terminal `TASK_STATE_*` strings (completed, failed,
/// canceled, rejected), kept next to the retention bound that uses it.
pub const A2A_TERMINAL_STATES_SQL: &str = "'TASK_STATE_COMPLETED', 'TASK_STATE_FAILED', \
     'TASK_STATE_CANCELED', 'TASK_STATE_REJECTED'";

const SELECT_COLUMNS: &str = "id, context_id, agent_id, state, status_timestamp, \
     history_json, artifacts_json, metadata_json, created_at, updated_at";

fn json_or_default(raw: &str, default: Value) -> Value {
    serde_json::from_str(raw).unwrap_or(default)
}

fn row_to_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<A2aTaskRow> {
    let history: String = row.get(5)?;
    let artifacts: String = row.get(6)?;
    let metadata: String = row.get(7)?;
    Ok(A2aTaskRow {
        id: row.get(0)?,
        context_id: row.get(1)?,
        agent_id: row.get(2)?,
        state: row.get(3)?,
        status_timestamp: row.get(4)?,
        history: json_or_default(&history, Value::Array(Vec::new())),
        artifacts: json_or_default(&artifacts, Value::Array(Vec::new())),
        metadata: json_or_default(&metadata, Value::Object(serde_json::Map::new())),
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

/// Insert a new Task row.
///
/// # Errors
///
/// Surfaces the record-stop refusal and any SQL failure (a duplicate id is a
/// primary-key violation, never an overwrite).
pub fn a2a_task_insert(conn: &Connection, task: &A2aTaskRow) -> Result<()> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    conn.execute(
        "INSERT INTO a2a_tasks (id, context_id, agent_id, state, status_timestamp, \
         history_json, artifacts_json, metadata_json, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            task.id,
            task.context_id,
            task.agent_id,
            task.state,
            task.status_timestamp,
            task.history.to_string(),
            task.artifacts.to_string(),
            task.metadata.to_string(),
            task.created_at,
            task.updated_at,
        ],
    )?;
    a2a_task_prune_terminal(conn, &task.agent_id, A2A_TERMINAL_TASK_RETENTION)?;
    Ok(())
}

/// Delete `agent_id`'s oldest terminal tasks beyond `keep`.
///
/// # Errors
///
/// Surfaces the record-stop refusal and SQL failures.
pub fn a2a_task_prune_terminal(conn: &Connection, agent_id: &str, keep: usize) -> Result<usize> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let keep = i64::try_from(keep).unwrap_or(i64::MAX);
    let sql = format!(
        "DELETE FROM a2a_tasks WHERE agent_id = ?1 AND state IN ({A2A_TERMINAL_STATES_SQL}) \
         AND id NOT IN (SELECT id FROM a2a_tasks WHERE agent_id = ?1 \
         AND state IN ({A2A_TERMINAL_STATES_SQL}) ORDER BY updated_at DESC, id DESC LIMIT ?2)"
    );
    Ok(conn.execute(&sql, params![agent_id, keep])?)
}

/// Fetch one task owned by `agent_id`. `Ok(None)` for an unknown id AND for
/// another caller's id.
///
/// # Errors
///
/// Surfaces SQL failures.
pub fn a2a_task_get(conn: &Connection, agent_id: &str, id: &str) -> Result<Option<A2aTaskRow>> {
    use rusqlite::OptionalExtension as _;
    let sql = format!("SELECT {SELECT_COLUMNS} FROM a2a_tasks WHERE id = ?1 AND agent_id = ?2");
    Ok(conn
        .query_row(&sql, params![id, agent_id], row_to_task)
        .optional()?)
}

/// List the caller's tasks, newest update first.
///
/// # Errors
///
/// Surfaces SQL failures.
pub fn a2a_task_list(
    conn: &Connection,
    agent_id: &str,
    filter: &A2aTaskFilter,
) -> Result<A2aTaskPage> {
    // Named parameters are bound positionally: `?1` is always the caller; an
    // absent filter binds NULL and the `IS NULL OR` guard makes it a no-op.
    let where_clause = "agent_id = ?1 \
         AND (?2 IS NULL OR context_id = ?2) \
         AND (?3 IS NULL OR state = ?3) \
         AND (?4 IS NULL OR status_timestamp > ?4)";
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM a2a_tasks WHERE {where_clause}"),
        params![
            agent_id,
            filter.context_id,
            filter.state,
            filter.status_timestamp_after
        ],
        |r| r.get(0),
    )?;
    let sql = format!(
        "SELECT {SELECT_COLUMNS} FROM a2a_tasks WHERE {where_clause} \
         ORDER BY updated_at DESC, id ASC LIMIT ?5 OFFSET ?6"
    );
    let mut stmt = conn.prepare(&sql)?;
    let limit = i64::try_from(filter.limit).unwrap_or(i64::MAX);
    let offset = i64::try_from(filter.offset).unwrap_or(i64::MAX);
    let rows = stmt
        .query_map(
            params![
                agent_id,
                filter.context_id,
                filter.state,
                filter.status_timestamp_after,
                limit,
                offset
            ],
            row_to_task,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(A2aTaskPage {
        rows,
        total: usize::try_from(total).unwrap_or(0),
    })
}

/// Atomic compare-and-set transition for the caller's task: move to
/// `to_state` only if the task is currently in one of `from_states`.
/// Returns `true` for the single winner, `false` when the task is unknown,
/// owned by someone else, or no longer in an allowed source state.
///
/// # Errors
///
/// Surfaces the record-stop refusal and any SQL failure.
pub fn a2a_task_transition(
    conn: &Connection,
    agent_id: &str,
    id: &str,
    from_states: &[&str],
    to_state: &str,
    update: &A2aTaskUpdate,
) -> Result<bool> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    if from_states.is_empty() {
        return Ok(false);
    }
    let placeholders = (0..from_states.len())
        .map(|i| format!("?{}", i + 7))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "UPDATE a2a_tasks SET state = ?1, status_timestamp = ?2, updated_at = ?2, \
         history_json = COALESCE(?3, history_json), \
         artifacts_json = COALESCE(?4, artifacts_json) \
         WHERE id = ?5 AND agent_id = ?6 AND state IN ({placeholders})"
    );
    let history = update.history.as_ref().map(ToString::to_string);
    let artifacts = update.artifacts.as_ref().map(ToString::to_string);
    let mut args: Vec<&dyn rusqlite::ToSql> = vec![
        &to_state,
        &update.status_timestamp,
        &history,
        &artifacts,
        &id,
        &agent_id,
    ];
    for s in from_states {
        args.push(s);
    }
    let changed = conn.execute(&sql, args.as_slice())?;
    Ok(changed == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        // The full migrated schema (the record-stop gate reads `signed_events`).
        crate::db::open(std::path::Path::new(":memory:")).expect("open migrated db")
    }

    fn task(id: &str, agent: &str, state: &str) -> A2aTaskRow {
        A2aTaskRow {
            id: id.to_string(),
            context_id: "ctx".to_string(),
            agent_id: agent.to_string(),
            state: state.to_string(),
            status_timestamp: "2026-10-31T00:00:00Z".to_string(),
            history: serde_json::json!([]),
            artifacts: serde_json::json!([]),
            metadata: serde_json::json!({}),
            created_at: "2026-10-31T00:00:00Z".to_string(),
            updated_at: "2026-10-31T00:00:00Z".to_string(),
        }
    }

    fn upd(ts: &str) -> A2aTaskUpdate {
        A2aTaskUpdate {
            status_timestamp: ts.to_string(),
            history: None,
            artifacts: None,
        }
    }

    #[test]
    fn get_and_list_are_scoped_to_the_caller() {
        let c = conn();
        a2a_task_insert(&c, &task("t1", "alice", "TASK_STATE_SUBMITTED")).expect("ins");
        a2a_task_insert(&c, &task("t2", "bob", "TASK_STATE_SUBMITTED")).expect("ins");
        assert!(a2a_task_get(&c, "alice", "t1").expect("get").is_some());
        assert!(a2a_task_get(&c, "alice", "t2").expect("get").is_none());
        let page = a2a_task_list(
            &c,
            "alice",
            &A2aTaskFilter {
                limit: 50,
                ..A2aTaskFilter::default()
            },
        )
        .expect("list");
        assert_eq!(page.total, 1);
        assert_eq!(page.rows[0].id, "t1");
    }

    #[test]
    fn prune_keeps_newest_terminal_and_all_active_tasks() {
        let c = conn();
        for i in 0..5 {
            let mut t = task(&format!("done-{i}"), "alice", "TASK_STATE_COMPLETED");
            t.updated_at = format!("2026-01-01T00:00:0{i}Z");
            a2a_task_insert(&c, &t).unwrap();
        }
        a2a_task_insert(&c, &task("live", "alice", "TASK_STATE_WORKING")).unwrap();
        a2a_task_insert(&c, &task("other", "bob", "TASK_STATE_COMPLETED")).unwrap();
        assert_eq!(a2a_task_prune_terminal(&c, "alice", 2).unwrap(), 3);
        assert!(a2a_task_get(&c, "alice", "done-4").unwrap().is_some());
        assert!(a2a_task_get(&c, "alice", "done-3").unwrap().is_some());
        assert!(a2a_task_get(&c, "alice", "done-0").unwrap().is_none());
        assert!(a2a_task_get(&c, "alice", "live").unwrap().is_some());
        assert!(a2a_task_get(&c, "bob", "other").unwrap().is_some());
    }

    #[test]
    fn transition_is_compare_and_set() {
        let c = conn();
        a2a_task_insert(&c, &task("t1", "alice", "TASK_STATE_WORKING")).expect("ins");
        let won = a2a_task_transition(
            &c,
            "alice",
            "t1",
            &["TASK_STATE_WORKING"],
            "TASK_STATE_CANCELED",
            &upd("2026-10-31T00:00:01Z"),
        )
        .expect("cas");
        assert!(won);
        let lost = a2a_task_transition(
            &c,
            "alice",
            "t1",
            &["TASK_STATE_SUBMITTED", "TASK_STATE_WORKING"],
            "TASK_STATE_COMPLETED",
            &upd("2026-10-31T00:00:02Z"),
        )
        .expect("cas");
        assert!(!lost);
        let row = a2a_task_get(&c, "alice", "t1").expect("get").expect("row");
        assert_eq!(row.state, "TASK_STATE_CANCELED");
    }

    #[test]
    fn transition_refuses_another_callers_task() {
        let c = conn();
        a2a_task_insert(&c, &task("t1", "alice", "TASK_STATE_WORKING")).expect("ins");
        let moved = a2a_task_transition(
            &c,
            "mallory",
            "t1",
            &["TASK_STATE_WORKING"],
            "TASK_STATE_CANCELED",
            &upd("2026-10-31T00:00:01Z"),
        )
        .expect("cas");
        assert!(!moved);
    }
}
