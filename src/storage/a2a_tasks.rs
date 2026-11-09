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
//!
//! # Content-free history
//!
//! A task row NEVER stores message content. `history_json` holds
//! [`A2aHistoryEntry`] values (ids only: messageId, role, contextId, taskId and
//! the stored inbox memory id). The content stays in the inbox memory, so
//! erase, at-rest sealing and the secret screen apply to it. The
//! `a2a_task_memories` link table names the memories a task's history points
//! at and cascades from `memories`, so every delete path (erase, delete, gc,
//! archive) removes the link in the same statement; reads keep only the
//! entries whose memory is still linked ([`filter_linked_history`]).

use std::collections::HashSet;

use anyhow::{Context as _, Result, anyhow};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One persisted A2A Task. `state` is the A2A TaskState wire string
/// (`TASK_STATE_*`); `history` is the content-free entry array (see the module
/// docs) and `artifacts` / `metadata` are the Task's JSON columns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2aTaskRow {
    /// Task id (primary key, chosen by the server).
    pub id: String,
    /// A2A context id the task belongs to.
    pub context_id: String,
    /// The AUTHENTICATED agent that owns the task.
    pub agent_id: String,
    /// `TASK_STATE_*` wire string.
    pub state: String,
    /// RFC 3339 timestamp of the last state change.
    pub status_timestamp: String,
    /// JSON array of [`A2aHistoryEntry`] values (ids only, never content).
    pub history: Value,
    /// JSON array of the task's artifacts.
    pub artifacts: Value,
    /// JSON object of task metadata.
    pub metadata: Value,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 timestamp of the last write (the `ListTasks` sort key).
    pub updated_at: String,
}

/// One content-free history entry: which message was exchanged and which
/// inbox memory holds its content. Serialised camelCase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aHistoryEntry {
    /// The caller-chosen A2A `messageId`.
    pub message_id: String,
    /// The remote-chosen role label (`ROLE_USER` / `ROLE_AGENT`).
    pub role: String,
    /// The A2A `contextId` of the message.
    pub context_id: String,
    /// The A2A `taskId` of the message.
    pub task_id: String,
    /// Id of the inbox memory that holds the message content.
    pub memory_id: String,
}

/// Largest serialised size of one history entry. Five id-like fields of at
/// most `a2a::MAX_ID_LEN` (128) bytes each, even if every byte JSON-escapes to
/// two, plus the keys stay below this; an entry above it is refused, so a task
/// row cannot be used as a content store.
pub const A2A_HISTORY_ENTRY_MAX_BYTES: usize = 2048;

impl A2aHistoryEntry {
    /// The entry as bounded JSON.
    ///
    /// # Errors
    ///
    /// Fails when the serialised entry exceeds [`A2A_HISTORY_ENTRY_MAX_BYTES`].
    pub fn to_bounded_json(&self) -> Result<String> {
        let text = serde_json::to_string(self)?;
        if text.len() > A2A_HISTORY_ENTRY_MAX_BYTES {
            return Err(anyhow!("a2a history entry exceeds its size bound"));
        }
        Ok(text)
    }
}

/// Keep only the history entries whose inbox memory is still linked to the
/// task. An entry without a readable `memoryId` is dropped (fail closed).
#[must_use]
pub fn filter_linked_history(history: &Value, linked: &HashSet<String>) -> Value {
    let kept = history
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter(|e| {
                    e.get("memoryId")
                        .and_then(Value::as_str)
                        .is_some_and(|m| linked.contains(m))
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Value::Array(kept)
}

/// `ListTasks` filter. `limit` is already clamped by the caller (1..=100).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct A2aTaskFilter {
    /// Only tasks in this context.
    pub context_id: Option<String>,
    /// Only tasks in this `TASK_STATE_*` state.
    pub state: Option<String>,
    /// RFC 3339 lower bound (exclusive) on `status_timestamp`.
    pub status_timestamp_after: Option<String>,
    /// Rows to skip.
    pub offset: usize,
    /// Page size (already clamped).
    pub limit: usize,
}

/// One page of `ListTasks` plus the total number of matching rows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct A2aTaskPage {
    /// The rows of this page, newest update first.
    pub rows: Vec<A2aTaskRow>,
    /// Number of rows matching the filter across all pages.
    pub total: usize,
}

/// What a state transition writes together with the new state. History and
/// artifacts are APPENDED inside the same statement (never read-modify-write
/// in the caller), so two concurrent continuations cannot lose each other's
/// entries.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct A2aTaskUpdate {
    /// New `status_timestamp` (also the new `updated_at`).
    pub status_timestamp: String,
    /// `Some` appends one content-free entry to `history_json` and links its
    /// inbox memory to the task, in the same transaction.
    pub history_append: Option<A2aHistoryEntry>,
    /// `Some` appends one artifact to `artifacts_json`.
    pub artifact_append: Option<Value>,
}

/// Most finished (terminal) tasks kept per authenticated agent. When an insert
/// pushes an agent past this bound its oldest finished tasks are deleted, so
/// the task table cannot grow without limit (A2A conformance 401). Active
/// (non-terminal) tasks younger than [`A2A_ACTIVE_TASK_MAX_AGE_SECS`] are never
/// pruned.
pub const A2A_TERMINAL_TASK_RETENTION: usize = 1000;

/// A task still SUBMITTED or WORKING after this long without an update can
/// never complete (the call is synchronous), so an insert fail-and-retires it
/// (state FAILED) and the terminal retention bound then covers it. Keeps the
/// non-terminal row count bounded.
pub const A2A_ACTIVE_TASK_MAX_AGE_SECS: i64 = crate::SECS_PER_DAY;

/// SQL list of the terminal `TASK_STATE_*` strings (completed, failed,
/// canceled, rejected), kept next to the retention bound that uses it.
pub const A2A_TERMINAL_STATES_SQL: &str = "'TASK_STATE_COMPLETED', 'TASK_STATE_FAILED', \
     'TASK_STATE_CANCELED', 'TASK_STATE_REJECTED'";

/// SQL list of the states an abandoned task is retired from.
const ACTIVE_STATES_SQL: &str = "'TASK_STATE_SUBMITTED', 'TASK_STATE_WORKING'";
const FAILED_STATE: &str = "TASK_STATE_FAILED";

const SELECT_COLUMNS: &str = "id, context_id, agent_id, state, status_timestamp, \
     history_json, artifacts_json, metadata_json, created_at, updated_at";

/// RFC 3339 (millisecond, `Z`) cutoff before which an active task is
/// abandoned, relative to `now`. Same text form as `status_timestamp`, so the
/// comparison is lexicographic.
#[must_use]
pub fn abandoned_cutoff(now: DateTime<Utc>) -> String {
    (now - Duration::seconds(A2A_ACTIVE_TASK_MAX_AGE_SECS))
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Column label used in the corrupt-column error for `history_json`.
pub const COLUMN_HISTORY_JSON: &str = "history_json";
/// Column label used in the corrupt-column error for `artifacts_json`.
pub const COLUMN_ARTIFACTS_JSON: &str = "artifacts_json";
/// Column label used in the corrupt-column error for `metadata_json`.
pub const COLUMN_METADATA_JSON: &str = "metadata_json";

/// Decode one JSON column. A corrupt column is an error, never replaced by a
/// default (a silent default would present fabricated state to the caller).
///
/// # Errors
///
/// Fails when `raw` is not valid JSON.
pub fn parse_json_column(raw: &str, column: &str) -> Result<Value> {
    serde_json::from_str(raw).with_context(|| format!("a2a_tasks.{column} holds corrupt JSON"))
}

fn conversion_error(idx: usize, err: &anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        idx,
        rusqlite::types::Type::Text,
        err.to_string().into(),
    )
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
        history: parse_json_column(&history, COLUMN_HISTORY_JSON)
            .map_err(|e| conversion_error(5, &e))?,
        artifacts: parse_json_column(&artifacts, COLUMN_ARTIFACTS_JSON)
            .map_err(|e| conversion_error(6, &e))?,
        metadata: parse_json_column(&metadata, COLUMN_METADATA_JSON)
            .map_err(|e| conversion_error(7, &e))?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn linked_memory_ids(conn: &Connection, task_id: &str) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare("SELECT memory_id FROM a2a_task_memories WHERE task_id = ?1")?;
    let ids = stmt
        .query_map(params![task_id], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;
    Ok(ids)
}

fn with_linked_history(conn: &Connection, mut task: A2aTaskRow) -> Result<A2aTaskRow> {
    let linked = linked_memory_ids(conn, &task.id)?;
    task.history = filter_linked_history(&task.history, &linked);
    Ok(task)
}

/// Insert a new Task row, then in the SAME transaction fail-and-retire the
/// caller's abandoned active tasks and prune its oldest terminal tasks beyond
/// [`A2A_TERMINAL_TASK_RETENTION`].
///
/// # Errors
///
/// Surfaces the record-stop refusal and any SQL failure (a duplicate id is a
/// primary-key violation, never an overwrite).
pub fn a2a_task_insert(conn: &Connection, task: &A2aTaskRow) -> Result<()> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    tx.execute(
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
    a2a_task_retire_abandoned(&tx, &task.agent_id, &abandoned_cutoff(Utc::now()))?;
    a2a_task_prune_terminal(&tx, &task.agent_id, A2A_TERMINAL_TASK_RETENTION)?;
    tx.commit()?;
    Ok(())
}

/// Fail-and-retire `agent_id`'s SUBMITTED / WORKING tasks last updated before
/// `cutoff`: the state becomes FAILED and the status timestamp and `updated_at`
/// take the cutoff text, so the move is deterministic and the terminal
/// retention bound covers the row afterwards.
///
/// # Errors
///
/// Surfaces the record-stop refusal and SQL failures.
pub fn a2a_task_retire_abandoned(conn: &Connection, agent_id: &str, cutoff: &str) -> Result<usize> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let sql = format!(
        "UPDATE a2a_tasks SET state = '{FAILED_STATE}', status_timestamp = ?2, updated_at = ?2 \
         WHERE agent_id = ?1 AND state IN ({ACTIVE_STATES_SQL}) AND updated_at < ?2"
    );
    Ok(conn.execute(&sql, params![agent_id, cutoff])?)
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
/// another caller's id. The history keeps only entries whose inbox memory is
/// still linked.
///
/// # Errors
///
/// Surfaces SQL failures and corrupt JSON columns.
pub fn a2a_task_get(conn: &Connection, agent_id: &str, id: &str) -> Result<Option<A2aTaskRow>> {
    use rusqlite::OptionalExtension as _;
    let sql = format!("SELECT {SELECT_COLUMNS} FROM a2a_tasks WHERE id = ?1 AND agent_id = ?2");
    let row = conn
        .query_row(&sql, params![id, agent_id], row_to_task)
        .optional()?;
    row.map(|t| with_linked_history(conn, t)).transpose()
}

/// List the caller's tasks, newest update first.
///
/// # Errors
///
/// Surfaces SQL failures and corrupt JSON columns.
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
    let rows = rows
        .into_iter()
        .map(|t| with_linked_history(conn, t))
        .collect::<Result<Vec<_>>>()?;
    Ok(A2aTaskPage {
        rows,
        total: usize::try_from(total).unwrap_or(0),
    })
}

/// Every task row of every agent (content-free by construction), oldest
/// first, for the export surfaces.
///
/// # Errors
///
/// Surfaces SQL failures and corrupt JSON columns.
pub fn a2a_task_export(conn: &Connection) -> Result<Vec<A2aTaskRow>> {
    let sql = format!("SELECT {SELECT_COLUMNS} FROM a2a_tasks ORDER BY created_at ASC, id ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map([], row_to_task)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|t| with_linked_history(conn, t))
        .collect()
}

/// Atomic compare-and-set transition for the caller's task: move to
/// `to_state` only if the task is currently in one of `from_states`, appending
/// the update's history entry and artifact in the same statement and linking
/// the entry's inbox memory in the same transaction. Returns `true` for the
/// single winner, `false` when the task is unknown, owned by someone else, or
/// no longer in an allowed source state.
///
/// # Errors
///
/// Surfaces the record-stop refusal, an oversized history entry and any SQL
/// failure.
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
    let history = update
        .history_append
        .as_ref()
        .map(A2aHistoryEntry::to_bounded_json)
        .transpose()?;
    let artifact = update.artifact_append.as_ref().map(ToString::to_string);
    let placeholders = (0..from_states.len())
        .map(|i| format!("?{}", i + 7))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "UPDATE a2a_tasks SET state = ?1, status_timestamp = ?2, updated_at = ?2, \
         history_json = CASE WHEN ?3 IS NULL THEN history_json \
             ELSE json_insert(history_json, '$[#]', json(?3)) END, \
         artifacts_json = CASE WHEN ?4 IS NULL THEN artifacts_json \
             ELSE json_insert(artifacts_json, '$[#]', json(?4)) END \
         WHERE id = ?5 AND agent_id = ?6 AND state IN ({placeholders})"
    );
    let mut args: Vec<&dyn rusqlite::ToSql> = vec![
        &to_state,
        &update.status_timestamp,
        &history,
        &artifact,
        &id,
        &agent_id,
    ];
    for s in from_states {
        args.push(s);
    }
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let changed = tx.execute(&sql, args.as_slice())?;
    if changed == 1 {
        if let Some(entry) = &update.history_append {
            // Linked only when the memory still exists: an already-erased
            // memory simply never appears in the rendered history.
            tx.execute(
                "INSERT OR IGNORE INTO a2a_task_memories (task_id, memory_id) \
                 SELECT ?1, id FROM memories WHERE id = ?2",
                params![id, entry.memory_id],
            )?;
        }
    }
    tx.commit()?;
    Ok(changed == 1)
}

// v101 (#8444): durable `a2a_tasks` table for the Agent2Agent standard
// binding. Additive `CREATE TABLE IF NOT EXISTS`, idempotent, NoLoss. The
// postgres twin is `PostgresStore::migrate_v101`.
const MIGRATION_V101_SQLITE: &str = include_str!("../../migrations/sqlite/0085_v101_a2a_tasks.sql");

pub(super) fn migrate_v101(conn: &Connection) -> Result<()> {
    conn.execute_batch(MIGRATION_V101_SQLITE)?;
    conn.execute(super::migrations::SQL_CLEAR_SCHEMA_VERSION, [])?;
    conn.execute("INSERT INTO schema_version (version) VALUES (101)", [])?;
    Ok(())
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
            status_timestamp: crate::a2a::now_timestamp(),
            history: serde_json::json!([]),
            artifacts: serde_json::json!([]),
            metadata: serde_json::json!({}),
            created_at: crate::a2a::now_timestamp(),
            updated_at: crate::a2a::now_timestamp(),
        }
    }

    fn upd(ts: &str) -> A2aTaskUpdate {
        A2aTaskUpdate {
            status_timestamp: ts.to_string(),
            ..A2aTaskUpdate::default()
        }
    }

    fn entry(memory_id: &str) -> A2aHistoryEntry {
        A2aHistoryEntry {
            message_id: "m1".to_string(),
            role: "ROLE_USER".to_string(),
            context_id: "ctx".to_string(),
            task_id: "t1".to_string(),
            memory_id: memory_id.to_string(),
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
            t.updated_at = format!("2026-01-01T00:00:0{i}.000Z");
            a2a_task_insert(&c, &t).unwrap();
        }
        a2a_task_insert(&c, &task("other", "bob", "TASK_STATE_COMPLETED")).unwrap();
        // An active task is kept only while it is younger than the abandoned
        // cutoff, so the active fixture carries the current time.
        let mut fresh = task("fresh", "alice", "TASK_STATE_WORKING");
        fresh.updated_at = crate::a2a::now_timestamp();
        a2a_task_insert(&c, &fresh).unwrap();
        assert_eq!(a2a_task_prune_terminal(&c, "alice", 2).unwrap(), 3);
        assert!(a2a_task_get(&c, "alice", "done-4").unwrap().is_some());
        assert!(a2a_task_get(&c, "alice", "done-3").unwrap().is_some());
        assert!(a2a_task_get(&c, "alice", "done-0").unwrap().is_none());
        assert!(a2a_task_get(&c, "bob", "other").unwrap().is_some());
        assert!(a2a_task_get(&c, "alice", "fresh").unwrap().is_some());
    }

    #[test]
    fn insert_fails_and_retires_abandoned_active_tasks() {
        // #8444 r2 code LOW-5: non-terminal rows are bounded.
        let c = conn();
        let mut stale_w = task("stale-w", "alice", "TASK_STATE_WORKING");
        stale_w.updated_at = "2026-01-01T00:00:00.000Z".to_string();
        a2a_task_insert(&c, &stale_w).unwrap();
        let mut stale_s = task("stale-s", "alice", "TASK_STATE_SUBMITTED");
        stale_s.updated_at = "2026-01-01T00:00:00.000Z".to_string();
        a2a_task_insert(&c, &stale_s).unwrap();
        let mut fresh = task("fresh", "alice", "TASK_STATE_WORKING");
        fresh.updated_at = crate::a2a::now_timestamp();
        a2a_task_insert(&c, &fresh).unwrap();
        a2a_task_insert(&c, &task("bobs", "bob", "TASK_STATE_WORKING")).unwrap();
        // Every insert retires the inserting agent's own abandoned rows; the
        // two stale rows are retired by their own and alice's later inserts.
        for id in ["stale-w", "stale-s"] {
            let row = a2a_task_get(&c, "alice", id).unwrap().unwrap();
            assert_eq!(row.state, FAILED_STATE, "{id} must be retired");
        }
        let fresh = a2a_task_get(&c, "alice", "fresh").unwrap().unwrap();
        assert_eq!(fresh.state, "TASK_STATE_WORKING");
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
            &upd("2026-10-31T00:00:01.000Z"),
        )
        .expect("cas");
        assert!(won);
        let lost = a2a_task_transition(
            &c,
            "alice",
            "t1",
            &["TASK_STATE_SUBMITTED", "TASK_STATE_WORKING"],
            "TASK_STATE_COMPLETED",
            &upd("2026-10-31T00:00:02.000Z"),
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
            &upd("2026-10-31T00:00:01.000Z"),
        )
        .expect("cas");
        assert!(!moved);
    }

    #[test]
    fn appends_accumulate_and_never_overwrite() {
        // #8444 r2 code LOW-2: history and artifacts are appended atomically.
        let c = conn();
        a2a_task_insert(&c, &task("t1", "alice", "TASK_STATE_WORKING")).expect("ins");
        for i in 0..3 {
            let mut u = upd(&format!("2026-10-31T00:00:0{i}.000Z"));
            u.history_append = Some(entry(&format!("mem-{i}")));
            u.artifact_append = Some(serde_json::json!({"artifactId": format!("a{i}")}));
            assert!(
                a2a_task_transition(
                    &c,
                    "alice",
                    "t1",
                    &["TASK_STATE_WORKING"],
                    "TASK_STATE_WORKING",
                    &u
                )
                .unwrap()
            );
        }
        let raw: String = c
            .query_row(
                "SELECT history_json FROM a2a_tasks WHERE id = 't1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let all: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(all.as_array().unwrap().len(), 3);
        let raw: String = c
            .query_row(
                "SELECT artifacts_json FROM a2a_tasks WHERE id = 't1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let all: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(all.as_array().unwrap().len(), 3);
    }

    #[test]
    fn corrupt_json_column_is_an_error_not_a_default() {
        // #8444 r2 code LOW-3.
        let c = conn();
        a2a_task_insert(&c, &task("t1", "alice", "TASK_STATE_WORKING")).expect("ins");
        c.execute(
            "UPDATE a2a_tasks SET artifacts_json = 'not json' WHERE id = 't1'",
            [],
        )
        .unwrap();
        assert!(a2a_task_get(&c, "alice", "t1").is_err());
        assert!(
            a2a_task_list(
                &c,
                "alice",
                &A2aTaskFilter {
                    limit: 10,
                    ..A2aTaskFilter::default()
                }
            )
            .is_err()
        );
        assert!(parse_json_column("{", "metadata_json").is_err());
    }

    #[test]
    fn history_entry_is_bounded_and_content_free() {
        // #8444 r2 sec LOW-2: an entry above the bound is refused.
        let mut big = entry("m");
        big.message_id = "x".repeat(A2A_HISTORY_ENTRY_MAX_BYTES);
        assert!(big.to_bounded_json().is_err());
        let ok = entry("mem-1").to_bounded_json().unwrap();
        assert!(ok.len() <= A2A_HISTORY_ENTRY_MAX_BYTES);
        let v: Value = serde_json::from_str(&ok).unwrap();
        let mut keys = v
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["contextId", "memoryId", "messageId", "role", "taskId"]
        );
    }

    #[test]
    fn only_linked_history_entries_are_kept() {
        let history = serde_json::json!([
            {"memoryId": "kept"}, {"memoryId": "erased"}, {"noMemoryId": 1}
        ]);
        let linked = HashSet::from(["kept".to_string()]);
        let out = filter_linked_history(&history, &linked);
        assert_eq!(out, serde_json::json!([{"memoryId": "kept"}]));
        assert_eq!(
            filter_linked_history(&Value::Null, &linked),
            serde_json::json!([])
        );
    }

    #[test]
    fn export_lists_every_agents_tasks() {
        let c = conn();
        a2a_task_insert(&c, &task("t1", "alice", "TASK_STATE_COMPLETED")).unwrap();
        a2a_task_insert(&c, &task("t2", "bob", "TASK_STATE_COMPLETED")).unwrap();
        let rows = a2a_task_export(&c).unwrap();
        assert_eq!(rows.len(), 2);
    }
}
