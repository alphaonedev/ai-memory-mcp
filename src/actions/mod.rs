// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — coordination-action sqlite free-functions.
//!
//! These operate on a raw [`rusqlite::Connection`] so BOTH the SAL
//! [`crate::store::sqlite::SqliteStore`] adapter (which delegates here) AND
//! the MCP stdio `memory_action_*` tool handlers (which hold a bare
//! `Connection`, not a SAL store) share one implementation — the same split
//! the recall-observations ledger uses (`crate::observations`). The postgres
//! adapter keeps its own sqlx-native path in `crate::store::postgres`.

use crate::models::Action;
use rusqlite::{Connection, OptionalExtension, params};

/// SELECT column list for the `actions` table, in the canonical order
/// [`row_to_action`] expects. One definition shared by every action read.
pub const ACTION_SELECT_SQL: &str = "SELECT id, namespace, kind, state, title, payload, \
     priority, agent_id, claimed_by, vector_clock, metadata, created_at, updated_at \
     FROM actions";

/// Map a `rusqlite` row (the [`ACTION_SELECT_SQL`] column order) to an
/// [`Action`].
///
/// # Errors
/// Propagates the `rusqlite` column-access error.
pub fn row_to_action(r: &rusqlite::Row<'_>) -> rusqlite::Result<Action> {
    Ok(Action {
        id: r.get(0)?,
        namespace: r.get(1)?,
        kind: r.get(2)?,
        state: crate::models::ActionState::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
        title: r.get(4)?,
        payload: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or(serde_json::Value::Null),
        priority: r.get(6)?,
        agent_id: r.get(7)?,
        claimed_by: r.get(8)?,
        vector_clock: serde_json::from_str(&r.get::<_, String>(9)?)
            .unwrap_or(serde_json::Value::Null),
        metadata: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or(serde_json::Value::Null),
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
    })
}

/// Insert a coordination action. Returns the action id.
///
/// # Errors
/// Propagates the `rusqlite` insert error.
pub fn create(conn: &Connection, action: &Action) -> rusqlite::Result<String> {
    conn.execute(
        "INSERT INTO actions \
            (id, namespace, kind, state, title, payload, priority, agent_id, \
             claimed_by, vector_clock, metadata, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            action.id,
            action.namespace,
            action.kind,
            action.state.as_str(),
            action.title,
            action.payload.to_string(),
            action.priority,
            action.agent_id,
            action.claimed_by,
            action.vector_clock.to_string(),
            action.metadata.to_string(),
            action.created_at,
            action.updated_at,
        ],
    )?;
    Ok(action.id.clone())
}

/// Fetch an action by id. `None` when absent.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn get(conn: &Connection, id: &str) -> rusqlite::Result<Option<Action>> {
    conn.query_row(
        &format!("{ACTION_SELECT_SQL} WHERE id = ?1"),
        params![id],
        row_to_action,
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ActionState;

    fn fresh() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn sample(id: &str) -> Action {
        Action {
            id: id.to_string(),
            namespace: "_act".to_string(),
            kind: "test.kind".to_string(),
            state: ActionState::Pending,
            title: "t".to_string(),
            payload: serde_json::json!({"a": 1}),
            priority: 5,
            agent_id: Some("agent-x".to_string()),
            claimed_by: None,
            vector_clock: serde_json::json!({}),
            metadata: serde_json::json!({}),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn create_then_get_roundtrips() {
        let conn = fresh();
        let id = create(&conn, &sample("a1")).unwrap();
        assert_eq!(id, "a1");
        let got = get(&conn, "a1").unwrap().expect("present");
        assert_eq!(got.namespace, "_act");
        assert_eq!(got.kind, "test.kind");
        assert_eq!(got.state, ActionState::Pending);
        assert_eq!(got.priority, 5);
        assert_eq!(got.agent_id.as_deref(), Some("agent-x"));
        assert_eq!(got.payload, serde_json::json!({"a": 1}));
        assert!(get(&conn, "missing").unwrap().is_none());
    }
}
