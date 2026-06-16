// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — attested-checkpoint sqlite free-functions.
//!
//! These operate on a raw [`rusqlite::Connection`] so BOTH the SAL
//! [`crate::store::sqlite::SqliteStore`] adapter (which delegates here) AND
//! the future MCP stdio `memory_checkpoint_*` tool handlers (which hold a
//! bare `Connection`, not a SAL store) share one implementation — exactly
//! the split [`crate::signals`] uses for the signed-signal surface. The
//! postgres adapter keeps its own sqlx-native path in
//! `crate::store::postgres`.
//!
//! Backs the v61 `checkpoints` table (conditional coordination gates whose
//! resolution is Ed25519-attested). The `signature` / `resolver_pubkey`
//! columns are persisted verbatim as byte vectors — a checkpoint resolved
//! with empty `signature` / `resolver_pubkey` is simply unattested; the
//! attested-resolution signing logic lands in a subsequent unit.

use crate::models::{Checkpoint, CheckpointState, ConditionType};
use rusqlite::{Connection, OptionalExtension, params};

/// SELECT column list for the `checkpoints` table, in the canonical order
/// [`row_to_checkpoint`] expects. One definition shared by every checkpoint
/// read.
pub const CHECKPOINT_SELECT_SQL: &str = "SELECT id, namespace, title, condition_type, condition, \
     state, created_by, resolved_by, resolution, resolution_note, signature, resolver_pubkey, \
     created_at, deadline_at, resolved_at, metadata FROM checkpoints";

/// Shared SQL fragment for the `state` equality narrowing — one definition
/// referenced by both the sqlite free-fns here and the postgres adapter so
/// the filter clause never drifts (and the literal lives at one site).
pub const SQL_AND_STATE_EQ: &str = " AND state = ";

/// Shared SQL fragment for the newest-first ordering + LIMIT placeholder
/// position — referenced by both the sqlite free-fns here and the postgres
/// adapter. Callers append the placeholder (`?`) / bind the limit.
pub const SQL_ORDER_BY_CREATED_DESC_LIMIT: &str = " ORDER BY created_at DESC LIMIT ";

/// Map a `rusqlite` row (the [`CHECKPOINT_SELECT_SQL`] column order) to a
/// [`Checkpoint`].
///
/// # Errors
/// Propagates the `rusqlite` column-access error.
pub fn row_to_checkpoint(r: &rusqlite::Row<'_>) -> rusqlite::Result<Checkpoint> {
    Ok(Checkpoint {
        id: r.get(0)?,
        namespace: r.get(1)?,
        title: r.get(2)?,
        condition_type: ConditionType::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
        condition: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(serde_json::Value::Null),
        state: CheckpointState::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
        created_by: r.get(6)?,
        resolved_by: r.get(7)?,
        resolution: r.get(8)?,
        resolution_note: r.get(9)?,
        // The `signature` / `resolver_pubkey` columns are nullable BLOB —
        // read as `Option<Vec<u8>>` and collapse NULL to an empty vec so a
        // pre-resolution (unattested) row round-trips without a column-type
        // error. INSERT always writes a non-NULL (possibly empty) vec.
        signature: r.get::<_, Option<Vec<u8>>>(10)?.unwrap_or_default(),
        resolver_pubkey: r.get::<_, Option<Vec<u8>>>(11)?.unwrap_or_default(),
        created_at: r.get(12)?,
        deadline_at: r.get(13)?,
        resolved_at: r.get(14)?,
        metadata: serde_json::from_str(&r.get::<_, String>(15)?).unwrap_or(serde_json::Value::Null),
    })
}

/// Insert a checkpoint. Returns the checkpoint id.
///
/// # Errors
/// Propagates the `rusqlite` insert error.
pub fn insert(conn: &Connection, cp: &Checkpoint) -> rusqlite::Result<String> {
    conn.execute(
        "INSERT INTO checkpoints \
            (id, namespace, title, condition_type, condition, state, created_by, \
             resolved_by, resolution, resolution_note, signature, resolver_pubkey, \
             created_at, deadline_at, resolved_at, metadata) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            cp.id,
            cp.namespace,
            cp.title,
            cp.condition_type.as_str(),
            cp.condition.to_string(),
            cp.state.as_str(),
            cp.created_by,
            cp.resolved_by,
            cp.resolution,
            cp.resolution_note,
            cp.signature,
            cp.resolver_pubkey,
            cp.created_at,
            cp.deadline_at,
            cp.resolved_at,
            cp.metadata.to_string(),
        ],
    )?;
    Ok(cp.id.clone())
}

/// Fetch a checkpoint by id. `None` when absent.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn get(conn: &Connection, id: &str) -> rusqlite::Result<Option<Checkpoint>> {
    conn.query_row(
        &format!("{CHECKPOINT_SELECT_SQL} WHERE id = ?1"),
        params![id],
        row_to_checkpoint,
    )
    .optional()
}

/// List a namespace's checkpoints, newest-first, capped at `limit`. When
/// `state` is `Some`, narrows to that lifecycle state; when `None`, returns
/// every checkpoint in the namespace.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn list(
    conn: &Connection,
    namespace: &str,
    state: Option<CheckpointState>,
    limit: usize,
) -> rusqlite::Result<Vec<Checkpoint>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut sql = format!("{CHECKPOINT_SELECT_SQL} WHERE namespace = ?");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(namespace.to_string())];
    if let Some(st) = state {
        sql.push_str(SQL_AND_STATE_EQ);
        sql.push('?');
        binds.push(Box::new(st.as_str().to_string()));
    }
    sql.push_str(SQL_ORDER_BY_CREATED_DESC_LIMIT);
    sql.push('?');
    binds.push(Box::new(lim));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_checkpoint,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Query a namespace's checkpoints narrowed by an optional `condition_type`
/// AND an optional `state`, newest-first, capped at `limit`.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn query(
    conn: &Connection,
    namespace: &str,
    condition_type: Option<ConditionType>,
    state: Option<CheckpointState>,
    limit: usize,
) -> rusqlite::Result<Vec<Checkpoint>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut sql = format!("{CHECKPOINT_SELECT_SQL} WHERE namespace = ?");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(namespace.to_string())];
    if let Some(ct) = condition_type {
        sql.push_str(" AND condition_type = ?");
        binds.push(Box::new(ct.as_str().to_string()));
    }
    if let Some(st) = state {
        sql.push_str(SQL_AND_STATE_EQ);
        sql.push('?');
        binds.push(Box::new(st.as_str().to_string()));
    }
    sql.push_str(SQL_ORDER_BY_CREATED_DESC_LIMIT);
    sql.push('?');
    binds.push(Box::new(lim));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_checkpoint,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Resolve a checkpoint: set `state` + `resolved_by` + `resolution` +
/// `resolution_note` + `resolved_at`. Returns the resolved row, or `None`
/// if the id does not exist.
///
/// # Errors
/// Propagates the `rusqlite` update/query error.
pub fn resolve(
    conn: &Connection,
    id: &str,
    state: CheckpointState,
    resolved_by: &str,
    resolution: Option<&str>,
    resolution_note: Option<&str>,
    resolved_at: i64,
) -> rusqlite::Result<Option<Checkpoint>> {
    let n = conn.execute(
        "UPDATE checkpoints SET state = ?1, resolved_by = ?2, resolution = ?3, \
            resolution_note = ?4, resolved_at = ?5 WHERE id = ?6",
        params![
            state.as_str(),
            resolved_by,
            resolution,
            resolution_note,
            resolved_at,
            id,
        ],
    )?;
    if n == 0 {
        return Ok(None);
    }
    get(conn, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn sample(id: &str) -> Checkpoint {
        Checkpoint {
            id: id.to_string(),
            namespace: "_cp".to_string(),
            title: "needs approval".to_string(),
            condition_type: ConditionType::Approval,
            condition: serde_json::json!({}),
            state: CheckpointState::Pending,
            created_by: "agent-creator".to_string(),
            resolved_by: None,
            resolution: None,
            resolution_note: None,
            signature: vec![],
            resolver_pubkey: vec![],
            created_at: 1_700_000_000,
            deadline_at: None,
            resolved_at: None,
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn insert_then_get_roundtrips() {
        let conn = fresh();
        let id = insert(&conn, &sample("c1")).unwrap();
        assert_eq!(id, "c1");
        let got = get(&conn, "c1").unwrap().expect("present");
        assert_eq!(got.namespace, "_cp");
        assert_eq!(got.title, "needs approval");
        assert_eq!(got.condition_type, ConditionType::Approval);
        assert_eq!(got.state, CheckpointState::Pending);
        assert_eq!(got.created_by, "agent-creator");
        assert_eq!(got.condition, serde_json::json!({}));
        assert_eq!(got.metadata, serde_json::json!({}));
        assert!(got.signature.is_empty());
        assert!(got.resolver_pubkey.is_empty());
        assert!(got.resolved_by.is_none());
        assert!(got.resolved_at.is_none());
        assert!(get(&conn, "missing").unwrap().is_none());
    }

    #[test]
    fn list_filters_by_namespace_and_state() {
        let conn = fresh();
        insert(&conn, &sample("p1")).unwrap();
        let mut p2 = sample("p2");
        p2.created_at = 1_700_000_100;
        insert(&conn, &p2).unwrap();
        // A resolved checkpoint in the same namespace.
        let mut done = sample("done");
        done.state = CheckpointState::Resolved;
        done.created_at = 1_700_000_050;
        insert(&conn, &done).unwrap();
        // A checkpoint in a different namespace must not surface.
        let mut other = sample("other-ns");
        other.namespace = "_cp_elsewhere".to_string();
        insert(&conn, &other).unwrap();

        // No state filter — every checkpoint in the namespace, newest-first.
        let all = list(&conn, "_cp", None, 50).unwrap();
        let ids: Vec<&str> = all.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["p2", "done", "p1"], "newest-first ordering");
        assert!(!ids.contains(&"other-ns"), "other-namespace hidden");

        // State filter narrows to pending only.
        let pending = list(&conn, "_cp", Some(CheckpointState::Pending), 50).unwrap();
        let pids: Vec<&str> = pending.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(pids, vec!["p2", "p1"]);
    }

    #[test]
    fn query_filters_by_condition_type() {
        let conn = fresh();
        insert(&conn, &sample("approval")).unwrap();
        let mut deadline = sample("deadline");
        deadline.condition_type = ConditionType::Deadline;
        deadline.created_at = 1_700_000_100;
        insert(&conn, &deadline).unwrap();

        let approvals = query(&conn, "_cp", Some(ConditionType::Approval), None, 50).unwrap();
        let ids: Vec<&str> = approvals.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["approval"]);

        // condition_type + state together.
        let none = query(
            &conn,
            "_cp",
            Some(ConditionType::Deadline),
            Some(CheckpointState::Resolved),
            50,
        )
        .unwrap();
        assert!(none.is_empty(), "no resolved deadline checkpoint exists");
    }

    #[test]
    fn resolve_flips_state_and_stamps_resolver() {
        let conn = fresh();
        insert(&conn, &sample("r1")).unwrap();
        let resolved = resolve(
            &conn,
            "r1",
            CheckpointState::Resolved,
            "agent-approver",
            Some("approved"),
            Some("looks good"),
            1_700_000_500,
        )
        .unwrap()
        .expect("resolve returns the updated row");
        assert_eq!(resolved.state, CheckpointState::Resolved);
        assert_eq!(resolved.resolved_by.as_deref(), Some("agent-approver"));
        assert_eq!(resolved.resolution.as_deref(), Some("approved"));
        assert_eq!(resolved.resolution_note.as_deref(), Some("looks good"));
        assert_eq!(resolved.resolved_at, Some(1_700_000_500));

        // The persisted row reflects the resolution.
        let got = get(&conn, "r1").unwrap().expect("present");
        assert_eq!(got.state, CheckpointState::Resolved);
        assert_eq!(got.resolved_at, Some(1_700_000_500));
    }

    #[test]
    fn resolve_missing_returns_none() {
        let conn = fresh();
        let missing = resolve(
            &conn,
            "does-not-exist",
            CheckpointState::Resolved,
            "agent-approver",
            None,
            None,
            1_700_000_500,
        )
        .unwrap();
        assert!(
            missing.is_none(),
            "resolving a missing checkpoint yields None"
        );
    }
}
