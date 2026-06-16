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

/// Outcome of a state-guarded transition (free-fn shared by SAL + MCP).
///
/// The SAL adapter maps these to its `StoreError` variants; the MCP
/// handler maps them to caller-facing error strings. Both share the
/// single sqlite implementation in [`transition`].
pub enum TransitionOutcome {
    /// No `actions` row matched the id.
    NotFound,
    /// `from → to` is not a legal coordination transition.
    Illegal {
        from: crate::models::ActionState,
        to: crate::models::ActionState,
    },
    /// The transition applied; carries the re-fetched action.
    Updated(Action),
}

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

/// Canonical wire-message for an illegal coordination transition,
/// shared byte-for-byte by the SAL sqlite + postgres adapters and the
/// MCP handler (pm-v3.1: one spelling of the magic string, not three).
#[must_use]
pub fn illegal_transition_detail(
    from: crate::models::ActionState,
    to: crate::models::ActionState,
) -> String {
    format!(
        "illegal action transition: {} -> {}",
        from.as_str(),
        to.as_str()
    )
}

/// State-guarded transition of one action. Fetches the current state,
/// validates `from → to` via [`crate::models::ActionState::can_transition_to`],
/// then updates `state` / `claimed_by` / `updated_at` and re-fetches.
///
/// # Errors
/// Propagates the `rusqlite` query/update error.
pub fn transition(
    conn: &Connection,
    id: &str,
    to: crate::models::ActionState,
    claimed_by: Option<&str>,
    now: i64,
) -> rusqlite::Result<TransitionOutcome> {
    let current: Option<String> = conn
        .query_row(
            "SELECT state FROM actions WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(cs) = current else {
        return Ok(TransitionOutcome::NotFound);
    };
    let from = crate::models::ActionState::from_str(&cs).unwrap_or_default();
    if !from.can_transition_to(to) {
        return Ok(TransitionOutcome::Illegal { from, to });
    }
    conn.execute(
        "UPDATE actions SET state = ?1, claimed_by = ?2, updated_at = ?3 WHERE id = ?4",
        params![to.as_str(), claimed_by, now, id],
    )?;
    let action = conn.query_row(
        &format!("{ACTION_SELECT_SQL} WHERE id = ?1"),
        params![id],
        row_to_action,
    )?;
    Ok(TransitionOutcome::Updated(action))
}

/// List actions filtered by optional `namespace` / `state`, newest-first,
/// capped at `limit`.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn list(
    conn: &Connection,
    namespace: Option<&str>,
    state: Option<crate::models::ActionState>,
    limit: usize,
) -> rusqlite::Result<Vec<Action>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut sql = format!("{ACTION_SELECT_SQL} WHERE 1 = 1");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(ns) = namespace {
        sql.push_str(" AND namespace = ?");
        binds.push(Box::new(ns.to_string()));
    }
    if let Some(st) = state {
        sql.push_str(" AND state = ?");
        binds.push(Box::new(st.as_str().to_string()));
    }
    sql.push_str(" ORDER BY updated_at DESC LIMIT ?");
    binds.push(Box::new(lim));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_action,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Insert a typed DAG edge between two actions. `INSERT OR IGNORE` so a
/// duplicate `(from, to, type)` triple is a no-op.
///
/// # Errors
/// Propagates the `rusqlite` insert error.
pub fn add_edge(
    conn: &Connection,
    from_action: &str,
    to_action: &str,
    edge_type: crate::models::EdgeType,
    now: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO action_edges (from_action, to_action, edge_type, created_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![from_action, to_action, edge_type.as_str(), now],
    )?;
    Ok(())
}

/// List every edge touching `action_id` (as either endpoint), oldest-first.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn edges_for(
    conn: &Connection,
    action_id: &str,
) -> rusqlite::Result<Vec<crate::models::ActionEdge>> {
    let mut stmt = conn.prepare(
        "SELECT from_action, to_action, edge_type, created_at FROM action_edges \
          WHERE from_action = ?1 OR to_action = ?1 ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map(params![action_id], |r| {
        Ok(crate::models::ActionEdge {
            from_action: r.get(0)?,
            to_action: r.get(1)?,
            edge_type: crate::models::EdgeType::from_str(&r.get::<_, String>(2)?)
                .unwrap_or(crate::models::EdgeType::Sibling),
            created_at: r.get(3)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// #1709 Pillar 1 — `leases` by-action-id SELECT (canonical column order for
/// [`row_to_lease`]). One definition shared by every lease read (the SAL
/// adapter + the MCP `memory_lease_*` handlers).
pub const LEASE_SELECT_BY_ID_SQL: &str = "SELECT action_id, holder, acquired_at, expires_at, heartbeat_at \
     FROM leases WHERE action_id = ?1";

/// Map a `rusqlite` row (the [`LEASE_SELECT_BY_ID_SQL`] column order) to a
/// [`crate::models::Lease`].
///
/// # Errors
/// Propagates the `rusqlite` column-access error.
pub fn row_to_lease(r: &rusqlite::Row<'_>) -> rusqlite::Result<crate::models::Lease> {
    Ok(crate::models::Lease {
        action_id: r.get(0)?,
        holder: r.get(1)?,
        acquired_at: r.get(2)?,
        expires_at: r.get(3)?,
        heartbeat_at: r.get(4)?,
    })
}

/// Outcome of a lease acquisition (free-fn shared by SAL + MCP).
///
/// The SAL adapter maps `Conflict` to `StoreError::Conflict`; the MCP
/// handler maps it to a caller-facing error string. Both share the single
/// sqlite implementation in [`lease_acquire`].
pub enum LeaseAcquire {
    /// A non-expired lease held by a different holder blocks acquisition.
    Conflict,
    /// The lease was acquired (or re-acquired by the same holder); carries
    /// the re-fetched lease row.
    Acquired(crate::models::Lease),
}

/// Acquire a single-holder lease on an action. A non-expired lease held by a
/// different holder blocks acquisition (`Conflict`); otherwise the lease is
/// inserted-or-replaced and re-fetched (`Acquired`).
///
/// # Errors
/// Propagates the `rusqlite` query/insert error.
pub fn lease_acquire(
    conn: &Connection,
    action_id: &str,
    holder: &str,
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<LeaseAcquire> {
    // A non-expired lease held by a different holder blocks acquisition.
    let existing: Option<(String, i64)> = conn
        .query_row(
            "SELECT holder, expires_at FROM leases WHERE action_id = ?1",
            params![action_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((h, exp)) = existing
        && exp > now
        && h != holder
    {
        return Ok(LeaseAcquire::Conflict);
    }
    conn.execute(
        "INSERT OR REPLACE INTO leases \
            (action_id, holder, acquired_at, expires_at, heartbeat_at) \
         VALUES (?1, ?2, ?3, ?4, ?3)",
        params![action_id, holder, now, expires_at],
    )?;
    let lease = conn.query_row(LEASE_SELECT_BY_ID_SQL, params![action_id], row_to_lease)?;
    Ok(LeaseAcquire::Acquired(lease))
}

/// Heartbeat-renew an owned lease (`expires_at` + `heartbeat_at` bump). Returns
/// `None` when no lease matches `(action_id, holder)` (missing or owned by a
/// different holder); otherwise the re-fetched lease.
///
/// # Errors
/// Propagates the `rusqlite` update/query error.
pub fn lease_renew(
    conn: &Connection,
    action_id: &str,
    holder: &str,
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<Option<crate::models::Lease>> {
    let n = conn.execute(
        "UPDATE leases SET expires_at = ?1, heartbeat_at = ?2 \
          WHERE action_id = ?3 AND holder = ?4",
        params![expires_at, now, action_id, holder],
    )?;
    if n == 0 {
        return Ok(None);
    }
    let lease = conn.query_row(LEASE_SELECT_BY_ID_SQL, params![action_id], row_to_lease)?;
    Ok(Some(lease))
}

/// Release an owned lease. Returns `true` when a row was deleted, `false` when
/// no lease matched `(action_id, holder)`.
///
/// # Errors
/// Propagates the `rusqlite` delete error.
pub fn lease_release(conn: &Connection, action_id: &str, holder: &str) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "DELETE FROM leases WHERE action_id = ?1 AND holder = ?2",
        params![action_id, holder],
    )?;
    Ok(n > 0)
}

/// Read the lease on an action. `None` when no lease row exists.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn lease_get(
    conn: &Connection,
    action_id: &str,
) -> rusqlite::Result<Option<crate::models::Lease>> {
    conn.query_row(LEASE_SELECT_BY_ID_SQL, params![action_id], row_to_lease)
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

    #[test]
    fn transition_legal_illegal_notfound() {
        let conn = fresh();
        create(&conn, &sample("t1")).unwrap();

        // Legal: pending → claimed, stamping claimed_by + updated_at.
        match transition(
            &conn,
            "t1",
            ActionState::Claimed,
            Some("holder-1"),
            1_700_000_500,
        )
        .unwrap()
        {
            TransitionOutcome::Updated(a) => {
                assert_eq!(a.state, ActionState::Claimed);
                assert_eq!(a.claimed_by.as_deref(), Some("holder-1"));
                assert_eq!(a.updated_at, 1_700_000_500);
            }
            _ => panic!("expected Updated"),
        }

        // Illegal: claimed → done (must go via in_progress).
        match transition(&conn, "t1", ActionState::Done, None, 1_700_000_600).unwrap() {
            TransitionOutcome::Illegal { from, to } => {
                assert_eq!(from, ActionState::Claimed);
                assert_eq!(to, ActionState::Done);
            }
            _ => panic!("expected Illegal"),
        }

        // NotFound: unknown id.
        assert!(matches!(
            transition(&conn, "missing", ActionState::Claimed, None, 1_700_000_700).unwrap(),
            TransitionOutcome::NotFound
        ));
    }

    #[test]
    fn list_filters_namespace_and_state() {
        let conn = fresh();
        let mut a = sample("l1");
        a.namespace = "ns-a".to_string();
        create(&conn, &a).unwrap();
        let mut b = sample("l2");
        b.namespace = "ns-b".to_string();
        create(&conn, &b).unwrap();

        let all = list(&conn, None, None, 50).unwrap();
        assert_eq!(all.len(), 2);

        let only_a = list(&conn, Some("ns-a"), None, 50).unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].id, "l1");

        // Move l1 to claimed, then filter by state.
        transition(&conn, "l1", ActionState::Claimed, None, 1_700_000_500).unwrap();
        let claimed = list(&conn, None, Some(ActionState::Claimed), 50).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, "l1");
    }

    #[test]
    fn add_edge_then_edges_for_roundtrips() {
        use crate::models::EdgeType;
        let conn = fresh();
        create(&conn, &sample("e1")).unwrap();
        create(&conn, &sample("e2")).unwrap();

        add_edge(&conn, "e1", "e2", EdgeType::Requires, 1_700_000_100).unwrap();
        // Duplicate triple is a no-op (INSERT OR IGNORE).
        add_edge(&conn, "e1", "e2", EdgeType::Requires, 1_700_000_200).unwrap();

        let from_e1 = edges_for(&conn, "e1").unwrap();
        assert_eq!(from_e1.len(), 1);
        assert_eq!(from_e1[0].from_action, "e1");
        assert_eq!(from_e1[0].to_action, "e2");
        assert_eq!(from_e1[0].edge_type, EdgeType::Requires);

        // e2 is the `to` endpoint, so it sees the same edge.
        let from_e2 = edges_for(&conn, "e2").unwrap();
        assert_eq!(from_e2.len(), 1);
    }

    #[test]
    fn lease_acquire_renew_release_get_roundtrips() {
        let conn = fresh();
        // A lease references a real action row, so create one first.
        create(&conn, &sample("lease-1")).unwrap();

        // First acquire by holder-a succeeds.
        match lease_acquire(&conn, "lease-1", "holder-a", 1_700_000_000, 1_700_000_060).unwrap() {
            LeaseAcquire::Acquired(l) => {
                assert_eq!(l.action_id, "lease-1");
                assert_eq!(l.holder, "holder-a");
                assert_eq!(l.acquired_at, 1_700_000_000);
                assert_eq!(l.expires_at, 1_700_000_060);
                assert_eq!(l.heartbeat_at, 1_700_000_000);
            }
            LeaseAcquire::Conflict => panic!("expected Acquired"),
        }

        // A different holder cannot acquire while the lease is non-expired.
        assert!(matches!(
            lease_acquire(&conn, "lease-1", "holder-b", 1_700_000_010, 1_700_000_070).unwrap(),
            LeaseAcquire::Conflict
        ));

        // The same holder may re-acquire (heartbeat-style refresh).
        match lease_acquire(&conn, "lease-1", "holder-a", 1_700_000_020, 1_700_000_080).unwrap() {
            LeaseAcquire::Acquired(l) => assert_eq!(l.expires_at, 1_700_000_080),
            LeaseAcquire::Conflict => panic!("same-holder re-acquire must succeed"),
        }

        // Renew by the owner bumps expires_at + heartbeat_at.
        let renewed = lease_renew(&conn, "lease-1", "holder-a", 1_700_000_030, 1_700_000_090)
            .unwrap()
            .expect("owned renew is Some");
        assert_eq!(renewed.expires_at, 1_700_000_090);
        assert_eq!(renewed.heartbeat_at, 1_700_000_030);

        // Renew by a non-owner is a no-op (None).
        assert!(
            lease_renew(&conn, "lease-1", "holder-b", 1_700_000_040, 1_700_000_100)
                .unwrap()
                .is_none()
        );
        // Renew on a missing action is None.
        assert!(
            lease_renew(&conn, "missing", "holder-a", 1_700_000_040, 1_700_000_100)
                .unwrap()
                .is_none()
        );

        // get returns the present lease.
        let got = lease_get(&conn, "lease-1").unwrap().expect("lease present");
        assert_eq!(got.holder, "holder-a");
        assert_eq!(got.expires_at, 1_700_000_090);

        // Release by a non-owner does nothing (false), the lease persists.
        assert!(!lease_release(&conn, "lease-1", "holder-b").unwrap());
        assert!(lease_get(&conn, "lease-1").unwrap().is_some());

        // Release by the owner removes it (true); get is then absent.
        assert!(lease_release(&conn, "lease-1", "holder-a").unwrap());
        assert!(lease_get(&conn, "lease-1").unwrap().is_none());
        // Release on an already-absent lease is false.
        assert!(!lease_release(&conn, "lease-1", "holder-a").unwrap());
    }
}
