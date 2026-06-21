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

/// The single-row-by-id action SELECT, built from [`ACTION_SELECT_SQL`] with a
/// `WHERE id = ?1` tail. Hoisted into one helper so the read paths
/// (`get` / `transition` / `transition_cas`) share one spelling of the
/// template rather than duplicating it (pm-v3.1 hardcoded-literal gate).
#[must_use]
fn action_select_by_id_sql() -> String {
    format!("{ACTION_SELECT_SQL} WHERE id = ?1")
}

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
    conn.query_row(&action_select_by_id_sql(), params![id], row_to_action)
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
    let action = conn.query_row(&action_select_by_id_sql(), params![id], row_to_action)?;
    Ok(TransitionOutcome::Updated(action))
}

/// Outcome of a compare-and-swap [`transition_cas`]. Unlike
/// [`TransitionOutcome`], a `from`-state mismatch is a first-class
/// **non-error** variant ([`CasOutcome::StateMismatch`]) because a CAS miss on
/// the federation receive path is a normal, safe no-op — a stale re-broadcast
/// of a transition that local state has already moved past (#1718 hazard H1:
/// the action state machine is non-monotonic, so the target state alone is not
/// a safe idempotency key — the *expected source* state is the guard).
#[derive(Debug, Clone)]
pub enum CasOutcome {
    /// No `actions` row matched the id.
    NotFound,
    /// The row exists but its current state is not the expected `from` state —
    /// the compare-and-swap guard rejected the transition. Carries the actual
    /// current state for the caller's causal-ordering decision.
    StateMismatch {
        /// The action's actual current state (≠ the expected `from`).
        current: crate::models::ActionState,
    },
    /// `from → to` is not a legal coordination transition.
    Illegal {
        /// Source state of the rejected edge.
        from: crate::models::ActionState,
        /// Target state of the rejected edge.
        to: crate::models::ActionState,
    },
    /// The compare-and-swap held and the transition applied; carries the
    /// re-fetched action.
    Applied(Action),
}

/// Compare-and-swap transition: apply `from → to` **only** when the action is
/// still in `from`. The state guard lives in the `UPDATE ... WHERE id = ?
/// AND state = ?` predicate so the compare and the swap are a single atomic
/// statement — there is no read-then-write TOCTOU window for a concurrent
/// transition (or a duplicate federated re-broadcast) to slip through, unlike
/// composing [`get`] + [`transition`] across two statements (#1718 H1).
///
/// Returns [`CasOutcome::Applied`] when the swap held, [`CasOutcome::StateMismatch`]
/// when the row exists but has moved on (a safe federation no-op),
/// [`CasOutcome::NotFound`] when no row matches, and [`CasOutcome::Illegal`]
/// when `from → to` is not a legal edge.
///
/// # Errors
/// Propagates the `rusqlite` query/update error.
pub fn transition_cas(
    conn: &Connection,
    id: &str,
    from: crate::models::ActionState,
    to: crate::models::ActionState,
    claimed_by: Option<&str>,
    now: i64,
) -> rusqlite::Result<CasOutcome> {
    // Legality is a static property of the edge — reject illegal edges before
    // touching the row (cheap, and keeps an illegal op from racing a legal one).
    if !from.can_transition_to(to) {
        return Ok(CasOutcome::Illegal { from, to });
    }
    // Atomic compare-and-swap: the `AND state = ?5` predicate is the guard.
    let changed = conn.execute(
        "UPDATE actions SET state = ?1, claimed_by = ?2, updated_at = ?3 \
         WHERE id = ?4 AND state = ?5",
        params![to.as_str(), claimed_by, now, id, from.as_str()],
    )?;
    if changed == 0 {
        // Either the row does not exist, or it was no longer in `from`
        // (lost the CAS). Disambiguate for the caller's causal decision.
        let current: Option<String> = conn
            .query_row(
                "SELECT state FROM actions WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        return Ok(match current {
            None => CasOutcome::NotFound,
            Some(cs) => CasOutcome::StateMismatch {
                current: crate::models::ActionState::from_str(&cs).unwrap_or_default(),
            },
        });
    }
    let action = conn.query_row(&action_select_by_id_sql(), params![id], row_to_action)?;
    Ok(CasOutcome::Applied(action))
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

/// The FRONTIER `WHERE`-tail shared by [`frontier`] and [`next_action`]
/// (#1709 §11.4 Pillar-1 frontier surface). A pending action is UNBLOCKED iff
/// every `requires` / `gated_by` prerequisite is `done` AND no `blocks` edge
/// from a still-active blocker targets it. The two `NOT EXISTS` sub-queries
/// encode that predicate (directionality per the `EdgeType` docs in
/// `src/models/action.rs`):
/// - prerequisites/gates: an edge FROM the candidate TO a target that is not
///   `done` keeps the candidate blocked;
/// - blockers: a `blocks` edge whose `to_action` is the candidate, from a
///   blocker that is not yet terminal (`done`/`failed`/`abandoned`), keeps it
///   blocked.
///
/// `?1` is the namespace; the caller appends the ordering + limit binds.
fn frontier_where_tail() -> String {
    use crate::models::{ActionState, EdgeType};
    format!(
        "a.namespace = ?1 AND a.state = '{pending}' \
           AND NOT EXISTS ( \
             SELECT 1 FROM action_edges e JOIN actions b ON b.id = e.to_action \
             WHERE e.from_action = a.id \
               AND e.edge_type IN ('{requires}', '{gated_by}') \
               AND b.state <> '{done}') \
           AND NOT EXISTS ( \
             SELECT 1 FROM action_edges e JOIN actions b ON b.id = e.from_action \
             WHERE e.to_action = a.id AND e.edge_type = '{blocks}' \
               AND b.state NOT IN ('{done}', '{failed}', '{abandoned}'))",
        pending = ActionState::Pending.as_str(),
        requires = EdgeType::Requires.as_str(),
        gated_by = EdgeType::GatedBy.as_str(),
        done = ActionState::Done.as_str(),
        blocks = EdgeType::Blocks.as_str(),
        failed = ActionState::Failed.as_str(),
        abandoned = ActionState::Abandoned.as_str(),
    )
}

/// #1709 §11.4 — the ranked UNBLOCKED frontier: every pending action in
/// `namespace` whose prerequisites/gates are all `done` and that no active
/// blocker holds, ordered `priority DESC, created_at ASC` and capped at
/// `limit`. This is the FRONTIER query — see [`frontier_where_tail`] for the
/// exact UNBLOCKED predicate.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn frontier(conn: &Connection, namespace: &str, limit: usize) -> rusqlite::Result<Vec<Action>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let sql = format!(
        "{ACTION_SELECT_SQL} a WHERE {} ORDER BY a.priority DESC, a.created_at ASC LIMIT ?2",
        frontier_where_tail()
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![namespace, lim], row_to_action)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// #1709 §11.4 — the single highest-ranked UNBLOCKED action a caller should
/// pick up next: the top row of the [`frontier`] query (`LIMIT 1`). When
/// `agent_id` is `Some`, the candidate set is narrowed to actions with no
/// owner OR owned by the caller (`agent_id IS NULL OR agent_id = ?agent`) so
/// each agent only sees work it may claim. `None` when the frontier is empty.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn next_action(
    conn: &Connection,
    namespace: &str,
    agent_id: Option<&str>,
) -> rusqlite::Result<Option<Action>> {
    let mut sql = format!("{ACTION_SELECT_SQL} a WHERE {}", frontier_where_tail());
    if agent_id.is_some() {
        sql.push_str(" AND (a.agent_id = ?2 OR a.agent_id IS NULL)");
    }
    sql.push_str(" ORDER BY a.priority DESC, a.created_at ASC LIMIT 1");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(namespace.to_string())];
    if let Some(a) = agent_id {
        binds.push(Box::new(a.to_string()));
    }
    let mut stmt = conn.prepare(&sql)?;
    stmt.query_row(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_action,
    )
    .optional()
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

/// Reclaim (delete) every lease whose `expires_at <= now`, releasing the
/// action for a fresh holder. Returns the number of leases reclaimed.
///
/// # Errors
/// Propagates the `rusqlite` delete error.
pub fn sweep_expired_leases(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM leases WHERE expires_at <= ?1", params![now])
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
    fn transition_cas_guards_on_from_state() {
        let conn = fresh();
        create(&conn, &sample("c1")).unwrap();

        // CAS holds: pending → claimed when still pending.
        match transition_cas(
            &conn,
            "c1",
            ActionState::Pending,
            ActionState::Claimed,
            Some("holder-1"),
            1_700_000_500,
        )
        .unwrap()
        {
            CasOutcome::Applied(a) => {
                assert_eq!(a.state, ActionState::Claimed);
                assert_eq!(a.claimed_by.as_deref(), Some("holder-1"));
                assert_eq!(a.updated_at, 1_700_000_500);
            }
            other => panic!("expected Applied, got {other:?}"),
        }

        // Stale replay: the same pending → claimed op now misses the CAS
        // because local state has moved to `claimed` (#1718 H1 — non-monotonic
        // state machine, so the guard is the expected SOURCE state). Safe no-op.
        match transition_cas(
            &conn,
            "c1",
            ActionState::Pending,
            ActionState::Claimed,
            Some("holder-2"),
            1_700_000_600,
        )
        .unwrap()
        {
            CasOutcome::StateMismatch { current } => assert_eq!(current, ActionState::Claimed),
            other => panic!("expected StateMismatch, got {other:?}"),
        }
        // The losing CAS left the row untouched — holder-1 still owns it.
        let still = get(&conn, "c1").unwrap().expect("present");
        assert_eq!(still.claimed_by.as_deref(), Some("holder-1"));
        assert_eq!(still.updated_at, 1_700_000_500);

        // Legal non-monotonic release: claimed → pending applies when the
        // guard matches the current state.
        match transition_cas(
            &conn,
            "c1",
            ActionState::Claimed,
            ActionState::Pending,
            None,
            1_700_000_700,
        )
        .unwrap()
        {
            CasOutcome::Applied(a) => assert_eq!(a.state, ActionState::Pending),
            other => panic!("expected Applied (release), got {other:?}"),
        }

        // Illegal edge is rejected before the row is touched, regardless of a
        // matching guard (pending → done must route via claimed/in_progress).
        match transition_cas(
            &conn,
            "c1",
            ActionState::Pending,
            ActionState::Done,
            None,
            1_700_000_800,
        )
        .unwrap()
        {
            CasOutcome::Illegal { from, to } => {
                assert_eq!(from, ActionState::Pending);
                assert_eq!(to, ActionState::Done);
            }
            other => panic!("expected Illegal, got {other:?}"),
        }

        // Unknown id with a legal edge → NotFound (no row matched the CAS).
        assert!(matches!(
            transition_cas(
                &conn,
                "missing",
                ActionState::Pending,
                ActionState::Claimed,
                None,
                1_700_000_900,
            )
            .unwrap(),
            CasOutcome::NotFound
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
    fn frontier_ranks_by_priority_and_respects_dependency_edges() {
        use crate::models::EdgeType;
        let conn = fresh();
        // A (prio 5) + B (prio 9), both pending in the same ns.
        let mut a = sample("A");
        a.priority = 5;
        create(&conn, &a).unwrap();
        let mut b = sample("B");
        b.priority = 9;
        create(&conn, &b).unwrap();

        // Priority order: B (9) before A (5).
        let f = frontier(&conn, "_act", 50).unwrap();
        assert_eq!(
            f.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
            vec!["B", "A"],
            "frontier ranks by priority DESC"
        );

        // A requires a still-pending C → A drops off the frontier; B stays.
        let mut c = sample("C");
        c.priority = 1;
        create(&conn, &c).unwrap();
        add_edge(&conn, "A", "C", EdgeType::Requires, 1_700_000_000).unwrap();
        let f = frontier(&conn, "_act", 50).unwrap();
        let ids: Vec<&str> = f.iter().map(|x| x.id.as_str()).collect();
        assert!(
            !ids.contains(&"A"),
            "A is blocked by pending prerequisite C"
        );
        assert!(ids.contains(&"B"), "B is unaffected");

        // C reaches Done (via claimed → in_progress → done) → A reappears.
        transition(&conn, "C", ActionState::Claimed, None, 1_700_000_010).unwrap();
        transition(&conn, "C", ActionState::InProgress, None, 1_700_000_020).unwrap();
        transition(&conn, "C", ActionState::Done, None, 1_700_000_030).unwrap();
        let f = frontier(&conn, "_act", 50).unwrap();
        let ids: Vec<&str> = f.iter().map(|x| x.id.as_str()).collect();
        assert!(
            ids.contains(&"A"),
            "A reappears once prerequisite C is done"
        );
    }

    #[test]
    fn frontier_honors_active_blocks_edge() {
        use crate::models::EdgeType;
        let conn = fresh();
        // B2 blocks A2 while B2 is active → A2 is not on the frontier.
        let a2 = sample("A2");
        create(&conn, &a2).unwrap();
        let b2 = sample("B2");
        create(&conn, &b2).unwrap();
        add_edge(&conn, "B2", "A2", EdgeType::Blocks, 1_700_000_000).unwrap();
        let ids: Vec<String> = frontier(&conn, "_act", 50)
            .unwrap()
            .into_iter()
            .map(|x| x.id)
            .collect();
        assert!(
            !ids.contains(&"A2".to_string()),
            "active blocker B2 hides A2"
        );

        // B2 reaches a terminal state → A2 surfaces.
        transition(&conn, "B2", ActionState::Claimed, None, 1_700_000_010).unwrap();
        transition(&conn, "B2", ActionState::InProgress, None, 1_700_000_020).unwrap();
        transition(&conn, "B2", ActionState::Done, None, 1_700_000_030).unwrap();
        let ids: Vec<String> = frontier(&conn, "_act", 50)
            .unwrap()
            .into_iter()
            .map(|x| x.id)
            .collect();
        assert!(ids.contains(&"A2".to_string()), "terminal blocker frees A2");
    }

    #[test]
    fn next_action_returns_top_and_filters_by_agent() {
        let conn = fresh();
        // A (prio 5, owned by agent-x) + B (prio 9, owned by agent-y).
        let mut a = sample("A");
        a.priority = 5;
        a.agent_id = Some("agent-x".to_string());
        create(&conn, &a).unwrap();
        let mut b = sample("B");
        b.priority = 9;
        b.agent_id = Some("agent-y".to_string());
        create(&conn, &b).unwrap();
        // An unowned, lower-priority C.
        let mut c = sample("C");
        c.priority = 1;
        c.agent_id = None;
        create(&conn, &c).unwrap();

        // No agent filter → the top of the frontier (B, prio 9).
        let top = next_action(&conn, "_act", None)
            .unwrap()
            .expect("a next action");
        assert_eq!(top.id, "B");

        // agent-x sees only its own (A) + the unowned C → A wins on priority.
        let mine = next_action(&conn, "_act", Some("agent-x"))
            .unwrap()
            .expect("agent-x has work");
        assert_eq!(
            mine.id, "A",
            "B is owned by agent-y, so A is the top for agent-x"
        );

        // An agent with no owned and only the unowned row gets C.
        let other = next_action(&conn, "_act", Some("agent-z"))
            .unwrap()
            .expect("agent-z sees the unowned action");
        assert_eq!(other.id, "C");
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

    #[test]
    fn sweep_expired_leases_reclaims_only_expired() {
        let conn = fresh();
        let now = 1_700_000_000;
        create(&conn, &sample("sweep-1")).unwrap();

        // Acquire a lease whose deadline is already in the past.
        match lease_acquire(&conn, "sweep-1", "holder", now, now - 1).unwrap() {
            LeaseAcquire::Acquired(l) => assert_eq!(l.expires_at, now - 1),
            LeaseAcquire::Conflict => panic!("expected Acquired"),
        }

        // The sweep reclaims exactly the one expired lease.
        assert_eq!(sweep_expired_leases(&conn, now).unwrap(), 1);
        assert!(lease_get(&conn, "sweep-1").unwrap().is_none());

        // A non-expired lease (expires_at = now + 1000) is NOT swept.
        match lease_acquire(&conn, "sweep-1", "holder", now, now + 1000).unwrap() {
            LeaseAcquire::Acquired(_) => {}
            LeaseAcquire::Conflict => panic!("expected Acquired"),
        }
        assert_eq!(sweep_expired_leases(&conn, now).unwrap(), 0);
        assert!(lease_get(&conn, "sweep-1").unwrap().is_some());
    }
}
