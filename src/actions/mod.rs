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

/// Wave-2 B6 — record-stop fence for the coordination-action sqlite
/// free-fn SSOT. Reads (`get` / `list` / `frontier`) stay live.
fn gate_record_stop_actions(conn: &Connection) -> rusqlite::Result<()> {
    crate::storage::record_stop::gate_storage_conn_rusqlite(conn)
}

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

/// Scalar `state`-only by-id probe shared by the [`transition`] /
/// [`transition_cas`] compare-and-swap disambiguation reads — one spelling of
/// the literal, not three (pm-v3.1 hardcoded-literal gate).
const SELECT_ACTION_STATE_BY_ID_SQL: &str = "SELECT state FROM actions WHERE id = ?1";

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
    gate_record_stop_actions(conn)?;
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
    gate_record_stop_actions(conn)?;
    let current: Option<String> = conn
        .query_row(SELECT_ACTION_STATE_BY_ID_SQL, params![id], |r| r.get(0))
        .optional()?;
    let Some(cs) = current else {
        return Ok(TransitionOutcome::NotFound);
    };
    let from = crate::models::ActionState::from_str(&cs).unwrap_or_default();
    if !from.can_transition_to(to) {
        return Ok(TransitionOutcome::Illegal { from, to });
    }
    // #3191 F-2 — GUARDED compare-and-swap. Pre-fix the UPDATE was UNGUARDED
    // (`WHERE id = ?`), so the read-then-write across the `SELECT state` above
    // and this UPDATE was a TOCTOU: two concurrent transitions both read the
    // same `from`, both validated `from -> to` legal, and both wrote — "one
    // action, many winners". The `AND state = ?5` predicate binds the exact
    // state we read, so the compare and the swap are a single atomic statement
    // and exactly ONE racer's UPDATE affects a row (mirrors `transition_cas`).
    let changed = conn.execute(
        "UPDATE actions SET state = ?1, claimed_by = ?2, updated_at = ?3 \
         WHERE id = ?4 AND state = ?5",
        params![to.as_str(), claimed_by, now, id, from.as_str()],
    )?;
    if changed == 0 {
        // Lost the race: the row moved out of `from` between the SELECT and the
        // UPDATE (or was deleted). Re-read and reclassify into an existing
        // non-success outcome — NEVER report `Updated` for a transition that did
        // not apply (that was the "many winners" bug). No row -> NotFound; a row
        // in some other state -> the `from -> to` edge we validated is now stale,
        // reported as Illegal against the actual current state.
        let latest: Option<String> = conn
            .query_row(SELECT_ACTION_STATE_BY_ID_SQL, params![id], |r| r.get(0))
            .optional()?;
        return Ok(match latest {
            None => TransitionOutcome::NotFound,
            Some(ls) => TransitionOutcome::Illegal {
                from: crate::models::ActionState::from_str(&ls).unwrap_or_default(),
                to,
            },
        });
    }
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
    gate_record_stop_actions(conn)?;
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
            .query_row(SELECT_ACTION_STATE_BY_ID_SQL, params![id], |r| r.get(0))
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
/// - unlockers (#3008): an `unlocks` edge whose `to_action` is the candidate
///   ("`from` unlocks `to` on completion"), from an unlocker that is not yet
///   `done`, keeps the candidate blocked. Pre-#3008 `EdgeType::Unlocks` had
///   ZERO effect on the frontier — a caller modelling a dependency via
///   `unlocks` got silent no-ordering, even though the edge documents one.
///
/// `?1` is the namespace; the caller appends the ordering + limit binds.
///
/// v1.0.0 #3179 — the predicate BODY lives in [`frontier_where_tail_with`],
/// which the postgres adapter formats with its own `$1` placeholder, so
/// neither backend can carry a clause the other lacks.
fn frontier_where_tail() -> String {
    frontier_where_tail_with(SQLITE_NS_PLACEHOLDER)
}

/// The sqlite namespace bind placeholder for [`frontier_where_tail_with`].
const SQLITE_NS_PLACEHOLDER: &str = "?1";

/// v1.0.0 #3179 — the ONE definition of the FRONTIER unblocked predicate,
/// parameterized by the backend's namespace bind placeholder (`?1` on
/// sqlite, `$1` on postgres).
///
/// This exists because the postgres adapter had a HAND-COPIED twin
/// (`pg_frontier_where_tail`) that carried only TWO of the three
/// `NOT EXISTS` clauses: the #3008 `unlocks` clause was added to the sqlite
/// original and never mirrored, so on a postgres-backed coordination plane
/// an action whose only dependency was an `EdgeType::Unlocks` edge was
/// dispatched to agents while sqlite correctly held it back — out-of-order
/// execution, under a doc comment that claimed the two were "byte-for-byte
/// the same predicate". Formatting BOTH backends from this one fragment
/// makes that class of drift structurally impossible: a future `EdgeType`
/// clause lands on both backends or neither.
///
/// The caller appends the ordering + limit binds.
pub(crate) fn frontier_where_tail_with(ns_placeholder: &str) -> String {
    use crate::models::{ActionState, EdgeType};
    format!(
        "a.namespace = {ns_placeholder} AND a.state = '{pending}' \
           AND NOT EXISTS ( \
             SELECT 1 FROM action_edges e JOIN actions b ON b.id = e.to_action \
             WHERE e.from_action = a.id \
               AND e.edge_type IN ('{requires}', '{gated_by}') \
               AND b.state <> '{done}') \
           AND NOT EXISTS ( \
             SELECT 1 FROM action_edges e JOIN actions b ON b.id = e.from_action \
             WHERE e.to_action = a.id AND e.edge_type = '{blocks}' \
               AND b.state NOT IN ('{done}', '{failed}', '{abandoned}')) \
           AND NOT EXISTS ( \
             SELECT 1 FROM action_edges e JOIN actions b ON b.id = e.from_action \
             WHERE e.to_action = a.id AND e.edge_type = '{unlocks}' \
               AND b.state <> '{done}')",
        pending = ActionState::Pending.as_str(),
        requires = EdgeType::Requires.as_str(),
        gated_by = EdgeType::GatedBy.as_str(),
        done = ActionState::Done.as_str(),
        blocks = EdgeType::Blocks.as_str(),
        unlocks = EdgeType::Unlocks.as_str(),
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

/// Disposition of an [`add_edge`] attempt (#3008). A self-edge or a cycle in
/// the ordering DAG permanently wedges the frontier (the node can never satisfy
/// its own prerequisite), so both are refused BEFORE the insert rather than
/// silently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddEdgeOutcome {
    /// The edge was inserted (or already existed — `INSERT OR IGNORE`).
    Added,
    /// Refused: `from_action == to_action`. A self-edge (e.g. `A requires A`)
    /// keeps `A` off its own frontier forever.
    SelfEdge,
    /// Refused: the edge would close a cycle in the ordering DAG (e.g.
    /// `A requires B` with `B requires A` — mutual deadlock; both wedge the
    /// frontier). Sibling edges impose no ordering and are never cycle-checked.
    WouldCycle,
}

/// Whether adding an ordering arc `from_action -> to_action` would close a
/// cycle — i.e. whether `to_action` already reaches `from_action` via
/// non-`sibling` arcs. The memory lineage DAG has the analogous acyclicity
/// guard (#1859); an action cycle wedges the frontier the same way. Sibling
/// arcs impose no ordering, so they are excluded from the reachability walk.
///
/// # Errors
/// Propagates the `rusqlite` query error (the caller MUST fail closed — an
/// unresolvable reachability probe cannot be treated as "no cycle").
fn ordering_edge_would_cycle(
    conn: &Connection,
    from_action: &str,
    to_action: &str,
) -> rusqlite::Result<bool> {
    let sql = format!(
        "WITH RECURSIVE reach(node) AS ( \
             SELECT ?1 \
             UNION \
             SELECT e.to_action FROM action_edges e JOIN reach r ON e.from_action = r.node \
             WHERE e.edge_type <> '{sibling}') \
         SELECT 1 FROM reach WHERE node = ?2 LIMIT 1",
        sibling = crate::models::EdgeType::Sibling.as_str(),
    );
    let reachable: Option<i64> = conn
        .query_row(&sql, params![to_action, from_action], |r| r.get(0))
        .optional()?;
    Ok(reachable.is_some())
}

/// Insert a typed DAG edge between two actions. `INSERT OR IGNORE` so a
/// duplicate `(from, to, type)` triple is a no-op.
///
/// #3008 — a self-edge or an ordering cycle is REFUSED (returns
/// [`AddEdgeOutcome::SelfEdge`] / [`AddEdgeOutcome::WouldCycle`], no insert)
/// rather than silently wedging the frontier. Sibling edges impose no ordering
/// and skip the cycle check (a self-sibling is still refused as pointless).
///
/// # Errors
/// Propagates the `rusqlite` insert / reachability-query error.
pub fn add_edge(
    conn: &Connection,
    from_action: &str,
    to_action: &str,
    edge_type: crate::models::EdgeType,
    now: i64,
) -> rusqlite::Result<AddEdgeOutcome> {
    gate_record_stop_actions(conn)?;
    if from_action == to_action {
        return Ok(AddEdgeOutcome::SelfEdge);
    }
    if edge_type != crate::models::EdgeType::Sibling
        && ordering_edge_would_cycle(conn, from_action, to_action)?
    {
        return Ok(AddEdgeOutcome::WouldCycle);
    }
    conn.execute(
        "INSERT OR IGNORE INTO action_edges (from_action, to_action, edge_type, created_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![from_action, to_action, edge_type.as_str(), now],
    )?;
    Ok(AddEdgeOutcome::Added)
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
/// # Concurrency (v1.0.0 FBL-06)
/// The whole acquire is ONE atomic `INSERT ... ON CONFLICT ... DO UPDATE`
/// statement, NOT a `SELECT`-then-`INSERT OR REPLACE` check-then-act. The
/// prior two-statement form ran as two independent autocommit statements
/// with no enclosing transaction, so under WAL two connections sharing one
/// DB (two MCP stdio processes, or an MCP client + the HTTP daemon — both
/// documented supported topologies) could interleave the conflict `SELECT`
/// and each observe "no live conflicting lease", then each `INSERT OR
/// REPLACE` and BOTH be granted the same single-holder lease. SQLite
/// executes an upsert as a single statement under the write lock, so
/// exactly one racer wins (the SQLite analogue of the postgres twin's
/// `SELECT ... FOR UPDATE`, and the same TOCTOU-closing discipline as
/// `crate::quotas::check_and_record`'s `BEGIN IMMEDIATE`). The
/// single-conditional-statement form is used here in preference to a
/// `BEGIN IMMEDIATE` transaction because both production callers pass a
/// bare `&Connection` (no outer tx), so a nested `BEGIN` is unavailable —
/// the atomic upsert is the minimal, allocation-free fix. Data-integrity
/// note (North Star): a double-grant of a single-holder lease is a
/// correctness/safety violation (two writers believe they hold exclusive
/// coordination authority); making the grant atomic fails closed — the
/// worst case is a spurious `Conflict` a caller retries, never two winners.
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
    gate_record_stop_actions(conn)?;
    // The `DO UPDATE` arm's `WHERE` re-derives the acquire predicate against
    // the EXISTING row (`leases.*` = pre-update values): acquisition is
    // permitted only when the current lease is EXPIRED (`expires_at <= now`)
    // OR held by the SAME holder (re-acquire / renew). A live lease held by a
    // DIFFERENT holder fails the guard, the update is a no-op, and
    // `changes()` is 0 — the same disposition the old `exp > now && h != holder`
    // branch produced, now evaluated atomically inside the single statement.
    let changed = conn.execute(
        "INSERT INTO leases \
            (action_id, holder, acquired_at, expires_at, heartbeat_at) \
         VALUES (?1, ?2, ?3, ?4, ?3) \
         ON CONFLICT(action_id) DO UPDATE SET \
            holder = excluded.holder, \
            acquired_at = excluded.acquired_at, \
            expires_at = excluded.expires_at, \
            heartbeat_at = excluded.heartbeat_at \
         WHERE leases.expires_at <= ?3 OR leases.holder = ?2",
        params![action_id, holder, now, expires_at],
    )?;
    if changed == 0 {
        // A non-expired lease is held by a different holder: the `DO UPDATE`
        // guard rejected the acquire (no row inserted, no row updated).
        return Ok(LeaseAcquire::Conflict);
    }
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
    gate_record_stop_actions(conn)?;
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
    gate_record_stop_actions(conn)?;
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

/// #3009 / #3226 — shape-validate a caller-supplied `claimed_by` and bind
/// it to the live lease holder.
///
/// A `claimed_by` with embedded control characters is refused (audit
/// log-injection guard). A live (non-expired) lease whose holder is not
/// `claimed_by` is refused so two agents cannot each believe they own
/// the action. `lease = None` (or an expired lease) is the unbound /
/// lease-free flow — leases are the ownership primitive, so this never
/// blocks a lease-less transition.
///
/// # Errors
/// Returns a caller-facing string on a shape or holder mismatch.
pub fn authorize_claimed_by(
    claimed_by: &str,
    lease: Option<&crate::models::Lease>,
    now: i64,
    action_id: &str,
) -> Result<(), String> {
    crate::validate::validate_agent_id(claimed_by).map_err(|e| e.to_string())?;
    if let Some(lease) = lease
        && lease.expires_at > now
        && lease.holder != claimed_by
    {
        return Err(format!(
            "claimed_by '{claimed_by}' is not the live lease holder '{}' on action {action_id}",
            lease.holder
        ));
    }
    Ok(())
}

/// `tracing` target for the lease-expiry reclaim/requeue sweep. Hoisted here
/// (the lowest layer that logs under it) so the background loop
/// [`crate::background::lease_sweep`] and this module share ONE spelling of
/// the target rather than scattering the literal (pm-v3.1 hardcoded-literal
/// gate).
pub const LEASE_SWEEP_TRACE_TARGET: &str = "lease.sweep";

/// Requeue an action stranded in `claimed` whose lease has just been reclaimed
/// by the expiry sweep (#2419).
///
/// **Why this exists.** `memory_action_frontier` returns only actions in
/// `pending`. Before #2419 the sweep DELETEd the expired lease row and left the
/// action in `claimed`, so a node whose holder died was simultaneously (a) not
/// leased by anyone and (b) invisible to `frontier` FOREVER — the work was
/// neither done nor surfaceable. The lease and the state had DIVERGED: the
/// substrate already considered the action free (any caller could
/// [`lease_acquire`] it) while the state machine still said "claimed". This
/// reconverges the two in the same transaction as the lease reclaim.
///
/// **No new state, no migration.** `claimed -> pending` is ALREADY a legal edge
/// in [`crate::models::ActionState::can_transition_to`], so this reuses
/// [`transition_cas`] — the state guard lives in the `UPDATE ... WHERE state = ?`
/// predicate, so an action a live worker concurrently advanced to `in_progress`
/// loses the CAS and is left ALONE (never yanked out from under a worker that
/// is genuinely progressing). `claimed_by` is cleared (`None`) exactly as a
/// caller-driven `claimed -> pending` transition would.
///
/// **Scope (documented residual).** Only `claimed` is requeued. `in_progress`
/// has NO legal edge back to `pending` in the state machine, so an
/// `in_progress` node whose lease expired is NOT auto-requeued here — adding
/// that edge would be a state-machine change, not a sweep fix. Such a node is
/// still surfaced: the sweep emits its
/// [`crate::coordination_audit::LEASE_SWEEP_RECLAIM`] audit row, and the node
/// remains listable via `memory_action_list { state: "in_progress" }`.
///
/// Returns `true` when the requeue applied.
///
/// # Errors
/// Propagates the `rusqlite` update/query error.
fn requeue_claimed_after_lease_expiry(
    conn: &Connection,
    action_id: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    use crate::models::ActionState;
    Ok(matches!(
        transition_cas(
            conn,
            action_id,
            ActionState::Claimed,
            ActionState::Pending,
            None,
            now,
        )?,
        CasOutcome::Applied(_)
    ))
}

/// Reclaim (delete) every lease whose `expires_at <= now`, releasing the
/// action for a fresh holder, AND requeue any action left stranded in `claimed`
/// back to `pending` (#2419) so it re-appears on `memory_action_frontier`.
/// Returns the reclaimed `(action_id, holder, requeued)` triples: the pair the
/// caller audits plus whether the state requeue applied.
///
/// The `DELETE ... RETURNING` is atomic, so the returned set is EXACTLY the rows
/// removed (no SELECT-then-DELETE TOCTOU where a concurrently renewed lease
/// could be audited as reclaimed without being deleted). #2419 wraps the delete
/// AND the requeues in ONE transaction (`unchecked_transaction` — both
/// production callers hold a bare autocommit `&Connection`) so a crash can never
/// leave the substrate with the lease gone but the state still `claimed`, which
/// is precisely the stranded shape the fix exists to prevent.
///
/// # Errors
/// Propagates the `rusqlite` delete/update/query error.
fn sweep_expired_leases_reclaim(
    conn: &Connection,
    now: i64,
) -> rusqlite::Result<Vec<(String, String, bool)>> {
    let tx = conn.unchecked_transaction()?;
    let expired = {
        let mut stmt =
            tx.prepare("DELETE FROM leases WHERE expires_at <= ?1 RETURNING action_id, holder")?;
        stmt.query_map(params![now], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<(String, String)>>>()?
    };
    let mut out = Vec::with_capacity(expired.len());
    for (action_id, holder) in expired {
        let requeued = requeue_claimed_after_lease_expiry(&tx, &action_id, now)?;
        out.push((action_id, holder, requeued));
    }
    tx.commit()?;
    Ok(out)
}

/// Reclaim (delete) every lease whose `expires_at <= now`, releasing the
/// action for a fresh holder. Returns the reclaimed `(action_id, holder)`
/// pairs so the caller can emit one coordination-audit `signed_events` row per
/// FORCED reclamation (#2371) — the asymmetric twin of the voluntary
/// [`lease_release`], which is the ONE lease op that previously left no
/// forensic trace.
///
/// Since #2419 this ALSO requeues any action left stranded in `claimed` back to
/// `pending` (see [`requeue_claimed_after_lease_expiry`]) in the same
/// transaction as the lease delete — the requeue lives at THIS primitive, not
/// only in the audited wrapper, so no caller can reclaim a lease without
/// reconverging the action state and re-stranding the work.
///
/// # Errors
/// Propagates the `rusqlite` delete/update/query error.
pub fn sweep_expired_leases(
    conn: &Connection,
    now: i64,
) -> rusqlite::Result<Vec<(String, String)>> {
    gate_record_stop_actions(conn)?;
    Ok(sweep_expired_leases_reclaim(conn, now)?
        .into_iter()
        .map(|(action_id, holder, _requeued)| (action_id, holder))
        .collect())
}

/// Reclaim expired leases via [`sweep_expired_leases`] AND emit one
/// coordination-audit `signed_events` row per reclaimed lease
/// ([`crate::coordination_audit::LEASE_SWEEP_RECLAIM`]), attributed to the
/// reclaimed `holder` (the entity losing coordination authority) with the same
/// `[action_id, holder]` identity the voluntary lease ops use. Returns the
/// reclaimed count. The audit append is best-effort (#1722): the DELETE has
/// already committed, so a rare append failure is WARN-logged inside
/// [`crate::coordination_audit::emit`], never propagated.
///
/// #2419 — an action that the reclaim also requeued `claimed -> pending`
/// additionally emits [`crate::coordination_audit::ACTION_LEASE_EXPIRE_REQUEUE`].
/// It is a SEPARATE slug from the lease row (and from the caller-driven
/// [`crate::coordination_audit::ACTION_TRANSITION`]) for the same reason
/// `LEASE_SWEEP_RECLAIM` is separate from `LEASE_RELEASE`: a FORCED state
/// reversion an operator never requested must be distinguishable in the audit
/// trail from one a caller asked for.
///
/// # Errors
/// Propagates the `rusqlite` delete/update/query error.
pub fn sweep_expired_leases_audited(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    // Wave-2 B9 — pg `lease_sweep_expired` already gates; the sqlite
    // audited wrapper used to skip `gate_record_stop_actions` and go
    // straight to reclaim (coordination read surfaces piggybacked an
    // ungated lease-reclaim DELETE). ERRORS-09.
    gate_record_stop_actions(conn)?;
    let reclaimed = sweep_expired_leases_reclaim(conn, now)?;
    let mut requeued_count = 0usize;
    for (action_id, holder, requeued) in &reclaimed {
        crate::coordination_audit::emit(
            conn,
            crate::coordination_audit::LEASE_SWEEP_RECLAIM,
            holder,
            &[action_id.as_str(), holder.as_str()],
        );
        if *requeued {
            requeued_count += 1;
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::ACTION_LEASE_EXPIRE_REQUEUE,
                holder,
                &[action_id.as_str(), holder.as_str()],
            );
        }
    }
    if requeued_count > 0 {
        // obs-structured-fields: the count is a discrete queryable field, not
        // text baked into the message, so a fleet aggregator can alert on a
        // rising requeue rate (the signal that workers are dying mid-claim).
        tracing::info!(
            target: LEASE_SWEEP_TRACE_TARGET,
            requeued = requeued_count,
            reclaimed = reclaimed.len(),
            "lease sweep requeued stranded claimed actions to pending"
        );
    }
    Ok(reclaimed.len())
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

    /// #3191 F-2 — `transition` is a GUARDED compare-and-swap: concurrent
    /// transitions of ONE pending action yield EXACTLY ONE winner. Pre-fix the
    /// `SELECT state` + UNGUARDED `UPDATE ... WHERE id = ?` were a read-then-write
    /// TOCTOU, so N racers all read `pending`, all validated `pending -> claimed`
    /// legal, and all wrote — "one action, many winners". The `AND state = ?`
    /// predicate in the UPDATE makes exactly one racer's write apply; the losers
    /// re-read and reclassify to a NON-`Updated` outcome (never a false success).
    #[test]
    fn transition_cross_connection_race_single_winner_3191() {
        use std::sync::{Arc, Barrier};

        // A file-backed DB is REQUIRED — `:memory:` connections do not share
        // state. Scratch under a project-local temp dir (never system /tmp).
        let dir = tempfile::tempdir().expect("temp dir for shared file DB");
        let db_path = dir.path().join("act3191_transition_race.db");
        {
            let writer = crate::storage::open(&db_path).expect("open writer");
            create(&writer, &sample("race-3191")).expect("create action");
        }

        const RACERS: usize = 12;
        let now = 1_700_000_500_i64;
        let barrier = Arc::new(Barrier::new(RACERS));
        let path = Arc::new(db_path.clone());
        let handles: Vec<_> = (0..RACERS)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                let path = Arc::clone(&path);
                std::thread::spawn(move || {
                    let conn = crate::storage::open(path.as_path()).expect("open racer conn");
                    let claimant = format!("claimant-{i}");
                    barrier.wait();
                    // A busy connection may surface `database is locked` under
                    // extreme contention; a returned Err is NOT a second winner
                    // (fail-closed), so treat it as a non-winner — as does the
                    // sibling FBL-06 lease race.
                    match transition(
                        &conn,
                        "race-3191",
                        ActionState::Claimed,
                        Some(&claimant),
                        now,
                    ) {
                        Ok(TransitionOutcome::Updated(a)) => a.claimed_by,
                        Ok(_) | Err(_) => None,
                    }
                })
            })
            .collect();

        let winners: Vec<String> = handles
            .into_iter()
            .filter_map(|h| h.join().expect("racer thread panicked"))
            .collect();
        assert_eq!(
            winners.len(),
            1,
            "exactly one racer may win the pending -> claimed transition; winners={winners:?}"
        );

        // The persisted row agrees with the sole winner.
        let verify = crate::storage::open(&db_path).expect("open verify conn");
        let row = get(&verify, "race-3191").expect("get").expect("row");
        assert_eq!(row.state, ActionState::Claimed);
        assert_eq!(row.claimed_by.as_deref(), Some(winners[0].as_str()));
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

    /// #3008 — `EdgeType::Unlocks` now gates the frontier: `A unlocks C` keeps
    /// C off the frontier until A is `done`. Pre-fix the edge was INERT and C
    /// was on the frontier immediately (silent no-ordering on an ordering edge).
    #[test]
    fn unlocks_edge_gates_the_frontier_3008() {
        use crate::models::EdgeType;
        let conn = fresh();
        let a = sample("UA");
        create(&conn, &a).unwrap();
        let c = sample("UC");
        create(&conn, &c).unwrap();
        // A unlocks C on completion.
        assert_eq!(
            add_edge(&conn, "UA", "UC", EdgeType::Unlocks, 1_700_000_000).unwrap(),
            AddEdgeOutcome::Added
        );
        let ids: Vec<String> = frontier(&conn, "_act", 50)
            .unwrap()
            .into_iter()
            .map(|x| x.id)
            .collect();
        assert!(
            !ids.contains(&"UC".to_string()),
            "C is gated by the not-yet-done unlocker A"
        );
        assert!(ids.contains(&"UA".to_string()), "the unlocker A is ready");

        // A reaches Done → C surfaces on the frontier.
        transition(&conn, "UA", ActionState::Claimed, None, 1_700_000_010).unwrap();
        transition(&conn, "UA", ActionState::InProgress, None, 1_700_000_020).unwrap();
        transition(&conn, "UA", ActionState::Done, None, 1_700_000_030).unwrap();
        let ids: Vec<String> = frontier(&conn, "_act", 50)
            .unwrap()
            .into_iter()
            .map(|x| x.id)
            .collect();
        assert!(
            ids.contains(&"UC".to_string()),
            "C is unlocked once A is done"
        );
    }

    /// #3008 — `add_edge` refuses a self-edge and an ordering cycle (both wedge
    /// the frontier permanently), instead of silently accepting them.
    #[test]
    fn add_edge_rejects_self_edge_and_cycle_3008() {
        use crate::models::EdgeType;
        let conn = fresh();
        create(&conn, &sample("X")).unwrap();
        create(&conn, &sample("Y")).unwrap();

        // Self-edge refused.
        assert_eq!(
            add_edge(&conn, "X", "X", EdgeType::Requires, 1_700_000_000).unwrap(),
            AddEdgeOutcome::SelfEdge
        );
        // X requires Y is fine.
        assert_eq!(
            add_edge(&conn, "X", "Y", EdgeType::Requires, 1_700_000_001).unwrap(),
            AddEdgeOutcome::Added
        );
        // Y requires X would close the X<->Y cycle → refused.
        assert_eq!(
            add_edge(&conn, "Y", "X", EdgeType::Requires, 1_700_000_002).unwrap(),
            AddEdgeOutcome::WouldCycle
        );
        // A cross-type cycle (X --blocks--> Y already exists via requires; a
        // Y --unlocks--> X arc also closes the ordering cycle) is refused.
        assert_eq!(
            add_edge(&conn, "Y", "X", EdgeType::Unlocks, 1_700_000_003).unwrap(),
            AddEdgeOutcome::WouldCycle
        );
        // A sibling edge imposes no ordering, so even a "back" sibling arc is OK.
        assert_eq!(
            add_edge(&conn, "Y", "X", EdgeType::Sibling, 1_700_000_004).unwrap(),
            AddEdgeOutcome::Added
        );
        // But a self-sibling is still refused as pointless.
        assert_eq!(
            add_edge(&conn, "X", "X", EdgeType::Sibling, 1_700_000_005).unwrap(),
            AddEdgeOutcome::SelfEdge
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

        // The sweep reclaims exactly the one expired lease and RETURNS the
        // (action_id, holder) pair so the caller can audit the reclamation.
        let reclaimed = sweep_expired_leases(&conn, now).unwrap();
        assert_eq!(
            reclaimed,
            vec![("sweep-1".to_string(), "holder".to_string())]
        );
        assert!(lease_get(&conn, "sweep-1").unwrap().is_none());

        // A non-expired lease (expires_at = now + 1000) is NOT swept.
        match lease_acquire(&conn, "sweep-1", "holder", now, now + 1000).unwrap() {
            LeaseAcquire::Acquired(_) => {}
            LeaseAcquire::Conflict => panic!("expected Acquired"),
        }
        assert!(sweep_expired_leases(&conn, now).unwrap().is_empty());
        assert!(lease_get(&conn, "sweep-1").unwrap().is_some());
    }

    #[test]
    fn sweep_expired_leases_audited_emits_one_row_per_reclaimed_lease() {
        let conn = fresh();
        let now = 1_700_000_000;
        create(&conn, &sample("audited-1")).unwrap();
        create(&conn, &sample("audited-2")).unwrap();
        // Two expired leases held by distinct holders.
        lease_acquire(&conn, "audited-1", "holder-a", now, now - 1).unwrap();
        lease_acquire(&conn, "audited-2", "holder-b", now, now - 1).unwrap();

        assert_eq!(sweep_expired_leases_audited(&conn, now).unwrap(), 2);

        // Exactly one LEASE_SWEEP_RECLAIM row per reclaimed lease, each
        // attributed to the reclaimed holder.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                params![crate::coordination_audit::LEASE_SWEEP_RECLAIM],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2, "one audit row per reclaimed lease");
        let holders: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT agent_id) FROM signed_events WHERE event_type = ?1",
                params![crate::coordination_audit::LEASE_SWEEP_RECLAIM],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(holders, 2, "rows attributed to each reclaimed holder");

        // An idempotent re-sweep reclaims nothing and appends no new rows.
        assert_eq!(sweep_expired_leases_audited(&conn, now).unwrap(), 0);
        let count2: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                params![crate::coordination_audit::LEASE_SWEEP_RECLAIM],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count2, 2, "no-op sweep appends no audit rows");
    }

    // v1.0.0 FBL-05/FBL-06 regression: `lease_acquire` must be atomic across
    // SEPARATE connections to one file-backed (WAL) DB — the documented
    // supported topology of two MCP stdio processes, or an MCP client + the
    // HTTP daemon, sharing one `AI_MEMORY_DB`. Pre-fix, the conflict `SELECT`
    // and the `INSERT OR REPLACE` were two independent autocommit statements
    // with no enclosing transaction, so N racers could each observe "no live
    // lease" and each be granted the SAME single-holder lease. The single
    // conditional `INSERT ... ON CONFLICT ... DO UPDATE` statement runs under
    // the write lock, so EXACTLY ONE contender wins.
    #[test]
    fn lease_acquire_cross_connection_race_single_winner_fbl_06() {
        use std::sync::{Arc, Barrier};

        // A file-backed DB is REQUIRED — `:memory:` connections do not share
        // state, so the cross-process contention cannot be reproduced there.
        // Scratch under a project-local temp dir (never system /tmp).
        let dir = tempfile::tempdir().expect("temp dir for shared file DB");
        let db_path = dir.path().join("fbl06_lease_race.db");

        // Seed the action row (the lease FK target) on a writer connection.
        {
            let writer = crate::storage::open(&db_path).expect("open writer");
            create(&writer, &sample("race-1")).expect("create action");
        }

        const RACERS: usize = 12;
        let now = 1_700_000_000_i64;
        let expires_at = now + 60;
        let barrier = Arc::new(Barrier::new(RACERS));
        let path = Arc::new(db_path.clone());

        let handles: Vec<_> = (0..RACERS)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                let path = Arc::clone(&path);
                std::thread::spawn(move || {
                    // Each racer opens its OWN connection to the shared file.
                    let conn = crate::storage::open(path.as_path()).expect("open racer conn");
                    let holder = format!("holder-{i}");
                    // Line every racer up so they hit the write path together.
                    barrier.wait();
                    // A busy connection may surface `database is locked`
                    // despite the 5s busy_timeout under extreme contention;
                    // a returned Err is NOT a second grant (fail-closed), so
                    // treat it as a non-winner.
                    match lease_acquire(&conn, "race-1", &holder, now, expires_at) {
                        Ok(LeaseAcquire::Acquired(lease)) => Some(lease.holder),
                        Ok(LeaseAcquire::Conflict) | Err(_) => None,
                    }
                })
            })
            .collect();

        let winners: Vec<String> = handles
            .into_iter()
            .filter_map(|h| h.join().expect("racer thread panicked"))
            .collect();

        assert_eq!(
            winners.len(),
            1,
            "exactly one racer may win the single-holder lease (FBL-06); winners={winners:?}"
        );

        // The persisted lease holder MUST equal the sole reported winner —
        // the acquire and the persisted row agree.
        let verify = crate::storage::open(&db_path).expect("open verify conn");
        let persisted = lease_get(&verify, "race-1")
            .expect("lease_get")
            .expect("a lease is persisted");
        assert_eq!(
            persisted.holder, winners[0],
            "the persisted holder must be the reported winner"
        );
    }

    /// #3009 / #3226 — `authorize_claimed_by` shape-validates and binds to
    /// the live lease holder; an expired or missing lease is unbound.
    #[test]
    fn authorize_claimed_by_binds_live_holder_3009() {
        let live = crate::models::Lease {
            action_id: "act-1".to_string(),
            holder: "ai:w1".to_string(),
            acquired_at: 1,
            expires_at: 1_000,
            heartbeat_at: 1,
        };
        assert!(authorize_claimed_by("ai:w1", Some(&live), 10, "act-1").is_ok());
        let err = authorize_claimed_by("ai:w2", Some(&live), 10, "act-1")
            .expect_err("non-holder must be refused");
        assert!(
            err.contains("not the live lease holder"),
            "holder-mismatch wording, got {err}"
        );
        // Expired lease is unbound.
        let expired = crate::models::Lease {
            expires_at: 5,
            ..live.clone()
        };
        assert!(authorize_claimed_by("ai:w2", Some(&expired), 10, "act-1").is_ok());
        // No lease is unbound.
        assert!(authorize_claimed_by("ai:w2", None, 10, "act-1").is_ok());
        // Control-char claimed_by is refused even with no lease.
        assert!(authorize_claimed_by("bad\nid", None, 10, "act-1").is_err());
    }
}
