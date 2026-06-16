// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — routine [`Routine`] + [`RoutineRun`] sqlite
//! free-functions.
//!
//! These operate on a raw [`rusqlite::Connection`] so BOTH the SAL
//! [`crate::store::sqlite::SqliteStore`] adapter (which delegates here) AND
//! the future MCP stdio `memory_routine_*` tool handlers (which hold a bare
//! `Connection`, not a SAL store) share one implementation — exactly the
//! split [`crate::checkpoints`] uses for the attested-checkpoint surface.
//! The postgres adapter keeps its own sqlx-native path in
//! `crate::store::postgres`.
//!
//! Back the v62 `routines` / `routine_runs` tables (parameterised
//! action+edge templates that can be frozen into an immutable,
//! regulatory-hold form, and their per-argument-binding materialisations).
//! The `signature` / `signer_pubkey` columns are persisted verbatim as byte
//! vectors — empty until the routine is frozen; the freeze-attestation
//! signing logic lands in a subsequent unit.

use crate::models::{Routine, RoutineRun, RoutineRunState, RoutineState};
use rusqlite::{Connection, OptionalExtension, params};

/// SELECT column list for the `routines` table, in the canonical order
/// [`row_to_routine`] expects. One definition shared by every routine read.
pub const ROUTINE_SELECT_SQL: &str = "SELECT id, namespace, name, template, parameters, state, \
     created_by, created_at, frozen_at, signature, signer_pubkey, metadata FROM routines";

/// SELECT column list for the `routine_runs` table, in the canonical order
/// [`row_to_routine_run`] expects. One definition shared by every run read.
pub const ROUTINE_RUN_SELECT_SQL: &str = "SELECT id, routine_id, namespace, arguments, state, \
     created_action_ids, started_at, finished_at, error, metadata FROM routine_runs";

/// Shared SQL fragment for the newest-first ordering + LIMIT placeholder
/// position — callers append the placeholder (`?`) / bind the limit. Mirrors
/// [`crate::checkpoints::SQL_ORDER_BY_CREATED_DESC_LIMIT`] for the routine
/// `started_at` ordering.
pub const SQL_ORDER_BY_STARTED_DESC_LIMIT: &str = " ORDER BY started_at DESC LIMIT ";

/// Map a `rusqlite` row (the [`ROUTINE_SELECT_SQL`] column order) to a
/// [`Routine`].
///
/// # Errors
/// Propagates the `rusqlite` column-access error.
pub fn row_to_routine(r: &rusqlite::Row<'_>) -> rusqlite::Result<Routine> {
    Ok(Routine {
        id: r.get(0)?,
        namespace: r.get(1)?,
        name: r.get(2)?,
        template: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or(serde_json::Value::Null),
        parameters: serde_json::from_str(&r.get::<_, String>(4)?)
            .unwrap_or(serde_json::Value::Null),
        state: RoutineState::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
        created_by: r.get(6)?,
        created_at: r.get(7)?,
        frozen_at: r.get::<_, Option<i64>>(8)?,
        // The `signature` / `signer_pubkey` columns are nullable BLOB — read
        // as `Option<Vec<u8>>` and collapse NULL to an empty vec so a Draft
        // (unfrozen) row round-trips without a column-type error. INSERT
        // always writes a non-NULL (possibly empty) vec.
        signature: r.get::<_, Option<Vec<u8>>>(9)?.unwrap_or_default(),
        signer_pubkey: r.get::<_, Option<Vec<u8>>>(10)?.unwrap_or_default(),
        metadata: serde_json::from_str(&r.get::<_, String>(11)?).unwrap_or(serde_json::Value::Null),
    })
}

/// Insert a routine. Returns the routine id.
///
/// # Errors
/// Propagates the `rusqlite` insert error.
pub fn routine_insert(conn: &Connection, rt: &Routine) -> rusqlite::Result<String> {
    conn.execute(
        "INSERT INTO routines \
            (id, namespace, name, template, parameters, state, created_by, \
             created_at, frozen_at, signature, signer_pubkey, metadata) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            rt.id,
            rt.namespace,
            rt.name,
            rt.template.to_string(),
            rt.parameters.to_string(),
            rt.state.as_str(),
            rt.created_by,
            rt.created_at,
            rt.frozen_at,
            rt.signature,
            rt.signer_pubkey,
            rt.metadata.to_string(),
        ],
    )?;
    Ok(rt.id.clone())
}

/// Fetch a routine by id. `None` when absent.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn routine_get(conn: &Connection, id: &str) -> rusqlite::Result<Option<Routine>> {
    conn.query_row(
        &format!("{ROUTINE_SELECT_SQL} WHERE id = ?1"),
        params![id],
        row_to_routine,
    )
    .optional()
}

/// List a namespace's routines, newest-first, capped at `limit`. When `state`
/// is `Some`, narrows to that lifecycle state; when `None`, returns every
/// routine in the namespace.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn routine_list(
    conn: &Connection,
    namespace: &str,
    state: Option<RoutineState>,
    limit: usize,
) -> rusqlite::Result<Vec<Routine>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut sql = format!("{ROUTINE_SELECT_SQL} WHERE namespace = ?");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(namespace.to_string())];
    if let Some(st) = state {
        sql.push_str(crate::checkpoints::SQL_AND_STATE_EQ);
        sql.push('?');
        binds.push(Box::new(st.as_str().to_string()));
    }
    sql.push_str(crate::checkpoints::SQL_ORDER_BY_CREATED_DESC_LIMIT);
    sql.push('?');
    binds.push(Box::new(lim));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_routine,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Freeze a routine (Draft → Frozen, sets `frozen_at`). Idempotent on an
/// already-frozen routine (the `frozen_at` is left as-is). Returns the
/// routine, or `None` if the id does not exist.
///
/// # Errors
/// Propagates the `rusqlite` update/query error.
pub fn routine_freeze(
    conn: &Connection,
    id: &str,
    frozen_at: i64,
) -> rusqlite::Result<Option<Routine>> {
    // Only flip a Draft → Frozen (set frozen_at on the transition); an
    // already-frozen routine keeps its original frozen_at (idempotent no-op
    // update). A missing id → `None`.
    conn.execute(
        "UPDATE routines SET state = ?1, frozen_at = ?2 \
         WHERE id = ?3 AND state = ?4",
        params![
            RoutineState::Frozen.as_str(),
            frozen_at,
            id,
            RoutineState::Draft.as_str(),
        ],
    )?;
    routine_get(conn, id)
}

/// Map a `rusqlite` row (the [`ROUTINE_RUN_SELECT_SQL`] column order) to a
/// [`RoutineRun`].
///
/// # Errors
/// Propagates the `rusqlite` column-access error.
pub fn row_to_routine_run(r: &rusqlite::Row<'_>) -> rusqlite::Result<RoutineRun> {
    Ok(RoutineRun {
        id: r.get(0)?,
        routine_id: r.get(1)?,
        namespace: r.get(2)?,
        arguments: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or(serde_json::Value::Null),
        state: RoutineRunState::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
        created_action_ids: serde_json::from_str(&r.get::<_, String>(5)?)
            .unwrap_or(serde_json::Value::Null),
        started_at: r.get(6)?,
        finished_at: r.get::<_, Option<i64>>(7)?,
        error: r.get(8)?,
        metadata: serde_json::from_str(&r.get::<_, String>(9)?).unwrap_or(serde_json::Value::Null),
    })
}

/// Insert a routine run. Returns the run id.
///
/// # Errors
/// Propagates the `rusqlite` insert error.
pub fn run_insert(conn: &Connection, run: &RoutineRun) -> rusqlite::Result<String> {
    conn.execute(
        "INSERT INTO routine_runs \
            (id, routine_id, namespace, arguments, state, created_action_ids, \
             started_at, finished_at, error, metadata) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            run.id,
            run.routine_id,
            run.namespace,
            run.arguments.to_string(),
            run.state.as_str(),
            run.created_action_ids.to_string(),
            run.started_at,
            run.finished_at,
            run.error,
            run.metadata.to_string(),
        ],
    )?;
    Ok(run.id.clone())
}

/// Fetch a routine run by id. `None` when absent.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn run_get(conn: &Connection, id: &str) -> rusqlite::Result<Option<RoutineRun>> {
    conn.query_row(
        &format!("{ROUTINE_RUN_SELECT_SQL} WHERE id = ?1"),
        params![id],
        row_to_routine_run,
    )
    .optional()
}

/// List a routine's runs, newest-first (by `started_at`), capped at `limit`.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn runs_for(
    conn: &Connection,
    routine_id: &str,
    limit: usize,
) -> rusqlite::Result<Vec<RoutineRun>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let sql = format!(
        "{ROUTINE_RUN_SELECT_SQL} WHERE routine_id = ?1{SQL_ORDER_BY_STARTED_DESC_LIMIT}?2"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![routine_id, lim], row_to_routine_run)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Advance a run's lifecycle: set `state` plus, when `Some`, `finished_at` /
/// `created_action_ids` / `error`. A `None` argument leaves that column
/// untouched. Returns the updated run, or `None` if the id does not exist.
///
/// # Errors
/// Propagates the `rusqlite` update/query error.
pub fn run_set_state(
    conn: &Connection,
    run_id: &str,
    state: RoutineRunState,
    finished_at: Option<i64>,
    created_action_ids: Option<&serde_json::Value>,
    error: Option<&str>,
) -> rusqlite::Result<Option<RoutineRun>> {
    // COALESCE-style partial update: each optional column is overwritten only
    // when the corresponding argument is `Some` (`?N IS NOT NULL` guard keeps
    // the existing value otherwise), so a state-only advance never clobbers a
    // previously-set finished_at / created_action_ids / error.
    let action_ids_json = created_action_ids.map(std::string::ToString::to_string);
    let n = conn.execute(
        "UPDATE routine_runs SET \
            state = ?1, \
            finished_at = COALESCE(?2, finished_at), \
            created_action_ids = COALESCE(?3, created_action_ids), \
            error = COALESCE(?4, error) \
         WHERE id = ?5",
        params![state.as_str(), finished_at, action_ids_json, error, run_id],
    )?;
    if n == 0 {
        return Ok(None);
    }
    run_get(conn, run_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn sample(id: &str) -> Routine {
        Routine {
            id: id.to_string(),
            namespace: "_rt".to_string(),
            name: "deploy".to_string(),
            template: serde_json::json!({ "actions": [] }),
            parameters: serde_json::json!([]),
            state: RoutineState::Draft,
            created_by: "agent-author".to_string(),
            created_at: 1_700_000_000,
            frozen_at: None,
            signature: vec![],
            signer_pubkey: vec![],
            metadata: serde_json::json!({}),
        }
    }

    fn sample_run(id: &str, routine_id: &str) -> RoutineRun {
        RoutineRun {
            id: id.to_string(),
            routine_id: routine_id.to_string(),
            namespace: "_rt".to_string(),
            arguments: serde_json::json!({}),
            state: RoutineRunState::Pending,
            created_action_ids: serde_json::json!([]),
            started_at: 1_700_000_000,
            finished_at: None,
            error: None,
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn routine_insert_then_get_roundtrips() {
        let conn = fresh();
        let id = routine_insert(&conn, &sample("rt1")).unwrap();
        assert_eq!(id, "rt1");
        let got = routine_get(&conn, "rt1").unwrap().expect("present");
        assert_eq!(got.namespace, "_rt");
        assert_eq!(got.name, "deploy");
        assert_eq!(got.state, RoutineState::Draft);
        assert_eq!(got.created_by, "agent-author");
        assert_eq!(got.template, serde_json::json!({ "actions": [] }));
        assert_eq!(got.parameters, serde_json::json!([]));
        assert_eq!(got.metadata, serde_json::json!({}));
        assert!(got.signature.is_empty());
        assert!(got.signer_pubkey.is_empty());
        assert!(got.frozen_at.is_none());
        assert!(routine_get(&conn, "missing").unwrap().is_none());
    }

    #[test]
    fn routine_list_filters_by_namespace_and_state() {
        let conn = fresh();
        routine_insert(&conn, &sample("d1")).unwrap();
        let mut d2 = sample("d2");
        d2.created_at = 1_700_000_100;
        routine_insert(&conn, &d2).unwrap();
        // A frozen routine in the same namespace.
        let mut frozen = sample("frozen");
        frozen.state = RoutineState::Frozen;
        frozen.frozen_at = Some(1_700_000_050);
        frozen.created_at = 1_700_000_050;
        routine_insert(&conn, &frozen).unwrap();
        // A routine in a different namespace must not surface.
        let mut other = sample("other-ns");
        other.namespace = "_rt_elsewhere".to_string();
        routine_insert(&conn, &other).unwrap();

        // No state filter — every routine in the namespace, newest-first.
        let all = routine_list(&conn, "_rt", None, 50).unwrap();
        let ids: Vec<&str> = all.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["d2", "frozen", "d1"], "newest-first ordering");
        assert!(!ids.contains(&"other-ns"), "other-namespace hidden");

        // State filter narrows to draft only.
        let drafts = routine_list(&conn, "_rt", Some(RoutineState::Draft), 50).unwrap();
        let dids: Vec<&str> = drafts.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(dids, vec!["d2", "d1"]);
    }

    #[test]
    fn routine_freeze_flips_draft_and_is_idempotent() {
        let conn = fresh();
        routine_insert(&conn, &sample("f1")).unwrap();
        let frozen = routine_freeze(&conn, "f1", 1_700_000_500)
            .unwrap()
            .expect("freeze returns the updated row");
        assert_eq!(frozen.state, RoutineState::Frozen);
        assert_eq!(frozen.frozen_at, Some(1_700_000_500));

        // Re-freeze is idempotent: frozen_at stays the original value.
        let again = routine_freeze(&conn, "f1", 1_700_009_999)
            .unwrap()
            .expect("re-freeze returns the row");
        assert_eq!(again.state, RoutineState::Frozen);
        assert_eq!(again.frozen_at, Some(1_700_000_500), "frozen_at unchanged");

        // Freezing a missing routine yields None.
        assert!(
            routine_freeze(&conn, "does-not-exist", 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn run_insert_then_get_roundtrips() {
        let conn = fresh();
        routine_insert(&conn, &sample("rt1")).unwrap();
        let id = run_insert(&conn, &sample_run("run1", "rt1")).unwrap();
        assert_eq!(id, "run1");
        let got = run_get(&conn, "run1").unwrap().expect("present");
        assert_eq!(got.routine_id, "rt1");
        assert_eq!(got.namespace, "_rt");
        assert_eq!(got.state, RoutineRunState::Pending);
        assert_eq!(got.arguments, serde_json::json!({}));
        assert_eq!(got.created_action_ids, serde_json::json!([]));
        assert!(got.finished_at.is_none());
        assert!(got.error.is_none());
        assert!(run_get(&conn, "missing").unwrap().is_none());
    }

    #[test]
    fn runs_for_lists_newest_first() {
        let conn = fresh();
        routine_insert(&conn, &sample("rt1")).unwrap();
        run_insert(&conn, &sample_run("a", "rt1")).unwrap();
        let mut b = sample_run("b", "rt1");
        b.started_at = 1_700_000_100;
        run_insert(&conn, &b).unwrap();
        // A run for a different routine must not surface.
        routine_insert(&conn, &sample("rt2")).unwrap();
        run_insert(&conn, &sample_run("c", "rt2")).unwrap();

        let runs = runs_for(&conn, "rt1", 50).unwrap();
        let ids: Vec<&str> = runs.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "a"], "newest-first ordering");
    }

    #[test]
    fn run_set_state_advances_lifecycle() {
        let conn = fresh();
        routine_insert(&conn, &sample("rt1")).unwrap();
        run_insert(&conn, &sample_run("run1", "rt1")).unwrap();

        // Pending → Running (state-only; no finished_at / action ids yet).
        let running = run_set_state(&conn, "run1", RoutineRunState::Running, None, None, None)
            .unwrap()
            .expect("present");
        assert_eq!(running.state, RoutineRunState::Running);
        assert!(running.finished_at.is_none());

        // Running → Completed: sets finished_at + created_action_ids.
        let action_ids = serde_json::json!(["a1", "a2"]);
        let completed = run_set_state(
            &conn,
            "run1",
            RoutineRunState::Completed,
            Some(1_700_000_500),
            Some(&action_ids),
            None,
        )
        .unwrap()
        .expect("present");
        assert_eq!(completed.state, RoutineRunState::Completed);
        assert_eq!(completed.finished_at, Some(1_700_000_500));
        assert_eq!(completed.created_action_ids, action_ids);
        assert!(completed.error.is_none());

        // Advancing a missing run yields None.
        assert!(
            run_set_state(&conn, "nope", RoutineRunState::Failed, None, None, None)
                .unwrap()
                .is_none()
        );
    }
}
