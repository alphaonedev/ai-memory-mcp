// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5235 — the read-snapshot guard. [`with_read_snapshot`] runs its closure
//! with `PRAGMA query_only = ON`, so any write inside the scope (in the
//! closure itself or in a helper it calls) fails loudly with an error that
//! names the guard, on the autocommit path AND on the path where the caller
//! already holds a transaction. The prior pragma value comes back on every
//! exit (Ok, Err, panic), a nested scope restores the outer value, and a
//! guard that cannot be set up refuses to run the closure.
//!
//! Decision: 5-agent vote (4d3ea1c5), option A, ai-memory
//! `665475b3-3e26-4fa4-a356-551f07977c27`.

use super::tests::{fresh_conn_with_audit, make_rule};
use super::{GUARD_FAULT_5235, GuardFault5235, with_read_snapshot};
use crate::governance::rules_store;
use crate::storage::connection::WriteTxn;
use anyhow::Result;
use rusqlite::Connection;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Every refusal the guard raises carries this phrase.
const GUARD_NAME: &str = "read-snapshot guard";

fn query_only(conn: &Connection) -> i64 {
    conn.pragma_query_value(None, "query_only", |r| r.get(0))
        .unwrap()
}

/// Arms one guard fault on this thread for the life of the value.
struct Fault;
impl Fault {
    fn arm(f: GuardFault5235) -> Self {
        GUARD_FAULT_5235.with(|c| c.set(Some(f)));
        Self
    }
}
impl Drop for Fault {
    fn drop(&mut self) {
        GUARD_FAULT_5235.with(|c| c.set(None));
    }
}

#[derive(Clone, Copy, Debug)]
enum Path {
    /// `conn` is in autocommit mode: the guard owns the snapshot transaction.
    Autocommit,
    /// The caller already holds a write transaction on `conn`.
    CallerTxn,
}
const PATHS: [Path; 2] = [Path::Autocommit, Path::CallerTxn];

/// Fixture: the governance tables plus probe tables, a trigger and FTS5.
fn probe_conn() -> Connection {
    let conn = fresh_conn_with_audit();
    conn.execute_batch(
        "CREATE TABLE p (id INTEGER PRIMARY KEY, v TEXT);
         INSERT INTO p (id, v) VALUES (1, 'a');
         CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
         INSERT INTO t (id, v) VALUES (1, 'a');
         CREATE TABLE t_log (n INTEGER);
         CREATE TRIGGER t_upd AFTER UPDATE ON t
             BEGIN INSERT INTO t_log (n) VALUES (NEW.id); END;
         CREATE VIRTUAL TABLE t_fts USING fts5(body);",
    )
    .unwrap();
    conn
}

/// What a write could have changed: row data, the trigger log, FTS rows,
/// the header cookie, and the schema of `main` and `temp`.
fn fingerprint(conn: &Connection) -> String {
    let one = |sql: &str| -> String {
        conn.query_row(sql, [], |r| r.get::<_, rusqlite::types::Value>(0))
            .map_or_else(|e| format!("err:{e}"), |v| format!("{v:?}"))
    };
    [
        one("SELECT group_concat(id || '=' || v) FROM p"),
        one("SELECT group_concat(id || '=' || v) FROM t"),
        one("SELECT count(*) FROM t_log"),
        one("SELECT count(*) FROM t_fts"),
        one("PRAGMA user_version"),
        one("SELECT group_concat(name) FROM sqlite_schema"),
        one("SELECT group_concat(name) FROM sqlite_temp_schema"),
        one("SELECT count(*) FROM governance_rules"),
    ]
    .join("|")
}

/// Run `read` under [`with_read_snapshot`] on `path`. Returns the result and
/// the fingerprint seen right after the scope (inside the caller's
/// transaction on [`Path::CallerTxn`], which is then rolled back).
fn in_scope<T>(
    conn: &Connection,
    path: Path,
    read: impl FnOnce(&Connection) -> Result<T>,
) -> (Result<T>, String) {
    match path {
        Path::Autocommit => {
            assert!(conn.is_autocommit());
            let r = with_read_snapshot(conn, read);
            (r, fingerprint(conn))
        }
        Path::CallerTxn => {
            let tx = WriteTxn::begin(conn).unwrap();
            let r = with_read_snapshot(conn, read);
            let fp = fingerprint(conn);
            drop(tx);
            (r, fp)
        }
    }
}

fn assert_named(err: &anyhow::Error, what: &str) {
    let text = format!("{err:#}");
    assert!(
        text.contains(GUARD_NAME),
        "{what}: the refusal must name the {GUARD_NAME}, got: {text}"
    );
}

// ---------------------------------------------------------------- refusals

#[test]
fn insert_in_closure_is_refused_with_named_error_on_both_paths_5235() {
    for path in PATHS {
        let conn = probe_conn();
        let before = fingerprint(&conn);
        let (r, during) = in_scope(&conn, path, |c| {
            c.execute("INSERT INTO p (id, v) VALUES (2, 'b')", [])?;
            Ok(())
        });
        let err = r.expect_err("an INSERT inside the read snapshot must be refused");
        assert_named(&err, &format!("{path:?} INSERT"));
        assert_eq!(during, before, "{path:?}: the INSERT must not land");
        assert_eq!(fingerprint(&conn), before, "{path:?}: nothing persisted");
        assert_eq!(query_only(&conn), 0, "{path:?}: prior OFF restored");
    }
}

#[test]
fn helper_that_writes_inside_scope_is_refused_5235() {
    for path in PATHS {
        let conn = probe_conn();
        let before = fingerprint(&conn);
        let (r, during) = in_scope(&conn, path, |c| {
            rules_store::insert(c, &make_rule("R-helper", "store", true))?;
            Ok(())
        });
        let err = r.expect_err("a helper's write inside the scope must be refused");
        assert_named(&err, &format!("{path:?} rules_store::insert"));
        assert_eq!(during, before, "{path:?}: the helper write must not land");

        let (r, during) = in_scope(&conn, path, |c| {
            rules_store::set_enabled(c, "missing", false)?;
            rules_store::remove(c, "missing")?;
            Ok(())
        });
        let err = r.expect_err("set_enabled inside the scope must be refused");
        assert_named(&err, &format!("{path:?} rules_store::set_enabled"));
        assert_eq!(during, before);
    }
}

#[test]
fn policy_readers_still_work_inside_and_after_a_caller_write_txn_5235() {
    let conn = probe_conn();
    let tx = WriteTxn::begin(&conn).unwrap();
    rules_store::insert(&conn, &make_rule("R1", "store", true)).unwrap();
    let pv = super::current_policy_version(&conn).unwrap();
    let (rules, pv2) = super::load_rules_with_policy_version(&conn, "store").unwrap();
    assert_eq!(pv, pv2);
    assert_eq!(rules.len(), 1, "the caller's uncommitted write is visible");
    // The caller's transaction is writable again after the scope.
    rules_store::insert(&conn, &make_rule("R2", "store", true)).unwrap();
    assert_eq!(query_only(&conn), 0);
    tx.commit().unwrap();
    assert_eq!(rules_store::list(&conn).unwrap().len(), 2);
}

// ---------------------------------------------------------------- restore

#[test]
fn pragma_is_on_inside_and_back_off_after_ok_on_both_paths_5235() {
    for path in PATHS {
        let conn = probe_conn();
        let inside = Cell::new(-1);
        let (r, _) = in_scope(&conn, path, |c| {
            inside.set(query_only(c));
            Ok(7)
        });
        assert_eq!(r.unwrap(), 7);
        assert_eq!(inside.get(), 1, "{path:?}: query_only must be ON inside");
        assert_eq!(query_only(&conn), 0, "{path:?}: prior OFF restored");
    }
}

#[test]
fn pragma_is_back_off_after_closure_err_on_both_paths_5235() {
    for path in PATHS {
        let conn = probe_conn();
        let inside = Cell::new(-1);
        let (r, _) = in_scope(&conn, path, |c| -> Result<()> {
            inside.set(query_only(c));
            anyhow::bail!("ordinary read failure")
        });
        let err = r.unwrap_err();
        assert!(
            !format!("{err:#}").contains(GUARD_NAME),
            "an ordinary closure error must not be relabelled as a guard refusal"
        );
        assert_eq!(inside.get(), 1, "{path:?}: query_only must be ON inside");
        assert_eq!(query_only(&conn), 0, "{path:?}: prior OFF restored");
    }
}

#[test]
fn pragma_is_back_off_after_a_caught_panic_5235() {
    for path in PATHS {
        let conn = probe_conn();
        let inside = Cell::new(-1);
        let tx = matches!(path, Path::CallerTxn).then(|| WriteTxn::begin(&conn).unwrap());
        let caught = catch_unwind(AssertUnwindSafe(|| {
            let _ = with_read_snapshot(&conn, |c| -> Result<()> {
                inside.set(query_only(c));
                panic!("closure panics inside the read snapshot");
            });
        }));
        assert!(caught.is_err(), "the panic propagates");
        assert_eq!(inside.get(), 1, "{path:?}: query_only must be ON inside");
        assert_eq!(query_only(&conn), 0, "{path:?}: prior OFF restored");
        drop(tx);
        assert!(conn.is_autocommit(), "{path:?}: no transaction left open");
        conn.execute("INSERT INTO p (id, v) VALUES (9, 'after')", [])
            .expect("the connection is writable again after the panic");
    }
}

#[test]
fn nested_scope_restores_the_outer_value_not_off_5235() {
    let conn = probe_conn();
    let seen = Cell::new((-1, -1, -1));
    with_read_snapshot(&conn, |outer| {
        let before_inner = query_only(outer);
        let inner_seen = with_read_snapshot(outer, |inner| Ok(query_only(inner)))?;
        seen.set((before_inner, inner_seen, query_only(outer)));
        let err = outer
            .execute("INSERT INTO p (id, v) VALUES (5, 'x')", [])
            .expect_err("the outer scope stays read-only after the inner one");
        assert!(format!("{err}").contains("readonly"), "{err}");
        Ok(())
    })
    .unwrap();
    assert_eq!(seen.get(), (1, 1, 1), "outer ON, inner ON, outer still ON");
    assert_eq!(query_only(&conn), 0, "outermost prior OFF restored");
}

#[test]
fn prior_on_stays_on_after_the_scope_on_both_paths_5235() {
    for path in PATHS {
        let conn = probe_conn();
        let tx = matches!(path, Path::CallerTxn).then(|| WriteTxn::begin(&conn).unwrap());
        conn.pragma_update(None, "query_only", true).unwrap();
        let r = with_read_snapshot(&conn, |c| Ok(query_only(c)));
        assert_eq!(r.unwrap(), 1);
        assert_eq!(query_only(&conn), 1, "{path:?}: prior ON must stay ON");
        let r = with_read_snapshot(&conn, |_| -> Result<()> { anyhow::bail!("x") });
        assert!(r.is_err());
        assert_eq!(
            query_only(&conn),
            1,
            "{path:?}: prior ON stays ON after Err"
        );
        conn.pragma_update(None, "query_only", false).unwrap();
        drop(tx);
    }
}

#[test]
fn read_only_pool_connection_stays_query_only_5235() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ro-5235.db");
    drop(crate::storage::connection::open(&db).unwrap());
    let ro = crate::storage::connection::open_read_only(&db).unwrap();
    assert_eq!(query_only(&ro), 1, "the read pool opens query_only");
    assert_eq!(with_read_snapshot(&ro, |c| Ok(query_only(c))).unwrap(), 1);
    assert_eq!(
        query_only(&ro),
        1,
        "the guard must never force a reader OFF"
    );
}

// ---------------------------------------------------------------- setup

#[test]
fn setup_failure_returns_before_the_closure_runs_5235() {
    for fault in [GuardFault5235::ReadPrior, GuardFault5235::SetOn] {
        for path in PATHS {
            let conn = probe_conn();
            let ran = Cell::new(false);
            let _f = Fault::arm(fault);
            let (r, _) = in_scope(&conn, path, |_| {
                ran.set(true);
                Ok(())
            });
            drop(_f);
            let err = r.expect_err("a guard that cannot be set up must refuse");
            assert_named(&err, &format!("{fault:?} {path:?}"));
            assert!(!ran.get(), "{fault:?} {path:?}: the closure must not run");
            assert_eq!(query_only(&conn), 0, "{fault:?} {path:?}");
            assert!(conn.is_autocommit(), "{fault:?} {path:?}: no txn left");
        }
    }
}

#[test]
fn restore_failure_after_ok_is_an_error_and_leaves_read_only_5235() {
    for path in PATHS {
        let conn = probe_conn();
        let tx = matches!(path, Path::CallerTxn).then(|| WriteTxn::begin(&conn).unwrap());
        let _f = Fault::arm(GuardFault5235::Restore);
        let r = with_read_snapshot(&conn, |_| Ok(1));
        drop(_f);
        let err = r.expect_err("a failed restore must not report success");
        assert_named(&err, &format!("{path:?} restore"));
        assert_eq!(
            query_only(&conn),
            1,
            "{path:?}: a failed restore leaves the connection read-only"
        );
        drop(tx);
    }
}

#[test]
fn restore_failure_in_drop_is_logged_and_leaves_read_only_5235() {
    if crate::config::run_env_isolated_child_or_spawn(
        "governance::policy_version::read_snapshot_guard_5235_tests::restore_failure_in_drop_is_logged_and_leaves_read_only_5235",
    ) {
        return;
    }
    let (subscriber, sink) = crate::test_support::error_debug_capture();
    let conn = probe_conn();
    tracing::subscriber::with_default(subscriber, || {
        let _f = Fault::arm(GuardFault5235::Restore);
        let r = with_read_snapshot(&conn, |_| -> Result<()> { anyhow::bail!("closure failed") });
        assert!(format!("{:#}", r.unwrap_err()).contains("closure failed"));
    });
    let (errors, _) = crate::test_support::count_error_and_debug_lines(&sink);
    assert!(
        errors >= 1,
        "a failed restore in Drop must be logged at ERROR"
    );
    let text = crate::test_support::captured_text(&sink);
    assert!(
        text.contains(GUARD_NAME) && text.contains("query_only"),
        "the log line names the guard and the pragma: {text}"
    );
    assert_eq!(
        query_only(&conn),
        1,
        "left read-only, never silently writable"
    );
}
