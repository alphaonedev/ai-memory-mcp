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
        one("PRAGMA application_id"),
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

// ---------------------------------------------------------------- neighbours

/// One neighbour probe: SQL the closure runs inside the scope.
struct Probe {
    name: &'static str,
    sql: &'static str,
}

/// Writes of every shape the pragma must refuse, on both paths: each one
/// errors, the error names the guard, and nothing it would change lands.
const WRITE_PROBES: &[Probe] = &[
    Probe {
        name: "INSERT",
        sql: "INSERT INTO p (id, v) VALUES (2, 'b')",
    },
    Probe {
        name: "UPDATE",
        sql: "UPDATE p SET v = 'z' WHERE id = 1",
    },
    Probe {
        name: "DELETE",
        sql: "DELETE FROM p",
    },
    Probe {
        name: "REPLACE",
        sql: "REPLACE INTO p (id, v) VALUES (1, 'r')",
    },
    Probe {
        name: "CREATE TABLE",
        sql: "CREATE TABLE x5235 (a)",
    },
    Probe {
        name: "CREATE TEMP TABLE",
        sql: "CREATE TEMP TABLE x5235 (a)",
    },
    Probe {
        name: "CREATE INDEX",
        sql: "CREATE INDEX p_v5235 ON p (v)",
    },
    Probe {
        name: "DROP TABLE",
        sql: "DROP TABLE p",
    },
    Probe {
        name: "ALTER TABLE",
        sql: "ALTER TABLE p ADD COLUMN w5235 TEXT",
    },
    Probe {
        name: "trigger-driven UPDATE",
        sql: "UPDATE t SET v = 'b' WHERE id = 1",
    },
    Probe {
        name: "FTS insert",
        sql: "INSERT INTO t_fts (body) VALUES ('x')",
    },
    Probe {
        name: "FTS rebuild",
        sql: "INSERT INTO t_fts (t_fts) VALUES ('rebuild')",
    },
    Probe {
        name: "PRAGMA user_version",
        sql: "PRAGMA user_version = 7",
    },
    Probe {
        name: "PRAGMA application_id",
        sql: "PRAGMA application_id = 7",
    },
    Probe {
        name: "SAVEPOINT then write",
        sql: "SAVEPOINT s5235; INSERT INTO p (id, v) VALUES (3, 'c'); RELEASE s5235",
    },
];

#[test]
fn neighbour_writes_are_refused_on_both_paths_5235() {
    for probe in WRITE_PROBES {
        for path in PATHS {
            let conn = probe_conn();
            let before = fingerprint(&conn);
            let (r, during) = in_scope(&conn, path, |c| {
                c.execute_batch(probe.sql)?;
                Ok(())
            });
            let what = format!("{} {path:?}", probe.name);
            let err = r.expect_err(&what);
            assert_named(&err, &what);
            assert_eq!(
                err.downcast_ref::<super::ReadSnapshotGuardRefusal>(),
                Some(&super::ReadSnapshotGuardRefusal::WriteRefused),
                "{what}: typed marker"
            );
            assert_eq!(during, before, "{what}: nothing lands");
            assert_eq!(query_only(&conn), 0, "{what}: prior OFF restored");
        }
    }
}

#[test]
fn cached_statement_prepared_before_the_scope_is_refused_5235() {
    const SQL: &str = "INSERT INTO p (id, v) VALUES (4, 'd')";
    for path in PATHS {
        let conn = probe_conn();
        let before = fingerprint(&conn);
        drop(conn.prepare_cached(SQL).unwrap());
        let (r, during) = in_scope(&conn, path, |c| {
            c.prepare_cached(SQL)?.execute([])?;
            Ok(())
        });
        assert_named(&r.expect_err("cached INSERT"), &format!("{path:?} cached"));
        assert_eq!(during, before, "{path:?}");
    }
}

#[test]
fn nested_begin_and_attach_fail_and_write_nothing_5235() {
    for (name, sql) in [
        ("nested BEGIN", "BEGIN"),
        (
            "ATTACH then write",
            "ATTACH ':memory:' AS aux5235; CREATE TABLE aux5235.x (a)",
        ),
    ] {
        for path in PATHS {
            let conn = probe_conn();
            let before = fingerprint(&conn);
            let (r, during) = in_scope(&conn, path, |c| {
                c.execute_batch(sql)?;
                Ok(())
            });
            assert!(
                r.is_err(),
                "{name} {path:?}: inside a transaction this fails"
            );
            assert_eq!(during, before, "{name} {path:?}");
            assert_eq!(query_only(&conn), 0, "{name} {path:?}");
        }
    }
}

#[test]
fn ordinary_read_only_error_is_not_marked_as_a_guard_refusal_5235() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ro-mark-5235.db");
    drop(crate::storage::connection::open(&db).unwrap());
    let ro = crate::storage::connection::open_read_only(&db).unwrap();
    let r = with_read_snapshot(&ro, |c| {
        c.execute_batch("CREATE TABLE y5235 (a)")?;
        Ok(())
    });
    let err = r.expect_err("a read-only pool connection refuses the write itself");
    assert!(format!("{err:#}").contains("readonly"), "{err:#}");
    assert!(
        err.downcast_ref::<super::ReadSnapshotGuardRefusal>()
            .is_none(),
        "the guard did not cause this refusal, so it must not claim it"
    );
}

#[test]
fn nested_refusal_is_marked_once_5235() {
    let conn = probe_conn();
    let r = with_read_snapshot(&conn, |outer| {
        with_read_snapshot(outer, |inner| {
            inner.execute("INSERT INTO p (id, v) VALUES (6, 'n')", [])?;
            Ok(())
        })
    });
    let text = format!("{:#}", r.unwrap_err());
    assert_eq!(text.matches(GUARD_NAME).count(), 1, "{text}");
}

/// A helper that flattens the SQLite error into text (no typed cause left)
/// is still recognised as a guard refusal, by the SQLite message.
#[test]
fn stringified_refusal_is_still_marked_5235() {
    let conn = probe_conn();
    let r: Result<()> = with_read_snapshot(&conn, |c| {
        c.execute("INSERT INTO p (id, v) VALUES (7, 's')", [])
            .map_err(|e| anyhow::anyhow!("helper failed: {e}"))?;
        Ok(())
    });
    let err = r.expect_err("refused");
    assert!(err.downcast_ref::<rusqlite::Error>().is_none(), "{err:#}");
    assert_eq!(
        err.downcast_ref::<super::ReadSnapshotGuardRefusal>(),
        Some(&super::ReadSnapshotGuardRefusal::WriteRefused),
        "{err:#}"
    );
}

/// A typed `SQLITE_READONLY` whose message is not the stock text is still
/// recognised as a guard refusal, by its error code.
#[test]
fn readonly_code_with_other_text_is_still_marked_5235() {
    let conn = probe_conn();
    let r: Result<()> = with_read_snapshot(&conn, |_| {
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_READONLY),
            Some("refused by a helper".to_owned()),
        )
        .into())
    });
    let err = r.expect_err("refused");
    assert!(
        !format!("{err:#}").contains(super::READONLY_TEXT),
        "{err:#}"
    );
    assert_eq!(
        err.downcast_ref::<super::ReadSnapshotGuardRefusal>(),
        Some(&super::ReadSnapshotGuardRefusal::WriteRefused),
        "{err:#}"
    );
}

// ---------------------------------------------------------------- bypass

/// Writes a closure could smuggle past the pragma by turning it OFF and
/// back ON around them. The post-scope check must refuse each one.
const BYPASS_WRITES: &[(&str, &str)] = &[
    ("INSERT", "INSERT INTO p (id, v) VALUES (8, 'h')"),
    ("CREATE TABLE", "CREATE TABLE bypass5235 (a)"),
    ("CREATE TEMP TABLE", "CREATE TEMP TABLE bypass5235 (a)"),
    ("user_version", "PRAGMA user_version = 9"),
    ("application_id", "PRAGMA application_id = 9"),
    ("FTS insert", "INSERT INTO t_fts (body) VALUES ('bypass')"),
];

fn assert_tampered(err: &anyhow::Error, what: &str) {
    assert_named(err, what);
    assert_eq!(
        err.downcast_ref::<super::ReadSnapshotGuardRefusal>(),
        Some(&super::ReadSnapshotGuardRefusal::ScopeTampered),
        "{what}: {err:#}"
    );
}

#[test]
fn off_write_on_is_refused_and_rolled_back_on_the_autocommit_path_5235() {
    for (name, sql) in BYPASS_WRITES {
        let conn = probe_conn();
        let before = fingerprint(&conn);
        let r = with_read_snapshot(&conn, |c| {
            c.pragma_update(None, "query_only", false)?;
            c.execute_batch(sql)?;
            c.pragma_update(None, "query_only", true)?;
            Ok(())
        });
        assert_tampered(&r.expect_err(name), name);
        assert_eq!(
            fingerprint(&conn),
            before,
            "{name}: the guard rolled it back"
        );
        assert_eq!(query_only(&conn), 0, "{name}: prior OFF restored");
        assert!(conn.is_autocommit(), "{name}");
    }
}

#[test]
fn off_left_off_is_refused_on_both_paths_5235() {
    for path in PATHS {
        let conn = probe_conn();
        let (r, _) = in_scope(&conn, path, |c| {
            c.pragma_update(None, "query_only", false)?;
            Ok(())
        });
        assert_tampered(&r.expect_err("OFF left off"), &format!("{path:?}"));
        assert_eq!(query_only(&conn), 0, "{path:?}");
    }
}

/// Known limit (#5881), pinned so a fix flips it: on the caller-transaction
/// path the guard refuses the scope, but the smuggled write is in the
/// CALLER's transaction, which the guard does not own and cannot roll back.
#[test]
fn off_write_on_in_a_caller_txn_is_refused_but_stays_in_the_caller_txn_5235() {
    for (name, sql) in BYPASS_WRITES {
        let conn = probe_conn();
        let before = fingerprint(&conn);
        let (r, during) = in_scope(&conn, Path::CallerTxn, |c| {
            c.pragma_update(None, "query_only", false)?;
            c.execute_batch(sql)?;
            c.pragma_update(None, "query_only", true)?;
            Ok(())
        });
        assert_tampered(&r.expect_err(name), name);
        assert_ne!(
            during, before,
            "{name}: limit #5881 -- the write is in the caller txn"
        );
        assert_eq!(fingerprint(&conn), before, "{name}: the caller rolled back");
    }
}

/// Known limit (#5882), pinned so a fix flips it: `touch_many` reads
/// `query_only` and returns `Ok(0)` without writing, so a touch inside the
/// scope is skipped silently instead of refused.
#[test]
fn touch_many_inside_the_scope_is_skipped_silently_5235() {
    let conn = probe_conn();
    let touched = with_read_snapshot(&conn, |c| {
        crate::storage::touch_many(c, &["no-such-id"], 1, 1)
    });
    assert_eq!(
        touched.unwrap(),
        0,
        "limit #5882: silent skip, not a refusal"
    );
}
