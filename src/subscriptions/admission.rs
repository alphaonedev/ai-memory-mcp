// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3980 — the per-delivery audit row is persisted at ADMISSION.
//!
//! Before #3980 a delivery's `subscription_events` row was written by its
//! worker, which runs only once the delivery holds a `DISPATCH_SEMAPHORE`
//! permit and the blocking pool has started it. #3979 records a delivery
//! still queued at the graceful drain deadline to the DLQ, but a crash
//! (SIGKILL, OOM kill, panic-abort) never reaches the drain, so every
//! admitted-but-unstarted delivery vanished with no row at all.
//!
//! Now `dispatch_event_to_subs` writes every matching delivery's row as
//! `delivery_status = 'pending'` BEFORE it spawns anything, and the worker
//! only UPDATEs that row. On the sqlite path the rows go through the
//! dispatching caller's own connection in one `BEGIN IMMEDIATE` transaction
//! (one commit per dispatch call; a caller already inside a transaction is
//! joined, so no second writer competes for the WAL lock the caller holds,
//! #6568); the postgres daemon, whose audit mirror is the sqlite sidecar at
//! `db_path`, opens that sidecar once per call.
//!
//! * **Fail closed (#3191 F-5 shape).** A delivery whose admission row
//!   cannot be written is not sent: it gets a DLQ row instead, synchronously.
//!   If the batch cannot be committed, every delivery it carried is
//!   refused the same way before any worker is spawned.
//! * **Crash recovery is a read, not a re-send.** A crash leaves the
//!   unstarted delivery's row `pending` with its full payload, so
//!   `memory_subscription_replay` returns it and `doctor` counts it as
//!   stale-pending. Nothing re-sends it automatically: a boot re-dispatch
//!   cannot tell "never sent" from "sent, killed before the status UPDATE",
//!   and a sibling process sharing the database may still own it
//!   (5-agent vote (4d3ea1c5), 4-1 for this minimal form).
//! * **Graceful drain miss (#3979).** The sweep moves an unstarted delivery
//!   to the DLQ AND deletes its still-`pending` admission row in the same
//!   transaction ([`transfer_unstarted_to_dlq`]), so a delivery is still
//!   recorded either as started (audit row) or as `shutdown_unstarted` (DLQ
//!   row), never both.

use std::path::Path;

use anyhow::{Context as _, Result};
use rusqlite::Connection;

use crate::storage::connection::WriteTxn;

/// Tracing target for admission failures.
const TRACE_TARGET: &str = "ai_memory::subscriptions::admission";

/// One dispatch call's admission batch.
///
/// #6568 (#5084) — the batch takes the write lock at BEGIN: on a connection
/// in autocommit (the sidecar, or a caller outside any transaction) it owns a
/// [`WriteTxn`] (`BEGIN IMMEDIATE`). A caller already inside a transaction is
/// JOINED instead ([`crate::storage::connection::in_write_txn`] semantics):
/// every production SQLite transaction opens `BEGIN IMMEDIATE` (closed-world
/// gate `scripts/check-sqlite-write-txn-immediate.py`), so that caller already
/// holds the write lock, and its own commit decides the batch.
pub(super) struct Admission<'c> {
    /// The audit connection, or why it could not be opened (every admission
    /// then fails closed).
    conn: std::result::Result<&'c Connection, String>,
    db_path: &'c Path,
    /// The batch's own transaction; `None` when joined to the caller's, or
    /// when `BEGIN IMMEDIATE` failed (each row then commits on its own).
    txn: Option<WriteTxn<'c>>,
}

impl<'c> Admission<'c> {
    /// Open the batch on `caller` (sqlite path) or on the sidecar at
    /// `db_path` (postgres path, `caller = None`), which is opened into
    /// `sidecar` so the batch's transaction can borrow it.
    pub(super) fn begin(
        caller: Option<&'c Connection>,
        db_path: &'c Path,
        sidecar: &'c mut Option<Connection>,
    ) -> Self {
        let conn = match caller {
            Some(c) => Ok(c),
            // Through the `crate::storage` open funnel (pragmas, sqlcipher
            // key), not a raw open (#2445 ledger).
            None => match crate::storage::open_unmigrated(db_path) {
                Ok(c) => Ok(&*sidecar.insert(c)),
                Err(e) => Err(e.to_string()),
            },
        };
        let txn = match conn {
            Ok(c) if c.is_autocommit() => match WriteTxn::begin(c) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        "webhook admission BEGIN IMMEDIATE failed: {e}; each admission row \
                         commits on its own (#6568)"
                    );
                    None
                }
            },
            _ => None,
        };
        Self { conn, db_path, txn }
    }

    fn conn(&self) -> Result<&'c Connection> {
        self.conn
            .as_ref()
            .copied()
            .map_err(|e| anyhow::anyhow!("audit db open failed: {e}"))
    }

    /// Write the delivery's `pending` audit row. `false` means the row could
    /// not be written: the delivery has been routed to the DLQ (or, if even
    /// that failed, logged at ERROR) and must not be sent.
    pub(super) fn admit(
        &self,
        sub_id: &str,
        correlation_id: &str,
        event: &str,
        body: &str,
    ) -> bool {
        let inserted = self.conn().and_then(|c| {
            super::record_subscription_event_with_conn(c, sub_id, correlation_id, event, body)
        });
        let Err(e) = inserted else {
            return true;
        };
        tracing::warn!(
            target: TRACE_TARGET,
            subscription_id = %sub_id,
            correlation_id = %correlation_id,
            "dispatch refused: admission audit write failed: {e}; routing to DLQ instead of \
             dispatching unaudited (#3191 F-5, #3980)"
        );
        let last_error = format!("event audit write failed; dispatch refused fail-closed: {e}");
        let now = chrono::Utc::now().to_rfc3339();
        let dlq = match self.conn() {
            Ok(c) => super::record_dlq_with_conn(
                c,
                sub_id,
                correlation_id,
                event,
                body,
                0,
                &last_error,
                &now,
                &now,
            ),
            Err(_) => super::record_dlq(
                self.db_path,
                sub_id,
                correlation_id,
                event,
                body,
                0,
                &last_error,
                &now,
                &now,
            ),
        };
        if let Err(de) = dlq {
            tracing::error!(
                target: TRACE_TARGET,
                subscription_id = %sub_id,
                correlation_id = %correlation_id,
                "subscription DLQ write failed after admission audit failure: {de}; the \
                 delivery is not sent and has no durable record"
            );
        }
        false
    }

    /// #4280 — a namespace-only row's event: its audit row, already settled
    /// as never-sent. Nothing is spawned for it; a failed write is logged.
    pub(super) fn record_namespace_only(
        &self,
        sub_id: &str,
        correlation_id: &str,
        event: &str,
        body: &str,
    ) {
        let res = self.conn().and_then(|c| {
            super::namespace_only::record_with_conn(c, sub_id, correlation_id, event, body)
        });
        if let Err(e) = res {
            tracing::error!(
                target: TRACE_TARGET,
                subscription_id = %sub_id,
                correlation_id = %correlation_id,
                "namespace-only subscription event could not be recorded; replay will \
                 not return it: {e}"
            );
        }
    }

    /// Commit the batch. On `Err` every admission row of the batch is gone
    /// and the caller must refuse every delivery it admitted.
    ///
    /// A failed COMMIT leaves the [`WriteTxn`] armed, so its drop rolls the
    /// batch back. A batch joined to the caller's transaction has nothing of
    /// its own to commit.
    pub(super) fn commit(self) -> Result<()> {
        match self.txn {
            Some(txn) => txn.commit().context("webhook admission commit"),
            None => Ok(()),
        }
    }
}

/// #3979 + #3980 — the graceful drain's ownership hand-off for a delivery
/// whose worker never started: its `shutdown_unstarted` DLQ row and the
/// deletion of its still-`pending` admission row commit together, so the
/// delivery ends with exactly one durable record. Only a `pending` row is
/// removed; a row a worker has already settled is never touched.
#[allow(clippy::too_many_arguments)]
pub(super) fn transfer_unstarted_to_dlq(
    db_path: &Path,
    sub_id: &str,
    correlation_id: &str,
    event: &str,
    body: &str,
    last_error: &str,
    at: &str,
) -> Result<()> {
    let conn = crate::storage::open_unmigrated(db_path).context("subscription_dlq open")?;
    // #6568 (#5084) — BEGIN IMMEDIATE: the write lock is taken up front.
    let tx = WriteTxn::begin(&conn).context("shutdown DLQ transaction")?;
    super::record_dlq_with_conn(
        &conn,
        sub_id,
        correlation_id,
        event,
        body,
        0,
        last_error,
        at,
        at,
    )?;
    conn.execute(
        "DELETE FROM subscription_events WHERE subscription_id = ?1 \
         AND correlation_id = ?2 AND delivery_status = 'pending'",
        rusqlite::params![sub_id, correlation_id],
    )
    .context("subscription_events pending-row delete")?;
    tx.commit().context("shutdown DLQ commit")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> (tempfile::NamedTempFile, std::path::PathBuf) {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let p = f.path().to_path_buf();
        drop(crate::db::open(&p).expect("db::open"));
        (f, p)
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).expect("count")
    }

    /// #6568 — a second connection's write, with no busy wait: `true` when
    /// it is refused with `SQLITE_BUSY` because another connection already
    /// holds the database write lock.
    fn write_is_locked_out(db: &Path) -> bool {
        let other = Connection::open(db).expect("probe connection");
        other
            .busy_timeout(std::time::Duration::ZERO)
            .expect("busy_timeout");
        match other.execute(
            "INSERT INTO subscription_dlq (subscription_id, correlation_id, event_type, payload, \
             retry_count, last_error, first_failed_at, last_failed_at) \
             VALUES ('probe', 'probe', 'probe', '{}', 0, 'probe', 't', 't')",
            [],
        ) {
            Ok(_) => false,
            Err(rusqlite::Error::SqliteFailure(e, _)) => {
                e.code == rusqlite::ErrorCode::DatabaseBusy
            }
            Err(e) => panic!("unexpected probe error: {e}"),
        }
    }

    #[test]
    fn admission_on_an_autocommit_caller_takes_the_write_lock_at_begin_6568() {
        let (_keep, db) = fresh_db();
        let conn = Connection::open(&db).expect("open");
        let mut sidecar = None;
        let adm = Admission::begin(Some(&conn), &db, &mut sidecar);
        assert!(
            write_is_locked_out(&db),
            "the admission batch must hold the write lock from BEGIN (BEGIN IMMEDIATE, #5084), \
             not upgrade a deferred lock at its first write"
        );
        adm.commit().expect("commit");
        assert!(!write_is_locked_out(&db), "commit releases the write lock");
    }

    #[test]
    fn admission_on_the_sidecar_takes_the_write_lock_at_begin_6568() {
        let (_keep, db) = fresh_db();
        let mut sidecar = None;
        let adm = Admission::begin(None, &db, &mut sidecar);
        assert!(
            write_is_locked_out(&db),
            "the sidecar admission batch must hold the write lock from BEGIN (#5084)"
        );
        adm.commit().expect("commit");
        assert!(!write_is_locked_out(&db), "commit releases the write lock");
    }

    #[test]
    fn a_caller_transaction_is_joined_and_its_rollback_discards_the_batch_6568() {
        let (_keep, db) = fresh_db();
        let conn = Connection::open(&db).expect("open");
        let caller = WriteTxn::begin(&conn).expect("caller BEGIN IMMEDIATE");
        let mut sidecar = None;
        let adm = Admission::begin(Some(&conn), &db, &mut sidecar);
        assert!(adm.admit("sub-a", "corr-a", "memory_store", "{}"));
        adm.commit()
            .expect("a joined batch has nothing of its own to commit");
        assert!(
            !conn.is_autocommit(),
            "the caller's transaction is still open"
        );
        caller.rollback();
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM subscription_events"),
            0,
            "the caller's rollback decides the joined batch"
        );
    }

    #[test]
    fn the_drain_transfer_takes_the_write_lock_at_begin_6568() {
        let (_keep, db) = fresh_db();
        let holder = Connection::open(&db).expect("lock holder");
        holder
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold the write lock");
        let err = transfer_unstarted_to_dlq(
            &db,
            "sub-a",
            "corr-a",
            "memory_store",
            "{}",
            "shutdown_unstarted",
            "t",
        )
        .expect_err("a held write lock must refuse the transfer");
        holder.execute_batch("ROLLBACK").expect("release");
        let chain = format!("{err:#}");
        assert!(
            chain.starts_with("shutdown DLQ transaction"),
            "contention must surface at BEGIN IMMEDIATE (the lock is taken up front, #5084), \
             not at the first write of a deferred transaction; got: {chain}"
        );
    }

    #[test]
    fn admission_rows_commit_together_and_survive_without_a_worker_3980() {
        let (_keep, db) = fresh_db();
        let conn = Connection::open(&db).expect("open");
        let mut sidecar = None;
        let adm = Admission::begin(Some(&conn), &db, &mut sidecar);
        assert!(adm.admit("sub-a", "corr-a", "memory_store", "{}"));
        assert!(adm.admit("sub-b", "corr-b", "memory_store", "{}"));
        adm.commit().expect("commit");
        let other = Connection::open(&db).expect("second connection");
        assert_eq!(
            count(
                &other,
                "SELECT COUNT(*) FROM subscription_events WHERE delivery_status = 'pending'"
            ),
            2
        );
    }

    #[test]
    fn a_failed_admission_row_is_routed_to_the_dlq_not_sent_3980() {
        let (_keep, db) = fresh_db();
        let conn = Connection::open(&db).expect("open");
        conn.execute_batch("DROP TABLE subscription_events")
            .expect("drop audit table");
        let mut sidecar = None;
        let adm = Admission::begin(Some(&conn), &db, &mut sidecar);
        assert!(!adm.admit("sub-a", "corr-a", "memory_store", "{}"));
        adm.commit().expect("commit");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM subscription_dlq"), 1);
    }

    #[test]
    fn the_sidecar_path_admits_without_a_caller_connection_3980() {
        let (_keep, db) = fresh_db();
        let mut sidecar = None;
        let adm = Admission::begin(None, &db, &mut sidecar);
        assert!(adm.admit("sub-a", "corr-a", "memory_store", "{}"));
        adm.commit().expect("commit");
        let conn = Connection::open(&db).expect("open");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM subscription_events"), 1);
    }

    #[test]
    fn the_drain_transfer_replaces_a_pending_row_but_never_a_settled_one_3980() {
        let (_keep, db) = fresh_db();
        let conn = Connection::open(&db).expect("open");
        let mut sidecar = None;
        let adm = Admission::begin(Some(&conn), &db, &mut sidecar);
        assert!(adm.admit("sub-a", "corr-a", "memory_store", "{}"));
        assert!(adm.admit("sub-b", "corr-b", "memory_store", "{}"));
        adm.commit().expect("commit");
        conn.execute(
            "UPDATE subscription_events SET delivery_status = 'ack' WHERE correlation_id = 'corr-b'",
            [],
        )
        .expect("settle b");
        for corr in ["corr-a", "corr-b"] {
            let sub = corr.replace("corr", "sub");
            transfer_unstarted_to_dlq(
                &db,
                &sub,
                corr,
                "memory_store",
                "{}",
                "shutdown_unstarted",
                "t",
            )
            .expect("transfer");
        }
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM subscription_events WHERE correlation_id = 'corr-a'"
            ),
            0,
            "the unstarted delivery's pending row moves to the DLQ"
        );
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM subscription_events WHERE correlation_id = 'corr-b'"
            ),
            1,
            "a settled row is never deleted"
        );
    }
}
