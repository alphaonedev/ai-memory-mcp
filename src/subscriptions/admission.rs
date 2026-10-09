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
//! dispatching caller's own connection inside one SAVEPOINT (one commit per
//! dispatch call, safe whether or not the caller is inside a transaction,
//! and no second writer competing for the WAL lock the caller may hold); the
//! postgres daemon, whose audit mirror is the sqlite sidecar at `db_path`,
//! opens that sidecar once per call.
//!
//! * **Fail closed (#3191 F-5 shape).** A delivery whose admission row
//!   cannot be written is not sent: it gets a DLQ row instead, synchronously.
//!   If the SAVEPOINT cannot be committed, every delivery it carried is
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

/// Tracing target for admission failures.
const TRACE_TARGET: &str = "ai_memory::subscriptions::admission";

/// The SAVEPOINT name; nested safely inside any caller transaction.
const SAVEPOINT: &str = "webhook_admission_3980";

enum Conn<'c> {
    Caller(&'c Connection),
    Sidecar(Connection),
    /// The sidecar could not be opened; every admission fails closed.
    Unavailable(String),
}

/// One dispatch call's admission batch.
pub(super) struct Admission<'c> {
    conn: Conn<'c>,
    db_path: &'c Path,
    savepoint: bool,
}

impl<'c> Admission<'c> {
    /// Open the batch on `caller` (sqlite path) or on the sidecar at
    /// `db_path` (postgres path, `caller = None`).
    pub(super) fn begin(caller: Option<&'c Connection>, db_path: &'c Path) -> Self {
        let conn = match caller {
            Some(c) => Conn::Caller(c),
            // Through the `crate::storage` open funnel (pragmas, sqlcipher
            // key), not a raw open (#2445 ledger).
            None => match crate::storage::open_unmigrated(db_path) {
                Ok(c) => Conn::Sidecar(c),
                Err(e) => Conn::Unavailable(e.to_string()),
            },
        };
        let savepoint = match &conn {
            Conn::Caller(c) => c.execute_batch(&format!("SAVEPOINT {SAVEPOINT}")).is_ok(),
            Conn::Sidecar(c) => c.execute_batch(&format!("SAVEPOINT {SAVEPOINT}")).is_ok(),
            Conn::Unavailable(_) => false,
        };
        Self {
            conn,
            db_path,
            savepoint,
        }
    }

    fn conn(&self) -> Result<&Connection> {
        match &self.conn {
            Conn::Caller(c) => Ok(c),
            Conn::Sidecar(c) => Ok(c),
            Conn::Unavailable(e) => Err(anyhow::anyhow!("audit db open failed: {e}")),
        }
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
    pub(super) fn commit(self) -> Result<()> {
        if !self.savepoint {
            return Ok(());
        }
        let c = self.conn()?;
        if let Err(e) = c.execute_batch(&format!("RELEASE {SAVEPOINT}")) {
            let _ = c.execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"));
            return Err(e).context("webhook admission commit");
        }
        Ok(())
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
    let mut conn = crate::storage::open_unmigrated(db_path).context("subscription_dlq open")?;
    let tx = conn.transaction().context("shutdown DLQ transaction")?;
    super::record_dlq_with_conn(
        &tx,
        sub_id,
        correlation_id,
        event,
        body,
        0,
        last_error,
        at,
        at,
    )?;
    tx.execute(
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

    #[test]
    fn admission_rows_commit_together_and_survive_without_a_worker_3980() {
        let (_keep, db) = fresh_db();
        let conn = Connection::open(&db).expect("open");
        let adm = Admission::begin(Some(&conn), &db);
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
        let adm = Admission::begin(Some(&conn), &db);
        assert!(!adm.admit("sub-a", "corr-a", "memory_store", "{}"));
        adm.commit().expect("commit");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM subscription_dlq"), 1);
    }

    #[test]
    fn the_sidecar_path_admits_without_a_caller_connection_3980() {
        let (_keep, db) = fresh_db();
        let adm = Admission::begin(None, &db);
        assert!(adm.admit("sub-a", "corr-a", "memory_store", "{}"));
        adm.commit().expect("commit");
        let conn = Connection::open(&db).expect("open");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM subscription_events"), 1);
    }

    #[test]
    fn the_drain_transfer_replaces_a_pending_row_but_never_a_settled_one_3980() {
        let (_keep, db) = fresh_db();
        let conn = Connection::open(&db).expect("open");
        let adm = Admission::begin(Some(&conn), &db);
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
