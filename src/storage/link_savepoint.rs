// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7559 — a SAVEPOINT guard around a link's edge INSERT and its
//! `memory_link.created` audit append, taken only when the connection sits
//! inside a caller-owned transaction. Split out of `storage/mod.rs` (QUAL-10
//! ceiling).
//!
//! Inside a caller-owned transaction an audit-append failure is returned as an
//! error, but a caller that logs and continues would still COMMIT the edge
//! without its audit row. The guard rolls the edge back to the savepoint on
//! every error exit and is disarmed only by [`LinkSavepoint::release`] or
//! [`LinkSavepoint::abort`], so a link never commits without its audit row.
//!
//! A failed `ROLLBACK TO` is never discarded (ERRORS-19, #7660): it is logged
//! at ERROR and escalated to a `ROLLBACK` of the owner's whole transaction, so
//! a caller that swallows the link error still cannot `COMMIT` the audit-less
//! edge (its `COMMIT` then fails because no transaction is active). The
//! connection is then in autocommit, so a caller that swallows the link error
//! and keeps writing would persist those writes unbatched (#7742): callers
//! inside a transaction must stop and propagate the error.

use anyhow::Result;
use rusqlite::Connection;
use std::cell::Cell;

const SAVEPOINT_NAME: &str = "link_audit_7559";

#[cfg(test)]
thread_local! {
    /// Test seam: make the next `ROLLBACK TO` target a savepoint that does not
    /// exist, so it fails the way a broken connection would (#7660).
    pub(crate) static FAIL_ROLLBACK_TO: Cell<bool> = const { Cell::new(false) };
    /// Test seam: make the audit pre-image encode fail (#7657).
    pub(super) static FAIL_ENCODE: Cell<bool> = const { Cell::new(false) };
}

/// Encode the `memory_link.created` pre-image. This is the single call site of
/// `canonical_cbor` for the audit row, so a test can inject a failure (#7657).
///
/// # Errors
///
/// Returns the encode error (or the injected test fault).
pub(super) fn encode_audit_preimage(
    signable: &crate::identity::sign::SignableLink<'_>,
) -> Result<Vec<u8>> {
    #[cfg(test)]
    if FAIL_ENCODE.with(Cell::get) {
        anyhow::bail!("injected audit pre-image encode fault");
    }
    crate::identity::sign::canonical_cbor(signable)
}

/// Guard over `SAVEPOINT link_audit_7559`; inert in autocommit mode.
pub(super) struct LinkSavepoint<'c> {
    conn: &'c Connection,
    armed: Cell<bool>,
}

impl<'c> LinkSavepoint<'c> {
    /// Open the savepoint when `conn` is inside a transaction.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error when the `SAVEPOINT` statement fails.
    pub(super) fn open(conn: &'c Connection) -> Result<Self> {
        let armed = !conn.is_autocommit();
        if armed {
            conn.execute_batch("SAVEPOINT link_audit_7559")?;
        }
        Ok(Self {
            conn,
            armed: Cell::new(armed),
        })
    }

    /// Keep the work done since [`open`](Self::open) and disarm the guard.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error when the `RELEASE` statement fails; the guard
    /// then rolls back on drop (fail closed).
    pub(super) fn release(self) -> Result<()> {
        if self.armed.get() {
            self.conn
                .execute_batch("RELEASE SAVEPOINT link_audit_7559")?;
            self.armed.set(false);
        }
        Ok(())
    }

    /// Roll the work back and hand `cause` to the caller. A failed
    /// `ROLLBACK TO` rolls back the owner's transaction (so no caller can
    /// `COMMIT` the audit-less edge, #7660) and is added to the returned error.
    pub(super) fn abort(&self, cause: impl Into<anyhow::Error>) -> anyhow::Error {
        let cause = cause.into();
        if !self.armed.replace(false) {
            return cause;
        }
        match self.undo() {
            None => cause,
            Some(e) => cause.context(format!(
                "{SAVEPOINT_NAME} rollback failed, owner transaction rolled back: {e}"
            )),
        }
    }

    /// `ROLLBACK TO` + `RELEASE`. A failed `ROLLBACK TO` is logged at ERROR
    /// (savepoint name and error only, no payload) and escalated to a
    /// `ROLLBACK` of the owner's transaction; returns that first failure.
    fn undo(&self) -> Option<rusqlite::Error> {
        #[cfg(test)]
        let target = if FAIL_ROLLBACK_TO.with(Cell::get) {
            "link_audit_7559_missing"
        } else {
            SAVEPOINT_NAME
        };
        #[cfg(not(test))]
        let target = SAVEPOINT_NAME;
        let failure = self
            .conn
            .execute_batch(&format!("ROLLBACK TO SAVEPOINT {target}"))
            .err();
        if let Some(e) = &failure {
            tracing::error!(
                target: crate::signed_events::SIGNED_EVENTS_TRACE_TARGET,
                savepoint = SAVEPOINT_NAME,
                unwinding = std::thread::panicking(),
                "link audit savepoint ROLLBACK TO failed: {e}"
            );
            if !self.conn.is_autocommit()
                && let Err(e2) = self.conn.execute_batch("ROLLBACK")
            {
                tracing::error!(
                    target: crate::signed_events::SIGNED_EVENTS_TRACE_TARGET,
                    savepoint = SAVEPOINT_NAME,
                    "owner transaction ROLLBACK after a failed savepoint rollback failed: {e2}"
                );
            }
            return failure;
        }
        if let Err(e) = self.conn.execute_batch("RELEASE SAVEPOINT link_audit_7559") {
            tracing::error!(
                target: crate::signed_events::SIGNED_EVENTS_TRACE_TARGET,
                savepoint = SAVEPOINT_NAME,
                "link audit savepoint RELEASE after rollback failed: {e}"
            );
        }
        None
    }
}

impl Drop for LinkSavepoint<'_> {
    /// Last resort for an exit that skipped [`release`](LinkSavepoint::release)
    /// and [`abort`](LinkSavepoint::abort) (a panic). `undo` has already logged
    /// and escalated any failure, so the result is consumed here knowingly.
    fn drop(&mut self) {
        if self.armed.get() {
            drop(self.undo());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FAIL_ENCODE, FAIL_ROLLBACK_TO};
    use crate::models::{Memory, MemoryLinkRelation, Tier, default_metadata};
    use rusqlite::Connection;

    const LINKS: &str = "SELECT COUNT(*) FROM memory_links";
    const AUDITS: &str =
        "SELECT COUNT(*) FROM signed_events WHERE event_type = 'memory_link.created'";

    /// Clears both seams when a cell ends, pass or fail.
    struct Faults;
    impl Drop for Faults {
        fn drop(&mut self) {
            FAIL_ENCODE.with(|f| f.set(false));
            FAIL_ROLLBACK_TO.with(|f| f.set(false));
        }
    }

    fn seed(conn: &Connection, title: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = default_metadata();
        metadata["agent_id"] = serde_json::Value::String("ai:7657".into());
        crate::db::insert(
            conn,
            &Memory {
                id: uuid::Uuid::new_v4().to_string(),
                tier: Tier::Long,
                namespace: "link-savepoint-7657".to_string(),
                title: title.to_string(),
                content: format!("durable text for {title}"),
                created_at: now.clone(),
                updated_at: now,
                metadata,
                ..Memory::default()
            },
        )
        .expect("seed")
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).expect("count")
    }

    fn pair() -> (Connection, String, String) {
        let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
        let a = seed(&conn, "a");
        let b = seed(&conn, "b");
        (conn, a, b)
    }

    #[test]
    fn encode_failure_in_a_transaction_fails_closed_7657() {
        let _faults = Faults;
        let (conn, a, b) = pair();
        FAIL_ENCODE.with(|f| f.set(true));
        conn.execute_batch("BEGIN IMMEDIATE").expect("begin");
        let outcome = crate::db::create_link_signed(
            &conn,
            &a,
            &b,
            MemoryLinkRelation::Supersedes.as_str(),
            None,
        );
        assert!(outcome.is_err(), "encode failure must surface: {outcome:?}");
        conn.execute_batch("COMMIT").expect("commit after swallow");
        assert_eq!(count(&conn, LINKS), 0, "#7657: no link without its audit");
        assert_eq!(count(&conn, AUDITS), 0);
    }

    #[test]
    fn encode_failure_in_autocommit_keeps_the_best_effort_arm_7657() {
        let _faults = Faults;
        let (conn, a, b) = pair();
        FAIL_ENCODE.with(|f| f.set(true));
        crate::db::create_link_signed(&conn, &a, &b, MemoryLinkRelation::Supersedes.as_str(), None)
            .expect("autocommit link is best-effort on the audit encode");
        assert_eq!(count(&conn, LINKS), 1);
        assert_eq!(count(&conn, AUDITS), 0);
    }

    #[test]
    fn failed_rollback_to_never_lets_the_owner_commit_the_link_7660() {
        let _faults = Faults;
        let (conn, a, b) = pair();
        conn.execute_batch(
            "CREATE TRIGGER x7660_audit_fault BEFORE INSERT ON signed_events \
             WHEN NEW.event_type = 'memory_link.created' \
             BEGIN SELECT RAISE(ABORT, 'x7660 injected audit fault'); END;",
        )
        .expect("install fault");
        FAIL_ROLLBACK_TO.with(|f| f.set(true));
        conn.execute_batch("BEGIN IMMEDIATE").expect("begin");
        let outcome = crate::db::create_link_signed(
            &conn,
            &a,
            &b,
            MemoryLinkRelation::Supersedes.as_str(),
            None,
        );
        let err = outcome.expect_err("the link must return Err, not Ok");
        assert!(
            format!("{err:#}").contains("rollback failed"),
            "the rollback failure must reach the caller: {err:#}"
        );
        // The caller swallows the error and COMMITs: it must not succeed.
        assert!(
            conn.execute_batch("COMMIT").is_err(),
            "#7660: COMMIT must fail after a failed ROLLBACK TO"
        );
        assert_eq!(count(&conn, LINKS), 0);
        assert_eq!(count(&conn, AUDITS), 0);
    }
}
