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
//! every early exit (any `?`, any error return) and is disarmed only by
//! [`LinkSavepoint::release`], so a link never commits without its audit row.

use anyhow::Result;
use rusqlite::Connection;

/// Guard over `SAVEPOINT link_audit_7559`; inert in autocommit mode.
pub(super) struct LinkSavepoint<'c> {
    conn: &'c Connection,
    armed: bool,
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
        Ok(Self { conn, armed })
    }

    /// Keep the work done since [`open`](Self::open) and disarm the guard.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error when the `RELEASE` statement fails; the guard
    /// then rolls back on drop (fail closed).
    pub(super) fn release(mut self) -> Result<()> {
        if self.armed {
            self.conn
                .execute_batch("RELEASE SAVEPOINT link_audit_7559")?;
            self.armed = false;
        }
        Ok(())
    }
}

impl Drop for LinkSavepoint<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Best effort: the owner's transaction is already unwinding on this
            // path, and a failed rollback leaves the owner's own ROLLBACK to
            // discard the work.
            let _ = self.conn.execute_batch(
                "ROLLBACK TO SAVEPOINT link_audit_7559; RELEASE SAVEPOINT link_audit_7559",
            );
        }
    }
}
