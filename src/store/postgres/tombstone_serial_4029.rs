// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4029 (SEC, data-integrity / erasure) — serialize federation
//! ADMISSION of an id against every ERASURE that writes that id's forget
//! tombstone.
//!
//! # The defect this closes
//!
//! The G30 resurrection guard (#1821 / #2314) read `forget_tombstones` on the
//! POOL, outside the transaction that later inserted the inbound row, and the
//! insert carried no tombstone predicate. A forget / hard delete / eviction
//! that committed between the negative check and the insert left BOTH a live
//! row and its tombstone: erased (GDPR-forgotten) content was back. Moving the
//! read into the READ COMMITTED transaction would not help — an uncommitted
//! tombstone is invisible to it — so the two sides need a SHARED lock.
//!
//! # The protocol
//!
//! Transaction-scoped advisory locks in the two-key space
//! `(TOMBSTONE_LOCK_CLASS, stripe)`, `stripe = fnv1a32(id) % STRIPES`:
//!
//! * **admission** (`apply_remote_memory`, `merge_inbound`, the federated
//!   `restores[]` apply): SHARED global lock + SHARED stripe lock, THEN the
//!   tombstone probe, all inside the transaction that writes the row. Two
//!   admissions never block each other.
//! * **erasure** (`pg_tombstone_and_erase_in_tx` for delete /
//!   `apply_remote_deletion`, the `forget` reap, TTL/byte-cap eviction):
//!   SHARED global + EXCLUSIVE stripe locks for its ids (ascending, so two
//!   erasures cannot cycle), or — for a bulk erasure spanning more than
//!   [`BULK_STRIPE_THRESHOLD`] stripes — ONE EXCLUSIVE global lock, keeping
//!   the lock-table footprint of any transaction bounded.
//!
//! An erasure therefore waits for every in-flight admission of its ids to
//! commit (and then deletes / tombstones the admitted row), and an admission
//! that starts after an erasure took its lock waits for the erasure to commit
//! and then SEES the tombstone (READ COMMITTED: a statement issued after the
//! lock is granted reads everything committed before it). The rare genuine
//! same-id race where an erasure locks AFTER its `DELETE` resolves as a
//! PostgreSQL deadlock (`40P01`): one side aborts whole, nothing half-applies,
//! and the erasure funnels retry through `tx_retry`. Fail closed, never a
//! live row beside its tombstone.
//!
//! The stripe function is FIXED (FNV-1a, 32-bit): every daemon sharing one
//! database must derive the same key for the same id.

use std::collections::BTreeSet;

type PgTx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// First key of the two-key advisory lock space ("AMTB" — ai-memory
/// tombstone). The two-key space never overlaps the one-key `hashtext(..)`
/// locks the rest of the adapter takes.
const TOMBSTONE_LOCK_CLASS: i32 = 0x414D_5442;
/// Number of per-id lock stripes.
const STRIPES: u32 = 1024;
/// Second key of the GLOBAL lock (outside the stripe range).
const GLOBAL_KEY: i32 = -1;
/// An erasure touching more distinct stripes than this takes the one
/// EXCLUSIVE global lock instead of per-stripe locks.
pub(crate) const BULK_STRIPE_THRESHOLD: usize = 64;

/// The FIXED stripe of an id (32-bit FNV-1a, mod [`STRIPES`]).
fn stripe(id: &str) -> i32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in id.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    // `STRIPES` fits i32, so the remainder does too.
    i32::try_from(h % STRIPES).unwrap_or(0)
}

async fn lock(tx: &mut PgTx<'_>, key2: i32, shared: bool) -> Result<(), sqlx::Error> {
    let sql = if shared {
        "SELECT pg_advisory_xact_lock_shared($1, $2)"
    } else {
        "SELECT pg_advisory_xact_lock($1, $2)"
    };
    sqlx::query(sql)
        .bind(TOMBSTONE_LOCK_CLASS)
        .bind(key2)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Admission side: take the shared locks for `id`. Call INSIDE the
/// transaction that writes the row, BEFORE the tombstone probe.
///
/// # Errors
/// Propagates the lock query error.
async fn lock_admission(tx: &mut PgTx<'_>, id: &str) -> Result<(), sqlx::Error> {
    lock(tx, GLOBAL_KEY, true).await?;
    lock(tx, stripe(id), true).await
}

/// Erasure side: take the exclusive locks for `ids`. Call INSIDE the erasure
/// transaction, before its tombstone INSERT commits. Empty `ids` is a no-op.
///
/// # Errors
/// Propagates the lock query error.
pub(crate) async fn lock_erasure(tx: &mut PgTx<'_>, ids: &[String]) -> Result<(), sqlx::Error> {
    if ids.is_empty() {
        return Ok(());
    }
    let stripes: BTreeSet<i32> = ids.iter().map(|id| stripe(id)).collect();
    if stripes.len() > BULK_STRIPE_THRESHOLD {
        return lock(tx, GLOBAL_KEY, false).await;
    }
    lock(tx, GLOBAL_KEY, true).await?;
    for s in stripes {
        lock(tx, s, false).await?;
    }
    Ok(())
}

/// The G30 tombstone probe, INSIDE the admission transaction (after
/// [`lock_admission`]).
///
/// # Errors
/// Propagates the probe error — an unresolvable probe is never "not
/// tombstoned".
async fn tombstoned_in_tx(tx: &mut PgTx<'_>, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(super::federation_3075::SQL_FORGET_TOMBSTONE_EXISTS)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
}

/// The whole admission step: [`lock_admission`], the in-transaction G30
/// probe, the audit line for a drop, and the `test-support` pause point.
/// Returns `true` when `id` is TOMBSTONED — the caller must drop the inbound
/// write (tombstone-wins) and return its no-op.
///
/// # Errors
/// Propagates the lock / probe error (never read as "not tombstoned").
pub(crate) async fn admit_or_tombstoned(tx: &mut PgTx<'_>, id: &str) -> Result<bool, sqlx::Error> {
    lock_admission(tx, id).await?;
    if tombstoned_in_tx(tx, id).await? {
        tracing::info!(
            target: crate::storage::FORGET_TOMBSTONE_TRACE_TARGET,
            memory_id = %id,
            "{}",
            crate::storage::FORGET_TOMBSTONE_DROP_MSG
        );
        return Ok(true);
    }
    crate::storage::admission_hook::checkpoint(id);
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripe_is_fixed_and_in_range() {
        // Pinned: every daemon sharing one database must agree.
        assert_eq!(
            stripe(""),
            i32::try_from(0x811c_9dc5_u32 % STRIPES).unwrap()
        );
        for id in ["a", "mem-1", "0f8fad5b-d9cb-469f-a165-70867728950e"] {
            let s = stripe(id);
            assert!((0..1024).contains(&s));
            assert_eq!(s, stripe(id));
        }
    }
}
