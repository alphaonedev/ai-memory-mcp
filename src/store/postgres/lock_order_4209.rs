// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4209 / #4210 — ONE canonical lock order for `memories` rows.
//!
//! # The defect this closes
//!
//! Since #4010 the containment writers (swarm rewind, contamination
//! auto-stamp) lock every `memories` row they touch in ascending
//! `id COLLATE "C"` order before writing (CONCURRENCY-04). Two other
//! transactions locked several rows in a different order:
//!
//! * bulk re-own (#4209) ran one `UPDATE … WHERE <namespace/owner>` with no
//!   prior lock, so its row locks followed the execution plan (heap order);
//! * link (#4210) locked the SOURCE row `FOR UPDATE` for the owner gate,
//!   then its `memory_links` INSERT took the foreign-key `FOR KEY SHARE`
//!   lock on the TARGET: source-then-target, whatever the ids. The
//!   federation replay (`apply_remote_link`) took the same two key-share
//!   locks in foreign-key order; consolidate rewrote its sources in caller
//!   order; reflect and archive-restore key-shared several link endpoints in
//!   caller / plan order.
//!
//! Either one, interleaved with an ascending-order writer on an overlapping
//! pair, closes a wait-for cycle and Postgres aborts one side with 40P01 —
//! in the observed runs the containment write, so the rewind or stamp is not
//! applied on that attempt.
//!
//! # The rule
//!
//! Every transaction that locks more than one `memories` row takes those
//! locks up front, in ascending bytewise id order (`COLLATE "C"` on the SQL
//! side, `str::cmp` on the Rust side — the same order auto-stamp uses), and
//! only then reads or writes them. Later statements re-lock rows the
//! transaction already holds, which never waits.

use sqlx::PgConnection;

/// The row-lock strength a caller needs on one `memories` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RowLock {
    /// `FOR KEY SHARE`: what a `memory_links` foreign key takes on each
    /// endpoint. Compatible with other key-share holders (many links to one
    /// hot row do not serialise), conflicts with `FOR UPDATE`.
    KeyShare,
    /// `FOR SHARE` (#4447): blocks an UPDATE of ANY column (unlike key-share,
    /// which lets a non-key column such as `namespace` change underneath the
    /// holder) while staying compatible with other `FOR SHARE` / `FOR KEY SHARE`
    /// holders. The authorized federation link replay takes this as its ONE lock
    /// per endpoint, so it can re-read the namespace under a lock that holds a
    /// relocation off without ever upgrading a key-share lock (which would
    /// deadlock two replays sharing an endpoint, 40P01).
    Share,
    /// `FOR UPDATE`: the row is gated, rewritten or deleted.
    Update,
}

/// Lock `rows` on `conn` in ascending bytewise id order.
///
/// Duplicate ids collapse to their strongest requested lock. Rows that do
/// not exist are skipped (a later existence check owns that error). Runs
/// one statement per row so each lock is acquired strictly after the
/// previous one; callers lock small bounded sets (a link's two endpoints, a
/// consolidate's source list). A large predicate-selected set (bulk re-own)
/// uses one `ORDER BY id COLLATE "C" FOR UPDATE` statement instead.
///
/// # Errors
///
/// Any query error, including a 40P01 / 55P03 from Postgres.
pub(super) async fn lock_memories_in_id_order(
    conn: &mut PgConnection,
    rows: &[(&str, RowLock)],
) -> Result<(), sqlx::Error> {
    for (id, lock) in canonical_lock_plan(rows) {
        let sql = match lock {
            RowLock::KeyShare => "SELECT 1 FROM memories WHERE id = $1 FOR KEY SHARE",
            RowLock::Share => "SELECT 1 FROM memories WHERE id = $1 FOR SHARE",
            RowLock::Update => "SELECT 1 FROM memories WHERE id = $1 FOR UPDATE",
        };
        sqlx::query(sql).bind(id).fetch_optional(&mut *conn).await?;
    }
    Ok(())
}

/// The acquisition plan: ascending bytewise id, one entry per id, strongest
/// lock wins. Pure, so the ordering rule is unit-tested without a database.
pub(super) fn canonical_lock_plan<'a>(rows: &[(&'a str, RowLock)]) -> Vec<(&'a str, RowLock)> {
    let mut plan: Vec<(&str, RowLock)> = rows.to_vec();
    // Ascending id; for equal ids the STRONGEST lock first so dedup keeps it.
    plan.sort_by(|(a, la), (b, lb)| a.as_bytes().cmp(b.as_bytes()).then(lb.cmp(la)));
    plan.dedup_by(|next, kept| next.0 == kept.0);
    plan
}

/// `archive_restore`'s link re-insert: key-share every OTHER endpoint of the
/// restored memory's archived edges, ascending by id, before the INSERT's
/// foreign keys take them in plan order. `$1` = the restored memory id.
pub(super) const SQL_KEY_SHARE_ARCHIVED_LINK_PEERS: &str = "SELECT m.id FROM memories m \
     WHERE m.id IN (SELECT source_id FROM archived_memory_links WHERE target_id = $1 \
                    UNION SELECT target_id FROM archived_memory_links WHERE source_id = $1) \
     ORDER BY m.id COLLATE \"C\" FOR KEY SHARE";

/// The ids a link locks: the source (owner gate: `FOR UPDATE`) and the target
/// (the foreign key's `FOR KEY SHARE`). A self-link is one `FOR UPDATE`.
pub(super) fn link_endpoint_locks<'a>(source: &'a str, target: &'a str) -> [(&'a str, RowLock); 2] {
    [(source, RowLock::Update), (target, RowLock::KeyShare)]
}

/// The ids a federation link replay locks: both endpoints `FOR KEY SHARE`
/// (it runs no owner gate; the foreign keys are its only row locks).
pub(super) fn replay_endpoint_locks<'a>(
    source: &'a str,
    target: &'a str,
) -> [(&'a str, RowLock); 2] {
    [(source, RowLock::KeyShare), (target, RowLock::KeyShare)]
}

/// #4447 — the ids an AUTHORIZED federation link replay locks: both endpoints
/// `FOR SHARE`, ONE lock each (never key-share then something stronger).
pub(super) fn replay_endpoint_share_locks<'a>(
    source: &'a str,
    target: &'a str,
) -> [(&'a str, RowLock); 2] {
    [(source, RowLock::Share), (target, RowLock::Share)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_ascending_bytewise_not_argument_order_4210() {
        let plan = canonical_lock_plan(&link_endpoint_locks("z-root", "a-child"));
        assert_eq!(
            plan,
            vec![("a-child", RowLock::KeyShare), ("z-root", RowLock::Update)]
        );
    }

    #[test]
    fn plan_uses_bytewise_order_like_collate_c_4210() {
        // Uppercase sorts before lowercase bytewise, unlike most locales.
        let plan = canonical_lock_plan(&replay_endpoint_locks("a", "B"));
        assert_eq!(plan[0].0, "B");
    }

    #[test]
    fn a_duplicate_id_keeps_its_strongest_lock_4210() {
        let plan = canonical_lock_plan(&link_endpoint_locks("same", "same"));
        assert_eq!(plan, vec![("same", RowLock::Update)]);
        let plan = canonical_lock_plan(&[("x", RowLock::KeyShare), ("x", RowLock::Update)]);
        assert_eq!(plan, vec![("x", RowLock::Update)]);
    }

    #[test]
    fn authorized_replay_takes_one_share_lock_per_endpoint_ascending_4447() {
        let plan = canonical_lock_plan(&replay_endpoint_share_locks("z", "a"));
        assert_eq!(plan, vec![("a", RowLock::Share), ("z", RowLock::Share)]);
        // Share sits between key-share and update, so a duplicate keeps the
        // strongest of the locks asked for.
        let plan = canonical_lock_plan(&[("x", RowLock::KeyShare), ("x", RowLock::Share)]);
        assert_eq!(plan, vec![("x", RowLock::Share)]);
        let plan = canonical_lock_plan(&[("x", RowLock::Share), ("x", RowLock::Update)]);
        assert_eq!(plan, vec![("x", RowLock::Update)]);
    }
}
