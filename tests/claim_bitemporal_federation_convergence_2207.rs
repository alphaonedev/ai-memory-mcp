// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

//! #2207 (residual of #1834) — claim-bitemporal VALID-time federation
//! convergence.
//!
//! The `valid_until` newer-wins-under-LWW contract was implemented ONLY on
//! the `(title, namespace)` dedup arm (`db::insert_if_newer`), NOT on the
//! load-bearing same-`id` `merge_inbound` CRDT lane (`crdt_merge::merge_memory`
//! resolved `valid_until` LOCAL-wins, and both full-row-overwrite writers
//! omitted the two v79 VALID-time columns). Net: a peer that CLOSED a claim
//! never replicated the close by id → replicas DIVERGED on VALID-time and a
//! `valid_at` recall on a receiver kept returning a closed claim as still
//! asserted (a WRONG-results class under the North Star: degrade-never-diverge).
//!
//! This suite pins, on the sqlite `merge_inbound` lane:
//!   (a) an id-matching inbound whose `valid_until` closes the claim (newer
//!       `updated_at`) is ADOPTED by the receiver, and a subsequent `valid_at`
//!       recall AFTER the close excludes the now-closed claim (replicas
//!       CONVERGE); and
//!   (b) a STALE remote reopen (`valid_until = None`, older `updated_at`) does
//!       NOT clobber a fresher LOCAL close (the close is sticky).
//!
//! The postgres twin behaviour is exercised by the same `crate::models::
//! merge_memory` reconciler (shared by both backends, no per-adapter merge
//! SQL) — the pg full-row writer omission is fixed in lockstep in
//! `src/store/postgres.rs::merge_inbound`.

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::storage;

mod common;
use common::fresh_db_tempfile_conn as fresh_db;

const NS: &str = "bitemporal-fed-2207";
const TERM: &str = "convergence";

// A claim opened with an unbounded window, updated at T0.
const T0_OPEN: &str = "2026-06-16T00:00:00+00:00";
// The peer's close write is stamped NEWER than the local open.
const T1_CLOSE_UPD: &str = "2026-06-16T09:00:00+00:00";
// The claim is asserted to have CLOSED on Jun 10 (valid_until value).
const CLOSE_AT: &str = "2026-06-10T00:00:00+00:00";
// Recall AS-OF Jun 20 — strictly AFTER the close, so the END-EXCLUSIVE
// half-open [valid_from, valid_until) window must EXCLUDE the row.
const RECALL_AFTER_CLOSE: &str = "2026-06-20T00:00:00+00:00";
// Recall AS-OF Jun 05 — strictly BEFORE the close, so the row is still valid.
const RECALL_BEFORE_CLOSE: &str = "2026-06-05T00:00:00+00:00";

fn claim(id: &str, updated_at: &str, valid_until: Option<&str>) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: "claim-alpha".to_string(),
        content: format!("{TERM} claim body"),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: T0_OPEN.to_string(),
        updated_at: updated_at.to_string(),
        memory_kind: MemoryKind::Claim,
        valid_from: None,
        valid_until: valid_until.map(str::to_string),
        version: 1,
        ..Memory::default()
    }
}

fn recall_titles(conn: &rusqlite::Connection, valid_at: Option<&str>) -> Vec<String> {
    let (rows, _) = db::recall(
        conn,
        TERM,
        Some(NS),
        50,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        false,
        None,
        None,
        valid_at,
    )
    .expect("keyword recall");
    let mut t: Vec<String> = rows.into_iter().map(|(m, _)| m.title).collect();
    t.sort();
    t
}

/// (a) A remote-NEWER close on the same-`id` merge lane replicates by id:
/// the receiver's row adopts `valid_until`, and a `valid_at` recall after
/// the close no longer returns the now-closed claim (replicas CONVERGE).
#[test]
fn remote_newer_close_replicates_by_id_and_valid_at_excludes() {
    let (_tmp, conn) = fresh_db();
    // Receiver holds an OPEN claim (valid_until = None), updated at T0.
    let id = storage::insert(&conn, &claim("fed-claim-1", T0_OPEN, None)).expect("seed open claim");

    // Before the close: the open claim is valid at every instant.
    assert_eq!(
        recall_titles(&conn, Some(RECALL_AFTER_CLOSE)),
        vec!["claim-alpha".to_string()],
        "open claim (valid_until=None) is valid at every instant pre-merge"
    );

    // A peer CLOSED the claim: same id, NEWER updated_at, valid_until set.
    let closed = claim(&id, T1_CLOSE_UPD, Some(CLOSE_AT));
    let merged_id = storage::merge_inbound(&conn, &closed).expect("merge inbound close");
    assert_eq!(merged_id, id, "merge_inbound reconciles the existing id");

    // The receiver ADOPTED the close (newer-wins LWW on valid_until).
    let got = db::get(&conn, &id).expect("get").expect("row present");
    assert_eq!(
        got.valid_until.as_deref(),
        Some(CLOSE_AT),
        "receiver adopts the peer's valid_until close (crdt_merge + full-row writer)"
    );

    // CONVERGENCE: a valid_at recall AFTER the close excludes the row.
    assert!(
        recall_titles(&conn, Some(RECALL_AFTER_CLOSE)).is_empty(),
        "post-close valid_at recall must EXCLUDE the now-closed claim (END-EXCLUSIVE)"
    );
    // ... but a recall BEFORE the close still returns it (the claim held then).
    assert_eq!(
        recall_titles(&conn, Some(RECALL_BEFORE_CLOSE)),
        vec!["claim-alpha".to_string()],
        "pre-close valid_at recall still returns the claim (held before close)"
    );
}

/// (c) CONVERGENCE, both orders: two replicas that each hold one side of
/// the same-`id` divergent pair (A = open/older, B = closed/newer) and
/// receive the OTHER side via `merge_inbound` end with IDENTICAL final
/// rows — including `valid_until` (the #2207 field) and `valid_from`.
/// Pre-fix, the merge-B-into-A order kept `valid_until = None` while the
/// merge-A-into-B order kept the close, so the replicas diverged.
#[test]
fn both_merge_orders_converge_to_identical_rows() {
    let mut a_open = claim("fed-claim-3", T0_OPEN, None);
    let mut b_closed = claim("fed-claim-3", T1_CLOSE_UPD, Some(CLOSE_AT));
    // Same genesis: `valid_from` is immutable after store, so both
    // replicas of one id share it (merge_memory keeps it LOCAL-wins).
    let genesis_from = "2026-06-01T00:00:00+00:00";
    a_open.valid_from = Some(genesis_from.to_string());
    b_closed.valid_from = Some(genesis_from.to_string());

    // Node 1 holds A (open), receives B (closed).
    let (_tmp1, conn1) = fresh_db();
    let id1 = storage::insert(&conn1, &a_open).expect("node1 seed A");
    storage::merge_inbound(&conn1, &b_closed).expect("node1 merge B");
    let row1 = db::get(&conn1, &id1).expect("node1 get").expect("node1 row");

    // Node 2 holds B (closed), receives A (open) — the REVERSE order.
    let (_tmp2, conn2) = fresh_db();
    let id2 = storage::insert(&conn2, &b_closed).expect("node2 seed B");
    storage::merge_inbound(&conn2, &a_open).expect("node2 merge A");
    let row2 = db::get(&conn2, &id2).expect("node2 get").expect("node2 row");

    // IDENTICAL final rows (full serialized shape), incl. valid_until.
    assert_eq!(
        row1.valid_until.as_deref(),
        Some(CLOSE_AT),
        "both orders must land the close (newer-wins)"
    );
    // `metadata.version_vector` is node-LOCAL observation state: each
    // insert stamps its own host clock entry, and these hand-built inbound
    // rows carry NO wire clock for the pointwise-max join to equalise —
    // so it is excluded from the replicated-row identity check (a real
    // exchange converges it via `VectorClock::merge`). Everything else,
    // including valid_from/valid_until, must be byte-identical.
    let strip_vv = |row: &Memory| {
        let mut v = serde_json::to_value(row).expect("row serialises");
        if let Some(meta) = v.get_mut("metadata").and_then(serde_json::Value::as_object_mut) {
            meta.remove("version_vector");
        }
        v
    };
    assert_eq!(
        strip_vv(&row1),
        strip_vv(&row2),
        "replicas must CONVERGE to byte-identical rows in BOTH merge orders \
         (incl. valid_from/valid_until — the #2207 CRDT contract)"
    );
}

/// (b) A STALE remote reopen (valid_until = None, OLDER updated_at) must NOT
/// clobber a fresher LOCAL close — the close is sticky (preservation over loss).
#[test]
fn stale_remote_reopen_does_not_clobber_local_close() {
    let (_tmp, conn) = fresh_db();
    // Receiver already CLOSED the claim locally (fresher updated_at).
    let id = storage::insert(&conn, &claim("fed-claim-2", T1_CLOSE_UPD, Some(CLOSE_AT)))
        .expect("seed closed claim");

    // A STALE peer row: same id, OLDER updated_at, still OPEN (valid_until=None).
    let stale_open = claim(&id, T0_OPEN, None);
    storage::merge_inbound(&conn, &stale_open).expect("merge stale open");

    // The local close survives (prefer-non-null / LWW keeps the close).
    let got = db::get(&conn, &id).expect("get").expect("row present");
    assert_eq!(
        got.valid_until.as_deref(),
        Some(CLOSE_AT),
        "a stale open must not reopen a fresher local close"
    );
    assert!(
        recall_titles(&conn, Some(RECALL_AFTER_CLOSE)).is_empty(),
        "the fresher local close still excludes the claim post-close"
    );
}
