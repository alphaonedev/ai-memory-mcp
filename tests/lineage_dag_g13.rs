// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

//! v0.9.0 G13-mem (#1859) — the memory-derivation lineage-DAG regression
//! suite (SQLite side; the postgres twin is `tests/cov_postgres_lineage.rs`).
//!
//! The lineage-DAG is a VIEW over `memory_links` restricted to the
//! provenance set P = {`derived_from`, `reflects_on`, `derives_from`}. The
//! real behavioral change is that `db::consolidate` — with the
//! `consolidate_tombstone_sources` sub-flag on — TOMBSTONES its sources
//! (retains id + cid, writes navigable `derived_from` edges, emits exactly
//! one CONSOLIDATE leaf per source) instead of hard-deleting them, so
//! multi-hop store -> reflect -> consolidate ancestry stays navigable.
//!
//! These tests pin:
//!  * `multi_hop_ancestry_store_reflect_consolidate` — `lineage_ancestors(C)`
//!    == {R, A, B}; R is Tombstoned yet still resident in `memories`;
//!    EXACTLY ONE CONSOLIDATE leaf per source (NOT >= 1, COND 1); every
//!    hop's `created_at` strictly decreases along a path.
//!  * `consolidate_emits_exactly_one_leaf_per_source` — two sources → two
//!    CONSOLIDATE leaves (COND 1, the per-source cardinality).
//!  * `consolidate_leaf_predicate_matrix` — the COND-1 single-emission-site
//!    predicate: append-only ON + tombstone OFF still emits exactly one
//!    leaf per source (sqlite now matches the pre-#1859 postgres posture);
//!    both flags ON never double-emits.
//!  * `lineage_is_acyclic_guard` — a forward `derived_from` is rejected
//!    with the `LINK_CYCLE_ERR_PREFIX` envelope (COND 4 strict `>`
//!    DateTime compare); closing a 3-node cycle is refused; a
//!    same-timestamp same-batch pair is NOT false-rejected.
//!  * `traversal_terminates_on_corrupt_cycle` — a directly-injected cyclic
//!    edge pair does not hang the recursive-CTE walk.
//!  * `cid_fallback_on_legacy_edge` — an edge with NULL `*_cid` mirrors
//!    resolves node cid via the `memories.cid` LEFT JOIN.
//!  * `descendants_are_reverse_of_ancestors`.
//!  * `consolidate_flag_off_preserves_legacy` — flags OFF hard-delete and
//!    emit no CONSOLIDATE leaf (byte-identical legacy).
//!
//! ## Concurrency
//!
//! The lineage flags are process-wide `AtomicBool`s, so the tests
//! serialize on a file-local `Mutex` and set the flags they need at the
//! top of each test under the guard.

use std::path::Path;
use std::sync::Mutex;

use ai_memory::db;
use ai_memory::models::{Memory, Tier};

/// Serializes the tests so one test's flag writes cannot race another's
/// expectation (the lineage flags are process-wide atomics).
static FLAG_LOCK: Mutex<()> = Mutex::new(());

fn flag_guard() -> std::sync::MutexGuard<'static, ()> {
    FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lineage_on() {
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
}

fn lineage_off() {
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
    ai_memory::config::set_append_only(false);
}

fn open_mem_db() -> rusqlite::Connection {
    db::open(Path::new(":memory:")).expect("open in-memory db")
}

/// A memory with an EXPLICIT `created_at` so the strictly-decreasing +
/// acyclicity assertions are deterministic (not dependent on wall-clock
/// ordering of the inserts).
fn make_mem(id: &str, title: &str, content: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        namespace: "lineage-g13".to_string(),
        tier: Tier::Mid,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        ..Default::default()
    }
}

fn created_at_of(conn: &rusqlite::Connection, id: &str) -> String {
    conn.query_row("SELECT created_at FROM memories WHERE id = ?1", [id], |r| {
        r.get::<_, String>(0)
    })
    .expect("created_at")
}

fn lifecycle_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT lifecycle_state FROM memories WHERE id = ?1",
        [id],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

fn consolidate_leaf_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memory_revisions WHERE kind = 'CONSOLIDATE'",
        [],
        |r| r.get(0),
    )
    .expect("count CONSOLIDATE leaves")
}

// ---------------------------------------------------------------------------
// 1. Multi-hop ancestry: store A,B -> reflect R -> consolidate C.
// ---------------------------------------------------------------------------

#[test]
fn multi_hop_ancestry_store_reflect_consolidate() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let a = "00000000-0000-0000-0000-0000000000a1";
    let b = "00000000-0000-0000-0000-0000000000b2";
    let r = "00000000-0000-0000-0000-0000000000c3";
    db::insert(
        &conn,
        &make_mem(a, "A", "base a", "2026-01-01T00:00:00+00:00"),
    )
    .unwrap();
    db::insert(
        &conn,
        &make_mem(b, "B", "base b", "2026-01-02T00:00:00+00:00"),
    )
    .unwrap();
    db::insert(
        &conn,
        &make_mem(r, "R", "reflection", "2026-03-01T00:00:00+00:00"),
    )
    .unwrap();

    // R reflects_on A and B (child R newer -> parent older; guard allows),
    // each edge carrying the endpoints' cid mirror.
    db::create_link(&conn, r, a, "reflects_on").unwrap();
    db::create_link(&conn, r, b, "reflects_on").unwrap();
    let (edge_source_cid, edge_target_cid): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT source_cid, target_cid FROM memory_links \
             WHERE source_id = ?1 AND target_id = ?2",
            [r, a],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let a_cid: Option<String> = conn
        .query_row("SELECT cid FROM memories WHERE id = ?1", [a], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(
        edge_source_cid.is_some(),
        "lineage-on edge must carry the source cid mirror"
    );
    assert_eq!(
        edge_target_cid, a_cid,
        "edge target_cid mirrors memories.cid at link-creation time"
    );

    // Consolidate [R] into C — C tombstones R and writes C --derived_from--> R.
    let c = db::consolidate(
        &conn,
        &[r.to_string()],
        "C",
        "consolidated",
        "lineage-g13",
        &Tier::Long,
        "consolidation",
        "ai:consolidator",
        false,
    )
    .unwrap();

    // R is Tombstoned yet STILL resident in memories (conserved lineage).
    assert_eq!(
        lifecycle_of(&conn, r).as_deref(),
        Some("tombstoned"),
        "consolidated source R must be tombstoned, not deleted"
    );
    assert!(
        db::get(&conn, r).unwrap().is_none(),
        "#2402: tombstoned R is hidden from the ordinary get lane \
         (not recall-visible); residency is the lifecycle_of pin above, \
         and lineage_ancestors walks links unfiltered"
    );

    // lineage_ancestors(C) == {R, A, B} — multi-hop across the
    // consolidation boundary.
    let ancestors = db::lineage_ancestors(&conn, &c, 5).unwrap();
    let mut ids: Vec<String> = ancestors.iter().map(|n| n.id.clone()).collect();
    ids.sort();
    let mut want = vec![a.to_string(), b.to_string(), r.to_string()];
    want.sort();
    assert_eq!(ids, want, "ancestors of C must be exactly {{R, A, B}}");

    // Every returned node resolves a cid (all three rows are post-v74).
    for n in &ancestors {
        assert!(n.cid.is_some(), "node {} must resolve a cid", n.id);
    }

    // EXACTLY ONE CONSOLIDATE leaf for the single source (NOT >= 1, COND 1).
    assert_eq!(
        consolidate_leaf_count(&conn),
        1,
        "exactly one CONSOLIDATE leaf per source"
    );

    // Every hop's created_at strictly decreases along C -> R -> A
    // (acyclicity on the realized path).
    let c_at = created_at_of(&conn, &c);
    let r_at = created_at_of(&conn, r);
    let a_at = created_at_of(&conn, a);
    assert!(c_at > r_at, "C newer than R");
    assert!(r_at > a_at, "R newer than A");

    // The direct hop to R carries depth 1; A and B are depth 2.
    let r_node = ancestors.iter().find(|n| n.id == r).unwrap();
    assert_eq!(r_node.depth, 1, "R is a direct (depth-1) ancestor of C");
    assert_eq!(r_node.relation, "derived_from");
    let a_node = ancestors.iter().find(|n| n.id == a).unwrap();
    assert_eq!(a_node.depth, 2, "A is a depth-2 ancestor of C");
    assert_eq!(a_node.relation, "reflects_on");
}

// ---------------------------------------------------------------------------
// 2. COND 1 — exactly one CONSOLIDATE leaf PER source.
// ---------------------------------------------------------------------------

#[test]
fn consolidate_emits_exactly_one_leaf_per_source() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let x = "00000000-0000-0000-0000-0000000000d4";
    let y = "00000000-0000-0000-0000-0000000000e5";
    db::insert(&conn, &make_mem(x, "X", "x", "2026-02-01T00:00:00+00:00")).unwrap();
    db::insert(&conn, &make_mem(y, "Y", "y", "2026-02-02T00:00:00+00:00")).unwrap();

    let c = db::consolidate(
        &conn,
        &[x.to_string(), y.to_string()],
        "XY",
        "merged",
        "lineage-g13",
        &Tier::Long,
        "consolidation",
        "ai:consolidator",
        false,
    )
    .unwrap();

    assert_eq!(
        consolidate_leaf_count(&conn),
        2,
        "two sources must yield exactly two CONSOLIDATE leaves (one each)"
    );
    // Both sources are tombstoned and remain navigable from C.
    let anc = db::lineage_ancestors(&conn, &c, 5).unwrap();
    assert_eq!(anc.len(), 2, "C has two direct lineage ancestors");
    assert_eq!(lifecycle_of(&conn, x).as_deref(), Some("tombstoned"));
    assert_eq!(lifecycle_of(&conn, y).as_deref(), Some("tombstoned"));
}

// ---------------------------------------------------------------------------
// 3. COND 1 — the single-emission-site predicate matrix.
// ---------------------------------------------------------------------------

#[test]
fn consolidate_leaf_predicate_matrix() {
    let _g = flag_guard();

    // (a) append-only ON + tombstone OFF: legacy hard-delete disposition,
    //     yet EXACTLY ONE leaf per source (capture-then-compact — the
    //     posture postgres shipped pre-#1859, now shared by sqlite).
    lineage_off();
    ai_memory::config::set_append_only(true);
    let conn = open_mem_db();
    let x = "00000000-0000-0000-0000-000000000801";
    db::insert(&conn, &make_mem(x, "AX", "x", "2026-02-01T00:00:00+00:00")).unwrap();
    db::consolidate(
        &conn,
        &[x.to_string()],
        "AXC",
        "merged",
        "lineage-g13",
        &Tier::Long,
        "consolidation",
        "ai:consolidator",
        false,
    )
    .unwrap();
    assert!(
        db::get(&conn, x).unwrap().is_none(),
        "tombstone OFF keeps the legacy hard-delete"
    );
    assert_eq!(
        consolidate_leaf_count(&conn),
        1,
        "append-only alone emits exactly one leaf per source"
    );

    // (b) BOTH flags ON: still exactly one leaf per source (no double
    //     emission from the two spines).
    lineage_on();
    ai_memory::config::set_append_only(true);
    let conn = open_mem_db();
    let y = "00000000-0000-0000-0000-000000000802";
    db::insert(&conn, &make_mem(y, "BY", "y", "2026-02-01T00:00:00+00:00")).unwrap();
    db::consolidate(
        &conn,
        &[y.to_string()],
        "BYC",
        "merged",
        "lineage-g13",
        &Tier::Long,
        "consolidation",
        "ai:consolidator",
        false,
    )
    .unwrap();
    assert_eq!(
        consolidate_leaf_count(&conn),
        1,
        "append-only + tombstone together must NOT double-emit"
    );
    ai_memory::config::set_append_only(false);
}

// ---------------------------------------------------------------------------
// 4. COND 4 — the acyclicity guard.
// ---------------------------------------------------------------------------

#[test]
fn lineage_is_acyclic_guard() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let old = "00000000-0000-0000-0000-0000000000f6";
    let new = "00000000-0000-0000-0000-000000000107";
    db::insert(
        &conn,
        &make_mem(old, "old", "o", "2026-01-01T00:00:00+00:00"),
    )
    .unwrap();
    db::insert(
        &conn,
        &make_mem(new, "new", "n", "2026-05-01T00:00:00+00:00"),
    )
    .unwrap();

    // Forward (older -> newer) derived_from must be rejected.
    let err = db::create_link(&conn, old, new, "derived_from")
        .expect_err("forward lineage edge must be refused");
    assert!(
        err.to_string().starts_with(db::LINK_CYCLE_ERR_PREFIX),
        "expected {} prefix, got: {err}",
        db::LINK_CYCLE_ERR_PREFIX
    );

    // Proper child -> parent (newer -> older) is allowed.
    db::create_link(&conn, new, old, "derived_from").expect("backward lineage edge is allowed");

    // Closing a 3-node cycle is refused: t3->t2, t2->t1 ok; t1->t3 forward.
    let t1 = "00000000-0000-0000-0000-000000000201";
    let t2 = "00000000-0000-0000-0000-000000000202";
    let t3 = "00000000-0000-0000-0000-000000000203";
    db::insert(&conn, &make_mem(t1, "t1", "1", "2026-01-01T00:00:00+00:00")).unwrap();
    db::insert(&conn, &make_mem(t2, "t2", "2", "2026-01-02T00:00:00+00:00")).unwrap();
    db::insert(&conn, &make_mem(t3, "t3", "3", "2026-01-03T00:00:00+00:00")).unwrap();
    db::create_link(&conn, t3, t2, "derives_from").unwrap();
    db::create_link(&conn, t2, t1, "derives_from").unwrap();
    let cycle_err = db::create_link(&conn, t1, t3, "derives_from")
        .expect_err("closing a lineage cycle must be refused");
    assert!(cycle_err.to_string().starts_with(db::LINK_CYCLE_ERR_PREFIX));

    // Same-timestamp same-batch pair must NOT be false-rejected (COND 4:
    // strict chrono `>`, never a string `>=`).
    let p = "00000000-0000-0000-0000-000000000301";
    let q = "00000000-0000-0000-0000-000000000302";
    let same = "2026-04-04T04:04:04+00:00";
    db::insert(&conn, &make_mem(p, "p", "p", same)).unwrap();
    db::insert(&conn, &make_mem(q, "q", "q", same)).unwrap();
    db::create_link(&conn, q, p, "derived_from")
        .expect("equal-timestamp lineage edge must NOT be false-rejected");

    // Guard OFF (legacy) — the same forward edge is admitted (guard is
    // flag-gated; byte-identical legacy behavior).
    lineage_off();
    db::create_link(&conn, old, new, "derived_from")
        .expect("guard is flag-gated: lineage OFF admits the forward edge");
}

// ---------------------------------------------------------------------------
// 4b. #3041 — EQUAL-`created_at` 2-cycle is refused, while a legitimate
//     same-instant DAG (fan-out / chain, no back-edge) is still admitted.
//
//     The strict-`>` wall-clock guard (COND 4) orders only DISTINCT instants;
//     an exact tie made BOTH `q -> p` and `p -> q` admissible, so an
//     equal-instant pair could close a 2-cycle. The fix keeps the first
//     same-instant edge legal (that is a valid same-batch DAG edge) but
//     refuses the reverse edge once it would close a cycle, via a bounded
//     structural ancestor check confined to the equal-instant clique.
// ---------------------------------------------------------------------------

#[test]
fn equal_instant_two_cycle_is_refused() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let same = "2026-06-06T06:06:06+00:00";
    let id_p = "00000000-0000-0000-0000-0000000003a1";
    let id_q = "00000000-0000-0000-0000-0000000003a2";
    db::insert(&conn, &make_mem(id_p, "p", "p", same)).unwrap();
    db::insert(&conn, &make_mem(id_q, "q", "q", same)).unwrap();

    // First equal-instant edge is a legitimate same-batch DAG edge (child q
    // -> parent p); it must NOT be false-rejected.
    db::create_link(&conn, id_q, id_p, "derived_from")
        .expect("first equal-instant lineage edge must be admitted");

    // The REVERSE edge would close a 2-cycle p -> q -> p. Before #3041 the
    // strict `>` admitted it (equal instants => not "forward"); it must now
    // be refused with the cycle envelope.
    let cycle_err = db::create_link(&conn, id_p, id_q, "derived_from")
        .expect_err("equal-instant reverse edge closes a 2-cycle and must be refused");
    assert!(
        cycle_err.to_string().starts_with(db::LINK_CYCLE_ERR_PREFIX),
        "expected {} prefix, got: {cycle_err}",
        db::LINK_CYCLE_ERR_PREFIX
    );

    // The refusal must be structural, not a write: exactly ONE lineage edge
    // between the pair survives (the durable graph is not corrupted).
    let edges: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memory_links \
             WHERE relation = 'derived_from' \
               AND ((source_id = ?1 AND target_id = ?2) \
                 OR (source_id = ?2 AND target_id = ?1))",
            [id_p, id_q],
            |r| r.get(0),
        )
        .expect("count pair edges");
    assert_eq!(edges, 1, "only the first (q -> p) edge may persist");

    // Legitimate same-instant DAG construction is preserved: a fan-out from
    // one child to two parents (all sharing the instant) forms no cycle and
    // must be admitted, and a non-cycle-closing chain edge likewise.
    let id_a = "00000000-0000-0000-0000-0000000003b1";
    let id_b = "00000000-0000-0000-0000-0000000003b2";
    let id_c = "00000000-0000-0000-0000-0000000003b3";
    db::insert(&conn, &make_mem(id_a, "a", "a", same)).unwrap();
    db::insert(&conn, &make_mem(id_b, "b", "b", same)).unwrap();
    db::insert(&conn, &make_mem(id_c, "c", "c", same)).unwrap();
    db::create_link(&conn, id_a, id_b, "derived_from")
        .expect("same-instant fan-out edge a -> b is a valid DAG edge");
    db::create_link(&conn, id_a, id_c, "derived_from")
        .expect("same-instant fan-out edge a -> c is a valid DAG edge");
    db::create_link(&conn, id_b, id_c, "derived_from")
        .expect("same-instant chain edge b -> c is a valid DAG edge (no back-edge)");
    // But closing the a -> b -> c -> a triangle is refused.
    let tri_err = db::create_link(&conn, id_c, id_a, "derived_from")
        .expect_err("closing the same-instant a -> b -> c -> a cycle must be refused");
    assert!(tri_err.to_string().starts_with(db::LINK_CYCLE_ERR_PREFIX));
}

// ---------------------------------------------------------------------------
// 5. Traversal terminates on a corrupt (directly-injected) cycle.
// ---------------------------------------------------------------------------

#[test]
fn traversal_terminates_on_corrupt_cycle() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let a = "00000000-0000-0000-0000-000000000401";
    let b = "00000000-0000-0000-0000-000000000402";
    db::insert(&conn, &make_mem(a, "a", "a", "2026-01-01T00:00:00+00:00")).unwrap();
    db::insert(&conn, &make_mem(b, "b", "b", "2026-01-02T00:00:00+00:00")).unwrap();

    // Inject a cyclic lineage edge pair directly, bypassing the write guard.
    conn.execute(
        "INSERT INTO memory_links (source_id, target_id, relation, created_at) \
         VALUES (?1, ?2, 'derived_from', ?3), (?2, ?1, 'derived_from', ?3)",
        rusqlite::params![a, b, "2026-06-01T00:00:00+00:00"],
    )
    .unwrap();

    // The json_each visited-set guard must bound the walk (no hang / no
    // unbounded rows).
    let anc = db::lineage_ancestors(&conn, a, 5).expect("walk terminates");
    assert!(
        anc.len() <= 8,
        "cycle-guarded walk must be bounded, got {} rows",
        anc.len()
    );
}

// ---------------------------------------------------------------------------
// 6. cid fallback on a legacy (NULL *_cid) edge.
// ---------------------------------------------------------------------------

#[test]
fn cid_fallback_on_legacy_edge() {
    let _g = flag_guard();
    let conn = open_mem_db();

    let a = "00000000-0000-0000-0000-000000000501";
    let r = "00000000-0000-0000-0000-000000000502";
    db::insert(&conn, &make_mem(a, "a", "a", "2026-01-01T00:00:00+00:00")).unwrap();
    db::insert(&conn, &make_mem(r, "r", "r", "2026-03-01T00:00:00+00:00")).unwrap();

    // Create the edge with lineage OFF so the *_cid mirror columns are NULL
    // (the legacy shape), then query with lineage ON.
    lineage_off();
    db::create_link(&conn, r, a, "reflects_on").unwrap();

    // Confirm the stored edge cids are NULL.
    let (sc, tc): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT source_cid, target_cid FROM memory_links WHERE source_id = ?1",
            [r],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(
        sc.is_none() && tc.is_none(),
        "legacy edge carries NULL cids"
    );

    lineage_on();
    let anc = db::lineage_ancestors(&conn, r, 5).unwrap();
    let a_node = anc.iter().find(|n| n.id == a).unwrap();
    let a_cid: Option<String> = conn
        .query_row("SELECT cid FROM memories WHERE id = ?1", [a], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(a_cid.is_some(), "A carries a genesis cid");
    assert_eq!(
        a_node.cid, a_cid,
        "node cid must fall back to memories.cid when the edge mirror is NULL"
    );
}

// ---------------------------------------------------------------------------
// 7. Descendants are the reverse of ancestors.
// ---------------------------------------------------------------------------

#[test]
fn descendants_are_reverse_of_ancestors() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let a = "00000000-0000-0000-0000-000000000601";
    let r = "00000000-0000-0000-0000-000000000602";
    db::insert(&conn, &make_mem(a, "a", "a", "2026-01-01T00:00:00+00:00")).unwrap();
    db::insert(&conn, &make_mem(r, "r", "r", "2026-03-01T00:00:00+00:00")).unwrap();
    db::create_link(&conn, r, a, "reflects_on").unwrap();

    // A is an ancestor of R; therefore R is a descendant of A.
    let anc_of_r = db::lineage_ancestors(&conn, r, 5).unwrap();
    assert!(anc_of_r.iter().any(|n| n.id == a));
    let desc_of_a = db::lineage_descendants(&conn, a, 5).unwrap();
    assert!(
        desc_of_a.iter().any(|n| n.id == r),
        "R must be a descendant of A (reverse of the ancestor edge)"
    );
}

// ---------------------------------------------------------------------------
// 8. Flags OFF preserve the legacy hard-delete path.
// ---------------------------------------------------------------------------

#[test]
fn consolidate_flag_off_preserves_legacy() {
    let _g = flag_guard();
    lineage_off();
    let conn = open_mem_db();

    let x = "00000000-0000-0000-0000-000000000701";
    let y = "00000000-0000-0000-0000-000000000702";
    db::insert(&conn, &make_mem(x, "X", "x", "2026-02-01T00:00:00+00:00")).unwrap();
    db::insert(&conn, &make_mem(y, "Y", "y", "2026-02-02T00:00:00+00:00")).unwrap();

    db::consolidate(
        &conn,
        &[x.to_string(), y.to_string()],
        "XY",
        "merged",
        "lineage-g13",
        &Tier::Long,
        "consolidation",
        "ai:consolidator",
        false,
    )
    .unwrap();

    // Legacy behavior: sources hard-deleted, no CONSOLIDATE leaf.
    assert!(
        db::get(&conn, x).unwrap().is_none(),
        "flag OFF hard-deletes X"
    );
    assert!(
        db::get(&conn, y).unwrap().is_none(),
        "flag OFF hard-deletes Y"
    );
    assert_eq!(
        consolidate_leaf_count(&conn),
        0,
        "flag OFF emits no CONSOLIDATE leaf (byte-identical legacy)"
    );
}

// ---------------------------------------------------------------------------
// 9. Depth-budget validation.
// ---------------------------------------------------------------------------

#[test]
fn lineage_depth_budget_is_enforced() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();
    let a = "00000000-0000-0000-0000-000000000901";
    db::insert(&conn, &make_mem(a, "a", "a", "2026-01-01T00:00:00+00:00")).unwrap();

    let err = db::lineage_ancestors(&conn, a, 0).expect_err("depth 0 refused");
    assert!(err.to_string().contains("max_depth"), "got: {err}");
    let err = db::lineage_ancestors(&conn, a, db::LINEAGE_MAX_DEPTH + 1)
        .expect_err("depth over budget refused");
    assert!(err.to_string().contains("max_depth"), "got: {err}");
}
