// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

//! v1.0.0 Gate-2 — trust-tier min-propagation (#1958 / R20) + transitive
//! suspect invalidation (#1959 / R55) over the v75 memory-derivation
//! lineage-DAG (SQLite side).
//!
//! ## What is pinned
//!
//! #1958 (R20) — a derived record's effective trust tier is bounded by the
//! MINIMUM trust tier over its recorded provenance chain (P =
//! {`derived_from`, `reflects_on`, `derives_from`}). You cannot launder a
//! low-trust source into a high-trust `confidence = 1.0` consolidated
//! summary:
//!  * `consolidate_stamps_min_propagated_trust` — a high-trust +
//!    unattested source pair → `metadata.propagated_trust = "unattested"`.
//!  * `consolidate_sibling_merge_takes_the_min` — attested + claimed
//!    siblings → `"claimed"`.
//!  * `propagated_trust_tier_bounds_by_low_ancestor` — a chain where an
//!    agent_attested derived record hangs off an unattested source reads
//!    back `Unattested` (read-time compute).
//!  * `propagated_trust_tier_chain_of_three` — a 3-hop chain propagates the
//!    floor to the tail.
//!
//! #1959 (R55) — invalidating a source reports ALL transitive derivations
//! suspect over the DAG, cycle-safe + depth-bounded:
//!  * `transitive_suspects_reports_all_derivations` — root → A → B → C, all
//!    three transitive derivations surface.
//!  * `transitive_suspects_ignores_non_derived` — a `related_to` neighbour
//!    is never flagged.
//!  * `transitive_suspects_is_cycle_safe` — a directly-injected cyclic edge
//!    pair terminates.
//!  * `transitive_suspects_respects_depth_bound` — max_depth caps the walk.
//!
//! ## Honest boundary (ESTIMABLE)
//!
//! Both guarantees are scoped to the RECORDED provenance DAG — an
//! un-recorded derivation is invisible to the walk. These tests exercise
//! the recorded-lineage guarantee only.
//!
//! ## Concurrency
//!
//! The lineage-DAG flags are process-wide `AtomicBool`s, so the tests
//! serialize on a file-local `Mutex` (the `tests/lineage_dag_g13.rs`
//! precedent).

use std::path::Path;
use std::sync::Mutex;

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use ai_memory::trust::TrustTier;
use serde_json::json;

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

/// A memory with an explicit `created_at` (so the acyclicity guard is
/// deterministic) and an explicit `attest_level` in its metadata (so the
/// trust tier is controllable). `attest` = None means no attestation.
fn mem_with_attest(id: &str, title: &str, created_at: &str, attest: Option<&str>) -> Memory {
    let mut meta = serde_json::Map::new();
    meta.insert("agent_id".to_string(), json!("ai:tester"));
    if let Some(a) = attest {
        meta.insert("attest_level".to_string(), json!(a));
    }
    Memory {
        id: id.to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        metadata: serde_json::Value::Object(meta),
        tier: Tier::Mid,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// #1958 (R20) — trust-tier min-propagation
// ---------------------------------------------------------------------------

#[test]
fn consolidate_stamps_min_propagated_trust() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    // One agent_attested source, one unattested source → min = unattested.
    let hi = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let lo = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    db::insert(
        &conn,
        &mem_with_attest(
            hi,
            "HI",
            "2026-01-01T00:00:00+00:00",
            Some("agent_attested"),
        ),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(lo, "LO", "2026-01-02T00:00:00+00:00", None),
    )
    .unwrap();

    let cid = db::consolidate(
        &conn,
        &[hi.to_string(), lo.to_string()],
        "merged",
        "merged summary",
        "ns",
        &Tier::Long,
        "test",
        "ai:consolidator",
        false,
    )
    .expect("consolidate");

    let merged = db::get(&conn, &cid).unwrap().expect("consolidated row");
    // confidence == min(source confidences); both sources here carry the
    // default 1.0, so the min is 1.0. The confidence-VALUE laundering vector
    // the issue named is closed separately by #2935 (a low-confidence source
    // now floors the derived confidence); this R20 test pins the orthogonal
    // trust-TIER floor, which stays honestly at the unattested source.
    assert!((merged.confidence - 1.0).abs() < f64::EPSILON);
    assert_eq!(
        merged.metadata["propagated_trust"].as_str(),
        Some(TrustTier::Unattested.as_str()),
        "high-trust derived record over a low-trust source must floor to unattested",
    );
    lineage_off();
}

#[test]
fn consolidate_sibling_merge_takes_the_min() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    // attested + claimed siblings → min = claimed.
    let a = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    let b = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    db::insert(
        &conn,
        &mem_with_attest(a, "A", "2026-01-01T00:00:00+00:00", Some("agent_attested")),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(b, "B", "2026-01-02T00:00:00+00:00", Some("claimed")),
    )
    .unwrap();

    let cid = db::consolidate(
        &conn,
        &[a.to_string(), b.to_string()],
        "merged2",
        "s",
        "ns",
        &Tier::Long,
        "test",
        "ai:consolidator",
        false,
    )
    .expect("consolidate");
    let merged = db::get(&conn, &cid).unwrap().unwrap();
    assert_eq!(
        merged.metadata["propagated_trust"].as_str(),
        Some(TrustTier::Claimed.as_str()),
    );
    lineage_off();
}

#[test]
fn propagated_trust_tier_bounds_by_low_ancestor() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    // S (unattested source) <- D (agent_attested derived record).
    // D's own tier is Attested, but its recorded ancestor S is Unattested,
    // so the read-time propagated tier floors to Unattested.
    let s = "11111111-1111-4111-8111-111111111111";
    let d = "22222222-2222-4222-8222-222222222222";
    db::insert(
        &conn,
        &mem_with_attest(s, "S", "2026-01-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(d, "D", "2026-02-01T00:00:00+00:00", Some("agent_attested")),
    )
    .unwrap();
    // D derived_from S (child newer than source — acyclicity guard passes).
    db::create_link(&conn, d, s, "derived_from").expect("derived_from edge");

    let tier = db::propagated_trust_tier(&conn, d, db::LINEAGE_MAX_DEPTH).unwrap();
    assert_eq!(
        tier,
        TrustTier::Unattested,
        "an agent_attested record derived from an unattested source cannot stay attested",
    );
    lineage_off();
}

#[test]
fn propagated_trust_tier_chain_of_three() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    // A(claimed) <- B(agent_attested) <- C(agent_attested). C's floor is the
    // weakest recorded ancestor = A(claimed).
    let a = "33333333-3333-4333-8333-333333333333";
    let b = "44444444-4444-4444-8444-444444444444";
    let c = "55555555-5555-4555-8555-555555555555";
    db::insert(
        &conn,
        &mem_with_attest(a, "A", "2026-01-01T00:00:00+00:00", Some("claimed")),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(b, "B", "2026-02-01T00:00:00+00:00", Some("agent_attested")),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(c, "C", "2026-03-01T00:00:00+00:00", Some("agent_attested")),
    )
    .unwrap();
    db::create_link(&conn, b, a, "derived_from").unwrap();
    db::create_link(&conn, c, b, "derived_from").unwrap();

    let tier = db::propagated_trust_tier(&conn, c, db::LINEAGE_MAX_DEPTH).unwrap();
    assert_eq!(tier, TrustTier::Claimed);
    lineage_off();
}

// ---------------------------------------------------------------------------
// #1959 (R55) — transitive suspect invalidation
// ---------------------------------------------------------------------------

#[test]
fn transitive_suspects_reports_all_derivations() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    // root <- A <- B <- C (each derived_from the previous). Invalidating root
    // must surface A, B, C as transitive suspects.
    let root = "66666666-6666-4666-8666-666666666666";
    let a = "77777777-7777-4777-8777-777777777777";
    let b = "88888888-8888-4888-8888-888888888888";
    let c = "99999999-9999-4999-8999-999999999999";
    db::insert(
        &conn,
        &mem_with_attest(root, "root", "2026-01-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(a, "A", "2026-02-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(b, "B", "2026-03-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(c, "C", "2026-04-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::create_link(&conn, a, root, "derived_from").unwrap();
    db::create_link(&conn, b, a, "reflects_on").unwrap();
    db::create_link(&conn, c, b, "derives_from").unwrap();

    let suspects = db::transitive_suspects(&conn, root, db::LINEAGE_MAX_DEPTH).unwrap();
    let ids: Vec<&str> = suspects.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(
        suspects.len(),
        3,
        "all 3 transitive derivations flagged: {ids:?}"
    );
    assert!(ids.contains(&a));
    assert!(ids.contains(&b));
    assert!(ids.contains(&c));
    lineage_off();
}

#[test]
fn transitive_suspects_ignores_non_derived() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let root = "aaaa1111-1111-4111-8111-111111111111";
    let derived = "aaaa2222-2222-4222-8222-222222222222";
    let neighbour = "aaaa3333-3333-4333-8333-333333333333";
    db::insert(
        &conn,
        &mem_with_attest(root, "root", "2026-01-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(derived, "D", "2026-02-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(neighbour, "N", "2026-02-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::create_link(&conn, derived, root, "derived_from").unwrap();
    // A non-provenance edge must NOT taint N.
    db::create_link(&conn, neighbour, root, "related_to").unwrap();

    let suspects = db::transitive_suspects(&conn, root, db::LINEAGE_MAX_DEPTH).unwrap();
    let ids: Vec<&str> = suspects.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![derived],
        "only the P-edge derivation is suspect: {ids:?}"
    );
    lineage_off();
}

#[test]
fn transitive_suspects_is_cycle_safe() {
    let _g = flag_guard();
    // Build the cyclic pair with the guard OFF (a corrupt/federation graph),
    // then read with it ON — the walk must terminate, not hang.
    lineage_off();
    let conn = open_mem_db();
    let x = "bbbb1111-1111-4111-8111-111111111111";
    let y = "bbbb2222-2222-4222-8222-222222222222";
    db::insert(
        &conn,
        &mem_with_attest(x, "X", "2026-01-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(y, "Y", "2026-01-01T00:00:00+00:00", None),
    )
    .unwrap();
    // Inject a cycle directly (both directions), bypassing the guard.
    db::create_link(&conn, y, x, "derived_from").unwrap();
    db::create_link(&conn, x, y, "derived_from").unwrap();

    let suspects = db::transitive_suspects(&conn, x, db::LINEAGE_MAX_DEPTH).unwrap();
    // Cycle-safe: terminates and reports the reachable node(s), not a hang.
    let ids: Vec<&str> = suspects.iter().map(|n| n.id.as_str()).collect();
    assert!(ids.contains(&y), "reachable node reported: {ids:?}");
}

#[test]
fn transitive_suspects_respects_depth_bound() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let root = "cccc0000-0000-4000-8000-000000000000";
    let a = "cccc1111-1111-4111-8111-111111111111";
    let b = "cccc2222-2222-4222-8222-222222222222";
    db::insert(
        &conn,
        &mem_with_attest(root, "root", "2026-01-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(a, "A", "2026-02-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::insert(
        &conn,
        &mem_with_attest(b, "B", "2026-03-01T00:00:00+00:00", None),
    )
    .unwrap();
    db::create_link(&conn, a, root, "derived_from").unwrap();
    db::create_link(&conn, b, a, "derived_from").unwrap();

    // depth 1 reaches only the direct derivation A.
    let d1 = db::transitive_suspects(&conn, root, 1).unwrap();
    let ids1: Vec<&str> = d1.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(
        ids1,
        vec![a],
        "depth 1 caps at the direct derivation: {ids1:?}"
    );

    // depth 2 reaches A and B.
    let d2 = db::transitive_suspects(&conn, root, 2).unwrap();
    assert_eq!(d2.len(), 2);
    lineage_off();
}
