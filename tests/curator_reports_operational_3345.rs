// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3345 — the curator's per-sweep self-report must not be a first-class,
//! EMBEDDED, recall-visible memory.
//!
//! **The defect.** Every curator cycle wrote a `_curator/reports` row through
//! the ordinary `db::insert` path. The row itself carried no embedding — but
//! the boot-spawned embedding backfill selects on `embedding IS NULL` with no
//! namespace or lifecycle filter, so it embedded every one of them. On one
//! fleet node: 24,930 rows (97% of the store) and 24,801 paid embedding calls,
//! against 512 real memories. A `curator --daemon`-only host also runs no GC
//! loop at all, so the TTL those rows already carried was never enforced —
//! which is the same leak, in the same namespace, as #1466 (2,905 of 2,921).
//!
//! **The control** is the fail-CLOSED `lifecycle_visible_clause` allow-list,
//! reused rather than re-invented: self-reports are written
//! `LifecycleState::Operational`, which is absent from
//! `RECALL_VISIBLE_LIFECYCLE_STATES`, and the embedding-backfill selectors now
//! carry that same clause. A namespace blocklist was deliberately NOT used —
//! `_inbox/<agent>` rows are meant to be recallable by their recipient, so
//! hiding `_`-prefixed namespaces would break inbox delivery.
//!
//! This suite pins the SQLite half; `curator_reports_operational_3345_pg.rs`
//! pins the PostgreSQL half against a live cluster.

#![allow(clippy::missing_panics_doc)]

use ai_memory::db;
use ai_memory::models::{LifecycleState, Memory, Tier};

fn conn() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn mem(id: &str, ns: &str, state: LifecycleState) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("t-{id}"),
        content: format!("body for {id}"),
        priority: 5,
        confidence: 1.0,
        source: "test3345".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({}),
        version: 1,
        lifecycle_state: state,
        ..Memory::default()
    }
}

/// DENIED — a row in a NON-visible lifecycle state is never selected for
/// embedding, on every selector the backfill uses. Pre-#3345 all three
/// returned it, which is where the 24,801 paid embeddings came from.
#[test]
fn non_visible_rows_are_never_selected_for_embedding_3345() {
    let c = conn();
    for (id, state) in [
        ("op-3345", LifecycleState::Operational),
        ("tomb-3345", LifecycleState::Tombstoned),
        ("quar-3345", LifecycleState::Quarantined),
        ("cont-3345", LifecycleState::Contaminated),
    ] {
        db::insert(&c, &mem(id, "ns3345", state)).expect("insert");
    }

    let unbounded = db::get_unembedded_ids(&c).expect("get_unembedded_ids");
    let batch = db::get_unembedded_ids_batch(&c, 100).expect("batch");
    let scan = db::get_unembedded_ids_batch_after(&c, None, 100).expect("keyset");

    assert!(
        unbounded.is_empty(),
        "unbounded selector must skip non-visible rows, got: {unbounded:?}"
    );
    assert!(
        batch.is_empty(),
        "bounded selector must skip non-visible rows, got: {batch:?}"
    );
    assert!(
        scan.rows.is_empty(),
        "keyset selector must skip non-visible rows, got: {:?}",
        scan.rows
    );
}

/// ALLOWED — an ordinary row is still selected. The gate must not break the
/// thing the backfill exists for.
#[test]
fn visible_rows_are_still_selected_for_embedding_3345() {
    let c = conn();
    db::insert(&c, &mem("open-3345", "ns3345", LifecycleState::Open)).expect("insert");
    db::insert(&c, &mem("op2-3345", "ns3345", LifecycleState::Operational)).expect("insert");

    let batch = db::get_unembedded_ids_batch(&c, 100).expect("batch");
    let ids: Vec<&str> = batch.iter().map(|(id, _, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["open-3345"],
        "exactly the recall-visible row is embeddable"
    );
}

/// A curator sweep leaves NO recall-visible row — the bar #3345 set.
#[test]
fn a_sweep_leaves_no_recall_visible_row_3345() {
    let c = conn();
    let pass = ai_memory::autonomy::AutonomyPassReport::default();
    ai_memory::autonomy::persist_self_report(&c, 12, &pass, 0, 0, 0, 0)
        .expect("persist_self_report");

    // `db::list` carries the visibility allow-list, so the report is absent
    // from the ordinary read lane in its own namespace AND corpus-wide.
    let in_ns = db::list(
        &c,
        Some(ai_memory::autonomy::CURATOR_REPORTS_NAMESPACE),
        None,
        1000,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("list ns");
    assert!(
        in_ns.is_empty(),
        "a sweep must leave no recall-visible row, got {} row(s)",
        in_ns.len()
    );

    // …but it IS stored, and reachable through the operator read path.
    let reports =
        db::list_operational_reports(&c, ai_memory::autonomy::CURATOR_REPORTS_NAMESPACE, 100)
            .expect("list_operational_reports");
    assert_eq!(
        reports.len(),
        1,
        "the report is stored, just not recallable"
    );

    // Short tier + an explicit expiry: bounded growth, reaped by the ordinary
    // TTL sweep the curator daemon now runs.
    let row = db::get_any(&c, &reports[0].0)
        .expect("get_any")
        .expect("row present");
    assert_eq!(row.tier, Tier::Short);
    assert!(row.expires_at.is_some(), "self-reports must carry a TTL");
    assert_eq!(row.lifecycle_state, LifecycleState::Operational);
}

/// The backlog stamp is idempotent, and stamps only what is left.
#[test]
fn backlog_stamp_is_idempotent_3345() {
    let c = conn();
    let ns = ai_memory::autonomy::CURATOR_REPORTS_NAMESPACE;
    for i in 0..3 {
        db::insert(
            &c,
            &mem(&format!("legacy-{i}-3345"), ns, LifecycleState::Open),
        )
        .expect("insert");
    }
    let fallback = ai_memory::validate::render_canonical_utc(
        chrono::Utc::now() + chrono::Duration::seconds(60),
    );

    let first = db::stamp_operational_backlog(&c, ns, &fallback).expect("stamp");
    assert_eq!(first, 3, "every legacy row is stamped");

    let second = db::stamp_operational_backlog(&c, ns, &fallback).expect("stamp again");
    assert_eq!(second, 0, "a second run stamps nothing (self-terminating)");

    // Stamped, NOT deleted — the durable text survives.
    let reports = db::list_operational_reports(&c, ns, 100).expect("list");
    assert_eq!(reports.len(), 3, "the stamp never deletes");
}
