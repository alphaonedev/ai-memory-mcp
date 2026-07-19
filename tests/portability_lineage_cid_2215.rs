// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2215 — the Portability-v2 import must repopulate the schema-v75
//! lineage-DAG cid mirror (`memory_links.source_cid` / `.target_cid`).
//!
//! Landed via PR #2205, the v2 importer's raw `INSERT INTO memory_links`
//! carried nine columns but NOT the `source_cid`/`target_cid` mirror, and the
//! wire model `MemoryLink` did not carry them either — so EVERY imported edge
//! lost its tombstone-resilient node identity (a #2006 residual fidelity gap).
//!
//! This suite pins BOTH sides of the round-trip:
//!   * the EXPORTER twin fix — `MemoryLink` + `storage::export_links` now carry
//!     the cids, so the v2 envelope round-trips them (the `round_trip_*` test
//!     FAILS pre-fix on BOTH the parsed-envelope AND the imported-row assertions);
//!   * the IMPORTER fix — prefer the bundle's cid, else BACKFILL from the staged
//!     endpoint's re-derived `memories.cid`, else leave NULL (degrade, do not
//!     invent — the pre-v75 legacy state), gated on `lineage_dag_enabled()` for
//!     byte-parity with the native `create_link_signed` write path.
//!
//! ## Concurrency
//! `lineage_dag` is a process-wide `AtomicBool`, so the tests serialize on a
//! file-local `Mutex` and set the flag they need under the guard (mirrors
//! `tests/lineage_dag_g13.rs`).

#![allow(clippy::missing_panics_doc)]

use std::path::Path;
use std::sync::Mutex;

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use ai_memory::portability::{emit, import};
use rusqlite::{Connection, params};

/// Serializes the tests so one test's flag write cannot race another's
/// expectation (the lineage flag is a process-wide atomic).
static FLAG_LOCK: Mutex<()> = Mutex::new(());

fn flag_guard() -> std::sync::MutexGuard<'static, ()> {
    FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn open_mem_db() -> Connection {
    db::open(Path::new(":memory:")).expect("open in-memory db")
}

/// A memory with an EXPLICIT `created_at` so the `derived_from` acyclicity
/// guard (COND 4: reject a target NEWER than its source) is deterministic.
/// `Tier::Long` (permanent, no `expires_at`) keeps the rows inside
/// `export_links`' non-expired JOIN regardless of wall-clock at test time.
fn make_mem(id: &str, title: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        title: title.to_string(),
        content: format!("durable content for {title}"),
        namespace: "portability-2215".to_string(),
        tier: Tier::Long,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        metadata: serde_json::json!({ "agent_id": "alice" }),
        ..Default::default()
    }
}

fn cid_of(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row("SELECT cid FROM memories WHERE id = ?1", params![id], |r| {
        r.get::<_, Option<String>>(0)
    })
    .expect("read cid")
}

/// The `(source_cid, target_cid)` mirror stored on the edge in `conn`.
fn edge_cids(conn: &Connection, src: &str, tgt: &str) -> (Option<String>, Option<String>) {
    conn.query_row(
        "SELECT source_cid, target_cid FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
        params![src, tgt],
        |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
            ))
        },
    )
    .expect("read edge cids")
}

fn default_import_opts() -> import::ImportOptions {
    import::ImportOptions {
        // The byte-exact identity round-trip (ids preserved verbatim so the
        // dest re-derives the SAME cid) is EARNED by `trust_source` (#2211).
        trust_source: true,
        caller_agent_id: "importer".into(),
        ..import::ImportOptions::default()
    }
}

const CHILD: &str = "00000000-0000-0000-0000-0000000002a1";
const PARENT: &str = "00000000-0000-0000-0000-0000000002b1";

/// Build a source DB carrying a `derived_from` edge (child -> parent) whose
/// cid mirror was stamped at link-creation time, and return
/// `(envelope, child_cid, parent_cid)`. The caller controls the lineage flag.
fn seed_linked_pair(src: &Connection) -> (emit::ExportEnvelope, String, String) {
    // child (source, NEWER) derives_from parent (target, OLDER) — an allowed
    // (backward) lineage edge under COND 4.
    let parent = make_mem(PARENT, "parent-claim", "2026-01-01T00:00:00Z");
    let child = make_mem(CHILD, "child-reflection", "2026-02-01T00:00:00Z");
    db::insert(src, &parent).expect("insert parent");
    db::insert(src, &child).expect("insert child");
    db::create_link(src, CHILD, PARENT, "derived_from").expect("create derived_from link");

    let child_cid = cid_of(src, CHILD).expect("child cid present");
    let parent_cid = cid_of(src, PARENT).expect("parent cid present");

    let envelope = emit::build_full_envelope(src, "src", "2026-07-18T00:00:00Z").expect("export");
    // Round-trip through the real JSON wire form.
    let json = serde_json::to_string(&envelope).expect("serialize envelope");
    let parsed: emit::ExportEnvelope = serde_json::from_str(&json).expect("deserialize envelope");
    (parsed, child_cid, parent_cid)
}

/// ★ Required round-trip test (FAILS pre-fix on BOTH the exporter and importer
/// side): export a linked pair carrying cids -> import into a FRESH dest ->
/// assert the imported edge carries the SAME `source_cid` / `target_cid`.
#[test]
fn round_trip_carries_lineage_cids() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);

    let src = open_mem_db();
    let (parsed, child_cid, parent_cid) = seed_linked_pair(&src);

    // EXPORTER twin fix: the v2 envelope carried the cids on the wire model
    // (pre-fix `MemoryLink` had no cid fields, so these were `None`).
    let wire = parsed
        .links
        .iter()
        .find(|l| l.source_id == CHILD && l.target_id == PARENT)
        .expect("linked pair in envelope");
    assert_eq!(
        wire.source_cid.as_deref(),
        Some(child_cid.as_str()),
        "envelope must carry the source (child) cid"
    );
    assert_eq!(
        wire.target_cid.as_deref(),
        Some(parent_cid.as_str()),
        "envelope must carry the target (parent) cid"
    );

    // IMPORTER fix: the mirror lands on the destination edge.
    let dst = open_mem_db();
    ai_memory::config::set_lineage_dag(true);
    import::import_full_envelope(&dst, &parsed, &default_import_opts()).expect("import");

    let (dsc, dtc) = edge_cids(&dst, CHILD, PARENT);
    assert_eq!(
        dsc.as_deref(),
        Some(child_cid.as_str()),
        "imported edge must carry the source cid (pre-fix this was NULL)"
    );
    assert_eq!(
        dtc.as_deref(),
        Some(parent_cid.as_str()),
        "imported edge must carry the target cid (pre-fix this was NULL)"
    );
}

/// An OLDER bundle (produced before the exporter twin fix) carries NO link
/// cids; the importer BACKFILLS from the staged endpoints' re-derived
/// `memories.cid` when the DAG is enabled.
#[test]
fn legacy_bundle_backfills_from_endpoint_cids() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);

    let src = open_mem_db();
    let (mut parsed, child_cid, parent_cid) = seed_linked_pair(&src);

    // Simulate a pre-#2215 exporter: strip the carried cids from the wire.
    for l in &mut parsed.links {
        l.source_cid = None;
        l.target_cid = None;
    }

    let dst = open_mem_db();
    ai_memory::config::set_lineage_dag(true);
    import::import_full_envelope(&dst, &parsed, &default_import_opts()).expect("import");

    // The dest re-derived identical cids on the staged memories; the importer
    // backfills the mirror from them (NOT from the absent bundle values).
    let (dsc, dtc) = edge_cids(&dst, CHILD, PARENT);
    assert_eq!(
        dsc.as_deref(),
        Some(child_cid.as_str()),
        "backfill from staged endpoint cid"
    );
    assert_eq!(
        dtc.as_deref(),
        Some(parent_cid.as_str()),
        "backfill from staged endpoint cid"
    );
}

/// ★ Required absent-cid legacy-bundle NULL case: an older bundle with no link
/// cids imported while the lineage DAG is OFF binds NULL — degrade, do NOT
/// invent (the pre-v75 legacy state / native-off byte-parity).
#[test]
fn legacy_bundle_without_dag_leaves_null() {
    let _g = flag_guard();

    // Seed the source WITH the DAG on so the bundle is otherwise well-formed.
    ai_memory::config::set_lineage_dag(true);
    let src = open_mem_db();
    let (mut parsed, _child_cid, _parent_cid) = seed_linked_pair(&src);
    for l in &mut parsed.links {
        l.source_cid = None;
        l.target_cid = None;
    }

    // Import with the DAG OFF: the mirror binds NULL (not garbage), matching
    // the native `create_link_signed` off-path.
    ai_memory::config::set_lineage_dag(false);
    let dst = open_mem_db();
    import::import_full_envelope(&dst, &parsed, &default_import_opts()).expect("import");

    let (dsc, dtc) = edge_cids(&dst, CHILD, PARENT);
    assert_eq!(dsc, None, "DAG-off import must leave source_cid NULL");
    assert_eq!(dtc, None, "DAG-off import must leave target_cid NULL");

    // Restore the default OFF posture for any subsequent test acquiring the lock.
    ai_memory::config::set_lineage_dag(false);
}
