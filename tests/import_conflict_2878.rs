// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2878 — the Portability-v2 importer must be ATOMICALLY fail-closed on a
//! `(title, namespace)` collision under every non-`Merge` disposition: a row
//! that raced into the key BETWEEN the collision probe and the write is
//! REFUSED (typed `ConflictError` → per-row skip), never allowed to silently
//! upsert-overwrite the destination's durable content.
//!
//! Pre-#2878 a probe MISS fell through to `storage::insert_imported`
//! (`insert_inner(.., false, false)` = `INSERT … ON CONFLICT DO UPDATE`), so a
//! writer that slipped into the key after the probe had the destination row's
//! content clobbered with no warning — the identical North-Star lost-update
//! #2771 closed on the create funnel, on the import funnel. `Merge` (the
//! operator's opt-in silent upsert) is unchanged.
//!
//! The importer wraps every apply in ONE `BEGIN IMMEDIATE` transaction, so two
//! concurrent imports SERIALIZE and the second's probe always SEES the first's
//! committed row (the collision is probe-visible, never a mid-transaction
//! race). The no-overwrite write arm is therefore STRUCTURAL defense-in-depth
//! — it makes "never clobber" hold by construction regardless of isolation
//! level or backend, rather than resting on the IMMEDIATE-transaction argument.
//! These tests pin BOTH halves: the certified `insert_imported_no_overwrite`
//! primitive the funnel now wires in (single-connection deterministic + a
//! genuine two-connection race), and the funnel's end-to-end non-clobber
//! contract under the `Version` (default) and `Error` dispositions.
//!
//! The load-bearing no-overwrite assertion is the schema-v45 `version` column:
//! a fresh insert lands `version = 1`, an upsert-MERGE bumps it (#1632).

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::portability::emit::{ExportEnvelope, SPEC_VERSION_V2};
use ai_memory::portability::import::{ImportOptions, import_full_envelope};
use rusqlite::Connection;

const AUTHOR: &str = "ai:bundle-author";

fn scratch_root(tag: &str) -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2878-import-conflict")
        .join(tag);
    std::fs::create_dir_all(&root).ok();
    root
}

/// A migrated DB file that outlives the returned connection (the file is
/// leaked, not the connection — the two-connection race re-opens it).
fn fresh_db_path(tag: &str) -> PathBuf {
    let dir = tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(scratch_root(tag))
        .expect("tempdir under .local-runs");
    let path = dir.path().join("db.sqlite");
    drop(ai_memory::db::open(&path).expect("init db"));
    std::mem::forget(dir); // keep the file alive for the test's connections
    path
}

fn mem(id: &str, title: &str, ns: &str, content: &str) -> Memory {
    let now = "2026-07-20T00:00:00Z".to_string();
    Memory {
        id: id.into(),
        tier: Tier::Mid,
        namespace: ns.into(),
        title: title.into(),
        content: content.into(),
        priority: 5,
        confidence: 1.0,
        source: "system".into(),
        created_at: now.clone(),
        updated_at: now,
        expires_at: Some("2099-01-01T00:00:00Z".into()),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": AUTHOR }),
        ..Memory::default()
    }
}

fn envelope_with(memories: Vec<Memory>) -> ExportEnvelope {
    let count = memories.len();
    ExportEnvelope {
        spec_version: SPEC_VERSION_V2.to_string(),
        // 0 <= any migrated destination schema, so the fail-closed
        // newer-producer gate never fires for this hand-built bundle.
        db_schema_version: 0,
        source: "issue-2878-test".into(),
        exported_at: "2026-07-20T00:00:00Z".into(),
        memories,
        links: Vec::new(),
        signed_events: Vec::new(),
        memory_revisions: Vec::new(),
        forget_tombstones: Vec::new(),
        agent_lineage: Vec::new(),
        model_attestations: Vec::new(),
        governance_rules: Vec::new(),
        trust_anchors: Vec::new(),
        archived_memories: Vec::new(),
        namespace_meta: Vec::new(),
        archived_memory_links: Vec::new(),
        portability_complete: false,
        conformance_level: "L1".into(),
        conformance_by_class: BTreeMap::new(),
        count,
    }
}

/// Default (secure) importer options — restamp identity, `Version` on
/// collision (never clobber).
fn default_opts() -> ImportOptions {
    ImportOptions {
        caller_agent_id: "ai:importer".into(),
        ..ImportOptions::default()
    }
}

fn error_opts() -> ImportOptions {
    ImportOptions {
        caller_agent_id: "ai:importer".into(),
        on_conflict: ai_memory::storage::ConflictMode::Error,
        ..ImportOptions::default()
    }
}

// ───────────────────────────────────────────────────────────────────
// primitive — `insert_imported_no_overwrite` (the funnel's write arm)
// ───────────────────────────────────────────────────────────────────

/// The remote-admission no-overwrite insert REFUSES a `(title, namespace)`
/// collision with the typed `ConflictError` carrying the incumbent's id, and
/// leaves the durable row byte-identical (winner's content, `version = 1`).
#[test]
fn insert_imported_no_overwrite_refuses_and_preserves_content_2878() {
    let path = fresh_db_path("primitive");
    let conn = ai_memory::db::open(&path).expect("open");

    let winner = mem(
        "id-winner",
        "shared-title",
        "team/ops",
        "WINNER durable content",
    );
    let winner_id = ai_memory::db::insert_imported_no_overwrite(&conn, &winner).expect("first ok");
    assert_eq!(winner_id, "id-winner");

    let loser = mem(
        "id-loser",
        "shared-title",
        "team/ops",
        "LOSER content MUST NOT land",
    );
    let err = ai_memory::db::insert_imported_no_overwrite(&conn, &loser)
        .expect_err("second import MUST be refused, never overwrite");
    let conflict = err
        .downcast_ref::<ai_memory::storage::ConflictError>()
        .expect("typed ConflictError");
    assert_eq!(conflict.existing_id, "id-winner");
    assert_eq!(conflict.title, "shared-title");
    assert_eq!(conflict.namespace, "team/ops");

    let row = ai_memory::db::get(&conn, "id-winner")
        .expect("get")
        .expect("row");
    assert_eq!(row.content, "WINNER durable content");
    assert_eq!(row.version, 1, "no upsert-merge ever bumped the version");
    assert!(
        ai_memory::db::get(&conn, "id-loser")
            .expect("get")
            .is_none(),
        "loser id must not exist"
    );
}

/// Control: the legacy `insert_imported` (the `Merge`/upsert path #2878 leaves
/// unchanged) DOES clobber — proving the no-overwrite fix changed only the
/// non-`Merge` write, and that the assertion above is load-bearing.
#[test]
fn insert_imported_still_upserts_on_merge_2878() {
    let path = fresh_db_path("merge-control");
    let conn = ai_memory::db::open(&path).expect("open");

    ai_memory::db::insert_imported(&conn, &mem("id-1", "shared-title", "team/ops", "first"))
        .expect("first");
    ai_memory::db::insert_imported(
        &conn,
        &mem("id-2", "shared-title", "team/ops", "second wins on merge"),
    )
    .expect("merge upsert");
    let row = ai_memory::db::get(&conn, "id-1")
        .expect("get")
        .expect("surviving row");
    assert_eq!(row.content, "second wins on merge");
    assert!(
        row.version >= 2,
        "merge upsert bumps version (#1632), got {}",
        row.version
    );
}

/// Genuine two-connection race on the no-overwrite primitive: the
/// `(title, namespace)` UNIQUE index guarantees exactly one winner; the loser
/// gets the typed `ConflictError` (never a silent overwrite, never two rows),
/// and the surviving content is the winner's at `version = 1`.
#[test]
fn insert_imported_no_overwrite_two_connection_race_one_winner_2878() {
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    let path = fresh_db_path("race");
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for tag in ["a", "b"] {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let conn = ai_memory::db::open(&path).expect("open");
            conn.busy_timeout(Duration::from_secs(10))
                .expect("busy_timeout");
            let m = mem(
                &format!("id-{tag}"),
                "raced-title",
                "race/ns",
                &format!("content-from-{tag}"),
            );
            barrier.wait();
            ai_memory::db::insert_imported_no_overwrite(&conn, &m)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();

    let winners: Vec<&String> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(winners.len(), 1, "exactly one import must win the race");
    for r in &results {
        if let Err(e) = r {
            e.downcast_ref::<ai_memory::storage::ConflictError>()
                .expect("loser must get the typed ConflictError, not a lock/other error");
        }
    }

    let conn = ai_memory::db::open(&path).expect("reopen");
    let winner_id = winners[0].clone();
    let row = ai_memory::db::get(&conn, &winner_id)
        .expect("get")
        .expect("winner row");
    let expected = format!("content-from-{}", winner_id.trim_start_matches("id-"));
    assert_eq!(row.content, expected, "winner content must be durable");
    assert_eq!(
        row.version, 1,
        "the race must never upsert-overwrite (version stays 1)"
    );
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = ?1 AND namespace = ?2",
            rusqlite::params!["raced-title", "race/ns"],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(count, 1, "the race must leave exactly one row");
}

// ───────────────────────────────────────────────────────────────────
// funnel — `import_full_envelope` end-to-end non-clobber contract
// ───────────────────────────────────────────────────────────────────

/// A fresh import lands the row at `version = 1` (baseline), and a SECOND
/// import of a DIFFERENT-id memory colliding on `(title, namespace)` under the
/// default `Version` disposition SUFFIXES the incoming title so BOTH rows
/// persist — the destination's original row is NEVER clobbered (content intact,
/// `version = 1`). Semantics unchanged by #2878; the no-overwrite write arm is
/// a structural no-op on this (probe-visible) collision.
#[test]
fn import_version_disposition_never_clobbers_destination_2878() {
    let path = fresh_db_path("funnel-version");
    let conn = Connection::open(&path).expect("open raw");
    // Re-run migrations/pragmas through the canonical opener on a fresh handle.
    drop(conn);
    let conn = ai_memory::db::open(&path).expect("open");

    let first = import_full_envelope(
        &conn,
        &envelope_with(vec![mem(
            "id-a",
            "runbook",
            "portability",
            "ORIGINAL destination text",
        )]),
        &default_opts(),
    )
    .expect("first import");
    assert_eq!(first.memories, 1);
    let row = ai_memory::db::get(&conn, "id-a")
        .expect("get")
        .expect("row");
    assert_eq!(row.version, 1, "fresh import lands version=1");

    // Second import: different id, SAME (title, namespace).
    let second = import_full_envelope(
        &conn,
        &envelope_with(vec![mem(
            "id-b",
            "runbook",
            "portability",
            "INCOMING different text",
        )]),
        &default_opts(),
    )
    .expect("second import");
    assert_eq!(
        second.memories, 1,
        "Version suffixes the incoming title so it also persists"
    );

    // The destination's ORIGINAL row is untouched — content + version.
    let original = ai_memory::db::get(&conn, "id-a")
        .expect("get")
        .expect("original row");
    assert_eq!(
        original.content, "ORIGINAL destination text",
        "#2878: the destination's durable content must never be clobbered"
    );
    assert_eq!(
        original.version, 1,
        "#2878: no upsert-merge ever bumped the original"
    );
    // The incoming row landed under a suffixed title.
    let incoming = ai_memory::db::get(&conn, "id-b")
        .expect("get")
        .expect("incoming row");
    assert_ne!(
        incoming.title, "runbook",
        "Version suffixes the colliding title"
    );
    assert!(
        incoming.title.starts_with("runbook"),
        "suffix keeps the base: {}",
        incoming.title
    );
}

/// Under the `Error` disposition a colliding import is SKIPPED
/// (`conflicts_skipped = 1`), the destination's original row is left intact
/// (content + `version = 1`), and no second row is created.
#[test]
fn import_error_disposition_skips_and_preserves_destination_2878() {
    let path = fresh_db_path("funnel-error");
    let conn = ai_memory::db::open(&path).expect("open");

    import_full_envelope(
        &conn,
        &envelope_with(vec![mem(
            "id-a",
            "runbook",
            "portability",
            "ORIGINAL destination text",
        )]),
        &error_opts(),
    )
    .expect("first import");

    let report = import_full_envelope(
        &conn,
        &envelope_with(vec![mem(
            "id-b",
            "runbook",
            "portability",
            "INCOMING must be refused",
        )]),
        &error_opts(),
    )
    .expect("second import (bundle still lands, colliding row skipped)");
    assert_eq!(
        report.memories, 0,
        "the colliding row is not admitted under Error"
    );
    assert_eq!(
        report.conflicts_skipped, 1,
        "the collision is counted, not clobbered"
    );

    let original = ai_memory::db::get(&conn, "id-a")
        .expect("get")
        .expect("original row");
    assert_eq!(original.content, "ORIGINAL destination text");
    assert_eq!(
        original.version, 1,
        "#2878: original never upsert-overwritten"
    );
    assert!(
        ai_memory::db::get(&conn, "id-b").expect("get").is_none(),
        "the refused row must not exist"
    );
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = ?1 AND namespace = ?2",
            rusqlite::params!["runbook", "portability"],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        count, 1,
        "Error disposition leaves exactly the original row"
    );
}
