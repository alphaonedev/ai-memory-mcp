// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2570 + #2569 — the import round-trip must survive an EDITED corpus and a
//! re-import onto an EXISTING corpus.
//!
//! - #2570: the import archive-admission gate must DISCRIMINATE
//!   `archive_reason`. #1725 snapshots the prior content of a STILL-LIVE row
//!   into `archived_memories` under `archive_reason='in_place_edit'` on every
//!   in-place edit, so a gate keyed on mere PRESENCE wrongly covenant-skipped
//!   an edited-but-live row's own backup. `db::memory_is_genuinely_archived`
//!   admits the `in_place_edit` snapshot and blocks only a genuine archival.
//! - #2569: the default `ConflictMode::Version` reuses the payload `id`, so a
//!   same-`id` re-import onto an existing corpus hit `UNIQUE constraint
//!   failed: memories.id` → `refused`. It is now an IDEMPOTENT no-op
//!   (`idempotent_skipped`), never overwriting the durable row (#2878).
//!
//! Both dispositions were chosen by the 5-agent adversarial vote `4d3ea1c5`
//! (A-with-reporting, unanimous). The GATING invariant (vote lens 5): the
//! forget/archive covenant gates run BEFORE the same-id idempotent skip, so it
//! can never resurrect a forgotten / genuinely-archived id — pinned below.

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
        .join("issue-2569-2570-roundtrip")
        .join(tag);
    std::fs::create_dir_all(&root).ok();
    root
}

fn fresh_db(tag: &str) -> (PathBuf, Connection) {
    let dir = tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(scratch_root(tag))
        .expect("tempdir under .local-runs");
    let path = dir.path().join("db.sqlite");
    let conn = ai_memory::db::open(&path).expect("init db");
    std::mem::forget(dir); // keep the file alive for the test's connection
    (path, conn)
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
        db_schema_version: 0, // 0 <= any dst schema, so the newer-producer gate never fires
        source: "issue-2569-2570-test".into(),
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

fn opts() -> ImportOptions {
    ImportOptions {
        caller_agent_id: "ai:importer".into(),
        ..ImportOptions::default()
    }
}

/// v1.0.0 #2570 — the SHARED archive-lifecycle predicate. An `in_place_edit`
/// snapshot of a STILL-LIVE row is NOT a genuine archival; a real archival is.
#[test]
fn memory_is_genuinely_archived_discriminates_in_place_edit_2570() {
    let (_path, conn) = fresh_db("predicate");

    // (a) An edited-but-live row: insert, then edit in place → #1725 snapshots
    // the prior content under archive_reason='in_place_edit' while the live row
    // survives in `memories`.
    ai_memory::db::insert(&conn, &mem("edited", "t-edit", "ns", "v1")).expect("insert");
    let (changed, _) = ai_memory::db::update(
        &conn,
        "edited",
        None,
        Some("v2"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("in-place edit");
    assert!(changed, "the in-place content edit landed");

    // The snapshot exists (so the un-discriminating `memory_is_archived` is
    // true), but it is NOT a genuine archival, and the live row is still there.
    assert!(
        ai_memory::db::memory_is_archived(&conn, "edited").expect("probe"),
        "the in_place_edit snapshot is present in archived_memories",
    );
    assert!(
        !ai_memory::db::memory_is_genuinely_archived(&conn, "edited").expect("probe"),
        "#2570: an in_place_edit snapshot must NOT count as a genuine archival",
    );
    assert!(
        ai_memory::db::memory_exists(&conn, "edited").expect("probe"),
        "the edited row is still LIVE",
    );

    // (b) A genuinely-archived row: insert then archive (operator reason).
    ai_memory::db::insert(&conn, &mem("archived", "t-arch", "ns", "c")).expect("insert");
    assert!(
        ai_memory::db::archive_memory(&conn, "archived", Some("explicit")).expect("archive"),
        "operator archive",
    );
    assert!(
        ai_memory::db::memory_is_genuinely_archived(&conn, "archived").expect("probe"),
        "#2570: a real archival (reason != in_place_edit) still blocks re-admission",
    );
    assert!(
        !ai_memory::db::memory_exists(&conn, "archived").expect("probe"),
        "a genuinely-archived row is no longer live",
    );
}

/// v1.0.0 #2569 — the durable-divergence predicate keys on title/content only,
/// never metadata (the restamp mutates `metadata.agent_id` on every self-restore).
#[test]
fn imported_row_diverges_ignores_metadata_2569() {
    let a = mem("id", "T", "ns", "same content");
    let mut b = mem("id", "T", "ns", "same content");
    // A different agent_id in metadata (what the default restamp produces) is
    // NOT divergence.
    b.metadata =
        serde_json::json!({ "agent_id": "ai:someone-else", "imported_from_agent_id": AUTHOR });
    assert!(
        !ai_memory::db::imported_row_diverges(&a, &b),
        "#2569: differing metadata must not read as content divergence",
    );

    let c = mem("id", "T", "ns", "DIFFERENT content");
    assert!(
        ai_memory::db::imported_row_diverges(&a, &c),
        "#2569: differing durable content IS divergence",
    );
    let d = mem("id", "DIFFERENT title", "ns", "same content");
    assert!(
        ai_memory::db::imported_row_diverges(&a, &d),
        "#2569: differing title IS divergence",
    );
}

/// ★ #2570 + #2569 end-to-end (v2 funnel): export a corpus, EDIT a row in
/// place, then re-import its own export onto the SAME corpus. The edited row is
/// ADMITTED (not covenant-skipped) and is an idempotent no-op — never a
/// UNIQUE-id refusal, never a clobber.
#[test]
fn v2_reimport_of_edited_corpus_is_idempotent_2569_2570() {
    let (_path, conn) = fresh_db("v2-edited");

    // Seed a corpus of 3 rows, then edit ONE in place (in_place_edit snapshot).
    for i in 0..3 {
        ai_memory::db::insert(
            &conn,
            &mem(&format!("m{i}"), &format!("t{i}"), "ns", &format!("c{i}")),
        )
        .expect("seed");
    }
    let (changed, _) = ai_memory::db::update(
        &conn,
        "m1",
        None,
        Some("c1-edited"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("edit");
    assert!(changed);
    assert!(
        ai_memory::db::memory_is_archived(&conn, "m1").expect("probe"),
        "precondition: the edit created an in_place_edit snapshot",
    );

    // The "current export": every live row, m1 carrying its EDITED content.
    let env = envelope_with(vec![
        mem("m0", "t0", "ns", "c0"),
        mem("m1", "t1", "ns", "c1-edited"),
        mem("m2", "t2", "ns", "c2"),
    ]);

    let report = import_full_envelope(&conn, &env, &opts()).expect("re-import");

    assert_eq!(
        report.archived_skipped, 0,
        "#2570: the edited-but-live row is NOT covenant-skipped as archived",
    );
    assert_eq!(
        report.memories, 0,
        "#2569: nothing was newly written — every id already exists",
    );
    assert_eq!(
        report.idempotent_skipped, 3,
        "#2569: all three already-present rows are idempotent no-ops",
    );
    assert!(report.committed);

    // The durable rows are untouched (never overwritten): m1 keeps its edit.
    assert_eq!(
        ai_memory::db::get(&conn, "m1")
            .expect("get")
            .expect("row")
            .content,
        "c1-edited",
        "#2878: the durable live row is never clobbered on re-import",
    );
    // No duplicate rows were manufactured under suffixed titles.
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count");
    assert_eq!(n, 3, "#2569: an idempotent re-import creates zero new rows");
}

/// A genuinely gc/operator-archived id stays covenant-skipped on re-import
/// (the #2570 fix narrows the gate WITHOUT re-opening resurrection), and a
/// dest-forgotten id stays refused — both covenant gates run BEFORE the
/// same-id idempotent skip (vote lens 5 gating invariant).
#[test]
fn v2_covenant_gates_precede_idempotent_skip_2569_2570() {
    let (_path, conn) = fresh_db("v2-covenant");

    // (a) genuinely archived id.
    ai_memory::db::insert(&conn, &mem("arch", "t-arch", "ns", "c")).expect("insert");
    assert!(ai_memory::db::archive_memory(&conn, "arch", Some("explicit")).expect("archive"));

    // (b) dest-forgotten id (tombstone).
    ai_memory::db::insert(&conn, &mem("forg", "t-forg", "ns-forget", "c")).expect("insert");
    assert_eq!(
        ai_memory::db::forget(&conn, Some("ns-forget"), None, None, false).expect("forget"),
        1,
    );

    let env = envelope_with(vec![
        mem("arch", "t-arch", "ns", "c"),
        mem("forg", "t-forg", "ns-forget", "c"),
    ]);
    let report = import_full_envelope(&conn, &env, &opts()).expect("re-import");

    assert_eq!(
        report.archived_skipped, 1,
        "#2570: a REAL archival still blocks re-admission"
    );
    assert_eq!(
        report.tombstoned_skipped, 1,
        "the forget tombstone still forbids resurrection"
    );
    assert_eq!(
        report.idempotent_skipped, 0,
        "neither reached the same-id idempotent path"
    );
    assert_eq!(report.memories, 0, "no covenant-gated id was re-admitted");

    assert!(
        ai_memory::db::get(&conn, "arch").expect("get").is_none(),
        "the archived id did not come back live",
    );
    assert!(
        ai_memory::db::get(&conn, "forg").expect("get").is_none(),
        "the forgotten id did not resurrect",
    );
}

/// A same-id re-import whose DURABLE content diverges from the live row is
/// still an idempotent no-op (never a clobber), but surfaces a WARNING so the
/// divergent backup is not silently swallowed (vote: A-with-reporting).
#[test]
fn v2_divergent_same_id_reimport_warns_and_never_clobbers_2569() {
    let (_path, conn) = fresh_db("v2-divergent");

    ai_memory::db::insert(&conn, &mem("z", "tz", "ns", "LIVE content")).expect("insert");

    // Byte-identical re-import → clean no-op, NO divergence warning.
    let env_same = envelope_with(vec![mem("z", "tz", "ns", "LIVE content")]);
    let r1 = import_full_envelope(&conn, &env_same, &opts()).expect("re-import same");
    assert_eq!(r1.idempotent_skipped, 1);
    assert!(
        !r1.warnings.iter().any(|w| w.contains("content differs")),
        "a byte-identical re-import must NOT warn: {:?}",
        r1.warnings,
    );

    // A DIVERGENT backup (older content) → still idempotent-skipped, but warned.
    let env_diff = envelope_with(vec![mem("z", "tz", "ns", "OLD backup content")]);
    let r2 = import_full_envelope(&conn, &env_diff, &opts()).expect("re-import diverged");
    assert_eq!(
        r2.idempotent_skipped, 1,
        "#2569: a diverged same-id row is still a no-op"
    );
    assert!(
        r2.warnings.iter().any(|w| w.contains("content differs")),
        "#2569: a divergent backup must surface a warning: {:?}",
        r2.warnings,
    );

    // The durable live row is NEVER overwritten by the older backup.
    assert_eq!(
        ai_memory::db::get(&conn, "z")
            .expect("get")
            .expect("row")
            .content,
        "LIVE content",
        "#2878: the durable row wins — the older backup never clobbers it",
    );
}
