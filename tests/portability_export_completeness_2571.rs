// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2571 — neither export mode carried `archived_memories` or
//! `namespace_meta` (nor the v70 `archived_memory_links` archive-link
//! snapshot), so an `export --full` -> `import` round-trip silently
//! dropped archived rows and every namespace's governance binding.
//!
//! 5-agent adversarial vote `17aa4567` (UNANIMOUS on structure): extend the
//! EXISTING v2 `ExportEnvelope` with three additive optional arrays
//! (`spec_version` stays `"2"`) — the v1 spec (`docs/spec/v1.md` §6.1
//! `namespaces[]` / §6.4 `archived[]`) already froze these classes' shapes,
//! and PORTABILITY-V2.md §V2-4 claims "all v1 members are retained"; the
//! `ExportEnvelope` struct simply never implemented that promise until now
//! (a conformance bug, not a design gap). Mechanically identical to the
//! pattern #2006 already used 7x for the signed-record arrays.
//!
//! These tests drive the REAL end-to-end path — `emit::build_full_envelope`
//! on a seeded source DB, `import::import_full_envelope` into a fresh
//! destination — not a hand-built envelope, so the export confidentiality
//! screen (issue #2571's security corollary: `list_archive`/`restore` are
//! admin-authorization-gated only with ZERO content screening, but
//! `export --full` has no such gate) and the import dual-residency guard
//! are both exercised, not merely the wire-shape.
//!
//! Scope note: the v2 envelope (`export --full` / `import_full_envelope`) is
//! STRUCTURALLY sqlite-only today — `export --full` already refuses a
//! postgres-backed store (the pre-existing #2444/#2490 `backup`-style
//! refusal), and `import_full_envelope` takes `conn: &rusqlite::Connection`
//! with no postgres call site anywhere in the codebase (confirmed by
//! survey before implementing). There is therefore no live-postgres leg for
//! THIS fix to exercise — the v2 envelope has never had one, on either side
//! of this change.

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

use std::path::PathBuf;

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::portability::emit;
use ai_memory::portability::import::{ImportOptions, import_full_envelope};
use rusqlite::Connection;

fn scratch_root(tag: &str) -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2571-export-completeness")
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

fn opts() -> ImportOptions {
    ImportOptions {
        caller_agent_id: "ai:importer".into(),
        ..ImportOptions::default()
    }
}

fn mem(id: &str, title: &str, ns: &str, content: &str) -> Memory {
    let now = "2026-08-11T00:00:00Z".to_string();
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
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:author" }),
        ..Memory::default()
    }
}

/// #2571 — the CORE regression: a corpus with an archived memory AND a
/// namespace governance standard round-trips losslessly through
/// `export --full` -> `import` (the exact defect reproduction from the
/// issue body, driven through the production code paths).
#[test]
fn archived_memories_and_namespace_meta_survive_export_full_round_trip() {
    let (_src_path, src) = fresh_db("src-corpus");

    // Seed a live memory, then archive it (a GENUINE archival, distinct
    // from #2570's `in_place_edit` live-snapshot exception) so it lands in
    // `archived_memories`.
    ai_memory::storage::insert(
        &src,
        &mem(
            "m-archived-1",
            "archived title",
            "team/eng",
            "archived content",
        ),
    )
    .expect("seed live memory");
    ai_memory::storage::archive_memory(&src, "m-archived-1", Some("manual"))
        .expect("archive memory");

    // Seed a namespace governance binding — `standard_id` must reference an
    // existing memory (`set_namespace_standard` validates it).
    ai_memory::storage::insert(&src, &mem("std-mem-1", "standard", "team/eng", "policy"))
        .expect("seed standard-carrying memory");
    ai_memory::storage::set_namespace_standard(&src, "team/eng", "std-mem-1", None)
        .expect("seed namespace standard");

    // Build the REAL v2 envelope from the source.
    let env = emit::build_full_envelope(&src, "issue-2571-test", "2026-08-11T00:00:00Z")
        .expect("build full v2 envelope");
    assert_eq!(
        env.archived_memories.len(),
        1,
        "the archived row must be exported"
    );
    assert_eq!(
        env.namespace_meta.len(),
        1,
        "the namespace governance binding must be exported"
    );
    assert_eq!(env.archived_memories[0].memory.id, "m-archived-1");
    assert_eq!(env.archived_memories[0].archive_reason, "manual");
    assert_eq!(env.namespace_meta[0].namespace, "team/eng");
    assert_eq!(
        env.namespace_meta[0].standard_id.as_deref(),
        Some("std-mem-1")
    );
    // The new classes must be visible in the honesty machinery too.
    assert_eq!(
        env.conformance_by_class
            .get("archived_memories")
            .map(String::as_str),
        Some("L1")
    );
    assert_eq!(
        env.conformance_by_class
            .get("namespace_meta")
            .map(String::as_str),
        Some("L1")
    );

    // Import into a FRESH destination.
    let (_dst_path, dst) = fresh_db("dst-corpus");
    let report = import_full_envelope(&dst, &env, &opts()).expect("import full v2 envelope");
    assert_eq!(
        report.archived_memories, 1,
        "the archived row must be imported"
    );
    assert_eq!(
        report.namespace_meta, 1,
        "the namespace binding must be imported"
    );
    assert_eq!(report.archived_memories_skipped_dual_residency, 0);

    // The archived row must be present at the destination, NOT live.
    assert!(
        ai_memory::storage::get(&dst, "m-archived-1")
            .expect("probe live")
            .is_none(),
        "an archived-only row must NOT be admitted live"
    );
    let dst_archived =
        ai_memory::portability::read::read_all_archived_memories(&dst).expect("read dst archived");
    assert_eq!(dst_archived.len(), 1);
    assert_eq!(dst_archived[0].memory.id, "m-archived-1");
    assert_eq!(dst_archived[0].memory.title, "archived title");
    assert_eq!(dst_archived[0].memory.content, "archived content");
    assert_eq!(dst_archived[0].archive_reason, "manual");

    // The namespace governance binding must be present at the destination.
    let dst_ns = ai_memory::portability::read::read_all_namespace_meta(&dst)
        .expect("read dst namespace_meta");
    assert_eq!(dst_ns.len(), 1);
    assert_eq!(dst_ns[0].namespace, "team/eng");
    assert_eq!(dst_ns[0].standard_id.as_deref(), Some("std-mem-1"));
}

/// #2571 — the v70 (#1771) archive-link snapshot: a memory's links,
/// preserved at the moment it was archived, must also survive the
/// export/import round-trip so a destination `archive restore` can
/// re-attach them.
#[test]
fn archived_memory_links_survive_export_full_round_trip() {
    let (_src_path, src) = fresh_db("src-links");

    ai_memory::storage::insert(&src, &mem("m-a", "a", "ns", "content a")).expect("seed a");
    ai_memory::storage::insert(&src, &mem("m-b", "b", "ns", "content b")).expect("seed b");
    ai_memory::storage::create_link(&src, "m-a", "m-b", "related_to").expect("link a->b");
    ai_memory::storage::archive_memory(&src, "m-a", Some("manual")).expect("archive a");

    let env = emit::build_full_envelope(&src, "issue-2571-links-test", "2026-08-11T00:00:00Z")
        .expect("build full v2 envelope");
    assert_eq!(
        env.archived_memory_links.len(),
        1,
        "the archive-link snapshot must be exported"
    );
    assert_eq!(env.archived_memory_links[0].source_id, "m-a");
    assert_eq!(env.archived_memory_links[0].target_id, "m-b");

    let (_dst_path, dst) = fresh_db("dst-links");
    let report = import_full_envelope(&dst, &env, &opts()).expect("import full v2 envelope");
    assert_eq!(
        report.archived_memory_links, 1,
        "the archive-link snapshot must be imported"
    );
    let dst_links = ai_memory::portability::read::read_all_archived_memory_links(&dst)
        .expect("read dst archived links");
    assert_eq!(dst_links.len(), 1);
    assert_eq!(dst_links[0].source_id, "m-a");
    assert_eq!(dst_links[0].target_id, "m-b");
}

/// #2571 back-compat (T4 crossroads back-compat requirement, per the
/// 5-agent vote): an OLD v2 envelope produced by a pre-#2571 binary — with
/// no `archived_memories` / `namespace_meta` / `archived_memory_links` keys
/// at all — must still import cleanly on the FIXED binary via serde
/// defaults, never a parse refusal.
#[test]
fn pre_2571_envelope_missing_the_new_arrays_still_imports() {
    let old_shape_json = serde_json::json!({
        "spec_version": "2",
        "db_schema_version": 0,
        "source": "pre-2571-producer",
        "exported_at": "2026-01-01T00:00:00Z",
        "memories": [],
        "links": [],
        "portability_complete": false,
        "conformance_level": "L1",
        "conformance_by_class": {},
        "count": 0
    })
    .to_string();
    let env: emit::ExportEnvelope =
        serde_json::from_str(&old_shape_json).expect("an old-shape v2 envelope must still parse");
    assert!(env.archived_memories.is_empty());
    assert!(env.namespace_meta.is_empty());
    assert!(env.archived_memory_links.is_empty());

    let (_dst_path, dst) = fresh_db("dst-oldshape");
    let report = import_full_envelope(&dst, &env, &opts()).expect("old-shape envelope imports");
    assert_eq!(report.archived_memories, 0);
    assert_eq!(report.namespace_meta, 0);
    assert_eq!(report.archived_memory_links, 0);
}

/// #2571 / #2570-adjacent — an archived row must NEVER be admitted when the
/// SAME id is currently LIVE at the destination under a GENUINE archive
/// reason (would create illegal dual residency: the id in both `memories`
/// and `archived_memories` for a reason other than the #2570
/// `in_place_edit` exception).
#[test]
fn archived_memory_import_refuses_dual_residency_for_genuine_archival() {
    let (_src_path, src) = fresh_db("src-dual");
    ai_memory::storage::insert(&src, &mem("m-dual", "t", "ns", "c")).expect("seed live");
    ai_memory::storage::archive_memory(&src, "m-dual", Some("manual")).expect("archive");
    let env = emit::build_full_envelope(&src, "issue-2571-dual-test", "2026-08-11T00:00:00Z")
        .expect("build envelope");
    assert_eq!(env.archived_memories.len(), 1);

    // The DESTINATION already has the SAME id LIVE (unrelated to the
    // source's archive event) — admitting the archived row would create
    // dual residency.
    let (_dst_path, dst) = fresh_db("dst-dual");
    ai_memory::storage::insert(&dst, &mem("m-dual", "t", "ns", "c")).expect("seed dest live");

    let report = import_full_envelope(&dst, &env, &opts()).expect("import");
    assert_eq!(
        report.archived_memories, 0,
        "the archived row must be skipped, not admitted"
    );
    assert_eq!(report.archived_memories_skipped_dual_residency, 1);
    assert!(
        ai_memory::storage::get(&dst, "m-dual")
            .expect("probe live")
            .is_some(),
        "the destination's own live row must be untouched"
    );
    let dst_archived =
        ai_memory::portability::read::read_all_archived_memories(&dst).expect("read dst archived");
    assert!(
        dst_archived.is_empty(),
        "no archived row should have been admitted"
    );
}
