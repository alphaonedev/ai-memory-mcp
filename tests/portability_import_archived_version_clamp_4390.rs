// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::doc_markdown)]

//! #4390 — the bundle `archived_memories[]` import lane (sqlite; the import
//! path is not shared with postgres) stored the bundle's remote-asserted
//! `version` unclamped. An archived row imported at 2^62, restored and edited
//! locally landed at 2^62 + 1, which every peer's receive validation refuses
//! (the #4373 divergence class through another entry point). The version is
//! clamped exactly as the federation merge funnels clamp it.

use std::collections::BTreeMap;

use ai_memory::models::replicated_version::{MAX_INBOUND_VERSION_REFUSAL, MAX_REPLICATED_VERSION};
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::portability::dto::ArchivedMemoryDto;
use ai_memory::portability::emit::{ExportEnvelope, SPEC_VERSION_V2};
use ai_memory::portability::import::{ImportOptions, import_full_envelope};

const AUTHOR: &str = "ai:archived-author-4390";

fn archived_dto(id: &str, version: i64) -> ArchivedMemoryDto {
    let now = "2026-07-20T00:00:00+00:00".to_string();
    let memory = Memory {
        id: id.into(),
        tier: Tier::Long,
        namespace: "portability-4390".into(),
        title: format!("archived snapshot {id}"),
        content: "archived text".into(),
        source: "system".into(),
        priority: 5,
        confidence: 1.0,
        created_at: now.clone(),
        updated_at: now,
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": AUTHOR }),
        version,
        ..Memory::default()
    };
    ArchivedMemoryDto {
        memory,
        archived_at: "2026-07-21T00:00:00+00:00".into(),
        archive_reason: "ttl_expired".into(),
        original_tier: None,
        original_expires_at: None,
        embedding: None,
        embedding_dim: None,
        embedding_space: None,
        atomised_into: None,
        atom_of: None,
        mentioned_entity_id: None,
        kind_provenance: None,
    }
}

fn envelope(rows: Vec<ArchivedMemoryDto>) -> ExportEnvelope {
    ExportEnvelope {
        spec_version: SPEC_VERSION_V2.to_string(),
        db_schema_version: 0,
        source: "issue-4390-test".into(),
        exported_at: "2026-07-21T00:00:00+00:00".into(),
        memories: Vec::new(),
        links: Vec::new(),
        signed_events: Vec::new(),
        memory_revisions: Vec::new(),
        forget_tombstones: Vec::new(),
        agent_lineage: Vec::new(),
        model_attestations: Vec::new(),
        governance_rules: Vec::new(),
        trust_anchors: Vec::new(),
        archived_memories: rows,
        namespace_meta: Vec::new(),
        archived_memory_links: Vec::new(),
        portability_complete: false,
        conformance_level: "L1".into(),
        conformance_by_class: BTreeMap::new(),
        count: 0,
    }
}

fn open() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("open");
    (dir, conn)
}

fn import(conn: &rusqlite::Connection, id: &str, version: i64) {
    let opts = ImportOptions {
        trust_source: true,
        caller_agent_id: AUTHOR.into(),
        ..ImportOptions::default()
    };
    let report = import_full_envelope(conn, &envelope(vec![archived_dto(id, version)]), &opts)
        .expect("import");
    assert_eq!(report.archived_memories, 1, "the archived row lands");
}

fn archived_version(conn: &rusqlite::Connection, id: &str) -> i64 {
    conn.query_row(
        "SELECT version FROM archived_memories WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .expect("archived version")
}

#[test]
fn archived_import_far_above_the_clamp_is_clamped_and_the_honest_edit_replicates_4390() {
    let (_dir, conn) = open();
    let id = "arch-4390-high";
    import(&conn, id, MAX_INBOUND_VERSION_REFUSAL);
    assert!(
        archived_version(&conn, id) <= MAX_REPLICATED_VERSION,
        "#4390: the bundle's remote-asserted version must be clamped on import"
    );
    assert!(ai_memory::db::restore_archived(&conn, id).expect("restore"));
    let restored = ai_memory::db::get_any(&conn, id)
        .expect("read")
        .expect("row");
    assert!(
        restored.version <= MAX_REPLICATED_VERSION,
        "restored at the clamp"
    );
    // An honest local edit, as If-Match would send it.
    ai_memory::db::update_with_expected_version(
        &conn,
        id,
        None,
        Some("honest edit"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(restored.version),
        None,
    )
    .expect("edit");
    let edited = ai_memory::db::get_any(&conn, id)
        .expect("read")
        .expect("row");
    assert!(
        ai_memory::validate::validate_memory(&edited).is_ok(),
        "#4390: every peer must still accept the honest edit of a restored row (version {})",
        edited.version
    );
}

#[test]
fn archived_import_inside_the_clamp_keeps_its_version_4390() {
    let (_dir, conn) = open();
    import(&conn, "arch-4390-ok", 41);
    assert_eq!(archived_version(&conn, "arch-4390-ok"), 41);
}
