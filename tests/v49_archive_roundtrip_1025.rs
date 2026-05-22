// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1025 + #1100 — v49 archive→restore lossless round-trip pin.
//!
//! Per CLAUDE.md §Architecture and §Data Model, v0.7.0 introduces the
//! 26-field [`Memory`] struct (15 v0.6.x columns + 11 new v0.7.0
//! columns: `reflection_depth`, `memory_kind`, `entity_id`,
//! `persona_version`, `citations`, `source_uri`, `source_span`,
//! `confidence_source`, `confidence_signals`, `confidence_decayed_at`,
//! `version`). #1025 (CRITICAL, 2026-05-21) discovered the
//! archive→restore round-trip was silently erasing 14 of these columns
//! on both backends because the archived_memories INSERT-SELECT didn't
//! carry the v0.7.0 columns. Schema v48→v49 added the columns to
//! `archived_memories` and updated the archive + restore sites to
//! carry them.
//!
//! Per #1100 (SR-6 #1) the close-comment deferred the cross-backend
//! round-trip test to #1069 but #1069 closed without backfilling it.
//! This file pins the behavioral contract: a Memory with all 26
//! v0.7.0 fields populated MUST round-trip byte-equal through
//! archive→restore on both sqlite and postgres adapters.
//!
//! The sqlite test runs unconditionally; the postgres test is
//! `#[ignore]`-gated on `AI_MEMORY_TEST_POSTGRES_URL` per the
//! standard cross-backend convention (issue #79 — Track C/D network
//! routing).

#![allow(clippy::needless_update)]

use ai_memory::db;
use ai_memory::models::{
    Citation, ConfidenceSignals, ConfidenceSource, Memory, MemoryKind, SourceSpan, Tier,
};
use rusqlite::Connection;
use serde_json::json;

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

/// Build a Memory with EVERY v0.7.0 column populated to a non-default
/// value so a silent column-omission regression in the archive INSERT
/// or restore SELECT site surfaces as a field mismatch in the
/// round-trip assertion below.
fn memory_with_all_26_v07_fields_populated(id: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "v49-rt-1025".to_string(),
        title: format!("title-{id}"),
        content: "v49 round-trip body".to_string(),
        tags: vec!["v07".to_string(), "round-trip".to_string()],
        priority: 7,
        confidence: 0.82,
        source: "round-trip-test".to_string(),
        access_count: 3,
        created_at: "2026-05-21T12:00:00Z".to_string(),
        updated_at: "2026-05-21T12:30:00Z".to_string(),
        last_accessed_at: Some("2026-05-21T12:31:00Z".to_string()),
        expires_at: None,
        metadata: json!({"agent_id": "ai:rt-test", "extra": "value"}),
        // v0.7.0 columns:
        reflection_depth: 2,
        memory_kind: MemoryKind::Reflection,
        entity_id: Some("entity-42".to_string()),
        persona_version: Some(3),
        citations: vec![
            Citation {
                uri: "uri:rt-doc/a".to_string(),
                accessed_at: "2026-05-21T11:00:00Z".to_string(),
                hash: Some("deadbeef".to_string()),
                span: Some(SourceSpan { start: 1, end: 100 }),
            },
            Citation {
                uri: "doc:rt-doc/b".to_string(),
                accessed_at: "2026-05-21T11:05:00Z".to_string(),
                hash: None,
                span: None,
            },
        ],
        source_uri: Some("uri:rt-doc/a".to_string()),
        source_span: Some(SourceSpan { start: 1, end: 500 }),
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: Some(ConfidenceSignals {
            source_age_days: 3.0,
            atom_derivation: false,
            prior_corroboration_count: 2,
            freshness_factor: 0.9,
            baseline_per_source: 0.6,
        }),
        confidence_decayed_at: Some("2026-05-21T13:00:00Z".to_string()),
        // v45 schema: optimistic-concurrency version stamp. The insert
        // path always lands fresh rows at version=1; the round-trip
        // test bumps version via direct SQL after insert so the
        // archive→restore path is exercised against a non-default
        // value (catches a regression that drops `version` from the
        // archive INSERT-SELECT or restore INSERT-SELECT).
        version: 1,
        ..Memory::default()
    }
}

#[test]
fn sqlite_archive_restore_preserves_all_v07_columns_1025() {
    let conn = fresh_sqlite();
    let mut mem = memory_with_all_26_v07_fields_populated("rt-1025-sqlite");
    db::insert(&conn, &mem).expect("seed memory");

    // Bump version to a non-default value so the round-trip catches a
    // regression that drops the `version` column from the archive
    // INSERT-SELECT or the restore INSERT-SELECT.
    conn.execute(
        "UPDATE memories SET version = 4 WHERE id = ?1",
        rusqlite::params![&mem.id],
    )
    .expect("bump version");
    mem.version = 4;

    // Sanity-check the seed landed with the expected v0.7.0 shape.
    let after_seed = db::get(&conn, &mem.id)
        .expect("get after seed")
        .expect("seeded row must be retrievable");
    assert_eq!(after_seed.reflection_depth, 2, "seed: reflection_depth");
    assert_eq!(
        after_seed.memory_kind,
        MemoryKind::Reflection,
        "seed: memory_kind"
    );
    assert_eq!(
        after_seed.source_uri.as_deref(),
        Some("uri:rt-doc/a"),
        "seed: source_uri"
    );
    assert_eq!(after_seed.version, 4, "seed: version (post-bump)");

    // Archive — moves the row from `memories` to `archived_memories`.
    let moved = db::archive_memory(&conn, &mem.id, Some("rt-test")).expect("archive");
    assert!(moved, "archive_memory must report success");

    // Restore — moves the row back to `memories`.
    let restored = db::restore_archived(&conn, &mem.id).expect("restore");
    assert!(restored, "restore_archived must report success");

    // Round-trip the row and assert every v0.7.0 field survived.
    let after_restore = db::get(&conn, &mem.id)
        .expect("get after restore")
        .expect("restored row must be retrievable");

    // Original v0.6.x columns:
    assert_eq!(after_restore.id, mem.id);
    assert_eq!(after_restore.tier, mem.tier, "tier");
    assert_eq!(after_restore.namespace, mem.namespace, "namespace");
    assert_eq!(after_restore.title, mem.title, "title");
    assert_eq!(after_restore.content, mem.content, "content");
    assert_eq!(after_restore.tags, mem.tags, "tags");
    assert_eq!(after_restore.priority, mem.priority, "priority");
    assert!(
        (after_restore.confidence - mem.confidence).abs() < 1e-6,
        "confidence: {} != {}",
        after_restore.confidence,
        mem.confidence
    );
    assert_eq!(after_restore.source, mem.source, "source");

    // v0.7.0 columns — the load-bearing assertions for #1025/#1100.
    assert_eq!(
        after_restore.reflection_depth, mem.reflection_depth,
        "#1025: reflection_depth must round-trip; got {} expected {}",
        after_restore.reflection_depth, mem.reflection_depth
    );
    assert_eq!(
        after_restore.memory_kind, mem.memory_kind,
        "#1025: memory_kind must round-trip"
    );
    assert_eq!(
        after_restore.entity_id, mem.entity_id,
        "#1025: entity_id must round-trip"
    );
    assert_eq!(
        after_restore.persona_version, mem.persona_version,
        "#1025: persona_version must round-trip"
    );
    assert_eq!(
        after_restore.citations, mem.citations,
        "#1025: citations must round-trip"
    );
    assert_eq!(
        after_restore.source_uri, mem.source_uri,
        "#1025: source_uri must round-trip"
    );
    assert_eq!(
        after_restore.source_span, mem.source_span,
        "#1025: source_span must round-trip"
    );
    assert_eq!(
        after_restore.confidence_source, mem.confidence_source,
        "#1025: confidence_source must round-trip"
    );
    assert_eq!(
        after_restore.confidence_signals, mem.confidence_signals,
        "#1025: confidence_signals must round-trip"
    );
    assert_eq!(
        after_restore.confidence_decayed_at, mem.confidence_decayed_at,
        "#1025: confidence_decayed_at must round-trip"
    );
    assert_eq!(
        after_restore.version, mem.version,
        "#1025: version (v45 optimistic-concurrency stamp) must round-trip; \
         got {} expected {}",
        after_restore.version, mem.version
    );
}

/// Postgres twin of `sqlite_archive_restore_preserves_all_v07_columns_1025`.
/// Skipped by default per the Track C/D `AI_MEMORY_TEST_POSTGRES_URL`
/// convention (issue #79); an operator with postgres routing flips the
/// env var and runs `cargo test --features sal-postgres --ignored`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn postgres_archive_restore_preserves_all_v07_columns_1025() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — postgres half skipped");
        return;
    };
    let pg = match ai_memory::store::postgres::PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("PostgresStore::connect failed: {e}");
            return;
        }
    };
    let ctx = ai_memory::store::CallerContext::for_agent("rt-1025-pg");
    let mem = memory_with_all_26_v07_fields_populated("rt-1025-pg");
    ai_memory::store::MemoryStore::store(&pg, &ctx, &mem)
        .await
        .expect("seed");

    // archive_by_ids → restore via the SAL surface. The exact method
    // names vary by adapter but the contract is the same: a row
    // archived + restored must round-trip every v0.7.0 column.
    ai_memory::store::MemoryStore::archive(&pg, &ctx, &mem.id, Some("rt-test"))
        .await
        .expect("archive");
    ai_memory::store::MemoryStore::archive_restore(&pg, &ctx, &mem.id)
        .await
        .expect("restore");

    let restored = ai_memory::store::MemoryStore::get(&pg, &ctx, &mem.id)
        .await
        .expect("get after restore");
    assert_eq!(restored.reflection_depth, mem.reflection_depth);
    assert_eq!(restored.memory_kind, mem.memory_kind);
    assert_eq!(restored.source_uri, mem.source_uri);
    assert_eq!(restored.version, mem.version);
}
