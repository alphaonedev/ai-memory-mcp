// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1029 + #1109 — postgres `apply_remote_memory` 26-column
//! round-trip + `GREATEST(version)` newer-wins pin.
//!
//! The #1029 close-comment cited the cross-backend regression test as
//! a #1069 follow-up that never landed. This file backfills it.
//!
//! `#[ignore]`-gated on `AI_MEMORY_TEST_POSTGRES_URL` per the standard
//! Track C/D blocker (issue #79 — 192.168.50.100 ↔ 192.168.1.50
//! subnet routing). An operator with postgres routing flips the env
//! var and runs `cargo test --features sal-postgres --ignored`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use ai_memory::models::{
    Citation, ConfidenceSignals, ConfidenceSource, Memory, MemoryKind, SourceSpan, Tier,
};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;
use serde_json::json;

async fn live_pg() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!(
                "skipping postgres parity verify: PostgresStore::connect failed: {e}\n\
                 (test-infra blocker per issue #79 — 192.168.50.100 ↔ 192.168.1.50 routing)"
            );
            None
        }
    }
}

fn full_v07_memory(id: &str, version: i64) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "apply-remote-1029".to_string(),
        title: format!("title-{id}"),
        content: "26-col federation roundtrip body".to_string(),
        tags: vec!["v07".to_string()],
        priority: 7,
        confidence: 0.85,
        source: "federation".to_string(),
        access_count: 0,
        created_at: "2026-05-21T10:00:00Z".to_string(),
        updated_at: "2026-05-21T11:00:00Z".to_string(),
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:remote-peer"}),
        reflection_depth: 1,
        memory_kind: MemoryKind::Reflection,
        entity_id: Some("entity-42".to_string()),
        persona_version: Some(2),
        citations: vec![Citation {
            uri: "uri:remote/a".to_string(),
            accessed_at: "2026-05-21T10:00:00Z".to_string(),
            hash: Some("abc123".to_string()),
            span: Some(SourceSpan { start: 0, end: 100 }),
        }],
        source_uri: Some("uri:remote/a".to_string()),
        source_span: Some(SourceSpan { start: 0, end: 200 }),
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: Some(ConfidenceSignals {
            source_age_days: 5.0,
            atom_derivation: false,
            prior_corroboration_count: 1,
            freshness_factor: 0.8,
            baseline_per_source: 0.6,
        }),
        confidence_decayed_at: None,
        version,
        ..Memory::default()
    }
}

/// v0.7.0 #1029 + #1109 — apply_remote_memory MUST preserve all 26
/// v0.7.0 Memory columns through the federation INSERT path.
///
/// Pre-#1029 the postgres INSERT-SELECT carried only the v0.6.x
/// 15-field shape; Form-4 (citations + source_uri + source_span),
/// Form-5 (confidence_*), QW-2 (entity_id + persona_version), and
/// the v45 `version` column were silently dropped on federation
/// replication. The fix wires every column through; this pin guards
/// against a future regression that drops a column from the SET
/// clause of the ON CONFLICT DO UPDATE branch.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn apply_remote_memory_preserves_all_26_columns_1029() {
    let Some(pg) = live_pg().await else {
        return;
    };
    let ctx = ai_memory::store::CallerContext::for_admin("federation-test-1029");
    let mem = full_v07_memory("pg-1029-roundtrip", 3);
    pg.apply_remote_memory(&ctx, &mem)
        .await
        .expect("apply_remote_memory");

    let got = MemoryStore::get(&pg, &ctx, &mem.id)
        .await
        .expect("get after apply_remote");
    assert_eq!(
        got.reflection_depth, mem.reflection_depth,
        "reflection_depth"
    );
    assert_eq!(got.memory_kind, mem.memory_kind, "memory_kind");
    assert_eq!(got.entity_id, mem.entity_id, "entity_id");
    assert_eq!(got.persona_version, mem.persona_version, "persona_version");
    assert_eq!(got.citations, mem.citations, "citations");
    assert_eq!(got.source_uri, mem.source_uri, "source_uri");
    assert_eq!(got.source_span, mem.source_span, "source_span");
    assert_eq!(
        got.confidence_source, mem.confidence_source,
        "confidence_source"
    );
    assert_eq!(got.version, mem.version, "version");
}

/// v0.7.0 #1029 + #1109 — `GREATEST(version, EXCLUDED.version)` pin
/// for out-of-order federation pushes. Two apply_remote calls with
/// versions (3, 2) must land at version=3 (the newer-wins clause).
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn apply_remote_memory_version_greatest_wins_1029() {
    let Some(pg) = live_pg().await else {
        return;
    };
    let ctx = ai_memory::store::CallerContext::for_admin("federation-test-1029-greatest");
    let mem3 = full_v07_memory("pg-1029-greatest", 3);
    pg.apply_remote_memory(&ctx, &mem3)
        .await
        .expect("first apply at version=3");

    // Out-of-order push with the OLDER version=2 — must NOT overwrite
    // the version=3 winner per the GREATEST clause.
    let mem2 = full_v07_memory("pg-1029-greatest", 2);
    pg.apply_remote_memory(&ctx, &mem2)
        .await
        .expect("second apply at version=2");

    let got = MemoryStore::get(&pg, &ctx, &mem3.id)
        .await
        .expect("get after out-of-order");
    assert_eq!(
        got.version, 3,
        "#1029: GREATEST(version) clause must defend against \
         out-of-order federation pushes; expected version=3 (newer wins), \
         got {}",
        got.version
    );
}
