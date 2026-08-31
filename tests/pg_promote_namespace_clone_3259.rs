// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3259 — POSTGRES parity for an APPROVED cross-namespace ("vertical")
//! promote through `PostgresStore::execute_pending_action`.
//!
//! ## The data-integrity bug this file pins
//!
//! The sqlite `db::execute_pending_action` "promote" arm reads `to_namespace`
//! from the pending payload and, when present, CLONES the memory into that
//! ancestor namespace (`storage::promote_to_namespace`). The postgres twin
//! IGNORED `to_namespace` entirely: it unconditionally tier-bumped the source
//! to `long` and returned the SOURCE id, reporting SUCCESS while landing NO
//! clone. On a mixed fleet (a pending row queued by the sqlite/MCP enforce
//! path, executed by a postgres daemon) an approved cross-namespace promote
//! silently degraded to a tier-only bump — a silent wrong-result /
//! data-divergence bug, strictly worse than a refusal.
//!
//! The fix ports the sqlite semantics EXACTLY: re-evaluate the destination
//! STORE gate at execute time (fail-closed, decide-only) and, if admitted,
//! clone into the destination via the SHARED
//! `storage::{validate_promotion_target, build_promotion_clone}` helpers, then
//! record the clone→source `derived_from` edge.
//!
//! This cell proves the CLONE actually LANDS: `execute_pending_action` returns
//! a NEW id (never the source id), the clone lives in the destination
//! namespace with the source content + re-stamped provenance, the source is
//! untouched, and the `derived_from` edge exists.
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip (the house pattern). Deliberately NOT `#[ignore]`: the PR postgres
//! job does not pass `--include-ignored`, so an ignored test silently never
//! runs.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown)]

use ai_memory::models::{ConfidenceSource, Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

async fn live_pg() -> Option<(PostgresStore, sqlx::PgPool)> {
    let url = pg_url()?;
    let store = match PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            return None;
        }
    };
    let probe = match sqlx::PgPool::connect(&url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skip: raw probe pool connect failed: {e}");
            return None;
        }
    };
    Some((store, probe))
}

fn test_ctx(agent: &str) -> CallerContext {
    let mut ctx = CallerContext::for_agent(agent);
    ctx.bypass_visibility = true;
    ctx
}

fn source_memory(id: &str, namespace: &str, author: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: "promote-me-3259".to_string(),
        content: "durable promoted content 3259".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": author }),
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

async fn cleanup(pool: &sqlx::PgPool, pending_id: &str, ids: &[&str]) {
    let _ = sqlx::query("DELETE FROM pending_actions WHERE id = $1")
        .bind(pending_id)
        .execute(pool)
        .await;
    for id in ids {
        let _ = sqlx::query("DELETE FROM memory_links WHERE source_id = $1 OR target_id = $1")
            .bind(id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }
}

/// #3259 — an approved `promote` pending whose payload carries `to_namespace`
/// must CLONE into the destination namespace on postgres, matching sqlite.
#[tokio::test]
async fn pg_execute_pending_promote_lands_cross_namespace_clone_3259() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };

    let suffix = &uuid::Uuid::new_v4().to_string()[..8];
    let parent_ns = format!("ns3259clone{suffix}");
    let child_ns = format!("{parent_ns}/child");
    let requester = "ai:promoter-3259";
    let ctx = test_ctx(requester);

    let source_id = uuid::Uuid::new_v4().to_string();
    let source = source_memory(&source_id, &child_ns, "ai:original-author-3259");
    store
        .store(&ctx, &source)
        .await
        .expect("seed source memory");

    // Queue an APPROVED source-side promote pending directly (the shape
    // `db::enforce_governance` / the MCP promote path lands on
    // GovernanceLevel::Approve): action_type = "promote", the source id in
    // `memory_id`, and `to_namespace` in the payload.
    let pending_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO pending_actions \
         (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status) \
         VALUES ($1, 'promote', $2, $3, $4, $5, $6, 'approved')",
    )
    .bind(&pending_id)
    .bind(&source_id)
    .bind(&child_ns)
    .bind(serde_json::json!({ "id": source_id, "to_namespace": parent_ns }))
    .bind(requester)
    .bind(chrono::Utc::now())
    .execute(&pool)
    .await
    .expect("insert approved promote pending");

    let executed = store
        .execute_pending_action(&ctx, &pending_id)
        .await
        .expect("execute_pending_action must succeed");

    // The core regression assertion: pre-fix this returned `Some(source_id)`
    // from a tier-only bump and NO clone. It must now return a NEW clone id.
    let clone_id = executed.expect("cross-namespace promote must return the clone id");
    assert_ne!(
        clone_id, source_id,
        "issue #3259: cross-namespace promote must land a NEW clone, not tier-bump the source"
    );

    // The clone actually exists in the DESTINATION namespace with the source
    // content and re-stamped provenance.
    let clone = store
        .get(&ctx, &clone_id)
        .await
        .expect("the promoted clone must exist in the destination namespace");
    assert_eq!(
        clone.namespace, parent_ns,
        "clone must live in the destination (ancestor) namespace"
    );
    assert_eq!(
        clone.content, "durable promoted content 3259",
        "clone must carry the source's durable text"
    );
    assert_eq!(
        clone.metadata["promoted_from"],
        serde_json::json!(source_id),
        "#3202 provenance: clone records its source id"
    );
    assert_eq!(
        clone.metadata["promoted_from_namespace"],
        serde_json::json!(child_ns),
        "#3202 provenance: clone records its source namespace"
    );
    assert_eq!(
        clone.metadata["agent_id"],
        serde_json::json!(requester),
        "#3202 provenance: the acting requester becomes the clone's agent_id"
    );
    assert_eq!(
        clone.metadata["promoted_from_agent_id"],
        serde_json::json!("ai:original-author-3259"),
        "#3202 provenance: the original author is preserved, never overwritten"
    );

    // The source row is UNTOUCHED — vertical promote is a fan-out, not a move.
    let src_after = store
        .get(&ctx, &source_id)
        .await
        .expect("source memory must still exist");
    assert_eq!(
        src_after.namespace, child_ns,
        "source memory is untouched by a vertical promote"
    );

    // The clone→source `derived_from` edge is recorded (parity with the
    // sqlite `create_link` at the tail of `promote_to_namespace`).
    let link_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM memory_links \
         WHERE source_id = $1 AND target_id = $2 AND relation = 'derived_from'",
    )
    .bind(&clone_id)
    .bind(&source_id)
    .fetch_one(&pool)
    .await
    .expect("derived_from edge probe");
    assert_eq!(
        link_count.0, 1,
        "clone→source derived_from edge must be recorded"
    );

    cleanup(&pool, &pending_id, &[&source_id, &clone_id]).await;
}
