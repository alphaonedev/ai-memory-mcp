// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3755 — POSTGRES parity for an APPROVED `store` pending that carries the
//! #3202 VERTICAL-promote payload (`mode: "vertical"`, `id`, `to_namespace`).
//!
//! ## The data-integrity bug this file pins
//!
//! A cross-namespace promote whose DESTINATION namespace requires approval is
//! queued by the destination STORE gate as `action_type = "store"` with the
//! vertical payload — not as a `Memory`. The sqlite executor
//! (`db::execute_pending_action`, the #3202 arm) dispatches that payload onto
//! `promote_to_namespace`. The postgres executor's `"store"` arm had no such
//! dispatch: it ran `serde_json::from_value::<Memory>` over the vertical
//! payload, which fails (the payload is not a `Memory`), and the approved
//! decision surfaced as `IntegrityFailed("invalid store payload …")`. On the
//! federated lane that is counted `skipped` behind an HTTP 200 — the receiver
//! APPROVES and lands NOTHING (the #3629 pg cell documents exactly that gap).
//!
//! The fix mirrors the sqlite arm with ONE predicate on
//! `field_names::MODE == MODE_VERTICAL`: source = `memory_id` or the payload
//! `id`, destination = `to_namespace`, clone via the shared
//! `pg_promote_to_namespace` (the #3259 promote-arm helper). No destination
//! re-gate in the `store` arm — the pending row IS the destination-store
//! approval, exactly as on sqlite.
//!
//! Cells: PRESENT — the clone lands in `to_namespace` with the #3202
//! provenance; CONTROL — a vertical payload missing `to_namespace` is refused
//! and lands nothing; CONTROL — a non-vertical malformed payload is still
//! refused as an invalid store payload (the pre-#3755 contract for a real
//! `Memory` payload is untouched).
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip (the house pattern). Deliberately NOT `#[ignore]`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown)]

use ai_memory::models::field_names;
use ai_memory::models::{ConfidenceSource, Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

/// The source memory's durable text — asserted verbatim on the clone.
const SOURCE_CONTENT: &str = "durable vertical-store content 3755";
/// The pending row's `action_type` this file exercises.
const ACTION_STORE: &str = "store";

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
        title: "vertical-store-me-3755".to_string(),
        content: SOURCE_CONTENT.to_string(),
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

/// Queue an already-APPROVED `store` pending carrying `payload` — the shape
/// the destination STORE gate lands on `GovernanceLevel::Approve` and the
/// federated `pending_decisions[]` lane approves.
async fn queue_approved_store(
    pool: &sqlx::PgPool,
    pending_id: &str,
    memory_id: Option<&str>,
    namespace: &str,
    payload: &serde_json::Value,
    requester: &str,
) {
    sqlx::query(
        "INSERT INTO pending_actions \
         (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'approved')",
    )
    .bind(pending_id)
    .bind(ACTION_STORE)
    .bind(memory_id)
    .bind(namespace)
    .bind(payload)
    .bind(requester)
    .bind(chrono::Utc::now())
    .execute(pool)
    .await
    .expect("insert approved store pending");
}

async fn count_ns(pool: &sqlx::PgPool, namespace: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM memories WHERE namespace = $1")
        .bind(namespace)
        .fetch_one(pool)
        .await
        .expect("count namespace rows");
    n
}

async fn cleanup(pool: &sqlx::PgPool, pending_id: &str, namespaces: &[&str]) {
    let _ = sqlx::query("DELETE FROM pending_actions WHERE id = $1")
        .bind(pending_id)
        .execute(pool)
        .await;
    for ns in namespaces {
        let _ = sqlx::query(
            "DELETE FROM memory_links WHERE source_id IN (SELECT id FROM memories WHERE namespace = $1) \
             OR target_id IN (SELECT id FROM memories WHERE namespace = $1)",
        )
        .bind(ns)
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
            .bind(ns)
            .execute(pool)
            .await;
    }
}

/// PRESENT — #3755: an approved vertical-store pending CLONES the source into
/// `to_namespace` on postgres, the way the sqlite #3202 arm does.
#[tokio::test]
async fn pg_execute_pending_vertical_store_lands_clone_in_to_namespace_3755() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };

    let suffix = &uuid::Uuid::new_v4().to_string()[..8];
    let parent_ns = format!("ns3755vstore{suffix}");
    let child_ns = format!("{parent_ns}/child");
    let requester = "ai:promoter-3755";
    let original_author = "ai:original-author-3755";
    let ctx = test_ctx(requester);

    let source_id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &source_memory(&source_id, &child_ns, original_author))
        .await
        .expect("seed source memory");

    // The destination-store gate's payload: NOT a Memory — the vertical
    // clone request (#3202), which `from_value::<Memory>` cannot parse.
    let pending_id = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        (field_names::MODE): field_names::MODE_VERTICAL,
        "id": source_id,
        (field_names::TO_NAMESPACE): parent_ns,
    });
    queue_approved_store(
        &pool,
        &pending_id,
        Some(&source_id),
        &child_ns,
        &payload,
        requester,
    )
    .await;

    let executed = store
        .execute_pending_action(&ctx, &pending_id)
        .await
        .expect("#3755: an approved vertical-store pending must execute on postgres");
    let clone_id = executed.expect("vertical store must return the clone id");
    assert_ne!(
        clone_id, source_id,
        "#3755: the executor must return a NEW clone id, never the source"
    );

    assert_eq!(
        count_ns(&pool, &parent_ns).await,
        1,
        "#3755: exactly one clone lands in the destination namespace"
    );
    let clone = store
        .get(&ctx, &clone_id)
        .await
        .expect("the clone must exist in the destination namespace");
    assert_eq!(clone.namespace, parent_ns, "clone lives in to_namespace");
    assert_eq!(
        clone.content, SOURCE_CONTENT,
        "clone carries the source's durable text"
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
        "#3202 provenance: the requester becomes the clone's agent_id"
    );
    assert_eq!(
        clone.metadata["promoted_from_agent_id"],
        serde_json::json!(original_author),
        "#3202 provenance: the original author is preserved"
    );

    // Fan-out, not a move: the source is untouched.
    let src_after = store
        .get(&ctx, &source_id)
        .await
        .expect("source memory must still exist");
    assert_eq!(
        src_after.namespace, child_ns,
        "source untouched by the clone"
    );
    assert_eq!(
        count_ns(&pool, &child_ns).await,
        1,
        "the source namespace still holds exactly the source"
    );

    // The clone→source `derived_from` edge is recorded (shared helper with
    // the #3259 promote arm).
    let (edges,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM memory_links \
         WHERE source_id = $1 AND target_id = $2 AND relation = 'derived_from'",
    )
    .bind(&clone_id)
    .bind(&source_id)
    .fetch_one(&pool)
    .await
    .expect("derived_from edge probe");
    assert_eq!(edges, 1, "clone→source derived_from edge must be recorded");

    cleanup(&pool, &pending_id, &[&child_ns, &parent_ns]).await;
}

/// CONTROL — a vertical payload with no `to_namespace` is refused as invalid
/// input and lands nothing (the sqlite arm's exact disposition).
#[tokio::test]
async fn pg_execute_pending_vertical_store_missing_destination_is_refused_3755() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };

    let suffix = &uuid::Uuid::new_v4().to_string()[..8];
    let parent_ns = format!("ns3755nodest{suffix}");
    let child_ns = format!("{parent_ns}/child");
    let requester = "ai:promoter-3755";
    let ctx = test_ctx(requester);

    let source_id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &source_memory(&source_id, &child_ns, requester))
        .await
        .expect("seed source memory");

    let pending_id = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        (field_names::MODE): field_names::MODE_VERTICAL,
        "id": source_id,
    });
    queue_approved_store(
        &pool,
        &pending_id,
        Some(&source_id),
        &child_ns,
        &payload,
        requester,
    )
    .await;

    let err = store
        .execute_pending_action(&ctx, &pending_id)
        .await
        .expect_err("a vertical payload without to_namespace must be refused");
    // The refusal is the typed `InvalidInput` carrying the ONE reason both
    // executors share — byte-for-byte the sqlite arm's.
    match &err {
        StoreError::InvalidInput { detail } => assert_eq!(
            detail,
            ai_memory::storage::MSG_VERTICAL_STORE_PAYLOAD_INCOMPLETE,
            "#3755: the refusal names the shared reason"
        ),
        other => panic!("#3755: the refusal is typed InvalidInput, got {other:?}"),
    }
    assert_eq!(
        count_ns(&pool, &parent_ns).await,
        0,
        "a refused vertical store lands nothing in the would-be destination"
    );
    assert_eq!(
        count_ns(&pool, &child_ns).await,
        1,
        "the source namespace still holds exactly the source"
    );

    cleanup(&pool, &pending_id, &[&child_ns, &parent_ns]).await;
}

/// CONTROL — a NON-vertical malformed payload keeps the pre-#3755 contract:
/// refused as an invalid store payload, nothing stored.
#[tokio::test]
async fn pg_execute_pending_malformed_store_payload_still_refused_3755() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };

    let suffix = &uuid::Uuid::new_v4().to_string()[..8];
    let ns = format!("ns3755malformed{suffix}");
    let requester = "ai:promoter-3755";
    let ctx = test_ctx(requester);

    let pending_id = uuid::Uuid::new_v4().to_string();
    // Not a Memory and not the vertical shape: `mode` is absent.
    let payload = serde_json::json!({ "id": "not-a-memory", "namespace": ns });
    queue_approved_store(&pool, &pending_id, None, &ns, &payload, requester).await;

    let err = store
        .execute_pending_action(&ctx, &pending_id)
        .await
        .expect_err("a malformed store payload must be refused");
    assert!(
        matches!(err, StoreError::IntegrityFailed { .. }),
        "#3755: a malformed Memory payload stays IntegrityFailed, got {err:?}"
    );
    assert_eq!(
        count_ns(&pool, &ns).await,
        0,
        "a refused malformed store lands nothing"
    );

    cleanup(&pool, &pending_id, &[&ns]).await;
}
