// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3290 — POSTGRES namespace-standard SEVER must emit the signed
//! `substrate.namespace_standard_severed` audit-chain event, at parity with the
//! sqlite `storage::sever_namespace_standards` twin.
//!
//! ## The defect this pins closed
//!
//! On postgres, both sever sites (`pg_hard_delete_in_tx`, reached by
//! `PostgresStore::delete` / `apply_remote_deletion`, and the `archive_by_ids`
//! per-batch loop) ran a BARE `UPDATE namespace_meta SET standard_id = NULL`
//! with NO pre-read, NO `TRACE_TARGET_STANDARD_SEVERED` WARN, and NO signed
//! `SUBSTRATE_NAMESPACE_STANDARD_SEVERED` event. The sqlite twin did all three.
//! So a governance-significant sever on a pg deployment left NO operator signal
//! and NO tamper-evident audit record — a silent, backend-specific integrity
//! gap. #3290 routes both pg sites through the shared
//! `pg_sever_namespace_standards_in_tx` helper, which emits the same evidence.
//!
//! Row/chain state is asserted with RAW SQL over the store's own pool. Gated on
//! `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip. Deliberately NOT `#[ignore]`: the PR postgres job does not pass
//! `--include-ignored`, so an ignored test silently never runs.

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{
    ConfidenceSource, CorePolicy, GovernanceLevel, GovernancePolicy, Memory, Tier,
};
use ai_memory::signed_events::event_types::SUBSTRATE_NAMESPACE_STANDARD_SEVERED;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

async fn live_pg() -> Option<PostgresStore> {
    let url = pg_url()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

fn approve_write_policy() -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            ..CorePolicy::default()
        },
        ..GovernancePolicy::default()
    }
}

fn standard_memory(standard_ns: &str, owner: &str, policy: &GovernancePolicy) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: standard_ns.to_string(),
        title: format!("standard-{}", uuid::Uuid::new_v4()),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({
            "agent_id": owner,
            "governance": serde_json::to_value(policy).unwrap(),
        }),
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// The number of severance events currently on the chain. The payload is an
/// opaque hash (`standard_id \0 ns... \0 timestamp`) so we cannot filter by the
/// standard id in SQL; each test instead pins the DELTA across its own reap to
/// exactly +1 and asserts the daemon principal + chained sequence on the newest
/// row. Tests use unique namespaces so concurrent runs do not perturb the count
/// they measure (the assertion is a before/after delta, not an absolute).
async fn severed_event_count(store: &PostgresStore) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM signed_events WHERE event_type = $1")
        .bind(SUBSTRATE_NAMESPACE_STANDARD_SEVERED)
        .fetch_one(store.pool())
        .await
        .expect("count severed events")
}

/// `(agent_id, payload_hash_len, sequence)` of the newest severance event.
async fn newest_severed_event(store: &PostgresStore) -> (String, i64, Option<i64>) {
    let (agent_id, ph, seq): (String, Vec<u8>, Option<i64>) = sqlx::query_as(
        "SELECT agent_id, payload_hash, sequence FROM signed_events \
         WHERE event_type = $1 ORDER BY COALESCE(sequence, 0) DESC LIMIT 1",
    )
    .bind(SUBSTRATE_NAMESPACE_STANDARD_SEVERED)
    .fetch_one(store.pool())
    .await
    .expect("read newest severed event");
    (
        agent_id,
        i64::try_from(ph.len()).expect("payload_hash length fits i64"),
        seq,
    )
}

async fn cleanup(store: &PostgresStore, namespaces: &[&str]) {
    for ns in namespaces {
        let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace = $1")
            .bind(ns)
            .execute(store.pool())
            .await;
    }
}

/// The `delete` reap funnel (`pg_hard_delete_in_tx`) must append exactly one
/// signed severance event, authored by the daemon principal and CHAINED.
#[tokio::test]
async fn pg_delete_sever_emits_signed_severed_event_3290() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:op-3290");
    let ctx = CallerContext::for_agent(owner.clone());
    let attacker_ns = uniq("public-3290");
    let victim_ns = uniq("secure-3290");

    let std_mem = standard_memory(&attacker_ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &victim_ns, &std_id, None)
        .await
        .expect("bind victim namespace");

    let before = severed_event_count(&store).await;
    store.delete(&ctx, &std_id).await.expect("delete standard");
    let after = severed_event_count(&store).await;

    assert_eq!(
        after,
        before + 1,
        "#3290: reaping a namespace standard on postgres must append exactly one \
         signed substrate.namespace_standard_severed event (was previously a bare, \
         silent UPDATE)"
    );

    let (agent_id, ph_len, seq) = newest_severed_event(&store).await;
    assert_eq!(
        agent_id, "daemon",
        "#3290: the severance event is authored by the daemon principal, matching \
         the sqlite twin"
    );
    assert!(
        ph_len > 0,
        "#3290: the event must carry a non-empty payload hash"
    );
    assert!(
        seq.is_some(),
        "#3290: the event must be CHAINED (a sequence assigned), i.e. tamper-evident, \
         not a floating unchained row"
    );

    cleanup(&store, &[&victim_ns]).await;
}

/// The `archive_by_ids` funnel must likewise emit the signed severance event,
/// at parity with BOTH sqlite archive twins.
#[tokio::test]
async fn pg_archive_by_ids_sever_emits_signed_severed_event_3290() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:arch-3290");
    let ctx = CallerContext::for_agent(owner.clone());
    let attacker_ns = uniq("public-arch-3290");
    let victim_ns = uniq("secure-arch-3290");

    let std_mem = standard_memory(&attacker_ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &victim_ns, &std_id, None)
        .await
        .expect("bind victim namespace");

    let before = severed_event_count(&store).await;
    let moved = store
        .archive_by_ids(&ctx, std::slice::from_ref(&std_id), Some("manual"))
        .await
        .expect("archive_by_ids");
    assert_eq!(moved, 1, "the archive must move exactly one row");
    let after = severed_event_count(&store).await;

    assert_eq!(
        after,
        before + 1,
        "#3290: archiving a namespace standard on postgres must append exactly one \
         signed substrate.namespace_standard_severed event, like the sqlite archive \
         funnels"
    );

    let (agent_id, _ph_len, seq) = newest_severed_event(&store).await;
    assert_eq!(agent_id, "daemon", "#3290: daemon-authored severance event");
    assert!(seq.is_some(), "#3290: the event must be chained");

    cleanup(&store, &[&victim_ns]).await;
}

/// Parity of the NO-OP path: deleting a memory that is NObody's standard must
/// emit NO severance event — byte-identical to the pre-#2503 no-op and to the
/// sqlite twin's early `Ok(0)` return.
#[tokio::test]
async fn pg_delete_non_standard_emits_no_severed_event_3290() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:plain-3290");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = uniq("plain-3290");

    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.clone(),
        title: "not a standard".to_string(),
        content: "ordinary memory".to_string(),
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": owner }),
        ..Memory::default()
    };
    let id = store.store(&ctx, &mem).await.expect("store plain memory");

    let before = severed_event_count(&store).await;
    store.delete(&ctx, &id).await.expect("delete plain memory");
    let after = severed_event_count(&store).await;

    assert_eq!(
        after, before,
        "#3290: deleting a non-standard memory must NOT emit a severance event — the \
         common-case reap stays a pure no-op (no pre-read match, no UPDATE, no WARN, \
         no signed event), exactly like the sqlite twin's early return"
    );
}
