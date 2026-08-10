// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2860 (federation data-integrity, 5-agent vote `4d3ea1c5`) — live-Postgres
//! parity for the tenant-facing federated-consolidation CONVERGENCE fix.
//!
//! The fix (Option A) authors a substrate-DERIVED consolidation as the daemon's
//! federation identity (so it self-relays past strict write-sig) and stamps the
//! best-effort daemon `write_signature` + tenant/summary provenance via the new
//! `MemoryStore::set_row_metadata` primitive. This file pins the two
//! backend-specific pieces on the LIVE postgres adapter so they cannot diverge
//! from the sqlite twin (whose logic is covered by the unit tests in
//! `handlers::consolidate_federation`):
//!
//!   1. `PostgresStore::consolidate` stamps the passed author id as the row's
//!      `metadata.agent_id` — i.e. authoring the row as the SENDER (not the
//!      tenant) works identically to sqlite, which is the whole convergence
//!      mechanism.
//!   2. `PostgresStore::set_row_metadata` replaces the row's `metadata` jsonb in
//!      place (the finalize step that persists the substrate signature +
//!      provenance so the STORED origin row byte-matches the broadcast copy).
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn mem(id: &str, ns: &str, title: &str, content: &str, author: &str) -> Memory {
    Memory {
        id: id.to_string(),
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        created_at: "2026-08-10T12:00:00+00:00".to_string(),
        updated_at: "2026-08-10T12:00:00+00:00".to_string(),
        metadata: serde_json::json!({ "agent_id": author }),
        ..Memory::default()
    }
}

/// #2860 — on postgres, consolidating with the SENDER id as the author stamps
/// `metadata.agent_id = <sender>` (the self-relay authorship), and
/// `set_row_metadata` then persists the substrate `write_signature` +
/// provenance in place without disturbing the authorship — mirroring the
/// sqlite finalize.
#[tokio::test]
async fn pg_federated_consolidation_authors_as_sender_and_finalize_persists_2860() {
    let Some(store) = connect().await else {
        return;
    };
    let sender = "ai:node-sender";
    let tenant = "tenant:alice";
    let ns = format!("fed-consolidate-2860-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent(tenant);

    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&a, &ns, "A", "alpha one two three", tenant))
        .await
        .expect("store source a");
    store
        .store(&ctx, &mem(&b, &ns, "B", "beta four five six", tenant))
        .await
        .expect("store source b");

    // Author the consolidation as the SENDER (the #2860 convergence mechanism).
    let new_id = store
        .consolidate(
            &ctx,
            &[a.clone(), b.clone()],
            "merged",
            "merged summary content",
            &ns,
            &Tier::Long,
            "consolidation",
            sender,
        )
        .await
        .expect("pg consolidate authored as sender");

    // The consolidated row is owned by the SENDER now, so read it back as the
    // author (the tenant ctx would visibility-filter it out — the documented
    // ownership consequence of substrate authorship).
    let author_ctx = CallerContext::for_agent(sender);
    let row = store
        .get(&author_ctx, &new_id)
        .await
        .expect("get consolidated");
    assert_eq!(
        row.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some(sender),
        "pg consolidate must author the row as the passed sender id (self-relay authorship)"
    );

    // Finalize: replace metadata jsonb in place (write_signature + provenance).
    let mut finalized = row.metadata.clone();
    let obj = finalized.as_object_mut().unwrap();
    obj.insert(
        "write_signature".to_string(),
        serde_json::json!("AAAA-not-a-real-sig-just-a-roundtrip-probe"),
    );
    obj.insert("consolidator_tenant".to_string(), serde_json::json!(tenant));
    obj.insert("summary_source".to_string(), serde_json::json!("substrate"));
    let js = serde_json::to_string(&finalized).unwrap();
    store
        .set_row_metadata(&ctx, &new_id, &js)
        .await
        .expect("pg set_row_metadata");

    let after = store
        .get(&author_ctx, &new_id)
        .await
        .expect("get after finalize");
    let am = after.metadata.as_object().unwrap();
    assert_eq!(
        am.get("agent_id").and_then(|v| v.as_str()),
        Some(sender),
        "finalize must NOT disturb the substrate authorship"
    );
    assert_eq!(
        am.get("consolidator_tenant").and_then(|v| v.as_str()),
        Some(tenant),
        "finalize persists the untrusted tenant provenance"
    );
    assert_eq!(
        am.get("summary_source").and_then(|v| v.as_str()),
        Some("substrate")
    );
    assert!(
        am.contains_key("write_signature"),
        "finalize persists the substrate write_signature in place (jsonb replace)"
    );
}
