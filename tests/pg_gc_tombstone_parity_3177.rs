// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// #1986: crate-level `//!` docs are still linted when `#![cfg(feature =
// "sal-postgres")]` is false (the allow below that cfg is configured out).
#![allow(clippy::doc_markdown)]

//! v1.0.0 #3177 — postgres eviction must tombstone + crypto-erase, and an
//! ARCHIVING eviction must carry the edge graph with it.
//!
//! Two proofs against the live pg backend:
//!
//! 1. `run_gc(archive = false)` on TTL-expired rows leaves, per victim, a
//!    `forget_tombstones` row AND a signed `substrate.crypto_erase`
//!    attestation — and a subsequent federated `apply_remote_memory` for the
//!    evicted id is DROPPED (tombstone-wins) instead of resurrecting it.
//!    Pre-#3177 the pg twins DELETEd outright: an encrypted row's per-record
//!    key survived the "erasure", and any peer could push the evicted row
//!    straight back under LWW while sqlite refused it.
//! 2. `size_gc(archive = true)` snapshots the victim's `memory_links` into
//!    `archived_memory_links`. Pre-#3177 the pg archive branch copied only the
//!    memory row, so `archive_restore` brought the memory back ISOLATED — the
//!    edges were reaped by the FK cascade and never recorded.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset).

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn count_crypto_erase(store: &PostgresStore) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM signed_events WHERE event_type = $1")
        .bind(ai_memory::signed_events::event_types::SUBSTRATE_CRYPTO_ERASE)
        .fetch_one(store.pool())
        .await
        .expect("count crypto_erase events")
}

#[tokio::test]
async fn pg_ttl_eviction_tombstones_and_crypto_erases_3177() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ctx = CallerContext::for_agent("ai:3177");
    let ns = format!("gc-3177-{}", uuid::Uuid::new_v4());
    let plain_id = format!("plain-{}", uuid::Uuid::new_v4());
    let sealed_id = format!("sealed-{}", uuid::Uuid::new_v4());

    // Two ALREADY-EXPIRED rows: one plaintext, one carrying a per-record
    // (0x03) envelope so both erasure KINDS are exercised in one sweep.
    // DISTINCT titles: `memories_title_ns_uidx` is UNIQUE over
    // (title, namespace), so a shared probe title collides on the second row.
    for (id, title, env) in [
        (&plain_id, "gc probe plaintext", None::<Vec<u8>>),
        (
            &sealed_id,
            "gc probe sealed",
            Some(vec![0x03_u8, 0xde, 0xad, 0xbe, 0xef]),
        ),
    ] {
        sqlx::query(
            "INSERT INTO memories \
                 (id, tier, namespace, title, content, source, metadata, expires_at, \
                  encrypted_envelope) \
             VALUES ($1, 'short', $2, $4, 'body', 'test', \
                     jsonb_build_object('agent_id', 'ai:3177'), NOW() - INTERVAL '1 hour', $3)",
        )
        .bind(id)
        .bind(&ns)
        .bind(env)
        .bind(title)
        .execute(store.pool())
        .await
        .expect("seed expired row");
    }

    let erase_before = count_crypto_erase(&store).await;
    store.run_gc(false).await.expect("run_gc hard delete");

    // --- tombstone per victim (the federation resurrection guard) ---
    for id in [&plain_id, &sealed_id] {
        let has_tombstone: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM forget_tombstones WHERE memory_id = $1)",
        )
        .bind(id)
        .fetch_one(store.pool())
        .await
        .expect("tombstone probe");
        assert!(
            has_tombstone,
            "#3177: a HARD TTL eviction must leave a forget_tombstone for {id} \
             — without it a peer resurrects the evicted row via LWW"
        );
        let gone: bool =
            sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM memories WHERE id = $1)")
                .bind(id)
                .fetch_one(store.pool())
                .await
                .expect("row-gone probe");
        assert!(gone, "the evicted row must be deleted: {id}");
    }

    // --- one signed erasure attestation per victim ---
    let erase_after = count_crypto_erase(&store).await;
    assert!(
        erase_after >= erase_before + 2,
        "#3177: each evicted row must append a substrate.crypto_erase \
         attestation ({erase_before} -> {erase_after})"
    );

    // --- resurrection is refused (tombstone-wins) ---
    let now = chrono::Utc::now().to_rfc3339();
    let inbound = Memory {
        id: plain_id.clone(),
        tier: Tier::Long,
        namespace: ns.clone(),
        title: "resurrected by a peer".to_string(),
        content: "should never land".to_string(),
        source: "federation".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    };
    store
        .apply_remote_memory(&ctx, &inbound)
        .await
        .expect("apply_remote_memory returns Ok on a tombstoned id (dropped)");
    let resurrected: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memories WHERE id = $1)")
            .bind(&plain_id)
            .fetch_one(store.pool())
            .await
            .expect("resurrection probe");
    assert!(
        !resurrected,
        "#3177: a federated apply for a tombstoned (evicted) id must be \
         DROPPED — the row came back, so the eviction was reversible"
    );

    // Cleanup — test-scoped rows only.
    for id in [&plain_id, &sealed_id] {
        sqlx::query("DELETE FROM forget_tombstones WHERE memory_id = $1")
            .bind(id)
            .execute(store.pool())
            .await
            .ok();
    }
}

#[tokio::test]
async fn pg_size_gc_archive_carries_the_edge_graph_3177() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("sizegc-3177-{}", uuid::Uuid::new_v4());
    let victim = format!("victim-{}", uuid::Uuid::new_v4());
    let peer = format!("peer-{}", uuid::Uuid::new_v4());

    // The victim is `short` tier / priority 0 so the lowest-value-first
    // eviction order picks it before the `long` peer.
    sqlx::query(
        "INSERT INTO memories (id, tier, namespace, title, content, source, priority, metadata) \
         VALUES ($1, 'short', $3, 'victim', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'test', 0, '{}'::jsonb), \
                ($2, 'long',  $3, 'peer',   'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'test', 9, '{}'::jsonb)",
    )
    .bind(&victim)
    .bind(&peer)
    .bind(&ns)
    .execute(store.pool())
    .await
    .expect("seed size_gc rows");
    sqlx::query(
        "INSERT INTO memory_links (source_id, target_id, relation, observed_by, attest_level) \
         VALUES ($1, $2, 'related_to', 'ai:3177', 'unsigned')",
    )
    .bind(&victim)
    .bind(&peer)
    .execute(store.pool())
    .await
    .expect("seed link");

    // Cap below the two-row corpus so exactly the victim is evicted.
    let corpus: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(length(title) + length(content) + length(metadata::text)), 0)::bigint \
         FROM memories WHERE namespace = $1",
    )
    .bind(&ns)
    .fetch_one(store.pool())
    .await
    .expect("corpus bytes");
    let evicted = store
        .size_gc(&ns, corpus / 2, true)
        .await
        .expect("size_gc archive");
    assert!(evicted >= 1, "size_gc must evict at least one row");

    let archived_edge: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM archived_memory_links \
         WHERE source_id = $1 AND target_id = $2 AND relation = 'related_to')",
    )
    .bind(&victim)
    .bind(&peer)
    .fetch_one(store.pool())
    .await
    .expect("archived link probe");
    assert!(
        archived_edge,
        "#3177: an ARCHIVING size_gc eviction must snapshot the victim's \
         memory_links into archived_memory_links BEFORE the cascade delete — \
         otherwise archive_restore returns the memory with no edge graph"
    );

    // Cleanup — test-scoped rows only.
    sqlx::query("DELETE FROM archived_memory_links WHERE source_id = $1")
        .bind(&victim)
        .execute(store.pool())
        .await
        .ok();
    sqlx::query("DELETE FROM archived_memories WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .ok();
    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .ok();
}
