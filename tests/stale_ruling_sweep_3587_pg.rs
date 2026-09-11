// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U3 — postgres twin of `stale_ruling_sweep_3587`.
//!
//! The U3 guarantee must hold on BOTH backends: the stale-ruling scan is a
//! pure SELECT — the ruling rows' `version` / `updated_at` are unchanged and
//! `archived_memories` delta is 0 — and the predicate (ruling tag OR
//! `metadata.ruling_key`, no supersede/verify marker, latest-per-key) matches
//! the SQLite twin. Exercised here against a LIVE cluster via the SAL
//! `MemoryStore::list_stale_rulings` surface.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; every seeded row is reaped in-test
//! (#2287) and every namespace is uuid-suffixed so concurrent lanes on one
//! cluster cannot collide.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

/// Insert a ruling row directly (substrate namespaces are write-gated), with
/// explicit tags + metadata so the predicate is exercised exactly.
async fn raw_ruling(
    store: &PostgresStore,
    namespace: &str,
    tags: &[&str],
    metadata: serde_json::Value,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO memories (id, tier, namespace, title, content, source, priority, \
                               confidence, created_at, updated_at, metadata, tags) \
         VALUES ($1, 'long', $2, $3, 'a ruling body', 'test-3587', 5, 1.0, $4, $4, \
                 $5::jsonb, $6::jsonb)",
    )
    .bind(&id)
    .bind(namespace)
    .bind(format!("ruling {id}"))
    .bind(updated_at)
    .bind(metadata)
    .bind(serde_json::to_value(tags).expect("tags json"))
    .execute(store.pool())
    .await
    .expect("raw insert ruling");
    id
}

async fn snapshot(store: &PostgresStore, id: &str) -> (i64, chrono::DateTime<chrono::Utc>) {
    sqlx::query_as::<_, (i64, chrono::DateTime<chrono::Utc>)>(
        "SELECT version, updated_at FROM memories WHERE id = $1",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .expect("snapshot ruling")
}

async fn cleanup(store: &PostgresStore, marker: &str) {
    let _ = sqlx::query("DELETE FROM memories WHERE namespace LIKE $1")
        .bind(format!("%{marker}%"))
        .execute(store.pool())
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_ruling_sweep_writes_nothing_to_the_rulings_3587_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3587 live-pg suite");
    };
    let marker = format!("m3587-{}", uuid::Uuid::new_v4());
    let ns = format!("proj/{marker}");
    let now = chrono::Utc::now();
    let cutoff = (now - chrono::Duration::days(14)).to_rfc3339();

    let id = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-write"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let before = snapshot(&store, &id).await;
    let archived_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories")
        .fetch_one(store.pool())
        .await
        .expect("archived count");

    let found = store.list_stale_rulings(&cutoff, 500).await.expect("scan");
    let hit = found
        .iter()
        .find(|r| r.id == id)
        .expect("seeded ruling found");
    assert_eq!(hit.namespace, ns);
    assert_eq!(hit.ruling_key.as_deref(), Some("k-write"));

    assert_eq!(snapshot(&store, &id).await, before, "ruling drifted");
    let archived_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories")
        .fetch_one(store.pool())
        .await
        .expect("archived count");
    assert_eq!(archived_after, archived_before, "scan must not archive");

    cleanup(&store, &marker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_ruling_markers_and_latest_only_3587_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3587 live-pg suite");
    };
    let marker = format!("m3587-{}", uuid::Uuid::new_v4());
    let ns = format!("proj/{marker}");
    let now = chrono::Utc::now();
    let cutoff = (now - chrono::Duration::days(14)).to_rfc3339();

    let plain = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let verified = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "verified_at": now.to_rfc3339()}),
        now - chrono::Duration::days(30),
    )
    .await;
    let superseded = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "superseded_id": "prior"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let older = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-latest"}),
        now - chrono::Duration::days(40),
    )
    .await;
    let newer = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-latest"}),
        now - chrono::Duration::days(30),
    )
    .await;

    let found = store.list_stale_rulings(&cutoff, 500).await.expect("scan");
    let ids: Vec<&str> = found.iter().map(|r| r.id.as_str()).collect();

    assert!(ids.contains(&plain.as_str()), "plain ruling is stale");
    assert!(!ids.contains(&verified.as_str()), "verified is not stale");
    assert!(
        !ids.contains(&superseded.as_str()),
        "superseded is not stale"
    );
    assert!(ids.contains(&newer.as_str()), "latest for key is stale");
    assert!(
        !ids.contains(&older.as_str()),
        "older same-key row is history"
    );

    cleanup(&store, &marker).await;
}

/// Count the rows in one inbox namespace.
async fn inbox_count_pg(store: &PostgresStore, ns: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE namespace = $1")
        .bind(ns)
        .fetch_one(store.pool())
        .await
        .expect("count inbox")
}

/// #3587 U3 R1 — drives the STORE-BACKED sweep ENTRY (not the raw trait
/// method) against a live cluster: scan via `list_stale_rulings`, digest via
/// the store-backed notify funnel with the curator's own sender, and dedup
/// state read/written through the store. Also pins the R2 unconditional floor
/// (a changed set inside the floor is suppressed; after the floor one digest
/// carries the current set) and the read-only guarantee on the ruling rows.
#[tokio::test(flavor = "multi_thread")]
async fn store_backed_stale_ruling_sweep_notifies_and_dedups_3587_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3587 live-pg suite");
    };
    let marker = format!("m3587-{}", uuid::Uuid::new_v4());
    let ns = format!("proj/{marker}");
    let recipient = format!("deputy-{marker}");
    let inbox_ns = ai_memory::inbox_namespace(&recipient);
    let now = chrono::Utc::now();
    let sender = "ai:curator";
    // The dedup state row is substrate bookkeeping owned by the curator
    // principal; in production the CLI supplies this admin ctx, so the library
    // defines no privacy bypass of its own.
    let state_ctx =
        ai_memory::store::CallerContext::for_admin(ai_memory::identity::sentinels::AI_CURATOR);

    // The shared dedup row must start absent so the first sweep actually emits.
    sqlx::query("DELETE FROM memories WHERE namespace = $1 AND title = $2")
        .bind(ai_memory::curator::STALE_RULING_STATE_NAMESPACE)
        .bind(ai_memory::curator::STALE_RULING_STATE_TITLE)
        .execute(store.pool())
        .await
        .expect("clear state row");

    let first = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-store"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let before = snapshot(&store, &first).await;
    let archived_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories")
        .fetch_one(store.pool())
        .await
        .expect("archived count");

    let cfg = ai_memory::curator::CuratorConfig {
        stale_ruling_days: 14,
        notify_agent_id: Some(recipient.clone()),
        ..ai_memory::curator::CuratorConfig::default()
    };

    let r1 =
        ai_memory::curator::run_store_backed_stale_ruling_pass(&store, &cfg, sender, &state_ctx)
            .await;
    assert!(
        r1.errors.is_empty(),
        "first store-backed sweep must be clean: {:?}",
        r1.errors
    );
    assert!(
        r1.stale_ruling_ids.contains(&first),
        "the seeded ruling is reported: {:?}",
        r1.stale_ruling_ids
    );
    assert_eq!(r1.stale_rulings_notified, 1, "first sweep emits one digest");
    assert_eq!(inbox_count_pg(&store, &inbox_ns).await, 1);

    // Read-only guarantee: the ruling row and the archive count are unchanged.
    assert_eq!(snapshot(&store, &first).await, before, "ruling drifted");
    let archived_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories")
        .fetch_one(store.pool())
        .await
        .expect("archived count");
    assert_eq!(archived_after, archived_before, "sweep must not archive");

    // R2 — a CHANGED set inside the floor is suppressed.
    let second = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-store-2"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let r2 =
        ai_memory::curator::run_store_backed_stale_ruling_pass(&store, &cfg, sender, &state_ctx)
            .await;
    assert!(
        r2.stale_ruling_ids.contains(&second),
        "the new ruling is in the current set"
    );
    assert_eq!(
        r2.stale_rulings_notified, 0,
        "changed set inside the floor is suppressed: {:?}",
        r2.errors
    );
    assert_eq!(inbox_count_pg(&store, &inbox_ns).await, 1);

    // After the floor, ONE digest carrying the CURRENT set.
    sqlx::query(
        "UPDATE memories SET updated_at = now() - interval '2 days' \
         WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::curator::STALE_RULING_STATE_NAMESPACE)
    .bind(ai_memory::curator::STALE_RULING_STATE_TITLE)
    .execute(store.pool())
    .await
    .expect("backdate state row");

    let r3 =
        ai_memory::curator::run_store_backed_stale_ruling_pass(&store, &cfg, sender, &state_ctx)
            .await;
    assert!(
        r3.errors.is_empty(),
        "post-floor sweep must be clean: {:?}",
        r3.errors
    );
    assert_eq!(
        r3.stale_rulings_notified, 1,
        "after the floor the changed set re-notifies once"
    );
    assert_eq!(inbox_count_pg(&store, &inbox_ns).await, 2);
    let body: String = sqlx::query_scalar(
        "SELECT content FROM memories WHERE namespace = $1 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(&inbox_ns)
    .fetch_one(store.pool())
    .await
    .expect("latest digest body");
    assert!(body.contains(&second), "current set is carried: {body}");

    // R3 — change the set AGAIN inside B's floor. The store-backed reader must
    // observe the LATEST (B) state row, so this is suppressed; reading an older
    // row would make the floor look elapsed and re-emit.
    let third = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-store-3"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let r4 =
        ai_memory::curator::run_store_backed_stale_ruling_pass(&store, &cfg, sender, &state_ctx)
            .await;
    assert!(
        r4.stale_ruling_ids.contains(&third),
        "the new ruling is in the current set"
    );
    assert_eq!(
        r4.stale_rulings_notified, 0,
        "changed set inside B's floor is suppressed: {:?}",
        r4.errors
    );
    assert_eq!(inbox_count_pg(&store, &inbox_ns).await, 2);

    // R3 — ONE deterministic-id state row after the digests.
    let (state_rows, state_id): (i64, String) = sqlx::query_as::<_, (i64, String)>(
        "SELECT COUNT(*), MIN(id) FROM memories WHERE namespace = $1 AND title = $2",
    )
    .bind(ai_memory::curator::STALE_RULING_STATE_NAMESPACE)
    .bind(ai_memory::curator::STALE_RULING_STATE_TITLE)
    .fetch_one(store.pool())
    .await
    .expect("state row");
    assert_eq!(state_rows, 1, "the state is a single row");
    assert_eq!(
        state_id,
        ai_memory::curator::stale_ruling_state_id(),
        "the state row carries the deterministic id"
    );

    cleanup(&store, &marker).await;
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1 AND title = $2")
        .bind(ai_memory::curator::STALE_RULING_STATE_NAMESPACE)
        .bind(ai_memory::curator::STALE_RULING_STATE_TITLE)
        .execute(store.pool())
        .await;
}
