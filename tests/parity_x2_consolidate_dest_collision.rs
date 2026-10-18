// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! campaign:X cell X2 — `MemoryStore::consolidate` onto an already-occupied
//! destination `(title, namespace)` slot, one scenario and one expected
//! outcome per backend.
//!
//! - #7111: postgres upserts the summary onto an existing same-owner row of
//!   that title (the surviving id is returned, the sources are consumed) and
//!   refuses a HIDDEN holder with a typed, unnamed `StoreError::Conflict`.
//!   sqlite ran a plain `INSERT` and failed with a raw UNIQUE violation
//!   flattened to `StoreError::Backend`. Both backends must agree.
//!
//! The postgres cells connect to the shared test database named by
//! `AI_MEMORY_TEST_POSTGRES_URL` (the tombstone path writes `memory_links`,
//! whose foreign keys the per-test schema does not carry) and use a unique
//! namespace per cell. They skip cleanly without the variable.

#![cfg(feature = "sal")]

use ai_memory::models::{LifecycleState, Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, StoreError};
use serde_json::json;

const OWNER: &str = "ai:owner-x2-dest";

fn unique_ns(cell: &str) -> String {
    format!("parity-x2d-{cell}-{}", uuid::Uuid::new_v4().simple())
}

fn row(ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": OWNER }),
        ..Default::default()
    }
}

/// Process-wide flags, set once and never reset (cells run concurrently).
fn enable_tombstone_path() {
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
}

async fn rows_in_ns(store: &dyn MemoryStore, ctx: &CallerContext, ns: &str) -> Vec<Memory> {
    let mut filter = Filter::new();
    filter.namespace = Some(ns.to_string());
    // `Filter::new()` carries limit 0, which both adapters clamp to ONE row.
    filter.limit = 100;
    let mut rows = store.list(ctx, &filter).await.expect("list");
    rows.sort_by(|a, b| a.title.cmp(&b.title));
    rows
}

/// Control: a fresh destination title consolidates as before.
async fn fresh_destination_control(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("fresh");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a fresh", "alpha");
    let b = row(&ns, "b fresh", "beta");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    let id = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest fresh",
            "merged fresh",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect("a fresh destination consolidates");
    let rows = rows_in_ns(store, &ctx, &ns).await;
    assert_eq!(rows.len(), 1, "only the summary stays visible");
    assert_eq!(rows[0].id, id);
}

/// #7111 scenario A: the destination title is already held by a visible
/// same-owner row. The consolidation merges into it in place and returns the
/// SURVIVING id; the sources leave the visible set; no duplicate title.
async fn existing_destination_is_upserted(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("upsert");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a upsert", "alpha");
    let b = row(&ns, "b upsert", "beta");
    let dest = row(&ns, "dest upsert", "old destination content");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    store.store(&ctx, &dest).await.expect("seed destination");
    let id = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest upsert",
            "merged upsert",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect("#7111: consolidate onto an existing same-owner title upserts");
    assert_eq!(
        id, dest.id,
        "#7111: the surviving destination id is returned"
    );
    let rows = rows_in_ns(store, &ctx, &ns).await;
    assert_eq!(
        rows.len(),
        1,
        "#7111: one destination row, sources consumed"
    );
    assert_eq!(rows[0].title, "dest upsert");
    assert_eq!(
        rows[0].content, "merged upsert",
        "content overwritten in place"
    );
}

/// #7111 scenario B: the destination title is held by a quarantined (hidden)
/// row. The refusal is the typed, unnamed `Conflict`, and the cluster is
/// atomic: no source is tombstoned, the holder is untouched.
async fn hidden_destination_holder_is_conflict(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("hidden");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a hidden-dest", "alpha");
    let b = row(&ns, "b hidden-dest", "beta");
    let mut holder = row(&ns, "dest hidden", "quarantined content");
    holder.lifecycle_state = LifecycleState::Quarantined;
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    store
        .store(&ctx, &holder)
        .await
        .expect("seed quarantined holder");
    let err = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest hidden",
            "merged hidden",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect_err("a hidden destination holder refuses the cluster");
    match &err {
        StoreError::Conflict { id } => {
            assert!(
                id.is_empty(),
                "#7111: the hidden holder is never named, got {id:?}"
            );
        }
        other => panic!("#7111: expected StoreError::Conflict, got {other:?}"),
    }
    let titles: Vec<String> = rows_in_ns(store, &ctx, &ns)
        .await
        .into_iter()
        .map(|m| m.title)
        .collect();
    assert_eq!(
        titles,
        vec!["a hidden-dest".to_string(), "b hidden-dest".to_string()],
        "the refused cluster tombstoned no source and wrote no summary"
    );
}

const OTHER: &str = "ai:other-x2-dest";

/// A row owned by `OTHER` with the given visibility scope.
fn other_row(ns: &str, title: &str, content: &str, scope: &str) -> Memory {
    let mut m = row(ns, title, content);
    m.metadata = json!({ "agent_id": OTHER, "scope": scope });
    m
}

/// #7111 acceptance, #7560 scenario C: the destination slot is held by ANOTHER
/// agent. A `scope=private` holder is hidden from the consolidator, so the
/// cluster is refused with the typed, UNNAMED `Conflict` and nothing moves; a
/// `scope=collective` holder is visible, so the summary merges into it in place
/// and the holder's `agent_id` survives (provenance is never re-stamped).
async fn destination_held_by_another_agent(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ctx = CallerContext::for_agent(OWNER.to_string());

    // Private holder: refused, holder unnamed, atomic.
    let ns = unique_ns("other-private");
    let a = row(&ns, "a other-private", "alpha");
    let b = row(&ns, "b other-private", "beta");
    let holder = other_row(&ns, "dest other-private", "private content", "private");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    let other_ctx = CallerContext::for_agent(OTHER.to_string());
    store
        .store(&other_ctx, &holder)
        .await
        .expect("seed private holder");
    let holder_before = store
        .get(&other_ctx, &holder.id)
        .await
        .expect("read the private holder before the refused merge");
    let err = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest other-private",
            "merged private",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect_err("another agent's private holder refuses the cluster");
    match &err {
        StoreError::Conflict { id } => assert!(
            id.is_empty(),
            "#7560: the private holder is never named, got {id:?}"
        ),
        other => panic!("#7560: expected StoreError::Conflict, got {other:?}"),
    }
    let mine: Vec<String> = rows_in_ns(store, &ctx, &ns)
        .await
        .into_iter()
        .map(|m| m.title)
        .collect();
    assert_eq!(
        mine,
        vec!["a other-private".to_string(), "b other-private".to_string()],
        "the refused cluster tombstoned no source and the holder stays hidden"
    );
    let holder_after = store
        .get(&other_ctx, &holder.id)
        .await
        .expect("the private holder survives the refused merge");
    assert_eq!(
        (
            &holder_after.content,
            &holder_after.title,
            holder_after.version,
            &holder_after.tier,
            &holder_after.metadata,
            &holder_after.updated_at,
        ),
        (
            &holder_before.content,
            &holder_before.title,
            holder_before.version,
            &holder_before.tier,
            &holder_before.metadata,
            &holder_before.updated_at,
        ),
        "#7560: the refused merge leaves the private holder row unchanged"
    );

    // Visible holder: merged in place, agent_id kept.
    let ns = unique_ns("other-visible");
    let a = row(&ns, "a other-visible", "alpha");
    let b = row(&ns, "b other-visible", "beta");
    let holder = other_row(&ns, "dest other-visible", "visible content", "collective");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    store
        .store(&other_ctx, &holder)
        .await
        .expect("seed visible holder");
    let holder_before = store
        .get(&other_ctx, &holder.id)
        .await
        .expect("read the visible holder before the merge");
    let id = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest other-visible",
            "merged visible",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect("a visible holder owned by another agent is merged into");
    assert_eq!(id, holder.id, "the visible holder's id survives");
    // The merged metadata carries the summary's scope, so the holder (not the
    // consolidator) reads the surviving row.
    let merged = store
        .get(&other_ctx, &id)
        .await
        .expect("read merged holder as its owner");
    assert_eq!(merged.content, "merged visible", "content overwritten");
    assert_eq!(
        merged.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some(OTHER),
        "#7560: the holder's agent_id survives the merge"
    );
    assert_eq!(
        merged.version,
        holder_before.version + 1,
        "#7560: the merge bumps the visible holder's version by one"
    );
}

/// #7558 / #7557 scenario D: merging onto a `mid` destination with a long-tier
/// summary promotes it, so the merge bumps `version` by one and clears
/// `expires_at` (GC deletes on `expires_at < now`; an optimistic writer holding
/// the pre-merge version must lose).
async fn promotion_to_long_bumps_version_and_clears_expiry(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("promote");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a promote", "alpha");
    let b = row(&ns, "b promote", "beta");
    let mut dest = row(&ns, "dest promote", "old destination content");
    dest.tier = Tier::Mid;
    dest.expires_at = Some((chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339());
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    store
        .store(&ctx, &dest)
        .await
        .expect("seed mid destination");
    let before = store.get(&ctx, &dest.id).await.expect("read before");
    assert_eq!(before.tier, Tier::Mid);
    assert!(before.expires_at.is_some(), "the mid destination expires");
    let id = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest promote",
            "merged promote",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect("consolidate onto the mid destination");
    assert_eq!(id, dest.id);
    let after = store.get(&ctx, &id).await.expect("read after");
    assert_eq!(after.tier, Tier::Long, "promoted to long");
    assert_eq!(
        after.version,
        before.version + 1,
        "#7557: the merge bumps the version"
    );
    assert!(
        after.expires_at.is_none(),
        "#7557: a long-tier row must not keep an expiry, got {:?}",
        after.expires_at
    );
}

fn sqlite_store() -> (tempfile::TempDir, SqliteStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("x2d.db")).expect("open sqlite store");
    (dir, store)
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_fresh_destination_control() {
    let (_dir, store) = sqlite_store();
    fresh_destination_control(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_existing_destination_is_upserted_7111() {
    let (_dir, store) = sqlite_store();
    existing_destination_is_upserted(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_hidden_destination_is_conflict_7111() {
    let (_dir, store) = sqlite_store();
    hidden_destination_holder_is_conflict(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_destination_held_by_another_agent_7560() {
    let (_dir, store) = sqlite_store();
    destination_held_by_another_agent(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_promotion_bumps_version_and_clears_expiry_7557() {
    let (_dir, store) = sqlite_store();
    promotion_to_long_bumps_version_and_clears_expiry(&store).await;
}

#[cfg(feature = "sal-postgres")]
async fn pg_store() -> Option<ai_memory::store::postgres::PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    Some(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_fresh_destination_control() {
    let Some(store) = pg_store().await else {
        return;
    };
    fresh_destination_control(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_existing_destination_is_upserted_7111() {
    let Some(store) = pg_store().await else {
        return;
    };
    existing_destination_is_upserted(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_hidden_destination_is_conflict_7111() {
    let Some(store) = pg_store().await else {
        return;
    };
    hidden_destination_holder_is_conflict(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_destination_held_by_another_agent_7560() {
    let Some(store) = pg_store().await else {
        return;
    };
    destination_held_by_another_agent(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_promotion_bumps_version_and_clears_expiry_7557() {
    let Some(store) = pg_store().await else {
        return;
    };
    promotion_to_long_bumps_version_and_clears_expiry(&store).await;
}
