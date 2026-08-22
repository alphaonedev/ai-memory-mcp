// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3085 — postgres lane: an UNATTRIBUTED (`embedding_space = ''`)
//! vector must be (a) impossible to write through the SAL funnels, and
//! (b) healable when an older binary already wrote one.
//!
//! ## The defect
//!
//! `migrate`'s #3060 Phase-3 embedding copy bucketed a source row whose
//! `embedding_space` was SQL NULL under `space.unwrap_or_default()` — the
//! EMPTY STRING — and wrote it with `set_embeddings_batch(&ctx, chunk, "")`.
//! On postgres that lands NON-NULL `embedding_space = ''`, which is:
//!
//! - excluded from recall (the #2167 gate is `AND embedding_space = $active`,
//!   and an active fingerprint is never empty), AND
//! - excluded from `PostgresStore::list_unembedded`'s heal arm, which was
//!   `embedding IS NULL OR (embedding IS NOT NULL AND embedding_space IS
//!   NULL)` — `'' IS NULL` is false.
//!
//! So the row was PERMANENTLY non-recallable and unhealable while `migrate`
//! reported `errors: []`. The memory TEXT was never at risk; the SILENT,
//! PERMANENT loss of its semantic recall was.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres --test embedding_space_unattributed_3085_pg
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::embeddings::embedding_space_fingerprint;
use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

async fn live_pg() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

fn mem(id: &str, namespace: &str, title: &str, owner: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "pg unattributed-space corpus body".to_string(),
        priority: 5,
        confidence: 0.9,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        ..Memory::default()
    }
}

async fn pg_dim(store: &PostgresStore) -> usize {
    usize::try_from(
        store
            .current_embedding_dim()
            .await
            .expect("current_embedding_dim")
            .unwrap_or(384),
    )
    .unwrap_or(384)
}

fn unit_vec(dim: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; dim];
    v[0] = 1.0;
    v
}

/// The scan `run_embedding_backfill_on_store` consumes.
async fn unembedded_ids(store: &PostgresStore, admin: &CallerContext) -> Vec<String> {
    store
        .list_unembedded(admin, 5_000)
        .await
        .expect("list_unembedded")
        .into_iter()
        .map(|(id, _, _)| id)
        .collect()
}

/// #3085 half 1 — **fail closed**: neither SAL embedding-write funnel accepts
/// an EMPTY space stamp for a real vector, so the poisoned state can never be
/// minted again (this is what makes `migrate`'s skip safe rather than merely
/// polite).
#[tokio::test]
async fn pg_write_funnels_refuse_an_empty_embedding_space_3085() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:3085-pg";
    let ctx = CallerContext::for_agent(owner);
    let admin = CallerContext::for_admin(owner);
    let ns = format!("space3085-{}", uuid::Uuid::new_v4());
    let dim = pg_dim(&store).await;
    let vec = unit_vec(dim);

    let id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&id, &ns, "refuse-empty-space", owner))
        .await
        .expect("store row");

    let single = store.update_embedding(&admin, &id, Some(&vec), "").await;
    let batch = store
        .set_embeddings_batch(&admin, &[(id.clone(), vec.clone())], "")
        .await;
    // Whitespace-only is the same corrupt state with different bytes.
    let blank = store.update_embedding(&admin, &id, Some(&vec), "   ").await;
    let stored = store
        .get_embedding_with_space(&admin, &id)
        .await
        .expect("read back");
    let _ = store.forget(&ctx, Some(&ns), None, None, true).await;

    assert!(
        single.is_err(),
        "#3085: update_embedding must REFUSE an empty embedding_space"
    );
    assert!(
        batch.is_err(),
        "#3085: set_embeddings_batch must REFUSE an empty embedding_space"
    );
    assert!(
        blank.is_err(),
        "#3085: a whitespace-only stamp is the same unattributed state"
    );
    assert!(
        stored.is_none(),
        "#3085: a refused write must leave the row unembedded, never partly stamped"
    );
}

/// #3085 half 2 — **heal**: a row an OLDER binary already poisoned with
/// `embedding_space = ''` must be picked up by the serve-boot backfill scan
/// (`PostgresStore::list_unembedded`), exactly like a legacy NULL-space row,
/// so it self-heals from the durable text under the live embedder.
///
/// Seeded by raw SQL because the funnels now refuse to produce this state —
/// which is the point: the only way in is an older binary.
#[tokio::test]
async fn pg_boot_backfill_heals_already_poisoned_empty_space_rows_3085() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:3085-pg-heal";
    let ctx = CallerContext::for_agent(owner);
    let admin = CallerContext::for_admin(owner);
    let ns = format!("space3085h-{}", uuid::Uuid::new_v4());
    let active = embedding_space_fingerprint("nomic-embed-text");
    let dim = pg_dim(&store).await;
    let vec = unit_vec(dim);

    // A control row stamped with the ACTIVE space must stay OUT of the scan
    // (the predicate is not vacuously true), and the poisoned row must be IN.
    let healthy_id = uuid::Uuid::new_v4().to_string();
    let poisoned_id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&healthy_id, &ns, "active space row", owner))
        .await
        .expect("store healthy");
    store
        .store(&ctx, &mem(&poisoned_id, &ns, "poisoned space row", owner))
        .await
        .expect("store poisoned");
    store
        .set_embeddings_batch(&admin, &[(healthy_id.clone(), vec.clone())], &active)
        .await
        .expect("stamp healthy");
    store
        .set_embeddings_batch(&admin, &[(poisoned_id.clone(), vec.clone())], &active)
        .await
        .expect("stamp poisoned (pre-corruption)");
    // Reproduce EXACTLY what a pre-#3085 `migrate` left behind.
    sqlx::query("UPDATE memories SET embedding_space = '' WHERE id = $1")
        .bind(&poisoned_id)
        .execute(store.pool())
        .await
        .expect("seed the pre-#3085 poisoned state");

    let scan = unembedded_ids(&store, &admin).await;
    let _ = store.forget(&ctx, Some(&ns), None, None, true).await;

    assert!(
        scan.contains(&poisoned_id),
        "#3085: an already-poisoned embedding_space='' row MUST be returned by \
         list_unembedded so the serve-boot backfill re-derives it from the durable text; \
         pre-fix the heal arm was `embedding_space IS NULL`, which '' never satisfies — \
         the row was stuck outside BOTH recall and every heal scan"
    );
    assert!(
        !scan.contains(&healthy_id),
        "an ACTIVE-space row must stay out of the backfill scan (the predicate is not \
         vacuously true)"
    );
}
