// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3245 — `PostgresStore::delete` must roll the `namespace_meta` SEVER
//! back with a failed row DELETE (sqlite twin:
//! `delete_rolls_the_namespace_standard_sever_back_with_the_row` in
//! `tests/parity_write_funnels.rs`).
//!
//! Pre-fix the sever ran pool-direct on `&self.pool` BEFORE `begin()`, so a
//! failing delete left the governance binding severed with the memory still
//! live. A `BEFORE DELETE` trigger injects the failure after the sever
//! (same shape as the sqlite test).
//!
//! `#[ignore]` + `sal-postgres`. Run against the scratch PG:
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://… \
//!   cargo test --features sal,sal-postgres \
//!     --test pg_delete_namespace_meta_atomicity_3245 \
//!     -- --include-ignored --nocapture
//! ```

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

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

fn sample_memory(id: &str, namespace: &str, owner: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("title-{id}"),
        content: "3245 pg delete atomicity".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        ..Memory::default()
    }
}

/// Identifier-safe suffix (hex only) for a per-run trigger / function name
/// so this test cannot collide with a sibling on the shared scratch PG.
fn ident_suffix(unique: uuid::Uuid) -> String {
    unique.simple().to_string()
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn pg_delete_failure_leaves_namespace_meta_intact_3245() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let unique = uuid::Uuid::new_v4();
    let suffix = ident_suffix(unique);
    let owner = format!("ai:3245-{suffix}");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = format!("fix-3245-{suffix}");
    let fn_name = format!("ai_memory_3245_block_del_{suffix}");
    let trig_name = format!("ai_memory_3245_trig_{suffix}");
    let pool = store.pool();

    let std_mem = sample_memory(&format!("mem-3245-{suffix}"), &ns, &owner);
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &ns, &std_id, None)
        .await
        .expect("set namespace standard");
    let pre = store
        .get_namespace_standard(&ctx, &ns)
        .await
        .expect("get standard pre-delete");
    assert_eq!(
        pre.as_ref().map(|(sid, _)| sid.as_str()),
        Some(std_id.as_str()),
        "standard must resolve before the injected failure"
    );

    // Drop any leftover from a previous killed run of this unique name,
    // then install a BEFORE DELETE trigger that aborts only this id.
    let drop_trig = format!("DROP TRIGGER IF EXISTS {trig_name} ON memories");
    let drop_fn = format!("DROP FUNCTION IF EXISTS {fn_name}()");
    sqlx::query(&drop_trig)
        .execute(pool)
        .await
        .expect("drop leftover trigger");
    sqlx::query(&drop_fn)
        .execute(pool)
        .await
        .expect("drop leftover function");

    let create_fn = format!(
        "CREATE FUNCTION {fn_name}() RETURNS trigger \
         LANGUAGE plpgsql AS $fn$ \
         BEGIN \
           RAISE EXCEPTION 'parity-injected delete failure'; \
         END; \
         $fn$;"
    );
    sqlx::query(&create_fn)
        .execute(pool)
        .await
        .expect("create abort function");
    let create_trig = format!(
        "CREATE TRIGGER {trig_name} \
         BEFORE DELETE ON memories \
         FOR EACH ROW \
         WHEN (OLD.id = '{std_id}') \
         EXECUTE FUNCTION {fn_name}()"
    );
    sqlx::query(&create_trig)
        .execute(pool)
        .await
        .expect("create abort trigger");

    let err = store
        .delete(&ctx, &std_id)
        .await
        .expect_err("the delete must fail");
    assert!(
        err.to_string().contains("parity-injected"),
        "expected the injected abort, got: {err}"
    );

    let bound: Option<String> =
        sqlx::query_scalar("SELECT standard_id FROM namespace_meta WHERE namespace = $1")
            .bind(&ns)
            .fetch_one(pool)
            .await
            .expect("read binding");
    assert_eq!(
        bound.as_deref(),
        Some(std_id.as_str()),
        "#3245: the namespace-standard SEVER must roll back with the failed \
         DELETE. Pre-fix the sever ran as its OWN autocommit statement, so \
         it COMMITTED and the namespace lost its governance binding while \
         the memory stayed live — an unrecoverable policy downgrade from a \
         delete that never happened"
    );
    let still_live = store.get(&ctx, &std_id).await;
    assert!(
        still_live.is_ok(),
        "the memory row must still be live after the rolled-back delete; \
         got {still_live:?}"
    );

    // Best-effort cleanup: drop the injector first so a later delete can
    // succeed, then remove the test rows.
    let _ = sqlx::query(&drop_trig).execute(pool).await;
    let _ = sqlx::query(&drop_fn).execute(pool).await;
    let _ = store.delete(&ctx, &std_id).await;
    let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace = $1")
        .bind(&ns)
        .execute(pool)
        .await;
}

/// Fable gate #3255 item 1 — deleting an unknown id must return `NotFound`
/// WITHOUT committing the namespace_meta sever (or any tombstone leaf).
/// Admin `bypass_visibility` is required so the caller-owns pre-check does
/// not NotFound before `begin()`; that is the arm that used to commit.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn pg_delete_unknown_id_does_not_commit_sever_or_tombstone_3245() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let unique = uuid::Uuid::new_v4();
    let suffix = ident_suffix(unique);
    let ns = format!("fix-3245-nf-{suffix}");
    let ghost_id = format!("ghost-3245-{suffix}");
    let pool = store.pool();
    let admin = CallerContext::for_admin("operator:3245-notfound");

    sqlx::query(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at) \
         VALUES ($1, $2, NOW()) \
         ON CONFLICT (namespace) DO UPDATE SET standard_id = EXCLUDED.standard_id",
    )
    .bind(&ns)
    .bind(&ghost_id)
    .execute(pool)
    .await
    .expect("seed namespace_meta bound to a never-stored id");

    let tombs_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forget_tombstones WHERE memory_id = $1")
            .bind(&ghost_id)
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    let err = store
        .delete(&admin, &ghost_id)
        .await
        .expect_err("unknown id must be NotFound");
    match err {
        ai_memory::store::StoreError::NotFound { id } => {
            assert_eq!(id, ghost_id);
        }
        other => panic!("expected NotFound, got {other:?}"),
    }

    let bound: Option<String> =
        sqlx::query_scalar("SELECT standard_id FROM namespace_meta WHERE namespace = $1")
            .bind(&ns)
            .fetch_one(pool)
            .await
            .expect("read binding");
    assert_eq!(
        bound.as_deref(),
        Some(ghost_id.as_str()),
        "NotFound must roll back the namespace_meta sever; a delete that \
         never happened must not downgrade governance"
    );

    let tombs_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forget_tombstones WHERE memory_id = $1")
            .bind(&ghost_id)
            .fetch_one(pool)
            .await
            .unwrap_or(0);
    assert_eq!(
        tombs_after, tombs_before,
        "NotFound must not insert a forget_tombstones row for a missing id"
    );

    let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace = $1")
        .bind(&ns)
        .execute(pool)
        .await;
}
