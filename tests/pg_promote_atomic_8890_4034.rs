// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8890 / #4034 — PostgreSQL atomicity of the vertical promote and the
//! stale-read lock of the two update funnels.
//!
//! ## Class
//!
//! Lost update / non-atomic multi-statement write on PostgreSQL. The invariant
//! these cells pin: `pg_promote_to_namespace` commits ALL of its row and link
//! writes or NONE, and a concurrent writer of a row cannot be overwritten by a
//! decision the update funnels made on a stale read.
//!
//! * **#8890 rows** — the promote clone (`store`) and its `derived_from` link
//!   (`link`) ran as two transactions. A failure of the link statement left the
//!   clone committed; when the target namespace already held the title, the
//!   clone upsert had already rewritten that memory. A scoped `BEFORE INSERT`
//!   trigger on `memory_links` forces the failure BETWEEN the row write and the
//!   link write (the exact injection point the class names), and the p05 shape
//!   reaches the same point through the lineage cycle guard with no trigger.
//! * **#4034 rows** — the trait `update` and the If-Match funnel
//!   (`update_with_expected_version`) compose the archive snapshot decision
//!   and the metadata merge from a pre-read. A concurrent content write
//!   committed between that read and the UPDATE must be the content that is
//!   archived as the in-place-edit pre-image. The interleaving is
//!   deterministic: a raw transaction holds the row lock, the funnel is
//!   started, a `pg_blocking_pids` barrier proves it is waiting on that lock,
//!   and only then does the holder commit. No sleep decides the order.
//!
//! Gated on `feature = "sal-postgres"` with the runtime
//! `AI_MEMORY_TEST_POSTGRES_URL` soft-skip (the house pattern); never
//! `#[ignore]`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown)]

#[path = "common/pg_barrier.rs"]
mod pg_barrier;

use std::sync::Arc;

use ai_memory::models::{ConfidenceSource, Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};

/// Marker the injected link-insert failure raises; asserted verbatim.
const LINK_FAILURE_MARKER: &str = "forced link failure 8890";
/// SQLSTATE of a PL/pgSQL `RAISE EXCEPTION` with no explicit code.
const SQLSTATE_RAISE_EXCEPTION: &str = "P0001";
/// The error label `link_internal` gives a failed `memory_links` INSERT.
const LINK_INSERT_LABEL: &str = "insert memory_link";
/// Title the child carries and, in the same-title rows, the target holds.
const SHARED_TITLE: &str = "shared title 8890";
/// Durable text of the child being promoted.
const CHILD_CONTENT: &str = "child content 8890";
/// Durable text of the target-namespace memory that must survive.
const PARENT_CONTENT: &str = "parent content 8890";
/// Agent acting as requester of the approved promote.
const REQUESTER: &str = "ai:promoter-8890";
/// Author stamped on the seeded memories.
const AUTHOR: &str = "ai:author-8890";
/// Agent driving the #4034 lock cells.
const LOCK_AGENT: &str = "ai:lock-4034";
/// Seed content of the #4034 row.
const LOCK_SEED_CONTENT: &str = "content A 4034";
/// Content the concurrent holder commits while the funnel waits.
const LOCK_CONCURRENT_CONTENT: &str = "content B 4034";
/// Content the funnel under test writes.
const LOCK_PATCH_CONTENT: &str = "content C 4034";
/// Archive reason of an in-place edit snapshot.
const ARCHIVE_REASON_IN_PLACE_EDIT: &str = "in_place_edit";
/// Waiters the #4034 barrier must observe behind the holder.
const ONE_WAITER: i64 = 1;
/// Expected row / link counts.
const NONE: i64 = 0;
const ONE: i64 = 1;

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

fn admin_ctx(agent: &str) -> CallerContext {
    let mut ctx = CallerContext::for_agent(agent);
    ctx.bypass_visibility = true;
    ctx
}

fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn memory(id: &str, namespace: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": AUTHOR }),
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// Queue an APPROVED vertical promote of `memory_id` into `to_namespace`.
async fn queue_promote(pool: &sqlx::PgPool, memory_id: &str, from_ns: &str, to_ns: &str) -> String {
    let pending_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO pending_actions \
         (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status) \
         VALUES ($1, 'promote', $2, $3, $4, $5, $6, 'approved')",
    )
    .bind(&pending_id)
    .bind(memory_id)
    .bind(from_ns)
    .bind(serde_json::json!({ "id": memory_id, "to_namespace": to_ns }))
    .bind(REQUESTER)
    .bind(chrono::Utc::now())
    .execute(pool)
    .await
    .expect("insert approved promote pending");
    pending_id
}

/// Install a `BEFORE INSERT` trigger on `memory_links` that raises
/// [`LINK_FAILURE_MARKER`] for a link whose target is `target_id` only, so no
/// other cell sharing the database is affected. Returns the trigger name.
async fn install_link_failure(pool: &sqlx::PgPool, target_id: &str) -> String {
    let name = format!("fail_link_8890_{}", suffix());
    let target = uuid::Uuid::parse_str(target_id).expect("seeded ids are uuids");
    sqlx::query(&format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $f$ \
         BEGIN IF NEW.target_id = '{target}' THEN RAISE EXCEPTION '{LINK_FAILURE_MARKER}'; \
         END IF; RETURN NEW; END $f$"
    ))
    .execute(pool)
    .await
    .expect("create link failure function");
    sqlx::query(&format!(
        "CREATE TRIGGER {name} BEFORE INSERT ON memory_links \
         FOR EACH ROW EXECUTE FUNCTION {name}()"
    ))
    .execute(pool)
    .await
    .expect("create link failure trigger");
    name
}

async fn drop_link_failure(pool: &sqlx::PgPool, name: &str) {
    let _ = sqlx::query(&format!("DROP TRIGGER IF EXISTS {name} ON memory_links"))
        .execute(pool)
        .await;
    let _ = sqlx::query(&format!("DROP FUNCTION IF EXISTS {name}()"))
        .execute(pool)
        .await;
}

async fn count_titled(pool: &sqlx::PgPool, namespace: &str, title: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM memories WHERE namespace = $1 AND title = $2")
        .bind(namespace)
        .bind(title)
        .fetch_one(pool)
        .await
        .expect("count titled rows")
}

async fn count_in_namespace(pool: &sqlx::PgPool, namespace: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM memories WHERE namespace = $1")
        .bind(namespace)
        .fetch_one(pool)
        .await
        .expect("count namespace rows")
}

async fn count_links_touching(pool: &sqlx::PgPool, id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM memory_links WHERE source_id = $1 OR target_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count links")
}

/// Byte image of a row: content, title, version, updated_at and metadata.
async fn row_image(pool: &sqlx::PgPool, id: &str) -> (String, String, i64, String, String) {
    sqlx::query_as(
        "SELECT content, title, version::bigint, updated_at::text, metadata::text \
         FROM memories WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("row image")
}

async fn cleanup(pool: &sqlx::PgPool, pending_ids: &[&str], namespaces: &[&str]) {
    for pending in pending_ids {
        let _ = sqlx::query("DELETE FROM pending_actions WHERE id = $1")
            .bind(pending)
            .execute(pool)
            .await;
    }
    for ns in namespaces {
        let _ = sqlx::query(
            "DELETE FROM memory_links WHERE source_id IN (SELECT id FROM memories WHERE namespace = $1) \
             OR target_id IN (SELECT id FROM memories WHERE namespace = $1)",
        )
        .bind(ns)
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM archived_memories WHERE namespace = $1")
            .bind(ns)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
            .bind(ns)
            .execute(pool)
            .await;
    }
}

fn assert_forced_link_failure(err: &StoreError) {
    match err {
        StoreError::BackendUnavailable {
            backend,
            detail,
            sqlstate,
        } => {
            assert_eq!(backend, "postgres", "backend of the forced failure");
            assert_eq!(
                sqlstate.as_deref(),
                Some(SQLSTATE_RAISE_EXCEPTION),
                "sqlstate of the forced failure"
            );
            assert!(
                detail.starts_with(LINK_INSERT_LABEL) && detail.contains(LINK_FAILURE_MARKER),
                "the failure must be the forced link insert, got: {detail}"
            );
        }
        other => panic!("expected the forced link-insert failure, got {other:?}"),
    }
}

/// #8890 row A — a fresh clone (no same-title row in the target namespace):
/// a failure of the link insert leaves NO clone and NO link behind.
#[tokio::test]
async fn pg_promote_link_failure_leaves_no_clone_8890() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let parent_ns = format!("ns8890a{}", suffix());
    let child_ns = format!("{parent_ns}/team");
    let ctx = admin_ctx(REQUESTER);

    let child_id = uuid::Uuid::new_v4().to_string();
    store
        .store(
            &ctx,
            &memory(&child_id, &child_ns, SHARED_TITLE, CHILD_CONTENT),
        )
        .await
        .expect("seed child");
    let pending_id = queue_promote(&pool, &child_id, &child_ns, &parent_ns).await;
    let trigger = install_link_failure(&pool, &child_id).await;

    let result = store.execute_pending_action(&ctx, &pending_id).await;
    drop_link_failure(&pool, &trigger).await;

    let err = result.expect_err("the forced link failure must surface");
    assert_forced_link_failure(&err);
    let clones = count_titled(&pool, &parent_ns, SHARED_TITLE).await;
    let parent_rows = count_in_namespace(&pool, &parent_ns).await;
    let links = count_links_touching(&pool, &child_id).await;
    cleanup(&pool, &[&pending_id], &[&parent_ns, &child_ns]).await;

    assert_eq!(
        clones, NONE,
        "#8890: a failed link must roll the promote clone back (no row in the target namespace)"
    );
    assert_eq!(
        parent_rows, NONE,
        "#8890: the target namespace holds no row at all"
    );
    assert_eq!(links, NONE, "#8890: no derived_from link exists");
}

/// #8890 row B — the target namespace already holds the title: a failure of
/// the link insert leaves that memory byte-identical (the clone upsert must
/// not commit an overwrite the caller is told failed).
#[tokio::test]
async fn pg_promote_link_failure_leaves_same_title_target_unchanged_8890() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let parent_ns = format!("ns8890b{}", suffix());
    let child_ns = format!("{parent_ns}/team");
    let ctx = admin_ctx(REQUESTER);

    // Child first, then the target: the target is the NEWER row, so the
    // lineage guard (when enabled by another cell) admits the link and the
    // failure is the injected one.
    let child_id = uuid::Uuid::new_v4().to_string();
    store
        .store(
            &ctx,
            &memory(&child_id, &child_ns, SHARED_TITLE, CHILD_CONTENT),
        )
        .await
        .expect("seed child");
    let parent_id = uuid::Uuid::new_v4().to_string();
    store
        .store(
            &ctx,
            &memory(&parent_id, &parent_ns, SHARED_TITLE, PARENT_CONTENT),
        )
        .await
        .expect("seed same-title target");
    let before = row_image(&pool, &parent_id).await;
    let pending_id = queue_promote(&pool, &child_id, &child_ns, &parent_ns).await;
    let trigger = install_link_failure(&pool, &child_id).await;

    let result = store.execute_pending_action(&ctx, &pending_id).await;
    drop_link_failure(&pool, &trigger).await;

    let err = result.expect_err("the forced link failure must surface");
    assert_forced_link_failure(&err);
    let after = row_image(&pool, &parent_id).await;
    let titled = count_titled(&pool, &parent_ns, SHARED_TITLE).await;
    let links = count_links_touching(&pool, &child_id).await;
    cleanup(&pool, &[&pending_id], &[&parent_ns, &child_ns]).await;

    assert_eq!(
        after, before,
        "#8890: the same-title target must be byte-identical after a failed promote"
    );
    assert_eq!(
        after.0, PARENT_CONTENT,
        "#8890: the target keeps its own text"
    );
    assert_eq!(
        titled, ONE,
        "#8890: exactly the original target row holds the title"
    );
    assert_eq!(links, NONE, "#8890: no derived_from link exists");
}

/// #8890 row C — the exact p05 shape with no injection: P (target ns) and C
/// (child ns) share a title and C derived_from P exists. With the lineage DAG
/// on, the clone link P -> C is refused as a cycle; P must be byte-identical
/// and the only link is still C -> P.
#[tokio::test]
async fn pg_promote_refused_cycle_leaves_target_unchanged_p05_8890() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    ai_memory::config::set_lineage_dag(true);
    let parent_ns = format!("ns8890c{}", suffix());
    let child_ns = format!("{parent_ns}/team");
    let ctx = admin_ctx(REQUESTER);

    let parent_id = uuid::Uuid::new_v4().to_string();
    store
        .store(
            &ctx,
            &memory(&parent_id, &parent_ns, SHARED_TITLE, PARENT_CONTENT),
        )
        .await
        .expect("seed parent");
    let child_id = uuid::Uuid::new_v4().to_string();
    store
        .store(
            &ctx,
            &memory(&child_id, &child_ns, SHARED_TITLE, CHILD_CONTENT),
        )
        .await
        .expect("seed child");
    store
        .link(
            &ctx,
            &MemoryLink {
                source_id: child_id.clone(),
                target_id: parent_id.clone(),
                relation: MemoryLinkRelation::DerivedFrom,
                created_at: chrono::Utc::now().to_rfc3339(),
                signature: None,
                observed_by: None,
                valid_from: None,
                valid_until: None,
                attest_level: None,
                source_cid: None,
                target_cid: None,
            },
        )
        .await
        .expect("seed C derived_from P");
    let before = row_image(&pool, &parent_id).await;
    let pending_id = queue_promote(&pool, &child_id, &child_ns, &parent_ns).await;

    let result = store.execute_pending_action(&ctx, &pending_id).await;

    let after = row_image(&pool, &parent_id).await;
    let titled = count_titled(&pool, &parent_ns, SHARED_TITLE).await;
    let links = count_links_touching(&pool, &child_id).await;
    cleanup(&pool, &[&pending_id], &[&parent_ns, &child_ns]).await;

    match result {
        Err(StoreError::LinkRefused { detail }) => assert!(
            detail.contains(&parent_id) && detail.contains(&child_id),
            "the refusal names the clone link endpoints, got: {detail}"
        ),
        other => panic!("expected the lineage cycle refusal, got {other:?}"),
    }
    assert_eq!(
        after, before,
        "#8890 p05: the same-title target must be byte-identical after a refused promote"
    );
    assert_eq!(
        titled, ONE,
        "#8890 p05: exactly the original target row holds the title"
    );
    assert_eq!(
        links, ONE,
        "#8890 p05: the only link is still C derived_from P"
    );
}

/// Which update funnel a #4034 cell drives.
#[derive(Clone, Copy, Debug)]
enum Funnel {
    TraitUpdate,
    ExpectedVersionNone,
}

async fn wait_blocked_behind(pool: &sqlx::PgPool, holder_pid: i32, n: i64) {
    let end = pg_barrier::deadline();
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
        )
        .bind(holder_pid)
        .fetch_one(pool)
        .await
        .expect("barrier probe");
        if blocked >= n {
            return;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "barrier not reached: {blocked}/{n} blocked"
        );
        tokio::task::yield_now().await;
    }
}

/// #4034 — a content write committed while the funnel waits on the row lock
/// is the pre-image the funnel archives; the funnel's own content is live.
async fn concurrent_content_write_is_archived(funnel: Funnel) {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let store = Arc::new(store);
    let ns = format!("ns4034{}", suffix());
    let ctx = admin_ctx(LOCK_AGENT);
    let id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &memory(&id, &ns, "lock row 4034", LOCK_SEED_CONTENT))
        .await
        .expect("seed lock row");

    let mut holder = pool.begin().await.expect("begin holder");
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *holder)
        .await
        .expect("holder pid");
    sqlx::query("UPDATE memories SET content = $2 WHERE id = $1")
        .bind(&id)
        .bind(LOCK_CONCURRENT_CONTENT)
        .execute(&mut *holder)
        .await
        .expect("holder writes content B");

    let patch = UpdatePatch {
        content: Some(LOCK_PATCH_CONTENT.to_string()),
        ..UpdatePatch::default()
    };
    let task = {
        let store = Arc::clone(&store);
        let ctx = ctx.clone();
        let id = id.clone();
        tokio::spawn(async move {
            match funnel {
                Funnel::TraitUpdate => store.update(&ctx, &id, patch).await,
                Funnel::ExpectedVersionNone => store
                    .update_with_expected_version(&ctx, &id, patch, None)
                    .await
                    .map(|_| ()),
            }
        })
    };
    wait_blocked_behind(&pool, holder_pid, ONE_WAITER).await;
    holder.commit().await.expect("holder commits content B");
    let outcome = task.await.expect("funnel task joins");

    let live: String = sqlx::query_scalar("SELECT content FROM memories WHERE id = $1")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("live content");
    let archived: Vec<(String, String)> =
        sqlx::query_as("SELECT content, archive_reason FROM archived_memories WHERE id = $1")
            .bind(&id)
            .fetch_all(&pool)
            .await
            .expect("archived rows");
    cleanup(&pool, &[], &[&ns]).await;

    outcome.unwrap_or_else(|e| panic!("{funnel:?} must succeed, got {e:?}"));
    assert_eq!(
        live, LOCK_PATCH_CONTENT,
        "{funnel:?}: the funnel's content is live"
    );
    assert_eq!(
        archived,
        vec![(
            LOCK_CONCURRENT_CONTENT.to_string(),
            ARCHIVE_REASON_IN_PLACE_EDIT.to_string()
        )],
        "#4034 {funnel:?}: the concurrently committed content must be the archived pre-image"
    );
}

#[tokio::test]
async fn pg_trait_update_archives_concurrent_content_4034() {
    concurrent_content_write_is_archived(Funnel::TraitUpdate).await;
}

#[tokio::test]
async fn pg_expected_version_none_archives_concurrent_content_4034() {
    concurrent_content_write_is_archived(Funnel::ExpectedVersionNone).await;
}
