// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3188 — POSTGRES twin proving cross-backend parity of `parent = None`
//! auto-detection in `set_namespace_standard`.
//!
//! ## The divergence this file pins
//!
//! `db::set_namespace_standard` (sqlite) resolves a `parent = None` bind by
//! walking the `-`-truncated ancestors and binding the first that has a
//! standard (`auto_detect_parent`), so `team-eng` inherits `team`. Pre-#3188
//! `PostgresStore::set_namespace_standard` bound the caller's parent verbatim
//! — NULL when `None` — so on postgres `team-eng` was an ungoverned ROOT while
//! on sqlite it inherited `team`. Governance inheritance walks
//! `namespace_meta.parent_namespace` (`build_namespace_chain` /
//! `pg_namespace_standard_owner_in_tx`), so the divergent bound parent meant a
//! DIVERGENT governance chain across backends. #3188 ports the `-`-prefix
//! detection to postgres (`pg_auto_detect_parent`) so both backends bind the
//! SAME `parent_namespace`. The sqlite half is asserted by
//! `storage::tests::set_standard_parent_none_binds_inferred_parent_3188`.
//!
//! Row state is asserted with RAW SQL over an independent sqlx pool (the bind
//! is what matters, and the raw read is not subject to the withholding /
//! visibility layers).
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip (the house pattern). Deliberately NOT `#[ignore]`: the PR postgres
//! job does not pass `--include-ignored`, so an ignored test silently never
//! runs (the `federation_delete_ns_scope_2488_pg.rs` precedent).

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

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

fn test_ctx() -> CallerContext {
    let mut ctx = CallerContext::for_agent("ai:test-3188-pg");
    ctx.bypass_visibility = true;
    ctx
}

/// A minimal standard memory living in `namespace`.
fn std_memory(id: &str, namespace: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("std-{}", uuid::Uuid::new_v4()),
        content: "policy".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": "ai:test-3188-pg" }),
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// RAW `namespace_meta.parent_namespace` for `namespace` (independent pool).
async fn raw_parent(pool: &sqlx::PgPool, namespace: &str) -> Option<String> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT parent_namespace FROM namespace_meta WHERE namespace = $1")
            .bind(namespace)
            .fetch_optional(pool)
            .await
            .expect("raw namespace_meta probe");
    row.and_then(|(p,)| p)
}

async fn cleanup(pool: &sqlx::PgPool, namespaces: &[&str], ids: &[&str]) {
    for ns in namespaces {
        let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace = $1")
            .bind(ns)
            .execute(pool)
            .await;
    }
    for id in ids {
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }
}

/// #3188 — postgres `set_namespace_standard(parent = None)` on a `-`-prefixed
/// child auto-detects and binds the inferred parent, exactly as the sqlite
/// twin does — the SAME `parent_namespace` on both backends.
#[tokio::test]
async fn pg_set_standard_parent_none_binds_inferred_parent_3188() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let ctx = test_ctx();

    let parent_ns = uniq("team3188");
    let child_ns = format!("{parent_ns}-eng");
    let parent_id = uniq("std-parent");
    let child_id = uniq("std-child");

    store
        .store(&ctx, &std_memory(&parent_id, &parent_ns))
        .await
        .expect("store parent standard");
    store
        .store(&ctx, &std_memory(&child_id, &child_ns))
        .await
        .expect("store child standard");

    // Bind the parent's standard first, then the child with NO explicit parent.
    store
        .set_namespace_standard(&ctx, &parent_ns, &parent_id, None)
        .await
        .expect("set parent standard");
    store
        .set_namespace_standard(&ctx, &child_ns, &child_id, None)
        .await
        .expect("set child standard (parent auto-detected)");

    let bound = raw_parent(&pool, &child_ns).await;
    assert_eq!(
        bound.as_deref(),
        Some(parent_ns.as_str()),
        "#3188 parity: pg must auto-detect and bind the `-`-prefix parent for parent=None, \
         got {bound:?} (pre-fix this was NULL — an ungoverned root diverging from sqlite)"
    );

    cleanup(&pool, &[&child_ns, &parent_ns], &[&parent_id, &child_id]).await;
}

/// #3188 — when NO `-`-prefix ancestor has a standard bound, the walk yields
/// no parent and postgres binds NULL — a genuine root, not a fabricated
/// parent. Parity with the sqlite `Ok(None)` path.
#[tokio::test]
async fn pg_set_standard_parent_none_no_ancestor_binds_null_3188() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let ctx = test_ctx();

    // A `-`-prefixed namespace whose ancestors have NO standard bound.
    let child_ns = uniq("orphan3188-child");
    let child_id = uniq("std-orphan");

    store
        .store(&ctx, &std_memory(&child_id, &child_ns))
        .await
        .expect("store orphan standard");
    store
        .set_namespace_standard(&ctx, &child_ns, &child_id, None)
        .await
        .expect("set orphan standard");

    let bound = raw_parent(&pool, &child_ns).await;
    assert!(
        bound.is_none(),
        "#3188: no bound ancestor → NULL parent (genuine root), got {bound:?}"
    );

    cleanup(&pool, &[&child_ns], &[&child_id]).await;
}
