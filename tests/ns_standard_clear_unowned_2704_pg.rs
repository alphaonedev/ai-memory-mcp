// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2704-F2 (CB-18, CWE-284) — POSTGRES `clear_namespace_standard` must
//! distinguish an UNOWNED standard (row exists, `agent_id` SQL NULL) from a
//! genuinely UNRESOLVABLE one (severed/dangling `standard_id`, no joined row).
//!
//! ## The defect this file pins
//!
//! The owner pre-fetch decoded the JOIN result with `.flatten()`:
//!
//! ```text
//! Option<Option<String>>  --flatten-->  Option<String>
//!   Some(None)  (row exists, agent_id NULL -> UNOWNED)  }-> both collapse to
//!   None        (no joined row -> UNRESOLVABLE)          }   None
//! ```
//!
//! So case (b) — a legacy pre-#929 / federated / non-object-metadata standard
//! whose `metadata->>'agent_id'` is SQL NULL — was misclassified as unresolvable
//! and REFUSED with a wrong "severed or dangling" error, even though the sqlite
//! twin (`recorded_owner == ""` => `is_unowned`) ALLOWS it (the documented
//! unowned-pass). The fix keeps `Some(None)` (unowned -> ALLOW) separable from
//! `None` (unresolvable -> refuse #2545).
//!
//! Pins:
//! - an UNOWNED pg standard is clearable again by a non-bypass caller (unowned-pass)
//! - a SEVERED (NULL `standard_id`) pg standard still refuses with the
//!   severed/dangling message (#2545 not weakened)
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip (the house pattern). Deliberately NOT `#[ignore]` (the PR postgres
//! job does not pass `--include-ignored`).

#![cfg(feature = "sal-postgres")]

use std::sync::Arc;

use serde_json::json;

use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Admin ctx — the TEST's own seed write, so it is not visibility-filtered.
fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2704-pg");
    ctx.bypass_visibility = true;
    ctx
}

async fn raw_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("raw pool for namespace_meta assertions")
}

async fn seed_memory(store: &Arc<dyn MemoryStore>, id: &str, namespace: &str) {
    let mem = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: uniq("std-mem-2704"),
        content: "namespace-standard candidate row (2704)".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:seed-2704", "scope": "shared"}),
        ..Default::default()
    };
    store.store(&admin_ctx(), &mem).await.expect("seed row");
}

// ---------------------------------------------------------------------
// R-203 #1 — an UNOWNED standard (agent_id SQL NULL) is clearable again by a
// non-bypass caller. Pre-fix `.flatten()` misclassified it as unresolvable
// and returned the wrong "severed or dangling" PermissionDenied.
// ---------------------------------------------------------------------

#[tokio::test]
async fn unowned_standard_clears_unowned_pass_2704_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP unowned_standard_clears_unowned_pass_2704_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    let pool = raw_pool(&url).await;

    let ns = uniq("unowned-ns-2704");
    let std_id = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &std_id, &ns).await;
    store
        .set_namespace_standard(&admin_ctx(), &ns, &std_id, None)
        .await
        .expect("bind standard");

    // Make the standard memory UNOWNED: strip agent_id so
    // `metadata->>'agent_id'` is SQL NULL (the JOIN yields Some(None)).
    sqlx::query("UPDATE memories SET metadata = '{}'::jsonb WHERE id = $1")
        .bind(&std_id)
        .execute(&pool)
        .await
        .expect("strip agent_id");

    // A non-bypass, non-owner caller clears it. Post-fix this is the
    // documented unowned-pass (ALLOW); pre-fix it was refused as unresolvable.
    let ctx = ai_memory::store::CallerContext::for_agent("ai:clearer-2704");
    let cleared = store
        .clear_namespace_standard(&ctx, &ns)
        .await
        .expect("#2704: an UNOWNED standard must be clearable (unowned-pass)");
    assert!(cleared, "#2704: the unowned standard row must be removed");

    // And the binding is gone.
    let row: Option<(String,)> =
        sqlx::query_as("SELECT namespace FROM namespace_meta WHERE namespace = $1")
            .bind(&ns)
            .fetch_optional(&pool)
            .await
            .expect("select namespace_meta");
    assert!(row.is_none(), "#2704: namespace_meta row must be deleted");
}

// ---------------------------------------------------------------------
// R-203 #2 — parity control: a SEVERED standard (NULL standard_id, no joined
// row) STILL refuses with the severed/dangling message. #2545 not weakened.
// ---------------------------------------------------------------------

#[tokio::test]
async fn severed_standard_still_refuses_2704_pg() {
    let Some(url) = pg_url() else {
        eprintln!("SKIP severed_standard_still_refuses_2704_pg: no AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    let pool = raw_pool(&url).await;

    let ns = uniq("severed-ns-2704");
    let std_id = uuid::Uuid::new_v4().to_string();
    seed_memory(&store, &std_id, &ns).await;
    store
        .set_namespace_standard(&admin_ctx(), &ns, &std_id, None)
        .await
        .expect("bind standard");

    // Sever the binding: standard_id NULL (the #2503 severed floor). The JOIN
    // now yields NO row -> None -> genuinely unresolvable.
    sqlx::query("UPDATE namespace_meta SET standard_id = NULL WHERE namespace = $1")
        .bind(&ns)
        .execute(&pool)
        .await
        .expect("sever standard_id");

    let ctx = ai_memory::store::CallerContext::for_agent("ai:clearer-2704");
    let err = store
        .clear_namespace_standard(&ctx, &ns)
        .await
        .expect_err("#2545: a severed/unresolvable standard must refuse a non-bypass clear");
    let msg = err.to_string();
    assert!(
        msg.contains("unresolvable") && msg.contains("severed or dangling"),
        "#2545: severed clear must refuse with the unresolvable message; got: {msg}"
    );

    // The severed binding row must survive the refused clear.
    let row: Option<(String,)> =
        sqlx::query_as("SELECT namespace FROM namespace_meta WHERE namespace = $1")
            .bind(&ns)
            .fetch_optional(&pool)
            .await
            .expect("select namespace_meta");
    assert!(
        row.is_some(),
        "#2545: the namespace_meta row must survive the refused severed clear"
    );
}
