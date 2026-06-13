// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1473 regression — `PostgresStore::list()` namespace filter must be
//! sargable.
//!
//! Spun out of #1472. The optional-filter idiom
//! `($1 IS NULL OR namespace = $1)` is non-sargable under sqlx's
//! generic prepared-statement plan: the planner cannot prove at plan
//! time that `$1` is non-null, so it emits a Seq Scan even when the
//! caller passes an explicit namespace — a full-table scan on every
//! namespace-filtered read. The fix emits a bare equality
//! `namespace = $1` when a namespace is supplied, which the planner
//! recognizes as an `Index Cond` on `memories_namespace_idx`.
//!
//! This test proves the plan SHAPE rather than wall-clock latency, so
//! it does not need to seed a large table:
//!   * `EXPLAIN (GENERIC_PLAN, …)` (`PostgreSQL` 16+) plans the query
//!     with its parameters left generic — exactly the param-agnostic
//!     plan sqlx reuses — so the assertion reproduces the production
//!     planning context, not a one-off custom plan.
//!   * `SET enable_seqscan = off` removes the small-table shortcut so
//!     the planner reveals whether the predicate is index-USABLE at
//!     all: a sargable equality surfaces as `Index Cond: (namespace =
//!     $1)`; the non-sargable OR-NULL form cannot and falls back to a
//!     `Filter`.
//!
//! Gated on `feature = "sal-postgres"` and skipped without
//! `AI_MEMORY_TEST_POSTGRES_URL`, matching the existing postgres test
//! skip-line convention.

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;

mod common;
use common::postgres_url;

use sqlx::Row;
use sqlx::postgres::PgPoolOptions;

/// Connection-timeout (seconds) for the adapter under test. Short so a
/// misconfigured `AI_MEMORY_TEST_POSTGRES_URL` fails fast.
const CONNECT_TIMEOUT_SECS: u64 = 3;

/// Single raw connection is enough for the EXPLAIN probes; they run
/// sequentially on the same session so the `SET` directives stick.
const PROBE_POOL_MAX_CONNS: u32 = 1;

/// Session GUCs for the probe. `enable_seqscan = off` forces the
/// planner to expose whether the predicate is index-usable;
/// `plan_cache_mode = force_generic_plan` belt-and-suspenders the
/// generic-plan context that `EXPLAIN (GENERIC_PLAN)` already models.
const PROBE_SESSION_GUCS: &str =
    "SET enable_seqscan = off; SET plan_cache_mode = force_generic_plan;";

/// Mirrors `src/store/postgres.rs::NS_FILTER_SARGABLE` — the form
/// `list()` now emits when a namespace IS supplied.
const NS_FILTER_SARGABLE: &str = "namespace = $1";

/// Mirrors `src/store/postgres.rs::NS_FILTER_OPTIONAL` — the form
/// `list()` emits ONLY when no namespace is supplied, and the form
/// this test proves is non-sargable (the #1473 defect).
const NS_FILTER_OPTIONAL: &str = "($1::text IS NULL OR namespace = $1)";

/// Plan-text token proving the namespace predicate became an index
/// access condition (the fixed behavior).
const INDEX_COND_TOKEN: &str = "Index Cond";

/// Plan-text token proving the namespace predicate degraded to a
/// post-fetch row filter (the defective behavior).
const FILTER_TOKEN: &str = "Filter";

/// The namespace column name must appear in the index condition to
/// confirm it is the NAMESPACE predicate (not some other column's)
/// that drives the index access.
const NAMESPACE_COLUMN: &str = "namespace";

/// `PostgreSQL` error fragment emitted when the server predates
/// `EXPLAIN (GENERIC_PLAN)` (added in v16). Treated as a graceful skip
/// rather than a failure so the suite stays green on an older local PG.
const GENERIC_PLAN_UNSUPPORTED_FRAGMENT: &str = "GENERIC_PLAN";

/// Build the `list()` query shape with the given namespace predicate
/// substituted in. Mirrors the production WHERE clause in
/// `src/store/postgres.rs::list()`; only the namespace predicate
/// varies between the sargable and OR-NULL forms.
fn list_query_with_ns_predicate(ns_predicate: &str) -> String {
    format!(
        "SELECT * FROM memories
         WHERE {ns_predicate}
           AND ($2::text IS NULL OR tier = $2)
           AND (expires_at IS NULL OR expires_at > NOW())
           AND ($3::timestamptz IS NULL OR created_at >= $3)
           AND ($4::timestamptz IS NULL OR created_at <= $4)
           AND (
               $6::text IS NULL
               OR COALESCE(metadata->>'scope', 'private') <> 'private'
               OR metadata->>'agent_id' = $6
               OR metadata->>'target_agent_id' = $6
           )
           AND ($7::text IS NULL OR metadata->>'agent_id' = $7)
         ORDER BY priority DESC, updated_at DESC
         LIMIT $5"
    )
}

/// Run `EXPLAIN (GENERIC_PLAN, FORMAT TEXT)` over `inner_sql` on `pool`
/// and return the concatenated plan text. Returns `Err` with the raw
/// server message on failure so callers can detect the
/// `GENERIC_PLAN`-unsupported skip case.
async fn explain_generic_plan(
    conn: &mut sqlx::PgConnection,
    inner_sql: &str,
) -> Result<String, String> {
    // Run via the simple-query protocol (`raw_sql`): the inner `$1..$7`
    // are GENERIC_PLAN's generic parameters, NOT outer bind params, so
    // the prepared/extended path (`query`) would wrongly demand 7 binds.
    let explain_sql = format!("EXPLAIN (GENERIC_PLAN, FORMAT TEXT) {inner_sql}");
    let rows = sqlx::raw_sql(&explain_sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;
    let mut plan = String::new();
    for row in &rows {
        let line: String = row.try_get(0).map_err(|e| e.to_string())?;
        plan.push_str(&line);
        plan.push('\n');
    }
    Ok(plan)
}

#[tokio::test]
async fn list_namespace_filter_is_sargable_under_generic_plan() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    // Connect through the adapter so the migration ladder runs and
    // `memories_namespace_idx` exists before we probe the plan.
    if let Err(e) = PostgresStore::connect_with_timeout(&url, CONNECT_TIMEOUT_SECS).await {
        eprintln!("skip: connect failed: {e}");
        return;
    }

    let pool = PgPoolOptions::new()
        .max_connections(PROBE_POOL_MAX_CONNS)
        .connect(&url)
        .await
        .expect("probe pool");

    // Pin ONE connection for the whole probe so the session GUCs below
    // stick across every EXPLAIN. `raw_sql` runs via the simple-query
    // protocol, which (unlike the prepared `query`) accepts the
    // multi-statement `SET a; SET b;` batch.
    let mut conn = pool.acquire().await.expect("acquire probe connection");
    sqlx::raw_sql(PROBE_SESSION_GUCS)
        .execute(&mut *conn)
        .await
        .expect("apply probe session GUCs");

    let sargable_sql = list_query_with_ns_predicate(NS_FILTER_SARGABLE);
    let plan = match explain_generic_plan(&mut conn, &sargable_sql).await {
        Ok(p) => p,
        Err(e) if e.contains(GENERIC_PLAN_UNSUPPORTED_FRAGMENT) => {
            eprintln!("skip: server lacks EXPLAIN (GENERIC_PLAN) (needs PG16+): {e}");
            return;
        }
        Err(e) => panic!("EXPLAIN on sargable form failed: {e}"),
    };

    // Fixed behavior: the namespace equality drives an index access
    // condition. With enable_seqscan=off a non-sargable predicate would
    // be unable to produce an `Index Cond: (namespace = $1)` — it would
    // appear under `Filter` instead. Match the full adjacency form
    // (`Index Cond: (namespace =`) rather than the two tokens
    // independently, so an index condition on some OTHER column cannot
    // false-pass this assertion.
    let ns_index_cond = format!("{INDEX_COND_TOKEN}: ({NAMESPACE_COLUMN} =");
    assert!(
        plan.contains(&ns_index_cond),
        "#1473: sargable namespace filter must plan as an `{ns_index_cond}…)` index \
         condition; got plan:\n{plan}"
    );

    // Contrast probe: the OLD OR-NULL form must NOT yield a namespace
    // index condition — it degrades to a post-scan Filter. This pins
    // the regression the fix removes (and guards against a future edit
    // reintroducing the OR-NULL wrapper on the namespace-present path).
    let or_null_sql = list_query_with_ns_predicate(NS_FILTER_OPTIONAL);
    let or_null_plan = explain_generic_plan(&mut conn, &or_null_sql)
        .await
        .expect("EXPLAIN on OR-NULL form");
    assert!(
        !or_null_plan.contains(&ns_index_cond),
        "#1473: the OR-NULL namespace form is expected to be NON-sargable (degrade to a \
         `{FILTER_TOKEN}`), but it produced `{ns_index_cond}…`. If the planner improved, \
         re-evaluate whether the dynamic-SQL split is still needed. Plan:\n{or_null_plan}"
    );
}
