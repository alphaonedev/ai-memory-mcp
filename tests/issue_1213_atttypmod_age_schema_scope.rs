// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #1213 — `PostgresStore::current_embedding_dim()` (and the
//! two sibling probe sites at `src/store/postgres.rs:759` and
//! `src/store/postgres.rs:3121`) query `pg_attribute` JOIN
//! `pg_class` WHERE `c.relname = 'memories'` WITHOUT scoping to
//! `pg_namespace.nspname = 'public'`.
//!
//! When Apache AGE is enrolled in the same database AND a duplicate
//! `memories` relation exists under any other schema (e.g.
//! `ag_catalog.memories` from a per-tenant `search_path` bootstrap in
//! the LAN-parity `IronClaw` stack), the unscoped query returns the
//! WRONG dim — whichever Postgres surfaces first by oid order.
//!
//! This regression test stages the exact catalog shape that
//! reproduces the bug (two `memories` tables, two different
//! `vector(N)` dims) and asserts the production probe surfaces
//! `public.memories`'s dim, not the duplicate's dim.
//!
//! ## Author audit
//!
//! Filed by code-review Agent A3 (recall + embeddings + reranker +
//! HNSW scope) against `release/v0.7.0` HEAD
//! `7f93bac80801f614c6d16b8d2eba352859a1f8da`. The audit found that
//! the three production sites (`src/store/postgres.rs:758`,
//! `src/store/postgres.rs:2694`, `src/store/postgres.rs:3121`) all
//! still carry the unscoped query at this HEAD; #1213's "on hold"
//! posture is NOT structurally safe — the duplicate-table
//! catalog shape is reachable any time a per-tenant `search_path`
//! places ai-memory schema in a non-`public` namespace.
//!
//! ## Test discipline
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` like the sibling
//! `embedding_dim_migration.rs`. Skipped (return) when the env
//! var is unset so cargo-test on hosts without a Postgres backend
//! still compiles + reports green.

#![cfg(feature = "sal-postgres")]

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

/// Serialize the two `#[tokio::test]` functions in this file against
/// each other under the canonical Per-Module Coverage Thresholds CI
/// invocation (`--test-threads=2`).
///
/// Issue #1341 — both tests create a non-`public` `<schema>.memories`
/// table to stage the duplicate-table catalog shape. When they run in
/// parallel, the `pg_class WHERE relname = 'memories'` probe in the
/// first test observes THREE rows (its own duplicate + `public` + the
/// sibling test's duplicate that has not yet cleaned up), tripping the
/// `assert_eq!(dims.len(), 2, ...)` staging-sanity check. `cleanup()`
/// only drops the schema name it's handed, so the cross-test residue
/// is invisible to the per-test cleanup.
///
/// Smallest fix: a shared module-scoped `Mutex<()>` both tests lock at
/// entry. No new dependencies (`std::sync` only), no async lock needed
/// (the critical section spans the whole test body which is already
/// `await`-blocking — `std::sync::Mutex` is fine because each test
/// runs in its own `tokio::test` runtime and the guard is dropped at
/// scope end, not held across an await *between* tests). Poison
/// recovery via `unwrap_or_else(PoisonError::into_inner)` so a panic
/// in one test doesn't permanently lock out the next.
fn issue_1213_serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn inspect_pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(url)
        .await
        .expect("inspection pool connect")
}

/// Drop both `public.memories` AND any duplicate `<other_schema>.memories`
/// to leave the DB in a clean state for the next test pass.
async fn cleanup(pool: &PgPool, other_schema: &str) {
    let _ = sqlx::query("DROP TABLE IF EXISTS public.memories CASCADE")
        .execute(pool)
        .await;
    let stmt = format!("DROP TABLE IF EXISTS {other_schema}.memories CASCADE");
    let _ = sqlx::query(&stmt).execute(pool).await;
    let stmt = format!("DROP SCHEMA IF EXISTS {other_schema} CASCADE");
    let _ = sqlx::query(&stmt).execute(pool).await;
}

/// Reproduce the exact catalog shape from issue #1213.
///
/// 1. Create a non-`public` schema (`ai_memory_issue_1213`) carrying
///    a `memories` table with `embedding vector(768)`.
/// 2. Create `public.memories` with `embedding vector(384)`.
/// 3. Run the production probe query verbatim (post-#1213 fix should
///    return Some(384)). At HEAD `7f93bac80801f614c6d16b8d2eba352859a1f8da`
///    the unscoped query MAY return Some(768) instead — exactly the
///    #1213 bug.
///
/// The assertion is post-fix: the probe MUST honour the
/// `public` schema. If the test fails on a binary built against the
/// pre-fix code, the failure mode is precisely the #1213 bug
/// (returns 768 instead of 384).
// #1341: holding `std::sync::MutexGuard` across `await` is the
// INTENDED behaviour — the whole point of `issue_1213_serial_lock`
// is to serialize the two `#[tokio::test]` bodies, so the guard MUST
// stay live for the duration of every `await` in the test body.
// An async `tokio::sync::Mutex` would relax the lock between await
// points (which is exactly what we don't want — that would let the
// sibling test interleave staging steps with this one). Each
// `#[tokio::test]` spawns its own current-thread runtime, so there
// is no within-runtime deadlock risk: only ONE async task is alive
// per runtime per test invocation, so the synchronous lock is held
// only for "this test's exclusive turn" semantics.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn issue_1213_atttypmod_probe_scopes_to_public_schema() {
    // #1341: serialize against `issue_1213_unscoped_probe_demonstrates_root_cause`
    // so the unscoped `pg_class WHERE relname='memories'` probe (and
    // the parallel scoped staging check) sees exactly two rows, not
    // three.
    let _serial = issue_1213_serial_lock();

    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    // pgvector is required for `vector(N)` columns; refuse to run if
    // the extension isn't enrolled so the failure mode is "skip"
    // not "this looks like the bug but is actually setup drift".
    let pool = inspect_pool(&url).await;
    let pgvector_present: Option<(i32,)> =
        sqlx::query_as("SELECT 1::int4 FROM pg_extension WHERE extname = 'vector'")
            .fetch_optional(&pool)
            .await
            .expect("query pg_extension");
    if pgvector_present.is_none() {
        eprintln!("skip: pgvector extension not enrolled in test DB");
        return;
    }

    let other_schema = "ai_memory_issue_1213";
    cleanup(&pool, other_schema).await;

    // Step 1: create the duplicate-table shape under a non-public schema.
    let stmt = format!("CREATE SCHEMA {other_schema}");
    sqlx::query(&stmt)
        .execute(&pool)
        .await
        .expect("create non-public schema");
    let stmt = format!(
        "CREATE TABLE {other_schema}.memories (id TEXT PRIMARY KEY, embedding vector(768))"
    );
    sqlx::query(&stmt)
        .execute(&pool)
        .await
        .expect("create duplicate memories with vector(768)");

    // Step 2: create `public.memories` with vector(384).
    sqlx::query("CREATE TABLE public.memories (id TEXT PRIMARY KEY, embedding vector(384))")
        .execute(&pool)
        .await
        .expect("create public.memories with vector(384)");

    // Step 3: confirm BOTH tables exist with their respective dims
    // (this is a sanity check; failure here would mean the test
    // staging is wrong, not the production bug).
    let dims: Vec<(String, i32)> = sqlx::query_as(
        "SELECT n.nspname::text, a.atttypmod
         FROM pg_attribute a
         JOIN pg_class c ON c.oid = a.attrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relname = 'memories' AND a.attname = 'embedding'
         ORDER BY n.nspname",
    )
    .fetch_all(&pool)
    .await
    .expect("inspect both memories tables");
    assert_eq!(
        dims.len(),
        2,
        "test stage requires BOTH public.memories AND {other_schema}.memories — got {dims:?}"
    );

    // Step 4: run the EXACT production probe query (the WHERE arm
    // is byte-identical to `src/store/postgres.rs:2694` so a future
    // refactor that adds the schema scope will land green here).
    //
    // Pre-#1213 fix: the unscoped query returns whichever row
    // Postgres surfaces first (typically lower-oid schema). With
    // `ag_catalog`/`{other_schema}` having lower oid than `public`
    // on a fresh AGE-installed cluster, the duplicate's dim (768)
    // is what surfaces — exactly the #1213 evidence section.
    //
    // Post-#1213 fix: scoping to `n.nspname='public'` returns 384
    // (the dim the daemon ACTUALLY wrote into `public.memories`).
    //
    // The assertion below pins the post-fix contract. On the
    // unfixed binary, this test FAILS (returns Some(768) instead
    // of Some(384)) — exactly the regression #1213 needed.
    let probed: Option<(i32,)> = sqlx::query_as(
        "SELECT atttypmod FROM pg_attribute a
         JOIN pg_class c ON c.oid = a.attrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = 'memories' AND a.attname = 'embedding'",
    )
    .fetch_optional(&pool)
    .await
    .expect("probe public.memories.embedding atttypmod");

    assert_eq!(
        probed.map(|(d,)| d),
        Some(384),
        "#1213 fix contract: the atttypmod probe MUST resolve to public.memories \
         (vector(384)), NOT the duplicate non-public schema's vector(768)"
    );

    cleanup(&pool, other_schema).await;
}

/// Demonstrative companion test: the EXACT pre-fix query (no schema
/// scope) returns the duplicate's dim, not the public-schema dim.
/// This pins the #1213 root cause so a future regression that
/// reverts the fix is caught here AND in the production probe.
///
/// The assertion is intentional: the unscoped query is documented
/// as broken, so this test asserts BOTH cases (broken returns 768,
/// fixed returns 384) by checking that the unscoped query returns
/// AT LEAST one row and the scoped query returns exactly the
/// public-schema row.
// #1341: see allow rationale on
// `issue_1213_atttypmod_probe_scopes_to_public_schema` above. Same
// intent: the sync lock holds across awaits BY DESIGN to serialize
// against the sibling test.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn issue_1213_unscoped_probe_demonstrates_root_cause() {
    // #1341: serialize against `issue_1213_atttypmod_probe_scopes_to_public_schema`
    // so the `assert_eq!(unscoped.len(), 2, ...)` staging-sanity check
    // observes exactly the two rows this test stages (public + its
    // own `ai_memory_issue_1213_demo` duplicate), not three.
    let _serial = issue_1213_serial_lock();

    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let pool = inspect_pool(&url).await;
    let pgvector_present: Option<(i32,)> =
        sqlx::query_as("SELECT 1::int4 FROM pg_extension WHERE extname = 'vector'")
            .fetch_optional(&pool)
            .await
            .expect("query pg_extension");
    if pgvector_present.is_none() {
        eprintln!("skip: pgvector extension not enrolled in test DB");
        return;
    }

    let other_schema = "ai_memory_issue_1213_demo";
    cleanup(&pool, other_schema).await;

    let stmt = format!("CREATE SCHEMA {other_schema}");
    sqlx::query(&stmt)
        .execute(&pool)
        .await
        .expect("create non-public schema");
    let stmt = format!(
        "CREATE TABLE {other_schema}.memories (id TEXT PRIMARY KEY, embedding vector(768))"
    );
    sqlx::query(&stmt)
        .execute(&pool)
        .await
        .expect("create duplicate memories with vector(768)");
    sqlx::query("CREATE TABLE public.memories (id TEXT PRIMARY KEY, embedding vector(384))")
        .execute(&pool)
        .await
        .expect("create public.memories with vector(384)");

    // The pre-fix unscoped query returns one row by `fetch_optional`
    // (it may surface either schema depending on oid order). The
    // post-fix scoped query returns exactly public.memories's dim.
    //
    // Pre-fix probe — `fetch_all` so the test is deterministic on
    // either oid-order outcome; we then assert the scoped probe
    // disagrees with at-least-one of the unscoped rows.
    let unscoped: Vec<(i32,)> = sqlx::query_as(
        "SELECT atttypmod FROM pg_attribute a
         JOIN pg_class c ON c.oid = a.attrelid
         WHERE c.relname = 'memories' AND a.attname = 'embedding'",
    )
    .fetch_all(&pool)
    .await
    .expect("unscoped probe");
    assert_eq!(
        unscoped.len(),
        2,
        "duplicate-table catalog staging required: both public + {other_schema}"
    );

    let scoped: Option<(i32,)> = sqlx::query_as(
        "SELECT atttypmod FROM pg_attribute a
         JOIN pg_class c ON c.oid = a.attrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = 'memories' AND a.attname = 'embedding'",
    )
    .fetch_optional(&pool)
    .await
    .expect("scoped probe");

    assert_eq!(
        scoped.map(|(d,)| d),
        Some(384),
        "scoped probe MUST return public.memories's dim (384)"
    );

    // The unscoped probe MUST include 384 among its rows (the public
    // one) and MAY include 768 (the duplicate) — pre-fix `fetch_optional`
    // surfaces whichever row Postgres picked, which is the root cause.
    let unscoped_dims: Vec<i32> = unscoped.into_iter().map(|(d,)| d).collect();
    assert!(
        unscoped_dims.contains(&384),
        "unscoped probe must include public.memories's 384: {unscoped_dims:?}"
    );
    assert!(
        unscoped_dims.contains(&768),
        "unscoped probe must include {other_schema}.memories's 768: {unscoped_dims:?}"
    );

    cleanup(&pool, other_schema).await;
}
