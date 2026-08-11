// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2602 + #2615 (postgres collation-stability twin) — this is the
//! #1724 collation-byte-range lesson class applied to the #2602/#2615
//! total-order tiebreaks: a TEXT column compared/ordered under a non-`C`
//! postgres collation orders DIFFERENTLY from sqlite's BINARY comparison,
//! so a tiebreak added to make ordering *cross-backend identical* can
//! itself silently reintroduce backend-dependent order if it isn't pinned
//! `COLLATE "C"`.
//!
//! `memories.id` is `TEXT PRIMARY KEY` on postgres (NOT `uuid`), and the
//! corpus is not guaranteed canonical lowercase UUIDs —
//! `portability::import` preserves ids verbatim and federation receive
//! applies a peer's `mem.id` verbatim with no UUID-format validation — so
//! a mixed-case id (`mem-a` vs `MEM-B`) is a live shape, not a
//! hypothetical. Likewise `recall_observations.recall_id` /
//! `.memory_id` are `TEXT`.
//!
//! This file proves, against a LIVE postgres instance:
//!
//! 1. `PostgresStore::list`'s `id ASC` tiebreak (#2602) is `COLLATE "C"`
//!    and produces the SAME order sqlite's BINARY comparison produces for
//!    mixed-case, non-canonical-UUID ids tied on `(priority, updated_at)`.
//! 2. `PostgresStore::list_recall_observations`'s `memory_id` / `recall_id`
//!    tiebreaks (#2615) are `COLLATE "C"` and produce the SAME order
//!    sqlite produces for rows tied on `(observed_at, rank)` that span
//!    TWO different `recall_id`s observing the SAME `memory_id` (the
//!    residual tie B2 closes: the ledger's actual PRIMARY KEY is
//!    `(recall_id, memory_id)`, so `memory_id` alone is unique only
//!    WITHIN one `recall_id`, and `recall_id = None` is a supported
//!    unfiltered read).
//!
//! Confirmed against the live reference instance
//! (`en_US.UTF-8` — the stock non-`C` default on the CI/dev postgres):
//!
//! ```text
//! default collation:  mem-a, MEM-B, mem-C   |  mem-x-<suf>, MEM-Y-<suf>  |  rid-a-<suf>, RID-B-<suf>
//! COLLATE "C":         MEM-B, mem-C, mem-a  |  MEM-Y-<suf>, mem-x-<suf>  |  RID-B-<suf>, rid-a-<suf>
//! ```
//!
//! i.e. the default-collation order and the `COLLATE "C"` order are
//! DIFFERENT orderings of the SAME rows for every id family this test
//! seeds — so `COLLATE "C"` is load-bearing, not decorative: reverting
//! either `postgres.rs` `ORDER BY` clause back to a bare (non-collated)
//! tiebreak makes `pg_list_id_tiebreak_matches_sqlite_binary_order_2602`
//! / `pg_recall_observations_tiebreak_matches_sqlite_across_recall_ids_2615`
//! FAIL (verified manually pre-commit by reverting the `COLLATE "C"`
//! clauses and re-running this file against the same live instance; the
//! `en_US.UTF-8` collation is a live property of the connected database,
//! not a compile-time constant, so it cannot be asserted in Rust without
//! coupling the test to postgres' locale internals — the PASS/FAIL
//! contrast against the documented pre-fix behavior above is the
//! R-203 evidence).
//!
//! Gated on `feature = "sal-postgres"` + `#[ignore]` (this repo's
//! `--include-ignored` live-PG convention — see e.g.
//! `tests/age_cypher_param_binding_2511.rs`); soft-skips with a printed
//! reason when `AI_MEMORY_TEST_POSTGRES_URL` is unset, so `cargo test
//! --features sal,sal-postgres` (without `--include-ignored`) never
//! attempts a live connection.

#![cfg(feature = "sal-postgres")]

use std::sync::Arc;

use serde_json::json;

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Bypass-visibility admin ctx — this test's seeded rows are its own, so
/// visibility filtering (an orthogonal concern to ORDER BY determinism)
/// is deliberately taken out of scope.
fn admin_ctx() -> CallerContext {
    let mut ctx = CallerContext::for_agent("ai:test-2602-2615-pg");
    ctx.bypass_visibility = true;
    ctx
}

async fn raw_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("raw pool for recall_observations seeding")
}

/// Seed a memory tied on `(priority, updated_at)` so only the `id`
/// tiebreak can distinguish it from its siblings.
async fn seed_tied_memory(store: &Arc<dyn MemoryStore>, id: &str, ns: &str) {
    let mem = Memory {
        id: id.to_string(),
        // `Tier::Long` never expires (`discrete_ttl_secs() == None`) — the
        // default `Tier::Mid` backfills `expires_at` to `created_at + 7
        // days` (#1466), which the fixed 2025-01-01 `created_at` below
        // would already be well past by the time this test runs, silently
        // dropping every seeded row from `list`'s
        // `expires_at IS NULL OR expires_at > NOW()` predicate. Matches
        // the sqlite twin's `seed_mem` helper, which inserts `'long'`.
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("title-{id}"),
        content: "ordering_determinism_2602_2615_pg fixture".to_string(),
        priority: 5,
        created_at: "2025-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-01T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:test-2602-2615-pg"}),
        ..Default::default()
    };
    store
        .store(&admin_ctx(), &mem)
        .await
        .expect("seed tied memory");
}

// ---------------------------------------------------------------------
// #2602 (B1) — `PostgresStore::list`'s `id COLLATE "C"` tiebreak matches
// sqlite BINARY order for mixed-case, non-canonical-UUID ids.
// ---------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL); run with --include-ignored"]
async fn pg_list_id_tiebreak_matches_sqlite_binary_order_2602() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP pg_list_id_tiebreak_matches_sqlite_binary_order_2602: \
             no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let suf = &uuid::Uuid::new_v4().to_string()[..8];
    let ns = uniq("list-order-2602-pg");
    // Mixed-case, non-canonical-UUID ids — the live shape `portability::
    // import` / federation receive can produce verbatim. Case differs at
    // the FIRST byte ('M' vs 'm') and, for the two lowercase-first ids,
    // at the 5th byte ('C' vs 'a') — the exact positions where postgres'
    // stock `en_US.UTF-8` collation and `COLLATE "C"` / sqlite BINARY
    // disagree (verified live: default → mem-a, MEM-B, mem-C; `C` →
    // MEM-B, mem-C, mem-a).
    let id_mem_a = format!("mem-a-{suf}");
    let id_mem_b = format!("MEM-B-{suf}");
    let id_mem_c = format!("mem-C-{suf}");

    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    // Insert deliberately out of the expected order.
    seed_tied_memory(&store, &id_mem_a, &ns).await;
    seed_tied_memory(&store, &id_mem_b, &ns).await;
    seed_tied_memory(&store, &id_mem_c, &ns).await;

    let filter = Filter {
        namespace: Some(ns.clone()),
        limit: 100,
        ..Default::default()
    };
    let pg_ids: Vec<String> = store
        .list(&admin_ctx(), &filter)
        .await
        .expect("pg list")
        .into_iter()
        .map(|m| m.id)
        .collect();

    // The sqlite twin, seeded with the SAME ids/priority/updated_at via
    // the raw storage funnel (mirrors
    // tests/ordering_determinism_2602_2615.rs's `seed_mem`).
    let sconn: rusqlite::Connection =
        ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open sqlite");
    for id in [&id_mem_a, &id_mem_b, &id_mem_c] {
        sconn
            .execute(
                "INSERT INTO memories \
                    (id, tier, namespace, title, content, priority, metadata, \
                     created_at, updated_at) \
                 VALUES (?1, 'long', ?2, ?3, 'content', 5, '{}', \
                         '2025-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                rusqlite::params![id, ns, format!("title-{id}")],
            )
            .expect("seed sqlite memory");
    }
    let sqlite_ids: Vec<String> = ai_memory::storage::list(
        &sconn,
        Some(&ns),
        None,
        100,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("sqlite list")
    .into_iter()
    .map(|m| m.id)
    .collect();

    assert_eq!(
        sqlite_ids,
        vec![id_mem_b.clone(), id_mem_c.clone(), id_mem_a.clone()],
        "sqlite BINARY order sanity check (byte order: 'M' < 'm', then 'C' < 'a')"
    );
    assert_eq!(
        pg_ids, sqlite_ids,
        "#2602/#1724: postgres `id COLLATE \"C\"` tiebreak must produce the \
         SAME order as sqlite BINARY for mixed-case ids tied on \
         (priority, updated_at) — without COLLATE \"C\" postgres' default \
         collation returns [{id_mem_a}, {id_mem_b}, {id_mem_c}] instead"
    );
}

// ---------------------------------------------------------------------
// #2615 (B2) — `PostgresStore::list_recall_observations`'s
// `memory_id COLLATE "C"` + `recall_id COLLATE "C"` tiebreaks match
// sqlite BINARY order, including the residual cross-`recall_id` tie
// (same `memory_id`, same `rank`, same `observed_at`, different
// `recall_id`) that only a FULL-PK tiebreak resolves.
// ---------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL); run with --include-ignored"]
async fn pg_recall_observations_tiebreak_matches_sqlite_across_recall_ids_2615() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP pg_recall_observations_tiebreak_matches_sqlite_across_recall_ids_2615: \
             no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let suf = &uuid::Uuid::new_v4().to_string()[..8];
    let ns = uniq("obs-order-2615-pg");
    let mem_x = format!("mem-x-{suf}"); // referenced by BOTH recall_ids
    let mem_y = format!("MEM-Y-{suf}"); // referenced only by rid_a

    // Mixed-case recall_ids — same live-shape argument as the memory ids
    // above; recall_id is caller-supplied, never format-validated.
    let rid_a = format!("rid-a-{suf}");
    let rid_b = format!("RID-B-{suf}");

    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    seed_tied_memory(&store, &mem_x, &ns).await;
    seed_tied_memory(&store, &mem_y, &ns).await;

    let pool = raw_pool(&url).await;
    let tied_at = chrono::DateTime::parse_from_rfc3339("2026-02-02T00:00:00Z")
        .expect("parse tied_at")
        .with_timezone(&chrono::Utc);
    // All THREE rows share (rank=1, observed_at=tied_at) — a full tie the
    // #2615 `rank`+`memory_id` fix narrowed to (memory_id, recall_id)
    // pairs, and the B2 fix is what makes THAT residual tie total.
    // (recall_id, memory_id) pairs: (rid_a, mem_x), (RID_B, mem_x),
    // (rid_a, mem_y) — all distinct under the table's real PRIMARY KEY.
    let insert = |recall_id: String, memory_id: String| {
        let pool = pool.clone();
        let observed_at = tied_at;
        async move {
            sqlx::query(
                "INSERT INTO recall_observations \
                    (recall_id, memory_id, retriever, rank, score, observed_at) \
                 VALUES ($1, $2, 'hybrid', 1, 0.5, $3)",
            )
            .bind(recall_id)
            .bind(memory_id)
            .bind(observed_at)
            .execute(&pool)
            .await
            .expect("insert recall_observations row");
        }
    };
    // Insert deliberately out of the expected order.
    insert(rid_a.clone(), mem_x.clone()).await;
    insert(rid_a.clone(), mem_y.clone()).await;
    insert(rid_b.clone(), mem_x.clone()).await;

    // Unfiltered read (`recall_id = None`) — the surface B2 targets.
    let pg_order: Vec<(String, String)> = store
        .list_recall_observations(None, None, None, None, 100)
        .await
        .expect("pg list_recall_observations")
        .into_iter()
        .filter(|o| o.memory_id == mem_x || o.memory_id == mem_y)
        .map(|o| (o.memory_id, o.recall_id))
        .collect();

    // sqlite twin: same memories + same observation rows via the raw
    // storage/observations funnels.
    let sconn: rusqlite::Connection =
        ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open sqlite");
    for id in [&mem_x, &mem_y] {
        sconn
            .execute(
                "INSERT INTO memories \
                    (id, tier, namespace, title, content, priority, metadata, \
                     created_at, updated_at) \
                 VALUES (?1, 'long', ?2, ?3, 'content', 5, '{}', \
                         '2025-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                rusqlite::params![id, ns, format!("title-{id}")],
            )
            .expect("seed sqlite memory");
    }
    let tied_at_text = "2026-02-02T00:00:00.000Z";
    for (recall_id, memory_id) in [
        (rid_a.as_str(), mem_x.as_str()),
        (rid_a.as_str(), mem_y.as_str()),
        (rid_b.as_str(), mem_x.as_str()),
    ] {
        sconn
            .execute(
                "INSERT INTO recall_observations \
                    (recall_id, memory_id, retriever, rank, score, observed_at, folded) \
                 VALUES (?1, ?2, 'hybrid', 1, 0.5, ?3, 0)",
                rusqlite::params![recall_id, memory_id, tied_at_text],
            )
            .expect("seed sqlite observation");
    }
    let sqlite_order: Vec<(String, String)> =
        ai_memory::observations::list_observations(&sconn, None, None, None, None, 100)
            .expect("sqlite list_observations")
            .into_iter()
            .map(|o| (o.memory_id, o.recall_id))
            .collect();

    assert_eq!(
        sqlite_order,
        vec![
            (mem_y.clone(), rid_a.clone()),
            (mem_x.clone(), rid_b.clone()),
            (mem_x.clone(), rid_a.clone()),
        ],
        "sqlite BINARY order sanity check: memory_id ASC first \
         ('M' < 'm'), then recall_id ASC within the tied memory_id \
         ('R' < 'r')"
    );
    assert_eq!(
        pg_order, sqlite_order,
        "#2615/#1724: postgres `memory_id COLLATE \"C\"` + \
         `recall_id COLLATE \"C\"` tiebreaks must produce the SAME order \
         as sqlite BINARY across two recall_ids observing the same \
         memory_id at the same rank/observed_at — without COLLATE \"C\" \
         postgres' default collation orders memory_id/recall_id \
         differently"
    );
}
