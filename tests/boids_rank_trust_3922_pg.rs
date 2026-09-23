// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Boids items 1+2 (#3922) — recall trust-weighting kill-test,
//! postgres twin of `tests/boids_rank_trust_3922.rs`. 5-agent vote
//! `4d3ea1c5`; spec `/ai-scratch/conductor/BOIDS-ITEMS-1-2-RULING-and-SPEC.md`.
//!
//! `#[ignore]` + `sal-postgres`; a live PG is required (the in-crate
//! `live_`/`_pg` tests never run in CI — vote condition 3). Run with:
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://... \
//!   cargo test --features sal-postgres --test boids_rank_trust_3922_pg \
//!   -- --include-ignored --test-threads=1
//! ```
//!
//! Same three contracts as the sqlite half (R1 cap, R3 provenance-aware
//! confidence, R2 no fold/touch escalation). PLUS the A11 NULL arm that
//! the sqlite half CANNOT exercise: on postgres the `confidence_source`
//! column is nullable (`ADD COLUMN ... TEXT`, no default), so a
//! genuinely-unattested legacy row is NULL — and the R3 CASE (`= 'default'
//! OR IS NULL`) neutralizes it to 0.5, asserted here. A legacy /
//! explicit `'caller_provided'` row still takes ELSE (keeps its stored
//! confidence). The postgres `recall_hybrid` score is `fts_score /
//! max_fts` — a per-query monotonic normalization of the real formula, so
//! equal inputs give equal scores (a tie on the pre-cut tip) and strict
//! `>` is a sound RED-first assertion; exact gaps (sqlite half) are not
//! asserted on the normalized scale.
//!
//! DOCUMENTED NON-GOAL (spec R5): per-reader distinct-reader trust
//! weighting is deferred to v1.1 with plan items 4-6 (see the sqlite
//! half's header). No `set_var` in this file.

#![cfg(feature = "sal-postgres")]

mod common;

use ai_memory::models::{ConfidenceSource, Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};
use common::postgres_env::PostgresTestEnv;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

const TS: &str = "2026-09-01T00:00:00+00:00";

async fn inspection_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("inspection pool")
}

#[allow(clippy::too_many_arguments)]
fn row(
    id: &str,
    title: &str,
    content: &str,
    ns: &str,
    access: i64,
    confidence: f64,
    cs: ConfidenceSource,
) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority: 5,
        confidence,
        source: "boids-3922".to_string(),
        access_count: access,
        confidence_source: cs,
        created_at: TS.to_string(),
        updated_at: TS.to_string(),
        expires_at: None,
        metadata: json!({ "scope": "collective" }),
        ..Default::default()
    }
}

/// Normalize `created_at` / `updated_at` to the fixed TS so the recency term is
/// byte-identical for every seeded row (the store stamps its own
/// timestamps on write; scoring parity requires equal recency).
async fn pin_timestamps(pool: &sqlx::PgPool, ns: &str) {
    sqlx::query("UPDATE memories SET created_at = $1, updated_at = $1 WHERE namespace = $2")
        .bind(TS)
        .bind(ns)
        .execute(pool)
        .await
        .expect("pin timestamps");
}

async fn recall_scored(store: &PostgresStore, query: &str, ns: &str) -> Vec<(String, f64)> {
    let ctx = CallerContext::for_agent("ai:test:boids");
    let mut filter = Filter::new();
    filter.namespace = Some(ns.to_string());
    filter.limit = 50;
    store
        .recall_hybrid(&ctx, query, None, &filter)
        .await
        .expect("recall_hybrid")
        .into_iter()
        .map(|(m, s)| (m.id, s))
        .collect()
}

fn score_of(scored: &[(String, f64)], id: &str) -> f64 {
    scored
        .iter()
        .find(|(i, _)| i == id)
        .unwrap_or_else(|| panic!("id {id} absent"))
        .1
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn pg_hot_low_confidence_ranks_below_calibrated_3922() {
    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("boids_cap").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let admin = CallerContext::for_admin("operator:boids");
    let ns = "boids/cap";
    let content = "boidcappg shared trust body";
    for m in [
        row(
            "hot",
            "alpha",
            content,
            ns,
            500,
            0.4,
            ConfidenceSource::CallerProvided,
        ),
        row(
            "cal",
            "bravo",
            content,
            ns,
            0,
            1.0,
            ConfidenceSource::CallerProvided,
        ),
    ] {
        store.store(&admin, &m).await.expect("store");
    }
    let pool = inspection_pool(env.url()).await;
    pin_timestamps(&pool, ns).await;

    let scored = recall_scored(&store, "boidcappg", ns).await;
    // RED on the tip (cap 50): hot dominates. GREEN after (cap 10):
    // calibrated (+2.0) outranks hot (+1.0 popularity + 0.8 confidence).
    assert!(
        score_of(&scored, "cal") > score_of(&scored, "hot"),
        "calibrated row must outrank the hot low-confidence row"
    );
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn pg_default_ranks_below_explicit_confidence_3922() {
    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("boids_prov").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let admin = CallerContext::for_admin("operator:boids");
    let ns = "boids/prov";
    let content = "boidprovpg shared trust body";
    for m in [
        row(
            "deflt",
            "alpha",
            content,
            ns,
            0,
            1.0,
            ConfidenceSource::Default,
        ),
        row(
            "expl",
            "bravo",
            content,
            ns,
            0,
            1.0,
            ConfidenceSource::CallerProvided,
        ),
    ] {
        store.store(&admin, &m).await.expect("store");
    }
    let pool = inspection_pool(env.url()).await;
    pin_timestamps(&pool, ns).await;

    let scored = recall_scored(&store, "boidprovpg", ns).await;
    // RED on the tip (no CASE): equal normalized score (tie). GREEN after:
    // explicit (+2.0) strictly outranks the neutralized default (+1.0).
    assert!(
        score_of(&scored, "expl") > score_of(&scored, "deflt"),
        "explicit confidence must strictly outrank the unassessed default"
    );
}

/// A11 (f2r pre-cut security amendment), postgres-only NULL arm: a
/// genuinely-unattested row (`confidence_source IS NULL`, reachable only
/// on postgres) takes the NEUTRAL branch, while a legacy / explicit
/// `'caller_provided'` row takes ELSE and keeps its stored confidence.
/// Asserted, not assumed.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn pg_a11_null_provenance_is_neutral_caller_provided_is_full_3922() {
    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("boids_a11").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let admin = CallerContext::for_admin("operator:boids");
    let ns = "boids/a11";
    let content = "boida11pg shared trust body";
    for m in [
        row(
            "nullprov",
            "alpha",
            content,
            ns,
            0,
            1.0,
            ConfidenceSource::CallerProvided,
        ),
        row(
            "legacy",
            "bravo",
            content,
            ns,
            0,
            1.0,
            ConfidenceSource::CallerProvided,
        ),
    ] {
        store.store(&admin, &m).await.expect("store");
    }
    let pool = inspection_pool(env.url()).await;
    pin_timestamps(&pool, ns).await;
    // Force the genuinely-unattested NULL provenance the postgres column
    // allows (the sqlite twin cannot: NOT NULL DEFAULT 'caller_provided').
    sqlx::query("UPDATE memories SET confidence_source = NULL WHERE id = 'nullprov'")
        .execute(&pool)
        .await
        .expect("null the provenance");

    let scored = recall_scored(&store, "boida11pg", ns).await;
    // NULL provenance → neutral (+1.0); 'caller_provided' → ELSE (+2.0).
    assert!(
        score_of(&scored, "legacy") > score_of(&scored, "nullprov"),
        "legacy 'caller_provided' (ELSE, +2.0) must outrank a NULL-provenance \
         neutral row (+1.0)"
    );
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn pg_fold_no_longer_escalates_3922() {
    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("boids_fold").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let admin = CallerContext::for_admin("operator:boids");
    let ns = "boids-fold";
    let soon = (chrono::Utc::now() + chrono::Duration::seconds(90)).to_rfc3339();
    let mut m = row(
        "fold-row",
        "boidfold",
        "body",
        ns,
        3,
        1.0,
        ConfidenceSource::CallerProvided,
    );
    m.tier = Tier::Mid;
    m.expires_at = Some(soon.clone());
    let id = store.store(&admin, &m).await.expect("store");
    let pool = inspection_pool(env.url()).await;
    // Capture updated_at BEFORE the fold (timestamptz rendering is
    // backend-canonical; compare pre/post rather than to a literal).
    let upd_before: String =
        sqlx::query_scalar("SELECT updated_at::text FROM memories WHERE id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("read updated_at before");

    // 8 observations would land access_count at 11 — crossing the
    // historical promotion threshold (5) and a priority decade (10).
    for k in 0..8 {
        store
            .record_recall_observation(
                &format!("r{k}"),
                &[(id.clone(), "fts5".to_string(), 1, 0.9)],
                None,
                None,
            )
            .await
            .expect("ledger row");
    }
    assert_eq!(store.fold_recall_accesses().await.expect("fold"), 1);

    let (ac, tier, pr, upd_after, exp_null): (i64, String, i32, String, bool) = sqlx::query_as(
        "SELECT access_count, tier, priority, updated_at::text, expires_at IS NULL \
         FROM memories WHERE id = $1",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .expect("read row");

    assert_eq!(ac, 11, "access_count still folds (3 + 8)");
    assert_eq!(tier, "mid", "R2: fold no longer auto-promotes mid→long");
    assert_eq!(pr, 5, "R2: fold no longer bumps priority");
    assert_eq!(
        upd_after, upd_before,
        "R2: fold no longer rewrites updated_at"
    );
    assert!(
        !exp_null,
        "R2: mid row keeps a non-NULL expiry (promotion no longer clears it)"
    );
}
