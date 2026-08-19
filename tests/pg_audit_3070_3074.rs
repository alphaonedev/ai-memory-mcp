// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Enterprise-federation audit regressions on the Postgres adapter surface.
//!
//! - **#3070** — the pg SEMANTIC recall pool's `scope=private` visibility
//!   clause omitted the `target_agent_id` inbox carve-out that the FTS pool
//!   (and sqlite `db::recall_hybrid`) already carried, so a private row
//!   targeted at the caller surfaced via FTS but never received a cosine
//!   score. Completeness-only, fail-closed.
//! - **#3074** — the bootstrap / migrate advisory-lock connections and the
//!   `CREATE INDEX CONCURRENTLY` connection RELAX their per-session
//!   `statement_timeout`/`lock_timeout` with a plain `SET` (0 / 900 s) and
//!   then returned to the pool; sqlx does not reset GUC state on checkout,
//!   so a normal query could later run UNBOUNDED. The fix CLOSES those
//!   connections so the pool self-heals via `after_connect`.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (skip-if-unset, the
//! `tests/cov_postgres_core.rs` pattern). Point it at the pg-main test
//! substrate (`:5433`), NOT a live corpus daemon.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::cast_precision_loss
)]

use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::{DEFAULT_STATEMENT_TIMEOUT_SECS, PostgresStore};
use ai_memory::store::{CallerContext, Filter, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn mem(id: &str, ns: &str, title: &str, content: &str, metadata: serde_json::Value) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["audit3070".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "pg-audit-3070-3074".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

/// #3070 — a `scope=private` row authored by agent B and TARGETED at agent A
/// (`metadata.target_agent_id == A`) must receive a SEMANTIC (cosine) score
/// for A. The row's title/content deliberately do NOT lexically match the
/// query, so the FTS pool returns NOTHING and the ONLY path by which the row
/// can surface is the semantic pool — isolating the fixed clause. A third,
/// unrelated agent C (neither author nor target) must NOT see it, proving the
/// carve-out stays scoped (completeness-only, never a widening).
#[tokio::test]
async fn semantic_pool_returns_targeted_private_row_for_target_agent_3070() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let agent_a = uid("ai:target-a"); // caller / target (the inbox owner)
    let agent_b = uid("ai:author-b"); // author of the private row
    let agent_c = uid("ai:bystander-c"); // unrelated third party

    let ns = uid("audit3070-ns");
    // A random lexical token that appears in the QUERY only, never in the
    // stored content — so the FTS pool cannot match and only the semantic
    // pool can surface the row.
    let query_token = format!("zq{}", uuid::Uuid::new_v4().simple());
    let id = uid("inbox");

    // Resolve the LIVE `memories.embedding` column dimension straight from
    // the catalog (pgvector stores the dim verbatim in `atttypmod`) so the
    // inline embedding matches whatever dim the fixture was built with — the
    // configured/requested dim can differ from the on-disk column.
    let dim_i32: i32 = sqlx::query_scalar(
        "SELECT atttypmod FROM pg_attribute \
         WHERE attrelid = 'memories'::regclass AND attname = 'embedding'",
    )
    .fetch_one(store.pool())
    .await
    .expect("resolve memories.embedding dim");
    let dim = usize::try_from(dim_i32).unwrap_or(768);
    // A non-degenerate ramp vector; recalled with the identical vector so
    // cosine similarity is 1.0 (> the 0.2 gate).
    let vec: Vec<f32> = (0..dim).map(|i| ((i % 17) as f32) * 0.01 + 0.001).collect();
    let space = "audit3070-space#none";

    let ctx_author = CallerContext::for_agent(&agent_b);
    let row = mem(
        &id,
        &ns,
        "unrelated horticulture notes",
        "filler prose about greenhouse irrigation and mulch",
        serde_json::json!({
            "agent_id": agent_b,
            "scope": "private",
            "target_agent_id": agent_a,
        }),
    );
    store
        .store_with_embedding(&ctx_author, &row, Some(&vec), Some(space))
        .await
        .expect("store_with_embedding");

    let filter = Filter {
        namespace: Some(ns.clone()),
        active_embedding_space: Some(space.to_string()),
        limit: 10,
        ..Filter::default()
    };

    // Caller A (the target) — must receive the row via the semantic pool.
    let ctx_a = CallerContext::for_agent(&agent_a);
    let scored_a = store
        .recall_hybrid(&ctx_a, &query_token, Some(&vec), &filter)
        .await
        .expect("recall_hybrid as target agent");
    assert!(
        scored_a.iter().any(|(m, _)| m.id == id),
        "#3070: the targeted-private row must surface via the SEMANTIC pool \
         for its target agent (FTS cannot match the query token, so only the \
         target_agent_id carve-out on the semantic clause can return it)"
    );

    // Bystander C — neither author nor target — must NOT see the private row.
    let ctx_c = CallerContext::for_agent(&agent_c);
    let scored_c = store
        .recall_hybrid(&ctx_c, &query_token, Some(&vec), &filter)
        .await
        .expect("recall_hybrid as bystander");
    assert!(
        scored_c.iter().all(|(m, _)| m.id != id),
        "#3070: the carve-out is completeness-only and must stay scoped — an \
         unrelated agent must never see another agent's scope=private row"
    );
}

/// #3074 — after `connect()` runs the bootstrap advisory-lock acquisition,
/// the migration ladder, and the v88 `CREATE INDEX CONCURRENTLY` build (each
/// of which RELAXES `statement_timeout`/`lock_timeout` on its connection),
/// EVERY connection the pool can hand out must still carry the bounded
/// `after_connect` `statement_timeout` — never the `0` (unbounded) that a
/// poisoned, returned-to-pool bootstrap/migrate connection left behind.
///
/// Draining the pool up to its ceiling materialises every physical
/// connection, so a regression (dropping a relaxed connection back into the
/// pool) would be caught here: one of the drained connections would report
/// `statement_timeout = 0`.
#[tokio::test]
async fn pool_connections_keep_bounded_statement_timeout_3074() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let expected = format!("{DEFAULT_STATEMENT_TIMEOUT_SECS}s"); // pg renders "30s"

    // Hold up to the pool ceiling concurrently so we inspect EVERY physical
    // connection (a poisoned idle connection is handed out before the pool
    // opens a fresh one, so draining is what makes the check deterministic).
    let ceiling = 16usize; // >= PoolConfig::default().max_connections
    let mut held = Vec::new();
    for _ in 0..ceiling {
        match store.pool().acquire().await {
            Ok(conn) => held.push(conn),
            Err(_) => break, // reached the real ceiling; the ones we hold suffice
        }
    }
    assert!(
        !held.is_empty(),
        "#3074: expected to acquire at least one pooled connection"
    );

    for conn in &mut held {
        let st: String = sqlx::query_scalar("SHOW statement_timeout")
            .fetch_one(&mut **conn)
            .await
            .expect("SHOW statement_timeout");
        assert_ne!(
            st, "0",
            "#3074: a pooled connection has an UNBOUNDED statement_timeout — a \
             bootstrap/migrate/index-build connection was returned to the pool \
             with its per-session timeout still cleared to 0"
        );
        assert_eq!(
            st, expected,
            "#3074: pooled connection statement_timeout must equal the \
             after_connect default (a relaxed connection must self-heal by \
             being closed, not returned to the pool)"
        );
    }
}
