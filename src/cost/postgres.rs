// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3323 — Postgres twin of the token/cost accounting increment
//! funnels and rollups. Same model, same `token_cost_counters` relation,
//! same best-effort posture as the SQLite path in the parent module: a
//! metering failure is logged and swallowed, never surfaced to the caller
//! (advisory, disposable — North Star: degrade, never corrupt).

use sqlx::PgPool;

use super::{CostRollup, SCOPE_LINEAGE, SCOPE_NAMESPACE};
use crate::models::Memory;

/// Embedded Postgres DDL doc twin, sourced by `migrate_v93`.
pub const MIGRATION_V93_POSTGRES: &str =
    include_str!("../../migrations/postgres/0050_v93_token_cost_counters.sql");

/// Upsert one scope's WRITE delta. `LEAST(..)` mirrors the SQLite
/// `MIN(..)` saturation clamp.
const WRITE_UPSERT_SQL: &str = "INSERT INTO token_cost_counters \
    (scope_kind, scope_key, tokens_written, write_events, tokens_recalled, recall_events, updated_at) \
    VALUES ($1, $2, $3, $4, 0, 0, now()) \
    ON CONFLICT (scope_kind, scope_key) DO UPDATE SET \
        tokens_written = LEAST(token_cost_counters.tokens_written + EXCLUDED.tokens_written, 9223372036854775807), \
        write_events   = LEAST(token_cost_counters.write_events + EXCLUDED.write_events, 9223372036854775807), \
        updated_at     = now()";

/// Upsert one scope's RECALL delta.
const RECALL_UPSERT_SQL: &str = "INSERT INTO token_cost_counters \
    (scope_kind, scope_key, tokens_written, write_events, tokens_recalled, recall_events, updated_at) \
    VALUES ($1, $2, 0, 0, $3, $4, now()) \
    ON CONFLICT (scope_kind, scope_key) DO UPDATE SET \
        tokens_recalled = LEAST(token_cost_counters.tokens_recalled + EXCLUDED.tokens_recalled, 9223372036854775807), \
        recall_events   = LEAST(token_cost_counters.recall_events + EXCLUDED.recall_events, 9223372036854775807), \
        updated_at      = now()";

/// Best-effort: attribute one LOCAL-authorship write to its namespace and
/// its own lineage node. Runs OUTSIDE the store's transaction (on the
/// shared pool) so a metering failure can never roll the durable write
/// back and never extends the write's lock window.
pub async fn record_write_pg(pool: &PgPool, mem: &Memory, memory_id: &str) {
    let tokens = clamp_tokens(crate::storage::count_memory_tokens(mem));
    if let Err(e) = try_record_write(pool, &mem.namespace, memory_id, tokens).await {
        tracing::debug!(target: "cost", "token/cost write metering skipped (non-fatal, pg): {e}");
    }
}

async fn try_record_write(
    pool: &PgPool,
    namespace: &str,
    memory_id: &str,
    tokens: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(WRITE_UPSERT_SQL)
        .bind(SCOPE_NAMESPACE)
        .bind(namespace)
        .bind(tokens)
        .bind(1_i64)
        .execute(pool)
        .await?;
    sqlx::query(WRITE_UPSERT_SQL)
        .bind(SCOPE_LINEAGE)
        .bind(memory_id)
        .bind(tokens)
        .bind(1_i64)
        .execute(pool)
        .await?;
    Ok(())
}

/// Best-effort: attribute a served recall set to each result's namespace
/// and lineage node, aggregated per scope so an N-result recall pays a
/// bounded number of upserts.
pub async fn record_recall_pg(pool: &PgPool, results: &[(Memory, f64)]) {
    if results.is_empty() {
        return;
    }
    if let Err(e) = try_record_recall(pool, results).await {
        tracing::debug!(target: "cost", "token/cost recall metering skipped (non-fatal, pg): {e}");
    }
}

async fn try_record_recall(pool: &PgPool, results: &[(Memory, f64)]) -> Result<(), sqlx::Error> {
    // (scope_kind, scope_key) -> (tokens, events)
    let mut agg: std::collections::BTreeMap<(&str, String), (i64, i64)> =
        std::collections::BTreeMap::new();
    for (mem, _score) in results {
        let tokens = clamp_tokens(crate::storage::count_memory_tokens(mem));
        accumulate(&mut agg, SCOPE_NAMESPACE, mem.namespace.clone(), tokens);
        accumulate(&mut agg, SCOPE_LINEAGE, mem.id.clone(), tokens);
    }
    for ((kind, key), (tokens, events)) in agg {
        sqlx::query(RECALL_UPSERT_SQL)
            .bind(kind)
            .bind(key)
            .bind(tokens)
            .bind(events)
            .execute(pool)
            .await?;
    }
    Ok(())
}

fn accumulate(
    agg: &mut std::collections::BTreeMap<(&'static str, String), (i64, i64)>,
    kind: &'static str,
    key: String,
    tokens: i64,
) {
    let entry = agg.entry((kind, key)).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(tokens);
    entry.1 = entry.1.saturating_add(1);
}

/// The per-namespace rollup for one namespace, or `None` if never metered.
///
/// # Errors
///
/// Propagates any `sqlx` error.
pub async fn namespace_rollup_pg(
    pool: &PgPool,
    namespace: &str,
) -> Result<Option<CostRollup>, sqlx::Error> {
    let row: Option<(i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT tokens_written, tokens_recalled, write_events, recall_events \
         FROM token_cost_counters WHERE scope_kind = $1 AND scope_key = $2",
    )
    .bind(SCOPE_NAMESPACE)
    .bind(namespace)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(w, r, we, re)| CostRollup {
        scope_kind: SCOPE_NAMESPACE.to_string(),
        scope_key: namespace.to_string(),
        tokens_written: w,
        tokens_recalled: r,
        write_events: we,
        recall_events: re,
    }))
}

/// Every per-namespace rollup, most-expensive first.
///
/// # Errors
///
/// Propagates any `sqlx` error.
pub async fn all_namespace_rollups_pg(pool: &PgPool) -> Result<Vec<CostRollup>, sqlx::Error> {
    let rows: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT scope_key, tokens_written, tokens_recalled, write_events, recall_events \
         FROM token_cost_counters WHERE scope_kind = $1 \
         ORDER BY (tokens_written + tokens_recalled) DESC, scope_key ASC",
    )
    .bind(SCOPE_NAMESPACE)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(key, w, r, we, re)| CostRollup {
            scope_kind: SCOPE_NAMESPACE.to_string(),
            scope_key: key,
            tokens_written: w,
            tokens_recalled: r,
            write_events: we,
            recall_events: re,
        })
        .collect())
}

/// The per-lineage-ROOT rollup: `root_id` plus every memory reachable
/// through the `derives_from` provenance DAG (up to `max_depth` hops),
/// summed. Mirrors the SQLite `storage::lineage_descendants` DESCENDANTS
/// semantics (edges `target -> source`, relation in the lineage subset)
/// with a `path`-array cycle guard.
///
/// # Errors
///
/// Propagates any `sqlx` error.
pub async fn lineage_rollup_pg(
    pool: &PgPool,
    root_id: &str,
    max_depth: usize,
) -> Result<CostRollup, sqlx::Error> {
    // Relation subset built from the typed SSOT (never a re-spelled literal
    // list); the values are compile-time enum strings with no injection
    // surface.
    let p_in_list = crate::models::MemoryLinkRelation::LINEAGE
        .iter()
        .map(|r| format!("'{}'", r.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    let max_depth_i64 = i64::try_from(max_depth).unwrap_or(i64::MAX);

    let sql = format!(
        "WITH RECURSIVE descendants(node_id, depth, path) AS ( \
            SELECT ml.source_id, 1, ARRAY[ml.target_id, ml.source_id] \
            FROM memory_links ml \
            WHERE ml.target_id = $1 AND ml.relation IN ({p_in_list}) \
            UNION ALL \
            SELECT ml.source_id, d.depth + 1, d.path || ml.source_id \
            FROM memory_links ml \
            JOIN descendants d ON ml.target_id = d.node_id \
            WHERE d.depth < $2 AND ml.relation IN ({p_in_list}) \
              AND NOT (ml.source_id = ANY(d.path)) \
        ), nodes(id) AS ( \
            SELECT $1 UNION SELECT node_id FROM descendants \
        ) \
        SELECT COALESCE(SUM(c.tokens_written), 0)::bigint, \
               COALESCE(SUM(c.tokens_recalled), 0)::bigint, \
               COALESCE(SUM(c.write_events), 0)::bigint, \
               COALESCE(SUM(c.recall_events), 0)::bigint \
        FROM nodes n \
        LEFT JOIN token_cost_counters c \
          ON c.scope_kind = '{SCOPE_LINEAGE}' AND c.scope_key = n.id"
    );

    let (w, r, we, re): (i64, i64, i64, i64) = sqlx::query_as(&sql)
        .bind(root_id)
        .bind(max_depth_i64)
        .fetch_one(pool)
        .await?;

    Ok(CostRollup {
        scope_kind: SCOPE_LINEAGE.to_string(),
        scope_key: root_id.to_string(),
        tokens_written: w,
        tokens_recalled: r,
        write_events: we,
        recall_events: re,
    })
}

fn clamp_tokens(tokens: usize) -> i64 {
    i64::try_from(tokens).unwrap_or(i64::MAX)
}
