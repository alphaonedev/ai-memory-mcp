// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Failed advisory metering must remain visible without failing recall.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use ai_memory::{cost, metrics, models::Memory};
use tracing_subscriber::prelude::*;

fn dropped(kind: &str) -> anyhow::Result<u64> {
    let prefix = format!("ai_memory_cost_metering_dropped_total{{kind=\"{kind}\"}} ");
    for line in metrics::render().lines() {
        if let Some(value) = line.strip_prefix(&prefix) {
            return Ok(value.parse()?);
        }
    }
    Ok(0)
}

struct CostWarnings(Arc<AtomicUsize>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CostWarnings {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "cost" && *event.metadata().level() == tracing::Level::WARN
        {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// One cell owns the process-global metric deltas on both backends: parallel
// tests must not race each other's before/after counter assertions.
#[test]
fn sqlite_busy_recall_loss_is_observable() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("metering.db");
    let conn = ai_memory::db::open(&path)?;
    conn.busy_timeout(std::time::Duration::ZERO)?;
    let competitor = rusqlite::Connection::open(&path)?;
    competitor.execute_batch("BEGIN IMMEDIATE")?;
    let memory = Memory {
        id: "busy-memory".into(),
        namespace: "busy-namespace".into(),
        content: "served content still reaches the caller".into(),
        ..Memory::default()
    };
    let before = dropped("recall")?;
    let warnings = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(CostWarnings(Arc::clone(&warnings)));
    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..20 {
            cost::record_recall_sqlite(&conn, &[(memory.clone(), 1.0)]);
        }
    });
    let writes_before = dropped("write")?;
    cost::record_write_sqlite(&conn, &memory, &memory.id);
    competitor.execute_batch("ROLLBACK")?;
    let rows: i64 = conn.query_row("SELECT COUNT(*) FROM token_cost_counters", [], |r| r.get(0))?;
    assert_eq!(rows, 0, "fixture must force dropped updates");
    assert_eq!(
        dropped("recall")?,
        before + 20,
        "SQLITE_BUSY recall loss must increment the exported dropped counter for EVERY attempt"
    );
    assert_eq!(
        warnings.load(Ordering::Relaxed),
        1,
        "only the WARN is rate limited"
    );
    assert_eq!(dropped("write")?, writes_before + 1);
    let lost = cost::lineage_rollup(&conn, &memory.id, cost::DEFAULT_ROLLUP_DEPTH)?;
    assert_eq!(lost.tokens_recalled, 0);
    assert_eq!(lost.accuracy, "lower bound under contention");

    // Empty calls and recovered writes do not report loss. The next successful
    // update is served once; there is no hidden retry of the discarded batch.
    cost::record_recall_sqlite(&conn, &[]);
    cost::record_recall_sqlite(&conn, &[(memory.clone(), 1.0)]);
    cost::record_write_sqlite(&conn, &memory, &memory.id);
    assert_eq!(dropped("recall")?, before + 20);
    assert_eq!(dropped("write")?, writes_before + 1);
    let rollup = cost::namespace_rollup(&conn, &memory.namespace)?
        .ok_or_else(|| anyhow::anyhow!("missing recovered namespace"))?;
    assert_eq!(rollup.recall_events, 1);
    assert_eq!(rollup.write_events, 1);
    assert_eq!(rollup.accuracy, "lower bound under contention");
    assert_eq!(
        cost::all_namespace_rollups(&conn)?[0].accuracy,
        rollup.accuracy
    );
    assert_eq!(
        cost::lineage_rollup(&conn, &memory.id, cost::DEFAULT_ROLLUP_DEPTH)?.accuracy,
        rollup.accuracy
    );

    // Same swallowed-error shape in report-time ledger derivation: the failed
    // read contributes zero but must no longer masquerade as complete data.
    conn.execute_batch("DROP TABLE recall_observations")?;
    let derives_before = dropped("rollup")?;
    cost::namespace_rollup(&conn, &memory.namespace)?;
    cost::all_namespace_rollups(&conn)?;
    cost::lineage_rollup(&conn, &memory.id, cost::DEFAULT_ROLLUP_DEPTH)?;
    assert_eq!(dropped("rollup")?, derives_before + 3);

    // Other errors (not just BUSY) use the same observable failure funnel.
    conn.execute_batch("DROP TABLE token_cost_counters")?;
    cost::record_recall_sqlite(&conn, &[(memory.clone(), 1.0)]);
    cost::record_write_sqlite(&conn, &memory, &memory.id);
    assert_eq!(dropped("recall")?, before + 21);
    assert_eq!(dropped("write")?, writes_before + 2);

    #[cfg(feature = "sal-postgres")]
    tokio::runtime::Runtime::new()?.block_on(postgres_loss_is_observable(&memory))?;
    Ok(())
}

#[cfg(feature = "sal-postgres")]
async fn postgres_loss_is_observable(memory: &Memory) -> anyhow::Result<()> {
    use cost::postgres as pg;
    use sqlx::postgres::PgPoolOptions;
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skipping Postgres: AI_MEMORY_TEST_POSTGRES_URL unset");
        return Ok(());
    };
    // A private schema keeps this failure-injection fixture out of the migrated
    // tables used by other integration binaries in the same test database.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO cost_metering_4124")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("SET lock_timeout = '1ms'")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    sqlx::raw_sql("CREATE SCHEMA IF NOT EXISTS cost_metering_4124")
        .execute(&pool)
        .await?;
    sqlx::raw_sql(pg::MIGRATION_V93_POSTGRES)
        .execute(&pool)
        .await?;
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS memories (id TEXT, namespace TEXT, content TEXT); \
        CREATE TABLE IF NOT EXISTS recall_observations (memory_id TEXT); \
        CREATE TABLE IF NOT EXISTS memory_links (source_id TEXT, target_id TEXT, relation TEXT)",
    )
    .execute(&pool)
    .await?;
    let competitor = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let mut lock = competitor.begin().await?;
    sqlx::query("LOCK TABLE cost_metering_4124.token_cost_counters IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await?;
    let before = dropped("recall")?;
    let writes_before = dropped("write")?;
    for _ in 0..20 {
        pg::record_recall_pg(&pool, &[(memory.clone(), 1.0)]).await;
    }
    pg::record_write_pg(&pool, memory, &memory.id).await;
    lock.rollback().await?;
    assert_eq!(dropped("recall")?, before + 20);
    assert_eq!(dropped("write")?, writes_before + 1);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM token_cost_counters")
        .fetch_one(&pool)
        .await?;
    assert_eq!(rows, 0, "PG lock timeout must discard updates");
    pg::record_recall_pg(&pool, &[]).await;
    pg::record_recall_pg(&pool, &[(memory.clone(), 1.0)]).await;
    pg::record_write_pg(&pool, memory, &memory.id).await;
    assert_eq!(dropped("recall")?, before + 20);
    assert_eq!(dropped("write")?, writes_before + 1);
    let rollup = pg::namespace_rollup_pg(&pool, &memory.namespace)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing recovered PG namespace"))?;
    assert_eq!(rollup.recall_events, 1);
    assert_eq!(rollup.accuracy, "lower bound under contention");
    assert_eq!(
        pg::all_namespace_rollups_pg(&pool).await?[0].accuracy,
        rollup.accuracy
    );
    assert_eq!(
        pg::lineage_rollup_pg(&pool, &memory.id, cost::DEFAULT_ROLLUP_DEPTH)
            .await?
            .accuracy,
        rollup.accuracy
    );
    sqlx::query("DROP TABLE recall_observations")
        .execute(&pool)
        .await?;
    let derives_before = dropped("rollup")?;
    pg::namespace_rollup_pg(&pool, &memory.namespace).await?;
    pg::all_namespace_rollups_pg(&pool).await?;
    pg::lineage_rollup_pg(&pool, &memory.id, cost::DEFAULT_ROLLUP_DEPTH).await?;
    assert_eq!(dropped("rollup")?, derives_before + 3);
    sqlx::query("DROP TABLE token_cost_counters")
        .execute(&pool)
        .await?;
    pg::record_recall_pg(&pool, &[(memory.clone(), 1.0)]).await;
    pg::record_write_pg(&pool, memory, &memory.id).await;
    assert_eq!(dropped("recall")?, before + 21);
    assert_eq!(dropped("write")?, writes_before + 2);
    sqlx::query("DROP SCHEMA cost_metering_4124 CASCADE")
        .execute(&pool)
        .await?;
    competitor.close().await;
    pool.close().await;
    eprintln!(
        "Postgres lock-timeout, recovery, rollup failures, and missing-table checks executed"
    );
    Ok(())
}
