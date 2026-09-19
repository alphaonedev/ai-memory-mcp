// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Descriptive, fail-closed native graph measurements; no performance SLA.
use ai_memory::{
    models::MemoryLink,
    store::{CallerContext, KgBackend, MemoryStore, postgres::PostgresStore},
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    io::{self, Read, Write},
    time::Instant,
};

const NODES: usize = 1024;
const SAMPLES: usize = 200;
const WARMUP: usize = 10;
const DRAIN_ROWS: usize = 64;
const SOURCE: &str = match option_env!("AI_MEMORY_GRAPH_BENCH_COMMIT") {
    Some(value) => value,
    None => "unbound",
};

struct Agtype(String);
impl sqlx::Type<sqlx::Postgres> for Agtype {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("agtype")
    }
}
impl sqlx::Encode<'_, sqlx::Postgres> for Agtype {
    fn encode_by_ref(
        &self,
        buffer: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        buffer.push(1);
        buffer.extend_from_slice(self.0.as_bytes());
        Ok(sqlx::encode::IsNull::No)
    }
}

async fn seed(store: &PostgresStore) -> Result<Vec<String>> {
    let namespace = format!("graph-baseline-{}", uuid::Uuid::new_v4());
    let ids: Vec<_> = (0..NODES).map(|n| format!("{namespace}-{n:04}")).collect();
    sqlx::query("INSERT INTO memories (id,tier,namespace,title,content,source) SELECT id,'long',$2,id,'synthetic graph baseline','graph-baseline' FROM UNNEST($1::text[]) AS id")
        .bind(&ids).bind(&namespace).execute(store.pool()).await?;
    let ctx = CallerContext::for_agent("ai:graph-baseline");
    for child in 1..NODES {
        let edge: MemoryLink = serde_json::from_value(json!({
            "source_id":ids[(child-1)/4],"target_id":ids[child],
            "relation":"related_to","created_at":"2020-01-01T00:00:00Z",
            "valid_from":"2020-01-01T00:00:00Z"
        }))?;
        store.link(&ctx, &edge).await?;
    }
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM memories WHERE namespace=$1), (SELECT count(*) FROM memory_links WHERE source_id=ANY($2))")
        .bind(&namespace).bind(&ids).fetch_one(store.pool()).await?;
    ensure!(
        counts == (i64::try_from(NODES)?, i64::try_from(NODES - 1)?),
        "fixture cardinality"
    );
    ensure!(
        age_count(store, &ids).await? == i64::try_from(NODES)?,
        "complete AGE projection"
    );
    Ok(ids)
}

async fn age_count(store: &PostgresStore, ids: &[String]) -> Result<i64> {
    let mut tx = store.pool().begin().await?;
    sqlx::query("LOAD 'age'").execute(&mut *tx).await?;
    sqlx::query("SET LOCAL search_path = ag_catalog, public")
        .execute(&mut *tx)
        .await?;
    let count:i64=sqlx::query_scalar("SELECT value::text::bigint FROM cypher('memory_graph', $$ MATCH (n:Memory) WHERE n.id IN $ids RETURN count(n) $$, $1) AS (value agtype)")
        .bind(Agtype(json!({"ids":ids}).to_string())).fetch_one(&mut *tx).await?;
    tx.rollback().await?;
    Ok(count)
}

async fn prepare_drain(store: &PostgresStore, ids: &[String]) -> Result<()> {
    let leaves = &ids[NODES - DRAIN_ROWS..];
    let mut tx = store.pool().begin().await?;
    sqlx::query("LOAD 'age'").execute(&mut *tx).await?;
    sqlx::query("SET LOCAL search_path = ag_catalog, public")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT * FROM cypher('memory_graph', $$ MATCH (n:Memory) WHERE n.id IN $ids DETACH DELETE n RETURN n $$, $1) AS (n agtype)")
        .bind(Agtype(json!({"ids":leaves}).to_string())).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    // Reset only this fixture's completed/pending queue rows outside timing.
    sqlx::query("DELETE FROM kg_projection_outbox WHERE target_id=ANY($1)")
        .bind(leaves)
        .execute(store.pool())
        .await?;
    sqlx::query("INSERT INTO kg_projection_outbox (source_id,target_id,relation) SELECT source_id,target_id,relation FROM memory_links WHERE target_id=ANY($1)")
        .bind(leaves).execute(store.pool()).await?;
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kg_projection_outbox WHERE projected_at IS NULL")
            .fetch_one(store.pool())
            .await?;
    ensure!(
        pending == i64::try_from(DRAIN_ROWS)?,
        "exact drain batch pending"
    );
    ensure!(
        age_count(store, leaves).await? == 0,
        "drain starts with absent projections"
    );
    Ok(())
}

fn emit(operation: &str, engine: &str, rows: usize, samples: &[u64]) -> Result<()> {
    ensure!(samples.len() == SAMPLES, "complete raw sample vector");
    writeln!(
        io::stdout(),
        "GRAPH_SAMPLES {}",
        json!({"operation":operation,"engine":engine,
        "rows":rows,"nodes":NODES,"edges":NODES-1,"warmup":WARMUP,"samples_us":samples})
    )?;
    Ok(())
}

async fn reads(store: &PostgresStore, ids: &[String]) -> Result<()> {
    for age in [false, true] {
        for depth in [1_usize, 2, 3] {
            let expected = match depth {
                1 => 4,
                2 => 20,
                _ => 84,
            };
            let mut samples = Vec::with_capacity(SAMPLES);
            for round in 0..WARMUP + SAMPLES {
                let start = Instant::now();
                let rows = if age {
                    store.kg_query_cypher(&ids[0], depth).await?
                } else {
                    store.kg_query_cte(&ids[0], depth).await?
                };
                let elapsed = u64::try_from(start.elapsed().as_micros())?;
                ensure!(rows.len() == expected, "actual query result cardinality");
                if round >= WARMUP {
                    samples.push(elapsed);
                }
            }
            emit(
                &format!("kg_query_depth_{depth}"),
                if age { "age" } else { "cte" },
                expected,
                &samples,
            )?;
        }
        let mut samples = Vec::with_capacity(SAMPLES);
        for round in 0..WARMUP + SAMPLES {
            let start = Instant::now();
            let rows = if age {
                store.kg_timeline_cypher(&ids[0], None, None, None).await?
            } else {
                store.kg_timeline_cte(&ids[0], None, None, None).await?
            };
            let elapsed = u64::try_from(start.elapsed().as_micros())?;
            ensure!(rows.len() == 4, "actual timeline cardinality");
            if round >= WARMUP {
                samples.push(elapsed);
            }
        }
        emit("kg_timeline", if age { "age" } else { "cte" }, 4, &samples)?;
    }
    Ok(())
}

async fn drains(store: &PostgresStore, ids: &[String]) -> Result<()> {
    let mut samples = Vec::with_capacity(SAMPLES);
    for round in 0..WARMUP + SAMPLES {
        prepare_drain(store, ids).await?;
        let start = Instant::now();
        let count = store
            .drain_kg_projection_outbox(i64::try_from(DRAIN_ROWS)?)
            .await?;
        let elapsed = u64::try_from(start.elapsed().as_micros())?;
        ensure!(count == DRAIN_ROWS, "actual successful projections");
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM kg_projection_outbox WHERE projected_at IS NULL",
        )
        .fetch_one(store.pool())
        .await?;
        ensure!(pending == 0, "same outbox cleared");
        ensure!(
            age_count(store, &ids[NODES - DRAIN_ROWS..]).await? == i64::try_from(DRAIN_ROWS)?,
            "projections restored"
        );
        if round >= WARMUP {
            samples.push(elapsed);
        }
    }
    emit("projection_drain", "age", DRAIN_ROWS, &samples)?;
    Ok(())
}

async fn measure() -> Result<()> {
    let url =
        std::env::var("AI_MEMORY_TEST_AGE_URL").context("explicit native AGE URL required")?;
    let store = PostgresStore::connect(&url).await?;
    ensure!(
        matches!(store.kg_backend(), KgBackend::Age),
        "AGE must execute"
    );
    writeln!(io::stdout(), "GRAPH_STAGE seed")?;
    let ids = seed(&store).await?;
    writeln!(io::stdout(), "GRAPH_STAGE reads")?;
    reads(&store, &ids).await?;
    writeln!(io::stdout(), "GRAPH_STAGE drains")?;
    drains(&store, &ids).await?;
    writeln!(
        io::stdout(),
        "GRAPH_MEASURED scenarios=9 samples_per_scenario={SAMPLES}"
    )?;
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    ensure!(
        SOURCE != "unbound",
        "producer must bind compilation to a source commit"
    );
    writeln!(
        io::stdout(),
        "GRAPH_READY {}",
        json!({"pid":std::process::id(),"source_commit":SOURCE})
    )?;
    io::stdout().flush()?;
    let mut permission = [0_u8; 4];
    io::stdin().read_exact(&mut permission)?;
    ensure!(
        permission == *b"RUN\n",
        "producer must bind the live executable first"
    );
    match tokio::time::timeout(std::time::Duration::from_mins(20), measure()).await {
        Ok(Ok(())) => Ok(()),
        _ => anyhow::bail!("native graph measurement failed (driver details suppressed)"),
    }
}
