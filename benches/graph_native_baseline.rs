// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Descriptive, fail-closed native graph measurements; no performance SLA.
use ai_memory::store::{KgBackend, postgres::PostgresStore};
#[path = "support/native_graph_fixture.rs"]
mod fixture;
use anyhow::{Context, Result, ensure};
use fixture::{DRAIN_ROWS, NODES, prepare_drain, seed, verify_drain};
use serde_json::json;
use std::{
    io::{self, Read, Write},
    time::Instant,
};

const SAMPLES: usize = 200;
const WARMUP: usize = 10;
const SOURCE: &str = match option_env!("AI_MEMORY_GRAPH_BENCH_COMMIT") {
    Some(value) => value,
    None => "unbound",
};

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
        verify_drain(store, ids).await?;
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
