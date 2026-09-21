// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]
#[path = "../benches/support/native_graph_fixture.rs"]
mod fixture;

use ai_memory::store::{KgBackend, postgres::PostgresStore};
use anyhow::{Context, Result, ensure};
use fixture::{DRAIN_ROWS, NODES, prepare_drain, seed, verify_drain, verify_seed};

async fn isolated_control<F, Fut>(control: F) -> Result<()>
where
    F: FnOnce(PostgresStore) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let url =
        std::env::var("AI_MEMORY_TEST_AGE_URL").context("explicit native AGE URL required")?;
    let admin = sqlx::PgPool::connect(&url)
        .await
        .map_err(|_| anyhow::anyhow!("native admin connection failed; details suppressed"))?;
    let mut child_url = reqwest::Url::parse(&url).context("native URL shape")?;
    let name = format!("astra_e6_guard_{}", uuid::Uuid::new_v4().simple());
    child_url.set_path(&format!("/{name}"));
    // UUID-generated ASCII identifier, never caller-controlled SQL text.
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await
        .map_err(|_| anyhow::anyhow!("native control database creation failed"))?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        let setup = sqlx::PgPool::connect(child_url.as_str())
            .await
            .map_err(|_| anyhow::anyhow!("native child connection failed"))?;
        let extensions = sqlx::raw_sql("CREATE EXTENSION age; CREATE EXTENSION vector;")
            .execute(&setup)
            .await;
        setup.close().await;
        extensions.map_err(|_| anyhow::anyhow!("native extensions unavailable"))?;
        let store = PostgresStore::connect(child_url.as_str())
            .await
            .map_err(|_| anyhow::anyhow!("native fixture connection failed"))?;
        ensure!(
            matches!(store.kg_backend(), KgBackend::Age),
            "AGE must execute"
        );
        control(store).await
    })
    .await
    .context("native fixture control deadline")
    .and_then(|value| value);
    let cleanup = sqlx::query(&format!("DROP DATABASE \"{name}\" WITH (FORCE)"))
        .execute(&admin)
        .await;
    let absent: bool =
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(&name)
            .fetch_one(&admin)
            .await
            .map_err(|_| anyhow::anyhow!("native cleanup verification failed"))?;
    admin.close().await;
    cleanup.map_err(|_| anyhow::anyhow!("native control database cleanup failed"))?;
    ensure!(absent, "native control database must be absent");
    result
}

async fn remove_incoming_edge(store: &PostgresStore, target: &str) -> Result<()> {
    let mut tx = store.pool().begin().await?;
    sqlx::query("LOAD 'age'").execute(&mut *tx).await?;
    sqlx::query("SET LOCAL search_path = ag_catalog, public")
        .execute(&mut *tx)
        .await?;
    // Corrupt the actual AGE projection while preserving its vertices and durable links.
    // Bind the target as binary agtype JSON; no ID is interpolated into Cypher.
    let removed = sqlx::query("SELECT * FROM cypher('memory_graph', $$ MATCH (:Memory)-[r:related_to]->(n:Memory) WHERE n.id = $target DELETE r RETURN r $$, $1) AS (r agtype)")
        .bind(fixture::Agtype(serde_json::json!({"target": target}).to_string())).fetch_all(&mut *tx).await?;
    ensure!(
        removed.len() == 1,
        "exactly one fixture relationship removed"
    );
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit native AGE; graph baseline producer runs this control"]
async fn missing_deep_relationship_refuses_baseline() -> Result<()> {
    isolated_control(|store| async move {
        let ids = seed(&store).await?;
        verify_seed(&store, &ids).await?;
        // Beyond the 84 shallow read results, before the 64 drain leaves.
        remove_incoming_edge(&store, &ids[500]).await?;
        let error = verify_seed(&store, &ids)
            .await
            .err()
            .context("missing AGE relationship was accepted")?;
        ensure!(
            error.to_string() == "complete AGE relationships",
            "relationship count must cause refusal"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires explicit native AGE; graph baseline producer runs this control"]
async fn vertices_without_restored_relationships_refuse_drain() -> Result<()> {
    isolated_control(|store| async move {
        let ids = seed(&store).await?;
        prepare_drain(&store, &ids).await?;
        ensure!(
            store
                .drain_kg_projection_outbox(i64::try_from(DRAIN_ROWS)?)
                .await?
                == DRAIN_ROWS,
            "exact drained batch"
        );
        verify_drain(&store, &ids).await?;
        remove_incoming_edge(&store, &ids[NODES - 1]).await?;
        let error = verify_drain(&store, &ids)
            .await
            .err()
            .context("vertex-only drain was accepted")?;
        ensure!(
            error.to_string() == "drain relationships restored",
            "relationship count must cause refusal"
        );
        Ok(())
    })
    .await
}
