// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Live AGE regression for #4049. Like the other AGE catalog fixtures, this
//! requires an isolated test database and must run serially with those fixtures.

#![cfg(feature = "sal-postgres")]

use ai_memory::cli::CliOutput;
use ai_memory::cli::schema_init::{SchemaInitArgs, SchemaInitReport};

async fn report(url: &str) -> anyhow::Result<SchemaInitReport> {
    let args = SchemaInitArgs {
        store_url: url.to_owned(),
        json: true,
        embedding_dim: Some(384),
        force_reembed: false,
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
    ai_memory::cli::schema_init::run(&args, None, &mut out).await?;
    Ok(serde_json::from_slice(&stdout)?)
}

#[tokio::test]
#[ignore = "requires an isolated live AGE database; run serially in cert-postgres-age"]
async fn schema_init_reports_orphan_false_and_preserves_data_4049() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_AGE_URL")
        .or_else(|_| std::env::var("AI_MEMORY_TEST_POSTGRES_URL"))
    else {
        eprintln!("skip: #4049 requires AI_MEMORY_TEST_AGE_URL / AI_MEMORY_TEST_POSTGRES_URL");
        return Ok(());
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    sqlx::query("CREATE EXTENSION IF NOT EXISTS age")
        .execute(&pool)
        .await?;
    sqlx::query("LOAD 'age'").execute(&pool).await?;
    sqlx::query("SET search_path = ag_catalog, public")
        .execute(&pool)
        .await?;
    let registered: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = 'memory_graph')",
    )
    .fetch_one(&pool)
    .await?;
    if registered {
        sqlx::query("SELECT drop_graph('memory_graph', true)")
            .execute(&pool)
            .await?;
    }
    // A bare schema reproduces the failure without deleting AGE catalog rows
    // underneath a backend that might have cached the old graph.
    sqlx::raw_sql(
        "CREATE SCHEMA memory_graph;
         CREATE TABLE memory_graph.operator_data (value text NOT NULL);
         INSERT INTO memory_graph.operator_data VALUES ('preserve me');",
    )
    .execute(&pool)
    .await?;
    let orphan_report = report(&url).await?;
    let (physical, registered): (bool, bool) = sqlx::query_as(
        "SELECT to_regnamespace('memory_graph') IS NOT NULL,
                EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = 'memory_graph')",
    )
    .fetch_one(&pool)
    .await?;
    let data: Vec<String> = sqlx::query_scalar("SELECT value FROM memory_graph.operator_data")
        .fetch_all(&pool)
        .await?;
    eprintln!(
        "SCHEMA physical={physical} registered={registered} reported={}",
        orphan_report.age_projection_created
    );
    assert!(physical, "schema-init must preserve the orphan schema");
    assert!(!registered, "schema-init must not repair the AGE registry");
    assert_eq!(data, ["preserve me"], "operator data must survive");

    // Only this fixture removes its schema. Exercise fresh creation and then
    // the already-registered control through the real JSON reporting path.
    sqlx::query("DROP SCHEMA memory_graph CASCADE")
        .execute(&pool)
        .await?;
    pool.close().await;
    assert!(report(&url).await?.age_projection_created);
    assert!(report(&url).await?.age_projection_created);
    assert!(
        !orphan_report.age_projection_created,
        "a missing graph cannot be a successful projection (#4049)"
    );
    Ok(())
}
