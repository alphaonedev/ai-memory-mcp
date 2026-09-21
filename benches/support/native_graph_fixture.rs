// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared native fixture checks used by the benchmark and its destructive controls.
use ai_memory::{
    models::MemoryLink,
    store::{CallerContext, MemoryStore, postgres::PostgresStore},
};
use anyhow::{Result, ensure};
use serde_json::json;

pub const NODES: usize = 1024;
pub const DRAIN_ROWS: usize = 64;

pub(crate) struct Agtype(pub(crate) String);
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

pub async fn seed(store: &PostgresStore) -> Result<Vec<String>> {
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
    verify_seed(store, &ids).await?;
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

async fn age_edge_count(store: &PostgresStore, ids: &[String], targets: &[String]) -> Result<i64> {
    let mut tx = store.pool().begin().await?;
    sqlx::query("LOAD 'age'").execute(&mut *tx).await?;
    sqlx::query("SET LOCAL search_path = ag_catalog, public")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT value::text::bigint FROM cypher('memory_graph', $$ MATCH (a:Memory)-[r:related_to]->(b:Memory) WHERE a.id IN $ids AND b.id IN $targets AND r.relation = 'related_to' RETURN count(r) $$, $1) AS (value agtype)")
        .bind(Agtype(json!({"ids": ids, "targets": targets}).to_string()))
        .fetch_one(&mut *tx).await?;
    tx.rollback().await?;
    Ok(count)
}

pub async fn prepare_drain(store: &PostgresStore, ids: &[String]) -> Result<()> {
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
    ensure!(
        age_edge_count(store, ids, leaves).await? == 0,
        "drain starts with absent relationships"
    );
    Ok(())
}

pub async fn verify_seed(store: &PostgresStore, ids: &[String]) -> Result<()> {
    ensure!(
        age_count(store, ids).await? == i64::try_from(NODES)?,
        "complete AGE vertices"
    );
    ensure!(
        age_edge_count(store, ids, ids).await? == i64::try_from(NODES - 1)?,
        "complete AGE relationships"
    );
    Ok(())
}

pub async fn verify_drain(store: &PostgresStore, ids: &[String]) -> Result<()> {
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kg_projection_outbox WHERE projected_at IS NULL")
            .fetch_one(store.pool())
            .await?;
    ensure!(pending == 0, "same outbox cleared");
    ensure!(
        age_count(store, &ids[NODES - DRAIN_ROWS..]).await? == i64::try_from(DRAIN_ROWS)?,
        "projections restored"
    );
    ensure!(
        age_edge_count(store, ids, &ids[NODES - DRAIN_ROWS..]).await? == i64::try_from(DRAIN_ROWS)?,
        "drain relationships restored"
    );
    Ok(())
}
