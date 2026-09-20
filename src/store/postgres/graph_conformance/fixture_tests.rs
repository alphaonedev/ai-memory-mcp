// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use crate::store::{KgBackend, postgres::PostgresStore};
use sqlx::Row;

pub(super) const STAMP: &str = "2020-01-01T00:00:00Z";
pub(super) const FROM: &str = "2019-01-01T00:00:00+00:00";

pub(super) struct Fixture {
    pub store: PostgresStore,
    pub ids: Vec<String>,
}

impl Fixture {
    pub async fn new() -> Self {
        let age = std::env::var("AI_MEMORY_TEST_AGE_URL")
            .ok()
            .filter(|url| !url.is_empty());
        let pg = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|url| !url.is_empty());
        let Some(url) = age else {
            let case = if pg.is_some() {
                "undeclared"
            } else {
                "url-unset"
            };
            panic!("GRAPH_CASE {case}: AGE conformance was selected without an AGE URL");
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&url)
            .await
            .unwrap_or_else(|_| panic!("GRAPH_CASE declared-unavailable: connection failed"));
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'age')")
                .fetch_one(&pool)
                .await
                .expect("probe extension catalog");
        assert!(
            present,
            "GRAPH_CASE declared-absent: AGE extension is absent"
        );
        eprintln!("GRAPH_CASE declared-present");
        pool.close().await;
        let store = PostgresStore::connect(&url)
            .await
            .unwrap_or_else(|_| panic!("GRAPH_CASE declared-present: store bootstrap failed"));
        assert!(
            matches!(store.kg_backend(), KgBackend::Age),
            "declared AGE must never degrade to CTE"
        );
        let namespace = format!("graph3573-{}", uuid::Uuid::new_v4());
        let ids: Vec<_> = (0..8).map(|n| format!("{namespace}-{n}")).collect();
        for id in &ids {
            sqlx::query("INSERT INTO memories (id,tier,namespace,title,content,source) VALUES ($1,'long',$2,$1,'fixture','graph3573')")
                .bind(id).bind(&namespace).execute(&store.pool).await.expect("seed memory");
        }
        let fixture = Self { store, ids };
        // Parallel relations, diamond, three-hop chain, cycle, isolated node,
        // and a historical edge whose only target is node 6.
        for (a, b, relation) in [
            (0, 1, "related_to"),
            (0, 1, "supersedes"),
            (1, 2, "related_to"),
            (2, 3, "related_to"),
            (0, 4, "derived_from"),
            (4, 5, "derived_from"),
            (1, 5, "related_to"),
            (2, 0, "related_to"),
            (0, 6, "contradicts"),
        ] {
            fixture.link(a, b, relation).await;
        }
        fixture.invalidate_fixture().await;
        fixture
    }

    pub async fn link(&self, a: usize, b: usize, relation: &str) {
        sqlx::query("INSERT INTO memory_links (source_id,target_id,relation,valid_from) VALUES ($1,$2,$3,$4::timestamptz)")
            .bind(&self.ids[a]).bind(&self.ids[b]).bind(relation).bind(FROM)
            .execute(&self.store.pool).await.expect("seed relational edge");
        let mut tx = self.store.pool.begin().await.expect("begin projection");
        super::super::project_link_into_age(
            &mut tx,
            &self.ids[a],
            &self.ids[b],
            relation,
            Some(FROM),
            None,
        )
        .await
        .expect("project fixture edge");
        tx.commit().await.expect("commit projection");
    }

    async fn invalidate_fixture(&self) {
        // Exercise the real mutation before any read cell. The separate
        // invalidation cell tests the never-invalidated -> invalidated transition.
        self.store
            .kg_invalidate_cypher(&self.ids[0], &self.ids[6], "contradicts", Some(STAMP), None)
            .await
            .expect("invalidate fixture");
        let relational: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT valid_until FROM memory_links WHERE source_id=$1 AND target_id=$2 AND relation='contradicts'")
            .bind(&self.ids[0]).bind(&self.ids[6]).fetch_one(&self.store.pool).await.expect("fixture relational stamp");
        assert_eq!(
            relational
                .map(|v| v.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
                .as_deref(),
            Some(STAMP)
        );
        assert_eq!(
            self.age_stamp(0, 6, "contradicts").await.as_deref(),
            Some(STAMP)
        );
        assert_eq!(self.age_stamp(0, 1, "related_to").await, None);
    }

    pub async fn age_stamp(&self, a: usize, b: usize, relation: &str) -> Option<String> {
        let mut tx = self
            .store
            .pool
            .begin()
            .await
            .expect("begin AGE ground truth");
        super::super::load_age_tolerated(&mut tx)
            .await
            .expect("load AGE");
        sqlx::query(super::super::SQL_SET_AGE_SEARCH_PATH)
            .execute(&mut *tx)
            .await
            .expect("search path");
        let rows = sqlx::query("SELECT stamp::text AS stamp FROM cypher('memory_graph', $$ MATCH (a)-[r]->(b) WHERE a.id=$src AND b.id=$dst AND r.relation=$rel RETURN r.valid_until $$, $1) AS (stamp agtype)")
            .bind(super::super::Agtype(serde_json::json!({"src":self.ids[a],"dst":self.ids[b],"rel":relation}).to_string()))
            .fetch_all(&mut *tx).await.expect("AGE stamp read");
        assert_eq!(
            rows.len(),
            1,
            "ground-truth edge must exist even when its property is absent"
        );
        let value: Option<String> = rows[0].try_get("stamp").expect("stamp decode");
        value
    }
}
