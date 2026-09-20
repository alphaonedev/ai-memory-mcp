// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3609: actual AGE predicates and the production relational path contract.
#![cfg(test)]

use super::{Agtype, KgBackend, PostgresStore};
use sqlx::Row;

struct Fixture {
    store: PostgresStore,
    ids: Vec<String>,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("AI_MEMORY_TEST_AGE_URL")
            .expect("PATH_PIN requires explicitly declared AGE");
        let store = PostgresStore::connect(&url)
            .await
            .unwrap_or_else(|_| panic!("PATH_PIN connection/bootstrap failed"));
        assert!(matches!(store.kg_backend(), KgBackend::Age));
        let namespace = format!("paths3609-{}", uuid::Uuid::new_v4());
        let ids: Vec<_> = (0..6).map(|n| format!("{namespace}-{n}")).collect();
        for id in &ids {
            sqlx::query("INSERT INTO memories (id,tier,namespace,title,content,source) VALUES ($1,'long',$2,$1,'fixture','paths3609')")
                .bind(id).bind(&namespace).execute(&store.pool).await.expect("seed memory");
        }
        let fixture = Self { store, ids };
        for (a, b, relation, until) in [
            (0, 1, "related_to", None),
            (0, 1, "supersedes", None),
            (1, 3, "related_to", None),
            (0, 2, "related_to", None),
            (2, 3, "related_to", None),
            (3, 0, "derived_from", Some("2020-01-01T00:00:00Z")),
            (0, 4, "contradicts", Some("2020-01-01T00:00:00Z")),
        ] {
            fixture.link(a, b, relation, until).await;
        }
        fixture
    }

    async fn link(&self, a: usize, b: usize, relation: &str, until: Option<&str>) {
        sqlx::query("INSERT INTO memory_links (source_id,target_id,relation,valid_from,valid_until) VALUES ($1,$2,$3,'2019-01-01T00:00:00Z'::timestamptz,$4::timestamptz)")
            .bind(&self.ids[a]).bind(&self.ids[b]).bind(relation).bind(until)
            .execute(&self.store.pool).await.expect("seed edge");
        let mut tx = self.store.pool.begin().await.expect("begin projection");
        super::project_link_into_age(
            &mut tx,
            &self.ids[a],
            &self.ids[b],
            relation,
            Some("2019-01-01T00:00:00Z"),
            until,
        )
        .await
        .expect("project edge");
        tx.commit().await.expect("commit projection");
    }

    async fn probe(&self, sql: &str) -> Result<Vec<String>, sqlx::Error> {
        let mut tx = self.store.pool.begin().await.expect("begin probe");
        super::load_age_tolerated(&mut tx).await.expect("load AGE");
        sqlx::query(super::SQL_SET_AGE_SEARCH_PATH)
            .execute(&mut *tx)
            .await
            .expect("search path");
        let result = sqlx::query(sql)
            .bind(Agtype(
                serde_json::json!({"src":self.ids[0],"dst":self.ids[1]}).to_string(),
            ))
            .fetch_all(&mut *tx)
            .await;
        tx.rollback().await.expect("isolate failed AGE statement");
        result?.iter().map(|row| row.try_get("value")).collect()
    }
}

#[tokio::test]
#[ignore = "requires native AGE 1.8.0"]
async fn age_180_predicate_runtime_failure_has_a_live_control() {
    let f = Fixture::new().await;
    let version: String =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname='age'")
            .fetch_one(&f.store.pool)
            .await
            .expect("extension version");
    assert_eq!(version, "1.8.0", "this characterization is version-bound");
    for sql in [
        "SELECT value::text FROM cypher('memory_graph', $$ RETURN ALL(x IN [1,2,3] WHERE x > 0) $$, $1) AS (value agtype)",
        "SELECT value::text FROM cypher('memory_graph', $$ RETURN ANY(x IN [1,2,3] WHERE x = 2) $$, $1) AS (value agtype)",
    ] {
        assert_eq!(
            f.probe(sql).await.expect("list predicate executes"),
            ["true"]
        );
    }
    let control = f.probe("SELECT value::text FROM cypher('memory_graph', $$ MATCH p=(a:Memory)-[*1..2]->(b:Memory) WHERE a.id=$src AND b.id=$dst RETURN a.id $$, $1) AS (value agtype)").await.expect("same seeded path without guard executes");
    assert!(!control.is_empty());
    assert!(control.iter().all(|id| id == &f.ids[0]));
    let failure = f.probe("SELECT value::text FROM cypher('memory_graph', $$ MATCH p=(a:Memory)-[*1..2]->(b:Memory) WHERE a.id=$src AND b.id=$dst AND ALL(e IN relationships(p) WHERE e.valid_until IS NULL) RETURN a.id $$, $1) AS (value agtype)").await.expect_err("runtime predicate remains unsupported");
    let database = failure
        .as_database_error()
        .expect("server error, not connection failure");
    assert!(database.message().contains("no relation entry for relid"));
    eprintln!(
        "PATH_PROBE AGE=1.8.0 ALL=list-ok ANY=list-ok path-ALL=runtime-relid-error control_rows={}",
        control.len()
    );
    let failure = f.probe("SELECT value::text FROM cypher('memory_graph', $$ RETURN filter(x IN [1,2,3] WHERE x > 1) $$, $1) AS (value agtype)").await.expect_err("filter parse rejected");
    assert_eq!(
        failure
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("42601")
    );
}

#[tokio::test]
#[ignore = "requires an explicitly declared live AGE database"]
async fn age_dispatch_and_relational_dispatch_preserve_current_paths() {
    let f = Fixture::new().await;
    let mut relational = f.store.clone();
    relational.kg_backend = KgBackend::Cte;
    let expected = vec![
        vec![f.ids[0].clone(), f.ids[1].clone(), f.ids[3].clone()],
        vec![f.ids[0].clone(), f.ids[2].clone(), f.ids[3].clone()],
    ];
    for store in [&f.store, &relational] {
        let paths = store
            .find_paths(&f.ids[0], &f.ids[3], Some(3), Some(10))
            .await
            .expect("executed dispatcher");
        assert_eq!(
            paths, expected,
            "diamond present; invalidated shortcut, cycles and duplicate relations absent"
        );
        assert_eq!(
            store
                .find_paths(&f.ids[0], &f.ids[3], Some(3), Some(1))
                .await
                .expect("capped dispatcher"),
            expected[..1]
        );
        assert!(
            store
                .find_paths(&f.ids[0], &f.ids[3], Some(1), Some(10))
                .await
                .expect("bounded depth")
                .is_empty()
        );
        for target in [4, 5] {
            assert!(
                store
                    .find_paths(&f.ids[0], &f.ids[target], Some(3), Some(10))
                    .await
                    .expect("expired or isolated endpoint")
                    .is_empty()
            );
        }
        let reverse = store
            .find_paths(&f.ids[3], &f.ids[0], Some(3), Some(10))
            .await
            .expect("undirected traversal");
        assert_eq!(reverse.len(), 2);
        assert_eq!(
            reverse[0],
            expected[0].iter().cloned().rev().collect::<Vec<_>>()
        );
    }
    // Prove the absent expired path is backed by a real, projected edge.
    let expired: i64=sqlx::query_scalar("SELECT count(*) FROM memory_links WHERE source_id=$1 AND target_id=$2 AND valid_until IS NOT NULL")
        .bind(&f.ids[0]).bind(&f.ids[4]).fetch_one(&f.store.pool).await.expect("historical presence");
    assert_eq!(expired, 1);
    eprintln!(
        "PATH_FALLBACK age_dispatch=2 cte_dispatch=2 cap=1 expired=absent historical_row=present"
    );
}
