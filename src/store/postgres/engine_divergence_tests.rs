// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Native engine pins for #3810 and #3809. Direct calls cannot silently fall back.
use super::{KgBackend, PostgresStore, kg_query_row_cap, project_link_into_age};

const FROM: &str = "2019-01-01T00:00:00+00:00";

struct Fixture {
    store: PostgresStore,
    ids: Vec<String>,
}

impl Fixture {
    async fn new(count: usize) -> Self {
        let url = std::env::var("AI_MEMORY_TEST_AGE_URL")
            .ok()
            .filter(|value| !value.is_empty())
            .expect("ENGINE_PIN requires explicit AGE URL");
        let store = PostgresStore::connect(&url)
            .await
            .unwrap_or_else(|_| panic!("ENGINE_PIN connection/bootstrap failed"));
        assert!(matches!(store.kg_backend(), KgBackend::Age));
        let namespace = format!("engine3810-{}", uuid::Uuid::new_v4());
        let ids: Vec<_> = (0..count).map(|i| format!("{namespace}-{i:04}")).collect();
        for id in &ids {
            sqlx::query("INSERT INTO memories (id,tier,namespace,title,content,source) VALUES ($1,'long',$2,$1,'fixture','engine3810')")
                .bind(id).bind(&namespace).execute(&store.pool).await.expect("seed memory");
        }
        Self { store, ids }
    }

    async fn link(&self, a: usize, b: usize, relation: &str) {
        sqlx::query("INSERT INTO memory_links (source_id,target_id,relation,valid_from) VALUES ($1,$2,$3,$4::timestamptz)")
            .bind(&self.ids[a]).bind(&self.ids[b]).bind(relation).bind(FROM)
            .execute(&self.store.pool).await.expect("seed relational edge");
        let mut tx = self.store.pool.begin().await.expect("begin projection");
        project_link_into_age(
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
}

#[tokio::test]
#[ignore = "requires an explicitly declared live AGE database"]
async fn parallel_edges_have_the_same_bounded_page_3810() {
    let cap = kg_query_row_cap(None);
    assert!(cap > 1);
    let f = Fixture::new(cap + 1).await;
    // cap - 1 lower target IDs, then two relations crossing the page boundary.
    for target in 1..cap {
        f.link(0, target, "related_to").await;
    }
    f.link(0, cap, "related_to").await;
    f.link(0, cap, "supersedes").await;
    let cte = f
        .store
        .kg_query_cte(&f.ids[0], 1)
        .await
        .expect("CTE executes");
    let age = f
        .store
        .kg_query_cypher(&f.ids[0], 1)
        .await
        .expect("AGE executes");
    assert_eq!(cte.len(), cap);
    assert_eq!(age.len(), cap);
    for rows in [&cte, &age] {
        let boundary: Vec<_> = rows
            .iter()
            .filter(|r| r.target_id == f.ids[cap])
            .map(|r| r.relation.as_str())
            .collect();
        assert_eq!(boundary, ["related_to"], "deterministic edge at the cap");
        assert!(rows.iter().any(|r| r.target_id == f.ids[1]));
        assert!(!rows.iter().any(|r| r.relation == "supersedes"));
    }
    assert_eq!(
        serde_json::to_value(&cte).unwrap(),
        serde_json::to_value(&age).unwrap()
    );
}

#[tokio::test]
#[ignore = "requires an explicitly declared live AGE database"]
async fn equal_relation_paths_have_a_total_order_3810() {
    let f = Fixture::new(4).await;
    // Reverse insertion order is deliberately different from the wire key.
    for (a, b) in [(0, 2), (2, 3), (0, 1), (1, 3)] {
        f.link(a, b, "related_to").await;
    }
    let cte = f
        .store
        .kg_query_cte(&f.ids[0], 2)
        .await
        .expect("CTE executes");
    let age = f
        .store
        .kg_query_cypher(&f.ids[0], 2)
        .await
        .expect("AGE executes");
    for rows in [&cte, &age] {
        assert_eq!(rows.len(), 4);
        let paths: Vec<_> = rows
            .iter()
            .filter(|r| r.depth == 2)
            .map(|r| r.path.clone())
            .collect();
        assert_eq!(
            paths,
            [
                format!("{}->{}->{}", f.ids[0], f.ids[1], f.ids[3]),
                format!("{}->{}->{}", f.ids[0], f.ids[2], f.ids[3])
            ]
        );
    }
    assert_eq!(
        serde_json::to_value(&cte).unwrap(),
        serde_json::to_value(&age).unwrap()
    );
}

#[tokio::test]
#[ignore = "requires an explicitly declared live AGE database"]
async fn timeline_invalidated_stamps_are_canonical_on_both_engines_3809() {
    let f = Fixture::new(4).await;
    for target in 1..4 {
        f.link(0, target, "related_to").await;
    }
    for (target, stamp) in [
        (1, "2020-01-01T02:00:00+02:00"),
        (2, "2020-01-01T00:00:00.123456Z"),
    ] {
        f.store
            .kg_invalidate_cypher(&f.ids[0], &f.ids[target], "related_to", Some(stamp), None)
            .await
            .expect("invalidate both sinks");
    }
    let cte = f
        .store
        .kg_timeline_cte(&f.ids[0], None, None, None)
        .await
        .expect("CTE executes");
    let age = f
        .store
        .kg_timeline_cypher(&f.ids[0], None, None, None)
        .await
        .expect("AGE executes");
    for rows in [&cte, &age] {
        assert_eq!(rows.len(), 3);
        for (target, stamp) in [
            (1, Some("2020-01-01T00:00:00Z")),
            (2, Some("2020-01-01T00:00:00.123456Z")),
            (3, None),
        ] {
            let row = rows
                .iter()
                .find(|r| r.target_id == f.ids[target])
                .expect("edge present even when stamp absent");
            assert_eq!(row.valid_until.as_deref(), stamp);
        }
    }
    // Compare by target: timeline tie order is a separate, pre-existing contract.
    let mut cte = cte;
    let mut age = age;
    cte.sort_by(|a, b| a.target_id.cmp(&b.target_id));
    age.sort_by(|a, b| a.target_id.cmp(&b.target_id));
    assert_eq!(
        serde_json::to_value(cte).unwrap(),
        serde_json::to_value(age).unwrap()
    );
}
