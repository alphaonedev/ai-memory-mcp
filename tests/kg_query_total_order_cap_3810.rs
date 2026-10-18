// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3810 — the `kg_query` sort key was `(depth, target_id)` on postgres and
//! `(depth, valid_from, created_at)` on sqlite: neither is a total order over
//! the rows a traversal emits (two parallel edges to one target at one depth
//! tie on the postgres key; same-instant edges tie on the sqlite key). The row
//! cap (200) is applied AFTER that sort, so a tied group straddling the cap
//! returned a different surviving edge per backend and per run.
//!
//! The fixture is one source with 200 distinct depth-1 targets, the last of
//! which (`...-200`, the greatest id) carries TWO parallel edges
//! (`supersedes` written first, `related_to` second): 201 rows, cap 200, the
//! cap splits the tied group. The total key `(depth, target_id, relation,
//! path)` keeps `related_to` (`"related_to" < "supersedes"` in byte order) on
//! every backend, in the same order, on every run.
//!
//! The sqlite cell always runs. The postgres CTE and AGE cells need
//! `AI_MEMORY_TEST_POSTGRES_URL` (and AGE for the cypher half) and skip with a
//! message otherwise.

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};

mod common;

const AGENT: &str = "ai:kg-order-3810";
/// Distinct depth-1 targets; the last one carries the tied parallel pair.
const TARGETS: usize = 200;
/// The default `kg_query` row cap on every backend.
const ROW_CAP: usize = 200;
const SURVIVOR: &str = "related_to";
const CUT: &str = "supersedes";

fn target_id(ns: &str, n: usize) -> String {
    format!("{ns}-mem-{n:03}")
}

fn make_memory(id: &str, namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        tags: vec!["kg-order-3810".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "kg-order-3810".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id": AGENT}),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    }
}

/// `(depth, target_id, relation, path)` — the whole observable row identity.
type Key = (usize, String, String, String);

fn expected_keys(ns: &str) -> Vec<Key> {
    let src = format!("{ns}-src");
    let mut keys: Vec<Key> = (1..=TARGETS)
        .map(|n| {
            let t = target_id(ns, n);
            (1, t.clone(), SURVIVOR.to_string(), format!("{src}->{t}"))
        })
        .collect();
    keys.truncate(ROW_CAP);
    keys
}

fn assert_expected(label: &str, ns: &str, got: &[Key]) {
    let want = expected_keys(ns);
    assert_eq!(got.len(), ROW_CAP, "{label}: the cap must be reached");
    let tied: Vec<&Key> = got
        .iter()
        .filter(|k| k.1 == target_id(ns, TARGETS))
        .collect();
    assert_eq!(tied.len(), 1, "{label}: the cap splits the tied pair");
    assert_eq!(
        tied[0].2, SURVIVOR,
        "{label}: the surviving parallel edge must be `{SURVIVOR}`, not `{CUT}`"
    );
    assert_eq!(got, want.as_slice(), "{label}: full ordered page");
}

#[test]
fn sqlite_kg_query_cap_keeps_total_order_survivor_3810() {
    let conn = common::fresh_conn();
    let ns = format!("kg-order-{}", uuid::Uuid::new_v4());
    let src = format!("{ns}-src");
    db::insert(&conn, &make_memory(&src, &ns, "src")).expect("insert src");
    for n in 1..=TARGETS {
        let id = target_id(&ns, n);
        db::insert(&conn, &make_memory(&id, &ns, &format!("t{n:03}"))).expect("insert target");
    }
    let last = target_id(&ns, TARGETS);
    // The cut relation is written FIRST so its created_at/valid_from sort
    // earlier: the pre-fix sqlite key kept it, the total key must not.
    db::create_link(&conn, &src, &last, CUT).expect("link cut");
    for n in 1..=TARGETS {
        db::create_link(&conn, &src, &target_id(&ns, n), SURVIVOR).expect("link");
    }
    let run = || -> Vec<Key> {
        db::kg_query(&conn, &src, 1, None, None, Some(ROW_CAP), false)
            .expect("kg_query")
            .into_iter()
            .map(|r| (r.depth, r.target_id, r.relation, r.path))
            .collect()
    };
    let first = run();
    assert_expected("sqlite", &ns, &first);
    assert_eq!(first, run(), "sqlite: order is deterministic across runs");
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        AGENT, CUT, Key, SURVIVOR, TARGETS, assert_expected, common, make_memory, target_id,
    };
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, KgBackend, KgQueryRow, MemoryStore};

    /// sqlx bind wrapper for AGE's `agtype` (mirrors the adapter-private one).
    struct Agtype(String);

    impl sqlx::Type<sqlx::Postgres> for Agtype {
        fn type_info() -> sqlx::postgres::PgTypeInfo {
            sqlx::postgres::PgTypeInfo::with_name("agtype")
        }
        fn compatible(_ty: &sqlx::postgres::PgTypeInfo) -> bool {
            true
        }
    }

    impl sqlx::Encode<'_, sqlx::Postgres> for Agtype {
        fn encode_by_ref(
            &self,
            buf: &mut sqlx::postgres::PgArgumentBuffer,
        ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
            buf.push(1);
            buf.extend_from_slice(self.0.as_bytes());
            Ok(sqlx::encode::IsNull::No)
        }
    }

    fn keys(rows: Vec<KgQueryRow>) -> Vec<Key> {
        rows.into_iter()
            .map(|r| (r.depth, r.target_id, r.relation, r.path))
            .collect()
    }

    /// Project every relational edge of `src` into AGE (one node per id, one
    /// edge per `(target, relation)` carrying the relation as a property).
    async fn project_into_age(
        url: &str,
        src: &str,
        edges: &[(String, &'static str)],
        valid_from: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(url)
            .await?;
        let mut tx = pool.begin().await?;
        sqlx::query("LOAD 'age'").execute(&mut *tx).await?;
        sqlx::query("SET search_path = ag_catalog, \"$user\", public")
            .execute(&mut *tx)
            .await?;
        let node_sql = "SELECT * FROM cypher('memory_graph', $$ MERGE (n {id: $id}) RETURN n $$, $1) AS (n agtype)";
        let mut ids: Vec<&str> = vec![src];
        ids.extend(edges.iter().map(|(t, _)| t.as_str()));
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            sqlx::query(node_sql)
                .bind(Agtype(serde_json::json!({ "id": id }).to_string()))
                .fetch_all(&mut *tx)
                .await?;
        }
        let cypher = "MATCH (a {id: $src}), (b {id: $dst}) \
             MERGE (a)-[r:related_to {relation: $rel}]->(b) \
             SET r.valid_from = $vf, r.observed_by = 'ai:kg-order-3810', r.created_at = $vf \
             RETURN r";
        let edge_sql =
            format!("SELECT * FROM cypher('memory_graph', $$ {cypher} $$, $1) AS (r agtype)");
        for (dst, rel) in edges {
            let params = serde_json::json!({
                "src": src, "dst": dst, "rel": rel, "vf": valid_from,
            })
            .to_string();
            sqlx::query(&edge_sql)
                .bind(Agtype(params))
                .fetch_all(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    #[tokio::test]
    async fn postgres_kg_query_cap_keeps_total_order_survivor_cte_and_age_3810() {
        let Some(url) = common::postgres_url().or_else(common::age_url) else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = match PostgresStore::connect(&url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                return;
            }
        };
        let ctx = CallerContext::for_agent(AGENT);
        let ns = format!("kg-order-{}", uuid::Uuid::new_v4());
        let src = format!("{ns}-src");
        store
            .store(&ctx, &make_memory(&src, &ns, "src"))
            .await
            .expect("store src");
        for n in 1..=TARGETS {
            let id = target_id(&ns, n);
            store
                .store(&ctx, &make_memory(&id, &ns, &format!("t{n:03}")))
                .await
                .expect("store target");
        }
        let last = target_id(&ns, TARGETS);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("pool");
        let valid_from = chrono::Utc::now() - chrono::Duration::seconds(1000);
        // The cut relation first, then every survivor edge.
        let mut edges: Vec<(String, &'static str)> = vec![(last.clone(), CUT)];
        edges.extend((1..=TARGETS).map(|n| (target_id(&ns, n), SURVIVOR)));
        for (dst, rel) in &edges {
            sqlx::query(
                "INSERT INTO memory_links (source_id, target_id, relation, valid_from, observed_by) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&src)
            .bind(dst)
            .bind(rel)
            .bind(valid_from)
            .bind(AGENT)
            .execute(&pool)
            .await
            .expect("insert link");
        }

        let cte = keys(store.kg_query_cte(&src, 1).await.expect("kg_query_cte"));
        assert_expected("postgres CTE", &ns, &cte);
        let cte_again = keys(store.kg_query_cte(&src, 1).await.expect("kg_query_cte"));
        assert_eq!(cte, cte_again, "postgres CTE: deterministic across runs");

        if matches!(store.kg_backend(), KgBackend::Age) {
            project_into_age(&url, &src, &edges, &valid_from.to_rfc3339())
                .await
                .expect("project into AGE");
            let age = keys(
                store
                    .kg_query_cypher(&src, 1)
                    .await
                    .expect("kg_query_cypher"),
            );
            assert_expected("AGE cypher", &ns, &age);
            assert_eq!(age, cte, "AGE and CTE return the identical ordered page");
            let age_again = keys(
                store
                    .kg_query_cypher(&src, 1)
                    .await
                    .expect("kg_query_cypher"),
            );
            assert_eq!(age, age_again, "AGE: deterministic across runs");
        } else {
            eprintln!("note: AGE absent; checked the CTE half only");
        }
    }
}
