// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3809 — `kg_timeline` rendered the same `valid_until` instant two ways:
//! `+00:00` on the postgres recursive-CTE read path (chrono `to_rfc3339`) and
//! the canonical `Z` stamp (`canonicalize_valid_until_stamp`, #3281 / #3322)
//! on the AGE path and on sqlite. Every KG read path must emit the one
//! canonical spelling, byte for byte.
//!
//! The sqlite cell always runs. The postgres cells need
//! `AI_MEMORY_TEST_POSTGRES_URL` (and AGE for the cypher half) and skip with a
//! message otherwise, like the other live-postgres suites.

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};

mod common;

/// A canonical stamp: UTC, microsecond precision, `Z` suffix.
const CANONICAL_UNTIL: &str = "2026-09-18T19:11:07.138208Z";
/// The same instant in the non-canonical spelling a caller may send.
#[cfg(feature = "sal-postgres")]
const OFFSET_UNTIL: &str = "2026-09-18T19:11:07.138208+00:00";
/// A still-current (future) stamp in the `+00:00` spelling, and its canonical
/// form: the current-view `kg_query` readers keep the edge, so the stamp they
/// render is the one under test.
const FUTURE_OFFSET_UNTIL: &str = "2099-01-01T00:00:00.123456+00:00";
const FUTURE_CANONICAL_UNTIL: &str = "2099-01-01T00:00:00.123456Z";
const AGENT: &str = "ai:kg-stamp-3809";

fn make_memory(id: &str, namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        tags: vec!["kg-stamp-3809".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "kg-stamp-3809".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id": AGENT}),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    }
}

#[test]
fn sqlite_kg_timeline_emits_canonical_z_valid_until_3809() {
    let conn = common::fresh_conn();
    let ns = format!("kg-stamp-{}", uuid::Uuid::new_v4());
    let src = db::insert(
        &conn,
        &make_memory(&uuid::Uuid::new_v4().to_string(), &ns, "src"),
    )
    .expect("insert src");
    let dst = db::insert(
        &conn,
        &make_memory(&uuid::Uuid::new_v4().to_string(), &ns, "dst"),
    )
    .expect("insert dst");
    db::create_link(&conn, &src, &dst, "related_to").expect("create link");
    // sqlite keeps the caller string verbatim (H2 signature bytes), so the
    // canonical stamp goes in and must come back byte-identical.
    db::invalidate_link(&conn, &src, &dst, "related_to", Some(CANONICAL_UNTIL), None)
        .expect("invalidate")
        .expect("link exists");
    let rows = db::kg_timeline(&conn, &src, None, None, None).expect("kg_timeline");
    assert_eq!(rows.len(), 1, "one timeline event");
    assert_eq!(
        rows[0].valid_until.as_deref(),
        Some(CANONICAL_UNTIL),
        "sqlite kg_timeline must emit the canonical Z stamp"
    );
}

/// F1 (review r1): every sqlite KG reader renders the canonical `Z` stamp for a
/// `+00:00` input, while the STORED text (the H2 signature bytes) is untouched.
#[test]
fn sqlite_kg_readers_emit_canonical_z_for_offset_input_3809() {
    let conn = common::fresh_conn();
    let ns = format!("kg-stamp-{}", uuid::Uuid::new_v4());
    let src = db::insert(
        &conn,
        &make_memory(&uuid::Uuid::new_v4().to_string(), &ns, "src"),
    )
    .expect("insert src");
    let dst = db::insert(
        &conn,
        &make_memory(&uuid::Uuid::new_v4().to_string(), &ns, "dst"),
    )
    .expect("insert dst");
    db::create_link(&conn, &src, &dst, "related_to").expect("create link");
    db::invalidate_link(
        &conn,
        &src,
        &dst,
        "related_to",
        Some(FUTURE_OFFSET_UNTIL),
        None,
    )
    .expect("invalidate")
    .expect("link exists");

    let timeline = db::kg_timeline(&conn, &src, None, None, None).expect("kg_timeline");
    assert_eq!(timeline.len(), 1, "one timeline event");
    assert_eq!(
        timeline[0].valid_until.as_deref(),
        Some(FUTURE_CANONICAL_UNTIL),
        "sqlite kg_timeline must emit the canonical Z stamp for a +00:00 input"
    );
    let query = db::kg_query(&conn, &src, 1, None, None, None, true).expect("kg_query");
    assert_eq!(query.len(), 1, "one kg_query row");
    assert_eq!(
        query[0].valid_until.as_deref(),
        Some(FUTURE_CANONICAL_UNTIL),
        "sqlite kg_query must emit the canonical Z stamp for a +00:00 input"
    );
    let links = db::get_links(&conn, &src).expect("get_links");
    assert_eq!(links.len(), 1, "one link");
    assert_eq!(
        links[0].valid_until.as_deref(),
        Some(FUTURE_CANONICAL_UNTIL),
        "sqlite get_links must emit the canonical Z stamp for a +00:00 input"
    );

    // The stored text is left as the caller sent it (H2 signature bytes).
    let stored: Option<String> = conn
        .query_row(
            "SELECT valid_until FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
            rusqlite::params![src, dst],
            |row| row.get(0),
        )
        .expect("stored valid_until");
    assert_eq!(
        stored.as_deref(),
        Some(FUTURE_OFFSET_UNTIL),
        "the stored valid_until text must be unchanged"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        AGENT, CANONICAL_UNTIL, FUTURE_CANONICAL_UNTIL, FUTURE_OFFSET_UNTIL, OFFSET_UNTIL, common,
        make_memory,
    };
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, KgBackend, MemoryStore};

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

    async fn project_edge_into_age(
        url: &str,
        src: &str,
        dst: &str,
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
        for id in [src, dst] {
            let sql = "SELECT * FROM cypher('memory_graph', $$ MERGE (n {id: $id}) RETURN n $$, $1) AS (n agtype)";
            sqlx::query(sql)
                .bind(Agtype(serde_json::json!({ "id": id }).to_string()))
                .fetch_all(&mut *tx)
                .await?;
        }
        let cypher = "MATCH (a {id: $src}), (b {id: $dst}) \
             MERGE (a)-[r:related_to {relation: 'related_to'}]->(b) \
             SET r.valid_from = $vf, r.observed_by = 'ai:kg-stamp-3809', r.created_at = $vf \
             RETURN r";
        let sql = format!("SELECT * FROM cypher('memory_graph', $$ {cypher} $$, $1) AS (r agtype)");
        sqlx::query(&sql)
            .bind(Agtype(
                serde_json::json!({"src": src, "dst": dst, "vf": valid_from}).to_string(),
            ))
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// F1 (review r1): every postgres KG reader (`get_links`,
    /// `get_links_for_anchor`, `kg_query` on the CTE and AGE paths, and
    /// `kg_timeline`) emits the canonical `Z` stamp for a `+00:00` input.
    #[tokio::test]
    async fn postgres_kg_readers_emit_canonical_z_for_offset_input_3809() {
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
        let ns = format!("kg-stamp-{}", uuid::Uuid::new_v4());
        let src = format!("{ns}-src");
        let dst = format!("{ns}-dst");
        for (id, title) in [(&src, "src"), (&dst, "dst")] {
            store
                .store(&ctx, &make_memory(id, &ns, title))
                .await
                .expect("store memory");
        }
        let valid_from = chrono::Utc::now() - chrono::Duration::seconds(1000);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("pool");
        sqlx::query(
            "INSERT INTO memory_links (source_id, target_id, relation, valid_from, observed_by) \
             VALUES ($1, $2, 'related_to', $3, $4)",
        )
        .bind(&src)
        .bind(&dst)
        .bind(valid_from)
        .bind(AGENT)
        .execute(&pool)
        .await
        .expect("insert link");
        let age = matches!(store.kg_backend(), KgBackend::Age);
        if age {
            project_edge_into_age(&url, &src, &dst, &valid_from.to_rfc3339())
                .await
                .expect("project edge into AGE");
            store
                .kg_invalidate_cypher(&src, &dst, "related_to", Some(FUTURE_OFFSET_UNTIL), None)
                .await
                .expect("kg_invalidate_cypher");
        } else {
            store
                .kg_invalidate_cte(&src, &dst, "related_to", Some(FUTURE_OFFSET_UNTIL), None)
                .await
                .expect("kg_invalidate_cte");
        }

        let links = store.get_links(&src).await.expect("get_links");
        assert_eq!(links.len(), 1, "one link");
        assert_eq!(
            links[0].valid_until.as_deref(),
            Some(FUTURE_CANONICAL_UNTIL),
            "postgres get_links must emit the canonical Z stamp"
        );
        let anchor = store
            .get_links_for_anchor(&src)
            .await
            .expect("get_links_for_anchor");
        assert_eq!(anchor.len(), 1, "one anchor link");
        assert_eq!(
            anchor[0].valid_until.as_deref(),
            Some(FUTURE_CANONICAL_UNTIL),
            "postgres get_links_for_anchor must emit the canonical Z stamp"
        );
        let cte = store
            .kg_query_cte_filtered(&src, 1, true)
            .await
            .expect("kg_query_cte_filtered");
        assert_eq!(cte.len(), 1, "one CTE kg_query row");
        assert_eq!(
            cte[0].valid_until.as_deref(),
            Some(FUTURE_CANONICAL_UNTIL),
            "postgres CTE kg_query must emit the canonical Z stamp"
        );
        if age {
            let cypher = store
                .kg_query_cypher(&src, 1)
                .await
                .expect("kg_query_cypher");
            assert_eq!(cypher.len(), 1, "one AGE kg_query row");
            assert_eq!(
                cypher[0].valid_until.as_deref(),
                Some(FUTURE_CANONICAL_UNTIL),
                "AGE kg_query must emit the canonical Z stamp"
            );
        } else {
            eprintln!("note: AGE absent; checked the CTE half only");
        }
    }

    #[tokio::test]
    async fn postgres_kg_timeline_cte_and_cypher_emit_canonical_z_valid_until_3809() {
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
        let ns = format!("kg-stamp-{}", uuid::Uuid::new_v4());
        let src = format!("{ns}-src");
        let dst = format!("{ns}-dst");
        store
            .store(&ctx, &make_memory(&src, &ns, "src"))
            .await
            .expect("store src");
        store
            .store(&ctx, &make_memory(&dst, &ns, "dst"))
            .await
            .expect("store dst");
        let valid_from = chrono::Utc::now() - chrono::Duration::seconds(1000);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("pool");
        sqlx::query(
            "INSERT INTO memory_links (source_id, target_id, relation, valid_from, observed_by) \
             VALUES ($1, $2, 'related_to', $3, $4)",
        )
        .bind(&src)
        .bind(&dst)
        .bind(valid_from)
        .bind(AGENT)
        .execute(&pool)
        .await
        .expect("insert link");

        let age = matches!(store.kg_backend(), KgBackend::Age);
        if age {
            project_edge_into_age(&url, &src, &dst, &valid_from.to_rfc3339())
                .await
                .expect("project edge into AGE");
            store
                .kg_invalidate_cypher(&src, &dst, "related_to", Some(OFFSET_UNTIL), None)
                .await
                .expect("kg_invalidate_cypher");
        } else {
            eprintln!("note: AGE absent; checking the CTE half only");
            store
                .kg_invalidate_cte(&src, &dst, "related_to", Some(OFFSET_UNTIL), None)
                .await
                .expect("kg_invalidate_cte");
        }

        let cte = store
            .kg_timeline_cte(&src, None, None, Some(10))
            .await
            .expect("kg_timeline_cte");
        assert_eq!(cte.len(), 1);
        assert_eq!(
            cte[0].valid_until.as_deref(),
            Some(CANONICAL_UNTIL),
            "postgres CTE kg_timeline must emit the canonical Z stamp"
        );
        if age {
            let cypher = store
                .kg_timeline_cypher(&src, None, None, Some(10))
                .await
                .expect("kg_timeline_cypher");
            assert_eq!(cypher.len(), 1);
            assert_eq!(
                cypher[0].valid_until, cte[0].valid_until,
                "AGE and CTE kg_timeline must emit byte-identical valid_until"
            );
            assert_eq!(
                cypher[0].valid_from, cte[0].valid_from,
                "AGE and CTE kg_timeline must emit byte-identical valid_from"
            );
        }
    }
}
