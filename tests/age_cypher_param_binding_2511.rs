// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

//! **R-203 (#2511)** — every AGE `cypher()` call this adapter builds must pass
//! its params dict as a bare, `agtype`-TYPED bind parameter.
//!
//! ## The defect
//!
//! `src/store/postgres.rs` inlined the third argument to `cypher()` as a
//! literal `'{"start_id":"…"}'::agtype` at all four AGE READ sites
//! (`kg_query`, `kg_timeline`, `lineage`, `kg_invalidate`). AGE's
//! `convert_cypher_to_subquery` analyzer rejects ANY non-`Param` node there:
//!
//! ```text
//! ERROR:  third argument of cypher function must be a parameter
//! ```
//!
//! Verified live on AGE **1.6.0** (the CI-certified image) and **1.7.0** (the
//! SSOT-pinned version). The dispatcher's `is_age_runtime_failure` arm then
//! re-served every request from the relational recursive CTE while
//! `Capabilities.kg_backend` kept reporting `Age` — so the derived graph was
//! served by a different engine than the one advertised, and any test
//! asserting AGE behaviour *through* `kg_query` was vacuous (#2397's warned
//! executed-evidence pattern).
//!
//! ## Why the assertions here go around `kg_query`
//!
//! A test that only calls `kg_query` and checks the rows cannot tell the two
//! engines apart — the CTE fallback returns the same shape. So the live tests
//! below deliberately drive the two engines into DISAGREEMENT using **direct
//! Cypher** (raw `cypher()` statements against `memory_graph`) and then assert
//! `kg_query` reports the AGE-side truth:
//!
//! * `r203_kg_query_reflects_an_age_only_edge_the_cte_cannot_see` — an edge
//!   that exists ONLY in the AGE projection (no `memory_links` row). The CTE
//!   returns nothing; AGE returns the edge.
//! * `r203_kg_query_reflects_an_age_side_deletion_the_cte_still_shows` — the
//!   mirror case: the `memory_links` row survives, the AGE edge is deleted.
//!   The CTE returns the edge; AGE returns nothing.
//!
//! Both FAIL at the parent commit (the CTE answer wins because AGE never ran)
//! and pass with the typed-Param bind. `r203_age_rejects_the_inlined_agtype_
//! literal_third_arg` pins the substrate premise itself.
//!
//! ## Gating
//!
//! `#![cfg(feature = "sal-postgres")]` + `#[ignore]` on the live tests, run by
//! the `postgres-age` job in `.github/workflows/postgres-parity-nightly.yml`
//! (`-- --include-ignored`, the #1799 lane convention) against the certified
//! PG 18.4 + AGE 1.7.0 + pgvector 0.8.5 stack. They also skip cleanly with a
//! printed reason when `AI_MEMORY_TEST_AGE_URL` / `AI_MEMORY_TEST_POSTGRES_URL`
//! is unset or the connected database has no AGE extension.
//!
//! The source-inspection pin (`no_inlined_agtype_literal_third_arg_…`) is NOT
//! ignored and needs no database: it runs on every `cargo test
//! --features sal-postgres`, so the rejected statement shape cannot come back
//! on a host that never sees AGE. Necessary-but-not-sufficient (a mechanical
//! token scan cannot prove execution), strictly additive to the live tests —
//! the same honest-scope posture as `tests/qual_pg_write_funnel_parity_2393_2397.rs`.

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, KgBackend, MemoryStore};

// ---------------------------------------------------------------------------
// Part A — DB-free mechanical pin on the statement shape.
// ---------------------------------------------------------------------------

/// The postgres SAL adapter, relative to `CARGO_MANIFEST_DIR`.
const PG_ADAPTER_PATH: &str = "src/store/postgres.rs";

/// Read the adapter with COMMENT lines dropped (the #2511 postmortem prose
/// names the rejected shapes verbatim, and a token scan must not trip over
/// documentation), Rust string-continuations (`\` + newline + indent) folded
/// away, and every whitespace run collapsed to a single space — so a SQL
/// statement split across source lines is scannable as one string.
fn adapter_source_flattened() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(PG_ADAPTER_PATH);
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {} : {e}", path.display()));
    let code_only: String = raw
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with('*'))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let folded = code_only.replace("\\\n", "");
    folded.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn no_inlined_agtype_literal_third_arg_in_the_postgres_adapter() {
    let src = adapter_source_flattened();

    // 1. The deleted helper must stay deleted. It rendered the rejected
    //    `'{…}'::agtype` shape AND SQL-quote-doubled apostrophes, which on the
    //    binary bind path would corrupt the payload outright.
    assert!(
        !src.contains("fn age_params_literal"),
        "#2511: `age_params_literal` renders the `'{{…}}'::agtype` third-arg \
         shape that AGE's analyzer REJECTS (verified on AGE 1.6.0 + 1.7.0). It \
         was deleted so the shape cannot be reintroduced — bind the dict \
         through `age_params_jsonb` + the `Agtype` sqlx wrapper instead."
    );

    // 2. No cypher() call site may cast its third argument. `$1::agtype` over
    //    a text-declared bind is rejected exactly like the literal: the cast
    //    wraps the Param so it is no longer bare.
    assert!(
        !src.contains("$1::agtype"),
        "#2511: `$1::agtype` is rejected by AGE's analyzer whenever the bind's \
         DECLARED type is not already agtype (sqlx's default `String` encoder \
         declares `text`). Bind `Agtype(..)` and write a bare `$1`."
    );

    // 3. Structural scan: every real `cypher('memory_graph', $$ … $$` statement
    //    must be followed by either `)` (the 2-arg form) or `, $1)`.
    let needle = "cypher('memory_graph', $$";
    let mut sites = 0usize;
    let mut cursor = 0usize;
    while let Some(rel) = src[cursor..].find(needle) {
        let open = cursor + rel;
        let body_start = open + needle.len();
        let close = body_start
            + src[body_start..]
                .find("$$")
                .unwrap_or_else(|| panic!("unterminated dollar-quoted cypher body at {open}"));
        let tail = &src[close + 2..];
        assert!(
            tail.starts_with(')') || tail.starts_with(", $1)"),
            "#2511: the third argument to cypher() must be a bare `$1` bound \
             through the `Agtype` wrapper (or absent, for the 2-arg form). \
             Offending tail: {:?}",
            &tail[..tail.len().min(80)]
        );
        sites += 1;
        cursor = close + 2;
    }

    // Guard the scanner itself: if a refactor renames the graph or reshapes the
    // statements, this test must fail loudly rather than pass over zero sites.
    assert!(
        sites >= 8,
        "#2511: expected to scan at least the 8 known cypher('memory_graph') \
         statements (4 reads + 4 projection writes); found {sites}. The scanner \
         has gone blind — fix it before trusting this pin."
    );
}

// ---------------------------------------------------------------------------
// Part B — live AGE tests. Direct Cypher, never `kg_query`, for the ground
// truth.
// ---------------------------------------------------------------------------

/// sqlx bind wrapper for AGE's `agtype`. Mirrors the production-side
/// `Agtype` in `src/store/postgres.rs` (kept private there because it is an
/// adapter-internal encoding detail), so this suite can issue direct Cypher
/// with the same typed-Param shape the fix relies on.
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
        // agtype_recv: version byte (1) then the JSON text payload.
        buf.push(1);
        buf.extend_from_slice(self.0.as_bytes());
        Ok(sqlx::encode::IsNull::No)
    }
}

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_AGE_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok())
}

/// Connect + require a live AGE backend; `None` (with a printed reason) when
/// the env is unset or the database resolved to the CTE backend.
async fn age_store_or_skip(test: &str) -> Option<(PostgresStore, sqlx::PgPool)> {
    let Some(url) = pg_url() else {
        eprintln!("skipping {test}: AI_MEMORY_TEST_AGE_URL / AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres adapter");
    if store.kg_backend() != KgBackend::Age {
        eprintln!("skipping {test}: postgres backend is not AGE (no graph to probe)");
        return None;
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("direct-cypher pool");
    Some((store, pool))
}

/// Open a transaction with `age` loaded and `ag_catalog` on the search path —
/// the session prerequisites every `cypher()` statement needs.
async fn age_tx(pool: &sqlx::PgPool) -> sqlx::Transaction<'_, sqlx::Postgres> {
    let mut tx = pool.begin().await.expect("begin age tx");
    // A non-superuser role may be refused `LOAD`; shared_preload_libraries
    // then provides the library. Tolerate it exactly like the adapter does.
    let _ = sqlx::query("LOAD 'age'").execute(&mut *tx).await;
    sqlx::query("SET LOCAL search_path = ag_catalog, \"$user\", public")
        .execute(&mut *tx)
        .await
        .expect("set search_path");
    tx
}

/// Run one direct-Cypher statement returning a single `agtype` column, with the
/// params dict bound as a typed `$1`. Returns the row count.
async fn direct_cypher(pool: &sqlx::PgPool, body: &str, params: &serde_json::Value) -> usize {
    let mut tx = age_tx(pool).await;
    let sql = format!("SELECT c FROM cypher('memory_graph', $$ {body} $$, $1) AS (c agtype)");
    let rows = sqlx::query(&sql)
        .bind(Agtype(params.to_string()))
        .persistent(false)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("direct cypher failed: {e}\nbody: {body}"));
    tx.commit().await.expect("commit direct cypher tx");
    rows.len()
}

fn mk_memory(namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "r203".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    }
}

/// **R-203 substrate premise.** Pins the exact behaviour the #2511 fix is built
/// on, straight against the live AGE build, so a future AGE upgrade that
/// changes it surfaces here rather than as another silent CTE degradation:
///
/// * an inlined `'{…}'::agtype` third argument is REJECTED;
/// * a bare `$1` bound with a declared `agtype` type is ACCEPTED.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Apache AGE postgres (AI_MEMORY_TEST_AGE_URL); run with --include-ignored"]
async fn r203_age_rejects_the_inlined_agtype_literal_third_arg() {
    let test = "r203_age_rejects_the_inlined_agtype_literal_third_arg";
    let Some((_store, pool)) = age_store_or_skip(test).await else {
        return;
    };

    // The pre-#2511 production shape.
    let mut tx = age_tx(&pool).await;
    let literal_sql = "SELECT c FROM cypher('memory_graph', \
         $$ MATCH (a) WHERE a.id = $start_id RETURN a.id $$, \
         '{\"start_id\":\"r203-nonexistent\"}'::agtype) AS (c agtype)";
    let literal_err = sqlx::query(literal_sql)
        .persistent(false)
        .fetch_all(&mut *tx)
        .await
        .expect_err(
            "#2511 premise broken: AGE ACCEPTED the inlined '{…}'::agtype third \
             argument. Re-examine the fix — the analyzer contract changed.",
        )
        .to_string();
    drop(tx);
    assert!(
        literal_err.contains("third argument of cypher function must be a parameter"),
        "expected AGE's analyzer rejection of the inlined literal, got: {literal_err}"
    );

    // The post-#2511 production shape: bare `$1`, declared type `agtype`.
    let hits = direct_cypher(
        &pool,
        "MATCH (a) WHERE a.id = $start_id RETURN a.id",
        &serde_json::json!({ "start_id": "r203-nonexistent" }),
    )
    .await;
    assert_eq!(
        hits, 0,
        "the typed-Param form must EXECUTE cleanly (0 rows for a missing id)"
    );
}

/// **R-203 primary regression.** An edge that exists ONLY in the AGE projection
/// — no `memory_links` row at all — must show up in `kg_query`. The relational
/// CTE physically cannot see it, so a non-empty result is proof that AGE served
/// the traversal.
///
/// Pre-fix: AGE's analyzer rejects the statement, `warn_age_fallback` fires, the
/// CTE runs and returns ZERO rows → this test FAILS.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Apache AGE postgres (AI_MEMORY_TEST_AGE_URL); run with --include-ignored"]
async fn r203_kg_query_reflects_an_age_only_edge_the_cte_cannot_see() {
    let test = "r203_kg_query_reflects_an_age_only_edge_the_cte_cannot_see";
    let Some((store, pool)) = age_store_or_skip(test).await else {
        return;
    };

    let ctx = CallerContext::for_agent("t-2511".to_string());
    let ns = format!("t2511-{}", uuid::Uuid::new_v4());
    let a_id = store
        .store(&ctx, &mk_memory(&ns, "age-only-src"))
        .await
        .expect("store a");
    let b_id = store
        .store(&ctx, &mk_memory(&ns, "age-only-dst"))
        .await
        .expect("store b");

    // Project the two nodes + a `related_to` edge with DIRECT Cypher only.
    // `store.link()` is deliberately NOT called, so `memory_links` stays empty
    // for this pair and the CTE branch has nothing to return.
    for id in [&a_id, &b_id] {
        direct_cypher(
            &pool,
            "MERGE (n:Memory {id: $id}) RETURN n",
            &serde_json::json!({ "id": id }),
        )
        .await;
    }
    let merged = direct_cypher(
        &pool,
        "MATCH (a:Memory {id: $src}), (b:Memory {id: $dst}) \
         MERGE (a)-[r:related_to {relation: 'related_to'}]->(b) RETURN r",
        &serde_json::json!({ "src": &a_id, "dst": &b_id }),
    )
    .await;
    assert_eq!(
        merged, 1,
        "direct-Cypher MERGE must create exactly one edge"
    );

    // Ground truth via direct Cypher: the edge IS in the graph...
    let in_graph = direct_cypher(
        &pool,
        "MATCH (a:Memory {id: $src})-[r:related_to]->(b:Memory {id: $dst}) RETURN r",
        &serde_json::json!({ "src": &a_id, "dst": &b_id }),
    )
    .await;
    assert_eq!(in_graph, 1, "AGE-side ground truth: one edge a->b");

    // ...and NOT in the relational mirror.
    let (relational,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM memory_links WHERE source_id = $1 AND target_id = $2")
            .bind(&a_id)
            .bind(&b_id)
            .fetch_one(&pool)
            .await
            .expect("count memory_links");
    assert_eq!(
        relational, 0,
        "fixture invariant: this pair must have NO memory_links row, so a \
         CTE-served kg_query can only return nothing"
    );

    let rows = store.kg_query(&a_id, 1).await.expect("kg_query depth 1");
    assert!(
        rows.iter().any(|r| r.target_id == b_id),
        "#2511: kg_query must be served by AGE and return the AGE-only edge \
         {a_id} -> {b_id}. An EMPTY result means the relational CTE answered \
         while Capabilities.kg_backend reported `age`. Got: {rows:?}"
    );
}

/// **R-203 mirror regression.** The inverse divergence: the `memory_links` row
/// survives while the AGE edge is deleted with direct Cypher. AGE must report
/// no edge; the CTE would still report one.
///
/// Pre-fix: the CTE answers and returns the stale edge → this test FAILS.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Apache AGE postgres (AI_MEMORY_TEST_AGE_URL); run with --include-ignored"]
async fn r203_kg_query_reflects_an_age_side_deletion_the_cte_still_shows() {
    let test = "r203_kg_query_reflects_an_age_side_deletion_the_cte_still_shows";
    let Some((store, pool)) = age_store_or_skip(test).await else {
        return;
    };

    let ctx = CallerContext::for_agent("t-2511".to_string());
    let ns = format!("t2511-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let a_id = store
        .store(&ctx, &mk_memory(&ns, "divergence-src"))
        .await
        .expect("store a");
    let b_id = store
        .store(&ctx, &mk_memory(&ns, "divergence-dst"))
        .await
        .expect("store b");

    // Dual-write: `memory_links` row + AGE projection (sync mode default).
    store
        .link(
            &ctx,
            &MemoryLink {
                source_id: a_id.clone(),
                target_id: b_id.clone(),
                relation: MemoryLinkRelation::RelatedTo,
                created_at: now,
                valid_from: None,
                valid_until: None,
                observed_by: None,
                signature: None,
                attest_level: None,
                source_cid: None,
                target_cid: None,
            },
        )
        .await
        .expect("link a->b");

    // Delete the AGE edge ONLY, via direct Cypher. The relational row stays.
    direct_cypher(
        &pool,
        "MATCH (a:Memory {id: $src})-[r]->(b:Memory {id: $dst}) DELETE r RETURN r",
        &serde_json::json!({ "src": &a_id, "dst": &b_id }),
    )
    .await;

    // Ground truth via direct Cypher: the graph no longer has the edge.
    let in_graph = direct_cypher(
        &pool,
        "MATCH (a:Memory {id: $src})-[r]->(b:Memory {id: $dst}) RETURN r",
        &serde_json::json!({ "src": &a_id, "dst": &b_id }),
    )
    .await;
    assert_eq!(in_graph, 0, "AGE-side ground truth: edge deleted");

    // ...while the relational mirror still carries it.
    let (relational,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM memory_links WHERE source_id = $1 AND target_id = $2")
            .bind(&a_id)
            .bind(&b_id)
            .fetch_one(&pool)
            .await
            .expect("count memory_links");
    assert_eq!(
        relational, 1,
        "fixture invariant: the memory_links row must survive, so a CTE-served \
         kg_query returns the stale edge"
    );

    let rows = store.kg_query(&a_id, 1).await.expect("kg_query depth 1");
    assert!(
        !rows.iter().any(|r| r.target_id == b_id),
        "#2511: kg_query must be served by AGE, which no longer has this edge. \
         Seeing {a_id} -> {b_id} means the relational CTE answered while \
         Capabilities.kg_backend reported `age`. Got: {rows:?}"
    );
}
