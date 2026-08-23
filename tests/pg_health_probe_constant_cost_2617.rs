// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2617](https://github.com/alphaonedev/ai-memory-mcp/issues/2617) —
//! `PostgresStore::health_check` must be O(1) in corpus size, per the
//! `MemoryStore::health_check` trait MUST ("Implementations MUST now keep this
//! method O(1) in corpus size and MUST NOT take a write lock").
//!
//! The pg twin of [#2579](https://github.com/alphaonedev/ai-memory-mcp/issues/2579)
//! (which closed the same class on sqlite, on the same endpoint). The probe
//! used to run `SELECT COUNT(*)::BIGINT FROM memories` and DISCARD the result
//! (`let _`), described in-comment as "a cheap SELECT against the memories
//! table". Postgres plans that as an Index Only Scan over EVERY row, so
//! `/health` — scraped on a fixed orchestrator interval and exempt from
//! admission control — grew linearly with the corpus until it crossed the
//! Kubernetes default `timeoutSeconds: 1` and started killing HEALTHY pods.
//!
//! **R-203 fail-at-parent.** Cell A references NO symbol introduced by the fix
//! (it reads the adapter's own source text), so the file compiles unchanged at
//! the parent commit and FAILS there. Cell B is the live-postgres plan proof
//! and is skipped without `AI_MEMORY_TEST_POSTGRES_URL`; Cell C is its
//! anti-vacuity CONTROL — it EXPLAINs the OLD statement on the same corpus and
//! asserts the old shape really was O(corpus), so cell B cannot pass because
//! the corpus happened to be empty.

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

/// The statement the probe must no longer issue: a full count over the content
/// table.
const CONTENT_TABLE_COUNT: &str = "COUNT(*)";

/// The relation the probe still has to touch — a probe that stopped reading
/// `memories` altogether would be "O(1)" for the wrong reason.
const CONTENT_TABLE: &str = "memories";

/// Source span of the adapter method under test.
fn health_check_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store/postgres.rs");
    let src = std::fs::read_to_string(&path).expect("read src/store/postgres.rs");
    let start = src
        .find("    async fn health_check(&self) -> StoreResult<bool> {")
        .expect("PostgresStore::health_check must exist");
    // The method body ends at the first line that closes it at method indent.
    let rest = &src[start..];
    let end = rest
        .find("\n    }\n")
        .expect("health_check body must terminate")
        + "\n    }\n".len();
    rest[..end].to_string()
}

// ---------------------------------------------------------------------------
// CELL A (fail-at-parent) — the probe issues no corpus-wide aggregate.
// ---------------------------------------------------------------------------

#[test]
fn a_pg_health_check_issues_no_corpus_count_2617() {
    let body = health_check_source();
    assert!(
        !body.contains(CONTENT_TABLE_COUNT),
        "the postgres liveness probe counts the whole content table — O(corpus) work on \
         an endpoint orchestrators scrape on a fixed interval:\n{body}"
    );
    // Anti-vacuity: the probe must still TOUCH the relation, so a dropped or
    // unreadable `memories` table still fails the probe. "O(1)" achieved by
    // no longer looking at the store would be a different defect.
    assert!(
        body.contains(CONTENT_TABLE),
        "the probe must still touch the memories relation:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// Live postgres cells.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod pg {
    use sqlx::Row;
    use sqlx::postgres::PgPoolOptions;

    /// The statement the fixed probe issues (mirrors
    /// `src/store/postgres.rs::health_check`).
    const PROBE_SQL: &str = "SELECT EXISTS (SELECT 1 FROM memories LIMIT 1)";

    /// The statement the PRE-#2617 probe issued.
    const LEGACY_SQL: &str = "SELECT COUNT(*)::BIGINT FROM memories";

    /// A probe that reads at most this many rows is constant in corpus size.
    const CONSTANT_COST_ROW_CEILING: u64 = 1;

    /// Below this corpus size the plan comparison proves nothing, so the cell
    /// says so instead of passing vacuously.
    const MIN_MEANINGFUL_CORPUS: i64 = 2;

    async fn probe_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PgPoolOptions::new().max_connections(1).connect(&url).await {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("skip: connect failed: {e}");
                None
            }
        }
    }

    /// `EXPLAIN (ANALYZE, FORMAT TEXT)` `sql`, returning the plan text.
    async fn explain_analyze(pool: &sqlx::PgPool, sql: &str) -> String {
        let rows = sqlx::raw_sql(&format!("EXPLAIN (ANALYZE, FORMAT TEXT) {sql}"))
            .fetch_all(pool)
            .await
            .expect("EXPLAIN ANALYZE");
        rows.iter()
            .map(|r| r.try_get::<String, _>(0).expect("plan line"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Largest `rows=N` reported by any ACTUAL (executed) plan node — i.e. how
    /// many rows the statement really touched.
    ///
    /// `PostgreSQL` **18** renders actual row counts with two decimal places
    /// (`rows=1317.00`); 17 and earlier render a bare integer (`rows=1317`).
    /// The integral part is taken TEXTUALLY so both render forms parse on the
    /// same path with no float arithmetic and no lossy cast (PERF-07/09). A
    /// token that parses as neither would silently vanish from the `max()` and
    /// report `0` rows touched — which would make cell B pass VACUOUSLY on a
    /// large corpus — so an unparsable token is a hard failure instead.
    fn max_actual_rows(plan: &str) -> u64 {
        let mut max = 0u64;
        for seg in plan.split("(actual ").skip(1) {
            let Some(after) = seg.split("rows=").nth(1) else {
                continue;
            };
            let Some(token) = after.split_whitespace().next() else {
                continue;
            };
            // `1317` (pg <= 17) and `1317.00` (pg 18) both yield `1317`.
            let integral = token.split('.').next().unwrap_or(token);
            let n: u64 = integral.parse().unwrap_or_else(|e| {
                panic!(
                    "could not read an actual row count from EXPLAIN token {token:?} ({e}) — \
                     the plan-parsing helper is out of date with this postgres version and \
                     would report 0 rows touched, passing this cell vacuously:\n{plan}"
                )
            });
            max = max.max(n);
        }
        max
    }

    async fn corpus_size(pool: &sqlx::PgPool) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM memories")
            .fetch_one(pool)
            .await
            .expect("corpus size")
    }

    /// CELL B — the fixed probe touches at most one row, whatever the corpus.
    #[tokio::test]
    async fn b_pg_health_probe_touches_at_most_one_row_2617() {
        let Some(pool) = probe_pool().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let corpus = corpus_size(&pool).await;
        assert!(
            corpus >= MIN_MEANINGFUL_CORPUS,
            "corpus is {corpus} row(s) — too small for an O(1)-vs-O(corpus) comparison to \
             mean anything; point AI_MEMORY_TEST_POSTGRES_URL at a populated database"
        );

        let plan = explain_analyze(&pool, PROBE_SQL).await;
        let touched = max_actual_rows(&plan);
        assert!(
            touched <= CONSTANT_COST_ROW_CEILING,
            "the liveness probe touched {touched} row(s) on a {corpus}-row corpus — that is \
             O(corpus), not O(1):\n{plan}"
        );
        assert!(
            !plan.contains("Aggregate"),
            "the probe must not aggregate over the corpus:\n{plan}"
        );

        // The probe still answers, and still answers TRUE about a live store.
        let alive: bool = sqlx::query_scalar(PROBE_SQL)
            .fetch_one(&pool)
            .await
            .expect("probe executes");
        assert!(alive, "a populated corpus must satisfy the EXISTS probe");
    }

    /// CELL C (CONTROL) — the statement cell B replaced really was O(corpus)
    /// on this same database, so cell B is not passing because the plan is
    /// cheap for everyone.
    #[tokio::test]
    async fn c_control_legacy_count_scanned_the_whole_corpus_2617() {
        let Some(pool) = probe_pool().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let corpus = corpus_size(&pool).await;
        assert!(
            corpus >= MIN_MEANINGFUL_CORPUS,
            "corpus is {corpus} row(s) — the control cannot demonstrate O(corpus) cost"
        );
        let plan = explain_analyze(&pool, LEGACY_SQL).await;
        let touched = max_actual_rows(&plan);
        assert!(
            touched >= u64::try_from(corpus).unwrap_or(u64::MAX),
            "control: the pre-#2617 COUNT(*) probe was expected to read all {corpus} rows, \
             read {touched}:\n{plan}"
        );
    }
}
