// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1482 regression — the three AGE Cypher dispatch sites
//! (`kg_query_cypher`, `kg_timeline_cypher`, `find_paths_cypher`) build
//! per-call-unique SQL text (inlined ids + depth + window/cap) and must
//! run via the postgres *unnamed* statement (`.persistent(false)`), NOT
//! the default persistent/named prepared statement.
//!
//! Spun out of #1472's EXPLAIN hot-path audit. sqlx 0.8.6 defaults
//! `Query::persistent = true` and bounds the per-connection prepared
//! statement cache at `statement_cache_capacity = 100`. Because each
//! cypher call's SQL text is unique, persisting it allocates a named
//! server-side prepared statement that is never reused and evicts a
//! genuinely-reusable hot statement (store / get / recall) from the
//! bounded LRU. Running the cypher unnamed keeps the hot statements
//! resident and is behaviourally identical (same rows, same params).
//!
//! ## What this proves
//!
//! `pg_prepared_statements` is session-local: only the *named* prepared
//! statements allocated on the current backend session appear; the
//! unnamed statement never does. After driving several distinct ids
//! through all three cypher entry points on a single backend session,
//! that session must hold ZERO prepared statements whose text contains
//! `cypher(`. A positive control (an explicitly-persistent marker
//! statement) proves the probe is actually sensitive — i.e. a regressed
//! persistent cypher WOULD have shown up — so the zero-count assertion
//! can't pass vacuously.
//!
//! ## Session pinning
//!
//! sqlx spreads work across up to `max_connections` distinct backend
//! sessions, but `pg_prepared_statements` is session-local — so the
//! probe must observe the *same* session the cypher ran on. The test
//! pins one session by exhausting the pool (checking out every
//! connection) and releasing exactly one back: with the pool at its
//! connection ceiling, every subsequent serial acquire — the cypher
//! dispatches, the control insert, and the probes — reuses that sole
//! idle session. The positive control is the guard: if the probe ever
//! read a different session than the work, the control marker would be
//! absent and the test fails loudly rather than false-greening.
//!
//! Gated on `feature = "sal-postgres"`, skipped without an AGE-enabled
//! database (`kg_backend() != Age` falls back to the recursive-CTE path,
//! which has no cypher statement to cache).

#![cfg(feature = "sal-postgres")]

use std::time::Duration;

use ai_memory::store::KgBackend;
use ai_memory::store::postgres::PostgresStore;

mod common;
use common::{age_url, postgres_url};

use sqlx::Row;

/// Distinct cypher texts to drive through each entry point. >1 so the
/// test exercises several *different* per-call-unique SQL strings — the
/// exact shape that, persisted, floods the bounded statement cache.
const DISTINCT_DRIVES: usize = 4;

/// Marker embedded in the positive-control statement. Deliberately not a
/// substring of either probe's SQL text, and the probes run unnamed so
/// they never self-list in `pg_prepared_statements`.
const CTRL_MARKER: &str = "persist_probe_ctrl_marker_1482";

#[tokio::test(flavor = "multi_thread")]
async fn age_cypher_dispatch_never_persists_named_statements() {
    // Prefer the AGE-specific URL; fall back to the generic postgres URL
    // and gate on the resolved backend below.
    let Some(url) = age_url().or_else(postgres_url) else {
        eprintln!("skip: neither AI_MEMORY_TEST_AGE_URL nor AI_MEMORY_TEST_POSTGRES_URL set");
        return;
    };
    let store = match PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: connect failed: {e}");
            return;
        }
    };

    // The cypher dispatch only lights up on the AGE backend; the CTE
    // fallback has no `cypher(` statement to (mis)cache.
    if store.kg_backend() != KgBackend::Age {
        eprintln!("skip: kg_backend != Age (no AGE extension on this fixture)");
        return;
    }

    // Pin a single backend session: check out every pooled connection,
    // then release exactly one. With the pool at its connection ceiling
    // the released connection is the sole idle session, so every
    // following serial acquire (cypher dispatch, control, probes) reuses
    // it — the only way the session-local `pg_prepared_statements` probe
    // can observe the cypher path's session.
    let mut held = Vec::new();
    while let Ok(Ok(conn)) =
        tokio::time::timeout(Duration::from_secs(2), store.pool().acquire()).await
    {
        held.push(conn);
    }
    assert!(
        held.len() >= 2,
        "#1482: expected to check out the full pool to pin one session; \
         only got {} connection(s)",
        held.len()
    );
    drop(held.pop());

    // Drive several DISTINCT per-call-unique cypher texts through every
    // AGE entry point. Empty result sets are fine — the named-statement
    // allocation a regression would leave behind happens on successful
    // execution regardless of how many rows come back. `memory_graph`
    // exists at connect (`ensure_memory_graph`), so each cypher succeeds.
    for _ in 0..DISTINCT_DRIVES {
        let source = uuid::Uuid::new_v4().to_string();
        let target = uuid::Uuid::new_v4().to_string();

        store
            .kg_query(&source, 3)
            .await
            .expect("kg_query cypher dispatch");
        store
            .kg_timeline(&source, None, None, Some(16))
            .await
            .expect("kg_timeline cypher dispatch");
        // source != target so `find_paths` doesn't take the trivial
        // same-node early return and actually runs the cypher.
        store
            .find_paths(&source, &target, Some(4), Some(16))
            .await
            .expect("find_paths cypher dispatch");
    }

    // Positive control: an explicitly-persistent marker statement. On the
    // same session the probes read, this MUST land in
    // `pg_prepared_statements` — proving the probe is sensitive to named
    // statements (so a regressed persistent cypher would be caught).
    sqlx::query(&format!("SELECT 1 AS {CTRL_MARKER}"))
        .persistent(true)
        .fetch_all(store.pool())
        .await
        .expect("persist positive-control statement");

    // Probes run UNNAMED so they never self-list in
    // `pg_prepared_statements` (which would let the cypher probe match
    // its own `cypher(` literal and false-fail).
    let ctrl_present: i64 =
        sqlx::query("SELECT count(*) AS n FROM pg_prepared_statements WHERE statement LIKE $1")
            .bind(format!("%{CTRL_MARKER}%"))
            .persistent(false)
            .fetch_one(store.pool())
            .await
            .expect("probe positive control")
            .try_get::<i64, _>("n")
            .expect("count column");
    assert!(
        ctrl_present >= 1,
        "#1482: positive control failed — a persistent statement is not \
         visible on the probed session, so the zero-cypher assertion would \
         be vacuous; got {ctrl_present}"
    );

    let cypher_named: i64 = sqlx::query(
        "SELECT count(*) AS n FROM pg_prepared_statements WHERE statement LIKE '%cypher(%'",
    )
    .persistent(false)
    .fetch_one(store.pool())
    .await
    .expect("probe cypher statements")
    .try_get::<i64, _>("n")
    .expect("count column");
    assert_eq!(
        cypher_named, 0,
        "#1482: AGE cypher dispatch must run via the unnamed statement; \
         found {cypher_named} named prepared statement(s) containing \
         `cypher(` on the session. Pre-fix the per-call-unique cypher text \
         was persisted (persistent=true), flooding the bounded \
         statement-cache LRU and evicting reusable hot statements."
    );
}
