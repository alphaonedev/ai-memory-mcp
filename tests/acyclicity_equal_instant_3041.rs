// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3041 pg-twin + completeness — cross-backend regression for the
//! equal-`created_at` lineage-DAG acyclicity guard.
//!
//! Two linked defects, both proven refused here on BOTH backends:
//!
//!  * DEFECT 1 (pg fail-OPEN twin of the sqlite #3041 fix): the postgres
//!    Pass-0 guard compared endpoints with a bare `target_at > source_at`,
//!    which on an EXACT tie was `false` and ADMITTED the edge with NO
//!    structural check. Pass 1 (the structural cycle gate) runs only for
//!    `reflects_on`, so a `derived_from` / `derives_from` equal-instant
//!    2-cycle could form on postgres that sqlite structurally refuses.
//!    Covered by `*_equal_instant_two_cycle_refused`.
//!
//!  * DEFECT 2 (completeness gap on BOTH backends): the equal-instant
//!    structural check walked the ancestor set only to `LINEAGE_MAX_DEPTH`
//!    (= 5) and read a silently-truncated "no cycle" as admit. An
//!    equal-instant provenance chain longer than 5 hops
//!    (`a1 -> … -> a7`, then `a7 -> a1`) escaped the walk, so the
//!    cycle-closing edge was admitted. The check now runs to the dedicated
//!    `LINEAGE_CYCLE_CHECK_MAX_DEPTH` ceiling and fails CLOSED on
//!    truncation. Covered by `*_equal_instant_deep_clique_cycle_refused`.
//!
//! The postgres cases are gated on `AI_MEMORY_TEST_POSTGRES_URL` and skip
//! cleanly when unset. Run the pg leg with `--test-threads=1` (the lineage
//! flags are process-wide atomics).

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names
)]
// The process-wide lineage-flag atomics must stay pinned for the whole test
// body (including its awaits) or a parallel test could flip them
// mid-assertion; each #[tokio::test] runs on its own runtime thread, so
// holding the std Mutex across awaits merely serializes this file's tests.
#![allow(clippy::await_holding_lock)]

use std::path::Path;
use std::sync::Mutex;

use ai_memory::db;
use ai_memory::models::{Memory, Tier};

/// Serializes the tests: the lineage flags are process-wide atomics.
static FLAG_LOCK: Mutex<()> = Mutex::new(());

fn flag_guard() -> std::sync::MutexGuard<'static, ()> {
    FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lineage_on() {
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
}

fn lineage_off() {
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
    ai_memory::config::set_append_only(false);
}

// ---------------------------------------------------------------------------
// SQLite leg
// ---------------------------------------------------------------------------

fn open_mem_db() -> rusqlite::Connection {
    db::open(Path::new(":memory:")).expect("open in-memory db")
}

/// A memory with an EXPLICIT `created_at` so the equal-instant tie-break is
/// deterministic (independent of wall-clock insert ordering).
fn make_mem(id: &str, title: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        title: title.to_string(),
        content: format!("content-{title}"),
        namespace: "acyclic-3041".to_string(),
        tier: Tier::Mid,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        ..Default::default()
    }
}

fn pair_edge_count_sqlite(conn: &rusqlite::Connection, a: &str, b: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memory_links \
         WHERE relation = 'derived_from' \
           AND ((source_id = ?1 AND target_id = ?2) \
             OR (source_id = ?2 AND target_id = ?1))",
        [a, b],
        |r| r.get(0),
    )
    .expect("count pair edges")
}

// DEFECT 1 (sqlite baseline — the invariant the pg twin must match): an
// equal-instant 2-cycle is refused, and only the first edge persists.
#[test]
fn sqlite_equal_instant_two_cycle_refused() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let same = "2026-07-07T07:07:07+00:00";
    let p = "00000000-0000-0000-0000-0000000009a1";
    let q = "00000000-0000-0000-0000-0000000009a2";
    db::insert(&conn, &make_mem(p, "p", same)).unwrap();
    db::insert(&conn, &make_mem(q, "q", same)).unwrap();

    // First same-instant edge is a legitimate same-batch DAG edge.
    db::create_link(&conn, q, p, "derived_from")
        .expect("first equal-instant lineage edge must be admitted");
    // The reverse edge would close a 2-cycle p -> q -> p; it must be refused.
    let err = db::create_link(&conn, p, q, "derived_from")
        .expect_err("equal-instant reverse edge closes a 2-cycle and must be refused");
    assert!(
        err.to_string().starts_with(db::LINK_CYCLE_ERR_PREFIX),
        "expected {} prefix, got: {err}",
        db::LINK_CYCLE_ERR_PREFIX
    );
    // The durable graph is not corrupted: exactly ONE edge survives.
    assert_eq!(pair_edge_count_sqlite(&conn, p, q), 1);
    lineage_off();
}

// DEFECT 2 (sqlite): a >5-hop equal-instant clique cycle must be refused.
// The old bounded walk truncated at LINEAGE_MAX_DEPTH (= 5) and could not
// reach a7 from a1 (6 hops), so it admitted the closing edge.
#[test]
fn sqlite_equal_instant_deep_clique_cycle_refused() {
    let _g = flag_guard();
    lineage_on();
    let conn = open_mem_db();

    let same = "2026-07-07T08:08:08+00:00";
    // Seven nodes, all sharing the instant.
    let ids: Vec<String> = (1..=7)
        .map(|i| format!("00000000-0000-0000-0000-00000000a70{i}"))
        .collect();
    for (i, id) in ids.iter().enumerate() {
        db::insert(&conn, &make_mem(id, &format!("a{}", i + 1), same)).unwrap();
    }

    // Build the chain a1 -> a2 -> … -> a7 (six forward child -> parent edges);
    // each is a valid same-instant DAG edge (no back-edge yet).
    for w in ids.windows(2) {
        db::create_link(&conn, &w[0], &w[1], "derived_from").unwrap_or_else(|e| {
            panic!(
                "same-instant chain edge {} -> {} must be admitted: {e}",
                w[0], w[1]
            )
        });
    }

    // Closing a7 -> a1 makes a1 -> … -> a7 -> a1 — a 7-node cycle whose
    // detection requires walking 6 hops from a1 to a7 (beyond the old
    // depth-5 cap). It MUST be refused (DEFECT 2 fail-open closed).
    let err = db::create_link(&conn, &ids[6], &ids[0], "derived_from")
        .expect_err(">5-hop equal-instant clique cycle must be refused");
    assert!(
        err.to_string().starts_with(db::LINK_CYCLE_ERR_PREFIX),
        "expected {} prefix, got: {err}",
        db::LINK_CYCLE_ERR_PREFIX
    );
    // Only the six chain edges persist; the closing edge did not land.
    let closing: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memory_links \
             WHERE relation = 'derived_from' AND source_id = ?1 AND target_id = ?2",
            [&ids[6], &ids[0]],
            |r| r.get(0),
        )
        .expect("count closing edge");
    assert_eq!(closing, 0, "the cycle-closing edge must not persist");
    lineage_off();
}

// ---------------------------------------------------------------------------
// Postgres leg — DEFECT 1 fix (equal-instant Pass-0 structural check) and
// DEFECT 2 fix (completeness) proven on a live daemon.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{flag_guard, lineage_off, lineage_on};
    use ai_memory::models::{
        ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
    };
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    fn postgres_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
    }

    async fn connect() -> Option<PostgresStore> {
        let url = postgres_url()?;
        Some(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        )
    }

    async fn raw_pool() -> Option<sqlx::PgPool> {
        let url = postgres_url()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect raw pool"),
        )
    }

    fn mem(id: &str, ns: &str, title: &str, created_at: &str) -> Memory {
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: id.to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("content-{title}"),
            tags: vec!["acyclic-3041".to_string()],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: created_at.to_string(),
            updated_at: created_at.to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({ "agent_id": "ai:lineage-test" }),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: LifecycleState::Open,
        }
    }

    fn link(src: &str, tgt: &str, created_at: &str) -> MemoryLink {
        MemoryLink {
            source_id: src.to_string(),
            target_id: tgt.to_string(),
            relation: MemoryLinkRelation::DerivedFrom,
            created_at: created_at.to_string(),
            signature: None,
            observed_by: None,
            valid_from: Some(created_at.to_string()),
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        }
    }

    async fn pair_edge_count(pool: &sqlx::PgPool, a: &str, b: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM memory_links \
             WHERE relation = 'derived_from' \
               AND ((source_id = $1 AND target_id = $2) \
                 OR (source_id = $2 AND target_id = $1))",
        )
        .bind(a)
        .bind(b)
        .fetch_one(pool)
        .await
        .expect("count pair edges")
    }

    // DEFECT 1 — the pg fail-open twin. On a live daemon the equal-instant
    // reverse edge must now be REFUSED with the byte-identical cycle envelope
    // (before the fix postgres admitted it while sqlite refused it).
    #[tokio::test]
    async fn pg_equal_instant_two_cycle_refused() {
        let Some(store) = connect().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let Some(pool) = raw_pool().await else { return };
        let _g = flag_guard();
        lineage_on();

        let ns = format!("acyclic-3041-{}", uuid::Uuid::new_v4());
        let ctx = CallerContext::for_agent("ai:lineage-test");
        let same = "2026-07-07T09:09:09+00:00";
        let p = uuid::Uuid::new_v4().to_string();
        let q = uuid::Uuid::new_v4().to_string();
        store.store(&ctx, &mem(&p, &ns, "p", same)).await.unwrap();
        store.store(&ctx, &mem(&q, &ns, "q", same)).await.unwrap();

        // First same-instant edge is a legitimate same-batch DAG edge.
        store
            .link(&ctx, &link(&q, &p, same))
            .await
            .expect("first equal-instant lineage edge must be admitted");
        // The reverse edge closes a 2-cycle p -> q -> p; it must be refused.
        let err = store
            .link(&ctx, &link(&p, &q, same))
            .await
            .expect_err("equal-instant reverse edge closes a 2-cycle and must be refused");
        assert!(
            err.to_string().starts_with(db_link_cycle_prefix()),
            "expected {} prefix, got: {err}",
            db_link_cycle_prefix()
        );
        // The durable graph is not corrupted: exactly ONE edge survives.
        assert_eq!(pair_edge_count(&pool, &p, &q).await, 1);
        lineage_off();
    }

    // DEFECT 2 — completeness on pg. A >5-hop equal-instant clique cycle must
    // be refused; the closing edge requires a 6-hop structural walk (beyond
    // the old depth-5 cap that would have silently admitted it).
    #[tokio::test]
    async fn pg_equal_instant_deep_clique_cycle_refused() {
        let Some(store) = connect().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let Some(pool) = raw_pool().await else { return };
        let _g = flag_guard();
        lineage_on();

        let ns = format!("acyclic-3041-{}", uuid::Uuid::new_v4());
        let ctx = CallerContext::for_agent("ai:lineage-test");
        let same = "2026-07-07T10:10:10+00:00";
        let ids: Vec<String> = (0..7).map(|_| uuid::Uuid::new_v4().to_string()).collect();
        for (i, id) in ids.iter().enumerate() {
            store
                .store(&ctx, &mem(id, &ns, &format!("a{}", i + 1), same))
                .await
                .unwrap();
        }

        // Chain a1 -> a2 -> … -> a7 (six forward edges), all admitted.
        for w in ids.windows(2) {
            store
                .link(&ctx, &link(&w[0], &w[1], same))
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "same-instant chain edge {} -> {} must be admitted: {e}",
                        w[0], w[1]
                    )
                });
        }

        // Closing a7 -> a1 forms a 7-node cycle; detection walks 6 hops from
        // a1 to a7 (beyond the old depth-5 cap). It MUST be refused.
        let err = store
            .link(&ctx, &link(&ids[6], &ids[0], same))
            .await
            .expect_err(">5-hop equal-instant clique cycle must be refused on postgres");
        assert!(
            err.to_string().starts_with(db_link_cycle_prefix()),
            "expected {} prefix, got: {err}",
            db_link_cycle_prefix()
        );
        // The cycle-closing edge did not land.
        let closing: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM memory_links \
             WHERE relation = 'derived_from' AND source_id = $1 AND target_id = $2",
        )
        .bind(&ids[6])
        .bind(&ids[0])
        .fetch_one(&pool)
        .await
        .expect("count closing edge");
        assert_eq!(closing, 0, "the cycle-closing edge must not persist");
        lineage_off();
    }

    fn db_link_cycle_prefix() -> &'static str {
        ai_memory::db::LINK_CYCLE_ERR_PREFIX
    }
}
