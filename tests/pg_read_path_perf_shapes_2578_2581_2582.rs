// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 — live-postgres behavioural pins for the read-path performance
//! fixes #2578 (v88 composite list indexes), #2581 (batched recall ledger)
//! and #2582 (`find_paths` routes through the relational CTE).
//!
//! # Why these assert SHAPE, not wall-clock
//!
//! A latency threshold in CI is a flake generator and proves nothing about
//! the mechanism. Each pin below asserts the STRUCTURAL property that makes
//! the fix work and that a regression would necessarily break:
//!
//!   * #2578 — the index EXISTS and is `indisvalid`, and the planner actually
//!     CHOOSES it with no sort node (read out of `EXPLAIN`, not timed).
//!   * #2581 — the ledger append is ONE statement whose row semantics are
//!     byte-identical to the per-row loop it replaced, including the
//!     intra-batch duplicate case that `ON CONFLICT DO UPDATE` would break.
//!   * #2582 — `find_paths` returns correct paths on an AGE-backed store
//!     WITHOUT the Cypher body that AGE 1.7.0 rejects.
//!
//! These are immune to host load, which matters: the box these were developed
//! on ran six concurrent audit lanes at load ~20 on 14 cores, and absolute
//! timings there are worthless.
//!
//! # Gating
//!
//! Requires `--features sal-postgres` and `AI_MEMORY_TEST_POSTGRES_URL`.
//! Without the env the tests print a skip and return cleanly, matching
//! `tests/postgres_ladder_replay.rs`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown)]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use sqlx::Row;

mod common;
use common::postgres_url;

/// Connect, or print a skip and return `None` when no live server is named.
async fn store_or_skip(label: &str) -> Option<PostgresStore> {
    let Some(url) = postgres_url() else {
        eprintln!("skip {label}: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip {label}: connect failed: {e}");
            None
        }
    }
}

/// Build a fully-populated `Memory` for seeding. Spelled out field-by-field
/// (there is no `Default`) so a new `Memory` field forces this file to be
/// revisited rather than silently defaulting.
fn seed_memory(
    ns: &str,
    title: String,
    content: String,
    priority: i32,
) -> ai_memory::models::Memory {
    let now = chrono::Utc::now().to_rfc3339();
    ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: ns.to_string(),
        title,
        content,
        tags: vec![],
        priority,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "perf-probe", "scope": "collective"}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
        cid: None,
        valid_from: None,
        valid_until: None,
    }
}

/// Build a `related_to` edge between two seeded ids.
fn seed_link(source_id: String, target_id: String) -> ai_memory::models::MemoryLink {
    ai_memory::models::MemoryLink {
        source_id,
        target_id,
        relation: ai_memory::models::MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// #2578 — the v88 composite list index
// ─────────────────────────────────────────────────────────────────────────────

/// The index exists AND is valid after `connect()`.
///
/// `indisvalid` (not mere existence) is the assertion that matters: a
/// `CREATE INDEX CONCURRENTLY` that fails midway leaves an INVALID index that
/// the planner ignores for reads while postgres still maintains it on every
/// write — pure cost, permanently. `CREATE INDEX CONCURRENTLY IF NOT EXISTS`
/// silently no-ops over exactly that leftover, which is why
/// `ensure_list_order_indexes` probes validity and drops before rebuilding.
///
/// R-203: at the parent commit v88 does not exist and neither index is
/// created, so this fails there.
#[tokio::test]
async fn v88_composite_list_indexes_exist_and_are_valid_2578() {
    let Some(store) = store_or_skip("v88_composite_list_indexes").await else {
        return;
    };
    let pool = store.pool();

    for name in ["idx_memories_ns_list_order", "idx_archived_ns_archived_at"] {
        let row: Option<(bool,)> = sqlx::query_as(
            "SELECT i.indisvalid FROM pg_class c \
               JOIN pg_index i ON i.indexrelid = c.oid \
              WHERE c.relname = $1 AND c.relkind = 'i'",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
        .expect("probe index validity");

        match row {
            None => panic!(
                "#2578: `{name}` is ABSENT after connect(). The v88 arm and the \
                 per-connect self-heal both failed to create it, so a \
                 namespace-scoped list is still O(namespace size)."
            ),
            Some((false,)) => panic!(
                "#2578: `{name}` exists but is INVALID — a CONCURRENTLY build did \
                 not finish and the self-heal did not drop+rebuild it. The \
                 planner ignores it for reads while postgres still maintains it \
                 on every write."
            ),
            Some((true,)) => {}
        }
    }
}

/// The UNSCOPED sibling `idx_memories_list_order` must NOT be created.
///
/// It was in the first draft and an adversarial re-measurement removed it: in
/// a namespace whose rows are expired-but-not-yet-GC'd, its presence makes the
/// planner abandon the namespace-scoped composite and walk the unscoped index
/// ACROSS EVERY NAMESPACE — buffers 1,989 -> 3,041 with 9,621 rows filtered
/// table-wide, versus 1,854 with 6,882 filtered in-namespace when only the
/// scoped index exists. This pin keeps a future "sqlite parity" tidy-up from
/// silently reintroducing that regression.
#[tokio::test]
async fn v88_does_not_create_the_unscoped_list_index_2578() {
    let Some(store) = store_or_skip("v88_no_unscoped_index").await else {
        return;
    };
    let present: Option<(String,)> =
        sqlx::query_as("SELECT relname FROM pg_class WHERE relname = $1 AND relkind = 'i'")
            .bind("idx_memories_list_order")
            .fetch_optional(store.pool())
            .await
            .expect("probe unscoped index");
    assert!(
        present.is_none(),
        "#2578: `idx_memories_list_order` (the UNSCOPED composite) was created. \
         It is deliberately withheld — measured on an isolated copy of the live \
         corpus with most of a namespace expired, its presence REGRESSES the \
         namespace-scoped list from 1,854 buffers (6,882 rows filtered inside \
         the namespace) to 3,041 buffers (9,621 rows filtered across ALL \
         namespaces), because the planner prefers it and then walks the whole \
         table. Its only benefit is the rarer unscoped list. If you want it \
         back, bring measurements."
    );
}

/// The planner actually CHOOSES the composite, and the sort node is gone.
///
/// Index existence alone proves nothing — the whole defect was that postgres
/// had a namespace index and still sorted the namespace. This reads the plan
/// rather than the clock.
#[tokio::test]
async fn v88_namespace_scoped_list_plan_has_no_sort_node_2578() {
    let Some(store) = store_or_skip("v88_plan_shape").await else {
        return;
    };
    let pool = store.pool();
    let ctx = CallerContext::for_agent("perf-2578-probe");
    let ns = format!("perf2578-plan-{}", uuid::Uuid::new_v4());

    // A namespace large enough that a sort would be visibly wrong to choose.
    for i in 0..200 {
        let m = seed_memory(
            &ns,
            format!("perf2578 title {i} {ns}"),
            format!("perf2578 body {i}"),
            (i % 10) + 1,
        );
        store.store(&ctx, &m).await.expect("seed row");
    }
    sqlx::query("ANALYZE memories")
        .execute(pool)
        .await
        .expect("analyze");

    let plan_lines: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (FORMAT TEXT) SELECT id FROM memories \
          WHERE namespace = $1 \
            AND (expires_at IS NULL OR expires_at > NOW()) \
          ORDER BY priority DESC, updated_at DESC LIMIT 10",
    )
    .bind(&ns)
    .fetch_all(pool)
    .await
    .expect("explain");
    let plan = plan_lines.join("\n");

    assert!(
        plan.contains("idx_memories_ns_list_order"),
        "#2578: the planner did NOT choose `idx_memories_ns_list_order` for a \
         namespace-scoped ordered LIMIT. Plan was:\n{plan}"
    );
    assert!(
        !plan.contains("Sort") && !plan.contains("Incremental Sort"),
        "#2578: the plan still contains a sort node, so the ordered walk is not \
         being used and the read is still O(namespace size). Plan was:\n{plan}"
    );

    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(pool)
        .await
        .expect("cleanup");
}

// ─────────────────────────────────────────────────────────────────────────────
// #2581 — the batched recall-observation ledger
// ─────────────────────────────────────────────────────────────────────────────

/// The batched append preserves the per-row loop's semantics EXACTLY,
/// including the intra-batch duplicate.
///
/// This is the pin that makes the batching safe. `ON CONFLICT DO NOTHING`
/// treats a repeated speculative insertion inside ONE command as a conflict,
/// so the first entry wins and the second is a silent no-op — byte-identical
/// to the loop. `ON CONFLICT DO UPDATE` would instead raise `21000: ON
/// CONFLICT DO UPDATE command cannot affect row a second time` and turn a
/// duplicate candidate into a hard failure on an APPEND-ONLY AUDIT surface.
/// If someone "upgrades" the conflict clause, this test is what stops them.
#[tokio::test]
async fn ledger_batch_preserves_first_wins_on_intra_batch_duplicate_2581() {
    let Some(store) = store_or_skip("ledger_batch_duplicate").await else {
        return;
    };
    let pool = store.pool();
    let recall_id = format!("perf2581-{}", uuid::Uuid::new_v4());

    // Candidate #1 and #3 are DISTINCT ids; #2 repeats #1's id with different
    // rank/score/retriever so first-wins is observable in the stored row.
    let candidates = vec![
        ("mem-alpha".to_string(), "fts".to_string(), 1_i64, 1.5_f64),
        ("mem-alpha".to_string(), "hnsw".to_string(), 2_i64, 9.9_f64),
        ("mem-beta".to_string(), "fts".to_string(), 3_i64, 3.5_f64),
    ];

    let written = store
        .recall_observation_insert(&recall_id, &candidates, Some("agent-x"), Some("ns-x"))
        .await
        .expect("batched ledger append");
    assert_eq!(
        written, 2,
        "#2581: an intra-batch duplicate must collapse to ONE row (first wins), \
         exactly as the per-row loop's ON CONFLICT DO NOTHING did — so 3 \
         candidates with one repeated id insert 2 rows."
    );

    let rows = sqlx::query(
        "SELECT memory_id, retriever, rank, score, agent_id, namespace, folded \
           FROM recall_observations WHERE recall_id = $1 ORDER BY memory_id",
    )
    .bind(&recall_id)
    .fetch_all(pool)
    .await
    .expect("read back ledger");
    assert_eq!(rows.len(), 2, "#2581: exactly two ledger rows expected");

    let alpha = &rows[0];
    assert_eq!(alpha.get::<String, _>("memory_id"), "mem-alpha");
    assert_eq!(
        alpha.get::<String, _>("retriever"),
        "fts",
        "#2581: FIRST candidate must win the conflict, not the last"
    );
    assert_eq!(alpha.get::<i64, _>("rank"), 1);
    assert!((alpha.get::<f64, _>("score") - 1.5).abs() < f64::EPSILON);
    assert_eq!(
        alpha.get::<Option<String>, _>("agent_id").as_deref(),
        Some("agent-x"),
        "#2581: the per-call scalar identity columns must survive the UNNEST hoist"
    );
    assert_eq!(
        alpha.get::<Option<String>, _>("namespace").as_deref(),
        Some("ns-x")
    );
    assert!(
        !alpha.get::<bool, _>("folded"),
        "#2581/#1953: every ledger row lands folded = FALSE; the fold job is the \
         only writer of access state"
    );

    // Idempotence across calls (the ON CONFLICT contract) is unchanged.
    let again = store
        .recall_observation_insert(&recall_id, &candidates, Some("agent-x"), Some("ns-x"))
        .await
        .expect("replay");
    assert_eq!(
        again, 0,
        "#2581: replaying the same recall_id must insert nothing (idempotent \
         append-only ledger)"
    );

    sqlx::query("DELETE FROM recall_observations WHERE recall_id = $1")
        .bind(&recall_id)
        .execute(pool)
        .await
        .expect("cleanup");
}

/// An empty candidate slice still short-circuits before touching the database.
#[tokio::test]
async fn ledger_batch_empty_is_a_noop_2581() {
    let Some(store) = store_or_skip("ledger_batch_empty").await else {
        return;
    };
    let written = store
        .recall_observation_insert("perf2581-empty", &[], None, None)
        .await
        .expect("empty append");
    assert_eq!(written, 0, "#2581: an empty batch writes nothing");
}

// ─────────────────────────────────────────────────────────────────────────────
// #2582 — find_paths routes through the relational CTE
// ─────────────────────────────────────────────────────────────────────────────

/// `find_paths` returns the correct path WITHOUT going through the Cypher body
/// AGE 1.7.0 rejects.
///
/// Before #2582 this call, on an AGE-backed store, paid BEGIN + `LOAD 'age'` +
/// `SET LOCAL search_path` + a Cypher parse that fails with `syntax error at
/// or near "("` (the `ALL(e IN relationships(p) …)` guard — AGE 1.7 has no
/// list predicates) + a rollback + a WARN, and only THEN ran the CTE. The
/// answer was always the CTE's; only the wasted round trips and the per-call
/// spurious WARN were new. This pins that the answer is still correct now that
/// the AGE attempt is gone — the property a naive "delete the AGE branch"
/// could break.
#[tokio::test]
async fn find_paths_returns_correct_paths_via_cte_2582() {
    let Some(store) = store_or_skip("find_paths_cte").await else {
        return;
    };
    let pool = store.pool();
    let ctx = CallerContext::for_agent("perf-2582-probe");
    let ns = format!("perf2582-{}", uuid::Uuid::new_v4());

    let mut ids = Vec::new();
    for i in 0..3 {
        let m = seed_memory(
            &ns,
            format!("perf2582 node {i} {ns}"),
            format!("perf2582 body {i}"),
            5,
        );
        ids.push(store.store(&ctx, &m).await.expect("seed node"));
    }
    for w in ids.windows(2) {
        let link = seed_link(w[0].clone(), w[1].clone());
        store.link(&ctx, &link).await.expect("seed edge");
    }

    let paths = store
        .find_paths(&ids[0], &ids[2], Some(4), Some(10))
        .await
        .expect("find_paths must succeed on both KgBackend values");

    assert!(
        !paths.is_empty(),
        "#2582: find_paths found no path over a seeded 3-node chain. The CTE is \
         now the only implementation, so an empty result here means the routing \
         change broke the answer, not merely the transport."
    );
    let shortest = paths.iter().min_by_key(|p| p.len()).expect("non-empty");
    assert_eq!(
        shortest.len(),
        3,
        "#2582: the shortest path across a 3-node chain is 3 nodes; got {shortest:?}"
    );
    assert_eq!(shortest.first(), Some(&ids[0]));
    assert_eq!(shortest.last(), Some(&ids[2]));

    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(pool)
        .await
        .expect("cleanup");
}
