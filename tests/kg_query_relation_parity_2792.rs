// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// Test scaffolding: pedantic doc-markdown lints on the narrative header have no
// behavioral impact (mirrors `g4_postgres_link_projects_into_age_graph.rs`).
#![allow(clippy::doc_markdown)]

//! #2792 — `kg_query` on the Postgres/AGE backend must traverse the SAME
//! relation set as the SQLite recursive CTE: ALL nine
//! [`ai_memory::models::MemoryLinkRelation`] variants, not only `related_to`.
//!
//! ## The defect this file pins
//!
//! `build_kg_query_current_view_cypher` hard-coded the AGE Cypher
//! relationship pattern as `-[r:related_to*1..N]->`, so on an AGE-enabled
//! Postgres deployment `kg_query` walked ONLY `related_to` edges and silently
//! under-reported every `supersedes` / `contradicts` / `derived_from` /
//! `reflects_on` / `derives_from` / `decomposes_into` / `depends_on` /
//! `advances` edge. Proven divergence (v1.0.0 cert Track-A): an identical
//! `supersedes` edge yielded `kg_query` count:0 on pg vs count:1 on sqlite.
//! The SQLite CTE (`db::kg_query`) reads `memory_links` with NO relation
//! filter, so it traverses all 9 relations (the CHECK-constrained set).
//!
//! The fix makes the AGE pattern UNTYPED (`-[r*1..N]->`) — Apache AGE's
//! parser does not implement a relationship-type ALTERNATION
//! (`-[r:a|b|c*1..N]->` → `syntax error at or near "|"`, verified live on AGE
//! 1.6.0/1.7.0) — with a fail-closed Rust-side membership guard keeping the
//! result set equivalent to the CTE's `memory_links` relation set.
//!
//! ## Tests
//!
//! - `sqlite_kg_query_traverses_supersedes_edge_2792` (default, always runs) —
//!   the SQLite reference: the proven-correct side. A `supersedes` edge is
//!   surfaced by `db::kg_query`.
//! - `sqlite_kg_query_traverses_all_nine_relations_2792` (default) — one
//!   target per relation; every one is reachable at depth 1.
//! - `pg_kg_query_traverses_all_nine_relations_2792` (`sal-postgres`,
//!   soft-skips without `AI_MEMORY_TEST_POSTGRES_URL`) — the parity twin.
//!   Against a live AGE instance this exercises the fixed Cypher path and
//!   FAILS pre-fix (every non-`related_to` target missing); against a plain
//!   pgvector Postgres it exercises the CTE fallback (already correct).
//!
//! Not `#[ignore]`: the PR-gating `postgres-feature` job runs
//! `cargo test --features sal-postgres` WITHOUT `--include-ignored`, so an
//! `#[ignore]` twin would be invisible to the PR gate. The runtime
//! `AI_MEMORY_TEST_POSTGRES_URL` soft-skip is the house pattern
//! (`cov_postgres_kg.rs`, `ns_standard_clear_unowned_2704_pg.rs`).

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, MemoryLinkRelation, Tier};

fn seed_mem(conn: &rusqlite::Connection, id: &str, title: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "kg2792".to_string(),
        title: title.to_string(),
        content: format!("kg2792 node {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-2792".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "ai:test-2792"}),
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
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("insert seed");
}

#[test]
fn sqlite_kg_query_traverses_supersedes_edge_2792() {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open");
    seed_mem(&conn, "src", "source");
    seed_mem(&conn, "dst", "target");
    ai_memory::db::create_link(&conn, "src", "dst", "supersedes").expect("link");

    let rows = ai_memory::db::kg_query(&conn, "src", 3, None, None, None, false).expect("kg_query");
    assert_eq!(rows.len(), 1, "supersedes edge must be traversed on sqlite");
    assert_eq!(rows[0].target_id, "dst");
    assert_eq!(rows[0].relation, "supersedes");
}

#[test]
fn sqlite_kg_query_traverses_all_nine_relations_2792() {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open");
    seed_mem(&conn, "src", "source");
    for rel in MemoryLinkRelation::all() {
        let tgt = format!("dst-{}", rel.as_str());
        seed_mem(&conn, &tgt, rel.as_str());
        ai_memory::db::create_link(&conn, "src", &tgt, rel.as_str()).expect("link");
    }

    let rows = ai_memory::db::kg_query(&conn, "src", 1, None, None, None, false).expect("kg_query");
    let got: std::collections::BTreeSet<String> = rows.iter().map(|r| r.relation.clone()).collect();
    for rel in MemoryLinkRelation::all() {
        assert!(
            got.contains(rel.as_str()),
            "sqlite kg_query must surface the {} edge; got {got:?}",
            rel.as_str()
        );
    }
    assert_eq!(rows.len(), MemoryLinkRelation::COUNT);
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::models::MemoryLink;
    use ai_memory::store::MemoryStore;
    use ai_memory::store::postgres::PostgresStore;

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_AGE_URL")
            .ok()
            .or_else(|| std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok())
            .filter(|s| !s.is_empty())
    }

    fn uniq(prefix: &str) -> String {
        format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
    }

    fn admin_ctx() -> ai_memory::store::CallerContext {
        let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2792-pg");
        ctx.bypass_visibility = true;
        ctx
    }

    fn pg_mem(id: &str, ns: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: id.to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: format!("kg2792-{id}"),
            content: format!("kg2792 pg node {id}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test-2792".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": "ai:test-2792-pg"}),
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
            ..Memory::default()
        }
    }

    fn pg_link(src: &str, tgt: &str, relation: &str) -> MemoryLink {
        let now = chrono::Utc::now().to_rfc3339();
        MemoryLink {
            source_id: src.to_string(),
            target_id: tgt.to_string(),
            relation: MemoryLinkRelation::from_str(relation).expect("valid relation"),
            created_at: now.clone(),
            signature: None,
            observed_by: None,
            valid_from: Some(now),
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        }
    }

    #[tokio::test]
    async fn pg_kg_query_traverses_all_nine_relations_2792() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL/AGE_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect pg");
        let ctx = admin_ctx();
        // Namespace-isolate this run so a shared test DB does not cross-talk.
        let ns = uniq("kg2792");
        let src = uniq("src");
        store
            .store(&ctx, &pg_mem(&src, &ns))
            .await
            .expect("store src");

        let mut expected: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for rel in MemoryLinkRelation::all() {
            let tgt = uniq(&format!("dst-{}", rel.as_str()));
            store
                .store(&ctx, &pg_mem(&tgt, &ns))
                .await
                .expect("store tgt");
            store
                .link(&ctx, &pg_link(&src, &tgt, rel.as_str()))
                .await
                .expect("link");
            expected.insert(rel.as_str().to_string());
        }

        let rows = MemoryStore::kg_query(&store, &src, 1, false)
            .await
            .expect("kg_query");
        let got: std::collections::BTreeSet<String> =
            rows.iter().map(|r| r.relation.clone()).collect();
        for rel in MemoryLinkRelation::all() {
            assert!(
                got.contains(rel.as_str()),
                "#2792: pg kg_query must surface the {} edge (pre-fix the AGE \
                 Cypher matched only related_to); got {got:?}",
                rel.as_str()
            );
        }
        assert_eq!(
            rows.len(),
            MemoryLinkRelation::COUNT,
            "expected exactly {} outbound neighbours, one per relation",
            MemoryLinkRelation::COUNT
        );
    }

    /// #2792 + #1689 — the untyped `-[r*1..N]->` pattern must STILL exclude
    /// INVALIDATED edges from the current-view traversal, for the
    /// newly-traversed non-`related_to` relations too. The invalidation guard
    /// is the Rust-side `age_path_edges_all_current` (`kg_query_cypher`),
    /// which the #2792 pattern change does NOT touch — this pins that the two
    /// guards compose: a `supersedes` edge is traversed (the #2792 fix) yet
    /// dropped once invalidated (the #1689 contract), and re-appears only
    /// under `include_invalidated=true`.
    #[tokio::test]
    async fn pg_kg_query_excludes_invalidated_supersedes_edge_2792() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL/AGE_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect pg");
        let ctx = admin_ctx();
        let ns = uniq("kg2792inv");
        let src = uniq("src");
        let tgt = uniq("dst");
        store
            .store(&ctx, &pg_mem(&src, &ns))
            .await
            .expect("store src");
        store
            .store(&ctx, &pg_mem(&tgt, &ns))
            .await
            .expect("store tgt");
        store
            .link(&ctx, &pg_link(&src, &tgt, "supersedes"))
            .await
            .expect("link");

        // Current-view BEFORE invalidation: the supersedes edge is traversed.
        let before = MemoryStore::kg_query(&store, &src, 3, false)
            .await
            .expect("kg_query before");
        assert!(
            before.iter().any(|r| r.target_id == tgt),
            "#2792: supersedes edge must be traversed before invalidation; got {before:?}"
        );

        // Invalidate the edge (SET valid_until = now on the AGE edge + row).
        let res = store
            .invalidate_link(&src, &tgt, "supersedes", None)
            .await
            .expect("invalidate_link");
        assert!(res.found, "invalidate_link must find the supersedes edge");

        // Current-view AFTER invalidation: the edge MUST be excluded (#1689).
        let after = MemoryStore::kg_query(&store, &src, 3, false)
            .await
            .expect("kg_query after");
        assert!(
            after.iter().all(|r| r.target_id != tgt),
            "#1689: invalidated supersedes edge must be EXCLUDED from the \
             current-view AGE traversal (the untyped #2792 pattern must not \
             walk invalidated edges); got {after:?}"
        );

        // include_invalidated=true lifts the filter — the edge is visible again.
        let history = MemoryStore::kg_query(&store, &src, 3, true)
            .await
            .expect("kg_query history");
        assert!(
            history.iter().any(|r| r.target_id == tgt),
            "include_invalidated=true must surface the invalidated edge; got {history:?}"
        );
    }

    /// #2792 sibling — `kg_timeline` on the AGE backend must return link
    /// events for ALL relations, not only `related_to`. `kg_timeline_cypher`
    /// hardcoded the same `-[r:related_to]->` pattern the #2792 `kg_query`
    /// carried, so an AGE-backed `memory_kg_timeline` silently omitted every
    /// `supersedes` / `contradicts` / … event that the SQLite CTE returns.
    #[tokio::test]
    async fn pg_kg_timeline_returns_non_related_to_events_2792sibling() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL/AGE_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect pg");
        let ctx = admin_ctx();
        let ns = uniq("kg2792tl");
        let src = uniq("src");
        let tgt = uniq("dst");
        store
            .store(&ctx, &pg_mem(&src, &ns))
            .await
            .expect("store src");
        store
            .store(&ctx, &pg_mem(&tgt, &ns))
            .await
            .expect("store tgt");
        store
            .link(&ctx, &pg_link(&src, &tgt, "supersedes"))
            .await
            .expect("link");

        let events = store
            .kg_timeline(&src, None, None, None)
            .await
            .expect("kg_timeline");
        assert!(
            events
                .iter()
                .any(|e| e.target_id == tgt && e.relation == "supersedes"),
            "#2792 sibling: kg_timeline must surface the supersedes event on AGE \
             (pre-fix the -[r:related_to]-> pattern omitted it); got {events:?}"
        );
    }
}
