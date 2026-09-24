// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! Boids predator plan item 3, part 3 (R3; #3266 / #3922, 5-agent vote
//! `4d3ea1c5`) — `PostgresStore::stamp_contaminated_descendants_pg`, the PG
//! twin of the #3324 sqlite auto-stamp. Before item 3 nothing on Postgres
//! could WRITE `contaminated` (PG only hid rows that already carried it).
//!
//! Live-PG cells: `#[ignore]`-gated (the postgres-ignored tier) and skipped
//! when `AI_MEMORY_TEST_POSTGRES_URL` is unset. RED on the parent: the method
//! does not exist (compile) — and with it present but the stamp loop removed,
//! the stamping cells fail.
#![cfg(feature = "sal-postgres")]

use ai_memory::models::{LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

const DEPTH: usize = ai_memory::storage::LINEAGE_MAX_DEPTH;

fn mem(ns: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:tester"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn edge(child: &Memory, parent: &Memory) -> MemoryLink {
    MemoryLink {
        source_id: child.id.clone(),
        target_id: parent.id.clone(),
        relation: MemoryLinkRelation::DerivesFrom,
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

/// root <- child <- grandchild, plus an off-DAG row, in a fresh namespace.
async fn seed(store: &PostgresStore) -> (Memory, Memory, Memory, Memory) {
    let ns = format!("stamp-{}", uuid::Uuid::new_v4().simple());
    let ctx = CallerContext::for_agent("ai:tester");
    let (root, child, grandchild, off) = (
        mem(&ns, "root"),
        mem(&ns, "child"),
        mem(&ns, "grandchild"),
        mem(&ns, "off-dag"),
    );
    for m in [&root, &child, &grandchild, &off] {
        store.store(&ctx, m).await.expect("seed");
    }
    store.link(&ctx, &edge(&child, &root)).await.expect("edge");
    store
        .link(&ctx, &edge(&grandchild, &child))
        .await
        .expect("edge");
    (root, child, grandchild, off)
}

async fn state(store: &PostgresStore, id: &str) -> String {
    let (s,): (String,) = sqlx::query_as("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .expect("state");
    s
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_stamp_taints_descendants_not_the_root_3266() {
    let Some(store) = connect().await else { return };
    let (root, child, grandchild, off) = seed(&store).await;
    let r = store
        .stamp_contaminated_descendants_pg(&root.id, DEPTH)
        .await
        .expect("stamp");
    assert_eq!(r.stamped, 2, "child + grandchild: {r:?}");
    assert_eq!(state(&store, &child.id).await, "contaminated");
    assert_eq!(state(&store, &grandchild.id).await, "contaminated");
    assert_eq!(
        state(&store, &root.id).await,
        "open",
        "the superseded ROOT is not stamped (sqlite parity)"
    );
    assert_eq!(
        state(&store, &off.id).await,
        "open",
        "off-DAG row untouched"
    );
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_stamp_is_idempotent_3266() {
    let Some(store) = connect().await else { return };
    let (root, ..) = seed(&store).await;
    store
        .stamp_contaminated_descendants_pg(&root.id, DEPTH)
        .await
        .expect("first");
    let again = store
        .stamp_contaminated_descendants_pg(&root.id, DEPTH)
        .await
        .expect("second");
    assert_eq!(again.stamped, 0, "nothing re-stamped: {again:?}");
    assert_eq!(again.already_contaminated, 2);
}

/// System-only descendants are never downgraded, and the report counts them
/// EXACTLY as the sqlite auto-stamp does. Two cases, because the shared
/// lineage walk treats them differently on BOTH backends (#3614,
/// `models::quarantine_hidden_clause`): a TOMBSTONED descendant is walked and
/// counted as `skipped_system_only`; a QUARANTINED descendant is hidden from
/// the walk (never rendered, so neither stamped nor counted) while the walk
/// still continues through it to its own descendants.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_stamp_never_downgrades_system_only_rows_and_counts_like_sqlite_3266() {
    let Some(store) = connect().await else { return };
    for sys in ["tombstoned", "quarantined"] {
        // Postgres: root <- child(sys) <- grandchild.
        let (root, child, grandchild, _) = seed(&store).await;
        sqlx::query("UPDATE memories SET lifecycle_state = $1 WHERE id = $2")
            .bind(sys)
            .bind(&child.id)
            .execute(store.pool())
            .await
            .expect("set system-only");
        let pg = store
            .stamp_contaminated_descendants_pg(&root.id, DEPTH)
            .await
            .expect("pg stamp");
        assert_eq!(
            state(&store, &child.id).await,
            sys,
            "{sys} is never downgraded"
        );
        assert_eq!(
            state(&store, &grandchild.id).await,
            "contaminated",
            "walk continues past a {sys} node"
        );
        // sqlite: the same fixture through the #3324 auto-stamp.
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("sqlite");
        let (sr, sc, sg) = (mem("p", "root"), mem("p", "child"), mem("p", "grandchild"));
        for m in [&sr, &sc, &sg] {
            ai_memory::db::insert(&conn, m).expect("insert");
        }
        ai_memory::db::create_link(&conn, &sc.id, &sr.id, "derives_from").expect("edge");
        ai_memory::db::create_link(&conn, &sg.id, &sc.id, "derives_from").expect("edge");
        conn.execute(
            "UPDATE memories SET lifecycle_state = ?1 WHERE id = ?2",
            [sys, sc.id.as_str()],
        )
        .expect("set system-only");
        let sq = ai_memory::storage::stamp_contaminated_descendants(&conn, &sr.id, DEPTH)
            .expect("sqlite stamp");
        assert_eq!(
            (pg.stamped, pg.already_contaminated, pg.skipped_system_only),
            (sq.stamped, sq.already_contaminated, sq.skipped_system_only),
            "{sys}: postgres report must count exactly like the sqlite auto-stamp"
        );
    }
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_stamp_marker_is_byte_parity_with_the_sqlite_auto_stamp_3266() {
    let Some(store) = connect().await else { return };
    let (root, child, ..) = seed(&store).await;
    store
        .stamp_contaminated_descendants_pg(&root.id, DEPTH)
        .await
        .expect("pg stamp");
    let (pg_meta,): (serde_json::Value,) =
        sqlx::query_as("SELECT metadata FROM memories WHERE id = $1")
            .bind(&child.id)
            .fetch_one(store.pool())
            .await
            .expect("pg metadata");
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("sqlite");
    let (sr, sc) = (mem("p", "root"), mem("p", "child"));
    ai_memory::db::insert(&conn, &sr).expect("root");
    ai_memory::db::insert(&conn, &sc).expect("child");
    ai_memory::db::create_link(&conn, &sc.id, &sr.id, "derives_from").expect("edge");
    ai_memory::storage::stamp_contaminated_descendants(&conn, &sr.id, DEPTH).expect("sqlite stamp");
    let sq: String = conn
        .query_row(
            "SELECT metadata FROM memories WHERE id = ?1",
            [&sc.id],
            |r| r.get(0),
        )
        .expect("sqlite metadata");
    let sq: serde_json::Value = serde_json::from_str(&sq).expect("json");
    let key = ai_memory::storage::CONTAMINATION_METADATA_KEY;
    let strip = |v: &serde_json::Value| {
        let mut m = v[key].as_object().expect("marker").clone();
        m.remove("stamped_at");
        m.remove("contaminated_from");
        m
    };
    let (p, q) = (&pg_meta[key], &sq[key]);
    assert_eq!(
        p.as_object().expect("pg marker").keys().collect::<Vec<_>>(),
        q.as_object()
            .expect("sqlite marker")
            .keys()
            .collect::<Vec<_>>(),
        "same keys, same order"
    );
    assert_eq!(
        strip(&pg_meta),
        strip(&sq),
        "identical marker values (ids and time aside)"
    );
}

// ---- A13 trigger specificity: PG `link_signed` stamps ONLY on a
// reflection -> reflection `supersedes` (the sqlite narrow trigger). ----

fn reflection(ns: &str, title: &str) -> Memory {
    let mut m = mem(ns, title);
    m.memory_kind = MemoryKind::Reflection;
    m.reflection_depth = 1;
    m
}

fn link_of(src: &Memory, tgt: &Memory, relation: MemoryLinkRelation) -> MemoryLink {
    let mut l = edge(src, tgt);
    l.relation = relation;
    l
}

/// A superseded target `t` (kind `t_kind`) with one derives_from descendant,
/// and a would-be superseder `s` (kind `s_kind`).
async fn seed_supersede(
    store: &PostgresStore,
    s_reflection: bool,
    t_reflection: bool,
) -> (Memory, Memory, Memory) {
    let ns = format!("trig-{}", uuid::Uuid::new_v4().simple());
    let ctx = CallerContext::for_agent("ai:tester");
    let pick = |r: bool, t: &str| if r { reflection(&ns, t) } else { mem(&ns, t) };
    let (s, t, child) = (
        pick(s_reflection, "superseder"),
        pick(t_reflection, "superseded"),
        mem(&ns, "child"),
    );
    for m in [&s, &t, &child] {
        store.store(&ctx, m).await.expect("seed");
    }
    store
        .link(&ctx, &edge(&child, &t))
        .await
        .expect("derives_from");
    (s, t, child)
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_link_signed_reflection_supersedes_stamps_the_targets_descendants_3266() {
    let Some(store) = connect().await else { return };
    let (s, t, child) = seed_supersede(&store, true, true).await;
    let ctx = CallerContext::for_agent("ai:tester");
    store
        .link_signed(&ctx, &link_of(&s, &t, MemoryLinkRelation::Supersedes), None)
        .await
        .expect("supersedes edge");
    assert_eq!(
        state(&store, &child.id).await,
        "contaminated",
        "descendant of the superseded reflection is stamped"
    );
    assert_eq!(
        state(&store, &t.id).await,
        "open",
        "the superseded target itself is not stamped (sqlite parity)"
    );
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_link_signed_does_not_stamp_a_non_reflection_supersedes_3266() {
    let Some(store) = connect().await else { return };
    for (s_ref, t_ref) in [(false, true), (true, false), (false, false)] {
        let (s, t, child) = seed_supersede(&store, s_ref, t_ref).await;
        let ctx = CallerContext::for_agent("ai:tester");
        store
            .link_signed(&ctx, &link_of(&s, &t, MemoryLinkRelation::Supersedes), None)
            .await
            .expect("supersedes edge");
        assert_eq!(
            state(&store, &child.id).await,
            "open",
            "supersedes with a non-reflection end (s={s_ref}, t={t_ref}) must NOT stamp"
        );
    }
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_link_signed_other_relations_between_reflections_do_not_stamp_3266() {
    let Some(store) = connect().await else { return };
    for rel in [
        MemoryLinkRelation::RelatedTo,
        MemoryLinkRelation::DerivedFrom,
    ] {
        let (s, t, child) = seed_supersede(&store, true, true).await;
        let ctx = CallerContext::for_agent("ai:tester");
        store
            .link_signed(&ctx, &link_of(&s, &t, rel), None)
            .await
            .expect("edge");
        assert_eq!(
            state(&store, &child.id).await,
            "open",
            "{} between reflections must NOT stamp",
            rel.as_str()
        );
    }
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_kg_invalidate_does_not_stamp_3266() {
    let Some(store) = connect().await else { return };
    let (s, t, child) = seed_supersede(&store, true, true).await;
    let ctx = CallerContext::for_agent("ai:tester");
    // Land the edge through the UNSIGNED `link` (no trigger there), then
    // invalidate it: sqlite never stamps on kg_invalidate, and neither may PG.
    store
        .link(&ctx, &link_of(&s, &t, MemoryLinkRelation::Supersedes))
        .await
        .expect("edge");
    assert_eq!(state(&store, &child.id).await, "open", "precondition");
    store
        .kg_invalidate(
            &s.id,
            &t.id,
            MemoryLinkRelation::Supersedes.as_str(),
            None,
            Some("ai:tester"),
        )
        .await
        .expect("invalidate");
    assert_eq!(
        state(&store, &child.id).await,
        "open",
        "kg_invalidate must NOT stamp"
    );
}
