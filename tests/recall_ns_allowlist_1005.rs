// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9 #1005 (§5.2) — end-to-end regression for the recall
//! namespace-starvation hazard, exercised through the REAL pipeline
//! (`db::recall_hybrid` → `semantic_phase` → the seam trait's
//! allowlist search), plus unit coverage for the in-scope id helper
//! `db::vector_recall_allowlist_ids`.
//!
//! ## The hazard (pre-fix, still the default posture)
//!
//! The semantic phase asks the vector index for the GLOBAL
//! `ann_limit = max(limit*5, 50)` nearest neighbors and only THEN
//! post-filters by namespace. When a small namespace's rows rank
//! behind `ann_limit` foreign neighbors, every candidate the cutoff
//! admits is discarded by the filter and the namespace semantically
//! starves — its rows exist, carry embeddings above the cosine gate,
//! and are never returned.
//!
//! ## The opt-in fix
//!
//! With `AI_MEMORY_VECTOR_NAMESPACE_ALLOWLIST` truthy, the recall
//! path threads the namespace's embedded-row id set into the search
//! and the walk lazily skips out-of-scope candidates until `k`
//! in-scope hits or iterator exhaustion. Flag unset = byte-identical
//! legacy (phase 1 of the regression test pins that posture too).
//!
//! Env mutation note: both phases run inside ONE `#[test]` so the
//! flag flip cannot race a sibling test in this binary; the var is
//! removed before the test returns (K2-gate test precedent).

use ai_memory::config::ResolvedScoring;
use ai_memory::hnsw::{VectorIndex, VectorSearchIndex};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use rusqlite::params;

/// FTS probe that matches nothing in the corpus, so ONLY the semantic
/// phase can produce candidates and the starvation is unambiguous.
const NO_MATCH_CONTEXT: &str = "zebraquark";

fn fresh_db() -> rusqlite::Connection {
    ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn mem(id: &str, namespace: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: id.to_string(),
        content: format!("plain corpus row {id}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::Value::Object(serde_json::Map::new()),
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

fn attach_embedding(conn: &rusqlite::Connection, id: &str, embedding: &[f32]) {
    let blob = ai_memory::embeddings::encode_embedding_blob(embedding);
    let dim = i64::try_from(embedding.len()).expect("dim fits i64");
    conn.execute(
        "UPDATE memories SET embedding = ?1, embedding_dim = ?2 WHERE id = ?3",
        params![blob, dim, id],
    )
    .expect("attach embedding");
}

fn normalize(values: &[f32]) -> Vec<f32> {
    let norm: f32 = values.iter().map(|v| v * v).sum::<f32>().sqrt();
    values.iter().map(|v| v / norm).collect()
}

/// Corpus fixture returned by [`seed_starvation_corpus`]: the (id,
/// embedding) index entries, the tiny-namespace ids, and the query.
struct StarvationCorpus {
    entries: Vec<(String, Vec<f32>)>,
    tiny_ids: Vec<String>,
    query: Vec<f32>,
}

/// Seed 60 decoy rows in `bulk` STRICTLY nearer to the query than the
/// 3 `tiny` rows (which still clear the `cosine > 0.2` recall gate).
#[allow(clippy::cast_precision_loss)]
fn seed_starvation_corpus(conn: &rusqlite::Connection) -> StarvationCorpus {
    let query = normalize(&[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    let mut entries = Vec::new();
    for i in 0..60_usize {
        let id = format!("bulk-{i}");
        let mut v = vec![0.0_f32; 8];
        v[0] = 1.0;
        v[1] = 0.01 + 0.005 * i as f32; // cosine ≈ 0.96..1.0 — nearest
        let emb = normalize(&v);
        ai_memory::db::insert(conn, &mem(&id, "bulk")).expect("insert decoy");
        attach_embedding(conn, &id, &emb);
        entries.push((id, emb));
    }
    let mut tiny_ids = Vec::new();
    for i in 0..3_usize {
        let id = format!("tiny-{i}");
        let mut v = vec![0.0_f32; 8];
        v[0] = 1.0;
        v[2] = 0.9 + 0.05 * i as f32; // cosine ≈ 0.72 — well above the 0.2 gate
        let emb = normalize(&v);
        ai_memory::db::insert(conn, &mem(&id, "tiny")).expect("insert tiny");
        attach_embedding(conn, &id, &emb);
        tiny_ids.push(id.clone());
        entries.push((id, emb));
    }
    StarvationCorpus {
        entries,
        tiny_ids,
        query,
    }
}

fn recall_tiny_ns(
    conn: &rusqlite::Connection,
    query: &[f32],
    idx: &dyn VectorSearchIndex,
) -> Vec<String> {
    let scoring = ResolvedScoring::default();
    let (results, _outcome) = ai_memory::db::recall_hybrid(
        conn,
        NO_MATCH_CONTEXT,
        query,
        Some("tiny"),
        10,
        None,
        None,
        None,
        Some(idx),
        0,
        0,
        None,
        None,
        &scoring,
        false,
        None,
        None,
        None,
    )
    .expect("recall_hybrid ok");
    results.into_iter().map(|(m, _)| m.id).collect()
}

/// §5.2 END-TO-END — phase 1 pins the legacy starvation (flag unset:
/// zero results for a live namespace), phase 2 proves the opt-in
/// allowlist returns every tiny-namespace row through the very same
/// pipeline call.
#[test]
fn recall_hybrid_ns_starvation_and_allowlist_fix_5_2_1005() {
    let conn = fresh_db();
    let StarvationCorpus {
        entries,
        tiny_ids,
        query,
    } = seed_starvation_corpus(&conn);
    let idx = VectorIndex::build(entries);

    // ---- Phase 1: flag UNSET → byte-identical legacy → starved ----
    // SAFETY: process-env mutation, scoped to this single test fn in
    // this test binary and removed before returning.
    unsafe { std::env::remove_var(ai_memory::hnsw::ENV_VECTOR_NS_ALLOWLIST) };
    let starved = recall_tiny_ns(&conn, &query, &idx);
    assert!(
        starved.is_empty(),
        "§5.2 hazard pin (default posture): 60 nearer foreign decoys must starve \
         the 3-row `tiny` namespace behind the ann_limit=50 global cutoff \
         (FTS contributes nothing for {NO_MATCH_CONTEXT:?}); got {starved:?}"
    );

    // ---- Phase 2: flag ON → the allowlist walk surfaces every row ----
    // SAFETY: as above.
    unsafe { std::env::set_var(ai_memory::hnsw::ENV_VECTOR_NS_ALLOWLIST, "1") };
    let fixed = recall_tiny_ns(&conn, &query, &idx);
    // SAFETY: restore the inert default before any assertion can panic
    // the test out with the flag still set.
    unsafe { std::env::remove_var(ai_memory::hnsw::ENV_VECTOR_NS_ALLOWLIST) };

    assert_eq!(
        fixed.len(),
        tiny_ids.len(),
        "allowlist recall must return ALL {} tiny-namespace rows, got {fixed:?}",
        tiny_ids.len()
    );
    for id in &tiny_ids {
        assert!(fixed.contains(id), "missing tiny row {id}: {fixed:?}");
    }
}

/// The allowlist helper lists exactly the EMBEDDED rows of the flat
/// namespace — no foreign-namespace ids, no embedding-less ids.
#[test]
fn vector_recall_allowlist_ids_flat_namespace_1005() {
    let conn = fresh_db();
    ai_memory::db::insert(&conn, &mem("in-1", "tiny")).expect("insert");
    attach_embedding(&conn, "in-1", &normalize(&[1.0, 0.0, 0.0]));
    ai_memory::db::insert(&conn, &mem("in-2", "tiny")).expect("insert");
    attach_embedding(&conn, "in-2", &normalize(&[0.0, 1.0, 0.0]));
    // In-namespace but WITHOUT an embedding — the index can't hold it.
    ai_memory::db::insert(&conn, &mem("no-emb", "tiny")).expect("insert");
    // Embedded but foreign namespace.
    ai_memory::db::insert(&conn, &mem("foreign", "bulk")).expect("insert");
    attach_embedding(&conn, "foreign", &normalize(&[0.0, 0.0, 1.0]));

    let mut ids = ai_memory::db::vector_recall_allowlist_ids(&conn, "tiny").expect("helper ok");
    ids.sort();
    assert_eq!(ids, vec!["in-1".to_string(), "in-2".to_string()]);
}

/// Hierarchical query namespace admits ancestor rows (the Task 1.12
/// recall contract mirrored by the semantic-phase post-filter):
/// recalling `org/team` sees rows in `org/team` AND `org`, but not
/// in a sibling.
#[test]
fn vector_recall_allowlist_ids_hierarchy_1005() {
    let conn = fresh_db();
    for (id, ns) in [
        ("child", "org/team"),
        ("parent", "org"),
        ("sibling", "org/other"),
    ] {
        ai_memory::db::insert(&conn, &mem(id, ns)).expect("insert");
        attach_embedding(&conn, id, &normalize(&[1.0, 0.0, 0.0]));
    }
    let mut ids = ai_memory::db::vector_recall_allowlist_ids(&conn, "org/team").expect("helper ok");
    ids.sort();
    assert_eq!(
        ids,
        vec!["child".to_string(), "parent".to_string()],
        "ancestors admitted, siblings excluded"
    );
}
