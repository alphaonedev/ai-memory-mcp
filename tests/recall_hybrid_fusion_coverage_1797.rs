// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #1797 — storage-layer hybrid-recall fusion coverage.
//!
//! #1797 reported `POST /api/v1/recall` returning `{"count":0,"mode":"hybrid"}`
//! with an embedder loaded, while CLI / MCP recall + HTTP list/get worked. The
//! issue correctly noted the hybrid path (`recall_hybrid_precomputed_hnsw`'s
//! FTS+semantic fusion) had no storage-level test coverage —
//! `tests/cov3_handlers_sqlite.rs` builds every recall fixture with
//! `embedder: None`, so only the keyword path was exercised.
//!
//! These tests close that gap and pin the fusion contract across the realistic
//! scenarios that distinguish hybrid from keyword recall: an OWNED memory
//! recalled with `caller = owner` (the #1720 A3 visibility path the HTTP
//! handler always takes), `caller = None`, a query embedding ORTHOGONAL to the
//! stored content embedding (cosine ~ 0 — the FTS-matched-but-low-cosine case
//! that query==stored fixtures mask), a freshly-stored memory ABSENT from the
//! boot-warmed HNSW hit set (the "store then recall" flow), and the
//! `budget_tokens=0` "return nothing" boundary. All pass: the storage fusion
//! surfaces FTS-keyword matches on the hybrid path under every case — so a
//! `count:0` hybrid response is not a fusion-layer defect.
#![allow(clippy::doc_markdown)]

use ai_memory::config::ResolvedScoring;
use ai_memory::hnsw::VectorHit;
use rusqlite::params;

fn fresh_db() -> rusqlite::Connection {
    ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// Seed a memory OWNED by `agent_id` (metadata.agent_id) with an embedding,
/// mirroring what `POST /api/v1/memories` with an `X-Agent-Id` header lands.
fn seed_owned(
    conn: &rusqlite::Connection,
    id: &str,
    namespace: &str,
    title: &str,
    content: &str,
    agent_id: &str,
    embedding: &[f32],
) {
    let now = chrono::Utc::now().to_rfc3339();
    let meta = serde_json::json!({ "agent_id": agent_id }).to_string();
    conn.execute(
        "INSERT INTO memories \
            (id, tier, namespace, title, content, confidence, source, \
             access_count, created_at, updated_at, last_accessed_at, metadata) \
         VALUES (?1, 'long', ?2, ?3, ?4, 0.9, 'api', 0, ?5, ?5, ?5, ?6)",
        params![id, namespace, title, content, now, meta],
    )
    .expect("seed memory");
    let blob = ai_memory::embeddings::encode_embedding_blob(embedding);
    let dim = i64::try_from(embedding.len()).expect("dim");
    conn.execute(
        "UPDATE memories SET embedding = ?1, embedding_dim = ?2 WHERE id = ?3",
        params![blob, dim, id],
    )
    .expect("attach embedding");
    conn.execute(
        "INSERT INTO memories_fts(rowid, title, content) \
         SELECT rowid, title, content FROM memories WHERE id = ?1",
        params![id],
    )
    .ok();
}

#[test]
fn repro_1797_keyword_vs_hybrid_with_owner_caller() {
    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    seed_owned(
        &conn,
        "m-1797",
        "ns",
        "kubernetes",
        "kubernetes deployment guide",
        "agent-x",
        &emb,
    );
    let scoring = ResolvedScoring::default();
    let empty: Vec<VectorHit> = Vec::new();

    // Keyword (the path the reporter says WORKS), caller = owner.
    let (kw, _) = ai_memory::db::recall(
        &conn,
        "kubernetes",
        Some("ns"),
        10,
        None,
        None,
        None,
        0,
        0,
        Some("agent-x"),
        None,
        false,
        None,
        Some("agent-x"),
        None, // #1834 valid_at
    )
    .expect("keyword recall ok");

    // Hybrid (the path that returns 0), SAME caller = owner, empty HNSW hits.
    let (hy, _) = ai_memory::db::recall_hybrid_precomputed_hnsw(
        &conn,
        "kubernetes",
        &emb,
        Some("ns"),
        10,
        None,
        None,
        None,
        &empty,
        0,
        0,
        Some("agent-x"),
        None,
        &scoring,
        false,
        None,
        Some("agent-x"),
        None,
        None, // #1834 valid_at
    )
    .expect("hybrid recall ok");

    eprintln!(
        "KEYWORD count={} ids={:?}",
        kw.len(),
        kw.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
    );
    eprintln!(
        "HYBRID  count={} ids={:?}",
        hy.len(),
        hy.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
    );

    assert!(
        kw.iter().any(|(m, _)| m.id == "m-1797"),
        "keyword must find the owned memory"
    );
    assert!(
        hy.iter().any(|(m, _)| m.id == "m-1797"),
        "#1797: hybrid recall MUST also find the owned memory (caller=owner) — got {} results",
        hy.len()
    );
}

#[test]
fn repro_1797_orthogonal_query_embedding_low_cosine() {
    // REALISTIC: the query TEXT embeds to a vector that is NOT identical to
    // the stored content's embedding — here orthogonal (cosine = 0). The
    // memory must STILL surface via the FTS keyword phase even though its
    // semantic cosine is ~0. (Prior repros used query==stored emb, cosine=1,
    // which masks any cosine-gate-drops-FTS-rows bug.)
    let conn = fresh_db();
    let stored = vec![1.0_f32, 0.0, 0.0, 0.0];
    let query_orthogonal = vec![0.0_f32, 0.0, 0.0, 1.0]; // cosine(stored,query)=0
    seed_owned(
        &conn,
        "m-ortho",
        "ns",
        "kubernetes",
        "kubernetes deployment guide",
        "agent-x",
        &stored,
    );
    let scoring = ResolvedScoring::default();
    let empty: Vec<VectorHit> = Vec::new();
    let (hy, _) = ai_memory::db::recall_hybrid_precomputed_hnsw(
        &conn,
        "kubernetes",
        &query_orthogonal,
        Some("ns"),
        10,
        None,
        None,
        None,
        &empty,
        0,
        0,
        Some("agent-x"),
        None,
        &scoring,
        false,
        None,
        Some("agent-x"),
        None,
        None, // #1834 valid_at
    )
    .expect("hybrid recall ok");
    eprintln!(
        "ORTHOGONAL count={} ids={:?}",
        hy.len(),
        hy.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
    );
    assert!(
        hy.iter().any(|(m, _)| m.id == "m-ortho"),
        "#1797: an FTS-keyword-matched memory with low/zero semantic cosine MUST still \
         surface on the hybrid path — got {} results",
        hy.len()
    );
}

#[test]
fn repro_1797_boot_warmed_index_missing_new_memory() {
    // REAL-WORLD: HNSW index warmed at boot; a memory stored AFTER boot is
    // NOT in the index, so precomputed_hits contains only OTHER (old)
    // memories. The freshly-stored memory must still surface via the FTS
    // keyword phase. This is the closest storage-level model of the
    // reporter's "store then recall" flow.
    let conn = fresh_db();
    let emb_new = vec![1.0_f32, 0.0, 0.0, 0.0];
    let emb_old = vec![0.0_f32, 1.0, 0.0, 0.0];
    seed_owned(
        &conn,
        "m-old",
        "ns",
        "postgres",
        "postgres tuning notes",
        "agent-x",
        &emb_old,
    );
    seed_owned(
        &conn,
        "m-new",
        "ns",
        "kubernetes",
        "kubernetes deployment guide",
        "agent-x",
        &emb_new,
    );
    let scoring = ResolvedScoring::default();
    // Boot-warmed hits contain ONLY the old memory (m-new wasn't indexed).
    let hits = vec![VectorHit {
        id: "m-old".to_string(),
        distance: 0.01,
    }];
    let query_emb = emb_new.clone();
    let (hy, _) = ai_memory::db::recall_hybrid_precomputed_hnsw(
        &conn,
        "kubernetes",
        &query_emb,
        Some("ns"),
        10,
        None,
        None,
        None,
        &hits,
        0,
        0,
        Some("agent-x"),
        None,
        &scoring,
        false,
        None,
        Some("agent-x"),
        None,
        None, // #1834 valid_at
    )
    .expect("hybrid recall ok");
    eprintln!(
        "BOOT-WARMED count={} ids={:?}",
        hy.len(),
        hy.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
    );
    assert!(
        hy.iter().any(|(m, _)| m.id == "m-new"),
        "#1797: a freshly-stored memory (not in the boot-warmed HNSW hits) must still \
         surface via FTS keyword phase on the hybrid path — got {} results",
        hy.len()
    );
}

#[test]
fn repro_1797_budget_zero_returns_nothing() {
    // Sanity: budget_tokens=Some(0) is the documented "return nothing" path.
    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    seed_owned(
        &conn,
        "m-bz",
        "ns",
        "kubernetes",
        "kubernetes deployment guide",
        "agent-x",
        &emb,
    );
    let scoring = ResolvedScoring::default();
    let empty: Vec<VectorHit> = Vec::new();
    let (hy, _) = ai_memory::db::recall_hybrid_precomputed_hnsw(
        &conn,
        "kubernetes",
        &emb,
        Some("ns"),
        10,
        None,
        None,
        None,
        &empty,
        0,
        0,
        Some("agent-x"),
        Some(0),
        &scoring,
        false,
        None,
        Some("agent-x"),
        None,
        None, // #1834 valid_at
    )
    .expect("hybrid recall ok");
    // budget_tokens=Some(0) is the documented "return nothing" path. The HTTP
    // wire defaults budget to None (no cap) when the client omits it, so this
    // is NOT the #1797 default cause — pinned here to keep the distinction
    // explicit.
    assert!(
        hy.is_empty(),
        "budget_tokens=0 must return nothing, got {}",
        hy.len()
    );
}

#[test]
fn repro_1797_caller_none_operator() {
    // caller=None (operator/CLI) — both should work (this is the fx4 case).
    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    seed_owned(
        &conn,
        "m-1797b",
        "ns",
        "kubernetes",
        "kubernetes deployment guide",
        "agent-x",
        &emb,
    );
    let scoring = ResolvedScoring::default();
    let empty: Vec<VectorHit> = Vec::new();
    let (hy, _) = ai_memory::db::recall_hybrid_precomputed_hnsw(
        &conn,
        "kubernetes",
        &emb,
        Some("ns"),
        10,
        None,
        None,
        None,
        &empty,
        0,
        0,
        None,
        None,
        &scoring,
        false,
        None,
        None,
        None,
        None, // #1834 valid_at
    )
    .expect("hybrid recall ok");
    eprintln!("HYBRID(caller=None) count={}", hy.len());
    assert!(
        hy.iter().any(|(m, _)| m.id == "m-1797b"),
        "caller=None hybrid must find it"
    );
}
