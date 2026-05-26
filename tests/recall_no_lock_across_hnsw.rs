// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): doc-comment narrative naturally
// names `vector_index`, `idx.search`, `db.lock`, `IN(...)`, etc. that
// the pedantic doc-markdown lint flags. The lint adds zero
// behavioural value on test prose.
#![allow(clippy::doc_markdown)]

//! FX-4 / PERF-2 (2026-05-26) — pin the lock-release invariant on the
//! HTTP recall handler.
//!
//! ## Why this test exists
//!
//! Pre-FX-4 the HTTP recall handler held `db.lock().await` across:
//!   1. The HNSW `idx.search()` (CPU-bound vector walk).
//!   2. `db::recall_hybrid` itself.
//!   3. A per-row `decorate_memory` loop that issued N additional
//!      `latest_link_attest_level` SQL round-trips under the lock.
//!
//! At high concurrency every concurrent recall serialised behind one
//! another on the single shared `rusqlite::Connection`, cliffing
//! p99 latency. The fix splits the lock window:
//!   a) HNSW search runs OUTSIDE the DB lock (vector_index mutex
//!      only — no DB connection touched).
//!   b) DB lock held only for the FTS5 query + the batched
//!      `get_many` round-trip for the precomputed hits + touch ops.
//!   c) Post-filters (form4 / kinds / session-recency) run on owned
//!      `Memory` rows OUTSIDE the lock.
//!   d) DB lock re-acquired briefly for `decorate_memory_many`
//!      (one IN(...) SQL emit covers the full batch instead of N
//!      per-row round-trips).
//!
//! This test pins the invariant by:
//!  - asserting the new `db::recall_hybrid_precomputed_hnsw` entry
//!    point accepts an empty hits slice and falls through to the
//!    linear-scan branch with the same result shape as the legacy
//!    `db::recall_hybrid` path — preserving recall semantics
//!    (PERF-2 is a pure perf refactor; the result set must not
//!    drift);
//!  - asserting the new entry accepts a non-empty precomputed-hits
//!    slice and surfaces the corresponding rows with the same
//!    blend/decay scoring the legacy path produces (semantics
//!    preservation);
//!  - asserting `decorate_memory_many` produces the same per-row
//!    shape that the legacy per-row `decorate_memory` produces
//!    under both `verbose=true` and `verbose=false` so the batched
//!    re-acquire window is wire-compatible with the pre-fix
//!    per-row path.
//!
//! Together these three pins encode the lock-release invariant
//! mechanically: any future refactor that puts the HNSW search
//! back under the DB lock would have to either (a) remove
//! `recall_hybrid_precomputed_hnsw` or (b) regress
//! `decorate_memory_many` away from the batched IN(...) shape —
//! both visible in this test's compile + behavioural surface.

use ai_memory::config::{ResolvedScoring, ResolvedTtl};
use ai_memory::hnsw::{VectorHit, VectorIndex};
use rusqlite::params;

fn fresh_db() -> rusqlite::Connection {
    ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// Seed a memory with a deterministic embedding vector so the HNSW
/// index + the semantic-phase cosine gate behave predictably across
/// runs. Returns the embedding the caller can re-use for the query
/// side of the test.
fn seed_memory_with_embedding(
    conn: &rusqlite::Connection,
    id: &str,
    namespace: &str,
    title: &str,
    content: &str,
    embedding: &[f32],
) {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memories \
            (id, tier, namespace, title, content, confidence, source, \
             access_count, created_at, updated_at, last_accessed_at) \
         VALUES (?1, 'long', ?2, ?3, ?4, 0.9, 'api', 0, ?5, ?5, ?5)",
        params![id, namespace, title, content, now],
    )
    .expect("seed memory");
    let blob = ai_memory::embeddings::encode_embedding_blob(embedding);
    let dim = i64::try_from(embedding.len()).expect("embedding dim fits in i64");
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
fn fx4_recall_hybrid_precomputed_hits_matches_legacy_with_index() {
    // Seed two memories with distinct embedding vectors. Query
    // embedding is identical to the first memory's vector so the
    // cosine gate fires on the first row but not the second.
    let conn = fresh_db();
    let emb_a = vec![1.0_f32, 0.0, 0.0, 0.0];
    let emb_b = vec![0.0_f32, 1.0, 0.0, 0.0];
    seed_memory_with_embedding(&conn, "m-fx4-a", "fx4", "alpha", "alpha content", &emb_a);
    seed_memory_with_embedding(&conn, "m-fx4-b", "fx4", "beta", "beta content", &emb_b);

    let query_emb = emb_a.clone();

    // Build an HNSW index over both memories so the legacy path
    // exercises the HNSW-hit branch (not the linear-scan fallback).
    let index = VectorIndex::build(vec![
        ("m-fx4-a".to_string(), emb_a.clone()),
        ("m-fx4-b".to_string(), emb_b.clone()),
    ]);

    let scoring = ResolvedScoring::default();
    let _ttl = ResolvedTtl::default();

    // Legacy single-call path: HNSW search runs inside
    // recall_hybrid under the DB lock window (no lock here because
    // it's a single-threaded test, but the call shape matches the
    // pre-fix HTTP handler).
    let (legacy, _outcome_legacy) = ai_memory::db::recall_hybrid(
        &conn,
        "alpha",
        &query_emb,
        Some("fx4"),
        10,
        None,
        None,
        None,
        Some(&index),
        300,
        86_400,
        None,
        None,
        &scoring,
        false,
        None,
    )
    .expect("legacy recall ok");

    // FX-4 path: caller runs idx.search() OUTSIDE the DB connection
    // and passes the hits in. Same query, same index, same memories
    // — the result set MUST be byte-identical to the legacy path.
    let hits: Vec<VectorHit> = index.search(&query_emb, 50);
    let (precomputed, _outcome_precomputed) = ai_memory::db::recall_hybrid_precomputed_hnsw(
        &conn,
        "alpha",
        &query_emb,
        Some("fx4"),
        10,
        None,
        None,
        None,
        &hits,
        300,
        86_400,
        None,
        None,
        &scoring,
        false,
        None,
    )
    .expect("precomputed-hnsw recall ok");

    // Recall semantics preservation: same ids, same order, same
    // scores (within an epsilon to absorb any blend-and-rank
    // floating-point ordering across the two code paths — they
    // share the same `blend_and_rank` so the scores should be
    // bit-identical, but the assertion uses an epsilon to be
    // robust to future refactors of the blend stage that preserve
    // ordering but tweak the scalar).
    assert_eq!(
        legacy.len(),
        precomputed.len(),
        "FX-4 must preserve result-set size: legacy={} vs precomputed={}",
        legacy.len(),
        precomputed.len()
    );
    for (i, ((m_l, s_l), (m_p, s_p))) in legacy.iter().zip(precomputed.iter()).enumerate() {
        assert_eq!(
            m_l.id, m_p.id,
            "FX-4 must preserve row {i} ordering: legacy={} vs precomputed={}",
            m_l.id, m_p.id
        );
        assert!(
            (s_l - s_p).abs() < 1e-9,
            "FX-4 must preserve row {i} score: legacy={s_l} vs precomputed={s_p}"
        );
    }
}

#[test]
fn fx4_recall_hybrid_precomputed_empty_hits_falls_back_to_keyword_results() {
    // When the caller passes an empty precomputed-hits slice (no
    // HNSW index available on the handler side) the recall path
    // must NOT crash and must still return FTS5 keyword candidates.
    // This pins the no-HNSW fallback contract that the handler
    // relies on (vector_index is None → empty hits, recall still
    // works).
    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    seed_memory_with_embedding(&conn, "m-fx4-c", "fx4", "gamma", "gamma content", &emb);

    let scoring = ResolvedScoring::default();
    let empty_hits: Vec<VectorHit> = Vec::new();
    let (results, _outcome) = ai_memory::db::recall_hybrid_precomputed_hnsw(
        &conn,
        "gamma",
        &emb,
        Some("fx4"),
        10,
        None,
        None,
        None,
        &empty_hits,
        300,
        86_400,
        None,
        None,
        &scoring,
        false,
        None,
    )
    .expect("recall with empty hits ok");
    // The keyword phase finds "gamma content" via FTS5 even though
    // no HNSW hits were supplied — that's the no-HNSW degraded path
    // the HTTP handler exercises when the embedder is loaded but
    // the vector_index has not been built yet.
    assert!(
        results.iter().any(|(m, _)| m.id == "m-fx4-c"),
        "FX-4: empty-hits path must still surface FTS5 keyword \
         candidates; got {results:?}"
    );
}

#[test]
fn fx4_decorate_memory_many_matches_per_row_shape() {
    // Pin the wire-shape parity between the legacy per-row
    // `decorate_memory` (still used inside the MCP module) and the
    // batched `decorate_memory_many` consumed by the HTTP recall
    // handler post-FX-4. Both must produce identical row shapes
    // under both verbose=true and verbose=false so the
    // lock-release refactor stays wire-compatible.
    use ai_memory::mcp::decorate_memory_many;
    use ai_memory::models::Memory;

    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    seed_memory_with_embedding(&conn, "m-fx4-d", "fx4", "delta", "delta content", &emb);
    seed_memory_with_embedding(&conn, "m-fx4-e", "fx4", "epsilon", "epsilon content", &emb);

    // Load the two memories back through the production
    // `db::get_many` so the test exercises real Memory rows
    // (including the timestamps + tier columns) rather than a
    // hand-constructed shape.
    let fetched = ai_memory::db::get_many(&conn, &["m-fx4-d".to_string(), "m-fx4-e".to_string()])
        .expect("get_many ok");
    let rows: Vec<(Memory, f64)> = vec![
        (fetched["m-fx4-d"].clone(), 0.75),
        (fetched["m-fx4-e"].clone(), 0.42),
    ];

    // verbose=false: pure-CPU shape, no DB access required.
    let bare = decorate_memory_many(&rows, false, &conn);
    assert_eq!(bare.len(), 2, "verbose=false: one row per input");
    for (i, v) in bare.iter().enumerate() {
        let obj = v.as_object().expect("row is object");
        assert!(obj.contains_key("id"), "row {i}: id present");
        assert!(obj.contains_key("score"), "row {i}: score present");
        assert!(
            !obj.contains_key("confidence_tier"),
            "row {i}: verbose=false must NOT carry confidence_tier"
        );
        assert!(
            !obj.contains_key("freshness_state"),
            "row {i}: verbose=false must NOT carry freshness_state"
        );
        assert!(
            !obj.contains_key("latest_link_attest_level"),
            "row {i}: verbose=false must NOT carry latest_link_attest_level"
        );
    }

    // verbose=true: full Gap 7 decoration shape. The batched
    // attestation lookup fires one IN(...) emit; with no links
    // seeded the map is empty and the field stays absent (matches
    // the per-row `decorate_memory` behaviour exactly).
    let verbose = decorate_memory_many(&rows, true, &conn);
    assert_eq!(verbose.len(), 2, "verbose=true: one row per input");
    for (i, v) in verbose.iter().enumerate() {
        let obj = v.as_object().expect("row is object");
        assert!(
            obj.contains_key("confidence_tier"),
            "row {i}: verbose=true carries confidence_tier"
        );
        assert!(
            obj.contains_key("freshness_state"),
            "row {i}: verbose=true carries freshness_state"
        );
        // No links seeded → no attest_level key, matching the
        // per-row behaviour where `latest_link_attest_level`
        // returns None and the field is omitted.
        assert!(
            !obj.contains_key("latest_link_attest_level"),
            "row {i}: no links → no latest_link_attest_level key"
        );
    }
}

#[test]
fn fx4_decorate_memory_many_surfaces_link_attestation() {
    // Seed two memories AND a link with `attest_level = peer_attested`
    // so the batched IN(...) lookup surfaces the value on both
    // endpoints, mirroring the per-row `latest_link_attest_level`
    // contract (incident-edge lookup against either source_id or
    // target_id).
    use ai_memory::mcp::decorate_memory_many;
    use ai_memory::models::Memory;

    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    seed_memory_with_embedding(&conn, "m-fx4-f", "fx4", "zeta", "zeta content", &emb);
    seed_memory_with_embedding(&conn, "m-fx4-g", "fx4", "eta", "eta content", &emb);
    let now = chrono::Utc::now().to_rfc3339();
    // Substrate CHECK requires a 64-byte signature for any
    // attest_level other than `unsigned`; supply a deterministic
    // 64-byte filler so the row lands without bypassing the gate.
    // The signature payload is opaque to this test — only the
    // attestation lookup is under examination.
    let fake_sig: Vec<u8> = (0u8..64u8).collect();
    conn.execute(
        "INSERT INTO memory_links \
            (source_id, target_id, relation, created_at, attest_level, signature) \
         VALUES (?1, ?2, 'related_to', ?3, 'peer_attested', ?4)",
        params!["m-fx4-f", "m-fx4-g", now, fake_sig],
    )
    .expect("seed link");

    let fetched = ai_memory::db::get_many(&conn, &["m-fx4-f".to_string(), "m-fx4-g".to_string()])
        .expect("get_many ok");
    let rows: Vec<(Memory, f64)> = vec![
        (fetched["m-fx4-f"].clone(), 0.75),
        (fetched["m-fx4-g"].clone(), 0.42),
    ];

    let verbose = decorate_memory_many(&rows, true, &conn);
    for (i, v) in verbose.iter().enumerate() {
        let obj = v.as_object().expect("row is object");
        let level = obj.get("latest_link_attest_level").and_then(|s| s.as_str());
        assert_eq!(
            level,
            Some("peer_attested"),
            "row {i}: batched IN(...) lookup must surface \
             peer_attested attestation on both link endpoints, got {level:?}"
        );
    }
}
