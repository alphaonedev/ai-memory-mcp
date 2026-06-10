// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(clippy::doc_markdown)]

//! v0.7.0 (issue #519) — proactive contradiction detection on
//! `memory_store`.
//!
//! Pins the substrate-level contract per the Initiative #9 v0.7.0-
//! blocker scope statement:
//!
//! 1. `proactive_conflict_check` returns `None` when no embedded
//!    candidate in the namespace passes the 0.95 cosine threshold.
//!
//! 2. `proactive_conflict_check` returns `Some(ProactiveConflict{..})`
//!    when at least one candidate is a near-duplicate (>= 0.95 cosine)
//!    AND its content body differs from the incoming write — the
//!    substrate-layer deterministic contradiction signal.
//!
//! 3. Same-content near-duplicates are NOT classified as conflicts
//!    (they're the upsert happy-path).
//!
//! 4. Self-matches (same memory id) are excluded.
//!
//! 5. Cross-namespace candidates do not trigger the guard.
//!
//! 6. Wire-shape: the new `force: bool` field on `CreateMemory`
//!    defaults to `false` and round-trips through serde.
//!
//! Embeddings are caller-supplied (no embedder required) so the
//! substrate-level contract is exercised under
//! `AI_MEMORY_NO_CONFIG=1` with zero network deps.

use ai_memory::models::{ConfidenceSource, CreateMemory, Memory, MemoryKind, Tier};
use ai_memory::storage as db;
use ai_memory::storage::{PROACTIVE_CONFLICT_SIM_THRESHOLD, proactive_conflict_check};

fn fresh_conn() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(title: &str, content: &str, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Insert a memory + attach a caller-supplied embedding. Mirrors the
/// pattern handlers/http.rs uses: embed BEFORE the lock, then insert,
/// then `db::set_embedding`.
fn insert_with_embedding(conn: &rusqlite::Connection, mem: &Memory, embedding: &[f32]) -> String {
    let id = db::insert(conn, mem).expect("insert");
    db::set_embedding(conn, &id, embedding).expect("set_embedding");
    id
}

#[test]
fn proactive_conflict_returns_none_on_low_similarity() {
    let conn = fresh_conn();
    // Existing memory A.
    let mem_a = make_mem("alpha", "the moon landing was 1969", "global");
    let emb_a = vec![1.0_f32, 0.0, 0.0, 0.0];
    insert_with_embedding(&conn, &mem_a, &emb_a);

    // Incoming write B with orthogonal embedding => low cosine.
    let mem_b = make_mem("beta", "the speed of light is c", "global");
    let emb_b = vec![0.0_f32, 1.0, 0.0, 0.0];

    let conflict = proactive_conflict_check(&conn, &mem_b, &emb_b).expect("check ok");
    assert!(
        conflict.is_none(),
        "orthogonal embeddings must not trigger the proactive conflict guard"
    );
}

#[test]
fn proactive_conflict_returns_some_on_near_duplicate_with_differing_content() {
    let conn = fresh_conn();
    // Existing memory A about a quoted fact.
    let mem_a = make_mem("project-deadline", "deadline is june 15", "global");
    let emb_a = vec![1.0_f32, 0.0, 0.0];
    insert_with_embedding(&conn, &mem_a, &emb_a);

    // Incoming write A' with IDENTICAL embedding (cosine 1.0) but
    // DIFFERENT content — the substrate-layer contradiction signal.
    let mut mem_a_prime = make_mem("project-deadline-revised", "deadline is june 22", "global");
    // Distinct id so the self-exclusion branch can't short-circuit.
    mem_a_prime.id = uuid::Uuid::new_v4().to_string();
    let emb_a_prime = emb_a.clone();

    let conflict = proactive_conflict_check(&conn, &mem_a_prime, &emb_a_prime)
        .expect("check ok")
        .expect("near-duplicate with differing content must be a conflict");
    assert!(
        conflict.similarity >= PROACTIVE_CONFLICT_SIM_THRESHOLD,
        "similarity must clear the 0.95 threshold; got {}",
        conflict.similarity
    );
    assert_eq!(conflict.existing_title, "project-deadline");
    assert_eq!(conflict.reason, "near_duplicate_with_differing_content");
}

#[test]
fn proactive_conflict_skips_same_content_near_duplicates() {
    // Same-content near-duplicates are NOT contradictions — they are
    // the upsert happy-path that the existing `ON CONFLICT(title,
    // namespace)` SQL already handles.
    let conn = fresh_conn();
    let plaintext = "user prefers dark mode";
    let mem_a = make_mem("user-pref", plaintext, "global");
    let emb_a = vec![0.5_f32, 0.5, 0.0];
    insert_with_embedding(&conn, &mem_a, &emb_a);

    let mut mem_a_dup = make_mem("user-pref-2", plaintext, "global");
    mem_a_dup.id = uuid::Uuid::new_v4().to_string();
    let emb_dup = emb_a.clone();

    let conflict = proactive_conflict_check(&conn, &mem_a_dup, &emb_dup).expect("check ok");
    assert!(
        conflict.is_none(),
        "same-content near-duplicate must NOT trigger the conflict guard"
    );
}

#[test]
fn proactive_conflict_excludes_self_match() {
    // A re-store that reuses the existing memory id (NHI replay path)
    // must not see itself as a conflict.
    let conn = fresh_conn();
    let mem = make_mem("self-replay", "version 1 of the fact", "global");
    let emb = vec![1.0_f32, 0.0];
    let id = insert_with_embedding(&conn, &mem, &emb);

    // Build the "incoming" write that reuses the same id but proposes
    // differing content with an identical embedding.
    let mut replay = make_mem("self-replay", "version 2 of the fact", "global");
    replay.id = id;

    let conflict = proactive_conflict_check(&conn, &replay, &emb).expect("check ok");
    assert!(
        conflict.is_none(),
        "self-match (same memory id) must be excluded from the conflict scan"
    );
}

#[test]
fn proactive_conflict_scoped_to_namespace() {
    // Cross-namespace near-duplicates do not trigger the guard —
    // namespaces are deliberately isolated scopes.
    let conn = fresh_conn();
    let mem_alpha = make_mem("shared-title", "fact body alpha", "ns-alpha");
    let emb = vec![0.0_f32, 1.0];
    insert_with_embedding(&conn, &mem_alpha, &emb);

    let mut mem_beta = make_mem("shared-title", "fact body beta", "ns-beta");
    mem_beta.id = uuid::Uuid::new_v4().to_string();

    let conflict = proactive_conflict_check(&conn, &mem_beta, &emb).expect("check ok");
    assert!(
        conflict.is_none(),
        "cross-namespace near-duplicate must NOT trigger the guard"
    );
}

#[test]
fn proactive_conflict_ignores_candidates_without_embedding() {
    // A row stored without an embedding is invisible to the proactive
    // check (the scan filters on `embedding IS NOT NULL`).
    let conn = fresh_conn();
    let mem_a = make_mem("no-embed", "established fact", "global");
    db::insert(&conn, &mem_a).expect("insert without embedding");

    let mut mem_a_prime = make_mem("no-embed-conflict", "contradicting fact", "global");
    mem_a_prime.id = uuid::Uuid::new_v4().to_string();
    let emb = vec![1.0_f32, 1.0];

    let conflict = proactive_conflict_check(&conn, &mem_a_prime, &emb).expect("check ok");
    assert!(
        conflict.is_none(),
        "embedding-less candidates must not trigger the guard"
    );
}

#[test]
fn proactive_conflict_empty_embedding_short_circuits() {
    // An empty query embedding (degraded mode, no embedder wired)
    // returns None without touching the candidate pool.
    let conn = fresh_conn();
    let mem = make_mem("anything", "anything", "global");
    let emb: Vec<f32> = vec![];
    let conflict = proactive_conflict_check(&conn, &mem, &emb).expect("check ok");
    assert!(
        conflict.is_none(),
        "empty query embedding must short-circuit to None"
    );
}

#[test]
fn create_memory_body_force_defaults_to_false() {
    // Wire-shape: callers that omit `force` see `false` after serde
    // round-trip. The new field is `#[serde(default)]` — pre-#519
    // clients keep working byte-for-byte.
    let raw = serde_json::json!({
        "title": "wire-shape-check",
        "content": "force defaults to false",
        "namespace": "global",
    });
    let body: CreateMemory = serde_json::from_value(raw).expect("parse");
    assert!(!body.force, "force defaults to false");

    let raw_with_force = serde_json::json!({
        "title": "wire-shape-check-2",
        "content": "force=true round-trips",
        "namespace": "global",
        "force": true,
    });
    let body2: CreateMemory = serde_json::from_value(raw_with_force).expect("parse");
    assert!(body2.force, "force=true round-trips");
}

// ---------------------------------------------------------------------------
// #1579 A5 — false-409 regression + HNSW-routed candidate pool.
// ---------------------------------------------------------------------------

use ai_memory::hnsw::VectorIndex;
use ai_memory::storage::{
    PROACTIVE_CONFLICT_SCAN_LIMIT, proactive_conflict_check_candidates,
    proactive_conflict_check_with_index,
};

/// Mirror of `loadtest::make_payload` — deterministic random-ish
/// alphanumeric filler, the exact payload shape that produced the P2
/// 81%-false-409 epidemic at semantic tier.
fn noise_payload(bytes: usize, salt: u64) -> String {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789 ";
    let mut s = String::with_capacity(bytes);
    let mut x = salt.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for _ in 0..bytes {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        #[allow(clippy::cast_possible_truncation)]
        let idx = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as usize % ALPHA.len();
        s.push(ALPHA[idx] as char);
    }
    s
}

/// **The P2 false-409 reproduction.** Two UNRELATED documents whose
/// embeddings the model happens to cluster above the 0.95 cosine
/// threshold (the probe on the release MiniLM measured ~28% of noise
/// PAIRS at >= 0.95, max 0.9722 — so at 1k rows essentially every
/// write found such a "near-duplicate") must NOT be classified as a
/// conflict: their contents share no vocabulary, so nothing is being
/// "restated". Pre-#1579 this returned `Some(..)` — the 409 the
/// loadtest measured on 81% of semantic-tier writes.
#[test]
fn a5_1579_false_409_noise_near_duplicate_is_not_a_conflict() {
    let conn = fresh_conn();
    let existing = make_mem("lt-p2sem-0-40", &noise_payload(256, 1), "loadns");
    // Caller-supplied embeddings simulate the model clustering: the
    // two noise documents get the SAME vector (cosine 1.0 >= 0.95).
    let emb = vec![0.6_f32, 0.8, 0.0];
    insert_with_embedding(&conn, &existing, &emb);

    let mut incoming = make_mem("lt-p2sem-0-41", &noise_payload(256, 2), "loadns");
    incoming.id = uuid::Uuid::new_v4().to_string();
    assert_ne!(existing.content, incoming.content, "payloads are distinct");

    let conflict = proactive_conflict_check(&conn, &incoming, &emb).expect("check ok");
    assert!(
        conflict.is_none(),
        "#1579 A5 regression: cosine-clustered noise with disjoint content \
         tokens must NOT 409 (was the 81% false-409 epidemic); got {conflict:?}"
    );
}

/// Counter-pin: a GENUINE restatement (high cosine AND shared content
/// vocabulary) still conflicts — the Jaccard floor must not over-filter.
#[test]
fn a5_1579_genuine_restatement_still_conflicts() {
    let conn = fresh_conn();
    let existing = make_mem(
        "migration-deadline",
        "the deadline for the migration project is june 15",
        "global",
    );
    let emb = vec![1.0_f32, 0.0, 0.0];
    insert_with_embedding(&conn, &existing, &emb);

    let mut incoming = make_mem(
        "migration-deadline-v2",
        "the deadline for the migration project is june 22",
        "global",
    );
    incoming.id = uuid::Uuid::new_v4().to_string();

    let conflict = proactive_conflict_check(&conn, &incoming, &emb)
        .expect("check ok")
        .expect("real restatement must still 409");
    assert_eq!(conflict.existing_title, "migration-deadline");
}

/// The fallback scan is BOUNDED: a near-duplicate older than the
/// `PROACTIVE_CONFLICT_SCAN_LIMIT` most-recently-updated rows is
/// outside the scan horizon (documented advisory miss — the write is
/// ALLOWED), while the HNSW-routed path still finds it.
#[test]
fn a5_1579_bounded_scan_horizon_and_indexed_path() {
    let conn = fresh_conn();
    let ns = "bounded-ns";

    // Oldest row: the genuine near-duplicate (identical embedding,
    // shared-vocabulary differing content).
    let old_conflict = make_mem("seed-fact", "service listens on port 9077", ns);
    let conflict_emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    let conflict_id = insert_with_embedding(&conn, &old_conflict, &conflict_emb);

    // Bury it under LIMIT+8 newer embedded rows that are near-
    // orthogonal to the query (they pass the recency horizon but not
    // the cosine gate). The fillers get slightly-varied vectors —
    // 1000+ byte-identical points would make the ANN graph
    // degenerate, which is not the production shape.
    let mut entries: Vec<(String, Vec<f32>)> = vec![(conflict_id.clone(), conflict_emb.clone())];
    for i in 0..(PROACTIVE_CONFLICT_SCAN_LIMIT + 8) {
        #[allow(clippy::cast_precision_loss)]
        let jitter = (i as f32).mul_add(0.000_1, 0.01);
        let raw = [0.0_f32, 1.0, jitter, 0.0];
        let norm: f32 = raw.iter().map(|v| v * v).sum::<f32>().sqrt();
        let filler_emb: Vec<f32> = raw.iter().map(|v| v / norm).collect();
        let filler = make_mem(&format!("filler-{i}"), &format!("filler body {i}"), ns);
        let fid = insert_with_embedding(&conn, &filler, &filler_emb);
        entries.push((fid, filler_emb));
    }

    let mut incoming = make_mem("seed-fact-restated", "service listens on port 9099", ns);
    incoming.id = uuid::Uuid::new_v4().to_string();

    // Bounded fallback: the conflict row fell off the recency horizon
    // — the write is allowed (the documented safe-direction miss).
    let scan_verdict = proactive_conflict_check(&conn, &incoming, &conflict_emb).expect("scan ok");
    assert!(
        scan_verdict.is_none(),
        "bounded scan must not see beyond its recency horizon"
    );

    // HNSW-routed path: the ANN query surfaces the buried row.
    let idx = VectorIndex::build(entries);
    assert!(idx.is_fully_searchable());
    let indexed_verdict =
        proactive_conflict_check_with_index(&conn, &incoming, &conflict_emb, Some(&idx))
            .expect("indexed ok")
            .expect("indexed path must surface the buried near-duplicate");
    assert_eq!(indexed_verdict.existing_id, conflict_id);
}

/// Namespace + liveness post-filters on the ANN candidate list: a
/// cross-namespace or expired candidate id must not produce a verdict
/// even when the index returned it.
#[test]
fn a5_1579_candidates_path_applies_namespace_and_liveness_filters() {
    let conn = fresh_conn();
    let emb = vec![1.0_f32, 0.0];

    // Cross-namespace near-duplicate.
    let foreign = make_mem("shared-fact", "the answer is 42", "ns-other");
    let foreign_id = insert_with_embedding(&conn, &foreign, &emb);

    // Expired in-namespace near-duplicate.
    let mut expired = make_mem("shared-fact-x", "the answer is 41", "ns-mine");
    expired.expires_at = Some((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339());
    let expired_id = insert_with_embedding(&conn, &expired, &emb);

    let mut incoming = make_mem("shared-fact-new", "the answer is 43", "ns-mine");
    incoming.id = uuid::Uuid::new_v4().to_string();

    let verdict =
        proactive_conflict_check_candidates(&conn, &incoming, &emb, &[foreign_id, expired_id])
            .expect("candidates ok");
    assert!(
        verdict.is_none(),
        "foreign-namespace + expired candidates must be filtered out"
    );
}

/// Dispatch: an index that is NOT fully searchable (the async-boot
/// warm window — entries seeded but no graph swapped in) must be
/// bypassed in favour of the bounded scan, which still finds a recent
/// in-namespace conflict.
#[test]
fn a5_1579_warm_window_falls_back_to_bounded_scan() {
    let conn = fresh_conn();
    let ns = "warm-ns";
    let existing = make_mem("port-fact", "daemon binds port 9077 by default", ns);
    let emb = vec![0.0_f32, 1.0, 0.0];
    let existing_id = insert_with_embedding(&conn, &existing, &emb);

    // Simulate the boot warm window: entries parked via seed_entries,
    // no rebuild yet — search() cannot see them.
    let idx = VectorIndex::empty();
    idx.seed_entries(vec![(existing_id.clone(), emb.clone())]);
    assert!(!idx.is_fully_searchable());

    let mut incoming = make_mem("port-fact-2", "daemon binds port 9099 by default", ns);
    incoming.id = uuid::Uuid::new_v4().to_string();

    let verdict = proactive_conflict_check_with_index(&conn, &incoming, &emb, Some(&idx))
        .expect("ok")
        .expect("warm-window fallback (bounded scan) must find the recent conflict");
    assert_eq!(verdict.existing_id, existing_id);
}

/// #1579 QC — the async-boot LOAD phase, the sub-window BEFORE
/// `seed_entries` lands: the daemon bound with `VectorIndex::empty()`
/// while the boot loader is still reading the stored embeddings. An
/// empty index is VACUOUSLY fully-searchable (`0 + 0 >= 0`), so
/// gating on `is_fully_searchable` alone consulted the empty index,
/// got zero candidates, and silently SKIPPED the conflict check —
/// neither the indexed path nor the documented bounded-scan fallback.
/// The dispatcher must treat empty as "no usable index" and route to
/// the bounded scan, which still finds the recent in-DB conflict.
#[test]
fn a5_1579_empty_index_boot_load_phase_routes_to_bounded_scan() {
    let conn = fresh_conn();
    let ns = "load-phase-ns";
    let existing = make_mem("cache-fact", "cache ttl is sixty seconds", ns);
    let emb = vec![1.0_f32, 0.0, 0.0];
    let existing_id = insert_with_embedding(&conn, &existing, &emb);

    // Boot LOAD phase shape: empty index, nothing seeded yet. Pin the
    // vacuous-truth premise so a future is_fully_searchable change
    // that invalidates this scenario surfaces here.
    let idx = VectorIndex::empty();
    assert!(
        idx.is_fully_searchable(),
        "premise: an empty index reports vacuously fully-searchable"
    );

    let mut incoming = make_mem("cache-fact-2", "cache ttl is ninety seconds", ns);
    incoming.id = uuid::Uuid::new_v4().to_string();

    let verdict = proactive_conflict_check_with_index(&conn, &incoming, &emb, Some(&idx))
        .expect("ok")
        .expect(
            "empty-index dispatch must route to the bounded scan, not silently \
             skip the conflict check (#1579 QC)",
        );
    assert_eq!(verdict.existing_id, existing_id);
}
