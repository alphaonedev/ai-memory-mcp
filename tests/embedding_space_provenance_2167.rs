// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2167 — embedding vector-space provenance acceptance tests.
//!
//! These are the invariant proofs (§10): recall NEVER scores a stored
//! vector from a different embedding space, and a NULL-provenance
//! (unverified) vector is excluded from semantic scoring while staying
//! keyword-recallable. Plus the §5 boot-adoption [G1]/[G2] rule.
//!
//! sqlite path here; the postgres twin rides `sal-postgres`
//! (`#[ignore]` + `--include-ignored`) — see the pg `<=>` predicate +
//! its site-count pin.
//!
//! Run: `AI_MEMORY_NO_CONFIG=1 cargo test --test embedding_space_provenance_2167`

use ai_memory::db;
use ai_memory::embeddings::embedding_space_fingerprint;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;

fn fresh_db() -> (rusqlite::Connection, std::path::PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("embedding-space-2167");
    std::fs::create_dir_all(&root).ok();
    let path = root.join(format!("ai-memory-2167-{}.db", uuid::Uuid::new_v4()));
    let conn = db::open(&path).expect("open fresh test db");
    (conn, path)
}

fn make_memory(title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: format!("test-{}", uuid::Uuid::new_v4()),
        tier: Tier::Long,
        namespace: "test".to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({}),
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

/// Seed a row with a raw embedding stamped to `space`. Returns its id.
fn seed_embedded(conn: &rusqlite::Connection, title: &str, emb: &[f32], space: &str) -> String {
    let id = db::insert(conn, &make_memory(title, "corpus body no-fts-hit-token")).unwrap();
    db::set_embedding(conn, &id, emb, space).unwrap();
    id
}

/// Seed a row whose embedding is written by RAW SQL (bypassing
/// `set_embedding`'s per-namespace dim-consistency guard) so a
/// deliberately cross-dim row can co-exist with the active-dim corpus.
fn seed_embedded_raw(
    conn: &rusqlite::Connection,
    title: &str,
    emb: &[f32],
    space: Option<&str>,
) -> String {
    let id = db::insert(conn, &make_memory(title, "corpus body no-fts-hit-token")).unwrap();
    let blob = ai_memory::embeddings::encode_embedding_blob(emb);
    conn.execute(
        "UPDATE memories SET embedding = ?1, embedding_dim = ?2, embedding_space = ?3 WHERE id = ?4",
        rusqlite::params![blob, i64::try_from(emb.len()).unwrap(), space, id],
    )
    .unwrap();
    id
}

/// Force a row's `embedding_space` to SQL NULL (a legacy / manually-
/// surgeried unverified row) — `set_embedding` always stamps, so we NULL
/// it out afterwards.
fn null_out_space(conn: &rusqlite::Connection, id: &str) {
    conn.execute(
        "UPDATE memories SET embedding_space = NULL WHERE id = ?1",
        rusqlite::params![id],
    )
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn recall(
    conn: &rusqlite::Connection,
    context: &str,
    query_emb: &[f32],
    active: Option<&str>,
) -> (Vec<(Memory, f64)>, ai_memory::models::RecallTelemetry) {
    let scoring = ai_memory::config::ResolvedScoring::default();
    let (results, _outcome, telemetry) = db::recall_hybrid_with_telemetry(
        conn,
        context,
        query_emb,
        Some("test"),
        50,
        None,
        None,
        None,
        None, // vector_index=None -> linear-scan semantic path
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        &scoring,
        false,
        None,
        None,   // caller
        active, // #2167 active space fingerprint
    )
    .expect("recall_hybrid_with_telemetry");
    (results, telemetry)
}

// ---------------------------------------------------------------------------
// T-INV-1 — the recall gate: semantic results NEVER contain a foreign- or
// NULL-fingerprint row; counts reconcile exactly with the seeded population.
// ---------------------------------------------------------------------------

#[test]
fn t_inv_1_semantic_never_scores_foreign_or_null_space() {
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text"); // dim-agnostic token
    let foreign = embedding_space_fingerprint("granite-embedding"); // same dim, DIFFERENT space
    assert_ne!(active, foreign);

    let qe = [1.0_f32, 0.0, 0.0, 0.0];

    // 3 active-space rows (cosine 1.0 → the ONLY rows that may be scored).
    let a1 = seed_embedded(&conn, "active one", &qe, &active);
    let a2 = seed_embedded(&conn, "active two", &qe, &active);
    let a3 = seed_embedded(&conn, "active three", &qe, &active);
    // 2 foreign same-dim rows (dim gate passes; space gate must exclude).
    seed_embedded(&conn, "foreign one", &qe, &foreign);
    seed_embedded(&conn, "foreign two", &qe, &foreign);
    // 1 NULL-provenance row (unverified).
    let n1 = seed_embedded(&conn, "null one", &qe, &active);
    null_out_space(&conn, &n1);
    // 1 cross-dim active-space row (space matches, dim disagrees → dim
    // gate). Raw-seeded to bypass set_embedding's per-namespace dim guard.
    seed_embedded_raw(&conn, "active cross dim", &[1.0_f32, 0.0], Some(&active));

    // Context matches no content (no FTS hits) → semantic phase is the
    // ONLY source, so the returned set is exactly the scored set.
    let (results, tel) = recall(&conn, "zzznoftshitzzz", &qe, Some(&active));

    let ids: std::collections::HashSet<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert_eq!(
        ids,
        [a1.as_str(), a2.as_str(), a3.as_str()].into_iter().collect(),
        "semantic recall must return ONLY active-space rows; got {ids:?}"
    );
    // Counts reconcile with the seeded population.
    assert_eq!(tel.embedding_space_mismatch, 2, "2 foreign-space rows excluded + counted");
    assert_eq!(tel.embedding_unverified_space, 1, "1 NULL-space row excluded + counted");
    assert_eq!(tel.embedding_dim_mismatch, 1, "1 cross-dim active row excluded + counted");
}

#[test]
fn t_inv_1_foreign_row_stays_keyword_recallable_degraded_not_invisible() {
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding");
    let qe = [1.0_f32, 0.0, 0.0, 0.0];

    // A foreign-space row whose CONTENT matches the FTS query.
    let fid = db::insert(&conn, &make_memory("kubernetes readiness probe", "kubernetes readiness")).unwrap();
    db::set_embedding(&conn, &fid, &qe, &foreign).unwrap();

    let (results, tel) = recall(&conn, "kubernetes readiness", &qe, Some(&active));
    let ids: Vec<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert!(
        ids.contains(&fid.as_str()),
        "a foreign-space row must stay KEYWORD-recallable (degraded, not invisible); got {ids:?}"
    );
    assert_eq!(
        tel.embedding_space_mismatch, 1,
        "its semantic cosine is forced to 0.0 + counted (excluded from SEMANTIC scoring)"
    );
}

#[test]
fn t_inv_1_none_active_skips_gate_legacy_dim_only() {
    // With no active fingerprint (keyword-only / no embedder) the space
    // gate is skipped — pre-#2167 dim-only behavior. A same-dim foreign
    // row IS scored (no space to gate against).
    let (conn, _p) = fresh_db();
    let foreign = embedding_space_fingerprint("granite-embedding");
    let qe = [1.0_f32, 0.0, 0.0, 0.0];
    let fid = seed_embedded(&conn, "foreign scored when active none", &qe, &foreign);
    let (results, tel) = recall(&conn, "zzznoftshitzzz", &qe, None);
    let ids: Vec<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert!(ids.contains(&fid.as_str()), "None active -> no space gate -> row scored");
    assert_eq!(tel.embedding_space_mismatch, 0);
    assert_eq!(tel.embedding_unverified_space, 0);
}

// ---------------------------------------------------------------------------
// T-funnel — the write funnel stamps vector + space in one statement.
// ---------------------------------------------------------------------------

#[test]
fn t_funnel_set_embedding_stamps_active_space() {
    let (conn, _p) = fresh_db();
    let fp = embedding_space_fingerprint("nomic-embed-text");
    let id = db::insert(&conn, &make_memory("funnel", "body")).unwrap();
    db::set_embedding(&conn, &id, &[0.1_f32, 0.2, 0.3, 0.4], &fp).unwrap();
    let stamped: Option<String> = conn
        .query_row(
            "SELECT embedding_space FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stamped.as_deref(), Some(fp.as_str()), "vector + space stamped together");
}

// ---------------------------------------------------------------------------
// T-INV-2 (adoption) — the §5 [G1]/[G2] rule.
// ---------------------------------------------------------------------------

#[test]
fn adoption_a_stamps_null_dim_matching_rows() {
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    // Two embedded rows with NULL provenance at the active dim (4).
    let r1 = seed_embedded(&conn, "legacy one", &[1.0_f32, 0.0, 0.0, 0.0], &active);
    let r2 = seed_embedded(&conn, "legacy two", &[0.0_f32, 1.0, 0.0, 0.0], &active);
    null_out_space(&conn, &r1);
    null_out_space(&conn, &r2);

    let stamped = db::adopt_legacy_embedding_space(&conn, &active, 4).unwrap();
    assert_eq!(stamped, 2, "no-nuke: both dim-matching NULL rows adopted");
    let census = db::distinct_embedding_spaces(&conn, None).unwrap();
    assert_eq!(census, vec![(Some(active), 2)], "corpus is now homogeneous-active");
}

#[test]
fn adoption_d_g2_refuses_on_mixed_history() {
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding");
    // A row already stamped in a DIFFERENT space proves multi-space history.
    seed_embedded(&conn, "foreign stamped", &[1.0_f32, 0.0, 0.0, 0.0], &foreign);
    // A NULL row that adoption would otherwise stamp.
    let nid = seed_embedded(&conn, "null candidate", &[0.0_f32, 1.0, 0.0, 0.0], &active);
    null_out_space(&conn, &nid);

    let stamped = db::adopt_legacy_embedding_space(&conn, &active, 4).unwrap();
    assert_eq!(stamped, 0, "[G2]: mixed-history corpus never auto-adopts");
    let still_null: Option<String> = conn
        .query_row(
            "SELECT embedding_space FROM memories WHERE id = ?1",
            rusqlite::params![nid],
            |r| r.get(0),
        )
        .unwrap();
    assert!(still_null.is_none(), "the NULL row stays excluded until reembed");
}

#[test]
fn adoption_e_g1_strict_disables_adoption() {
    // [G1] — strict mode OFF is required for adoption; boot maintenance
    // must NOT stamp under strict.
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let nid = seed_embedded(&conn, "null under strict", &[1.0_f32, 0.0, 0.0, 0.0], &active);
    null_out_space(&conn, &nid);

    ai_memory::hnsw::set_strict_embed_model_match_for_test(Some(true));
    db::embedding_space_boot_maintenance(&conn, &active, 4);
    ai_memory::hnsw::set_strict_embed_model_match_for_test(None);

    let still_null: Option<String> = conn
        .query_row(
            "SELECT embedding_space FROM memories WHERE id = ?1",
            rusqlite::params![nid],
            |r| r.get(0),
        )
        .unwrap();
    assert!(still_null.is_none(), "[G1] strict: adoption disabled, NULL row untouched");
}

#[test]
fn adoption_dim_mismatch_row_not_stamped() {
    // A NULL row at a NON-active dim is never adopted (it is a genuinely
    // different-space vector; only reembed can heal it).
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let good = seed_embedded(&conn, "dim ok", &[1.0_f32, 0.0, 0.0, 0.0], &active);
    let bad = seed_embedded_raw(&conn, "dim off", &[1.0_f32, 0.0], None);
    null_out_space(&conn, &good);

    let stamped = db::adopt_legacy_embedding_space(&conn, &active, 4).unwrap();
    assert_eq!(stamped, 1, "only the dim-matching NULL row is adopted");
    let bad_space: Option<String> = conn
        .query_row(
            "SELECT embedding_space FROM memories WHERE id = ?1",
            rusqlite::params![bad],
            |r| r.get(0),
        )
        .unwrap();
    assert!(bad_space.is_none(), "the non-active-dim NULL row stays excluded");
}
