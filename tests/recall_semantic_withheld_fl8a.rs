// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! F-L8a (#2167 follow-up) — the in-band `meta.semantic_withheld` recall
//! signal.
//!
//! The correctness danger (recall scoring a foreign / unverified / dim-
//! mismatched vector) is already CLOSED by #2167 — such rows are excluded
//! from semantic scoring and stay keyword-recallable. What was MISSING is
//! an in-band signal that `mode:"hybrid"` served fewer semantically-scored
//! rows than the corpus holds: on MCP stdio there is no `/metrics`, so the
//! daemon's tracing WARN is invisible to a JSON-only NHI. This test proves
//! the additive `meta.semantic_withheld` block populates from the already-
//! computed recall telemetry when a mismatch occurs, and reports a truthful
//! measured zero otherwise.
//!
//! R-203: at the parent commit `RecallMeta` carried no `semantic_withheld`
//! field, so `resp["meta"]["semantic_withheld"]` was ABSENT — every
//! assertion below on that path fails pre-fix.
//!
//! Run: `AI_MEMORY_NO_CONFIG=1 cargo test --test recall_semantic_withheld_fl8a`

use ai_memory::config::{ResolvedScoring, ResolvedTtl};
use ai_memory::db;
use ai_memory::embeddings::{Embed, embedding_space_fingerprint};
use ai_memory::mcp::handle_recall;
use ai_memory::models::{
    ConfidenceSource, Memory, MemoryKind, RecallTelemetry, SemanticWithheld, Tier,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Fixtures — mirror the #2167 acceptance-test seeding so the withheld counts
// reconcile with a known population.
// ---------------------------------------------------------------------------

fn fresh_db() -> (rusqlite::Connection, std::path::PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("recall-semantic-withheld-fl8a");
    std::fs::create_dir_all(&root).ok();
    let path = root.join(format!("ai-memory-fl8a-{}.db", uuid::Uuid::new_v4()));
    let conn = db::open(&path).expect("open fresh test db");
    (conn, path)
}

fn make_memory(title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: format!("fl8a-{}", uuid::Uuid::new_v4()),
        tier: Tier::Long,
        namespace: "test".to_string(),
        title: title.to_string(),
        // Deliberately no overlap with the recall context token below, so
        // FTS returns nothing and the SEMANTIC phase is the only source —
        // the returned set is then exactly the scored set.
        content: "corpus body no-fts-hit-token".to_string(),
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

/// Seed a row with a raw embedding stamped to `space` (via the guarded
/// `set_embedding`). Returns its id.
fn seed_embedded(conn: &rusqlite::Connection, title: &str, emb: &[f32], space: &str) -> String {
    let id = db::insert(conn, &make_memory(title)).unwrap();
    db::set_embedding(conn, &id, emb, space).unwrap();
    id
}

/// Seed a cross-dim row via RAW SQL (bypassing `set_embedding`'s per-
/// namespace dim guard) so a deliberately dim-mismatched row can co-exist.
fn seed_embedded_raw(conn: &rusqlite::Connection, title: &str, emb: &[f32], space: &str) -> String {
    let id = db::insert(conn, &make_memory(title)).unwrap();
    let blob = ai_memory::embeddings::encode_embedding_blob(emb);
    conn.execute(
        "UPDATE memories SET embedding = ?1, embedding_dim = ?2, embedding_space = ?3 WHERE id = ?4",
        rusqlite::params![blob, i64::try_from(emb.len()).unwrap(), space, id],
    )
    .unwrap();
    id
}

/// Force a row's `embedding_space` to SQL NULL (an unverified row).
fn null_out_space(conn: &rusqlite::Connection, id: &str) {
    conn.execute(
        "UPDATE memories SET embedding_space = NULL WHERE id = ?1",
        rusqlite::params![id],
    )
    .unwrap();
}

/// A deterministic embedder returning a FIXED 4-dim query vector and a
/// caller-chosen active space fingerprint. Leaves `query_cache_space` at the
/// default `None` so the process-global #2577 query-embed cache is NOT
/// consulted (no cross-test interference).
struct FixedEmbedder {
    space: String,
}

impl Embed for FixedEmbedder {
    fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
        // cosine 1.0 with every active-space seed row → all pass the gate.
        Ok(vec![1.0, 0.0, 0.0, 0.0])
    }
    fn space_fingerprint(&self) -> String {
        self.space.clone()
    }
}

fn ttl() -> ResolvedTtl {
    ResolvedTtl::default()
}
fn scoring() -> ResolvedScoring {
    ResolvedScoring::default()
}

// ---------------------------------------------------------------------------
// The behavioral proof: the field POPULATES on a mismatch corpus.
// ---------------------------------------------------------------------------

#[test]
fn mcp_recall_meta_reports_semantic_withheld_on_mismatch_corpus() {
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding"); // same dim, different space
    assert_ne!(active, foreign);
    let qe = [1.0_f32, 0.0, 0.0, 0.0];

    // 3 active-space rows (the ONLY rows that may be semantically scored).
    seed_embedded(&conn, "active one", &qe, &active);
    seed_embedded(&conn, "active two", &qe, &active);
    seed_embedded(&conn, "active three", &qe, &active);
    // 2 foreign same-dim rows (dim gate passes; SPACE gate must exclude).
    seed_embedded(&conn, "foreign one", &qe, &foreign);
    seed_embedded(&conn, "foreign two", &qe, &foreign);
    // 1 NULL-provenance (unverified) row.
    let n1 = seed_embedded(&conn, "null one", &qe, &active);
    null_out_space(&conn, &n1);
    // 1 cross-dim active-space row (space matches, dim disagrees → dim gate).
    seed_embedded_raw(&conn, "active cross dim", &[1.0_f32, 0.0], &active);

    let emb = FixedEmbedder {
        space: active.clone(),
    };
    // Context matches no content (no FTS hits) → semantic phase is the ONLY
    // source, so the returned set is exactly the scored set.
    let resp = handle_recall(
        &conn,
        &json!({ "context": "zzznoftshitzzz", "namespace": "test" }),
        Some(&emb as &dyn Embed),
        None,
        None,
        false,
        &ttl(),
        &scoring(),
        None,
    )
    .expect("recall must succeed");

    // mode is UNCHANGED — still hybrid (this is the additive-not-breaking
    // contract: the withheld block is a NEW signal, not a mode reinterpret).
    assert_eq!(
        resp["mode"].as_str(),
        Some("hybrid"),
        "mode must stay hybrid; got: {resp}"
    );

    let sw = &resp["meta"]["semantic_withheld"];
    assert_eq!(
        sw["measured"].as_bool(),
        Some(true),
        "sqlite MCP recall is a MEASURED path; got: {resp}"
    );
    assert_eq!(
        sw["space_mismatch"].as_u64(),
        Some(2),
        "2 foreign-space rows excluded + counted; got: {sw}"
    );
    assert_eq!(
        sw["unverified_space"].as_u64(),
        Some(1),
        "1 NULL-space row excluded + counted; got: {sw}"
    );
    assert_eq!(
        sw["dim_mismatch"].as_u64(),
        Some(1),
        "1 cross-dim active row excluded + counted; got: {sw}"
    );
    assert_eq!(
        sw["total"].as_u64(),
        Some(4),
        "total is the sum of the three causes; got: {sw}"
    );
    // Only the 3 active-space rows made it into the ranking.
    assert_eq!(
        resp["count"].as_u64(),
        Some(3),
        "only active-space rows scored; got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// ... and is a truthful measured ZERO on a clean homogeneous corpus.
// ---------------------------------------------------------------------------

#[test]
fn mcp_recall_meta_reports_zero_withheld_on_clean_corpus() {
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let qe = [1.0_f32, 0.0, 0.0, 0.0];
    seed_embedded(&conn, "active one", &qe, &active);
    seed_embedded(&conn, "active two", &qe, &active);

    let emb = FixedEmbedder {
        space: active.clone(),
    };
    let resp = handle_recall(
        &conn,
        &json!({ "context": "zzznoftshitzzz", "namespace": "test" }),
        Some(&emb as &dyn Embed),
        None,
        None,
        false,
        &ttl(),
        &scoring(),
        None,
    )
    .expect("recall must succeed");

    let sw = &resp["meta"]["semantic_withheld"];
    assert_eq!(sw["measured"].as_bool(), Some(true));
    assert_eq!(
        sw["total"].as_u64(),
        Some(0),
        "a homogeneous active-space corpus withholds nothing; got: {sw}"
    );
    assert_eq!(sw["space_mismatch"].as_u64(), Some(0));
    assert_eq!(sw["unverified_space"].as_u64(), Some(0));
    assert_eq!(sw["dim_mismatch"].as_u64(), Some(0));
}

// ---------------------------------------------------------------------------
// Keyword-only recall (no embedder) — no semantic scoring ran, so the block
// is present and a truthful measured zero (never absent, never a lie).
// ---------------------------------------------------------------------------

#[test]
fn mcp_recall_meta_semantic_withheld_present_and_zero_on_keyword_only() {
    let (conn, _p) = fresh_db();
    db::insert(&conn, &make_memory("kw needle title")).unwrap();

    let resp = handle_recall(
        &conn,
        &json!({ "context": "no-fts-hit-token", "namespace": "test" }),
        None, // no embedder → keyword-only path
        None,
        None,
        false,
        &ttl(),
        &scoring(),
        None,
    )
    .expect("recall must succeed");

    let sw = &resp["meta"]["semantic_withheld"];
    assert_eq!(
        sw["measured"].as_bool(),
        Some(true),
        "keyword-only is still a MEASURED sqlite path; got: {resp}"
    );
    assert_eq!(
        sw["total"].as_u64(),
        Some(0),
        "no semantic scoring ran → nothing withheld from it; got: {sw}"
    );
}

// ---------------------------------------------------------------------------
// Unit: the honesty contract of the wire shape itself.
// ---------------------------------------------------------------------------

#[test]
fn semantic_withheld_measured_maps_telemetry_counters() {
    let telemetry = RecallTelemetry {
        embedding_space_mismatch: 2,
        embedding_unverified_space: 1,
        embedding_dim_mismatch: 3,
        ..RecallTelemetry::default()
    };
    let v = serde_json::to_value(SemanticWithheld::measured(&telemetry)).unwrap();
    assert_eq!(v["measured"], json!(true));
    assert_eq!(v["space_mismatch"], json!(2));
    assert_eq!(v["unverified_space"], json!(1));
    assert_eq!(v["dim_mismatch"], json!(3));
    assert_eq!(v["total"], json!(6), "total = 2 + 1 + 3");
}

#[test]
fn semantic_withheld_unmeasured_omits_numeric_fields_never_fabricates_zero() {
    // The postgres SAL recall path excludes foreign-space rows in SQL but
    // does not count them; emitting `0` would be a WRONG result on the wire.
    // The honest shape carries the discriminator and NO numeric keys.
    let v = serde_json::to_value(SemanticWithheld::unmeasured()).unwrap();
    assert_eq!(v["measured"], json!(false));
    let obj = v.as_object().expect("object");
    assert_eq!(
        obj.len(),
        1,
        "unmeasured block must be exactly {{measured:false}} — no fabricated \
         counts; got: {v}"
    );
    assert!(obj.get("space_mismatch").is_none());
    assert!(obj.get("total").is_none());
}
