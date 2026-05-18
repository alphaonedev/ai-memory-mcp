// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Gap 7 (issue #890) — recall-response Tier-3 decoration
//! regression suite.
//!
//! Acceptance criteria from the playbook:
//!
//! 1. Default `memory_recall` (`verbose_provenance=true`, the v0.7.0
//!    default) returns rows decorated with the full provenance
//!    audit trail: `confidence`, `confidence_tier`, `source`,
//!    `source_uri`, `freshness_state`, `access_count`,
//!    `last_accessed_at` (when set), and `latest_link_attest_level`
//!    (when at least one link is incident on the memory).
//! 2. `verbose_provenance=false` collapses the row to the v0.6.x
//!    shape (no derived fields) for callers that want the trimmed
//!    payload.
//! 3. The token-budget guards (`tests/token_budget_guard.rs`)
//!    continue to pass — the new tool definition and per-row
//!    decoration stay under their respective ceilings.

use ai_memory::config::{ResolvedScoring, ResolvedTtl};
use rusqlite::params;
use serde_json::json;

fn fresh_db() -> rusqlite::Connection {
    ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn seed_memory_full(conn: &rusqlite::Connection, id: &str, source_uri: Option<&str>) {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memories \
            (id, tier, namespace, title, content, confidence, source, source_uri, \
             access_count, created_at, updated_at, last_accessed_at) \
         VALUES (?1, 'long', 'g7', ?2, ?3, 0.92, 'api', ?4, 3, ?5, ?5, ?5)",
        params![
            id,
            format!("title-{id}"),
            format!("payload {id} for gap-7 decoration"),
            source_uri,
            now
        ],
    )
    .expect("seed memory");
    // FTS5 sync — the test bypasses the crate's insert helper for
    // compactness.
    conn.execute(
        "INSERT INTO memories_fts(rowid, title, content) \
         SELECT rowid, title, content FROM memories WHERE id = ?1",
        params![id],
    )
    .ok();
}

#[test]
fn gap7_recall_row_carries_full_provenance_block_by_default() {
    let conn = fresh_db();
    seed_memory_full(&conn, "m-gap7-a", Some("doc:gap-7-spec#para-1"));
    seed_memory_full(&conn, "m-gap7-b", None);

    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();
    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &json!({"context": "decoration", "namespace": "g7"}),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");

    let memories = resp["memories"]
        .as_array()
        .expect("recall response carries memories array");
    assert!(!memories.is_empty(), "expected at least one row");

    let row = &memories[0];
    // Base substrate columns serialized via Memory's serde derive.
    assert!(row["confidence"].is_number(), "confidence present");
    assert!(row["source"].is_string(), "source present");
    assert!(row["access_count"].is_number(), "access_count present");
    assert!(
        row["last_accessed_at"].is_string(),
        "last_accessed_at present (seeded above)"
    );
    // Gap 7 derived decoration:
    assert!(
        row["confidence_tier"].is_string(),
        "Gap 7: confidence_tier decoration present"
    );
    assert!(
        row["freshness_state"].is_string(),
        "Gap 7: freshness_state decoration present"
    );

    // The recall envelope echoes the Gap 3 recall_id so the caller
    // can cite it on a downstream store/link.
    assert!(
        resp["recall_id"].is_string() && !resp["recall_id"].as_str().unwrap().is_empty(),
        "Gap 3: recall_id echoed in the response envelope"
    );
}

#[test]
fn gap7_verbose_provenance_false_collapses_to_legacy_shape() {
    let conn = fresh_db();
    seed_memory_full(&conn, "m-gap7-c", None);

    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();
    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &json!({
            "context": "decoration",
            "namespace": "g7",
            "verbose_provenance": false,
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");

    let memories = resp["memories"].as_array().unwrap();
    assert!(!memories.is_empty());
    let row = &memories[0];
    // Substrate columns still present (they ride on Memory's serde).
    assert!(row["confidence"].is_number());
    // Gap 7 derived decoration MUST be absent on this branch.
    assert!(
        row.get("confidence_tier").is_none(),
        "verbose_provenance=false ⇒ no confidence_tier decoration"
    );
    assert!(
        row.get("freshness_state").is_none(),
        "verbose_provenance=false ⇒ no freshness_state decoration"
    );
    assert!(
        row.get("latest_link_attest_level").is_none(),
        "verbose_provenance=false ⇒ no latest_link_attest_level decoration"
    );
}

#[test]
fn gap7_token_budget_guard_still_passes_post_decoration() {
    // Pin the post-Gap-7 catalog totals so the new tool definition
    // (`memory_recall_observations`) + extended `memory_recall`
    // schema can't blow the operator-agreed budgets. The
    // `token_budget_guard` integration test enforces the same
    // ceiling end-to-end; this regression test re-runs the
    // computations directly so a guard regression surfaces in this
    // suite too.
    let trimmed = ai_memory::sizes::trimmed_full_profile_total_tokens();
    let verbose = ai_memory::sizes::full_profile_total_tokens();
    assert!(
        trimmed <= 5_000,
        "Gap 7 regression: trimmed full-profile total {trimmed} exceeds the 5000-token ceiling"
    );
    assert!(
        verbose <= 10_000,
        "Gap 7 regression: verbose full-profile total {verbose} exceeds the 10000-token ceiling"
    );
}
