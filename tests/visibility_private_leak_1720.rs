// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! v0.8.0 #1709/#1720 Workstream-A (unit A6) — cross-tenant
//! `scope=private` leak regression on the low-level storage read
//! predicates.
//!
//! ## The bug (pre-A2/A3/A4)
//!
//! Two of the three visibility predicates were **namespace-keyed**,
//! not **owner-keyed**:
//!
//!   * `storage::visibility_clause` private arm was
//!     `(scope_idx='private' AND namespace = ?private_ph)` — so ANY
//!     caller operating in the same namespace (`as_agent`) matched.
//!   * `storage::is_visible` (the HNSW Rust-side branch of
//!     `recall_hybrid`) checked `&mem.namespace == ns` for the
//!     `Private` arm — same namespace-keyed leak.
//!
//! Concretely: alice stores a `scope=private` row in namespace
//! `fortitude/X` (`metadata.agent_id = ai:alice`). bob recalls/searches
//! that same namespace as `as_agent = "fortitude/X"` with visibility
//! caller `ai:bob`. Because the SQL/Rust predicates only compared the
//! namespace (which matches), bob received alice's private row.
//!
//! The canonical, correct predicate is owner-keyed:
//! [`ai_memory::visibility::is_visible_to_caller`] — visible iff scope
//! is non-private, OR `metadata.agent_id == caller`, OR
//! `metadata.target_agent_id == caller` (inbox carve-out). A2/A3/A4
//! thread a `caller: Option<&str>` through `recall` / `search` /
//! `recall_hybrid` and make ALL THREE predicates owner-keyed.
//!
//! These tests exercise the **storage predicates directly** (not the
//! MCP post-filter, which #1468 already closed) across all three
//! retrieval paths: keyword recall, FTS search, and hybrid (HNSW +
//! linear-SQL semantic). On the pre-fix tree the `bob_*_leak` tests
//! FAIL (bob sees alice's row); post-fix they PASS.

use ai_memory::config::ResolvedScoring;
use ai_memory::hnsw::VectorIndex;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier, namespace::MemoryScope};
use rusqlite::params;
use serde_json::json;

const NS: &str = "fortitude/X";
const ALICE: &str = "ai:alice";
const BOB: &str = "ai:bob";
/// Shared content token so the FTS `MATCH` fires on every seeded row.
const NEEDLE: &str = "needle";

fn fresh_db() -> rusqlite::Connection {
    ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// Build a memory in `NS` with explicit `agent_id`, optional `scope`,
/// and optional `target_agent_id` (inbox carve-out), carrying the
/// shared FTS needle in its content.
fn mem(
    id: &str,
    owner: Option<&str>,
    scope: Option<&str>,
    target_agent_id: Option<&str>,
) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = serde_json::Map::new();
    if let Some(o) = owner {
        metadata.insert(ai_memory::META_KEY_AGENT_ID.to_string(), json!(o));
    }
    if let Some(s) = scope {
        metadata.insert(ai_memory::META_KEY_SCOPE.to_string(), json!(s));
    }
    if let Some(t) = target_agent_id {
        metadata.insert(ai_memory::META_KEY_TARGET_AGENT_ID.to_string(), json!(t));
    }
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: id.to_string(),
        content: format!("{NEEDLE} content for {id}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::Value::Object(metadata),
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

/// Attach a deterministic embedding so the HNSW + semantic-SQL phases
/// of `recall_hybrid` admit the row past the cosine gate.
fn attach_embedding(conn: &rusqlite::Connection, id: &str, embedding: &[f32]) {
    let blob = ai_memory::embeddings::encode_embedding_blob(embedding);
    let dim = i64::try_from(embedding.len()).expect("dim fits i64");
    conn.execute(
        "UPDATE memories SET embedding = ?1, embedding_dim = ?2 WHERE id = ?3",
        params![blob, dim, id],
    )
    .expect("attach embedding");
}

fn ids(results: &[(Memory, f64)]) -> Vec<String> {
    results.iter().map(|(m, _)| m.id.clone()).collect()
}

fn search_ids(results: &[Memory]) -> Vec<String> {
    results.iter().map(|m| m.id.clone()).collect()
}

// ---------------------------------------------------------------------------
// recall (keyword) path
// ---------------------------------------------------------------------------

fn do_recall(conn: &rusqlite::Connection, caller: Option<&str>) -> Vec<(Memory, f64)> {
    let (results, _outcome) = ai_memory::db::recall(
        conn,
        NEEDLE,
        Some(NS),
        50,
        None,
        None,
        None,
        300,
        86_400,
        Some(NS), // as_agent == namespace (bob & alice operate in fortitude/X)
        None,
        false,
        None,
        caller,
        None, // #1834 valid_at
    )
    .expect("recall ok");
    results
}

#[test]
fn recall_bob_does_not_see_alice_private_leak_1720() {
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    let got = do_recall(&conn, Some(BOB));
    assert!(
        !ids(&got).contains(&"alice-priv".to_string()),
        "#1720 LEAK: bob (caller=ai:bob) must NOT see alice's scope=private row \
         in shared namespace via recall; got={:?}",
        ids(&got)
    );
    assert!(
        got.is_empty(),
        "bob should see nothing; got={:?}",
        ids(&got)
    );
}

#[test]
fn recall_default_private_excluded_for_non_owner_1720() {
    // No scope key => defaults to private per the NHI contract.
    let conn = fresh_db();
    ai_memory::db::insert(&conn, &mem("alice-default", Some(ALICE), None, None)).expect("insert");
    let got = do_recall(&conn, Some(BOB));
    assert!(
        got.is_empty(),
        "#1720: a no-scope (default-private) row must be excluded for a non-owner; got={:?}",
        ids(&got)
    );
}

#[test]
fn recall_owner_sees_own_private_1720() {
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    let got = do_recall(&conn, Some(ALICE));
    assert_eq!(
        ids(&got),
        vec!["alice-priv".to_string()],
        "owner (caller=ai:alice) MUST retrieve her own private row"
    );
}

#[test]
fn recall_target_agent_inbox_carveout_1720() {
    // alice stamps target_agent_id=bob on a private row => bob (the
    // recipient) reads it even though alice owns it.
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "inbox",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            Some(BOB),
        ),
    )
    .expect("insert");
    let got = do_recall(&conn, Some(BOB));
    assert_eq!(
        ids(&got),
        vec!["inbox".to_string()],
        "inbox carve-out: target_agent_id=bob MUST let bob read alice's private inbox row"
    );
}

#[test]
fn recall_collective_visible_to_all_1720() {
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "coll",
            Some(ALICE),
            Some(MemoryScope::Collective.as_str()),
            None,
        ),
    )
    .expect("insert");
    let got = do_recall(&conn, Some(BOB));
    assert_eq!(
        ids(&got),
        vec!["coll".to_string()],
        "a collective row MUST be visible cross-tenant"
    );
}

#[test]
fn recall_null_caller_sees_no_private_fail_closed_1720() {
    // No identity (caller=None) must match NO private rows: fail-closed.
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    let got = do_recall(&conn, None);
    assert!(
        got.is_empty(),
        "#1720 fail-closed: a NULL caller (no identity) must see NO private rows; got={:?}",
        ids(&got)
    );
}

#[test]
fn recall_team_scope_same_subtree_still_works_1720() {
    // Regression guard against placeholder-bind breakage on the
    // team/unit/org arms: a team-scope row in NS must be visible to a
    // caller operating in the same subtree.
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem("team", Some(ALICE), Some(MemoryScope::Team.as_str()), None),
    )
    .expect("insert");
    // bob operates in the same namespace subtree (fortitude/X) — the
    // team arm is namespace-keyed by design, so bob sees it.
    let got = do_recall(&conn, Some(BOB));
    assert_eq!(
        ids(&got),
        vec!["team".to_string()],
        "team-scope row MUST remain visible to a same-subtree caller (no placeholder-bind regression)"
    );
}

// ---------------------------------------------------------------------------
// search (FTS) path
// ---------------------------------------------------------------------------

fn do_search(conn: &rusqlite::Connection, caller: Option<&str>) -> Vec<Memory> {
    ai_memory::db::search(
        conn,
        NEEDLE,
        Some(NS),
        None,
        50,
        None,
        None,
        None,
        None,
        None,
        Some(NS), // as_agent == namespace
        false,
        caller,
    )
    .expect("search ok")
}

#[test]
fn search_bob_does_not_see_alice_private_leak_1720() {
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    let got = do_search(&conn, Some(BOB));
    assert!(
        !search_ids(&got).contains(&"alice-priv".to_string()),
        "#1720 LEAK: bob must NOT see alice's scope=private row via search; got={:?}",
        search_ids(&got)
    );
    assert!(
        got.is_empty(),
        "bob should see nothing; got={:?}",
        search_ids(&got)
    );
}

#[test]
fn search_owner_sees_own_private_1720() {
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    let got = do_search(&conn, Some(ALICE));
    assert_eq!(search_ids(&got), vec!["alice-priv".to_string()]);
}

#[test]
fn search_collective_visible_to_all_1720() {
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "coll",
            Some(ALICE),
            Some(MemoryScope::Collective.as_str()),
            None,
        ),
    )
    .expect("insert");
    let got = do_search(&conn, Some(BOB));
    assert_eq!(search_ids(&got), vec!["coll".to_string()]);
}

#[test]
fn search_null_caller_fail_closed_1720() {
    let conn = fresh_db();
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    let got = do_search(&conn, None);
    assert!(
        got.is_empty(),
        "fail-closed: NULL caller sees no private; got={:?}",
        search_ids(&got)
    );
}

// ---------------------------------------------------------------------------
// recall_hybrid path — both the HNSW Rust branch (is_visible) and the
// linear-scan semantic SQL branch (visibility_clause).
// ---------------------------------------------------------------------------

fn do_hybrid(
    conn: &rusqlite::Connection,
    query_emb: &[f32],
    index: Option<&dyn ai_memory::hnsw::VectorSearchIndex>,
    caller: Option<&str>,
) -> Vec<(Memory, f64)> {
    let scoring = ResolvedScoring::default();
    let (results, _outcome) = ai_memory::db::recall_hybrid(
        conn,
        NEEDLE,
        query_emb,
        Some(NS),
        50,
        None,
        None,
        None,
        index,
        300,
        86_400,
        Some(NS),
        None,
        &scoring,
        false,
        None,
        caller,
        None,
        None, // #1834 valid_at
    )
    .expect("recall_hybrid ok");
    results
}

#[test]
fn hybrid_hnsw_bob_does_not_see_alice_private_leak_1720() {
    // HNSW branch: index present => is_visible() Rust predicate gates.
    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    attach_embedding(&conn, "alice-priv", &emb);
    let index = VectorIndex::build(vec![("alice-priv".to_string(), emb.clone())]);
    let got = do_hybrid(&conn, &emb, Some(&index), Some(BOB));
    assert!(
        !ids(&got).contains(&"alice-priv".to_string()),
        "#1720 LEAK (HNSW/is_visible): bob must NOT see alice's private row; got={:?}",
        ids(&got)
    );
}

#[test]
fn hybrid_linear_bob_does_not_see_alice_private_leak_1720() {
    // Linear-scan branch: no HNSW index => visibility_clause SQL gates
    // on the semantic phase.
    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    attach_embedding(&conn, "alice-priv", &emb);
    let got = do_hybrid(&conn, &emb, None, Some(BOB));
    assert!(
        !ids(&got).contains(&"alice-priv".to_string()),
        "#1720 LEAK (linear-SQL/visibility_clause): bob must NOT see alice's private row; got={:?}",
        ids(&got)
    );
}

#[test]
fn hybrid_owner_sees_own_private_both_branches_1720() {
    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    ai_memory::db::insert(
        &conn,
        &mem(
            "alice-priv",
            Some(ALICE),
            Some(MemoryScope::Private.as_str()),
            None,
        ),
    )
    .expect("insert");
    attach_embedding(&conn, "alice-priv", &emb);
    let index = VectorIndex::build(vec![("alice-priv".to_string(), emb.clone())]);

    let got_hnsw = do_hybrid(&conn, &emb, Some(&index), Some(ALICE));
    assert!(
        ids(&got_hnsw).contains(&"alice-priv".to_string()),
        "owner MUST see own private row via HNSW branch; got={:?}",
        ids(&got_hnsw)
    );

    let got_linear = do_hybrid(&conn, &emb, None, Some(ALICE));
    assert!(
        ids(&got_linear).contains(&"alice-priv".to_string()),
        "owner MUST see own private row via linear-SQL branch; got={:?}",
        ids(&got_linear)
    );
}

#[test]
fn hybrid_collective_visible_to_all_1720() {
    let conn = fresh_db();
    let emb = vec![1.0_f32, 0.0, 0.0, 0.0];
    ai_memory::db::insert(
        &conn,
        &mem(
            "coll",
            Some(ALICE),
            Some(MemoryScope::Collective.as_str()),
            None,
        ),
    )
    .expect("insert");
    attach_embedding(&conn, "coll", &emb);
    let index = VectorIndex::build(vec![("coll".to_string(), emb.clone())]);
    let got = do_hybrid(&conn, &emb, Some(&index), Some(BOB));
    assert!(
        ids(&got).contains(&"coll".to_string()),
        "collective row MUST be visible cross-tenant via hybrid; got={:?}",
        ids(&got)
    );
}
