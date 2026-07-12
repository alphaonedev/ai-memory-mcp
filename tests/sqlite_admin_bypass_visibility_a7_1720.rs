// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! v0.8.0 #1709/#1720 Workstream-A (unit A7) — admin/operator
//! BYPASS-path correctness regression on the `SQLite` `SAL` adapter.
//!
//! ## Why this binary exists
//!
//! A2-A6 (commit 15e0504f) closed the cross-tenant `scope=private`
//! leak by making the `storage::visibility_clause` private arm
//! **owner-keyed**:
//!
//! ```text
//! (scope_idx='private' AND ?caller IS NOT NULL
//!     AND (agent_id_idx=?caller OR target_agent_id_idx=?caller))
//! ```
//!
//! That arm only fires the trust-all sentinel `?private_ph IS NULL`,
//! and `private_ph` is bound from `compute_visibility_prefixes(as_agent)`
//! — i.e. the sentinel is keyed on `as_agent` (the namespace prefix),
//! NOT on the bypass flag. On a BYPASS read the SAL adapter passed
//! `vis_caller = None` (good) but `as_agent = ctx.as_agent` **as-is**.
//!
//! That left a sharp edge: a bypass context that ALSO carries
//! `as_agent = Some(..)` (e.g. an operator/admin impersonating an
//! agent namespace, or any background path that set both) would bind a
//! non-NULL `private_ph`, so the `?private_ph IS NULL` sentinel would
//! NOT fire, AND the private arm would be false because `?caller` is
//! NULL. Net effect: **the admin/operator sees NO private rows on the
//! bypass path** — a fail-CLOSED regression for the very paths that
//! are supposed to read everything (migrate, full export, federation
//! catchup, GC sweeps), AND a divergence from the Postgres adapter,
//! whose `recall/search/recall_hybrid` bind `caller = NULL` on bypass
//! and trust-all via `$N::text IS NULL` REGARDLESS of `as_agent`.
//!
//! ## The contract this binary pins (matches Postgres)
//!
//! `bypass_visibility = true` MUST mean **trust-all** — the admin sees
//! every row, private or not, regardless of whether `as_agent` is set.
//! This is asserted for BOTH `as_agent = None` (the common bypass
//! shape) AND `as_agent = Some(..)` (the risky shape that A2's
//! namespace-keyed sentinel could otherwise exclude). The non-bypass
//! owner-keyed contract (the closed #1720 leak) is unchanged and is
//! pinned by `tests/visibility_private_leak_1720.rs` +
//! `tests/scope_private_sal_level_visibility.rs`.
//!
//! All three read paths that thread `vis_caller`/`as_agent` into the
//! SQL `visibility_clause` are exercised: `search` (FTS), `recall_hybrid`
//! keyword-fallback (no embedding), and `recall_hybrid` with an
//! embedding (HNSW + linear-semantic). The leak fix never touched the
//! `visibility_clause` itself — A7's fix (if needed) lives only in the
//! SAL adapter's bypass branch.

#![cfg(feature = "sal")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::sync::Arc;

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier, namespace::MemoryScope};
use ai_memory::store::{CallerContext, Filter, MemoryStore, sqlite::SqliteStore};
use serde_json::json;
use tempfile::NamedTempFile;

/// `as_agent` doubles as the namespace prefix for the
/// `visibility_clause` placeholder binds — the row lives in this exact
/// namespace and the risky bypass ctx impersonates it.
const NS: &str = "fortitude/X";
const ALICE: &str = "ai:alice";
const ADMIN: &str = "ai:operator-admin";
/// Shared FTS needle so the `MATCH` fires on every seeded row.
const NEEDLE: &str = "needle";

fn make_private(id: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
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
        metadata: json!({
            "agent_id": owner,
            "scope": MemoryScope::Private.as_str(),
        }),
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

/// Seed alice's `scope=private` row in `NS`, returning a live store and
/// its backing tempfile (kept alive for the test duration).
async fn fixture() -> (Arc<dyn MemoryStore>, NamedTempFile, String) {
    let f = NamedTempFile::new().expect("tempfile");
    let store: Arc<dyn MemoryStore> =
        Arc::new(SqliteStore::open(f.path()).expect("open SqliteStore"));
    // The seeding ctx is irrelevant to visibility — SqliteStore::store
    // does not stamp agent_id; the row carries the metadata above.
    let alice_ctx = CallerContext::for_agent(ALICE);
    let id = store
        .store(&alice_ctx, &make_private("alice-priv", ALICE))
        .await
        .expect("store alice private");
    (store, f, id)
}

/// Build an admin/operator bypass context. When `with_as_agent`, the
/// ctx ALSO carries `as_agent = Some(NS)` — the risky shape that A2's
/// namespace-keyed `?private_ph IS NULL` sentinel could exclude.
fn admin_bypass_ctx(with_as_agent: bool) -> CallerContext {
    let mut ctx = CallerContext::for_admin(ADMIN);
    assert!(ctx.bypass_visibility, "for_admin sets bypass_visibility");
    if with_as_agent {
        ctx.as_agent = Some(NS.to_string());
    }
    ctx
}

fn ns_filter() -> Filter {
    Filter {
        namespace: Some(NS.to_string()),
        limit: 100,
        ..Filter::default()
    }
}

/// Deterministic embedding so the HNSW + linear-semantic branch of
/// `recall_hybrid` admits the row past the cosine gate.
fn unit_embedding() -> Vec<f32> {
    let mut v = vec![0.0_f32; 8];
    v[0] = 1.0;
    v
}

// ---------------------------------------------------------------------------
// The CORE A7 assertion: bypass + as_agent=Some MUST trust-all (the
// risky shape). On the pre-A7 tree this is the regression that A2
// could have introduced; post-A7 it MUST pass.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_admin_bypass_with_as_agent_sees_private_a7() {
    let (store, _f, _id) = fixture().await;
    let ctx = admin_bypass_ctx(true);
    let rows = store
        .search(&ctx, NEEDLE, &ns_filter())
        .await
        .expect("search");
    assert!(
        rows.iter().any(|m| m.id == "alice-priv"),
        "#1720 A7: admin bypass (as_agent=Some) MUST see alice's private row via search \
         (bypass = trust-all, matching postgres NULL-caller); got={:?}",
        rows.iter().map(|m| &m.id).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn recall_keyword_admin_bypass_with_as_agent_sees_private_a7() {
    let (store, _f, _id) = fixture().await;
    let ctx = admin_bypass_ctx(true);
    // No embedding => recall_hybrid keyword-fallback (db::recall).
    let rows = store
        .recall_hybrid(&ctx, NEEDLE, None, &ns_filter())
        .await
        .expect("recall_hybrid keyword");
    assert!(
        rows.iter().any(|(m, _)| m.id == "alice-priv"),
        "#1720 A7: admin bypass (as_agent=Some) MUST see alice's private row via \
         recall_hybrid keyword-fallback; got={:?}",
        rows.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn recall_hybrid_embedded_admin_bypass_with_as_agent_sees_private_a7() {
    let (store, f, id) = fixture().await;
    // Attach an embedding so the HNSW + linear-semantic SQL branch runs.
    {
        let conn = ai_memory::db::open(f.path()).expect("reopen for embedding");
        let blob = ai_memory::embeddings::encode_embedding_blob(&unit_embedding());
        let dim = i64::try_from(unit_embedding().len()).expect("dim fits i64");
        conn.execute(
            "UPDATE memories SET embedding = ?1, embedding_dim = ?2 WHERE id = ?3",
            rusqlite::params![blob, dim, id],
        )
        .expect("attach embedding");
    }
    let ctx = admin_bypass_ctx(true);
    let emb = unit_embedding();
    let rows = store
        .recall_hybrid(&ctx, NEEDLE, Some(&emb), &ns_filter())
        .await
        .expect("recall_hybrid embedded");
    assert!(
        rows.iter().any(|(m, _)| m.id == "alice-priv"),
        "#1720 A7: admin bypass (as_agent=Some) MUST see alice's private row via \
         recall_hybrid with embedding; got={:?}",
        rows.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Sanity: bypass + as_agent=None already trust-alls (the common shape).
// These would pass on the pre-A7 tree too — they document the second
// half of the contract and guard against any future change that would
// drop trust-all when as_agent is unset.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_admin_bypass_no_as_agent_sees_private_a7() {
    let (store, _f, _id) = fixture().await;
    let ctx = admin_bypass_ctx(false);
    let rows = store
        .search(&ctx, NEEDLE, &ns_filter())
        .await
        .expect("search");
    assert!(
        rows.iter().any(|m| m.id == "alice-priv"),
        "#1720 A7: admin bypass (as_agent=None) MUST see alice's private row via search; got={:?}",
        rows.iter().map(|m| &m.id).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn recall_keyword_admin_bypass_no_as_agent_sees_private_a7() {
    let (store, _f, _id) = fixture().await;
    let ctx = admin_bypass_ctx(false);
    let rows = store
        .recall_hybrid(&ctx, NEEDLE, None, &ns_filter())
        .await
        .expect("recall_hybrid keyword");
    assert!(
        rows.iter().any(|(m, _)| m.id == "alice-priv"),
        "#1720 A7: admin bypass (as_agent=None) MUST see alice's private row via \
         recall_hybrid keyword-fallback; got={:?}",
        rows.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Cross-adapter contract pin (documentation + regression guard): the
// non-admin (non-bypass) read remains owner-keyed even when as_agent
// names the row's namespace — the closed #1720 leak. This is the
// adapter-agnostic invariant the postgres twin in
// `tests/store_parity_gaps.rs` mirrors: admin bypass = trust-all on
// BOTH; non-admin = owner-keyed on BOTH.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_non_admin_with_as_agent_still_owner_keyed_a7() {
    let (store, _f, _id) = fixture().await;
    let mut ctx = CallerContext::for_agent("ai:bob");
    ctx.as_agent = Some(NS.to_string());
    assert!(!ctx.bypass_visibility, "non-admin ctx never bypasses");
    let rows = store
        .search(&ctx, NEEDLE, &ns_filter())
        .await
        .expect("search");
    assert!(
        !rows.iter().any(|m| m.id == "alice-priv"),
        "#1720: a non-admin (no bypass) caller with as_agent=NS MUST NOT see alice's \
         private row — owner-keyed, the closed leak; got={:?}",
        rows.iter().map(|m| &m.id).collect::<Vec<_>>()
    );
}
