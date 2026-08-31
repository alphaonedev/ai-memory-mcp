// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
#![cfg(feature = "sal")]

//! #3281 (SECURITY / audit-integrity, tamper-evident chain byte-parity) —
//! `invalidate_link`'s `memory_link.invalidated` audit leaf must hash the SAME
//! `payload_hash` on BOTH backends for the SAME logical invalidation.
//!
//! ## The defect this file pins
//!
//! A caller supplies `valid_until` on the wire (e.g. `"...Z"`). The sqlite
//! path hashed the RAW wire string into the `SignableLink` pre-image, while
//! the postgres path bound it as `TIMESTAMPTZ` and re-rendered the DB readback
//! through chrono `to_rfc3339()` (`+00:00`, fractional-second normalization).
//! Different bytes → different canonical CBOR → a DIFFERENT audit-leaf hash for
//! the same event — which breaks cross-backend verifiability of the
//! hash-chained audit trail.
//!
//! The fix canonicalizes `valid_until` IDENTICALLY on both backends
//! (`crate::storage::canonicalize_valid_until_stamp`) BEFORE it is stored and
//! hashed. Both now commit to `parse → UTC → truncate-to-µs →
//! to_rfc3339_opts(AutoSi, use_z = true)` (the `Z` zulu suffix, #3322).
//!
//! ## Coverage
//!
//! - `sqlite_invalidate_leaf_commits_to_canonical_valid_until_3281` — the
//!   sqlite leaf hashes the CANONICAL `valid_until`, not the raw `Z` wire form
//!   (fails PRE-fix). Runs on every `sal` leg; no postgres required.
//! - `pg::cross_backend_invalidate_payload_hash_parity_3281` — the postgres
//!   leaf's `payload_hash` is BYTE-IDENTICAL to sqlite's for the same
//!   invalidation (the exact cross-backend parity). Soft-skips without
//!   `AI_MEMORY_TEST_POSTGRES_URL`; deliberately NOT `#[ignore]` so the
//!   `sal-postgres` PR gate exercises it.

use std::path::PathBuf;

use ai_memory::identity::sign::{SignableLink, canonical_cbor};
use ai_memory::models::{Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::signed_events::payload_hash;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

/// Micro-precision claim-window stamps, byte-identical across backends (the
/// #3178/#3291 cross-backend link-signing parity guarantees this).
const CREATED_AT: &str = "2026-01-02T03:04:05.123456+00:00";
const VALID_FROM: &str = "2026-02-03T04:05:06.654321+00:00";
/// The caller supplies `valid_until` in `Z` form — the exact shape that
/// diverged pre-fix (`...Z` on sqlite vs `...+00:00` re-render on pg).
const VALID_UNTIL_WIRE: &str = "2026-05-06T12:00:00Z";
/// The canonical form both backends must converge on. #3322 (2026-08-31)
/// renders UTC with the RFC3339 `Z` suffix (not `+00:00`) so the canonical
/// wire form matches the caller's `...Z` and the export golden's `Z`
/// convention; the expected `payload_hash` below is recomputed from this
/// string, so both backends still agree by construction.
const VALID_UNTIL_CANONICAL: &str = "2026-05-06T12:00:00Z";
const REL_STR: &str = "related_to";
const ACTOR: &str = "ai:invalidator-3281";

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated write.
    ONCE.call_once(|| unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    });
}

fn memory(ns: &str, title: &str, owner: &str, id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "parity-3281".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

/// A signed link whose claim window is fixed to the micro-precision stamps
/// above; `valid_until` is `None` at create (set by the invalidation).
fn windowed_link(src: &str, dst: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: dst.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: CREATED_AT.to_string(),
        signature: None,
        observed_by: None,
        valid_from: Some(VALID_FROM.to_string()),
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// The stored `SignableLink` field values needed to independently re-derive the
/// expected audit-leaf `payload_hash`.
struct RowFields {
    created_at: String,
    valid_from: Option<String>,
    observed_by: Option<String>,
}

fn read_row_fields(path: &std::path::Path, src: &str, dst: &str) -> RowFields {
    let conn = ai_memory::db::open(path).expect("reopen sqlite for raw read");
    conn.query_row(
        "SELECT created_at, valid_from, observed_by \
         FROM memory_links WHERE source_id = ?1 AND target_id = ?2 AND relation = ?3",
        rusqlite::params![src, dst, REL_STR],
        |r| {
            Ok(RowFields {
                created_at: r.get(0)?,
                valid_from: r.get(1)?,
                observed_by: r.get(2)?,
            })
        },
    )
    .expect("link row")
}

fn expected_leaf_hash(src: &str, dst: &str, row: &RowFields) -> Vec<u8> {
    let signable = SignableLink {
        src_id: src,
        dst_id: dst,
        relation: REL_STR,
        observed_by: row.observed_by.as_deref(),
        created_at: Some(row.created_at.as_str()),
        valid_from: row.valid_from.as_deref(),
        valid_until: Some(VALID_UNTIL_CANONICAL),
    };
    payload_hash(&canonical_cbor(&signable).expect("canonical cbor"))
}

fn fresh_db_path() -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("sal-parity-3281");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let path = dir.path().join("memories.db");
    (dir, path)
}

/// Seed a signed link and invalidate it with the `Z`-form wire `valid_until`;
/// return the `memory_link.invalidated` leaf `payload_hash`, the STORED
/// (canonicalized) `valid_until`, and the pre-image fields for re-derivation.
async fn sqlite_invalidated_leaf(
    path: &std::path::Path,
    src: &str,
    dst: &str,
) -> (Vec<u8>, String) {
    let store = SqliteStore::open(path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    store
        .store(&ctx, &memory("parity/3281", "src", "alice", src))
        .await
        .expect("store src");
    store
        .store(&ctx, &memory("parity/3281", "dst", "alice", dst))
        .await
        .expect("store dst");

    let kp = ai_memory::identity::keypair::generate(ACTOR).expect("keypair");
    let attest = store
        .link_signed(&ctx, &windowed_link(src, dst), Some(&kp))
        .await
        .expect("link_signed");
    assert_eq!(attest, "self_signed", "link must be self-signed to audit");

    store
        .invalidate_link(src, dst, REL_STR, Some(VALID_UNTIL_WIRE), Some(ACTOR))
        .await
        .expect("invalidate_link Ok")
        .found
        .then_some(())
        .expect("link must be found");

    // The STORED column must have been canonicalized, not left as raw `Z`.
    let stored_valid_until: String = {
        let conn = ai_memory::db::open(path).expect("reopen");
        conn.query_row(
            "SELECT valid_until FROM memory_links \
             WHERE source_id = ?1 AND target_id = ?2 AND relation = ?3",
            rusqlite::params![src, dst, REL_STR],
            |r| r.get::<_, Option<String>>(0),
        )
        .expect("read stored valid_until")
        .expect("valid_until is stamped")
    };

    let conn = ai_memory::db::open(path).expect("reopen for audit read");
    let leaf = ai_memory::signed_events::list_signed_events(&conn, None, 1000, 0)
        .expect("list signed_events")
        .into_iter()
        .find(|e| e.event_type == "memory_link.invalidated")
        .expect("memory_link.invalidated leaf must exist")
        .payload_hash;

    (leaf, stored_valid_until)
}

#[tokio::test]
async fn sqlite_invalidate_leaf_commits_to_canonical_valid_until_3281() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let src = uuid::Uuid::new_v4().to_string();
    let dst = uuid::Uuid::new_v4().to_string();
    let (leaf, stored_valid_until) = sqlite_invalidated_leaf(&path, &src, &dst).await;

    assert_eq!(
        stored_valid_until, VALID_UNTIL_CANONICAL,
        "the stored `valid_until` must be canonicalized (µs RFC3339 +00:00), \
         not the raw `Z` wire form"
    );

    let row = read_row_fields(&path, &src, &dst);
    assert_eq!(
        leaf,
        expected_leaf_hash(&src, &dst, &row),
        "the audit leaf must hash the CANONICAL `valid_until`, not the raw `Z` \
         wire string (the #3281 divergence)"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        ACTOR, MemoryStore, REL_STR, VALID_UNTIL_WIRE, memory, permissive_attestation_for_tests,
        sqlite_invalidated_leaf, windowed_link,
    };
    use ai_memory::store::CallerContext;
    use ai_memory::store::postgres::PostgresStore;

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    fn seed_ctx() -> CallerContext {
        let mut ctx = CallerContext::for_agent("ai:test-3281-seed");
        ctx.bypass_visibility = true;
        ctx
    }

    /// Seed + sign + invalidate on postgres; return the
    /// `memory_link.invalidated` leaf `payload_hash`, keyed by the row's own
    /// (deterministic, cross-backend-identical) original Ed25519 signature.
    async fn pg_invalidated_leaf(url: &str, src: &str, dst: &str) -> Vec<u8> {
        let store = PostgresStore::connect(url).await.expect("connect pg");
        let ctx = seed_ctx();
        store
            .store(&ctx, &memory("parity/3281", "src", "alice", src))
            .await
            .expect("store src");
        store
            .store(&ctx, &memory("parity/3281", "dst", "alice", dst))
            .await
            .expect("store dst");

        let kp = ai_memory::identity::keypair::generate(ACTOR).expect("keypair");
        let attest = store
            .link_signed(&ctx, &windowed_link(src, dst), Some(&kp))
            .await
            .expect("link_signed");
        assert_eq!(attest, "self_signed", "pg link must be self-signed");

        let pool = sqlx::PgPool::connect(url).await.expect("pool");
        let orig_sig_opt: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT signature FROM memory_links \
             WHERE source_id = $1 AND target_id = $2 AND relation = $3",
        )
        .bind(src)
        .bind(dst)
        .bind(REL_STR)
        .fetch_one(&pool)
        .await
        .expect("read original signature");
        let orig_sig = orig_sig_opt.expect("signature present");

        store
            .invalidate_link(src, dst, REL_STR, Some(VALID_UNTIL_WIRE), Some(ACTOR))
            .await
            .expect("pg invalidate_link Ok");

        // The audit leaf carries the PRIOR (original) signature verbatim; it is
        // deterministic and unique to this run's (src,dst), so it selects
        // exactly this invalidation's leaf out of the shared table.
        let leaf: Vec<u8> = sqlx::query_scalar(
            "SELECT payload_hash FROM signed_events \
             WHERE event_type = 'memory_link.invalidated' AND signature = $1",
        )
        .bind(&orig_sig)
        .fetch_one(&pool)
        .await
        .expect("read pg invalidated leaf payload_hash");

        // The CI `sal-postgres` suite shares ONE `ai_memory_test` DB with NO
        // per-test isolation (coverage.yml), and `sal_parity_link_window_3178`
        // asserts a GLOBAL `COUNT(*) FROM signed_events WHERE event_type =
        // 'memory_link.invalidated'` of exactly 1. So this test must leave the
        // shared audit table byte-neutral: delete the signed_events leaves it
        // appended (keyed by this run's unique Ed25519 `orig_sig`) and the
        // link/memory rows it seeded. `orig_sig` is globally unique (it commits
        // to the fresh src/dst UUIDs), so this touches only this run's rows.
        let _ = sqlx::query("DELETE FROM signed_events WHERE signature = $1")
            .bind(&orig_sig)
            .execute(&pool)
            .await
            .expect("cleanup signed_events");
        let _ = sqlx::query("DELETE FROM memory_links WHERE source_id = $1 AND target_id = $2")
            .bind(src)
            .bind(dst)
            .execute(&pool)
            .await
            .expect("cleanup memory_links");
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1 OR id = $2")
            .bind(src)
            .bind(dst)
            .execute(&pool)
            .await
            .expect("cleanup memories");

        leaf
    }

    #[tokio::test]
    async fn cross_backend_invalidate_payload_hash_parity_3281() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        permissive_attestation_for_tests();

        // The SAME logical link (shared src/dst/relation) on both backends —
        // src_id/dst_id are part of the signed pre-image, so parity is only
        // meaningful when they match; only `valid_until`'s wire→canonical form
        // is the variable under test.
        let src = uuid::Uuid::new_v4().to_string();
        let dst = uuid::Uuid::new_v4().to_string();

        let (_dir, path) = super::fresh_db_path();
        let (sqlite_leaf, _stored) = sqlite_invalidated_leaf(&path, &src, &dst).await;
        let pg_leaf = pg_invalidated_leaf(&url, &src, &dst).await;

        assert_eq!(
            pg_leaf, sqlite_leaf,
            "#3281: the `memory_link.invalidated` audit-leaf payload_hash MUST be \
             byte-identical across sqlite and postgres for the same `valid_until` \
             invalidation (tamper-evident chain cross-backend parity)"
        );
    }
}
