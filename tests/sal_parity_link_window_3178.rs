// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::missing_panics_doc, clippy::too_many_lines)]
#![cfg(feature = "sal")]

//! #3178 — `MemoryStore::link` / `link_signed` must persist AND SIGN the
//! caller's temporal claim identically on both backends, and supersession must
//! clear the signing surface + leave an audit leaf on both.
//!
//! ## The two defects pinned here
//!
//! **sqlite discarded the claim window.** The adapter passed only
//! `(source_id, target_id, relation)`; `db::create_link_signed` had NO
//! `valid_until` in its INSERT at all, bound `created_at = valid_from = now`
//! through a shared `?4`, and signed a pre-image of
//! `valid_from: Some(now), valid_until: None` — a window the caller never
//! supplied. `PostgresStore::link_internal` honoured and signed all three. So
//! the SAME `MemoryStore::link_signed(link)` produced different durable rows
//! AND different Ed25519 pre-images per backend: a link minted on one backend
//! could not verify on the other, and every caller-supplied claim window was
//! silently lost on sqlite.
//!
//! **postgres supersession left a stale signature and no audit leaf.**
//! `kg_invalidate_cte` stamped `valid_until` only, so a superseded row kept a
//! signature over bytes that had changed — a later `memory_verify` reported a
//! misleading "signature mismatch" instead of an honest "unsigned" — and the
//! postgres audit chain carried no `memory_link.invalidated` event. sqlite has
//! cleared both and appended the leaf since v0.7.0 #628 H5.
//!
//! **R-203.** Parent behaviour per cell:
//!
//! | cell | parent behaviour |
//! |---|---|
//! | `sqlite_link_signed_persists_caller_window_3178` | `valid_until` NULL; `valid_from` = now |
//! | `sqlite_link_unsigned_persists_caller_window_3178` | same |
//! | `sqlite_link_signature_commits_to_persisted_window_3178` | signature verifies only against `(now, None)`, not the row |
//! | `sqlite_link_signed_refuses_malformed_window_3178` | garbage silently replaced by `now` |
//! | `pg_and_sqlite_sign_identical_bytes_3178` | signatures DIFFER (different pre-images) |
//! | `pg_invalidate_clears_signature_and_emits_event_3178` | `attest_level` stays `self_signed`, no event row |
//!
//! The postgres twins soft-skip without `AI_MEMORY_TEST_POSTGRES_URL`.

use std::path::PathBuf;

use ai_memory::models::{Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, VerifyFilter};
use serde_json::json;

/// A window whose three instants are all DISTINCT from `now` and from each
/// other, so a funnel that quietly substitutes `now` cannot accidentally pass.
const CREATED_AT: &str = "2026-01-02T03:04:05.123456+00:00";
const VALID_FROM: &str = "2026-02-03T04:05:06.654321+00:00";
const VALID_UNTIL: &str = "2027-03-04T05:06:07.111222+00:00";

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated write.
    ONCE.call_once(|| unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    });
}

/// Hermetic DB path under `.local-runs/` (never `/tmp`, per project rule).
fn fresh_db_path() -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("sal-parity-3178");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let path = dir.path().join("memories.db");
    (dir, path)
}

fn memory(ns: &str, title: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "parity-3178".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

fn windowed_link(src: &str, dst: &str) -> MemoryLink {
    // `MemoryLink` derives no `Default`, so every field is explicit.
    MemoryLink {
        source_id: src.to_string(),
        target_id: dst.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: CREATED_AT.to_string(),
        signature: None,
        observed_by: None,
        valid_from: Some(VALID_FROM.to_string()),
        valid_until: Some(VALID_UNTIL.to_string()),
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// Raw `memory_links` row read — `db::get_links` deliberately does NOT surface
/// the `signature` blob, and this suite is about exactly those bytes.
struct RawLink {
    created_at: String,
    valid_from: Option<String>,
    valid_until: Option<String>,
    signature: Option<Vec<u8>>,
    attest_level: Option<String>,
    observed_by: Option<String>,
}

fn read_raw_link(path: &std::path::Path, src: &str, dst: &str) -> RawLink {
    let conn = ai_memory::db::open(path).expect("reopen sqlite for raw read");
    conn.query_row(
        "SELECT created_at, valid_from, valid_until, signature, attest_level, observed_by \
         FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
        rusqlite::params![src, dst],
        |r| {
            Ok(RawLink {
                created_at: r.get(0)?,
                valid_from: r.get(1)?,
                valid_until: r.get(2)?,
                signature: r.get(3)?,
                attest_level: r.get(4)?,
                observed_by: r.get(5)?,
            })
        },
    )
    .expect("link row")
}

async fn seeded_pair(store: &SqliteStore, ctx: &CallerContext) -> (String, String) {
    let a = store
        .store(ctx, &memory("parity/3178", "link-src", "alice"))
        .await
        .expect("store src");
    let b = store
        .store(ctx, &memory("parity/3178", "link-dst", "alice"))
        .await
        .expect("store dst");
    (a, b)
}

// ─────────────────────────────────────────────────────────────────────
// 1 — the caller's window reaches the durable row.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_link_signed_persists_caller_window_3178() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;

    let kp = ai_memory::identity::keypair::generate("ai:link-3178").expect("keypair");
    let attest = store
        .link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
        .await
        .expect("link_signed");
    assert_eq!(attest, "self_signed");

    // PRE-FIX: `valid_until` was NULL (not even a column in the INSERT) and
    // `valid_from` / `created_at` were both wall-clock `now`.
    let row = read_raw_link(&path, &src, &dst);
    assert_eq!(row.created_at, CREATED_AT, "created_at must be the claim");
    assert_eq!(row.valid_from.as_deref(), Some(VALID_FROM));
    assert_eq!(row.valid_until.as_deref(), Some(VALID_UNTIL));

    // Also visible through the public read surface.
    let links = store
        .get_links_for_anchor(&src)
        .await
        .expect("get_links_for_anchor");
    let l = links
        .iter()
        .find(|l| l.target_id == dst)
        .expect("link present");
    assert_eq!(l.valid_from.as_deref(), Some(VALID_FROM));
    assert_eq!(l.valid_until.as_deref(), Some(VALID_UNTIL));
}

#[tokio::test]
async fn sqlite_link_unsigned_persists_caller_window_3178() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;

    // The UNSIGNED funnel (`link`) drops through the same core, so it must
    // honour the claim too — the postgres twin routes both through
    // `link_internal`.
    store
        .link(&ctx, &windowed_link(&src, &dst))
        .await
        .expect("link");
    let row = read_raw_link(&path, &src, &dst);
    assert_eq!(row.created_at, CREATED_AT);
    assert_eq!(row.valid_from.as_deref(), Some(VALID_FROM));
    assert_eq!(row.valid_until.as_deref(), Some(VALID_UNTIL));
    assert_eq!(row.attest_level.as_deref(), Some("unsigned"));
}

// ─────────────────────────────────────────────────────────────────────
// 2 — the SIGNATURE commits to the window that was persisted.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_link_signature_commits_to_persisted_window_3178() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;

    let kp = ai_memory::identity::keypair::generate("ai:link-3178").expect("keypair");
    store
        .link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
        .await
        .expect("link_signed");

    let row = read_raw_link(&path, &src, &dst);
    let sig = row.signature.clone().expect("signature blob present");

    // Re-derive the pre-image FROM THE ROW — that is what a verifier (local or
    // federated) does. PRE-FIX this failed: the row said
    // `(VALID_FROM, VALID_UNTIL)` was never persisted at all and the signature
    // committed to `(now, None)`.
    let from_row = ai_memory::identity::sign::SignableLink {
        src_id: &src,
        dst_id: &dst,
        relation: MemoryLinkRelation::RelatedTo.as_str(),
        observed_by: row.observed_by.as_deref(),
        valid_from: row.valid_from.as_deref(),
        valid_until: row.valid_until.as_deref(),
    };
    let expected = ai_memory::identity::sign::sign(&kp, &from_row).expect("re-sign from row");
    assert_eq!(
        sig, expected,
        "the persisted signature must be re-derivable from the persisted row"
    );

    // And the row-derived pre-image is NOT the legacy `(now, None)` one.
    let legacy = ai_memory::identity::sign::SignableLink {
        src_id: &src,
        dst_id: &dst,
        relation: MemoryLinkRelation::RelatedTo.as_str(),
        observed_by: row.observed_by.as_deref(),
        valid_from: row.valid_from.as_deref(),
        valid_until: None,
    };
    let legacy_sig = ai_memory::identity::sign::sign(&kp, &legacy).expect("legacy sign");
    assert_ne!(
        sig, legacy_sig,
        "control: the two pre-images must differ, else this cell proves nothing"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3 — a malformed claim is refused, never silently replaced.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_link_signed_refuses_malformed_window_3178() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;

    let mut bad = windowed_link(&src, &dst);
    bad.valid_until = Some("not-a-timestamp".to_string());
    // PRE-FIX: accepted (the field was ignored outright) and the row landed.
    let err = store
        .link_signed(&ctx, &bad, None)
        .await
        .expect_err("a malformed claim must fail closed, not be replaced by now");
    assert!(
        format!("{err}").contains("valid_until"),
        "the refusal must name the offending field, got {err}"
    );

    // And nothing was written.
    let conn = ai_memory::db::open(&path).expect("reopen");
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memory_links WHERE source_id = ?1",
            rusqlite::params![&src],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 0, "a refused link must write no row");
}

// ─────────────────────────────────────────────────────────────────────
// 4 — sqlite supersession CONTROL (the behaviour postgres now mirrors).
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_invalidate_clears_signature_and_emits_event_3178() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;

    let kp = ai_memory::identity::keypair::generate("ai:link-3178").expect("keypair");
    store
        .link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
        .await
        .expect("link_signed");

    let outcome = store
        .invalidate_link(&src, &dst, MemoryLinkRelation::RelatedTo.as_str(), None)
        .await
        .expect("invalidate_link");
    assert!(outcome.found);

    let report = store
        .verify_link(VerifyFilter {
            source_id: Some(src.clone()),
            target_id: Some(dst.clone()),
            link_id: None,
        })
        .await
        .expect("verify_link");
    assert_eq!(report.attest_level, "unsigned");
    assert!(!report.signature_present);

    let conn = ai_memory::db::open(&path).expect("reopen");
    let events: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            rusqlite::params!["memory_link.invalidated"],
            |r| r.get(0),
        )
        .expect("count events");
    assert_eq!(events, 1, "supersession must leave exactly one audit leaf");
}

// ─────────────────────────────────────────────────────────────────────
// postgres twins.
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        CREATED_AT, VALID_FROM, VALID_UNTIL, fresh_db_path, memory,
        permissive_attestation_for_tests, read_raw_link, windowed_link,
    };
    use ai_memory::models::MemoryLinkRelation;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore, VerifyFilter};

    async fn store_or_skip() -> Option<(PostgresStore, String)> {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return None;
        };
        match PostgresStore::connect(&url).await {
            Ok(s) => Some((s, url)),
            Err(e) => {
                eprintln!("skip: postgres connect failed: {e}");
                None
            }
        }
    }

    fn unique_ns() -> String {
        format!("parity3178/{}", uuid::Uuid::new_v4())
    }

    /// The strongest cross-backend pin available: Ed25519 (RFC 8032) is
    /// DETERMINISTIC, so the same key over the same pre-image yields the same
    /// 64 bytes. If the two adapters sign byte-identical signatures for the
    /// same `MemoryLink`, their pre-images are byte-identical — which is
    /// exactly "a link minted on one backend verifies on the other".
    /// PRE-FIX these differed, because sqlite signed `(now, None)`.
    #[tokio::test]
    async fn pg_and_sqlite_sign_identical_bytes_3178() {
        permissive_attestation_for_tests();
        let Some((pgstore, url)) = store_or_skip().await else {
            return;
        };
        let ctx = CallerContext::for_agent("alice");
        let kp = ai_memory::identity::keypair::generate("ai:link-3178").expect("keypair");
        let ns = unique_ns();

        // Same logical endpoints on both backends (the ids are part of the
        // pre-image, so they must match).
        let src_mem = memory(&ns, "xb-src", "alice");
        let dst_mem = memory(&ns, "xb-dst", "alice");
        let (src, dst) = (src_mem.id.clone(), dst_mem.id.clone());

        let (_dir, path) = fresh_db_path();
        let sq = SqliteStore::open(&path).expect("open SqliteStore");
        sq.store(&ctx, &src_mem).await.expect("sqlite src");
        sq.store(&ctx, &dst_mem).await.expect("sqlite dst");
        sq.link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
            .await
            .expect("sqlite link_signed");
        let sqlite_sig = read_raw_link(&path, &src, &dst)
            .signature
            .expect("sqlite signature");

        pgstore.store(&ctx, &src_mem).await.expect("pg src");
        pgstore.store(&ctx, &dst_mem).await.expect("pg dst");
        pgstore
            .link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
            .await
            .expect("pg link_signed");

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("pool");
        let (pg_sig, pg_created, pg_from, pg_until): (
            Option<Vec<u8>>,
            chrono::DateTime<chrono::Utc>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT signature, created_at, valid_from, valid_until FROM memory_links \
             WHERE source_id = $1 AND target_id = $2",
        )
        .bind(&src)
        .bind(&dst)
        .fetch_one(&pool)
        .await
        .expect("pg link row");

        assert_eq!(
            sqlite_sig,
            pg_sig.expect("pg signature"),
            "the two adapters must sign the SAME pre-image for the same link"
        );
        // And both landed the caller's window (the pg side has always done so;
        // this is the control half of the comparison).
        assert_eq!(pg_created.to_rfc3339(), CREATED_AT);
        assert_eq!(pg_from.map(|t| t.to_rfc3339()).as_deref(), Some(VALID_FROM));
        assert_eq!(
            pg_until.map(|t| t.to_rfc3339()).as_deref(),
            Some(VALID_UNTIL)
        );
    }

    #[tokio::test]
    async fn pg_invalidate_clears_signature_and_emits_event_3178() {
        permissive_attestation_for_tests();
        let Some((store, url)) = store_or_skip().await else {
            return;
        };
        let ctx = CallerContext::for_agent("alice");
        let kp = ai_memory::identity::keypair::generate("ai:link-3178").expect("keypair");
        let ns = unique_ns();

        let src_mem = memory(&ns, "inv-src", "alice");
        let dst_mem = memory(&ns, "inv-dst", "alice");
        let (src, dst) = (src_mem.id.clone(), dst_mem.id.clone());
        store.store(&ctx, &src_mem).await.expect("src");
        store.store(&ctx, &dst_mem).await.expect("dst");
        store
            .link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
            .await
            .expect("link_signed");

        let outcome = store
            .invalidate_link(&src, &dst, MemoryLinkRelation::RelatedTo.as_str(), None)
            .await
            .expect("invalidate_link");
        assert!(outcome.found);

        // PRE-FIX: `self_signed` with the stale signature still present, so a
        // later verify reported "signature mismatch" for a merely superseded
        // edge.
        let report = store
            .verify_link(VerifyFilter {
                source_id: Some(src.clone()),
                target_id: Some(dst.clone()),
                link_id: None,
            })
            .await
            .expect("verify_link");
        assert_eq!(report.attest_level, "unsigned");
        assert!(!report.signature_present);

        // PRE-FIX: zero rows — the postgres audit chain had no record at all.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("pool");
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = $1 AND agent_id = $2",
        )
        .bind("memory_link.invalidated")
        .bind(&kp.agent_id)
        .fetch_one(&pool)
        .await
        .expect("count events");
        assert_eq!(events, 1, "supersession must leave exactly one audit leaf");
    }
}
