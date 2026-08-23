// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
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
//! | `sqlite_invalidate_audit_names_the_actor_not_the_attester_3203` | `agent_id` == the ATTESTER (`bob`) |
//! | `sqlite_invalidate_is_fenced_by_record_stop_3203` | the supersession COMMITS with the record plane stopped |
//! | `sqlite_inbound_link_substitute_stamp_is_microsecond_truncated_3204` | nanosecond `valid_from`, never locally re-verifiable |
//!
//! ## Folded in
//!
//! **#3203 — the `memory_link.invalidated` leaf named the wrong actor, and
//! `invalidate_link` had no record-stop fence.** `agent_id` was taken from the
//! row's `observed_by`, i.e. the agent that ATTESTED the edge, so an audit
//! replay showed the original attesting peer as the actor of an invalidation
//! it never performed. It is now the acting principal (`system` when there is
//! none); the superseded signer's proof stays in the `signature` column and
//! its identity inside the CBOR `payload_hash` commits to. The mutation also
//! now sits behind `record_stop::gate_storage_conn`, like its create twin.
//!
//! **#3204 item 3 — `create_link_inbound` substituted an UNTRUNCATED
//! receiver-`now`** for a peer's absent `valid_from`, while every outbound
//! signer truncates to microseconds. A genuinely `peer_attested` edge whose
//! peer sent `valid_from: None` therefore never re-verified locally.
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
    // Unique titles per call: `(title, namespace)` is the upsert key, so a
    // second pair with the same titles would reuse the first pair's ids and
    // the subsequent `link_signed` would `INSERT OR IGNORE` onto an already-
    // invalidated edge (no second audit leaf).
    let tag = uuid::Uuid::new_v4();
    let a = store
        .store(
            ctx,
            &memory("parity/3178", &format!("link-src-{tag}"), "alice"),
        )
        .await
        .expect("store src");
    let b = store
        .store(
            ctx,
            &memory("parity/3178", &format!("link-dst-{tag}"), "alice"),
        )
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
        .invalidate_link(
            &src,
            &dst,
            MemoryLinkRelation::RelatedTo.as_str(),
            None,
            None,
        )
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
// 5 — #3203 / #3204 fold-ins.
// ─────────────────────────────────────────────────────────────────────

/// #3203 — the audit leaf names the ACTOR, never the edge's attester.
#[tokio::test]
async fn sqlite_invalidate_audit_names_the_actor_not_the_attester_3203() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;

    // BOB attests the edge — `observed_by` is set to the keypair's agent_id by
    // the H2 signer, so pre-#3203 the audit leaf was stamped `bob`.
    let bob_kp = ai_memory::identity::keypair::generate("bob").expect("keypair");
    store
        .link_signed(&ctx, &windowed_link(&src, &dst), Some(&bob_kp))
        .await
        .expect("link_signed");
    assert_eq!(
        read_raw_link(&path, &src, &dst).observed_by.as_deref(),
        Some("bob"),
        "fixture precondition: the edge must be attested by bob"
    );

    // ALICE performs the supersession.
    store
        .invalidate_link(
            &src,
            &dst,
            MemoryLinkRelation::RelatedTo.as_str(),
            None,
            Some("alice"),
        )
        .await
        .expect("invalidate_link");

    {
        let conn = ai_memory::db::open(&path).expect("reopen after first invalidate");
        let actor: String = conn
            .query_row(
                "SELECT agent_id FROM signed_events WHERE event_type = ?1",
                rusqlite::params!["memory_link.invalidated"],
                |r| r.get(0),
            )
            .expect("invalidated audit row");
        // PRE-FIX: "bob" — the attester, credited with an act he never performed.
        assert_eq!(
            actor, "alice",
            "the supersession audit leaf must name the ACTING principal"
        );
    }

    // An unattributed substrate path records the `system` sentinel rather than
    // borrowing anyone's identity.
    let (src2, dst2) = seeded_pair(&store, &CallerContext::for_agent("alice")).await;
    store
        .link_signed(&ctx, &windowed_link(&src2, &dst2), Some(&bob_kp))
        .await
        .expect("link_signed 2");
    store
        .invalidate_link(
            &src2,
            &dst2,
            MemoryLinkRelation::RelatedTo.as_str(),
            None,
            None,
        )
        .await
        .expect("invalidate_link 2");
    // Re-open AFTER the second write so this reader is not sitting on a WAL
    // snapshot taken before the substrate committed the `system` leaf.
    let conn = ai_memory::db::open(&path).expect("reopen after second invalidate");
    let actors: Vec<String> = conn
        .prepare("SELECT agent_id FROM signed_events WHERE event_type = ?1 ORDER BY sequence")
        .expect("prepare")
        .query_map(rusqlite::params!["memory_link.invalidated"], |r| r.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows");
    assert_eq!(actors, vec!["alice".to_string(), "system".to_string()]);
}

/// #3203 — `invalidate_link` mutates `memory_links` (and appends a
/// `signed_events` leaf), so it must sit behind the same #1955 R45 fence its
/// create twin has. PRE-FIX the supersession committed with the record plane
/// STOPPED.
#[tokio::test]
async fn sqlite_invalidate_is_fenced_by_record_stop_3203() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;
    let kp = ai_memory::identity::keypair::generate("alice").expect("keypair");
    store
        .link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
        .await
        .expect("link_signed");

    store
        .record_stop(&ctx, true, "operator", "all")
        .await
        .expect("engage record stop");

    let err = store
        .invalidate_link(
            &src,
            &dst,
            MemoryLinkRelation::RelatedTo.as_str(),
            None,
            Some("alice"),
        )
        .await
        .expect_err("a link-plane mutation must refuse while the record plane is stopped");
    assert!(
        format!("{err}").to_lowercase().contains("record"),
        "the refusal must name the record stop, got {err}"
    );

    // The edge is untouched: still signed, still open-ended.
    let raw = read_raw_link(&path, &src, &dst);
    assert!(raw.signature.is_some(), "signature must survive a refusal");
    assert_eq!(raw.valid_until.as_deref(), Some(VALID_UNTIL));

    // CONTROL — released, the same call succeeds.
    store
        .record_stop(&ctx, false, "operator", "all")
        .await
        .expect("release record stop");
    store
        .invalidate_link(
            &src,
            &dst,
            MemoryLinkRelation::RelatedTo.as_str(),
            None,
            Some("alice"),
        )
        .await
        .expect("invalidate after release");
}

/// #3204 item 3 — the receiver-side substitute for a peer's absent
/// `valid_from` must be microsecond-truncated, or the edge can never
/// re-verify locally.
#[test]
fn sqlite_inbound_link_substitute_stamp_is_microsecond_truncated_3204() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let conn = ai_memory::db::open(&path).expect("open");

    let src = memory("parity/3204", "inb-src", "alice");
    let dst = memory("parity/3204", "inb-dst", "alice");
    ai_memory::db::insert(&conn, &src).expect("insert src");
    ai_memory::db::insert(&conn, &dst).expect("insert dst");

    // A peer that sent NO temporal claim at all — the receiver substitutes its
    // own clock for both stamps. `peer_attested` is the inbound federation
    // rung this cell is about; the CHECK requires a 64-byte signature blob
    // (length only — this cell pins stamp truncation, not cryptographic
    // verification of the peer sig).
    let mut link = windowed_link(&src.id, &dst.id);
    link.created_at = String::new();
    link.valid_from = None;
    link.valid_until = None;
    link.signature = Some(vec![0u8; 64]);
    link.observed_by = Some("peer".to_string());
    ai_memory::db::create_link_inbound(&conn, &link, "peer_attested").expect("inbound link");

    let raw = read_raw_link(&path, &src.id, &dst.id);
    let vf = raw.valid_from.expect("valid_from substituted");
    // PRE-FIX: `Utc::now().to_rfc3339()` verbatim — NINE fractional digits,
    // a precision the postgres TIMESTAMPTZ round-trip (and therefore the
    // signed pre-image) can never reproduce.
    for stamp in [&vf, &raw.created_at] {
        let frac = stamp
            .split('.')
            .nth(1)
            .map_or(0, |t| t.chars().take_while(char::is_ascii_digit).count());
        assert!(
            frac <= 6,
            "a receiver-substituted stamp must be microsecond-truncated, got {stamp}"
        );
    }
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

    /// The four durable columns #3178 is about, as postgres returns them
    /// (`clippy::type_complexity` — the inline tuple is over the pedantic
    /// threshold).
    type PgLinkWindowRow = (
        Option<Vec<u8>>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    );

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
        let (pg_sig, pg_created, pg_from, pg_until): PgLinkWindowRow = sqlx::query_as(
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
            .invalidate_link(
                &src,
                &dst,
                MemoryLinkRelation::RelatedTo.as_str(),
                None,
                None,
            )
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
        // Count by event_type only (same as the sqlite twin): after #3203
        // `agent_id` is the ACTING principal (`system` here — `invalidate_link`
        // was passed `None`), not the attester `kp.agent_id`.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("pool");
        let events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signed_events WHERE event_type = $1")
                .bind("memory_link.invalidated")
                .fetch_one(&pool)
                .await
                .expect("count events");
        assert_eq!(events, 1, "supersession must leave exactly one audit leaf");
        let actor: String =
            sqlx::query_scalar("SELECT agent_id FROM signed_events WHERE event_type = $1")
                .bind("memory_link.invalidated")
                .fetch_one(&pool)
                .await
                .expect("actor");
        assert_eq!(
            actor,
            ai_memory::identity::sentinels::SYSTEM_PRINCIPAL,
            "#3203: unattributed pg supersession names the system sentinel, not the attester"
        );
    }
}
