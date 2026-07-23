// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 STORAGE-CHAIN lane regression pins (fable-3x7 findings).
//!
//! One test group per finding/issue, all against the canonical
//! `db::open(":memory:")` fixture so the migration ladder fires:
//!
//! * #2331 (FBL-01) — `memory_update` tier→long must clear the stale
//!   short/mid `expires_at` (the #1626 coupling, sqlite parity), and the
//!   tier-blind GC must therefore never reap the promoted row.

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use rusqlite::Connection;
use serde_json::json;

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

/// Seed a memory row through the canonical `db::insert` funnel.
fn seed(conn: &Connection, id: &str, tier: Tier, expires_at: Option<&str>) -> String {
    let mem = Memory {
        id: id.to_string(),
        tier,
        namespace: "storage-chain".to_string(),
        title: format!("title-{id}"),
        content: format!("content for {id}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        expires_at: expires_at.map(str::to_string),
        metadata: json!({}),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed memory")
}

fn row_tier_and_expiry(conn: &Connection, id: &str) -> (String, Option<String>) {
    conn.query_row(
        "SELECT tier, expires_at FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("row present")
}

// ─────────────────────────────────────────────────────────────────────
// #2331 (FBL-01)
// ─────────────────────────────────────────────────────────────────────

/// `memory_update {tier:"long"}` on a mid-tier row (which always carries a
/// live TTL) must clear `expires_at` — the pg #1626 contract, previously
/// missing on sqlite.
#[test]
fn fbl01_update_tier_long_clears_stale_expiry() {
    let conn = fresh_sqlite();
    // Expiry already in the past: the worst case — without the coupling
    // the very next gc() reaps the freshly-promoted "permanent" row.
    let stale = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let id = seed(&conn, "fbl01-a", Tier::Mid, Some(&stale));

    let (found, _) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        Some(&Tier::Long),
        None,
        None,
        None,
        None,
        None, // no expires_at in the patch — the natural "make permanent" call
        None,
        None,
        None,
        None,
    )
    .expect("tier promotion update succeeds");
    assert!(found, "row must be found");

    let (tier, expiry) = row_tier_and_expiry(&conn, &id);
    assert_eq!(tier, "long");
    assert_eq!(
        expiry, None,
        "tier→long must clear the stale short/mid expires_at (#1626 sqlite parity)"
    );

    // The tier-blind GC must not reap the promoted row.
    db::gc(&conn, true).expect("gc runs");
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(live, 1, "gc must not reap an explicitly-promoted long row");
}

/// An explicitly-supplied `expires_at` patch value LOSES to the long⇒NULL
/// clear (mirrors the pg CASE, which nulls unconditionally when the new
/// tier is long).
#[test]
fn fbl01_update_tier_long_overrides_explicit_expiry_patch() {
    let conn = fresh_sqlite();
    let id = seed(&conn, "fbl01-b", Tier::Short, None);
    let future = (chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339();

    db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        Some(&Tier::Long),
        None,
        None,
        None,
        None,
        Some(&future),
        None,
        None,
        None,
        None,
    )
    .expect("update succeeds");

    let (tier, expiry) = row_tier_and_expiry(&conn, &id);
    assert_eq!(tier, "long");
    assert_eq!(
        expiry, None,
        "an explicit expires_at patch loses to the long⇒NULL clear"
    );
}

/// A non-promoting update keeps the existing expiry untouched (the fix
/// must not widen into clearing short/mid TTLs).
#[test]
fn fbl01_update_without_tier_change_preserves_expiry() {
    let conn = fresh_sqlite();
    let future = (chrono::Utc::now() + chrono::Duration::days(2)).to_rfc3339();
    let id = seed(&conn, "fbl01-c", Tier::Mid, Some(&future));

    db::update_with_expected_version(
        &conn,
        &id,
        Some("retitled"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("update succeeds");

    let (tier, expiry) = row_tier_and_expiry(&conn, &id);
    assert_eq!(tier, "mid");
    // Instant-preserving comparison: the #2332 funnel canonicalizes the
    // carried-forward rendering (micros + `Z`), so compare instants, not
    // bytes.
    let stored = chrono::DateTime::parse_from_rfc3339(expiry.as_deref().expect("expiry kept"))
        .expect("parseable");
    let expected = chrono::DateTime::parse_from_rfc3339(&future).expect("parseable");
    assert_eq!(
        stored.timestamp_micros(),
        expected.timestamp_micros(),
        "a non-promoting update must not move expires_at"
    );
}

/// The append-and-archive supersede path shares the coupling: a mid→long
/// supersede mints a FRESH row (the insert ON CONFLICT long⇒NULL arm never
/// fires for it), so the guard must clear the inherited TTL.
#[test]
fn fbl01_supersede_tier_long_clears_inherited_expiry() {
    let conn = fresh_sqlite();
    let stale = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
    let id = seed(&conn, "fbl01-d", Tier::Mid, Some(&stale));

    let result = db::update_with_archive_on_supersede(
        &conn,
        &id,
        None,
        Some("superseding content"),
        Some(&Tier::Long),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        ai_memory::models::EditSource::Llm,
    )
    .expect("supersede succeeds");

    let (tier, expiry) = row_tier_and_expiry(&conn, &result.new_id);
    assert_eq!(tier, "long");
    assert_eq!(
        expiry, None,
        "supersede to long must not inherit the OLD row's live TTL"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #2332 (FBL-02)
// ─────────────────────────────────────────────────────────────────────

fn stored_expiry(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT expires_at FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .expect("row present")
}

/// A FUTURE expiry supplied in a negative-offset RFC3339 rendering sorts
/// lexicographically BELOW a UTC-rendered `now` (the pre-fix premature-GC
/// shape). The insert funnel must canonicalize it to the fixed-UTC form so
/// the same instant survives gc() and the byte order is chronological.
#[test]
fn fbl02_insert_canonicalizes_offset_expiry_and_gc_does_not_reap() {
    let conn = fresh_sqlite();
    let future = chrono::Utc::now() + chrono::Duration::hours(4);
    let offset = chrono::FixedOffset::west_opt(5 * 3600).expect("offset");
    let rendered = future.with_timezone(&offset).to_rfc3339();
    let id = seed(&conn, "fbl02-a", Tier::Mid, Some(&rendered));

    let stored = stored_expiry(&conn, &id).expect("expiry stored");
    assert!(
        stored.ends_with('Z'),
        "stored expiry must be the canonical fixed-UTC rendering, got {stored}"
    );
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    assert_eq!(
        stored_dt.timestamp_micros(),
        future.timestamp_micros(),
        "canonicalization must preserve the instant"
    );

    db::gc(&conn, true).expect("gc runs");
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        live, 1,
        "a 4h-in-the-future expiry must not be reaped just because its \
         offset rendering byte-sorts below now"
    );
}

/// The inverse hazard: an EXPIRED instant in a positive-offset rendering
/// byte-sorts ABOVE `now` (pre-fix over-retention). Canonicalized, gc()
/// reaps it on schedule.
#[test]
fn fbl02_insert_canonicalizes_positive_offset_expired_row_so_gc_reaps() {
    let conn = fresh_sqlite();
    let past = chrono::Utc::now() - chrono::Duration::hours(4);
    let offset = chrono::FixedOffset::east_opt(9 * 3600).expect("offset");
    let rendered = past.with_timezone(&offset).to_rfc3339();
    let id = seed(&conn, "fbl02-b", Tier::Short, Some(&rendered));

    db::gc(&conn, true).expect("gc runs");
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        live, 0,
        "an expired row must be reaped even when its +09:00 rendering \
         byte-sorts above now"
    );
}

/// The optimistic-update funnel canonicalizes a caller-patched offset
/// rendering too.
#[test]
fn fbl02_update_patch_canonicalizes_offset_expiry() {
    let conn = fresh_sqlite();
    let id = seed(&conn, "fbl02-c", Tier::Mid, None);
    let future = chrono::Utc::now() + chrono::Duration::days(2);
    let offset = chrono::FixedOffset::west_opt(3 * 3600).expect("offset");
    let rendered = future.with_timezone(&offset).to_rfc3339();

    db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&rendered),
        None,
        None,
        None,
        None,
    )
    .expect("update succeeds");

    let stored = stored_expiry(&conn, &id).expect("expiry stored");
    assert!(stored.ends_with('Z'), "canonical rendering, got {stored}");
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    assert_eq!(stored_dt.timestamp_micros(), future.timestamp_micros());
}

/// The federation-receive funnel (`insert_if_newer`) canonicalizes a
/// peer-supplied offset rendering.
#[test]
fn fbl02_insert_if_newer_canonicalizes_offset_expiry() {
    let conn = fresh_sqlite();
    let future = chrono::Utc::now() + chrono::Duration::hours(6);
    let offset = chrono::FixedOffset::west_opt(7 * 3600).expect("offset");
    let mem = Memory {
        id: "fbl02-d".to_string(),
        tier: Tier::Mid,
        namespace: "storage-chain".to_string(),
        title: "fed offset expiry".to_string(),
        content: "peer row".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        expires_at: Some(future.with_timezone(&offset).to_rfc3339()),
        metadata: json!({}),
        ..Memory::default()
    };
    let id = db::insert_if_newer(&conn, &mem).expect("federation insert");

    let stored = stored_expiry(&conn, &id).expect("expiry stored");
    assert!(stored.ends_with('Z'), "canonical rendering, got {stored}");
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    assert_eq!(stored_dt.timestamp_micros(), future.timestamp_micros());
}

// ─────────────────────────────────────────────────────────────────────
// #2338 (FBL-33) — G7 soft-loser recall down-weight
// ─────────────────────────────────────────────────────────────────────

/// After a G7 conserve, the soft-loser marker must actually LOWER the
/// loser's recall rank: a long-tier priority-8 conserved loser previously
/// outranked its fresh mid-tier winner at full score.
#[test]
fn fbl33_conserved_soft_loser_ranks_below_winner_on_keyword_recall() {
    let conn = fresh_sqlite();
    // Loser: long tier, high priority — pre-fix score dominance.
    let loser = Memory {
        id: "fbl33-loser".to_string(),
        tier: Tier::Long,
        namespace: "storage-chain".to_string(),
        title: "deploy target directive v1".to_string(),
        content: "the canonical deploy target is server X".to_string(),
        priority: 8,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({}),
        ..Memory::default()
    };
    let winner = Memory {
        id: "fbl33-winner".to_string(),
        tier: Tier::Mid,
        namespace: "storage-chain".to_string(),
        title: "deploy target directive v2".to_string(),
        content: "the canonical deploy target is server Y".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({}),
        ..Memory::default()
    };
    db::insert(&conn, &loser).expect("insert loser");
    db::insert(&conn, &winner).expect("insert winner");

    let rank = |conn: &Connection| -> Vec<String> {
        let (rows, _) = db::recall(
            conn,
            "deploy target",
            Some("storage-chain"),
            10,
            None,
            None,
            None,
            ai_memory::SECS_PER_HOUR,
            ai_memory::SECS_PER_DAY,
            None,
            None,
            false,
            None,
            None,
            None,
        )
        .expect("recall");
        rows.into_iter().map(|(m, _)| m.id).collect()
    };

    // Sanity: pre-conserve the long/priority-8 loser outranks the winner.
    let before = rank(&conn);
    assert_eq!(
        before.first().map(String::as_str),
        Some("fbl33-loser"),
        "pre-conserve the stale directive dominates (tier +3.0, priority +4.0)"
    );

    // Conserve the pair (writes the soft-loser marker + contradicts edge).
    db::conserve_contradiction(&conn, &loser, "fbl33-winner", None).expect("conserve");

    let after = rank(&conn);
    assert_eq!(
        after.first().map(String::as_str),
        Some("fbl33-winner"),
        "the promised soft down-weight must rank the conserved loser below its winner"
    );
    assert!(
        after.contains(&"fbl33-loser".to_string()),
        "the loser stays recallable (down-weighted, never hidden — G7 conserve)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #2336 (FBL-24) — embedding scans advance past decrypt-skipped batches
// ─────────────────────────────────────────────────────────────────────

/// A WHOLE batch of undecryptable envelopes must not read as
/// end-of-corpus: the scan exposes the RAW cursor + skip count so the
/// sweep steps past the poison window and reaches the rows behind it.
#[test]
fn fbl24_scan_advances_past_all_decrypt_skipped_batch() {
    let conn = fresh_sqlite();
    // Two consecutive-by-id rows whose envelope is garbage (undecryptable)
    // followed by a healthy plaintext row.
    for id in ["fbl24-a", "fbl24-b"] {
        seed(&conn, id, Tier::Long, None);
        conn.execute(
            "UPDATE memories SET encrypted_envelope = X'DEADBEEF' WHERE id = ?1",
            rusqlite::params![id],
        )
        .expect("plant garbage envelope");
    }
    seed(&conn, "fbl24-z", Tier::Long, None);

    // Page 1 (batch of 2): both rows decrypt-skip — the resolved chunk is
    // empty, but the RAW cursor covers the poison window and the skips are
    // counted (pre-fix: empty chunk => sweep reported SUCCESS and never
    // scanned further).
    let page1 = db::get_unembedded_ids_batch_after(&conn, None, 2).expect("page 1");
    assert!(page1.rows.is_empty(), "both rows are undecryptable");
    assert_eq!(page1.decrypt_skipped, 2, "skips are counted, not omitted");
    assert_eq!(
        page1.raw_last_id.as_deref(),
        Some("fbl24-b"),
        "the raw cursor advances past the poison window"
    );

    // Page 2 from the raw cursor: the healthy row behind the window IS
    // reached.
    let page2 =
        db::get_unembedded_ids_batch_after(&conn, page1.raw_last_id.as_deref(), 2).expect("page 2");
    assert_eq!(page2.decrypt_skipped, 0);
    assert_eq!(page2.rows.len(), 1);
    assert_eq!(page2.rows[0].0, "fbl24-z", "the post-window row is scanned");

    // Page 3: RAW fetch empty ⇔ true end of corpus (the only break
    // condition the sweeps use now).
    let page3 =
        db::get_unembedded_ids_batch_after(&conn, page2.raw_last_id.as_deref(), 2).expect("page 3");
    assert!(page3.raw_last_id.is_none(), "end of corpus");
    assert!(page3.rows.is_empty());

    // The reembed full-corpus scan exposes the same contract.
    let texts = db::get_memory_texts_batch(&conn, None, None, 2, None).expect("texts page 1");
    assert!(texts.rows.is_empty());
    assert_eq!(texts.decrypt_skipped, 2);
    assert_eq!(texts.raw_last_id.as_deref(), Some("fbl24-b"));
    let texts2 = db::get_memory_texts_batch(&conn, None, texts.raw_last_id.as_deref(), 2, None)
        .expect("texts page 2");
    assert_eq!(texts2.rows.len(), 1);
    assert_eq!(texts2.rows[0].0, "fbl24-z");
}

// ─────────────────────────────────────────────────────────────────────
// #2334 (FBL-15) — stats expiry-axis reconciliation
// ─────────────────────────────────────────────────────────────────────

/// `stats.total` stays the raw physical count while the additive `live` /
/// `expired_pending_gc` fields reconcile the expiry axis against the boot
/// inventory's live definition — no more phantom rows between surfaces.
#[test]
fn fbl15_stats_live_and_expired_pending_gc_reconcile_total() {
    let conn = fresh_sqlite();
    // One live row + one expired-awaiting-GC row.
    let future = (chrono::Utc::now() + chrono::Duration::days(2)).to_rfc3339();
    seed(&conn, "fbl15-live", Tier::Mid, Some(&future));
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    seed(&conn, "fbl15-expired", Tier::Short, Some(&past));

    let stats = db::stats(&conn, std::path::Path::new(":memory:")).expect("stats");
    assert_eq!(stats.total, 2, "total stays the raw physical count");
    assert_eq!(
        stats.live, 1,
        "live counts only non-expired lifecycle-visible rows (the boot definition)"
    );
    assert_eq!(
        stats.expired_pending_gc, 1,
        "the expired row awaiting the GC tick is surfaced, not hidden inside total"
    );

    // After gc() the axes re-converge.
    db::gc(&conn, true).expect("gc");
    let stats = db::stats(&conn, std::path::Path::new(":memory:")).expect("stats");
    assert_eq!(stats.total, 1);
    assert_eq!(stats.live, 1);
    assert_eq!(stats.expired_pending_gc, 0);
}

// ─────────────────────────────────────────────────────────────────────
// #2335 (FBL-20) — federation LWW expiry extension floor
// ─────────────────────────────────────────────────────────────────────

fn fed_mem(title: &str, updated_at: &str, expires_at: &str) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "storage-chain".to_string(),
        title: title.to_string(),
        content: format!("content of {title}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: updated_at.to_string(),
        updated_at: updated_at.to_string(),
        expires_at: Some(expires_at.to_string()),
        metadata: json!({}),
        ..Memory::default()
    }
}

/// A STALE losing peer (older updated_at) must not shorten the local
/// row's expiry — pre-fix the bare COALESCE adopted it verbatim and GC
/// reaped the live row early.
#[test]
fn fbl20_stale_loser_push_cannot_shorten_local_expiry() {
    let conn = fresh_sqlite();
    let now = chrono::Utc::now();
    let local_expiry = (now + chrono::Duration::days(7)).to_rfc3339();
    let local = fed_mem("fbl20 row", &now.to_rfc3339(), &local_expiry);
    let id = db::insert_if_newer(&conn, &local).expect("local insert");

    // Stale peer: same (title, namespace), OLDER updated_at, MUCH shorter
    // expiry.
    let peer = fed_mem(
        "fbl20 row",
        &(now - chrono::Duration::hours(2)).to_rfc3339(),
        &(now + chrono::Duration::hours(1)).to_rfc3339(),
    );
    let merged_id = db::insert_if_newer(&conn, &peer).expect("peer push");
    assert_eq!(merged_id, id, "(title, namespace) upsert merges");

    let stored = stored_expiry(&conn, &id).expect("expiry present");
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    let local_dt = chrono::DateTime::parse_from_rfc3339(&local_expiry).expect("parseable");
    assert_eq!(
        stored_dt.timestamp_micros(),
        local_dt.timestamp_micros(),
        "a stale losing peer must not shorten the local expiry (#1596 floor)"
    );
}

/// Even a WINNING peer (newer updated_at) with an EARLIER expiry keeps
/// the local later expiry — recall fold-extensions raise expires_at
/// without bumping updated_at, so the extension floor must hold across
/// federation (the merge is the MAX lattice join, convergent both ways).
#[test]
fn fbl20_winning_peer_with_earlier_expiry_keeps_local_extension() {
    let conn = fresh_sqlite();
    let now = chrono::Utc::now();
    let extended = (now + chrono::Duration::days(7)).to_rfc3339();
    let local = fed_mem(
        "fbl20 winner",
        &(now - chrono::Duration::hours(1)).to_rfc3339(),
        &extended,
    );
    let id = db::insert_if_newer(&conn, &local).expect("local insert");

    let peer = fed_mem(
        "fbl20 winner",
        &now.to_rfc3339(), // newer — wins the content tiebreak
        &(now + chrono::Duration::days(1)).to_rfc3339(), // earlier expiry
    );
    db::insert_if_newer(&conn, &peer).expect("peer push");

    // Content followed the winner…
    let content: String = conn
        .query_row(
            "SELECT content FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("row");
    assert_eq!(content, "content of fbl20 winner");
    // …but the expiry kept the local extension floor.
    let stored = stored_expiry(&conn, &id).expect("expiry present");
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    let ext_dt = chrono::DateTime::parse_from_rfc3339(&extended).expect("parseable");
    assert_eq!(
        stored_dt.timestamp_micros(),
        ext_dt.timestamp_micros(),
        "a winning peer's earlier expiry must not roll back a local fold-extension"
    );
}

/// A peer carrying a LATER expiry extends the local row (the other half
/// of the lattice join — replicas converge to the later instant).
#[test]
fn fbl20_peer_with_later_expiry_extends_local() {
    let conn = fresh_sqlite();
    let now = chrono::Utc::now();
    let local = fed_mem(
        "fbl20 extend",
        &now.to_rfc3339(),
        &(now + chrono::Duration::hours(2)).to_rfc3339(),
    );
    let id = db::insert_if_newer(&conn, &local).expect("local insert");

    let later = (now + chrono::Duration::days(3)).to_rfc3339();
    let peer = fed_mem(
        "fbl20 extend",
        &(now - chrono::Duration::hours(3)).to_rfc3339(), // stale loser
        &later,
    );
    db::insert_if_newer(&conn, &peer).expect("peer push");

    let stored = stored_expiry(&conn, &id).expect("expiry present");
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    let later_dt = chrono::DateTime::parse_from_rfc3339(&later).expect("parseable");
    assert_eq!(
        stored_dt.timestamp_micros(),
        later_dt.timestamp_micros(),
        "the merge converges to the LATER expiry regardless of tiebreak"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #2333 (FBL-03) — schema v87
// ─────────────────────────────────────────────────────────────────────

fn seed_with_kind_provenance(conn: &Connection, id: &str, prov: &str) -> String {
    let mem = Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "storage-chain".to_string(),
        title: format!("kp-{id}"),
        content: format!("content for {id}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({ "kind_provenance": prov }),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed")
}

fn column_kind_provenance(conn: &Connection, table: &str, id: &str) -> Option<String> {
    let sql = format!("SELECT kind_provenance FROM {table} WHERE id = ?1");
    conn.query_row(&sql, rusqlite::params![id], |r| r.get(0))
        .expect("row present")
}

/// archive→restore must round-trip the v79 denormalized column (the
/// v49/#1025 + v85/#2035 archive-column-parity contract).
#[test]
fn fbl03_archive_restore_roundtrips_kind_provenance() {
    let conn = fresh_sqlite();
    let id = seed_with_kind_provenance(&conn, "fbl03-a", "llm");
    assert_eq!(
        column_kind_provenance(&conn, "memories", &id).as_deref(),
        Some("llm"),
        "insert denormalizes the metadata carrier"
    );

    assert!(db::archive_memory(&conn, &id, Some("test")).expect("archive"));
    assert_eq!(
        column_kind_provenance(&conn, "archived_memories", &id).as_deref(),
        Some("llm"),
        "archive INSERT...SELECT must carry kind_provenance"
    );

    assert!(db::restore_archived(&conn, &id).expect("restore"));
    assert_eq!(
        column_kind_provenance(&conn, "memories", &id).as_deref(),
        Some("llm"),
        "restore must re-insert kind_provenance (column == metadata carrier)"
    );
}

/// A LEGACY archive row (archived pre-v87, column NULL) re-derives the
/// column from the metadata carrier on restore, vocab-guarded.
#[test]
fn fbl03_restore_rederives_kind_provenance_for_legacy_archive_rows() {
    let conn = fresh_sqlite();
    let id = seed_with_kind_provenance(&conn, "fbl03-b", "declared");
    assert!(db::archive_memory(&conn, &id, Some("test")).expect("archive"));
    // Simulate a pre-v87 archive row: column NULL, carrier intact.
    conn.execute(
        "UPDATE archived_memories SET kind_provenance = NULL WHERE id = ?1",
        rusqlite::params![&id],
    )
    .expect("null out");

    assert!(db::restore_archived(&conn, &id).expect("restore"));
    assert_eq!(
        column_kind_provenance(&conn, "memories", &id).as_deref(),
        Some("declared"),
        "legacy archive rows re-derive the column from metadata.kind_provenance"
    );
}

/// The federation-receive funnel (`insert_if_newer`) stamps the
/// denormalized column (pg store-lane parity).
#[test]
fn fbl03_insert_if_newer_stamps_kind_provenance() {
    let conn = fresh_sqlite();
    let mem = Memory {
        id: "fbl03-c".to_string(),
        tier: Tier::Long,
        namespace: "storage-chain".to_string(),
        title: "fed kp".to_string(),
        content: "peer row".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({ "kind_provenance": "channel_derived" }),
        ..Memory::default()
    };
    let id = db::insert_if_newer(&conn, &mem).expect("federation insert");
    assert_eq!(
        column_kind_provenance(&conn, "memories", &id).as_deref(),
        Some("channel_derived"),
        "insert_if_newer must denormalize the carrier like db::insert does"
    );
}

/// The v87 one-time heal normalizes pre-fix offset expiry renderings on a
/// LEGACY database (the #2332 stored-corpus half).
#[test]
fn fbl03_v87_migration_heals_offset_expiry_renderings() {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("storage-chain-fbl");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir");
    let path = dir.path().join("v87-heal.db");

    let future = chrono::Utc::now() + chrono::Duration::days(30);
    let offset = chrono::FixedOffset::west_opt(5 * 3600).expect("offset");
    let rendered = future.with_timezone(&offset).to_rfc3339();
    {
        let conn = db::open(&path).expect("open fresh db");
        let id = seed(&conn, "fbl03-d", Tier::Mid, None);
        // Plant a pre-fix verbatim offset rendering (bypassing the now-
        // canonicalizing funnels) and roll the version stamp back to 86 so
        // the reopen replays the v87 arm.
        conn.execute(
            "UPDATE memories SET expires_at = ?1 WHERE id = ?2",
            rusqlite::params![&rendered, &id],
        )
        .expect("plant offset rendering");
        conn.execute_batch(
            "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES (86);",
        )
        .expect("roll stamp back");
    }
    let conn = db::open(&path).expect("reopen runs the v87 arm");
    let stored = stored_expiry(&conn, "fbl03-d").expect("expiry present");
    assert!(
        stored.ends_with('Z'),
        "v87 heal must canonicalize the rendering, got {stored}"
    );
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored).expect("parseable");
    assert_eq!(
        stored_dt.timestamp_micros(),
        future.timestamp_micros(),
        "heal is instant-preserving"
    );
}
