// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2418 (L-EXPIRY-CANON) — `expires_at` canonicalization at EVERY
//! sqlite ingress, not just the create/update patch funnels.
//!
//! # The defect
//!
//! sqlite stores `memories.expires_at` as TEXT and every expiry consumer
//! (GC reap `expires_at < now`, list/recall visibility `expires_at > now`,
//! the #1596 touch/fold `MAX(expires_at, floor)` extension floors,
//! `storage::lifecycle::is_expired`) compares it **lexicographically**.
//! That is only chronological when every stored value shares ONE fixed-width
//! rendering. Postgres is structurally immune — it stores `TIMESTAMPTZ` —
//! so any sqlite rendering drift is also a **backend divergence**.
//!
//! Schema v87 (`normalize_expiry_rows`) healed the rows that already
//! existed; #2331/#2332 (FBL-01/02) closed the `insert` / `insert_if_newer`
//! / `update_with_expected_version` funnels. Three ingresses stayed open and
//! re-accrue the drift on every write:
//!
//! 1. **`touch`** — binds `(now + extend).to_rfc3339()` into
//!    `expires_at = MAX(expires_at, ?N)`. `to_rfc3339()` renders
//!    `+00:00` with an `AutoSi` fraction (0/3/6/9 digits), NOT the
//!    canonical fixed `.ffffffZ`.
//! 2. **`touch_many`** — same bind, same statement shape.
//! 3. **`fold_recall_accesses`** — same, off the recall-observation ledger's
//!    `t_max`.
//! 4. **`restore_archived` / `restore_archived_for_caller`** — copy
//!    `archived_memories.original_expires_at` straight back into
//!    `memories.expires_at` with no canonicalization, so any archive row
//!    that predates the v87 heal (or was re-materialized from an erasure
//!    cold-tier bundle) re-injects a legacy rendering into the LIVE table.
//!
//! Under `AI_MEMORY_ENCRYPT_AT_REST` a wrong-ordering reap is an
//! unrecoverable **premature crypto-erase**, which is why this is a
//! North-Star data-integrity pin rather than a cosmetic-format one.
//!
//! # The invariant these tests pin
//!
//! Every value that lands in `memories.expires_at` (and, on the way back
//! out, `archived_memories.original_expires_at`) is BYTE-IDENTICAL to
//! `validate::canonicalize_valid_time` of itself — i.e. canonicalization is
//! a fixpoint at rest. Fixed-width `YYYY-MM-DDTHH:MM:SS.ffffffZ`.

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use ai_memory::validate::canonicalize_valid_time;
use rusqlite::{Connection, params};

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

fn seed(conn: &Connection, id: &str, tier: Tier, expires_at: Option<&str>) -> String {
    let mem = Memory {
        id: id.to_string(),
        tier,
        namespace: "expiry-canon".to_string(),
        title: format!("title-{id}"),
        content: format!("content for {id}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        expires_at: expires_at.map(str::to_string),
        metadata: serde_json::json!({}),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed memory")
}

fn expiry(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT expires_at FROM memories WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )
    .expect("row present")
}

/// The load-bearing assertion: canonicalization must be a FIXPOINT on the
/// stored bytes. Any other RFC3339 spelling of the same instant fails here.
#[track_caller]
fn assert_canonical_at_rest(stored: Option<&str>, what: &str) {
    let Some(v) = stored else {
        panic!("{what}: expected a stored expires_at, found NULL");
    };
    assert_eq!(
        canonicalize_valid_time(v).as_deref(),
        Some(v),
        "#2418 {what}: stored expires_at {v:?} is not the canonical fixed-UTC \
         rendering — lexicographic expiry comparison is no longer chronological"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 1. update funnel — the #1596 TTL extension floors (touch / touch_many /
//    fold). These WRITE into expires_at; they are ingress, not read-path.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn touch_extension_floor_lands_canonical() {
    let conn = fresh_sqlite();
    // Near-term expiry so the +1d / +7d extension floor definitively wins
    // the MAX() and the funnel's own rendering is what lands.
    let soon =
        canonicalize_valid_time(&(chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339())
            .expect("canonical seed");
    let id = seed(&conn, "canon-touch", Tier::Short, Some(&soon));

    db::touch(&conn, &id, 86_400, 604_800).expect("touch");

    let after = expiry(&conn, &id);
    assert_ne!(
        after.as_deref(),
        Some(soon.as_str()),
        "floor must have moved"
    );
    assert_canonical_at_rest(after.as_deref(), "touch");
}

#[test]
fn touch_many_extension_floor_lands_canonical() {
    let conn = fresh_sqlite();
    let soon =
        canonicalize_valid_time(&(chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339())
            .expect("canonical seed");
    let a = seed(&conn, "canon-tm-a", Tier::Short, Some(&soon));
    let b = seed(&conn, "canon-tm-b", Tier::Mid, Some(&soon));

    let n = db::touch_many(&conn, &[a.as_str(), b.as_str()], 86_400, 604_800).expect("touch_many");
    assert!(n > 0, "touch_many must have updated rows");

    assert_canonical_at_rest(expiry(&conn, &a).as_deref(), "touch_many short");
    assert_canonical_at_rest(expiry(&conn, &b).as_deref(), "touch_many mid");
}

#[test]
fn fold_recall_accesses_extension_floor_lands_canonical() {
    let conn = fresh_sqlite();
    let soon =
        canonicalize_valid_time(&(chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339())
            .expect("canonical seed");
    let id = seed(&conn, "canon-fold", Tier::Short, Some(&soon));

    ai_memory::observations::record_recall_with_identity(
        &conn,
        "recall-2418",
        &[ai_memory::observations::Candidate {
            memory_id: id.as_str(),
            retriever: "fts5",
            rank: 1,
            score: 1.0,
        }],
        Some("agent-2418"),
        Some("expiry-canon"),
    )
    .expect("record recall observation");

    let folded = db::fold_recall_accesses(&conn, 86_400, 604_800).expect("fold");
    assert!(folded > 0, "fold must have processed the observation");

    let after = expiry(&conn, &id);
    assert_ne!(
        after.as_deref(),
        Some(soon.as_str()),
        "floor must have moved"
    );
    assert_canonical_at_rest(after.as_deref(), "fold_recall_accesses");
}

// ─────────────────────────────────────────────────────────────────────
// 2. original_expires_at — BOTH restore funnels re-inject the archived
//    rendering into the live table.
// ─────────────────────────────────────────────────────────────────────

/// A legacy / bundle-materialized archive row carrying a NON-UTC offset
/// rendering. `2027-01-01T00:00:00-11:00` is `2027-01-01T11:00:00Z`; as
/// bytes it sorts BELOW a canonical `2027-01-01T05:00:00.000000Z` even
/// though it is six hours LATER — the premature-reap / crypto-erase shape.
const LEGACY_OFFSET_EXPIRY: &str = "2027-01-01T00:00:00-11:00";

fn archive_then_poison(conn: &Connection, id: &str) {
    assert!(
        db::archive_memory(conn, id, Some("2418-test")).expect("archive"),
        "archive_memory must report success"
    );
    conn.execute(
        "UPDATE archived_memories SET original_expires_at = ?1 WHERE id = ?2",
        params![LEGACY_OFFSET_EXPIRY, id],
    )
    .expect("poison the archived rendering");
}

#[test]
fn restore_archived_canonicalizes_original_expires_at() {
    let conn = fresh_sqlite();
    let id = seed(
        &conn,
        "canon-restore",
        Tier::Mid,
        Some("2027-06-01T00:00:00Z"),
    );
    archive_then_poison(&conn, &id);

    assert!(
        db::restore_archived(&conn, &id).expect("restore"),
        "restore must report success"
    );

    let after = expiry(&conn, &id);
    assert_canonical_at_rest(after.as_deref(), "restore_archived");
    // Instant preserved — canonicalization must never move the deadline.
    assert_eq!(
        after.as_deref(),
        canonicalize_valid_time(LEGACY_OFFSET_EXPIRY).as_deref(),
        "#2418: restore must preserve the INSTANT while fixing the rendering"
    );
}

#[test]
fn restore_archived_for_caller_canonicalizes_original_expires_at() {
    let conn = fresh_sqlite();
    let id = seed(
        &conn,
        "canon-restore-caller",
        Tier::Mid,
        Some("2027-06-01T00:00:00Z"),
    );
    archive_then_poison(&conn, &id);

    assert!(
        db::restore_archived_for_caller(&conn, &id, "agent-2418").expect("restore"),
        "caller-scoped restore must report success (legacy unowned row)"
    );

    let after = expiry(&conn, &id);
    assert_canonical_at_rest(after.as_deref(), "restore_archived_for_caller");
    assert_eq!(
        after.as_deref(),
        canonicalize_valid_time(LEGACY_OFFSET_EXPIRY).as_deref(),
        "#2418: caller-scoped restore must preserve the INSTANT"
    );
}

/// An UNPARSEABLE archived rendering must pass through byte-for-byte —
/// fail-safe. Canonicalization is a repair, never an eraser: we degrade to
/// the prior behaviour rather than destroy a value the gates admitted.
#[test]
fn restore_archived_preserves_unparseable_expiry_byte_for_byte() {
    let conn = fresh_sqlite();
    let id = seed(
        &conn,
        "canon-restore-junk",
        Tier::Mid,
        Some("2027-06-01T00:00:00Z"),
    );
    assert!(db::archive_memory(&conn, &id, Some("2418-test")).expect("archive"));
    conn.execute(
        "UPDATE archived_memories SET original_expires_at = 'not-a-timestamp' WHERE id = ?1",
        params![&id],
    )
    .expect("poison with junk");

    assert!(db::restore_archived(&conn, &id).expect("restore"));
    assert_eq!(
        expiry(&conn, &id).as_deref(),
        Some("not-a-timestamp"),
        "#2418: an unparseable value must survive verbatim (degrade, never destroy)"
    );
}

/// A NULL `original_expires_at` (permanent row) must stay NULL — the
/// canonicalizer must not synthesize a deadline where there was none.
#[test]
fn restore_archived_keeps_null_expiry_null() {
    let conn = fresh_sqlite();
    let id = seed(&conn, "canon-restore-null", Tier::Long, None);
    assert!(db::archive_memory(&conn, &id, Some("2418-test")).expect("archive"));
    assert!(db::restore_archived(&conn, &id).expect("restore"));
    assert_eq!(
        expiry(&conn, &id),
        None,
        "#2418: a permanent row must restore with expires_at still NULL"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. create funnel + sqlite/postgres parity.
// ─────────────────────────────────────────────────────────────────────

/// The create funnel (#2332) re-pinned here so the four completeness
/// criteria live in ONE file, and widened with the ordering consequence:
/// two rows seeded from semantically-ordered offset renderings must ORDER
/// correctly under the lexicographic predicate the storage layer uses.
#[test]
fn create_funnel_canonicalizes_and_orders_chronologically() {
    let conn = fresh_sqlite();
    // earlier instant, LATER-sorting bytes if stored verbatim.
    let earlier = "2027-01-01T00:00:00-11:00"; // = 2027-01-01T11:00:00Z
    let later = "2027-01-01T23:00:00+00:00"; // = 2027-01-01T23:00:00Z
    let a = seed(&conn, "canon-create-a", Tier::Mid, Some(earlier));
    let b = seed(&conn, "canon-create-b", Tier::Mid, Some(later));

    let ea = expiry(&conn, &a);
    let eb = expiry(&conn, &b);
    assert_canonical_at_rest(ea.as_deref(), "create funnel (a)");
    assert_canonical_at_rest(eb.as_deref(), "create funnel (b)");
    assert!(
        ea < eb,
        "#2418: lexicographic order must match chronological order — got {ea:?} vs {eb:?}"
    );
}

/// sqlite/postgres parity assertion (non-live half).
///
/// Postgres stores `expires_at` as `TIMESTAMPTZ`, so its ordering is
/// structurally chronological and its read-back rendering is derived from
/// the instant, not from the caller's spelling. The sqlite TEXT column can
/// only match that contract if every ingress renders the ONE canonical
/// form. This test pins the sqlite side of that contract across every
/// funnel this issue touches: whatever spelling a caller supplies, both
/// backends agree on the INSTANT and sqlite's bytes are the canonical
/// rendering of it.
#[test]
fn sqlite_expiry_rendering_matches_the_timestamptz_contract() {
    let conn = fresh_sqlite();
    // Four spellings of the SAME instant — what a TIMESTAMPTZ column
    // collapses to one value. sqlite must collapse them identically.
    let spellings = [
        "2027-03-01T12:00:00Z",
        "2027-03-01T12:00:00+00:00",
        "2027-03-01T12:00:00.000Z",
        "2027-03-01T21:00:00+09:00",
    ];
    let canonical = canonicalize_valid_time(spellings[0]).expect("canonical");
    for (i, spelling) in spellings.iter().enumerate() {
        let id = seed(
            &conn,
            &format!("canon-parity-{i}"),
            Tier::Mid,
            Some(spelling),
        );
        let stored = expiry(&conn, &id);
        assert_eq!(
            stored.as_deref(),
            Some(canonical.as_str()),
            "#2418 parity: spelling {spelling:?} must persist as the ONE rendering \
             a postgres TIMESTAMPTZ round-trip would yield"
        );
    }
    // Fixed width is what makes the byte comparison total.
    assert_eq!(
        canonical.len(),
        27,
        "#2418: canonical rendering must be fixed-width YYYY-MM-DDTHH:MM:SS.ffffffZ"
    );
}

/// Live postgres twin — same four spellings through the SAL surface; the
/// backend must agree with sqlite on the INSTANT. Skipped without a live
/// instance per the Track C/D `AI_MEMORY_TEST_POSTGRES_URL` convention
/// (issue #79).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn postgres_expiry_parity_2418() {
    use ai_memory::store::MemoryStore as _;

    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — postgres half skipped");
        return;
    };
    let pg = match ai_memory::store::postgres::PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("PostgresStore::connect failed: {e}");
            return;
        }
    };
    let ctx = ai_memory::store::CallerContext::for_admin("parity-2418");
    let spellings = [
        "2027-03-01T12:00:00Z",
        "2027-03-01T12:00:00+00:00",
        "2027-03-01T12:00:00.000Z",
        "2027-03-01T21:00:00+09:00",
    ];
    let canonical = canonicalize_valid_time(spellings[0]).expect("canonical");
    for (i, spelling) in spellings.iter().enumerate() {
        let id = format!("canon-parity-pg-{i}");
        let mem = Memory {
            id: id.clone(),
            namespace: "expiry-canon".to_string(),
            title: format!("parity-{i}"),
            content: "parity body".to_string(),
            tier: Tier::Mid,
            expires_at: Some((*spelling).to_string()),
            ..Memory::default()
        };
        let _ = pg.delete(&ctx, &id).await;
        pg.store(&ctx, &mem).await.expect("pg store");
        let got = pg
            .get(&ctx, &id)
            .await
            .expect("pg get")
            .expires_at
            .expect("pg expiry present");
        assert_eq!(
            canonicalize_valid_time(&got).as_deref(),
            Some(canonical.as_str()),
            "#2418 parity: postgres and sqlite must agree on the instant for {spelling:?}"
        );
        let _ = pg.delete(&ctx, &id).await;
    }
}
