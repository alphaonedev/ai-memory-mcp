// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3345 — the curator's per-sweep self-report was a first-class,
//! permanently-retained, EMBEDDED memory.
//!
//! ## The measurement (f1 macOS, `curator --daemon --interval-secs 300`)
//!
//! ```text
//! ~/.claude/ai-memory.db   25,671 memories total
//!                          24,930 in _curator/reports   (287/day since 2026-06-06)
//!                          24,801 of those EMBEDDED     (one paid call each)
//!                             512 memories outside system namespaces
//! ```
//!
//! 97% of the store — and of every backfill / re-embed pass over it — was the
//! curator talking about itself, at recurring embedding cost, polluting stats
//! and inventory.
//!
//! ## The controls under test
//!
//! 1. **No embedding is ever spent on a substrate row.** Every unembedded
//!    selector carries [`ai_memory::visibility::SQL_AND_NOT_SUBSTRATE`], built
//!    from the SAME closed list the #3348 read predicate uses — so this is one
//!    posture with two forms, not a second visibility mechanism. Naming the
//!    namespace remains the opt-in on the operator-driven `reembed` scan.
//! 2. **Bounded retention.** The per-sweep row is `Tier::Short` with an
//!    explicit 24 h expiry, and each cycle folds the day into ONE summary row
//!    so the aggregate outlives the detail.
//! 3. **The backlog collapses safely.** `--prune-reports` is a dry run by
//!    default, rolls each affected day up BEFORE touching anything, only ever
//!    STAMPS the expiry the row should have had, and is idempotent — it never
//!    deletes a row.
//!
//! Every assertion below fails against the pre-#3345 tree: the writer produced
//! `Tier::Mid` + `expires_at: None`, and all four unembedded selectors returned
//! the substrate rows.

use ai_memory::autonomy::{
    CURATOR_REPORT_TTL_HOURS, CURATOR_REPORTS_DAILY_NAMESPACE, CURATOR_REPORTS_NAMESPACE,
};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;

/// An ordinary caller namespace — the row that must ALWAYS stay embeddable.
const ORDINARY_NS: &str = "proj/notes";

/// How many curator sweeps the Ask's regression drives.
const SWEEPS: usize = 5;

fn open_db() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::Builder::new()
        .prefix("ai-memory-3345-")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("m.db");
    drop(ai_memory::db::open(&path).expect("init"));
    let conn = ai_memory::db::open(&path).expect("open");
    (dir, conn)
}

/// Seed a row with a NULL embedding, so it is a backfill candidate.
fn seed(conn: &rusqlite::Connection, namespace: &str, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("body of {title}"),
        priority: 5,
        confidence: 1.0,
        source: "test-3345".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": "ai:curator"}),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("db::insert");
    id
}

/// Seed one row in every substrate namespace shape plus one ordinary row.
/// Returns the ordinary row's id — the ONLY id any embedding scan may return.
fn seed_substrate_and_ordinary(conn: &rusqlite::Connection) -> String {
    seed(conn, CURATOR_REPORTS_NAMESPACE, "curator cycle @ seeded");
    seed(conn, "_messages/ai:carol", "a2a mail");
    seed(conn, "_inbox/ai:carol", "inbox mail");
    seed(conn, "_subscriptions/ai:carol", "subscription");
    seed(conn, "_agents", "registry row");
    seed(conn, "_agent_sessions", "session row");
    seed(conn, ORDINARY_NS, "an ordinary memory")
}

fn write_self_report(conn: &rusqlite::Connection) {
    let pass = ai_memory::autonomy::AutonomyPassReport::default();
    ai_memory::autonomy::persist_self_report(conn, 12, &pass, 1, 0, 0, 0)
        .expect("persist_self_report");
}

fn report_rows(conn: &rusqlite::Connection) -> Vec<(String, Option<String>)> {
    let mut stmt = conn
        .prepare("SELECT tier, expires_at FROM memories WHERE namespace = ?1")
        .expect("prepare");
    let rows = stmt
        .query_map([CURATOR_REPORTS_NAMESPACE], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .expect("query");
    rows.collect::<rusqlite::Result<Vec<_>>>().expect("collect")
}

// ---------------------------------------------------------------------------
// 1. no embedding is ever spent on a substrate row
// ---------------------------------------------------------------------------

/// DENIED + ALLOWED in one: all four sqlite unembedded selectors must return
/// the ordinary row and NOTHING from a substrate namespace. Pre-#3345 each of
/// them returned all seven rows, which is where the 24,801 paid embeddings
/// came from.
#[test]
fn no_unembedded_selector_offers_a_substrate_row_for_embedding() {
    let (_dir, conn) = open_db();
    let ordinary = seed_substrate_and_ordinary(&conn);

    let unbounded = ai_memory::db::get_unembedded_ids(&conn).expect("get_unembedded_ids");
    let batch = ai_memory::db::get_unembedded_ids_batch(&conn, 100).expect("batch");
    let keyset_start =
        ai_memory::db::get_unembedded_ids_batch_after(&conn, None, 100).expect("keyset start");
    let keyset_cursor =
        ai_memory::db::get_unembedded_ids_batch_after(&conn, Some(""), 100).expect("keyset cursor");

    for (label, ids) in [
        (
            "get_unembedded_ids",
            unbounded
                .iter()
                .map(|(id, ..)| id.clone())
                .collect::<Vec<_>>(),
        ),
        (
            "get_unembedded_ids_batch",
            batch.iter().map(|(id, ..)| id.clone()).collect::<Vec<_>>(),
        ),
        (
            "get_unembedded_ids_batch_after(None)",
            keyset_start
                .rows
                .iter()
                .map(|(id, ..)| id.clone())
                .collect::<Vec<_>>(),
        ),
        (
            "get_unembedded_ids_batch_after(cursor)",
            keyset_cursor
                .rows
                .iter()
                .map(|(id, ..)| id.clone())
                .collect::<Vec<_>>(),
        ),
    ] {
        assert_eq!(
            ids,
            vec![ordinary.clone()],
            "#3345: {label} must offer the embedder the ordinary row and NO substrate row"
        );
    }
}

/// The operator-driven `reembed` scan uses the #3348 opt-in shape: an UNSCOPED
/// sweep skips substrate rows (the f1 "re-embed 25k memories" that was 97%
/// curator reports), while NAMING the namespace still heals it on purpose.
#[test]
fn reembed_scan_skips_substrate_unless_the_namespace_is_named() {
    let (_dir, conn) = open_db();
    let ordinary = seed_substrate_and_ordinary(&conn);

    let unscoped = ai_memory::db::get_memory_texts_batch(&conn, None, None, 100, None)
        .expect("unscoped reembed scan");
    let ids: Vec<&str> = unscoped.rows.iter().map(|(id, ..)| id.as_str()).collect();
    assert_eq!(
        ids,
        vec![ordinary.as_str()],
        "#3345: an unscoped reembed must not pay to re-embed substrate bookkeeping"
    );

    let named = ai_memory::db::get_memory_texts_batch(
        &conn,
        Some(CURATOR_REPORTS_NAMESPACE),
        None,
        100,
        None,
    )
    .expect("named reembed scan");
    assert_eq!(
        named.rows.len(),
        1,
        "#3345: naming the namespace is the opt-in — it must still be reachable"
    );
}

// ---------------------------------------------------------------------------
// 2. bounded retention
// ---------------------------------------------------------------------------

/// The Ask's regression, verbatim: N curator sweeps produce at most N
/// short-tier rows, with no embedding spent on any of them.
#[test]
fn n_sweeps_produce_at_most_n_short_tier_rows_with_no_embeddings() {
    let (_dir, conn) = open_db();
    for _ in 0..SWEEPS {
        write_self_report(&conn);
        // Distinct titles come from the RFC3339 stamp; a same-instant upsert
        // would collapse two sweeps into one row, which still satisfies "at
        // most N" — the bound is the assertion, not the exact count.
        std::thread::sleep(std::time::Duration::from_millis(2));
    }

    let rows = report_rows(&conn);
    assert!(
        !rows.is_empty() && rows.len() <= SWEEPS,
        "#3345: {SWEEPS} sweeps must leave at most {SWEEPS} rows, got {}",
        rows.len()
    );
    for (tier, expires_at) in &rows {
        assert_eq!(
            tier, "short",
            "#3345: a self-report is bookkeeping, not a mid-tier memory"
        );
        let expiry = expires_at
            .as_deref()
            .expect("#3345: every self-report must carry an explicit expiry");
        let parsed = chrono::DateTime::parse_from_rfc3339(expiry).expect("RFC3339 expiry");
        let horizon = chrono::Utc::now() + chrono::Duration::hours(CURATOR_REPORT_TTL_HOURS + 1);
        assert!(
            parsed < horizon,
            "#3345: retention must be bounded at ~{CURATOR_REPORT_TTL_HOURS}h, got {expiry}"
        );
    }

    let offered = ai_memory::db::get_unembedded_ids(&conn).expect("unembedded");
    assert!(
        offered.is_empty(),
        "#3345: not one of the {SWEEPS} sweep reports may be offered to the embedder, got {}",
        offered.len()
    );
}

/// The day's detail is bounded, but the day's INFORMATION is not lost: the
/// rollup folds every cycle into one summary row whose counters are the sum of
/// the cycles it replaced.
#[test]
fn the_daily_rollup_preserves_the_days_aggregate() {
    let (_dir, conn) = open_db();
    for _ in 0..3 {
        write_self_report(&conn);
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let folded = ai_memory::curator::reports::roll_up_today(&conn).expect("rollup");
    assert!(folded >= 1, "the day's cycles must be folded, got {folded}");

    let content: String = conn
        .query_row(
            "SELECT content FROM memories WHERE namespace = ?1",
            [CURATOR_REPORTS_DAILY_NAMESPACE],
            |r| r.get(0),
        )
        .expect("exactly one daily summary row");
    let body: serde_json::Value = serde_json::from_str(&content).expect("summary JSON");
    assert_eq!(
        body["cycles"].as_u64().expect("cycles"),
        u64::try_from(folded).expect("cycles fit u64"),
        "the summary must report the cycles it folded"
    );
    assert_eq!(
        body["totals"]["auto_tagged"].as_u64().expect("auto_tagged"),
        u64::try_from(folded).expect("cycles fit u64"),
        "counters must be SUMMED across the day, not overwritten"
    );

    // Idempotent: re-folding the same day replaces the summary, never appends.
    ai_memory::curator::reports::roll_up_today(&conn).expect("second rollup");
    let daily: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [CURATOR_REPORTS_DAILY_NAMESPACE],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(daily, 1, "#3345: one summary row per day, re-fold or not");
}

// ---------------------------------------------------------------------------
// 3. the historical backlog collapses safely
// ---------------------------------------------------------------------------

/// Seed the shape the f1 store was really in: `Tier::Mid` report rows.
///
/// NOT "rows with no expiry" — that shape is unreachable through `db::insert`,
/// which backfills the tier default (#1466). The measured 24,930 rows were
/// mid-tier rows stamped `created_at + 7 days` that nothing ever reaped, which
/// is exactly what this seeds.
fn seed_backlog(conn: &rusqlite::Connection, days: &[&str], per_day: usize) -> usize {
    let mut n = 0;
    for day in days {
        for i in 0..per_day {
            let created = format!("{day}T0{i}:00:00+00:00");
            let mem = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                tier: Tier::Mid,
                namespace: CURATOR_REPORTS_NAMESPACE.to_string(),
                title: format!("curator cycle @ {created}"),
                content: json!({"cycle_ts": created, "auto_tagged": 2}).to_string(),
                priority: 2,
                confidence: 1.0,
                source: "test-3345".to_string(),
                created_at: created.clone(),
                updated_at: created,
                expires_at: None,
                metadata: json!({"agent_id": "ai:curator"}),
                memory_kind: MemoryKind::Observation,
                confidence_source: ConfidenceSource::CallerProvided,
                version: 1,
                ..Memory::default()
            };
            ai_memory::db::insert(conn, &mem).expect("seed backlog");
            n += 1;
        }
    }
    n
}

#[test]
fn prune_is_a_dry_run_by_default_and_idempotent_when_applied() {
    let (_dir, conn) = open_db();
    let seeded = seed_backlog(&conn, &["2026-06-06", "2026-06-07"], 3);

    let physical_before: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count");

    // DRY RUN (the default) reports the backlog and writes nothing.
    let dry = ai_memory::curator::reports::prune_reports(&conn, false).expect("dry run");
    assert!(dry.dry_run, "the default mode must be a dry run");
    assert_eq!(
        dry.backlog, seeded,
        "the dry run must report the real count"
    );
    assert_eq!(dry.stamped, 0, "a dry run must stamp nothing");
    assert_eq!(dry.days_rolled_up, 0, "a dry run must write no summary");
    let still_backlog: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND tier <> 'short'",
            [CURATOR_REPORTS_NAMESPACE],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        still_backlog,
        i64::try_from(seeded).expect("seeded fits i64"),
        "a dry run must leave every row untouched"
    );

    // APPLY: fold both days, stamp every row, delete nothing.
    let applied = ai_memory::curator::reports::prune_reports(&conn, true).expect("apply");
    assert!(!applied.dry_run);
    assert_eq!(applied.stamped, seeded, "every backlog row must be stamped");
    assert_eq!(applied.days_rolled_up, 2, "both seeded days must be folded");

    let daily: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [CURATOR_REPORTS_DAILY_NAMESPACE],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(daily, 2, "one summary row per collapsed day");

    let physical_after: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count");
    assert_eq!(
        physical_after,
        physical_before + 2,
        "#3345: the collapse must DELETE nothing — it stamps retention and adds \
         the two daily summaries; reaping belongs to the audited GC path"
    );

    // Every re-targeted expiry is derived from the row's OWN created_at, so a
    // June backlog row is already past its window rather than given a fresh
    // 24h — and the tier moves with it, which is what makes the pass
    // idempotent.
    let future: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND expires_at > ?2",
            rusqlite::params![CURATOR_REPORTS_NAMESPACE, chrono::Utc::now().to_rfc3339()],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        future, 0,
        "a 2026-06 backlog row must not be handed a fresh retention window"
    );
    let non_short: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND tier <> 'short'",
            [CURATOR_REPORTS_NAMESPACE],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        non_short, 0,
        "#3345: a collapsed row carries the short-tier retention marker"
    );

    // IDEMPOTENT: a second apply finds nothing left to do.
    let again = ai_memory::curator::reports::prune_reports(&conn, true).expect("second apply");
    assert_eq!(again.backlog, 0, "the backlog is drained");
    assert_eq!(again.stamped, 0, "a re-run must stamp nothing");
}

/// A backlog deeper than `PRUNE_MAX_DAYS` is collapsed over several runs — and
/// crucially, a day the pass did NOT fold is left entirely alone. Stamping a
/// row whose day has no summary standing behind it is the one way this
/// collapse could lose information, so the pairing is structural: fold day D,
/// then stamp only day D.
#[test]
fn prune_never_stamps_a_day_it_did_not_fold() {
    let (_dir, conn) = open_db();
    let max_days = ai_memory::curator::reports::PRUNE_MAX_DAYS;
    let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
        .expect("base")
        .with_timezone(&chrono::Utc);
    let days: Vec<String> = (0..max_days + 2)
        .map(|d| {
            (base + chrono::Duration::days(i64::try_from(d).expect("fits")))
                .format("%Y-%m-%d")
                .to_string()
        })
        .collect();
    let day_refs: Vec<&str> = days.iter().map(String::as_str).collect();
    let seeded = seed_backlog(&conn, &day_refs, 1);

    let applied = ai_memory::curator::reports::prune_reports(&conn, true).expect("apply");
    assert_eq!(
        applied.days_rolled_up, max_days,
        "one pass folds at most PRUNE_MAX_DAYS days"
    );
    assert_eq!(
        applied.stamped, max_days,
        "exactly the folded days' rows are stamped — never a day with no summary"
    );

    let untouched: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND tier <> 'short'",
            [CURATOR_REPORTS_NAMESPACE],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        untouched,
        i64::try_from(seeded - max_days).expect("fits"),
        "the un-folded tail keeps its legacy retention until a later pass folds it"
    );

    // A second pass completes the job — resumable, never destructive.
    let second = ai_memory::curator::reports::prune_reports(&conn, true).expect("second apply");
    assert_eq!(
        second.stamped, 2,
        "the remaining two days collapse next pass"
    );
}

/// The collapse only ever moves an expiry EARLIER. A row already scheduled to
/// die sooner than the #3345 window keeps its own, shorter expiry — the
/// collapse shortens over-long substrate retention (its purpose) but can never
/// extend the life of a row the store was already going to reap.
#[test]
fn prune_only_ever_moves_an_expiry_earlier() {
    let (_dir, conn) = open_db();
    seed_backlog(&conn, &["2026-06-06"], 1);
    let sooner = "2026-06-06T00:30:00+00:00";
    conn.execute(
        "UPDATE memories SET expires_at = ?1 WHERE namespace = ?2",
        rusqlite::params![sooner, CURATOR_REPORTS_NAMESPACE],
    )
    .expect("hand-set a sooner expiry");

    let report = ai_memory::curator::reports::prune_reports(&conn, true).expect("apply");
    assert_eq!(report.stamped, 1, "the mid-tier row is still backlog");
    let (kept, tier): (String, String) = conn
        .query_row(
            "SELECT expires_at, tier FROM memories WHERE namespace = ?1",
            [CURATOR_REPORTS_NAMESPACE],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read row");
    assert_eq!(
        kept, sooner,
        "#3345: an expiry already inside the window is kept — the collapse never lengthens"
    );
    assert_eq!(tier, "short", "the retention marker still moves");
}

// ---------------------------------------------------------------------------
// 4. stats stops hiding the pollution
// ---------------------------------------------------------------------------

#[test]
fn stats_reports_the_substrate_share_and_keeps_total_physical() {
    let (dir, conn) = open_db();
    seed_substrate_and_ordinary(&conn);
    let stats = ai_memory::db::stats(&conn, &dir.path().join("m.db")).expect("stats");
    assert_eq!(
        stats.total, 7,
        "#2334: `total` keeps its documented meaning — the RAW physical count"
    );
    assert_eq!(
        stats.substrate, 6,
        "#3345: the substrate share must be visible, or 24,930 curator reports \
         read as 24,930 memories"
    );
    assert_eq!(
        stats.total - stats.substrate,
        1,
        "the operator-legible corpus size is total - substrate"
    );
}
