// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Boids predator-plan items 1+2 (#3922) — recall trust-weighting
//! kill-test, sqlite half. 5-agent vote `4d3ea1c5`; spec
//! `/ai-scratch/conductor/BOIDS-ITEMS-1-2-RULING-and-SPEC.md`.
//!
//! Item 1 (R1): the recall POPULARITY term is capped by the named const
//! `models::ACCESS_SCORE_CAP` (10), so `MIN(access_count, CAP) * 0.1`
//! contributes at most +1.0 — a tiebreak, never a driver. Before the cut
//! a hot row bought +5.0 and dominated textual relevance.
//!
//! Item 2 (R3): the score reads confidence PROVENANCE, stored value
//! untouched: `CASE WHEN confidence_source = 'default' OR
//! confidence_source IS NULL THEN 0.5 ELSE confidence END * 2.0`. A row
//! whose confidence was never assessed (caller omitted it ⇒
//! `ConfidenceSource::Default`) scores as neutral 0.5 instead of the
//! compiled 1.0 fallback; an explicitly-asserted confidence keeps full
//! weight. A11 (f2r security pre-cut): the legacy / NULL arm is pinned
//! EXPLICITLY, asserted not assumed. Measured schema reality:
//! `memories.confidence_source` is `TEXT NOT NULL DEFAULT 'caller_provided'`
//! on BOTH backends (sqlite v39; postgres bootstrap `postgres_schema.sql`
//! plus `migrate_v38` / `0020_...sql`), so a genuinely-NULL provenance row does
//! NOT exist in `memories` on either backend and the CASE's `OR ... IS NULL`
//! arm is DEFENSIVE-DEAD there (the only nullable `confidence_source` is on
//! `archived_memories`, which the score sites never read). What A11 turns on
//! and what is testable: a legacy/explicit `'caller_provided'` row takes ELSE
//! and keeps its stored confidence. `'caller_provided'` is stamped for BOTH explicit-caller
//! and legacy-backfill rows (`mcp/tools/store/validation.rs`), so it
//! CANNOT be neutralized without de-weighting explicit values — that
//! residual is disclosed in the GA line (A10).
//!
//! R2: the recall MAINTENANCE verbs (`fold_recall_accesses`, `touch`,
//! `touch_many`) no longer ESCALATE — the mid→long auto-promotion, its
//! `updated_at` rewrite and the priority decade ladder are gone. Recall
//! popularity can no longer rewrite a row's tier, recency or priority;
//! `memory_promote` is the sole tier-raising verb. The fold STILL folds
//! `access_count` (cap 1M), `last_accessed_at` and the per-tier TTL
//! floor-extend (#1596).
//!
//! DOCUMENTED NON-GOAL (spec R5, deferred behind the benchmark gate with
//! plan items 4-6): this file does NOT pin "N distinct readers vs 1
//! reader × N recalls". Per-reader trust weighting needs a bound reader
//! identity in the recall ledger; the ledger's `agent_id` is the
//! read-visibility caller (None on MCP stdio unless `AI_MEMORY_AGENT_ID`,
//! a self-asserted `X-Agent-Id`, or a fresh `anonymous:req-<uuid8>` per
//! header-less HTTP request), so a distinct-reader count is a Sybil
//! counter with a trust label and its RED pin cannot be written honestly
//! at GA. Not fabricated here; tracked for v1.1 with items 4-6.
//!
//! No `set_var` in this file (no env dependency).

mod common;

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, Tier};
use rusqlite::Connection;
use serde_json::json;

const TS: &str = "2026-09-01T00:00:00+00:00";
const EPS: f64 = 1e-9;

fn fresh_db() -> (Connection, tempfile::TempDir) {
    common::permissive_attestation_for_tests();
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("boids-rank-trust-3922");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir");
    let conn = db::open(&dir.path().join("boids.db")).expect("open fresh db");
    (conn, dir)
}

/// A `long`-tier row (NULL expiry, constant +3.0 tier bonus) with fully
/// controlled scoring inputs. The FTS token lives ONLY in `content`,
/// which is identical across a comparison pair, and `updated_at` is a
/// fixed constant, so `fts.rank`, the tier bonus and the recency term are
/// byte-identical for every row in a test — the ONLY score differences
/// are the capped popularity term and the provenance-aware confidence
/// term. Distinct titles keep `(title, namespace)` unique (no upsert).
#[allow(clippy::too_many_arguments)]
fn row(
    id: &str,
    title: &str,
    content: &str,
    ns: &str,
    priority: i32,
    access: i64,
    confidence: f64,
    cs: ConfidenceSource,
) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority,
        confidence,
        access_count: access,
        confidence_source: cs,
        created_at: TS.to_string(),
        updated_at: TS.to_string(),
        expires_at: None,
        metadata: json!({ "scope": "collective" }),
        ..Default::default()
    }
}

/// Run keyword recall and return `(id, score)` in ranked order. The
/// second tuple element is the raw score expression (`row.get("score")`).
fn recall_scored(conn: &Connection, query: &str, ns: &str) -> Vec<(String, f64)> {
    let (rows, _) = db::recall(
        conn,
        query,
        Some(ns),
        50,
        None,
        None,
        None,
        3600,
        86_400,
        None,
        None,
        false,
        None,
        None,
        None,
    )
    .expect("db::recall");
    rows.into_iter().map(|(m, s)| (m.id, s)).collect()
}

fn score_of(scored: &[(String, f64)], id: &str) -> f64 {
    scored
        .iter()
        .find(|(i, _)| i == id)
        .unwrap_or_else(|| panic!("id {id} absent from recall result"))
        .1
}

// ---------------------------------------------------------------------
// Item 1 (R1) — the cap: earned popularity is a tiebreak, not a driver.
// ---------------------------------------------------------------------

#[test]
fn hot_low_confidence_row_ranks_below_unseen_calibrated_row_3922() {
    let (conn, _d) = fresh_db();
    let ns = "boids/cap";
    // Identical CONTENT (carries the FTS token), distinct titles.
    let content = "boidcapquery shared trust body";
    // Hot but low-confidence (explicit 0.4): access 500 → capped +1.0,
    // confidence +0.8.
    db::insert(
        &conn,
        &row(
            "hot",
            "alpha",
            content,
            ns,
            5,
            500,
            0.4,
            ConfidenceSource::CallerProvided,
        ),
    )
    .unwrap();
    // Unseen but calibrated (explicit 1.0): access 0 → +0.0, confidence +2.0.
    db::insert(
        &conn,
        &row(
            "cal",
            "bravo",
            content,
            ns,
            5,
            0,
            1.0,
            ConfidenceSource::CallerProvided,
        ),
    )
    .unwrap();
    // Presence control for the cap: identical to `hot` except access 0.
    db::insert(
        &conn,
        &row(
            "cold",
            "gamma",
            content,
            ns,
            5,
            0,
            0.4,
            ConfidenceSource::CallerProvided,
        ),
    )
    .unwrap();

    let scored = recall_scored(&conn, "boidcapquery", ns);
    let (s_hot, s_cal, s_cold) = (
        score_of(&scored, "hot"),
        score_of(&scored, "cal"),
        score_of(&scored, "cold"),
    );

    // RED on the tip (cap 50): s_hot = K + 5.0 + 0.8 > s_cal = K + 2.0.
    // GREEN after (cap 10): s_cal = K + 2.0 > s_hot = K + 1.0 + 0.8.
    assert!(
        s_cal > s_hot,
        "calibrated row must outrank the hot low-confidence row \
         (s_cal={s_cal}, s_hot={s_hot})"
    );
    // Presence control: `hot` and `cold` differ ONLY in access_count
    // (500 vs 0); the score gap is exactly the capped popularity term
    // MIN(500, ACCESS_SCORE_CAP) * 0.1 = 1.0 (was 5.0 at cap 50).
    let gap = s_hot - s_cold;
    assert!(
        (gap - 1.0).abs() < EPS,
        "capped popularity gain must be exactly +1.0 (ACCESS_SCORE_CAP=10), got {gap}"
    );
}

// ---------------------------------------------------------------------
// Item 2 (R3) — provenance-aware confidence.
// ---------------------------------------------------------------------

#[test]
fn default_provenance_row_ranks_below_explicit_confidence_3922() {
    let (conn, _d) = fresh_db();
    let ns = "boids/prov";
    let content = "boidprovquery shared trust body";
    // Caller OMITTED confidence → Default provenance, stored 1.0 fallback.
    db::insert(
        &conn,
        &row(
            "deflt",
            "alpha",
            content,
            ns,
            5,
            0,
            1.0,
            ConfidenceSource::Default,
        ),
    )
    .unwrap();
    // Caller ASSERTED confidence 1.0 → CallerProvided.
    db::insert(
        &conn,
        &row(
            "expl",
            "bravo",
            content,
            ns,
            5,
            0,
            1.0,
            ConfidenceSource::CallerProvided,
        ),
    )
    .unwrap();

    let scored = recall_scored(&conn, "boidprovquery", ns);
    let (s_def, s_expl) = (score_of(&scored, "deflt"), score_of(&scored, "expl"));

    // RED on the tip (no CASE): s_def == s_expl (tie — the explicit row
    // does NOT rank strictly first). GREEN after: explicit +2.0 vs
    // default neutral +1.0, gap exactly 1.0.
    assert!(
        s_expl > s_def,
        "explicit confidence must outrank the unassessed default \
         (s_expl={s_expl}, s_def={s_def})"
    );
    assert!(
        (s_expl - s_def - 1.0).abs() < EPS,
        "explicit(+2.0) − default-neutral(+1.0) must be exactly 1.0, got {}",
        s_expl - s_def
    );
}

/// A11 (f2r pre-cut security amendment) — the legacy / NULL arm pinned
/// EXPLICITLY, asserted not assumed. On sqlite the column is `NOT NULL
/// DEFAULT 'caller_provided'`, so a legacy row backfills to
/// `'caller_provided'` and takes the CASE ELSE branch (keeps its stored
/// confidence, +2.0 at 1.0) — it CANNOT be neutralized without also
/// de-weighting explicit caller confidences, which share the same
/// string. The `OR ... IS NULL` arm is defensive-dead on `memories`
/// (NOT NULL on both backends); the postgres twin pins the same
/// `'default'`-vs-`'caller_provided'` behaviour on postgres
/// (`tests/boids_rank_trust_3922_pg.rs`).
#[test]
fn a11_legacy_caller_provided_takes_else_not_neutral_3922() {
    let (conn, _d) = fresh_db();
    let ns = "boids/legacy";
    let content = "boidlegacyquery shared trust body";
    // Legacy / explicit provenance (the sqlite backfill value).
    db::insert(
        &conn,
        &row(
            "legacy",
            "alpha",
            content,
            ns,
            5,
            0,
            1.0,
            ConfidenceSource::CallerProvided,
        ),
    )
    .unwrap();
    // Unassessed default provenance (neutralized).
    db::insert(
        &conn,
        &row(
            "deflt",
            "bravo",
            content,
            ns,
            5,
            0,
            1.0,
            ConfidenceSource::Default,
        ),
    )
    .unwrap();

    let scored = recall_scored(&conn, "boidlegacyquery", ns);
    let (s_legacy, s_def) = (score_of(&scored, "legacy"), score_of(&scored, "deflt"));
    // The legacy 'caller_provided' row takes ELSE → +2.0; the default row
    // is neutralized → +1.0. Gap exactly 1.0, asserted not assumed.
    assert!(
        (s_legacy - s_def - 1.0).abs() < EPS,
        "legacy 'caller_provided' must take ELSE (keep +2.0) while default \
         is neutral (+1.0): gap {} != 1.0",
        s_legacy - s_def
    );
}

// ---------------------------------------------------------------------
// R2 — the fold / touch maintenance verbs no longer escalate.
// ---------------------------------------------------------------------

fn seed_mid(conn: &Connection, id: &str, access: i64) {
    // A mid row at priority 5 with a near-future expiry, so the TTL
    // floor-extend is observable and the pre-R2 promotion/decade would
    // both have fired.
    let soon = (chrono::Utc::now() + chrono::Duration::seconds(90)).to_rfc3339();
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, priority, access_count, \
                               created_at, updated_at, expires_at) \
         VALUES (?1, 'mid', 'boids-fold', 'boidfold', 'body', 5, ?2, ?3, ?3, ?4)",
        rusqlite::params![id, access, TS, soon],
    )
    .unwrap();
}

fn read_row(
    conn: &Connection,
    id: &str,
) -> (i64, String, i32, String, Option<String>, Option<String>) {
    conn.query_row(
        "SELECT access_count, tier, priority, updated_at, expires_at, last_accessed_at \
         FROM memories WHERE id = ?1",
        [id],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    )
    .unwrap()
}

#[test]
fn fold_no_longer_escalates_tier_priority_updated_at_3922() {
    const SHORT: i64 = 3600;
    const MID: i64 = 86_400;
    let (conn, _d) = fresh_db();
    // access 3; 8 recalls would land it at 11 — crossing the historical
    // promotion threshold (5) AND a priority decade (10).
    seed_mid(&conn, "fold-row", 3);
    for k in 0..8 {
        ai_memory::observations::record_recall(
            &conn,
            &format!("r{k}"),
            &[ai_memory::observations::Candidate {
                memory_id: "fold-row",
                retriever: "fts5",
                rank: 1,
                score: 0.9,
            }],
        )
        .unwrap();
    }
    assert_eq!(
        db::fold_recall_accesses(&conn, SHORT, MID).unwrap(),
        1,
        "one distinct memory folded"
    );

    let (ac, tier, pr, upd, exp, la) = read_row(&conn, "fold-row");
    assert_eq!(ac, 11, "access_count still folds (3 + 8)");
    assert_eq!(tier, "mid", "R2: fold no longer auto-promotes mid→long");
    assert_eq!(pr, 5, "R2: fold no longer bumps priority across a decade");
    assert_eq!(upd, TS, "R2: fold no longer rewrites updated_at");
    assert!(la.is_some(), "last_accessed_at advances");
    // TTL floor-extend still applies: the mid window (1 day) floors the
    // near-future expiry forward.
    let exp = exp.expect("mid row keeps a non-NULL expiry");
    assert!(exp.as_str() > TS, "TTL floor-extend still applies: {exp}");
}

#[test]
fn touch_many_no_longer_escalates_matching_the_fold_3922() {
    const SHORT: i64 = 3600;
    const MID: i64 = 86_400;
    let (conn, _d) = fresh_db();
    seed_mid(&conn, "touch-row", 3);
    for _ in 0..8 {
        db::touch_many(&conn, &["touch-row"], SHORT, MID).unwrap();
    }
    let (ac, tier, pr, upd, exp, la) = read_row(&conn, "touch-row");
    assert_eq!(ac, 11, "access_count still bumps (3 + 8)");
    assert_eq!(tier, "mid", "R2: touch_many no longer auto-promotes");
    assert_eq!(pr, 5, "R2: touch_many no longer bumps priority");
    assert_eq!(upd, TS, "R2: touch_many no longer rewrites updated_at");
    assert!(la.is_some(), "last_accessed_at advances");
    assert!(
        exp.expect("expiry present").as_str() > TS,
        "TTL floor-extend still applies"
    );
}
