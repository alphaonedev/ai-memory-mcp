// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3507 — `memory_calibrate_confidence` caller gate, sqlite half.
//!
//! Before #3507 the Form-5 calibration sweep had NO caller gate on either
//! backend: any caller that reached the MCP tool, the HTTP route or the SAL
//! method received the GLOBAL aggregate, whose `baselines` array NAMES every
//! namespace that produced a shadow observation and discloses per-namespace
//! confidence statistics over rows the caller may not read. That is a
//! cross-namespace aggregate disclosure of the #3171/#3348 residual class.
//!
//! The gate is a CALLER-SCOPED aggregate: the sweep is computed only over
//! rows the caller can read, using the store's OWN visibility machinery
//! (#1921 subtree scopes, #1720 owner-keyed private, #3348 substrate
//! exclusion, the fail-closed lifecycle allow-list) rather than a second
//! predicate that could drift (#951).
//!
//! Every cell here asserts on the NUMBERS — the group set and the counts —
//! not merely on "ok", because a gate that returns 200 while still
//! aggregating the foreign rows is exactly the defect.
//!
//! The postgres twin is `tests/calibrate_confidence_caller_gate_3507_pg.rs`.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use ai_memory::confidence::calibrate::{
    CalibrationAudience, CalibrationReport, calibrate_from_shadow,
};
use ai_memory::confidence::shadow::observe;
use ai_memory::models::ConfidenceSignals;
use chrono::Utc;
use rusqlite::{Connection, params};

mod common;
use common::fresh_db_tempfile_conn as fresh_db;

/// The two tenant principals. Both carry a `/` so the #1921 subtree arms
/// have an ancestor to resolve (`namespace_ancestors("team/alice")[1]` is
/// `"team"`), which is what makes the `scope=team` cell meaningful.
const ALICE: &str = "team/alice";
const BOB: &str = "team/bob";
/// One source for every observation, so the report's groups are keyed by
/// NAMESPACE and a missing/extra group is unambiguous.
const SOURCE: &str = "nhi";

/// Insert a memory row with an explicit owner + scope so the sqlite
/// `scope_idx` / `agent_id_idx` generated columns project the values the
/// visibility clause reads.
fn seed_memory(conn: &Connection, id: &str, namespace: &str, owner: &str, scope: Option<&str>) {
    let metadata = scope.map_or_else(
        || serde_json::json!({ "agent_id": owner }),
        |scope| serde_json::json!({ "agent_id": owner, "scope": scope }),
    );
    conn.execute(
        "INSERT INTO memories
             (id, tier, namespace, title, content, source, metadata, created_at, updated_at)
         VALUES (?1, 'mid', ?2, ?1, 'body', ?3, ?4, '2026-05-15T00:00:00Z', '2026-05-15T00:00:00Z')",
        params![id, namespace, SOURCE, metadata.to_string()],
    )
    .expect("seed memory");
}

/// Seed the corpus every ALLOWED/DENIED cell below reasons over.
///
/// | row              | namespace          | owner | scope      | alice | bob |
/// |------------------|--------------------|-------|------------|-------|-----|
/// | `m_alice`        | `team/alice`       | alice | (absent)   | yes   | no  |
/// | `m_bob`          | `team/bob`         | bob   | (absent)   | no    | yes |
/// | `m_team`         | `team/shared`      | bob   | `team`     | yes   | yes |
/// | `m_collective`   | `open/space`       | bob   | `collective`| yes  | yes |
/// | `m_substrate`    | `_curator/reports` | alice | (absent)   | no    | no  |
/// | orphan           | `team/alice`       | (gone)| —          | no    | no  |
///
/// The substrate row is owned by ALICE on purpose: without the #3348
/// exclusion she would see it, so the cell proves the exclusion fires rather
/// than merely riding the ownership gate. The orphan observation proves the
/// fail-closed direction — a row whose visibility cannot be evaluated is
/// dropped from a scoped sweep, and only the admin sweep still counts it.
fn seed_corpus(conn: &Connection) {
    seed_memory(conn, "m_alice", "team/alice", ALICE, None);
    seed_memory(conn, "m_bob", "team/bob", BOB, None);
    seed_memory(conn, "m_team", "team/shared", BOB, Some("team"));
    seed_memory(conn, "m_collective", "open/space", BOB, Some("collective"));
    seed_memory(conn, "m_substrate", "_curator/reports", ALICE, None);

    let signals = ConfidenceSignals::default();
    for (id, ns) in [
        ("m_alice", "team/alice"),
        ("m_bob", "team/bob"),
        ("m_team", "team/shared"),
        ("m_collective", "open/space"),
        ("m_substrate", "_curator/reports"),
    ] {
        observe(conn, id, ns, SOURCE, 0.9, 0.5, &signals, None).expect("observe");
    }

    // The orphan: an observation whose source memory no longer exists. The
    // FK is `ON DELETE CASCADE`, so this state is only reachable when FK
    // enforcement was off for the delete — which is exactly the historical
    // shape the module's orphan-tolerance paragraph describes.
    conn.execute_batch("PRAGMA foreign_keys = OFF")
        .expect("disable fk for orphan seed");
    conn.execute(
        "INSERT INTO confidence_shadow_observations
             (memory_id, namespace, source, caller_confidence, derived_confidence,
              signals, observed_at)
         VALUES ('m_vanished', 'team/alice', ?1, 0.9, 0.5, '{}', ?2)",
        params![SOURCE, Utc::now().to_rfc3339()],
    )
    .expect("seed orphan observation");
}

/// `(namespace, count)` pairs, sorted — the discriminating fingerprint of a
/// report.
fn groups(report: &CalibrationReport) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = report
        .baselines
        .iter()
        .map(|b| (b.namespace.clone(), b.count))
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// ALLOWED / DENIED — the caller-scoped aggregate
// ---------------------------------------------------------------------------

#[test]
fn scoped_sweep_counts_only_rows_the_caller_can_read_3507() {
    let (_tmp, conn) = fresh_db();
    seed_corpus(&conn);

    let alice = calibrate_from_shadow(
        &conn,
        30,
        Utc::now(),
        &CalibrationAudience::for_caller(ALICE).expect("alice is a usable principal"),
    )
    .expect("scoped calibrate");

    assert_eq!(
        groups(&alice),
        vec![
            ("open/space".to_string(), 1),
            ("team/alice".to_string(), 1),
            ("team/shared".to_string(), 1),
        ],
        "#3507: alice must see her own private row, the team-scoped row in her \
         subtree and the collective row — and NOTHING else: {alice:?}"
    );
    assert_eq!(
        alice.total_observations, 3,
        "#3507: the total must count exactly the readable rows, not the corpus"
    );

    // The DENIED half, stated as absences on the SAME report so a gate that
    // merely renamed the leak cannot pass.
    let names: Vec<&str> = alice
        .baselines
        .iter()
        .map(|b| b.namespace.as_str())
        .collect();
    assert!(
        !names.contains(&"team/bob"),
        "#3507: a foreign tenant's namespace must never be named: {names:?}"
    );
    assert!(
        !names.contains(&"_curator/reports"),
        "#3507: a substrate namespace must be excluded from the ambient sweep \
         even when the caller OWNS the row: {names:?}"
    );
}

#[test]
fn foreign_caller_sees_a_different_aggregate_3507() {
    let (_tmp, conn) = fresh_db();
    seed_corpus(&conn);

    let bob = calibrate_from_shadow(
        &conn,
        30,
        Utc::now(),
        &CalibrationAudience::for_caller(BOB).expect("bob is a usable principal"),
    )
    .expect("scoped calibrate");

    assert_eq!(
        groups(&bob),
        vec![
            ("open/space".to_string(), 1),
            ("team/bob".to_string(), 1),
            ("team/shared".to_string(), 1),
        ],
        "#3507: bob's aggregate must be HIS rows, not alice's: {bob:?}"
    );
    assert_eq!(bob.total_observations, 3);
}

#[test]
fn admin_sweep_keeps_the_global_aggregate_3507() {
    let (_tmp, conn) = fresh_db();
    seed_corpus(&conn);

    let admin = calibrate_from_shadow(&conn, 30, Utc::now(), &CalibrationAudience::admin())
        .expect("admin calibrate");

    assert_eq!(
        groups(&admin),
        vec![
            ("_curator/reports".to_string(), 1),
            ("open/space".to_string(), 1),
            ("team/alice".to_string(), 2),
            ("team/bob".to_string(), 1),
            ("team/shared".to_string(), 1),
        ],
        "#3507: an admin caller keeps the pre-fix GLOBAL sweep, INCLUDING the \
         orphan observation folded into team/alice: {admin:?}"
    );
    assert_eq!(
        admin.total_observations, 6,
        "#3507: the admin total counts every observation in the window"
    );
}

#[test]
fn orphan_observation_is_dropped_from_a_scoped_sweep_3507() {
    let (_tmp, conn) = fresh_db();
    seed_corpus(&conn);

    let alice = calibrate_from_shadow(
        &conn,
        30,
        Utc::now(),
        &CalibrationAudience::for_caller(ALICE).expect("principal"),
    )
    .expect("scoped calibrate");
    let alice_ns = alice
        .baselines
        .iter()
        .find(|b| b.namespace == "team/alice")
        .expect("alice's own namespace baseline");
    assert_eq!(
        alice_ns.count, 1,
        "#3507: the orphan observation in the SAME namespace has no memories row \
         to judge, so a scoped sweep must fail CLOSED and drop it — the admin \
         sweep counts 2 for this group"
    );
}

/// The scoped sweep is strictly READ-ONLY: the `recall_outcome` backfill is
/// the one write the admin sweep performs, and a non-admin must never drive
/// a corpus-wide UPDATE over rows it cannot read.
#[test]
fn scoped_sweep_does_not_backfill_recall_outcomes_3507() {
    let (_tmp, conn) = fresh_db();
    seed_corpus(&conn);
    // A ledger entry that WOULD be correlated by the backfill.
    conn.execute(
        "INSERT INTO recall_observations
             (recall_id, memory_id, retriever, rank, score, consumed, observed_at)
         VALUES ('r-3507', 'm_bob', 'fts', 1, 0.9, 1, ?1)",
        params![Utc::now().to_rfc3339()],
    )
    .expect("seed ledger row");

    let outcomes = |conn: &Connection| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM confidence_shadow_observations WHERE recall_outcome IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("count outcomes")
    };
    assert_eq!(outcomes(&conn), 0, "precondition: nothing backfilled yet");

    let _ = calibrate_from_shadow(
        &conn,
        30,
        Utc::now(),
        &CalibrationAudience::for_caller(ALICE).expect("principal"),
    )
    .expect("scoped calibrate");
    assert_eq!(
        outcomes(&conn),
        0,
        "#3507: a caller-scoped sweep must not write; the backfill is admin-only"
    );

    let _ = calibrate_from_shadow(&conn, 30, Utc::now(), &CalibrationAudience::admin())
        .expect("admin calibrate");
    assert!(
        outcomes(&conn) > 0,
        "#3507: the admin sweep still rides the ledger backfill (unchanged)"
    );
}

// ---------------------------------------------------------------------------
// The fail-closed audience constructor
// ---------------------------------------------------------------------------

#[test]
fn audience_refuses_every_non_principal_3507() {
    for candidate in [
        "",
        "   ",
        "anonymous:invalid",
        "anonymous:req-deadbeef",
        "has whitespace",
        "../../etc/passwd",
    ] {
        let refusal = CalibrationAudience::for_caller(candidate)
            .expect_err("#3507: a non-principal must be refused, never scoped");
        assert!(
            refusal.contains("caller-scoped aggregate"),
            "#3507: the refusal must explain the posture: {refusal}"
        );
    }
    assert!(
        CalibrationAudience::for_caller(ALICE).is_ok(),
        "#3507: a real principal is admitted"
    );
    assert!(CalibrationAudience::admin().is_admin());
    assert_eq!(
        CalibrationAudience::for_caller(ALICE)
            .expect("principal")
            .caller(),
        Some(ALICE)
    );
}

// ---------------------------------------------------------------------------
// The MCP tool wrapper honours the audience it is handed
// ---------------------------------------------------------------------------

#[test]
fn mcp_tool_envelope_is_scoped_3507() {
    let (_tmp, conn) = fresh_db();
    seed_corpus(&conn);

    let scoped = ai_memory::mcp::handle_calibrate_confidence(
        &conn,
        &serde_json::json!({}),
        &CalibrationAudience::for_caller(ALICE).expect("principal"),
    )
    .expect("mcp calibrate");
    assert_eq!(
        scoped["report"]["total_observations"].as_u64(),
        Some(3),
        "#3507: the MCP envelope carries the SCOPED aggregate: {scoped}"
    );

    let admin = ai_memory::mcp::handle_calibrate_confidence(
        &conn,
        &serde_json::json!({}),
        &CalibrationAudience::admin(),
    )
    .expect("mcp calibrate");
    assert_eq!(
        admin["report"]["total_observations"].as_u64(),
        Some(6),
        "#3507: an admin audience keeps the global envelope: {admin}"
    );
}
