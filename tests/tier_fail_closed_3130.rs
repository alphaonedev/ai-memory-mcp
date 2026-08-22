// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3130 — an unrecognised `--tier` must FAIL CLOSED on every CLI
//! surface that takes one.
//!
//! Pre-fix `forget` / `search` / `list` all wrote
//! `args.tier.as_deref().and_then(Tier::from_str)`. `Tier::from_str`
//! answers `None` for anything that is not `short` / `mid` / `long`, and
//! the storage layer reads `None` as **"no tier constraint"** — so a
//! typo did not narrow the operation, it WIDENED it:
//!
//! - `forget --tier Long` matched every tier, erased the whole scope and
//!   printed `forgot N memories` (silent, unintentional data loss — the
//!   prime-directive violation this suite exists to pin);
//! - `search --tier Long` / `list --tier Long` returned UNFILTERED rows,
//!   i.e. wrong results rather than fewer results.
//!
//! Every test below asserts BOTH halves of the contract: the refusal
//! itself, and that the durable corpus is byte-for-byte unchanged after
//! it. The valid-tier paths are asserted alongside so the fix cannot be
//! satisfied by refusing everything.

#![allow(clippy::needless_update)]

use ai_memory::cli::CliOutput;
use ai_memory::cli::crud::{ListArgs, cmd_list};
use ai_memory::cli::forget::{ForgetArgs, cmd_forget};
use ai_memory::cli::search::{SearchArgs, run as cmd_search};
use ai_memory::config::AppConfig;
use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};

const NS: &str = "tier-fail-closed-3130";
/// A typo an operator plausibly makes: the enum name, not the wire form.
const BOGUS_TIER: &str = "Long";

fn seed(conn: &rusqlite::Connection, title: &str, tier: Tier) {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("durable text for {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
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
    };
    db::insert(conn, &mem).expect("seed insert");
}

/// One row per tier, so a dropped tier filter is observable as a
/// per-tier count change rather than only as a total.
fn fresh_corpus() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("memories.db");
    let conn = db::open(&db_path).expect("open");
    seed(&conn, "short-row", Tier::Short);
    seed(&conn, "mid-row", Tier::Mid);
    seed(&conn, "long-row", Tier::Long);
    drop(conn);
    (tmp, db_path)
}

/// `(short, mid, long)` row counts, read straight from the store so the
/// assertion does not depend on any of the surfaces under test.
fn tier_counts(db_path: &std::path::Path) -> (usize, usize, usize) {
    let conn = db::open(db_path).expect("open");
    let count = |tier: &Tier| -> usize {
        db::list(
            &conn,
            Some(NS),
            Some(tier),
            1000,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("list")
        .len()
    };
    (count(&Tier::Short), count(&Tier::Mid), count(&Tier::Long))
}

fn forget_args(tier: &str) -> ForgetArgs {
    ForgetArgs {
        namespace: Some(NS.to_string()),
        pattern: None,
        tier: Some(tier.to_string()),
        confirm_global: false,
        show_receipt: None,
        verify_receipt: None,
    }
}

fn search_args(tier: Option<&str>) -> SearchArgs {
    SearchArgs {
        query: "durable".to_string(),
        namespace: Some(NS.to_string()),
        tier: tier.map(ToString::to_string),
        limit: 20,
        since: None,
        until: None,
        tags: None,
        agent_id: None,
        as_agent: None,
        include_archived: false,
    }
}

fn list_args(tier: Option<&str>) -> ListArgs {
    ListArgs {
        namespace: Some(NS.to_string()),
        tier: tier.map(ToString::to_string),
        limit: 20,
        since: None,
        until: None,
        valid_at: None,
        tags: None,
        offset: 0,
        agent_id: None,
    }
}

/// Run a CLI handler against a captured `CliOutput` and hand back its
/// result together with everything it wrote to stdout. The `CliOutput`
/// borrow ends with the inner scope, so the buffers are readable after
/// without a `drop` dance.
fn capture<T>(f: impl FnOnce(&mut CliOutput<'_>) -> T) -> (T, String) {
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let result = {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        f(&mut out)
    };
    (result, String::from_utf8_lossy(&stdout).into_owned())
}

fn assert_names_the_valid_tiers(msg: &str) {
    assert!(msg.contains("invalid tier"), "got: {msg}");
    assert!(
        msg.contains(Tier::VALUES_HINT),
        "the refusal must tell the operator what IS valid; got: {msg}"
    );
}

// ---------------------------------------------------------------------
// forget — the data-loss half
// ---------------------------------------------------------------------

#[test]
fn forget_with_unknown_tier_is_refused_and_erases_nothing_3130() {
    let (_tmp, db_path) = fresh_corpus();
    let before = tier_counts(&db_path);
    assert_eq!(before, (1, 1, 1), "fixture must seed one row per tier");

    let (result, stdout) =
        capture(|out| cmd_forget(&db_path, &forget_args(BOGUS_TIER), false, out));
    let err = result.expect_err("an unrecognised --tier must be refused");
    assert_names_the_valid_tiers(&err.to_string());

    assert_eq!(
        tier_counts(&db_path),
        before,
        "a refused forget must not erase a single row in ANY tier (#3130)"
    );
    assert!(
        !stdout.contains("forgot"),
        "a refused forget must not report success"
    );
}

#[test]
fn forget_with_a_valid_tier_still_erases_exactly_that_tier_3130() {
    let (_tmp, db_path) = fresh_corpus();
    let (result, _stdout) =
        capture(|out| cmd_forget(&db_path, &forget_args(Tier::Short.as_str()), false, out));
    result.expect("a valid tier must still forget");

    assert_eq!(
        tier_counts(&db_path),
        (0, 1, 1),
        "only the named tier may be erased"
    );
}

// ---------------------------------------------------------------------
// search / list — the wrong-results half
// ---------------------------------------------------------------------

#[test]
fn search_with_unknown_tier_is_refused_not_unfiltered_3130() {
    let (_tmp, db_path) = fresh_corpus();
    let (result, stdout) =
        capture(|out| cmd_search(&db_path, &search_args(Some(BOGUS_TIER)), true, out));
    let err = result.expect_err("an unrecognised --tier must be refused");
    assert_names_the_valid_tiers(&err.to_string());
    assert!(
        stdout.is_empty(),
        "a refused search must not emit results at all"
    );
}

#[test]
fn search_with_a_valid_tier_still_returns_that_tier_3130() {
    let (_tmp, db_path) = fresh_corpus();
    let (result, stdout) =
        capture(|out| cmd_search(&db_path, &search_args(Some(Tier::Long.as_str())), true, out));
    result.expect("a valid tier must still search");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json");
    assert_eq!(v["count"].as_u64(), Some(1), "exactly the long-tier row");
}

#[test]
fn list_with_unknown_tier_is_refused_not_unfiltered_3130() {
    let (_tmp, db_path) = fresh_corpus();
    let cfg = AppConfig::default();
    let (result, stdout) =
        capture(|out| cmd_list(&db_path, &list_args(Some(BOGUS_TIER)), true, &cfg, out));
    let err = result.expect_err("an unrecognised --tier must be refused");
    assert_names_the_valid_tiers(&err.to_string());
    assert!(
        stdout.is_empty(),
        "a refused list must not emit rows at all"
    );
}

#[test]
fn list_with_a_valid_tier_still_returns_that_tier_3130() {
    let (_tmp, db_path) = fresh_corpus();
    let cfg = AppConfig::default();
    let (result, stdout) = capture(|out| {
        cmd_list(
            &db_path,
            &list_args(Some(Tier::Mid.as_str())),
            true,
            &cfg,
            out,
        )
    });
    result.expect("a valid tier must still list");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json");
    assert_eq!(v["count"].as_u64(), Some(1), "exactly the mid-tier row");
}

#[test]
fn list_with_no_tier_stays_genuinely_unconstrained_3130() {
    // The distinction `.and_then(Tier::from_str)` collapsed: ABSENT is
    // unconstrained, PRESENT-but-unparseable is a refusal.
    let (_tmp, db_path) = fresh_corpus();
    let cfg = AppConfig::default();
    let (result, stdout) = capture(|out| cmd_list(&db_path, &list_args(None), true, &cfg, out));
    result.expect("no tier filter is legal");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json");
    assert_eq!(v["count"].as_u64(), Some(3), "all three tiers");
}

// ---------------------------------------------------------------------
// the shared parser itself
// ---------------------------------------------------------------------

#[test]
fn parse_strict_accepts_every_canonical_wire_string_3130() {
    for tier in [Tier::Short, Tier::Mid, Tier::Long] {
        assert_eq!(
            Tier::parse_strict(tier.as_str()).expect("canonical wire string"),
            tier
        );
    }
}

#[test]
fn parse_strict_refuses_typos_and_names_the_valid_values_3130() {
    for bad in ["Long", "longterm", "SHORT", "", "  mid"] {
        let err = Tier::parse_strict(bad).expect_err("must refuse");
        assert_names_the_valid_tiers(&err);
    }
}

#[test]
fn parse_optional_distinguishes_absent_from_unparseable_3130() {
    assert_eq!(Tier::parse_optional(None).expect("absent is legal"), None);
    assert_eq!(
        Tier::parse_optional(Some("mid")).expect("valid is legal"),
        Some(Tier::Mid)
    );
    assert!(Tier::parse_optional(Some("Mid")).is_err());
}
