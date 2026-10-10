// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6383 / #6386 — per-binary Postgres database isolation helper
//! (`tests/common/pg_isolate.rs`).
//!
//! Cases (design `CI-PG-ISOLATION-DESIGN-2026-10-09` section 5, step 1):
//!
//! * (a) flag unset -> the helper is today's behaviour: the raw env value, no
//!   database is minted;
//! * (b) flag set + live Postgres + a template -> the minted URL names an
//!   `ai_memory_t_*` database that is a lane database, carries the age and
//!   vector extensions, and the process-wide answer is stable;
//! * (c) the minted name stays inside the 63-byte identifier limit and has the
//!   exact `<prefix>_<10 digits>_<8 hex>` shape the stale sweep recognises
//!   (the design's `<bin>_<pid>` infix would never match that shape, so the
//!   binary name goes to the log line instead);
//! * (d) the URL rewrite preserves the TLS query (`sslmode`, `sslrootcert`);
//! * (e) review r1 H2: clone names carry the run id, the sweep only ever sees
//!   this run's clones, a clone with a held session is never dropped, and no
//!   drop uses `WITH (FORCE)`;
//! * (f) review r1 M1/M6: minting needs an explicit template (no implicit
//!   fallback to the live shared database), `CI_PG_ISOLATE_OFF=1` is a hard
//!   kill switch, and with the flag on a missing template FAILS the live case
//!   instead of skipping it.
//!
//! (a), (c), (d) and the pure halves of (e)/(f) always run. (b) and the live
//! half of (e) need a live Postgres and a template database; they skip with a
//! stderr line when the URL is unset, and when only the template is unset they
//! skip ONLY while `AI_MEMORY_TEST_PG_ISOLATE` is not `1`.
//!
//! Red on the carrier: `common::pg_isolate` does not exist there, so this file
//! does not compile.
#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

mod common;

use common::lane_db;
use common::pg_isolate::{self, Plan};

const SHARED: &str = "postgres://u:pw@127.0.0.1:5445/ai_memory_test_ci_9_1_x";
const ISOLATED: &str = "postgres://u:pw@127.0.0.1:5445/ai_memory_t_r6383_1700000000_0123abcd";
const RUN: &str = "r6383";

#[test]
fn flag_unset_is_passthrough_6383() {
    // (a) every non-"1" flag value, with and without a URL.
    for flag in [None, Some(""), Some("0"), Some("true"), Some("yes")] {
        assert_eq!(
            pg_isolate::plan(flag, None, Some(SHARED)),
            Plan::Passthrough(Some(SHARED.to_string())),
            "flag {flag:?} must leave the URL untouched"
        );
        assert_eq!(pg_isolate::plan(flag, None, None), Plan::Passthrough(None));
    }
    // flag on but no URL: nothing to isolate, the cell skips as before.
    assert_eq!(
        pg_isolate::plan(Some("1"), None, None),
        Plan::Passthrough(None)
    );
}

#[test]
fn flag_set_mints_unless_already_isolated_6383() {
    assert_eq!(
        pg_isolate::plan(Some("1"), None, Some(SHARED)),
        Plan::Mint {
            base: SHARED.to_string()
        }
    );
    // The CI wrapper already minted: the helper must not mint a second layer.
    assert_eq!(
        pg_isolate::plan(Some("1"), None, Some(ISOLATED)),
        Plan::Passthrough(Some(ISOLATED.to_string()))
    );
    assert!(pg_isolate::is_isolated_url(ISOLATED));
    assert!(!pg_isolate::is_isolated_url(SHARED));
    // `ai_memory_test*` must never be mistaken for an isolated database.
    assert!(!pg_isolate::is_isolated_url(
        "postgres://u:pw@h:5445/ai_memory_test"
    ));
    assert!(!pg_isolate::is_isolated_url(
        "postgres://u:pw@h:5445/ai_memory_tx"
    ));
}

#[test]
fn minted_name_shape_and_length_6383() {
    // (c)
    let name = pg_isolate::isolated_db_name(RUN, 1_700_000_000);
    assert!(name.starts_with("ai_memory_t_r6383_"), "{name}");
    assert!(name.len() <= 63, "{name} is {} bytes", name.len());
    assert!(
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "{name} must be a plain lowercase identifier"
    );
    assert_eq!(
        pg_isolate::parse_isolated_name(RUN, &name),
        Some(1_700_000_000),
        "the run-scoped sweep must recognise the name it mints"
    );
    // Distinct on every call (8 random hex), so two binaries never collide.
    assert_ne!(name, pg_isolate::isolated_db_name(RUN, 1_700_000_000));
    // The longest run id still fits the 63-byte identifier limit.
    let long_run = "a".repeat(pg_isolate::RUN_ID_MAX_LEN);
    assert!(pg_isolate::isolated_db_name(&long_run, 1_700_000_000).len() <= 63);
    // The sweep must refuse anything that is not the exact shape of THIS run.
    for bad in [
        "ai_memory_t_r6383_1700000000_0123ABCD",
        "ai_memory_t_r6383_170000000_0123abcd",
        "ai_memory_t_r6383_1700000000_0123abc",
        "ai_memory_t_r6383_1700000000_0123abcd_x",
        // another run's clone (review r1 H2) and the r1 run-less shape
        "ai_memory_t_other_1700000000_0123abcd",
        "ai_memory_t_r63831_1700000000_0123abcd",
        "ai_memory_t_1700000000_0123abcd",
        "ai_memory_test_ci_9_1_x",
        "ai_memory_t_",
        "ai_memory_test",
    ] {
        assert_eq!(pg_isolate::parse_isolated_name(RUN, bad), None, "{bad}");
    }
}

#[test]
fn url_rewrite_preserves_tls_query_6383() {
    // (d)
    let base = "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test_ci_9_1_x\
                ?sslmode=verify-full&sslrootcert=/home/x/pg/certs/ca.crt";
    let rewritten = pg_isolate::with_database(base, "ai_memory_t_r6383_1700000000_0123abcd");
    assert_eq!(
        rewritten,
        "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_t_r6383_1700000000_0123abcd\
         ?sslmode=verify-full&sslrootcert=/home/x/pg/certs/ca.crt"
    );
    assert_eq!(
        lane_db::database_name(&rewritten),
        "ai_memory_t_r6383_1700000000_0123abcd"
    );
    assert_eq!(lane_db::lane_database_refusal(&rewritten), None);
    // No query: still rewritten, no dangling `?`.
    assert_eq!(
        pg_isolate::with_database("postgres://u:p@h:5445/db", "x"),
        "postgres://u:p@h:5445/x"
    );
}

#[test]
fn isolated_url_is_stable_within_a_process_6383() {
    // Two calls give the identical answer whether the flag is on (one mint,
    // cached) or off (the raw env value).
    assert_eq!(pg_isolate::isolated_url(), pg_isolate::isolated_url());
}

#[test]
fn kill_switch_and_template_rules_6383() {
    // (f) CI_PG_ISOLATE_OFF=1 overrides the flag: nothing is minted.
    assert_eq!(
        pg_isolate::plan(Some("1"), Some("1"), Some(SHARED)),
        Plan::Passthrough(Some(SHARED.to_string()))
    );
    // Any other kill-switch value leaves the opt-in in charge.
    for kill in [None, Some(""), Some("0")] {
        assert!(matches!(
            pg_isolate::plan(Some("1"), kill, Some(SHARED)),
            Plan::Mint { .. }
        ));
    }
    // Review r1 M1: no implicit fallback to the live shared database.
    assert!(pg_isolate::template_for_mint(None).is_err());
    assert!(pg_isolate::template_for_mint(Some("")).is_err());
    assert!(pg_isolate::template_for_mint(Some("tpl; DROP")).is_err());
    assert_eq!(
        pg_isolate::template_for_mint(Some("ai_memory_test_ci_9_1_x_tpl")),
        Ok("ai_memory_test_ci_9_1_x_tpl".to_string())
    );
}

#[test]
fn run_id_rules_6383() {
    // (e) an explicit run id is used verbatim; a malformed one fails closed;
    // an absent one gets a fresh per-process id.
    assert_eq!(pg_isolate::run_id_from(Some(RUN)), Ok(RUN.to_string()));
    for bad in ["", "UPPER", "a-b", "a_b", "x;y"] {
        assert!(pg_isolate::run_id_from(Some(bad)).is_err(), "{bad:?}");
    }
    assert!(pg_isolate::run_id_from(Some(&"a".repeat(pg_isolate::RUN_ID_MAX_LEN + 1))).is_err());
    let fresh = pg_isolate::run_id_from(None).expect("a generated run id");
    assert!(pg_isolate::is_valid_run_id(&fresh), "{fresh}");
    assert_ne!(
        fresh,
        pg_isolate::run_id_from(None).expect("a second run id")
    );
}

#[test]
fn no_drop_uses_force_6383() {
    // (e) review r1 H2: a FORCE drop terminates whoever holds the database.
    let src = include_str!("common/pg_isolate.rs");
    assert!(
        !src.contains("WITH (FORCE)"),
        "tests/common/pg_isolate.rs must never DROP ... WITH (FORCE)"
    );
}

/// Live prerequisites: `None` means skip. With the flag on, a missing template
/// is a failure (review r1 M6), never a skip.
fn live_inputs(case: &str) -> Option<(String, String)> {
    let Some(base) = std::env::var(pg_isolate::URL_VAR).ok() else {
        eprintln!("SKIP {case}: {} unset", pg_isolate::URL_VAR);
        return None;
    };
    let flag_on = std::env::var(pg_isolate::FLAG_VAR).ok().as_deref() == Some("1");
    if let Some(template) = std::env::var(pg_isolate::TEMPLATE_VAR)
        .ok()
        .filter(|t| !t.is_empty())
    {
        return Some((base, template));
    }
    assert!(
        !flag_on,
        "#6383 {case}: {}=1 but {} is unset; the clone path must run, not skip",
        pg_isolate::FLAG_VAR,
        pg_isolate::TEMPLATE_VAR
    );
    eprintln!(
        "SKIP {case}: {} unset (no clone source)",
        pg_isolate::TEMPLATE_VAR
    );
    None
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn test_run_id() -> String {
    format!("t{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

#[test]
fn mint_clones_template_with_extensions_6383() {
    // (b) live Postgres + template.
    let Some((base, template)) = live_inputs("mint_clones_template_with_extensions_6383") else {
        return;
    };
    let run = test_run_id();
    let minted = pg_isolate::mint_blocking(&base, &template, &run).expect("mint from the template");
    let name = lane_db::database_name(&minted).to_string();
    let verdict = std::panic::catch_unwind(|| {
        assert!(
            pg_isolate::parse_isolated_name(&run, &name).is_some(),
            "{name}"
        );
        assert_eq!(lane_db::lane_database_refusal(&minted), None);
        let found = pg_isolate::extension_count_blocking(&minted, &["age", "vector"])
            .expect("count extensions in the clone");
        assert_eq!(
            found, 2,
            "the clone must carry age + vector from the template"
        );
    });
    // Always reclaim the clone, even when an assertion above failed.
    pg_isolate::drop_database_blocking(&base, &run, &name).expect("drop the clone");
    if let Err(panic) = verdict {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn sweep_is_run_scoped_and_spares_held_clones_6383() {
    // (e) live: an idle stale clone of ANOTHER run and a stale clone of this
    // run that still has a session both survive; only this run's idle stale
    // clone is swept.
    let Some((base, template)) = live_inputs("sweep_is_run_scoped_and_spares_held_clones_6383")
    else {
        return;
    };
    let (mine, other) = (test_run_id(), test_run_id());
    let stale = now_unix().saturating_sub(pg_isolate::STALE_AFTER.as_secs() + 300);
    let other_idle = pg_isolate::isolated_db_name(&other, stale);
    let mine_held = pg_isolate::isolated_db_name(&mine, stale);
    let mine_idle = pg_isolate::isolated_db_name(&mine, stale);
    for name in [&other_idle, &mine_held, &mine_idle] {
        pg_isolate::clone_as_blocking(&base, &template, name).expect("create a stale clone");
    }
    let hold = pg_isolate::hold_blocking(&pg_isolate::with_database(&base, &mine_held))
        .expect("hold a session on the clone");
    let verdict = std::panic::catch_unwind(|| {
        let swept = pg_isolate::sweep_run_blocking(&base, &mine).expect("run-scoped sweep");
        assert_eq!(
            swept,
            vec![mine_idle.clone()],
            "only this run's idle stale clone"
        );
        for name in [&other_idle, &mine_held] {
            assert!(
                pg_isolate::database_exists_blocking(&base, name).expect("exists query"),
                "{name} must survive the sweep"
            );
        }
        // Without FORCE a held clone cannot be dropped out from under its session.
        assert!(pg_isolate::drop_database_blocking(&base, &mine, &mine_held).is_err());
    });
    drop(hold);
    for (run, name) in [
        (&other, &other_idle),
        (&mine, &mine_held),
        (&mine, &mine_idle),
    ] {
        if let Err(e) = pg_isolate::drop_database_blocking(&base, run, name) {
            eprintln!("WARN cleanup {name}: {e}");
        }
        assert!(
            !pg_isolate::database_exists_blocking(&base, name).expect("exists query"),
            "{name} must be dropped once its hold is released"
        );
    }
    if let Err(panic) = verdict {
        std::panic::resume_unwind(panic);
    }
}
