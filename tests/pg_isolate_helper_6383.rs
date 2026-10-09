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
//! * (d) the URL rewrite preserves the TLS query (`sslmode`, `sslrootcert`).
//!
//! (a), (c), (d) are pure and always run. (b) needs a live Postgres and a
//! template database and skips cleanly (stderr line) otherwise.
//!
//! Red on the carrier: `common::pg_isolate` does not exist there, so this file
//! does not compile.
#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

mod common;

use common::lane_db;
use common::pg_isolate::{self, Plan};

const SHARED: &str = "postgres://u:pw@127.0.0.1:5445/ai_memory_test_ci_9_1_x";
const ISOLATED: &str = "postgres://u:pw@127.0.0.1:5445/ai_memory_t_1700000000_0123abcd";

#[test]
fn flag_unset_is_passthrough_6383() {
    // (a) every non-"1" flag value, with and without a URL.
    for flag in [None, Some(""), Some("0"), Some("true"), Some("yes")] {
        assert_eq!(
            pg_isolate::plan(flag, Some(SHARED)),
            Plan::Passthrough(Some(SHARED.to_string())),
            "flag {flag:?} must leave the URL untouched"
        );
        assert_eq!(pg_isolate::plan(flag, None), Plan::Passthrough(None));
    }
    // flag on but no URL: nothing to isolate, the cell skips as before.
    assert_eq!(pg_isolate::plan(Some("1"), None), Plan::Passthrough(None));
}

#[test]
fn flag_set_mints_unless_already_isolated_6383() {
    assert_eq!(
        pg_isolate::plan(Some("1"), Some(SHARED)),
        Plan::Mint {
            base: SHARED.to_string()
        }
    );
    // The CI wrapper already minted: the helper must not mint a second layer.
    assert_eq!(
        pg_isolate::plan(Some("1"), Some(ISOLATED)),
        Plan::Passthrough(Some(ISOLATED.to_string()))
    );
    assert!(pg_isolate::is_isolated_url(ISOLATED));
    assert!(!pg_isolate::is_isolated_url(SHARED));
    // `ai_memory_test*` must never be mistaken for an isolated database.
    assert!(!pg_isolate::is_isolated_url(
        "postgres://u:pw@h:5445/ai_memory_test"
    ));
    assert!(!pg_isolate::is_isolated_url("postgres://u:pw@h:5445/ai_memory_tx"));
}

#[test]
fn minted_name_shape_and_length_6383() {
    // (c)
    let name = pg_isolate::isolated_db_name(1_700_000_000);
    assert!(name.starts_with("ai_memory_t_"), "{name}");
    assert!(name.len() <= 63, "{name} is {} bytes", name.len());
    assert!(
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "{name} must be a plain lowercase identifier"
    );
    assert_eq!(
        pg_isolate::parse_isolated_name(&name),
        Some(1_700_000_000),
        "the stale sweep must recognise the name it mints"
    );
    // Distinct on every call (8 random hex), so two binaries never collide.
    assert_ne!(name, pg_isolate::isolated_db_name(1_700_000_000));
    // The sweep must refuse anything that is not the exact shape.
    for bad in [
        "ai_memory_t_1700000000_0123ABCD",
        "ai_memory_t_170000000_0123abcd",
        "ai_memory_t_1700000000_0123abc",
        "ai_memory_t_1700000000_0123abcd_x",
        "ai_memory_test_ci_9_1_x",
        "ai_memory_t_",
        "ai_memory_test",
    ] {
        assert_eq!(pg_isolate::parse_isolated_name(bad), None, "{bad}");
    }
}

#[test]
fn url_rewrite_preserves_tls_query_6383() {
    // (d)
    let base = "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test_ci_9_1_x\
                ?sslmode=verify-full&sslrootcert=/home/x/pg/certs/ca.crt";
    let rewritten = pg_isolate::with_database(base, "ai_memory_t_1700000000_0123abcd");
    assert_eq!(
        rewritten,
        "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_t_1700000000_0123abcd\
         ?sslmode=verify-full&sslrootcert=/home/x/pg/certs/ca.crt"
    );
    assert_eq!(
        lane_db::database_name(&rewritten),
        "ai_memory_t_1700000000_0123abcd"
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
fn mint_clones_template_with_extensions_6383() {
    // (b) live Postgres + template.
    let Some(base) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() else {
        eprintln!("SKIP mint_clones_template_with_extensions_6383: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let Some(template) = std::env::var("AI_MEMORY_TEST_PG_TEMPLATE").ok() else {
        eprintln!("SKIP mint_clones_template_with_extensions_6383: AI_MEMORY_TEST_PG_TEMPLATE unset (no clone source)");
        return;
    };
    let minted = pg_isolate::mint_blocking(&base, &template).expect("mint from the template");
    let name = lane_db::database_name(&minted).to_string();
    let verdict = std::panic::catch_unwind(|| {
        assert!(name.starts_with("ai_memory_t_"), "{name}");
        assert_eq!(lane_db::lane_database_refusal(&minted), None);
        let found = pg_isolate::extension_count_blocking(&minted, &["age", "vector"])
            .expect("count extensions in the clone");
        assert_eq!(found, 2, "the clone must carry age + vector from the template");
    });
    // Always reclaim the clone, even when an assertion above failed.
    pg_isolate::drop_database_blocking(&base, &name).expect("drop the clone");
    if let Err(panic) = verdict {
        std::panic::resume_unwind(panic);
    }
}
