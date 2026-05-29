// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_lazy_continuation)]

//! Discovery Gate **T0 calibration cells** — assert canonical phrasing
//! present in capabilities-v3 responses across all named profiles.
//!
//! v0.7.0 A2 (`to_describe_to_user`) is the user-facing sentence the
//! NHI Discovery Gate expects every reasoning-class LLM to reproduce
//! when asked "what tools do you have?". This test file is the
//! corresponding T0 calibration cell that runs in CI: it pins the
//! canonical strings from `docs/v0.7/canonical-phrasings.md` so any
//! drift in the substrate breaks the build before it reaches a
//! Discovery Gate observation cell.
//!
//! When a phrasing changes intentionally (e.g., a future increment
//! adds a new recovery path), update both:
//! 1. `docs/v0.7/canonical-phrasings.md` (the human-readable spec)
//! 2. `src/mcp.rs::build_capabilities_{summary,describe_to_user}`
//!    (the substrate)
//!
//! …and re-run this test. Drift between the spec and the substrate is
//! exactly what this file is designed to surface.

use ai_memory::config::{FeatureTier, ResolvedModels, TierConfig};
use ai_memory::mcp::handle_capabilities_with_conn_v3;
use ai_memory::profile::Profile;
use serde_json::Value;

mod common;
use common::{describe_counts, fresh_conn};

fn semantic_tier() -> TierConfig {
    FeatureTier::Semantic.config()
}

fn v3_response(profile: &Profile) -> Value {
    let tier_config = semantic_tier();
    let conn = fresh_conn();
    handle_capabilities_with_conn_v3(
        &tier_config,
        &ResolvedModels::from_tier_preset(&tier_config),
        None,
        false,
        Some(&conn),
        profile,
        None,
        None,
        None,
    )
    .expect("v3 capabilities serialize")
}

// ---------------------------------------------------------------------------
// T0-A2-CORE — `to_describe_to_user` on `--profile core` matches the
// canonical phrasing pinned in docs/v0.7/canonical-phrasings.md verbatim.
// ---------------------------------------------------------------------------
#[test]
fn t0_describe_to_user_core_profile_canonical_phrasing() {
    let val = v3_response(&Profile::core());
    let describe = val["to_describe_to_user"]
        .as_str()
        .expect("describe present");

    // Counts are SSOT-derived (see `describe_counts`): `n_loaded` is the
    // substantive core surface (the original 5 + B1 `memory_load_family`
    // + B2 `memory_smart_load`, overflowing the 5-name preview cap so it
    // ends ", ..."); `n_unloaded` is every other family's tools minus the
    // always-on bootstrap. The sentence is pinned verbatim; the two
    // numbers float with `Family::tool_names` so a new tool in any family
    // can't drift this test (no hardcoded tool-count literal).
    let (n_loaded, n_unloaded) = describe_counts(&Profile::core());
    let expected = format!(
        "I can directly use {n_loaded} memory tools right now \
         (store, recall, list, get, search, ...). {n_unloaded} more \
         (update, delete, forget, gc, etc.) are available on demand — \
         I can load them if you ask for something that needs them, \
         or you can restart the server with a different profile."
    );

    assert_eq!(
        describe, expected,
        "T0-A2-CORE: describe_to_user drifted from canonical phrasing.\n\
         expected: {expected}\n\
         actual:   {describe}"
    );
}

// ---------------------------------------------------------------------------
// T0-A2-FULL — `to_describe_to_user` on `--profile full` uses the
// "nothing more to load" closing form. The "all N" count is the full
// substantive surface (every family's tools minus the always-on
// `memory_capabilities` bootstrap); it is SSOT-derived below, not a
// literal, so adding a tool to any family floats it automatically.
// ---------------------------------------------------------------------------
#[test]
fn t0_describe_to_user_full_profile_canonical_phrasing() {
    let val = v3_response(&Profile::full());
    let describe = val["to_describe_to_user"]
        .as_str()
        .expect("describe present");

    // Under `full` every family loads, so the unloaded count is 0 and
    // `n_loaded` is the entire substantive surface (bootstrap stripped).
    let (n_loaded, n_unloaded) = describe_counts(&Profile::full());
    assert_eq!(
        n_unloaded, 0,
        "T0-A2-FULL: full profile must load every family"
    );
    let expected = format!(
        "I can directly use all {n_loaded} memory tools right now \
         (store, recall, list, get, search, ...). Nothing more to load — \
         the full memory surface is already active."
    );

    assert_eq!(
        describe, expected,
        "T0-A2-FULL: describe_to_user drifted from canonical phrasing.\n\
         expected: {expected}\n\
         actual:   {describe}"
    );
}

// ---------------------------------------------------------------------------
// T0-A2-GRAPH — `to_describe_to_user` on `--profile graph` uses the
// preview-with-ellipsis form (5 loaded shown + ", ..."). Both the
// loaded count and the "N more" unloaded count are SSOT-derived below
// (see `describe_counts`), so a tool landing in any family floats them
// automatically — no hardcoded literal to drift.
// ---------------------------------------------------------------------------
#[test]
fn t0_describe_to_user_graph_profile_canonical_phrasing() {
    let val = v3_response(&Profile::graph());
    let describe = val["to_describe_to_user"]
        .as_str()
        .expect("describe present");

    let (n_loaded, n_unloaded) = describe_counts(&Profile::graph());
    let expected = format!(
        "I can directly use {n_loaded} memory tools right now \
         (store, recall, list, get, search, ...). {n_unloaded} more \
         (update, delete, forget, gc, etc.) are available on demand — \
         I can load them if you ask for something that needs them, \
         or you can restart the server with a different profile."
    );

    assert_eq!(
        describe, expected,
        "T0-A2-GRAPH: describe_to_user drifted from canonical phrasing.\n\
         expected: {expected}\n\
         actual:   {describe}"
    );
}

// ---------------------------------------------------------------------------
// T0-A2-NO-JARGON — `to_describe_to_user` MUST NOT contain MCP-internal
// vocabulary across ANY profile. This is the tone gate from
// docs/v0.7/canonical-phrasings.md §"Tone constraint".
// ---------------------------------------------------------------------------
#[test]
fn t0_describe_to_user_omits_mcp_jargon_across_profiles() {
    for profile in &[
        Profile::core(),
        Profile::graph(),
        Profile::admin(),
        Profile::power(),
        Profile::full(),
    ] {
        let val = v3_response(profile);
        let describe = val["to_describe_to_user"]
            .as_str()
            .expect("describe present");

        for forbidden in &[
            "--profile <family>",
            "--profile full",
            "memory_load_family",
            "memory_smart_load",
            "JSON-RPC",
            "-32601",
            "tools/list",
            "memory_",
        ] {
            assert!(
                !describe.contains(forbidden),
                "T0-A2-NO-JARGON: profile={profile:?}: describe_to_user contains MCP jargon \
                 \"{forbidden}\" — keep it plain for end users.\nfull: {describe}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// T0-A1-CORE — the `summary` (operator-facing) string on `--profile core`
// names the four recovery paths verbatim (a, b, c, d). This is the
// counterpart calibration cell for the A1 phrasing — operators get the
// recovery vocabulary even when LLMs mute it from the user-facing
// describe sentence.
// ---------------------------------------------------------------------------
#[test]
fn t0_summary_core_profile_lists_four_recovery_paths() {
    let val = v3_response(&Profile::core());
    let summary = val["summary"].as_str().expect("summary present");

    // Path (a) — CLI escape hatch
    assert!(
        summary.contains("(a) restart the server with --profile <family>"),
        "T0-A1-CORE: summary missing recovery path (a); got: {summary}"
    );
    // Path (b) — preferred runtime loader (B1, lands later in v0.7.0)
    assert!(
        summary.contains("(b) call memory_load_family(family=<name>) — preferred"),
        "T0-A1-CORE: summary missing recovery path (b); got: {summary}"
    );
    // Path (c) — easiest runtime loader (B2, lands later in v0.7.0)
    assert!(
        summary.contains("(c) call memory_smart_load(intent='<plain language>') — easiest"),
        "T0-A1-CORE: summary missing recovery path (c); got: {summary}"
    );
    // Path (d) — call-by-name fallback for harnesses without runtime loaders
    assert!(
        summary.contains("(d) call the tool by name and recover from JSON-RPC -32601"),
        "T0-A1-CORE: summary missing recovery path (d); got: {summary}"
    );
}

// ---------------------------------------------------------------------------
// T0-CONTRACT — both calibration strings are present and well-typed in
// every named profile's v3 response. Catches structural regressions
// (missing field, null instead of string, etc.) ahead of the per-string
// content tests above.
// ---------------------------------------------------------------------------
#[test]
fn t0_v3_contract_both_strings_present_under_every_named_profile() {
    for profile in &[
        Profile::core(),
        Profile::graph(),
        Profile::admin(),
        Profile::power(),
        Profile::full(),
    ] {
        let val = v3_response(profile);
        assert_eq!(
            val["schema_version"], "3",
            "T0-CONTRACT profile={profile:?}: schema_version missing or wrong"
        );
        assert!(
            val["summary"].as_str().is_some_and(|s| !s.is_empty()),
            "T0-CONTRACT profile={profile:?}: summary missing/empty"
        );
        assert!(
            val["to_describe_to_user"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "T0-CONTRACT profile={profile:?}: to_describe_to_user missing/empty"
        );
    }
}
