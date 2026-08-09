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
// names the ONE real recovery path verbatim, states the -32601 outcome of
// calling an unloaded tool, and explicitly disclaims the two memory
// loaders as tool-recovery paths.
//
// #2781 rewrote this cell. It used to assert four "recovery paths"
// (a/b/c/d) because the manifest advertised four; two of them were
// FALSE. `memory_load_family` / `memory_smart_load` load MEMORIES
// tagged with a family — their handlers return memory rows and never
// mutate the registry or the resolved `Profile` — so an NHI that
// followed path (b) or (c) to "reach an unloaded tool" took a dead end.
// The old (d) was not a recovery path either: calling an unloaded tool
// by name yields `-32601 unknown tool`, which is the OUTCOME, not a way
// to reach it. Asserting the old strings would now pin a false claim
// into the substrate's own calibration suite.
// ---------------------------------------------------------------------------
#[test]
fn t0_summary_core_profile_names_the_one_real_recovery_path() {
    let val = v3_response(&Profile::core());
    let summary = val["summary"].as_str().expect("summary present");

    // The only path that makes an unloaded tool callable.
    assert!(
        summary.contains(
            "(a) The only way to make an unloaded tool callable is to restart \
                          the server with --profile <family> or --profile full"
        ),
        "T0-A1-CORE: summary missing the real recovery path (a); got: {summary}"
    );
    // The honest outcome of calling an unloaded tool.
    assert!(
        summary.contains("calling one returns JSON-RPC -32601 unknown tool"),
        "T0-A1-CORE: summary must state the -32601 outcome; got: {summary}"
    );
    // The two memory loaders are still NAMED (the LLM should know they
    // exist) but explicitly disclaimed as tool-recovery paths (#2781).
    assert!(
        summary.contains("memory_load_family(family=<name>)")
            && summary.contains("memory_smart_load(intent='<plain language>')"),
        "T0-A1-CORE: summary must still name both memory loaders; got: {summary}"
    );
    assert!(
        summary.contains("load MEMORIES tagged with a family; they do NOT register tools"),
        "T0-A1-CORE: summary must disclaim the loaders as tool-recovery paths (#2781); \
         got: {summary}"
    );
    // The retired false framing must not come back.
    for banned in [
        "(b) call memory_load_family(family=<name>) — preferred",
        "(c) call memory_smart_load(intent='<plain language>') — easiest",
        "(d) call the tool by name and recover from JSON-RPC -32601",
        "To use any unloaded tool, choose one of:",
    ] {
        assert!(
            !summary.contains(banned),
            "T0-A1-CORE: #2781 retired phrasing is back: {banned:?}; got: {summary}"
        );
    }
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
