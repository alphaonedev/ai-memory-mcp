// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]
#![allow(clippy::doc_lazy_continuation)]

//! Regression suite for issue #1257 — Recall DTO parity gap: CLI lacked
//! `--session-id` flag.
//!
//! ## Defect
//!
//! `RecallRequest::from_cli_args` (`src/models/recall_request.rs`) hard-coded
//! `session_id: None`. The CLI clap struct [`RecallArgs`] had no
//! `--session-id` flag at all. The MCP, HTTP-body, and HTTP-query surfaces
//! all wire `session_id` through to [`RecallRequest`], so the CLI surface
//! was the only one that could not exercise the +0.05 rerank boost for
//! the in-session ring (cap 50) introduced under #518.
//!
//! Per CLAUDE.md Wave-2 Tier-C2 (#967) the three-surface DTO parity
//! contract is load-bearing — adding a new field is "one struct field +
//! one constructor branch per surface", not three out of four with the
//! fourth silently dropped.
//!
//! ## Invariants pinned by this file
//!
//! 1. `RecallArgs::session_id` is a public field (compile-time check).
//! 2. `RecallRequest::from_cli_args` round-trips the CLI value into the
//!    DTO byte-for-byte.
//! 3. The clap parser accepts `--session-id <value>` and rejects no
//!    legitimate value shape.

use ai_memory::cli::recall::RecallArgs;
use ai_memory::models::RecallRequest;
use clap::Parser;

/// Minimal clap host so the test can drive `RecallArgs` through the
/// parser without dragging in the full top-level `Command` enum (which
/// pulls SAL feature flags + a wider surface than this test cares
/// about).
#[derive(Parser)]
struct TestHost {
    #[command(flatten)]
    args: RecallArgs,
}

#[test]
fn recall_args_carries_session_id_field() {
    // Compile-time check: the struct field exists and is the expected
    // type. If a future refactor renames or removes it, this test fails
    // at compilation, not at runtime — exactly the contract we want.
    let args = RecallArgs {
        context: "hello".to_string(),
        namespace: None,
        limit: 10,
        tags: None,
        since: None,
        until: None,
        tier: None,
        as_agent: None,
        budget_tokens: None,
        context_tokens: None,
        session_default: false,
        include_archived: false,
        has_citations: false,
        source_uri_prefix: None,
        kind: None,
        confidence_tier: None,
        verbose_provenance: false,
        format: "human".to_string(),
        session_id: Some("sess-7".to_string()),
    };
    assert_eq!(args.session_id.as_deref(), Some("sess-7"));
}

#[test]
fn from_cli_args_round_trips_session_id_into_dto() {
    let args = RecallArgs {
        context: "hello".to_string(),
        namespace: None,
        limit: 10,
        tags: None,
        since: None,
        until: None,
        tier: None,
        as_agent: None,
        budget_tokens: None,
        context_tokens: None,
        session_default: false,
        include_archived: false,
        has_citations: false,
        source_uri_prefix: None,
        kind: None,
        confidence_tier: None,
        verbose_provenance: false,
        format: "human".to_string(),
        session_id: Some("sess-42".to_string()),
    };
    let req = RecallRequest::from_cli_args(&args);
    assert_eq!(
        req.session_id.as_deref(),
        Some("sess-42"),
        "#1257: CLI --session-id must round-trip into RecallRequest.session_id"
    );
}

#[test]
fn from_cli_args_session_id_none_when_omitted() {
    // Omitting the flag preserves v0.6.x recall semantics (None).
    let args = RecallArgs {
        context: "hello".to_string(),
        namespace: None,
        limit: 10,
        tags: None,
        since: None,
        until: None,
        tier: None,
        as_agent: None,
        budget_tokens: None,
        context_tokens: None,
        session_default: false,
        include_archived: false,
        has_citations: false,
        source_uri_prefix: None,
        kind: None,
        confidence_tier: None,
        verbose_provenance: false,
        format: "human".to_string(),
        session_id: None,
    };
    let req = RecallRequest::from_cli_args(&args);
    assert!(
        req.session_id.is_none(),
        "#1257: omitted --session-id must remain None in the DTO"
    );
}

#[test]
fn clap_accepts_session_id_long_flag() {
    // Drive the actual clap parser to ensure the `--session-id` long
    // flag is recognised and bound to the field. This catches
    // attribute-typo regressions (e.g. `long = "session_id"` vs
    // `long = "session-id"`).
    let parsed = TestHost::try_parse_from(["test", "--session-id", "sess-clap", "hello"])
        .expect("clap must accept --session-id");
    assert_eq!(parsed.args.session_id.as_deref(), Some("sess-clap"));
    assert_eq!(parsed.args.context, "hello");
}

#[test]
fn clap_session_id_optional() {
    // Without --session-id, parsing should still succeed and the field
    // remains None.
    let parsed =
        TestHost::try_parse_from(["test", "hello"]).expect("clap must parse without --session-id");
    assert!(parsed.args.session_id.is_none());
}
