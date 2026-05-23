// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for v0.7.x (#1155) — `Accept-Provenance` HTTP
//! header negotiating Gap 7 verbose decoration on the HTTP recall
//! envelope.
//!
//! These tests pin the parser contract that `resolve_from_headers`
//! exposes. The end-to-end HTTP→sqlite verbose-decoration round-trip
//! is exercised by the existing recall HTTP integration tests at
//! `src/handlers/tests.rs` (they hit the live recall path with the
//! injected header) so we don't duplicate those here. This file
//! focuses on the parser invariants the substrate's wire-shape
//! decision rests on.
//!
//! # Pinned invariants
//!
//! 1. **Absent header → minimal shape** (v0.6.x HTTP backwards-compat
//!    default).
//! 2. **`Accept-Provenance: verbose` → verbose shape** (opt-in to Gap 7
//!    derived fields: `confidence_tier`, `freshness_state`,
//!    `latest_link_attest_level`).
//! 3. **Case-insensitive matching** — both header name and value
//!    follow RFC 7230 / informal HTTP conventions.
//! 4. **Forward-compatible parsing** — unrecognised values silently
//!    fall through to minimal (no 400) so a future spec extension
//!    does not require lockstep daemon upgrades.
//! 5. **Whitespace tolerance** — leading / trailing whitespace
//!    trimmed.
//! 6. **MCP asymmetry preserved** — the substrate's MCP wire path at
//!    `src/mcp/tools/recall.rs:490` continues to default to
//!    `verbose_provenance=true`; this issue's negotiation surface
//!    applies only to HTTP. The asymmetry is intentional (v0.7.x
//!    HTTP backwards-compat) and documented in
//!    `src/handlers/accept_provenance.rs`.

use ai_memory::handlers::accept_provenance::{ProvenanceShape, parse_value, resolve_from_headers};
use axum::http::{HeaderMap, HeaderName, HeaderValue};

// ============================================================================
//  Test fixtures
// ============================================================================

fn header_map(name: &str, value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        name.parse::<HeaderName>().unwrap(),
        HeaderValue::from_str(value).unwrap(),
    );
    h
}

// ============================================================================
//  Group A — default-off invariant (backwards compatibility)
// ============================================================================

#[test]
fn absent_header_resolves_to_minimal() {
    let h = HeaderMap::new();
    assert_eq!(resolve_from_headers(&h), ProvenanceShape::Minimal);
}

#[test]
fn empty_string_header_resolves_to_minimal() {
    let h = header_map("accept-provenance", "");
    assert_eq!(resolve_from_headers(&h), ProvenanceShape::Minimal);
}

#[test]
fn explicit_minimal_header_resolves_to_minimal() {
    let h = header_map("accept-provenance", "minimal");
    assert_eq!(resolve_from_headers(&h), ProvenanceShape::Minimal);
}

#[test]
fn minimal_is_not_verbose() {
    assert!(!ProvenanceShape::Minimal.is_verbose());
}

// ============================================================================
//  Group B — opt-in verbose
// ============================================================================

#[test]
fn verbose_header_resolves_to_verbose() {
    let h = header_map("accept-provenance", "verbose");
    assert_eq!(resolve_from_headers(&h), ProvenanceShape::Verbose);
}

#[test]
fn verbose_shape_is_verbose() {
    assert!(ProvenanceShape::Verbose.is_verbose());
}

#[test]
fn verbose_round_trip_through_header() {
    let h = header_map("accept-provenance", "verbose");
    let shape = resolve_from_headers(&h);
    assert!(shape.is_verbose());
    assert_eq!(shape, ProvenanceShape::Verbose);
}

// ============================================================================
//  Group C — case-insensitivity
// ============================================================================

#[test]
fn header_name_is_case_insensitive_per_rfc_7230() {
    // Axum normalises HeaderMap keys to lowercase on insert per RFC.
    for name in [
        "Accept-Provenance",
        "accept-provenance",
        "ACCEPT-PROVENANCE",
        "Accept-PROVENANCE",
    ] {
        let h = header_map(name, "verbose");
        assert_eq!(
            resolve_from_headers(&h),
            ProvenanceShape::Verbose,
            "header name `{name}` must resolve case-insensitively"
        );
    }
}

#[test]
fn header_value_verbose_is_case_insensitive() {
    for value in ["verbose", "Verbose", "VERBOSE", "vErBoSe", "VERBose"] {
        let h = header_map("accept-provenance", value);
        assert_eq!(
            resolve_from_headers(&h),
            ProvenanceShape::Verbose,
            "value `{value}` must parse as Verbose"
        );
    }
}

#[test]
fn header_value_minimal_is_case_insensitive_no_op() {
    // `minimal` and any unrecognised value both resolve to Minimal,
    // so case-insensitive minimal parsing is irrelevant for the
    // wire-shape decision — but the contract should still be
    // case-insensitive for procurement-reviewer clarity.
    for value in ["minimal", "Minimal", "MINIMAL"] {
        let h = header_map("accept-provenance", value);
        assert_eq!(
            resolve_from_headers(&h),
            ProvenanceShape::Minimal,
            "value `{value}` must resolve to Minimal"
        );
    }
}

// ============================================================================
//  Group D — forward-compatibility (unrecognised values fall through)
// ============================================================================

#[test]
fn unrecognised_value_falls_through_to_minimal_no_400() {
    // Critical contract: a v0.8.0+ value the v0.7.x daemon doesn't
    // know about must NOT 400. It silently falls through to the
    // minimal default so downstream client upgrades don't require
    // lockstep daemon upgrades. The procurement-grade negotiation
    // contract assumes forward-compat.
    for value in [
        "experimental",
        "experimental-v2",
        "extended",
        "richer",
        "verbose-plus",
        "true",
        "1",
        "yes",
        "0",
        "false",
        "null",
        "undefined",
        "verbose;q=0.9",
        "verbose, minimal",
    ] {
        let h = header_map("accept-provenance", value);
        assert_eq!(
            resolve_from_headers(&h),
            ProvenanceShape::Minimal,
            "value `{value}` must fall through to Minimal (no 400)"
        );
    }
}

// ============================================================================
//  Group E — whitespace tolerance
// ============================================================================

#[test]
fn leading_whitespace_tolerated() {
    for value in [" verbose", "  verbose", "\tverbose"] {
        let h = header_map("accept-provenance", value);
        assert_eq!(
            resolve_from_headers(&h),
            ProvenanceShape::Verbose,
            "value `{value:?}` must parse as Verbose after trim"
        );
    }
}

#[test]
fn trailing_whitespace_tolerated() {
    for value in ["verbose ", "verbose  ", "verbose\t"] {
        let h = header_map("accept-provenance", value);
        assert_eq!(
            resolve_from_headers(&h),
            ProvenanceShape::Verbose,
            "value `{value:?}` must parse as Verbose after trim"
        );
    }
}

#[test]
fn surrounding_whitespace_tolerated() {
    for value in [" verbose ", "  verbose  ", "\tverbose\t"] {
        let h = header_map("accept-provenance", value);
        assert_eq!(
            resolve_from_headers(&h),
            ProvenanceShape::Verbose,
            "value `{value:?}` must parse as Verbose"
        );
    }
}

// ============================================================================
//  Group F — direct parser surface (parse_value bypass for unit tests)
// ============================================================================

#[test]
fn parse_value_verbose() {
    assert_eq!(parse_value("verbose"), ProvenanceShape::Verbose);
}

#[test]
fn parse_value_minimal() {
    assert_eq!(parse_value("minimal"), ProvenanceShape::Minimal);
}

#[test]
fn parse_value_empty() {
    assert_eq!(parse_value(""), ProvenanceShape::Minimal);
}

#[test]
fn parse_value_garbage() {
    assert_eq!(parse_value("@@@!!!"), ProvenanceShape::Minimal);
}

// ============================================================================
//  Group G — trait derives sanity
// ============================================================================

#[test]
fn provenance_shape_copy_works() {
    let a = ProvenanceShape::Verbose;
    let b = a;
    let c = a;
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn provenance_shape_partial_eq_works() {
    assert_eq!(ProvenanceShape::Verbose, ProvenanceShape::Verbose);
    assert_eq!(ProvenanceShape::Minimal, ProvenanceShape::Minimal);
    assert_ne!(ProvenanceShape::Verbose, ProvenanceShape::Minimal);
}

#[test]
fn provenance_shape_debug_works() {
    let v = format!("{:?}", ProvenanceShape::Verbose);
    let m = format!("{:?}", ProvenanceShape::Minimal);
    assert!(v.contains("Verbose"));
    assert!(m.contains("Minimal"));
}

// ============================================================================
//  Group H — invariant: multi-call determinism
// ============================================================================

#[test]
fn repeated_resolution_is_deterministic() {
    let h = header_map("accept-provenance", "verbose");
    let s1 = resolve_from_headers(&h);
    let s2 = resolve_from_headers(&h);
    let s3 = resolve_from_headers(&h);
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
    assert_eq!(s1, ProvenanceShape::Verbose);
}

// ============================================================================
//  Group I — MCP asymmetry preserved (documentation invariant)
// ============================================================================

#[test]
fn mcp_path_is_unaffected_by_http_header() {
    // The MCP wire default at v0.7.0 is verbose_provenance=true per
    // `src/mcp/tools/recall.rs:490` — `let verbose_provenance =
    // req.verbose_provenance.unwrap_or(true);`. This issue's header
    // negotiation applies only to HTTP. This test documents the
    // asymmetry as a procurement-grade invariant; the verbose default
    // on MCP is the legacy v0.7.0 contract and was not changed by
    // #1155.
    //
    // The check here is purely documentary — we cannot easily probe
    // the MCP recall handler from a unit test without spinning up the
    // whole substrate. The intent is that any future refactor that
    // accidentally changes the MCP default will trigger a manual
    // review of this test's docstring and force the corresponding doc
    // update at `docs/compliance/honest-limitations.md` §5.
    //
    // The minimal load-bearing check: the HTTP parser default
    // remains `Minimal`, encoding the asymmetry with the MCP
    // default at the wire layer.
    let h = HeaderMap::new();
    assert_eq!(
        resolve_from_headers(&h),
        ProvenanceShape::Minimal,
        "HTTP default Minimal vs MCP default verbose=true is the documented intentional asymmetry per #1155 design"
    );
}
