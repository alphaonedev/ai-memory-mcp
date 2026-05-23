// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP `Accept-Provenance` header parser (v0.7.x #1155).
//!
//! Closes the consumer-default friction documented in
//! [`docs/compliance/honest-limitations.md`][1] §3.2 (output poisoning
//! gap). Lets HTTP consumers opt into the verbose-provenance recall
//! envelope shape per-session via a request header without breaking
//! v0.6.x HTTP clients that expect the legacy wire shape.
//!
//! [1]: https://alphaonedev.github.io/ai-memory-mcp/compliance/honest-limitations.md
//!
//! # Asymmetric defaults (intentional)
//!
//! - **MCP** wire default at v0.7.0 is `verbose_provenance=true`
//!   (see `src/mcp/tools/recall.rs:490`). The MCP recall envelope
//!   already includes the Gap 7 derived fields by default.
//! - **HTTP** wire default at v0.7.x is `verbose_provenance=false`
//!   for v0.6.x-HTTP-client backwards compatibility. The HTTP
//!   recall envelope ships the bare serde-roundtripped Memory shape
//!   unless the caller sends `Accept-Provenance: verbose`.
//!
//! Operators who want HTTP-side verbose by default can set
//! `[recall].default_provenance = "verbose"` in `config.toml`
//! (deferred to v0.8.0; for v0.7.x the header is the negotiation
//! surface).
//!
//! # Header values (case-insensitive)
//!
//! - `verbose` — opt in to Gap 7 derived fields
//!   (`confidence_tier`, `freshness_state`, `latest_link_attest_level`)
//! - `minimal` — explicit opt out (same as absent header)
//! - any other value — silently falls through to default (does not
//!   error, to avoid breaking forward-compatible negotiation)
//!
//! # Wire shape
//!
//! With `Accept-Provenance: verbose`, every memory row in the recall
//! response includes the three Gap 7 derived fields when the substrate
//! has the data to compute them. Without the header (or with
//! `minimal`), the row is the legacy bare serde shape — Form 4/5/6
//! columns are still present (citations, source_uri, source_span,
//! confidence_source, memory_kind, etc) because they're real columns
//! the serde derive surfaces. The header gates only the *derived*
//! decoration.

/// Provenance shape requested by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceShape {
    /// Bare serde-roundtripped shape (v0.6.x HTTP wire default).
    Minimal,
    /// Verbose decoration with Gap 7 derived fields appended per row.
    Verbose,
}

impl ProvenanceShape {
    /// True when the verbose Gap 7 derived fields should be appended
    /// to each recalled memory row.
    #[must_use]
    pub const fn is_verbose(self) -> bool {
        matches!(self, Self::Verbose)
    }
}

/// Parse the `Accept-Provenance` HTTP request header into a typed
/// [`ProvenanceShape`]. Falls through to [`ProvenanceShape::Minimal`]
/// (the v0.7.x HTTP backwards-compat default) when the header is
/// absent, empty, or carries an unrecognised value. Case-insensitive.
///
/// This is the v0.7.x #1155 contract — HTTP consumers opt in to the
/// Gap 7 verbose-provenance recall decoration via the header. Absent
/// header preserves the v0.6.x HTTP wire shape exactly.
#[must_use]
pub fn resolve_from_headers(headers: &axum::http::HeaderMap) -> ProvenanceShape {
    headers
        .get("accept-provenance")
        .and_then(|v| v.to_str().ok())
        .map(parse_value)
        .unwrap_or(ProvenanceShape::Minimal)
}

/// Inner parser exposed for direct testing. Case-insensitive trim.
#[must_use]
pub fn parse_value(raw: &str) -> ProvenanceShape {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("verbose") {
        ProvenanceShape::Verbose
    } else {
        // "minimal", "", any unrecognised value → minimal default.
        // Silent fall-through (not 400) to preserve forward-compat
        // when future spec versions add new negotiation values.
        ProvenanceShape::Minimal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn hm(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name.parse::<axum::http::HeaderName>().unwrap(), HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn absent_header_yields_minimal() {
        let h = HeaderMap::new();
        assert_eq!(resolve_from_headers(&h), ProvenanceShape::Minimal);
        assert!(!resolve_from_headers(&h).is_verbose());
    }

    #[test]
    fn verbose_header_yields_verbose() {
        let h = hm("accept-provenance", "verbose");
        assert_eq!(resolve_from_headers(&h), ProvenanceShape::Verbose);
        assert!(resolve_from_headers(&h).is_verbose());
    }

    #[test]
    fn verbose_header_is_case_insensitive() {
        for value in ["VERBOSE", "Verbose", "vErBoSe", "verbose"] {
            let h = hm("accept-provenance", value);
            assert_eq!(
                resolve_from_headers(&h),
                ProvenanceShape::Verbose,
                "Accept-Provenance: {value} must parse as Verbose"
            );
        }
    }

    #[test]
    fn minimal_header_explicit_value_yields_minimal() {
        let h = hm("accept-provenance", "minimal");
        assert_eq!(resolve_from_headers(&h), ProvenanceShape::Minimal);
    }

    #[test]
    fn unrecognised_value_falls_through_to_minimal() {
        // Forward-compatible: a v0.8.0+ value the v0.7.x daemon doesn't
        // know about should NOT 400; it should silently fall through to
        // the minimal default so downstream client upgrades don't
        // require lockstep daemon upgrades.
        for value in [
            "experimental-v2",
            "extended",
            "richer",
            "true",
            "1",
            "verbose-plus",
        ] {
            let h = hm("accept-provenance", value);
            assert_eq!(
                resolve_from_headers(&h),
                ProvenanceShape::Minimal,
                "Accept-Provenance: {value} must fall through to Minimal"
            );
        }
    }

    #[test]
    fn whitespace_tolerated() {
        for value in ["verbose", " verbose", "verbose ", "  verbose  ", "\tverbose"] {
            let h = hm("accept-provenance", value);
            assert_eq!(
                resolve_from_headers(&h),
                ProvenanceShape::Verbose,
                "Accept-Provenance: {value:?} must parse as Verbose after trim"
            );
        }
    }

    #[test]
    fn empty_header_value_yields_minimal() {
        let h = hm("accept-provenance", "");
        assert_eq!(resolve_from_headers(&h), ProvenanceShape::Minimal);
    }

    #[test]
    fn header_name_case_insensitive() {
        // HTTP header names are case-insensitive per RFC 7230. Axum
        // normalises during HeaderMap insertion so this test verifies
        // the contract holds end-to-end.
        for name in ["Accept-Provenance", "accept-provenance", "ACCEPT-PROVENANCE"] {
            let h = hm(name, "verbose");
            assert_eq!(
                resolve_from_headers(&h),
                ProvenanceShape::Verbose,
                "header name `{name}` must resolve case-insensitively"
            );
        }
    }

    #[test]
    fn parse_value_directly() {
        assert_eq!(parse_value("verbose"), ProvenanceShape::Verbose);
        assert_eq!(parse_value("minimal"), ProvenanceShape::Minimal);
        assert_eq!(parse_value(""), ProvenanceShape::Minimal);
        assert_eq!(parse_value("garbage"), ProvenanceShape::Minimal);
        assert_eq!(parse_value("Verbose"), ProvenanceShape::Verbose);
    }

    #[test]
    fn shape_copy_clone_equality() {
        // Trivial trait-impl sanity checks for the typed enum surface.
        let a = ProvenanceShape::Verbose;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a, a.clone());
        assert!(a.is_verbose());
        assert!(!ProvenanceShape::Minimal.is_verbose());
    }
}
