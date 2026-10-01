// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4300 — the ONE canonical form for a `network_request` host.
//!
//! DNS names are case-insensitive and may carry a single root dot, and the
//! outbound clients that follow the governance gate parse hosts with the WHATWG
//! URL parser (IDNA/UTS-46, IPv4 short/octal/hex forms). The governance
//! `network_request` matcher used to compare the rule host and the evaluated
//! host byte-for-byte, so a `refuse` rule for `evil.example.com` did not apply
//! to `EVIL.example.com`, `evil.example.com.` or the equivalent A-label of a
//! Unicode spelling: a silent fail-open.
//!
//! Both sides now pass through [`canonicalize_host`] /
//! [`canonicalize_host_pattern`] before the glob engine runs. They share one
//! implementation so a rule and a request can never be canonicalised
//! differently (per ERRORS-09, the validated output is a plain `String` that
//! only these constructors produce).
//!
//! # Canonical form
//!
//! * ASCII-lowercase; exactly ONE trailing root dot is removed (`a.com..` is
//!   rejected as an empty label).
//! * Unicode labels are converted to the A-label (punycode) form by the same
//!   URL parser every outbound client uses (no extra dependency).
//! * Empty labels, labels over 63 bytes, hosts over 253 bytes, and any
//!   whitespace, control or NUL character are rejected, as are the URL
//!   delimiters `/ \ ? # @ %` and `<>^|`.
//! * IPv4 literals are the WHATWG dotted quad (so `127.1` and `127.000.000.001`
//!   canonicalise to `127.0.0.1`, exactly the address a client would dial);
//!   IPv6 literals are bracketed and compressed (`[::1]`).
//! * An optional `:port` suffix is kept (digits, `u16`, leading zeros
//!   stripped) so a rule written with a port keeps matching.
//!
//! # Wildcards
//!
//! A rule pattern may carry `*` (see [`canonicalize_host_pattern`]). Matching
//! stays the existing governance glob run on the canonical strings: `*` spans
//! any run of bytes INCLUDING dots, so `*.example.com` matches
//! `a.example.com` AND `a.b.example.com` (any depth) but never the bare apex
//! `example.com`, never `evilexample.com`, and never
//! `a.example.com.evil.org`. Because a canonical host has no empty label it
//! can never start with `.`, so the wildcard cannot match an empty
//! sub-label.
//!
//! # Failure
//!
//! A host that cannot be canonicalised is NEVER treated as allowed: the engine
//! (`agent_action::matcher_status`) makes it match every blocking
//! (`refuse`/`escalate`) `network_request` rule and no `warn`/`log` rule, and a
//! rule PATTERN that cannot be canonicalised is structurally inert (which the
//! engine already fails closed on for blocking severities, #3031).

use std::net::{Ipv4Addr, Ipv6Addr};

/// Maximum total length of a canonical host name in bytes (RFC 1035).
pub const MAX_HOST_BYTES: usize = 253;
/// Maximum length of one label in bytes (RFC 1035).
pub const MAX_LABEL_BYTES: usize = 63;
/// Upper bound on the raw input examined, so a hostile string cannot make the
/// IDNA step do unbounded work. Anything longer cannot canonicalise to a
/// valid host anyway.
const MAX_RAW_BYTES: usize = 1024;

/// Why a host or host pattern could not be canonicalised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCanonError {
    /// Empty host (or only a root dot).
    Empty,
    /// Longer than [`MAX_HOST_BYTES`] (or the raw-input bound).
    TooLong,
    /// Whitespace, control, NUL or URL-delimiter character.
    BadChar,
    /// An empty label (`a..b`, a leading dot, or a second trailing dot).
    EmptyLabel,
    /// A label longer than [`MAX_LABEL_BYTES`].
    LabelTooLong,
    /// IDNA / host parsing refused the name.
    BadName,
    /// A malformed IP literal or bracket.
    BadIp,
    /// A malformed `:port` suffix.
    BadPort,
}

impl std::fmt::Display for HostCanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty host",
            Self::TooLong => "host exceeds 253 bytes",
            Self::BadChar => "host contains a whitespace, control or delimiter character",
            Self::EmptyLabel => "host has an empty label",
            Self::LabelTooLong => "host label exceeds 63 bytes",
            Self::BadName => "host is not a valid domain name",
            Self::BadIp => "malformed IP literal",
            Self::BadPort => "malformed port",
        })
    }
}

impl std::error::Error for HostCanonError {}

/// Canonicalise an evaluated (request-side) host. `*` is rejected: a real
/// host never contains it.
///
/// # Errors
///
/// Returns a [`HostCanonError`] when the host cannot be put into canonical
/// form; the caller must fail closed.
pub fn canonicalize_host(raw: &str) -> Result<String, HostCanonError> {
    canonicalize(raw, false)
}

/// Canonicalise a rule-side host pattern: identical to [`canonicalize_host`]
/// except `*` is allowed inside a (non-IP) label. A pattern with no `*`
/// canonicalises exactly like a host, so a rule `127.000.000.001` and a request
/// `127.0.0.1` meet at the same string.
///
/// # Errors
///
/// Returns a [`HostCanonError`]; an un-canonicalisable pattern is inert.
pub fn canonicalize_host_pattern(raw: &str) -> Result<String, HostCanonError> {
    canonicalize(raw, true)
}

fn canonicalize(raw: &str, allow_star: bool) -> Result<String, HostCanonError> {
    if raw.is_empty() {
        return Err(HostCanonError::Empty);
    }
    if raw.len() > MAX_RAW_BYTES {
        return Err(HostCanonError::TooLong);
    }
    for c in raw.chars() {
        let bad = c.is_control()
            || c.is_whitespace()
            || matches!(
                c,
                '/' | '\\' | '?' | '#' | '@' | '%' | '<' | '>' | '^' | '|'
            )
            || (c == '*' && !allow_star);
        if bad {
            return Err(HostCanonError::BadChar);
        }
    }
    let (host_part, port) = split_port(raw)?;
    let mut out = canonical_host_part(host_part, allow_star)?;
    if let Some(p) = port {
        out.push(':');
        out.push_str(&p.to_string());
    }
    Ok(out)
}

/// Split an optional `:port`; a bare IPv6 literal (several colons) is
/// bracketed here so the caller sees one shape.
fn split_port(raw: &str) -> Result<(&str, Option<u16>), HostCanonError> {
    if let Some(rest) = raw.strip_prefix('[') {
        let close = rest.find(']').ok_or(HostCanonError::BadIp)?;
        let after = &rest[close + 1..];
        let port = match after {
            "" => None,
            _ => Some(parse_port(
                after.strip_prefix(':').ok_or(HostCanonError::BadIp)?,
            )?),
        };
        // `raw[..=close+1]` is `[inner]`: keep the brackets for the caller.
        return Ok((&raw[..close + 2], port));
    }
    match raw.matches(':').count() {
        0 => Ok((raw, None)),
        1 => {
            let (h, p) = raw.split_once(':').ok_or(HostCanonError::BadPort)?;
            Ok((h, Some(parse_port(p)?)))
        }
        // Bare IPv6 (no port is expressible without brackets).
        _ => Ok((raw, None)),
    }
}

fn parse_port(p: &str) -> Result<u16, HostCanonError> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HostCanonError::BadPort);
    }
    p.parse::<u16>().map_err(|_| HostCanonError::BadPort)
}

fn canonical_host_part(host: &str, allow_star: bool) -> Result<String, HostCanonError> {
    // IPv6: bracketed, or bare with several colons.
    if host.starts_with('[') || host.contains(':') {
        let inner = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let addr: Ipv6Addr = inner.parse().map_err(|_| HostCanonError::BadIp)?;
        return Ok(format!("[{addr}]"));
    }
    // Exactly one trailing root dot.
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return Err(HostCanonError::Empty);
    }
    if allow_star && host.contains('*') {
        return canonical_wildcard(host);
    }
    let canon = parse_domain_or_ipv4(host)?;
    check_lengths(&canon)?;
    Ok(canon)
}

/// Run the host through the WHATWG URL host parser (the parser every outbound
/// client uses): lowercases, applies IDNA to A-labels, and normalises IPv4.
fn parse_domain_or_ipv4(host: &str) -> Result<String, HostCanonError> {
    let url =
        reqwest::Url::parse(&format!("http://{host}/")).map_err(|_| HostCanonError::BadName)?;
    let parsed = url.host_str().ok_or(HostCanonError::BadName)?;
    if url.port().is_some() || !parsed.is_ascii() {
        return Err(HostCanonError::BadName);
    }
    if let Ok(v4) = parsed.parse::<Ipv4Addr>() {
        return Ok(v4.to_string());
    }
    Ok(parsed.to_ascii_lowercase())
}

/// Wildcard pattern: canonicalise label by label, leaving `*` untouched.
fn canonical_wildcard(host: &str) -> Result<String, HostCanonError> {
    let mut labels = Vec::new();
    for label in host.split('.') {
        if label.is_empty() {
            return Err(HostCanonError::EmptyLabel);
        }
        if label.is_ascii() {
            labels.push(label.to_ascii_lowercase());
            continue;
        }
        // A Unicode label with a wildcard: A-label each literal run.
        let mut piece_out = Vec::new();
        for piece in label.split('*') {
            if piece.is_empty() {
                piece_out.push(String::new());
            } else {
                piece_out.push(parse_domain_or_ipv4(piece)?);
            }
        }
        labels.push(piece_out.join("*"));
    }
    let canon = labels.join(".");
    check_lengths(&canon)?;
    Ok(canon)
}

fn check_lengths(canon: &str) -> Result<(), HostCanonError> {
    if canon.len() > MAX_HOST_BYTES {
        return Err(HostCanonError::TooLong);
    }
    for label in canon.split('.') {
        if label.is_empty() {
            return Err(HostCanonError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_BYTES {
            return Err(HostCanonError::LabelTooLong);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_and_root_dot() {
        assert_eq!(canonicalize_host("EXAMPLE.com").unwrap(), "example.com");
        assert_eq!(canonicalize_host("example.com.").unwrap(), "example.com");
        assert_eq!(canonicalize_host("ExAmPlE.CoM.").unwrap(), "example.com");
        assert_eq!(
            canonicalize_host("example.com..").unwrap_err(),
            HostCanonError::EmptyLabel
        );
    }

    #[test]
    fn idn_to_a_label() {
        assert_eq!(
            canonicalize_host("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            canonicalize_host("BÜCHER.example.").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            canonicalize_host_pattern("*.bücher.example").unwrap(),
            "*.xn--bcher-kva.example"
        );
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            ".",
            " example.com",
            "example.com ",
            "exa mple.com",
            "a\0b.com",
            "a\tb.com",
            "a..b.com",
            ".a.com",
            "a/b.com",
            "a@b.com",
            "a%41.com",
            "*.a.com",
        ] {
            assert!(canonicalize_host(bad).is_err(), "{bad:?} must fail");
        }
        let long_label = format!("{}.com", "a".repeat(64));
        assert_eq!(
            canonicalize_host(&long_label).unwrap_err(),
            HostCanonError::LabelTooLong
        );
        let long_host = vec!["a".repeat(60); 5].join(".");
        assert_eq!(
            canonicalize_host(&long_host).unwrap_err(),
            HostCanonError::TooLong
        );
    }

    #[test]
    fn ip_literals() {
        assert_eq!(canonicalize_host("127.000.000.001").unwrap(), "127.0.0.1");
        assert_eq!(canonicalize_host("127.1").unwrap(), "127.0.0.1");
        assert_eq!(canonicalize_host("127.0.0.1.").unwrap(), "127.0.0.1");
        assert_eq!(canonicalize_host("[0:0:0:0:0:0:0:1]").unwrap(), "[::1]");
        assert_eq!(canonicalize_host("::1").unwrap(), "[::1]");
        assert_eq!(canonicalize_host("[::1]:08080").unwrap(), "[::1]:8080");
        assert!(canonicalize_host("[::1").is_err());
        assert!(canonicalize_host("a:b:c").is_err());
    }

    #[test]
    fn ports_kept() {
        assert_eq!(canonicalize_host("Evil.com.:0443").unwrap(), "evil.com:443");
        assert!(canonicalize_host("evil.com:99999").is_err());
        assert!(canonicalize_host("evil.com:").is_err());
    }

    #[test]
    fn pattern_matches_host_shape() {
        assert_eq!(
            canonicalize_host_pattern("*.Evil.Example.COM.").unwrap(),
            "*.evil.example.com"
        );
        assert_eq!(canonicalize_host_pattern("**").unwrap(), "**");
        assert!(canonicalize_host_pattern("*..com").is_err());
        assert_eq!(
            canonicalize_host_pattern("127.000.000.001").unwrap(),
            "127.0.0.1"
        );
    }
}
