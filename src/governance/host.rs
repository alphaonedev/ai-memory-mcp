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
//!   IPv6 literals are bracketed and compressed (`[::1]`). An IPv4-mapped
//!   IPv6 literal (`::ffff:a.b.c.d` or its hex form) canonicalises to the IPv4
//!   dotted quad on BOTH sides, so each spelling matches the other (#4415).
//! * An optional `:port` suffix is parsed (digits, `u16`, leading zeros
//!   stripped) into [`CanonHost::port`]; see "Ports" below.
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
//! A wildcard pattern is converted label by label, but punycode is not
//! prefix- or substring-preserving, so a `*` that shares a label with
//! non-ASCII text can never line up with the request's A-label. Fail closed:
//! such a pattern (`bü*.example`) is REJECTED (inert when already stored, and
//! refused by `rules add`); use a whole-label `*` (`*.bücher.example`). An
//! ASCII pattern with an in-label `*` (`evil*.com`) is matched against BOTH the
//! request's A-label form and its Unicode (U-label) form, so `evilü.com` is
//! still caught. A wildcard pattern whose all-digit or `0x` labels are not
//! canonical decimal octets (`0177.0.0.*`) is rejected for the same reason:
//! the numeric label would never be normalised.
//!
//! # Ports
//!
//! A rule WITHOUT a port compares only the host part and matches any port or
//! none. A rule WITH a port matches only the same effective port: the
//! request's explicit port, or the scheme default (`https`/`wss` 443,
//! `http`/`ws` 80, `ftp` 21) when absent. When the effective port cannot be
//! established the port rule matches (fail closed: over-block). The egress
//! sinks pass the effective port (#4414). A malformed rule port (including
//! `evil.com:*`) is an inert pattern.
//!
//! # Failure
//!
//! A host that cannot be canonicalised is NEVER treated as allowed: the engine
//! (`agent_action::matcher_status`) makes it match every blocking
//! (`refuse`/`escalate`) `network_request` rule and no `warn`/`log` rule, and a
//! rule PATTERN that cannot be canonicalised is structurally inert (which the
//! engine already fails closed on for blocking severities, #3031).

use std::net::{Ipv4Addr, Ipv6Addr};

/// A canonicalised host (or host pattern) with its optional port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonHost {
    /// Canonical host: lowercase A-label name, dotted-quad IPv4 or bracketed
    /// compressed IPv6.
    pub host: String,
    /// Explicit port, leading zeros stripped.
    pub port: Option<u16>,
}

impl CanonHost {
    /// The Unicode (U-label) spelling of the host when it differs from the
    /// A-label form; `None` when it is identical or cannot be decoded.
    #[must_use]
    pub fn unicode_form(&self) -> Option<String> {
        let mut changed = false;
        let mut out = Vec::new();
        for label in self.host.split('.') {
            match label.strip_prefix("xn--") {
                Some(rest) => {
                    out.push(punycode_decode(rest)?);
                    changed = true;
                }
                None => out.push(label.to_string()),
            }
        }
        changed.then(|| out.join("."))
    }
}

/// Scheme default port, when one is known.
#[must_use]
pub fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme.to_ascii_lowercase().as_str() {
        "https" | "wss" => Some(443),
        "http" | "ws" => Some(80),
        "ftp" => Some(21),
        _ => None,
    }
}

/// The `host[:port]` string an egress sink hands the governance gate for a
/// parsed URL: the URL host plus its EXPLICIT port (the scheme default is
/// applied by the engine from the action's scheme), so a port-scoped rule
/// can enforce on a non-default port (#4414). `None` when the URL has no host.
#[must_use]
pub fn egress_host(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

/// Does a rule port accept the request? No rule port: any. Otherwise the
/// request's explicit port, else the scheme default; unknown matches (fail
/// closed).
#[must_use]
pub fn port_matches(rule: Option<u16>, request: Option<u16>, scheme: &str) -> bool {
    match rule {
        None => true,
        Some(r) => request
            .or_else(|| default_port_for_scheme(scheme))
            .is_none_or(|p| p == r),
    }
}

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
    /// A wildcard that cannot be matched reliably after canonicalisation: a
    /// `*` sharing a label with non-ASCII text, or a numeric/hex label that
    /// is not a canonical decimal octet.
    BadWildcard,
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
            Self::BadWildcard => {
                "wildcard shares a label with non-ASCII text or a non-canonical numeric label"
            }
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
pub fn canonicalize_host(raw: &str) -> Result<CanonHost, HostCanonError> {
    canonicalize(raw, false)
}

/// Canonicalise a rule-side host pattern: identical to [`canonicalize_host`]
/// except `*` is allowed inside a (non-IP) label, with the wildcard
/// restrictions in the module docs. A pattern with no `*` canonicalises
/// exactly like a host, so a rule `127.000.000.001` and a request `127.0.0.1`
/// meet at the same string.
///
/// # Errors
///
/// Returns a [`HostCanonError`]; an un-canonicalisable pattern is inert.
pub fn canonicalize_host_pattern(raw: &str) -> Result<CanonHost, HostCanonError> {
    canonicalize(raw, true)
}

fn canonicalize(raw: &str, allow_star: bool) -> Result<CanonHost, HostCanonError> {
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
    let host = canonical_host_part(host_part, allow_star)?;
    Ok(CanonHost { host, port })
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
        // #4415 — an IPv4-mapped IPv6 literal reaches the same endpoint as
        // the IPv4 address: unify both spellings on the dotted quad.
        if let Some(v4) = addr.to_ipv4_mapped() {
            return Ok(v4.to_string());
        }
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

/// Wildcard pattern: lowercase label by label, leaving `*` untouched.
///
/// Fail closed on the two shapes that cannot be matched reliably: a label
/// mixing `*` with non-ASCII text (punycode is not substring-preserving), and
/// an all-digit / `0x` label that is not a canonical decimal octet (the request
/// side would normalise it, the pattern side cannot with a `*` present).
fn canonical_wildcard(host: &str) -> Result<String, HostCanonError> {
    let mut labels = Vec::new();
    for label in host.split('.') {
        if label.is_empty() {
            return Err(HostCanonError::EmptyLabel);
        }
        if !label.is_ascii() {
            if label.contains('*') {
                return Err(HostCanonError::BadWildcard);
            }
            labels.push(parse_domain_or_ipv4(label)?);
            continue;
        }
        let lower = label.to_ascii_lowercase();
        if !lower.contains('*') && numeric_label_is_noncanonical(&lower) {
            return Err(HostCanonError::BadWildcard);
        }
        labels.push(lower);
    }
    let canon = labels.join(".");
    check_lengths(&canon)?;
    Ok(canon)
}

/// All-digit or `0x`-hex label that is not a canonical decimal octet.
fn numeric_label_is_noncanonical(label: &str) -> bool {
    let all_digits = !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit());
    let hex = label
        .strip_prefix("0x")
        .is_some_and(|r| r.bytes().all(|b| b.is_ascii_hexdigit()));
    if hex {
        return true;
    }
    if !all_digits {
        return false;
    }
    let canonical_octet =
        (label == "0" || !label.starts_with('0')) && label.parse::<u16>().is_ok_and(|v| v <= 255);
    !canonical_octet
}

/// RFC 3492 punycode decode of one label body (the part after `xn--`).
/// `None` on any malformed or overflowing input (checked arithmetic, PERF-02).
fn punycode_decode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    let (basic, ext) = match input.rfind('-') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => ("", input),
    };
    if !basic.is_ascii() {
        return None;
    }
    let mut out: Vec<char> = basic.chars().collect();
    let (mut n, mut i, mut bias) = (128u32, 0u32, 72u32);
    let mut bytes = ext.bytes().peekable();
    while bytes.peek().is_some() {
        let oldi = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let b = bytes.next()?;
            let digit = u32::from(match b {
                b'a'..=b'z' => b - b'a',
                b'A'..=b'Z' => b - b'A',
                b'0'..=b'9' => b - b'0' + 26,
                _ => return None,
            });
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k = k.checked_add(BASE)?;
        }
        let len = u32::try_from(out.len()).ok()?.checked_add(1)?;
        // Bias adaptation (RFC 3492 section 6.1).
        let mut delta = i - oldi;
        delta = if oldi == 0 { delta / DAMP } else { delta / 2 };
        delta += delta / len;
        let mut kk = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            kk += BASE;
        }
        bias = kk + (BASE - TMIN + 1) * delta / (delta + SKEW);
        n = n.checked_add(i / len)?;
        i %= len;
        out.insert(usize::try_from(i).ok()?, char::from_u32(n)?);
        i += 1;
    }
    Some(out.into_iter().collect())
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

    fn h(raw: &str) -> String {
        canonicalize_host(raw).unwrap().host
    }

    #[test]
    fn case_and_root_dot() {
        assert_eq!(h("EXAMPLE.com"), "example.com");
        assert_eq!(h("example.com."), "example.com");
        assert_eq!(h("ExAmPlE.CoM."), "example.com");
        assert_eq!(
            canonicalize_host("example.com..").unwrap_err(),
            HostCanonError::EmptyLabel
        );
    }

    #[test]
    fn idn_to_a_label_and_back() {
        assert_eq!(h("b\u{fc}cher.example"), "xn--bcher-kva.example");
        assert_eq!(h("B\u{dc}CHER.example."), "xn--bcher-kva.example");
        assert_eq!(
            canonicalize_host("xn--bcher-kva.example")
                .unwrap()
                .unicode_form()
                .as_deref(),
            Some("b\u{fc}cher.example")
        );
        assert_eq!(
            canonicalize_host("plain.example").unwrap().unicode_form(),
            None
        );
        assert_eq!(punycode_decode("bcher-kva").as_deref(), Some("b\u{fc}cher"));
        assert_eq!(punycode_decode("!!"), None);
        assert_eq!(
            canonicalize_host_pattern("*.b\u{fc}cher.example")
                .unwrap()
                .host,
            "*.xn--bcher-kva.example"
        );
    }

    #[test]
    fn wildcard_fail_closed_shapes() {
        for bad in [
            "b\u{fc}*.example",
            "*b\u{fc}cher.example",
            "0177.0.0.*",
            "0x7f.0.0.*",
            "00.1.*",
            "256.0.0.*",
        ] {
            assert_eq!(
                canonicalize_host_pattern(bad).unwrap_err(),
                HostCanonError::BadWildcard,
                "{bad:?}"
            );
        }
        assert!(canonicalize_host_pattern("127.0.0.*").is_ok());
        assert!(canonicalize_host_pattern("evil*.com").is_ok());
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
    fn ip_literals_and_mapped() {
        assert_eq!(h("127.000.000.001"), "127.0.0.1");
        assert_eq!(h("127.1"), "127.0.0.1");
        assert_eq!(h("[0:0:0:0:0:0:0:1]"), "[::1]");
        assert_eq!(h("::1"), "[::1]");
        assert_eq!(h("::ffff:127.0.0.1"), "127.0.0.1");
        assert_eq!(h("[::ffff:7f00:1]"), "127.0.0.1");
        assert_eq!(
            canonicalize_host_pattern("[::ffff:127.0.0.1]")
                .unwrap()
                .host,
            "127.0.0.1"
        );
        assert_eq!(h("[::ffff:7f00:2]"), "127.0.0.2");
        assert!(canonicalize_host("[::1").is_err());
        assert!(canonicalize_host("a:b:c").is_err());
    }

    #[test]
    fn ports_parsed_and_matched() {
        let c = canonicalize_host("Evil.com.:0443").unwrap();
        assert_eq!((c.host.as_str(), c.port), ("evil.com", Some(443)));
        assert_eq!(canonicalize_host("[::1]:08080").unwrap().port, Some(8080));
        assert!(canonicalize_host("evil.com:99999").is_err());
        assert!(canonicalize_host("evil.com:").is_err());
        assert!(canonicalize_host_pattern("evil.com:*").is_err());
        assert!(port_matches(None, Some(1), "https"));
        assert!(port_matches(Some(443), None, "https"));
        assert!(!port_matches(Some(443), None, "http"));
        assert!(!port_matches(Some(443), Some(8443), "https"));
        assert!(port_matches(Some(443), None, "gopher"));
    }
}
