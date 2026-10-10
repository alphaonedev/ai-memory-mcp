// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4165 (WP-EGRESS #6053) — the DNS-resolved SSRF guard's refusal, typed by
//! what the retry ladder may do with it (child module of `subscriptions` so
//! the parent stays under its QUAL-10 ceiling).
//!
//! Before #4165 the guard returned one `anyhow` error and `send` mapped every
//! refusal to the single DLQ reason `dns_ssrf_rejected`. That token covered
//! two verdicts with opposite retry semantics: "the stored URL names a
//! forbidden address class" (permanent — a pure function of the URL bytes and
//! the process posture) and "the resolver did not answer" (transient). Since
//! the ladder could not tell them apart, `refusal_is_terminal` had to treat
//! the shared token as retryable, so a webhook pointing at a private or
//! cloud-metadata address was retried through the full backoff ladder
//! (~6.2 s of a bounded dispatch worker per event) before landing in the DLQ.
//!
//! The split: [`DnsGuardRefusal::ForbiddenAddress`] is TERMINAL and lands as
//! [`super::dlq_reason::DNS_SSRF_FORBIDDEN_ADDRESS`];
//! [`DnsGuardRefusal::ResolutionFailed`] is RETRYABLE and lands as
//! [`super::dlq_reason::DNS_RESOLUTION_FAILED`]. The old token is gone: it
//! was pinned only by tests (now re-pinned on the class each fixture
//! belongs to), never by a document or a wire consumer.

use std::fmt;

/// The port an `https://` URL without an explicit port connects to.
const HTTPS_DEFAULT_PORT: u16 = 443;
/// The port an `http://` (or scheme-less) URL without an explicit port
/// connects to.
const HTTP_DEFAULT_PORT: u16 = 80;

/// #4075 — append the SCHEME's default port to a bracket/colon-normalized
/// `host_port` that omits one, so `ToSocketAddrs` resolves it on the port
/// the connector will actually open. The webhook SSRF lane
/// (`validate_url_dns_with`) resolves through this; the egress inference
/// lane (`egress::resolve_inference_authority`) reads the same rule off its
/// `reqwest::Url` parse (`port_or_known_default`, #4018), so the two lanes
/// agree on the port without sharing a string helper.
///
/// Before #4075 this appended `:80` for every scheme. reqwest's per-host
/// override (`Client::builder().resolve(host, addr)`) is installed with that
/// port, and the locked connector (reqwest 0.12.28 / hyper-util 0.1.20)
/// replaces an override's port only when the URI port is explicit or the
/// override port is 0 — so an implicit-port `https://` target had its TLS
/// connection opened to TCP 80 and every delivery to a normal :443 receiver
/// failed into the DLQ.
#[must_use]
pub(crate) fn host_port_with_default_port(host_port: &str, scheme: &str) -> String {
    let port = if scheme.eq_ignore_ascii_case("https") {
        HTTPS_DEFAULT_PORT
    } else {
        HTTP_DEFAULT_PORT
    };
    format!("{host_port}:{port}")
}

/// Why the DNS-resolved SSRF guard refused a webhook target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsGuardRefusal {
    /// TERMINAL. The verdict is a pure function of the stored URL and the
    /// process posture, so no later attempt can change it: every resolved
    /// address is checked and one is private / link-local / loopback
    /// (without the opt-in), or the host can never name an address at all
    /// (no scheme; an RFC 1035 label/length violation the guard refuses
    /// before any resolver round-trip).
    ForbiddenAddress(String),
    /// RETRYABLE. The resolver did not answer (SERVFAIL, timeout, no route);
    /// the next attempt may see a different resolver outcome.
    ResolutionFailed(String),
}

impl DnsGuardRefusal {
    /// The closed-vocabulary DLQ reason this refusal is recorded under. The
    /// ladder reads terminality off that token (`refusal_is_terminal`), so
    /// the stored `last_error` and the retry decision cannot disagree.
    #[must_use]
    pub(crate) fn dlq_reason(&self) -> &'static str {
        match self {
            Self::ForbiddenAddress(_) => super::dlq_reason::DNS_SSRF_FORBIDDEN_ADDRESS,
            Self::ResolutionFailed(_) => super::dlq_reason::DNS_RESOLUTION_FAILED,
        }
    }
}

impl fmt::Display for DnsGuardRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenAddress(msg) | Self::ResolutionFailed(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for DnsGuardRefusal {}
