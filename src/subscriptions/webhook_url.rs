// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6371 (WP-EGRESS #6053, follow-up to #4018) — ONE parse of a webhook URL
//! for the syntactic guard, the DNS-resolved guard and the HTTP client.
//!
//! Both SSRF guards used to carve the host out of the raw string with a
//! hand-rolled `find(['/', '?', '#'])` / `rfind('@')` / `rfind(':')` scan,
//! while `send()` handed the same string to reqwest, whose WHATWG parser ends
//! the authority at a backslash in the special schemes (`https`, `http`),
//! strips tab/newline, and normalizes legacy IPv4 spellings (`2130706433`,
//! `0x7f.1`, `127.1`). The guard therefore cleared host A while the client
//! connected to host B: `https://127.0.0.1\@8.8.8.8/hook` read as the public
//! `8.8.8.8` to the guard and as loopback to reqwest, so a tenant who could
//! register a webhook reached loopback and cloud-metadata endpoints with the
//! loopback opt-in off. The inference lane closed the same class in #4018 by
//! reading host, port and DNS pin off a single `reqwest::Url`
//! (`egress::parse_target`); this module is that rule for the webhook lane.
//!
//! The contract is agree-or-refuse: every guard decision reads
//! [`ParsedWebhookUrl::host`] / [`ParsedWebhookUrl::port`], and `send()`
//! posts [`ParsedWebhookUrl::url`], the parsed object itself, so reqwest never
//! re-parses the string. A string the parser rejects is refused.

use reqwest::Url;

/// Why a webhook URL could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebhookUrlError {
    /// No `scheme://` separator at all.
    MissingScheme,
    /// The reqwest URL parser rejects the string (empty host, bad port,
    /// unbalanced bracket, invalid character, ...). The client could never
    /// send to it.
    Malformed,
}

/// A webhook URL parsed once, by the parser the HTTP client uses.
#[derive(Debug, Clone)]
pub(crate) struct ParsedWebhookUrl {
    url: Url,
}

impl ParsedWebhookUrl {
    /// Parse `raw` with `reqwest::Url::parse` (per ERRORS-19: a string the
    /// client could not parse is refused, never guessed at).
    ///
    /// # Errors
    /// [`WebhookUrlError::MissingScheme`] when `raw` has no `://`;
    /// [`WebhookUrlError::Malformed`] when the parser rejects it.
    pub(crate) fn parse(raw: &str) -> Result<Self, WebhookUrlError> {
        match Url::parse(raw) {
            Ok(url) => Ok(Self { url }),
            Err(_) if !raw.contains("://") => Err(WebhookUrlError::MissingScheme),
            Err(_) => Err(WebhookUrlError::Malformed),
        }
    }

    /// The lowercased scheme.
    pub(crate) fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// The bracket-free, lowercased host exactly as the client will connect
    /// to it (an IPv4/IPv6 literal in canonical text form, or a domain). The
    /// form reqwest's `Client::builder().resolve()` keys on and
    /// `ToSocketAddrs` resolves. `None` when the URL has no host.
    pub(crate) fn host(&self) -> Option<String> {
        let host = self.url.host_str()?;
        Some(
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase(),
        )
    }

    /// The port the client opens: the explicit one, else the scheme default
    /// (443 for https, #4075).
    pub(crate) fn port(&self) -> Option<u16> {
        self.url.port_or_known_default()
    }

    /// The parsed URL the client must post to.
    pub(crate) fn url(&self) -> &Url {
        &self.url
    }
}

/// #6860 — the dispatch client builder, factored out of `send()` so a unit
/// cell can prove the DNS-rebind pin (#1082) is applied and keyed on the host
/// the client will look up ([`ParsedWebhookUrl::host`]). No system proxy
/// (#6372), no redirects (SR-W3), the operator CA (#3705), and one
/// `resolve(host, addr)` override per guard-validated address.
pub(crate) fn pinned_client_builder(
    host: &str,
    addrs: &[std::net::SocketAddr],
) -> reqwest::blocking::ClientBuilder {
    // #6372 — never honour HTTP(S)_PROXY / ALL_PROXY: a proxy resolves the
    // host itself and would receive the signed body, bypassing the pins below
    // (per ERRORS-19, fail closed).
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(super::ACK_TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    // v1.0.0 #3705 — a receiver behind a private PKI: the operator-installed
    // root (`[subscriptions] ca_cert`) is trusted in addition to the public
    // roots. Never a peer's certificate by inference; always an explicit act.
    if let Some(ca) = super::dispatch_root_certificate() {
        builder = builder.add_root_certificate(ca);
    }
    for addr in addrs {
        // The override SHADOWS reqwest's own DNS query for this host on this
        // client, closing the rebind window (#1082).
        builder = builder.resolve(host, *addr);
    }
    builder
}
