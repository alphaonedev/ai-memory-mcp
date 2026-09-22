// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3711 family — **render a URL from an ALLOWLIST, never mask it.**
//!
//! Every sink that used to print a store DSN, a federation peer URL or a
//! webhook target through the userinfo-only maskers
//! (`logging::redact_url_password` / `redact_urls_in_message`) kept the
//! rest of the URL verbatim: a `?password=` / `sslpassword=` / `sslkey=`
//! query key, a Slack/Discord path token, a bearer token in the fragment.
//! A masker is a denylist — it can only hide the credential shapes its
//! author enumerated (the #3674 ruling; #3667 #3675 #3684 #3687 #3710 #3711
//! are the same class found nine times). This module is the inverse: the
//! renderer knows what it is ALLOWED to show — scheme, host, port (and for
//! a store URL the database name) — and shows nothing else. There is no
//! credential shape it can fail to recognise because it never looks for one.
//!
//! Parsing is `reqwest::Url` (the `url` crate). An unparseable URL renders
//! as its scheme token plus `<unparseable>`, never its bytes: a URL that
//! failed to parse is exactly the one whose shape nobody vouched for.
//!
//! The same principle applied to a transport error: `reqwest::Error`'s
//! `Display` appends ` for url (<full request URL>)` (#3710), so a
//! transport failure is CLASSIFIED into [`TransportFailure`] — a closed
//! vocabulary — at the origin, before it becomes a log line, a DLQ
//! `last_error` or an `anyhow` chain. The class is what an operator acts
//! on; the URL was never what they needed.

use std::fmt;

/// The scheme every rendering falls back to when the input has none.
const NO_SCHEME: &str = "<no scheme>";
/// Marker for a URL `reqwest::Url` refused to parse. The bytes are never
/// shown: an unparseable URL is one whose shape nobody vouched for.
const UNPARSEABLE: &str = "<unparseable>";
/// Marker for a URL with no host component (`sqlite:///path` renders its
/// path instead and never reaches this).
const NO_HOST: &str = "<no host>";

/// The scheme token of `url` (up to the first `://`), or [`NO_SCHEME`].
fn scheme_token(url: &str) -> &str {
    url.trim().split_once("://").map_or(NO_SCHEME, |(s, _)| s)
}

/// The rendering of a URL `reqwest::Url` refused: its scheme token and
/// the [`UNPARSEABLE`] marker, never its bytes.
fn unparseable(url: &str) -> String {
    format!("{}://{UNPARSEABLE}", scheme_token(url))
}

/// `scheme://host[:port]` — the origin of `url` and nothing else. No
/// userinfo, no path, no query, no fragment.
///
/// Use it for a federation peer, a webhook target, an LLM / embedder base
/// URL, an MCP forward URL — any URL that reaches a log line, a refusal,
/// a doctor fact or a stored record.
#[must_use]
pub fn url_origin(url: &str) -> String {
    let trimmed = url.trim();
    match reqwest::Url::parse(trimmed) {
        Ok(parsed) => {
            let host = parsed.host_str().unwrap_or(NO_HOST);
            match parsed.port() {
                Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
                None => format!("{}://{host}", parsed.scheme()),
            }
        }
        Err(_) => unparseable(trimmed),
    }
}

/// `scheme://host[:port]/path` — the origin plus the PATH of `url`, still
/// without userinfo, query or fragment.
///
/// This is the identity of a federation peer for a DURABLE key (#3675,
/// `sync_state.peer_id`): two peers behind one host differ by path, and a
/// peer's path is operator config, never a tenant credential channel. A
/// webhook target is NOT rendered this way — chat webhooks carry their
/// secret in the path (#3684); use [`url_origin`] there.
#[must_use]
pub fn url_origin_and_path(url: &str) -> String {
    let trimmed = url.trim();
    match reqwest::Url::parse(trimmed) {
        Ok(parsed) => {
            let mut out = url_origin(trimmed);
            let path = parsed.path();
            if path != "/" {
                out.push_str(path);
            }
            out
        }
        Err(_) => unparseable(trimmed),
    }
}

/// A store URL (`--store-url`, `AI_MEMORY_STORE_URL[_FILE]`) for every
/// human- and machine-readable sink: the boot `info!` line, doctor,
/// `schema-init --json`, `migrate --json`, refusals.
///
/// - `sqlite://<path>` renders verbatim: the path IS the database file and
///   carries no credential channel.
/// - Any other scheme (`postgres://`, `postgresql://`, a typo) renders
///   `scheme://host[:port]/<database>` — the database name is the last
///   thing an operator needs to tell two stores apart and is not a
///   secret. The query string (`sslpassword=`, `sslkey=`, `options=`,
///   `password=`) and the userinfo are never rendered.
#[must_use]
pub fn store_url_display(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.starts_with(crate::store_url::SQLITE_URL_SCHEME) {
        return trimmed.to_string();
    }
    match reqwest::Url::parse(trimmed) {
        Ok(parsed) => {
            let mut out = url_origin(trimmed);
            // The database is the FIRST path segment; libpq allows nothing
            // deeper, so a longer path is simply not rendered.
            if let Some(db) = parsed
                .path_segments()
                .and_then(|mut s| s.next())
                .filter(|db| !db.is_empty())
            {
                out.push('/');
                out.push_str(db);
            }
            out
        }
        Err(_) => unparseable(trimmed),
    }
}

/// The closed vocabulary a `reqwest::Error` collapses to at the ORIGIN of
/// every transport failure (#3710). Nothing here carries the request URL,
/// the redirect target or the response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    /// The client could not be built (TLS config, proxy, builder).
    Builder,
    /// The request deadline elapsed.
    Timeout,
    /// TCP / TLS connect failed (refused, unreachable, DNS, handshake).
    Connect,
    /// The receiver answered with a non-success status.
    Status(u16),
    /// The response body could not be read.
    Body,
    /// The response body could not be decoded.
    Decode,
    /// The redirect policy refused the hop.
    Redirect,
    /// The request could not be sent for another reason.
    Request,
}

impl TransportFailure {
    /// Classify a `reqwest::Error` without retaining it — the error's
    /// `Display` and its `source` chain both carry the full request URL.
    #[must_use]
    pub fn classify(e: &reqwest::Error) -> Self {
        if e.is_builder() {
            Self::Builder
        } else if e.is_timeout() {
            Self::Timeout
        } else if e.is_connect() {
            Self::Connect
        } else if let Some(status) = e.status() {
            Self::Status(status.as_u16())
        } else if e.is_redirect() {
            Self::Redirect
        } else if e.is_decode() {
            Self::Decode
        } else if e.is_body() {
            Self::Body
        } else {
            Self::Request
        }
    }

    /// The stable token (`timeout`, `connect`, `http_503`, …) — the shape
    /// a DLQ `last_error` classifier or a metric label can match on.
    #[must_use]
    pub fn token(self) -> String {
        match self {
            Self::Builder => "client_build".to_string(),
            Self::Timeout => "timeout".to_string(),
            Self::Connect => "connect".to_string(),
            Self::Status(code) => format!("http_{code}"),
            Self::Body => "body".to_string(),
            Self::Decode => "decode".to_string(),
            Self::Redirect => "redirect".to_string(),
            Self::Request => "request".to_string(),
        }
    }
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token())
    }
}

/// `"network: <class>"` — the ONE rendering of a `reqwest::Error` for a
/// log line, an `anyhow` context or a stored record. Replaces
/// `errors::msg::network(e)` wherever `e` is a `reqwest::Error`: that
/// helper takes any `Display` and so would carry the URL.
#[must_use]
pub fn network_failure(e: &reqwest::Error) -> String {
    crate::errors::msg::network(TransportFailure::classify(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDS: &[&str] = &[
        "alice",
        "s3cr3t",
        "hooktoken",
        "qpw",
        "sslpw",
        "/etc/pg/client.key",
    ];

    fn assert_clean(rendered: &str) {
        for c in CREDS {
            assert!(!rendered.contains(c), "{c:?} leaked into {rendered:?}");
        }
    }

    #[test]
    fn origin_drops_userinfo_path_query_fragment_3711() {
        let r = url_origin("https://alice:s3cr3t@peer.example:9077/services/hooktoken?x=qpw#frag");
        assert_eq!(r, "https://peer.example:9077");
        assert_clean(&r);
        assert_eq!(url_origin("http://127.0.0.1"), "http://127.0.0.1");
        assert_eq!(url_origin("https://[::1]:9077/x"), "https://[::1]:9077");
    }

    #[test]
    fn origin_and_path_keeps_path_only_3675() {
        let r = url_origin_and_path("https://alice:s3cr3t@peer.example:9077/mesh/a?token=qpw");
        assert_eq!(r, "https://peer.example:9077/mesh/a");
        assert_clean(&r);
        assert_eq!(
            url_origin_and_path("https://peer.example:9077/"),
            "https://peer.example:9077"
        );
        assert_eq!(
            url_origin_and_path("https://peer.example:9077"),
            "https://peer.example:9077"
        );
    }

    #[test]
    fn store_url_renders_scheme_host_port_db_only_3711() {
        let dsn = "postgres://alice:s3cr3t@db.example:5433/ai_memory?password=qpw&sslpassword=sslpw&sslkey=/etc/pg/client.key&sslmode=verify-full";
        let r = store_url_display(dsn);
        assert_eq!(r, "postgres://db.example:5433/ai_memory");
        assert_clean(&r);
        assert_eq!(
            store_url_display("postgresql://db.example/ai_memory"),
            "postgresql://db.example/ai_memory"
        );
        assert_eq!(
            store_url_display("postgres://db.example:5432"),
            "postgres://db.example:5432"
        );
    }

    #[test]
    fn sqlite_store_url_is_a_path_and_renders_verbatim_3711() {
        assert_eq!(
            store_url_display("sqlite:///var/lib/ai-memory/x.db"),
            "sqlite:///var/lib/ai-memory/x.db"
        );
    }

    #[test]
    fn unparseable_urls_never_render_their_bytes_3711() {
        for bad in [
            "postgres://alice:s3cr3t@[bad host/x",
            "http://",
            "://alice:s3cr3t@h",
            "not a url s3cr3t",
        ] {
            for f in [url_origin, url_origin_and_path, store_url_display] {
                let r = f(bad);
                assert_clean(&r);
                assert!(
                    r.contains(UNPARSEABLE) || r.contains(NO_HOST) || r.contains(NO_SCHEME),
                    "{r}"
                );
            }
        }
    }

    #[test]
    fn transport_failure_tokens_are_closed_vocabulary_3710() {
        assert_eq!(TransportFailure::Status(503).token(), "http_503");
        assert_eq!(TransportFailure::Timeout.to_string(), "timeout");
        assert_eq!(TransportFailure::Connect.to_string(), "connect");
        assert_eq!(TransportFailure::Builder.to_string(), "client_build");
    }

    #[test]
    fn network_failure_never_carries_the_request_url_3710() {
        // A closed loopback port: the error is a connect failure whose
        // Display names the full request URL, credential included.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("client");
        let err = client
            .get("http://alice:s3cr3t@127.0.0.1:9/hooktoken?token=qpw")
            .send()
            .expect_err("closed port refuses");
        let raw = err.to_string();
        assert!(
            raw.contains("127.0.0.1:9"),
            "precondition: reqwest Display names the URL: {raw}"
        );
        let rendered = network_failure(&err);
        assert_clean(&rendered);
        assert!(!rendered.contains("127.0.0.1"), "{rendered}");
        assert!(rendered.starts_with("network: "), "{rendered}");
        assert!(
            matches!(
                TransportFailure::classify(&err),
                TransportFailure::Connect | TransportFailure::Request
            ),
            "{:?}",
            TransportFailure::classify(&err)
        );
    }
}
