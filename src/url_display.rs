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

/// Rendering of text that has a `://` but whose prefix is not a scheme
/// (#6100). Echoes nothing.
const UNPARSEABLE_STORE_URL: &str = "<unparseable-store-url>";
/// Marker for a store URL whose authority is ambiguous (#6096): the
/// userinfo holds an unencoded `/`, `?` or `#`, so the WHATWG parser ended
/// the authority early and read the credential remainder as host, port or
/// path. Nothing parsed from such a URL is safe to show.
const REDACTED_AUTHORITY: &str = "<redacted-authority>";

/// Longest scheme token [`scheme_token`] will echo.
const MAX_SCHEME_LEN: usize = 32;

/// `true` for an RFC 3986 scheme: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`,
/// bounded to [`MAX_SCHEME_LEN`].
fn is_rfc3986_scheme(token: &str) -> bool {
    let mut chars = token.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && token.len() <= MAX_SCHEME_LEN
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The scheme token of `url` (up to the first `://`), [`NO_SCHEME`] when
/// there is no `://`, or [`UNPARSEABLE_STORE_URL`] when the text before it
/// is not an RFC 3986 scheme (#6100): a libpq key/value DSN with a URL-valued
/// option (`host=db password=... sslrootcert=file://ca`) has its password
/// before the first `://`.
fn scheme_token(url: &str) -> &str {
    match url.trim().split_once("://") {
        None => NO_SCHEME,
        Some((s, _)) if is_rfc3986_scheme(s) => s,
        Some(_) => UNPARSEABLE_STORE_URL,
    }
}

/// The rendering of a URL `reqwest::Url` refused: its scheme token and
/// the [`UNPARSEABLE`] marker, never its bytes.
fn unparseable(url: &str) -> String {
    match scheme_token(url) {
        UNPARSEABLE_STORE_URL => UNPARSEABLE_STORE_URL.to_string(),
        scheme => format!("{scheme}://{UNPARSEABLE}"),
    }
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

/// `true` when `url` PARSES to a URL whose path, query or fragment holds an
/// `@` - the ambiguous-authority shape (#6096).
///
/// An unencoded `/`, `?` or `#` (or `\` on a special scheme) in the userinfo
/// makes the WHATWG parser end the authority inside the credential, so the
/// rest of the credential and the real `@host` land in the path, query or
/// fragment, and the parsed host / port / path are credential bytes. The
/// decision is made on the PARSED value, never on the raw text, because the
/// parser first deletes tab / LF / CR, folds `\`, and accepts `http:` with no
/// slashes: a raw-text scan is bypassed by each (ERRORS-09, one predicate).
/// `@` stays literal in the path, query and fragment encode sets, so the
/// parsed components are a faithful witness. It errs on the side of refusal:
/// a literal `@` in a query value also trips it (percent-encode it), the
/// cost being a less specific log line (ERRORS-01, fail closed).
///
/// Shared by [`store_url_display`] and the transit floor
/// (`transit_encryption::dsn_transport`), so a DSN the renderer redacts is
/// also one the floor refuses before any connection or DNS lookup.
#[must_use]
pub(crate) fn store_url_is_ambiguous(url: &str) -> bool {
    reqwest::Url::parse(url.trim()).is_ok_and(|parsed| {
        parsed.path().contains('@')
            || parsed.query().is_some_and(|q| q.contains('@'))
            || parsed.fragment().is_some_and(|f| f.contains('@'))
    })
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
/// - A URL whose authority is ambiguous (an unencoded `/`, `?` or `#` in the
///   userinfo, #6096) renders `scheme://<redacted-authority>`: the parsed
///   host, port and path of such a URL are credential bytes.
#[must_use]
pub fn store_url_display(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.starts_with(crate::store_url::SQLITE_URL_SCHEME) {
        return trimmed.to_string();
    }
    match reqwest::Url::parse(trimmed) {
        Ok(parsed) => {
            if store_url_is_ambiguous(trimmed) {
                return format!("{}://{REDACTED_AUTHORITY}", parsed.scheme());
            }
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

    /// #6096 — one DSN per (delimiter, position) shape: the unencoded
    /// delimiter sits in the password (leading, numeric-prefixed) or in the
    /// username, so the WHATWG authority ends inside the credential.
    fn ambiguous_userinfo_dsns_6096() -> Vec<String> {
        let mut out = Vec::new();
        for d in ['/', '?', '#'] {
            out.push(format!(
                "postgres://svc:{d}SECRET6096pw@db.example:5432/mem"
            ));
            out.push(format!("postgres://svc:123{d}SECRET6096pw@db.example/mem"));
            out.push(format!("postgres://svc{d}SECRET6096user:pw@db.example/mem"));
        }
        out
    }

    #[test]
    fn store_url_redacts_an_ambiguous_authority_6096() {
        for dsn in ambiguous_userinfo_dsns_6096() {
            let r = store_url_display(&dsn);
            assert!(
                !r.contains("SECRET6096"),
                "#6096: credential bytes reached the rendering of {dsn:?}: {r:?}"
            );
            assert_eq!(r, "postgres://<redacted-authority>", "{dsn:?}");
        }
    }

    #[test]
    fn store_url_keeps_well_formed_shapes_unchanged_6096() {
        // Percent-encoded delimiters in the userinfo are well-formed: the
        // host is still named and the credential is still absent.
        for dsn in [
            "postgres://svc:%2FSECRET6096pw@db.example:5432/mem",
            "postgres://svc:123%3FSECRET6096pw@db.example:5432/mem",
            "postgres://svc%23SECRET6096user:pw@db.example:5432/mem",
            "postgres://svc:SECRET6096pw@db.example:5432/mem?sslmode=verify-full",
        ] {
            let r = store_url_display(dsn);
            assert_eq!(r, "postgres://db.example:5432/mem", "{dsn:?}");
            assert!(!r.contains("SECRET6096"), "{r:?}");
        }
        assert_eq!(
            store_url_display("postgres://db.example/mem?sslmode=verify-full"),
            "postgres://db.example/mem"
        );
        assert_eq!(
            store_url_display("postgres://svc:pw@[::1]:5432/mem"),
            "postgres://[::1]:5432/mem"
        );
    }

    /// #6096 r2 - shapes the parser NORMALISES before the authority ends:
    /// tab / LF / CR inside the scheme separator, secret-before-delimiter
    /// (the parsed host is credential bytes), `\\` and missing slashes on a
    /// special scheme.
    fn normalised_ambiguous_dsns_6096() -> Vec<String> {
        let mk = "SECRETX6096";
        let mut out = vec![
            format!("postgres:\t//svc:a@{mk}/x@db.example/mem?sslmode=verify-full"),
            format!("postgres:/\n/svc:a@{mk}/x@db.example/mem?sslmode=verify-full"),
            format!("postgres:/\r/svc:/{mk}pw@db.example/mem"),
            format!("postgres:/\t/svc:/{mk}pw@db.example/mem"),
            format!("postgres://svc:a@{mk}?x@db.example/mem"),
            format!("postgres://svc:a@{mk}#x@db.example/mem"),
            format!("postgres://{mk}user/x:pw@db.example/mem?sslmode=verify-full"),
            format!("POSTGRES://svc:a@{mk}/x@db.example/mem"),
            format!("postgresql://svc:a@{mk}/x@db.example/mem"),
            format!("https://svc:a@{mk}\\x@db.example/mem"),
            format!("https://svc:\\{mk}@db.example/mem"),
            format!("http:svc:a@{mk}/x@db.example/mem"),
            format!("postgres:/svc:/{mk}pw@db.example/mem"),
        ];
        out.push(format!("  postgres://svc:/{mk}@db.example/mem \n"));
        out
    }

    #[test]
    fn store_url_redacts_normalised_ambiguous_shapes_6096() {
        for dsn in normalised_ambiguous_dsns_6096() {
            let r = store_url_display(&dsn);
            assert!(
                !r.contains("SECRETX6096") && !r.to_ascii_lowercase().contains("secretx6096"),
                "#6096: credential bytes reached the rendering of {dsn:?}: {r:?}"
            );
            assert!(r.ends_with("://<redacted-authority>"), "{dsn:?} -> {r:?}");
            assert!(store_url_is_ambiguous(&dsn), "{dsn:?}");
        }
    }

    #[test]
    fn unparseable_never_echoes_a_non_scheme_prefix_6100() {
        for bad in [
            "host=db password=SECRETX6100 sslrootcert=file://ca",
            "password=SECRETX6100://x",
            "a b://x",
            "1postgres://SECRETX6100",
        ] {
            for f in [url_origin, url_origin_and_path, store_url_display] {
                let r = f(bad);
                assert!(!r.contains("SECRETX6100"), "{bad:?} -> {r:?}");
            }
            assert_eq!(store_url_display(bad), UNPARSEABLE_STORE_URL, "{bad:?}");
        }
        assert_eq!(
            store_url_display("host=db password=SECRETX6100"),
            "<no scheme>://<unparseable>"
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
                    r.contains(UNPARSEABLE)
                        || r.contains(NO_HOST)
                        || r.contains(NO_SCHEME)
                        || r.contains(UNPARSEABLE_STORE_URL),
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
