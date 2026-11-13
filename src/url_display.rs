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

/// The rendering of an ambiguous-authority URL (#6096 #6101): its scheme and
/// [`REDACTED_AUTHORITY`], nothing parsed from the authority.
fn redacted_authority(parsed: &reqwest::Url) -> String {
    format!("{}://{REDACTED_AUTHORITY}", parsed.scheme())
}

/// `scheme://host[:port]` of an already-parsed URL that is NOT ambiguous.
fn origin_of(parsed: &reqwest::Url) -> String {
    let host = parsed.host_str().unwrap_or(NO_HOST);
    match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    }
}

/// `true` when the PARSED path, query or fragment holds an `@` - the
/// ambiguous-authority witness (#6096 #6101). The ONE predicate every
/// renderer and the durable-key guard share (ERRORS-09).
///
/// An unencoded `/`, `?` or `#` (or `\` on a special scheme) in the
/// userinfo makes the WHATWG parser end the authority inside the credential,
/// so the rest of the credential and the real `@host` land in the path,
/// query or fragment, and the parsed host / port / path are credential
/// bytes. The decision is made on the PARSED value, never on the raw text,
/// because the parser first deletes tab / LF / CR, folds `\`, and accepts
/// `http:` with no slashes: a raw-text scan is bypassed by each. `@` stays
/// literal in the path, query and fragment encode sets, so the parsed
/// components are a faithful witness. It errs on the side of refusal: a
/// literal `@` in a query value also trips it (percent-encode it as `%40`),
/// the cost being a less specific line (ERRORS-01, fail closed).
fn at_after_authority(parsed: &reqwest::Url) -> bool {
    parsed.path().contains('@')
        || parsed.query().is_some_and(|q| q.contains('@'))
        || parsed.fragment().is_some_and(|f| f.contains('@'))
}

/// `scheme://host[:port]` — the origin of `url` and nothing else. No
/// userinfo, no path, no query, no fragment.
///
/// Use it for a federation peer, a webhook target, an LLM / embedder base
/// URL, an MCP forward URL — any URL that reaches a log line, a refusal,
/// a doctor fact or a stored record. An ambiguous authority (#6101, an
/// unencoded `/`, `?` or `#` in the userinfo) renders
/// `scheme://<redacted-authority>`: its parsed host is credential bytes.
#[must_use]
pub fn url_origin(url: &str) -> String {
    let trimmed = url.trim();
    match reqwest::Url::parse(trimmed) {
        Ok(parsed) if at_after_authority(&parsed) => redacted_authority(&parsed),
        Ok(parsed) => origin_of(&parsed),
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
///
/// An ambiguous authority (#6101) renders `scheme://<redacted-authority>`:
/// the parsed path of such a URL carries the password. That rendering is
/// shared by every ambiguous URL of one scheme, so it is NOT a unique key:
/// a durable-key writer checks [`durable_key_refusal`] first.
#[must_use]
pub fn url_origin_and_path(url: &str) -> String {
    let trimmed = url.trim();
    match reqwest::Url::parse(trimmed) {
        Ok(parsed) if at_after_authority(&parsed) => redacted_authority(&parsed),
        Ok(parsed) => {
            let mut out = origin_of(&parsed);
            let path = parsed.path();
            if path != "/" {
                out.push_str(path);
            }
            out
        }
        Err(_) => unparseable(trimmed),
    }
}

/// Why [`url_origin_and_path`] of a peer URL is NOT a durable sync key
/// (#6101 #6628). Each variant names its own remedy, so the refusal never
/// gives advice that does not apply to the URL in hand (ERRORS-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableKeyRefusal {
    /// The URL does not parse: it renders `scheme://<unparseable>`.
    Unparseable,
    /// The URL parses, but its authority is ambiguous (an `@` in the parsed
    /// path, query or fragment): it renders `scheme://<redacted-authority>`.
    AmbiguousAuthority,
}

/// Renders [`DurableKeyRefusal::reason`].
impl fmt::Display for DurableKeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl DurableKeyRefusal {
    /// The operator-facing remedy for this refusal.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unparseable => {
                "the peer URL does not parse; write it as scheme://host[:port][/path]"
            }
            Self::AmbiguousAuthority => {
                "its authority is ambiguous; percent-encode each '/', '?', '#' or '@' inside the userinfo, path or query (a literal '@' as %40)"
            }
        }
    }
}

/// `None` when [`url_origin_and_path`] of `url` names ONE peer: the URL
/// parses and its authority is not ambiguous (#6101 #6628); otherwise the
/// [`DurableKeyRefusal`]. The redacted and unparseable renderings are shared
/// by many URLs, so two such peers would share one `sync_state` cursor row;
/// the sync cycle refuses them instead.
#[must_use]
pub fn durable_key_refusal(url: &str) -> Option<DurableKeyRefusal> {
    match reqwest::Url::parse(url.trim()) {
        Err(_) => Some(DurableKeyRefusal::Unparseable),
        Ok(parsed) if at_after_authority(&parsed) => Some(DurableKeyRefusal::AmbiguousAuthority),
        Ok(_) => None,
    }
}

/// `true` when [`durable_key_refusal`] of `url` is `None`.
#[must_use]
pub fn origin_and_path_is_durable_key(url: &str) -> bool {
    durable_key_refusal(url).is_none()
}

/// `true` when `value` starts with an RFC 3986 `scheme:` and holds an `@`
/// after it: the userinfo shape `scheme:user:pw@host` (#6102, LOW-3 of the
/// #9173 review). Any scheme qualifies, known or not, so an unknown or
/// slashless scheme (`ftp:svc:pw@h`, `gopher:...`) is still URL-shaped and
/// renders through the funnel (ERRORS-01, fail closed on an unclassified
/// form). Leading and trailing C0 controls and spaces are trimmed and tab,
/// LF and CR are dropped, as the WHATWG parser does before it reads the
/// scheme. One linear pass over `value`.
#[must_use]
pub(crate) fn has_scheme_and_userinfo(value: &str) -> bool {
    let folded: String = value
        .trim_matches(|c: char| c.is_whitespace() || c.is_ascii_control())
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    folded.split_once(':').is_some_and(|(scheme, rest)| {
        is_rfc3986_scheme(scheme)
            && rest
                .split_once('@')
                .is_some_and(|(userinfo, host)| !is_agent_id_form(scheme, userinfo, host))
    })
}

/// The scheme token of the product's agent-id form `ai:<name>@<host>`.
const AGENT_ID_SCHEME: &str = "ai";

/// `true` for the agent-id form `ai:<name>@<host>` (scheme [`AGENT_ID_SCHEME`],
/// any case): a public identity, not a URL. A `:`, `/`, `?` or `#` in the
/// name, or a second `@`, is a userinfo credential shape and is NOT exempt.
fn is_agent_id_form(scheme: &str, userinfo: &str, host: &str) -> bool {
    scheme.eq_ignore_ascii_case(AGENT_ID_SCHEME)
        && !userinfo.contains([':', '/', '?', '#'])
        && !host.contains('@')
}

/// `true` when `url` PARSES to a URL whose path, query or fragment holds an
/// `@` - the ambiguous-authority shape (#6096), decided by
/// [`at_after_authority`].
///
/// Shared by [`store_url_display`] and the transit floor
/// (`transit_encryption::dsn_transport`), so a DSN the renderer redacts is
/// also one the floor refuses before any connection or DNS lookup.
#[must_use]
pub(crate) fn store_url_is_ambiguous(url: &str) -> bool {
    reqwest::Url::parse(url.trim()).is_ok_and(|parsed| at_after_authority(&parsed))
}

/// The text after a `sqlite://` prefix, matched case-insensitively (RFC 3986
/// section 3.1: the scheme is case-insensitive, #6107), or `None` when `url`
/// is not a sqlite URL. `get` keeps the slice on a char boundary
/// (OWNERSHIP-15): a multi-byte char inside the prefix window is a `None`.
#[must_use]
pub fn strip_sqlite_scheme(url: &str) -> Option<&str> {
    let prefix = crate::store_url::SQLITE_URL_SCHEME;
    url.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .and_then(|_| url.get(prefix.len()..))
}

/// Characters that make a sqlite path or a schemeless db value a possible
/// credential carrier: `@` (a userinfo `user:pw@host`, #6107) and `=` (a
/// libpq key/value DSN `host=.. password=..`, #6102 #6106). A real path may
/// hold either; it then renders redacted, never verbatim (ERRORS-01).
const CREDENTIAL_DELIMITERS: [char; 2] = ['@', '='];

/// `sqlite://<path>` for the text after the scheme: the path up to the first
/// `?` / `#` (a query or fragment is not part of the file name), or
/// `sqlite://<redacted-authority>` when the path holds a
/// [`CREDENTIAL_DELIMITERS`] char (#6107: `sqlite://svc:pw@x/db`).
fn sqlite_store_display(rest: &str) -> String {
    if rest.contains(CREDENTIAL_DELIMITERS) {
        return format!("sqlite://{REDACTED_AUTHORITY}");
    }
    let path = rest.split(['?', '#']).next().unwrap_or_default();
    format!("sqlite://{path}")
}

/// Rendering of a db path whose text could carry a credential (#6106): a
/// schemeless value holding a [`CREDENTIAL_DELIMITERS`] char. The marker
/// states WHY the path is hidden, so an operator whose real path holds an
/// `@` or `=` is told what to rename (F6 of the #9173 review).
const REDACTED_DB_PATH: &str = "<redacted-db-path: '@' or '=' may delimit a credential>";

/// A database PATH (`--db`, `AI_MEMORY_DB`, config `db =`) for every
/// human- and machine-readable sink: doctor `source:` and notes, the open
/// error, the boot `info!` line, governance and audit refusals (#6106).
///
/// - Text holding `://` is a URL and renders through [`store_url_display`].
/// - Schemeless text holding `@` or `=` renders [`REDACTED_DB_PATH`]: a
///   libpq key/value DSN (`host=db password=..`) or a `user:pw@host` value
///   has no scheme to parse, so nothing of it is shown (ERRORS-01). A real
///   file path cannot be told apart from such a DSN by its text, so it is
///   redacted too, and the marker names the two characters as the reason.
/// - Any other path renders as written: a file path is not a credential.
#[must_use]
pub fn db_path_display(path: &std::path::Path) -> String {
    let text = path.to_string_lossy();
    if text.contains("://") {
        return store_url_display(&text);
    }
    if text.contains(CREDENTIAL_DELIMITERS) {
        return REDACTED_DB_PATH.to_string();
    }
    text.into_owned()
}

/// A store URL (`--store-url`, `AI_MEMORY_STORE_URL[_FILE]`) for every
/// human- and machine-readable sink: the boot `info!` line, doctor,
/// `schema-init --json`, `migrate --json`, refusals.
///
/// - `sqlite://<path>` (any scheme case, #6107) renders the path: the path IS
///   the database file. A path holding `@` or `=` renders
///   `sqlite://<redacted-authority>`: `sqlite://svc:pw@host/db` is a
///   credential written behind the wrong scheme, not a file name.
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
    if let Some(rest) = strip_sqlite_scheme(trimmed) {
        return sqlite_store_display(rest);
    }
    match reqwest::Url::parse(trimmed) {
        Ok(parsed) if at_after_authority(&parsed) => redacted_authority(&parsed),
        Ok(parsed) => {
            let mut out = origin_of(&parsed);
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

    // ---- #8741 credential-display class: the funnel corpus (#6101 #6107) ----

    /// The credential marker every corpus shape carries (a fake placeholder).
    const MARKER_8741: &str = "SECRETX8741";
    /// The rendering every ambiguous-authority http(s) URL collapses to.
    const REDACTED_HTTPS: &str = "https://<redacted-authority>";
    /// The rendering every credential-bearing sqlite URL collapses to.
    const REDACTED_SQLITE: &str = "sqlite://<redacted-authority>";
    /// Size of the oversized-input cells (OWNERSHIP-15, PERF: linear scan).
    const HUGE_INPUT_LEN: usize = 120_000;
    /// Wall-clock ceiling for rendering every oversized cell
    /// [`HUGE_ITERATIONS`] times: linear work is well under a second.
    const HUGE_INPUT_CEILING: std::time::Duration = std::time::Duration::from_secs(5);
    /// Repetitions of each oversized cell under [`HUGE_INPUT_CEILING`].
    const HUGE_ITERATIONS: usize = 20;

    fn assert_no_marker(input: &str, rendered: &str) {
        assert!(
            !rendered
                .to_ascii_lowercase()
                .contains(&MARKER_8741.to_ascii_lowercase()),
            "credential bytes of {input:?} reached the rendering {rendered:?}"
        );
    }

    /// #6101 — federation / webhook / LLM base URLs whose userinfo holds an
    /// unencoded `/`, `?`, `#` or `\`: the WHATWG authority ends inside the
    /// credential. Every one renders exactly [`REDACTED_HTTPS`] through BOTH
    /// `url_origin` and `url_origin_and_path`, in every scheme case.
    fn ambiguous_http_urls_6101() -> Vec<String> {
        let m = MARKER_8741;
        vec![
            format!("https://localhost:/{m}pw@127.0.0.1:9/v1"),
            format!("https://svc:/{m}@peer.example:9077/mesh"),
            format!("https://svc:123/{m}@peer.example/mesh"),
            format!("https://svc/{m}user:pw@peer.example/mesh"),
            format!("https://svc:a@{m}/x@peer.example/mesh"),
            format!("https://svc:a@{m}?x@peer.example/mesh"),
            format!("https://svc:a@{m}#x@peer.example/mesh"),
            format!("https://svc:a@{m}\\x@peer.example/mesh"),
            format!("HTTPS://svc:a@{m}/x@peer.example/mesh"),
            format!("Https://svc:/{m}@peer.example/mesh"),
            format!("https:\t//svc:a@{m}/x@peer.example/mesh"),
            format!("https:svc:a@{m}/x@peer.example/mesh"),
            format!("  https://svc:/{m}@peer.example/mesh \n"),
        ]
    }

    #[test]
    fn url_origin_redacts_an_ambiguous_authority_6101() {
        for url in ambiguous_http_urls_6101() {
            let r = url_origin(&url);
            assert_no_marker(&url, &r);
            assert_eq!(r, REDACTED_HTTPS, "#6101 url_origin({url:?})");
        }
    }

    #[test]
    fn url_origin_and_path_redacts_an_ambiguous_authority_6101() {
        for url in ambiguous_http_urls_6101() {
            let r = url_origin_and_path(&url);
            assert_no_marker(&url, &r);
            assert_eq!(r, REDACTED_HTTPS, "#6101 url_origin_and_path({url:?})");
        }
    }

    /// Well-formed userinfo shapes per RFC 3986 / WHATWG: an unencoded `@`
    /// or `:` inside the password (the LAST `@` ends the userinfo) and every
    /// percent-encoded delimiter keep the real host, and the credential is
    /// still absent. `(input, url_origin, url_origin_and_path)`.
    fn well_formed_userinfo_cells_6101() -> Vec<(String, &'static str, &'static str)> {
        let m = MARKER_8741;
        vec![
            (
                format!("https://svc:a@{m}@peer.example:9077/mesh"),
                "https://peer.example:9077",
                "https://peer.example:9077/mesh",
            ),
            (
                format!("https://svc:a:{m}@peer.example/mesh"),
                "https://peer.example",
                "https://peer.example/mesh",
            ),
            (
                format!("https://svc:%2F{m}@peer.example/mesh"),
                "https://peer.example",
                "https://peer.example/mesh",
            ),
            (
                format!("https://svc:%3F{m}%23@peer.example/mesh"),
                "https://peer.example",
                "https://peer.example/mesh",
            ),
            (
                format!("https://svc:%40{m}@peer.example/"),
                "https://peer.example",
                "https://peer.example",
            ),
            (
                format!("HTTP://svc:{m}@Peer.Example:8080/a/b?token={m}#{m}"),
                "http://peer.example:8080",
                "http://peer.example:8080/a/b",
            ),
        ]
    }

    #[test]
    fn well_formed_userinfo_keeps_the_real_host_6101() {
        for (url, origin, origin_and_path) in well_formed_userinfo_cells_6101() {
            let o = url_origin(&url);
            let op = url_origin_and_path(&url);
            assert_no_marker(&url, &o);
            assert_no_marker(&url, &op);
            assert_eq!(o, origin, "url_origin({url:?})");
            assert_eq!(op, origin_and_path, "url_origin_and_path({url:?})");
        }
    }

    /// #6107 — a credential written behind `sqlite://` (any scheme case)
    /// renders [`REDACTED_SQLITE`]; a plain path renders as the path only.
    /// `(input, store_url_display)`.
    fn sqlite_cells_6107() -> Vec<(String, String)> {
        let m = MARKER_8741;
        vec![
            (format!("sqlite://svc:{m}@x/db"), REDACTED_SQLITE.into()),
            (format!("SQLITE://svc:{m}@x/db"), REDACTED_SQLITE.into()),
            (format!("Sqlite://svc:{m}@x/db"), REDACTED_SQLITE.into()),
            (
                format!("sqlite://{m}@lba-missing-dir/sub/x.db"),
                REDACTED_SQLITE.into(),
            ),
            (format!("sqlite://svc:/{m}@x/db"), REDACTED_SQLITE.into()),
            (
                format!("sqlite:///var/x.db?key={m}"),
                REDACTED_SQLITE.into(),
            ),
            (
                format!("sqlite:///var/x.db?password={m}"),
                REDACTED_SQLITE.into(),
            ),
            (format!("  SQLITE://svc:{m}@x/db\n"), REDACTED_SQLITE.into()),
            (
                "sqlite:///var/lib/ai-memory/x.db".into(),
                "sqlite:///var/lib/ai-memory/x.db".into(),
            ),
            (
                "SQLITE:///var/lib/ai-memory/x.db".into(),
                "sqlite:///var/lib/ai-memory/x.db".into(),
            ),
            (
                "sqlite:///var/x.db#frag".into(),
                "sqlite:///var/x.db".into(),
            ),
            ("sqlite:///var/x.db?mode=ro".into(), REDACTED_SQLITE.into()),
            (
                "sqlite://relative/x.db".into(),
                "sqlite://relative/x.db".into(),
            ),
        ]
    }

    #[test]
    fn store_url_sqlite_branch_is_case_insensitive_and_fail_closed_6107() {
        for (url, want) in sqlite_cells_6107() {
            let r = store_url_display(&url);
            assert_no_marker(&url, &r);
            assert_eq!(r, want, "#6107 store_url_display({url:?})");
        }
    }

    /// Postgres store URLs in every scheme case keep scheme/host/port/db and
    /// drop the userinfo and query; an ambiguous one is redacted (#6102).
    #[test]
    fn store_url_postgres_scheme_case_variants_6102() {
        let m = MARKER_8741;
        for (url, want) in [
            (
                format!("POSTGRES://svc:{m}@db.example:5433/mem?password={m}"),
                "postgres://db.example:5433/mem",
            ),
            (
                format!("PostgreSQL://svc:{m}@db.example/mem"),
                "postgresql://db.example/mem",
            ),
            (
                format!("postgres://svc:{m}@db.example/mem?sslpassword={m}"),
                "postgres://db.example/mem",
            ),
            (
                format!("POSTGRES://svc:/{m}pw@db.example/mem"),
                "postgres://<redacted-authority>",
            ),
            (
                format!("postgres:svc:{m}@db.example/mem"),
                "postgres://<redacted-authority>",
            ),
        ] {
            let r = store_url_display(&url);
            assert_no_marker(&url, &r);
            assert_eq!(r, want, "store_url_display({url:?})");
        }
    }

    /// Oversized inputs render in linear time and still fail closed: a
    /// 120K-char ambiguous userinfo, a 120K-char sqlite credential, and a
    /// 120K run of multi-byte chars around the scheme window (OWNERSHIP-15:
    /// no slice may split a char).
    #[test]
    fn oversized_inputs_are_bounded_and_fail_closed_8741() {
        let pad = "/".repeat(HUGE_INPUT_LEN);
        let ambiguous = format!("https://svc:{pad}{MARKER_8741}@peer.example/mesh");
        let sqlite = format!(
            "SQLITE://svc:{}{MARKER_8741}@x/db",
            "a".repeat(HUGE_INPUT_LEN)
        );
        let multibyte = format!("sqli{}://{MARKER_8741}@x", "\u{e9}".repeat(HUGE_INPUT_LEN));
        let started = std::time::Instant::now();
        for _ in 0..HUGE_ITERATIONS {
            assert_eq!(url_origin(&ambiguous), REDACTED_HTTPS);
            assert_eq!(url_origin_and_path(&ambiguous), REDACTED_HTTPS);
            assert_eq!(store_url_display(&sqlite), REDACTED_SQLITE);
            let r = store_url_display(&multibyte);
            assert_no_marker("<multibyte>", &r);
            assert_eq!(r, UNPARSEABLE_STORE_URL);
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < HUGE_INPUT_CEILING,
            "oversized rendering took {elapsed:?} (ceiling {HUGE_INPUT_CEILING:?})"
        );
    }

    /// #6101 — the redacted rendering keeps the parsed (lower-cased) scheme,
    /// so an `http://` base URL collapses to `http://<redacted-authority>`.
    #[test]
    fn ambiguous_http_scheme_keeps_its_scheme_6101() {
        let url = format!("HTTP://localhost:/{MARKER_8741}pw@127.0.0.1:9/v1");
        for r in [url_origin(&url), url_origin_and_path(&url)] {
            assert_no_marker(&url, &r);
            assert_eq!(r, "http://<redacted-authority>");
        }
    }

    /// #6101 — a durable `sync_state` key exists only for a URL that parses
    /// and is not ambiguous; every redacted or unparseable shape is refused.
    #[test]
    fn durable_key_only_for_an_unambiguous_parse_6101() {
        for url in ambiguous_http_urls_6101() {
            assert!(
                !origin_and_path_is_durable_key(&url),
                "{url:?} must be refused"
            );
        }
        for url in ["not a url", "", "://x", "http://[::1"] {
            assert!(
                !origin_and_path_is_durable_key(url),
                "{url:?} must be refused"
            );
        }
        for (url, _, _) in well_formed_userinfo_cells_6101() {
            assert!(
                origin_and_path_is_durable_key(&url),
                "{url:?} is a durable key"
            );
        }
        assert!(origin_and_path_is_durable_key(
            "https://peer.example:9077/mesh"
        ));
    }

    /// #6107 — the sqlite prefix matches in any case and never splits a char.
    #[test]
    fn strip_sqlite_scheme_is_case_insensitive_and_char_safe_6107() {
        for (url, want) in [
            ("sqlite:///x.db", Some("/x.db")),
            ("SQLITE:///x.db", Some("/x.db")),
            ("SqLiTe://rel.db", Some("rel.db")),
            ("sqlite://", Some("")),
            ("sqlite:/x.db", None),
            ("postgres://h/db", None),
            ("sqlit", None),
            ("", None),
            ("sqli\u{e9}e://x", None),
            ("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}://x", None),
        ] {
            assert_eq!(
                strip_sqlite_scheme(url),
                want,
                "strip_sqlite_scheme({url:?})"
            );
        }
    }

    /// #6106 — every db PATH shape renders through one funnel: a URL through
    /// `store_url_display`, a schemeless value holding `@` / `=` as
    /// [`REDACTED_DB_PATH`], a plain path as written. `(input, rendering)`.
    fn db_path_cells_6106() -> Vec<(String, String)> {
        let m = MARKER_8741;
        vec![
            (
                format!("postgres://svc:{m}@db.example:5433/mem"),
                "postgres://db.example:5433/mem".into(),
            ),
            (
                format!("POSTGRES://svc:/{m}pw@db.example/mem"),
                "postgres://<redacted-authority>".into(),
            ),
            (format!("SQLITE://svc:{m}@x/db"), REDACTED_SQLITE.into()),
            (
                format!("postgres:/svc:{m}@db.example/mem"),
                REDACTED_DB_PATH.into(),
            ),
            (
                format!("postgres:svc:{m}@db.example/mem"),
                REDACTED_DB_PATH.into(),
            ),
            (
                format!("host=db.example password={m} dbname=mem"),
                REDACTED_DB_PATH.into(),
            ),
            (format!("svc:{m}@db.example/mem"), REDACTED_DB_PATH.into()),
            (
                format!("/var/lib/{m}=x/ai-memory.db"),
                REDACTED_DB_PATH.into(),
            ),
            (
                "/var/lib/ai-memory/ai-memory.db".into(),
                "/var/lib/ai-memory/ai-memory.db".into(),
            ),
            ("relative/x.db".into(), "relative/x.db".into()),
            (":memory:".into(), ":memory:".into()),
        ]
    }

    #[test]
    fn db_path_display_routes_every_shape_through_the_funnel_6106() {
        for (value, want) in db_path_cells_6106() {
            let r = db_path_display(std::path::Path::new(&value));
            assert_no_marker(&value, &r);
            assert_eq!(r, want, "#6106 db_path_display({value:?})");
        }
        let huge = format!("{}{MARKER_8741}@h", "a".repeat(HUGE_INPUT_LEN));
        let started = std::time::Instant::now();
        for _ in 0..HUGE_ITERATIONS {
            assert_eq!(
                db_path_display(std::path::Path::new(&huge)),
                REDACTED_DB_PATH
            );
        }
        assert!(started.elapsed() < HUGE_INPUT_CEILING);
    }

    /// Code F6 (#6106): the db-path marker states WHY the path is not shown,
    /// and a real path holding '@' or '=' gets exactly that text.
    #[test]
    fn redacted_db_path_marker_states_its_reason_6106() {
        assert_eq!(
            REDACTED_DB_PATH,
            "<redacted-db-path: '@' or '=' may delimit a credential>"
        );
        for path in ["/home/a@b/mem.db", "/srv/k=v/mem.db"] {
            assert_eq!(
                db_path_display(std::path::Path::new(path)),
                REDACTED_DB_PATH,
                "{path}"
            );
        }
    }

    /// Code F4 (#6101): each refusal names its own remedy; the `%40` advice
    /// is given only for an ambiguous authority.
    #[test]
    fn durable_key_refusal_names_the_cause_exactly_6101() {
        const UNPARSEABLE: &str =
            "the peer URL does not parse; write it as scheme://host[:port][/path]";
        const AMBIGUOUS: &str = "its authority is ambiguous; percent-encode each '/', '?', '#' or \
                                 '@' inside the userinfo, path or query (a literal '@' as %40)";
        for (url, want) in [
            (
                "http://[::1",
                Some((DurableKeyRefusal::Unparseable, UNPARSEABLE)),
            ),
            (
                "not a url",
                Some((DurableKeyRefusal::Unparseable, UNPARSEABLE)),
            ),
            (
                "http://svc:/pw@127.0.0.1:9/mesh",
                Some((DurableKeyRefusal::AmbiguousAuthority, AMBIGUOUS)),
            ),
            ("https://peer.example:9077/mesh", None),
            ("https://svc:pw@peer.example/mesh", None),
        ] {
            let got = durable_key_refusal(url);
            assert_eq!(got, want.map(|(r, _)| r), "{url}");
            if let Some((refusal, text)) = want {
                assert_eq!(refusal.reason(), text, "{url}");
                assert_eq!(refusal.to_string(), text, "{url}");
            }
            assert_eq!(origin_and_path_is_durable_key(url), want.is_none(), "{url}");
        }
        assert!(!DurableKeyRefusal::Unparseable.reason().contains("%40"));
    }

    /// Security LOW-3 (#6102): `scheme:` + userinfo of ANY RFC 3986 scheme is
    /// URL-shaped. Generative over schemes, case, control bytes and shapes.
    #[test]
    fn has_scheme_and_userinfo_is_scheme_agnostic_6102() {
        const SCHEMES: &[&str] = &[
            "http", "HTTPS", "ftp", "Gopher", "ldap", "x-vendor", "a+b.c-d", "z", "AI",
        ];
        const SHAPES: &[&str] = &["svc:pw@h", "/svc:pw@h/x", "a@b/c@h", "svc:pw@h:1?q#f"];
        for scheme in SCHEMES {
            for shape in SHAPES {
                for wrap in ["", " ", "\u{1}", "\t"] {
                    let value = format!("{wrap}{scheme}:{shape}{wrap}");
                    assert!(has_scheme_and_userinfo(&value), "{value:?}");
                }
                // A tab, CR or LF inside the scheme is dropped by the WHATWG
                // parser, so it is dropped here too.
                let split = format!("{}\r\n{}:{shape}", &scheme[..1], &scheme[1..]);
                assert!(has_scheme_and_userinfo(&split), "{split:?}");
            }
        }
        for value in [
            "ai:claude@host-1",
            "AI:node.f2@host",
            "llama3:8b",
            "C:\\path\\mem.db",
            "no-at:here",
            "1http:svc:pw@h",
            "plain@text",
            "",
        ] {
            assert!(!has_scheme_and_userinfo(value), "{value:?}");
        }
        // The agent-id exemption refuses a userinfo that could hold a password.
        assert!(has_scheme_and_userinfo("ai:svc:pw@h"));
        assert!(has_scheme_and_userinfo("ai:a@b@h"));
    }

    #[test]
    fn has_scheme_and_userinfo_is_linear_on_huge_input_6102() {
        let huge_scheme = format!("{}:svc:pw@h", "a".repeat(HUGE_INPUT_LEN));
        let huge_rest = format!("http:{}@h", "b".repeat(HUGE_INPUT_LEN));
        let no_at = format!("http:{}", ":".repeat(HUGE_INPUT_LEN));
        let started = std::time::Instant::now();
        for _ in 0..HUGE_ITERATIONS {
            assert!(
                !has_scheme_and_userinfo(&huge_scheme),
                "over MAX_SCHEME_LEN"
            );
            assert!(has_scheme_and_userinfo(&huge_rest));
            assert!(!has_scheme_and_userinfo(&no_at));
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < HUGE_INPUT_CEILING,
            "took {elapsed:?} (ceiling {HUGE_INPUT_CEILING:?})"
        );
    }
}
