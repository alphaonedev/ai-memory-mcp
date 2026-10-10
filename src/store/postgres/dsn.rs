// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3674 — the ONE funnel a store DSN crosses on its way into sqlx.
//!
//! # The defect this closes
//!
//! `sqlx-postgres` 0.8.6 `PgConnectOptions::parse_from_url` ends its
//! query-parameter match with
//!
//! ```text
//! _ => tracing::warn!(%key, %value, "ignoring unrecognized connect parameter"),
//! ```
//!
//! so every query parameter it does not recognise is written to our tracing
//! subscriber, VALUE INCLUDED, at `warn`. It matches keys case-sensitively
//! and treats only `password` as a credential, so a libpq-style
//! `?sslpassword=…`, a `?PASSWORD=…`, a pasted `?token=…`, or a bare `?<secret>`
//! lands in the log sink verbatim. The line is emitted INSIDE the dependency,
//! so redacting our own rendering of the URL cannot help: by the time we could
//! redact, the value has been written. It was latent while the default filter
//! was `ai_memory=info`; #3650 made the default a bare `info` over every
//! target, which turned it into a default-on credential leak on every
//! postgres node (the regression #3674 names).
//!
//! # The control
//!
//! [`connect_options`] removes every query parameter sqlx would NOT honour
//! BEFORE sqlx parses the DSN. A parameter sqlx never sees cannot be logged
//! by it, at any level, under any filter, now or after a future widening.
//! Nothing is lost by the removal: sqlx ignores exactly these parameters
//! anyway, so the connection sqlx builds is the one it would have built from
//! the raw DSN. When nothing needs removing the DSN is handed over unchanged.
//!
//! What we log about a removal is the count and the 1-based positions of the
//! removed parameters — never a key or a value. A key is not safe to render:
//! a bare `?<token>` parses as a KEY with an empty value.
//!
//! Every production sqlx connect goes through here; the inventory is pinned by
//! `tests/pg_dsn_screen_3674.rs`, so a new raw `.connect(url)` fails CI.

use std::borrow::Cow;
use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgSslMode};

use crate::transit_encryption::SslmodeFloor;

/// Tracing target for this funnel's own events.
const TRACE_TARGET: &str = "store::postgres::dsn";

/// The query keys `sqlx-postgres` 0.8.6 `PgConnectOptions::parse_from_url`
/// honours, byte-for-byte and case-sensitively (its explicit match arms).
///
/// A key missing from this list is REMOVED before sqlx sees the DSN (a
/// connection-feature loss, never a leak). A key on this list that the linked
/// sqlx does NOT honour would reach sqlx's catch-all `warn!` with its value,
/// so `tests/pg_dsn_screen_3674.rs` asserts every entry is recognised by the
/// linked sqlx; a sqlx upgrade that drops a key fails that test.
pub const SQLX_RECOGNISED_QUERY_KEYS: &[&str] = &[
    "sslmode",
    "ssl-mode",
    "sslrootcert",
    "ssl-root-cert",
    "ssl-ca",
    "sslcert",
    "ssl-cert",
    "sslkey",
    "ssl-key",
    "statement-cache-capacity",
    "host",
    "hostaddr",
    "port",
    "dbname",
    "user",
    "password",
    "application_name",
    "options",
];

/// sqlx's `options[<name>]=<value>` map form (`k.starts_with("options[")`
/// arm): honoured, never logged.
pub const SQLX_OPTIONS_MAP_KEY_PREFIX: &str = "options[";

/// True when sqlx 0.8.6 would honour `key` rather than log it.
#[must_use]
pub fn is_recognised_query_key(key: &str) -> bool {
    SQLX_RECOGNISED_QUERY_KEYS.contains(&key) || key.starts_with(SQLX_OPTIONS_MAP_KEY_PREFIX)
}

/// The result of [`screen_dsn`]: the DSN to hand to sqlx and what was removed.
#[derive(Debug)]
pub struct ScreenedDsn<'a> {
    /// The DSN sqlx may parse. Borrowed (byte-identical) when nothing was
    /// removed.
    pub dsn: Cow<'a, str>,
    /// 1-based positions, in query order, of the removed parameters.
    pub removed_positions: Vec<usize>,
}

/// Remove every query parameter sqlx would not honour. PURE: no logging, no
/// I/O.
///
/// Keys and values are compared after the same `application/x-www-form-urlencoded`
/// decoding sqlx applies (`Url::query_pairs`), so a percent-encoded key cannot
/// slip past. The rebuilt query re-encodes the kept pairs, which sqlx decodes
/// back to the same `(key, value)` pairs; scheme, userinfo, host, port, path
/// and fragment are untouched.
///
/// A DSN that does not parse as a URL is returned unchanged: sqlx parses it
/// with the same `url` crate, fails the same way, and never reaches its
/// query-parameter loop.
#[must_use]
pub fn screen_dsn(dsn: &str) -> ScreenedDsn<'_> {
    let unchanged = || ScreenedDsn {
        dsn: Cow::Borrowed(dsn),
        removed_positions: Vec::new(),
    };
    // `reqwest::Url` is the `url` crate's `Url`, the type sqlx parses with.
    let Ok(mut url) = reqwest::Url::parse(dsn) else {
        return unchanged();
    };
    let mut kept: Vec<(String, String)> = Vec::new();
    let mut removed_positions = Vec::new();
    for (index, (key, value)) in url.query_pairs().enumerate() {
        if is_recognised_query_key(&key) {
            kept.push((key.into_owned(), value.into_owned()));
        } else {
            removed_positions.push(index.saturating_add(1));
        }
    }
    if removed_positions.is_empty() {
        return unchanged();
    }
    if kept.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(kept);
    }
    ScreenedDsn {
        dsn: Cow::Owned(url.into()),
        removed_positions,
    }
}

/// Parse a store DSN into sqlx connect options, removing every query
/// parameter sqlx would log instead of honour (see the module docs).
///
/// This is the only place production code turns a DSN string into
/// [`PgConnectOptions`]; connect with `connect_with(&options)`, never
/// `connect(url)`.
///
/// # Errors
///
/// sqlx's own parse error for a malformed DSN. Its `Display` can interpolate
/// the connection target, so callers never render it; [`evaluate`] drops it
/// and renders only `url_display::store_url_display` (#4934).
pub fn connect_options(dsn: &str) -> Result<PgConnectOptions, sqlx::Error> {
    let screened = screen_dsn(dsn);
    if !screened.removed_positions.is_empty() {
        tracing::warn!(
            target: TRACE_TARGET,
            removed = screened.removed_positions.len(),
            positions = ?screened.removed_positions,
            "removed store-URL query parameters the postgres driver does not \
             honour; it ignores them, and logging them could expose a credential, \
             so names and values are not shown (#3674). recognised parameters: \
             sslmode, sslrootcert, sslcert, sslkey, statement-cache-capacity, \
             host, hostaddr, port, dbname, user, password, application_name, \
             options, options[<name>]"
        );
    }
    PgConnectOptions::from_str(&screened.dsn)
}

/// Why [`floored_connect_options`] produced no options.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlooredConnectError {
    /// The DSN is below the #3705 transit-encryption floor. Carries the typed
    /// verdict (never [`SslmodeFloor::Pinned`]); `Display` renders the
    /// operator-facing refusal, which never echoes the DSN. No socket was
    /// opened.
    Refused(SslmodeFloor),
    /// sqlx could not parse the DSN. Carries the allowlist rendering of the
    /// DSN ([`crate::url_display::store_url_display`]) and nothing of the
    /// driver's own text. ERRORS-15 exception: the `sqlx::Error` is neither
    /// chained as `source()` nor rendered, because its `Display` can
    /// interpolate the raw DSN (credential included) and masking that text
    /// is a denylist the query string walks straight past (#3711 / #4934).
    Parse(String),
}

impl std::fmt::Display for FlooredConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(verdict) => f.write_str(
                &crate::transit_encryption::pg_floor_refusal(verdict)
                    .unwrap_or_else(crate::transit_encryption::pg_sslmode_refusal),
            ),
            Self::Parse(detail) => write!(f, "parse url: {detail}"),
        }
    }
}

impl std::error::Error for FlooredConnectError {}

/// The one floor evaluation (#3705 / #4434): the text screen, then the
/// options sqlx PARSES from the DSN. sqlx matches keys case-sensitively,
/// honours the `ssl-mode` alias, percent-decodes keys, drops tab/newline
/// characters, ignores the fragment and falls back to `PGSSLMODE` when the URL
/// names no sslmode; the text reading does none of that, so the decision is
/// made on the parsed value and the floor and the driver can never disagree
/// (ERRORS-01 / ERRORS-09).
fn evaluate(dsn: &str) -> Result<PgConnectOptions, FlooredConnectError> {
    let text_host = match crate::transit_encryption::dsn_sslmode_floor(dsn) {
        SslmodeFloor::Pinned { host } => host,
        refused => return Err(FlooredConnectError::Refused(refused)),
    };
    // #4934 / #3711: the driver text can echo query values (`password=`,
    // `sslpassword=`) a userinfo-only masker leaves intact, so it is dropped
    // (CWE-532); only the allowlisted `scheme://host/db` rendering is kept.
    let options = connect_options(dsn).map_err(|_| {
        FlooredConnectError::Parse(format!(
            "invalid connection string for {}",
            crate::url_display::store_url_display(dsn)
        ))
    })?;
    // The driver's own transport predicate (`fetch_socket`): a socket is set,
    // or the host starts with `/`. The path-host arm is reachable: `PGHOST=/dir`
    // with a URL whose only host key the driver does not recognise (an
    // upper-case `HOST=`) leaves no socket set and host `/dir`.
    if options.get_socket().is_some() || options.get_host().starts_with('/') {
        let dir = options.get_socket().map_or_else(
            || options.get_host().to_string(),
            |p| p.display().to_string(),
        );
        return Err(FlooredConnectError::Refused(SslmodeFloor::UnixSocket {
            dir,
        }));
    }
    let resolved = match options.get_ssl_mode() {
        PgSslMode::VerifyFull => {
            // The host the text names must be the host the driver dials.
            if !options.get_host().eq_ignore_ascii_case(text_host.trim()) {
                return Err(FlooredConnectError::Refused(SslmodeFloor::DriverHost {
                    named: text_host,
                    dialed: options.get_host().to_string(),
                }));
            }
            return Ok(options);
        }
        PgSslMode::Disable => "disable",
        PgSslMode::Allow => "allow",
        PgSslMode::Prefer => "prefer",
        PgSslMode::Require => "require",
        PgSslMode::VerifyCa => "verify-ca",
    };
    Err(FlooredConnectError::Refused(SslmodeFloor::DriverResolved {
        host: options.get_host().to_string(),
        resolved: resolved.to_string(),
    }))
}

/// The typed floor verdict for `dsn` - what
/// [`crate::transit_encryption::dsn_floor_verdict`] returns under
/// `sal-postgres`. [`SslmodeFloor::Pinned`] only when
/// [`floored_connect_options`] would succeed.
#[must_use]
pub fn floor_verdict(dsn: &str) -> SslmodeFloor {
    match evaluate(dsn) {
        Ok(options) => SslmodeFloor::Pinned {
            host: options.get_host().to_string(),
        },
        Err(FlooredConnectError::Refused(verdict)) => verdict,
        Err(FlooredConnectError::Parse(_)) => SslmodeFloor::Unparseable,
    }
}

/// [`connect_options`] behind the #3705 transit-encryption floor (#4333):
/// the ONE function production code uses to turn a store DSN into connect
/// options. A DSN whose PARSED options are not `sslmode=verify-full` on a TCP
/// transport (absent, weaker, a Unix socket, unparseable, or a shape the
/// driver reads differently from the text, #4434) is refused HERE, before any
/// socket exists. Fails closed (ERRORS-01).
///
/// # Errors
///
/// [`FlooredConnectError::Refused`] below the floor;
/// [`FlooredConnectError::Parse`] when sqlx cannot parse the DSN.
pub fn floored_connect_options(dsn: &str) -> Result<PgConnectOptions, FlooredConnectError> {
    evaluate(dsn)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "postgres://u:pw@db.internal:5432/mem";

    // #6351: the value-printing assertion forms (`assert_eq!`, `expect`,
    // `expect_err`) print the operands, or the `Debug` of a result that
    // carries the DSN or `PgConnectOptions` (which holds the password in
    // cleartext). These helpers fail with a fixed text and no operand.

    /// Equality check whose failure text names the check, never the operands.
    #[track_caller]
    fn same<T: PartialEq + ?Sized>(what: &str, left: &T, right: &T) {
        assert!(left == right, "{what} differs (operands redacted)");
    }

    /// The `Ok` value, or a fixed-text failure that carries no error value.
    #[track_caller]
    fn present<T, E>(result: Result<T, E>) -> T {
        let Ok(value) = result else {
            panic!("a call that must succeed failed (error redacted)");
        };
        value
    }

    /// The `Err` value, or a fixed-text failure that carries no `Ok` value.
    #[track_caller]
    fn refused<T, E>(result: Result<T, E>) -> E {
        let Err(error) = result else {
            panic!("a call that must fail succeeded (value redacted)");
        };
        error
    }

    #[test]
    fn recognised_only_dsn_is_returned_unchanged() {
        let dsn = format!(
            "{BASE}?sslmode=verify-full&sslrootcert=%2Fetc%2Fca%20dir%2Fca.pem\
             &application_name=a&options=-c%20search_path%3Dx&options[lock_timeout]=5s"
        );
        let screened = screen_dsn(&dsn);
        assert!(screened.removed_positions.is_empty());
        assert!(matches!(screened.dsn, Cow::Borrowed(s) if s == dsn));
    }

    #[test]
    fn dsn_without_query_is_returned_unchanged() {
        let screened = screen_dsn(BASE);
        assert!(matches!(screened.dsn, Cow::Borrowed(s) if s == BASE));
    }

    #[test]
    fn unrecognised_keys_are_removed_and_kept_pairs_survive_exactly() {
        let dsn = format!(
            "{BASE}?sslmode=require&sslpassword=S1&PASSWORD=S2&S3\
             &sslrootcert=%2Fa%20b%2Fca.pem&tok%65n=S4#frag"
        );
        let screened = screen_dsn(&dsn);
        same(
            "removed positions",
            screened.removed_positions.as_slice(),
            &[2, 3, 4, 6][..],
        );
        let out = screened.dsn.as_ref();
        for (i, secret) in ["S1", "S2", "S3", "S4"].iter().enumerate() {
            // #6098: name the fixture by index, never by value or rendering.
            assert!(
                !out.contains(secret),
                "#6098: fixture {i} survived the screen"
            );
        }
        let url = present(reqwest::Url::parse(out));
        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        same(
            "query pairs",
            pairs.as_slice(),
            &[
                ("sslmode".to_string(), "require".to_string()),
                ("sslrootcert".to_string(), "/a b/ca.pem".to_string()),
            ][..],
        );
        same("username", url.username(), "u");
        same("password", &url.password(), &Some("pw"));
        same("host", &url.host_str(), &Some("db.internal"));
        same("port", &url.port(), &Some(5432));
        same("path", url.path(), "/mem");
        same("fragment", &url.fragment(), &Some("frag"));
    }

    #[test]
    fn a_query_of_only_unrecognised_keys_is_dropped_entirely() {
        let dsn = format!("{BASE}?sslpassword=S1");
        let screened = screen_dsn(&dsn);
        same(
            "removed positions",
            screened.removed_positions.as_slice(),
            &[1][..],
        );
        same("screened dsn", &*screened.dsn, BASE);
    }

    #[test]
    fn key_matching_is_case_sensitive_like_sqlx() {
        assert!(is_recognised_query_key("password"));
        assert!(!is_recognised_query_key("Password"));
        assert!(!is_recognised_query_key("SSLMODE"));
        assert!(is_recognised_query_key("options[search_path]"));
        assert!(!is_recognised_query_key("option[search_path]"));
    }

    #[test]
    fn an_unparseable_dsn_is_passed_through_for_sqlx_to_refuse() {
        let dsn = "not a url ?sslpassword=S1";
        let screened = screen_dsn(dsn);
        assert!(matches!(screened.dsn, Cow::Borrowed(s) if s == dsn));
        assert!(connect_options(dsn).is_err());
    }

    #[test]
    fn connect_options_keeps_the_honoured_parameters() {
        let opts = present(connect_options(&format!(
            "{BASE}?sslpassword=S1&application_name=ai-memory-3674&port=6543"
        )));
        same(
            "application name",
            &opts.get_application_name(),
            &Some("ai-memory-3674"),
        );
        same("port", &opts.get_port(), &6543);
        same("host", opts.get_host(), "db.internal");
        same("username", opts.get_username(), "u");
        same("database", &opts.get_database(), &Some("mem"));
    }

    /// #4934 / #3711 — a sqlx parse failure reaches the operator as the
    /// allowlist rendering of the DSN and NOTHING of the driver's own text.
    ///
    /// sqlx honours the `ssl-mode` ALIAS of the `sslmode` key the text floor
    /// pins on, and its parse error interpolates the VALUE it rejected, so a
    /// credential pasted there was echoed by the dependency. The userinfo-only
    /// masker this replaced never touched that text. Restoring it fails the
    /// secret-ABSENCE loop below.
    #[test]
    fn parse_error_never_renders_query_secrets_4934() {
        let dsn = "postgres://svc-alice:userinfo-s3cr3t@db.internal:5432/mem\
                   ?sslmode=verify-full&ssl-mode=pasted-s3cr3t-4934\
                   &sslpassword=ssl-p4ss&password=query-p4ssw0rd";
        let Err(err) = floored_connect_options(dsn) else {
            panic!("an unknown ssl-mode value is refused");
        };
        for rendering in [format!("{err}"), format!("{err:?}")] {
            for (i, secret) in [
                "pasted-s3cr3t-4934",
                "userinfo-s3cr3t",
                "ssl-p4ss",
                "query-p4ssw0rd",
                "sslpassword",
                "password",
                "svc-alice",
                "?",
            ]
            .iter()
            .enumerate()
            {
                // #6098: name the fixture by index, never by value.
                assert!(
                    !rendering.contains(secret),
                    "#4934: fixture {i} reached the parse error (rendering redacted)"
                );
            }
            assert!(
                rendering.contains("db.internal"),
                "the host an operator needs is still named: {rendering}"
            );
        }
        // #6098: printed only after the absence loops above have run, so a
        // regression that both leaks and changes the variant cannot print it.
        assert!(
            matches!(err, FlooredConnectError::Parse(_)),
            "the text floor pinned the host, so sqlx's parse is what failed: {err:?}"
        );
        // Non-numeric port: a second parse-failure shape stays clean.
        let dsn = "postgres://u:pw4934@db.internal/mem?sslmode=verify-full&sslpassword=SECRETQ4934&port=notaport";
        let err = refused(evaluate(dsn));
        let shown = format!("{err}");
        for (i, secret) in ["SECRETQ4934", "pw4934", "sslpassword", "notaport"]
            .iter()
            .enumerate()
        {
            assert!(
                !shown.contains(secret),
                "#4934: fixture {i} leaked in the non-numeric-port shape"
            );
        }
        // #6098: after the absence loop, so the rendering is printed only
        // once it is known to carry no fixture.
        assert!(shown.contains("db.internal"), "{shown}");
    }

    /// The test module's own source with the pin below cut out, so the pin's
    /// literals are not scanned as if they were assertions.
    fn tests_source_without_the_6098_pin() -> String {
        const SOURCE: &str = include_str!("dsn.rs");
        let module = SOURCE.find("mod tests {").map_or("", |at| &SOURCE[at..]);
        let pin = module
            .find("fn secret_absence_messages_never_interpolate_the_fixture_6098")
            .unwrap_or(module.len());
        let tail = &module[pin..];
        let pin_end = tail
            .find("\n    }\n")
            .map_or(tail.len(), |at| at + "\n    }\n".len());
        format!("{}{}", &module[..pin], &tail[pin_end..])
    }

    /// Why a secret-absence assertion message is refused, or `None` when the
    /// message is one string literal whose only placeholder is `{i}`.
    fn absence_message_defect(after_condition: &str) -> Option<&'static str> {
        let Some(message) = after_condition.trim_start().strip_prefix(',') else {
            return Some("no message");
        };
        let Some(body) = message.trim_start().strip_prefix('"') else {
            return Some("message is not a string literal");
        };
        let Some(end) = body.find('"') else {
            return Some("unterminated message literal");
        };
        let literal = &body[..end];
        if literal.ends_with('\\') {
            return Some("escaped quote in message literal");
        }
        if literal.replace("{i}", "").contains(['{', '}']) {
            return Some("placeholder other than {i}");
        }
        let after = body[end + 1..].trim_start();
        let after = after.strip_prefix(',').unwrap_or(after).trim_start();
        if after.starts_with(')') {
            None
        } else {
            Some("format arguments after the literal")
        }
    }

    /// The identifiers a failure message would print: the names inside its
    /// `{..}` placeholders plus every identifier in the arguments after the
    /// literal. `stmt` is one whole assertion statement.
    fn message_words(stmt: &str) -> Vec<String> {
        let flat = stmt.split_whitespace().collect::<Vec<_>>().join(" ");
        let Some(at) = flat.find("), \"") else {
            return Vec::new();
        };
        let message = &flat[at + 3..];
        let Some(body) = message.strip_prefix('"') else {
            return Vec::new();
        };
        let end = body.find('"').unwrap_or(body.len());
        let (literal, args) = body.split_at(end);
        let mut words: Vec<String> = Vec::new();
        for placeholder in literal.split('{').skip(1) {
            let name = placeholder.split(['}', ':']).next().unwrap_or("");
            words.push(name.to_string());
        }
        words.extend(
            args.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| !w.is_empty())
                .map(str::to_string),
        );
        words
    }

    /// Every panic macro call in `source` must carry one plain string literal
    /// with no placeholder and no arguments, so its text cannot print a value.
    fn panic_sink_defects(source: &str) -> usize {
        // Built at run time so this helper's own text is not a match.
        let call = format!("{}!(", "panic");
        let mut defects = 0_usize;
        for (at, _) in source.match_indices(call.as_str()) {
            let rest = source[at + call.len()..].trim_start();
            let plain = rest.strip_prefix('"').and_then(|body| {
                let end = body.find('"')?;
                let tail = body[end + 1..].trim_start();
                (!body[..end].contains('{') && tail.starts_with(')')).then_some(())
            });
            if plain.is_none() {
                defects += 1;
            }
        }
        defects
    }

    /// #6098 / #6351 — a secret-ABSENCE assertion (`!<x>.contains(secret)`)
    /// must not put the fixture value, or any rendering that carries it, into
    /// its own panic text: a failing run would print exactly the cleartext
    /// #4934 forbids, and static analysis flags the shape whether or not the
    /// fixture is a real credential.
    ///
    /// Scanning decision (test structure, no vote): the pin reads this
    /// module's own source and parses each absence assertion's message
    /// STRUCTURALLY (one string literal, only `{i}` allowed, no format
    /// arguments after it) rather than blacklisting identifiers, so
    /// `{secret:?}`, positional arguments, `{err:?}` and `{dsn}` are all
    /// refused by one rule. Ordering: inside a test fn, no other assertion
    /// message prints a rendering (`shown`, `rendering`, `out`, `err`,
    /// whether by placeholder or by positional argument) before that
    /// rendering's absence assertion has run. #6351 sinks: this module may
    /// not use the value-printing macros and result accessors at all (they
    /// print the operands, or the `Debug` of the credential-bearing value),
    /// and a `panic!` carries a plain literal only. Redacting helpers
    /// replace them.
    #[test]
    fn secret_absence_messages_never_interpolate_the_fixture_6098() {
        let source = tests_source_without_the_6098_pin();
        let mut absence_asserts = 0_usize;
        let mut defects = Vec::new();
        for token in [
            "assert_eq!(",
            "assert_ne!(",
            ".expect(",
            ".expect_err(",
            ".unwrap(",
            ".unwrap_err(",
            "eprintln!(",
            "println!(",
            "dbg!(",
        ] {
            let n = source.matches(token).count();
            if n > 0 {
                defects.push(format!("{n} use(s) of the value-printing sink {token}"));
            }
        }
        let bad_panics = panic_sink_defects(&source);
        if bad_panics > 0 {
            defects.push(format!("{bad_panics} panic sink(s) with a placeholder"));
        }
        for function in source.split("\n    fn ").skip(1) {
            let mut first_absence: Vec<(String, usize)> = Vec::new();
            let mut others: Vec<usize> = Vec::new();
            for (at, _) in function.match_indices("assert!(") {
                let rest = function[at + "assert!(".len()..].trim_start();
                let guard = rest
                    .strip_prefix('!')
                    .and_then(|r| r.split_once(".contains(secret)"))
                    .filter(|(g, _)| {
                        !g.is_empty() && g.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    });
                let Some((guard, after)) = guard else {
                    others.push(at);
                    continue;
                };
                absence_asserts += 1;
                if let Some(why) = absence_message_defect(after) {
                    defects.push(format!("absence assertion {absence_asserts}: {why}"));
                }
                if !first_absence.iter().any(|(g, _)| g == guard) {
                    first_absence.push((guard.to_string(), at));
                }
            }
            if first_absence.is_empty() {
                continue;
            }
            for at in others {
                let stmt = &function[at..];
                let stmt = &stmt[..stmt.find(");").unwrap_or(stmt.len())];
                let words = message_words(stmt);
                for (var, guard) in [
                    ("shown", "shown"),
                    ("rendering", "rendering"),
                    ("out", "out"),
                    ("err", "rendering"),
                    ("dsn", "rendering"),
                ] {
                    if !words.iter().any(|w| w == var) {
                        continue;
                    }
                    let guarded = first_absence.iter().any(|(g, p)| g == guard && *p < at);
                    if !guarded {
                        defects.push(format!(
                            "an assertion prints {var} before its secret-absence check"
                        ));
                    }
                }
            }
        }
        assert!(defects.is_empty(), "#6098: {defects:?}");
        assert_eq!(
            absence_asserts, 3,
            "#6098: every secret-absence assertion in the module is pinned"
        );
    }
}
