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
//! redact, the value has been written. It was latent only because the default
//! filter (`ai_memory=info`) hid the `sqlx_postgres` target; #3650 widens the
//! default to every target.
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

use sqlx::postgres::PgConnectOptions;

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
/// the connection target, so callers redact it with
/// [`crate::logging::redact_urls_in_message`] before it leaves the process.
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

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "postgres://u:pw@db.internal:5432/mem";

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
        assert_eq!(screened.removed_positions, vec![2, 3, 4, 6]);
        let out = screened.dsn.as_ref();
        for secret in ["S1", "S2", "S3", "S4"] {
            assert!(!out.contains(secret), "{secret} survived: {out}");
        }
        let url = reqwest::Url::parse(out).expect("screened DSN parses");
        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert_eq!(
            pairs,
            vec![
                ("sslmode".to_string(), "require".to_string()),
                ("sslrootcert".to_string(), "/a b/ca.pem".to_string()),
            ]
        );
        assert_eq!(url.username(), "u");
        assert_eq!(url.password(), Some("pw"));
        assert_eq!(url.host_str(), Some("db.internal"));
        assert_eq!(url.port(), Some(5432));
        assert_eq!(url.path(), "/mem");
        assert_eq!(url.fragment(), Some("frag"));
    }

    #[test]
    fn a_query_of_only_unrecognised_keys_is_dropped_entirely() {
        let screened = screen_dsn(&format!("{BASE}?sslpassword=S1"));
        assert_eq!(screened.removed_positions, vec![1]);
        assert_eq!(screened.dsn, BASE);
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
        let opts = connect_options(&format!(
            "{BASE}?sslpassword=S1&application_name=ai-memory-3674&port=6543"
        ))
        .expect("parses");
        assert_eq!(opts.get_application_name(), Some("ai-memory-3674"));
        assert_eq!(opts.get_port(), 6543);
        assert_eq!(opts.get_host(), "db.internal");
        assert_eq!(opts.get_username(), "u");
        assert_eq!(opts.get_database(), Some("mem"));
    }
}
