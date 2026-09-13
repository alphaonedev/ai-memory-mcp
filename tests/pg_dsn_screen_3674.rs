// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(feature = "sal-postgres")]
//! v1.0.0 #3674 — a store DSN reaches sqlx only through
//! `store::postgres::dsn::connect_options`, which removes every query
//! parameter sqlx would log instead of honour.
//!
//! sqlx-postgres 0.8.6 logs an unrecognised DSN query parameter WITH ITS VALUE
//! at `warn` (`options/parse.rs`: `tracing::warn!(%key, %value, …)`). The line
//! is emitted inside the dependency, so only keeping the parameter away from
//! sqlx prevents it. These tests capture every event the process emits and
//! assert a planted secret never appears:
//!
//! * under `info` for every target — the #3650 default (`DEFAULT_LOG_LEVEL`);
//! * under `trace` for every target — the widest filter there is, so no future
//!   widening can reopen the leak.
//!
//! Each capture is proven non-vacuous: the same sink, handed the RAW DSN
//! through sqlx directly, does contain the secret.

use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError};

use ai_memory::store::PoolConfig;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::postgres::dsn::{self, SQLX_RECOGNISED_QUERY_KEYS};
use sqlx::postgres::PgConnectOptions;

/// The #3650 default filter (a bare `info` for every target) and the widest.
const FILTERS: &[&str] = &["info", "trace"];

/// sqlx 0.8.6's catch-all message. Asserted present in the controls, so a
/// wording change in a sqlx upgrade fails loudly instead of making the
/// recognised-key test vacuous.
const SQLX_UNRECOGNISED_MSG: &str = "ignoring unrecognized connect parameter";

/// Planted secrets: one per shape sqlx does not honour.
const SECRET_SSLPASSWORD: &str = "S3CRET-3674-sslpassword";
const SECRET_UPPER_PASSWORD: &str = "S3CRET-3674-upper-password";
const SECRET_BARE_KEY: &str = "S3CRET-3674-bare-key";
const SECRET_TOKEN: &str = "S3CRET-3674-token";
const SECRETS: &[&str] = &[
    SECRET_SSLPASSWORD,
    SECRET_UPPER_PASSWORD,
    SECRET_BARE_KEY,
    SECRET_TOKEN,
];

/// The planted query string: four unrecognised parameters carrying secrets.
fn planted_query() -> String {
    format!(
        "sslpassword={SECRET_SSLPASSWORD}&PASSWORD={SECRET_UPPER_PASSWORD}\
         &{SECRET_BARE_KEY}&token={SECRET_TOKEN}"
    )
}

fn with_query(url: &str, query: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{query}")
}

/// An in-memory log sink shared by a scoped subscriber.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    /// Install a thread-scoped subscriber writing every event `filter` admits
    /// into this sink. Hold the guard for the duration of the capture.
    fn install(&self, filter: &str) -> tracing::subscriber::DefaultGuard {
        let buf = Arc::clone(&self.0);
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_ansi(false)
            .with_writer(move || CaptureWriter(Arc::clone(&buf)))
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }
}

fn assert_no_secret(sink: &str, filter: &str, what: &str) {
    for secret in SECRETS {
        assert!(
            !sink.contains(secret),
            "#3674: {what} leaked {secret:?} into the log sink under filter {filter:?}:\n{sink}"
        );
    }
}

/// Control: the raw DSN handed to sqlx directly DOES leak through this sink,
/// so a clean result below is the funnel's doing, not a blind capture.
fn assert_raw_dsn_leaks(raw_dsn: &str, filter: &str) {
    let capture = Capture::default();
    {
        let _guard = capture.install(filter);
        let _ = PgConnectOptions::from_str(raw_dsn);
    }
    let sink = capture.text();
    assert!(
        sink.contains(SQLX_UNRECOGNISED_MSG) && sink.contains(SECRET_SSLPASSWORD),
        "control failed: the capture did not see sqlx log the raw DSN under {filter:?} — \
         the leak assertions would be vacuous:\n{sink}"
    );
}

/// A loopback port with nothing listening: a real TCP connect is refused.
fn closed_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// ACCEPTANCE (#3674): plant secret-valued unrecognised parameters, drive a
/// real connection attempt through the production store connect, and assert
/// no secret reaches the log sink — under the #3650 default and under
/// `trace`. Runs without a database: the attempt is refused at TCP, after
/// sqlx has parsed the DSN.
#[tokio::test(flavor = "current_thread")]
async fn store_connect_never_logs_planted_dsn_secrets_3674() {
    for filter in FILTERS {
        let port = closed_loopback_port();
        let dsn = with_query(
            &format!("postgres://ai_memory@127.0.0.1:{port}/mem?sslmode=require"),
            &planted_query(),
        );
        assert_raw_dsn_leaks(&dsn, filter);

        let capture = Capture::default();
        let result = {
            let _guard = capture.install(filter);
            PostgresStore::connect_with_dim_and_timeout(
                &dsn,
                768,
                5,
                PoolConfig {
                    max_connections: 1,
                    min_connections: 0,
                    acquire_timeout_secs: 2,
                },
            )
            .await
        };
        assert!(
            result.is_err(),
            "nothing listens on 127.0.0.1:{port}; the connect must fail"
        );
        let sink = capture.text();
        assert_no_secret(&sink, filter, "PostgresStore::connect_with_dim_and_timeout");
        // Non-vacuous: the funnel's own WARN (count, no names) is in the sink.
        assert!(
            sink.contains("removed store-URL query parameters") && sink.contains("removed=4"),
            "the #3674 funnel WARN is missing under {filter:?}:\n{sink}"
        );
        if let Err(e) = result {
            let detail = e.to_string();
            assert_no_secret(&detail, filter, "the returned connect error");
        }
    }
}

/// Every key on the allowlist must be one the LINKED sqlx honours. A key sqlx
/// does not recognise would pass the screen and reach sqlx's catch-all `warn!`
/// with its value, so this is the test that keeps the allowlist from being
/// wider than sqlx. A sqlx upgrade that drops a key fails here.
#[test]
fn every_allowlisted_key_is_honoured_by_the_linked_sqlx_3674() {
    fn sample_value(key: &str) -> &'static str {
        match key {
            "sslmode" | "ssl-mode" => "require",
            "sslrootcert" | "ssl-root-cert" | "ssl-ca" => "/nonexistent/ca.pem",
            "sslcert" | "ssl-cert" => "/nonexistent/client.pem",
            "sslkey" | "ssl-key" => "/nonexistent/client.key",
            "statement-cache-capacity" => "10",
            "host" => "db.internal",
            "hostaddr" => "127.0.0.1",
            "port" => "5432",
            "dbname" => "mem",
            "user" => "ai_memory",
            "password" => "pw",
            "application_name" => "ai-memory",
            "options" => "-c search_path=public",
            other => panic!("no sample value for allowlisted key {other:?}; add one"),
        }
    }

    let capture = Capture::default();
    {
        let _guard = capture.install("trace");
        let mut query = reqwest::Url::parse("postgres://h/db").expect("base url");
        {
            let mut pairs = query.query_pairs_mut();
            for key in SQLX_RECOGNISED_QUERY_KEYS {
                pairs.append_pair(key, sample_value(key));
            }
            pairs.append_pair("options[lock_timeout]", "5s");
        }
        PgConnectOptions::from_str(query.as_str()).expect("every allowlisted key parses");
    }
    let sink = capture.text();
    assert!(
        !sink.contains(SQLX_UNRECOGNISED_MSG),
        "an allowlisted key is NOT honoured by the linked sqlx — its value would be logged:\n{sink}"
    );

    // Control: an unlisted key does produce the message this test looks for.
    assert_raw_dsn_leaks(&with_query("postgres://h/db", &planted_query()), "trace");
}

/// With a live database: the screened options still connect, keep every
/// parameter sqlx honours (the test URL's TLS parameters and a planted
/// `application_name`), and log no planted secret.
#[tokio::test(flavor = "current_thread")]
async fn screened_dsn_connects_and_keeps_honoured_parameters_3674() {
    let Ok(base) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    use sqlx::Connection as _;

    const APP_NAME: &str = "ai-memory-3674";
    let dsn = with_query(
        &base,
        &format!("{}&application_name={APP_NAME}", planted_query()),
    );
    for filter in FILTERS {
        let capture = Capture::default();
        let app_name: String = {
            let _guard = capture.install(filter);
            let options = dsn::connect_options(&dsn).expect("screened DSN parses");
            let mut conn = sqlx::PgConnection::connect_with(&options)
                .await
                .expect("screened DSN connects");
            let name = sqlx::query_scalar("SELECT current_setting('application_name')")
                .fetch_one(&mut conn)
                .await
                .expect("read application_name");
            conn.close().await.expect("close");
            name
        };
        assert_eq!(app_name, APP_NAME, "an honoured parameter was dropped");
        assert_no_secret(&capture.text(), filter, "a live connection");
    }
}

// ---------------------------------------------------------------------------
// Funnel inventory — every production sqlx connection is built from
// `dsn::connect_options`. Production/test boundary heuristic mirrors
// `tests/db_open_funnel_ceiling_2445.rs`.
// ---------------------------------------------------------------------------

/// The funnel. Its own `PgConnectOptions::from_str` is the one permitted.
const FUNNEL_FILE: &str = "src/store/postgres/dsn.rs";

/// `(file, sqlx connection constructions, dsn::connect_options calls)`.
/// A new construction, or one that stops calling the funnel, fails.
const LEDGER: &[(&str, usize, usize)] = &[
    ("src/cli/doctor.rs", 1, 1),
    ("src/cli/keys.rs", 1, 1),
    ("src/cli/schema_init.rs", 1, 1),
    ("src/store/postgres.rs", 1, 1),
];

/// Tokens that START a sqlx connection (pool builder or single connection).
const CONSTRUCTION_TOKENS: &[&str] = &[
    "PgPoolOptions::new()",
    "PgConnection::connect",
    "PgPool::connect",
    "PgListener::connect",
];

/// Tokens that hand sqlx a DSN STRING (or parse one) — forbidden outside the
/// funnel.
const RAW_DSN_TOKENS: &[&str] = &[
    "PgConnectOptions::from_str",
    "parse::<PgConnectOptions>",
    "PgConnectOptions::from_url",
    "PgConnection::connect(",
    "PgPool::connect(",
    "PgPool::connect_lazy(",
    "PgListener::connect(",
];

/// The funnel call as it appears at a call site.
const FUNNEL_CALL: &str = "dsn::connect_options(";

fn strip_vis(t: &str) -> &str {
    let t = t.trim_start();
    let Some(rest) = t.strip_prefix("pub") else {
        return t;
    };
    let rest = rest.trim_start();
    if rest.starts_with('(') {
        if let Some(idx) = rest.find(')') {
            return rest[idx + 1..].trim_start();
        }
    }
    rest
}

fn is_cfg_test_attr(t: &str) -> bool {
    let t = t.trim_start();
    t.starts_with("#[cfg(test)]")
        || t.starts_with("#[cfg(any(test")
        || t.starts_with("#[cfg(all(test")
}

fn is_comment_or_empty(t: &str) -> bool {
    let t = t.trim_start();
    t.is_empty() || t.starts_with("//") || t.starts_with('*')
}

/// Source before the first `#[cfg(test)]` inline test module.
fn production_prefix(src: &str) -> &str {
    let mut pending_attr_start: Option<usize> = None;
    let mut line_start = 0;
    for line in src.split_inclusive('\n') {
        let content = line.trim_start().trim_end_matches(['\n', '\r']);
        if is_comment_or_empty(content) {
            line_start += line.len();
            continue;
        }
        if is_cfg_test_attr(content) {
            pending_attr_start.get_or_insert(line_start);
            line_start += line.len();
            continue;
        }
        if content.starts_with("#[") {
            line_start += line.len();
            continue;
        }
        if let Some(cut) = pending_attr_start {
            let head = strip_vis(content);
            if head.starts_with("mod ") && head.contains('{') {
                return &src[..cut];
            }
            pending_attr_start = None;
        }
        line_start += line.len();
    }
    src
}

/// Production code lines (comments dropped).
fn code_lines(src: &str) -> Vec<&str> {
    production_prefix(src)
        .lines()
        .filter(|l| !is_comment_or_empty(l))
        .collect()
}

fn count(lines: &[&str], tokens: &[&str]) -> usize {
    lines
        .iter()
        .map(|l| tokens.iter().filter(|t| l.contains(*t)).count())
        .sum()
}

/// A `PgPoolOptions` chain must end in `connect_with` / `connect_lazy_with`,
/// never the DSN-string `connect` / `connect_lazy`.
fn raw_pool_connects(lines: &[&str]) -> usize {
    let mut raw = 0;
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("PgPoolOptions::new()") {
            continue;
        }
        for next in lines.iter().skip(i).take(200) {
            if next.contains(".connect_with(") || next.contains(".connect_lazy_with(") {
                break;
            }
            if next.contains(".connect(") || next.contains(".connect_lazy(") {
                raw += 1;
                break;
            }
        }
    }
    raw
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_production_sqlx_connect_goes_through_the_dsn_funnel_3674() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk_rs(&root.join("src"), &mut files);
    files.sort();

    let mut observed: Vec<(String, usize, usize)> = Vec::new();
    let mut violations = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .expect("under repo")
            .to_string_lossy()
            .replace('\\', "/");
        // Test-only files `include!`d into a test module.
        if rel.ends_with("tests.rs") {
            continue;
        }
        let src = std::fs::read_to_string(path).expect("read source");
        let lines = code_lines(&src);
        if rel == FUNNEL_FILE {
            assert_eq!(
                count(&lines, &["PgConnectOptions::from_str("]),
                1,
                "the funnel must parse exactly once"
            );
            continue;
        }
        let raw = count(&lines, RAW_DSN_TOKENS) + raw_pool_connects(&lines);
        if raw > 0 {
            violations.push(format!("{rel}: {raw} raw-DSN sqlx entry point(s)"));
        }
        let constructions = count(&lines, CONSTRUCTION_TOKENS);
        let funnel_calls = count(&lines, &[FUNNEL_CALL]);
        if constructions > 0 || funnel_calls > 0 {
            observed.push((rel, constructions, funnel_calls));
        }
    }

    assert!(
        violations.is_empty(),
        "#3674: sqlx is handed a raw DSN outside {FUNNEL_FILE}; build options with \
         `crate::store::postgres::dsn::connect_options` and connect with `connect_with`:\n{}",
        violations.join("\n")
    );
    let expected: Vec<(String, usize, usize)> = LEDGER
        .iter()
        .map(|(f, c, k)| ((*f).to_string(), *c, *k))
        .collect();
    assert_eq!(
        observed, expected,
        "#3674: the production sqlx connection inventory changed. Every construction \
         must take its options from `dsn::connect_options`; update LEDGER only for a \
         site that does."
    );
}

#[test]
fn the_funnel_inventory_heuristics_are_load_bearing_3674() {
    let raw_chain =
        "let p = PgPoolOptions::new()\n    .max_connections(1)\n    .connect(&url)\n    .await?;\n";
    assert_eq!(raw_pool_connects(&code_lines(raw_chain)), 1);
    let screened_chain = "let p = PgPoolOptions::new()\n    .after_connect(|c, _| x)\n    .connect_with(opts)\n    .await?;\n";
    assert_eq!(raw_pool_connects(&code_lines(screened_chain)), 0);
    assert_eq!(
        count(
            &code_lines("let c = sqlx::PgConnection::connect(url).await?;\n"),
            RAW_DSN_TOKENS
        ),
        1
    );
    let test_mod =
        "fn prod() {}\n#[cfg(test)]\nmod tests {\n    fn t() { PgConnection::connect(url); }\n}\n";
    assert_eq!(count(&code_lines(test_mod), RAW_DSN_TOKENS), 0);
}
