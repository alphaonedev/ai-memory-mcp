// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(feature = "sal-postgres")]
//! #4333 - `ai-memory doctor`'s postgres probe sections connect through the
//! SAME #3705 `sslmode=verify-full` floor the store funnel enforces.
//!
//! Before the fix each doctor section built its own pool from the store URL
//! (`dsn::connect_options` only) and dialled the driver default (`prefer`),
//! so a DSN the daemon REFUSES was still connected to by `doctor`. These cells
//! observe the defect on the wire: a counting TCP listener stands in for the
//! database, and a weak-`sslmode` store URL must produce ZERO accepted
//! connections from every doctor section that opens a postgres session
//! (Postgres extensions, Unstamped owners, Identity key registry), each
//! reporting the refusal as its own fact instead of connecting.
//!
//! The green cell (gated on `AI_MEMORY_TEST_POSTGRES_URL`, a verify-full DSN)
//! proves the floor does not break a compliant URL.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// Every libpq environment variable sqlx 0.8.6 (or a future one) may read.
const PG_ENV_VARS: &[&str] = &[
    "PGSSLMODE",
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGSSLROOTCERT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGUSER",
    "PGPASSWORD",
    "PGDATABASE",
    "PGPASSFILE",
    "PGOPTIONS",
    "PGAPPNAME",
];

const SECRET: &str = "S3CRET-4333-pw";
const REFUSAL_MARK: &str = "refusing the PostgreSQL store DSN";

/// A TCP listener that counts accepted connections and drops them.
struct CountingListener {
    port: u16,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl CountingListener {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind counting listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (a, s) = (Arc::clone(&accepted), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok(_) => {
                        a.fetch_add(1, Ordering::AcqRel);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self {
            port,
            accepted,
            stop,
            handle: Some(handle),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }
}

impl Drop for CountingListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Run `ai-memory doctor --json` as a subprocess scoped to `store_url`.
fn doctor_json(store_url: &str, home: &std::path::Path) -> serde_json::Value {
    doctor_json_env(store_url, home, &[])
}

fn doctor_json_env(
    store_url: &str,
    home: &std::path::Path,
    extra_env: &[(&str, &str)],
) -> serde_json::Value {
    let keys = home.join("keys");
    std::fs::create_dir_all(&keys).expect("keys dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let mut cmd = assert_cmd::Command::cargo_bin("ai-memory").expect("ai-memory binary");
    // Hermetic: no ambient libpq variable may change what the driver resolves.
    for var in PG_ENV_VARS {
        cmd.env_remove(var);
    }
    let out = cmd
        .env("HOME", home)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("AI_MEMORY_STORE_URL", store_url)
        .envs(extra_env.iter().copied())
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        !stdout.contains(SECRET) && !String::from_utf8_lossy(&out.stderr).contains(SECRET),
        "doctor output must never carry the DSN password"
    );
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("doctor --json parse: {e}\n{stdout}"))
}

fn section<'a>(report: &'a serde_json::Value, needle: &str) -> &'a serde_json::Value {
    report["sections"]
        .as_array()
        .expect("sections array")
        .iter()
        .find(|s| s["name"].as_str().is_some_and(|n| n.contains(needle)))
        .unwrap_or_else(|| panic!("no `{needle}` section in {report}"))
}

fn is_critical(s: &serde_json::Value) -> bool {
    s["severity"]
        .as_str()
        .is_some_and(|v| v.eq_ignore_ascii_case("critical"))
}

/// Every weak shape the floor refuses on TCP: absent, `prefer`, `disable`,
/// `require`, and a trailing weaker `sslmode` masking an earlier verify-full.
fn weak_urls(port: u16) -> Vec<String> {
    let base = format!("postgres://u:{SECRET}@127.0.0.1:{port}/db");
    vec![
        base.clone(),
        format!("{base}?sslmode=prefer"),
        format!("{base}?sslmode=disable"),
        format!("{base}?sslmode=require"),
        format!("{base}?sslmode=verify-full&sslmode=require"),
    ]
}

/// Assert every doctor section that opens a postgres session refused `url`
/// and that the listener saw no connection.
fn assert_doctor_refused_without_connecting(
    listener: &CountingListener,
    url: &str,
    extra_env: &[(&str, &str)],
) {
    let home = tempfile::tempdir().expect("scratch HOME");
    let report = doctor_json_env(url, home.path(), extra_env);

    let ext = section(&report, "Postgres extensions");
    assert!(is_critical(ext), "extensions must be critical: {ext}");
    assert!(
        ext.to_string().contains(REFUSAL_MARK),
        "extensions must report the floor refusal: {ext}"
    );

    let owners = section(&report, "Unstamped owners");
    assert!(is_critical(owners), "owners must be critical: {owners}");
    assert!(
        owners.to_string().contains(REFUSAL_MARK),
        "owners must report the floor refusal: {owners}"
    );

    let identity = section(&report, "Identity");
    assert!(
        identity.to_string().contains(REFUSAL_MARK),
        "the identity key-registry inspection must report the floor refusal: {identity}"
    );
    assert_eq!(
        identity["severity"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("warning"),
        "a refused key-registry read is a Warning note: {identity}"
    );

    // #4434 - the Transit report decides with the SAME verdict as the connect:
    // never "pinned" for a DSN the sections above refused.
    let transit = section(&report, "Transit encryption");
    let transit_text = transit.to_string();
    assert!(
        transit_text.contains("REFUSES at connect")
            && !transit_text.contains("sslmode=verify-full pinned"),
        "Transit must report REFUSES, not pinned, for {url:?}: {transit}"
    );
    assert!(is_critical(transit), "Transit must be critical: {transit}");

    assert_eq!(
        listener.accepted(),
        0,
        "doctor opened a socket for a DSN below the #3705 floor: {url:?}"
    );
}

#[test]
fn doctor_refuses_every_pg_probe_below_the_sslmode_floor_without_connecting_4333() {
    let listener = CountingListener::start();
    for url in weak_urls(listener.port) {
        assert_doctor_refused_without_connecting(&listener, &url, &[]);
    }
}

/// #4434 - DSNs the text floor approved while sqlx parsed a weaker sslmode:
/// the `ssl-mode` alias after verify-full, an upper-case key, a
/// percent-encoded key, sslmode text in the fragment, a tab / newline inside
/// a key. Each must be refused with no socket, from every doctor section.
fn bypass_urls(port: u16) -> Vec<(&'static str, String)> {
    let base = format!("postgres://u:{SECRET}@127.0.0.1:{port}/db");
    vec![
        (
            "alias key",
            format!("{base}?sslmode=verify-full&ssl-mode=disable"),
        ),
        (
            "upper-case key",
            format!("{base}?sslmode=disable&SSLMODE=verify-full"),
        ),
        (
            "percent-encoded key",
            format!("{base}?sslmode=verify-full&%73slmode=disable"),
        ),
        (
            "fragment",
            format!("{base}?sslmode=disable#x&sslmode=verify-full"),
        ),
        ("fragment only", format!("{base}?a=1#&sslmode=verify-full")),
        (
            "tab in key",
            format!("{base}?sslmode=verify-full&ss\tlmode=disable"),
        ),
        (
            "newline in key",
            format!("{base}?sslmode=verify-full&ss\nlmode=require"),
        ),
    ]
}

#[test]
fn doctor_refuses_the_parser_differential_dsns_without_connecting_4434() {
    let listener = CountingListener::start();
    for (kind, url) in bypass_urls(listener.port) {
        eprintln!("4434 row: {kind}");
        assert_doctor_refused_without_connecting(&listener, &url, &[]);
    }
}

#[test]
fn floored_connect_options_refuses_the_parser_differential_dsns_4434() {
    use ai_memory::store::postgres::dsn::{FlooredConnectError, floored_connect_options};
    let mut not_refused = Vec::new();
    // "fragment only" has no sslmode in the driver's view, so the ambient
    // PGSSLMODE decides it; it runs in the env-scrubbed subprocess cells.
    for (kind, url) in bypass_urls(5432)
        .into_iter()
        .filter(|(k, _)| *k != "fragment only")
    {
        match floored_connect_options(&url) {
            Err(refused @ FlooredConnectError::Refused(_)) => {
                let m = refused.to_string();
                assert!(m.contains(REFUSAL_MARK), "{kind}: {m}");
                assert!(!m.contains(SECRET), "{kind}: refusal must not echo the DSN");
            }
            _ => not_refused.push(kind),
        }
    }
    assert!(
        not_refused.is_empty(),
        "rows the floor approved while the driver parses a weaker sslmode: {not_refused:?}"
    );
}

/// #4434 - PGSSLMODE is read by sqlx when the parsed URL names no sslmode.
/// (1) A DSN whose only sslmode sits in the fragment is refused under each
/// WEAKER PGSSLMODE, with no socket. (2) A URL that pins verify-full in its
/// query keeps verify-full under a hostile PGSSLMODE: doctor, run with
/// `PGSSLMODE=disable`, still probes the live TLS tier.
#[test]
fn pgsslmode_env_cannot_change_the_outcome_4434() {
    let listener = CountingListener::start();
    let base = format!("postgres://u:{SECRET}@127.0.0.1:{}/db", listener.port);
    for env_mode in ["disable", "prefer", "require", "allow"] {
        assert_doctor_refused_without_connecting(
            &listener,
            &format!("{base}?a=1#&sslmode=verify-full"),
            &[("PGSSLMODE", env_mode)],
        );
    }
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset - skipping live half");
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("bootstrap the verify-full store")
    });
    for hostile in ["disable", "prefer", "require"] {
        let home = tempfile::tempdir().expect("scratch HOME");
        let report = doctor_json_env(&url, home.path(), &[("PGSSLMODE", hostile)]);
        let ext = section(&report, "Postgres extensions");
        assert!(
            !ext.to_string().contains(REFUSAL_MARK)
                && ext.to_string().contains("pgvector_installed"),
            "PGSSLMODE={hostile} must not change a verify-full URL's outcome: {ext}"
        );
    }
}

/// #4434 - the enterprise posture check #15 reads the SAME verdict: a bypass
/// shape must FAIL it (never `sslmode=verify-full=true`).
#[test]
fn enterprise_posture_check_15_fails_every_parser_differential_dsn_4434() {
    let home = tempfile::tempdir().expect("scratch HOME");
    let mut shapes = bypass_urls(5432);
    shapes.push((
        "weak control",
        format!("postgres://u:{SECRET}@127.0.0.1:5432/db?sslmode=require"),
    ));
    for (kind, url) in shapes {
        let mut cmd = assert_cmd::Command::cargo_bin("ai-memory").expect("ai-memory binary");
        for var in PG_ENV_VARS {
            cmd.env_remove(var);
        }
        let out = cmd
            .env("HOME", home.path())
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_STORE_URL", &url)
            .args(["doctor", "--posture", "enterprise-federation", "--json"])
            .output()
            .expect("run posture");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            !text.contains(SECRET),
            "{kind}: posture output must not echo the DSN"
        );
        assert!(
            text.contains("sslmode=verify-full=false"),
            "{kind}: posture #15 must report the floor NOT met: {text}"
        );
        assert!(
            !text.contains("sslmode=verify-full=true"),
            "{kind}: posture #15 must never say pinned: {text}"
        );
    }
}

#[test]
fn the_floored_connect_options_refuses_every_weak_shape_4333() {
    use ai_memory::store::postgres::dsn::{FlooredConnectError, floored_connect_options};
    for url in weak_urls(5432) {
        match floored_connect_options(&url) {
            Err(refused @ FlooredConnectError::Refused(_)) => {
                let m = refused.to_string();
                assert!(m.contains(REFUSAL_MARK), "{m}");
                assert!(!m.contains(SECRET), "refusal must not echo the DSN");
            }
            other => panic!("expected a floor refusal for {url:?}, got {other:?}"),
        }
    }
    for url in [
        format!("postgres://u:{SECRET}@%2Fvar%2Frun%2Fpostgresql/db?sslmode=verify-full"),
        // The driver decodes the key and treats the value as a socket dir.
        format!("postgres://u:{SECRET}@db.internal:5432/db?sslmode=verify-full&%68ost=/tmp"),
        format!("postgres://u:{SECRET}@/db?host=/var/run/postgresql&sslmode=verify-full"),
        "not a url".to_string(),
    ] {
        assert!(
            matches!(
                floored_connect_options(&url),
                Err(FlooredConnectError::Refused(_))
            ),
            "socket / unparseable DSNs are refused by name"
        );
    }
    assert!(
        floored_connect_options(&format!(
            "postgres://u:{SECRET}@db.internal:5432/db?sslmode=verify-full"
        ))
        .is_ok(),
        "a verify-full TCP DSN passes the floor"
    );
}

/// Green: a verify-full DSN against the TLS tier still connects and reports.
#[test]
fn doctor_still_probes_a_verify_full_store_4333() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset - skipping (#4333 green cell)");
        return;
    };
    // Bootstrap the schema so the census table exists.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("bootstrap the verify-full store")
    });
    let home = tempfile::tempdir().expect("scratch HOME");
    let report = doctor_json(&url, home.path());

    let ext = section(&report, "Postgres extensions");
    assert!(
        !ext.to_string().contains(REFUSAL_MARK),
        "a verify-full DSN must not be refused: {ext}"
    );
    assert!(
        ext.to_string().contains("pgvector_installed"),
        "extensions must carry live probe facts: {ext}"
    );
    let owners = section(&report, "Unstamped owners");
    assert!(
        owners.to_string().contains("unstamped_rows"),
        "the census must have run against the live store: {owners}"
    );
    let identity = section(&report, "Identity");
    assert!(
        !identity.to_string().contains(REFUSAL_MARK),
        "a verify-full DSN must not be refused by the key registry read: {identity}"
    );
}

/// #4434 real-PG controls: DSNs whose parsed sslmode IS verify-full still
/// connect, and the session is TLS (`pg_stat_ssl`). The first-weak/last-strong
/// duplicate and the upper-case VALUE are the benign differentials.
#[test]
fn verify_full_controls_connect_over_tls_on_the_real_tier_4434() {
    use sqlx::Connection as _;
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset - skipping (#4434 live controls)");
        return;
    };
    let Some((head, query)) = url.split_once('?') else {
        panic!("the test tier URL carries a query");
    };
    let controls = [
        url.clone(),
        format!("{head}?sslmode=disable&{query}"),
        format!("{head}?{}", query.replace("verify-full", "VERIFY-FULL")),
    ];
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    for control in controls {
        let options = ai_memory::store::postgres::dsn::floored_connect_options(&control)
            .expect("a verify-full control passes the floor");
        let ssl: bool = rt.block_on(async {
            let mut conn = sqlx::PgConnection::connect_with(&options)
                .await
                .expect("verify-full control connects");
            sqlx::query_scalar("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
                .fetch_one(&mut conn)
                .await
                .expect("pg_stat_ssl")
        });
        assert!(ssl, "the control session must be TLS");
    }
}
