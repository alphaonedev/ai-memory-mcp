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
    let keys = home.join("keys");
    std::fs::create_dir_all(&keys).expect("keys dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let out = assert_cmd::Command::cargo_bin("ai-memory")
        .expect("ai-memory binary")
        .env("HOME", home)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("AI_MEMORY_STORE_URL", store_url)
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

#[test]
fn doctor_refuses_every_pg_probe_below_the_sslmode_floor_without_connecting_4333() {
    let listener = CountingListener::start();
    for url in weak_urls(listener.port) {
        let home = tempfile::tempdir().expect("scratch HOME");
        let report = doctor_json(&url, home.path());

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
            listener.accepted(),
            0,
            "doctor opened a socket for a DSN below the #3705 floor: {url:?}"
        );
    }
}

#[test]
fn the_floored_connect_options_refuses_every_weak_shape_4333() {
    use ai_memory::store::postgres::dsn::{FlooredConnectError, floored_connect_options};
    for url in weak_urls(5432) {
        match floored_connect_options(&url) {
            Err(FlooredConnectError::Refused(m)) => {
                assert!(m.contains(REFUSAL_MARK), "{m}");
                assert!(!m.contains(SECRET), "refusal must not echo the DSN");
            }
            other => panic!("expected a floor refusal for {url:?}, got {other:?}"),
        }
    }
    for url in [
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
