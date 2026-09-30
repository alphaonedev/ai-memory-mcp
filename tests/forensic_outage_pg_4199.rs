// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4199 A1 (GOD ruling on the 5-agent vote `4d3ea1c5`) — a postgres-backed
//! `serve` whose forensic log cannot continue its chain attests the outage
//! in the POSTGRES `signed_events` chain, exactly once per `(day, path,
//! cause)`, and writes nothing into a local sqlite file.
//!
//! FAILS ON THE PARENT (3d74fa24f): the boot recorder skipped a postgres
//! store, so no outage row landed in postgres at all.
//!
//! Live only under `AI_MEMORY_TEST_POSTGRES_URL` (a fresh lane database);
//! skips otherwise, so a run that is meant as evidence must show no SKIP line.
//! TRANSPORT: the daemon serves the minted leaf over `https://` (#3705).

#![cfg(feature = "sal-postgres")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
const OUTAGE_EVENT: &str = "audit.forensic_sink_unavailable";
const DEFERRED_NOTE: &str = "recorded in the postgres signed_events";

fn pg_url() -> Option<String> {
    match std::env::var(PG_URL_ENV) {
        Ok(u) if !u.trim().is_empty() => Some(u),
        _ => {
            eprintln!("SKIP forensic_outage_pg_4199: {PG_URL_ENV} unset");
            None
        }
    }
}

struct Sandbox {
    _root: tempfile::TempDir,
    home: PathBuf,
    keys: PathBuf,
    audit: PathBuf,
    db: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    tls_cert_pem: String,
}

fn mint_tls_leaf(dir: &Path) -> (PathBuf, PathBuf, String) {
    std::fs::create_dir_all(dir).expect("tls scratch dir");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("certificate params");
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    let cert = params.self_signed(&key).expect("self-signed leaf");
    let cert_pem = cert.pem();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).expect("write cert.pem");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key.pem");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 key.pem");
    }
    (cert_path, key_path, cert_pem)
}

fn sandbox() -> Sandbox {
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&scratch).expect("scratch root");
    let root = tempfile::tempdir_in(scratch).expect("isolated test directory");
    let home = root.path().join("home");
    let keys = root.path().join("keys");
    let audit = root.path().join("audit");
    std::fs::create_dir_all(home.join(".config")).expect("home");
    std::fs::create_dir_all(&keys).expect("keys");
    std::fs::create_dir_all(&audit).expect("audit");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("0700");
    }
    let db = root.path().join("sidecar.db");
    let (tls_cert, tls_key, tls_cert_pem) = mint_tls_leaf(&root.path().join("tls"));
    Sandbox {
        _root: root,
        home,
        keys,
        audit,
        db,
        tls_cert,
        tls_key,
        tls_cert_pem,
    }
}

struct Daemon {
    child: Child,
    stderr: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl Daemon {
    fn stderr_text(&self) -> String {
        let buf = self.stderr.lock().map(|b| b.clone()).unwrap_or_default();
        String::from_utf8_lossy(&buf).into_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Boot a postgres-backed daemon over TLS and wait for `/health`.
fn serve(sb: &Sandbox, url: &str) -> Daemon {
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &sb.home)
        .env("XDG_CONFIG_HOME", sb.home.join(".config"))
        .env("AI_MEMORY_KEY_DIR", &sb.keys)
        .env("AI_MEMORY_AUDIT_DIR", &sb.audit)
        .env("AI_MEMORY_DB", &sb.db)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_STORE_URL", url)
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .args(["serve", "--port", &port.to_string(), "--tls-cert"])
        .arg(&sb.tls_cert)
        .arg("--tls-key")
        .arg(&sb.tls_key)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    if let Some(mut pipe) = child.stderr.take() {
        let sink = std::sync::Arc::clone(&sink);
        std::thread::spawn(move || {
            use std::io::Read as _;
            let mut chunk = [0u8; 8192];
            while let Ok(n) = pipe.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if let Ok(mut b) = sink.lock() {
                    b.extend_from_slice(&chunk[..n]);
                }
            }
        });
    }
    let mut daemon = Daemon {
        child,
        stderr: sink,
    };
    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(sb.tls_cert_pem.as_bytes()).expect("parse leaf PEM"),
        )
        .timeout(Duration::from_secs(2))
        .build()
        .expect("trusting client");
    let health = format!("https://127.0.0.1:{port}/api/v1/health");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(resp) = client.get(&health).send()
            && resp.status().is_success()
        {
            return daemon;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            std::thread::sleep(Duration::from_millis(200));
            panic!(
                "serve exited before /health ({status}): {}",
                daemon.stderr_text()
            );
        }
        assert!(
            Instant::now() < deadline,
            "serve never became healthy within 60 s: {}",
            daemon.stderr_text()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn outage_rows(rt: &tokio::runtime::Runtime, url: &str) -> i64 {
    rt.block_on(async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .expect("pg pool");
        // A fresh lane database has no chain before the first boot bootstraps
        // the schema: that is zero rows, not an error.
        let exists: bool = sqlx::query_scalar("SELECT to_regclass('signed_events') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("probe signed_events");
        if !exists {
            return 0;
        }
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM signed_events WHERE event_type = $1")
            .bind(OUTAGE_EVENT)
            .fetch_one(&pool)
            .await
            .expect("count outage rows")
    })
}

#[test]
fn pg_serve_attests_a_forensic_outage_once_in_postgres_4199() {
    let Some(url) = pg_url() else { return };
    let sb = sandbox();
    // No file holds a parseable row: the tail cannot be established.
    std::fs::write(
        sb.audit.join("forensic-2026-01-01.jsonl"),
        b"not a forensic row\n",
    )
    .expect("plant an unparseable forensic file");
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let before = outage_rows(&rt, &url);

    let first = serve(&sb, &url);
    let err = first.stderr_text();
    drop(first);
    assert!(
        err.contains("WITHOUT the forensic audit sink"),
        "stderr: {err}"
    );
    assert_eq!(
        outage_rows(&rt, &url),
        before + 1,
        "one signed outage row in the POSTGRES chain; stderr: {err}"
    );
    assert!(err.contains(DEFERRED_NOTE), "stderr: {err}");

    // A second boot on the same (day, path, cause) adds none.
    let second = serve(&sb, &url);
    drop(second);
    assert_eq!(outage_rows(&rt, &url), before + 1, "dedupe across boots");

    // Nothing was written into a local sqlite store in its place.
    assert!(
        !sb.db.exists()
            || rusqlite::Connection::open(&sb.db)
                .and_then(|c| {
                    c.query_row(
                        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                        [OUTAGE_EVENT],
                        |r| r.get::<_, i64>(0),
                    )
                })
                .map_or(true, |n| n == 0),
        "no outage row in a local sqlite store"
    );
}
