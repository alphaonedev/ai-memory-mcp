// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v1.0.0 #2679 — `ai-memory serve` must FAIL CLOSED on a postgres:// store
//! URL when the binary cannot open Postgres.
//!
//! # The defect these tests pin
//!
//! Before #2679, the default (sqlite-only) build ignored
//! `AI_MEMORY_STORE_URL=postgres://…` entirely. `serve` opened the local
//! `--db` SQLite path (creating the file + WAL if absent), logged
//! `database: <path>`, and reported healthy — while the operator believed
//! agent memory was landing in Postgres. The argv `--store-url` channel
//! fails loud via clap (flag is `#[cfg(feature = "sal")]`); the env and
//! file channels failed silent.
//!
//! # Why these tests drive the BINARY
//!
//! R-203: the regression must FAIL against the parent commit and PASS after.
//! Spawning the real binary through the env channel that already shipped
//! (#1927) keeps the test source valid at the parent (no new struct fields)
//! and keeps `AI_MEMORY_*` mutations out of the test process.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use tempfile::TempDir;

const PG_STORE_URL: &str = "postgres://ai_memory:hunter2@127.0.0.1:5432/ai_memory";
const PG_PASSWORD: &str = "hunter2";

/// Spawn `ai-memory serve` with a short timeout. On success the daemon would
/// listen forever; on the #2679 refuse path it exits non-zero quickly.
fn serve_once(db: &Path, store_url: Option<&str>) -> std::process::Output {
    let mut cmd = Command::new(cargo_bin("ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .args([
            "--db",
            db.to_str().expect("utf-8 db path"),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0", // may not be valid — use high ephemeral
        ]);
    // Port 0 may be rejected by clap as invalid; use a high unused port.
    // Override port after — rewrite args properly:
    let _ = cmd;
    let mut cmd = Command::new(cargo_bin("ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .args([
            "--db",
            db.to_str().expect("utf-8 db path"),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "19391",
        ]);
    if let Some(url) = store_url {
        cmd.env("AI_MEMORY_STORE_URL", url);
    }
    // Cap runtime: refuse path exits fast; accidental success would hang.
    // Use timeout(1) style via kill after wait_timeout if available; for
    // portability spawn and wait with a hard kill.
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn ai-memory serve");
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = {
                    let mut s = String::new();
                    if let Some(mut out) = child.stdout.take() {
                        use std::io::Read;
                        let _ = out.read_to_string(&mut s);
                    }
                    s
                };
                let stderr = {
                    let mut s = String::new();
                    if let Some(mut out) = child.stderr.take() {
                        use std::io::Read;
                        let _ = out.read_to_string(&mut s);
                    }
                    s
                };
                return std::process::Output {
                    status,
                    stdout: stdout.into_bytes(),
                    stderr: stderr.into_bytes(),
                };
            }
            Ok(None) if start.elapsed() > Duration::from_secs(8) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("serve still running after 8s — #2679 refuse did not fire");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("try_wait: {e}"),
        }
    }
}

#[test]
fn serve_refuses_postgres_store_url_env_without_creating_sqlite() {
    // Default (no sal-postgres) CI builds exercise the refuse path.
    // sal-postgres builds skip — the URL is legitimate there and serve
    // would try to connect (and hang/fail for a different reason).
    if cfg!(feature = "sal-postgres") {
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("must-not-be-created.db");
    assert!(!db.exists());

    let output = serve_once(&db, Some(PG_STORE_URL));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}\n{stdout}");

    assert!(
        !output.status.success(),
        "serve must exit non-zero on postgres:// without sal-postgres; status={:?} out={combined}",
        output.status
    );
    assert!(
        combined.contains("#2679")
            || combined.contains("sal-postgres")
            || combined.contains("Postgres"),
        "refusal must name the defect: {combined}"
    );
    assert!(
        !combined.contains(PG_PASSWORD),
        "refusal must redact password: {combined}"
    );
    // The silent-wrong-store signature: a conjured SQLite file + WAL.
    assert!(
        !db.exists(),
        "must not create the local sqlite db after refusing postgres:// (#2679)"
    );
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    assert!(
        !wal.exists(),
        "must not create a WAL for a refused wrong-store boot (#2679)"
    );
}

#[test]
fn serve_without_store_url_still_starts_sqlite_path_smoke() {
    // Smoke: no store URL → serve still boots on sqlite (then we kill it).
    // This guards against the refuse path over-firing on legitimate boots.
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("ok.db");

    let mut cmd = Command::new(cargo_bin("ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .args([
            "--db",
            db.to_str().expect("utf-8"),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "19392",
        ]);
    let mut child = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    // Wait until the db file appears (boot progressed) or timeout.
    let start = std::time::Instant::now();
    let mut booted = false;
    while start.elapsed() < Duration::from_secs(15) {
        if db.exists() {
            booted = true;
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(mut e) = child.stderr.take() {
                use std::io::Read;
                let _ = e.read_to_string(&mut stderr);
            }
            panic!("serve exited early without creating db: {status:?} {stderr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        booted,
        "legitimate sqlite serve must create --db (#2679 over-refuse guard)"
    );
}
