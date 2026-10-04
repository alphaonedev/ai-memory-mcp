// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4939 — `ai-memory schema-init` and `ai-memory migrate` must install the
//! console tracing subscriber (stderr only), so the warnings and channel log
//! lines their bodies emit reach the operator:
//!
//! * the #1927 "--store-url carries a password in argv" warning from
//!   `src/store_url.rs::resolve_store_url`;
//! * the #4782 F8 info line naming which store-URL channel won (never the
//!   value);
//! * any `tracing` diagnostic of the migrate body (proved here with the
//!   logging funnel's own rejected-directive warning).
//!
//! The subscriber writes to stderr only, so `--json` stdout stays a single
//! machine-readable document.
//!
//! Red on e4285449b: neither command installs a subscriber, so every
//! assertion on stderr content below fails (stderr carries no log line).

#![cfg(feature = "sal")]
#![cfg(unix)]

use std::path::Path;
use std::process::Output;

use assert_cmd::Command;
use tempfile::TempDir;

const PW: &str = "pw4939canary";

/// `ai-memory --db <sidecar> <args...>` with every store-URL channel and the
/// host log configuration scrubbed so the environment cannot leak in.
fn ai_memory(sidecar: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .env_remove("AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS")
        .env_remove("AI_MEMORY_DB")
        .env_remove("RUST_LOG")
        .args(["--db", sidecar.to_str().unwrap()])
        .args(args);
    cmd
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn assert_stdout_has_no_log_line(out: &Output, what: &str) {
    let stdout = text(&out.stdout);
    for level in [" WARN ", " INFO ", " ERROR "] {
        assert!(
            !stdout.contains(level),
            "{what}: a log line reached stdout (the subscriber must write to stderr only)\n{stdout}"
        );
    }
}

#[test]
fn schema_init_4939_argv_password_warning_reaches_stderr() {
    let dir = TempDir::new().unwrap();
    let url = format!("postgres://aimemory:{PW}@127.0.0.1:1/aimemory?sslmode=verify-full");
    let out = ai_memory(
        &dir.path().join("sidecar.db"),
        &["schema-init", "--store-url", &url, "--json"],
    )
    .output()
    .unwrap();
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("--store-url carries a password in argv"),
        "the #1927 argv-password warning must reach stderr\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains(PW) && !stderr.contains(PW),
        "password echoed\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_stdout_has_no_log_line(&out, "schema-init");
}

#[test]
fn schema_init_4939_winning_channel_is_logged_without_the_value() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("target-4939.db");
    let url = format!("sqlite://{}", target.to_string_lossy());
    let out = ai_memory(&dir.path().join("sidecar.db"), &["schema-init", "--json"])
        .env("AI_MEMORY_STORE_URL", &url)
        .output()
        .unwrap();
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("store URL resolved") && stderr.contains("AI_MEMORY_STORE_URL"),
        "the winning store-URL channel must be logged on stderr\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("target-4939.db"),
        "the channel log must never carry the URL value\nstderr: {stderr}"
    );
    assert_stdout_has_no_log_line(&out, "schema-init --json");
    serde_json::from_str::<serde_json::Value>(&stdout).unwrap_or_else(|e| {
        panic!("schema-init --json stdout is not one JSON document ({e}): {stdout}")
    });
}

#[test]
fn migrate_4939_diagnostics_reach_stderr_and_json_stdout_stays_clean() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    let _ = ai_memory::db::open(&src).unwrap();
    let _ = ai_memory::db::open(&dst).unwrap();
    let from = format!("sqlite://{}", src.to_string_lossy());
    let to = format!("sqlite://{}", dst.to_string_lossy());
    let out = ai_memory(
        &dir.path().join("sidecar.db"),
        &["migrate", "--from", &from, "--to", &to, "--json"],
    )
    .env("RUST_LOG", "info,ai_memory=notalevel4939")
    .output()
    .unwrap();
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("ignoring unparseable log directive"),
        "migrate must install the console subscriber, so its diagnostics reach stderr\nstderr: {stderr}"
    );
    assert_stdout_has_no_log_line(&out, "migrate --json");
    serde_json::from_str::<serde_json::Value>(&stdout).unwrap_or_else(|e| {
        panic!("migrate --json stdout is not one JSON document ({e}): {stdout}")
    });
}
