// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4915 / #4820 — `ai-memory quarantine` and `ai-memory
//! recover-previous-session` must route on the SAME store-URL channel ladder
//! that `serve`, `schema-init` and `curator` use (`AI_MEMORY_STORE_URL_FILE` >
//! `AI_MEMORY_STORE_URL` > `--store-url`, `src/store_url.rs`
//! `resolve_store_url`). Before the fix both read `--store-url` from argv
//! only, so a unit that carries a Postgres URL in its `EnvironmentFile` (the
//! sanctioned non-argv channel, #4600 / #4603) silently operated the local
//! sqlite file and exited 0: a quarantine release or a session recovery
//! against a store the operator did not name.
//!
//! The Postgres URL below points at a closed port, so the fixed binary
//! attempts the configured store and fails closed (non-zero exit), while the
//! carrier exits 0 on the local sqlite file. The password never reaches the
//! output on either path.
//!
//! Red on e4285449b: every `*_routes_to_the_configured_store` test fails
//! (exit 0, local sqlite).

#![cfg(unix)]
#![allow(clippy::zombie_processes)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

const PW: &str = "pw4915canary";

fn pg_url() -> String {
    format!("postgres://aimemory:{PW}@127.0.0.1:1/aimemory?sslmode=verify-full")
}

/// `ai-memory --db <sidecar> <args...>` with every store-URL channel scrubbed
/// so the host environment cannot leak into the test.
fn ai_memory(sidecar: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .env_remove("AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS")
        .env_remove("AI_MEMORY_DB")
        .args(["--db", sidecar.to_str().unwrap()])
        .args(args);
    cmd
}

fn write_url_file(dir: &Path, url: &str, mode: u32) -> std::path::PathBuf {
    let p = dir.join("store-url");
    std::fs::write(&p, format!("{url}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    p
}

/// Run `cmd` and assert it REFUSED to fall back to the local sqlite file:
/// non-zero exit, and the password is absent from stdout and stderr.
fn assert_fails_closed_without_echo(cmd: &mut Command, what: &str) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "{what}: exited 0, so it operated the local sqlite file instead of the \
         configured store.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains(PW) && !stderr.contains(PW),
        "{what}: password echoed"
    );
}

const QUARANTINE_LIST: &[&str] = &["quarantine", "list"];

#[test]
fn quarantine_4915_no_channel_keeps_the_local_sqlite_file() {
    let dir = TempDir::new().unwrap();
    ai_memory(&dir.path().join("sidecar.db"), QUARANTINE_LIST)
        .assert()
        .success();
}

#[test]
fn quarantine_4915_env_channel_routes_to_the_configured_store() {
    let dir = TempDir::new().unwrap();
    let mut cmd = ai_memory(&dir.path().join("sidecar.db"), QUARANTINE_LIST);
    cmd.env("AI_MEMORY_STORE_URL", pg_url());
    assert_fails_closed_without_echo(&mut cmd, "quarantine (env channel)");
}

#[test]
fn quarantine_4915_file_channel_routes_to_the_configured_store() {
    let dir = TempDir::new().unwrap();
    let f = write_url_file(dir.path(), &pg_url(), 0o600);
    let mut cmd = ai_memory(&dir.path().join("sidecar.db"), QUARANTINE_LIST);
    cmd.env("AI_MEMORY_STORE_URL_FILE", &f);
    assert_fails_closed_without_echo(&mut cmd, "quarantine (file channel)");
}

#[test]
fn quarantine_4915_lax_file_channel_fails_closed() {
    let dir = TempDir::new().unwrap();
    let f = write_url_file(dir.path(), &pg_url(), 0o644);
    let mut cmd = ai_memory(&dir.path().join("sidecar.db"), QUARANTINE_LIST);
    cmd.env("AI_MEMORY_STORE_URL_FILE", &f);
    assert_fails_closed_without_echo(&mut cmd, "quarantine (0644 file channel)");
}

/// `recover-previous-session` keeps its graceful sqlite fallback on a build
/// without `sal` (the `SessionStart` hook must not wedge), so the routing proof
/// runs on `sal` builds, where the store-backed arm exists.
#[cfg(feature = "sal")]
const RECOVER: &[&str] = &["recover-previous-session", "--dry-run", "--quiet"];

#[cfg(feature = "sal")]
#[test]
fn recover_4915_no_channel_keeps_the_local_sqlite_file() {
    let dir = TempDir::new().unwrap();
    ai_memory(&dir.path().join("sidecar.db"), RECOVER)
        .env("HOME", dir.path())
        .assert()
        .success();
}

#[cfg(feature = "sal")]
#[test]
fn recover_4915_env_channel_routes_to_the_configured_store() {
    let dir = TempDir::new().unwrap();
    let mut cmd = ai_memory(&dir.path().join("sidecar.db"), RECOVER);
    cmd.env("HOME", dir.path())
        .env("AI_MEMORY_STORE_URL", pg_url());
    assert_fails_closed_without_echo(&mut cmd, "recover-previous-session (env channel)");
}

#[cfg(feature = "sal")]
#[test]
fn recover_4915_file_channel_routes_to_the_configured_store() {
    let dir = TempDir::new().unwrap();
    let f = write_url_file(dir.path(), &pg_url(), 0o600);
    let mut cmd = ai_memory(&dir.path().join("sidecar.db"), RECOVER);
    cmd.env("HOME", dir.path())
        .env("AI_MEMORY_STORE_URL_FILE", &f);
    assert_fails_closed_without_echo(&mut cmd, "recover-previous-session (file channel)");
}

/// #5290 — the recover path refuses a group/world-readable store-URL file, and
/// the refusal comes from the channel permission check itself (the message
/// names the lax permissions), not from some unrelated failure.
#[cfg(feature = "sal")]
#[test]
fn recover_5290_lax_file_channel_fails_closed_with_the_permission_refusal() {
    let dir = TempDir::new().unwrap();
    let f = write_url_file(dir.path(), &pg_url(), 0o644);
    let out = ai_memory(&dir.path().join("sidecar.db"), RECOVER)
        .env("HOME", dir.path())
        .env("AI_MEMORY_STORE_URL_FILE", &f)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a 0644 URL file must be refused.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("lax permissions"),
        "refusal must come from the store-URL file permission check; stderr: {stderr}"
    );
    assert!(
        !stdout.contains(PW) && !stderr.contains(PW),
        "password echoed"
    );
}
