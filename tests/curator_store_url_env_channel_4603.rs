// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4603 — the curator must route on the SAME store-URL channel ladder that
//! binds its store (`AI_MEMORY_STORE_URL_FILE` > `AI_MEMORY_STORE_URL` >
//! `--store-url`, `src/store_url.rs` `resolve_store_url`). The deploy units
//! rendered by PR #4782 carry the URL only in the `EnvironmentFile`; before this
//! fix `curator_store_url` read argv only, so an env-only unit silently ran the
//! conn-bound sqlite daemon against the local sidecar instead of the
//! store-backed (SAL) sweep against the configured store.
//!
//! The routing check is scheme-independent, so it is proven against a sqlite
//! store URL (no live server). The marker is the store-backed sweep's
//! "reflection pass report" line, which the conn-bound daemon never prints.
//!
//! Red on 242505447 and on e4285449b: `env_channel_routes_to_store_backed_sweep` and
//! `file_channel_routes_to_store_backed_sweep` fail (no report line).

#![cfg(feature = "sal")]
#![cfg(unix)]
#![allow(clippy::zombie_processes)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

const MARKER: &str = "reflection pass report";

/// `ai-memory --db <sidecar> curator --once --dry-run` with every store-URL
/// channel scrubbed so the host environment cannot leak into the test.
fn curator(sidecar: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .env_remove("AI_MEMORY_DB")
        .args([
            "--db",
            sidecar.to_str().unwrap(),
            "curator",
            "--once",
            "--dry-run",
        ]);
    cmd
}

fn stdout_of(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "curator exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn no_channel_keeps_the_conn_bound_sqlite_daemon() {
    let dir = TempDir::new().unwrap();
    let s = stdout_of(&mut curator(&dir.path().join("sidecar.db")));
    assert!(
        !s.contains(MARKER),
        "no store URL must keep the sqlite daemon: {s}"
    );
}

#[test]
fn env_channel_routes_to_store_backed_sweep() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("store.db");
    let mut cmd = curator(&dir.path().join("sidecar.db"));
    cmd.env(
        "AI_MEMORY_STORE_URL",
        format!("sqlite://{}", store.display()),
    );
    let s = stdout_of(&mut cmd);
    assert!(
        s.contains(MARKER),
        "env-only store URL must select the store-backed sweep: {s}"
    );
}

#[test]
fn file_channel_routes_to_store_backed_sweep() {
    let dir = TempDir::new().unwrap();
    let store = dir.path().join("store.db");
    let url_file = dir.path().join("store-url");
    std::fs::write(&url_file, format!("sqlite://{}\n", store.display())).unwrap();
    std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut cmd = curator(&dir.path().join("sidecar.db"));
    cmd.env("AI_MEMORY_STORE_URL_FILE", &url_file);
    let s = stdout_of(&mut cmd);
    assert!(
        s.contains(MARKER),
        "file-only store URL must select the store-backed sweep: {s}"
    );
}

#[test]
fn lax_file_channel_fails_closed() {
    let dir = TempDir::new().unwrap();
    let url_file = dir.path().join("store-url");
    std::fs::write(&url_file, "sqlite:///nonexistent/x.db\n").unwrap();
    std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = curator(&dir.path().join("sidecar.db"))
        .env("AI_MEMORY_STORE_URL_FILE", &url_file)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a group/world-readable URL file must be refused"
    );
}
