// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4600 (CWE-214) — `ai-memory schema-init` takes its store URL from the same
//! non-argv channels `serve` has (`AI_MEMORY_STORE_URL_FILE`, then
//! `AI_MEMORY_STORE_URL`, then `--store-url`; `src/store_url.rs`
//! `resolve_store_url`), so a password-bearing Postgres URL never has to sit on
//! `/proc/<pid>/cmdline`. The channel logic is backend-agnostic (it runs before
//! the scheme dispatch), so the channels are proven here against a sqlite
//! target, which needs no live server; the Postgres dispatch itself is covered
//! by `tests/cli_schema_init.rs` / `tests/pgvector_preflight_3264.rs`.
//!
//! Red on the carrier: `--store-url` was a required argv string, so every
//! channel-only invocation below exited 2 (clap "required argument") instead of 0.

#![cfg(feature = "sal")]
#![cfg(unix)]
#![allow(clippy::zombie_processes)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

/// `ai-memory --db <tmp> schema-init --json` with every store-URL channel
/// scrubbed so the host environment cannot leak into the test.
fn schema_init(main_db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .env_remove("AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS")
        .args(["--db", main_db.to_str().unwrap(), "schema-init", "--json"]);
    cmd
}

fn sqlite_url(dir: &Path, name: &str) -> String {
    format!("sqlite://{}", dir.join(name).to_string_lossy())
}

fn write_url_file(dir: &Path, name: &str, url: &str, mode: u32) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("{url}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    p
}

#[test]
fn schema_init_4600_file_channel_without_flag_succeeds() {
    let tmp = TempDir::new().unwrap();
    let url = sqlite_url(tmp.path(), "via-file.db");
    let f = write_url_file(tmp.path(), "store-url", &url, 0o600);
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL_FILE", &f)
        .assert()
        .success();
    assert!(
        tmp.path().join("via-file.db").exists(),
        "file channel target not created"
    );
}

#[test]
fn schema_init_4600_env_channel_without_flag_succeeds() {
    let tmp = TempDir::new().unwrap();
    let url = sqlite_url(tmp.path(), "via-env.db");
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL", &url)
        .assert()
        .success();
    assert!(
        tmp.path().join("via-env.db").exists(),
        "env channel target not created"
    );
}

#[test]
fn schema_init_4600_precedence_file_then_env_and_flag_alone() {
    let tmp = TempDir::new().unwrap();
    let file_url = sqlite_url(tmp.path(), "p-file.db");
    let env_url = sqlite_url(tmp.path(), "p-env.db");
    let flag_url = sqlite_url(tmp.path(), "p-flag.db");
    let f = write_url_file(tmp.path(), "store-url", &file_url, 0o600);
    // FILE beats ENV (the two non-argv channels; no flag involved).
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL_FILE", &f)
        .env("AI_MEMORY_STORE_URL", &env_url)
        .assert()
        .success();
    assert!(tmp.path().join("p-file.db").exists());
    assert!(!tmp.path().join("p-env.db").exists());
    // The flag still works alone (unchanged argv form).
    schema_init(&tmp.path().join("main.db"))
        .args(["--store-url", &flag_url])
        .assert()
        .success();
    assert!(tmp.path().join("p-flag.db").exists());
}

/// #4611: the winning env/file channel is named at info (never the URL's
/// password), so an operator can see which channel bound the store.
#[test]
fn schema_init_4611_winning_channel_is_logged_without_the_secret() {
    let tmp = TempDir::new().unwrap();
    let url = sqlite_url(tmp.path(), "l-file.db");
    let f = write_url_file(tmp.path(), "store-url", &url, 0o600);
    let out = schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL_FILE", &f)
        .env("RUST_LOG", "info")
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();
    let err = String::from_utf8_lossy(&out);
    assert!(
        err.contains("store URL taken from AI_MEMORY_STORE_URL_FILE"),
        "the winning channel must be logged; stderr: {err}"
    );
}

/// #4611: a `--store-url` that DISAGREES with a set env/file channel is
/// refused (it used to be silently dropped in favour of the channel), and the
/// refusal creates neither store. An equal URL is accepted.
#[test]
fn schema_init_4611_flag_disagreeing_with_a_channel_is_refused() {
    let tmp = TempDir::new().unwrap();
    let file_url = sqlite_url(tmp.path(), "r-file.db");
    let env_url = sqlite_url(tmp.path(), "r-env.db");
    let flag_url = sqlite_url(tmp.path(), "r-flag.db");
    let f = write_url_file(tmp.path(), "store-url", &file_url, 0o600);
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL_FILE", &f)
        .args(["--store-url", &flag_url])
        .assert()
        .failure()
        .stderr(predicates::str::contains("ambiguous store"));
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL", &env_url)
        .args(["--store-url", &flag_url])
        .assert()
        .failure()
        .stderr(predicates::str::contains("ambiguous store"));
    for n in ["r-file.db", "r-env.db", "r-flag.db"] {
        assert!(!tmp.path().join(n).exists(), "{n} must not be created");
    }
    // Same URL on both channels is not ambiguous.
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL", &flag_url)
        .args(["--store-url", &flag_url])
        .assert()
        .success();
    assert!(tmp.path().join("r-flag.db").exists());
}

#[test]
fn schema_init_4600_group_or_world_readable_file_refused() {
    for mode in [0o640_u32, 0o604, 0o644] {
        let tmp = TempDir::new().unwrap();
        let url = sqlite_url(tmp.path(), "lax.db");
        let f = write_url_file(tmp.path(), "store-url", &url, mode);
        let out = schema_init(&tmp.path().join("main.db"))
            .env("AI_MEMORY_STORE_URL_FILE", &f)
            .assert()
            .failure()
            .get_output()
            .stderr
            .clone();
        let err = String::from_utf8_lossy(&out);
        assert!(
            err.contains("lax permissions"),
            "mode {mode:o}: stderr was {err}"
        );
        assert!(
            !tmp.path().join("lax.db").exists(),
            "mode {mode:o}: store opened despite refusal"
        );
    }
}

#[test]
fn schema_init_4600_no_channel_fails_closed_without_echoing_a_url() {
    let tmp = TempDir::new().unwrap();
    let out = schema_init(&tmp.path().join("main.db"))
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let err = String::from_utf8_lossy(&out);
    assert!(err.contains("no store URL"), "stderr was {err}");
}

#[test]
fn schema_init_4600_empty_file_refused() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("store-url");
    std::fs::write(&p, "\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL_FILE", &p)
        .assert()
        .failure();
}
