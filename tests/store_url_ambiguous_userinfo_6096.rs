// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6096 (WP-SECRETS umbrella #6052) — a store DSN whose userinfo holds an
//! UNENCODED `/`, `?` or `#` must reach no display sink with any credential
//! byte. The WHATWG parser ends the authority at the delimiter and reads the
//! credential remainder as host / port / path; `store_url_display` used to
//! render exactly those. It now renders `scheme://<redacted-authority>`.
//!
//! Each cell plants the secret marker in one (delimiter, position) shape and
//! asserts by ABSENCE over the whole sink, the family idiom of
//! `credential_to_sink_3711.rs`.

#![cfg(feature = "sal")]

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::path::Path;

use tempfile::TempDir;

/// The credential marker every shape carries.
const MARKER: &str = "SECRET6096";

/// One DSN per (delimiter, position): leading-delimiter password,
/// numeric-prefix password, delimiter in the username.
fn ambiguous_dsns() -> Vec<String> {
    let mut out = Vec::new();
    for d in ['/', '?', '#'] {
        out.push(format!("postgres://svc:{d}{MARKER}pw@127.0.0.1:9/mem"));
        out.push(format!("postgres://svc:123{d}{MARKER}pw@127.0.0.1:9/mem"));
        out.push(format!("postgres://svc{d}{MARKER}user:pw@127.0.0.1:9/mem"));
    }
    out
}

fn assert_clean(sink: &str, what: &str, dsn: &str) {
    assert!(
        !sink.contains(MARKER),
        "#6096: credential bytes reached {what} for DSN shape {dsn:?}:\n{sink}"
    );
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("store-url-ambiguous-6096");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn run_bin(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (String, String) {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("scratch home");
    let keys = dir.join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .args(args)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("RUST_LOG", "trace");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn ai-memory");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn display_renderer_redacts_every_ambiguous_shape_6096() {
    for dsn in ambiguous_dsns() {
        let r = ai_memory::url_display::store_url_display(&dsn);
        assert_clean(&r, "store_url_display", &dsn);
        assert_eq!(r, "postgres://<redacted-authority>", "{dsn:?}");
    }
}

#[test]
fn well_formed_dsn_still_names_the_host_6096() {
    let r = ai_memory::url_display::store_url_display(&format!(
        "postgres://svc:%2F{MARKER}pw@127.0.0.1:9/mem?sslmode=verify-full"
    ));
    assert_eq!(r, "postgres://127.0.0.1:9/mem");
}

#[test]
fn migrate_sink_carries_no_ambiguous_credential_6096() {
    let dir = scratch("migrate");
    let src = dir.path().join("src.db");
    let _ = ai_memory::db::open(&src).expect("seed source");
    let from = format!("sqlite://{}", src.display());
    for dsn in ambiguous_dsns() {
        let (out, err) = run_bin(
            dir.path(),
            &["migrate", "--from", &from, "--to", &dsn, "--json"],
            &[],
        );
        assert_clean(&out, "migrate --json stdout", &dsn);
        assert_clean(&err, "migrate stderr", &dsn);
    }
}

#[test]
fn schema_init_sink_carries_no_ambiguous_credential_6096() {
    let dir = scratch("schema-init");
    for dsn in ambiguous_dsns() {
        let (out, err) = run_bin(
            dir.path(),
            &["schema-init", "--store-url", &dsn, "--json"],
            &[],
        );
        assert_clean(&out, "schema-init --json stdout", &dsn);
        assert_clean(&err, "schema-init stderr", &dsn);
    }
}

#[test]
fn boot_conflict_refusal_carries_no_ambiguous_credential_6096() {
    let dir = scratch("conflict");
    let db = dir.path().join("d.db");
    let db_s = db.display().to_string();
    for dsn in ambiguous_dsns() {
        let (out, err) = run_bin(
            dir.path(),
            &["--db", &db_s, "serve", "--store-url", &dsn, "--port", "0"],
            &[],
        );
        assert_clean(&out, "serve stdout", &dsn);
        assert_clean(&err, "serve stderr", &dsn);
    }
}

#[cfg(feature = "sal-postgres")]
#[test]
fn doctor_sink_carries_no_ambiguous_credential_6096() {
    let dir = scratch("doctor");
    let db = dir.path().join("d.db");
    let db_s = db.display().to_string();
    for dsn in ambiguous_dsns() {
        let (out, err) = run_bin(
            dir.path(),
            &["--db", &db_s, "doctor"],
            &[("AI_MEMORY_STORE_URL", dsn.as_str())],
        );
        assert_clean(&out, "doctor stdout", &dsn);
        assert_clean(&err, "doctor stderr", &dsn);
    }
}

/// The `FlooredConnectError` text (the `Parse` and `Refused` arms) is a
/// display sink too: it is what `PostgresStore::connect` surfaces.
#[cfg(feature = "sal-postgres")]
#[test]
fn floored_connect_error_carries_no_ambiguous_credential_6096() {
    for dsn in ambiguous_dsns() {
        match ai_memory::store::postgres::dsn::floored_connect_options(&dsn) {
            Ok(_) => {}
            Err(e) => assert_clean(&format!("{e} / {e:?}"), "FlooredConnectError", &dsn),
        }
    }
}
