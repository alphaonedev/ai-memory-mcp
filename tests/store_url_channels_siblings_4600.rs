// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4600 sibling sweep (Class A, credential-argv): every subcommand that can
//! open the SAL store honours the same store-URL channels `serve` does
//! (`AI_MEMORY_STORE_URL_FILE` > `AI_MEMORY_STORE_URL` > `--store-url`,
//! `src/store_url.rs` `resolve_store_url`) with the same refusal rules (a
//! group/world-readable URL file is refused).
//!
//! Siblings covered here: `quarantine` and `recover-previous-session`. On the
//! carrier both matched on the raw `--store-url` flag only, so a Postgres URL
//! held in a 0600 file was silently ignored and the verb ran against the local
//! SQLite `--db` instead — the operator had to put the password on argv to
//! reach the store they meant.
//!
//! The table is subcommand x channel. The Postgres endpoint is a raw recording
//! listener, so "routed to Postgres" is observed as a TCP connect without a
//! live server.

#![cfg(feature = "sal")]
#![cfg(unix)]

#[path = "common/recording_listener.rs"]
mod recording_listener;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use recording_listener::RecordingListener;

/// Obvious fixture password; must never be printed.
const FIXTURE_PASSWORD: &str = "fixture-pass-4600";
const STORE_URL_ENV: &str = "AI_MEMORY_STORE_URL";
const STORE_URL_FILE_ENV: &str = "AI_MEMORY_STORE_URL_FILE";
const LAX_OPT_OUT_ENV: &str = "AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS";

/// Every store-opening sibling verb, as argv after `--db <db>`.
const VERBS: [&[&str]; 2] = [
    &["quarantine", "list"],
    &["recover-previous-session", "--json"],
];

#[derive(Clone, Copy, Debug)]
enum Channel {
    /// `AI_MEMORY_STORE_URL_FILE` -> a 0600 file.
    File,
    /// `AI_MEMORY_STORE_URL`.
    Env,
    /// `--store-url` (the control: always worked).
    Flag,
}

const CHANNELS: [Channel; 3] = [Channel::File, Channel::Env, Channel::Flag];

fn scratch(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("store-url-siblings-4600-{tag}-"))
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("scratch dir under CARGO_TARGET_TMPDIR")
}

fn pg_url(listener: &RecordingListener) -> String {
    format!(
        "postgres://fixture_user:{FIXTURE_PASSWORD}@{}/fixture_db?sslmode=disable",
        listener.addr()
    )
}

fn write_url_file(dir: &Path, url: &str, mode: u32) -> PathBuf {
    let path = dir.join("store-url");
    std::fs::write(&path, format!("{url}\n")).expect("write url file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod url file");
    path
}

/// Run `ai-memory --db <dir>/main.db <verb...>` with the given extra argv and
/// env; every store-URL channel not named is scrubbed.
fn run(dir: &Path, verb: &[&str], extra_args: &[&str], env: &[(&str, &str)]) -> Output {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("scratch home");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .arg("--db")
        .arg(dir.join("main.db"))
        .args(verb)
        .args(extra_args)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env_remove(STORE_URL_ENV)
        .env_remove(STORE_URL_FILE_ENV)
        .env_remove(LAX_OPT_OUT_ENV);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn ai-memory")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// What the binary must do once a Postgres URL is resolved: under `sal` only
/// it refuses with the exact feature message (it never falls back to the
/// local SQLite file); under `sal-postgres` it connects to the endpoint.
fn assert_routed_to_postgres(out: &Output, listener: &RecordingListener, label: &str) {
    assert!(
        !out.status.success(),
        "#4600 {label}: a resolved Postgres URL must not fall back to local SQLite (exit 0); stderr: {}",
        stderr(out)
    );
    #[cfg(not(feature = "sal-postgres"))]
    {
        let _ = listener;
        assert!(
            stderr(out).contains(
                "--store-url postgres:// requires the binary to be built with --features sal-postgres"
            ),
            "#4600 {label}: exact sal-only refusal; stderr: {}",
            stderr(out)
        );
    }
    #[cfg(feature = "sal-postgres")]
    assert!(
        listener.connections() >= 1,
        "#4600 {label}: the Postgres endpoint must be dialled; stderr: {}",
        stderr(out)
    );
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(out));
    assert!(
        !all.contains(FIXTURE_PASSWORD),
        "#4600 {label}: the password must never be printed"
    );
}

#[test]
fn every_sibling_routes_every_channel_to_the_configured_store_4600() {
    for verb in VERBS {
        for channel in CHANNELS {
            let listener = RecordingListener::start(None);
            let dir = scratch("route");
            let url = pg_url(&listener);
            let label = format!("{verb:?}/{channel:?}");
            let out = match channel {
                Channel::File => {
                    let f = write_url_file(dir.path(), &url, 0o600);
                    let f = f.to_string_lossy().into_owned();
                    run(dir.path(), verb, &[], &[(STORE_URL_FILE_ENV, &f)])
                }
                Channel::Env => run(dir.path(), verb, &[], &[(STORE_URL_ENV, &url)]),
                Channel::Flag => run(dir.path(), verb, &["--store-url", &url], &[]),
            };
            assert_routed_to_postgres(&out, &listener, &label);
        }
    }
}

#[test]
fn every_sibling_refuses_a_lax_store_url_file_4600() {
    for verb in VERBS {
        let listener = RecordingListener::start(None);
        let dir = scratch("lax");
        let f = write_url_file(dir.path(), &pg_url(&listener), 0o644);
        let fs = f.to_string_lossy().into_owned();
        let out = run(dir.path(), verb, &[], &[(STORE_URL_FILE_ENV, &fs)]);
        assert!(
            !out.status.success(),
            "#4600 {verb:?}: lax file must be refused"
        );
        let expected = format!(
            "store-url file {} has lax permissions (mode 644, group/world bits set)",
            f.display()
        );
        assert!(
            stderr(&out).contains(&expected),
            "#4600 {verb:?}: exact lax-permission refusal; stderr: {}",
            stderr(&out)
        );
        assert_eq!(
            listener.connections(),
            0,
            "#4600 {verb:?}: a refused URL file opens no connection"
        );
        assert!(!stderr(&out).contains(FIXTURE_PASSWORD));
    }
}

#[test]
fn every_sibling_refuses_an_empty_store_url_file_4600() {
    for verb in VERBS {
        let dir = scratch("empty");
        let f = write_url_file(dir.path(), "", 0o600);
        std::fs::write(&f, b"").expect("truncate url file");
        let fs = f.to_string_lossy().into_owned();
        let out = run(dir.path(), verb, &[], &[(STORE_URL_FILE_ENV, &fs)]);
        assert!(
            !out.status.success(),
            "#4600 {verb:?}: empty file must be refused"
        );
        assert!(
            stderr(&out).contains(&format!("store-url file {} is empty", f.display())),
            "#4600 {verb:?}: exact empty-file refusal; stderr: {}",
            stderr(&out)
        );
    }
}

#[test]
fn file_channel_wins_over_a_flag_4600() {
    // Precedence parity with `serve`: FILE > ENV > flag. A sqlite flag with a
    // Postgres file must reach Postgres.
    for verb in VERBS {
        let listener = RecordingListener::start(None);
        let dir = scratch("precedence");
        let f = write_url_file(dir.path(), &pg_url(&listener), 0o600);
        let fs = f.to_string_lossy().into_owned();
        let flag = format!("sqlite://{}", dir.path().join("flag.db").display());
        let out = run(
            dir.path(),
            verb,
            &["--store-url", &flag],
            &[(STORE_URL_FILE_ENV, &fs)],
        );
        assert_routed_to_postgres(&out, &listener, &format!("{verb:?}/precedence"));
    }
}

#[test]
fn no_channel_still_runs_on_local_sqlite_4600() {
    for verb in VERBS {
        let dir = scratch("none");
        let out = run(dir.path(), verb, &[], &[]);
        assert!(
            out.status.success(),
            "#4600 {verb:?}: no store channel keeps the local sqlite default; stderr: {}",
            stderr(&out)
        );
    }
}
