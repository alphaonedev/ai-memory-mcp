// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4600 sibling sweep (Class A, credential-argv): every subcommand that can
//! open the SAL store honours the same store-URL channels `serve` does
//! (`AI_MEMORY_STORE_URL_FILE`, `AI_MEMORY_STORE_URL`, `--store-url`) with the
//! same refusal rules (a group/world-readable URL file is refused). These
//! one-shot writers resolve through `src/store_url_writer.rs` `resolve`:
//! any two SET channels (FILE, ENV, `--store-url`) that disagree are refused
//! by channel name before any connection (PR #9175 r1b, 3-agent vote
//! 71472661 A 3-0).
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

use ai_memory::store_url_writer::ARGV_CREDENTIAL_WARNING;
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
        // `--store-url` is an argument of the top verb (`quarantine
        // --store-url URL list`), so the extra args go right after verb[0].
        .args(&verb[..1])
        .args(extra_args)
        .args(&verb[1..])
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

const STORE_URL_FLAG: &str = "--store-url";

/// The ONE conflict refusal (3-agent vote 71472661, V-4): the two channel
/// names and a one-line remedy; never any part of a URL.
fn conflict_message(first: &str, second: &str) -> String {
    let unset = if second == STORE_URL_FLAG {
        first
    } else {
        second
    };
    format!(
        "refusing to open a store: {first} and {second} name different stores (#4600); unset \
         the channel you do not mean, for example `env -u {unset} ...`, and run again"
    )
}

/// What the binary must do once a Postgres URL is resolved: under `sal` only
/// it refuses with the exact feature message (it never falls back to the
/// local SQLite file); under `sal-postgres` the Postgres adapter takes it and
/// its #3705 TLS floor refuses the fixture's `sslmode=disable`.
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
    // Under `sal-postgres` the fixture URL (`sslmode=disable`) reaches the
    // Postgres adapter, whose #3705 TLS floor refuses it before any socket
    // opens: that refusal exists only on the Postgres path, so it proves the
    // resolved URL was routed there and not to the local SQLite file.
    #[cfg(feature = "sal-postgres")]
    {
        assert!(
            stderr(out).contains("#3705: refusing the PostgreSQL store DSN"),
            "#4600 {label}: exact Postgres-adapter refusal; stderr: {}",
            stderr(out)
        );
        assert_eq!(
            listener.connections(),
            0,
            "#4600 {label}: the TLS floor refuses before any dial"
        );
    }
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
            // #4600 (r1 C-L1) — these verbs install no console tracing
            // subscriber, so the argv-credential warning must reach stderr
            // directly, and only when the URL actually sat on argv.
            let warned = stderr(&out).contains(ARGV_CREDENTIAL_WARNING);
            assert_eq!(
                warned,
                matches!(channel, Channel::Flag),
                "#4600 {label}: argv-credential warning on stderr iff the flag carried the URL; stderr: {}",
                stderr(&out)
            );
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

/// #4600 (r1 C-M1 / S-L1) — a `--store-url` that differs from a set FILE or
/// ENV channel is refused naming the channel only (never a URL); the same
/// URL on both is accepted and routed. Replaces `file_channel_wins_over_a_flag_4600`,
/// which pinned the silent override (a sqlite flag with a Postgres file reached Postgres).
#[test]
fn every_sibling_refuses_a_flag_that_differs_from_a_channel_4600() {
    for verb in VERBS {
        for channel in [Channel::File, Channel::Env] {
            for same in [true, false] {
                let listener = RecordingListener::start(None);
                let dir = scratch("conflict");
                let url = pg_url(&listener);
                let label = format!("{verb:?}/{channel:?}/same={same}");
                let flag = if same {
                    url.clone()
                } else {
                    format!("sqlite://{}", dir.path().join("flag.db").display())
                };
                let (name, value) = match channel {
                    Channel::File => {
                        let f = write_url_file(dir.path(), &url, 0o600);
                        (STORE_URL_FILE_ENV, f.to_string_lossy().into_owned())
                    }
                    _ => (STORE_URL_ENV, url.clone()),
                };
                let out = run(dir.path(), verb, &["--store-url", &flag], &[(name, &value)]);
                if same {
                    assert_routed_to_postgres(&out, &listener, &label);
                    continue;
                }
                assert!(!out.status.success(), "#4600 {label}: must be refused");
                let expected = conflict_message(name, STORE_URL_FLAG);
                assert!(
                    stderr(&out).contains(&expected),
                    "#4600 {label}: exact conflict refusal; stderr: {}",
                    stderr(&out)
                );
                assert!(
                    !stderr(&out).contains("://"),
                    "#4600 {label}: no URL in the refusal"
                );
                assert!(!stderr(&out).contains(FIXTURE_PASSWORD));
                assert_eq!(
                    listener.connections(),
                    0,
                    "#4600 {label}: refused before any dial"
                );
                assert!(
                    !dir.path().join("flag.db").exists(),
                    "#4600 {label}: flag store written"
                );
            }
        }
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

/// #4600 class gap (3-agent vote 71472661, A 3-0) — FILE and ENV set to
/// different stores refuse on every sibling, with the flag absent and with it
/// present, before any dial; the pre-r1b funnel let FILE win silently.
#[test]
fn every_sibling_refuses_file_and_env_that_disagree_4600() {
    for verb in VERBS {
        for flag in [false, true] {
            let file_listener = RecordingListener::start(None);
            let env_listener = RecordingListener::start(None);
            let dir = scratch("file-env");
            let label = format!("{verb:?}/flag={flag}");
            let file_url = pg_url(&file_listener);
            let f = write_url_file(dir.path(), &file_url, 0o600);
            let fs = f.to_string_lossy().into_owned();
            let env_url = pg_url(&env_listener);
            let extra: Vec<&str> = if flag {
                vec![STORE_URL_FLAG, &file_url]
            } else {
                Vec::new()
            };
            let out = run(
                dir.path(),
                verb,
                &extra,
                &[(STORE_URL_FILE_ENV, &fs), (STORE_URL_ENV, &env_url)],
            );
            assert!(!out.status.success(), "#4600 {label}: must be refused");
            assert!(
                stderr(&out).contains(&conflict_message(STORE_URL_FILE_ENV, STORE_URL_ENV)),
                "#4600 {label}: exact conflict refusal; stderr: {}",
                stderr(&out)
            );
            assert!(!stderr(&out).contains("://"), "#4600 {label}: no URL");
            assert!(!stderr(&out).contains(FIXTURE_PASSWORD));
            assert_eq!(
                file_listener.connections() + env_listener.connections(),
                0,
                "#4600 {label}: refused before any dial"
            );
        }
    }
}

/// FILE and ENV naming the same store route to it on every sibling.
#[test]
fn every_sibling_routes_file_and_env_that_agree_4600() {
    for verb in VERBS {
        let listener = RecordingListener::start(None);
        let dir = scratch("file-env-same");
        let url = pg_url(&listener);
        let f = write_url_file(dir.path(), &url, 0o600);
        let fs = f.to_string_lossy().into_owned();
        let out = run(
            dir.path(),
            verb,
            &[],
            &[(STORE_URL_FILE_ENV, &fs), (STORE_URL_ENV, &url)],
        );
        assert_routed_to_postgres(&out, &listener, &format!("{verb:?}/agree"));
    }
}

/// 3-agent vote (71472661) V-2 — a SET but unreadable file channel refuses
/// on every sibling and never falls through to a usable ENV store.
#[test]
fn every_sibling_refuses_an_unreadable_file_channel_without_fallthrough_4600() {
    for verb in VERBS {
        let listener = RecordingListener::start(None);
        let dir = scratch("missing");
        let missing = dir.path().join("no-such-store-url");
        let ms = missing.to_string_lossy().into_owned();
        let url = pg_url(&listener);
        let out = run(
            dir.path(),
            verb,
            &[],
            &[(STORE_URL_FILE_ENV, &ms), (STORE_URL_ENV, &url)],
        );
        assert!(!out.status.success(), "#4600 {verb:?}: must be refused");
        assert!(
            stderr(&out).contains(&format!("reading store-url file {}", missing.display())),
            "#4600 {verb:?}: exact read error; stderr: {}",
            stderr(&out)
        );
        assert_eq!(
            listener.connections(),
            0,
            "#4600 {verb:?}: fell through to ENV"
        );
    }
}
