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
    let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
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
    let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
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

/// Which non-argv channels a table row sets next to `--store-url`, and
/// whether each one names the same store as the flag.
#[derive(Clone, Copy, Debug)]
enum Row {
    /// `--store-url` only (the argv form, unchanged).
    FlagAlone,
    File {
        same: bool,
    },
    Env {
        same: bool,
    },
    Both {
        file_same: bool,
        env_same: bool,
    },
}

/// The ONE refusal text a differing channel produces; names channels only.
fn conflict_message(channels: &str) -> String {
    format!(
        "refusing --store-url: it differs from the store URL set by {channels}; pass the same \
         URL on both, or drop one of them, so the write cannot reach a store you did not name \
         (#4600)"
    )
}

/// #4600 (r1 C-M1 / S-L1) — an explicit `--store-url` that differs from a set
/// FILE or ENV channel is refused with a typed error naming the channel
/// names only; the same value on both is accepted. Replaces the
/// precedence row that pinned the silent override (env set +
/// `--store-url p-flag.db` wrote p-env.db).
#[test]
fn schema_init_4600_flag_against_channels_table() {
    const FILE: &str = "AI_MEMORY_STORE_URL_FILE";
    const ENV: &str = "AI_MEMORY_STORE_URL";
    let rows: [(Row, Option<&str>); 9] = [
        (Row::FlagAlone, None),
        (Row::File { same: true }, None),
        (Row::File { same: false }, Some(FILE)),
        (Row::Env { same: true }, None),
        (Row::Env { same: false }, Some(ENV)),
        (
            Row::Both {
                file_same: true,
                env_same: true,
            },
            None,
        ),
        (
            Row::Both {
                file_same: true,
                env_same: false,
            },
            Some(ENV),
        ),
        (
            Row::Both {
                file_same: false,
                env_same: true,
            },
            Some(FILE),
        ),
        (
            Row::Both {
                file_same: false,
                env_same: false,
            },
            Some("AI_MEMORY_STORE_URL_FILE and AI_MEMORY_STORE_URL"),
        ),
    ];
    for (row, refused_by) in rows {
        let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let flag_url = sqlite_url(tmp.path(), "flag.db");
        let other_url = sqlite_url(tmp.path(), "other.db");
        let pick = |same: bool| {
            if same {
                flag_url.clone()
            } else {
                other_url.clone()
            }
        };
        let mut cmd = schema_init(&tmp.path().join("main.db"));
        cmd.args(["--store-url", &flag_url]);
        let (file, env) = match row {
            Row::FlagAlone => (None, None),
            Row::File { same } => (Some(pick(same)), None),
            Row::Env { same } => (None, Some(pick(same))),
            Row::Both {
                file_same,
                env_same,
            } => (Some(pick(file_same)), Some(pick(env_same))),
        };
        if let Some(url) = file {
            cmd.env(FILE, write_url_file(tmp.path(), "store-url", &url, 0o600));
        }
        if let Some(url) = env {
            cmd.env(ENV, url);
        }
        let out = cmd.output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        match refused_by {
            None => {
                assert!(
                    out.status.success(),
                    "{row:?}: must be accepted; stderr: {err}"
                );
                assert!(
                    tmp.path().join("flag.db").exists(),
                    "{row:?}: flag store not initialised"
                );
            }
            Some(channels) => {
                assert!(!out.status.success(), "{row:?}: must be refused");
                assert!(
                    err.contains(&conflict_message(channels)),
                    "{row:?}: exact conflict refusal; stderr: {err}"
                );
                assert!(
                    !err.contains("sqlite://"),
                    "{row:?}: the refusal must name no URL"
                );
                assert!(
                    !tmp.path().join("flag.db").exists(),
                    "{row:?}: flag store written"
                );
                assert!(
                    !tmp.path().join("other.db").exists(),
                    "{row:?}: channel store written"
                );
            }
        }
    }
}

/// Without `--store-url` the ladder is unchanged: FILE beats ENV.
#[test]
fn schema_init_4600_without_flag_file_beats_env() {
    let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = write_url_file(
        tmp.path(),
        "store-url",
        &sqlite_url(tmp.path(), "p-file.db"),
        0o600,
    );
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL_FILE", &f)
        .env("AI_MEMORY_STORE_URL", sqlite_url(tmp.path(), "p-env.db"))
        .assert()
        .success();
    assert!(tmp.path().join("p-file.db").exists());
    assert!(!tmp.path().join("p-env.db").exists());
}

/// #4600 (r1 C-L1) — schema-init installs no console tracing subscriber, so
/// the argv-credential warning must reach stderr directly (as `migrate`
/// does). Placeholder password, closed port 1; the password never prints.
#[test]
fn schema_init_4600_argv_credential_warning_reaches_stderr() {
    const PLACEHOLDER: &str = "placeholder-pw-4600";
    for url in [
        format!("postgres://fixture_user:{PLACEHOLDER}@127.0.0.1:1/x?sslmode=disable"),
        format!("postgres://fixture_user@127.0.0.1:1/x?sslmode=disable&password={PLACEHOLDER}"),
    ] {
        let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let out = schema_init(&tmp.path().join("main.db"))
            .args(["--store-url", &url])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains(ai_memory::store_url_writer::ARGV_CREDENTIAL_WARNING),
            "the argv-credential warning must reach stderr; stderr: {err}"
        );
        let all = format!("{}{err}", String::from_utf8_lossy(&out.stdout));
        assert!(
            !all.contains(PLACEHOLDER),
            "the password must never be printed"
        );
    }
}

#[test]
fn schema_init_4600_group_or_world_readable_file_refused() {
    for mode in [0o640_u32, 0o604, 0o644] {
        let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
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
    let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
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
    let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let p = tmp.path().join("store-url");
    std::fs::write(&p, "\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    schema_init(&tmp.path().join("main.db"))
        .env("AI_MEMORY_STORE_URL_FILE", &p)
        .assert()
        .failure();
}
