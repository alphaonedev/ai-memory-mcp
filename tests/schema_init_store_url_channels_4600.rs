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

const FILE: &str = "AI_MEMORY_STORE_URL_FILE";
const ENV: &str = "AI_MEMORY_STORE_URL";
const FLAG: &str = "--store-url";

/// The ONE refusal text (3-agent vote 71472661, V-4): the two disagreeing
/// channel names, then a one-line remedy that unsets an env channel. Never
/// any part of a URL.
fn conflict_message(first: &str, second: &str) -> String {
    let unset = if second == FLAG { first } else { second };
    format!(
        "refusing to open a store: {first} and {second} name different stores (#4600); unset \
         the channel you do not mean, for example `env -u {unset} ...`, and run again"
    )
}

/// Run one schema-init with the given channels and assert the exact
/// conflict refusal: non-zero exit, the pinned text, no URL on stderr.
fn assert_conflict_refused(cmd: &mut Command, pair: (&str, &str), label: &str) -> String {
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "{label}: must be refused");
    assert!(
        err.contains(&conflict_message(pair.0, pair.1)),
        "{label}: exact conflict refusal; stderr: {err}"
    );
    assert!(
        !err.contains("://"),
        "{label}: the refusal must name no URL"
    );
    err
}

/// #4600 (r1 C-M1 / S-L1) — an explicit `--store-url` that differs from a set
/// FILE or ENV channel is refused with a typed error naming the two
/// disagreeing channels only; the same value on every set channel is
/// accepted. Replaces the precedence row that pinned the silent override (env
/// set + `--store-url p-flag.db` wrote p-env.db).
#[test]
fn schema_init_4600_flag_against_channels_table() {
    let rows: [(Row, Option<(&str, &str)>); 9] = [
        (Row::FlagAlone, None),
        (Row::File { same: true }, None),
        (Row::File { same: false }, Some((FILE, FLAG))),
        (Row::Env { same: true }, None),
        (Row::Env { same: false }, Some((ENV, FLAG))),
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
            Some((FILE, ENV)),
        ),
        (
            Row::Both {
                file_same: false,
                env_same: true,
            },
            Some((FILE, ENV)),
        ),
        (
            // FILE and ENV agree with each other; the flag is the odd one.
            Row::Both {
                file_same: false,
                env_same: false,
            },
            Some((FILE, FLAG)),
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
        cmd.args([FLAG, &flag_url]);
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
        let label = format!("{row:?}");
        match refused_by {
            None => {
                let out = cmd.output().unwrap();
                let err = String::from_utf8_lossy(&out.stderr);
                assert!(
                    out.status.success(),
                    "{label}: must be accepted; stderr: {err}"
                );
                assert!(
                    tmp.path().join("flag.db").exists(),
                    "{label}: flag store not initialised"
                );
            }
            Some(pair) => {
                assert_conflict_refused(&mut cmd, pair, &label);
                assert!(
                    !tmp.path().join("flag.db").exists(),
                    "{label}: flag store written"
                );
                assert!(
                    !tmp.path().join("other.db").exists(),
                    "{label}: channel store written"
                );
            }
        }
    }
}

/// #4600 class gap (3-agent vote 71472661, A 3-0: refuse when two SET
/// channels disagree) — FILE and ENV set to different stores refuse with the
/// flag absent AND with the flag present (equal to either channel, or to
/// neither). The pre-r1b funnel let FILE win silently when no flag was given.
#[test]
fn schema_init_4600_file_and_env_disagree_refused_with_and_without_flag() {
    for flag in [None, Some("p-file.db"), Some("p-env.db"), Some("p-flag.db")] {
        let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let f = write_url_file(
            tmp.path(),
            "store-url",
            &sqlite_url(tmp.path(), "p-file.db"),
            0o600,
        );
        let mut cmd = schema_init(&tmp.path().join("main.db"));
        cmd.env(FILE, &f)
            .env(ENV, sqlite_url(tmp.path(), "p-env.db"));
        if let Some(name) = flag {
            cmd.args([FLAG, &sqlite_url(tmp.path(), name)]);
        }
        assert_conflict_refused(&mut cmd, (FILE, ENV), &format!("flag={flag:?}"));
        for db in ["p-file.db", "p-env.db", "p-flag.db"] {
            assert!(
                !tmp.path().join(db).exists(),
                "flag={flag:?}: {db} written after a refusal"
            );
        }
    }
}

/// FILE and ENV naming the same store, with no flag, proceed to that store.
#[test]
fn schema_init_4600_file_and_env_agree_without_flag_succeeds() {
    let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let url = sqlite_url(tmp.path(), "p-both.db");
    let f = write_url_file(tmp.path(), "store-url", &url, 0o600);
    schema_init(&tmp.path().join("main.db"))
        .env(FILE, &f)
        .env(ENV, &url)
        .assert()
        .success();
    assert!(tmp.path().join("p-both.db").exists());
}

/// Distinct fixture parts so the "no URL part in the refusal" check is exact.
const V1_HOST: &str = "db-host-4600.invalid";
const V1_USER: &str = "user_alpha_4600";
const V1_OTHER_USER: &str = "user_beta_4600";
const V1_PASSWORD: &str = "pw_secret_4600";
const V1_DB: &str = "dbname_alpha_4600";
const V1_OTHER_DB: &str = "dbname_beta_4600";
const V1_PORT: &str = "6543";
const V1_DEFAULT_PORT: &str = "5432";

/// Every part of a V-1 fixture URL; none may appear in a refusal.
const V1_URL_PARTS: [&str; 10] = [
    "postgres",
    "://",
    V1_HOST,
    V1_USER,
    V1_OTHER_USER,
    V1_PASSWORD,
    V1_DB,
    V1_OTHER_DB,
    V1_PORT,
    V1_DEFAULT_PORT,
];

/// The V-1 corpus: pairs that name the same Postgres store under a URL
/// normaliser or an origin compare, or differ only by whitespace on argv.
/// "Same store" is exact byte equality, so every pair refuses.
fn v1_rows() -> [(&'static str, String, String); 6] {
    let base = format!("postgres://{V1_USER}@{V1_HOST}:{V1_PORT}/{V1_DB}");
    [
        (
            "credentialed vs bare",
            format!("postgres://{V1_USER}:{V1_PASSWORD}@{V1_HOST}:{V1_PORT}/{V1_DB}"),
            base.clone(),
        ),
        ("trailing slash", base.clone(), format!("{base}/")),
        (
            "default port",
            format!("postgres://{V1_USER}@{V1_HOST}/{V1_DB}"),
            format!("postgres://{V1_USER}@{V1_HOST}:{V1_DEFAULT_PORT}/{V1_DB}"),
        ),
        (
            "other database",
            base.clone(),
            format!("postgres://{V1_USER}@{V1_HOST}:{V1_PORT}/{V1_OTHER_DB}"),
        ),
        (
            "other user",
            base.clone(),
            format!("postgres://{V1_OTHER_USER}@{V1_HOST}:{V1_PORT}/{V1_DB}"),
        ),
        ("argv trailing space", base.clone(), format!("{base} ")),
    ]
}

/// 3-agent vote (71472661) V-1 — "same store" is exact byte equality of the
/// resolved values; no URL normalisation, no origin compare. Each row runs on
/// the three channel pairs (FILE vs flag, ENV vs flag, FILE vs ENV with no
/// flag) and each refuses with the exact text and no URL part on stderr.
#[test]
fn schema_init_4600_same_store_is_exact_bytes_table() {
    for (row, channel_value, other_value) in v1_rows() {
        for pair in [(FILE, FLAG), (ENV, FLAG), (FILE, ENV)] {
            let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
            let mut cmd = schema_init(&tmp.path().join("main.db"));
            if pair.0 == FILE {
                cmd.env(
                    FILE,
                    write_url_file(tmp.path(), "store-url", &channel_value, 0o600),
                );
            } else {
                cmd.env(ENV, &channel_value);
            }
            if pair.1 == FLAG {
                cmd.args([FLAG, &other_value]);
            } else {
                cmd.env(ENV, &other_value);
            }
            let label = format!("{row} / {} vs {}", pair.0, pair.1);
            let err = assert_conflict_refused(&mut cmd, pair, &label);
            for part in V1_URL_PARTS {
                assert!(
                    !err.contains(part),
                    "{label}: URL part {part:?} leaked into stderr: {err}"
                );
            }
        }
    }
}

/// 3-agent vote (71472661) V-2 — a SET file channel that is unreadable
/// (missing path) or empty refuses with the shared reader's exact error and
/// never falls through to ENV or the flag, which both name a usable store.
#[test]
fn schema_init_4600_set_file_channel_unreadable_or_empty_never_falls_through() {
    for (case, with_flag) in [
        ("missing", false),
        ("missing", true),
        ("empty", false),
        ("empty", true),
    ] {
        let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let path = tmp.path().join("store-url");
        let expected = if case == "empty" {
            std::fs::write(&path, "\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            format!("store-url file {} is empty", path.display())
        } else {
            format!("reading store-url file {}", path.display())
        };
        let fallback = sqlite_url(tmp.path(), "fallback.db");
        let mut cmd = schema_init(&tmp.path().join("main.db"));
        cmd.env(FILE, &path).env(ENV, &fallback);
        if with_flag {
            cmd.args([FLAG, &fallback]);
        }
        let out = cmd.output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        let label = format!("{case} file, flag={with_flag}");
        assert!(!out.status.success(), "{label}: must be refused");
        assert!(
            err.contains(&expected),
            "{label}: exact file-channel error; stderr: {err}"
        );
        assert!(
            !tmp.path().join("fallback.db").exists(),
            "{label}: fell through to the ENV / flag store"
        );
    }
}

/// 3-agent vote (71472661) V-2 — an empty (or blank) env value has ONE
/// meaning: unset, exactly as the shared resolver treats it. Pinned for both
/// env vars: the flag alone then decides.
#[test]
fn schema_init_4600_empty_env_value_is_unset() {
    for (var, value) in [(ENV, ""), (ENV, "   "), (FILE, ""), (FILE, "  ")] {
        let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let out = schema_init(&tmp.path().join("main.db"))
            .env(var, value)
            .args([FLAG, &sqlite_url(tmp.path(), "flag.db")])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{var}={value:?}: an empty value is unset; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(tmp.path().join("flag.db").exists(), "{var}={value:?}");
    }
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
