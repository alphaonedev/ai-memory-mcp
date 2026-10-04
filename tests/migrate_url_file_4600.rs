// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4600 (CWE-214) — `ai-memory migrate` takes each endpoint through a NON-argv
//! channel: `--from-url-file PATH` / `--to-url-file PATH` (5-agent vote
//! (4d3ea1c5), decision memory 6ceaee9a). Either side can be a `postgres://`
//! URL with a password, which `--from` / `--to` put on `/proc/<pid>/cmdline`.
//!
//! Red on the base: neither flag existed and `--from` / `--to` were required,
//! so every file-only invocation below exited 2 (clap "unexpected argument").
//!
//! Decided behaviour pinned here:
//! * each side takes exactly one of the plain flag or the file flag; both or
//!   neither is refused at parse time (exit 2);
//! * the file is read through `store_url::store_url_from_file` (one open,
//!   fstat on that handle, group/world-readable modes refused; the existing
//!   `AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS` knob is the only opt-out);
//! * `migrate` never reads `AI_MEMORY_STORE_URL` / `AI_MEMORY_STORE_URL_FILE`,
//!   so a stale exported destination can never redirect a bulk write;
//! * a credential-bearing `--from` / `--to` is warned about per side, naming
//!   the file flags, and is still accepted.

#![cfg(feature = "sal")]
#![cfg(unix)]
#![allow(clippy::doc_markdown)]

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

/// A password that must never reach stdout, stderr or a log line.
const SECRET: &str = "s3cr3t-4600-argv-leak";

fn run(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
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
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .env_remove("AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn ai-memory")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

fn sqlite_url(path: &Path) -> String {
    format!("sqlite://{}", path.display())
}

fn url_file(dir: &Path, name: &str, url: &str, mode: u32) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("{url}\n")).expect("write url file");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
    p
}

/// An existing, empty source store (the read-only source funnel refuses a
/// missing path, #3435).
fn seed_source(dir: &Path) -> PathBuf {
    let src = dir.join("src.db");
    let _ = ai_memory::db::open(&src).expect("seed source");
    src
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

#[test]
fn migrate_4600_file_only_invocation_succeeds_and_writes_the_destination() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dst = dir.path().join("dst.db");
    let from_f = url_file(dir.path(), "from.url", &sqlite_url(&src), 0o600);
    let to_f = url_file(dir.path(), "to.url", &sqlite_url(&dst), 0o600);
    let out = run(
        dir.path(),
        &[
            "migrate",
            "--from-url-file",
            s(&from_f),
            "--to-url-file",
            s(&to_f),
            "--json",
        ],
        &[],
    );
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        dst.exists(),
        "destination named by --to-url-file not created"
    );
    let report: serde_json::Value = serde_json::from_str(text(&out.stdout).trim()).unwrap();
    assert_eq!(report["dry_run"], false);
}

#[test]
fn migrate_4600_plain_flag_and_file_flag_mix_across_sides() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dst = dir.path().join("dst.db");
    let to_f = url_file(dir.path(), "to.url", &sqlite_url(&dst), 0o600);
    let out = run(
        dir.path(),
        &[
            "migrate",
            "--from",
            &sqlite_url(&src),
            "--to-url-file",
            s(&to_f),
            "--json",
        ],
        &[],
    );
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(dst.exists());
}

#[test]
fn migrate_4600_both_forms_for_one_side_is_a_parse_error() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dst = dir.path().join("dst.db");
    let from_f = url_file(dir.path(), "from.url", &sqlite_url(&src), 0o600);
    let to_f = url_file(dir.path(), "to.url", &sqlite_url(&dst), 0o600);
    let cases: [&[&str]; 2] = [
        &[
            "migrate",
            "--from",
            &sqlite_url(&src),
            "--from-url-file",
            s(&from_f),
            "--to-url-file",
            s(&to_f),
        ],
        &[
            "migrate",
            "--from-url-file",
            s(&from_f),
            "--to",
            &sqlite_url(&dst),
            "--to-url-file",
            s(&to_f),
        ],
    ];
    for args in cases {
        let out = run(dir.path(), args, &[]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "args {args:?}: {}",
            text(&out.stderr)
        );
        assert!(
            !dst.exists(),
            "a refused parse must not create the destination"
        );
    }
}

#[test]
fn migrate_4600_neither_form_for_a_side_is_a_parse_error() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dst = dir.path().join("dst.db");
    let from_f = url_file(dir.path(), "from.url", &sqlite_url(&src), 0o600);
    let to_f = url_file(dir.path(), "to.url", &sqlite_url(&dst), 0o600);
    let cases: [&[&str]; 3] = [
        &["migrate", "--to-url-file", s(&to_f)],
        &["migrate", "--from-url-file", s(&from_f)],
        &["migrate"],
    ];
    for args in cases {
        // Even a set store-url env channel must not stand in for a side.
        let out = run(
            dir.path(),
            args,
            &[("AI_MEMORY_STORE_URL", &sqlite_url(&dst))],
        );
        assert_eq!(
            out.status.code(),
            Some(2),
            "args {args:?}: {}",
            text(&out.stderr)
        );
        assert!(!dst.exists());
    }
}

#[test]
fn migrate_4600_group_or_world_readable_url_file_is_refused() {
    for mode in [0o640_u32, 0o604, 0o644] {
        let dir = tempfile::tempdir().unwrap();
        let src = seed_source(dir.path());
        let dst = dir.path().join("dst.db");
        let from_f = url_file(dir.path(), "from.url", &sqlite_url(&src), 0o600);
        let to_f = url_file(dir.path(), "to.url", &sqlite_url(&dst), mode);
        let out = run(
            dir.path(),
            &[
                "migrate",
                "--from-url-file",
                s(&from_f),
                "--to-url-file",
                s(&to_f),
            ],
            &[],
        );
        assert!(!out.status.success(), "mode {mode:o} must be refused");
        let err = text(&out.stderr);
        assert!(err.contains("lax permissions"), "mode {mode:o}: {err}");
        assert!(!dst.exists(), "mode {mode:o}: store opened despite refusal");
    }
}

#[test]
fn migrate_4600_lax_file_accepted_only_via_the_existing_opt_out() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dst = dir.path().join("dst.db");
    let from_f = url_file(dir.path(), "from.url", &sqlite_url(&src), 0o644);
    let to_f = url_file(dir.path(), "to.url", &sqlite_url(&dst), 0o600);
    let out = run(
        dir.path(),
        &[
            "migrate",
            "--from-url-file",
            s(&from_f),
            "--to-url-file",
            s(&to_f),
        ],
        &[("AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS", "1")],
    );
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(dst.exists());
}

#[test]
fn migrate_4600_empty_or_missing_url_file_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dst = dir.path().join("dst.db");
    let from_f = url_file(dir.path(), "from.url", &sqlite_url(&src), 0o600);
    let empty = dir.path().join("empty.url");
    std::fs::write(&empty, "\n").unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600)).unwrap();
    let missing = dir.path().join("missing.url");
    for to in [&empty, &missing] {
        let out = run(
            dir.path(),
            &[
                "migrate",
                "--from-url-file",
                s(&from_f),
                "--to-url-file",
                s(to),
            ],
            &[],
        );
        assert!(!out.status.success());
        assert!(!dst.exists());
    }
}

#[test]
fn migrate_4600_never_reads_the_store_url_env_channels() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dst = dir.path().join("dst.db");
    let decoy = dir.path().join("decoy.db");
    let decoy_file = url_file(dir.path(), "decoy.url", &sqlite_url(&decoy), 0o600);
    let out = run(
        dir.path(),
        &[
            "migrate",
            "--from",
            &sqlite_url(&src),
            "--to",
            &sqlite_url(&dst),
        ],
        &[
            ("AI_MEMORY_STORE_URL", &sqlite_url(&decoy)),
            ("AI_MEMORY_STORE_URL_FILE", s(&decoy_file)),
        ],
    );
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(dst.exists(), "explicit --to must win");
    assert!(
        !decoy.exists(),
        "a stale store-url env/file channel redirected a migrate write"
    );
}

#[test]
fn migrate_4600_warns_per_side_for_a_credentialed_argv_url_naming_the_file_flags() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dsn = format!("postgres://ai_memory:{SECRET}@127.0.0.1:9/ai_memory");

    // --to side (dry run: no destination is opened, the source is a real file).
    let out = run(
        dir.path(),
        &[
            "migrate",
            "--from",
            &sqlite_url(&src),
            "--to",
            &dsn,
            "--dry-run",
        ],
        &[],
    );
    let err = text(&out.stderr);
    assert!(
        err.contains("--to-url-file") && !err.contains("--from-url-file"),
        "expected one warning naming --to-url-file only:\n{err}"
    );
    assert!(!err.contains(SECRET), "password leaked to stderr:\n{err}");
    assert!(!text(&out.stdout).contains(SECRET));

    // --from side (the connect refusal comes after the warning).
    let to_dst = dir.path().join("dst.db");
    let out = run(
        dir.path(),
        &["migrate", "--from", &dsn, "--to", &sqlite_url(&to_dst)],
        &[],
    );
    let err = text(&out.stderr);
    assert!(
        err.contains("--from-url-file") && !err.contains("--to-url-file"),
        "expected one warning naming --from-url-file only:\n{err}"
    );
    assert!(!err.contains(SECRET), "password leaked to stderr:\n{err}");
}

#[test]
fn migrate_4600_credentialed_url_in_a_file_does_not_warn_and_does_not_leak() {
    let dir = tempfile::tempdir().unwrap();
    let src = seed_source(dir.path());
    let dsn = format!("postgres://ai_memory:{SECRET}@127.0.0.1:9/ai_memory");
    let to_f = url_file(dir.path(), "to.url", &dsn, 0o600);
    let out = run(
        dir.path(),
        &[
            "migrate",
            "--from",
            &sqlite_url(&src),
            "--to-url-file",
            s(&to_f),
            "--dry-run",
        ],
        &[],
    );
    let err = text(&out.stderr);
    assert!(
        !err.contains("carries a password") && !err.contains(SECRET),
        "file-channel URL must neither warn about argv nor leak:\n{err}"
    );
    assert!(!text(&out.stdout).contains(SECRET));
}
