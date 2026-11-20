// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9620 — a read-only or diagnostic invocation creates, changes and truncates
//! no file; every filesystem write the binary makes at start either succeeds
//! or is reported with a named error.
//!
//! Pre-fix, `src/main.rs` called `AppConfig::write_default_if_missing()` for
//! EVERY subcommand, so `wake-hub --posture` (whose contract in
//! `src/cli/wake_hub.rs` is "binds nothing and must change nothing"),
//! `doctor`, `config check` and the `verify-*` verbs created
//! `<config dir>/ai-memory/config.toml` on a host that had none. The function
//! also tested `path.exists()` and then called `fs::write` (which truncates):
//! a check-then-write race, and it dropped both `io::Result`s with `let _ =`,
//! so a refused write was invisible.
//!
//! Every cell drives the REAL binary in a subprocess with its own `$HOME`,
//! `$XDG_CONFIG_HOME` and working directory (never `set_var` in this
//! process), so the pins cover the shipped entry point.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

/// First line of the default config template (`write_default_if_missing`).
const DEFAULT_CONFIG_FIRST_LINE: &str = "# ai-memory configuration";

/// Fixed text before the path in the refused-write warning. Source:
/// `src/main.rs`, the `eprintln!` after `write_default_if_missing()` fails
/// (`ai-memory: WARN could not write the default config {path}: {e}`). The
/// binary crate is not reachable from an integration test, so the text is
/// pinned here.
const REFUSED_WRITE_WARN_PREFIX: &str = "ai-memory: WARN could not write the default config ";

/// Body of the config a pre-existing-file cell plants. Valid TOML (comment
/// only) so it changes no setting if it is read.
const SENTINEL_CONFIG: &str = "# sentinel 9620 - must survive byte for byte\n";

/// Age of the planted config, so an mtime bump is visible.
const SENTINEL_AGE: Duration = Duration::from_hours(720);

/// Scratch root under the repo's gitignored `.local-runs/` (no `/tmp`).
fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-9620-readonly-config-write");
    fs::create_dir_all(&root).expect("mkdir scratch root");
    root
}

/// A fresh `(home, xdg, cwd)` triple. `xdg` is the config root the child
/// resolves `ai-memory/config.toml` under; it starts EMPTY.
struct Sandbox {
    _dir: tempfile::TempDir,
    home: PathBuf,
    xdg: PathBuf,
    cwd: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir under .local-runs");
        let home = dir.path().join("home");
        let xdg = home.join(".config");
        let cwd = dir.path().join("cwd");
        fs::create_dir_all(&xdg).expect("mkdir xdg");
        fs::create_dir_all(&cwd).expect("mkdir cwd");
        Self {
            _dir: dir,
            home,
            xdg,
            cwd,
        }
    }

    fn config_dir(&self) -> PathBuf {
        self.xdg.join("ai-memory")
    }

    fn config_path(&self) -> PathBuf {
        self.config_dir().join("config.toml")
    }

    fn db(&self) -> PathBuf {
        self.cwd.join("t9620.db")
    }

    /// Plant `SENTINEL_CONFIG` with an mtime `SENTINEL_AGE` in the past.
    fn plant_config(&self) -> SystemTime {
        fs::create_dir_all(self.config_dir()).expect("mkdir config dir");
        fs::write(self.config_path(), SENTINEL_CONFIG).expect("plant config");
        let old = SystemTime::now() - SENTINEL_AGE;
        let f = fs::File::options()
            .write(true)
            .open(self.config_path())
            .expect("open planted config");
        f.set_modified(old).expect("backdate planted config");
        fs::metadata(self.config_path())
            .and_then(|m| m.modified())
            .expect("planted mtime")
    }

    fn run(&self, args: &[&str]) -> Output {
        let db = self.db();
        Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .arg("--db")
            .arg(&db)
            .args(args)
            .current_dir(&self.cwd)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            // The boot key setup (#9574, PR 9578) writes signing keys. Point
            // it OUTSIDE the config root so this suite pins the default
            // config write alone and stays valid before and after that PR.
            .env("AI_MEMORY_KEY_DIR", self.home.join("keydir"))
            .env_remove("AI_MEMORY_DB")
            .env_remove("AI_MEMORY_NO_CONFIG")
            .output()
            .expect("spawn ai-memory")
    }
}

/// Every path under `root` (files and directories), relative, sorted.
fn tree(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            out.push(
                p.strip_prefix(root)
                    .expect("under root")
                    .display()
                    .to_string(),
            );
            if p.is_dir() {
                walk(&p, root, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The read-only and diagnostic verbs. Taken from the `Command` enum: the
/// verbs the issue names plus the read-only verbs `ledger_writer` lists as
/// opening no write funnel. Each row is the argv after `--db <path>`.
const READ_ONLY_VERBS: &[&[&str]] = &[
    &["wake-hub", "--posture"],
    &["wake-hub", "--health"],
    &["doctor"],
    &["config", "check"],
    &["config", "show"],
    &["verify-reflection-chain", "no-such-memory"],
    &["verify-signed-events-chain"],
    &["verify-audit-trail"],
    &["verify-forensic-bundle", "no-such-bundle.tar"],
    &["completions", "bash"],
    &["man"],
    &["stats"],
    &["namespaces"],
    &["features"],
    &["list"],
    &["get", "no-such-memory"],
    &["recall", "anything"],
    &["search", "anything"],
];

/// (a) each read-only verb, started against a config root that holds no
/// config, leaves that root byte-for-byte empty.
#[test]
fn read_only_verbs_leave_an_empty_config_root_empty_9620() {
    let mut violations = Vec::new();
    for argv in READ_ONLY_VERBS {
        let sb = Sandbox::new();
        let out = sb.run(argv);
        let stderr = stderr_of(&out);
        // A clap usage failure never reaches `main`'s start sequence, so it
        // would make this cell vacuous. Pin that the verb really started.
        assert!(
            !stderr.contains("Usage:"),
            "{argv:?}: argv must reach the start sequence, not a usage error; stderr={stderr}"
        );
        let found = tree(&sb.xdg);
        if !found.is_empty() {
            violations.push(format!("{argv:?} created {found:?}"));
        }
    }
    assert!(
        violations.is_empty(),
        "#9620: read-only verbs must create nothing under the config root; \
         violations={violations:#?}"
    );
}

/// (b) a config that already exists is never truncated or changed by a
/// read-only verb or by a writing verb: content AND mtime.
#[test]
fn existing_config_is_never_touched_9620() {
    for argv in [
        &["wake-hub", "--posture"][..],
        &["doctor"][..],
        &["stats"][..],
        &["store", "--title", "t", "--content", "c"][..],
    ] {
        let sb = Sandbox::new();
        let mtime = sb.plant_config();
        let _ = sb.run(argv);
        assert_eq!(
            fs::read_to_string(sb.config_path()).expect("read config back"),
            SENTINEL_CONFIG,
            "#9620: {argv:?} changed the content of an existing config"
        );
        assert_eq!(
            fs::metadata(sb.config_path())
                .and_then(|m| m.modified())
                .expect("mtime back"),
            mtime,
            "#9620: {argv:?} changed the mtime of an existing config"
        );
        assert_eq!(
            tree(&sb.config_dir()),
            vec!["config.toml".to_string()],
            "#9620: {argv:?} left extra files beside the existing config"
        );
    }
}

/// (c) a writing verb still creates the default config on a host that has
/// none, and a second start leaves it alone.
#[test]
fn writing_verb_still_creates_the_default_config_9620() {
    let sb = Sandbox::new();
    let out = sb.run(&["store", "--title", "t", "--content", "c"]);
    assert!(
        sb.config_path().is_file(),
        "a writing verb must still create the default config; exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
    let body = fs::read_to_string(sb.config_path()).expect("read default config");
    assert!(
        body.starts_with(DEFAULT_CONFIG_FIRST_LINE),
        "default config must start with {DEFAULT_CONFIG_FIRST_LINE:?}; got {:?}",
        body.lines().next()
    );
    let mtime = fs::metadata(sb.config_path())
        .and_then(|m| m.modified())
        .expect("mtime");
    let _ = sb.run(&["store", "--title", "t2", "--content", "c2"]);
    assert_eq!(
        fs::read_to_string(sb.config_path()).expect("read again"),
        body,
        "a second start must not rewrite the default config"
    );
    assert_eq!(
        fs::metadata(sb.config_path())
            .and_then(|m| m.modified())
            .expect("mtime again"),
        mtime,
        "a second start must not touch the default config mtime"
    );
}

/// (d) a config directory that cannot be created: the verb still runs, and
/// stderr carries the full fixed WARN text, then the path, then the reason.
///
/// The refusal does not depend on the uid: the config directory's path is a
/// dangling symlink, so reading the config finds nothing (`NotFound`) while
/// creating the directory fails for root and for every other user, and the
/// cell asserts on every run. (A regular file at that path would make the
/// config READ fail first and refuse boot, which is a different path.)
#[cfg(unix)]
#[test]
fn refused_default_config_write_is_reported_by_path_9620() {
    let sb = Sandbox::new();
    let dangling = sb.xdg.join("no-such-target-9620");
    std::os::unix::fs::symlink(&dangling, sb.config_dir()).expect("plant a dangling symlink");
    let out = sb.run(&["store", "--title", "t", "--content", "c"]);
    let stderr = stderr_of(&out);
    let expected_prefix = format!(
        "{REFUSED_WRITE_WARN_PREFIX}{}: ",
        sb.config_path().display()
    );
    assert!(
        stderr.contains(&expected_prefix),
        "#9620: a refused default-config write must print {expected_prefix:?}; stderr={stderr}"
    );
    assert!(
        sb.db().is_file(),
        "the command must still run after the refused write; exit={:?} stderr={stderr}",
        out.status.code()
    );
    assert!(
        !dangling.exists(),
        "the refused write must not create the symlink target"
    );
}
