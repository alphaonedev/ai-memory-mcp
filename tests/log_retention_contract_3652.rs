// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3652 — the operational log is bounded by someone who says so.
//!
//! Two halves. The file sink is bounded by ai-memory (a rotation period
//! and `max_files`) or declared external (`rotation = "external"`);
//! `rotation = "never"` bounds nothing and refuses boot. And every systemd
//! unit the project ships hands its output to the journal.
//!
//! `StandardOutput=append:<file>` (or `file:` / `truncate:`) makes systemd
//! open the file once and write to it for the life of the unit. Nothing
//! rotates it, nothing reopens it, and it grows without a bound — the
//! curator installer and the sync template both shipped that shape, while
//! the sync template's own header told operators to read the output with
//! `journalctl`, which then showed nothing. With `journal`, journald owns
//! capture, rotation and retention (`SystemMaxUse=`, `MaxRetentionSec=`).
//!
//! The scan walks the whole source tree, not a list of directories: a
//! list goes stale the day a unit lands somewhere else (the first version
//! of this test never reached `docs/ops/ai-memory-watch.service`). Every text file is read, so installer scripts that generate a
//! unit and guides that print one inline are covered with the `*.service`
//! files themselves.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Directory names never descended into: VCS metadata, build output,
/// scratch space (which holds whole worktrees) and caches.
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "target",
    ".local-runs",
    "node_modules",
    ".codegraph",
];

/// Files larger than this carry no unit text worth reading.
const MAX_SCANNED_BYTES: u64 = 1 << 20;

/// systemd output directives whose value opens a file the unit then holds
/// for its whole life.
const FILE_OUTPUT_PREFIXES: &[&str] = &["append:", "file:", "truncate:"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_dir() {
            let skipped = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| SKIPPED_DIRS.contains(&name));
            if !skipped {
                collect(&path, out);
            }
        } else if file_type.is_file()
            && entry
                .metadata()
                .is_ok_and(|meta| meta.len() <= MAX_SCANNED_BYTES)
        {
            out.push(path);
        }
    }
}

fn scanned_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect(&repo_root(), &mut files);
    files
}

fn is_unit_file(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "service")
}

/// `(path, line number, value)` for every `StandardOutput=` /
/// `StandardError=` directive in the scanned files.
fn output_directives() -> Vec<(PathBuf, usize, String)> {
    let mut found = Vec::new();
    for path in scanned_files() {
        // Binary files and unreadable paths carry no unit text.
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            for key in ["StandardOutput=", "StandardError="] {
                if let Some(value) = trimmed.strip_prefix(key) {
                    found.push((path.clone(), idx + 1, value.trim().to_string()));
                }
            }
        }
    }
    found
}

#[test]
fn the_scan_is_not_vacuous() {
    let units: Vec<PathBuf> = scanned_files()
        .into_iter()
        .filter(|path| is_unit_file(path))
        .collect();
    // One unit from the packaging directory and the one an enumerated
    // directory list missed: both must be reached by the walk.
    for expected in [
        "packaging/systemd/ai-memory.service",
        "docs/ops/ai-memory-watch.service",
    ] {
        assert!(
            units.contains(&repo_root().join(expected)),
            "the tree walk did not reach {expected}; found units: {units:?}"
        );
    }
    let directives = output_directives();
    assert!(
        directives.len() >= 4,
        "expected the curator installer, the sync template and the operator \
         guide to carry at least 4 output directives, found {}: {directives:?}",
        directives.len()
    );
}

#[test]
fn no_shipped_unit_appends_its_output_to_a_file_3652() {
    let offenders: Vec<String> = output_directives()
        .into_iter()
        .filter(|(_, _, value)| {
            FILE_OUTPUT_PREFIXES
                .iter()
                .any(|prefix| value.starts_with(prefix))
        })
        .map(|(path, line, value)| {
            let rel = path.strip_prefix(repo_root()).unwrap_or(&path);
            format!("{}:{line}: {value}", rel.display())
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "#3652: these systemd units write their output to a file that nothing \
         rotates, reopens or bounds. Use `StandardOutput=journal` / \
         `StandardError=journal` so journald owns retention:\n{}",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// File-sink rotation contract (Conductor ruling A on #3652)
// ---------------------------------------------------------------------------

/// `EX_CONFIG` from sysexits.h, the code every boot refusal exits with.
const EX_CONFIG: i32 = 78;

fn sandbox() -> tempfile::TempDir {
    let root = repo_root().join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

/// Write a file-sink `[logging]` block into an isolated HOME and run the
/// binary there.
fn run_with_file_sink(home: &Path, extra: &str, args: &[&str]) -> Output {
    let config_root = home.join(".config").join("ai-memory");
    std::fs::create_dir_all(&config_root).expect("create config root");
    std::fs::write(
        config_root.join("config.toml"),
        format!(
            "schema_version = 2\ntier = \"keyword\"\n\n[logging]\nenabled = true\n\
             sink = \"file\"\npath = \"{}\"\n{extra}",
            home.join("logs").display()
        ),
    )
    .expect("write config");
    Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env(
            "AI_MEMORY_KEY_DIR",
            ai_memory::identity::test_key_dir::install(),
        )
        .current_dir(home)
        .arg("--db")
        .arg(home.join("retention.db"))
        .args(args)
        .output()
        .expect("run isolated CLI")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The `Log retention (#3652)` section of a `doctor --json` report.
fn retention_section(out: &Output) -> serde_json::Value {
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json prints a report");
    report["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"] == "Log retention (#3652)")
        .cloned()
        .expect("the log retention section is present")
}

#[test]
fn rotation_never_refuses_boot_3652() {
    let home = sandbox();
    let out = run_with_file_sink(home.path(), "rotation = \"never\"\n", &["stats"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "stderr: {err}");
    assert!(err.contains("no size or retention bound"), "stderr: {err}");
    assert!(err.contains("rotation = \"external\""), "stderr: {err}");
}

#[test]
fn rotation_external_boots_and_doctor_reports_the_operator_bound_3652() {
    let home = sandbox();
    let out = run_with_file_sink(home.path(), "rotation = \"external\"\n", &["stats"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let out = run_with_file_sink(
        home.path(),
        "rotation = \"external\"\n",
        &["doctor", "--json"],
    );
    let section = retention_section(&out);
    let facts = section["facts"].to_string();
    assert!(facts.contains("EXTERNAL"), "facts: {facts}");
    assert!(!facts.contains("ai-memory: at most"), "facts: {facts}");
}

#[test]
fn a_rotation_period_is_reported_as_bounded_by_ai_memory_3652() {
    let home = sandbox();
    let out = run_with_file_sink(
        home.path(),
        "rotation = \"hourly\"\nmax_files = 7\n",
        &["doctor", "--json"],
    );
    let section = retention_section(&out);
    assert_eq!(section["severity"], "info", "section: {section}");
    let facts = section["facts"].to_string();
    assert!(
        facts.contains("at most 7 files of one hourly period each"),
        "facts: {facts}"
    );
}

#[test]
fn max_size_mb_is_reported_as_not_enforced_3652() {
    let home = sandbox();
    let out = run_with_file_sink(
        home.path(),
        "rotation = \"daily\"\nmax_size_mb = 100\n",
        &["doctor", "--json"],
    );
    let section = retention_section(&out);
    assert_eq!(section["severity"], "warning", "section: {section}");
    let facts = section["facts"].to_string();
    assert!(facts.contains("NOT ENFORCED"), "facts: {facts}");

    // The same WARN reaches the log file the operator reads. `stats` returns
    // normally, so the sink's worker guard flushes on exit.
    let out = run_with_file_sink(
        home.path(),
        "rotation = \"daily\"\nmax_size_mb = 100\n",
        &["stats"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let logs = home.path().join("logs");
    let text: String = std::fs::read_dir(&logs)
        .expect("the file sink created its directory")
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .collect();
    assert!(
        text.contains("max_size_mb is not enforced"),
        "log files under {}: {text}",
        logs.display()
    );
}
