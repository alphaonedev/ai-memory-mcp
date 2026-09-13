// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3652 — every systemd unit the project ships hands its output to the
//! journal.
//!
//! `StandardOutput=append:<file>` (or `file:` / `truncate:`) makes systemd
//! open the file once and write to it for the life of the unit. Nothing
//! rotates it, nothing reopens it, and it grows without a bound — the
//! curator installer and the sync template both shipped that shape, while
//! the sync template's own header told operators to read the output with
//! `journalctl`, which then showed nothing. With `journal`, journald owns
//! capture, rotation and retention (`SystemMaxUse=`, `MaxRetentionSec=`).
//!
//! The scan covers every file under the directories that ship units or
//! generate them (`scripts/`, `infra/`, `packaging/`, `docs/deploy/`,
//! `docs/operations/`) plus the operator guide that prints a unit inline.

use std::path::{Path, PathBuf};

/// Directories scanned recursively. A missing directory is skipped, but
/// the scan as a whole must find at least one unit (see
/// [`the_scan_is_not_vacuous`]).
const SCANNED_DIRS: &[&str] = &[
    "scripts",
    "infra",
    "packaging",
    "docs/deploy",
    "docs/operations",
];

/// Single documents that print a unit inline.
const SCANNED_FILES: &[&str] = &["docs/batman-active-mode.md"];

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
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn scanned_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in SCANNED_DIRS {
        collect(&root.join(dir), &mut files);
    }
    for file in SCANNED_FILES {
        files.push(root.join(file));
    }
    files
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
