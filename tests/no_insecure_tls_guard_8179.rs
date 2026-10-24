// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8179 source guard: no certificate-verification bypass may be (re)introduced.
//!
//! CodeQL flags `danger_accept_invalid_certs`, but CodeQL is not a required
//! check, so a re-added bypass would otherwise survive every test. This guard
//! walks `tests/` and `src/` and fails with every `file:line` that calls
//! `danger_accept_invalid_certs` or `danger_accept_invalid_hostnames` outside
//! a `//` or `//!` comment.
//!
//! Exactly ONE site is permitted: `src/cli/sync.rs`, the operator opt-in
//! `--insecure-skip-server-verify`. It is pinned by file AND by enclosing match
//! arm: the matching line must sit inside the `SyncTlsMode::AcceptAny` arm (one
//! of the 8 preceding non-blank lines names it) and may occur only once in that
//! file. A second occurrence anywhere, or that one moved out of the arm, fails.
//! Tests use the pinned-root helper in `tests/common/tls.rs` instead.

use std::path::{Path, PathBuf};

const BYPASS_CALLS: [&str; 2] = [
    "danger_accept_invalid_certs",
    "danger_accept_invalid_hostnames",
];
/// The single permitted production file (`--insecure-skip-server-verify`).
const PERMITTED_FILE: &str = "src/cli/sync.rs";
/// The match arm that must enclose the permitted call.
const PERMITTED_ARM: &str = "SyncTlsMode::AcceptAny";
/// How many preceding non-blank lines may separate the arm from the call.
const ARM_LOOKBACK_LINES: usize = 8;
const SCANNED_DIRS: [&str; 2] = ["tests", "src"];

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn has_bypass(line: &str) -> bool {
    !is_comment(line) && BYPASS_CALLS.iter().any(|c| line.contains(c))
}

/// Offending `file:line` strings for one file's text; `rel` is the
/// repo-relative path with `/` separators.
fn violations_in(rel: &str, text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let hits: Vec<usize> = (0..lines.len()).filter(|&i| has_bypass(lines[i])).collect();
    let mut out = Vec::new();
    for (n, &i) in hits.iter().enumerate() {
        let in_arm = rel == PERMITTED_FILE
            && n == 0
            && lines[..i]
                .iter()
                .rev()
                .filter(|l| !l.trim().is_empty())
                .take(ARM_LOOKBACK_LINES)
                .any(|l| l.contains(PERMITTED_ARM));
        if !in_arm {
            out.push(format!("{rel}:{}", i + 1));
        }
    }
    out
}

#[test]
fn no_certificate_verification_bypass_in_tests_or_src_8179() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for d in SCANNED_DIRS {
        collect_rs(&root.join(d), &mut files);
    }
    let mut bad = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(root)
            .expect("under manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "tests/no_insecure_tls_guard_8179.rs" {
            continue;
        }
        let text = std::fs::read_to_string(f).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        bad.extend(violations_in(&rel, &text));
    }
    assert!(
        bad.is_empty(),
        "certificate-verification bypass found (use the pinned-root helper in tests/common/tls.rs; \
         the only permitted site is the {PERMITTED_ARM} arm for --insecure-skip-server-verify in \
         {PERMITTED_FILE}):\n{}",
        bad.join("\n")
    );
}

#[test]
fn guard_pins_the_single_sync_arm_8179() {
    let arm = "match m {\n    SyncTlsMode::AcceptAny => {\n        b.danger_accept_invalid_certs(true);\n    }\n}\n";
    assert!(violations_in(PERMITTED_FILE, arm).is_empty());
    // moved out of the arm
    let moved = "fn f() {\n    b.danger_accept_invalid_certs(true);\n}\n";
    assert_eq!(violations_in(PERMITTED_FILE, moved), [format!("{PERMITTED_FILE}:2")]);
    // a second occurrence in the permitted file
    let twice = format!("{arm}{arm}");
    assert_eq!(violations_in(PERMITTED_FILE, &twice).len(), 1);
    // the arm text in any other file does not excuse it
    assert_eq!(violations_in("src/other.rs", arm).len(), 1);
    // comments are ignored
    assert!(violations_in("tests/x.rs", "// danger_accept_invalid_certs(true)\n//! danger_accept_invalid_hostnames\n").is_empty());
}
