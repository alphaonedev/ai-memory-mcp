// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7321 — a lib test that mutates the process-global fail-closed latch must
//! never do it inside the shared test process.
//!
//! The latch (`LATCHED`, `LAST_PROBE_MS`, the forced-on mode) is read by the
//! record-stop gate on every write path (`audit_trail_gate`: storage, store,
//! federation). `sink_test_lock` only serialises the tests that TAKE it; the
//! hundreds of write-path tests that do not take it still read the latch, so a
//! locked latch test refused (503) an unrelated concurrent write, or a gate
//! call from one of them cleared the latch under the locked test. A lock cannot
//! close that class, because the readers are every storage test in the binary.
//!
//! The invariant here is fail-closed by construction: every test that mutates
//! the latch runs its body in an isolated child process
//! ([`crate::test_support::run_env_isolated_child_or_spawn`], or the handlers
//! suite's `with_legacy_push_env`, which spawns the same way), where it holds
//! `sink_test_lock` alone. The parent process then never has a latched trail.
//!
//! This ratchet is an ALLOWLIST over the whole `src/` tree: any function that
//! calls a latch mutator and is neither isolated nor listed in
//! [`DEFINITION_SITES`] fails with its file, line and name. Integration
//! binaries under `tests/` cannot name the `pub(crate)` mutators and run in
//! their own processes, so they are out of reach of this class.

use std::path::{Path, PathBuf};

/// Calls that mutate the latch, the forced-on mode or the retry clock.
const LATCH_MUTATORS: [&str; 5] = [
    "fail_closed_latch_for_test(",
    "latch_for_test(",
    "force_on_for_test(",
    "reset_probe_clock_for_test(",
    "LATCHED.store(",
];

/// A function that contains one of these runs in an isolated child.
const ISOLATION_MARKERS: [&str; 2] = ["run_env_isolated_child_or_spawn", "with_legacy_push_env"];

/// Functions that DEFINE or implement the latch protocol (production gate and
/// the test setters themselves), as `(path suffix, fn name)`.
const DEFINITION_SITES: [(&str, &str); 6] = [
    ("src/audit/fail_closed.rs", "gate_with"),
    ("src/audit/fail_closed.rs", "reset_for_test"),
    ("src/audit/fail_closed.rs", "force_on_for_test"),
    ("src/audit/fail_closed.rs", "latch_for_test"),
    ("src/audit/fail_closed.rs", "drop"),
    ("src/audit/fail_closed.rs", "reset_probe_clock_for_test"),
];

/// This file names every mutator as data, so the scan skips it.
const SELF_PATH_SUFFIX: &str = "src/audit/latch_isolation_7321_tests.rs";

/// The name of the function declared on `line`, if it declares one.
fn fn_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let after = trimmed.split_once("fn ")?;
    let prefix = after.0.trim();
    let known_prefix = prefix.is_empty()
        || prefix
            .split_whitespace()
            .all(|w| matches!(w, "pub" | "pub(crate)" | "pub(super)" | "async" | "const"));
    if !known_prefix {
        return None;
    }
    let name = after
        .1
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()?;
    (!name.is_empty()).then_some(name)
}

/// Every `file:line fn name` where a latch mutator is called outside an
/// isolated child and outside [`DEFINITION_SITES`].
fn unisolated_sites(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, text) in files {
        if path.ends_with(SELF_PATH_SUFFIX) {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//")
                || code.starts_with("use ")
                || code.starts_with("pub(crate) use ")
            {
                continue;
            }
            if !LATCH_MUTATORS.iter().any(|m| code.contains(m)) {
                continue;
            }
            let enclosing = (0..=idx)
                .rev()
                .find_map(|i| fn_name(lines[i]).map(|name| (i, name)));
            let Some((start, name)) = enclosing else {
                found.push(format!("{path}:{} <no enclosing fn>", idx + 1));
                continue;
            };
            let defined = DEFINITION_SITES
                .iter()
                .any(|(suffix, def)| path.ends_with(suffix) && *def == name);
            let isolated = lines[start..=idx]
                .iter()
                .any(|l| ISOLATION_MARKERS.iter().any(|m| l.contains(m)));
            if !defined && !isolated {
                found.push(format!("{path}:{} fn {name}", idx + 1));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Every `.rs` file under `dir`, sorted, as `(repo-relative path, text)`.
fn read_tree(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read src directory")
        .map(|e| e.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            read_tree(root, &path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = path
                .strip_prefix(root)
                .expect("under the manifest root")
                .to_string_lossy()
                .into_owned();
            out.push((
                rel,
                std::fs::read_to_string(&path).expect("read source file"),
            ));
        }
    }
}

/// The class invariant over the real tree. Red before the fix: the MCP latch
/// test and the audit latch cells mutated the shared process's latch.
#[test]
fn no_lib_test_latches_the_shared_process_7321() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    read_tree(root, &root.join("src"), &mut files);
    assert!(files.len() > 100, "the scan must see the whole src tree");
    let found = unisolated_sites(&files);
    assert!(
        found.is_empty(),
        "these tests mutate the process-global audit latch in the shared test process; \
         wrap each in `run_env_isolated_child_or_spawn` (#7321):\n{}",
        found.join("\n")
    );
}

/// The scanner itself, on synthetic sources: one row per decision.
#[test]
fn the_latch_scanner_decides_each_form_exactly_7321() {
    let plain = "#[test]\nfn plain() {\n    let _l = latch_for_test();\n}\n";
    let isolated = "#[test]\nfn iso() {\n    if run_env_isolated_child_or_spawn(\"x\") { return; }\n    force_on_for_test(true);\n}\n";
    let legacy = "fn t() {\n    with_legacy_push_env(\"n\", async {\n        let _l = fail_closed_latch_for_test();\n    });\n}\n";
    let defined =
        "pub(crate) fn force_on_for_test(on: bool) {\n    reset_probe_clock_for_test();\n}\n";
    let storing = "#[test]\nfn raw() {\n    LATCHED.store(true, Ordering::SeqCst);\n}\n";
    let comment = "fn quiet() {\n    // latch_for_test( is only named here\n}\n";
    let import = "pub(crate) use fail_closed::latch_for_test as x;\n";
    let table: [(&str, &str, &[&str]); 7] = [
        ("src/a.rs", plain, &["src/a.rs:3 fn plain"]),
        ("src/b.rs", isolated, &[]),
        ("src/c.rs", legacy, &[]),
        ("src/audit/fail_closed.rs", defined, &[]),
        ("src/d.rs", storing, &["src/d.rs:3 fn raw"]),
        ("src/e.rs", comment, &[]),
        ("src/f.rs", import, &[]),
    ];
    for (path, text, expected) in table {
        let got = unisolated_sites(&[(path.to_string(), text.to_string())]);
        assert_eq!(got, expected, "{path}");
    }
    let outside = unisolated_sites(&[("src/other.rs".to_string(), defined.to_string())]);
    assert_eq!(
        outside,
        [
            "src/other.rs:1 fn force_on_for_test",
            "src/other.rs:2 fn force_on_for_test"
        ],
        "the definition allowlist is keyed by file, not by name alone"
    );
}
