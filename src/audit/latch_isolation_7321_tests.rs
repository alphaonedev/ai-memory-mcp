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
//! The invariant is fail-closed by construction, in two layers:
//!
//! 1. RUN TIME (the guarantee). Every test-only function in
//!    `audit::fail_closed` that sets, clears or swaps the latch first asserts
//!    that it runs in an isolated child process (the role env the isolation
//!    helper sets on the child only) and panics with one exact message naming
//!    the function otherwise. No spelling of the call (alias, spacing, line
//!    split, helper, `Drop` impl, comment, ignored guard result) can reach the
//!    latch from the shared process, because the check lives in the mutator.
//!    [`every_way_of_reaching_the_latch_refuses_in_the_shared_process_7321`]
//!    drives each form through the real mutators.
//! 2. SOURCE TEXT (the ratchet). The latch's names may appear only in the
//!    files, and only as the names, listed in [`ALLOWLIST`], each with its
//!    reason. The private statics cannot be named outside `fail_closed.rs`
//!    (the compiler enforces it); inside it the `mod tests` section may not
//!    name them at all and goes through the asserting setters.

use std::path::Path;

/// The names that reach the latch: the four private statics, then every
/// test-only function that sets, clears or swaps it (and the alias and guard
/// type that name them).
const LATCH_NAMES: [&str; 11] = [
    "LATCHED",
    "LAST_PROBE_MS",
    "FORCE_ON_FOR_TEST",
    "FAILURE_EPOCH",
    "force_on_for_test",
    "latch_for_test",
    "fail_closed_latch_for_test",
    "reset_probe_clock_for_test",
    "reset_for_test",
    "set_latched_for_test",
    "LatchGuard",
];

/// The private statics: no `mod tests` code may name them.
const LATCH_STATICS: [&str; 4] = [
    "LATCHED",
    "LAST_PROBE_MS",
    "FORCE_ON_FOR_TEST",
    "FAILURE_EPOCH",
];

/// The file that defines the latch.
const FAIL_CLOSED_PATH: &str = "src/audit/fail_closed.rs";

/// One file that may name the latch, which names it may use, and why.
struct Permit {
    path: &'static str,
    names: &'static [&'static str],
    reason: &'static str,
}

/// Every file that may name a latch name. A file not listed here, or a listed
/// file naming a name it does not permit, fails the ratchet.
const ALLOWLIST: [Permit; 7] = [
    Permit {
        path: FAIL_CLOSED_PATH,
        names: &[
            "LATCHED",
            "LAST_PROBE_MS",
            "FORCE_ON_FOR_TEST",
            "FAILURE_EPOCH",
            "force_on_for_test",
            "latch_for_test",
            "reset_probe_clock_for_test",
            "reset_for_test",
            "set_latched_for_test",
            "LatchGuard",
        ],
        reason: "defines the statics, the production gate and the asserting test setters",
    },
    Permit {
        path: "src/audit.rs",
        names: &["latch_for_test", "fail_closed_latch_for_test"],
        reason: "the cfg(test) re-export that gives the other modules' tests one alias",
    },
    Permit {
        path: "src/audit/fail_closed_4400_tests.rs",
        names: &["force_on_for_test", "reset_probe_clock_for_test"],
        reason: "end-to-end cells; each runs in an isolated child (the setters assert it)",
    },
    Permit {
        path: "src/mcp/mod.rs",
        names: &["fail_closed_latch_for_test"],
        reason: "the MCP latched-write test; isolated child (the setter asserts it)",
    },
    Permit {
        path: "src/handlers/tests.rs",
        names: &["fail_closed_latch_for_test"],
        reason: "the sync-push latch test; isolated child through with_legacy_push_env",
    },
    Permit {
        path: "src/cli/doctor.rs",
        names: &["LATCHED"],
        reason: "the word in the doctor status text and its assertion; the statics are private",
    },
    Permit {
        path: "src/audit/latch_isolation_7321_tests.rs",
        names: &LATCH_NAMES,
        reason: "this file names every latch name as data and drives each mutator",
    },
];

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Every latch name that appears on `line` as a whole identifier. Comments and
/// strings are NOT skipped: a name anywhere in a file needs the file listed.
fn names_on_line(line: &str) -> Vec<&'static str> {
    LATCH_NAMES
        .iter()
        .copied()
        .filter(|name| {
            line.match_indices(*name).any(|(at, _)| {
                let before = line[..at].chars().next_back();
                let after = line[at + name.len()..].chars().next();
                !before.is_some_and(is_ident_char) && !after.is_some_and(is_ident_char)
            })
        })
        .collect()
}

/// Every `file:line name` that breaks the allowlist, sorted.
fn unlisted_names(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, text) in files {
        let permit = ALLOWLIST.iter().find(|p| p.path == path);
        let lines: Vec<&str> = text.lines().collect();
        let tests_start = if path == FAIL_CLOSED_PATH {
            let start = lines.iter().position(|l| l.trim_end() == "mod tests {");
            if start.is_none() {
                found.push(format!("{path}: no `mod tests {{` line found"));
            }
            start
        } else {
            None
        };
        for (idx, line) in lines.iter().enumerate() {
            for name in names_on_line(line) {
                let at = idx + 1;
                if !permit.is_some_and(|p| p.names.contains(&name)) {
                    found.push(format!("{path}:{at} {name}"));
                } else if LATCH_STATICS.contains(&name) && tests_start.is_some_and(|s| idx > s) {
                    found.push(format!("{path}:{at} {name} inside mod tests"));
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Every `.rs` file under `dir`, sorted, as `(repo-relative path, text)`.
/// Hidden directories and `target` are build or tool output, not source. A
/// symlink or an unreadable file panics: it cannot be proven free of the latch.
fn read_tree(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read source directory")
        .map(|e| e.expect("directory entry"))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = entry.file_type().expect("file type");
        assert!(!kind.is_symlink(), "symlink in the source tree: {path:?}");
        if kind.is_dir() {
            if !name.starts_with('.') && name != "target" {
                read_tree(root, &path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = path
                .strip_prefix(root)
                .expect("under the manifest root")
                .to_string_lossy()
                .replace('\\', "/");
            out.push((
                rel,
                std::fs::read_to_string(&path).expect("read source file"),
            ));
        }
    }
}

fn whole_tree() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    read_tree(root, root, &mut files);
    assert!(files.len() > 100, "the scan must see the whole tree");
    assert!(
        files.iter().any(|(p, _)| p == FAIL_CLOSED_PATH),
        "the scan must see {FAIL_CLOSED_PATH}"
    );
    files
}

/// The class invariant over the real tree: only the listed files name the
/// latch, and `fail_closed.rs`'s tests never touch a static.
#[test]
fn the_latch_names_appear_only_where_the_allowlist_says_7321() {
    let found = unlisted_names(&whole_tree());
    assert!(
        found.is_empty(),
        "these places name the process-global audit latch outside ALLOWLIST (#7321); \
         use the asserting setters from an isolated test, or list the file with its reason:\n{}",
        found.join("\n")
    );
}

/// No stale allowance: every name each entry permits really appears in it, and
/// every entry carries its reason.
#[test]
fn every_allowlist_entry_is_used_and_explained_7321() {
    let files = whole_tree();
    for permit in &ALLOWLIST {
        assert!(!permit.reason.is_empty(), "{} has no reason", permit.path);
        let (_, text) = files
            .iter()
            .find(|(p, _)| p == permit.path)
            .unwrap_or_else(|| panic!("allowlisted file {} is gone", permit.path));
        for name in permit.names {
            assert!(
                text.lines().any(|l| names_on_line(l).contains(name)),
                "{} permits {name} but never names it: drop it from ALLOWLIST",
                permit.path
            );
        }
    }
}

/// The scanner on synthetic sources: one row per bypass form the round-1
/// review listed, plus the boundary and allowlist rows. The expected column is
/// written out by hand.
#[test]
fn the_allowlist_scanner_decides_each_form_exactly_7321() {
    const OTHER: &str = "src/other.rs";
    let tests_touching_static = "fn gate() { LATCHED.store(false); }\n#[cfg(test)]\nmod tests {\n    fn t() { LATCHED.store(true); }\n}\n";
    let table: [(&str, &str, &str, &[&str]); 21] = [
        (
            "plain call",
            OTHER,
            "let _l = latch_for_test();",
            &["src/other.rs:1 latch_for_test"],
        ),
        (
            "use alias",
            OTHER,
            "use crate::audit::fail_closed_latch_for_test as renamed;\nlet _l = renamed();",
            &["src/other.rs:1 fail_closed_latch_for_test"],
        ),
        (
            "space before the parenthesis",
            OTHER,
            "force_on_for_test (true);",
            &["src/other.rs:1 force_on_for_test"],
        ),
        (
            "LATCHED.swap",
            OTHER,
            "LATCHED.swap(true, Ordering::SeqCst);",
            &["src/other.rs:1 LATCHED"],
        ),
        (
            "FORCE_ON_FOR_TEST direct store",
            OTHER,
            "FORCE_ON_FOR_TEST.store(true, Ordering::SeqCst);",
            &["src/other.rs:1 FORCE_ON_FOR_TEST"],
        ),
        (
            "name and .store split across lines",
            OTHER,
            "LATCHED\n    .store(true, Ordering::SeqCst);",
            &["src/other.rs:1 LATCHED"],
        ),
        (
            "one-line test fn",
            OTHER,
            "#[test] fn bad() { reset_for_test(); }",
            &["src/other.rs:1 reset_for_test"],
        ),
        (
            "guard name only in a comment",
            OTHER,
            "// run_env_isolated_child_or_spawn(\"x\")\nreset_for_test();",
            &["src/other.rs:2 reset_for_test"],
        ),
        (
            "guard result ignored",
            OTHER,
            "let _ = run_env_isolated_child_or_spawn(\"x\");\nforce_on_for_test(true);",
            &["src/other.rs:2 force_on_for_test"],
        ),
        (
            "pub(in path) fn prefix",
            OTHER,
            "pub(in crate::audit) fn bad() { latch_for_test(); }",
            &["src/other.rs:1 latch_for_test"],
        ),
        (
            "fn drop in another impl",
            OTHER,
            "impl Drop for X { fn drop(&mut self) { force_on_for_test(false); } }",
            &["src/other.rs:1 force_on_for_test"],
        ),
        (
            "reset_probe_clock_for_test",
            OTHER,
            "reset_probe_clock_for_test();",
            &["src/other.rs:1 reset_probe_clock_for_test"],
        ),
        (
            "set_latched_for_test",
            OTHER,
            "set_latched_for_test(true);",
            &["src/other.rs:1 set_latched_for_test"],
        ),
        (
            "a listed file naming a name it does not permit",
            "src/mcp/mod.rs",
            "reset_for_test();",
            &["src/mcp/mod.rs:1 reset_for_test"],
        ),
        (
            "a listed file naming a permitted name",
            "src/mcp/mod.rs",
            "let _l = crate::audit::fail_closed_latch_for_test();",
            &[],
        ),
        (
            "the defining file under another prefix",
            "x/src/audit/fail_closed.rs",
            "force_on_for_test(true);",
            &["x/src/audit/fail_closed.rs:1 force_on_for_test"],
        ),
        (
            "a child module of fail_closed",
            "src/audit/fail_closed/child.rs",
            "LATCHED.store(true, Ordering::SeqCst);",
            &["src/audit/fail_closed/child.rs:1 LATCHED"],
        ),
        (
            "a static inside the tests section of fail_closed.rs",
            FAIL_CLOSED_PATH,
            tests_touching_static,
            &["src/audit/fail_closed.rs:4 LATCHED inside mod tests"],
        ),
        (
            "fail_closed.rs without a tests section",
            FAIL_CLOSED_PATH,
            "fn gate() { LATCHED.store(false); }",
            &["src/audit/fail_closed.rs: no `mod tests {` line found"],
        ),
        (
            "other identifiers that merely contain a name",
            OTHER,
            "let a = AUDIT_TRAIL_LATCHED_GAUGE; let b = unlatched; let c = my_latch_for_test_helper;",
            &[],
        ),
        (
            "the doctor word is the only name that file may use",
            "src/cli/doctor.rs",
            "\"on, LATCHED (refused)\"",
            &[],
        ),
    ];
    for (form, path, text, expected) in table {
        let got = unlisted_names(&[(path.to_string(), text.to_string())]);
        assert_eq!(got, expected, "{form}");
    }
}

/// The exact refusal a latch mutator gives outside an isolated child. Written
/// out here, not read from the code under test.
pub(super) fn refusal_for(function: &str) -> String {
    format!(
        "{function} mutates the process-global audit latch and may only run in an isolated \
         child test process (#7321); wrap the test in run_env_isolated_child_or_spawn"
    )
}

/// The panic message of `body`, or `None` when it returned normally.
pub(super) fn panic_message(body: fn()) -> Option<String> {
    std::panic::catch_unwind(body).err().map(|payload| {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_else(|| "<non-string panic payload>".to_string())
    })
}

/// A test that is not an isolated child must not be mistaken for one.
pub(super) fn assert_shared_process() {
    assert_ne!(
        std::env::var(crate::test_support::TEST_ENV_ISOLATION_ROLE_ENV).as_deref(),
        Ok("child"),
        "this test proves the refusal in the shared process; never run it as an isolated child"
    );
}

use super::fail_closed::{
    force_on_for_test, latch_for_test, reset_for_test, reset_probe_clock_for_test,
    set_latched_for_test,
};

fn direct_force_on() {
    force_on_for_test(true);
}

fn direct_reset() {
    reset_for_test();
}

fn direct_set_latched() {
    set_latched_for_test(true);
}

fn direct_latch() {
    let _guard = latch_for_test();
}

fn direct_probe_clock() {
    reset_probe_clock_for_test();
}

fn through_a_use_alias() {
    use super::fail_closed_latch_for_test as renamed;
    let _guard = renamed();
}

#[rustfmt::skip]
fn space_before_the_parenthesis() { force_on_for_test (true); }

#[rustfmt::skip]
fn call_split_across_lines() {
    super::fail_closed::force_on_for_test
        (true)
        ;
}

#[rustfmt::skip]
fn one_line_fn() { reset_for_test() }

fn guard_name_only_in_a_comment() {
    // run_env_isolated_child_or_spawn("x") is named here and never called
    reset_for_test();
}

/// Stands for an isolation guard whose result the caller drops.
fn guard_stub(_exact_path: &str) -> bool {
    false
}

fn guard_result_ignored() {
    let _ = guard_stub("x");
    force_on_for_test(true);
}

pub(in crate::audit) fn pub_in_path_helper() {
    let _guard = latch_for_test();
}

fn through_a_pub_in_path_fn() {
    pub_in_path_helper();
}

struct DropsTheLatch;

impl Drop for DropsTheLatch {
    fn drop(&mut self) {
        force_on_for_test(false);
    }
}

fn through_another_drop_impl() {
    let _dropped = DropsTheLatch;
}

/// Every way a test can reach the latch from the shared process panics with
/// the exact message naming the function reached. Red before the fix: none of
/// them panicked, each mutated the shared process's latch.
#[test]
fn every_way_of_reaching_the_latch_refuses_in_the_shared_process_7321() {
    assert_shared_process();
    let table: [(&str, &str, fn()); 13] = [
        ("force_on_for_test", "force_on_for_test", direct_force_on),
        ("reset_for_test", "reset_for_test", direct_reset),
        (
            "set_latched_for_test",
            "set_latched_for_test",
            direct_set_latched,
        ),
        ("latch_for_test", "latch_for_test", direct_latch),
        (
            "reset_probe_clock_for_test",
            "reset_probe_clock_for_test",
            direct_probe_clock,
        ),
        ("use alias", "latch_for_test", through_a_use_alias),
        (
            "space before the parenthesis",
            "force_on_for_test",
            space_before_the_parenthesis,
        ),
        (
            "call split across lines",
            "force_on_for_test",
            call_split_across_lines,
        ),
        ("one-line fn", "reset_for_test", one_line_fn),
        (
            "guard name only in a comment",
            "reset_for_test",
            guard_name_only_in_a_comment,
        ),
        (
            "guard result ignored",
            "force_on_for_test",
            guard_result_ignored,
        ),
        (
            "pub(in path) fn",
            "latch_for_test",
            through_a_pub_in_path_fn,
        ),
        (
            "fn drop in another impl",
            "force_on_for_test",
            through_another_drop_impl,
        ),
    ];
    let wrong: Vec<String> = table
        .iter()
        .filter_map(|(form, function, body)| {
            let got = panic_message(*body);
            (got.as_deref() != Some(refusal_for(function).as_str()))
                .then(|| format!("{form}: expected {:?}, got {got:?}", refusal_for(function)))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// #7321, the issue's victim (`mcp::tests::chunkc_archive_gc_dry_run_returns_count`)
/// and every other write-path test that does not isolate reads the latch in the
/// shared process; the owner's 2026-11-19 comment on #7321 says that test "must
/// not depend on that state". This pins why it cannot: nothing in the shared
/// process can set the latch or force the mode on. Every test-only mutator
/// refuses there (the table above), the mode comes only from the environment,
/// and a gate that never sees the mode on never latches
/// (`note_failure_for_latch`). After driving every mutator, the shared
/// process's latch is clear and its mode equals the environment's.
#[test]
fn the_shared_process_latch_stays_clear_for_unisolated_readers_7321() {
    assert_shared_process();
    let mutators: [fn(); 5] = [
        direct_force_on,
        direct_reset,
        direct_latch,
        direct_probe_clock,
        direct_set_latched,
    ];
    for mutator in mutators {
        assert!(
            panic_message(mutator).is_some(),
            "a mutator ran in the shared process"
        );
    }
    assert!(
        !crate::audit::audit_trail_latched(),
        "no test in the shared process may leave the latch set"
    );
    let from_environment = std::env::var(crate::audit::REQUIRE_AUDIT_TRAIL_ENV)
        .is_ok_and(|v| crate::security_profile::is_truthy(&v));
    assert_eq!(
        crate::audit::require_audit_trail_enabled(),
        from_environment,
        "the shared process's mode is the environment's, never forced"
    );
}
