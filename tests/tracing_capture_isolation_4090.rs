// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4090 — every lib-test that CAPTURES `tracing` output must run its body
//! alone in a re-exec'd child process.
//!
//! The `tracing` callsite-interest cache and the global max-level hint are
//! process-global. In the shared lib test binary a sibling test on another
//! thread (no subscriber, or a lower-level one) can race a thread-local
//! `set_default` / `with_default` capture so the capture reads NOTHING (the
//! #3426 / #4088 mechanism). A present-plus-absent capture then flakes red;
//! an absence-only capture passes VACUOUSLY — for a secret-redaction guard
//! such as #1579 A3 that is the worst direction.
//!
//! #4088 isolated seven sites with `crate::config::run_env_isolated_child_or_spawn`
//! and #4090 isolates the last one (`daemon_runtime`). This census closes the
//! CLASS: it scans `src/` for every thread-local subscriber install and
//! requires, for the enclosing function, one of:
//!
//! 1. an isolation guard `run_env_isolated_child_or_spawn("<path>")` that
//!    appears BEFORE the install and whose exact path ends in
//!    `::<enclosing fn name>` (a copy-pasted guard naming another test fails);
//! 2. the enclosing function is a capture HELPER: then every call of that
//!    helper in the same file must itself satisfy (1);
//! 3. the site is listed as IMMUNE with a written reason (it never reads a
//!    capture through the callsite cache).
//!
//! Stale allowlist entries fail too, so the lists cannot rot.

use std::fs;
use std::path::{Path, PathBuf};

/// Thread-local subscriber installs that start a capture.
const INSTALL_PATTERNS: &[&str] = &[
    "subscriber::set_default(",
    "subscriber::with_default(",
    "dispatcher::set_default(",
    "dispatcher::with_default(",
];

const GUARD: &str = "run_env_isolated_child_or_spawn(";

/// (file, fn): capture helpers whose CALLERS must be isolated. A caller that
/// is itself listed here is followed in turn (same file).
const HELPERS: &[(&str, &str)] = &[
    ("src/mcp/span_capture_4088_tests.rs", "run_with_capture"),
    ("src/mcp/provider_echo_sinks_3648_tests.rs", "assert_sink"),
    ("src/mcp/provider_echo_sinks_3648_tests.rs", "run_matrix"),
];

/// (file, enclosing fn, tracking): known-unguarded sites whose guard is
/// already written but rides another landing unit. Accepted guarded or not,
/// so the other unit landing cannot turn this census red; remove the entry
/// once it has landed.
const PENDING: &[(&str, &str, &str)] = &[(
    "src/federation/mod.rs",
    "broadcast_emits_entry_line_log_for_track_d_grep",
    "#4088 guard f57aa7e05 rides the lane A federation-wire batch (a watched \
     cert path, not editable outside that batch)",
)];

/// (file, enclosing fn, reason): installs that never read a capture through
/// the process-global callsite cache.
const IMMUNE: &[(&str, &str, &str)] = &[
    (
        "src/logging.rs",
        "filter_admits_3650",
        "writer is io::sink; asserts dispatch.enabled() on synthetic metadata, \
         which never consults the callsite-interest cache (f2r, #4088 review)",
    ),
    (
        "src/logging.rs",
        "default_filter_admits_every_explicit_target_3650",
        "#3650 census: writer is io::sink; asserts dispatch.enabled() on \
         synthetic metadata (f2r, #4088 review)",
    ),
];

fn walk_rs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Name of the fn declared on `line`, if any (`fn`, `async fn`, `pub fn`, ...).
fn fn_name(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if t.starts_with("//") {
        return None;
    }
    let idx = t.find("fn ")?;
    let prefix = &t[..idx];
    let prefix_ok = prefix
        .split_whitespace()
        .all(|w| matches!(w, "pub" | "async" | "const" | "unsafe") || w.starts_with("pub("));
    if !prefix_ok {
        return None;
    }
    let rest = &t[idx + 3..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    (end > 0).then(|| &rest[..end])
}

/// The innermost fn that ENCLOSES line `at`: the nearest preceding fn
/// declaration with a strictly smaller indentation (skips nested helper
/// impls such as `fn write` inside a test body).
fn enclosing_fn(lines: &[&str], at: usize) -> Option<(usize, String)> {
    let site_indent = indent_of(lines[at]);
    (0..at).rev().find_map(|i| {
        let l = lines[i];
        if indent_of(l) < site_indent {
            fn_name(l).map(|n| (i, n.to_string()))
        } else {
            None
        }
    })
}

/// Does the text between the fn declaration and the site carry a guard whose
/// exact path names this very fn?
fn guarded(lines: &[&str], fn_line: usize, site: usize, name: &str) -> Result<(), String> {
    let body = lines[fn_line..site].join("\n");
    let Some(pos) = body.find(GUARD) else {
        return Err("no run_env_isolated_child_or_spawn guard before the capture".into());
    };
    let after = &body[pos + GUARD.len()..];
    let lit = after
        .split('"')
        .nth(1)
        .ok_or_else(|| "guard has no string-literal exact path".to_string())?;
    let want = format!("::{name}");
    if lit.ends_with(&want) {
        Ok(())
    } else {
        Err(format!("guard exact path `{lit}` does not end in `{want}`"))
    }
}

/// Check one call site of a capture helper: the enclosing fn must be
/// guarded, or itself be a helper whose callers are (followed recursively).
fn check_caller(
    rel: &str,
    lines: &[&str],
    at: usize,
    helper: &str,
    depth: usize,
    failures: &mut Vec<String>,
) -> usize {
    let Some((cl, cname)) = enclosing_fn(lines, at) else {
        failures.push(format!(
            "{rel}:{}: call of `{helper}` outside any fn",
            at + 1
        ));
        return 0;
    };
    if HELPERS.iter().any(|(f, n)| *f == rel && *n == cname) {
        return check_helper(rel, lines, &cname, depth + 1, failures);
    }
    match guarded(lines, cl, at, &cname) {
        Ok(()) => 1,
        Err(e) => {
            failures.push(format!(
                "{rel}:{}: `{cname}` calls capture helper `{helper}`: {e}",
                at + 1
            ));
            0
        }
    }
}

/// Every call of `helper` in the file must reach a guarded test.
fn check_helper(
    rel: &str,
    lines: &[&str],
    helper: &str,
    depth: usize,
    failures: &mut Vec<String>,
) -> usize {
    if depth > 4 {
        failures.push(format!(
            "{rel}: helper chain through `{helper}` is too deep"
        ));
        return 0;
    }
    let call = format!("{helper}(");
    let mut guarded_calls = 0usize;
    let mut callers = 0usize;
    for (j, l) in lines.iter().enumerate() {
        if !l.contains(&call) || fn_name(l).is_some() || l.trim_start().starts_with("//") {
            continue;
        }
        callers += 1;
        guarded_calls += check_caller(rel, lines, j, helper, depth, failures);
    }
    if callers == 0 {
        failures.push(format!("{rel}: capture helper `{helper}` has no callers"));
    }
    guarded_calls
}

#[test]
fn every_lib_tracing_capture_runs_in_an_isolated_child_4090() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk_rs(&root.join("src"), &mut files);
    files.sort();

    let mut failures = Vec::new();
    let mut sites = 0usize;
    let mut guarded_sites = 0usize;
    let mut seen: Vec<(String, String)> = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(root)
            .expect("under manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(path).expect("read src file");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//")
                || !INSTALL_PATTERNS.iter().any(|p| line.contains(p))
            {
                continue;
            }
            sites += 1;
            let Some((fn_line, name)) = enclosing_fn(&lines, i) else {
                failures.push(format!("{rel}:{}: install outside any fn", i + 1));
                continue;
            };
            seen.push((rel.clone(), name.clone()));
            if IMMUNE.iter().any(|(f, n, _)| *f == rel && *n == name)
                || PENDING.iter().any(|(f, n, _)| *f == rel && *n == name)
            {
                continue;
            }
            if HELPERS.iter().any(|(f, n)| *f == rel && *n == name) {
                guarded_sites += check_helper(&rel, &lines, &name, 0, &mut failures);
                continue;
            }
            match guarded(&lines, fn_line, i, &name) {
                Ok(()) => guarded_sites += 1,
                Err(e) => failures.push(format!(
                    "{rel}:{}: `{name}` captures tracing in the shared lib binary: {e}",
                    i + 1
                )),
            }
        }
    }

    let installs = |f: &str, n: &str| seen.iter().any(|(sf, sn)| sf == f && sn == n);
    for (f, n, _) in IMMUNE.iter().chain(PENDING) {
        if !installs(f, n) {
            failures.push(format!(
                "stale allowlist entry: {f} `{n}` installs no subscriber"
            ));
        }
    }
    for (f, n) in HELPERS {
        let text = fs::read_to_string(root.join(f)).unwrap_or_default();
        if !text.lines().any(|l| fn_name(l) == Some(n)) {
            failures.push(format!("stale HELPERS entry: {f} has no fn `{n}`"));
        }
    }

    assert!(
        failures.is_empty(),
        "#4090: tracing-capture lib tests must run alone in a re-exec'd child \
         (`if crate::config::run_env_isolated_child_or_spawn(\"<exact path>\") {{ return; }}` \
         as the first statement), or be listed with a reason:\n{}",
        failures.join("\n")
    );
    // Anti-vacuous: the scanner must see the known population (10 installs;
    // 11 guarded tests counting each helper call).
    assert!(
        sites >= 10 && guarded_sites >= 10,
        "#4090 census scanner found too few sites ({sites} installs, {guarded_sites} \
         guarded) — the scanner is broken, not the class closed"
    );
}
