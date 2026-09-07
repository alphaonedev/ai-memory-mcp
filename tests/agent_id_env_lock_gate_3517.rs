// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (issue #3517) — the STRUCTURAL gate for caller-identity env
//! mutation inside the lib test binary.
//!
//! # Why this gate exists
//!
//! `src/**/*.rs` compiles into ONE `cargo test --lib` binary whose `#[test]`
//! functions run in PARALLEL THREADS. `std::env::set_var` /
//! `std::env::remove_var` mutate the single process-global environment table,
//! so two tests touching `AI_MEMORY_AGENT_ID` at once are a genuine data race
//! (rust-1.98 UNSAFE-01/03) — and worse, the mutation is globally VISIBLE:
//! `identity::resolve_read_visibility_caller()` reads that variable with no
//! injectable seam, so while one test holds a foreign principal installed,
//! every concurrently-running reader resolves it too. That is the
//! `agent_id mismatch: caller 'ai:bob' …` / cross-tenant-refusal flake class
//! reported in #3517 against `mcp::pending` and `coordination_guard`.
//!
//! Serializing the mutators is the containment (the victims — the readers —
//! never take the lock, which is why #3475 additionally BANS installing a
//! value from a lib test; `scripts/check-test-env-lock.sh` arm (d) ratchets
//! that census). This gate closes the OTHER half of the same defect: the
//! mutators must all serialize on **one** mutex.
//!
//! # The defect this gate makes unrepresentable
//!
//! Before #3517 the crate held TWO independent mutexes over the SAME variable:
//! the crate-wide `identity::agent_id_env_test_lock()` (#1772) that
//! `mcp::tools::*` / `storage` / `cli::recall` / `coordination_guard` take, and
//! a MODULE-LOCAL `OnceLock<Mutex<()>>` named `env_var_lock` in each of
//! `identity::tests` and `daemon_runtime::tests`. Holding either one excluded
//! only its own users, so `identity::tests` and `mcp::tools::pending::tests`
//! could mutate `AI_MEMORY_AGENT_ID` at literally the same instant. This is
//! the identical per-module-mutex defect `$HOME` suffered three times
//! (#1998 → #2115 → #2127) before `config::test_env_lock()` unified it.
//!
//! # The marker (documented, deliberately simple)
//!
//! A mutation line is any non-comment `src/**/*.rs` line that spells
//! `set_var(` or `remove_var(` together with one of [`CALLER_ENV_MARKERS`].
//! For each one the gate resolves the ENCLOSING `fn` (the nearest preceding
//! `fn` line through the next `fn` line) and requires that function body to
//! cite a canonical guard token — [`CANONICAL_GUARD_TOKENS`] — either
//! directly, or through a FILE-LOCAL DELEGATE: a `fn NAME(` defined in the
//! same file whose own body cites a canonical token. The delegate arm is what
//! keeps `let _g = env_var_lock();` legal in `identity` / `daemon_runtime` /
//! `config` while remaining self-verifying: rewrite a delegate back into a
//! private `static LOCK: OnceLock<Mutex<()>>` and every call site in that file
//! turns into a violation, which is exactly the #3517 regression.
//!
//! Line-based, like every sibling `scripts/check-*.sh` gate: a commented-out
//! mutation is skipped, and the fn window is bounded by `fn` lines rather than
//! brace counting (brace counting mis-parses `format!("{x}")`).
//!
//! The `detector_*` tests drive [`unguarded_mutations`] over six synthetic
//! buffers so the gate is proven to CATCH the naked / module-local-mutex /
//! admin-twin shapes and SPARE the canonical, delegated and commented-out
//! ones, rather than passing vacuously on today's tree.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Process-global environment variables that decide WHO THE CALLER IS. A lib
/// test mutating one of these steers every concurrent reader in the binary, so
/// each mutation must sit inside a canonically-guarded function.
///
/// `AI_MEMORY_ANONYMIZE` is deliberately absent: `daemon_runtime` mutates it
/// from PRODUCTION startup code (`apply_startup_env`, single-threaded before
/// the tokio runtime exists), so a line-based gate cannot separate the
/// production site from the test sites. Its test sites are nonetheless
/// serialized, because they run under the same delegated `env_var_lock()`.
const CALLER_ENV_MARKERS: [&str; 3] = [
    "\"AI_MEMORY_AGENT_ID\"",
    "\"AI_MEMORY_ADMIN_AGENT_IDS\"",
    "ENV_AGENT_ID",
];

/// The ONE canonical serialization for [`CALLER_ENV_MARKERS`]:
/// `identity::agent_id_env_test_lock()` and the RAII fixture built on it,
/// `identity::agent_id_env_unset_guard()`. Citing either token inside the
/// enclosing function satisfies the gate.
const CANONICAL_GUARD_TOKENS: [&str; 2] = ["agent_id_env_test_lock", "agent_id_env_unset_guard"];

/// The one sanctioned mutation with no in-function guard token: the `Drop`
/// impl of `identity::AgentIdEnvUnsetGuard`, which restores the pre-guard
/// value while STILL HOLDING the canonical lock in its own `_lock` field. The
/// guard is the reason the lock is held, so it cannot re-acquire it
/// (`std::sync::Mutex` is not reentrant — CONCURRENCY-04).
const ALLOWLISTED_SITES: [(&str, &str); 1] = [("src/identity/mod.rs", "drop")];

fn repo_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Dot-prefixed scratch files are never compiled into the lib test
        // binary (they are the `scripts/check-*.sh` self-test fixtures).
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("*/")
}

/// Does this line START a function definition? Skips the leading
/// visibility/qualifier tokens (`pub`, `pub(crate)`, `async`, `unsafe`,
/// `const`, `extern "C"`) and asks whether the next token is `fn`.
fn fn_name_at(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    loop {
        let token = tokens.next()?;
        if token == "fn" {
            break;
        }
        let is_qualifier = token == "async"
            || token == "unsafe"
            || token == "const"
            || token == "extern"
            || token == "pub"
            || token.starts_with("pub(")
            || token.starts_with('"'); // the ABI string of `extern "C"`
        if !is_qualifier {
            return None;
        }
    }
    let rest = tokens.next()?;
    let name: &str = rest.split(['(', '<']).next().unwrap_or(rest);
    (!name.is_empty()).then_some(name)
}

/// Is this a caller-identity env mutation the gate polices?
fn is_caller_env_mutation(line: &str) -> bool {
    let trimmed = line.trim_start();
    if is_comment_line(trimmed) {
        return false;
    }
    if !(line.contains("set_var(") || line.contains("remove_var(")) {
        return false;
    }
    CALLER_ENV_MARKERS.iter().any(|m| line.contains(*m))
}

/// Names of file-local functions whose own body cites a canonical guard token
/// — i.e. verified DELEGATES to the one canonical lock. Calling one of these
/// is as good as calling the canonical helper directly.
fn verified_delegate_names(lines: &[&str]) -> BTreeSet<String> {
    let fn_starts: Vec<usize> = (0..lines.len())
        .filter(|&i| fn_name_at(lines[i]).is_some())
        .collect();
    let mut out = BTreeSet::new();
    for (n, &start) in fn_starts.iter().enumerate() {
        let end = fn_starts.get(n + 1).copied().unwrap_or(lines.len());
        let Some(name) = fn_name_at(lines[start]) else {
            continue;
        };
        // The canonical helpers themselves are matched by token, not by name.
        if CANONICAL_GUARD_TOKENS.contains(&name) {
            continue;
        }
        let body = &lines[start..end];
        if body
            .iter()
            .any(|l| CANONICAL_GUARD_TOKENS.iter().any(|t| l.contains(*t)))
        {
            out.insert(name.to_string());
        }
    }
    out
}

/// The gate detector, factored out of the filesystem walk so the self-test can
/// drive it over synthetic buffers (M-TAUTOLOGICAL-TESTS: the gate is proven
/// to CATCH the defect shape, not merely to pass on today's tree).
///
/// Returns one `"<line-number>: <fn name>"` entry per UNGUARDED mutation.
fn unguarded_mutations(rel_path: &str, source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let delegates = verified_delegate_names(&lines);
    let fn_starts: Vec<usize> = (0..lines.len())
        .filter(|&i| fn_name_at(lines[i]).is_some())
        .collect();

    let mut findings = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !is_caller_env_mutation(line) {
            continue;
        }
        // Enclosing fn = nearest preceding `fn` line; its window ends at the
        // next `fn` line (never brace counting — see the module header).
        let Some(&start) = fn_starts.iter().rev().find(|&&s| s <= i) else {
            findings.push(format!("{}: <no enclosing fn>", i + 1));
            continue;
        };
        let end = fn_starts
            .iter()
            .find(|&&s| s > start)
            .copied()
            .unwrap_or(lines.len());
        let name = fn_name_at(lines[start]).unwrap_or("<unnamed>");
        if ALLOWLISTED_SITES
            .iter()
            .any(|&(p, f)| p == rel_path && f == name)
        {
            continue;
        }
        let guarded = lines[start..end].iter().any(|l| {
            CANONICAL_GUARD_TOKENS.iter().any(|t| l.contains(*t))
                || delegates.iter().any(|d| l.contains(&format!("{d}(")))
        });
        if !guarded {
            findings.push(format!("{}: fn {name}", i + 1));
        }
    }
    findings
}

/// THE GATE. Every caller-identity env mutation in `src/**/*.rs` sits inside a
/// function serialized on the ONE canonical lock.
#[test]
fn caller_identity_env_mutation_is_canonically_locked_3517() {
    let src = repo_src_dir();
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(!files.is_empty(), "no src/**/*.rs files found");

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(manifest)
            .unwrap_or(file.as_path())
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for finding in unguarded_mutations(&rel, &source) {
            violations.push(format!("  {rel}:{finding}"));
        }
    }

    assert!(
        violations.is_empty(),
        "UNGUARDED caller-identity env mutation in the LIB TEST BINARY (#3517):\n{}\n\n\
         src/**/*.rs compiles into ONE test binary whose tests run in PARALLEL\n\
         THREADS. `AI_MEMORY_AGENT_ID` / `AI_MEMORY_ADMIN_AGENT_IDS` decide WHO\n\
         THE CALLER IS for every concurrent reader, so each mutation must be\n\
         serialized on the ONE canonical lock:\n\n  \
         let _g = crate::identity::agent_id_env_test_lock();   // mutating\n  \
         let _g = crate::identity::agent_id_env_unset_guard(); // asserting unset\n\n\
         A module-local `static LOCK: OnceLock<Mutex<()>>` does NOT count: it\n\
         excludes only its own users, which is the #3517 defect (and the\n\
         #1998 -> #2115 -> #2127 $HOME defect before it). A file-local wrapper\n\
         that DELEGATES to the canonical helper is fine.\n\n\
         Better still, per #3475: do not install a value from a lib test at\n\
         all — put the test in its own binary (tests/<name>.rs).",
        violations.join("\n")
    );
}

/// POSITIVE pin for the two wrappers #3517 converted. If either reverts to a
/// private mutex the gate above still fires — this test names WHICH one and
/// why, so the failure is diagnosable rather than a wall of call sites.
#[test]
fn module_local_env_var_lock_wrappers_delegate_to_the_canonical_lock_3517() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel in ["src/identity/mod.rs", "src/daemon_runtime.rs"] {
        let source = std::fs::read_to_string(manifest.join(rel))
            .unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let lines: Vec<&str> = source.lines().collect();
        let start = lines
            .iter()
            .position(|l| fn_name_at(l) == Some("env_var_lock"))
            .unwrap_or_else(|| panic!("{rel}: no `fn env_var_lock` found"));
        // The wrapper's body ends at ITS closing brace, not at the next `fn`
        // line: the doc comment of the sibling test below deliberately quotes
        // `OnceLock<Mutex<()>>` while describing the defect, and a next-`fn`
        // window would swallow that prose and self-trip the assertion.
        let end = (start + 1..lines.len())
            .find(|&i| lines[i].trim() == "}")
            .map_or(lines.len(), |i| i + 1);
        let body = lines[start..end].join("\n");
        assert!(
            body.contains("agent_id_env_test_lock"),
            "{rel}: `env_var_lock` must DELEGATE to the canonical \
             `identity::agent_id_env_test_lock()` (#3517), got:\n{body}"
        );
        assert!(
            !body.contains("OnceLock<"),
            "{rel}: `env_var_lock` declares its own mutex again — that is the \
             #3517 defect (a second, independent lock over the SAME \
             process-global variable):\n{body}"
        );
    }
}

// ---------------------------------------------------------------------------
// Detector self-tests. Without these the gate above could pass VACUOUSLY — a
// detector that never matches anything is green on every tree
// (M-TAUTOLOGICAL-TESTS). Each case is a separate `#[test]` so a regression
// names the SHAPE it broke.
// ---------------------------------------------------------------------------

/// The probe path is never a real file; only the allowlist compares against it.
const PROBE: &str = "src/contrived.rs";

/// NAKED — a mutation with no guard of any kind is caught.
#[test]
fn detector_catches_a_naked_mutation_3517() {
    let src = r#"
mod tests {
    #[test]
    fn naked() {
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:contrived") };
    }
}
"#;
    assert_eq!(
        unguarded_mutations(PROBE, src).len(),
        1,
        "an unguarded mutation must be caught"
    );
}

/// MODULE-LOCAL MUTEX — the exact #3517 defect. A second, independent lock
/// over the same process-global variable serializes nothing against the
/// canonical one, so it must NOT satisfy the gate.
#[test]
fn detector_catches_a_module_local_mutex_3517() {
    let src = r#"
mod tests {
    fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap()
    }
    #[test]
    fn locally_locked() {
        let _g = env_var_lock();
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:contrived") };
    }
}
"#;
    assert_eq!(
        unguarded_mutations(PROBE, src).len(),
        1,
        "a module-local mutex is NOT the canonical lock and must be caught"
    );
}

/// The sibling caller-affecting variable is policed identically.
#[test]
fn detector_catches_a_naked_admin_agent_ids_mutation_3517() {
    let src = r#"
mod tests {
    #[test]
    fn admin_naked() {
        unsafe { std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", "alice") };
    }
}
"#;
    assert_eq!(
        unguarded_mutations(PROBE, src).len(),
        1,
        "AI_MEMORY_ADMIN_AGENT_IDS must be policed like AI_MEMORY_AGENT_ID"
    );
}

/// CANONICAL — a direct acquisition of the one lock is spared.
#[test]
fn detector_spares_a_canonically_locked_mutation_3517() {
    let src = r#"
mod tests {
    #[test]
    fn canonically_locked() {
        let _g = crate::identity::agent_id_env_test_lock();
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:contrived") };
    }
}
"#;
    assert!(
        unguarded_mutations(PROBE, src).is_empty(),
        "a canonically-locked mutation must be spared"
    );
}

/// VERIFIED DELEGATE — the post-#3517 wrapper shape is spared. This is the arm
/// that keeps `let _g = env_var_lock();` legal in `identity` / `daemon_runtime`
/// / `config` while staying self-verifying (cf. the module-local case above,
/// which differs ONLY in the wrapper body).
#[test]
fn detector_spares_a_verified_delegate_3517() {
    let src = r"
mod tests {
    fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::identity::agent_id_env_test_lock()
    }
    #[test]
    fn delegated() {
        let _g = env_var_lock();
        unsafe { std::env::remove_var(ENV_AGENT_ID) };
    }
}
";
    assert!(
        unguarded_mutations(PROBE, src).is_empty(),
        "a verified delegate to the canonical lock must be spared"
    );
}

/// A commented-out mutation is not a mutation.
#[test]
fn detector_spares_a_commented_out_mutation_3517() {
    let src = r#"
mod tests {
    #[test]
    fn only_a_comment() {
        // unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:contrived") };
    }
}
"#;
    assert!(
        unguarded_mutations(PROBE, src).is_empty(),
        "a commented-out mutation must not be flagged"
    );
}
