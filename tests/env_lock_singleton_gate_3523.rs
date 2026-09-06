// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (issue #3523) — the STRUCTURAL gate for the crate's PROCESS-ENV
//! serialization mutex: there must be exactly ONE of it.
//!
//! # Why this gate exists
//!
//! `src/**/*.rs` compiles into ONE `cargo test --lib` binary whose `#[test]`
//! functions run in PARALLEL THREADS. `std::env::set_var` /
//! `std::env::remove_var` mutate the single process-global environment table,
//! so two tests touching `HOME` (or any `AI_MEMORY_*` knob) at once are a
//! genuine data race (rust-1.98 UNSAFE-01/03) AND a mutual-visibility bug: one
//! test's transient `HOME` is the value every concurrent reader resolves.
//!
//! A mutex only helps when every mutator takes the SAME mutex. Before #3523
//! the crate held TWO independent ones over exactly the same writes:
//!
//! * `crate::config::test_env_lock()` — the lock #2127 unified the first
//!   cohort onto (`config`, `reranker`, `egress`, `security_profile`,
//!   `cli::commands::config`, `recover::transcript_paths`,
//!   `enterprise_federation_posture`), and the one
//!   `scripts/check-test-env-lock.sh` names as crate-canonical; and
//! * `crate::test_support::env_lock()` — a SECOND
//!   `static LOCK: OnceLock<Mutex<()>>` introduced with the `EnvGuard` helper
//!   and taken by `log_paths`, `encryption` and `daemon_runtime`.
//!
//! Holding either excluded only its own users, so a `log_paths` test setting
//! `HOME` and a `config` test reading `~/.config/ai-memory/config.toml` could
//! run at literally the same instant. That is the identical per-module-mutex
//! defect `$HOME` already suffered THREE times (#1998 -> #2115 -> #2127); this
//! was its fourth instance.
//!
//! #3523 makes `test_support::env_lock()` DELEGATE to
//! `config::test_env_lock()`, which in turn acquires the one
//! `config::test_env_mutex()`. Both names survive so no call site had to move.
//!
//! # What this gate asserts
//!
//! 1. [`the_two_process_env_lock_paths_delegate_to_one_mutex_3523`] — neither
//!    entry point declares a mutex of its own, and each cites the next link in
//!    the chain. This is the pin that fires the moment someone re-adds a
//!    private `OnceLock<Mutex<()>>` to either.
//! 2. [`exactly_one_owner_in_the_process_env_lock_family_3523`] — a census over
//!    `src/**/*.rs` of every `env_lock`-family function that OWNS a
//!    `Mutex<()>`. [`SANCTIONED_OWNERS`] is the CEILING, so a new owner cannot
//!    appear silently while a sibling lane converting one of the listed
//!    cohorts to a delegate stays green.
//!
//! The runtime half of the proof lives beside the code, in
//! `src/test_support.rs::tests::the_two_env_lock_paths_are_one_mutex_3523`:
//! it holds one wrapper and requires a PROBE THREAD to fail `try_lock()` on
//! the other. A source walk cannot see that; a delegate that is spelled
//! correctly but resolves elsewhere would still pass this file. The two halves
//! are deliberately complementary.
//!
//! # Documented scope (what this gate does NOT claim)
//!
//! The census is scoped to the PROCESS-ENV family — the functions that serialize
//! `HOME` and the general `AI_MEMORY_*` knobs. The crate also carries
//! module-local mutexes over DISJOINT variable sets, each pre-existing #3523 and
//! each a separate migration: they are enumerated in [`SANCTIONED_OWNERS`] with
//! the variables they guard, so this gate ratchets them (no NEW owner may
//! appear) without claiming they are already unified. Unifying them is
//! follow-up work, not #3523's scope — `identity`'s
//! `AI_MEMORY_AGENT_ID` cohort in particular is #3517's.
//!
//! Line-based, like every sibling `scripts/check-*.sh` gate: a commented-out
//! declaration is skipped and a function's window is bounded by `fn` lines
//! rather than brace counting (brace counting mis-parses `format!("{x}")`).
//! The `detector_*` tests drive the detector over synthetic buffers so the gate
//! is proven to CATCH the two-mutex shape and SPARE the delegated one, rather
//! than passing vacuously on today's tree (M-TAUTOLOGICAL-TESTS).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Function names that serialize PROCESS-GLOBAL environment writes. A function
/// with one of these names that declares its OWN `Mutex<()>` is an env-lock
/// OWNER; anything else in the family must delegate.
///
/// `store_url_env_lock` / `key_dir_env_lock` / `fed_env_test_lock` are
/// deliberately absent: they are named for the ONE variable each guards, they
/// are not part of the `$HOME` cohort, and they are reached only through their
/// own module.
const ENV_LOCK_FN_NAMES: [&str; 6] = [
    "env_lock",
    "test_env_lock",
    "env_mutex",
    "test_env_mutex",
    "env_var_lock",
    "home_lock",
];

/// A CEILING, not an exact set: every `(file, fn)` in [`ENV_LOCK_FN_NAMES`]
/// that is allowed to OWN a `Mutex<()>`, with the variable family it
/// serializes. An owner appearing OUTSIDE this list fails the census; one
/// DISAPPEARING from it (converted to a delegate) is the direction of travel
/// and always passes, so a sibling lane doing the same unification for its own
/// cohort — #3517 is doing exactly that to the two `env_var_lock` entries —
/// never reds this gate.
///
/// * `src/config.rs::test_env_mutex` — THE one #3523 unified onto: `HOME` plus
///   the general `AI_MEMORY_*` knobs, taken by both `config::test_env_lock()`
///   and `test_support::env_lock()`.
///
/// The rest pre-date #3523, each covering a disjoint variable set inside one
/// module. They are listed so the census RATCHETS them (no new owner may
/// appear, and none may quietly grow into the `$HOME` cohort) — not because
/// they are already unified. See the module header's scope note.
const SANCTIONED_OWNERS: [(&str, &str); 8] = [
    // #3523 — THE process-env mutex.
    ("src/config.rs", "test_env_mutex"),
    // #3517's cohort: AI_MEMORY_AGENT_ID / AI_MEMORY_ADMIN_AGENT_IDS.
    ("src/identity/mod.rs", "env_var_lock"),
    ("src/daemon_runtime.rs", "env_var_lock"),
    // Per-module knob cohorts, each disjoint from $HOME.
    ("src/storage/schema_guard.rs", "test_env_lock"),
    ("src/cli/governance_install_defaults.rs", "env_lock"),
    ("src/federation/push_dlq.rs", "env_lock"),
    ("src/erasure/mod.rs", "env_lock"),
    ("src/recover/durability.rs", "env_lock"),
];

/// The two entry points #3523 unified, each with the token its body MUST cite
/// to prove it delegates one link further down the chain.
const DELEGATION_CHAIN: [(&str, &str, &str); 3] = [
    ("src/test_support.rs", "env_lock", "test_env_lock"),
    ("src/test_support.rs", "env_mutex", "test_env_mutex"),
    ("src/config.rs", "test_env_lock", "test_env_mutex"),
];

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
    let trimmed = line.trim_start();
    if is_comment_line(trimmed) {
        return None;
    }
    let mut tokens = trimmed.split_whitespace();
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

/// Is this line a `static … Mutex<()>` declaration — i.e. does the enclosing
/// function OWN a mutex rather than borrow one? Covers the three spellings
/// this codebase uses: a bare `static X: Mutex<()>`, a fully-qualified
/// `std::sync::Mutex<()>`, and an `OnceLock<Mutex<()>>` lazy-init.
fn declares_a_mutex(line: &str) -> bool {
    let trimmed = line.trim_start();
    !is_comment_line(trimmed) && trimmed.starts_with("static ") && line.contains("Mutex<()>")
}

/// `(line-number, fn-name)` for every function in `source` named in
/// [`ENV_LOCK_FN_NAMES`] whose body declares its own `Mutex<()>`.
///
/// Factored out of the filesystem walk so the self-tests can drive it over
/// synthetic buffers (M-TAUTOLOGICAL-TESTS).
fn env_lock_owners(source: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let fn_starts: Vec<usize> = (0..lines.len())
        .filter(|&i| fn_name_at(lines[i]).is_some())
        .collect();

    let mut owners = Vec::new();
    for (n, &start) in fn_starts.iter().enumerate() {
        let Some(name) = fn_name_at(lines[start]) else {
            continue;
        };
        if !ENV_LOCK_FN_NAMES.contains(&name) {
            continue;
        }
        // The window ends at the next `fn` line — never brace counting, which
        // mis-parses `format!("{x}")` (the sibling gates' documented bound).
        let end = fn_starts.get(n + 1).copied().unwrap_or(lines.len());
        if lines[start..end].iter().any(|l| declares_a_mutex(l)) {
            owners.push((start + 1, name.to_string()));
        }
    }
    owners
}

/// Body of the function named `name` in `source`, bounded by ITS closing
/// brace rather than the next `fn` line: the doc comments around these
/// wrappers deliberately quote `OnceLock<Mutex<()>>` while describing the
/// defect, and a next-`fn` window would swallow that prose.
fn fn_body(rel: &str, name: &str, lines: &[&str]) -> String {
    let start = lines
        .iter()
        .position(|l| fn_name_at(l) == Some(name))
        .unwrap_or_else(|| panic!("{rel}: no `fn {name}` found"));
    let end = (start + 1..lines.len())
        .find(|&i| lines[i].trim() == "}")
        .map_or(lines.len(), |i| i + 1);
    lines[start..end].join("\n")
}

/// THE PIN. Neither unified entry point owns a mutex, and each cites the next
/// link in the chain down to `config::test_env_mutex`.
#[test]
fn the_two_process_env_lock_paths_delegate_to_one_mutex_3523() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (rel, name, must_cite) in DELEGATION_CHAIN {
        let source = std::fs::read_to_string(manifest.join(rel))
            .unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let lines: Vec<&str> = source.lines().collect();
        let body = fn_body(rel, name, &lines);
        assert!(
            body.contains(must_cite),
            "{rel}: `fn {name}` must DELEGATE to `{must_cite}` (#3523) so both \
             process-env lock paths resolve to ONE mutex, got:\n{body}"
        );
        assert!(
            !body.lines().any(declares_a_mutex),
            "{rel}: `fn {name}` declares its OWN mutex again — that is the \
             #3523 defect (a second, independent lock over the SAME \
             process-global environment table, as in \
             #1998 -> #2115 -> #2127):\n{body}"
        );
    }
}

/// THE CENSUS. Exactly the sanctioned set of `env_lock`-family functions owns
/// a `Mutex<()>`; a new owner cannot appear and a converted one cannot revert.
#[test]
fn exactly_one_owner_in_the_process_env_lock_family_3523() {
    let src = repo_src_dir();
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(!files.is_empty(), "no src/**/*.rs files found");

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut observed: BTreeSet<String> = BTreeSet::new();
    for file in &files {
        let rel = file
            .strip_prefix(manifest)
            .unwrap_or(file.as_path())
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (_, name) in env_lock_owners(&source) {
            observed.insert(format!("{rel}::{name}"));
        }
    }

    let sanctioned: BTreeSet<String> = SANCTIONED_OWNERS
        .iter()
        .map(|(f, n)| format!("{f}::{n}"))
        .collect();

    let new_owners: Vec<&str> = observed
        .difference(&sanctioned)
        .map(String::as_str)
        .collect();
    assert!(
        new_owners.is_empty(),
        "NEW process-env mutex owner(s) in the lib test binary (#3523):\n  {}\n\n\
         `src/**/*.rs` compiles into ONE test binary whose tests run in PARALLEL\n\
         THREADS, and `std::env::set_var` mutates the single process-global\n\
         environment table. A SECOND mutex over the same variables serializes\n\
         nothing against the first — that is the #3523 defect, and the\n\
         #1998 -> #2115 -> #2127 $HOME defect before it.\n\n\
         Take the ONE canonical lock instead:\n\n  \
         let _guard = crate::config::test_env_lock();      // the `config` spelling\n  \
         let _guard = crate::test_support::env_lock();     // the delegate spelling\n\n\
         A file-local wrapper that DELEGATES to either is fine.",
        new_owners.join("\n  ")
    );

    // A sanctioned owner that has VANISHED is a sibling lane converting its
    // own cohort to a delegate — the direction of travel, never a failure.
    // Vacuity is prevented instead by the `detector_*` self-tests (which prove
    // the detector matches the defect shape at all) and by the assertion
    // below (which proves the census reached the real tree).
    assert!(
        observed.contains("src/config.rs::test_env_mutex"),
        "the ONE process-env mutex (`config::test_env_mutex`) was not found; \
         both `config::test_env_lock()` and `test_support::env_lock()` resolve \
         to it (#3523)"
    );
}

// ---------------------------------------------------------------------------
// Detector self-tests. Without these the census above could pass VACUOUSLY — a
// detector that never matches anything is green on every tree
// (M-TAUTOLOGICAL-TESTS). Each case is a separate `#[test]` so a regression
// names the SHAPE it broke.
// ---------------------------------------------------------------------------

/// The pre-#3523 shape: a second, independent `OnceLock<Mutex<()>>` in an
/// `env_lock` wrapper. This is exactly what `src/test_support.rs` looked like.
#[test]
fn detector_catches_a_second_private_mutex_3523() {
    let src = r"
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}
";
    let owners = env_lock_owners(src);
    assert_eq!(
        owners.len(),
        1,
        "a private mutex must be caught: {owners:?}"
    );
    assert_eq!(owners[0].1, "env_lock");
}

/// The bare `static LOCK: std::sync::Mutex<()>` spelling (no `OnceLock`) is
/// the same defect and must be caught too — `storage::schema_guard` uses it.
#[test]
fn detector_catches_a_bare_static_mutex_3523() {
    let src = r"
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
";
    assert_eq!(env_lock_owners(src).len(), 1);
}

/// The post-#3523 shape: a wrapper that only acquires someone else's mutex
/// owns nothing and must be spared. This differs from
/// `detector_catches_a_second_private_mutex_3523` ONLY in the body.
#[test]
fn detector_spares_a_delegate_3523() {
    let src = r"
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    crate::config::test_env_lock()
}
";
    assert!(
        env_lock_owners(src).is_empty(),
        "a delegate owns no mutex and must be spared"
    );
}

/// An unrelated module-local mutex under a name OUTSIDE the family (a
/// `GATE_LOCK` in some helper) is not a process-env lock and must not be
/// counted — otherwise the census would false-positive across the tree.
#[test]
fn detector_spares_a_mutex_outside_the_family_3523() {
    let src = r"
fn gate_lock() -> &'static std::sync::Mutex<()> {
    static GATE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    GATE_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}
";
    assert!(
        env_lock_owners(src).is_empty(),
        "a mutex outside the env-lock family must not be counted"
    );
}

/// A COMMENTED-OUT declaration is not a declaration — the doc comments on the
/// real wrappers quote `OnceLock<Mutex<()>>` verbatim while describing this
/// defect, and the gate must not self-trip on its own prose.
#[test]
fn detector_spares_a_commented_out_declaration_3523() {
    let src = r"
/// Until #3523 this declared its own
/// `static LOCK: OnceLock<Mutex<()>>` — a second, independent mutex.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    // static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    crate::config::test_env_lock()
}
";
    assert!(
        env_lock_owners(src).is_empty(),
        "a commented-out declaration must not be flagged"
    );
}
