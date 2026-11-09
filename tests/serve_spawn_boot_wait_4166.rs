//! #4166: every integration test that spawns the real `serve` binary must keep
//! the boot off the embedder download path, and must not fail because a healthy
//! boot was slow.
//!
//! Class: a test spawns `serve` (with or without `env_clear`) and waits on
//! `/health`, a log line or the db file under a fixed deadline. Without
//! `AI_MEMORY_EMBED_OFFLINE` the semantic tier tries a model fetch under an
//! empty `HOME`, the boot outlasts the deadline on a loaded runner, and the
//! test fails although nothing is wrong (PR #8602 linux-fed, PR #8705
//! macos-fed).
//!
//! Invariant, checked here over every `tests/**/*.rs` source file:
//!   (a) every file that spawns the `ai-memory` binary with a `"serve"`
//!       argument either calls the shared `serve_test_env(` helper from
//!       `tests/common/mod.rs`, sets `AI_MEMORY_EMBED_OFFLINE` itself, or is
//!       listed in [`EXEMPT`] with the reason the daemon's boot is not on its
//!       path (help-only, refusal-only, embedder under test);
//!   (b) a file that clears the environment, spawns `serve` and probes
//!       `/health` never asserts on a bare boot deadline while the child is
//!       still running unless the handle reaps the child on drop (the panic
//!       would otherwise leak an orphan `serve` on an already saturated
//!       runner); the wait ends on child exit or health and kills the child
//!       when its hang guard trips.
//!
//! The scan is a text scan with named fixtures proving both directions.

use std::fs;
use std::path::{Path, PathBuf};

/// The knob the spawned child must carry.
const EMBED_OFFLINE_KNOB: &str = "AI_MEMORY_EMBED_OFFLINE";

/// The shared helper every serve spawn calls (tests/common/mod.rs).
const SERVE_ENV_HELPER: &str = "serve_test_env(";

/// A line that spawns the real binary: the cargo-provided path or the
/// `assert_cmd`-style lookup.
const BIN_SPAWN_MARKERS: [&str; 2] = ["CARGO_BIN_EXE_ai-memory", "cargo_bin("];

/// Files that name `"serve"` and spawn the binary but are deliberately not
/// given the knob, each with the reason the boot is not on their path.
const EXEMPT: &[(&str, &str)] = &[
    (
        "b3_precompute_doesnt_block_serve.rs",
        "exercises the embedder precompute on purpose (family-embedding \
         precompute switched on); offline would remove the path under test. \
         HF_HUB_OFFLINE=1 already blocks the download",
    ),
    (
        "cli_integration.rs",
        "names serve only in a `serve --help` subcommand probe; no daemon boots",
    ),
    (
        "cli_serve_help_text.rs",
        "asserts `serve --help` text; no daemon boots",
    ),
    (
        "credential_to_sink_3711.rs",
        "serve is refused (--db with --store-url conflict) before any embedder \
         init; the test waits for the process exit",
    ),
    (
        "store_url_ambiguous_userinfo_6096.rs",
        "serve is refused (ambiguous store URL) before any embedder init; the \
         test waits for the process exit",
    ),
    (
        "federation_peer_posture_3582.rs",
        "every serve spawn is refused by the peer-posture gate before the \
         database opens; output() waits for the exit, there is no /health wait",
    ),
];

/// This guard's own source quotes every pattern it looks for.
const SELF_FILE: &str = "serve_spawn_boot_wait_4166.rs";

const ENV_CLEAR_CALL: &str = "env_clear()";
const SERVE_LITERAL: &str = "\"serve\"";
const HEALTH_LITERAL: &str = "/health";

/// Source lines with comments dropped, as `(1-based line, text)`.
fn code_lines(src: &str) -> Vec<(usize, &str)> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .map(|(i, l)| (i + 1, l))
        .collect()
}

/// Whether `src` is in the class: clears the env, spawns `serve`, probes
/// `/health`. Returns the line of the first `env_clear()` call.
fn class_line(src: &str) -> Option<usize> {
    let lines = code_lines(src);
    let has = |needle: &str| lines.iter().any(|(_, l)| l.contains(needle));
    if !(has(SERVE_LITERAL) && has(HEALTH_LITERAL)) {
        return None;
    }
    lines
        .iter()
        .find(|(_, l)| l.contains(ENV_CLEAR_CALL))
        .map(|(n, _)| *n)
}

/// Whether `src` spawns the real binary with a `"serve"` argument. Returns the
/// line of the first `"serve"` literal.
fn serve_spawn_line(src: &str) -> Option<usize> {
    let lines = code_lines(src);
    let has = |needle: &str| lines.iter().any(|(_, l)| l.contains(needle));
    if !BIN_SPAWN_MARKERS.iter().any(|m| has(m)) {
        return None;
    }
    lines
        .iter()
        .find(|(_, l)| l.contains(SERVE_LITERAL))
        .map(|(n, _)| *n)
}

/// Whether the source routes its serve spawn through the helper or sets the
/// knob itself, on a code line (a comment does not count).
fn sets_embed_offline(src: &str) -> bool {
    let knob = format!("\"{EMBED_OFFLINE_KNOB}\"");
    code_lines(src)
        .iter()
        .any(|(_, l)| l.contains(SERVE_ENV_HELPER) || l.contains(&knob))
}

/// Invariant (a): `Some(line)` when the file spawns `serve` and neither calls
/// the helper nor sets the knob. Exemptions are applied by the caller.
fn missing_embed_offline(src: &str) -> Option<usize> {
    let line = serve_spawn_line(src)?;
    (!sets_embed_offline(src)).then_some(line)
}

/// Invariant (b): `Some(line)` of an `assert!(` whose condition is a bare
/// `Instant::now() < <deadline>` comparison in a file of the class whose
/// child handle does not reap on drop (`impl Drop for` plus `.kill()`).
fn bare_deadline_assert(src: &str) -> Option<usize> {
    class_line(src)?;
    let code = code_lines(src);
    let reaps_on_drop = code.iter().any(|(_, l)| l.contains("impl Drop for"))
        && code.iter().any(|(_, l)| l.contains(".kill()"));
    if reaps_on_drop {
        return None;
    }
    let lines: Vec<&str> = src.lines().collect();
    lines.iter().enumerate().find_map(|(i, l)| {
        let t = l.trim();
        if t.starts_with("//") || !t.starts_with("assert!(") {
            return None;
        }
        // The condition is the rest of this line or the next one.
        let cond = if t == "assert!(" {
            lines.get(i + 1).map_or("", |n| n.trim())
        } else {
            t
        };
        (cond.contains("Instant::now() <") && cond.contains("deadline")).then_some(i + 1)
    })
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") && !p.ends_with(SELF_FILE) {
            out.push(p);
        }
    }
}

fn all_test_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    rust_sources(&root, &mut out);
    assert!(out.len() > 100, "scan found only {} test files", out.len());
    out
}

fn is_exempt(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| EXEMPT.iter().any(|(f, _)| *f == n))
}

fn scan(check: fn(&str) -> Option<usize>, skip_exempt: bool) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    all_test_sources()
        .iter()
        .filter(|p| !(skip_exempt && is_exempt(p)))
        .filter_map(|p| {
            let src = fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            check(&src)
                .map(|line| format!("{}:{line}", p.strip_prefix(root).unwrap_or(p).display()))
        })
        .collect()
}

/// Fixture: the shape of the sites that flaked.
const SPAWN_WITHOUT_KNOB: &str = r#"
fn command(root: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("HOME", root)
        .env("RUST_LOG", "error");
    cmd
}
fn boot(cmd: &mut Command) {
    cmd.args(["serve", "--port", "0"]);
    let url = "https://127.0.0.1/api/v1/health";
}
"#;

#[test]
fn guard_flags_a_spawn_without_the_knob_4166() {
    assert_eq!(missing_embed_offline(SPAWN_WITHOUT_KNOB), Some(10));
}

#[test]
fn guard_flags_a_spawn_without_env_clear_or_health_wait_4166() {
    // The class is every serve spawn, not only cleared-env /health waiters.
    // Dropping the `env_clear` line shifts the serve literal up by one.
    let inherited = SPAWN_WITHOUT_KNOB.replace("cmd.env_clear()\n        .env(", "cmd.env(");
    assert_eq!(missing_embed_offline(&inherited), Some(9));
    let log_wait = SPAWN_WITHOUT_KNOB.replace("/health", "/ready-log");
    assert_eq!(missing_embed_offline(&log_wait), Some(10));
    let cargo_bin_lookup = SPAWN_WITHOUT_KNOB.replace(
        "Command::new(env!(\"CARGO_BIN_EXE_ai-memory\"))",
        "Command::new(cargo_bin(\"ai-memory\"))",
    );
    assert_eq!(missing_embed_offline(&cargo_bin_lookup), Some(10));
}

#[test]
fn guard_accepts_the_helper_or_the_knob_literal_4166() {
    let with_knob = SPAWN_WITHOUT_KNOB.replace(
        ".env(\"RUST_LOG\", \"error\");",
        ".env(\"AI_MEMORY_EMBED_OFFLINE\", \"1\");",
    );
    assert!(with_knob.contains("\"AI_MEMORY_EMBED_OFFLINE\""));
    assert_eq!(missing_embed_offline(&with_knob), None);
    let with_helper = SPAWN_WITHOUT_KNOB.replace(
        "    cmd\n}",
        "    common::serve_test_env(&mut cmd);\n    cmd\n}",
    );
    assert!(with_helper.contains("serve_test_env("));
    assert_eq!(missing_embed_offline(&with_helper), None);
}

#[test]
fn guard_ignores_a_knob_or_helper_that_is_only_in_a_comment_4166() {
    let commented = SPAWN_WITHOUT_KNOB.replace(
        "        .env(\"RUST_LOG\", \"error\");",
        "        // .env(\"AI_MEMORY_EMBED_OFFLINE\", \"1\")\n        // common::serve_test_env(&mut cmd);\n        .env(\"RUST_LOG\", \"error\");",
    );
    assert_eq!(missing_embed_offline(&commented), Some(12));
}

#[test]
fn guard_skips_files_that_never_spawn_serve_4166() {
    // Spawns the binary but never with a serve argument.
    let other_verb = SPAWN_WITHOUT_KNOB.replace("\"serve\"", "\"doctor\"");
    assert_eq!(missing_embed_offline(&other_verb), None);
    // Names serve but never spawns the binary (a string or a table only).
    let no_spawn = SPAWN_WITHOUT_KNOB.replace("CARGO_BIN_EXE_ai-memory", "OTHER");
    assert_eq!(missing_embed_offline(&no_spawn), None);
}

#[test]
fn guard_flags_a_bare_deadline_assert_and_accepts_a_reaping_wait_4166() {
    let bare = format!(
        "{SPAWN_WITHOUT_KNOB}\nfn wait() {{\n    assert!(\n        Instant::now() < deadline,\n        \"x\"\n    );\n}}\n"
    );
    assert_eq!(bare_deadline_assert(&bare), Some(15));
    let inline = format!(
        "{SPAWN_WITHOUT_KNOB}\nfn wait() {{\n    assert!(Instant::now() < deadline, \"x\");\n}}\n"
    );
    assert_eq!(bare_deadline_assert(&inline), Some(15));
    let reaping = format!(
        "{SPAWN_WITHOUT_KNOB}\nfn wait() {{\n    if Instant::now() >= deadline {{\n        let _ = child.kill();\n        panic!(\"x\");\n    }}\n}}\n"
    );
    assert_eq!(bare_deadline_assert(&reaping), None);
    // A handle that kills and reaps the child on drop makes the panic safe.
    let dropped = format!(
        "{bare}\nimpl Drop for Daemon {{\n    fn drop(&mut self) {{\n        let _ = self.child.kill();\n    }}\n}}\n"
    );
    assert_eq!(bare_deadline_assert(&dropped), None);
    // Outside the class the same assert is not this guard's business.
    let other = "fn wait() {\n    assert!(Instant::now() < deadline);\n}\n";
    assert_eq!(bare_deadline_assert(other), None);
}

/// Every exemption names a file that still spawns `serve` and still does not
/// set the knob, with a real reason; a stale row would hide a regression.
#[test]
fn exemptions_are_current_and_reasoned_4166() {
    let sources = all_test_sources();
    for (name, reason) in EXEMPT {
        assert!(reason.len() > 20, "{name}: exemption needs a real reason");
        let path = sources
            .iter()
            .find(|p| p.file_name().is_some_and(|n| n == *name))
            .unwrap_or_else(|| panic!("exempt file {name} does not exist"));
        let src = fs::read_to_string(path).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            serve_spawn_line(&src).is_some(),
            "{name} no longer spawns serve; drop it from EXEMPT"
        );
        assert!(
            !sets_embed_offline(&src),
            "{name} now sets the knob; drop it from EXEMPT"
        );
    }
}

/// Invariant (a) over the real tree.
#[test]
fn every_serve_spawn_sets_embed_offline_4166() {
    let offenders = scan(missing_embed_offline, true);
    assert!(
        offenders.is_empty(),
        "serve spawns must call serve_test_env() or set {EMBED_OFFLINE_KNOB} (#4166), \
         or be listed in EXEMPT with a reason; missing at: {offenders:?}"
    );
}

/// Invariant (b) over the real tree.
#[test]
fn no_serve_boot_wait_asserts_on_a_bare_deadline_4166() {
    let offenders = scan(bare_deadline_assert, false);
    assert!(
        offenders.is_empty(),
        "a serve boot wait must end on child exit or health and kill the child \
         when its hang guard trips, not assert on a bare deadline with the \
         child still running (#4166); found at: {offenders:?}"
    );
}
