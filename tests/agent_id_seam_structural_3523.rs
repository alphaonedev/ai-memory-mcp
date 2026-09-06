// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (issue #3523, item 4) — the caller-principal injection seam is
//! TEST-ONLY, STRUCTURALLY, and it actually works.
//!
//! # What the seam is
//!
//! Until #3523 the ONLY way a test could influence
//! [`ai_memory::identity::resolve_agent_id`] /
//! [`ai_memory::identity::resolve_read_visibility_caller`] was to write
//! `AI_MEMORY_AGENT_ID` into the PROCESS environment. `src/**/*.rs` compiles
//! into ONE `cargo test --lib` binary whose tests run in PARALLEL THREADS, so
//! that write is both unsound (rust-1.98 UNSAFE-01/03) and globally VISIBLE:
//! every concurrently-running reader resolves the foreign principal for as
//! long as it is installed. That is the #3475 / #3517 flake class, and
//! serializing the mutators cannot fix it because the victims are READERS
//! that take no lock.
//!
//! `identity::test_agent_id::AgentIdOverride` replaces the process write with
//! a THREAD-LOCAL override consulted by the one `agent_id_env()` chokepoint.
//! A value installed on one test thread is invisible to every other by
//! construction — no lock, no window, no way to steer a sibling.
//!
//! # The security claim, and what proves it
//!
//! The claim is UNREACHABILITY IN PRODUCTION, and it rests on TWO
//! independent properties, because the first alone is not enough:
//!
//! 1. **Structural absence from the shipped binary.**
//!    [`seam_is_cfg_gated_to_test_builds_3523`] asserts by source walk that
//!    the `pub mod test_agent_id` declaration AND the `agent_id_env()` line
//!    that consults it are each attributed
//!    `#[cfg(any(test, feature = "test-support"))]`. Under
//!    `cargo build --release` (default features) neither exists, so
//!    `agent_id_env()` compiles to exactly `std::env::var(ENV_AGENT_ID)`.
//!    This is a `cfg` gate, NOT a runtime flag: there is no branch to
//!    mis-set and no environment variable that arms it.
//!
//! 2. **No production caller, even where the seam IS compiled.** Property 1
//!    is insufficient on its own, and #3516 is why: `Cargo.toml` carries a
//!    self dev-dependency (`ai-memory = { path = ".", features =
//!    ["test-support"] }`), so EVERY `cargo test` unifies `test-support`
//!    into the whole build — including the `ai-memory` BIN that overwrites
//!    `target/{debug,release}/ai-memory`. In that binary the seam module IS
//!    compiled. It is inert there for two reasons: the thread-local defaults
//!    to `None`, so an unarmed process behaves byte-identically to one
//!    without the seam; and nothing production-side ever arms it.
//!    [`no_production_code_arms_the_agent_id_seam_3523`] asserts the second
//!    by source walk over all of `src/`, so the day someone wires the setter
//!    into a handler this gate fires.
//!
//! # And that it is not decorative
//!
//! A `cfg`-gated module nothing consults would pass both structural tests
//! while doing nothing. [`the_seam_steers_the_read_visibility_caller_3523`]
//! and [`the_seam_is_thread_local_and_cannot_steer_a_sibling_3523`] pin the
//! RUNTIME behaviour: the override reaches the resolver on the installing
//! thread, is restored on drop, and is NOT visible to a probe thread — which
//! is the whole property that makes it safe where the environment was not.
//!
//! The `detector_*` cases drive the source-walk predicates over synthetic
//! buffers so the gate is proven to CATCH an un-gated seam and an armed
//! production call site, rather than passing vacuously on today's tree
//! (M-TAUTOLOGICAL-TESTS).

use std::path::{Path, PathBuf};

/// The `cfg` attribute both halves of the seam must carry, verbatim.
const SEAM_CFG: &str = r#"#[cfg(any(test, feature = "test-support"))]"#;

/// The seam module's declaration line in `src/identity/mod.rs`.
const SEAM_MODULE_DECL: &str = "pub mod test_agent_id {";

/// The line inside `agent_id_env()` that consults the seam.
const SEAM_CONSULT: &str = "if let Some(override_value) = test_agent_id::current_override()";

/// The only file allowed to mention the seam's arming API: the file that
/// DEFINES it.
const SEAM_DEFINITION_FILE: &str = "src/identity/mod.rs";

/// Tokens that ARM the seam. A production call site of any of these would
/// make a test-only override reachable from a shipped code path.
const SEAM_ARMING_TOKENS: [&str; 3] = [
    "AgentIdOverride::set",
    "AgentIdOverride::unset",
    "test_agent_id::AgentIdOverride",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Dot-prefixed scratch files are never compiled (they are the
        // `scripts/check-*.sh` self-test fixtures).
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

/// Is the line carrying `needle` immediately preceded by [`SEAM_CFG`]?
///
/// "Immediately preceded" skips blank lines, comments, and a lone `{`,
/// because a documented item legitimately carries prose between its attribute
/// and its signature, and the seam's consult sits inside a `#[cfg]`-attributed
/// BLOCK (an attribute on a bare expression-statement is still unstable, so
/// the block is the stable spelling). It does NOT skip real code, so an
/// attribute cannot be borrowed from an unrelated item further up.
fn line_is_cfg_gated(source: &str, needle: &str) -> Option<bool> {
    let lines: Vec<&str> = source.lines().collect();
    let idx = lines.iter().position(|l| l.contains(needle))?;
    for candidate in lines[..idx].iter().rev() {
        let trimmed = candidate.trim();
        if trimmed.is_empty() || is_comment_line(trimmed) || trimmed == "{" {
            continue;
        }
        return Some(trimmed == SEAM_CFG);
    }
    Some(false)
}

/// `"<rel>:<line-number>: <trimmed line>"` for every NON-COMMENT line in
/// `source` that arms the seam.
///
/// Factored out of the filesystem walk so the self-tests can drive it over
/// synthetic buffers.
fn arming_call_sites(rel: &str, source: &str) -> Vec<String> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !is_comment_line(trimmed) && SEAM_ARMING_TOKENS.iter().any(|t| line.contains(t))
        })
        .map(|(i, line)| format!("{rel}:{}: {}", i + 1, line.trim()))
        .collect()
}

/// STRUCTURE 1. Both halves of the seam are `cfg`-gated to test builds, so
/// `cargo build --release` compiles neither.
#[test]
fn seam_is_cfg_gated_to_test_builds_3523() {
    let source = std::fs::read_to_string(manifest_dir().join(SEAM_DEFINITION_FILE))
        .unwrap_or_else(|e| panic!("read {SEAM_DEFINITION_FILE}: {e}"));

    for needle in [SEAM_MODULE_DECL, SEAM_CONSULT] {
        let gated = line_is_cfg_gated(&source, needle).unwrap_or_else(|| {
            panic!(
                "{SEAM_DEFINITION_FILE}: the seam anchor `{needle}` was not found. \
                 If it was renamed, rename it HERE too — this gate is the only \
                 thing asserting the #3523 seam stays out of a release build."
            )
        });
        assert!(
            gated,
            "{SEAM_DEFINITION_FILE}: `{needle}` is NOT immediately preceded by\n  \
             {SEAM_CFG}\n\n\
             The caller-principal injection seam must be STRUCTURALLY absent from a \
             production build (#3523) — a runtime flag would not do, because a flag \
             can be set. Without the cfg the shipped `ai-memory` binary carries a \
             thread-local that can replace the resolved caller identity."
        );
    }
}

/// STRUCTURE 2. Nothing in `src/` outside the seam's own file ARMS it, so the
/// seam is inert even in the `test-support`-unified build the #3516 self
/// dev-dependency produces.
#[test]
fn no_production_code_arms_the_agent_id_seam_3523() {
    let manifest = manifest_dir();
    let mut files = Vec::new();
    collect_rs_files(&manifest.join("src"), &mut files);
    assert!(!files.is_empty(), "no src/**/*.rs files found");

    let mut violations = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(&manifest)
            .unwrap_or(file.as_path())
            .to_string_lossy()
            .replace('\\', "/");
        if rel == SEAM_DEFINITION_FILE {
            continue;
        }
        let source = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        violations.extend(arming_call_sites(&rel, &source));
    }

    assert!(
        violations.is_empty(),
        "the TEST-ONLY caller-principal seam is armed from `src/` (#3523):\n  {}\n\n\
         `identity::test_agent_id::AgentIdOverride` replaces the resolved caller \
         identity on the calling thread. Its safety claim is that NO production path \
         ever arms it — the cfg gate alone is not enough, because every `cargo test` \
         unifies `test-support` into the whole build INCLUDING the `ai-memory` BIN \
         (the #3516 lesson), so the module IS compiled there.\n\n\
         A test that needs a specific caller should build the guard in its own test \
         module, or pass an EXPLICIT caller argument.",
        violations.join("\n  ")
    );
}

/// BEHAVIOUR 1. The seam is not decorative: it steers the resolver on the
/// installing thread, and the previous state is restored on drop.
#[test]
fn the_seam_steers_the_read_visibility_caller_3523() {
    use ai_memory::identity::test_agent_id::AgentIdOverride;

    // This is its OWN test binary (its own process), so the environment is
    // whatever cargo handed it. Assert the precondition rather than assume
    // it: a harness that pre-set the variable would make the restore leg
    // below assert the wrong thing.
    let ambient = ai_memory::identity::resolve_read_visibility_caller();

    {
        let _guard = AgentIdOverride::set("ai:seam-probe-3523");
        assert_eq!(
            ai_memory::identity::resolve_read_visibility_caller().as_deref(),
            Some("ai:seam-probe-3523"),
            "#3523: an armed override must reach `resolve_read_visibility_caller`"
        );
    }
    assert_eq!(
        ai_memory::identity::resolve_read_visibility_caller(),
        ambient,
        "#3523: the guard must restore the pre-guard state on drop"
    );

    {
        let _guard = AgentIdOverride::unset();
        assert_eq!(
            ai_memory::identity::resolve_read_visibility_caller(),
            None,
            "#3523: `unset()` must resolve the single-tenant trust-all posture \
             regardless of the real environment"
        );
    }
    assert_eq!(
        ai_memory::identity::resolve_read_visibility_caller(),
        ambient,
        "#3523: the guard must restore the pre-guard state on drop"
    );
}

/// BEHAVIOUR 2 — the property that makes the seam SAFE where the process
/// environment was not: an override is invisible to another thread.
///
/// This is the whole point. An `AI_MEMORY_AGENT_ID` write steers every
/// concurrently-running reader in the process (#3475 / #3517); a
/// thread-local steers exactly one thread, so a test using this seam cannot
/// make a sibling test resolve a foreign principal no matter how they are
/// scheduled.
#[test]
fn the_seam_is_thread_local_and_cannot_steer_a_sibling_3523() {
    use ai_memory::identity::test_agent_id::AgentIdOverride;

    let _guard = AgentIdOverride::set("ai:must-not-escape-3523");
    assert_eq!(
        ai_memory::identity::resolve_read_visibility_caller().as_deref(),
        Some("ai:must-not-escape-3523"),
        "precondition: the override is armed on THIS thread"
    );

    let observed_by_probe = std::thread::spawn(ai_memory::identity::resolve_read_visibility_caller)
        .join()
        .expect("probe thread must not panic");

    assert_ne!(
        observed_by_probe.as_deref(),
        Some("ai:must-not-escape-3523"),
        "#3523: a caller principal installed on one thread LEAKED to another. \
         The seam's entire safety argument is that it is thread-local — if it \
         crosses threads it is just `set_var` with extra steps, and the \
         #3475 / #3517 flake class is reopened."
    );
}

// ---------------------------------------------------------------------------
// Detector self-tests. Without these, both structural tests could pass
// VACUOUSLY — a predicate that never matches is green on every tree
// (M-TAUTOLOGICAL-TESTS). Each case is a separate `#[test]` so a regression
// names the SHAPE it broke.
// ---------------------------------------------------------------------------

/// The regression this gate exists for: the seam module loses its `cfg` and
/// ships in the release binary.
#[test]
fn detector_catches_an_ungated_seam_module_3523() {
    let src = r#"
/// Some prose.
pub mod test_agent_id {
    // ...
}
"#;
    assert_eq!(
        line_is_cfg_gated(src, SEAM_MODULE_DECL),
        Some(false),
        "an un-gated seam module must be caught"
    );
}

/// The correctly-gated shape is spared — including with doc comments between
/// the attribute and the declaration, which is how the real seam is written.
#[test]
fn detector_spares_a_gated_seam_module_3523() {
    let src = r#"
#[cfg(any(test, feature = "test-support"))]
/// Some prose.
/// More prose.
pub mod test_agent_id {
    // ...
}
"#;
    assert_eq!(
        line_is_cfg_gated(src, SEAM_MODULE_DECL),
        Some(true),
        "the gated shape must be spared"
    );
}

/// An attribute belonging to an UNRELATED earlier item must not be borrowed:
/// only blank lines, comments and a lone `{` may sit between the gate and the
/// item — never real code.
#[test]
fn detector_catches_a_borrowed_attribute_3523() {
    let src = r#"
#[cfg(any(test, feature = "test-support"))]
pub fn something_else() {}

pub mod test_agent_id {
    // ...
}
"#;
    assert_eq!(
        line_is_cfg_gated(src, SEAM_MODULE_DECL),
        Some(false),
        "a cfg attached to an unrelated earlier item must not count"
    );
}

/// The BLOCK form the real seam uses — `#[cfg]` on a block statement, the
/// consult one line inside it — is spared. Without the lone-`{` skip this
/// would read the `{` as real code and report the seam as un-gated, which
/// would red the gate on a correctly-written tree.
#[test]
fn detector_spares_the_cfg_block_form_3523() {
    let src = r#"
fn agent_id_env() -> Result<String, std::env::VarError> {
    #[cfg(any(test, feature = "test-support"))]
    {
        if let Some(override_value) = test_agent_id::current_override() {
            return override_value.ok_or(std::env::VarError::NotPresent);
        }
    }
    std::env::var(ENV_AGENT_ID)
}
"#;
    assert_eq!(
        line_is_cfg_gated(src, SEAM_CONSULT),
        Some(true),
        "the cfg-attributed BLOCK form the real seam uses must be spared"
    );
}

/// A production call site that ARMS the seam is caught.
#[test]
fn detector_catches_a_production_arming_call_site_3523() {
    let src = r#"
pub fn handle_something() {
    let _g = crate::identity::test_agent_id::AgentIdOverride::set("ai:oops");
}
"#;
    assert_eq!(
        arming_call_sites("src/contrived.rs", src).len(),
        1,
        "a production call site arming the seam must be caught"
    );
}

/// A COMMENTED-OUT mention is not a call site — this gate's own module header
/// names the arming API verbatim while describing the defect, and a rule that
/// could not tell prose from code would fire on documentation.
#[test]
fn detector_spares_a_commented_out_mention_3523() {
    let src = r"
// Nothing here calls AgentIdOverride::set — it is only described.
/// See `test_agent_id::AgentIdOverride` for the test-only seam.
pub fn handle_something() {}
";
    assert!(
        arming_call_sites("src/contrived.rs", src).is_empty(),
        "a commented-out mention must not be flagged"
    );
}
