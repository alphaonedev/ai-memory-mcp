//! FIT docs-B false claims, issues #4000-#4009: each cell pins one shipped
//! reference sentence to the behaviour the code has today.
//!
//! This file re-lands the #4006 row only (lost commit `ea27e5b0e9a8`, #9017);
//! the other rows re-land through their own lanes.

use std::path::PathBuf;

/// Repository root of the crate under test.
fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// `rel` read and whitespace-flattened, so a re-wrapped paragraph never
/// hides or forges a pinned phrase.
fn flat_text(rel: &str) -> String {
    let path = repo_path(rel);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whitespace-flatten a needle the same way as [`flat_text`].
fn flat_needle(needle: &str) -> String {
    needle.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_present(rel: &str, needle: &str, issue: &str) {
    let needle = flat_needle(needle);
    assert!(
        flat_text(rel).contains(&needle),
        "{issue}: {rel} must contain {needle:?}"
    );
}

fn assert_absent(rel: &str, needle: &str, issue: &str) {
    let needle = flat_needle(needle);
    assert!(
        !flat_text(rel).contains(&needle),
        "{issue}: {rel} must not contain {needle:?}"
    );
}

/// #4006 — `ai-memory tls init|import|status` ship in v1.0.0 (unconditionally
/// registered, `src/cli/tls.rs`); the references must not defer them to
/// v1.0.1, and must not tell operators rotation needs an unshipped verb.
#[test]
fn tls_verbs_are_not_deferred_to_v1_0_1_4006() {
    const ISSUE: &str = "#4006";
    // Premise anchor: the verbs exist.
    for verb in ["Init {", "Import {", "Status,"] {
        assert_present("src/cli/tls.rs", verb, ISSUE);
    }
    assert_absent(
        "docs/CLI_REFERENCE.md",
        "init|import|renew` and `ai-memory db check-tls` verbs are v1.0.1",
        ISSUE,
    );
    assert_absent(
        "docs/SECURITY.md",
        "init|import|renew` and `ai-memory db check-tls` verbs",
        ISSUE,
    );
    assert_absent(
        "docs/SECURITY.md",
        "an `ai-memory tls import` verb is #3709 item 2, v1.0.1",
        ISSUE,
    );
    for rel in ["docs/CLI_REFERENCE.md", "docs/SECURITY.md"] {
        assert_present(
            rel,
            "v1.0.0 ships `ai-memory tls init`, `tls import`, and `tls status`",
            ISSUE,
        );
    }
    assert_absent("src/daemon_runtime.rs", "flags = plain HTTP", ISSUE);
}
